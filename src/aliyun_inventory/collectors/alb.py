"""ALB Collector — 收集应用型负载均衡"""
from typing import Any

from alibabacloud_alb20200616 import models as alb_models
from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_next_token, model_to_dict
from ..config import AccountConfig
from ..models import LoadBalancer, BackendServer

class AlbCollector(BaseCollector):
    """应用型负载均衡 (ALB) 收集器"""

    def collect(self) -> None:
        """探测有 ALB 的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("alb")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 ALB", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s ALB 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s ALB 同步完成: 共 %d 个", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 ALB 实例"""
        client = self.client_factory.create_client("alb", region_id)

        lbs = paginate_next_token(
            client=client,
            method_name="list_load_balancers",
            request_class=alb_models.ListLoadBalancersRequest,
            list_extractor=lambda resp: resp.body.load_balancers or [],
        )

        for lb in lbs:
            try:
                self._save_lb(lb, region_id, client)
            except Exception as e:
                self.logger.warning("保存 ALB %s 失败: %s", lb.load_balancer_id, e)
                continue

        self.session.commit()
        return len(lbs)

    def _save_lb(self, lb: Any, region_id: str, client: Any) -> None:
        """保存单个 ALB 实例"""
        lb_id = lb.load_balancer_id
        lb_name = lb.load_balancer_name or ""
        status = lb.load_balancer_status or ""
        # ALB SDK 属性名: dnsname (全小写无分隔), address_type
        # ALB 没有 address 字段，通过 dnsname 提供访问域名
        address = ""  # ALB 无固定 IP
        address_type = getattr(lb, "address_type", "") or ""
        dns_name = getattr(lb, "dnsname", "") or ""
        vpc_id = lb.vpc_id or ""

        raw_dict = model_to_dict(lb)

        # 写入 load_balancers 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "lb_type": "alb",
            "lb_id": lb_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "lb_name": lb_name,
            "status": status,
            "address": address,
            "address_type": address_type,
            "dns_name": dns_name,
            "vpc_id": vpc_id,
            "raw_json": raw_dict,
        }
        self.upsert(LoadBalancer, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="alb",
            region_id=region_id,
            resource_id=lb_id,
            resource_name=lb_name,
            raw_json=raw_dict,
            source_api="ListLoadBalancers",
        )

        # 写入 ip_addresses 表 — ALB DNS 名称不是 IP，不写入 ip_addresses
        # ALB 通过 DNSName 提供，不是固定 IP 地址

        # 获取监听器 → 从监听器提取服务器组 → 获取后端服务器
        try:
            self._collect_listeners_and_server_groups(lb_id, region_id, client)
        except Exception as e:
            self.logger.warning("获取 ALB %s 监听器和服务器组失败: %s", lb_id, e)

    def _collect_listeners_and_server_groups(
        self, lb_id: str, region_id: str, client: Any
    ) -> None:
        """通过监听器获取 ALB 关联的服务器组和后端服务器

        ALB 的 ListServerGroupsRequest 不支持 load_balancer_id 参数，
        需要先查 Listener，从 DefaultActions 中提取 server_group_id，
        再逐个获取服务器组详情和后端。
        """
        listeners = paginate_next_token(
            client=client,
            method_name="list_listeners",
            request_class=alb_models.ListListenersRequest,
            extra_params={"load_balancer_ids": [lb_id]},
            list_extractor=lambda resp: resp.body.listeners or [],
        )

        # 收集所有引用的 server_group_id
        server_group_ids: set[str] = set()
        for ln in listeners:
            default_actions = getattr(ln, "default_actions", None) or []
            for action in default_actions:
                forward_config = getattr(action, "forward_group_config", None)
                if not forward_config:
                    continue
                tuples = getattr(forward_config, "server_group_tuples", None) or []
                for t in tuples:
                    sg_id = getattr(t, "server_group_id", None)
                    if sg_id:
                        server_group_ids.add(sg_id)

        # 也从转发规则中获取 server_group_id
        try:
            self._collect_forwarding_rules_from_listeners(
                lb_id, region_id, client, listeners, server_group_ids
            )
        except Exception as e:
            self.logger.warning("获取 ALB %s 转发规则失败: %s", lb_id, e)

        # 对每个 server_group_id 获取后端服务器
        for sg_id in server_group_ids:
            try:
                self._collect_backends(sg_id, lb_id, region_id, client)
            except Exception as e:
                self.logger.warning("获取服务器组 %s 后端服务器失败: %s", sg_id, e)

    def _collect_forwarding_rules_from_listeners(
        self,
        lb_id: str,
        region_id: str,
        client: Any,
        listeners: list,
        server_group_ids: set[str],
    ) -> None:
        """从监听器中获取转发规则（ALB 叫路由规则）"""
        for ln in listeners:
            listener_id = getattr(ln, "listener_id", None)
            if not listener_id:
                continue
            try:
                rules = paginate_next_token(
                    client=client,
                    method_name="list_rules",
                    request_class=alb_models.ListRulesRequest,
                    extra_params={"listener_ids": [listener_id]},
                    list_extractor=lambda resp: resp.body.rules or [],
                )
                for rule in rules:
                    # 从转发规则中提取 server_group_id
                    actions = getattr(rule, "actions", None) or []
                    for action in actions:
                        forward_config = getattr(action, "forward_group_config", None)
                        if not forward_config:
                            continue
                        tuples = getattr(forward_config, "server_group_tuples", None) or []
                        for t in tuples:
                            sg_id = getattr(t, "server_group_id", None)
                            if sg_id:
                                server_group_ids.add(sg_id)
            except Exception as e:
                self.logger.warning("获取 ALB listener %s 转发规则失败: %s", listener_id, e)

    def _collect_backends(
        self,
        server_group_id: str,
        lb_id: str,
        region_id: str,
        client: Any,
    ) -> None:
        """获取服务器组的后端服务器"""
        backends = paginate_next_token(
            client=client,
            method_name="list_server_group_servers",
            request_class=alb_models.ListServerGroupServersRequest,
            extra_params={"server_group_id": server_group_id},
            list_extractor=lambda resp: resp.body.servers or [],
        )

        for backend in backends:
            try:
                self._save_backend(lb_id, server_group_id, backend, region_id)
            except Exception as e:
                self.logger.warning("保存 ALB 后端服务器失败: %s", e)
                continue

    def _save_backend(
        self,
        lb_id: str,
        server_group_id: str,
        backend: Any,
        region_id: str,
    ) -> None:
        """保存单个后端服务器"""
        server_id = backend.server_id or ""
        backend_ip = backend.server_ip or ""
        port = backend.port if backend.port else None
        weight = backend.weight if backend.weight else None

        raw_dict = model_to_dict(backend)

        # 写入 backend_servers 表
        unique_keys = {
            "account_name": self.account.name,
            "lb_type": "alb",
            "region_id": region_id,
            "lb_id": lb_id,
            "server_group_id": server_group_id or "",
            "backend_resource_id": server_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "server_group_id": server_group_id,
            "backend_ip": backend_ip,
            "port": port,
            "weight": weight,
            "raw_json": raw_dict,
        }
        self.upsert(BackendServer, unique_keys, values)

        # 如果有 backend_ip，写入 ip_addresses 表
        if backend_ip:
            self.upsert_ip(
                resource_type="backend",
                resource_id=server_id,
                resource_name=f"ALB-{lb_id}-backend-{server_id}",
                ip=backend_ip,
                ip_type="backend",
                region_id=region_id,
            )
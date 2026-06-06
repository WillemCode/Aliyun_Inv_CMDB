"""CLB Collector — 收集传统型负载均衡 (SLB/CLB)"""

from typing import Any

from sqlalchemy import select
from alibabacloud_slb20140515 import models as slb_models
from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, paginate_next_token, model_to_dict
from ..config import AccountConfig
from ..models import LoadBalancer, BackendServer, LbListener, LbVServerGroup, LbForwardingRule

class ClbCollector(BaseCollector):
    """传统型负载均衡 (CLB/SLB) 收集器"""

    def collect(self) -> None:
        """探测有 CLB 的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("clb")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 CLB", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s CLB 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s CLB 同步完成: 共 %d 个", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 CLB 实例"""
        client = self.client_factory.create_client("slb", region_id)

        lbs = paginate_page_number(
            client=client,
            method_name="describe_load_balancers",
            request_class=slb_models.DescribeLoadBalancersRequest,
            extra_params={"region_id": region_id},
            list_extractor=lambda resp: resp.body.load_balancers.load_balancer if resp.body.load_balancers else [],
        )

        for lb in lbs:
            try:
                self._save_lb(lb, region_id, client)
            except Exception as e:
                self.logger.warning("保存 CLB %s 失败: %s", lb.load_balancer_id, e)
                continue

        self.session.commit()
        return len(lbs)

    def _save_lb(self, lb: Any, region_id: str, client: Any) -> None:
        """保存单个 CLB 实例"""
        lb_id = lb.load_balancer_id
        lb_name = lb.load_balancer_name or ""
        status = lb.load_balancer_status or ""
        address = lb.address or ""
        address_type = lb.address_type or ""
        dns_name = getattr(lb, "dns_name", "") or ""
        vpc_id = lb.vpc_id or ""

        raw_dict = model_to_dict(lb)

        # 写入 load_balancers 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "lb_type": "clb",
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
            resource_type="clb",
            region_id=region_id,
            resource_id=lb_id,
            resource_name=lb_name,
            raw_json=raw_dict,
            source_api="DescribeLoadBalancers",
        )

        # 写入 ip_addresses 表 — CLB 地址
        if address:
            self.upsert_ip(
                resource_type="clb",
                resource_id=lb_id,
                resource_name=lb_name,
                ip=address,
                ip_type="lb_address",
                region_id=region_id,
            )

        # 获取后端服务器信息（默认组 + vServerGroup）
        try:
            self._collect_backends(lb_id, region_id, client)
        except Exception as e:
            self.logger.warning("获取 CLB %s 后端服务器失败: %s", lb_id, e)

        # 获取监听器信息（前端协议/端口 → 后端端口/服务器组）
        try:
            self._collect_listeners(lb_id, region_id, client)
        except Exception as e:
            self.logger.warning("获取 CLB %s 监听器失败: %s", lb_id, e)

        # 获取 HTTP/HTTPS 监听器的转发规则（域名/路径 → vServerGroup）
        try:
            self._collect_forwarding_rules_for_lb(lb_id, region_id, client)
        except Exception as e:
            self.logger.warning("获取 CLB %s 转发规则失败: %s", lb_id, e)

    def _collect_backends(self, lb_id: str, region_id: str, client: Any) -> None:
        """获取 CLB 的后端服务器

        两个来源：
        1. DescribeLoadBalancerAttribute — 默认后端组（很多 CLB 此组为空）
        2. DescribeVServerGroups + DescribeVServerGroupAttribute — vServerGroup 后端（通常在这里）
        """
        # 1. 默认后端组
        try:
            request = slb_models.DescribeLoadBalancerAttributeRequest(
                load_balancer_id=lb_id,
            )
            response = client.describe_load_balancer_attribute(request)
            backend_servers = response.body.backend_servers.backend_server if response.body.backend_servers else []
            for server in backend_servers:
                try:
                    self._save_backend(lb_id, server, region_id, server_group_id=None)
                except Exception as e:
                    self.logger.warning("保存 CLB 后端服务器 %s 失败: %s", server.server_id, e)
                    continue
        except Exception as e:
            self.logger.warning("DescribeLoadBalancerAttribute %s 失败: %s", lb_id, e)

        # 2. vServerGroup 后端（这才是主要的后端数据来源）
        try:
            vsg_request = slb_models.DescribeVServerGroupsRequest(
                region_id=region_id,
                load_balancer_id=lb_id,
            )
            vsg_response = client.describe_vserver_groups(vsg_request)
            vserver_groups = vsg_response.body.vserver_groups.vserver_group if vsg_response.body.vserver_groups else []
        except Exception as e:
            self.logger.warning("DescribeVServerGroups %s 失败: %s", lb_id, e)
            vserver_groups = []

        for vsg in vserver_groups:
            vsg_id = vsg.vserver_group_id
            vsg_name = vsg.vserver_group_name or ""
            # 保存 vServerGroup 元数据到 LbVServerGroup 表
            try:
                vsg_raw_dict = model_to_dict(vsg)
                vsg_unique_keys = {
                    "account_name": self.account.name,
                    "lb_type": "clb",
                    "region_id": region_id,
                    "lb_id": lb_id,
                    "vserver_group_id": vsg_id,
                }
                self.upsert(LbVServerGroup, vsg_unique_keys, {
                    **vsg_unique_keys,
                    "account_display_name": self.account.display_name,
                    "vserver_group_name": vsg_name,
                    "server_count": vsg.server_count,
                    "raw_json": vsg_raw_dict,
                })
            except Exception as e:
                self.logger.warning("保存 vServerGroup %s 失败: %s", vsg_id, e)
            try:
                self._collect_vserver_group_backends(lb_id, vsg_id, vsg_name, region_id, client)
            except Exception as e:
                self.logger.warning("获取 vServerGroup %s 后端失败: %s", vsg_id, e)
                continue

    def _collect_vserver_group_backends(
        self, lb_id: str, vsg_id: str, vsg_name: str, region_id: str, client: Any
    ) -> None:
        """获取 vServerGroup 的后端服务器"""
        request = slb_models.DescribeVServerGroupAttributeRequest(
            region_id=region_id,
            vserver_group_id=vsg_id,
        )

        try:
            response = client.describe_vserver_group_attribute(request)
            backend_servers = response.body.backend_servers.backend_server if response.body.backend_servers else []
        except Exception as e:
            self.logger.warning("DescribeVServerGroupAttribute %s 失败: %s", vsg_id, e)
            return

        for server in backend_servers:
            try:
                self._save_backend(lb_id, server, region_id, server_group_id=vsg_id)
            except Exception as e:
                self.logger.warning("保存 vServerGroup 后端 %s 失败: %s", server.server_id, e)
                continue

    def _save_backend(self, lb_id: str, server: Any, region_id: str, server_group_id: str | None = None) -> None:
        """保存单个后端服务器

        Args:
            lb_id: 负载均衡 ID
            server: 后端服务器对象
            region_id: 地域
            server_group_id: vServerGroup ID（默认后端组为 None）
        """
        server_id = getattr(server, "server_id", "") or server.server_id or ""
        weight = server.weight  # 保留原始值（weight=0 表示已停用但仍挂载）
        port = getattr(server, "port", None)
        backend_ip = getattr(server, "server_ip", "") or ""

        raw_dict = model_to_dict(server)

        # 写入 backend_servers 表
        # 对于同一个 server_id 在同一个 lb 下可能在多个 vServerGroup 中出现
        # 唯一键用 (account_name, lb_type, region_id, lb_id, backend_resource_id) 会冲突
        # 需要把 server_group_id 也纳入唯一键来区分
        # 但原表结构唯一键不含 server_group_id，需要调整
        # 用复合键确保同一 server 在不同 vsg 中能分别保存
        unique_keys = {
            "account_name": self.account.name,
            "lb_type": "clb",
            "region_id": region_id,
            "lb_id": lb_id,
            "server_group_id": server_group_id or "",
            "backend_resource_id": server_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
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
                resource_name=f"CLB-{lb_id}-backend-{server_id}",
                ip=backend_ip,
                ip_type="backend",
                region_id=region_id,
            )

    def _collect_listeners(self, lb_id: str, region_id: str, client: Any) -> None:
        """获取 CLB 的监听器信息（前端协议/端口 → 后端端口/服务器组）"""
        listeners = paginate_next_token(
            client=client,
            method_name="describe_load_balancer_listeners",
            request_class=slb_models.DescribeLoadBalancerListenersRequest,
            extra_params={"region_id": region_id, "load_balancer_id": [lb_id]},
            list_extractor=lambda resp: resp.body.listeners if resp.body.listeners else [],
        )

        for listener in listeners:
            try:
                self._save_listener(lb_id, listener, region_id)
            except Exception as e:
                self.logger.warning("保存 CLB 监听器 %s/%s 失败: %s", listener.listener_port, listener.listener_protocol, e)
                continue

    def _save_listener(self, lb_id: str, listener: Any, region_id: str) -> None:
        """保存单个监听器"""
        listener_port = listener.listener_port
        listener_protocol = listener.listener_protocol or ""
        backend_server_port = listener.backend_server_port
        vserver_group_id = listener.vserver_group_id or None
        status = listener.status or ""
        description = listener.description or ""

        # 提取 HTTP→HTTPS 重定向信息
        # SDK 属性名是 httplistener_config（无下划线），包含 ListenerForward 和 ForwardPort
        forward_port = None
        listener_forward = None
        http_config = getattr(listener, "httplistener_config", None)
        if http_config:
            http_config_dict = model_to_dict(http_config)
            listener_forward = http_config_dict.get("ListenerForward")
            forward_port = http_config_dict.get("ForwardPort")
            # forward_port 可能是字符串，转为整数
            if forward_port is not None:
                try:
                    forward_port = int(forward_port)
                except (ValueError, TypeError):
                    forward_port = None

        raw_dict = model_to_dict(listener)

        unique_keys = {
            "account_name": self.account.name,
            "lb_type": "clb",
            "region_id": region_id,
            "lb_id": lb_id,
            "listener_port": listener_port,
            "listener_protocol": listener_protocol,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "backend_server_port": backend_server_port,
            "vserver_group_id": vserver_group_id,
            "forward_port": forward_port,
            "listener_forward": listener_forward,
            "status": status,
            "description": description,
            "raw_json": raw_dict,
        }
        self.upsert(LbListener, unique_keys, values)

    def _collect_forwarding_rules_for_lb(self, lb_id: str, region_id: str, client: Any) -> None:
        """获取 CLB 的 HTTP/HTTPS 监听器转发规则

        只对 HTTP/HTTPS 监听器调用 DescribeRules（TCP/UDP 无转发规则）
        """
        # 先查询已保存的监听器，只对 HTTP/HTTPS 调用 DescribeRules
        listener_stmt = select(LbListener).where(
            LbListener.lb_id == lb_id,
            LbListener.lb_type == "clb",
            LbListener.listener_protocol.in_(["http", "https"]),
        )
        listeners = self.session.execute(listener_stmt).scalars().all()

        for ln in listeners:
            try:
                self._collect_forwarding_rules(
                    lb_id, region_id, ln.listener_port, ln.listener_protocol, client
                )
            except Exception as e:
                self.logger.warning("获取 CLB %s 转发规则 %s:%s 失败: %s", lb_id, ln.listener_protocol, ln.listener_port, e)
                continue

    def _collect_forwarding_rules(
        self, lb_id: str, region_id: str, listener_port: int, listener_protocol: str, client: Any
    ) -> None:
        """获取单个 HTTP/HTTPS 监听器的转发规则"""
        req = slb_models.DescribeRulesRequest(
            region_id=region_id,
            load_balancer_id=lb_id,
            listener_port=listener_port,
        )
        try:
            resp = client.describe_rules(req)
        except Exception as e:
            self.logger.warning("DescribeRules %s %s:%s 失败: %s", lb_id, listener_protocol, listener_port, e)
            return

        rules = resp.body.rules.rule if resp.body and resp.body.rules else []
        for rule in rules:
            try:
                self._save_forwarding_rule(lb_id, rule, region_id, listener_port, listener_protocol)
            except Exception as e:
                self.logger.warning("保存转发规则 %s 失败: %s", rule.rule_id, e)
                continue

    def _save_forwarding_rule(
        self, lb_id: str, rule: Any, region_id: str, listener_port: int, listener_protocol: str
    ) -> None:
        """保存单个转发规则"""
        rule_id = rule.rule_id or ""
        rule_name = rule.rule_name or ""
        domain = rule.domain or ""
        url = rule.url or ""
        vserver_group_id = rule.vserver_group_id or None

        raw_dict = model_to_dict(rule)

        unique_keys = {
            "account_name": self.account.name,
            "lb_type": "clb",
            "region_id": region_id,
            "lb_id": lb_id,
            "listener_port": listener_port,
            "listener_protocol": listener_protocol,
            "rule_id": rule_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "rule_name": rule_name,
            "domain": domain,
            "url": url,
            "vserver_group_id": vserver_group_id,
            "raw_json": raw_dict,
        }
        self.upsert(LbForwardingRule, unique_keys, values)
"""Tair Collector — 收集 Tair/Redis 实例信息"""

from typing import Any

from alibabacloud_r_kvstore20150101 import models as kv_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import TairInstance

class TairCollector(BaseCollector):
    """Tair/Redis 实例收集器"""

    def collect(self) -> None:
        """探测有 Tair/Redis 实例的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("tair")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 Tair/Redis 实例", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s Tair 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s Tair 同步完成: 共 %d 个实例", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 Tair/Redis 实例"""
        client = self.client_factory.create_client("kvstore", region_id)

        instances = paginate_page_number(
            client=client,
            method_name="describe_instances",
            request_class=kv_models.DescribeInstancesRequest,
            extra_params={"region_id": region_id},
            page_size=100,
            list_extractor=lambda resp: (
                resp.body.instances.kvstore_instance if resp.body.instances else []
            ),
        )

        for instance in instances:
            try:
                self._save_instance(instance, region_id)
            except Exception as e:
                self.logger.warning("保存 Tair 实例 %s 失败: %s", instance.instance_id, e)
                continue

        self.session.commit()
        return len(instances)

    def _save_instance(self, instance: Any, region_id: str) -> None:
        """保存单个 Tair/Redis 实例"""
        instance_id = instance.instance_id or ""
        instance_name = instance.instance_name or ""
        instance_type = instance.instance_type or ""
        instance_class = instance.instance_class or ""
        instance_status = instance.instance_status or ""
        engine_version = instance.engine_version or ""
        connection_domain = instance.connection_domain or ""
        port = instance.port if instance.port else None
        bandwidth = instance.bandwidth or ""
        capacity = instance.capacity or ""
        zone_id = instance.zone_id or ""
        vpc_id = instance.vpc_id or ""
        vswitch_id = instance.v_switch_id or ""
        charge_type = instance.charge_type or ""

        raw_dict = model_to_dict(instance)

        # 获取外网连接地址
        # 1. 先从列表接口尝试提取 public_domain
        public_domain = getattr(instance, "public_domain", "") or ""
        public_port = None
        # 2. 如果列表接口没有，尝试调用 DescribeDBInstanceNetInfo
        if not public_domain:
            try:
                client = self.client_factory.create_client("kvstore", region_id)
                net_info_req = kv_models.DescribeDBInstanceNetInfoRequest(
                    instance_id=instance_id,
                )
                net_info_resp = client.describe_dbinstance_net_info(net_info_req)
                if net_info_resp.body and net_info_resp.body.net_info_items:
                    net_infos = net_info_resp.body.net_info_items.instance_net_info or []
                    for net_info in net_infos or []:
                        ip_type = net_info.iptype or ""  # SDK字段名是 iptype，值 "Private"/"Public"
                        if ip_type == "Public":
                            public_domain = net_info.connection_string or ""
                            public_port = net_info.port if net_info.port else None
                            break
                    # 合并网络信息到 raw_dict
                    net_raw_list = []
                    for net_info in net_infos or []:
                        net_raw_list.append(model_to_dict(net_info))
                    if isinstance(raw_dict, dict) and net_raw_list:
                        raw_dict["InstanceNetInfo"] = net_raw_list
            except Exception:
                self.logger.debug("获取 Tair 外网连接地址失败", exc_info=True)

        # 写入 tair_instances 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "instance_id": instance_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "zone_id": zone_id,
            "instance_name": instance_name,
            "instance_type": instance_type,
            "instance_class": instance_class,
            "instance_status": instance_status,
            "engine_version": engine_version,
            "connection_domain": connection_domain,
            "port": port,
            "public_domain": public_domain,
            "public_port": public_port,
            "bandwidth": bandwidth,
            "capacity": capacity,
            "vpc_id": vpc_id,
            "vswitch_id": vswitch_id,
            "charge_type": charge_type,
            "raw_json": raw_dict,
        }
        self.upsert(TairInstance, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="tair",
            region_id=region_id,
            resource_id=instance_id,
            resource_name=instance_name,
            raw_json=raw_dict,
            source_api="DescribeInstances",
        )
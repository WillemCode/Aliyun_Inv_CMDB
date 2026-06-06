"""RDS Collector — 收集 RDS 数据库实例信息"""

from typing import Any

from alibabacloud_rds20140815 import models as rds_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import RdsInstance

class RdsCollector(BaseCollector):
    """RDS 数据库实例收集器"""

    def collect(self) -> None:
        """探测有 RDS 实例的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("rds")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 RDS 实例", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s RDS 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s RDS 同步完成: 共 %d 个实例", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 RDS 实例"""
        client = self.client_factory.create_client("rds", region_id)

        instances = paginate_page_number(
            client=client,
            method_name="describe_dbinstances",
            request_class=rds_models.DescribeDBInstancesRequest,
            extra_params={"region_id": region_id},
            page_size=100,
            list_extractor=lambda resp: (
                resp.body.items.dbinstance if resp.body.items else []
            ),
        )

        for instance in instances:
            try:
                self._save_instance(instance, region_id)
            except Exception as e:
                self.logger.warning("保存 RDS 实例 %s 失败: %s", instance.dbinstance_id, e)
                continue

        self.session.commit()
        return len(instances)

    def _save_instance(self, instance: Any, region_id: str) -> None:
        """保存单个 RDS 实例"""
        instance_id = instance.dbinstance_id or ""
        instance_name = instance.dbinstance_description or ""
        engine = instance.engine or ""
        engine_version = instance.engine_version or ""
        instance_type = instance.dbinstance_type or ""
        instance_class = instance.dbinstance_class or ""
        status = instance.dbinstance_status or ""
        zone_id = instance.zone_id or ""
        vpc_id = instance.vpc_id or ""
        vswitch_id = instance.v_switch_id or ""
        category = instance.category or ""

        # 连接地址
        connection_string = ""
        port = ""
        try:
            connection_string = instance.connection_string or ""
            # RDS 的 port 可能不在列表接口返回中，在详情接口里
        except Exception:
            pass

        raw_dict = model_to_dict(instance)

        # 如果 connection_string 为空，尝试获取详情
        if not connection_string:
            try:
                client = self.client_factory.create_client("rds", region_id)
                detail_req = rds_models.DescribeDBInstanceDetailRequest(
                    dbinstance_id=instance_id,
                    region_id=region_id,
                )
                detail_resp = client.describe_dbinstance_detail(detail_req)
                if detail_resp.body and detail_resp.body.dbinstance_attribute:
                    attr = detail_resp.body.dbinstance_attribute
                    # 合并详情信息
                    if not connection_string:
                        try:
                            connection_string = attr.connection_string or ""
                        except Exception:
                            pass
                    if not port:
                        try:
                            port = str(attr.port) if attr.port else ""
                        except Exception:
                            pass
                    # 合并 raw_dict
                    detail_raw = model_to_dict(attr)
                    if isinstance(raw_dict, dict) and isinstance(detail_raw, dict):
                        raw_dict = {**raw_dict, **detail_raw}
            except Exception:
                self.logger.debug("获取 RDS 连接地址失败", exc_info=True)

        # 获取内外网连接地址（DescribeDBInstanceNetInfo 返回 Private + Public 两类）
        public_connection_string = ""
        public_port = ""
        try:
            client = self.client_factory.create_client("rds", region_id)
            net_info_req = rds_models.DescribeDBInstanceNetInfoRequest(
                dbinstance_id=instance_id,
            )
            net_info_resp = client.describe_dbinstance_net_info(net_info_req)
            if net_info_resp.body and net_info_resp.body.dbinstance_net_infos:
                net_infos = net_info_resp.body.dbinstance_net_infos.dbinstance_net_info
                for net_info in net_infos or []:
                    ip_type = net_info.iptype or ""  # SDK字段名是 iptype，值 "Private"/"Public"
                    if ip_type == "Private":
                        # 内网连接地址：NetInfo 返回的更完整（有 port）
                        if not connection_string:
                            connection_string = net_info.connection_string or ""
                        if not port:
                            port = str(net_info.port) if net_info.port else ""
                    elif ip_type == "Public":
                        public_connection_string = net_info.connection_string or ""
                        public_port = str(net_info.port) if net_info.port else ""
                # 合并网络信息到 raw_dict
                net_raw_list = [model_to_dict(ni) for ni in net_infos or []]
                if isinstance(raw_dict, dict) and net_raw_list:
                    raw_dict["DBInstanceNetInfo"] = net_raw_list
        except Exception:
            self.logger.debug("获取 RDS 连接地址失败", exc_info=True)

        # 写入 rds_instances 表
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
            "engine": engine,
            "engine_version": engine_version,
            "instance_type": instance_type,
            "instance_class": instance_class,
            "status": status,
            "connection_string": connection_string,
            "port": port,
            "public_connection_string": public_connection_string,
            "public_port": public_port,
            "vpc_id": vpc_id,
            "vswitch_id": vswitch_id,
            "category": category,
            "raw_json": raw_dict,
        }
        self.upsert(RdsInstance, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="rds",
            region_id=region_id,
            resource_id=instance_id,
            resource_name=instance_name,
            raw_json=raw_dict,
            source_api="DescribeDBInstances",
        )
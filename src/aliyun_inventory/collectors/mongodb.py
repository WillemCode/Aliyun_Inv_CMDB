"""MongoDB Collector — 收集 MongoDB(DDS) 实例信息"""

from typing import Any

from alibabacloud_dds20151201 import models as dds_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import MongoDBInstance

class MongoDBCollector(BaseCollector):
    """MongoDB 实例收集器"""

    def collect(self) -> None:
        """探测有 MongoDB 实例的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("mongodb")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 MongoDB 实例", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s MongoDB 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s MongoDB 同步完成: 共 %d 个实例", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 MongoDB 实例"""
        client = self.client_factory.create_client("dds", region_id)

        instances = paginate_page_number(
            client=client,
            method_name="describe_dbinstances",
            request_class=dds_models.DescribeDBInstancesRequest,
            extra_params={"region_id": region_id},
            page_size=0,  # DDS 不支持 page_size 参数，不传即可
            list_extractor=lambda resp: (
                resp.body.dbinstances.dbinstance if resp.body.dbinstances else []
            ),
        )

        for instance in instances:
            try:
                self._save_instance(instance, region_id)
            except Exception as e:
                self.logger.warning("保存 MongoDB 实例 %s 失败: %s", instance.dbinstance_id, e)
                continue

        self.session.commit()
        return len(instances)

    def _save_instance(self, instance: Any, region_id: str) -> None:
        """保存单个 MongoDB 实例"""
        instance_id = instance.dbinstance_id or ""
        instance_description = instance.dbinstance_description or ""
        dbinstance_type = instance.dbinstance_type or ""
        dbinstance_class = instance.dbinstance_class or ""
        dbinstance_status = instance.dbinstance_status or ""
        engine = instance.engine or ""
        engine_version = instance.engine_version or ""
        zone_id = instance.zone_id or ""
        network_type = instance.network_type or ""
        vpc_id = getattr(instance, "vpc_id", "") or ""
        charge_type = instance.charge_type or ""
        storage_type = instance.storage_type or ""

        raw_dict = model_to_dict(instance)

        # 获取连接地址（内网 + 外网）
        private_connection = ""
        public_connection = ""
        connection_port = ""
        try:
            client = self.client_factory.create_client("dds", region_id)
            if dbinstance_type == "sharding":
                # 分片集群：用 DescribeShardingNetworkAddress
                net_req = dds_models.DescribeShardingNetworkAddressRequest(
                    dbinstance_id=instance_id,
                )
                net_resp = client.describe_sharding_network_address(net_req)
                if net_resp.body and net_resp.body.network_addresses:
                    addresses = net_resp.body.network_addresses.network_address or []
                    for addr in addresses or []:
                        network_type_val = addr.network_type or ""
                        net_addr = addr.network_address or ""
                        port_val = str(addr.port) if addr.port else ""
                        if network_type_val == "VPC" and not private_connection:
                            private_connection = net_addr
                            if not connection_port and port_val:
                                connection_port = port_val
                        elif network_type_val == "Public" and not public_connection:
                            public_connection = net_addr
                            if not connection_port and port_val:
                                connection_port = port_val
                    # 合入 raw_dict
                    addr_raw_list = [model_to_dict(a) for a in addresses or []]
                    if isinstance(raw_dict, dict) and addr_raw_list:
                        raw_dict["NetworkAddresses"] = addr_raw_list
            else:
                # 副本集/单节点：用 DescribeReplicaSetRole
                role_req = dds_models.DescribeReplicaSetRoleRequest(
                    dbinstance_id=instance_id,
                )
                role_resp = client.describe_replica_set_role(role_req)
                if role_resp.body and role_resp.body.replica_sets:
                    replica_sets = role_resp.body.replica_sets.replica_set or []
                    for rs in replica_sets or []:
                        conn_domain = rs.connection_domain or ""
                        conn_port = str(rs.connection_port) if rs.connection_port else ""
                        net_type = rs.network_type or ""  # SDK字段名是 network_type，值 "VPC"/"Public"
                        role = rs.replica_set_role or ""   # Primary/Secondary
                        # 取 Primary 角色的 VPC 连接作为内网地址，Public 连接作为外网地址
                        if net_type == "VPC" and role == "Primary" and not private_connection:
                            private_connection = conn_domain
                            if not connection_port and conn_port:
                                connection_port = conn_port
                        elif net_type == "Public" and not public_connection:
                            public_connection = conn_domain
                            if not connection_port and conn_port:
                                connection_port = conn_port
                    # 合入 raw_dict
                    rs_raw_list = [model_to_dict(r) for r in replica_sets or []]
                    if isinstance(raw_dict, dict) and rs_raw_list:
                        raw_dict["ReplicaSets"] = rs_raw_list
        except Exception:
            self.logger.debug("获取 MongoDB 连接地址失败", exc_info=True)

        # 写入 mongodb_instances 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "instance_id": instance_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "zone_id": zone_id,
            "instance_description": instance_description,
            "dbinstance_type": dbinstance_type,
            "dbinstance_class": dbinstance_class,
            "dbinstance_status": dbinstance_status,
            "engine": engine,
            "engine_version": engine_version,
            "network_type": network_type,
            "vpc_id": vpc_id,
            "charge_type": charge_type,
            "storage_type": storage_type,
            "private_connection": private_connection,
            "public_connection": public_connection,
            "connection_port": connection_port,
            "raw_json": raw_dict,
        }
        self.upsert(MongoDBInstance, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="mongodb",
            region_id=region_id,
            resource_id=instance_id,
            resource_name=instance_description,
            raw_json=raw_dict,
            source_api="DescribeDBInstances",
        )
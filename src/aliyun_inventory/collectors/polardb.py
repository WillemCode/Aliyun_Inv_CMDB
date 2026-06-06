"""PolarDB Collector — 收集 PolarDB 集群信息"""

from typing import Any

from alibabacloud_polardb20170801 import models as polar_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import PolarDBCluster

class PolarDBCollector(BaseCollector):
    """PolarDB 集群收集器"""

    def collect(self) -> None:
        """探测有 PolarDB 集群的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("polardb")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 PolarDB 集群", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s PolarDB 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s PolarDB 同步完成: 共 %d 个集群", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 PolarDB 集群"""
        client = self.client_factory.create_client("polardb", region_id)

        clusters = paginate_page_number(
            client=client,
            method_name="describe_dbclusters",
            request_class=polar_models.DescribeDBClustersRequest,
            extra_params={"region_id": region_id},
            page_size=0,  # PolarDB 不支持 page_size 参数，不传即可
            list_extractor=lambda resp: (
                resp.body.items.dbcluster if resp.body.items else []
            ),
        )

        for cluster in clusters:
            try:
                self._save_cluster(cluster, region_id)
            except Exception as e:
                self.logger.warning("保存 PolarDB 集群 %s 失败: %s", cluster.dbcluster_id, e)
                continue

        self.session.commit()
        return len(clusters)

    def _save_cluster(self, cluster: Any, region_id: str) -> None:
        """保存单个 PolarDB 集群"""
        cluster_id = cluster.dbcluster_id or ""
        cluster_description = cluster.dbcluster_description or ""
        dbtype = cluster.dbtype or ""
        dbversion = cluster.dbversion or ""
        engine = cluster.engine or ""
        category = cluster.category or ""
        cluster_status = cluster.dbcluster_status or ""
        vpc_id = cluster.vpc_id or ""
        vswitch_id = cluster.vswitch_id or ""
        pay_type = cluster.pay_type or ""
        cpu_cores = cluster.cpu_cores if cluster.cpu_cores else None
        memory_size = cluster.memory_size if cluster.memory_size else None

        raw_dict = model_to_dict(cluster)

        # 获取连接地址（内网 + 外网）
        private_connection_string = ""
        public_connection_string = ""
        connection_port = ""
        try:
            client = self.client_factory.create_client("polardb", region_id)
            endpoint_req = polar_models.DescribeDBClusterEndpointsRequest(
                dbcluster_id=cluster_id,
            )
            endpoint_resp = client.describe_dbcluster_endpoints(endpoint_req)
            if endpoint_resp.body and endpoint_resp.body.items:
                for endpoint_item in endpoint_resp.body.items or []:
                    address_items = endpoint_item.address_items or []
                    for addr in address_items:
                        net_type = addr.net_type or ""
                        conn_str = addr.connection_string or ""
                        port = str(addr.port) if addr.port else ""
                        if net_type == "Private" and not private_connection_string:
                            private_connection_string = conn_str
                            if not connection_port and port:
                                connection_port = port
                        elif net_type == "Public" and not public_connection_string:
                            public_connection_string = conn_str
                            if not connection_port and port:
                                connection_port = port
                # 合并 endpoint 信息到 raw_dict
                endpoint_raw_list = []
                for endpoint_item in endpoint_resp.body.items or []:
                    endpoint_raw_list.append(model_to_dict(endpoint_item))
                if isinstance(raw_dict, dict) and endpoint_raw_list:
                    raw_dict["DBClusterEndpoints"] = endpoint_raw_list
        except Exception:
            self.logger.debug("获取 PolarDB 连接地址失败", exc_info=True)

        # 写入 polardb_clusters 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "cluster_id": cluster_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "cluster_description": cluster_description,
            "dbtype": dbtype,
            "dbversion": dbversion,
            "engine": engine,
            "category": category,
            "cluster_status": cluster_status,
            "vpc_id": vpc_id,
            "vswitch_id": vswitch_id,
            "pay_type": pay_type,
            "private_connection_string": private_connection_string,
            "public_connection_string": public_connection_string,
            "connection_port": connection_port,
            "cpu_cores": cpu_cores,
            "memory_size": memory_size,
            "raw_json": raw_dict,
        }
        self.upsert(PolarDBCluster, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="polardb",
            region_id=region_id,
            resource_id=cluster_id,
            resource_name=cluster_description,
            raw_json=raw_dict,
            source_api="DescribeDBClusters",
        )
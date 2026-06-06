"""SAE Collector — 收集 Serverless 应用引擎的命名空间和应用"""

from typing import Any

from alibabacloud_sae20190506 import models as sae_models
from .base import BaseCollector
from ..aliyun_client import model_to_dict
from ..config import AccountConfig
from ..models import SaeNamespace, SaeApp

class SaeCollector(BaseCollector):
    """SAE (Serverless 应用引擎) 收集器

    收集：
    1. 命名空间 (DescribeNamespaces)
    2. 应用 (ListApplications)

    SAE SDK 的分页参数名是 current_page/page_size（不是 page_number/page_size），
    所以 paginate_page_number 不兼容，需要手动分页。
    """

    def collect(self) -> None:
        """收集 SAE 资源"""
        total_ns = 0
        total_apps = 0

        # SAE 资源集中在少数地域，优先探测有 ECS 的地域
        sae_regions = [
            "cn-hangzhou", "cn-beijing", "cn-shanghai", "cn-shenzhen",
            "cn-chengdu", "cn-hongkong", "ap-southeast-1",
        ]
        ecs_regions = self.client_factory.discover_active_regions("ecs")
        all_regions = set(sae_regions + ecs_regions)

        # 先收集所有命名空间（用于生成 service_url 时查 namespace_short_id）
        namespace_map: dict[str, str] = {}  # namespace_id -> namespace_short_id

        for region_id in all_regions:
            try:
                client = self.client_factory.create_client("sae", region_id)
            except Exception:
                self.logger.debug("SAE 地域 %s 创建客户端失败", region_id, exc_info=True)
                continue

            try:
                ns_count = self._collect_namespaces(region_id, client, namespace_map)
                if ns_count > 0:
                    self.logger.info("地域 %s: %d 个 SAE 命名空间", region_id, ns_count)
                total_ns += ns_count
            except Exception as e:
                self.logger.warning("SAE 命名空间 %s 收集失败", region_id, exc_info=True)
                self.session.rollback()
                continue

            try:
                app_count = self._collect_apps(region_id, client, namespace_map)
                if app_count > 0:
                    self.logger.info("地域 %s: %d 个 SAE 应用", region_id, app_count)
                total_apps += app_count
            except Exception as e:
                self.logger.warning("SAE 应用 %s 收集失败", region_id, exc_info=True)
                self.session.rollback()
                continue

        self.session.commit()
        self.logger.info(
                "账号 %s SAE 同步完成: %d 个命名空间, %d 个应用",
                self.account.display_name, total_ns, total_apps,
        )

    # ──────────────────────────────────────────────
    # 命名空间收集
    # ──────────────────────────────────────────────

    def _collect_namespaces(
        self, region_id: str, client: Any, namespace_map: dict[str, str],
    ) -> int:
        """收集 SAE 命名空间（手动分页，SAE 使用 current_page/page_size）"""
        all_namespaces = []
        current_page = 1
        page_size = 50

        while True:
            try:
                req = sae_models.DescribeNamespacesRequest(
                    current_page=current_page,
                    page_size=page_size,
                )
                resp = client.describe_namespaces(req)
                data = resp.body.data
                if not data or not data.namespaces:
                    break

                ns_items = data.namespaces
                # namespces 是一个 DescribeNamespacesResponseBodyDataNamespaces 对象
                # 它包含多个 Namespace 属性，需要遍历
                # 实际返回: data.namespaces 是列表式对象，直接遍历即可
                if hasattr(ns_items, 'namespace') and ns_items.namespace:
                    items = ns_items.namespace
                elif isinstance(ns_items, list):
                    items = ns_items
                else:
                    items = []

                all_namespaces.extend(items)

                total_size = data.total_size or 0
                if len(all_namespaces) >= total_size or not items:
                    break
                current_page += 1
            except Exception as e:
                self.logger.warning("SAE DescribeNamespaces 分页 %d 失败", current_page, exc_info=True)
                break

        for ns in all_namespaces:
            try:
                self._save_namespace(ns, region_id, namespace_map)
            except Exception as e:
                self.logger.warning("保存 SAE 命名空间失败: %s", e)
                continue

        return len(all_namespaces)

    def _save_namespace(
        self, ns: Any, region_id: str, namespace_map: dict[str, str],
    ) -> None:
        """保存单个 SAE 命名空间"""
        raw_dict = model_to_dict(ns)

        ns_id = getattr(ns, "namespace_id", "") or ""
        ns_short_id = getattr(ns, "name_space_short_id", "") or ""
        ns_name = getattr(ns, "namespace_name", "") or ""
        ns_description = getattr(ns, "namespace_description", "") or ""
        ns_region = getattr(ns, "region_id", "") or region_id
        ns_tenant_id = getattr(ns, "tenant_id", "") or ""

        # SAE DescribeNamespaces 不返回 VPC 信息，vpc_id 从应用级别获取
        # 尝试从 namespace raw 数据中查找 vpc_id（有些格式可能包含）
        vpc_id = ""
        if isinstance(raw_dict, dict):
            # 搜索可能的 vpc_id 字段
            vpc_id = raw_dict.get("VpcId", raw_dict.get("vpc_id", ""))

        if not ns_id:
            return

        # 填充 namespace_map 用于应用 service_url 生成
        namespace_map[ns_id] = ns_short_id

        unique_keys = {
            "account_name": self.account.name,
            "region_id": ns_region or region_id,
            "namespace_id": ns_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "namespace_short_id": ns_short_id,
            "namespace_name": ns_name,
            "namespace_description": ns_description,
            "vpc_id": vpc_id,
            "tenant_id": ns_tenant_id,
            "raw_json": raw_dict,
        }
        self.upsert(SaeNamespace, unique_keys, values)

        self.save_raw(
            resource_type="sae_namespace",
            region_id=ns_region or region_id,
            resource_id=ns_id,
            resource_name=ns_name,
            raw_json=raw_dict,
            source_api="DescribeNamespaces",
        )

    # ──────────────────────────────────────────────
    # 应用收集
    # ──────────────────────────────────────────────

    def _collect_apps(
        self, region_id: str, client: Any, namespace_map: dict[str, str],
    ) -> int:
        """收集 SAE 应用（手动分页）"""
        all_apps = []
        current_page = 1
        page_size = 50

        while True:
            try:
                req = sae_models.ListApplicationsRequest(
                    current_page=current_page,
                    page_size=page_size,
                )
                resp = client.list_applications(req)
                data = resp.body.data
                if not data or not data.applications:
                    break

                app_items = data.applications
                # applications 是 ListApplicationsResponseBodyDataApplications 对象
                # 它可能是一个嵌套结构或列表
                if hasattr(app_items, 'application') and app_items.application:
                    # 实际返回是 ApplicationWithStatus 列表
                    items = app_items.application
                elif isinstance(app_items, list):
                    items = app_items
                else:
                    items = []

                all_apps.extend(items)

                total_size = data.total_size or 0
                if len(all_apps) >= total_size or not items:
                    break
                current_page += 1
            except Exception as e:
                self.logger.warning("SAE ListApplications 分页 %d 失败", current_page, exc_info=True)
                break

        for app_ws in all_apps:
            try:
                # ListApplications 返回 ApplicationWithStatus，包含 application + status
                app = getattr(app_ws, "application", app_ws)
                app_status = getattr(app_ws, "status", None)
                # app_status 是 ApplicationStatus 对象，包含 status 和 running_instances
                # 保存完整的 ApplicationWithStatus 结构作为 raw_json
                raw_dict = model_to_dict(app)
                # 把 status 信息也注入 raw_dict（来自外层 ApplicationWithStatus）
                if app_status:
                    status_info = model_to_dict(app_status) if hasattr(app_status, "to_map") else {}
                    status_str = getattr(app_status, "status", "") or ""
                    if isinstance(status_info, dict):
                        status_str = status_info.get("Status", status_info.get("status", status_str))
                    raw_dict["Status"] = status_str
                    raw_dict["ApplicationStatus"] = status_info
                self._save_app(app, raw_dict, region_id, namespace_map)
            except Exception as e:
                app_name = getattr(app_ws, "app_name", "") or getattr(getattr(app_ws, "application", None), "app_name", "") or ""
                self.logger.warning("保存 SAE 应用 %s 失败: %s", app_name, e)
                continue

        return len(all_apps)

    def _save_app(
        self, app: Any, raw_dict: dict, region_id: str, namespace_map: dict[str, str],
    ) -> None:
        """保存单个 SAE 应用"""
        app_id = raw_dict.get("AppId", "") or raw_dict.get("app_id", "") or getattr(app, "app_id", "") or getattr(app, "application_id", "") or ""
        app_name = raw_dict.get("AppName", "") or raw_dict.get("app_name", "") or getattr(app, "app_name", "") or getattr(app, "application_name", "") or ""
        ns_id = raw_dict.get("NamespaceId", "") or raw_dict.get("namespace_id", "") or getattr(app, "namespace_id", "") or ""
        ns_name = raw_dict.get("NamespaceName", "") or raw_dict.get("namespace_name", "") or getattr(app, "namespace_name", "") or ""
        app_type = raw_dict.get("AppType", "") or raw_dict.get("app_type", "") or getattr(app, "app_type", "") or ""
        programming_language = raw_dict.get("ProgrammingLanguage", "") or raw_dict.get("programming_language", "") or getattr(app, "programming_language", "") or ""
        running_instances = raw_dict.get("RunningInstances", None) or getattr(app, "running_instances", None)
        instance_count = raw_dict.get("Instances", None) or raw_dict.get("instances", None) or getattr(app, "instances", None)
        cpu = raw_dict.get("Cpu", None) or getattr(app, "cpu", None)
        mem = raw_dict.get("Mem", None) or raw_dict.get("mem", None) or getattr(app, "mem", None)
        image_url = raw_dict.get("ImageUrl", "") or raw_dict.get("image_url", "") or getattr(app, "image_url", "") or ""
        app_description = raw_dict.get("AppDescription", "") or raw_dict.get("app_description", "") or raw_dict.get("Description", "") or raw_dict.get("description", "") or getattr(app, "app_description", "") or getattr(app, "description", "") or ""
        app_vpc_id = raw_dict.get("VpcId", "") or raw_dict.get("vpc_id", "")
        # 尝试从 vpc_config 提取 vpc_id（如果直接字段为空）
        if not app_vpc_id:
            vpc_config = raw_dict.get("VpcConfig", raw_dict.get("vpc_config", {}))
            if isinstance(vpc_config, dict):
                app_vpc_id = vpc_config.get("VpcId", vpc_config.get("vpc_id", ""))
            elif vpc_config:
                app_vpc_id = getattr(vpc_config, "vpc_id", "") or ""
        app_region = raw_dict.get("RegionId", "") or raw_dict.get("region_id", "") or getattr(app, "region_id", "") or region_id

        # 状态: SAE ListApplications 不直接返回运行状态字符串
        # ApplicationStatus 只包含 instance_count/scale_config
        # 从 RunningInstances 推断: >0 为 RUNNING, 0 为 STOPPED
        status_str = raw_dict.get("Status", "") or raw_dict.get("status", "")
        if not status_str:
            if running_instances and running_instances > 0:
                status_str = "RUNNING"
            else:
                # 检查 ApplicationStatus 中的 instance_count
                app_status_info = raw_dict.get("ApplicationStatus", {})
                if isinstance(app_status_info, dict):
                    ic = app_status_info.get("InstanceCount", app_status_info.get("instance_count", 0))
                    if ic and ic > 0:
                        status_str = "RUNNING"
                    else:
                        status_str = "STOPPED"

        if not app_id:
            return

        # 生成 service_url: {app_name}.{namespace_short_id}.svc.cluster.local.{region_id}
        # 需要 namespace_short_id 来生成正确的 service_url
        ns_short_id = namespace_map.get(ns_id, "")
        if ns_short_id and app_name and app_region:
            # 查找 region_id 部分（去掉前缀如 cn-hangzhou:chuandaodev -> cn-hangzhou）
            region_part = app_region
            service_url = f"{app_name}.{ns_short_id}.svc.cluster.local.{region_part}"
        else:
            # fallback: 使用 intranet URL from SDK response
            service_url = getattr(app, "url_intranet", "") or ""

        unique_keys = {
            "account_name": self.account.name,
            "region_id": app_region or region_id,
            "namespace_id": ns_id,
            "app_id": app_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "app_name": app_name,
            "app_type": app_type,
            "programming_language": programming_language,
            "status": status_str,
            "running_instances": running_instances,
            "instance_count": instance_count,
            "cpu": cpu,
            "memory": mem,
            "image_url": image_url,
            "app_description": app_description,
            "vpc_id": app_vpc_id,
            "service_url": service_url,
            "raw_json": raw_dict,
        }
        self.upsert(SaeApp, unique_keys, values)

        self.save_raw(
            resource_type="sae",
            region_id=app_region or region_id,
            resource_id=app_id,
            resource_name=app_name,
            raw_json=raw_dict,
            source_api="ListApplications",
        )
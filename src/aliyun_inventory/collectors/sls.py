"""SLS Collector — 收集日志服务项目、日志库，以及 CLB/ALB 的访问日志配置"""

from typing import Any

from alibabacloud_sls20201230 import models as sls_models
from alibabacloud_slb20140515 import models as slb_models
from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, model_to_dict
from ..config import AccountConfig
from ..models import SlsProject, SlsLogstore, LbLogConfig, LoadBalancer

class SlsCollector(BaseCollector):
    """SLS 日志服务收集器

    收集内容：
    1. SLS 项目列表（ListProject）和每个项目下的日志库（ListLogStore）
    2. CLB 访问日志配置（DescribeAccessLogsDownloadAttribute）
    """

    def collect(self) -> None:
        """自动发现所有地域的 SLS 项目，并收集日志库和 LB 访问日志配置"""
        # SLS 项目可能在多个地域，需要探测
        regions = self.client_factory.discover_active_regions("ecs")  # 用 ECS 的有资源地域作为参考
        # 加上常见的 SLS 地域
        sls_regions = set(regions)
        # SLS 可能部署在其他地域，补充常见地域
        for r in ("cn-beijing", "cn-hangzhou", "cn-shanghai", "cn-shenzhen",
                  "cn-hongkong", "ap-southeast-1"):
            sls_regions.add(r)

        total_projects = 0
        total_logstores = 0

        for region_id in sls_regions:
            try:
                proj_count, store_count = self._collect_region(region_id)
                total_projects += proj_count
                total_logstores += store_count
            except Exception as e:
                # SLS 在某些地域可能没有项目，忽略错误
                self.logger.debug("SLS 地域 %s 收集失败", region_id, exc_info=True)
                continue

        self.logger.info(
                "账号 %s SLS 同步完成: 共 %d 个项目, %d 个日志库",
                self.account.display_name, total_projects, total_logstores,
        )

        # 收集 CLB 访问日志配置
        try:
            self._collect_clb_log_configs()
        except Exception as e:
            self.logger.warning("CLB 访问日志配置收集失败", exc_info=True)

        # 收集 ALB 访问日志配置（ALB 日志配置从 raw_json 中提取）
        try:
            self._collect_alb_log_configs()
        except Exception as e:
            self.logger.warning("ALB 访问日志配置收集失败", exc_info=True)

    def _collect_region(self, region_id: str) -> tuple[int, int]:
        """收集单个地域的 SLS 项目和日志库"""
        try:
            client = self.client_factory.create_client("sls", region_id)
        except Exception:
            self.logger.debug("SLS 地域 %s 创建客户端失败", region_id, exc_info=True)
            return 0, 0

        # 列出所有项目
        projects = self._list_projects(client, region_id)
        if not projects:
            return 0, 0

        self.logger.info("地域 %s: %d 个 SLS 项目", region_id, len(projects))

        # 保存项目
        for project in projects:
            try:
                self._save_project(project, region_id)
            except Exception as e:
                self.logger.warning("保存 SLS 项目 %s 失败: %s", project.project_name, e)
                continue

        # 列出每个项目下的日志库
        total_logstores = 0
        for project in projects:
            project_name = project.project_name
            try:
                logstores = self._list_logstores(client, project_name)
                for logstore in logstores:
                    try:
                        self._save_logstore(logstore, project_name, region_id)
                    except Exception as e:
                        self.logger.warning("保存日志库 %s 失败: %s", logstore.logstore_name, e)
                        continue
                total_logstores += len(logstores)
            except Exception as e:
                self.logger.warning("获取项目 %s 日志库失败: %s", project_name, e)
                continue

        self.session.commit()
        return len(projects), total_logstores

    def _list_projects(self, client: Any, region_id: str) -> list[Any]:
        """列出所有 SLS 项目"""
        all_projects = []
        offset = 0
        size = 100

        while True:
            try:
                request = sls_models.ListProjectRequest(offset=offset, size=size)
                response = client.list_project(request)
                projects = response.body.projects or []
                all_projects.extend(projects)

                total = response.body.count or 0
                if len(all_projects) >= total or not projects:
                    break
                offset += size
            except Exception as e:
                self.logger.warning("地域 %s ListProject 失败", region_id, exc_info=True)
                break

        return all_projects

    def _list_logstores(self, client: Any, project_name: str) -> list[Any]:
        """列出项目下所有日志库"""
        try:
            request = sls_models.ListLogStoresRequest(offset=0, size=100)
            response = client.list_log_stores(project_name, request)
            # list_log_stores 返回 logstores 列表（字符串名称列表）
            logstore_names = response.body.logstores or []
            return logstore_names
        except Exception as e:
            self.logger.warning("ListLogStores %s 失败: %s", project_name, e)
            return []

    def _save_project(self, project: Any, region_id: str) -> None:
        """保存单个 SLS 项目"""
        project_name = project.project_name
        description = project.description or ""
        status = project.status or ""

        raw_dict = model_to_dict(project)

        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "project_name": project_name,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "description": description,
            "status": status,
            "raw_json": raw_dict,
        }
        self.upsert(SlsProject, unique_keys, values)

        # 也写入 resources_raw
        self.save_raw(
            resource_type="sls_project",
            region_id=region_id,
            resource_id=project_name,
            resource_name=project_name,
            raw_json=raw_dict,
            source_api="ListProject",
        )

    def _save_logstore(self, logstore_name: str, project_name: str, region_id: str) -> None:
        """保存单个日志库"""
        # ListLogStore 返回的是字符串名称，没有详细信息
        raw_dict = {"logstore_name": logstore_name, "project_name": project_name}

        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "project_name": project_name,
            "logstore_name": logstore_name,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "raw_json": raw_dict,
        }
        self.upsert(SlsLogstore, unique_keys, values)

    # ──────────────────────────────────────────────
    # CLB 访问日志配置
    # ──────────────────────────────────────────────

    def _collect_clb_log_configs(self) -> None:
        """收集所有 CLB 的访问日志 SLS 配置"""
        # 从已有 CLB 数据中获取所有 CLB ID
        from sqlalchemy import select
        lbs = self.session.execute(
            select(LoadBalancer).where(LoadBalancer.lb_type == "clb")
        ).scalars().all()

        if not lbs:
            return

        self.logger.info("收集 %d 个 CLB 的访问日志配置...", len(lbs))

        for lb in lbs:
            try:
                self._get_clb_log_config(lb)
            except Exception as e:
                self.logger.warning("CLB %s 日志配置获取失败: %s", lb.lb_id, e)
                continue

        self.session.commit()

    def _get_clb_log_config(self, lb: LoadBalancer) -> None:
        """获取单个 CLB 的访问日志配置"""
        client = self.client_factory.create_client("slb", lb.region_id)

        request = slb_models.DescribeAccessLogsDownloadAttributeRequest(
            region_id=lb.region_id,
            load_balancer_id=lb.lb_id,
        )

        try:
            response = client.describe_access_logs_download_attribute(request)
            attrs = response.body.logs_download_attributes.logs_download_attribute if response.body.logs_download_attributes else []
        except Exception:
            # 该 CLB 可能没有配置访问日志
            self.logger.debug("CLB %s 无访问日志配置", lb.lb_id, exc_info=True)
            return

        for attr in attrs:
            log_project = attr.log_project or ""
            log_store = attr.log_store or ""
            log_type = attr.log_type or ""

            if not log_project and not log_store:
                continue

            raw_dict = model_to_dict(attr)

            unique_keys = {
                "account_name": self.account.name,
                "lb_type": "clb",
                "region_id": lb.region_id,
                "lb_id": lb.lb_id,
            }
            values = {
                **unique_keys,
                "account_display_name": self.account.display_name,
                "lb_name": lb.lb_name,
                "log_project": log_project,
                "log_store": log_store,
                "log_type": log_type,
                "raw_json": raw_dict,
            }
            self.upsert(LbLogConfig, unique_keys, values)

            self.logger.info("CLB %s → SLS %s/%s (%s)", lb.lb_name, log_project, log_store, log_type)

    # ──────────────────────────────────────────────
    # ALB 访问日志配置
    # ──────────────────────────────────────────────

    def _collect_alb_log_configs(self) -> None:
        """从 ALB raw_json 中提取访问日志配置"""
        from sqlalchemy import select, type_coerce, String

        lbs = self.session.execute(
            select(LoadBalancer).where(LoadBalancer.lb_type == "alb")
        ).scalars().all()

        for lb in lbs:
            raw = lb.raw_json
            if not raw:
                continue

            # ALB 的 raw_json 中可能有 LogProject 和 LogStore 信息
            # 格式: {"AccessLogConfig": {"LogProject": "xxx", "LogStore": "xxx"}}
            access_log_config = raw.get("AccessLogConfig") or raw.get("accessLogConfig")
            if not access_log_config:
                continue

            log_project = access_log_config.get("LogProject") or access_log_config.get("logProject") or ""
            log_store = access_log_config.get("LogStore") or access_log_config.get("logStore") or ""

            if not log_project and not log_store:
                continue

            unique_keys = {
                "account_name": self.account.name,
                "lb_type": "alb",
                "region_id": lb.region_id,
                "lb_id": lb.lb_id,
            }
            values = {
                **unique_keys,
                "account_display_name": self.account.display_name,
                "lb_name": lb.lb_name,
                "log_project": log_project,
                "log_store": log_store,
                "log_type": "layer7",
                "raw_json": access_log_config,
            }
            self.upsert(LbLogConfig, unique_keys, values)
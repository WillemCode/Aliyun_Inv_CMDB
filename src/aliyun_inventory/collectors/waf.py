"""WAF Collector — 收集 WAF 防护域名信息"""

import json
from typing import Any

from alibabacloud_waf_openapi20190910 import models as waf_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, model_to_dict
from ..config import AccountConfig
from ..models import WafDomain

class WafCollector(BaseCollector):
    """WAF 防护域名收集器

    WAF 是全局服务。需要先获取 WAF 实例 ID（DescribeInstanceInfo），
    再用 instance_id 分页获取域名列表（DescribeDomainList），
    最后获取每个域名的详细配置（DescribeDomain）获取回源 IP 等。

    注意：按量付费(PayType=0)的 WAF 实例没有 instance_id，
    DescribeDomainList 不传 instance_id 时默认查询按量版实例的域名。
    """

    def collect(self) -> None:
        """收集 WAF 防护域名信息（全局服务）"""
        client = self.client_factory.create_client("waf", "cn-hangzhou")

        # 第一步：获取 WAF 实例 ID（包年包月版有 instance_id，按量版没有）
        instance_id = self._get_instance_id(client)

        # 服务未开通时直接跳过
        if instance_id == "__SERVICE_NOT_OPENED__":
            self.logger.info("账号 %s WAF 同步完成: 共 0 个域名（未开通 WAF 服务）", self.account.display_name)
            return

        self.logger.info("WAF instance_id: %s", instance_id or "(按量付费版)")

        # 第二步：获取所有 WAF 防护域名列表（使用 DescribeDomainList 分页）
        # 按量版不传 instance_id，包年包月版需传 instance_id
        domain_names = self._list_domain_names(client, instance_id)
        self.logger.info("发现 %d 个 WAF 防护域名", len(domain_names))

        # 第三步：获取每个域名的详细配置
        total = 0
        for domain_name in domain_names:
            try:
                self._save_domain(client, domain_name, instance_id)
                total += 1
            except Exception as e:
                self.logger.warning("保存 WAF 域名 %s 失败: %s", domain_name, e)
                continue

        self.session.commit()
        self.logger.info("账号 %s WAF 同步完成: 共 %d 个域名", self.account.display_name, total)

    def _get_instance_id(self, client: Any) -> str:
        """获取 WAF 实例 ID

        包年包月版（PayType=1）有 instance_id，可以直接获取。
        按量付费版（PayType=0）没有 instance_id，返回空字符串，
        后续调用 DescribeDomainList 时不传 instance_id 即可查询按量版域名。
        """
        try:
            request = waf_models.DescribeInstanceInfoRequest()
            response = client.describe_instance_info(request)
            if response.body.instance_info:
                info = response.body.instance_info
                # 如果有 instance_id，直接返回
                inst_id = info.instance_id
                if inst_id:
                    return inst_id
                # PayType=0 表示按量付费版，没有 instance_id
                # 但 WAF 服务是存在的，后续 API 不传 instance_id 即可
                self.logger.debug("WAF 按量付费版 (PayType=%s)，无 instance_id", info.pay_type)
        except Exception as e:
            error_msg = str(e)
            # 账号未开通 WAF 服务
            if "WafServiceNotFound" in error_msg or "does not open WAF service" in error_msg or "NotOpenedWaf" in error_msg:
                self.logger.info("账号 %s 未开通 WAF 服务，跳过", self.account.display_name)
                return "__SERVICE_NOT_OPENED__"
            self.logger.warning("获取 WAF 实例信息失败: %s", error_msg)
        return ""

    def _list_domain_names(self, client: Any, instance_id: str) -> list[str]:
        """使用 DescribeDomainList 分页获取所有 WAF 防护域名名称列表

        instance_id 为空时查询按量付费版的域名列表。
        """
        domain_names = []
        page_number = 1
        page_size = 50

        while True:
            try:
                params = {"page_number": page_number, "page_size": page_size}
                if instance_id:
                    params["instance_id"] = instance_id
                request = waf_models.DescribeDomainListRequest(**params)
                response = client.describe_domain_list(request)
                names = response.body.domain_names or []
                domain_names.extend(names)

                total_count = response.body.total_count or 0
                if total_count and len(domain_names) >= total_count or not names:
                    break
                page_number += 1
            except Exception as e:
                error_msg = str(e)
                # MissingInstanceId: 该账号 WAF 不是按量版，需要 instance_id 但没有获取到
                if "MissingInstanceId" in error_msg:
                    self.logger.info("账号 %s WAF 版本需要 instance_id 但未获取到，跳过域名列表", self.account.display_name)
                else:
                    self.logger.warning("获取 WAF 域名列表失败", exc_info=True)
                break

        return domain_names

    def _save_domain(self, client: Any, domain_name: str, instance_id: str) -> None:
        """保存单个 WAF 域名"""
        cname = ""
        cluster_type = ""
        access_type = ""
        http_port = ""
        https_port = ""
        source_ips = []
        domain = None

        try:
            params = {"domain": domain_name}
            if instance_id:
                params["instance_id"] = instance_id
            request = waf_models.DescribeDomainRequest(**params)
            response = client.describe_domain(request)
            domain = response.body.domain if response.body.domain else None

            if domain:
                cname = domain.cname or ""
                cluster_type = str(domain.cluster_type) if domain.cluster_type else ""
                access_type = domain.access_type or ""
                # http_port / https_port are List[int]
                if domain.http_port:
                    http_port = ",".join(str(p) for p in domain.http_port)
                if domain.https_port:
                    https_port = ",".join(str(p) for p in domain.https_port)
                try:
                    if domain.source_ips:
                        source_ips = list(domain.source_ips) if isinstance(domain.source_ips, (list, tuple)) else [domain.source_ips]
                except Exception:
                    pass
        except Exception as e:
            self.logger.warning("获取 WAF 埨名 %s 详情失败: %s", domain_name, e)

        raw_dict = model_to_dict(domain) if domain else {"domain_name": domain_name}

        # 写入 waf_domains 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": "cn-hangzhou",  # WAF 全局服务
            "domain_name": domain_name,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "instance_id": instance_id,
            "cname": cname,
            "cluster_type": cluster_type,
            "access_type": access_type,
            "http_port": http_port,
            "https_port": https_port,
            "source_ips_json": json.dumps(source_ips),
            "raw_json": raw_dict,
        }
        self.upsert(WafDomain, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="waf",
            region_id="cn-hangzhou",
            resource_id=domain_name,
            resource_name=domain_name,
            raw_json=raw_dict,
            source_api="DescribeDomain",
        )
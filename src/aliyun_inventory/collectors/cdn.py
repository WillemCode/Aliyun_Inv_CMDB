"""CDN Collector — 收集 CDN 加速域名及回源信息"""

import json
from typing import Any

from alibabacloud_cdn20180510 import models as cdn_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import CdnDomain

class CdnCollector(BaseCollector):
    """CDN 加速域名收集器

    CDN 是全局服务，DescribeUserDomains 获取所有域名。
    同时获取每个域名的回源配置（Sources）用于链路关联。
    """

    def collect(self) -> None:
        """收集 CDN 域名信息（全局服务）"""
        client = self.client_factory.create_client("cdn", "cn-hangzhou")

        # 第一步：获取所有 CDN 域名列表
        # paginate 内部已处理"服务未开通"等异常，返回空列表
        domains = paginate_page_number(
            client=client,
            method_name="describe_user_domains",
            request_class=cdn_models.DescribeUserDomainsRequest,
            page_size=50,
            list_extractor=lambda resp: (
                resp.body.domains.page_data if resp.body.domains else []
            ),
        )

        self.logger.info("发现 %d 个 CDN 域名", len(domains))

        # 第二步：对每个域名获取详细信息（含回源配置）
        total = 0
        for domain_item in domains:
            try:
                self._save_domain(client, domain_item)
                total += 1
            except Exception as e:
                self.logger.warning("保存 CDN 域名 %s 失败: %s", domain_item.domain_name, e)
                continue

        self.session.commit()
        self.logger.info("账号 %s CDN 同步完成: 共 %d 个域名", self.account.display_name, total)

    def _save_domain(self, client: Any, domain_item: Any) -> None:
        """保存单个 CDN 域名"""
        domain_name = domain_item.domain_name or ""
        domain_id = domain_item.domain_id or ""
        cname = domain_item.cname or ""
        cdn_type = domain_item.cdn_type or ""
        domain_status = domain_item.domain_status or ""
        coverage = domain_item.coverage or ""
        ssl_protocol = domain_item.ssl_protocol or ""

        # 提取回源信息（Sources）
        origin_type = ""
        origin_addresses = []
        try:
            sources = domain_item.sources
            if sources and sources.source:
                origin_types = []
                origin_addrs = []
                for source in sources.source:
                    origin_types.append(source.type or "")
                    addr = source.content or ""
                    if source.port and source.port != "80":
                        addr = f"{addr}:{source.port}"
                    origin_addrs.append(addr)
                origin_type = ",".join(origin_types)
                origin_addresses = origin_addrs
        except Exception:
            self.logger.debug("提取 CDN 回源信息失败", exc_info=True)

        # 尝试获取域名详细配置（DescribeCdnDomainDetail）
        try:
            detail_request = cdn_models.DescribeCdnDomainDetailRequest(
                domain_name=domain_name,
            )
            detail_response = client.describe_cdn_domain_detail(detail_request)
            # 合并详细信息到 raw_json
            detail_dict = model_to_dict(detail_response.body.domain if detail_response.body.domain else domain_item)
        except Exception:
            self.logger.debug("获取 CDN 域名详情失败", exc_info=True)
            detail_dict = model_to_dict(domain_item)

        raw_dict = detail_dict

        # 写入 cdn_domains 表
        unique_keys = {
            "account_name": self.account.name,
            "domain_name": domain_name,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "domain_id": domain_id,
            "cname": cname,
            "cdn_type": cdn_type,
            "domain_status": domain_status,
            "coverage": coverage,
            "origin_type": origin_type,
            "origin_address": json.dumps(origin_addresses),  # JSON list
            "ssl_protocol": ssl_protocol,
            "raw_json": raw_dict,
        }
        self.upsert(CdnDomain, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="cdn",
            region_id="global",
            resource_id=domain_name,
            resource_name=domain_name,
            raw_json=raw_dict,
            source_api="DescribeUserDomains",
        )
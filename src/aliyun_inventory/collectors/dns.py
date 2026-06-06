"""DNS Collector — 收集云解析 DNS 记录"""
from typing import Any

import re

from alibabacloud_alidns20150109 import models as dns_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import DnsRecord

# 简单 IP 格式匹配（IPv4）
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
# IPv6 简单匹配
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")


def _is_ip_address(value: str) -> bool:
    """判断 DNS 记录值是否是 IP 地址"""
    return IPV4_PATTERN.match(value) is not None or (
        ":" in value and IPV6_PATTERN.match(value) is not None
    )


def _build_fqdn(rr: str, domain_name: str) -> str:
    """构建完整域名 (FQDN)"""
    if rr == "@" or not rr:
        return domain_name
    return f"{rr}.{domain_name}"


class DnsCollector(BaseCollector):
    """DNS 解析记录收集器"""

    def collect(self) -> None:
        """自动发现所有域名，收集 DNS 解析记录"""
        domains = self.client_factory.discover_domains()
        total_count = 0

        for domain_name in domains:
            try:
                count = self._collect_domain(domain_name)
                total_count += count
                if count > 0:
                    self.logger.info("域名 %s: %d 条解析记录", domain_name, count)
            except Exception as e:
                self.logger.error("域名 %s DNS 同步失败: %s", domain_name, e)
                continue

        self.logger.info("账号 %s DNS 同步完成: 共 %d 条记录", self.account.display_name, total_count)

    def _collect_domain(self, domain_name: str) -> int:
        """收集单个域名的 DNS 解析记录"""
        client = self.client_factory.create_client("dns", "cn-hangzhou")  # DNS 全局服务

        records = paginate_page_number(
            client=client,
            method_name="describe_domain_records",
            request_class=dns_models.DescribeDomainRecordsRequest,
            extra_params={"domain_name": domain_name},
            page_size=500,
            list_extractor=lambda resp: resp.body.domain_records.record if resp.body.domain_records else [],
        )

        for record in records:
            try:
                self._save_record(record, domain_name)
            except Exception as e:
                self.logger.warning("保存 DNS 记录 %s 失败: %s", record.record_id, e)
                continue

        self.session.commit()
        return len(records)

    def _save_record(self, record: Any, domain_name: str) -> None:
        """保存单个 DNS 解析记录"""
        record_id = record.record_id
        rr = record.rr or ""
        fqdn = _build_fqdn(rr, record.domain_name or domain_name)
        record_type = record.type or ""
        value = record.value or ""
        ttl = record.ttl if record.ttl else None
        status = record.status or ""

        raw_dict = model_to_dict(record)

        # 写入 dns_records 表
        unique_keys = {
            "account_name": self.account.name,
            "record_id": record_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "domain_name": domain_name,
            "rr": rr,
            "fqdn": fqdn,
            "record_type": record_type,
            "value": value,
            "ttl": ttl,
            "status": status,
            "line": getattr(record, "line", None),
            "weight": getattr(record, "weight", None),
            "raw_json": raw_dict,
        }
        self.upsert(DnsRecord, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="dns",
            region_id="global",  # DNS 是全局服务
            resource_id=record_id,
            resource_name=fqdn,
            raw_json=raw_dict,
            source_api="DescribeDomainRecords",
        )

        # 如果记录类型是 A/AAAA 且 value 是 IP，写入 ip_addresses 表
        if record_type.upper() in ("A", "AAAA") and _is_ip_address(value):
            self.upsert_ip(
                resource_type="dns_record",
                resource_id=record_id,
                resource_name=fqdn,
                ip=value,
                ip_type="dns_value",
                region_id="global",
            )
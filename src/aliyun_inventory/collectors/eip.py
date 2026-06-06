"""EIP Collector — 收集弹性公网 IP"""
from typing import Any

from alibabacloud_vpc20160428 import models as vpc_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import EipAddress

class EipCollector(BaseCollector):
    """弹性公网 IP 收集器"""

    def collect(self) -> None:
        """探测有 EIP 的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("eip")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 EIP", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s EIP 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s EIP 同步完成: 共 %d 个", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 EIP"""
        client = self.client_factory.create_client("vpc", region_id)

        eips = paginate_page_number(
            client=client,
            method_name="describe_eip_addresses",
            request_class=vpc_models.DescribeEipAddressesRequest,
            extra_params={"region_id": region_id},
            list_extractor=lambda resp: resp.body.eip_addresses.eip_address if resp.body.eip_addresses else [],
        )

        for eip in eips:
            try:
                self._save_eip(eip, region_id)
            except Exception as e:
                self.logger.warning("保存 EIP %s 失败: %s", eip.allocation_id, e)
                continue

        self.session.commit()
        return len(eips)

    def _save_eip(self, eip: Any, region_id: str) -> None:
        """保存单个 EIP"""
        allocation_id = eip.allocation_id
        ip_address = eip.ip_address or ""  # SDK 字段名是 ip_address 不是 eip_address
        status = eip.status or ""
        instance_type = eip.instance_type or ""
        instance_id = eip.instance_id or ""

        # EIP 名称可能在 name 或 description 字段
        eip_name = ""
        try:
            eip_name = eip.name or eip.description or allocation_id
        except Exception:
            eip_name = allocation_id

        raw_dict = model_to_dict(eip)

        # 写入 eip_addresses 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "allocation_id": allocation_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "ip_address": ip_address,
            "status": status,
            "instance_type": instance_type,
            "instance_id": instance_id,
            "raw_json": raw_dict,
        }
        self.upsert(EipAddress, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="eip",
            region_id=region_id,
            resource_id=allocation_id,
            resource_name=eip_name,
            raw_json=raw_dict,
            source_api="DescribeEipAddresses",
        )

        # 写入 ip_addresses 表
        if ip_address:
            self.upsert_ip(
                resource_type="eip",
                resource_id=allocation_id,
                resource_name=eip_name,
                ip=ip_address,
                ip_type="eip",
                region_id=region_id,
            )
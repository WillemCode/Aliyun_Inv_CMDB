"""ECS Collector — 收集 ECS 实例信息"""
from typing import Any

from alibabacloud_ecs20140526 import models as ecs_models
import logging

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import EcsInstance

_logger = logging.getLogger(__name__)


def _extract_private_ips(instance: Any) -> list[str]:
    """提取 ECS 实例的私网 IP 列表（主网卡）"""
    try:
        vpc_attrs = instance.vpc_attributes
        if vpc_attrs and vpc_attrs.private_ip_address and vpc_attrs.private_ip_address.ip_address:
            return vpc_attrs.private_ip_address.ip_address
    except Exception:
        _logger.debug("提取私网IP失败", exc_info=True)
    # fallback: 从 inner_ip_address 取（经典网络）
    try:
        if instance.inner_ip_address and instance.inner_ip_address.ip_address:
            return instance.inner_ip_address.ip_address
    except Exception:
        _logger.debug("提取私网IP失败(经典网络)", exc_info=True)
    return []


def _extract_eni_secondary_ips(instance: Any) -> list[str]:
    """提取 ECS 实例弹性网卡（ENI）的辅助私网 IP

    network_interfaces 包含所有 ENI（包括主网卡），private_ip_sets 包含辅助 IP。
    主网卡的主 IP 已在 vpc_attributes 中提取，这里只取辅助 IP。
    """
    ips: list[str] = []
    try:
        interfaces = instance.network_interfaces
        if not interfaces or not interfaces.network_interface:
            return ips
        primary_ips = _extract_private_ips(instance)
        for eni in interfaces.network_interface:
            # 辅助私网 IP（private_ip_sets）
            if eni.private_ip_sets and eni.private_ip_sets.private_ip_set:
                for ip_set in eni.private_ip_sets.private_ip_set:
                    ip_addr = ip_set.private_ip_address
                    if ip_addr and ip_addr not in primary_ips:
                        ips.append(ip_addr)
    except Exception:
        _logger.debug("提取ENI辅助IP失败", exc_info=True)
    return ips


def _extract_nat_ip(instance: Any) -> str:
    """提取 ECS 实例的 NAT IP（SNAT 后的外网 IP）"""
    try:
        if instance.vpc_attributes and instance.vpc_attributes.nat_ip_address:
            return instance.vpc_attributes.nat_ip_address
    except Exception:
        _logger.debug("提取NAT IP失败", exc_info=True)
    return ""


def _extract_public_ips(instance: Any) -> list[str]:
    """提取 ECS 实例的公网 IP 列表"""
    try:
        if instance.public_ip_address and instance.public_ip_address.ip_address:
            return instance.public_ip_address.ip_address
    except Exception:
        _logger.debug("提取公网IP失败", exc_info=True)
    return []


def _extract_eip(instance: Any) -> str:
    """提取 ECS 实例的 EIP 地址"""
    try:
        if instance.eip_address and instance.eip_address.ip_address:
            return instance.eip_address.ip_address
    except Exception:
        _logger.debug("提取EIP失败", exc_info=True)
    return ""


class EcsCollector(BaseCollector):
    """ECS 实例收集器"""

    def collect(self) -> None:
        """探测有 ECS 实例的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("ecs")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个 ECS 实例", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s ECS 同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s ECS 同步完成: 共 %d 个实例", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的 ECS 实例"""
        client = self.client_factory.create_client("ecs", region_id)

        instances = paginate_page_number(
            client=client,
            method_name="describe_instances",
            request_class=ecs_models.DescribeInstancesRequest,
            extra_params={"region_id": region_id},
            list_extractor=lambda resp: resp.body.instances.instance if resp.body.instances else [],
        )

        for instance in instances:
            try:
                self._save_instance(instance, region_id)
            except Exception as e:
                self.logger.warning("保存 ECS 实例 %s 失败: %s", instance.instance_id, e)
                continue

        self.session.commit()
        return len(instances)

    def _save_instance(self, instance: Any, region_id: str) -> None:
        """保存单个 ECS 实例到数据库"""
        instance_id = instance.instance_id
        instance_name = instance.instance_name or ""
        status = instance.status or ""
        zone_id = instance.zone_id or ""
        vpc_id = ""

        # 提取 VPC ID
        try:
            if instance.vpc_attributes and instance.vpc_attributes.vpc_id:
                vpc_id = instance.vpc_attributes.vpc_id
        except Exception:
            _logger.debug("提取 VPC ID 失败", exc_info=True)

        private_ips = _extract_private_ips(instance)
        eni_ips = _extract_eni_secondary_ips(instance)
        # 合并：主网卡 IP 在前，ENI 辅助 IP 在后（去重）
        all_private_ips = private_ips + [ip for ip in eni_ips if ip not in private_ips]
        public_ips = _extract_public_ips(instance)
        eip = _extract_eip(instance)
        nat_ip = _extract_nat_ip(instance)

        raw_dict = model_to_dict(instance)

        # 获取关联的磁盘信息（DescribeDisks）
        try:
            client = self.client_factory.create_client("ecs", region_id)
            disk_req = ecs_models.DescribeDisksRequest(
                region_id=region_id,
                instance_id=instance_id,
                page_size=100,
                page_number=1,
            )
            disk_resp = client.describe_disks(disk_req)
            if disk_resp.body and disk_resp.body.disks:
                disks = disk_resp.body.disks.disk or []
                raw_dict["Disks"] = [model_to_dict(d) for d in disks]
        except Exception:
            _logger.debug("获取磁盘信息失败", exc_info=True)

        # 获取关联的安全组详情（DescribeSecurityGroups）
        try:
            sg_ids = raw_dict.get("SecurityGroupIds", {}).get("SecurityGroupId", [])
            if sg_ids:
                client = self.client_factory.create_client("ecs", region_id)
                sg_details = []
                for sg_id in sg_ids:
                    sg_req = ecs_models.DescribeSecurityGroupsRequest(
                        region_id=region_id,
                        security_group_id=sg_id,
                    )
                    sg_resp = client.describe_security_groups(sg_req)
                    if sg_resp.body and sg_resp.body.security_groups:
                        groups = sg_resp.body.security_groups.security_group or []
                        for g in groups:
                            sg_details.append(model_to_dict(g))
                raw_dict["SecurityGroups"] = sg_details
        except Exception:
            _logger.debug("获取安全组信息失败", exc_info=True)

        # 写入 ecs_instances 表
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
            "status": status,
            "vpc_id": vpc_id,
            "private_ips_json": all_private_ips,
            "public_ips_json": public_ips,
            "eip_address": eip,
            "nat_ip_address": nat_ip,
            "raw_json": raw_dict,
        }
        self.upsert(EcsInstance, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="ecs",
            region_id=region_id,
            resource_id=instance_id,
            resource_name=instance_name,
            raw_json=raw_dict,
            source_api="DescribeInstances",
        )

        # 写入 ip_addresses 表 — 所有私网 IP（含 ENI 辅助 IP）
        for ip in all_private_ips:
            self.upsert_ip(
                resource_type="ecs",
                resource_id=instance_id,
                resource_name=instance_name,
                ip=ip,
                ip_type="private",
                region_id=region_id,
            )

        # 写入 ip_addresses 表 — 公网 IP
        for ip in public_ips:
            self.upsert_ip(
                resource_type="ecs",
                resource_id=instance_id,
                resource_name=instance_name,
                ip=ip,
                ip_type="public",
                region_id=region_id,
            )

        # 写入 ip_addresses 表 — EIP
        if eip:
            self.upsert_ip(
                resource_type="ecs",
                resource_id=instance_id,
                resource_name=instance_name,
                ip=eip,
                ip_type="eip",
                region_id=region_id,
            )

        # 写入 ip_addresses 表 — NAT IP
        if nat_ip:
            self.upsert_ip(
                resource_type="ecs",
                resource_id=instance_id,
                resource_name=instance_name,
                ip=nat_ip,
                ip_type="nat",
                region_id=region_id,
            )
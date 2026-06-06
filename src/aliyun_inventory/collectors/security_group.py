"""SecurityGroup Collector — 收集安全组信息（含入方向/出方向规则）"""
from typing import Any

from alibabacloud_ecs20140526 import models as ecs_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import SecurityGroup

class SecurityGroupCollector(BaseCollector):
    """安全组收集器"""

    def collect(self) -> None:
        """探测有安全组的地域，只同步有资源的地域"""
        regions = self.client_factory.discover_active_regions("ecs")
        total_count = 0

        for region_id in regions:
            try:
                count = self._collect_region(region_id)
                total_count += count
                if count > 0:
                    self.logger.info("地域 %s: %d 个安全组", region_id, count)
            except Exception as e:
                self.logger.error("地域 %s 安全组同步失败", region_id, exc_info=True)
                continue

        self.logger.info("账号 %s 安全组同步完成: 共 %d 个", self.account.display_name, total_count)

    def _collect_region(self, region_id: str) -> int:
        """收集单个 region 的安全组"""
        client = self.client_factory.create_client("ecs", region_id)

        security_groups = paginate_page_number(
            client=client,
            method_name="describe_security_groups",
            request_class=ecs_models.DescribeSecurityGroupsRequest,
            extra_params={"region_id": region_id},
            list_extractor=lambda resp: resp.body.security_groups.security_group if resp.body.security_groups else [],
        )

        for sg in security_groups:
            try:
                self._save_security_group(sg, region_id, client)
            except Exception as e:
                self.logger.warning("保存安全组 %s 失败: %s", sg.security_group_id, e)
                continue

        self.session.commit()
        return len(security_groups)

    def _save_security_group(self, sg: Any, region_id: str, client: Any) -> None:
        """保存单个安全组到数据库"""
        sg_id = sg.security_group_id
        sg_name = sg.security_group_name or ""
        sg_type = sg.security_group_type or ""
        sg_desc = sg.description or ""
        vpc_id = sg.vpc_id or ""
        rule_count = sg.rule_count or 0

        # 获取安全组基础信息的 raw_dict
        raw_dict = model_to_dict(sg)

        # 获取安全组规则 — DescribeSecurityGroupAttribute(direction="all")
        try:
            attr_req = ecs_models.DescribeSecurityGroupAttributeRequest(
                region_id=region_id,
                security_group_id=sg_id,
                direction="all",
            )
            attr_resp = client.describe_security_group_attribute(attr_req)
            attr_body = attr_resp.body

            # 补充 DescribeSecurityGroupAttribute 返回的额外字段
            if attr_body.security_group_name:
                raw_dict["SecurityGroupNameFromAttr"] = attr_body.security_group_name
                sg_name = attr_body.security_group_name
            if attr_body.description:
                raw_dict["DescriptionFromAttr"] = attr_body.description
                sg_desc = attr_body.description
            if attr_body.inner_access_policy:
                raw_dict["InnerAccessPolicy"] = attr_body.inner_access_policy

            # 规则列表
            if attr_body.permissions:
                perms = attr_body.permissions.permission or []
                raw_dict["Permissions"] = [model_to_dict(p) for p in perms]
                rule_count = len(perms)
        except Exception as e:
            self.logger.warning("获取安全组 %s 规则失败: %s", sg_id, e)
            # 规则获取失败不影响基础信息保存

        # 写入 security_groups 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "security_group_id": sg_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "security_group_name": sg_name,
            "security_group_type": sg_type,
            "description": sg_desc,
            "vpc_id": vpc_id,
            "inner_access_policy": raw_dict.get("InnerAccessPolicy", ""),
            "rule_count": rule_count,
            "raw_json": raw_dict,
        }
        self.upsert(SecurityGroup, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="security_group",
            region_id=region_id,
            resource_id=sg_id,
            resource_name=sg_name,
            raw_json=raw_dict,
            source_api="DescribeSecurityGroups+DescribeSecurityGroupAttribute",
        )
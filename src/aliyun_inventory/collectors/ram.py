"""RAM Collector — 收集 RAM 用户、AccessKey、授权策略"""

from typing import Any

from alibabacloud_ram20150501 import models as ram_models
from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, model_to_dict
from ..config import AccountConfig
from ..models import RamUser, RamAccessKey, RamUserPolicy

class RamCollector(BaseCollector):
    """RAM 用户/AK/策略收集器

    RAM 是全局服务，无需按地域遍历。
    收集内容：
    1. 所有 RAM 用户（含最后登录时间、MFA 信息）
    2. 每个用户的 AccessKey（含状态、最后使用时间）
    3. 每个用户的授权策略（系统策略 + 自定义策略）
    """

    def collect(self) -> None:
        """收集 RAM 用户信息（全局服务）"""
        client = self.client_factory.create_client("ram", "cn-hangzhou")

        total_users = 0
        total_aks = 0
        total_policies = 0

        # 第一步：列出所有 RAM 用户
        users = self._list_users(client)
        total_users = len(users)
        self.logger.info("发现 %d 个 RAM 用户", total_users)

        for user in users:
            try:
                self._save_user(user, client)
            except Exception as e:
                self.logger.warning("保存 RAM 用户 %s 失败: %s", user.user_name, e)
                continue

        self.session.commit()

        # 第二步：为每个用户收集 AccessKey（含最后使用时间）
        for user in users:
            try:
                ak_count = self._collect_access_keys(client, user.user_name)
                total_aks += ak_count
            except Exception as e:
                self.logger.warning("收集用户 %s 的 AK 失败: %s", user.user_name, e)
                continue

        self.session.commit()

        # 第三步：为每个用户收集授权策略
        for user in users:
            try:
                policy_count = self._collect_user_policies(client, user.user_name)
                total_policies += policy_count
            except Exception as e:
                self.logger.warning("收集用户 %s 的策略失败: %s", user.user_name, e)
                continue

        self.session.commit()

        self.logger.info(
                "账号 %s RAM 同步完成: %d 个用户, %d 个 AK, %d 个策略",
                self.account.display_name, total_users, total_aks, total_policies,
        )

    # ──────────────────────────────────────────────
    # 列出所有 RAM 用户
    # ──────────────────────────────────────────────

    def _list_users(self, client: Any) -> list[Any]:
        """使用 ListUsers 分页获取所有 RAM 用户"""
        all_users = []

        try:
            # 第一次请求不带 marker
            request = ram_models.ListUsersRequest(max_items=100)
            response = client.list_users(request)
            users = response.body.users.user if response.body.users else []
            all_users.extend(users)

            # 后续请求使用 marker 分页
            while response.body.is_truncated:
                marker = response.body.marker or ""
                if not marker:
                    break
                request = ram_models.ListUsersRequest(max_items=100, marker=marker)
                response = client.list_users(request)
                users = response.body.users.user if response.body.users else []
                all_users.extend(users)
        except Exception as e:
            error_msg = str(e)
            self.logger.warning("获取 RAM 用户列表失败: %s", error_msg)
            return []

        return all_users

    # ──────────────────────────────────────────────
    # 用户信息丰富（最后登录时间、MFA）
    # ──────────────────────────────────────────────

    def _enrich_user_raw(self, client: Any, user_name: str) -> dict:
        """调用 GetUser + GetUserMFAInfo 丰富用户信息"""
        extra = {}

        # GetUser → last_login_date
        try:
            req = ram_models.GetUserRequest(user_name=user_name)
            resp = client.get_user(req)
            if resp.body and resp.body.user:
                extra["LastLoginDate"] = resp.body.user.last_login_date or ""
        except Exception as e:
            self.logger.debug("获取用户 %s 详细信息失败", user_name, exc_info=True)

        # GetUserMFAInfo → MFA 设备类型 + 序列号
        # 注意：无 MFA 设备的用户调用此 API 会抛异常
        try:
            req = ram_models.GetUserMFAInfoRequest(user_name=user_name)
            resp = client.get_user_mfainfo(req)
            if resp.body and resp.body.mfa_device:
                extra["MFADeviceType"] = resp.body.mfa_device.type or ""
                extra["MFASerialNumber"] = resp.body.mfa_device.serial_number or ""
        except Exception:
            # 无 MFA 设备 → 正常情况，不算错误
            self.logger.debug("用户 %s 无 MFA 设备", user_name, exc_info=True)
            extra["MFADeviceType"] = ""

        return extra

    def _save_user(self, user: Any, client: Any) -> None:
        """保存单个 RAM 用户（含最后登录时间、MFA 信息）"""
        raw_dict = model_to_dict(user)

        # 丰富 raw_json：加入 last_login_date 和 MFA 信息
        try:
            enriched = self._enrich_user_raw(client, user.user_name)
            raw_dict.update(enriched)
        except Exception:
            self.logger.debug("丰富用户 %s raw_json 失败", user.user_name, exc_info=True)

        unique_keys = {
            "account_name": self.account.name,
            "user_id": user.user_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "user_name": user.user_name,
            "display_name": user.display_name or "",
            "email": user.email or "",
            "mobile_phone": user.mobile_phone or "",
            "comments": user.comments or "",
            "create_date": user.create_date or "",
            "update_date": user.update_date or "",
            "raw_json": raw_dict,
        }
        self.upsert(RamUser, unique_keys, values)

        # 写入 resources_raw
        self.save_raw(
            resource_type="ram_user",
            region_id="global",
            resource_id=user.user_id,
            resource_name=user.user_name,
            raw_json=raw_dict,
            source_api="ListUsers",
        )

    # ──────────────────────────────────────────────
    # AccessKey（含最后使用时间）
    # ──────────────────────────────────────────────

    def _collect_access_keys(self, client: Any, user_name: str) -> int:
        """收集指定用户的 AccessKey（含最后使用时间）"""
        request = ram_models.ListAccessKeysRequest(
            user_name=user_name,
        )
        response = client.list_access_keys(request)
        aks = response.body.access_keys.access_key if response.body.access_keys else []

        for ak in aks:
            try:
                # 获取 AK 最后使用时间
                last_used_date = self._get_ak_last_used(client, ak.access_key_id, user_name)
                self._save_access_key(ak, user_name, last_used_date)
            except Exception as e:
                self.logger.warning("保存 AK %s 失败: %s", ak.access_key_id, e)
                continue

        return len(aks)

    def _get_ak_last_used(self, client: Any, access_key_id: str, user_name: str) -> str:
        """调用 GetAccessKeyLastUsed 获取 AK 最后使用时间"""
        try:
            request = ram_models.GetAccessKeyLastUsedRequest(
                user_access_key_id=access_key_id,
                user_name=user_name,
            )
            response = client.get_access_key_last_used(request)
            if response.body and response.body.access_key_last_used:
                return response.body.access_key_last_used.last_used_date or ""
        except Exception as e:
            self.logger.debug("获取 AK %s 最后使用时间失败", access_key_id, exc_info=True)
        return ""

    def _save_access_key(self, ak: Any, user_name: str, last_used_date: str = "") -> None:
        """保存单个 AccessKey（含最后使用时间）"""
        raw_dict = model_to_dict(ak)

        # 将 last_used_date 也加入 raw_json
        if last_used_date:
            raw_dict["LastUsedDate"] = last_used_date

        unique_keys = {
            "account_name": self.account.name,
            "user_name": user_name,
            "access_key_id": ak.access_key_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "ak_name": "",  # RAM API 不返回 AK 名称，IMS API 才有
            "status": ak.status or "",
            "create_date": ak.create_date or "",
            "expiration_time": "",  # RAM API 不返回到期时间，需 IMS API
            "last_used_date": last_used_date,
            "raw_json": raw_dict,
        }
        self.upsert(RamAccessKey, unique_keys, values)

        # 写入 resources_raw
        self.save_raw(
            resource_type="ram_ak",
            region_id="global",
            resource_id=ak.access_key_id,
            resource_name=f"{user_name}/{ak.access_key_id}",
            raw_json=raw_dict,
            source_api="ListAccessKeys",
        )

    # ──────────────────────────────────────────────
    # 授权策略
    # ──────────────────────────────────────────────

    def _collect_user_policies(self, client: Any, user_name: str) -> int:
        """收集指定用户的授权策略（系统策略+自定义策略一次返回）"""
        total = 0

        try:
            request = ram_models.ListPoliciesForUserRequest(
                user_name=user_name,
            )
            response = client.list_policies_for_user(request)
            policies = response.body.policies.policy if response.body.policies else []
            for policy in policies:
                try:
                    self._save_policy(policy, user_name)
                    total += 1
                except Exception as e:
                    self.logger.warning("保存策略 %s 失败: %s", policy.policy_name, e)
                    continue
        except Exception as e:
            self.logger.warning("获取用户 %s 的策略失败: %s", user_name, e)

        return total

    def _save_policy(self, policy: Any, user_name: str) -> None:
        """保存单个授权策略"""
        raw_dict = model_to_dict(policy)

        unique_keys = {
            "account_name": self.account.name,
            "user_name": user_name,
            "policy_name": policy.policy_name,
            "policy_type": policy.policy_type,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "description": policy.description or "",
            "default_version": policy.default_version or "",
            "attach_date": policy.attach_date or "",
            "raw_json": raw_dict,
        }
        self.upsert(RamUserPolicy, unique_keys, values)
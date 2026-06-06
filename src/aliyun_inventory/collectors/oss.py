"""OSS Collector — 收集 OSS 存储桶信息"""

import json
from typing import Any

import oss2

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, model_to_dict
from ..config import AccountConfig
from ..models import OssBucket

class OssCollector(BaseCollector):
    """OSS 存储桶收集器

    OSS 使用 oss2 SDK（不同于其他 SDK 2.0 的模式）。
    ListBuckets 是全局操作，然后对每个桶获取详细信息。
    """

    def collect(self) -> None:
        """收集 OSS 存储桶信息（全局服务）"""
        try:
            auth = oss2.Auth(
                self.client_factory.ak,
                self.client_factory.sk,
            )
        except Exception as e:
            self.logger.warning("创建 OSS Auth 失败: %s", e)
            return

        # 列出所有桶（全局服务，使用默认 endpoint）
        try:
            service = oss2.Service(auth, "https://oss-cn-hangzhou.aliyuncs.com")
        except Exception as e:
            self.logger.warning("创建 OSS Service 失败: %s", e)
            return

        buckets = []
        try:
            for bucket in oss2.BucketIterator(service):
                buckets.append(bucket)
        except Exception as e:
            error_msg = str(e)
            # OSS 服务未开通/权限不足类错误
            if "AccessDenied" in error_msg or "NoSuchService" in error_msg or "ServiceNotActivated" in error_msg:
                self.logger.info("账号 %s 未开通 OSS 服务或权限不足，跳过", self.account.display_name)
            else:
                self.logger.warning("列出 OSS 桶失败: %s", error_msg)
            return

        self.logger.info("发现 %d 个 OSS 桶", len(buckets))

        total = 0
        for bucket_info in buckets:
            try:
                self._save_bucket(auth, bucket_info)
                total += 1
            except Exception as e:
                self.logger.warning("保存 OSS 桶 %s 失败: %s", bucket_info.name, e)
                continue

        self.session.commit()
        self.logger.info("账号 %s OSS 同步完成: 共 %d 个桶", self.account.display_name, total)

    def _save_bucket(self, auth: Any, bucket_info: Any) -> None:
        """保存单个 OSS 桶信息"""
        bucket_name = bucket_info.name or ""
        region = bucket_info.location or ""
        creation_date = str(bucket_info.creation_date) if bucket_info.creation_date else ""
        storage_class = bucket_info.storage_class or ""

        # 尝试获取桶的详细信息（ACL、Endpoint 等）
        access_control = ""
        extranet_endpoint = ""
        intranet_endpoint = ""
        endpoint = ""
        try:
            bucket_obj = oss2.Bucket(auth, f"https://{region}.aliyuncs.com", bucket_name)
            acl_result = bucket_obj.get_bucket_acl()
            access_control = acl_result.acl or ""
        except Exception:
            self.logger.debug("获取 OSS 桶 ACL 失败", exc_info=True)

        # 构建 endpoint（region 格式已是 oss-cn-beijing，直接使用）
        if region:
            extranet_endpoint = f"{region}.aliyuncs.com"
            intranet_endpoint = f"{region}-internal.aliyuncs.com"
            endpoint = extranet_endpoint

        # 构造 raw_dict（oss2 对象没有 to_map 方法，手动构造）
        raw_dict = {
            "name": bucket_name,
            "location": region,
            "creation_date": creation_date,
            "storage_class": storage_class,
            "access_control": access_control,
            "extranet_endpoint": extranet_endpoint,
            "intranet_endpoint": intranet_endpoint,
        }

        # 写入 oss_buckets 表
        unique_keys = {
            "account_name": self.account.name,
            "bucket_name": bucket_name,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "region": region,
            "storage_class": storage_class,
            "access_control": access_control,
            "creation_date": creation_date,
            "endpoint": endpoint,
            "extranet_endpoint": extranet_endpoint,
            "intranet_endpoint": intranet_endpoint,
            "raw_json": raw_dict,
        }
        self.upsert(OssBucket, unique_keys, values)

        # 写入 resources_raw 表
        self.save_raw(
            resource_type="oss",
            region_id=region,
            resource_id=bucket_name,
            resource_name=bucket_name,
            raw_json=raw_dict,
            source_api="ListBuckets",
        )
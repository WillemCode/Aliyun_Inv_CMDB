"""Collector 基类 — 提供 upsert 逻辑、IP 写入、raw 保存、错误隔离"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import AccountConfig
from ..aliyun_client import AliyunClientFactory
from ..models import (
    IpAddress,
    ResourceRaw,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BaseCollector(ABC):
    """资源收集器基类

    子类需要实现 collect() 方法，在其中：
    1. 调用阿里云 API 获取资源
    2. 使用 upsert() 写入对应的资源表
    3. 使用 save_raw() 写入 resources_raw 表
    4. 使用 upsert_ip() 写入 ip_addresses 表
    """

    def __init__(
        self,
        session: Session,
        account_config: AccountConfig,
        client_factory: AliyunClientFactory,
    ) -> None:
        self.session = session
        self.account = account_config
        self.client_factory = client_factory
        # 子 logger：自带账号名和 Collector 类型上下文
        self.logger = logging.getLogger(
            f"aliyun_inv.{account_config.display_name}.{type(self).__name__}"
        )

    @abstractmethod
    def collect(self) -> None:
        """收集资源数据，子类实现"""
        ...

    def upsert(self, model_class: type, unique_keys: dict[str, str], values: dict[str, Any]) -> None:
        """通用 upsert 操作：按 unique_keys 查询，存在则更新，不存在则插入

        Args:
            model_class: SQLAlchemy 模型类
            unique_keys: 用于查找的唯一键值对
            values: 所有字段值（包含 unique_keys 的值）
        """
        from typing import Any

        # 构建查询条件
        stmt = select(model_class)
        for key, val in unique_keys.items():
            stmt = stmt.where(getattr(model_class, key) == val)

        existing = self.session.execute(stmt).scalar_one_or_none()

        if existing:
            # 更新已有记录
            for key, val in values.items():
                if key != "id" and hasattr(existing, key):
                    setattr(existing, key, val)
            setattr(existing, "last_seen_at", utcnow())
            # 如果模型有 updated_at 字段也更新
            if hasattr(existing, "updated_at"):
                setattr(existing, "updated_at", utcnow())
        else:
            # 插入新记录 — unique_keys 也需要包含在初始值中
            all_values = {**unique_keys, **values}
            new_record = model_class(**all_values)
            self.session.add(new_record)

        self.session.flush()

    def upsert_ip(
        self,
        resource_type: str,
        resource_id: str,
        resource_name: str,
        ip: str,
        ip_type: str,
        region_id: str = "",
    ) -> None:
        """便捷方法：写入 ip_addresses 表

        Args:
            resource_type: 资源类型 (ecs / eip / clb / alb / dns_record / backend)
            resource_id: 资源 ID
            resource_name: 资源名称
            ip: IP 地址
            ip_type: IP 类型 (public / private / eip / lb_address / dns_value / backend)
            region_id: 地域 ID
        """
        if not ip:
            return

        unique_keys = {
            "account_name": self.account.name,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "ip": ip,
            "ip_type": ip_type,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "region_id": region_id,
            "resource_name": resource_name,
            "last_seen_at": utcnow(),
        }

        self.upsert(IpAddress, unique_keys, values)

    def save_raw(
        self,
        resource_type: str,
        region_id: str,
        resource_id: str,
        resource_name: str,
        raw_json: dict,
        source_api: str,
    ) -> None:
        """写入 resources_raw 表，保留原始 API 返回

        Args:
            resource_type: 资源类型
            region_id: 地域 ID
            resource_id: 资源 ID
            resource_name: 资源名称
            raw_json: 原始 API 返回的字典
            source_api: API 方法名
        """
        unique_keys = {
            "account_name": self.account.name,
            "resource_type": resource_type,
            "region_id": region_id,
            "resource_id": resource_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "resource_name": resource_name,
            "raw_json": raw_json,
            "source_api": source_api,
            "last_seen_at": utcnow(),
        }

        self.upsert(ResourceRaw, unique_keys, values)
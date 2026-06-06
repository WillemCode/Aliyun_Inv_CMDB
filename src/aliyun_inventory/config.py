"""账号配置加载与 AK/SK 环境变量读取"""

import os
import logging
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


class ResourceConfig(BaseModel):
    """单个资源类型的启用配置

    支持两种 YAML 格式:
    - 简单格式: dns: true  (直接布尔值)
    - 嵌套格式: dns: {enabled: true}  (对象含 enabled 字段)
    """

    dns: bool = False
    ecs: bool = False
    eip: bool = False
    clb: bool = False
    alb: bool = False
    sls: bool = False
    ram: bool = False
    cdn: bool = False
    api: bool = False
    oss: bool = False
    rds: bool = False
    waf: bool = False
    tair: bool = False
    polardb: bool = False
    mongodb: bool = False
    security_group: bool = False
    sae: bool = False

    @classmethod
    def _normalize_resource_value(cls, value: Any) -> bool:
        """将 YAML 中的资源配置值统一为布尔值"""
        if isinstance(value, bool):
            return value
        if isinstance(value, dict):
            return value.get("enabled", False)
        return False

    def __init__(self, **data: Any) -> None:
        normalized = {}
        for key in (
            "dns", "ecs", "eip", "clb", "alb", "sls",
            "ram", "cdn", "api", "oss", "rds", "waf", "tair", "polardb", "mongodb", "security_group", "sae",
        ):
            if key in data:
                normalized[key] = self._normalize_resource_value(data[key])
            else:
                normalized[key] = False
        super().__init__(**normalized)


class AccountConfig(BaseModel):
    """单个阿里云账号配置"""

    name: str
    display_name: str
    credential_env_prefix: str
    enabled: bool = True
    resources: ResourceConfig = Field(default_factory=ResourceConfig)


class AccountCredentials(BaseModel):
    """账号的 AK/SK 凭据"""

    access_key_id: str
    access_key_secret: str


def load_dotenv_if_exists() -> None:
    """如果存在 .env 文件则自动加载"""
    env_path = Path(".env")
    if env_path.exists():
        load_dotenv(env_path)
        _logger.info("已加载 .env 文件: %s", env_path)


def load_accounts(config_path: str = "config/accounts.yaml") -> list[AccountConfig]:
    """从 YAML 文件加载账号配置"""
    path = Path(config_path)
    if not path.exists():
        _logger.error("账号配置文件不存在: %s", path)
        raise FileNotFoundError(f"账号配置文件不存在: {path}")

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data or "accounts" not in data:
        _logger.error("账号配置文件格式错误: 缺少 'accounts' 键")
        raise ValueError("账号配置文件格式错误: 缺少 'accounts' 键")

    accounts = []
    for item in data["accounts"]:
        accounts.append(AccountConfig(**item))

    _logger.info("已加载 %d 个账号配置", len(accounts))
    return accounts


def get_credentials(prefix: str) -> Optional[AccountCredentials]:
    """从环境变量读取指定账号的 AK/SK

    环境变量格式: {PREFIX}_ACCESS_KEY_ID, {PREFIX}_ACCESS_KEY_SECRET
    """
    ak_id = os.environ.get(f"{prefix}_ACCESS_KEY_ID", "")
    ak_secret = os.environ.get(f"{prefix}_ACCESS_KEY_SECRET", "")

    if not ak_id or not ak_secret:
        _logger.error(
            "账号 %s 的 AK/SK 未配置，请设置环境变量 %s_ACCESS_KEY_ID 和 %s_ACCESS_KEY_SECRET",
            prefix, prefix, prefix,
        )
        return None

    return AccountCredentials(
        access_key_id=ak_id,
        access_key_secret=ak_secret,
    )


def get_database_url() -> str:
    """获取数据库 URL，默认为 SQLite 本地路径"""
    return os.environ.get(
        "ALIYUN_INVENTORY_DATABASE_URL",
        "sqlite:///data/aliyun_inventory.db",
    )
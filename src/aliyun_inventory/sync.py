"""同步引擎 — 编排各 Collector 按账号同步资源"""

import logging

from sqlalchemy.orm import Session

from .config import AccountConfig, load_accounts, get_credentials
from .aliyun_client import AliyunClientFactory
from .models import CloudAccount
from .collectors.base import BaseCollector, utcnow
from .collectors.ecs import EcsCollector
from .collectors.dns import DnsCollector
from .collectors.eip import EipCollector
from .collectors.clb import ClbCollector
from .collectors.alb import AlbCollector
from .collectors.sls import SlsCollector
from .collectors.ram import RamCollector
from .collectors.cdn import CdnCollector
from .collectors.api import ApiCollector
from .collectors.oss import OssCollector
from .collectors.rds import RdsCollector
from .collectors.waf import WafCollector
from .collectors.tair import TairCollector
from .collectors.polardb import PolarDBCollector
from .collectors.mongodb import MongoDBCollector
from .collectors.security_group import SecurityGroupCollector
from .collectors.sae import SaeCollector

logger = logging.getLogger("aliyun_inv.sync")

# Collector 注册表：资源类型 -> Collector 类
COLLECTOR_MAP: dict[str, type[BaseCollector]] = {
    "ecs": EcsCollector,
    "dns": DnsCollector,
    "eip": EipCollector,
    "clb": ClbCollector,
    "alb": AlbCollector,
    "sls": SlsCollector,
    "ram": RamCollector,
    "cdn": CdnCollector,
    "api": ApiCollector,
    "oss": OssCollector,
    "rds": RdsCollector,
    "waf": WafCollector,
    "tair": TairCollector,
    "polardb": PolarDBCollector,
    "mongodb": MongoDBCollector,
    "security_group": SecurityGroupCollector,
    "sae": SaeCollector,
}


def _upsert_account(session: Session, account: AccountConfig) -> None:
    """将账号信息写入 cloud_accounts 表"""
    unique_keys = {"name": account.name}
    values = {
        "name": account.name,
        "display_name": account.display_name,
        "credential_env_prefix": account.credential_env_prefix,
        "enabled": account.enabled,
        "updated_at": utcnow(),
    }
    existing = session.query(CloudAccount).filter_by(name=account.name).first()
    if existing:
        existing.display_name = account.display_name
        existing.credential_env_prefix = account.credential_env_prefix
        existing.enabled = account.enabled
        existing.updated_at = utcnow()
    else:
        new_account = CloudAccount(
            name=account.name,
            display_name=account.display_name,
            credential_env_prefix=account.credential_env_prefix,
            enabled=account.enabled,
        )
        session.add(new_account)
    session.flush()


def sync_account(
    account_name: str,
    session: Session,
    accounts: list[AccountConfig],
    resource_filter: str | None = None,
    region_filter: str | None = None,
) -> None:
    """同步指定账号的资源

    Args:
        account_name: 账号名称（对应 accounts.yaml 中的 name）
        session: 数据库会话
        accounts: 已加载的账号配置列表
        resource_filter: 只同步指定资源类型
        region_filter: 只同步指定地域
    """
    # 找到目标账号
    account = None
    for a in accounts:
        if a.name == account_name:
            account = a
            break

    if not account:
        logger.error("账号 %s 未在配置中找到", account_name)
        return

    if not account.enabled:
        logger.warning("账号 %s 已禁用，跳过", account_name)
        return

    # 获取 AK/SK
    credentials = get_credentials(account.credential_env_prefix)
    if not credentials:
        logger.error("账号 %s 凭据缺失，跳过", account_name)
        return

    # 写入账号信息
    _upsert_account(session, account)

    # 创建客户端工厂
    factory = AliyunClientFactory(
        ak=credentials.access_key_id,
        sk=credentials.access_key_secret,
    )

    logger.info("=" * 60)
    logger.info("开始同步账号: %s (%s)", account.display_name, account.name)
    logger.info("=" * 60)

    # 确定要同步的资源类型
    resources_to_sync = []
    for resource_type in COLLECTOR_MAP:
        if not getattr(account.resources, resource_type, False):
            continue
        if resource_filter and resource_type != resource_filter:
            continue
        resources_to_sync.append(resource_type)

    if not resources_to_sync:
        logger.warning("没有需要同步的资源类型")
        return

    logger.info("将同步: %s", ", ".join(resources_to_sync))

    # 同步统计
    synced_types = []
    failed_types = []
    total_items = 0
    error_count = 0

    # 遍历每个资源类型的 Collector
    for resource_type in resources_to_sync:
        collector_class = COLLECTOR_MAP[resource_type]
        collector = collector_class(
            session=session,
            account_config=account,
            client_factory=factory,
        )

        logger.info("── 同步 %s ──", resource_type)
        try:
            collector.collect()
            synced_types.append(resource_type)
        except Exception as e:
            failed_types.append(resource_type)
            error_count += 1
            logger.error("%s 同步失败: %s", resource_type, e, exc_info=True)
            session.rollback()
            continue

    try:
        session.commit()
    except Exception as e:
        logger.error("提交数据库失败: %s", e, exc_info=True)
        session.rollback()

    # ─── 同步统计汇总 ───
    logger.info("-" * 60)
    logger.info(
        "账号 %s 同步完成 | 成功=%s | 失败=%s | 错误=%d",
        account.display_name,
        len(synced_types),
        len(failed_types),
        error_count,
    )
    if synced_types:
        logger.info("  成功类型: %s", ", ".join(synced_types))
    if failed_types:
        logger.warning("  失败类型: %s", ", ".join(failed_types))
    logger.info("-" * 60)


def sync_all(
    session: Session,
    accounts: list[AccountConfig],
    resource_filter: str | None = None,
) -> None:
    """同步所有已启用的账号

    Args:
        session: 数据库会话
        accounts: 已加载的账号配置列表
        resource_filter: 只同步指定资源类型
    """
    enabled_accounts = [a for a in accounts if a.enabled]

    if not enabled_accounts:
        logger.warning("没有已启用的账号")
        return

    logger.info("将同步 %d 个账号", len(enabled_accounts))

    total_synced = 0
    total_failed = 0

    for account in enabled_accounts:
        sync_account(
            account_name=account.name,
            session=session,
            accounts=accounts,
            resource_filter=resource_filter,
        )

    logger.info("=" * 60)
    logger.info("所有账号同步完成")
    logger.info("=" * 60)
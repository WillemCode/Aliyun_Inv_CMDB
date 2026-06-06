"""资源类型列表查询 — 按资源类型聚合列出所有资源"""

from sqlalchemy import select, func, distinct, case
from sqlalchemy.orm import Session

from .models import (
    EcsInstance, DnsRecord, EipAddress, LoadBalancer,
    CdnDomain, WafDomain, ApiGateway, OssBucket,
    RdsInstance, TairInstance, PolarDBCluster, MongoDBInstance,
    SecurityGroup, SaeApp, SlsProject, RamUser,
)

# 合法的资源类型名称（与 COLLECTOR_MAP 一致）
VALID_RESOURCE_TYPES = [
    "ecs", "dns", "eip", "clb", "alb", "cdn", "waf", "api",
    "oss", "rds", "tair", "polardb", "mongodb", "security_group",
    "sae", "sls", "ram",
]


def list_resources(
    session: Session,
    resource_type: str,
    account_name: str = "",
    region_id: str = "",
) -> list[dict]:
    """按资源类型列出所有资源

    Args:
        session: 数据库会话
        resource_type: 资源类型名称 (ecs/dns/eip/clb/...)
        account_name: 按账户名称过滤（空字符串=全部）
        region_id: 按地域过滤（空字符串=全部）

    Returns:
        list[dict]: 资源列表，每个 dict 包含列表显示所需的关键字段
    """
    if resource_type not in VALID_RESOURCE_TYPES:
        raise ValueError(f"不支持的资源类型 '{resource_type}'，合法类型: {', '.join(VALID_RESOURCE_TYPES)}")

    handler = _TYPE_HANDLERS.get(resource_type)
    if not handler:
        raise ValueError(f"资源类型 '{resource_type}' 尚未实现列表查询")

    return handler(session, account_name, region_id)


def _apply_filters(stmt, model, account_name: str, region_id: str):
    """给查询语句添加账户和地域过滤

    account_name 支持匹配 account_name 或 account_display_name（精确或包含）
    """
    if account_name:
        name_col = getattr(model, "account_name", None)
        display_col = getattr(model, "account_display_name", None)
        if name_col is not None and display_col is not None:
            stmt = stmt.where(
                (name_col == account_name) | (display_col == account_name) |
                (name_col.contains(account_name)) | (display_col.contains(account_name))
            )
        elif name_col is not None:
            stmt = stmt.where(name_col.contains(account_name))
        elif display_col is not None:
            stmt = stmt.where(display_col.contains(account_name))
    if region_id:
        # OSS 桶的 region 字段叫 "region" 而非 "region_id"
        region_col = getattr(model, "region_id", None) or getattr(model, "region", None)
        if region_col is not None:
            stmt = stmt.where(region_col == region_id)
    return stmt


# ──────────────────────────────────────────────
# 各资源类型的查询与转换
# ──────────────────────────────────────────────

def _list_ecs(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(EcsInstance).order_by(EcsInstance.account_name, EcsInstance.region_id, EcsInstance.instance_name)
    stmt = _apply_filters(stmt, EcsInstance, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "instance_id": r.instance_id or "",
        "instance_name": r.instance_name or "",
        "status": r.status or "",
        "private_ips": r.private_ips_json if isinstance(r.private_ips_json, str) else (",".join(r.private_ips_json) if r.private_ips_json else ""),
        "public_ips": r.public_ips_json if isinstance(r.public_ips_json, str) else (",".join(r.public_ips_json) if r.public_ips_json else ""),
        "eip_address": r.eip_address or "",
    } for r in rows]


def _list_dns(session: Session, account_name: str, region_id: str) -> list[dict]:
    """DNS 域名列表 — 按域名聚合，显示每个域名的记录数和启用状态"""
    # 按域名聚合统计
    stmt = select(
        DnsRecord.account_name,
        DnsRecord.account_display_name,
        DnsRecord.domain_name,
        func.count(DnsRecord.record_id).label("total_records"),
        func.sum(case((DnsRecord.status == "ENABLE", 1), else_=0)).label("enabled_records"),
        func.sum(case((DnsRecord.status != "ENABLE", 1), else_=0)).label("disabled_records"),
    ).group_by(DnsRecord.account_name, DnsRecord.account_display_name, DnsRecord.domain_name)

    # 过滤
    if account_name:
        name_col = DnsRecord.account_name
        display_col = DnsRecord.account_display_name
        stmt = stmt.where(
            (name_col == account_name) | (display_col == account_name) |
            (name_col.contains(account_name)) | (display_col.contains(account_name))
        )

    stmt = stmt.order_by(DnsRecord.account_name, DnsRecord.domain_name)
    rows = session.execute(stmt).all()

    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "domain_name": r.domain_name or "",
        "total_records": r.total_records,
        "enabled_records": r.enabled_records,
        "disabled_records": r.disabled_records,
    } for r in rows]


def _list_eip(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(EipAddress).order_by(EipAddress.account_name, EipAddress.region_id)
    stmt = _apply_filters(stmt, EipAddress, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "allocation_id": r.allocation_id or "",
        "ip_address": r.ip_address or "",
        "status": r.status or "",
        "instance_type": r.instance_type or "",
        "instance_id": r.instance_id or "",
    } for r in rows]


def _list_clb(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(LoadBalancer).where(LoadBalancer.lb_type == "clb").order_by(LoadBalancer.account_name, LoadBalancer.region_id, LoadBalancer.lb_name)
    stmt = _apply_filters(stmt, LoadBalancer, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return _lb_rows_to_dict(rows)


def _list_alb(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(LoadBalancer).where(LoadBalancer.lb_type == "alb").order_by(LoadBalancer.account_name, LoadBalancer.region_id, LoadBalancer.lb_name)
    stmt = _apply_filters(stmt, LoadBalancer, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return _lb_rows_to_dict(rows)


def _lb_rows_to_dict(rows: list) -> list[dict]:
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "lb_id": r.lb_id or "",
        "lb_name": r.lb_name or "",
        "status": r.status or "",
        "address": r.address or "",
        "address_type": r.address_type or "",
    } for r in rows]


def _list_cdn(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(CdnDomain).order_by(CdnDomain.account_name, CdnDomain.domain_name)
    stmt = _apply_filters(stmt, CdnDomain, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "domain_name": r.domain_name or "",
        "cname": r.cname or "",
        "cdn_type": r.cdn_type or "",
        "domain_status": r.domain_status or "",
        "coverage": r.coverage or "",
        "origin_type": r.origin_type or "",
        "ssl_protocol": r.ssl_protocol or "",
    } for r in rows]


def _list_waf(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(WafDomain).order_by(WafDomain.account_name, WafDomain.domain_name)
    stmt = _apply_filters(stmt, WafDomain, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "domain_name": r.domain_name or "",
        "instance_id": r.instance_id or "",
        "cname": r.cname or "",
        "cluster_type": r.cluster_type or "",
        "access_type": r.access_type or "",
    } for r in rows]


def _list_api(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(ApiGateway).order_by(ApiGateway.account_name, ApiGateway.region_id, ApiGateway.group_name)
    stmt = _apply_filters(stmt, ApiGateway, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "api_type": r.api_type or "",
        "group_id": r.group_id or "",
        "group_name": r.group_name or "",
        "status": r.status or "",
        "sub_domain": r.sub_domain or "",
        "vpc_id": r.vpc_id or "",
    } for r in rows]


def _list_oss(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(OssBucket).order_by(OssBucket.account_name, OssBucket.bucket_name)
    stmt = _apply_filters(stmt, OssBucket, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region": r.region or "",
        "bucket_name": r.bucket_name or "",
        "storage_class": r.storage_class or "",
        "access_control": r.access_control or "",
        "creation_date": r.creation_date or "",
    } for r in rows]


def _list_rds(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(RdsInstance).order_by(RdsInstance.account_name, RdsInstance.region_id, RdsInstance.instance_name)
    stmt = _apply_filters(stmt, RdsInstance, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "instance_id": r.instance_id or "",
        "instance_name": r.instance_name or "",
        "engine": r.engine or "",
        "engine_version": r.engine_version or "",
        "status": r.status or "",
        "connection_string": r.connection_string or "",
        "public_connection_string": r.public_connection_string or "",
    } for r in rows]


def _list_tair(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(TairInstance).order_by(TairInstance.account_name, TairInstance.region_id, TairInstance.instance_name)
    stmt = _apply_filters(stmt, TairInstance, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "instance_id": r.instance_id or "",
        "instance_name": r.instance_name or "",
        "instance_type": r.instance_type or "",
        "instance_status": r.instance_status or "",
        "connection_domain": r.connection_domain or "",
        "public_domain": r.public_domain or "",
    } for r in rows]


def _list_polardb(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(PolarDBCluster).order_by(PolarDBCluster.account_name, PolarDBCluster.region_id)
    stmt = _apply_filters(stmt, PolarDBCluster, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "cluster_id": r.cluster_id or "",
        "cluster_description": r.cluster_description or "",
        "dbtype": r.dbtype or "",
        "dbversion": r.dbversion or "",
        "cluster_status": r.cluster_status or "",
        "private_connection_string": r.private_connection_string or "",
        "public_connection_string": r.public_connection_string or "",
    } for r in rows]


def _list_mongodb(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(MongoDBInstance).order_by(MongoDBInstance.account_name, MongoDBInstance.region_id)
    stmt = _apply_filters(stmt, MongoDBInstance, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "instance_id": r.instance_id or "",
        "instance_description": r.instance_description or "",
        "dbinstance_type": r.dbinstance_type or "",
        "dbinstance_status": r.dbinstance_status or "",
        "engine": r.engine or "",
        "private_connection": r.private_connection or "",
        "public_connection": r.public_connection or "",
    } for r in rows]


def _list_security_group(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(SecurityGroup).order_by(SecurityGroup.account_name, SecurityGroup.region_id, SecurityGroup.security_group_name)
    stmt = _apply_filters(stmt, SecurityGroup, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "security_group_id": r.security_group_id or "",
        "security_group_name": r.security_group_name or "",
        "security_group_type": r.security_group_type or "",
        "vpc_id": r.vpc_id or "",
        "rule_count": r.rule_count,
    } for r in rows]


def _list_sae(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(SaeApp).order_by(SaeApp.account_name, SaeApp.region_id, SaeApp.app_name)
    stmt = _apply_filters(stmt, SaeApp, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "app_id": r.app_id or "",
        "app_name": r.app_name or "",
        "programming_language": r.programming_language or "",
        "status": r.status or "",
        "running_instances": r.running_instances,
        "instance_count": r.instance_count,
        "service_url": r.service_url or "",
    } for r in rows]


def _list_sls(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(SlsProject).order_by(SlsProject.account_name, SlsProject.region_id, SlsProject.project_name)
    stmt = _apply_filters(stmt, SlsProject, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "region_id": r.region_id or "",
        "project_name": r.project_name or "",
        "description": r.description or "",
        "status": r.status or "",
    } for r in rows]


def _list_ram(session: Session, account_name: str, region_id: str) -> list[dict]:
    stmt = select(RamUser).order_by(RamUser.account_name, RamUser.user_name)
    stmt = _apply_filters(stmt, RamUser, account_name, region_id)
    rows = list(session.execute(stmt).scalars().all())
    return [{
        "account_name": r.account_name,
        "account_display_name": r.account_display_name or "",
        "user_name": r.user_name or "",
        "display_name": r.display_name or "",
        "create_date": r.create_date or "",
        "update_date": r.update_date or "",
    } for r in rows]


# 类型 → 查询函数映射
_TYPE_HANDLERS = {
    "ecs": _list_ecs,
    "dns": _list_dns,
    "eip": _list_eip,
    "clb": _list_clb,
    "alb": _list_alb,
    "cdn": _list_cdn,
    "waf": _list_waf,
    "api": _list_api,
    "oss": _list_oss,
    "rds": _list_rds,
    "tair": _list_tair,
    "polardb": _list_polardb,
    "mongodb": _list_mongodb,
    "security_group": _list_security_group,
    "sae": _list_sae,
    "sls": _list_sls,
    "ram": _list_ram,
}
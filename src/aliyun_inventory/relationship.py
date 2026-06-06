"""关系链路构建 — 发现 DNS→CDN→LB→ECS / WAF→LB→ECS / DNS→APIG→SAE 全链路关联（嵌套树结构，VPC DB 关联已移除）"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select, type_coerce, String
from sqlalchemy.orm import Session

from .models import (
    CdnDomain,
    DnsRecord,
    EcsInstance,
    EipAddress,
    IpAddress,
    LoadBalancer,
    BackendServer,
    LbForwardingRule,
    LbListener,
    OssBucket,
    RdsInstance,
    WafDomain,
    TairInstance,
    PolarDBCluster,
    MongoDBInstance,
    ApiGateway,
    ApigDomain,
    ApigRoute,
    SaeApp,
    SaeNamespace,
)


@dataclass
class ChainNode:
    """链路中的一个节点（支持嵌套树结构）"""

    account_name: str
    account_display_name: str
    resource_type: str  # dns_record / clb / alb / eip / ecs / backend / apig / apig_route / sae / nacos_service / ...
    resource_id: str
    resource_name: str
    region_id: str = ""
    ip: str = ""
    ip_type: str = ""
    role: str = ""  # 节点在链路中的角色描述（如 "CNAME→ env-xxx.alicloudapi.com"）
    extra_info: dict = field(default_factory=dict)
    children: list[ChainNode] = field(default_factory=list)  # 子节点（嵌套树）


@dataclass
class ChainResult:
    """链路发现结果（支持嵌套树结构）"""

    root_value: str
    nodes: list[ChainNode] = field(default_factory=list)
    chains: list[list[ChainNode]] = field(default_factory=list)  # 保留：兼容旧代码/JSON
    chain_trees: list[ChainNode] = field(default_factory=list)  # 嵌套树式链路根节点
    chain_types: list[str] = field(default_factory=list)  # 与 chain_trees 一一对应的类型标签
    warnings: list[str] = field(default_factory=list)


def _make_node_from_ip(ip_record: IpAddress) -> ChainNode:
    """从 ip_addresses 记录创建链路节点"""
    return ChainNode(
        account_name=ip_record.account_name,
        account_display_name=ip_record.account_display_name,
        resource_type=ip_record.resource_type,
        resource_id=ip_record.resource_id,
        resource_name=ip_record.resource_name,
        region_id=ip_record.region_id or "",
        ip=ip_record.ip,
        ip_type=ip_record.ip_type,
    )


def _find_ecs_by_id(session: Session, instance_id: str) -> Optional[EcsInstance]:
    """通过 instance_id 查找 ECS 实例"""
    stmt = select(EcsInstance).where(EcsInstance.instance_id == instance_id)
    return session.execute(stmt).scalar_one_or_none()


def _find_ecs_by_private_ip(session: Session, private_ip: str) -> list[EcsInstance]:
    """通过私网 IP 查找 ECS 实例（JSON 列模糊匹配）"""
    # SQLite 中 JSON 列需要用 type_coerce 转 String 才能 like
    stmt = select(EcsInstance).where(
        type_coerce(EcsInstance.private_ips_json, String).like(f'%{private_ip}%')
    )
    return list(session.execute(stmt).scalars().all())


def _find_dns_by_value(session: Session, value: str) -> list[DnsRecord]:
    """通过 DNS 记录值查找指向该值的 DNS 记录"""
    stmt = select(DnsRecord).where(DnsRecord.value == value)
    return list(session.execute(stmt).scalars().all())


def _find_lb_by_address(session: Session, address: str) -> list[LoadBalancer]:
    """通过 LB 地址查找负载均衡"""
    stmt = select(LoadBalancer).where(LoadBalancer.address == address)
    return list(session.execute(stmt).scalars().all())


def _find_lb_by_dns_name(session: Session, dns_name: str) -> list[LoadBalancer]:
    """通过 LB DNS 名称查找负载均衡"""
    stmt = select(LoadBalancer).where(LoadBalancer.dns_name == dns_name)
    return list(session.execute(stmt).scalars().all())


def _find_backends_by_lb_id(session: Session, lb_id: str) -> list[BackendServer]:
    """通过 LB ID 查找后端服务器"""
    stmt = select(BackendServer).where(BackendServer.lb_id == lb_id)
    return list(session.execute(stmt).scalars().all())


def _find_eip_by_ip(session: Session, ip: str) -> list[EipAddress]:
    """通过 IP 地址查找 EIP"""
    stmt = select(EipAddress).where(EipAddress.ip_address == ip)
    return list(session.execute(stmt).scalars().all())


# ──────────────────────────────────────────────
# 新增资源查找函数
# ──────────────────────────────────────────────

def _find_cdn_by_domain(session: Session, domain_name: str) -> list[CdnDomain]:
    """通过域名查找 CDN 加速域名"""
    stmt = select(CdnDomain).where(CdnDomain.domain_name == domain_name)
    return list(session.execute(stmt).scalars().all())


def _find_cdn_by_origin(session: Session, origin_address: str) -> list[CdnDomain]:
    """通过回源地址查找 CDN（回源 IP 或域名包含该地址）"""
    stmt = select(CdnDomain).where(
        type_coerce(CdnDomain.origin_address, String).like(f"%{origin_address}%")
    )
    return list(session.execute(stmt).scalars().all())


def _find_waf_by_domain(session: Session, domain_name: str) -> list[WafDomain]:
    """通过域名查找 WAF 防护域名"""
    stmt = select(WafDomain).where(WafDomain.domain_name == domain_name)
    return list(session.execute(stmt).scalars().all())


def _find_waf_by_source_ip(session: Session, ip: str) -> list[WafDomain]:
    """通过回源 IP 查找 WAF（JSON 列模糊匹配）"""
    stmt = select(WafDomain).where(
        type_coerce(WafDomain.source_ips_json, String).like(f"%{ip}%")
    )
    return list(session.execute(stmt).scalars().all())


def _find_oss_by_bucket_name(session: Session, bucket_name: str) -> list[OssBucket]:
    """通过桶名查找 OSS"""
    stmt = select(OssBucket).where(OssBucket.bucket_name == bucket_name)
    return list(session.execute(stmt).scalars().all())


def _find_rds_by_vpc(session: Session, vpc_id: str) -> list[RdsInstance]:
    """通过 VPC ID 查找 RDS 实例（同 VPC 内 ECS↔RDS 关联）"""
    stmt = select(RdsInstance).where(RdsInstance.vpc_id == vpc_id)
    return list(session.execute(stmt).scalars().all())


def _find_tair_by_vpc(session: Session, vpc_id: str) -> list[TairInstance]:
    """通过 VPC ID 查找 Tair/Redis 实例"""
    stmt = select(TairInstance).where(TairInstance.vpc_id == vpc_id)
    return list(session.execute(stmt).scalars().all())


def _find_polardb_by_vpc(session: Session, vpc_id: str) -> list[PolarDBCluster]:
    """通过 VPC ID 查找 PolarDB 集群"""
    stmt = select(PolarDBCluster).where(PolarDBCluster.vpc_id == vpc_id)
    return list(session.execute(stmt).scalars().all())


def _find_mongodb_by_vpc(session: Session, vpc_id: str) -> list[MongoDBInstance]:
    """通过 VPC ID 查找 MongoDB 实例"""
    stmt = select(MongoDBInstance).where(MongoDBInstance.vpc_id == vpc_id)
    return list(session.execute(stmt).scalars().all())


# ──────────────────────────────────────────────
# APIG 和 SAE 资源查找函数
# ──────────────────────────────────────────────

def _find_apig_by_domain(session: Session, domain_name: str) -> list[ApiGateway]:
    """通过绑定域名查找云原生 API 网关（sub_domain 匹配或 domain_names 包含）"""
    # 精确匹配 sub_domain
    stmt = select(ApiGateway).where(
        ApiGateway.api_type == "apig",
        ApiGateway.sub_domain == domain_name,
    )
    results = list(session.execute(stmt).scalars().all())
    if results:
        return results
    # 模糊搜索 sub_domain
    stmt = select(ApiGateway).where(
        ApiGateway.api_type == "apig",
        type_coerce(ApiGateway.sub_domain, String).like(f"%{domain_name}%"),
    )
    return list(session.execute(stmt).scalars().all())


def _find_apig_by_group_id(session: Session, group_id: str) -> Optional[ApiGateway]:
    """通过 group_id 查找云原生 API 网关"""
    stmt = select(ApiGateway).where(
        ApiGateway.api_type == "apig",
        ApiGateway.group_id == group_id,
    )
    return session.execute(stmt).scalar_one_or_none()


def _find_apig_by_domain_via_domains_table(session: Session, domain_name: str) -> list[ApiGateway]:
    """通过 apig_domains 表查找域名所属的 APIG 网关

    1. 在 apig_domains 表中精确匹配 domain_name
    2. 如果没有精确匹配，尝试模糊匹配
    3. 用匹配到的 gateway_id 查找 ApiGateway
    """
    # 精确匹配
    stmt = select(ApigDomain).where(ApigDomain.domain_name == domain_name)
    domains = session.execute(stmt).scalars().all()
    if not domains:
        # 模糊匹配
        stmt = select(ApigDomain).where(ApigDomain.domain_name.like(f"%{domain_name}%"))
        domains = session.execute(stmt).scalars().all()

    gateways = []
    seen = set()
    for d in domains:
        if d.gateway_id in seen:
            continue
        seen.add(d.gateway_id)
        gw = session.execute(
            select(ApiGateway).where(ApiGateway.group_id == d.gateway_id)
        ).scalar_one_or_none()
        if gw:
            gateways.append(gw)
    return gateways


def _find_routes_by_gateway_id(session: Session, gateway_id: str) -> list[ApigRoute]:
    """通过 gateway_id 查找 APIG 路由"""
    stmt = select(ApigRoute).where(ApigRoute.gateway_id == gateway_id)
    return list(session.execute(stmt).scalars().all())


def _find_sae_by_service_url(session: Session, service_url: str) -> list[SaeApp]:
    """通过 service_url 查找 SAE 应用（精确匹配或模糊匹配）"""
    # 精确匹配
    stmt = select(SaeApp).where(SaeApp.service_url == service_url)
    results = list(session.execute(stmt).scalars().all())
    if results:
        return results
    # 模糊匹配
    stmt = select(SaeApp).where(SaeApp.service_url.like(f"%{service_url}%"))
    return list(session.execute(stmt).scalars().all())


def _find_sae_by_app_name(session: Session, app_name: str) -> list[SaeApp]:
    """通过 app_name 查找 SAE 应用"""
    stmt = select(SaeApp).where(SaeApp.app_name == app_name)
    return list(session.execute(stmt).scalars().all())


def _parse_all_backends_from_route(raw_json: dict) -> list[dict]:
    """从 APIG 路由的 raw_json 中解析所有后端服务（SAE + Nacos + 其他）

    返回 [{"backend_type": "sae"/"nacos"/"unknown", "name": ..., "port": ..., "protocol": ..., "weight": ..., "sae_app_name": ..., "sae_ns_short_id": ...}, ...]
    """
    backends = raw_json.get("Backend", raw_json.get("backend", {}))
    if not isinstance(backends, dict):
        return []
    services = backends.get("Services", backends.get("services", []))
    result = []
    for svc in services:
        svc_name = svc.get("Name", svc.get("name", ""))
        svc_port = svc.get("Port", svc.get("port", ""))
        svc_protocol = svc.get("Protocol", svc.get("protocol", ""))
        svc_weight = svc.get("Weight", svc.get("weight", ""))
        svc_id = svc.get("ServiceId", svc.get("serviceId", ""))

        backend_type = "unknown"
        sae_app_name = ""
        sae_ns_short_id = ""

        if svc_name and ".svc.cluster.local" in svc_name:
            backend_type = "sae"
            first_part = svc_name.split(".")[0]
            parts = first_part.rsplit("-", 1)
            if len(parts) >= 2:
                sae_app_name = parts[0]
                sae_ns_short_id = parts[1]
            else:
                sae_app_name = first_part
        elif svc_name and ".nacos" in svc_name:
            backend_type = "nacos"

        result.append({
            "backend_type": backend_type,
            "name": svc_name,
            "port": svc_port,
            "protocol": svc_protocol,
            "weight": svc_weight,
            "service_id": svc_id,
            "sae_app_name": sae_app_name,
            "sae_ns_short_id": sae_ns_short_id,
        })
    return result


def _find_dbs_by_vpc(session: Session, vpc_id: str) -> list[ChainNode]:
    """查找同一 VPC 内的所有数据库实例（ECS↔DB / SAE↔DB 关联）"""
    db_nodes = []

    for rds in _find_rds_by_vpc(session, vpc_id):
        role = ""
        if rds.connection_string:
            role = rds.connection_string
        db_nodes.append(ChainNode(
            account_name=rds.account_name,
            account_display_name=rds.account_display_name,
            resource_type="rds",
            resource_id=rds.instance_id,
            resource_name=rds.instance_name or "",
            region_id=rds.region_id,
            role=role,
            extra_info={
                "engine": rds.engine,
                "engine_version": rds.engine_version,
                "connection_string": rds.connection_string,
                "vpc_id": rds.vpc_id,
            },
        ))

    for tair in _find_tair_by_vpc(session, vpc_id):
        role = ""
        if tair.connection_domain:
            role = tair.connection_domain
        db_nodes.append(ChainNode(
            account_name=tair.account_name,
            account_display_name=tair.account_display_name,
            resource_type="tair",
            resource_id=tair.instance_id,
            resource_name=tair.instance_name or "",
            region_id=tair.region_id,
            role=role,
            extra_info={
                "connection_domain": tair.connection_domain,
                "connection_string": tair.connection_domain,
                "engine_version": tair.engine_version,
                "vpc_id": tair.vpc_id,
            },
        ))

    for polar in _find_polardb_by_vpc(session, vpc_id):
        db_nodes.append(ChainNode(
            account_name=polar.account_name,
            account_display_name=polar.account_display_name,
            resource_type="polardb",
            resource_id=polar.cluster_id,
            resource_name=polar.cluster_description or "",
            region_id=polar.region_id,
            role=f"{polar.dbtype or ''} {polar.dbversion or ''}",
            extra_info={
                "dbtype": polar.dbtype,
                "dbversion": polar.dbversion,
                "vpc_id": polar.vpc_id,
            },
        ))

    for mongo in _find_mongodb_by_vpc(session, vpc_id):
        db_nodes.append(ChainNode(
            account_name=mongo.account_name,
            account_display_name=mongo.account_display_name,
            resource_type="mongodb",
            resource_id=mongo.instance_id,
            resource_name=mongo.instance_description or "",
            region_id=mongo.region_id,
            role=f"{mongo.engine or ''} {mongo.engine_version or ''}",
            extra_info={
                "engine": mongo.engine,
                "engine_version": mongo.engine_version,
                "vpc_id": mongo.vpc_id,
            },
        ))

    return db_nodes


def find_chain(query_value: str, session: Session, max_depth: int = 3) -> ChainResult:
    """根据查询值发现全链路关联

    链路发现逻辑：
    1. 从 ip_addresses 表找到所有匹配的 IP 记录
    2. 如果是 LB 地址 → 找后端服务器 → 找 ECS → 找同 VPC 的数据库
    3. 如果是 DNS value → 检查是否指向 CDN → 回源 → LB/ECS/OSS
    4. 如果是 CNAME → 检查是否指向 CDN → WAF → APIG → ALB → LB → ECS
    5. 检查是否是 WAF 防护域名 → 回源 → LB/ECS
    6. 递归查找，最大深度 max_depth
    7. 检查是否是 APIG 网关 → 路由 → SAE 后端
    8. 检查是否是 SAE 应用 → APIG 路由 → APIG 域名 → DNS

    Args:
        query_value: 查询值（IP、域名、资源ID等）
        session: 数据库会话
        max_depth: 最大链路深度（防止无限循环）

    Returns:
        ChainResult: 链路发现结果
    """
    result = ChainResult(root_value=query_value)

    # 第一步：从 ip_addresses 表查找所有匹配
    ip_records = _find_ips(session, query_value)

    # 为每个 IP 记录构建节点
    for ip_record in ip_records:
        node = _make_node_from_ip(ip_record)
        result.nodes.append(node)

        # 发现链路（树式）
        ip_tree = _discover_chain_from_node(node, session, max_depth)
        if ip_tree.children:
            result.chain_trees.append(ip_tree)
            result.chain_types.append("dns_to_lb")

    # 第二步：如果查询值是 DNS 记录的值（如域名指向的 IP 或 CNAME 目标）
    dns_records = _find_dns_by_value(session, query_value)
    for dns in dns_records:
        dns_node = ChainNode(
            account_name=dns.account_name,
            account_display_name=dns.account_display_name,
            resource_type="dns_record",
            resource_id=dns.record_id,
            resource_name=dns.fqdn or "",
            region_id="global",
            ip=dns.value or "",
            role=f"{dns.record_type}→{dns.value or ''}",
            ip_type="dns_value",
            extra_info={"record_type": dns.record_type, "domain_name": dns.domain_name},
        )
        result.nodes.append(dns_node)

        # DNS→下游链路（树式）
        dns_tree = _discover_chain_from_dns_value(dns, session, max_depth)
        if dns_tree.children:
            # 根据 DNS 记录类型判断链路类型
            first_type = dns_tree.children[0].resource_type
            if first_type == "cdn":
                result.chain_types.append("dns_to_cdn")
            elif first_type == "waf":
                result.chain_types.append("dns_to_waf")
            elif first_type == "apig":
                result.chain_types.append("dns_to_sae")
            elif first_type in ("clb", "alb"):
                result.chain_types.append("dns_to_lb")
            elif first_type == "eip":
                result.chain_types.append("dns_to_eip")
            elif first_type == "ecs":
                result.chain_types.append("dns_to_ecs")
            else:
                result.chain_types.append("dns_to_other")
            result.chain_trees.append(dns_tree)

    # 第二步补充：如果查询值是域名（fqdn），从该域名的 DNS 记录出发追踪链路
    fqdn_stmt = select(DnsRecord).where(DnsRecord.fqdn == query_value)
    fqdn_dns_records = list(session.execute(fqdn_stmt).scalars().all())
    seen_fqdns = {(dns.record_id, dns.fqdn) for dns in dns_records}  # 避免重复
    for dns in fqdn_dns_records:
        key = (dns.record_id, dns.fqdn)
        if key in seen_fqdns:
            continue
        seen_fqdns.add(key)
        dns_tree = _discover_chain_from_dns_value(dns, session, max_depth)
        if dns_tree.children:
            first_type = dns_tree.children[0].resource_type
            if first_type == "cdn":
                result.chain_types.append("dns_to_cdn")
            elif first_type == "waf":
                result.chain_types.append("dns_to_waf")
            elif first_type == "apig":
                result.chain_types.append("dns_to_sae")
            elif first_type in ("clb", "alb"):
                result.chain_types.append("dns_to_lb")
            elif first_type == "eip":
                result.chain_types.append("dns_to_eip")
            elif first_type == "ecs":
                result.chain_types.append("dns_to_ecs")
            else:
                result.chain_types.append("dns_to_other")
            result.chain_trees.append(dns_tree)

    # 第三步：检查是否是 CDN 域名（DNS→CDN→回源）
    cdn_domains = _find_cdn_by_domain(session, query_value)
    for cdn in cdn_domains:
        cdn_tree = _discover_chain_from_cdn(cdn, session, max_depth)
        result.chain_trees.append(cdn_tree)
        result.chain_types.append("dns_to_cdn")

    # 第四步：检查是否是 WAF 防护域名（WAF→回源→LB/ECS）
    waf_domains = _find_waf_by_domain(session, query_value)
    for waf in waf_domains:
        waf_tree = _discover_chain_from_waf(waf, session, max_depth)
        result.chain_trees.append(waf_tree)
        result.chain_types.append("dns_to_waf")

    # 第五步：如果是 IP，检查 WAF 的回源 IP 是否包含此 IP
    if ip_records:
        for ip_record in ip_records:
            waf_matches = _find_waf_by_source_ip(session, ip_record.ip)
            for waf in waf_matches:
                waf_node = ChainNode(
                    account_name=waf.account_name,
                    account_display_name=waf.account_display_name,
                    resource_type="waf",
                    resource_id=waf.domain_name,
                    resource_name=waf.domain_name,
                    region_id=waf.region_id,
                    extra_info={
                        "instance_id": waf.instance_id,
                        "cname": waf.cname,
                        "access_type": waf.access_type,
                    },
                )
                if not any(n.resource_id == waf_node.resource_id and n.resource_type == "waf" for n in result.nodes):
                    result.nodes.append(waf_node)

    # 第六步：检查 CDN 回源是否指向查询值（IP 或域名）
    cdn_by_origin = _find_cdn_by_origin(session, query_value)
    for cdn in cdn_by_origin:
        cdn_node = ChainNode(
            account_name=cdn.account_name,
            account_display_name=cdn.account_display_name,
            resource_type="cdn",
            resource_id=cdn.domain_name,
            resource_name=cdn.domain_name,
            region_id="global",
            extra_info={
                "cdn_type": cdn.cdn_type,
                "origin_type": cdn.origin_type,
                "origin_address": cdn.origin_address,
            },
        )
        if not any(n.resource_id == cdn_node.resource_id and n.resource_type == "cdn" for n in result.nodes):
            result.nodes.append(cdn_node)

    # 第七步：OSS bucket → 反向查找加速它的 CDN
    # 如果查询值是 OSS bucket name，搜索 origin_address 中包含该 bucket 的 CDN
    oss_buckets = _find_oss_by_bucket_name(session, query_value)
    for oss in oss_buckets:
        # 添加 OSS 节点到 nodes
        oss_node = ChainNode(
            account_name=oss.account_name,
            account_display_name=oss.account_display_name,
            resource_type="oss",
            resource_id=oss.bucket_name,
            resource_name=oss.bucket_name,
            region_id=oss.region,
            extra_info={
                "endpoint": oss.extranet_endpoint,
                "storage_class": oss.storage_class,
            },
        )
        if not any(n.resource_id == oss_node.resource_id and n.resource_type == "oss" for n in result.nodes):
            result.nodes.append(oss_node)

        # 查找以该 OSS bucket 为回源的 CDN（origin_address 中包含 bucket name）
        cdn_matches = _find_cdn_by_origin(session, oss.bucket_name)
        for cdn in cdn_matches:
            # 验证 CDN 回源确实指向此 bucket（避免误匹配）
            origin_str = cdn.origin_address or ""
            if oss.bucket_name in origin_str:
                # 用 _discover_chain_from_cdn 构建链路树（CDN→回源→OSS）
                cdn_tree = _discover_chain_from_cdn(cdn, session, max_depth)
                if not any(
                    t.resource_id == cdn.domain_name and t.resource_type == "cdn"
                    for t in result.chain_trees
                ):
                    result.chain_trees.append(cdn_tree)
                    result.chain_types.append("dns_to_cdn")
                    # CDN 根节点也加入 nodes
                    if not any(n.resource_id == cdn.domain_name and n.resource_type == "cdn" for n in result.nodes):
                        result.nodes.append(ChainNode(
                            account_name=cdn.account_name,
                            account_display_name=cdn.account_display_name,
                            resource_type="cdn",
                            resource_id=cdn.domain_name,
                            resource_name=cdn.domain_name,
                            region_id="global",
                            role=f"回源:{cdn.origin_type or '-'}",
                            extra_info={
                                "cdn_type": cdn.cdn_type,
                                "origin_type": cdn.origin_type,
                                "origin_address": cdn.origin_address,
                            },
                        ))

    # 第八步：检查是否是 APIG 网关域名或网关 ID（DNS→APIG→SAE）
    # 查询值可能是: APIG 的 sub_domain、自定义域名、group_id、或路由绑定的域名
    # 优先通过 apig_domains 表查找（精确+完整），再 fallback 到 sub_domain 匹配
    # 注意：如果第二步（DNS→APIG）已经发现了该网关，此处不重复
    apig_gateways = _find_apig_by_domain_via_domains_table(session, query_value)
    if not apig_gateways:
        apig_gateways = _find_apig_by_domain(session, query_value)
    for gw in apig_gateways:
        # 避免重复：检查是否已有该网关的树
        if not any(
            t.resource_id == gw.group_id and t.resource_type == "apig"
            for t in result.chain_trees
        ) and not any(
            any(c.resource_id == gw.group_id and c.resource_type == "apig" for c in t.children)
            for t in result.chain_trees
        ):
            apig_tree = _discover_chain_from_apig(gw, session, max_depth)
            result.chain_trees.append(apig_tree)
            result.chain_types.append("dns_to_sae")

    # 也按 group_id 查找（查询值可能是网关 ID）
    gw_by_id = _find_apig_by_group_id(session, query_value)
    if gw_by_id and gw_by_id not in apig_gateways:
        if not any(
            t.resource_id == gw_by_id.group_id and t.resource_type == "apig"
            for t in result.chain_trees
        ) and not any(
            any(c.resource_id == gw_by_id.group_id and c.resource_type == "apig" for c in t.children)
            for t in result.chain_trees
        ):
            apig_tree = _discover_chain_from_apig(gw_by_id, session, max_depth)
            result.chain_trees.append(apig_tree)
            result.chain_types.append("dns_to_sae")

    # 第九步：检查是否是 SAE 应用的 service_url 或 app_name
    # SAE → APIG 路由 → APIG 网关 → DNS（反向链路）
    sae_apps = _find_sae_by_service_url(session, query_value)
    for sae_app in sae_apps:
        sae_tree = _discover_chain_from_sae(sae_app, session, max_depth)
        result.chain_trees.append(sae_tree)
        result.chain_types.append("sae_to_dns")

    # 也按 app_name 查找（查询值可能是 SAE 应用名）
    if not sae_apps:
        sae_apps_by_name = _find_sae_by_app_name(session, query_value)
        for sae_app in sae_apps_by_name:
            if not any(n.resource_id == sae_app.app_id and n.resource_type == "sae" for n in result.nodes):
                sae_tree = _discover_chain_from_sae(sae_app, session, max_depth)
                result.chain_trees.append(sae_tree)
                result.chain_types.append("sae_to_dns")

    return result


def _find_ips(session: Session, query_value: str) -> list[IpAddress]:
    """从 ip_addresses 表查找匹配的 IP 记录"""
    # 精确匹配优先
    stmt = select(IpAddress).where(IpAddress.ip == query_value)
    results = list(session.execute(stmt).scalars().all())

    if not results:
        # 模糊匹配
        stmt = select(IpAddress).where(IpAddress.ip.like(f"%{query_value}%"))
        results = list(session.execute(stmt).scalars().all())

    return results


def _discover_chain_from_node(node: ChainNode, session: Session, max_depth: int, domain: str = "") -> ChainNode:
    """从单个节点出发发现链路 — 嵌套树式（原地修改 node.children）

    Args:
        domain: 查询的域名上下文，用于过滤 LB 后端。为空时不做域名过滤。
    """
    if max_depth <= 0:
        return node

    # 如果节点是负载均衡，查找后端服务器 → ECS（按 domain 过滤 + ECS 去重）
    if node.resource_type in ("clb", "alb"):
        backends = _find_backends_by_lb_id(session, node.resource_id)

        # 按域名筛选相关的 vServer group
        if domain:
            rules = session.execute(
                select(LbForwardingRule).where(
                    LbForwardingRule.lb_id == node.resource_id,
                    LbForwardingRule.domain == domain,
                )
            ).scalars().all()
            relevant_groups = set(r.vserver_group_id for r in rules if r.vserver_group_id)

            if not relevant_groups:
                listeners = session.execute(
                    select(LbListener).where(LbListener.lb_id == node.resource_id)
                ).scalars().all()
                relevant_groups = set(l.vserver_group_id for l in listeners if l.vserver_group_id)

            if relevant_groups:
                backends = [b for b in backends if b.server_group_id in relevant_groups]

        # 按 ECS instance_id 去重
        seen_ecs_ids = set()
        for backend in backends:
            if backend.backend_resource_id in seen_ecs_ids:
                continue
            seen_ecs_ids.add(backend.backend_resource_id)

            backend_node = ChainNode(
                account_name=backend.account_name,
                account_display_name=backend.account_display_name,
                resource_type="backend",
                resource_id=backend.backend_resource_id,
                resource_name=backend.backend_resource_id,
                region_id=backend.region_id,
                ip=backend.backend_ip or "",
                ip_type="backend",
                role=f"{backend.lb_type.upper()}:{backend.port}",
                extra_info={
                    "lb_id": backend.lb_id,
                    "lb_type": backend.lb_type,
                    "server_group_id": backend.server_group_id,
                    "port": backend.port,
                    "weight": backend.weight,
                },
            )

            # 继续查找后端 ECS
            ecs = _find_ecs_by_id(session, backend.backend_resource_id)
            if ecs:
                ecs_node = ChainNode(
                    account_name=ecs.account_name,
                    account_display_name=ecs.account_display_name,
                    resource_type="ecs",
                    resource_id=ecs.instance_id,
                    resource_name=ecs.instance_name or "",
                    region_id=ecs.region_id,
                    ip=backend.backend_ip or "",
                    ip_type="private",
                    role="",
                    extra_info={
                        "status": ecs.status,
                        "vpc_id": ecs.vpc_id,
                    },
                )

                # ECS 节点（VPC 关联的 DB 不再自动挂载）
                backend_node.children.append(ecs_node)

            node.children.append(backend_node)

    # 如果节点是 ECS（VPC 关联的 DB 不再自动挂载）
    if node.resource_type == "ecs":
        pass  # 不再通过 VPC 关联数据库

    # 如果节点是 EIP，查找绑定的实例
    if node.resource_type == "eip":
        eips = _find_eip_by_ip(session, node.ip)
        for eip in eips:
            if eip.instance_id:
                ecs = _find_ecs_by_id(session, eip.instance_id)
                if ecs:
                    ecs_node = ChainNode(
                        account_name=ecs.account_name,
                        account_display_name=ecs.account_display_name,
                        resource_type="ecs",
                        resource_id=ecs.instance_id,
                        resource_name=ecs.instance_name or "",
                        region_id=ecs.region_id,
                        ip=node.ip,
                        ip_type="eip",
                        role="",
                        extra_info={"vpc_id": ecs.vpc_id},
                    )

                    # ECS（VPC 关联的 DB 不再自动挂载）
                    node.children.append(ecs_node)

    # 查找哪些 DNS 记录指向该 IP
    dns_records = _find_dns_by_value(session, node.ip)
    for dns in dns_records:
        dns_node = ChainNode(
            account_name=dns.account_name,
            account_display_name=dns.account_display_name,
            resource_type="dns_record",
            resource_id=dns.record_id,
            resource_name=dns.fqdn or "",
            region_id="global",
            ip=dns.value or "",
            role=f"{dns.record_type}→{dns.value or ''}",
            ip_type="dns_value",
            extra_info={"record_type": dns.record_type},
        )
        # 避免 DNS 节点重复
        if not any(c.resource_id == dns_node.resource_id and c.resource_type == "dns_record" for c in node.children):
            node.children.append(dns_node)

    return node


def _populate_lb_children(lb_node: ChainNode, session: Session, max_depth: int, domain: str = "") -> None:
    """填充 LB 节点的子节点：后端服务器 → ECS

    Args:
        domain: 查询的域名（如 api.xiaozhenwaimai.com）。不为空时，
            通过转发规则过滤只显示该域名对应的 vServer group 后端；
            为空时（IP 查询等场景），显示所有后端但按 ECS 去重。
    """
    if max_depth <= 0:
        return

    backends = _find_backends_by_lb_id(session, lb_node.resource_id)

    # 按域名筛选相关的 vServer group
    if domain:
        rules = session.execute(
            select(LbForwardingRule).where(
                LbForwardingRule.lb_id == lb_node.resource_id,
                LbForwardingRule.domain == domain,
            )
        ).scalars().all()
        relevant_groups = set(r.vserver_group_id for r in rules if r.vserver_group_id)

        if not relevant_groups:
            # 该域名没有明确的转发规则 → 用所有监听器的默认 vserver_group
            listeners = session.execute(
                select(LbListener).where(LbListener.lb_id == lb_node.resource_id)
            ).scalars().all()
            relevant_groups = set(l.vserver_group_id for l in listeners if l.vserver_group_id)

        if relevant_groups:
            backends = [b for b in backends if b.server_group_id in relevant_groups]

    # 按 ECS instance_id 去重（同一个 ECS 只出现一次）
    seen_ecs_ids = set()
    for backend in backends:
        if backend.backend_resource_id in seen_ecs_ids:
            continue
        seen_ecs_ids.add(backend.backend_resource_id)

        backend_node = ChainNode(
            account_name=backend.account_name,
            account_display_name=backend.account_display_name,
            resource_type="backend",
            resource_id=backend.backend_resource_id,
            resource_name=backend.backend_resource_id,
            region_id=backend.region_id,
            ip=backend.backend_ip or "",
            ip_type="backend",
            role=f"{backend.lb_type.upper()}:{backend.port}",
            extra_info={
                "lb_id": backend.lb_id,
                "lb_type": backend.lb_type,
                "server_group_id": backend.server_group_id,
                "port": backend.port,
                "weight": backend.weight,
            },
        )

        # 查找后端 ECS
        ecs = _find_ecs_by_id(session, backend.backend_resource_id)
        if ecs:
            ecs_node = ChainNode(
                account_name=ecs.account_name,
                account_display_name=ecs.account_display_name,
                resource_type="ecs",
                resource_id=ecs.instance_id,
                resource_name=ecs.instance_name or "",
                region_id=ecs.region_id,
                ip=backend.backend_ip or "",
                ip_type="private",
                role="",
                extra_info={
                    "status": ecs.status,
                    "vpc_id": ecs.vpc_id,
                },
            )
            # ECS（VPC 关联的 DB 不再自动挂载）
            backend_node.children.append(ecs_node)

        lb_node.children.append(backend_node)


def _populate_ecs_reverse_lb(ecs_node: ChainNode, session: Session, max_depth: int) -> None:
    """查找哪些 LB 把该 ECS 作为后端服务器（反向链路）"""
    if max_depth <= 0:
        return

    stmt = select(BackendServer).where(BackendServer.backend_resource_id == ecs_node.resource_id)
    backends = list(session.execute(stmt).scalars().all())
    seen_lb_ids = set()
    for backend in backends:
        if backend.lb_id in seen_lb_ids:
            continue
        seen_lb_ids.add(backend.lb_id)
        lb_stmt = select(LoadBalancer).where(LoadBalancer.lb_id == backend.lb_id)
        lb = session.execute(lb_stmt).scalar_one_or_none()
        if lb:
            lb_node = ChainNode(
                account_name=lb.account_name,
                account_display_name=lb.account_display_name,
                resource_type=lb.lb_type,
                resource_id=lb.lb_id,
                resource_name=lb.lb_name or "",
                region_id=lb.region_id,
                ip=lb.address or "",
                ip_type="lb_address",
                role="反向关联（该 ECS 是此 LB 的后端）",
                extra_info={"dns_name": lb.dns_name, "address_type": lb.address_type},
                children=[],
            )
            ecs_node.children.append(lb_node)


def _discover_chain_from_dns_value(dns: DnsRecord, session: Session, max_depth: int) -> ChainNode:
    """从 DNS 记录出发发现链路（DNS→CDN→回源 / DNS→WAF→LB→ECS / DNS→LB→ECS→DB / DNS→APIG→SAE）— 嵌套树式"""
    dns_node = ChainNode(
        account_name=dns.account_name,
        account_display_name=dns.account_display_name,
        resource_type="dns_record",
        resource_id=dns.record_id,
        resource_name=dns.fqdn or "",
        region_id="global",
        ip=dns.value or "",
        role=f"{dns.record_type}→{dns.value or ''}",
        ip_type="dns_value",
        extra_info={"record_type": dns.record_type, "domain_name": dns.domain_name},
    )

    if max_depth <= 0:
        return dns_node

    value = dns.value or ""
    record_type = dns.record_type or ""

    # A/AAAA 记录：value 是 IP → 可能是 LB 地址或 ECS 公网 IP
    if record_type.upper() in ("A", "AAAA"):
        # 1. 先查公网型 CLB
        lbs = _find_lb_by_address(session, value)
        for lb in lbs:
            lb_node = ChainNode(
                account_name=lb.account_name,
                account_display_name=lb.account_display_name,
                resource_type=lb.lb_type,
                resource_id=lb.lb_id,
                resource_name=lb.lb_name or "",
                region_id=lb.region_id,
                ip=lb.address or "",
                ip_type="lb_address",
                extra_info={"dns_name": lb.dns_name, "address_type": lb.address_type},
                children=[],
            )
            # LB → 后端服务器 + ECS（按域名过滤）
            _populate_lb_children(lb_node, session, max_depth - 1, domain=dns.fqdn or "")
            dns_node.children.append(lb_node)

        # 2. 再查 EIP 表（内网型 CLB 绑定 EIP）
        eips = _find_eip_by_ip(session, value)
        for eip in eips:
            if eip.instance_type in ("SlbInstance", "NetworkSlbInstance"):
                lb_stmt = select(LoadBalancer).where(LoadBalancer.lb_id == eip.instance_id)
                lb = session.execute(lb_stmt).scalar_one_or_none()
                if lb:
                    eip_node = ChainNode(
                        account_name=eip.account_name,
                        account_display_name=eip.account_display_name,
                        resource_type="eip",
                        resource_id=eip.allocation_id,
                        resource_name=eip.allocation_id,
                        region_id=eip.region_id,
                        ip=eip.ip_address or "",
                        ip_type="eip",
                    )
                    lb_child = ChainNode(
                        account_name=lb.account_name,
                        account_display_name=lb.account_display_name,
                        resource_type=lb.lb_type,
                        resource_id=lb.lb_id,
                        resource_name=lb.lb_name or "",
                        region_id=lb.region_id,
                        ip=lb.address or "",
                        ip_type="lb_address",
                        extra_info={"dns_name": lb.dns_name},
                        children=[],
                    )
                    _populate_lb_children(lb_child, session, max_depth - 1, domain=dns.fqdn or "")
                    eip_node.children.append(lb_child)
                    dns_node.children.append(eip_node)

        # 3. 查 ECS 实例（DNS 直接指向 ECS 公网 IP，不经过 LB）
        # 从 ip_addresses 表找 ip_type=public/resource_type=ecs 的记录
        ecs_ip_stmt = select(IpAddress).where(
            IpAddress.ip == value,
            IpAddress.resource_type == "ecs",
            IpAddress.ip_type == "public",
        )
        ecs_ip_records = list(session.execute(ecs_ip_stmt).scalars().all())
        seen_ecs_ids = set()
        for ip_rec in ecs_ip_records:
            if ip_rec.resource_id in seen_ecs_ids:
                continue
            seen_ecs_ids.add(ip_rec.resource_id)
            ecs_stmt = select(EcsInstance).where(EcsInstance.instance_id == ip_rec.resource_id)
            ecs_obj = session.execute(ecs_stmt).scalar_one_or_none()
            if ecs_obj:
                ecs_node = ChainNode(
                    account_name=ecs_obj.account_name,
                    account_display_name=ecs_obj.account_display_name,
                    resource_type="ecs",
                    resource_id=ecs_obj.instance_id,
                    resource_name=ecs_obj.instance_name or "",
                    region_id=ecs_obj.region_id,
                    ip=ip_rec.ip,
                    ip_type="public",
                    role=f"公网IP {ip_rec.ip}",
                    children=[],
                )
                # ECS → 查哪些 LB 把它作为后端（反向链路）
                _populate_ecs_reverse_lb(ecs_node, session, max_depth - 1)
                dns_node.children.append(ecs_node)

    # CNAME 记录：value 是域名 → 可能指向 CDN、WAF、APIG 或 ALB
    elif record_type.upper() == "CNAME":
        # 检查是否指向 CDN
        cdn_matches = _find_cdn_by_domain(session, dns.domain_name or "")
        if cdn_matches:
            for cdn in cdn_matches:
                cdn_tree = _discover_chain_from_cdn(cdn, session, max_depth - 1)
                dns_node.children.append(cdn_tree)
        else:
            # 检查是否指向 WAF
            waf_matches = _find_waf_by_domain(session, dns.domain_name or "")
            if waf_matches:
                for waf in waf_matches:
                    waf_tree = _discover_chain_from_waf(waf, session, max_depth - 1)
                    dns_node.children.append(waf_tree)
            else:
                # 检查是否指向 APIG 网关（优先 apig_domains 表，再 fallback 到 sub_domain）
                apig_matches = _find_apig_by_domain_via_domains_table(session, value)
                if not apig_matches:
                    apig_matches = _find_apig_by_domain(session, value)
                if apig_matches:
                    for gw in apig_matches:
                        apig_tree = _discover_chain_from_apig(gw, session, max_depth - 1)
                        dns_node.children.append(apig_tree)
                else:
                    # 检查是否是 ALB 的 dns_name
                    lbs = _find_lb_by_dns_name(session, value)
                    if lbs:
                        for lb in lbs:
                            lb_node = ChainNode(
                                account_name=lb.account_name,
                                account_display_name=lb.account_display_name,
                                resource_type=lb.lb_type,
                                resource_id=lb.lb_id,
                                resource_name=lb.lb_name or "",
                                region_id=lb.region_id,
                                ip=lb.address or "",
                                ip_type="lb_address",
                                extra_info={"dns_name": lb.dns_name},
                                children=[],
                            )
                            _populate_lb_children(lb_node, session, max_depth - 1, domain=dns.fqdn or "")
                            dns_node.children.append(lb_node)
                    else:
                        # CNAME 递归追踪：CNAME 目标不是 CDN/WAF/APIG/LB，
                        # 继续查找该域名的 DNS 记录（可能是 A 记录指向 ECS/LB IP）
                        cname_dns_stmt = select(DnsRecord).where(
                            DnsRecord.fqdn == value,
                            DnsRecord.record_type.in_(["A", "AAAA", "CNAME"]),
                        )
                        cname_dns_records = list(session.execute(cname_dns_stmt).scalars().all())
                        for cname_dns in cname_dns_records:
                            sub_tree = _discover_chain_from_dns_value(cname_dns, session, max_depth - 1)
                            if sub_tree.children:
                                dns_node.children.append(sub_tree)

    return dns_node


def _discover_chain_from_cdn(cdn: CdnDomain, session: Session, max_depth: int) -> ChainNode:
    """从 CDN 域名出发发现回源链路（CDN→回源→LB/ECS/OSS）— 嵌套树式"""
    cdn_node = ChainNode(
        account_name=cdn.account_name,
        account_display_name=cdn.account_display_name,
        resource_type="cdn",
        resource_id=cdn.domain_name,
        resource_name=cdn.domain_name,
        region_id="global",
        role=f"回源:{cdn.origin_type or '-'}",
        extra_info={
            "cdn_type": cdn.cdn_type,
            "origin_type": cdn.origin_type,
            "origin_address": cdn.origin_address,
            "cname": cdn.cname,
        },
    )

    if max_depth <= 0:
        return cdn_node

    # 解析回源地址，发现目标资源
    origin_address = cdn.origin_address or ""
    origin_type = cdn.origin_type or ""

    try:
        origins = json.loads(origin_address) if origin_address else []
    except (json.JSONDecodeError, TypeError):
        origins = [origin_address] if origin_address else []

    for origin in origins:
        origin_str = str(origin)

        # IP 类回源 → 可能是 ECS 或 LB
        if origin_type in ("ipaddr", "ip") or _is_ip_like(origin_str):
            # 查找 LB
            lbs = _find_lb_by_address(session, origin_str)
            for lb in lbs:
                lb_node = ChainNode(
                    account_name=lb.account_name,
                    account_display_name=lb.account_display_name,
                    resource_type=lb.lb_type,
                    resource_id=lb.lb_id,
                    resource_name=lb.lb_name or "",
                    region_id=lb.region_id,
                    ip=lb.address or "",
                    ip_type="cdn_origin",
                    extra_info={"dns_name": lb.dns_name},
                    children=[],
                )
                _populate_lb_children(lb_node, session, max_depth - 1)
                cdn_node.children.append(lb_node)

            # 查找 EIP
            eips = _find_eip_by_ip(session, origin_str)
            for eip in eips:
                eip_node = ChainNode(
                    account_name=eip.account_name,
                    account_display_name=eip.account_display_name,
                    resource_type="eip",
                    resource_id=eip.allocation_id,
                    resource_name=eip.ip_address or "",
                    region_id=eip.region_id,
                    ip=eip.ip_address,
                    ip_type="cdn_origin",
                )
                cdn_node.children.append(eip_node)

        # 域名类回源 → 可能是 OSS bucket 域名 或 LB dns_name
        elif origin_type in ("domain", "oss"):
            # 检查是否是 OSS bucket
            oss_domain_match = origin_str.split(".")[0] if "." in origin_str else ""
            oss_buckets = _find_oss_by_bucket_name(session, oss_domain_match)
            for oss in oss_buckets:
                oss_node = ChainNode(
                    account_name=oss.account_name,
                    account_display_name=oss.account_display_name,
                    resource_type="oss",
                    resource_id=oss.bucket_name,
                    resource_name=oss.bucket_name,
                    region_id=oss.region,
                    extra_info={
                        "endpoint": oss.extranet_endpoint,
                        "storage_class": oss.storage_class,
                    },
                )
                cdn_node.children.append(oss_node)

            # 检查是否是 LB dns_name
            lbs = _find_lb_by_dns_name(session, origin_str)
            for lb in lbs:
                lb_node = ChainNode(
                    account_name=lb.account_name,
                    account_display_name=lb.account_display_name,
                    resource_type=lb.lb_type,
                    resource_id=lb.lb_id,
                    resource_name=lb.lb_name or "",
                    region_id=lb.region_id,
                    ip_type="cdn_origin",
                    extra_info={"dns_name": lb.dns_name},
                    children=[],
                )
                _populate_lb_children(lb_node, session, max_depth - 1)
                cdn_node.children.append(lb_node)

    return cdn_node


def _discover_chain_from_waf(waf: WafDomain, session: Session, max_depth: int) -> ChainNode:
    """从 WAF 防护域名出发发现回源链路（WAF→回源→LB/ECS）— 嵌套树式"""
    waf_node = ChainNode(
        account_name=waf.account_name,
        account_display_name=waf.account_display_name,
        resource_type="waf",
        resource_id=waf.domain_name,
        resource_name=waf.domain_name,
        region_id=waf.region_id,
        role=f"CNAME→{waf.cname or ''}",
        extra_info={
            "instance_id": waf.instance_id,
            "cname": waf.cname,
            "access_type": waf.access_type,
            "source_ips": waf.source_ips_json,
        },
    )

    if max_depth <= 0:
        return waf_node

    # 解析 WAF 回源 IP，发现目标资源
    source_ips_json = waf.source_ips_json or ""
    try:
        source_ips = json.loads(source_ips_json) if source_ips_json else []
    except (json.JSONDecodeError, TypeError):
        source_ips = [source_ips_json] if source_ips_json else []

    for source_ip in source_ips:
        ip_str = str(source_ip)

        # 查找 LB
        lbs = _find_lb_by_address(session, ip_str)
        for lb in lbs:
            lb_node = ChainNode(
                account_name=lb.account_name,
                account_display_name=lb.account_display_name,
                resource_type=lb.lb_type,
                resource_id=lb.lb_id,
                resource_name=lb.lb_name or "",
                region_id=lb.region_id,
                ip=lb.address or "",
                ip_type="waf_origin",
                extra_info={"dns_name": lb.dns_name},
                children=[],
            )
            _populate_lb_children(lb_node, session, max_depth - 1)
            waf_node.children.append(lb_node)

        # 查找 EIP
        eips = _find_eip_by_ip(session, ip_str)
        for eip in eips:
            eip_node = ChainNode(
                account_name=eip.account_name,
                account_display_name=eip.account_display_name,
                resource_type="eip",
                resource_id=eip.eip_id,
                resource_name=eip.eip_name or "",
                region_id=eip.region_id,
                ip=eip.ip_address,
                ip_type="waf_origin",
            )
            waf_node.children.append(eip_node)

    return waf_node


def _discover_chain_from_apig(gw: ApiGateway, session: Session, max_depth: int) -> ChainNode:
    """从云原生 API 网关出发发现链路（APIG→路由→后端(SAE/Nacos/其他)）— 嵌套树式"""
    apig_node = ChainNode(
        account_name=gw.account_name,
        account_display_name=gw.account_display_name,
        resource_type="apig",
        resource_id=gw.group_id,
        resource_name=gw.group_name or "",
        region_id=gw.region_id,
        extra_info={
            "api_type": gw.api_type,
            "base_path": gw.base_path,
            "sub_domain": gw.sub_domain,
            "status": gw.status,
            "instance_id": gw.instance_id,
            "vpc_id": gw.vpc_id,
        },
    )

    if max_depth <= 0:
        return apig_node

    # 查找该网关下的所有路由
    routes = _find_routes_by_gateway_id(session, gw.group_id)
    for rt in routes:
        raw = rt.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = {}

        all_backends = _parse_all_backends_from_route(raw)

        route_node = ChainNode(
            account_name=rt.account_name,
            account_display_name=rt.account_display_name,
            resource_type="apig_route",
            resource_id=rt.route_id,
            resource_name=rt.route_name or "",
            region_id=rt.region_id,
            role=f"{rt.path or '/'} 方法:{rt.methods or '-'} 域名:{rt.domain_names or '-'}",
            extra_info={
                "gateway_id": rt.gateway_id,
                "api_id": rt.api_id,
                "path": rt.path,
                "path_type": rt.path_type,
                "methods": rt.methods,
                "domain_names": rt.domain_names,
                "deploy_status": rt.deploy_status,
            },
        )

        # 每个后端作为路由的子节点
        for backend in all_backends:
            backend_type = backend["backend_type"]
            if backend_type == "sae" and backend["sae_app_name"]:
                sae_apps = _find_sae_by_app_name(session, backend["sae_app_name"])
                for sae_app in sae_apps:
                    sae_node = ChainNode(
                        account_name=sae_app.account_name,
                        account_display_name=sae_app.account_display_name,
                        resource_type="sae",
                        resource_id=sae_app.app_id,
                        resource_name=sae_app.app_name or "",
                        region_id=sae_app.region_id,
                        role=f"{sae_app.programming_language or '-'} :{backend['port'] or '-'} {backend['protocol'] or '-'}",
                        extra_info={
                            "app_name": sae_app.app_name,
                            "namespace_id": sae_app.namespace_id,
                            "programming_language": sae_app.programming_language,
                            "status": sae_app.status,
                            "service_url": sae_app.service_url,
                            "backend_port": backend["port"],
                            "backend_protocol": backend["protocol"],
                            "backend_weight": backend["weight"],
                            "vpc_id": sae_app.vpc_id,
                        },
                    )
                    # VPC 关联的数据库不再自动挂载（VPC 基本通用，挂载所有 DB 噪音太大）
                    route_node.children.append(sae_node)
            elif backend_type == "nacos":
                nacos_node = ChainNode(
                    account_name=gw.account_name,
                    account_display_name=gw.account_display_name,
                    resource_type="nacos_service",
                    resource_id=backend.get("service_id", ""),
                    resource_name=backend["name"],
                    region_id=gw.region_id,
                    role=f"Nacos :{backend['port'] or '-'} {backend['protocol'] or '-'}",
                    extra_info=backend,
                )
                route_node.children.append(nacos_node)
            elif backend_type == "unknown":
                other_node = ChainNode(
                    account_name=gw.account_name,
                    account_display_name=gw.account_display_name,
                    resource_type="backend_service",
                    resource_id=backend.get("service_id", ""),
                    resource_name=backend["name"] or backend.get("service_id", ""),
                    region_id=gw.region_id,
                    role=f":{backend['port'] or '-'} {backend['protocol'] or '-'}",
                    extra_info=backend,
                )
                route_node.children.append(other_node)

        # 即使没有后端也添加路由节点（有些路由可能只有空后端）
        apig_node.children.append(route_node)

    return apig_node


def _discover_chain_from_sae(sae_app: SaeApp, session: Session, max_depth: int) -> ChainNode:
    """从 SAE 应用出发发现链路（SAE→APIG路由→APIG网关→DNS）— 嵌套树式"""
    sae_node = ChainNode(
        account_name=sae_app.account_name,
        account_display_name=sae_app.account_display_name,
        resource_type="sae",
        resource_id=sae_app.app_id,
        resource_name=sae_app.app_name or "",
        region_id=sae_app.region_id,
        role=f"{sae_app.programming_language or '-'}",
        extra_info={
            "app_name": sae_app.app_name,
            "namespace_id": sae_app.namespace_id,
            "programming_language": sae_app.programming_language,
            "status": sae_app.status,
            "service_url": sae_app.service_url,
            "vpc_id": sae_app.vpc_id,
        },
    )

    if max_depth <= 0:
        return sae_node

    # VPC 关联的数据库不再自动挂载（VPC 基本通用，挂载所有 DB 噪音太大）

    # 反向查找：哪些 APIG 路由的后端指向该 SAE 应用
    stmt = select(ApigRoute).where(
        type_coerce(ApigRoute.raw_json, String).like(f"%{sae_app.app_name}%"),
    )
    routes = session.execute(stmt).scalars().all()

    for rt in routes:
        raw = rt.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = {}

        all_backends = _parse_all_backends_from_route(raw)
        matching_backends = [
            b for b in all_backends
            if b.get("sae_app_name") == sae_app.app_name
        ]
        # 也匹配 nacos 和 unknown 后端（暂不做反向查找）

        if not matching_backends:
            continue

        # 构建路由节点
        route_node = ChainNode(
            account_name=rt.account_name,
            account_display_name=rt.account_display_name,
            resource_type="apig_route",
            resource_id=rt.route_id,
            resource_name=rt.route_name or "",
            region_id=rt.region_id,
            role=f"{rt.path or '/'} 域名:{rt.domain_names or '-'}",
            extra_info={
                "gateway_id": rt.gateway_id,
                "api_id": rt.api_id,
                "path": rt.path,
                "methods": rt.methods,
                "domain_names": rt.domain_names,
                "backend_service": matching_backends[0].get("name", ""),
                "backend_port": matching_backends[0].get("port", ""),
                "backend_protocol": matching_backends[0].get("protocol", ""),
            },
        )

        # 查找所属 APIG 网关
        gw = _find_apig_by_group_id(session, rt.gateway_id)
        if gw:
            gw_node = ChainNode(
                account_name=gw.account_name,
                account_display_name=gw.account_display_name,
                resource_type="apig",
                resource_id=gw.group_id,
                resource_name=gw.group_name or "",
                region_id=gw.region_id,
                role="",
                extra_info={
                    "api_type": gw.api_type,
                    "base_path": gw.base_path,
                    "sub_domain": gw.sub_domain,
                    "status": gw.status,
                    "instance_id": gw.instance_id,
                    "vpc_id": gw.vpc_id,
                },
            )

            # DNS 记录作为网关的子节点
            # 1. 通过 sub_domain 查找 DNS
            if gw.sub_domain:
                dns_records = _find_dns_by_value(session, gw.sub_domain)
                for dns in dns_records:
                    dns_node = ChainNode(
                        account_name=dns.account_name,
                        account_display_name=dns.account_display_name,
                        resource_type="dns_record",
                        resource_id=dns.record_id,
                        resource_name=dns.fqdn or "",
                        region_id="global",
                        ip=dns.value or "",
                        role=f"{dns.record_type}→{dns.value or ''}",
                        ip_type="dns_value",
                        extra_info={"record_type": dns.record_type, "domain_name": dns.domain_name},
                    )
                    gw_node.children.append(dns_node)

            # 2. 通过 apig_domains 表查找绑定的自定义域名 → 再查找 DNS
            apig_domains_stmt = select(ApigDomain).where(
                ApigDomain.gateway_id == gw.group_id,
                ApigDomain.domain_type != "default",  # 只查自定义域名
            )
            custom_domains = session.execute(apig_domains_stmt).scalars().all()
            for ad in custom_domains:
                # 自定义域名本身可能就有 DNS 记录指向它
                dns_records = _find_dns_by_value(session, ad.domain_name)
                for dns in dns_records:
                    dns_node = ChainNode(
                        account_name=dns.account_name,
                        account_display_name=dns.account_display_name,
                        resource_type="dns_record",
                        resource_id=dns.record_id,
                        resource_name=dns.fqdn or "",
                        region_id="global",
                        ip=dns.value or "",
                        role=f"{dns.record_type}→{dns.value or ''}",
                        ip_type="dns_value",
                        extra_info={"record_type": dns.record_type, "domain_name": dns.domain_name},
                    )
                    # 避免重复
                    if not any(c.resource_id == dns_node.resource_id for c in gw_node.children):
                        gw_node.children.append(dns_node)

            route_node.children.append(gw_node)

        # 路由绑定的域名也可能有 DNS 记录（直接 DNS→路由域名）
        domain_names_str = rt.domain_names or ""
        if domain_names_str:
            for domain in domain_names_str.split(","):
                domain = domain.strip()
                if domain:
                    dns_records = _find_dns_by_value(session, domain)
                    for dns in dns_records:
                        dns_node = ChainNode(
                            account_name=dns.account_name,
                            account_display_name=dns.account_display_name,
                            resource_type="dns_record",
                            resource_id=dns.record_id,
                            resource_name=dns.fqdn or "",
                            region_id="global",
                            ip=dns.value or "",
                            role=f"{dns.record_type}→{dns.value or ''}",
                            ip_type="dns_value",
                            extra_info={"record_type": dns.record_type, "domain_name": dns.domain_name},
                        )
                        # 避免重复（检查 route_node 的所有子节点中的 gw_node 的子节点）
                        already_in_tree = False
                        for child in route_node.children:
                            if child.resource_type == "apig":
                                for gw_child in child.children:
                                    if gw_child.resource_id == dns_node.resource_id:
                                        already_in_tree = True
                                        break
                        if not already_in_tree:
                            route_node.children.append(dns_node)

        sae_node.children.append(route_node)

    return sae_node


def _is_ip_like(value: str) -> bool:
    """判断值是否像 IP 地址"""
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(ipv4_pattern, value.strip()))
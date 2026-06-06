"""查询引擎 — 通用搜索，支持按任意信息查询"""

import re
from dataclasses import dataclass, field

from sqlalchemy import select, or_, type_coerce, String
from sqlalchemy.orm import Session

from .models import (
    DnsRecord,
    EcsInstance,
    EipAddress,
    IpAddress,
    LoadBalancer,
    BackendServer,
    ResourceRaw,
    LbLogConfig,
    SlsProject,
    SlsLogstore,
    RamUser,
    RamAccessKey,
    RamUserPolicy,
    CdnDomain,
    ApiGateway,
    ApigDomain,
    ApigApi,
    ApigRoute,
    OssBucket,
    RdsInstance,
    WafDomain,
    TairInstance,
    PolarDBCluster,
    MongoDBInstance,
    SecurityGroup,
    LbListener,
    LbVServerGroup,
    LbForwardingRule,
    SaeNamespace,
    SaeApp,
)
from .relationship import find_chain, ChainNode, ChainResult


@dataclass
class QueryResult:
    """查询结果"""

    query_type: str   # ip / domain / resource / text
    query_value: str
    matched_resources: list[dict] = field(default_factory=list)  # 直接命中的本资源
    related_resources: list[dict] = field(default_factory=list)  # 通过域名/APIG关联的间接资源
    dns_records: list[dict] = field(default_factory=list)
    backends: list[dict] = field(default_factory=list)
    lb_listeners: list[dict] = field(default_factory=list)
    lb_vserver_groups: list[dict] = field(default_factory=list)
    lb_forwarding_rules: list[dict] = field(default_factory=list)
    lb_log_configs: list[dict] = field(default_factory=list)
    chains: list[list[dict]] = field(default_factory=list)  # 保留：兼容旧 JSON 输出
    chain_types: list[str] = field(default_factory=list)    # 每条链的类型标签
    chain_trees: list[dict] = field(default_factory=list)   # 嵌套树式链路（dict 格式）
    warnings: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────
# 输入分类
# ──────────────────────────────────────────────

IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$")
RESOURCE_ID_PATTERNS = {
    "ecs": re.compile(r"^i-[a-zA-Z0-9]+$"),
    "eip": re.compile(r"^eip-[a-zA-Z0-9]+$"),
    "clb": re.compile(r"^lb-[a-zA-Z0-9]+$"),
    "alb": re.compile(r"^alb-[a-zA-Z0-9]+$"),
    "security_group": re.compile(r"^sg-[a-zA-Z0-9]+$"),
    "sgp": re.compile(r"^sgp-[a-zA-Z0-9]+$"),
    "disk": re.compile(r"^d-[a-zA-Z0-9]+$"),
    "rds": re.compile(r"^rm-[a-zA-Z0-9]+$"),
    "tair": re.compile(r"^r-[a-zA-Z0-9]+$"),
    "polardb": re.compile(r"^pc-[a-zA-Z0-9]+$"),
    "mongodb": re.compile(r"^dds-[a-zA-Z0-9]+$"),
    "ram_ak": re.compile(r"^LTAI[A-Za-z0-9]{12,24}$"),  # 阿里云 AccessKey ID
    "oss_bucket": re.compile(r"^[a-z][a-z0-9\-]{2,61}$"),  # OSS bucket name pattern
}


def classify_input(value: str) -> str:
    """判断输入值的类型

    Returns:
        'ip' | 'domain' | 'resource_id' | 'text'
    """
    # IPv4
    if IPV4_PATTERN.match(value):
        return "ip"

    # IPv6（简单判断）
    if ":" in value and IPV6_PATTERN.match(value) and len(value) > 5:
        return "ip"

    # 域名
    if DOMAIN_PATTERN.match(value):
        return "domain"

    # 阿里云资源 ID
    for resource_type, pattern in RESOURCE_ID_PATTERNS.items():
        if pattern.match(value):
            return "resource_id"

    # 其他都当作自由文本搜索
    return "text"


# ──────────────────────────────────────────────
# 搜索函数
# ──────────────────────────────────────────────

def _ip_record_to_dict(ip_record: IpAddress) -> dict:
    """将 IpAddress 记录转为字典"""
    return {
        "account_name": ip_record.account_name,
        "account_display_name": ip_record.account_display_name,
        "region_id": ip_record.region_id,
        "resource_type": ip_record.resource_type,
        "resource_id": ip_record.resource_id,
        "resource_name": ip_record.resource_name,
        "ip": ip_record.ip,
        "ip_type": ip_record.ip_type,
    }


def _dns_record_to_dict(dns: DnsRecord) -> dict:
    """将 DnsRecord 转为字典"""
    # 从 raw_json 提取 weight（模型有 weight 列但可能未同步，raw_json 中有 Weight 字段）
    weight = dns.weight
    if weight is None and dns.raw_json:
        raw = dns.raw_json if isinstance(dns.raw_json, dict) else {}
        weight = raw.get("Weight", raw.get("weight", None))

    line = dns.line
    if line is None and dns.raw_json:
        raw = dns.raw_json if isinstance(dns.raw_json, dict) else {}
        line = raw.get("Line", raw.get("line", None))

    return {
        "account_name": dns.account_name,
        "account_display_name": dns.account_display_name,
        "resource_type": "dns",
        "resource_id": dns.record_id,
        "region_id": "global",
        "fqdn": dns.fqdn,
        "domain_name": dns.domain_name,
        "rr": dns.rr,
        "record_type": dns.record_type,
        "value": dns.value,
        "ttl": dns.ttl,
        "status": dns.status,
        "line": line or "",
        "weight": weight,
    }


def _ecs_to_dict(ecs: EcsInstance) -> dict:
    """将 EcsInstance 转为字典"""
    private_ips = ecs.private_ips_json or []
    public_ips = ecs.public_ips_json or []
    eip = ecs.eip_address or ""

    # 选择最佳展示 IP：公网优先，其次 EIP，最后私网
    display_ip = ""
    ip_type_label = ""
    if public_ips:
        display_ip = public_ips[0]
        ip_type_label = "public"
    elif eip:
        display_ip = eip
        ip_type_label = "eip"
    elif private_ips:
        display_ip = private_ips[0]
        ip_type_label = "private"

    # 内网地址：所有私网 IP
    private_addr = ", ".join(private_ips) if private_ips else ""
    # 外网地址：公网 IP + EIP
    public_parts = list(public_ips)
    if eip and eip not in public_parts:
        public_parts.append(eip)
    public_addr = ", ".join(public_parts) if public_parts else ""

    # 从 raw_json 提取安全组信息
    raw_json = ecs.raw_json or {}
    if isinstance(raw_json, str):
        import json
        raw_json = json.loads(raw_json)

    security_groups = []
    security_groups_display = ""
    for sg in raw_json.get("SecurityGroups", []) or []:
        sg_id = sg.get("SecurityGroupId", "")
        sg_name = sg.get("SecurityGroupName", "")
        sg_type = sg.get("SecurityGroupType", "")
        sg_desc = sg.get("Description", "")
        sg_vpc = sg.get("VpcId", "")
        security_groups.append({
            "security_group_id": sg_id,
            "security_group_name": sg_name,
            "security_group_type": sg_type,
            "description": sg_desc,
            "vpc_id": sg_vpc,
        })
    if security_groups:
        sg_lines = []
        for sg in security_groups:
            name_part = f" ({sg['security_group_name']})" if sg['security_group_name'] else ""
            type_part = f" [{sg['security_group_type']}]" if sg['security_group_type'] else ""
            sg_lines.append(f"{sg['security_group_id']}{name_part}{type_part}")
        security_groups_display = "\n".join(sg_lines)

    # 从 raw_json 提取磁盘信息
    disks = []
    disks_display = ""
    for d in raw_json.get("Disks", []) or []:
        disk_id = d.get("DiskId", "")
        disk_type = d.get("Type", "")         # system / data
        disk_category = d.get("Category", "") # cloud_essd / cloud_ssd etc.
        disk_size = d.get("Size", 0)          # GB
        disk_device = d.get("Device", "")     # /dev/xvda
        disk_name = d.get("DiskName", "")
        disk_dwi = d.get("DeleteWithInstance", False)
        disk_encrypted = d.get("Encrypted", False)
        disk_pl = d.get("PerformanceLevel", "")
        disk_charge = d.get("DiskChargeType", "")
        disks.append({
            "disk_id": disk_id,
            "type": disk_type,
            "category": disk_category,
            "size": disk_size,
            "device": disk_device,
            "disk_name": disk_name,
            "delete_with_instance": disk_dwi,
            "encrypted": disk_encrypted,
            "performance_level": disk_pl,
            "disk_charge_type": disk_charge,
        })
    if disks:
        disk_lines = []
        for dk in disks:
            # 格式: disk_id | system/data | 类别 | 大小GB | 设备 | 随实例删除 | 加密 | PL | 付费类型
            name_part = f" ({dk['disk_name']})" if dk['disk_name'] else ""
            dwi_str = "随实例删除" if dk['delete_with_instance'] else "独立保留"
            enc_str = "加密" if dk['encrypted'] else ""
            pl_str = dk['performance_level'] if dk['performance_level'] else ""
            charge_str = dk['disk_charge_type'] if dk['disk_charge_type'] else ""
            parts = [
                f"{dk['disk_id']}{name_part}",
                dk['type'],
                dk['category'],
                f"{dk['size']}GB",
                dk['device'],
            ]
            extras = [dwi_str, enc_str, pl_str, charge_str]
            parts.extend([e for e in extras if e])
            disk_lines.append(" | ".join(parts))
        disks_display = "\n".join(disk_lines)

    return {
        "account_name": ecs.account_name,
        "account_display_name": ecs.account_display_name,
        "region_id": ecs.region_id,
        "zone_id": ecs.zone_id,
        "resource_type": "ecs",
        "resource_id": ecs.instance_id,
        "instance_id": ecs.instance_id,
        "instance_name": ecs.instance_name,
        "status": ecs.status,
        "vpc_id": ecs.vpc_id,
        "ip": display_ip,
        "ip_type": ip_type_label,
        "private_address": private_addr,
        "public_address": public_addr,
        "private_ips": private_ips,
        "public_ips": public_ips,
        "eip_address": eip,
        "nat_ip_address": ecs.nat_ip_address,
        "security_groups": security_groups,
        "security_groups_display": security_groups_display,
        "disks": disks,
        "disks_display": disks_display,
    }


def _sg_to_dict(sg: SecurityGroup) -> dict:
    """将 SecurityGroup 转为字典（含规则列表）"""
    raw_json = sg.raw_json or {}
    if isinstance(raw_json, str):
        import json
        raw_json = json.loads(raw_json)

    # 提取规则列表
    rules = []
    for perm in raw_json.get("Permissions", []) or []:
        direction = perm.get("Direction", "")
        source = perm.get("SourceCidrIp", "") or perm.get("SourceGroupId", "")
        dest = perm.get("DestCidrIp", "") or perm.get("DestGroupId", "")
        # ingress 显示源地址，egress 显示目标地址
        address = source if direction == "ingress" else dest
        rules.append({
            "direction": direction,
            "policy": perm.get("Policy", ""),
            "ip_protocol": perm.get("IpProtocol", ""),
            "port_range": perm.get("PortRange", ""),
            "address": address,
            "source_cidr_ip": perm.get("SourceCidrIp", ""),
            "dest_cidr_ip": perm.get("DestCidrIp", ""),
            "source_group_id": perm.get("SourceGroupId", ""),
            "dest_group_id": perm.get("DestGroupId", ""),
            "priority": perm.get("Priority", ""),
            "description": perm.get("Description", ""),
            "nic_type": perm.get("NicType", ""),
            "security_group_rule_id": perm.get("SecurityGroupRuleId", ""),
        })

    # 规则展示文本
    rules_display = ""
    if rules:
        rule_lines = []
        for r in rules:
            dir_label = "入" if r["direction"] == "ingress" else "出"
            policy_label = r["policy"]
            proto = r["ip_protocol"]
            port = r["port_range"]
            addr = r["address"] or "全部"
            pri = r["priority"]
            desc = r["description"]
            parts = [f"{dir_label}/{policy_label}", proto, port, addr]
            if pri:
                parts.append(f"P{pri}")
            if desc:
                parts.append(desc)
            rule_lines.append(" | ".join(parts))
        rules_display = "\n".join(rule_lines)

    return {
        "account_name": sg.account_name,
        "account_display_name": sg.account_display_name,
        "region_id": sg.region_id,
        "resource_type": "security_group",
        "resource_id": sg.security_group_id,
        "security_group_id": sg.security_group_id,
        "security_group_name": sg.security_group_name,
        "security_group_type": sg.security_group_type,
        "description": sg.description,
        "vpc_id": sg.vpc_id,
        "inner_access_policy": sg.inner_access_policy,
        "rule_count": sg.rule_count,
        "rules": rules,
        "rules_display": rules_display,
    }


def _eip_to_dict(eip: EipAddress) -> dict:
    """将 EipAddress 转为字典"""
    return {
        "account_name": eip.account_name,
        "account_display_name": eip.account_display_name,
        "resource_type": "eip",
        "resource_id": eip.allocation_id,
        "region_id": eip.region_id,
        "allocation_id": eip.allocation_id,
        "ip_address": eip.ip_address,
        "status": eip.status,
        "instance_type": eip.instance_type,
        "instance_id": eip.instance_id,
    }


def _lb_to_dict(lb: LoadBalancer) -> dict:
    """将 LoadBalancer 转为字典"""
    return {
        "account_name": lb.account_name,
        "account_display_name": lb.account_display_name,
        "resource_type": lb.lb_type,  # "clb" / "alb"
        "resource_id": lb.lb_id,
        "lb_type": lb.lb_type,
        "region_id": lb.region_id,
        "lb_id": lb.lb_id,
        "lb_name": lb.lb_name,
        "status": lb.status,
        "address": lb.address,
        "address_type": lb.address_type,
        "dns_name": lb.dns_name,
        "vpc_id": lb.vpc_id,
    }


def _enrich_lb_with_eip(session: Session, lb_dict: dict) -> dict:
    """为 LB 字典补充 EIP 和正确的 private/public 地址

    对于 address_type=intranet 的 CLB:
    - address 是私网 IP，应归入内网地址
    - 公网 IP 来自绑定的 EIP（instance_type='SlbInstance'）

    对于 address_type=internet 的 CLB:
    - address 是公网 VIP，归入外网地址
    """
    lb_id = lb_dict.get("lb_id", "")
    address_type = lb_dict.get("address_type", "")
    address = lb_dict.get("address", "")
    dns_name = lb_dict.get("dns_name", "") or ""

    # 查找绑定到该 LB 的 EIP
    lb_eip = ""
    eip_stmt = select(EipAddress).where(
        EipAddress.instance_id == lb_id,
        EipAddress.instance_type == "SlbInstance",
    )
    eip_obj = session.execute(eip_stmt).scalar_one_or_none()
    if eip_obj:
        lb_eip = eip_obj.ip_address or ""
    lb_dict["eip_address"] = lb_eip

    # 根据 address_type 决定 private/public 地址
    if address_type == "intranet":
        lb_dict["private_address"] = address
        lb_dict["public_address"] = lb_eip or dns_name
    else:
        # CLB: address 是公网 VIP; ALB: address 为空，通过 dns_name 提供访问
        lb_dict["private_address"] = dns_name
        lb_dict["public_address"] = address or dns_name

    return lb_dict


def _backend_to_dict(backend: BackendServer) -> dict:
    """将 BackendServer 转为字典"""
    return {
        "account_name": backend.account_name,
        "account_display_name": backend.account_display_name,
        "resource_type": "backend",
        "lb_type": backend.lb_type,
        "region_id": backend.region_id,
        "lb_id": backend.lb_id,
        "server_group_id": backend.server_group_id,
        "backend_resource_id": backend.backend_resource_id,
        "backend_ip": backend.backend_ip,
        "port": backend.port,
        "weight": backend.weight,
    }


def _chain_node_to_dict(node: ChainNode) -> dict:
    """将 ChainNode 转为字典（含 role 和 children 递归）"""
    result = {
        "account_name": node.account_name,
        "account_display_name": node.account_display_name,
        "resource_type": node.resource_type,
        "resource_id": node.resource_id,
        "resource_name": node.resource_name,
        "region_id": node.region_id,
        "ip": node.ip,
        "ip_type": node.ip_type,
        "role": node.role,
        "children": [_chain_node_to_dict(c) for c in node.children],
    }
    if node.extra_info:
        result["extra_info"] = node.extra_info
    return result


def _ram_user_to_dict(ram_user: RamUser) -> dict:
    """将 RamUser 转为字典"""
    return {
        "account_name": ram_user.account_name,
        "account_display_name": ram_user.account_display_name,
        "resource_type": "ram_user",
        "resource_id": ram_user.user_id,
        "region_id": "global",
        "user_name": ram_user.user_name,
        "user_id": ram_user.user_id,
        "display_name": ram_user.display_name,
        "create_time": ram_user.create_date,
        "update_time": ram_user.update_date,
        "last_login_time": getattr(ram_user, "last_login_time", ""),
        "mfa_enabled": getattr(ram_user, "mfa_enabled", ""),
    }


def _ram_ak_to_dict(ram_ak: RamAccessKey) -> dict:
    """将 RamAccessKey 转为字典"""
    return {
        "account_name": ram_ak.account_name,
        "account_display_name": ram_ak.account_display_name,
        "resource_type": "ram_ak",
        "resource_id": ram_ak.access_key_id,
        "region_id": "global",
        "user_name": ram_ak.user_name,
        "access_key_id": ram_ak.access_key_id,
        "status": ram_ak.status,
        "create_time": ram_ak.create_date,
        "ak_name": ram_ak.ak_name,
        "expiration_time": ram_ak.expiration_time,
        "last_used_date": ram_ak.last_used_date or "",
    }


def _ram_policy_to_dict(ram_policy: RamUserPolicy) -> dict:
    """将 RamUserPolicy 转为字典"""
    return {
        "account_name": ram_policy.account_name,
        "account_display_name": ram_policy.account_display_name,
        "resource_type": "ram_user_policy",
        "resource_id": f"{ram_policy.user_name}/{ram_policy.policy_name}",
        "region_id": "global",
        "user_name": ram_policy.user_name,
        "policy_name": ram_policy.policy_name,
        "policy_type": ram_policy.policy_type,
        "description": ram_policy.description,
        "default_version": ram_policy.default_version,
        "attach_date": ram_policy.attach_date,
    }


def _cdn_to_dict(cdn: CdnDomain) -> dict:
    """将 CdnDomain 转为字典"""
    return {
        "account_name": cdn.account_name,
        "account_display_name": cdn.account_display_name,
        "resource_type": "cdn",
        "resource_id": cdn.domain_name,
        "region_id": "global",
        "domain_name": cdn.domain_name,
        "cdn_type": cdn.cdn_type,
        "domain_status": cdn.domain_status,
        "origin_type": cdn.origin_type,
        "origin_address": cdn.origin_address,
        "cname": cdn.cname,
        "coverage": cdn.coverage,
        "ssl_protocol": cdn.ssl_protocol,
    }


def _api_gateway_to_dict(api_gw: ApiGateway) -> dict:
    """将 ApiGateway 转为字典"""
    d = {
        "account_name": api_gw.account_name,
        "account_display_name": api_gw.account_display_name,
        "resource_type": "api_gateway",
        "resource_id": api_gw.group_id,
        "region_id": api_gw.region_id,
        "api_type": api_gw.api_type,
        "group_id": api_gw.group_id,
        "group_name": api_gw.group_name,
        "description": api_gw.description,
        "base_path": api_gw.base_path,
        "sub_domain": api_gw.sub_domain,
        "status": api_gw.status,
        "instance_id": api_gw.instance_id,
        "vpc_id": api_gw.vpc_id,
    }

    # 云原生 API 网关 (APIG): 从 raw_json 提取公网/内网地址
    if api_gw.api_type == "apig" and api_gw.raw_json:
        raw = api_gw.raw_json if isinstance(api_gw.raw_json, dict) else {}
        load_balancers = raw.get("LoadBalancers", []) or raw.get("loadBalancers", [])
        public_ips = []
        private_ips = []
        for lb in load_balancers:
            addr_type = lb.get("AddressType", lb.get("addressType", ""))
            ipv4 = lb.get("Ipv4Addresses", lb.get("IPv4Addresses", lb.get("ipv_4Addresses", lb.get("ipv4Addresses", []))))
            if addr_type == "Internet":
                public_ips.extend(ipv4)
            elif addr_type == "Intranet":
                private_ips.extend(ipv4)
        d["public_address"] = ", ".join(public_ips) if public_ips else ""
        d["private_address"] = ", ".join(private_ips) if private_ips else ""

        # 提取接入域名 (sub_domain_infos)
        sdi_list = raw.get("SubDomainInfos", raw.get("subDomainInfos", []))
        public_domains = [s.get("Name", s.get("name", "")) for s in sdi_list
                         if s.get("NetworkType", s.get("networkType", "")) == "Internet"]
        private_domains = [s.get("Name", s.get("name", "")) for s in sdi_list
                          if s.get("NetworkType", s.get("networkType", "")) == "Intranet"]
        d["public_domain"] = ", ".join(public_domains) if public_domains else ""
        d["private_domain"] = ", ".join(private_domains) if private_domains else ""

    return d


def _apig_domain_to_dict(dm: ApigDomain) -> dict:
    """将 ApigDomain 转为字典"""
    return {
        "account_name": dm.account_name,
        "account_display_name": dm.account_display_name,
        "region_id": dm.region_id,
        "gateway_id": dm.gateway_id,
        "domain_id": dm.domain_id,
        "domain_name": dm.domain_name,
        "domain_type": dm.domain_type,
        "network_type": dm.network_type,
        "protocol": dm.protocol,
        "cert_identifier": dm.cert_identifier or "",
        "force_https": dm.force_https,
        "status": dm.status or "",
    }


def _apig_api_to_dict(api: ApigApi) -> dict:
    """将 ApigApi 转为字典"""
    return {
        "account_name": api.account_name,
        "account_display_name": api.account_display_name,
        "region_id": api.region_id,
        "gateway_id": api.gateway_id,
        "api_id": api.api_id,
        "api_name": api.api_name,
        "api_type": api.api_type or "",
        "base_path": api.base_path or "",
        "description": api.description or "",
    }


def _apig_route_to_dict(rt: ApigRoute) -> dict:
    """将 ApigRoute 转为字典"""
    d = {
        "account_name": rt.account_name,
        "account_display_name": rt.account_display_name,
        "region_id": rt.region_id,
        "gateway_id": rt.gateway_id,
        "api_id": rt.api_id,
        "route_id": rt.route_id,
        "route_name": rt.route_name,
        "path": rt.path,
        "path_type": rt.path_type or "",
        "methods": rt.methods or [],
        "domain_names": rt.domain_names or "",
        "description": rt.description or "",
        "deploy_status": rt.deploy_status or "",
    }

    # 从 raw_json 解析 SAE 后端信息
    raw = rt.raw_json if isinstance(rt.raw_json, dict) else {}
    backends = raw.get("Backend", raw.get("backend", {}))
    if isinstance(backends, dict):
        services = backends.get("Services", backends.get("services", []))
        sae_backends = []
        for svc in services:
            svc_name = svc.get("Name", svc.get("name", ""))
            if svc_name and ".svc.cluster.local" in svc_name:
                # 解析 SAE 后端格式:
                # {app_name}-{namespace_short_id}.sl-{uid}-{region}-{namespace_short_id}.svc.cluster.local
                # 或简化格式: {app_name}.{namespace_short_id}.svc.cluster.local.{region}
                first_part = svc_name.split(".")[0]
                # 提取 namespace_short_id: 最后一个 - 后的部分
                parts = first_part.rsplit("-", 1)
                if len(parts) >= 2:
                    sae_app_name = parts[0]
                    sae_ns_short_id = parts[1]
                else:
                    sae_app_name = first_part
                    sae_ns_short_id = ""
                sae_backends.append({
                    "sae_app_name": sae_app_name,
                    "sae_ns_short_id": sae_ns_short_id,
                    "backend_service": svc_name,
                })
        if sae_backends:
            d["sae_backends"] = sae_backends

    return d


def _sae_namespace_to_dict(ns: SaeNamespace) -> dict:
    """将 SaeNamespace 转为字典"""
    return {
        "account_name": ns.account_name,
        "account_display_name": ns.account_display_name,
        "region_id": ns.region_id,
        "resource_type": "sae_namespace",
        "resource_id": ns.namespace_id,
        "namespace_id": ns.namespace_id,
        "namespace_short_id": ns.namespace_short_id or "",
        "namespace_name": ns.namespace_name or "",
        "namespace_description": ns.namespace_description or "",
        "vpc_id": ns.vpc_id or "",
        "tenant_id": ns.tenant_id or "",
    }


def _sae_app_to_dict(app: SaeApp) -> dict:
    """将 SaeApp 转为字典"""
    return {
        "account_name": app.account_name,
        "account_display_name": app.account_display_name,
        "region_id": app.region_id,
        "resource_type": "sae",
        "resource_id": app.app_id,
        "namespace_id": app.namespace_id,
        "namespace_name": "",  # 不在 sae_apps 表中，需要关联查后补充
        "app_id": app.app_id,
        "app_name": app.app_name or "",
        "app_type": app.app_type or "",
        "programming_language": app.programming_language or "",
        "status": app.status or "",
        "running_instances": app.running_instances,
        "instance_count": app.instance_count,
        "cpu": app.cpu,
        "memory": app.memory,
        "image_url": app.image_url or "",
        "app_description": app.app_description or "",
        "vpc_id": app.vpc_id or "",
        "service_url": app.service_url or "",
    }


def _oss_to_dict(oss: OssBucket) -> dict:
    """将 OssBucket 转为字典"""
    return {
        "account_name": oss.account_name,
        "account_display_name": oss.account_display_name,
        "resource_type": "oss",
        "resource_id": oss.bucket_name,
        "region_id": oss.region,
        "bucket_name": oss.bucket_name,
        "endpoint": oss.extranet_endpoint,
        "intranet_endpoint": oss.intranet_endpoint,
        "storage_class": oss.storage_class,
        "acl": oss.access_control,
    }


def _rds_to_dict(rds: RdsInstance) -> dict:
    """将 RdsInstance 转为字典"""
    # 内网连接地址 + 端口
    private_addr = ""
    if rds.connection_string:
        private_addr = f"{rds.connection_string}:{rds.port}" if rds.port else rds.connection_string

    # 外网连接地址 + 端口
    public_addr = ""
    if rds.public_connection_string:
        public_addr = f"{rds.public_connection_string}:{rds.public_port}" if rds.public_port else rds.public_connection_string

    return {
        "account_name": rds.account_name,
        "account_display_name": rds.account_display_name,
        "resource_type": "rds",
        "resource_id": rds.instance_id,
        "region_id": rds.region_id,
        "zone_id": rds.zone_id,
        "instance_id": rds.instance_id,
        "instance_name": rds.instance_name,
        "engine": rds.engine,
        "engine_version": rds.engine_version,
        "instance_type": rds.instance_type,
        "instance_class": rds.instance_class,
        "instance_status": rds.status,
        "connection_string": rds.connection_string,
        "port": rds.port,
        "public_connection_string": rds.public_connection_string,
        "public_port": rds.public_port,
        "private_address": private_addr,
        "public_address": public_addr,
        "vpc_id": rds.vpc_id,
        "vswitch_id": rds.vswitch_id,
        "category": rds.category,
    }


def _waf_to_dict(waf: WafDomain) -> dict:
    """将 WafDomain 转为字典"""
    return {
        "account_name": waf.account_name,
        "account_display_name": waf.account_display_name,
        "resource_type": "waf",
        "resource_id": waf.domain_name,
        "region_id": waf.region_id,
        "domain_name": waf.domain_name,
        "instance_id": waf.instance_id,
        "cname": waf.cname,
        "cluster_type": waf.cluster_type,
        "access_type": waf.access_type,
        "http_port": waf.http_port,
        "https_port": waf.https_port,
        "source_ips": waf.source_ips_json,
    }


def _tair_to_dict(tair: TairInstance) -> dict:
    """将 TairInstance 转为字典"""
    # 内网连接域名 + 端口
    private_addr = ""
    if tair.connection_domain:
        private_addr = f"{tair.connection_domain}:{tair.port}" if tair.port else tair.connection_domain

    # 外网连接域名 + 端口
    public_addr = ""
    if tair.public_domain:
        public_addr = f"{tair.public_domain}:{tair.public_port}" if tair.public_port else tair.public_domain

    return {
        "account_name": tair.account_name,
        "account_display_name": tair.account_display_name,
        "resource_type": "tair",
        "resource_id": tair.instance_id,
        "region_id": tair.region_id,
        "zone_id": tair.zone_id,
        "instance_id": tair.instance_id,
        "instance_name": tair.instance_name,
        "instance_type": tair.instance_type,
        "instance_class": tair.instance_class,
        "instance_status": tair.instance_status,
        "engine_version": tair.engine_version,
        "connection_domain": tair.connection_domain,
        "port": tair.port,
        "public_domain": tair.public_domain,
        "public_port": tair.public_port,
        "private_address": private_addr,
        "public_address": public_addr,
        "bandwidth": tair.bandwidth,
        "capacity": tair.capacity,
        "vpc_id": tair.vpc_id,
        "vswitch_id": tair.vswitch_id,
        "charge_type": tair.charge_type,
    }


def _polardb_to_dict(polardb: PolarDBCluster) -> dict:
    """将 PolarDBCluster 转为字典"""
    # 内网连接地址 + 端口
    private_addr = ""
    if polardb.private_connection_string:
        private_addr = f"{polardb.private_connection_string}:{polardb.connection_port}" if polardb.connection_port else polardb.private_connection_string

    # 外网连接地址 + 端口
    public_addr = ""
    if polardb.public_connection_string:
        public_addr = f"{polardb.public_connection_string}:{polardb.connection_port}" if polardb.connection_port else polardb.public_connection_string

    return {
        "account_name": polardb.account_name,
        "account_display_name": polardb.account_display_name,
        "resource_type": "polardb",
        "resource_id": polardb.cluster_id,
        "region_id": polardb.region_id,
        "zone_id": polardb.zone_id,
        "cluster_id": polardb.cluster_id,
        "cluster_description": polardb.cluster_description,
        "dbtype": polardb.dbtype,
        "dbversion": polardb.dbversion,
        "engine": polardb.engine,
        "category": polardb.category,
        "cluster_status": polardb.cluster_status,
        "vpc_id": polardb.vpc_id,
        "vswitch_id": polardb.vswitch_id,
        "pay_type": polardb.pay_type,
        "private_connection_string": polardb.private_connection_string,
        "public_connection_string": polardb.public_connection_string,
        "connection_port": polardb.connection_port,
        "private_address": private_addr,
        "public_address": public_addr,
        "cpu_cores": polardb.cpu_cores,
        "memory_size": polardb.memory_size,
    }


def _mongodb_to_dict(mongodb: MongoDBInstance) -> dict:
    """将 MongoDBInstance 转为字典"""
    # 内网连接地址 + 端口
    private_addr = ""
    if mongodb.private_connection:
        private_addr = f"{mongodb.private_connection}:{mongodb.connection_port}" if mongodb.connection_port else mongodb.private_connection

    # 外网连接地址 + 端口
    public_addr = ""
    if mongodb.public_connection:
        public_addr = f"{mongodb.public_connection}:{mongodb.connection_port}" if mongodb.connection_port else mongodb.public_connection

    return {
        "account_name": mongodb.account_name,
        "account_display_name": mongodb.account_display_name,
        "resource_type": "mongodb",
        "resource_id": mongodb.instance_id,
        "region_id": mongodb.region_id,
        "zone_id": mongodb.zone_id,
        "instance_id": mongodb.instance_id,
        "instance_description": mongodb.instance_description,
        "dbinstance_type": mongodb.dbinstance_type,
        "dbinstance_class": mongodb.dbinstance_class,
        "dbinstance_status": mongodb.dbinstance_status,
        "engine": mongodb.engine,
        "engine_version": mongodb.engine_version,
        "network_type": mongodb.network_type,
        "vpc_id": mongodb.vpc_id,
        "charge_type": mongodb.charge_type,
        "storage_type": mongodb.storage_type,
        "private_connection": mongodb.private_connection,
        "public_connection": mongodb.public_connection,
        "connection_port": mongodb.connection_port,
        "private_address": private_addr,
        "public_address": public_addr,
    }


def _sls_project_to_dict(sls: SlsProject) -> dict:
    """将 SlsProject 转为字典"""
    return {
        "account_name": sls.account_name,
        "account_display_name": sls.account_display_name,
        "resource_type": "sls_project",
        "resource_id": sls.project_name,
        "resource_name": sls.project_name,
        "region_id": sls.region_id,
        "project_name": sls.project_name,
        "description": sls.description,
        "status": sls.status,
    }


def _lb_listener_to_dict(listener: LbListener) -> dict:
    """将 LbListener 转为字典"""
    return {
        "account_name": listener.account_name,
        "account_display_name": listener.account_display_name,
        "resource_type": "lb_listener",
        "resource_id": f"{listener.lb_id}:{listener.listener_port}:{listener.listener_protocol}",
        "region_id": listener.region_id,
        "lb_type": listener.lb_type,
        "lb_id": listener.lb_id,
        "listener_port": listener.listener_port,
        "listener_protocol": listener.listener_protocol,
        "backend_server_port": listener.backend_server_port,
        "vserver_group_id": listener.vserver_group_id,
        "status": listener.status,
        "description": listener.description,
    }


def _lb_vserver_group_to_dict(vsg: LbVServerGroup) -> dict:
    """将 LbVServerGroup 转为字典"""
    return {
        "account_name": vsg.account_name,
        "account_display_name": vsg.account_display_name,
        "resource_type": "lb_vserver_group",
        "resource_id": vsg.vserver_group_id,
        "region_id": vsg.region_id,
        "lb_type": vsg.lb_type,
        "lb_id": vsg.lb_id,
        "vserver_group_id": vsg.vserver_group_id,
        "vserver_group_name": vsg.vserver_group_name,
        "server_count": vsg.server_count,
    }


def _lb_forwarding_rule_to_dict(rule: LbForwardingRule) -> dict:
    """将 LbForwardingRule 转为字典"""
    return {
        "account_name": rule.account_name,
        "account_display_name": rule.account_display_name,
        "resource_type": "lb_forwarding_rule",
        "resource_id": rule.rule_id,
        "region_id": rule.region_id,
        "lb_type": rule.lb_type,
        "lb_id": rule.lb_id,
        "rule_id": rule.rule_id,
        "domain": rule.domain,
        "url": rule.url,
        "listener_port": rule.listener_port,
        "listener_protocol": rule.listener_protocol,
        "vserver_group_id": rule.vserver_group_id,
    }


def _search_by_ip(session: Session, ip_value: str) -> list[dict]:
    """按 IP 搜索 ip_addresses 表"""
    # 精确匹配优先
    stmt = select(IpAddress).where(IpAddress.ip == ip_value)
    results = list(session.execute(stmt).scalars().all())

    if not results:
        # 模糊匹配
        stmt = select(IpAddress).where(IpAddress.ip.like(f"%{ip_value}%"))
        results = list(session.execute(stmt).scalars().all())

    return [_ip_record_to_dict(r) for r in results]


def _search_by_domain(session: Session, domain_value: str, exact: bool = False) -> tuple[list[dict], list[dict]]:
    """按域名搜索 dns_records 表 + APIG 域名表

    Args:
        exact: 精确匹配模式 — 只匹配 fqdn == domain_value，不做模糊匹配

    Returns:
        (direct_results, related_results) —
        direct_results: 直接命中的本资源（DNS 记录）
        related_results: 通过域名关联的间接资源（APIG 网关、SAE 应用）
    """
    # 直接命中：DNS 记录
    dns_conditions = [
        DnsRecord.fqdn == domain_value,
        DnsRecord.domain_name == domain_value,
        DnsRecord.value == domain_value,
    ]
    if not exact:
        dns_conditions.append(DnsRecord.fqdn.like(f"%{domain_value}%"))
    stmt = select(DnsRecord).where(or_(*dns_conditions))
    direct_results = [_dns_record_to_dict(r) for r in session.execute(stmt).scalars().all()]
    related_results = []

    # 关联资源：APIG 域名（接入域名 + 自定义绑定域名）
    apig_conditions = [ApigDomain.domain_name == domain_value]
    if not exact:
        apig_conditions.append(ApigDomain.domain_name.like(f"%{domain_value}%"))
    stmt = select(ApigDomain).where(or_(*apig_conditions))
    for dm in session.execute(stmt).scalars().all():
        gw_stmt = select(ApiGateway).where(
            ApiGateway.account_name == dm.account_name,
            ApiGateway.api_type == "apig",
            ApiGateway.group_id == dm.gateway_id,
        )
        gw_obj = session.execute(gw_stmt).scalar_one_or_none()
        if gw_obj:
            d = _api_gateway_to_dict(gw_obj)
            d["matched_by"] = "apig_domain"
            d["matched_domain"] = dm.domain_name
            related_results.append(d)

    # 关联资源：SAE 应用（service_url 包含 svc.cluster.local 格式的内部访问地址）
    sae_conditions = [SaeApp.service_url == domain_value]
    if not exact:
        sae_conditions.append(SaeApp.service_url.like(f"%{domain_value}%"))
    stmt = select(SaeApp).where(or_(*sae_conditions))
    for sae_app in session.execute(stmt).scalars().all():
        d = _sae_app_to_dict(sae_app)
        d["matched_by"] = "sae_service_url"
        # 补充命名空间名称
        ns_stmt = select(SaeNamespace).where(
            SaeNamespace.namespace_id == sae_app.namespace_id,
        )
        ns_obj = session.execute(ns_stmt).scalar_one_or_none()
        if ns_obj:
            d["namespace_name"] = ns_obj.namespace_name or ""
        related_results.append(d)

    return direct_results, related_results


def _search_by_resource_id(session: Session, resource_id: str, exact: bool = False) -> list[dict]:
    """按资源 ID 搜索各资源表

    Args:
        exact: 粯精匹配模式 — 只用 == 匹配，不做 .like() 模糊搜索
    """
    # 辅助函数：精确模式只 == 匹配，模糊模式用 or_(==, .like())
    def _match(column, value: str):
        if exact:
            return column == value
        return or_(column == value, column.like(f"%{value}%"))

    results = []

    # ECS
    stmt = select(EcsInstance).where(_match(EcsInstance.instance_id, resource_id))
    ecs_list = list(session.execute(stmt).scalars().all())
    for ecs in ecs_list:
        d = _ecs_to_dict(ecs)
        d["matched_by"] = "instance_id"
        results.append(d)

    # EIP
    stmt = select(EipAddress).where(_match(EipAddress.allocation_id, resource_id))
    eip_list = list(session.execute(stmt).scalars().all())
    for eip in eip_list:
        d = _eip_to_dict(eip)
        d["matched_by"] = "allocation_id"
        results.append(d)

    # Load Balancers
    stmt = select(LoadBalancer).where(_match(LoadBalancer.lb_id, resource_id))
    lb_list = list(session.execute(stmt).scalars().all())
    for lb in lb_list:
        d = _lb_to_dict(lb)
        d = _enrich_lb_with_eip(session, d)
        d["matched_by"] = "lb_id"
        results.append(d)

    # RDS
    stmt = select(RdsInstance).where(_match(RdsInstance.instance_id, resource_id))
    for rds in session.execute(stmt).scalars().all():
        d = _rds_to_dict(rds)
        d["matched_by"] = "instance_id"
        results.append(d)

    # Tair/Redis
    stmt = select(TairInstance).where(_match(TairInstance.instance_id, resource_id))
    for tair in session.execute(stmt).scalars().all():
        d = _tair_to_dict(tair)
        d["matched_by"] = "instance_id"
        results.append(d)

    # PolarDB
    stmt = select(PolarDBCluster).where(_match(PolarDBCluster.cluster_id, resource_id))
    for polardb in session.execute(stmt).scalars().all():
        d = _polardb_to_dict(polardb)
        d["matched_by"] = "cluster_id"
        results.append(d)

    # MongoDB
    stmt = select(MongoDBInstance).where(_match(MongoDBInstance.instance_id, resource_id))
    for mongodb in session.execute(stmt).scalars().all():
        d = _mongodb_to_dict(mongodb)
        d["matched_by"] = "instance_id"
        results.append(d)

    # OSS
    stmt = select(OssBucket).where(
        OssBucket.bucket_name == resource_id,
    )
    for oss in session.execute(stmt).scalars().all():
        d = _oss_to_dict(oss)
        d["matched_by"] = "bucket_name"
        results.append(d)

    # CDN
    stmt = select(CdnDomain).where(
        CdnDomain.domain_name == resource_id,
    )
    for cdn in session.execute(stmt).scalars().all():
        d = _cdn_to_dict(cdn)
        d["matched_by"] = "domain_name"
        results.append(d)

    # WAF
    stmt = select(WafDomain).where(
        WafDomain.domain_name == resource_id,
    )
    for waf in session.execute(stmt).scalars().all():
        d = _waf_to_dict(waf)
        d["matched_by"] = "domain_name"
        results.append(d)

    # API Gateway
    stmt = select(ApiGateway).where(_match(ApiGateway.group_id, resource_id))
    for api_gw in session.execute(stmt).scalars().all():
        d = _api_gateway_to_dict(api_gw)
        d["matched_by"] = "group_id"
        results.append(d)

    # RAM
    stmt = select(RamUser).where(
        or_(
            RamUser.user_id == resource_id,
            RamUser.user_name == resource_id,
        )
    )
    for ram_user in session.execute(stmt).scalars().all():
        d = _ram_user_to_dict(ram_user)
        d["matched_by"] = "user_id"
        results.append(d)

    # ── AccessKey ID (LTAI...) → 搜索 RamAccessKey，然后查找所属 RamUser ──
    if resource_id.startswith("LTAI"):
        # 1. 精确搜索 RamAccessKey
        stmt = select(RamAccessKey).where(RamAccessKey.access_key_id == resource_id)
        for ak_obj in session.execute(stmt).scalars().all():
            d = _ram_ak_to_dict(ak_obj)
            d["matched_by"] = "access_key_id"
            results.append(d)

            # 2. 同时查找所属的 RAM 用户
            ram_stmt = select(RamUser).where(
                RamUser.account_name == ak_obj.account_name,
                RamUser.user_name == ak_obj.user_name,
            )
            ram_user = session.execute(ram_stmt).scalar_one_or_none()
            if ram_user:
                rd = _ram_user_to_dict(ram_user)
                rd["matched_by"] = "ram_user_by_ak"
                results.append(rd)

    # ── 安全组ID (sg-xxx) → 精确搜索 SecurityGroup 表 + ECS raw_json ──
    if resource_id.startswith("sg-"):
        # 1. 精确搜索 security_groups 表
        stmt = select(SecurityGroup).where(SecurityGroup.security_group_id == resource_id)
        for sg_obj in session.execute(stmt).scalars().all():
            d = _sg_to_dict(sg_obj)
            d["matched_by"] = "security_group_id"
            results.append(d)

        # 2. 搜索 ECS raw_json 找到绑定了该安全组的 ECS 实例（模糊匹配，精确模式跳过）
        if not exact:
            stmt = select(EcsInstance).where(
                type_coerce(EcsInstance.raw_json, String).like(f"%{resource_id}%")
            )
            for ecs in session.execute(stmt).scalars().all():
                d = _ecs_to_dict(ecs)
                d["matched_by"] = "security_group_id"
                results.append(d)

        # 3. 搜索 resources_raw（非 ECS 类型，如 CLB 安全组）（模糊匹配，精确模式跳过）
        if not exact:
            stmt = select(ResourceRaw).where(
                type_coerce(ResourceRaw.raw_json, String).like(f"%{resource_id}%")
            )
        for raw in session.execute(stmt).scalars().all():
            if raw.resource_type in ("ecs", "security_group"):
                continue  # 已在上方搜索
            d = {
                "account_name": raw.account_name,
                "account_display_name": raw.account_display_name,
                "resource_type": raw.resource_type,
                "region_id": raw.region_id,
                "resource_id": raw.resource_id,
                "resource_name": raw.resource_name,
                "matched_by": "resources_raw",
            }
            results.append(d)

    # ── 磁盘ID (d-xxx) → 搜索 ECS raw_json ──
    if resource_id.startswith("d-") and not exact:
        stmt = select(EcsInstance).where(
            type_coerce(EcsInstance.raw_json, String).like(f"%{resource_id}%")
        )
        for ecs in session.execute(stmt).scalars().all():
            d = _ecs_to_dict(ecs)
            d["matched_by"] = "disk_id"
            results.append(d)

        # 同时搜索 resources_raw，可能在其他资源类型中也引用了该 ID
        stmt = select(ResourceRaw).where(
            type_coerce(ResourceRaw.raw_json, String).like(f"%{resource_id}%")
        )
        for raw in session.execute(stmt).scalars().all():
            if raw.resource_type == "ecs":
                continue  # 已在上方搜索
            d = {
                "account_name": raw.account_name,
                "account_display_name": raw.account_display_name,
                "resource_type": raw.resource_type,
                "region_id": raw.region_id,
                "resource_id": raw.resource_id,
                "resource_name": raw.resource_name,
                "matched_by": "resources_raw",
            }
            results.append(d)

    # SAE 应用 — app_id (UUID 格式, 如 de6dfaca-c0fa-4753-a4c7-2fe0285f3b97)
    stmt = select(SaeApp).where(_match(SaeApp.app_id, resource_id))
    for sae_app in session.execute(stmt).scalars().all():
        d = _sae_app_to_dict(sae_app)
        d["matched_by"] = "app_id"
        # 补充命名空间名称
        ns_stmt = select(SaeNamespace).where(
            SaeNamespace.namespace_id == sae_app.namespace_id,
        )
        ns_obj = session.execute(ns_stmt).scalar_one_or_none()
        if ns_obj:
            d["namespace_name"] = ns_obj.namespace_name or ""
        results.append(d)

    # SAE 命名空间 — namespace_id (如 cn-hangzhou:chuandaodev)
    ns_conditions = [SaeNamespace.namespace_id == resource_id]
    if not exact:
        ns_conditions.append(SaeNamespace.namespace_id.like(f"%{resource_id}%"))
    ns_conditions.append(SaeNamespace.namespace_short_id == resource_id)
    stmt = select(SaeNamespace).where(or_(*ns_conditions))
    for ns in session.execute(stmt).scalars().all():
        d = _sae_namespace_to_dict(ns)
        d["matched_by"] = "namespace_id"
        results.append(d)

    # APIG 域名 — domain_id
    apig_dm_conditions = [ApigDomain.domain_id == resource_id, ApigDomain.domain_name == resource_id]
    if not exact:
        apig_dm_conditions.append(ApigDomain.domain_id.like(f"%{resource_id}%"))
    stmt = select(ApigDomain).where(or_(*apig_dm_conditions))
    for dm in session.execute(stmt).scalars().all():
        gw_stmt = select(ApiGateway).where(
            ApiGateway.account_name == dm.account_name,
            ApiGateway.api_type == "apig",
            ApiGateway.group_id == dm.gateway_id,
        )
        gw_obj = session.execute(gw_stmt).scalar_one_or_none()
        if gw_obj:
            d = _api_gateway_to_dict(gw_obj)
            d["matched_by"] = "apig_domain"
            d["matched_domain"] = dm.domain_name
            results.append(d)

    # APIG API — api_id (http_api_id)
    stmt = select(ApigApi).where(_match(ApigApi.api_id, resource_id))
    for apig_api in session.execute(stmt).scalars().all():
        d = _apig_api_to_dict(apig_api)
        d["matched_by"] = "api_id"
        results.append(d)

    # APIG 路由 — route_id
    stmt = select(ApigRoute).where(_match(ApigRoute.route_id, resource_id))
    for apig_route in session.execute(stmt).scalars().all():
        d = _apig_route_to_dict(apig_route)
        d["matched_by"] = "route_id"
        results.append(d)

    # LB 监听器 — 在 raw_json 中搜索 listener_id 或 lb_id + listener_port 组合
    if exact:
        stmt = select(LbListener).where(LbListener.lb_id == resource_id)
    else:
        stmt = select(LbListener).where(
            or_(
                LbListener.lb_id == resource_id,
                type_coerce(LbListener.raw_json, String).like(f"%{resource_id}%"),
            )
        )
    for listener in session.execute(stmt).scalars().all():
        d = _lb_listener_to_dict(listener)
        d["matched_by"] = "lb_listener"
        results.append(d)

    # LB vServerGroup — vserver_group_id
    stmt = select(LbVServerGroup).where(_match(LbVServerGroup.vserver_group_id, resource_id))
    for vsg in session.execute(stmt).scalars().all():
        d = _lb_vserver_group_to_dict(vsg)
        d["matched_by"] = "vserver_group_id"
        results.append(d)

    # LB 转发规则 — rule_id（模糊搜索 raw_json，精确模式跳过）
    if not exact:
        stmt = select(LbForwardingRule).where(
            type_coerce(LbForwardingRule.raw_json, String).like(f"%{resource_id}%"),
        )
    for rule in session.execute(stmt).scalars().all():
        d = _lb_forwarding_rule_to_dict(rule)
        d["matched_by"] = "forwarding_rule_id"
        results.append(d)

    # SLS Project — project_name
    stmt = select(SlsProject).where(
        SlsProject.project_name == resource_id,
    )
    for sls_proj in session.execute(stmt).scalars().all():
        d = _sls_project_to_dict(sls_proj)
        d["matched_by"] = "project_name"
        results.append(d)

    # DNS Record — record_id
    stmt = select(DnsRecord).where(_match(DnsRecord.record_id, resource_id))
    for dns_rec in session.execute(stmt).scalars().all():
        d = _dns_record_to_dict(dns_rec)
        d["matched_by"] = "record_id"
        results.append(d)

    return results


def _search_by_text(session: Session, text: str, exact: bool = False) -> list[dict]:
    """通用文本搜索 — 在所有表中模糊匹配

    Args:
        exact: 粯精匹配模式 — 只用 == 匹配，不做 .like() 模糊搜索
    """
    results = []
    like_pattern = f"%{text}%"

    # ip_addresses（有索引，最快）
    ip_results = _search_by_ip(session, text)
    # 粯精模式：只保留 resource_name == text 或 ip == text 的记录
    if exact:
        ip_results = [r for r in ip_results if r.get("ip") == text or r.get("resource_name") == text]
    results.extend(ip_results)

    # dns_records — _search_by_domain 返回 (direct_results, related_results)
    dns_direct, dns_related = _search_by_domain(session, text, exact=exact)
    for d in dns_direct:
        d["matched_by"] = "dns_record"
        results.append(d)
    # related_results（APIG 网关、SAE 应用）已自带 matched_by，直接追加
    results.extend(dns_related)

    # ECS instance_id / instance_name
    if exact:
        stmt = select(EcsInstance).where(
            or_(EcsInstance.instance_id == text, EcsInstance.instance_name == text)
        )
    else:
        stmt = select(EcsInstance).where(
            or_(
                EcsInstance.instance_id.like(like_pattern),
                EcsInstance.instance_name.like(like_pattern),
            )
        )
    for ecs in session.execute(stmt).scalars().all():
        d = _ecs_to_dict(ecs)
        d["matched_by"] = "ecs_instance"
        results.append(d)

    # EIP allocation_id / ip_address
    if exact:
        stmt = select(EipAddress).where(
            or_(EipAddress.allocation_id == text, EipAddress.ip_address == text)
        )
    else:
        stmt = select(EipAddress).where(
            or_(
                EipAddress.allocation_id.like(like_pattern),
                EipAddress.ip_address.like(like_pattern),
            )
        )
    for eip in session.execute(stmt).scalars().all():
        d = _eip_to_dict(eip)
        d["matched_by"] = "eip_address"
        results.append(d)

    # Load Balancers lb_id / lb_name / address / dns_name
    if exact:
        stmt = select(LoadBalancer).where(
            or_(
                LoadBalancer.lb_id == text,
                LoadBalancer.lb_name == text,
                LoadBalancer.address == text,
                LoadBalancer.dns_name == text,
            )
        )
    else:
        stmt = select(LoadBalancer).where(
            or_(
                LoadBalancer.lb_id.like(like_pattern),
                LoadBalancer.lb_name.like(like_pattern),
                LoadBalancer.address.like(like_pattern),
                LoadBalancer.dns_name.like(like_pattern),
            )
        )
    for lb in session.execute(stmt).scalars().all():
        d = _lb_to_dict(lb)
        d = _enrich_lb_with_eip(session, d)
        d["matched_by"] = "load_balancer"
        results.append(d)

    # Backend servers
    if exact:
        stmt = select(BackendServer).where(
            or_(BackendServer.backend_resource_id == text, BackendServer.backend_ip == text)
        )
    else:
        stmt = select(BackendServer).where(
            or_(
                BackendServer.backend_resource_id.like(like_pattern),
                BackendServer.backend_ip.like(like_pattern),
            )
        )
    for backend in session.execute(stmt).scalars().all():
        d = _backend_to_dict(backend)
        d["matched_by"] = "backend_server"
        results.append(d)

    # resources_raw — 在 raw_json 中文本搜索（搜备注/描述）
    # 精确模式：只匹配 resource_id 或 resource_name 完全等于 text
    if exact:
        stmt = select(ResourceRaw).where(
            or_(ResourceRaw.resource_id == text, ResourceRaw.resource_name == text)
        )
    else:
        stmt = select(ResourceRaw).where(
            or_(
                ResourceRaw.resource_id.like(like_pattern),
                ResourceRaw.resource_name.like(like_pattern),
                type_coerce(ResourceRaw.raw_json, String).like(like_pattern),
            )
        )
    for raw in session.execute(stmt).scalars().all():
        d = {
            "account_name": raw.account_name,
            "account_display_name": raw.account_display_name,
            "resource_type": raw.resource_type,
            "region_id": raw.region_id,
            "resource_id": raw.resource_id,
            "resource_name": raw.resource_name,
            "matched_by": "resources_raw",
        }
        results.append(d)

    # RDS instance_id / instance_name / connection_string
    if exact:
        stmt = select(RdsInstance).where(
            or_(
                RdsInstance.instance_id == text,
                RdsInstance.instance_name == text,
                RdsInstance.connection_string == text,
            )
        )
    else:
        stmt = select(RdsInstance).where(
            or_(
                RdsInstance.instance_id.like(like_pattern),
                RdsInstance.instance_name.like(like_pattern),
                RdsInstance.connection_string.like(like_pattern),
            )
        )
    for rds in session.execute(stmt).scalars().all():
        d = _rds_to_dict(rds)
        d["matched_by"] = "rds_instance"
        results.append(d)

    # Tair instance_id / instance_name / connection_domain
    if exact:
        stmt = select(TairInstance).where(
            or_(
                TairInstance.instance_id == text,
                TairInstance.instance_name == text,
                TairInstance.connection_domain == text,
            )
        )
    else:
        stmt = select(TairInstance).where(
            or_(
                TairInstance.instance_id.like(like_pattern),
                TairInstance.instance_name.like(like_pattern),
                TairInstance.connection_domain.like(like_pattern),
            )
        )
    for tair in session.execute(stmt).scalars().all():
        d = _tair_to_dict(tair)
        d["matched_by"] = "tair_instance"
        results.append(d)

    # PolarDB cluster_id / cluster_description
    if exact:
        stmt = select(PolarDBCluster).where(
            or_(PolarDBCluster.cluster_id == text, PolarDBCluster.cluster_description == text)
        )
    else:
        stmt = select(PolarDBCluster).where(
            or_(
                PolarDBCluster.cluster_id.like(like_pattern),
                PolarDBCluster.cluster_description.like(like_pattern),
            )
        )
    for polardb in session.execute(stmt).scalars().all():
        d = _polardb_to_dict(polardb)
        d["matched_by"] = "polardb_cluster"
        results.append(d)

    # MongoDB instance_id / instance_description
    if exact:
        stmt = select(MongoDBInstance).where(
            or_(MongoDBInstance.instance_id == text, MongoDBInstance.instance_description == text)
        )
    else:
        stmt = select(MongoDBInstance).where(
            or_(
                MongoDBInstance.instance_id.like(like_pattern),
                MongoDBInstance.instance_description.like(like_pattern),
            )
        )
    for mongodb in session.execute(stmt).scalars().all():
        d = _mongodb_to_dict(mongodb)
        d["matched_by"] = "mongodb_instance"
        results.append(d)

    # OSS bucket_name
    if exact:
        stmt = select(OssBucket).where(OssBucket.bucket_name == text)
    else:
        stmt = select(OssBucket).where(OssBucket.bucket_name.like(like_pattern))
    for oss in session.execute(stmt).scalars().all():
        d = _oss_to_dict(oss)
        d["matched_by"] = "oss_bucket"
        results.append(d)

    # CDN domain_name
    if exact:
        stmt = select(CdnDomain).where(CdnDomain.domain_name == text)
    else:
        stmt = select(CdnDomain).where(
            or_(
                CdnDomain.domain_name.like(like_pattern),
                type_coerce(CdnDomain.origin_address, String).like(like_pattern),
            )
        )
    for cdn in session.execute(stmt).scalars().all():
        d = _cdn_to_dict(cdn)
        d["matched_by"] = "cdn_domain"
        results.append(d)

    # WAF domain_name
    if exact:
        stmt = select(WafDomain).where(
            or_(WafDomain.domain_name == text, WafDomain.instance_id == text)
        )
    else:
        stmt = select(WafDomain).where(
            or_(
                WafDomain.domain_name.like(like_pattern),
                WafDomain.instance_id.like(like_pattern),
                type_coerce(WafDomain.source_ips_json, String).like(like_pattern),
            )
        )
    for waf in session.execute(stmt).scalars().all():
        d = _waf_to_dict(waf)
        d["matched_by"] = "waf_domain"
        results.append(d)

    # API Gateway group_id / group_name
    if exact:
        stmt = select(ApiGateway).where(
            or_(ApiGateway.group_id == text, ApiGateway.group_name == text)
        )
    else:
        stmt = select(ApiGateway).where(
            or_(
                ApiGateway.group_id.like(like_pattern),
                ApiGateway.group_name.like(like_pattern),
            )
        )
    for api_gw in session.execute(stmt).scalars().all():
        d = _api_gateway_to_dict(api_gw)
        d["matched_by"] = "api_gateway"
        results.append(d)

    # APIG 域名 — 搜索绑定域名，返回所属网关
    if exact:
        stmt = select(ApigDomain).where(ApigDomain.domain_name == text)
    else:
        stmt = select(ApigDomain).where(ApigDomain.domain_name.like(like_pattern))
    for dm in session.execute(stmt).scalars().all():
        gw_stmt = select(ApiGateway).where(
            ApiGateway.account_name == dm.account_name,
            ApiGateway.api_type == "apig",
            ApiGateway.group_id == dm.gateway_id,
        )
        gw_obj = session.execute(gw_stmt).scalar_one_or_none()
        if gw_obj:
            d = _api_gateway_to_dict(gw_obj)
            d["matched_by"] = "apig_domain"
            d["matched_domain"] = dm.domain_name
            results.append(d)

    # SAE 应用 — 搜索应用名、service_url
    if exact:
        stmt = select(SaeApp).where(
            or_(SaeApp.app_name == text, SaeApp.service_url == text)
        )
    else:
        stmt = select(SaeApp).where(
            or_(
                SaeApp.app_name.like(like_pattern),
                SaeApp.service_url.like(like_pattern),
        )
    )
    for sae_app in session.execute(stmt).scalars().all():
        d = _sae_app_to_dict(sae_app)
        d["matched_by"] = "sae_app"
        # 补充命名空间名称
        ns_stmt = select(SaeNamespace).where(
            SaeNamespace.namespace_id == sae_app.namespace_id,
        )
        ns_obj = session.execute(ns_stmt).scalar_one_or_none()
        if ns_obj:
            d["namespace_name"] = ns_obj.namespace_name or ""
        results.append(d)

    # RAM user_name / display_name
    if exact:
        stmt = select(RamUser).where(
            or_(RamUser.user_name == text, RamUser.display_name == text)
        )
    else:
        stmt = select(RamUser).where(
            or_(
                RamUser.user_name.like(like_pattern),
                RamUser.display_name.like(like_pattern),
            )
        )
    for ram_user in session.execute(stmt).scalars().all():
        d = _ram_user_to_dict(ram_user)
        d["matched_by"] = "ram_user"
        results.append(d)

    # RAM AccessKey — 按 access_key_id 搜索（如输入部分 LTAI...）
    if exact:
        stmt = select(RamAccessKey).where(RamAccessKey.access_key_id == text)
    else:
        stmt = select(RamAccessKey).where(RamAccessKey.access_key_id.like(like_pattern))
    for ak_obj in session.execute(stmt).scalars().all():
        d = _ram_ak_to_dict(ak_obj)
        d["matched_by"] = "access_key_id"
        results.append(d)
        # 同时查找所属 RamUser
        ram_stmt = select(RamUser).where(
            RamUser.account_name == ak_obj.account_name,
            RamUser.user_name == ak_obj.user_name,
        )
        ram_user = session.execute(ram_stmt).scalar_one_or_none()
        if ram_user:
            rd = _ram_user_to_dict(ram_user)
            rd["matched_by"] = "ram_user_by_ak"
            results.append(rd)

    # RAM 策略 — 按 policy_name / description 搜索
    if exact:
        stmt = select(RamUserPolicy).where(
            or_(RamUserPolicy.policy_name == text, RamUserPolicy.description == text)
        )
    else:
        stmt = select(RamUserPolicy).where(
            or_(
                RamUserPolicy.policy_name.like(like_pattern),
                RamUserPolicy.description.like(like_pattern),
            )
        )
    for policy in session.execute(stmt).scalars().all():
        d = _ram_policy_to_dict(policy)
        d["matched_by"] = "ram_user_policy"
        results.append(d)

    return results


def _resource_key(resource: dict) -> tuple[str, str] | None:
    """从任意资源字典提取去重键 (resource_type, resource_id)

    不同搜索函数返回的字典字段名不同（ecs 用 instance_id，lb 用 lb_id 等），
    这里统一提取为 (type, id) 格式，用于去重。
    """
    res_type = (
        resource.get("resource_type")
        or resource.get("lb_type")
        or ""
    )
    # 补充 matched_by 的类型映射
    matched_by = resource.get("matched_by", "")
    if not res_type:
        if matched_by in ("instance_id", "ecs_instance"):
            res_type = "ecs"
        elif matched_by in ("allocation_id", "eip_address"):
            res_type = "eip"
        elif matched_by in ("lb_id", "load_balancer"):
            res_type = resource.get("lb_type", "clb")
        elif matched_by == "dns_record":
            res_type = "dns"
        elif matched_by in ("rds_instance", "instance_id") and resource.get("engine"):
            res_type = "rds"
        elif matched_by == "tair_instance":
            res_type = "tair"
        elif matched_by == "polardb_cluster":
            res_type = "polardb"
        elif matched_by == "mongodb_instance":
            res_type = "mongodb"
        elif matched_by == "oss_bucket":
            res_type = "oss"
        elif matched_by == "cdn_domain":
            res_type = "cdn"
        elif matched_by == "waf_domain":
            res_type = "waf"
        elif matched_by == "api_gateway":
            res_type = "api_gateway"
        elif matched_by == "ram_user":
            res_type = "ram_user"
        elif matched_by == "ram_user_by_ak":
            res_type = "ram_user"
        elif matched_by == "access_key_id":
            res_type = "ram_ak"
        elif matched_by == "sae_app" or matched_by == "sae_service_url":
            res_type = "sae"

    # 云原生 API 网关 (APIG) 统一归入 api_gateway 类型，便于去重
    if res_type == "apig":
        res_type = "api_gateway"

    res_id = (
        resource.get("resource_id")
        or resource.get("instance_id")
        or resource.get("allocation_id")
        or resource.get("lb_id")
        or resource.get("record_id")
        or resource.get("cluster_id")
        or resource.get("bucket_name")
        or resource.get("domain_name")
        or resource.get("group_id")
        or resource.get("user_id")
        or resource.get("access_key_id")
        or ""
    )
    if res_type and res_id:
        return (res_type, res_id)
    return None


def _deduplicate_resources(resources: list[dict]) -> list[dict]:
    """去除重复的资源记录

    同一资源可能同时出现在多个搜索来源中（主表 + ip_addresses + resources_raw），
    保留信息最丰富的版本（主表 > ip_addresses > resources_raw）。
    """
    # 按 (resource_type, resource_id) 分组，每组保留信息最丰富的记录
    # 信息丰富度: 主表 (matched_by=具体表名) > ip_addresses (有 ip_type) > resources_raw
    seen: dict[tuple[str, str], dict] = {}
    for r in resources:
        key = _resource_key(r)
        if not key:
            continue
        matched_by = r.get("matched_by", "")
        # 主表记录信息最丰富，优先保留
        if key not in seen:
            seen[key] = r
        else:
            existing = seen[key]
            existing_by = existing.get("matched_by", "")
            # 如果新记录来自主表（非 ip_addresses / resources_raw），替换
            if matched_by not in ("ip_addresses", "resources_raw") and existing_by in ("ip_addresses", "resources_raw"):
                seen[key] = r
            # 如果两者都是主表，保留信息量更多的（字段数更多）
            elif matched_by not in ("ip_addresses", "resources_raw") and existing_by not in ("ip_addresses", "resources_raw"):
                if len(r) > len(existing):
                    seen[key] = r

    # 保留去重后的记录 + 没有 key 的记录（无法去重的）
    deduped = list(seen.values())
    no_key = [r for r in resources if not _resource_key(r)]
    return deduped + no_key


# ──────────────────────────────────────────────
# 补充 resources_raw 匹配资源的完整信息
# ──────────────────────────────────────────────

# 资源类型 → (主表 Model, 主键字段名, _to_dict 函数) 的映射
_RAW_ENRICH_MAP = {
    "eip": (EipAddress, "allocation_id", _eip_to_dict),
    "ecs": (EcsInstance, "instance_id", _ecs_to_dict),
    "clb": (LoadBalancer, "lb_id", _lb_to_dict),
    "alb": (LoadBalancer, "lb_id", _lb_to_dict),
    "security_group": (SecurityGroup, "security_group_id", _sg_to_dict),
    "ram_user": (RamUser, "user_id", _ram_user_to_dict),
    "ram_ak": (RamAccessKey, "access_key_id", _ram_ak_to_dict),
    "ram_user_policy": (RamUserPolicy, "policy_name", _ram_policy_to_dict),
    "cdn": (CdnDomain, "domain_name", _cdn_to_dict),
    "api_cloudapi": (ApiGateway, "group_id", _api_gateway_to_dict),
    "api_apig": (ApiGateway, "group_id", _api_gateway_to_dict),
    "api_mse": (ApiGateway, "group_id", _api_gateway_to_dict),
    "apig": (ApiGateway, "group_id", _api_gateway_to_dict),
    "apig_domain": (ApigDomain, "domain_id", _apig_domain_to_dict),
    "apig_api": (ApigApi, "api_id", _apig_api_to_dict),
    "apig_route": (ApigRoute, "route_id", _apig_route_to_dict),
    "dns": (DnsRecord, "record_id", _dns_record_to_dict),
    "dns_record": (DnsRecord, "record_id", _dns_record_to_dict),
    "backend": (BackendServer, "backend_resource_id", _backend_to_dict),
    "sls_project": (SlsProject, "project_name", _sls_project_to_dict),
    "oss": (OssBucket, "bucket_name", _oss_to_dict),
    "rds": (RdsInstance, "instance_id", _rds_to_dict),
    "waf": (WafDomain, "domain_name", _waf_to_dict),
    "tair": (TairInstance, "instance_id", _tair_to_dict),
    "polardb": (PolarDBCluster, "cluster_id", _polardb_to_dict),
    "mongodb": (MongoDBInstance, "instance_id", _mongodb_to_dict),
    "sae": (SaeApp, "app_id", _sae_app_to_dict),
    "sae_namespace": (SaeNamespace, "namespace_id", _sae_namespace_to_dict),
}


def _enrich_raw_resources(session: Session, resources: list[dict]) -> list[dict]:
    """对 matched_by='resources_raw' 的资源，从主表补充完整信息

    resources_raw 搜索只返回基本字段（account_name, resource_type, resource_id 等），
    缺少 ip_address、private_ips 等关键字段。此函数从对应主表获取完整 _to_dict 结果，
    并保留 matched_by 和原始 matched_by 不为 resources_raw 的记录不变。
    """
    enriched = []
    for r in resources:
        matched_by = r.get("matched_by", "")
        if matched_by != "resources_raw":
            enriched.append(r)
            continue

        res_type = r.get("resource_type", "")
        res_id = r.get("resource_id", "")

        mapping = _RAW_ENRICH_MAP.get(res_type)
        if not mapping or not res_id:
            enriched.append(r)
            continue

        model_cls, pk_field, to_dict_fn = mapping
        stmt = select(model_cls).where(getattr(model_cls, pk_field) == res_id)
        obj = session.execute(stmt).scalar_one_or_none()
        if obj:
            full_dict = to_dict_fn(obj)
            full_dict["matched_by"] = "resources_raw"
            # 保留原始 resources_raw 中的 resource_name（主表可能没有名称字段）
            if r.get("resource_name") and not full_dict.get("resource_name"):
                full_dict["resource_name"] = r["resource_name"]
            # CLB/ALB: 补充 EIP 和正确的 private/public 地址
            if res_type in ("clb", "alb"):
                full_dict = _enrich_lb_with_eip(session, full_dict)
            enriched.append(full_dict)
        else:
            enriched.append(r)

    return enriched


# ──────────────────────────────────────────────
# 主查询入口
# ──────────────────────────────────────────────

def query(session: Session, value: str, exact: bool = False) -> QueryResult:
    """通用查询入口 — 根据任意信息查询相关资源

    Args:
        session: 数据库会话
        value: 查询值（IP、域名、资源ID、任意文本）
        exact: 精确匹配模式 — 只匹配完全等于查询值的记录，不做模糊匹配

    Returns:
        QueryResult: 包含匹配资源、DNS 记录、后端服务器、链路信息
    """
    input_type = classify_input(value)
    result = QueryResult(query_type=input_type, query_value=value)

    # 根据输入类型选择搜索策略
    if input_type == "ip":
        ip_results = _search_by_ip(session, value)
        # DNS 类型已在 DNS 解析记录表格中展示，不在命中资源中重复
        result.matched_resources = [r for r in ip_results if r.get("resource_type") != "dns_record"]
        # 同时搜索 DNS 记录（可能指向该 IP）
        dns_stmt = select(DnsRecord).where(DnsRecord.value == value)
        result.dns_records = [_dns_record_to_dict(r) for r in session.execute(dns_stmt).scalars().all()]
        # 同时搜索 EIP
        eip_stmt = select(EipAddress).where(EipAddress.ip_address == value)
        eip_results = [_eip_to_dict(r) for r in session.execute(eip_stmt).scalars().all()]
        if eip_results:
            result.matched_resources.extend(eip_results)
        # 同时搜索 LB
        lb_stmt = select(LoadBalancer).where(LoadBalancer.address == value)
        lb_results = [_enrich_lb_with_eip(session, _lb_to_dict(r)) for r in session.execute(lb_stmt).scalars().all()]
        if lb_results:
            result.matched_resources.extend(lb_results)

    elif input_type == "domain":
        direct, related = _search_by_domain(session, value, exact=exact)
        result.matched_resources = direct
        result.related_resources = related
        result.dns_records = direct  # DNS 记录只有直接命中的 DNS 类型记录
        # 同时搜索 CDN 加速域名（域名可能是 CDN 域名） — 关联资源
        cdn_conditions = [CdnDomain.domain_name == value]
        if not exact:
            cdn_conditions.append(CdnDomain.domain_name.like(f"%{value}%"))
            cdn_conditions.append(type_coerce(CdnDomain.origin_address, String).like(f"%{value}%"))
        cdn_stmt = select(CdnDomain).where(or_(*cdn_conditions))
        cdn_results = [_cdn_to_dict(r) for r in session.execute(cdn_stmt).scalars().all()]
        if cdn_results:
            result.related_resources.extend(cdn_results)
        # 同时搜索 WAF 防护域名 — 关联资源
        waf_conditions = [WafDomain.domain_name == value]
        if not exact:
            waf_conditions.append(WafDomain.domain_name.like(f"%{value}%"))
        waf_stmt = select(WafDomain).where(or_(*waf_conditions))
        waf_results = [_waf_to_dict(r) for r in session.execute(waf_stmt).scalars().all()]
        if waf_results:
            result.related_resources.extend(waf_results)
        # DNS A/AAAA 记录指向 IP 时，查找该 IP 对应的 ECS/LB/EIP — 关联资源
        dns_ip_values = set()
        for dns_rec in direct:
            rec_type = dns_rec.get("record_type", "").upper()
            rec_value = dns_rec.get("value", "")
            if rec_type in ("A", "AAAA") and rec_value:
                dns_ip_values.add(rec_value)
        if dns_ip_values:
            seen_resource_ids = set()
            for ip_val in dns_ip_values:
                ip_stmt = select(IpAddress).where(
                    IpAddress.ip == ip_val,
                    IpAddress.resource_type.in_(["ecs", "clb", "alb", "eip"]),
                )
                for ip_rec in session.execute(ip_stmt).scalars().all():
                    if ip_rec.resource_id in seen_resource_ids:
                        continue
                    seen_resource_ids.add(ip_rec.resource_id)
                    if ip_rec.resource_type == "ecs":
                        ecs_stmt = select(EcsInstance).where(EcsInstance.instance_id == ip_rec.resource_id)
                        ecs_obj = session.execute(ecs_stmt).scalar_one_or_none()
                        if ecs_obj:
                            d = _ecs_to_dict(ecs_obj)
                            d["matched_by"] = "dns_value_ip"
                            d["matched_dns_value"] = ip_val
                            result.related_resources.append(d)
                    elif ip_rec.resource_type in ("clb", "alb"):
                        lb_stmt = select(LoadBalancer).where(LoadBalancer.lb_id == ip_rec.resource_id)
                        lb_obj = session.execute(lb_stmt).scalar_one_or_none()
                        if lb_obj:
                            d = _lb_to_dict(lb_obj)
                            d["matched_by"] = "dns_value_ip"
                            d["matched_dns_value"] = ip_val
                            result.related_resources.append(d)
                    elif ip_rec.resource_type == "eip":
                        eip_stmt = select(EipAddress).where(EipAddress.allocation_id == ip_rec.resource_id)
                        eip_obj = session.execute(eip_stmt).scalar_one_or_none()
                        if eip_obj:
                            d = _eip_to_dict(eip_obj)
                            d["matched_by"] = "dns_value_ip"
                            d["matched_dns_value"] = ip_val
                            result.related_resources.append(d)

    elif input_type == "resource_id":
        result.matched_resources = _search_by_resource_id(session, value, exact=exact)
        # 对于 ECS/EIP/LB，还搜索 IP（精确模式只用 == 匹配）
        if exact:
            ip_stmt = select(IpAddress).where(IpAddress.resource_id == value)
        else:
            ip_stmt = select(IpAddress).where(IpAddress.resource_id.like(f"%{value}%"))
        ip_results = [_ip_record_to_dict(r) for r in session.execute(ip_stmt).scalars().all()]
        if ip_results:
            result.matched_resources.extend(ip_results)

    else:  # text
        result.matched_resources = _search_by_text(session, value, exact=exact)

    # 去重：同一资源在主表和 ip_addresses 表都有记录时，只保留主表版本
    # 必须在后端查找之前去重，否则同一个 LB 会触发两次后端查找，导致后端重复
    result.matched_resources = _deduplicate_resources(result.matched_resources)

    # 补充：对 resources_raw 匹配的资源，从主表获取完整信息
    # resources_raw 只返回基本字段（account_name, resource_type, resource_id 等），
    # 缺少 ip_address、private_ips 等关键信息，需要从对应主表补充
    result.matched_resources = _enrich_raw_resources(session, result.matched_resources)

    # 关联资源也需要去重和补充完整信息
    result.related_resources = _deduplicate_resources(result.related_resources)
    result.related_resources = _enrich_raw_resources(session, result.related_resources)

    # 过滤掉 backend 类型和 ip_type=backend 的 ip_addresses 记录
    # backend 是关联数据（ECS 作为 LB 后端），不是独立资源，应只在后端服务器表格中展示
    result.matched_resources = [
        r for r in result.matched_resources
        if r.get("resource_type") != "backend"
        and r.get("ip_type") != "backend"
    ]

    # 反向查找：当 ECS 被命中时，查找哪些 LB 把它作为后端服务器
    # 将这些 LB 加入 matched_resources，这样后端服务器表格就会自动展示关联
    ecs_ids_in_results = set()
    for resource in result.matched_resources:
        if resource.get("resource_type") == "ecs":
            instance_id = resource.get("instance_id") or resource.get("resource_id")
            if instance_id:
                ecs_ids_in_results.add(instance_id)

    if ecs_ids_in_results:
        for ecs_id in ecs_ids_in_results:
            stmt = select(BackendServer).where(BackendServer.backend_resource_id == ecs_id)
            backend_records = list(session.execute(stmt).scalars().all())
            for br in backend_records:
                lb_id = br.lb_id
                # 查找对应的 LB 并加入 matched_resources
                lb_stmt = select(LoadBalancer).where(LoadBalancer.lb_id == lb_id)
                lb_obj = session.execute(lb_stmt).scalar_one_or_none()
                if lb_obj:
                    lb_dict = _enrich_lb_with_eip(session, _lb_to_dict(lb_obj))
                    lb_dict["matched_by"] = "backend_server_reverse"
                    result.matched_resources.append(lb_dict)

    # 去重新增的 LB 记录（可能有重复）
    result.matched_resources = _deduplicate_resources(result.matched_resources)

    # 发现链路关系
    chain_result = find_chain(value, session)
    # chains（兼容旧 JSON 输出）
    result.chains = [
        [_chain_node_to_dict(node) for node in chain]
        for chain in chain_result.chains
    ]
    # chain_trees + chain_types（嵌套树式链路）
    result.chain_types = chain_result.chain_types
    result.chain_trees = [_chain_node_to_dict(t) for t in chain_result.chain_trees]

    # 如果有 LB 匹配，查找后端服务器（对已去重的 LB 列表只查一次）
    seen_lb_ids = set()
    for resource in result.matched_resources:
        if resource.get("resource_type") in ("clb", "alb") or resource.get("lb_type"):
            lb_id = resource.get("lb_id") or resource.get("resource_id")
            if lb_id and lb_id not in seen_lb_ids:
                seen_lb_ids.add(lb_id)
                backends = _find_backends_for_lb(session, lb_id)
                for backend_dict in backends:
                    # 查找匹配的 ECS
                    backend_dict["matched_ecs"] = _find_matching_ecs(session, backend_dict)
                    result.backends.append(backend_dict)

                # 查找 LB 的监听器信息
                listener_stmt = select(LbListener).where(LbListener.lb_id == lb_id)
                listeners = session.execute(listener_stmt).scalars().all()
                for ln in listeners:
                    # 当 backend_server_port 为空但监听器转发到 vServerGroup 时，
                    # 用 vServerGroup 的后端端口作为 backend_server_port
                    # (vsg_ports_map 在后面构建，这里先记录，之后回填)
                    result.lb_listeners.append({
                        "account_name": ln.account_name,
                        "account_display_name": ln.account_display_name,
                        "lb_type": ln.lb_type,
                        "lb_id": ln.lb_id,
                        "listener_port": ln.listener_port,
                        "listener_protocol": ln.listener_protocol,
                        "backend_server_port": ln.backend_server_port,
                        "vserver_group_id": ln.vserver_group_id or "",
                        "forward_port": ln.forward_port,
                        "listener_forward": ln.listener_forward or "",
                        "status": ln.status,
                        "description": ln.description or "",
                    })

                # 查找 LB 的 vServerGroup 名称
                vsg_stmt = select(LbVServerGroup).where(LbVServerGroup.lb_id == lb_id)
                vserver_groups = session.execute(vsg_stmt).scalars().all()
                for vsg in vserver_groups:
                    result.lb_vserver_groups.append({
                        "account_name": vsg.account_name,
                        "account_display_name": vsg.account_display_name,
                        "lb_type": vsg.lb_type,
                        "lb_id": vsg.lb_id,
                        "vserver_group_id": vsg.vserver_group_id,
                        "vserver_group_name": vsg.vserver_group_name or "",
                        "server_count": vsg.server_count,
                    })

                # 查找 LB 的转发规则（HTTP/HTTPS 域名转发）
                rule_stmt = select(LbForwardingRule).where(LbForwardingRule.lb_id == lb_id)
                rules = session.execute(rule_stmt).scalars().all()

                # 构建 vServerGroup ID → 后端端口映射（从 BackendServer 表查出）
                # 同一 vServerGroup 的后端通常端口一致，偶有不同端口用逗号分隔
                vsg_ports_map: dict[str, str] = {}
                for vsg in vserver_groups:
                    vsg_id = vsg.vserver_group_id
                    bd_stmt = select(BackendServer).where(
                        BackendServer.lb_id == lb_id,
                        BackendServer.server_group_id == vsg_id,
                        BackendServer.port.isnot(None),
                    )
                    bd_list = session.execute(bd_stmt).scalars().all()
                    unique_ports = sorted(set(str(b.port) for b in bd_list if b.port is not None))
                    vsg_ports_map[vsg_id] = ", ".join(unique_ports) if unique_ports else ""

                for rule in rules:
                    vsg_id = rule.vserver_group_id or ""
                    result.lb_forwarding_rules.append({
                        "account_name": rule.account_name,
                        "account_display_name": rule.account_display_name,
                        "lb_type": rule.lb_type,
                        "lb_id": rule.lb_id,
                        "listener_port": rule.listener_port,
                        "listener_protocol": rule.listener_protocol,
                        "rule_id": rule.rule_id,
                        "rule_name": rule.rule_name or "",
                        "domain": rule.domain or "",
                        "url": rule.url or "",
                        "vserver_group_id": vsg_id,
                        "backend_port": vsg_ports_map.get(vsg_id, ""),
                    })

                # 回填监听器中 backend_server_port 为空的后端端口
                # 当监听器转发到 vServerGroup 时，端口不在监听器上而是在 vServerGroup 的后端
                for ln_dict in result.lb_listeners:
                    if ln_dict.get("lb_id") == lb_id and ln_dict.get("backend_server_port") is None:
                        vsg_id = ln_dict.get("vserver_group_id", "")
                        if vsg_id and vsg_id in vsg_ports_map:
                            ln_dict["backend_server_port_from_vsg"] = vsg_ports_map[vsg_id]
                        elif not vsg_id:
                            # 默认组后端：从默认组 BackendServer 取端口
                            bd_stmt = select(BackendServer).where(
                                BackendServer.lb_id == lb_id,
                                BackendServer.server_group_id == "",
                                BackendServer.port.isnot(None),
                            )
                            bd_list = session.execute(bd_stmt).scalars().all()
                            unique_ports = sorted(set(str(b.port) for b in bd_list if b.port is not None))
                            default_port = ", ".join(unique_ports) if unique_ports else ""
                            if default_port:
                                ln_dict["backend_server_port_from_vsg"] = default_port

                # 查找 LB 的访问日志 SLS 配置
                log_configs = _find_lb_log_configs(session, lb_id)
                for log_config in log_configs:
                    result.lb_log_configs.append(log_config)

    # 如果查询值是 SLS 项目名，搜索 SLS 项目和日志库
    sls_projects = _search_sls(session, value)
    if sls_projects:
        result.matched_resources.extend(sls_projects)
        # SLS 搜索结果可能与之前的搜索（resource_id/text）重复，需要再次去重
        result.matched_resources = _deduplicate_resources(result.matched_resources)

    if not result.matched_resources and not result.dns_records and not result.chain_trees:
        result.warnings.append(f"未找到与 '{value}' 相关的资源")

    return result


def _find_backends_for_lb(session: Session, lb_id: str) -> list[dict]:
    """查找 LB 的后端服务器，附带监听器关联信息和服务器组名称"""
    stmt = select(BackendServer).where(BackendServer.lb_id == lb_id)
    backends = list(session.execute(stmt).scalars().all())
    backend_dicts = [_backend_to_dict(b) for b in backends]

    # 查找 LB 的所有监听器，用于关联后端与前端端口
    listener_stmt = select(LbListener).where(LbListener.lb_id == lb_id)
    listeners = list(session.execute(listener_stmt).scalars().all())

    # 构建 vServerGroup ID → 名称映射
    vsg_stmt = select(LbVServerGroup).where(LbVServerGroup.lb_id == lb_id)
    vserver_groups = list(session.execute(vsg_stmt).scalars().all())
    vsg_name_map = {vsg.vserver_group_id: vsg.vserver_group_name or vsg.vserver_group_id
                    for vsg in vserver_groups}

    # 为每个后端查找关联的监听器，并附加服务器组名称
    for bd in backend_dicts:
        sg_id = bd.get("server_group_id", "")

        # 附加服务器组名称
        if sg_id:
            bd["server_group_name"] = vsg_name_map.get(sg_id, sg_id)
        else:
            bd["server_group_name"] = "默认组"

        associated_listeners = []

        if sg_id:
            # vServerGroup 后端：查找 vserver_group_id 匹配的监听器
            for ln in listeners:
                if ln.vserver_group_id == sg_id:
                    associated_listeners.append(ln)
        else:
            # 默认组后端：查找 vserver_group_id 为空/None 的监听器
            for ln in listeners:
                if not ln.vserver_group_id:
                    associated_listeners.append(ln)

        # 将监听器信息附加到后端字典
        if associated_listeners:
            # 构建监听器显示信息
            frontend_info = []
            backend_port_from_listener = None
            for ln in associated_listeners:
                proto = ln.listener_protocol.upper() if ln.listener_protocol else ""
                port = ln.listener_port or ""
                frontend_info.append(f"{proto}:{port}")
                # 取第一个监听器的 backend_server_port 作为后端端口补充
                if ln.backend_server_port and not backend_port_from_listener:
                    backend_port_from_listener = ln.backend_server_port
            bd["frontend_listeners"] = ", ".join(frontend_info)
            if backend_port_from_listener and not bd.get("port"):
                bd["backend_port_from_listener"] = backend_port_from_listener

    return backend_dicts


def _find_matching_ecs(session: Session, backend_dict: dict) -> dict | None:
    """查找后端服务器对应的 ECS 实例"""
    resource_id = backend_dict.get("backend_resource_id", "")
    backend_ip = backend_dict.get("backend_ip", "")

    # 先按 instance_id 查
    ecs = None
    if resource_id:
        stmt = select(EcsInstance).where(EcsInstance.instance_id == resource_id)
        ecs = session.execute(stmt).scalar_one_or_none()

    # 再按 private_ip 查
    if not ecs and backend_ip:
        ecs_list = _find_ecs_by_private_ip_in_session(session, backend_ip)
        if ecs_list:
            ecs = ecs_list[0]

    if ecs:
        return _ecs_to_dict(ecs)
    return None


def _find_ecs_by_private_ip_in_session(session: Session, private_ip: str) -> list[EcsInstance]:
    """通过私网 IP 查找 ECS 实例"""
    stmt = select(EcsInstance).where(
        type_coerce(EcsInstance.private_ips_json, String).like(f"%{private_ip}%")
    )
    return list(session.execute(stmt).scalars().all())


def _find_lb_log_configs(session: Session, lb_id: str) -> list[dict]:
    """查找 LB 的访问日志 SLS 配置"""
    stmt = select(LbLogConfig).where(LbLogConfig.lb_id == lb_id)
    configs = list(session.execute(stmt).scalars().all())
    return [
        {
            "account_name": c.account_name,
            "account_display_name": c.account_display_name,
            "lb_type": c.lb_type,
            "lb_id": c.lb_id,
            "lb_name": c.lb_name,
            "region_id": c.region_id,
            "log_project": c.log_project,
            "log_store": c.log_store,
            "log_type": c.log_type,
        }
        for c in configs
    ]


def _search_sls(session: Session, value: str) -> list[dict]:
    """搜索 SLS 项目和日志库"""
    results = []
    like_pattern = f"%{value}%"

    # SLS 项目
    stmt = select(SlsProject).where(
        or_(
            SlsProject.project_name.like(like_pattern),
            SlsProject.description.like(like_pattern),
        )
    )
    for project in session.execute(stmt).scalars().all():
        d = {
            "account_name": project.account_name,
            "account_display_name": project.account_display_name,
            "resource_type": "sls_project",
            "region_id": project.region_id,
            "resource_id": project.project_name,
            "resource_name": project.project_name,
            "matched_by": "sls_project",
        }
        results.append(d)

    # SLS 日志库
    stmt = select(SlsLogstore).where(
        SlsLogstore.logstore_name.like(like_pattern),
    )
    for logstore in session.execute(stmt).scalars().all():
        d = {
            "account_name": logstore.account_name,
            "account_display_name": logstore.account_display_name,
            "resource_type": "sls_logstore",
            "region_id": logstore.region_id,
            "resource_id": f"{logstore.project_name}/{logstore.logstore_name}",
            "resource_name": f"{logstore.project_name}/{logstore.logstore_name}",
            "matched_by": "sls_logstore",
        }
        results.append(d)

    # LB 日志配置
    stmt = select(LbLogConfig).where(
        or_(
            LbLogConfig.log_project.like(like_pattern),
            LbLogConfig.log_store.like(like_pattern),
        )
    )
    for config in session.execute(stmt).scalars().all():
        d = {
            "account_name": config.account_name,
            "account_display_name": config.account_display_name,
            "resource_type": "lb_log_config",
            "region_id": config.region_id,
            "resource_id": config.lb_id,
            "resource_name": f"{config.lb_name} → {config.log_project}/{config.log_store}",
            "matched_by": "lb_log_config",
        }
        results.append(d)

    return results


# ──────────────────────────────────────────────
# 资源详情查询
# ──────────────────────────────────────────────

def _with_raw_json(result_dict: dict, model_obj: object) -> dict:
    """将 model_obj 的 raw_json 字段合并到 result_dict，供 detail 显示使用"""
    raw_json = getattr(model_obj, "raw_json", None)
    if raw_json:
        result_dict["raw_json"] = raw_json
    return result_dict


def query_detail(session: Session, resource_id: str) -> dict | None:
    """查询指定资源 ID 的完整详细信息（不做关联/链路分析）

    搜索所有资源表，返回第一个匹配的资源的完整字段字典（含 raw_json）。
    如果未找到，返回 None。
    """
    # 搜索各表 — 精确匹配优先
    # ECS
    stmt = select(EcsInstance).where(EcsInstance.instance_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_ecs_to_dict(obj), obj)

    # EIP
    stmt = select(EipAddress).where(EipAddress.allocation_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_eip_to_dict(obj), obj)

    # Load Balancer
    stmt = select(LoadBalancer).where(LoadBalancer.lb_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_enrich_lb_with_eip(session, _lb_to_dict(obj)), obj)

    # RDS
    stmt = select(RdsInstance).where(RdsInstance.instance_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_rds_to_dict(obj), obj)

    # Tair
    stmt = select(TairInstance).where(TairInstance.instance_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_tair_to_dict(obj), obj)

    # PolarDB
    stmt = select(PolarDBCluster).where(PolarDBCluster.cluster_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_polardb_to_dict(obj), obj)

    # MongoDB
    stmt = select(MongoDBInstance).where(MongoDBInstance.instance_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_mongodb_to_dict(obj), obj)

    # Security Group
    stmt = select(SecurityGroup).where(SecurityGroup.security_group_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_sg_to_dict(obj), obj)

    # OSS
    stmt = select(OssBucket).where(OssBucket.bucket_name == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_oss_to_dict(obj), obj)

    # CDN
    stmt = select(CdnDomain).where(CdnDomain.domain_name == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_cdn_to_dict(obj), obj)

    # WAF
    stmt = select(WafDomain).where(WafDomain.domain_name == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_waf_to_dict(obj), obj)

    # API Gateway
    stmt = select(ApiGateway).where(ApiGateway.group_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        result_dict = _with_raw_json(_api_gateway_to_dict(obj), obj)
        # APIG 网关：查询子资源（域名、API、路由）
        if obj.api_type == "apig":
            domains = session.query(ApigDomain).filter_by(
                account_name=obj.account_name, gateway_id=obj.group_id,
            ).all()
            result_dict["apig_domains"] = [_apig_domain_to_dict(dm) for dm in domains]
            apis = session.query(ApigApi).filter_by(
                account_name=obj.account_name, gateway_id=obj.group_id,
            ).all()
            result_dict["apig_apis"] = [_apig_api_to_dict(a) for a in apis]
            routes = session.query(ApigRoute).filter_by(
                account_name=obj.account_name, gateway_id=obj.group_id,
            ).all()
            # 为每条路由附加 SAE 后端信息
            apig_routes = [_apig_route_to_dict(rt) for rt in routes]
            for rt_dict in apig_routes:
                sae_backends = rt_dict.get("sae_backends", [])
                if sae_backends:
                    # 根据 sae_app_name 查找 SaeApp 表中的应用
                    for sb in sae_backends:
                        app_stmt = select(SaeApp).where(SaeApp.app_name == sb["sae_app_name"])
                        sae_app = session.execute(app_stmt).scalar_one_or_none()
                        if sae_app:
                            sb["sae_app_id"] = sae_app.app_id
                            sb["sae_app_status"] = sae_app.status
                            # 补充命名空间名称
                            ns_stmt = select(SaeNamespace).where(
                                SaeNamespace.namespace_id == sae_app.namespace_id,
                            )
                            ns_obj = session.execute(ns_stmt).scalar_one_or_none()
                            if ns_obj:
                                sb["sae_ns_name"] = ns_obj.namespace_name or ""
            result_dict["apig_routes"] = apig_routes
        return result_dict

    # SAE 应用
    stmt = select(SaeApp).where(SaeApp.app_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        result_dict = _with_raw_json(_sae_app_to_dict(obj), obj)
        # 补充命名空间名称
        ns_stmt = select(SaeNamespace).where(
            SaeNamespace.namespace_id == obj.namespace_id,
        )
        ns_obj = session.execute(ns_stmt).scalar_one_or_none()
        if ns_obj:
            result_dict["namespace_name"] = ns_obj.namespace_name or ""
        # 反向查找：哪些 APIG 路由的后端指向该 SAE 应用
        apig_routes_to_sae = _find_apig_routes_to_sae(session, obj.app_name)
        if apig_routes_to_sae:
            result_dict["apig_routes_to_sae"] = apig_routes_to_sae
        return result_dict

    # RAM User
    stmt = select(RamUser).where(
        or_(
            RamUser.user_name == resource_id,
            RamUser.user_id == resource_id,
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        result_dict = _with_raw_json(_ram_user_to_dict(obj), obj)
        # 查询该用户的 AccessKey 列表
        ak_stmt = select(RamAccessKey).where(
            RamAccessKey.account_name == obj.account_name,
            RamAccessKey.user_name == obj.user_name,
        )
        aks = session.execute(ak_stmt).scalars().all()
        result_dict["access_keys"] = [_ram_ak_to_dict(ak) for ak in aks]
        # 查询该用户的授权策略列表
        policy_stmt = select(RamUserPolicy).where(
            RamUserPolicy.account_name == obj.account_name,
            RamUserPolicy.user_name == obj.user_name,
        )
        policies = session.execute(policy_stmt).scalars().all()
        result_dict["policies"] = [_ram_policy_to_dict(p) for p in policies]
        return result_dict

    # RAM AccessKey
    stmt = select(RamAccessKey).where(RamAccessKey.access_key_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        result_dict = _with_raw_json(_ram_ak_to_dict(obj), obj)
        # 同时查找所属的 RAM 用户
        ram_stmt = select(RamUser).where(
            RamUser.account_name == obj.account_name,
            RamUser.user_name == obj.user_name,
        )
        ram_user = session.execute(ram_stmt).scalar_one_or_none()
        if ram_user:
            result_dict["ram_user"] = _with_raw_json(_ram_user_to_dict(ram_user), ram_user)
        return result_dict

    # DNS Record — record_id 精确匹配（唯一），fqdn 匹配可能多条（轮询负载）
    stmt = select(DnsRecord).where(DnsRecord.record_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_dns_record_to_dict(obj), obj)

    # record_id 没匹配到，再按 fqdn 查找（可能多条，返回所有记录）
    stmt = select(DnsRecord).where(DnsRecord.fqdn == resource_id)
    dns_records = session.execute(stmt).scalars().all()
    if dns_records:
        # 用第一条记录的基本信息作为 Panel 内容，所有记录作为子表格
        first = dns_records[0]
        result_dict = _with_raw_json(_dns_record_to_dict(first), first)
        # 如果有多条记录，附上所有解析值列表供 detail 显示
        result_dict["all_dns_records"] = [_dns_record_to_dict(r) for r in dns_records]
        return result_dict

    # Backend Server
    stmt = select(BackendServer).where(BackendServer.backend_resource_id == resource_id)
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_backend_to_dict(obj), obj)

    # 精确匹配未找到，尝试模糊匹配
    like_pattern = f"%{resource_id}%"

    # ECS 模糊
    stmt = select(EcsInstance).where(EcsInstance.instance_id.like(like_pattern))
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_ecs_to_dict(obj), obj)

    # EIP 模糊
    stmt = select(EipAddress).where(EipAddress.allocation_id.like(like_pattern))
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_eip_to_dict(obj), obj)

    # RDS 模糊
    stmt = select(RdsInstance).where(
        or_(
            RdsInstance.instance_id.like(like_pattern),
            RdsInstance.instance_name.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_rds_to_dict(obj), obj)

    # LB 模糊
    stmt = select(LoadBalancer).where(
        or_(
            LoadBalancer.lb_id.like(like_pattern),
            LoadBalancer.lb_name.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_enrich_lb_with_eip(session, _lb_to_dict(obj)), obj)

    # Tair 模糊
    stmt = select(TairInstance).where(
        or_(
            TairInstance.instance_id.like(like_pattern),
            TairInstance.instance_name.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_tair_to_dict(obj), obj)

    # PolarDB 模糊
    stmt = select(PolarDBCluster).where(
        or_(
            PolarDBCluster.cluster_id.like(like_pattern),
            PolarDBCluster.cluster_description.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_polardb_to_dict(obj), obj)

    # MongoDB 模糊
    stmt = select(MongoDBInstance).where(
        or_(
            MongoDBInstance.instance_id.like(like_pattern),
            MongoDBInstance.instance_description.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_mongodb_to_dict(obj), obj)

    # OSS 模糊
    stmt = select(OssBucket).where(OssBucket.bucket_name.like(like_pattern))
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_oss_to_dict(obj), obj)

    # CDN 模糊
    stmt = select(CdnDomain).where(CdnDomain.domain_name.like(like_pattern))
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_cdn_to_dict(obj), obj)

    # WAF 模糊
    stmt = select(WafDomain).where(WafDomain.domain_name.like(like_pattern))
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_waf_to_dict(obj), obj)

    # API Gateway 模糊
    stmt = select(ApiGateway).where(
        or_(
            ApiGateway.group_id.like(like_pattern),
            ApiGateway.group_name.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        result_dict = _with_raw_json(_api_gateway_to_dict(obj), obj)
        if obj.api_type == "apig":
            domains = session.query(ApigDomain).filter_by(
                account_name=obj.account_name, gateway_id=obj.group_id,
            ).all()
            result_dict["apig_domains"] = [_apig_domain_to_dict(dm) for dm in domains]
            apis = session.query(ApigApi).filter_by(
                account_name=obj.account_name, gateway_id=obj.group_id,
            ).all()
            result_dict["apig_apis"] = [_apig_api_to_dict(a) for a in apis]
            routes = session.query(ApigRoute).filter_by(
                account_name=obj.account_name, gateway_id=obj.group_id,
            ).all()
            # 为每条路由附加 SAE 后端信息
            apig_routes = [_apig_route_to_dict(rt) for rt in routes]
            for rt_dict in apig_routes:
                sae_backends = rt_dict.get("sae_backends", [])
                if sae_backends:
                    for sb in sae_backends:
                        app_stmt = select(SaeApp).where(SaeApp.app_name == sb["sae_app_name"])
                        sae_app = session.execute(app_stmt).scalar_one_or_none()
                        if sae_app:
                            sb["sae_app_id"] = sae_app.app_id
                            sb["sae_app_status"] = sae_app.status
                            ns_stmt = select(SaeNamespace).where(
                                SaeNamespace.namespace_id == sae_app.namespace_id,
                            )
                            ns_obj = session.execute(ns_stmt).scalar_one_or_none()
                            if ns_obj:
                                sb["sae_ns_name"] = ns_obj.namespace_name or ""
            result_dict["apig_routes"] = apig_routes
        return result_dict

    # SAE 应用模糊
    stmt = select(SaeApp).where(
        or_(
            SaeApp.app_id.like(like_pattern),
            SaeApp.app_name.like(like_pattern),
        )
    )
    obj = session.execute(stmt).scalars().first()
    if obj:
        result_dict = _with_raw_json(_sae_app_to_dict(obj), obj)
        # 补充命名空间名称
        ns_stmt = select(SaeNamespace).where(
            SaeNamespace.namespace_id == obj.namespace_id,
        )
        ns_obj = session.execute(ns_stmt).scalar_one_or_none()
        if ns_obj:
            result_dict["namespace_name"] = ns_obj.namespace_name or ""
        # 反向查找：哪些 APIG 路由的后端指向该 SAE 应用
        apig_routes_to_sae = _find_apig_routes_to_sae(session, obj.app_name)
        if apig_routes_to_sae:
            result_dict["apig_routes_to_sae"] = apig_routes_to_sae
        return result_dict

    # ECS 模糊（实例名称）
    stmt = select(EcsInstance).where(EcsInstance.instance_name.like(like_pattern))
    obj = session.execute(stmt).scalar_one_or_none()
    if obj:
        return _with_raw_json(_ecs_to_dict(obj), obj)

    # 如果全都没找到，返回 None
    return None


def _find_apig_routes_to_sae(session: Session, sae_app_name: str) -> list[dict]:
    """反向查找：哪些 APIG 路由的后端指向指定 SAE 应用

    从 apig_routes 的 raw_json 中解析 backend.services[].name，
    匹配包含 sae_app_name 的后端服务。
    """
    # 搜索所有包含 svc.cluster.local 的 APIG 路由 raw_json
    stmt = select(ApigRoute).where(
        type_coerce(ApigRoute.raw_json, String).like(f"%{sae_app_name}%"),
    )
    routes = session.execute(stmt).scalars().all()

    results = []
    for rt in routes:
        # 解析路由的 SAE 后端
        rt_dict = _apig_route_to_dict(rt)
        sae_backends = rt_dict.get("sae_backends", [])
        # 检查是否有匹配当前 sae_app_name 的后端
        matching_backends = [
            sb for sb in sae_backends
            if sb.get("sae_app_name") == sae_app_name
        ]
        if matching_backends:
            # 查找所属 APIG 网关
            gw_stmt = select(ApiGateway).where(
                ApiGateway.account_name == rt.account_name,
                ApiGateway.api_type == "apig",
                ApiGateway.group_id == rt.gateway_id,
            )
            gw_obj = session.execute(gw_stmt).scalar_one_or_none()
            results.append({
                "gateway_id": rt.gateway_id,
                "gateway_name": gw_obj.group_name if gw_obj else "",
                "api_id": rt.api_id,
                "route_id": rt.route_id,
                "route_name": rt.route_name,
                "path": rt.path,
                "methods": rt.methods,
                "domain_names": rt.domain_names,
                "sae_backends": matching_backends,
            })

    return results
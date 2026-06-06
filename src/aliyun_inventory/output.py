"""输出格式化 — Rich 文本输出 & JSON 输出"""

import json

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from .query import QueryResult

console = Console()


# 资源类型的中文友好名映射（用于"命中资源"表格和详情显示）
TYPE_DISPLAY: dict[str, str] = {
    "ecs": "ECS",
    "eip": "EIP",
    "clb": "CLB",
    "alb": "ALB",
    "lb": "LB",
    "dns": "DNS",
    "dns_record": "DNS",
    "rds": "RDS",
    "tair": "Tair",
    "polardb": "PolarDB",
    "mongodb": "MongoDB",
    "oss": "OSS",
    "cdn": "CDN",
    "waf": "WAF",
    "api_cloudapi": "API网关",
    "api_apig": "API网关",
    "api_mse": "MSE网关",
    "api_gateway": "API网关",
    "apig": "云原生API网关",
    "apig_route": "APIG路由",
    "nacos_service": "Nacos服务",
    "backend_service": "后端服务",
    "ram_user": "RAM用户",
    "ram_ak": "RAM AK",
    "ram_user_policy": "RAM策略",
    "sls_project": "SLS",
    "security_group": "安全组",
    "backend": "后端",
    "sae": "SAE",
    "sae_namespace": "SAE命名空间",
    "sae_app": "SAE应用",
    "lb_listener": "LB监听器",
    "lb_vserver_group": "LB服务器组",
    "lb_forwarding_rule": "LB转发规则",
    "apig_domain": "APIG域名",
    "apig_api": "APIG API",
}


def _normalize_resource(resource: dict) -> dict:
    """将不同资源类型的字典统一为标准显示格式

    不同搜索函数返回的字典字段名不同（ecs 用 instance_id，dns 用 record_id 等），
    这里统一提取为 display_name / display_id / display_type / private_address / public_address
    """
    # 提取账号
    account = f"{resource.get('account_display_name', '')} / {resource.get('account_name', '')}"

    # 提取地域
    region = resource.get("region_id", "")

    # 提取资源类型
    res_type = (
        resource.get("resource_type")
        or resource.get("lb_type")
        or ""
    )
    # 如果 matched_by 是特定表名，补充类型信息
    matched_by = resource.get("matched_by", "")
    if matched_by == "ecs_instance" and not res_type:
        res_type = "ecs"
    elif matched_by == "eip_address" and not res_type:
        res_type = "eip"
    elif matched_by == "load_balancer" and not res_type:
        res_type = "lb"
    elif matched_by == "dns_record" and not res_type:
        res_type = "dns"
    elif matched_by == "backend_server" and not res_type:
        res_type = "backend"
    elif matched_by == "rds_instance" and not res_type:
        res_type = "rds"
    elif matched_by == "tair_instance" and not res_type:
        res_type = "tair"
    elif matched_by == "polardb_cluster" and not res_type:
        res_type = "polardb"
    elif matched_by == "mongodb_instance" and not res_type:
        res_type = "mongodb"
    elif matched_by == "oss_bucket" and not res_type:
        res_type = "oss"
    elif matched_by == "cdn_domain" and not res_type:
        res_type = "cdn"
    elif matched_by == "waf_domain" and not res_type:
        res_type = "waf"
    elif matched_by == "api_gateway":
        # 根据 api_type 区分传统 API 网关和云原生 API 网关
        api_type = resource.get("api_type", "")
        if api_type == "apig":
            res_type = "apig"
        else:
            res_type = "api_cloudapi"
    elif matched_by == "apig_domain":
        res_type = "apig"
    elif matched_by == "ram_user" and not res_type:
        res_type = "ram_user"
    elif matched_by == "ram_user_by_ak" and not res_type:
        res_type = "ram_user"
    elif matched_by == "access_key_id" and not res_type:
        res_type = "ram_ak"
    elif matched_by == "ram_user_policy" and not res_type:
        res_type = "ram_user_policy"
    elif matched_by == "sae_app" and not res_type:
        res_type = "sae"
    elif matched_by == "sae_service_url" and not res_type:
        res_type = "sae"

    # 通用兜底：api_type == "apig" 时，无论 matched_by 是什么，都显示为云原生API网关
    if res_type == "api_gateway" and resource.get("api_type") == "apig":
        res_type = "apig"

    # 提取资源 ID — 多种字段名兜底
    res_id = (
        resource.get("resource_id")
        or resource.get("instance_id")
        or resource.get("security_group_id")
        or resource.get("allocation_id")
        or resource.get("lb_id")
        or resource.get("record_id")
        or resource.get("backend_resource_id")
        or resource.get("cluster_id")
        or resource.get("bucket_name")
        or resource.get("domain_name")
        or resource.get("group_id")
        or resource.get("user_id")
        or resource.get("access_key_id")
        or resource.get("app_id")
        or ""
    )

    # 提取资源名称 — 多种字段名兜底
    res_name = (
        resource.get("resource_name")
        or resource.get("instance_name")
        or resource.get("security_group_name")
        or resource.get("lb_name")
        or resource.get("fqdn")
        or resource.get("cluster_description")
        or resource.get("instance_description")
        or resource.get("group_name")
        or resource.get("display_name")
        or resource.get("policy_name")
        or resource.get("app_name")
        or ""
    )

    # ── 提取内网地址 ──
    # 各类型优先使用 _to_dict 已经计算好的 private_address
    private_addr = resource.get("private_address") or ""

    if not private_addr:
        # ECS：私网 IP 列表
        private_ips = resource.get("private_ips") or []
        if isinstance(private_ips, list) and private_ips:
            private_addr = ", ".join(private_ips)

    if not private_addr:
        # RDS/Tair/PolarDB/MongoDB：连接地址 + 端口
        conn = resource.get("connection_string") or ""
        if conn:
            port = resource.get("port", "")
            private_addr = f"{conn}:{port}" if port else conn

    if not private_addr:
        conn = resource.get("private_connection_string") or ""
        if conn:
            port = resource.get("connection_port", "")
            private_addr = f"{conn}:{port}" if port else conn

    if not private_addr:
        conn = resource.get("connection_domain") or ""
        if conn:
            port = resource.get("port", "")
            private_addr = f"{conn}:{port}" if port else conn

    if not private_addr:
        conn = resource.get("private_connection") or ""
        if conn:
            port = resource.get("connection_port", "")
            private_addr = f"{conn}:{port}" if port else conn

    if not private_addr:
        # OSS：内网 Endpoint
        private_addr = resource.get("intranet_endpoint") or ""

    if not private_addr:
        # LB：DNS 名称（VPC 内部访问用）
        private_addr = resource.get("dns_name") or ""

    if not private_addr:
        # WAF：回源 IP
        source_ips = resource.get("source_ips") or []
        if isinstance(source_ips, list) and source_ips:
            private_addr = ", ".join(str(ip) for ip in source_ips)
        elif isinstance(source_ips, str) and source_ips:
            private_addr = source_ips

    if not private_addr:
        # APIG：内网接入域名
        private_addr = resource.get("private_domain") or ""

    if not private_addr:
        # SAE：内部访问地址
        private_addr = resource.get("service_url") or ""

    # ── 提取外网地址 ──
    # 各类型优先使用 _to_dict 已经计算好的 public_address
    public_addr = resource.get("public_address") or ""

    if not public_addr:
        # RDS：外网连接地址
        conn = resource.get("public_connection_string") or ""
        if conn:
            port = resource.get("public_port", "") or resource.get("port", "")
            public_addr = f"{conn}:{port}" if port else conn

    if not public_addr:
        # PolarDB：外网连接地址
        conn = resource.get("public_connection_string") or ""
        if conn:
            port = resource.get("connection_port", "")
            public_addr = f"{conn}:{port}" if port else conn

    if not public_addr:
        # Tair：外网连接域名
        conn = resource.get("public_domain") or ""
        if conn:
            port = resource.get("public_port", "") or resource.get("port", "")
            public_addr = f"{conn}:{port}" if port else conn

    if not public_addr:
        # MongoDB：外网连接地址
        conn = resource.get("public_connection") or ""
        if conn:
            port = resource.get("connection_port", "")
            public_addr = f"{conn}:{port}" if port else conn

    if not public_addr:
        # ECS：公网 IP + EIP
        public_ips = resource.get("public_ips") or []
        eip = resource.get("eip_address") or ""
        parts = list(public_ips) if isinstance(public_ips, list) else []
        if eip and eip not in parts:
            parts.append(eip)
        if parts:
            public_addr = ", ".join(parts)

    if not public_addr:
        # EIP：IP 地址
        public_addr = resource.get("ip_address") or ""

    if not public_addr:
        # LB：VIP 地址（仅公网型 LB；内网型 LB 的 address 是私网 IP，不应放在外网地址）
        address_type = resource.get("address_type", "")
        if address_type != "intranet":
            public_addr = resource.get("address") or ""

    if not public_addr:
        # OSS：外网 Endpoint
        public_addr = resource.get("endpoint") or resource.get("extranet_endpoint") or ""

    if not public_addr:
        # CDN：CNAME
        public_addr = resource.get("cname") or ""

    if not public_addr:
        # WAF：CNAME
        public_addr = resource.get("cname") or ""

    if not public_addr:
        # DNS：记录值
        public_addr = resource.get("value") or ""

    if not public_addr:
        # API Gateway：子域名
        public_addr = resource.get("sub_domain") or ""

    if not public_addr:
        # APIG：公网接入域名
        public_addr = resource.get("public_domain") or ""

    if not public_addr:
        # APIG：匹配域名
        public_addr = resource.get("matched_domain") or ""

    if not public_addr:
        # ip_addresses 表的 ip 字段兜底
        # 仅当 ip_type 指示是公网类 IP 时才归入外网地址
        ip_type = resource.get("ip_type", "")
        if ip_type in ("public", "eip", "lb_address", "dns_value"):
            public_addr = resource.get("ip") or ""

    # 如果 ip_addresses 表的 ip 是 private 类型，补充到内网地址
    if not private_addr:
        ip_type = resource.get("ip_type", "")
        if ip_type == "private":
            private_addr = resource.get("ip") or ""

    # 将资源类型转为友好显示名
    res_type_display = TYPE_DISPLAY.get(res_type, res_type)

    return {
        "account": account,
        "region": region,
        "res_type": res_type,
        "res_type_display": res_type_display,
        "res_id": res_id,
        "res_name": res_name,
        "private_address": private_addr,
        "public_address": public_addr,
    }


def _chain_type_to_title(chain_type: str) -> str:
    """将链路类型标签转为中文标题"""
    titles = {
        "dns_to_sae": "确定性链路 (DNS→APIG→SAE)",
        "dns_to_lb": "确定性链路 (DNS→LB→ECS)",
        "dns_to_cdn": "确定性链路 (DNS→CDN→回源)",
        "dns_to_waf": "确定性链路 (DNS→WAF→回源)",
        "dns_to_eip": "确定性链路 (DNS→EIP→LB→ECS)",
        "dns_to_ecs": "确定性链路 (DNS→ECS)",
        "dns_to_other": "确定性链路",
        "sae_to_dns": "确定性链路 (SAE→APIG→DNS)",
    }
    return titles.get(chain_type, "确定性链路")


def _format_chain_node_label(node: dict) -> str:
    """格式化链路节点的显示标签（Rich markup 安全 — 不使用方括号包裹类型）"""
    res_type = node.get("resource_type", "")
    res_type_display = TYPE_DISPLAY.get(res_type, res_type)
    name = node.get("resource_name", node.get("resource_id", ""))
    role = node.get("role", "")
    extra = node.get("extra_info", {})

    # 用中文括号代替 Rich 方括号 markup
    label = f"「{res_type_display}」{name}"

    # role 描述
    if role:
        label += f" ({role})"

    # 资源类型特定补充信息（role 不覆盖的）
    if res_type == "dns_record":
        rt = extra.get("record_type", "")
        val = node.get("ip", "")
        if rt and val and not role:
            label += f" {rt}→{val}"
    elif res_type == "apig":
        sub_domain = extra.get("sub_domain", "")
        if sub_domain:
            label += f" 域名:{sub_domain}"
    elif res_type == "sae":
        pass
    elif res_type in ("rds", "tair"):
        # role 已包含 connection_string/connection_domain，不再重复
        pass
    elif res_type == "polardb":
        # role 已包含 dbtype+dbversion
        pass
    elif res_type == "mongodb":
        # role 已包含 engine+engine_version
        pass
    elif res_type == "cdn" and extra.get("origin_type"):
        label += f" / 回源:{TYPE_DISPLAY.get(extra['origin_type'], extra['origin_type'])}"
    elif res_type == "waf" and extra.get("cname"):
        label += f" CNAME→{extra['cname']}"
    elif res_type == "backend" and extra.get("lb_type"):
        label += f" / {extra['lb_type'].upper()}:{extra.get('port', '')}"
    elif res_type == "oss" and extra.get("endpoint"):
        label += f" / {extra['endpoint']}"
    elif res_type == "eip" and node.get("ip"):
        label += f" / IP:{node['ip']}"
    elif res_type == "nacos_service":
        pass
    elif res_type == "backend_service":
        pass

    # 简化账号/地域显示
    account = node.get("account_display_name", "")
    region = node.get("region_id", "")
    if account:
        label += f" / {account}"
    if region:
        label += f" / {region}"

    return label


def _render_chain_tree(rich_tree: Tree, node_dict: dict) -> None:
    """递归渲染 ChainNode 树到 Rich Tree"""
    label = _format_chain_node_label(node_dict)
    branch = rich_tree.add(label)
    for child in node_dict.get("children", []):
        _render_chain_tree(branch, child)


def format_results_text(result: QueryResult, show_chain: bool = False, chain_limit: int = 0) -> None:
    """Rich 格式化输出查询结果"""
    console.print(f"\n[bold]查询: {result.query_value}[/bold] (类型: {result.query_type})")

    # 判断命中资源是否全是 DNS 类型 — 用 DNS 专用列布局
    all_dns = result.matched_resources and all(
        r.get("resource_type") == "dns" for r in result.matched_resources
    )

    # 匹配资源表
    if result.matched_resources:
        if all_dns:
            # DNS 专用表：类型 / 记录值 / 线路 / 权重 / TTL / 状态
            dns_table = Table(title="命中资源", show_lines=True)
            dns_table.add_column("账号", style="cyan", max_width=30)
            dns_table.add_column("FQDN", style="green", max_width=40)
            dns_table.add_column("类型", style="magenta", width=6)
            dns_table.add_column("记录值", style="yellow", max_width=30, no_wrap=False)
            dns_table.add_column("线路", style="cyan", width=8)
            dns_table.add_column("权重", style="white", width=6)
            dns_table.add_column("TTL", style="blue", width=6)
            dns_table.add_column("状态", style="green", width=8)

            seen_ids = set()
            for r in result.matched_resources:
                rid = r.get("resource_id", "")
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)

                account = f"{r.get('account_display_name', '')} / {r.get('account_name', '')}"
                weight = r.get("weight")
                weight_str = str(weight) if weight is not None else "-"
                dns_table.add_row(
                    account,
                    r.get("fqdn", ""),
                    r.get("record_type", ""),
                    r.get("value", ""),
                    r.get("line", "") or "-",
                    weight_str,
                    str(r.get("ttl", "")),
                    r.get("status", ""),
                )
            console.print(dns_table)
        else:
            # 通用命中资源表 — 动态显示名称列和地址列（仅在存在非空值时）
            normalized = [_normalize_resource(r) for r in result.matched_resources]
            has_name = any(n["res_name"] for n in normalized)
            has_private = any(n["private_address"] for n in normalized)
            has_public = any(n["public_address"] for n in normalized)

            table = Table(title="命中资源", show_lines=True)
            table.add_column("账号", style="cyan", max_width=30)
            table.add_column("地域", style="green", max_width=15)
            table.add_column("资源类型", style="magenta", max_width=10)
            table.add_column("资源ID", style="yellow", max_width=25)
            if has_name:
                table.add_column("资源名称", style="white", max_width=20)
            if has_private:
                table.add_column("内网地址", style="green", max_width=40, no_wrap=False)
            if has_public:
                table.add_column("外网地址", style="red", max_width=40, no_wrap=False)

            for norm in normalized:
                row = [
                    norm["account"],
                    norm["region"],
                    norm["res_type_display"],
                    norm["res_id"],
                ]
                if has_name:
                    row.append(norm["res_name"])
                if has_private:
                    row.append(norm["private_address"])
                if has_public:
                    row.append(norm["public_address"])
                table.add_row(*row)

            console.print(table)

    # 关联资源表（链路发现到的间接资源）
    if result.related_resources:
        related_normalized = [_normalize_resource(r) for r in result.related_resources]
        has_name = any(n["res_name"] for n in related_normalized)
        has_private = any(n["private_address"] for n in related_normalized)
        has_public = any(n["public_address"] for n in related_normalized)

        related_table = Table(title="关联资源", show_lines=True)
        related_table.add_column("账号", style="cyan", max_width=30)
        related_table.add_column("地域", style="green", max_width=15)
        related_table.add_column("资源类型", style="magenta", max_width=10)
        related_table.add_column("资源ID", style="yellow", max_width=25)
        if has_name:
            related_table.add_column("资源名称", style="white", max_width=20)
        if has_private:
            related_table.add_column("内网地址", style="green", max_width=40, no_wrap=False)
        if has_public:
            related_table.add_column("外网地址", style="red", max_width=40, no_wrap=False)

        for norm in related_normalized:
            row = [
                norm["account"],
                norm["region"],
                norm["res_type_display"],
                norm["res_id"],
            ]
            if has_name:
                row.append(norm["res_name"])
            if has_private:
                row.append(norm["private_address"])
            if has_public:
                row.append(norm["public_address"])
            related_table.add_row(*row)

        console.print(related_table)

    # DNS 记录表 — 仅在命中资源不全为 DNS 时显示（纯 DNS 场景已合并到命中资源表中）
    if result.dns_records and not all_dns:
        # 过滤掉非 DNS 类型的记录（避免 APIG/SAE 等资源混入导致空行）
        dns_only = [dns for dns in result.dns_records if dns.get("resource_type") == "dns"]
        if dns_only:
            dns_table = Table(title="DNS 解析记录", show_lines=True)
            dns_table.add_column("账号", style="cyan", max_width=30)
            dns_table.add_column("FQDN", style="green", max_width=40)
            dns_table.add_column("类型", style="magenta", max_width=8)
            dns_table.add_column("记录值", style="yellow", max_width=30)
            dns_table.add_column("线路", style="cyan", max_width=8)
            dns_table.add_column("权重", style="white", max_width=6)
            dns_table.add_column("TTL", style="blue", max_width=6)
            dns_table.add_column("状态", style="green", max_width=8)

            seen_ids = set()
            for dns in dns_only:
                rid = dns.get("resource_id", "")
                if rid in seen_ids:
                    continue
                seen_ids.add(rid)

                account = f"{dns.get('account_display_name', '')} / {dns.get('account_name', '')}"
                weight = dns.get("weight")
                weight_str = str(weight) if weight is not None else "-"
                dns_table.add_row(
                    account,
                    dns.get("fqdn", ""),
                    dns.get("record_type", ""),
                    dns.get("value", ""),
                    dns.get("line", "") or "-",
                    weight_str,
                    str(dns.get("ttl", "")),
                    dns.get("status", ""),
                )

            console.print(dns_table)

    # 后端服务器
    if result.backends:
        # 构建 vServerGroup ID → 名称映射
        vsg_name_map = {}
        for vsg in result.lb_vserver_groups:
            vsg_name_map[vsg["vserver_group_id"]] = vsg.get("vserver_group_name") or vsg["vserver_group_id"]

        # 预处理：确定哪些列有非空数据
        has_private_ip = any(
            b.get("backend_ip") or (b.get("matched_ecs", {}) or {}).get("private_ips")
            for b in result.backends
        )
        has_public_ip = any(
            (b.get("matched_ecs", {}) or {}).get("public_ips") or (b.get("matched_ecs", {}) or {}).get("eip_address")
            for b in result.backends
        )
        has_weight = any(b.get("weight") is not None for b in result.backends)
        has_port = any(
            b.get("port") is not None or b.get("backend_port_from_listener") is not None
            for b in result.backends
        )

        backend_table = Table(title="负载均衡后端服务器", show_lines=True)
        backend_table.add_column("服务器组", style="cyan", max_width=20)
        backend_table.add_column("后端ID", style="magenta", max_width=20)
        if has_private_ip:
            backend_table.add_column("内网IP", style="green", max_width=15)
        if has_public_ip:
            backend_table.add_column("外网IP", style="red", max_width=15)
        if has_weight:
            backend_table.add_column("权重", style="white", max_width=6)
        if has_port:
            backend_table.add_column("后端端口", style="yellow", max_width=8)
        backend_table.add_column("ECS", style="red", max_width=25)

        for backend in result.backends:
            matched_ecs = backend.get("matched_ecs", {}) or {}

            # 服务器组名称
            sg_id = backend.get("server_group_id", "")
            if sg_id:
                sg_name = vsg_name_map.get(sg_id, sg_id)
            else:
                sg_name = backend.get("server_group_name", "默认组")

            # 内网IP: 优先取 backend_ip，空则取 ECS private_ips
            private_ip = backend.get("backend_ip", "")
            if not private_ip and matched_ecs:
                private_ips = matched_ecs.get("private_ips", [])
                if isinstance(private_ips, list) and private_ips:
                    private_ip = ", ".join(private_ips)

            # 外网IP: 取 ECS public_ips + eip_address
            public_ip = ""
            if matched_ecs:
                public_ips = matched_ecs.get("public_ips", [])
                eip_addr = matched_ecs.get("eip_address", "")
                parts = list(public_ips) if isinstance(public_ips, list) else []
                if eip_addr and eip_addr not in parts:
                    parts.append(eip_addr)
                if parts:
                    public_ip = ", ".join(str(p) for p in parts)

            # 后端端口: 优先取 BackendServer.port，空则取监听器的 backend_server_port
            port_val = backend.get("port")
            if port_val is None:
                port_val = backend.get("backend_port_from_listener")
            port_str = str(port_val) if port_val is not None else ""

            # 权重
            weight_val = backend.get("weight")
            weight_str = str(weight_val) if weight_val is not None else ""

            # ECS 信息
            ecs_info = ""
            if matched_ecs:
                ecs_name = matched_ecs.get("instance_name", "")
                ecs_id = matched_ecs.get("instance_id", "")
                ecs_info = f"{ecs_name} / {ecs_id}" if ecs_name else ecs_id

            row = [sg_name, backend.get("backend_resource_id", "")]
            if has_private_ip:
                row.append(private_ip)
            if has_public_ip:
                row.append(public_ip)
            if has_weight:
                row.append(weight_str)
            if has_port:
                row.append(port_str)
            row.append(ecs_info)
            backend_table.add_row(*row)

        console.print(backend_table)

    # 转发规则表格（替代原"监听器"表格）
    if result.lb_listeners:
        # 构建 vServerGroup ID → 名称映射
        vsg_name_map = {}
        for vsg in result.lb_vserver_groups:
            vsg_name_map[vsg["vserver_group_id"]] = vsg.get("vserver_group_name") or vsg["vserver_group_id"]

        # 构建转发规则列表: (listener, forwarding_rule_or_None)
        # 每个监听器至少有一行（默认转发），HTTP/HTTPS 还有域名转发行
        forwarding_rows = []

        for ln in result.lb_listeners:
            proto = ln.get("listener_protocol", "").upper()
            port = ln.get("listener_port", "")
            listener_key = f"{proto}:{port}"

            # HTTP→HTTPS 重定向
            if ln.get("listener_forward") == "on" and ln.get("forward_port"):
                condition = f"→重定向 {proto}:{ln['forward_port']}" if proto == "HTTP" else f"→重定向 HTTPS:{ln['forward_port']}"
                # 重定向时 HTTPS 的 forward_port 应该显示为 HTTPS
                if proto == "HTTP":
                    condition = f"→HTTPS:{ln['forward_port']}"
                forwarding_rows.append({
                    "listener": listener_key,
                    "condition": condition,
                    "group": "",
                    "backend_port": "",
                })
                continue

            # 监听器默认转发
            vsg_id = ln.get("vserver_group_id", "")
            if vsg_id:
                group_name = vsg_name_map.get(vsg_id, vsg_id)
            else:
                group_name = "默认组"

            backend_port_str = str(ln.get("backend_server_port", "")) if ln.get("backend_server_port") is not None else ""
            # 如果 backend_server_port 为空，从 vServerGroup 的后端端口补充
            if not backend_port_str:
                backend_port_str = ln.get("backend_server_port_from_vsg", "")
            backend_port_display = backend_port_str

            forwarding_rows.append({
                "listener": listener_key,
                "condition": "默认",
                "group": group_name,
                "backend_port": backend_port_display,
            })

            # HTTP/HTTPS 监听器的域名转发规则
            if proto in ("HTTP", "HTTPS"):
                # 查找该监听器的转发规则
                for rule in result.lb_forwarding_rules:
                    if rule.get("listener_port") == ln.get("listener_port") and \
                       rule.get("listener_protocol", "").lower() == ln.get("listener_protocol", "").lower():
                        rule_vsg_id = rule.get("vserver_group_id", "")
                        if rule_vsg_id:
                            rule_group_name = vsg_name_map.get(rule_vsg_id, rule_vsg_id)
                        else:
                            rule_group_name = "默认组"

                        # 构建条件显示：domain + url
                        domain = rule.get("domain", "")
                        url_path = rule.get("url", "")
                        condition = domain
                        if url_path:
                            condition = f"{domain}{url_path}"

                        # 后端端口：从 vServerGroup 的后端服务器查出
                        rule_backend_port = rule.get("backend_port", "")

                        forwarding_rows.append({
                            "listener": listener_key,
                            "condition": condition,
                            "group": rule_group_name,
                            "backend_port": rule_backend_port,
                        })

        if forwarding_rows:
            rule_table = Table(title="转发规则", show_lines=True)
            rule_table.add_column("监听", style="magenta", max_width=12)
            rule_table.add_column("条件", style="green", max_width=25)
            rule_table.add_column("服务器组", style="cyan", max_width=20)
            rule_table.add_column("后端端口", style="yellow", max_width=8)

            for row in forwarding_rows:
                rule_table.add_row(
                    row["listener"],
                    row["condition"],
                    row["group"],
                    row["backend_port"],
                )

            console.print(rule_table)

    # LB 访问日志 SLS 配置
    if result.lb_log_configs:
        log_table = Table(title="访问日志 SLS 配置", show_lines=True)
        log_table.add_column("账号", style="cyan", max_width=30)
        log_table.add_column("LB", style="green", max_width=20)
        log_table.add_column("地域", style="white", max_width=15)
        log_table.add_column("SLS 项目", style="yellow", max_width=20)
        log_table.add_column("日志库", style="magenta", max_width=20)
        log_table.add_column("日志类型", style="blue", max_width=10)

        for config in result.lb_log_configs:
            account = f"{config.get('account_display_name', '')} / {config.get('account_name', '')}"
            log_table.add_row(
                account,
                config.get("lb_name", config.get("lb_id", "")),
                config.get("region_id", ""),
                config.get("log_project", ""),
                config.get("log_store", ""),
                config.get("log_type", ""),
            )

        console.print(log_table)

    # 链路树（嵌套树式显示）
    if result.chain_trees:
        chain_count = len(result.chain_trees)
        # ≤5 条自动展示，>5 条需 --chain 才展开
        show_chain_detail = show_chain or chain_count <= 5

        if not show_chain_detail:
            # 折叠模式：只显示摘要
            console.print(f"\n[bold]确定性链路: {chain_count} 条[/bold]")
            console.print("[dim]  使用 --chain 查看完整链路详情[/dim]")
            console.print("[dim]  使用 --chain --limit 5 只看前 5 条[/dim]")
        else:
            # 展示模式：完整树形渲染
            trees_to_show = result.chain_trees
            if chain_limit > 0 and chain_limit < chain_count:
                trees_to_show = trees_to_show[:chain_limit]

            for i, tree_root in enumerate(trees_to_show):
                chain_type = ""
                if result.chain_types and i < len(result.chain_types):
                    chain_type = result.chain_types[i]

                # 标题
                title = _chain_type_to_title(chain_type)

                # 根节点标签
                root_label = f"[bold]{tree_root.get('resource_name', tree_root.get('resource_id', ''))}[/bold]"
                role = tree_root.get("role", "")
                if role:
                    root_label += f" [{role}]"
                account = tree_root.get("account_display_name", "")
                if account:
                    root_label += f" ({account})"

                rich_tree = Tree(root_label)
                for child in tree_root.get("children", []):
                    _render_chain_tree(rich_tree, child)

                console.print(f"\n[bold]{title}:[/bold]")
                console.print(rich_tree)

            if chain_limit > 0 and chain_count > chain_limit:
                console.print(f"\n[dim]... 还有 {chain_count - chain_limit} 条链路未显示[/dim]")

    # 警告
    for warning in result.warnings:
        console.print(f"[yellow]⚠ {warning}[/yellow]")


def format_results_json(result: QueryResult) -> str:
    """JSON 格式化输出查询结果（给 hermes agent 调用）"""
    output = {
        "query": {
            "type": result.query_type,
            "value": result.query_value,
        },
        "matched_resources": result.matched_resources,
        "related_resources": result.related_resources,
        "dns_records": result.dns_records,
        "backends": result.backends,
        "lb_listeners": result.lb_listeners,
        "lb_vserver_groups": result.lb_vserver_groups,
        "lb_forwarding_rules": result.lb_forwarding_rules,
        "lb_log_configs": result.lb_log_configs,
        "chains": result.chains,
        "chain_types": result.chain_types,
        "chain_trees": result.chain_trees,
        "warnings": result.warnings,
    }

    return json.dumps(output, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────
# 资源详情显示
# ──────────────────────────────────────────────

# 每种资源类型的字段模板：(字段key, 中文标签)
DETAIL_FIELDS: dict[str, list[tuple[str, str]]] = {
    "ecs": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("zone_id", "可用区"),
        ("instance_id", "实例ID"),
        ("instance_name", "实例名称"),
        ("status", "状态"),
        ("vpc_id", "VPC"),
        ("private_address", "内网IP"),
        ("public_address", "公网IP"),
        ("nat_ip_address", "NAT IP"),
        ("security_groups_display", "安全组"),
        ("disks_display", "块存储(磁盘)"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:ExpiredTime", "到期时间"),
        ("_raw:InstanceTypeFamily", "规格族"),
        ("_raw:OSName", "操作系统"),
        ("_raw:Cpu", "CPU核数"),
        ("_raw:Memory", "内存(MB)"),
    ],
    "rds": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("zone_id", "可用区"),
        ("instance_id", "实例ID"),
        ("instance_name", "实例名称"),
        ("engine", "引擎"),
        ("engine_version", "版本"),
        ("instance_type", "角色"),
        ("instance_class", "规格"),
        ("instance_status", "状态"),
        ("private_address", "内网连接地址"),
        ("public_address", "外网连接地址"),
        ("vpc_id", "VPC"),
        ("vswitch_id", "vSwitch"),
        ("category", "类别"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:ExpireTime", "到期时间"),
        ("_raw:PayType", "付费类型"),
        ("_raw:DBInstanceStorageType", "存储类型"),
        ("_raw:DBInstanceNetType", "网络类型"),
        ("_raw:DBInstanceMemory", "内存(MB)"),
        ("_raw:DBInstanceCPU", "CPU核数"),
        ("_raw:DBInstanceStorage", "存储容量(GB)"),
    ],
    "tair": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("zone_id", "可用区"),
        ("instance_id", "实例ID"),
        ("instance_name", "实例名称"),
        ("instance_type", "实例类型"),
        ("instance_class", "规格"),
        ("instance_status", "状态"),
        ("engine_version", "版本"),
        ("private_address", "内网连接地址"),
        ("public_address", "外网连接地址"),
        ("bandwidth", "带宽"),
        ("capacity", "容量"),
        ("vpc_id", "VPC"),
        ("vswitch_id", "vSwitch"),
        ("charge_type", "付费类型"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:EndTime", "到期时间"),
        ("_raw:ArchitectureType", "架构类型"),
        ("_raw:StorageType", "存储类型"),
    ],
    "polardb": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("zone_id", "可用区"),
        ("cluster_id", "集群ID"),
        ("cluster_description", "描述"),
        ("dbtype", "引擎"),
        ("dbversion", "版本"),
        ("category", "集群类别"),
        ("cluster_status", "状态"),
        ("private_address", "内网连接地址"),
        ("public_address", "外网连接地址"),
        ("vpc_id", "VPC"),
        ("vswitch_id", "vSwitch"),
        ("pay_type", "付费类型"),
        ("cpu_cores", "CPU"),
        ("memory_size", "内存(MB)"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:ExpireTime", "到期时间"),
        ("_raw:StoragePayType", "存储付费类型"),
        ("_raw:DBNodeNumber", "节点数量"),
    ],
    "mongodb": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("zone_id", "可用区"),
        ("instance_id", "实例ID"),
        ("instance_description", "描述"),
        ("dbinstance_type", "架构类型"),
        ("dbinstance_class", "规格"),
        ("dbinstance_status", "状态"),
        ("engine", "引擎"),
        ("engine_version", "版本"),
        ("network_type", "网络类型"),
        ("private_address", "内网连接地址"),
        ("public_address", "外网连接地址"),
        ("vpc_id", "VPC"),
        ("charge_type", "付费类型"),
        ("storage_type", "存储类型"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:ExpireTime", "到期时间"),
        ("_raw:ReplicationFactor", "副本数"),
    ],
    "eip": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("allocation_id", "分配ID"),
        ("ip_address", "IP地址"),
        ("status", "状态"),
        ("instance_type", "绑定类型"),
        ("instance_id", "绑定实例ID"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:ChargeType", "付费类型"),
        ("_raw:Bandwidth", "带宽"),
    ],
    "clb": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("lb_type", "负载均衡类型"),
        ("lb_id", "LB ID"),
        ("lb_name", "名称"),
        ("status", "状态"),
        ("address", "VIP地址"),
        ("address_type", "地址类型"),
        ("dns_name", "DNS名称"),
        ("vpc_id", "VPC"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:PayType", "付费类型"),
        ("_raw:LoadBalancerSpec", "规格"),
        ("_raw:Bandwidth", "带宽"),
    ],
    "alb": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("lb_type", "负载均衡类型"),
        ("lb_id", "LB ID"),
        ("lb_name", "名称"),
        ("status", "状态"),
        ("address", "VIP地址"),
        ("address_type", "地址类型"),
        ("dns_name", "DNS名称"),
        ("vpc_id", "VPC"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:PayType", "付费类型"),
        ("_raw:Edition", "版本"),
        ("_raw:Capacity", "容量"),
    ],
    "lb": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("lb_type", "负载均衡类型"),
        ("lb_id", "LB ID"),
        ("lb_name", "名称"),
        ("status", "状态"),
        ("address", "VIP地址"),
        ("address_type", "地址类型"),
        ("dns_name", "DNS名称"),
        ("vpc_id", "VPC"),
        ("_raw:CreateTime", "创建时间"),
        ("_raw:PayType", "付费类型"),
    ],
    "oss": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("bucket_name", "Bucket名"),
        ("storage_class", "存储类型"),
        ("acl", "ACL"),
        ("endpoint", "外网Endpoint"),
        ("intranet_endpoint", "内网Endpoint"),
        ("_raw:CreationDate", "创建时间"),
        ("_raw:Location", "地域"),
    ],
    "cdn": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("domain_name", "域名"),
        ("cdn_type", "加速类型"),
        ("domain_status", "状态"),
        ("cname", "CNAME"),
        ("coverage", "覆盖范围"),
        ("origin_type", "回源类型"),
        ("origin_address", "回源地址"),
        ("ssl_protocol", "SSL"),
        ("_raw:Cname", "CNAME确认"),
        ("_raw:DomainType", "域名类型"),
    ],
    "waf": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("domain_name", "域名"),
        ("instance_id", "WAF实例ID"),
        ("cname", "CNAME"),
        ("cluster_type", "集群类型"),
        ("access_type", "接入类型"),
        ("http_port", "HTTP端口"),
        ("https_port", "HTTPS端口"),
        ("source_ips", "回源IP"),
        ("_raw:CloudType", "云类型"),
        ("_raw:Http2Port", "HTTP2端口"),
    ],
    "apig": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("api_type", "类型"),
        ("group_id", "网关ID"),
        ("group_name", "网关名"),
        ("description", "规格"),
        ("status", "状态"),
        ("public_domain", "公网域名"),
        ("private_domain", "内网域名"),
        ("public_address", "公网地址"),
        ("private_address", "内网地址"),
        ("vpc_id", "VPC"),
        ("_raw:GatewayEdition", "版本"),
        ("_raw:GatewayType", "网关类型"),
        ("_raw:CreateTime", "创建时间"),
    ],
    "api_gateway": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("api_type", "类型"),
        ("group_id", "分组ID"),
        ("group_name", "分组名"),
        ("description", "描述"),
        ("base_path", "基础路径"),
        ("sub_domain", "子域名"),
        ("status", "状态"),
        ("instance_id", "实例ID"),
        ("vpc_id", "VPC"),
        ("_raw:CreatedTime", "创建时间"),
        ("_raw:ModifiedTime", "修改时间"),
    ],
    "sae": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("region_id", "地域"),
        ("namespace_name", "命名空间"),
        ("app_id", "应用ID"),
        ("app_name", "应用名"),
        ("app_type", "类型"),
        ("programming_language", "语言"),
        ("status", "状态"),
        ("running_instances", "运行实例"),
        ("instance_count", "配置实例"),
        ("cpu", "CPU(m)"),
        ("memory", "内存(MB)"),
        ("image_url", "镜像"),
        ("service_url", "内部访问地址"),
        ("app_description", "描述"),
        ("vpc_id", "VPC"),
    ],
    "dns": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("fqdn", "FQDN"),
        ("domain_name", "域名"),
        ("rr", "主机记录"),
        ("record_type", "记录类型"),
        ("value", "记录值"),
        ("ttl", "TTL"),
        ("status", "状态"),
    ],
    "ram_user": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("user_id", "用户ID"),
        ("user_name", "用户名"),
        ("display_name", "显示名"),
        ("create_time", "创建时间"),
        ("update_time", "更新时间"),
        ("_raw:LastLoginDate", "最后登录"),
        ("_raw:MFADeviceType", "MFA类型"),
    ],
    "ram_ak": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("account_name", "账号名"),
        ("user_name", "用户名"),
        ("access_key_id", "AccessKey ID"),
        ("ak_name", "AK名称"),
        ("status", "状态"),
        ("create_time", "创建时间"),
        ("expiration_time", "过期时间"),
        ("last_used_date", "最后使用"),
    ],
    "ram_user_policy": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("user_name", "用户名"),
        ("policy_name", "策略名称"),
        ("policy_type", "策略类型"),
        ("description", "描述"),
        ("default_version", "版本"),
        ("attach_date", "绑定时间"),
    ],
    "security_group": [
        ("resource_type_display", "资源类型"),
        ("account_display_name", "账号"),
        ("region_id", "地域"),
        ("security_group_id", "安全组ID"),
        ("security_group_name", "名称"),
        ("security_group_type", "类型"),
        ("description", "描述"),
        ("vpc_id", "VPC"),
        ("inner_access_policy", "组内互通"),
        ("rule_count", "规则数量"),
    ],
}

# 资源类型的中文标题
TYPE_TITLES: dict[str, str] = {
    "ecs": "ECS 实例",
    "rds": "RDS 数据库",
    "tair": "Tair/Redis",
    "polardb": "PolarDB 集群",
    "mongodb": "MongoDB",
    "eip": "EIP 弹性公网IP",
    "clb": "CLB 负载均衡",
    "alb": "ALB 负载均衡",
    "lb": "负载均衡",
    "oss": "OSS 存储桶",
    "cdn": "CDN 加速域名",
    "waf": "WAF 防护域名",
    "api_cloudapi": "API 网关",
    "api_apig": "API 网关",
    "api_mse": "MSE 网关",
    "api_gateway": "API 网关",
    "apig": "云原生API网关",
    "dns": "DNS 域名",
    "dns_record": "DNS 解析记录",
    "ram_user": "RAM 用户",
    "ram_ak": "RAM AccessKey",
    "ram_user_policy": "RAM 授权策略",
    "security_group": "安全组",
    "sae": "SAE 应用",
    "sae_namespace": "SAE 命名空间",
    "sls_project": "SLS 项目",
    "backend": "后端服务器",
    "apig_domain": "APIG 域名",
    "apig_api": "APIG API",
    "apig_route": "APIG 路由",
}


def _format_value(value: object) -> str:
    """格式化字段值用于详情显示"""
    if value is None:
        return "-"
    if isinstance(value, list):
        if not value:
            return "-"
        return ", ".join(str(v) for v in value)
    if isinstance(value, bool):
        return "✓" if value else "✗"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value) if value else "-"


def format_detail_text(resource_dict: dict) -> None:
    """Rich 格式化输出单个资源的完整详细信息"""
    res_type = resource_dict.get("resource_type") or resource_dict.get("lb_type") or ""
    # 云原生 API 网关 (APIG): api_type="apig" 时使用专用模板和标题
    if res_type == "api_gateway" and resource_dict.get("api_type") == "apig":
        res_type = "apig"
    title = TYPE_TITLES.get(res_type, res_type or "资源")

    # 注入 resource_type_display，让详情中第一行显示资源类型名
    resource_dict["resource_type_display"] = TYPE_TITLES.get(res_type, res_type)

    # 查找对应的字段模板
    fields = DETAIL_FIELDS.get(res_type)
    if not fields:
        # 没有专用模板，使用通用模板：展示所有非空字段
        fields = [("resource_type_display", "资源类型")]
        skip_keys = {"matched_by", "resource_type", "lb_type", "raw_json", "last_seen_at",
                      "resource_type_display", "security_groups", "security_groups_display",
                      "disks", "disks_display", "rules", "rules_display",
                      "access_keys", "policies", "ram_user"}
        for key in resource_dict:
            if key not in skip_keys and resource_dict[key] is not None:
                fields.append((key, key))

    # 获取 raw_json（用于 _raw: 前缀的字段）
    raw_json = resource_dict.get("raw_json") or {}

    # 构建 Panel 内容（跳过列表型字段，它们用子表格展示）
    skip_keys_in_panel = {"security_groups", "security_groups_display", "disks", "disks_display",
                          "rules", "rules_display", "access_keys", "policies", "ram_user",
                          "apig_domains", "apig_apis", "apig_routes",
                          "apig_routes_to_sae", "all_dns_records"}
    from rich.panel import Panel
    lines = []
    for field_key, label in fields:
        if field_key in skip_keys_in_panel:
            continue  # 安全组、磁盘等用子表格展示
        # _raw: 前缀的字段从 raw_json 中提取
        if field_key.startswith("_raw:"):
            raw_key = field_key[5:]
            value = _extract_raw_field(raw_json, raw_key)
        else:
            value = resource_dict.get(field_key)
        # DNS 多条记录时，value 字段显示所有解析值的汇总
        if res_type == "dns" and field_key == "value":
            all_dns = resource_dict.get("all_dns_records") or []
            if len(all_dns) > 1:
                value = ", ".join(r.get("value", "") for r in all_dns)
        display = _format_value(value)
        # 跳过空值（-）以避免面板过长
        if display == "-":
            continue
        lines.append(f"[cyan]{label}:[/cyan]  {display}")

    content = "\n".join(lines)
    panel = Panel(content, title=f"[bold]{title} 详情[/bold]", border_style="blue", padding=(1, 2))
    console.print(panel)

    # ── DNS 多记录子表格（同一 fqdn 有多条解析值时显示）──
    all_dns_records = resource_dict.get("all_dns_records") or []
    if len(all_dns_records) > 1:
        dns_table = Table(title="所有解析记录", show_lines=True, border_style="green", expand=True)
        dns_table.add_column("记录ID", style="yellow", min_width=20)
        dns_table.add_column("类型", style="magenta", width=6)
        dns_table.add_column("记录值", style="white", no_wrap=False)
        dns_table.add_column("线路", style="cyan", width=8)
        dns_table.add_column("权重", style="white", width=6)
        dns_table.add_column("TTL", style="cyan", width=6)
        dns_table.add_column("状态", style="blue", width=8)
        dns_table.add_column("账号", style="cyan", no_wrap=False)
        for rec in all_dns_records:
            account = f"{rec.get('account_display_name', '')} / {rec.get('account_name', '')}"
            weight = rec.get("weight")
            weight_str = str(weight) if weight is not None else "-"
            dns_table.add_row(
                str(rec.get("resource_id", "")),
                rec.get("record_type", ""),
                rec.get("value", ""),
                rec.get("line", "") or "-",
                weight_str,
                str(rec.get("ttl", "")),
                rec.get("status", ""),
                account,
            )
        console.print(dns_table)

    # ── 安全组子表格 ──
    security_groups = resource_dict.get("security_groups") or []
    if security_groups:
        sg_table = Table(title="安全组", show_lines=True, border_style="green", expand=True)
        sg_table.add_column("安全组ID", style="yellow", min_width=28)
        sg_table.add_column("名称", style="white", min_width=12)
        sg_table.add_column("类型", style="magenta", width=10)
        sg_table.add_column("描述", style="cyan", no_wrap=False)
        for sg in security_groups:
            sg_table.add_row(
                sg.get("security_group_id", ""),
                sg.get("security_group_name", ""),
                sg.get("security_group_type", ""),
                sg.get("description", ""),
            )
        console.print(sg_table)

    # ── 磁盘子表格 ──
    disks = resource_dict.get("disks") or []
    if disks:
        disk_table = Table(title="块存储(磁盘)", show_lines=True, border_style="green")
        disk_table.add_column("磁盘ID", style="yellow", min_width=22)
        disk_table.add_column("名称", style="white", min_width=6)
        disk_table.add_column("类型", style="magenta", min_width=6)
        disk_table.add_column("类别", style="green", min_width=10)
        disk_table.add_column("大小", style="blue", min_width=6)
        disk_table.add_column("设备", style="cyan", min_width=10)
        disk_table.add_column("删除策略", style="red", min_width=8)
        disk_table.add_column("加密", style="magenta", width=4)
        disk_table.add_column("性能", style="green", width=4)
        disk_table.add_column("付费", style="white", min_width=8)
        for dk in disks:
            disk_name = dk.get("disk_name", "") or "-"
            disk_table.add_row(
                dk.get("disk_id", ""),
                disk_name,
                dk.get("type", ""),
                dk.get("category", ""),
                f"{dk.get('size', '')}GB",
                dk.get("device", ""),
                "随实例删" if dk.get("delete_with_instance") else "独立",
                "✓" if dk.get("encrypted") else "-",
                dk.get("performance_level", "") or "-",
                dk.get("disk_charge_type", "") or "-",
            )
        console.print(disk_table)

    # ── 安全组规则子表格（仅 security_group 类型详情显示）──
    rules = resource_dict.get("rules") or []
    if rules:
        rule_table = Table(title="安全组规则", show_lines=True, border_style="yellow", expand=True)
        rule_table.add_column("方向", style="magenta", width=6)
        rule_table.add_column("策略", style="green", width=6)
        rule_table.add_column("协议", style="cyan", width=8)
        rule_table.add_column("端口范围", style="yellow", min_width=14)
        rule_table.add_column("源/目标地址", style="white", min_width=18)
        rule_table.add_column("优先级", style="blue", width=4)
        rule_table.add_column("网卡", style="dim", width=8)
        rule_table.add_column("描述", style="cyan", no_wrap=False)
        for r in rules:
            direction = "入方向" if r.get("direction") == "ingress" else "出方向"
            policy = r.get("policy", "")
            ip_proto = r.get("ip_protocol", "")
            port_range = r.get("port_range", "")
            # ingress 显示源地址，egress 显示目标地址
            if r.get("direction") == "ingress":
                address = r.get("source_cidr_ip") or r.get("source_group_id") or ""
            else:
                address = r.get("dest_cidr_ip") or r.get("dest_group_id") or ""
            priority = str(r.get("priority", "")) if r.get("priority") else ""
            nic_type = r.get("nic_type", "")
            desc = r.get("description", "") or ""
            rule_table.add_row(
                direction,
                policy,
                ip_proto,
                port_range,
                address,
                priority,
                nic_type,
                desc,
            )
        console.print(rule_table)

    # ── AccessKey 子表格（仅 ram_user 类型详情显示）──
    access_keys = resource_dict.get("access_keys") or []
    if access_keys:
        ak_table = Table(title="AccessKey 列表", show_lines=True, border_style="green", expand=True)
        ak_table.add_column("AccessKey ID", style="yellow", min_width=20)
        ak_table.add_column("名称", style="white", min_width=8)
        ak_table.add_column("状态", style="magenta", width=8)
        ak_table.add_column("创建时间", style="cyan", min_width=18)
        ak_table.add_column("过期时间", style="red", min_width=18)
        ak_table.add_column("最后使用", style="green", min_width=18)
        for ak in access_keys:
            ak_table.add_row(
                ak.get("access_key_id", ""),
                ak.get("ak_name", "") or "-",
                ak.get("status", ""),
                ak.get("create_time", ""),
                ak.get("expiration_time", "") or "-",
                ak.get("last_used_date", "") or "-",
            )
        console.print(ak_table)

    # ── 授权策略子表格（仅 ram_user 类型详情显示）──
    policies = resource_dict.get("policies") or []
    if policies:
        policy_table = Table(title="授权策略", show_lines=True, border_style="yellow", expand=True)
        policy_table.add_column("策略名称", style="yellow", min_width=20)
        policy_table.add_column("类型", style="magenta", width=8)
        policy_table.add_column("描述", style="cyan", no_wrap=False)
        policy_table.add_column("版本", style="blue", width=8)
        policy_table.add_column("绑定时间", style="green", min_width=18)
        for p in policies:
            policy_table.add_row(
                p.get("policy_name", ""),
                p.get("policy_type", ""),
                p.get("description", "") or "-",
                p.get("default_version", "") or "-",
                p.get("attach_date", "") or "-",
            )
        console.print(policy_table)

    # ── APIG 域名子表格（仅云原生API网关详情显示）──
    apig_domains = resource_dict.get("apig_domains") or []
    if apig_domains:
        domain_table = Table(title="接入域名", show_lines=True, border_style="green", expand=True)
        domain_table.add_column("类型", style="magenta", width=8)
        domain_table.add_column("域名", style="yellow", no_wrap=False)
        domain_table.add_column("网络", style="cyan", width=8)
        domain_table.add_column("协议", style="green", width=6)
        domain_table.add_column("SSL证书", style="dim", no_wrap=False)
        domain_table.add_column("强制HTTPS", style="white", width=8)
        domain_table.add_column("状态", style="blue", width=10)
        for dm in apig_domains:
            # domain_type: default → 默认, custom → 自定义
            dm_type = "默认" if dm.get("domain_type") == "default" else "自定义"
            network = dm.get("network_type", "") or ""
            network_display = {"Internet": "公网", "Intranet": "内网"}.get(network, network) or "-"
            domain_table.add_row(
                dm_type,
                dm.get("domain_name", ""),
                network_display,
                dm.get("protocol", "") or "-",
                dm.get("cert_identifier", "") or "-",
                "✓" if dm.get("force_https") else "-",
                dm.get("status", "") or "-",
            )
        console.print(domain_table)

    # ── APIG API 列表子表格 ──
    apig_apis = resource_dict.get("apig_apis") or []
    if apig_apis:
        # 计算 API → 路由数量映射
        apig_routes = resource_dict.get("apig_routes") or []
        route_count_map = {}
        for rt in apig_routes:
            api_id = rt.get("api_id", "")
            route_count_map[api_id] = route_count_map.get(api_id, 0) + 1

        api_table = Table(title="API 列表", show_lines=True, border_style="green", expand=True)
        api_table.add_column("API名称", style="yellow", no_wrap=False)
        api_table.add_column("类型", style="magenta", width=8)
        api_table.add_column("路径前缀", style="cyan", no_wrap=False)
        api_table.add_column("描述", style="white", no_wrap=False)
        api_table.add_column("路由数", style="blue", width=6)
        for a in apig_apis:
            route_count = route_count_map.get(a.get("api_id", ""), 0)
            api_table.add_row(
                a.get("api_name", ""),
                a.get("api_type", "") or "-",
                a.get("base_path", "") or "-",
                a.get("description", "") or "-",
                str(route_count),
            )
        console.print(api_table)

    # ── APIG 路由列表子表格 ──
    apig_routes = resource_dict.get("apig_routes") or []
    if apig_routes:
        # 构建 api_id → api_name 映射
        api_name_map = {}
        for a in apig_apis:
            api_name_map[a.get("api_id", "")] = a.get("api_name", "")

        route_table = Table(title="路由列表", show_lines=True, border_style="yellow", expand=True)
        route_table.add_column("API", style="magenta", no_wrap=False)
        route_table.add_column("路由名称", style="yellow", no_wrap=False)
        route_table.add_column("绑定域名", style="cyan", no_wrap=False)
        route_table.add_column("路径", style="green", no_wrap=False)
        route_table.add_column("路径类型", style="dim", width=8)
        route_table.add_column("方法", style="blue", width=10)
        route_table.add_column("后端(SAE)", style="red", no_wrap=False)
        route_table.add_column("状态", style="white", width=10)
        for rt in apig_routes:
            methods = rt.get("methods", []) or []
            methods_str = ", ".join(methods) if methods else "-"
            api_name = api_name_map.get(rt.get("api_id", ""), rt.get("api_id", ""))
            # 提取 SAE 后端名称
            sae_backends = rt.get("sae_backends", []) or []
            sae_str = ", ".join(sb.get("sae_app_name", "") for sb in sae_backends) if sae_backends else "-"
            route_table.add_row(
                api_name,
                rt.get("route_name", "") or "-",
                rt.get("domain_names", "") or "-",
                rt.get("path", "") or "-",
                rt.get("path_type", "") or "-",
                methods_str,
                sae_str,
                rt.get("deploy_status", "") or "-",
            )
        console.print(route_table)

    # ── SAE 应用 → APIG 路由关联子表格（仅 SAE 应用详情显示）──
    apig_routes_to_sae = resource_dict.get("apig_routes_to_sae") or []
    if apig_routes_to_sae:
        route_assoc_table = Table(title="关联的 APIG 路由", show_lines=True, border_style="red", expand=True)
        route_assoc_table.add_column("网关", style="magenta", no_wrap=False)
        route_assoc_table.add_column("路由名", style="yellow", no_wrap=False)
        route_assoc_table.add_column("绑定域名", style="cyan", no_wrap=False)
        route_assoc_table.add_column("路径", style="green", no_wrap=False)
        route_assoc_table.add_column("方法", style="blue", width=10)
        for route_assoc in apig_routes_to_sae:
            methods = route_assoc.get("methods", []) or []
            methods_str = ", ".join(methods) if methods else "-"
            gw_name = route_assoc.get("gateway_name", "") or route_assoc.get("gateway_id", "")
            route_assoc_table.add_row(
                gw_name,
                route_assoc.get("route_name", "") or "-",
                route_assoc.get("domain_names", "") or "-",
                route_assoc.get("path", "") or "-",
                methods_str,
            )
        console.print(route_assoc_table)

    # ── 所属 RAM 用户面板（仅 ram_ak 类型详情显示）──
    ram_user_info = resource_dict.get("ram_user")
    if ram_user_info:
        from rich.panel import Panel
        user_lines = []
        user_lines.append(f"[cyan]用户名:[/cyan]  {ram_user_info.get('user_name', '')}")
        user_lines.append(f"[cyan]显示名:[/cyan]  {ram_user_info.get('display_name', '')}")
        user_lines.append(f"[cyan]用户ID:[/cyan]  {ram_user_info.get('user_id', '')}")
        user_lines.append(f"[cyan]账号:[/cyan]  {ram_user_info.get('account_display_name', '')}")
        user_panel = Panel(
            "\n".join(user_lines),
            title="[bold]所属 RAM 用户[/bold]",
            border_style="green",
            padding=(1, 2),
        )
        console.print(user_panel)


def _extract_raw_field(raw_json: dict, key: str) -> object:
    """从 raw_json 中提取指定字段，支持点号分隔的嵌套路径"""
    if not raw_json:
        return None
    # 支持嵌套路径，如 "Body.Attribute.Key"
    parts = key.split(".")
    current = raw_json
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            idx = int(part)
            if idx < len(current):
                current = current[idx]
            else:
                return None
        else:
            return None
    return current


# ──────────────────────────────────────────────
# 资源类型列表输出（query list 命令）
# ──────────────────────────────────────────────

# 每种资源类型的列配置：(dict_key, 列标题, style, max_width_or_0)
# max_width=0 表示不限制宽度（由 Rich 自动计算）
LIST_COLUMNS: dict[str, list[tuple[str, str, str, int]]] = {
    "ecs": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("instance_id", "实例ID", "yellow", 25),
        ("instance_name", "名称", "white", 20),
        ("status", "状态", "blue", 10),
        ("private_ips", "内网地址", "green", 0),
        ("public_ips", "外网地址", "red", 0),
        ("eip_address", "EIP", "magenta", 0),
    ],
    "dns": [
        ("account_display_name", "账号", "cyan", 30),
        ("domain_name", "域名", "green", 0),
        ("total_records", "记录总数", "yellow", 8),
        ("enabled_records", "启用", "blue", 8),
        ("disabled_records", "禁用", "magenta", 8),
    ],
    "eip": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("allocation_id", "ID", "yellow", 25),
        ("ip_address", "IP", "red", 0),
        ("status", "状态", "blue", 10),
        ("instance_type", "绑定类型", "magenta", 20),
        ("instance_id", "绑定实例", "white", 0),
    ],
    "clb": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("lb_id", "LB ID", "yellow", 25),
        ("lb_name", "名称", "white", 20),
        ("status", "状态", "blue", 10),
        ("address", "地址", "red", 0),
        ("address_type", "地址类型", "magenta", 10),
    ],
    "alb": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("lb_id", "LB ID", "yellow", 25),
        ("lb_name", "名称", "white", 20),
        ("status", "状态", "blue", 10),
        ("address", "地址", "red", 0),
        ("address_type", "地址类型", "magenta", 10),
    ],
    "cdn": [
        ("account_display_name", "账号", "cyan", 30),
        ("domain_name", "域名", "green", 0),
        ("cname", "CNAME", "yellow", 0),
        ("cdn_type", "类型", "magenta", 8),
        ("domain_status", "状态", "blue", 10),
        ("coverage", "覆盖", "white", 8),
        ("origin_type", "回源类型", "cyan", 10),
        ("ssl_protocol", "SSL", "green", 6),
    ],
    "waf": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("domain_name", "域名", "green", 0),
        ("instance_id", "实例ID", "yellow", 20),
        ("cname", "CNAME", "magenta", 0),
        ("cluster_type", "集群", "white", 10),
        ("access_type", "接入", "cyan", 10),
    ],
    "api": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("api_type", "类型", "magenta", 12),
        ("group_id", "ID", "yellow", 25),
        ("group_name", "名称", "white", 20),
        ("status", "状态", "blue", 10),
        ("sub_domain", "域名", "green", 0),
        ("vpc_id", "VPC", "cyan", 20),
    ],
    "oss": [
        ("account_display_name", "账号", "cyan", 30),
        ("region", "地域", "green", 15),
        ("bucket_name", "桶名", "yellow", 0),
        ("storage_class", "存储类型", "magenta", 12),
        ("access_control", "ACL", "white", 10),
        ("creation_date", "创建时间", "blue", 12),
    ],
    "rds": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("instance_id", "ID", "yellow", 25),
        ("instance_name", "名称", "white", 20),
        ("engine", "引擎", "magenta", 8),
        ("engine_version", "版本", "cyan", 8),
        ("status", "状态", "blue", 10),
        ("connection_string", "内网连接", "green", 0),
        ("public_connection_string", "外网连接", "red", 0),
    ],
    "tair": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("instance_id", "ID", "yellow", 25),
        ("instance_name", "名称", "white", 20),
        ("instance_type", "类型", "magenta", 12),
        ("instance_status", "状态", "blue", 10),
        ("connection_domain", "内网连接", "green", 0),
        ("public_domain", "外网连接", "red", 0),
    ],
    "polardb": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("cluster_id", "ID", "yellow", 25),
        ("cluster_description", "名称", "white", 20),
        ("dbtype", "引擎", "magenta", 8),
        ("dbversion", "版本", "cyan", 8),
        ("cluster_status", "状态", "blue", 10),
        ("private_connection_string", "内网连接", "green", 0),
        ("public_connection_string", "外网连接", "red", 0),
    ],
    "mongodb": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("instance_id", "ID", "yellow", 25),
        ("instance_description", "名称", "white", 20),
        ("dbinstance_type", "类型", "magenta", 12),
        ("dbinstance_status", "状态", "blue", 10),
        ("engine", "引擎", "cyan", 8),
        ("private_connection", "内网连接", "green", 0),
        ("public_connection", "外网连接", "red", 0),
    ],
    "security_group": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("security_group_id", "ID", "yellow", 25),
        ("security_group_name", "名称", "white", 20),
        ("security_group_type", "类型", "magenta", 10),
        ("vpc_id", "VPC", "cyan", 20),
        ("rule_count", "规则数", "blue", 8),
    ],
    "sae": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("app_id", "ID", "yellow", 25),
        ("app_name", "名称", "white", 20),
        ("programming_language", "语言", "magenta", 8),
        ("status", "状态", "blue", 10),
        ("running_instances", "运行实例", "green", 8),
        ("instance_count", "总实例", "white", 8),
        ("service_url", "访问地址", "cyan", 0),
    ],
    "sls": [
        ("account_display_name", "账号", "cyan", 30),
        ("region_id", "地域", "green", 15),
        ("project_name", "项目", "yellow", 0),
        ("description", "描述", "white", 20),
        ("status", "状态", "blue", 10),
    ],
    "ram": [
        ("account_display_name", "账号", "cyan", 30),
        ("user_name", "用户名", "yellow", 20),
        ("display_name", "显示名", "white", 20),
        ("create_date", "创建时间", "blue", 12),
        ("update_date", "更新时间", "cyan", 12),
    ],
}

# 资源类型的中文标题（用于表格标题）
LIST_TYPE_TITLES: dict[str, str] = {
    "ecs": "ECS 实例",
    "dns": "DNS 域名",
    "eip": "EIP 弹性公网IP",
    "clb": "CLB 负载均衡",
    "alb": "ALB 负载均衡",
    "cdn": "CDN 加速域名",
    "waf": "WAF 防护域名",
    "api": "API 网关",
    "oss": "OSS 存储桶",
    "rds": "RDS 数据库",
    "tair": "Tair/Redis",
    "polardb": "PolarDB 集群",
    "mongodb": "MongoDB",
    "security_group": "安全组",
    "sae": "SAE 应用",
    "sls": "SLS 项目",
    "ram": "RAM 用户",
}


def _truncate(value: str, max_width: int) -> str:
    """截断过长字符串"""
    if max_width > 0 and len(value) > max_width:
        return value[:max_width - 1] + "…"
    return value


def format_list_text(resource_type: str, items: list[dict]) -> None:
    """Rich 表格输出资源类型列表"""
    if not items:
        title = LIST_TYPE_TITLES.get(resource_type, resource_type)
        console.print(f"[yellow]⚠ 未找到 {title} 资源[/yellow]")
        return

    columns = LIST_COLUMNS.get(resource_type)
    if not columns:
        # 通用表格：展示所有字段
        title = LIST_TYPE_TITLES.get(resource_type, resource_type)
        table = Table(title=title, show_lines=True, border_style="blue", expand=True)
        if items:
            for key in items[0]:
                table.add_column(key, style="white")
        for item in items:
            table.add_row(*[str(item.get(k, "-")) for k in items[0]])
        console.print(table)
        return

    title = LIST_TYPE_TITLES.get(resource_type, resource_type)
    count_str = f"共 {len(items)} 个"
    table = Table(title=f"{title} ({count_str})", show_lines=True, border_style="blue", expand=True)

    # 动态列：只有有数据的列才添加
    has_data = {}
    for key, header, style, max_w in columns:
        non_empty = sum(1 for item in items if item.get(key) and str(item.get(key)) != "-")
        has_data[key] = non_empty > 0

    for key, header, style, max_w in columns:
        if not has_data[key]:
            continue
        col_kwargs = {"style": style}
        if max_w > 0:
            col_kwargs["max_width"] = max_w
        # 地址类长字段允许换行
        if header in ("内网地址", "外网地址", "内网连接", "外网连接", "记录值", "FQDN",
                       "域名", "CNAME", "回源地址", "访问地址", "桶名", "项目", "绑定实例"):
            col_kwargs["no_wrap"] = False
        table.add_column(header, **col_kwargs)

    for item in items:
        row = []
        for key, header, style, max_w in columns:
            if not has_data[key]:
                continue
            val = item.get(key)
            if val is None:
                display = "-"
            elif isinstance(val, (int, float)):
                display = str(val)
            else:
                display = str(val) if val else "-"
            row.append(_truncate(display, max_w))
        table.add_row(*row)

    console.print(table)


def format_list_json(resource_type: str, items: list[dict]) -> str:
    """JSON 输出资源类型列表"""
    output = {
        "resource_type": resource_type,
        "count": len(items),
        "items": items,
    }
    return json.dumps(output, ensure_ascii=False, indent=2)
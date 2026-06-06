"""CLI 命令入口 — Typer 应用

阿里云多账号资源同步与查询工具 (CMDB)
支持 17 种云资源类型的同步、查询、链路发现和资源列表浏览。

常用命令:
  aliyun-inv sync all              同步所有账号的全部资源
  aliyun-inv query ip <IP>         查询 IP 相关资源与链路
  aliyun-inv query domain <域名>   查询域名相关资源与链路
  aliyun-inv query list ecs        列出所有 ECS 实例
  aliyun-inv query list dns        列出所有域名
  aliyun-inv accounts list         查看已配置的账号列表

完整帮助: aliyun-inv --help
"""

import json
import logging

import typer
from rich.console import Console

from .config import load_accounts, load_dotenv_if_exists, get_database_url
from .db import get_engine, init_db, get_session
from .log import setup_logging
from .sync import sync_account, sync_all
from .query import query as do_query, query_detail as do_query_detail
from .query_list import list_resources, VALID_RESOURCE_TYPES
from .output import format_results_text, format_results_json, format_detail_text, format_list_text, format_list_json

console = Console()

# 主应用
app = typer.Typer(
    name="aliyun-inv",
    help="阿里云多账号资源同步与查询工具\n\n支持 17 种云资源同步到 SQLite，按任意信息查询资源及其全链路关联。\n\n子命令: db init / accounts list / sync all / sync account / query ip / query domain / query resource / query detail / query list",
    rich_help_panel="主命令",
)

# 子命令组
db_app = typer.Typer(name="db", help="数据库管理", rich_help_panel="子命令组")
accounts_app = typer.Typer(name="accounts", help="账号管理", rich_help_panel="子命令组")
sync_app = typer.Typer(name="sync", help="资源同步", rich_help_panel="子命令组")
query_app = typer.Typer(name="query", help="资源查询（ip/domain/resource/detail/list）", rich_help_panel="子命令组")

app.add_typer(db_app, name="db")
app.add_typer(accounts_app, name="accounts")
app.add_typer(sync_app, name="sync")
app.add_typer(query_app, name="query")


# ──────────────────────────────────────────────
# db 命令
# ──────────────────────────────────────────────

@db_app.command("init")
def db_init() -> None:
    """初始化数据库（创建所有表）"""
    load_dotenv_if_exists()
    logger = setup_logging()
    db_url = get_database_url()
    logger.info("数据库路径: %s", db_url)

    engine = get_engine(db_url)
    init_db(engine)

    logger.info("数据库初始化完成")


# ──────────────────────────────────────────────
# accounts 命令
# ──────────────────────────────────────────────

@accounts_app.command("list")
def accounts_list(
    json_output: bool = typer.Option(False, "--json", "-j", help="以 JSON 格式输出"),
) -> None:
    """列出配置中的所有账号"""
    load_dotenv_if_exists()
    accounts = load_accounts()

    if json_output:
        import json as _json
        result = []
        for account in accounts:
            enabled_resources = []
            for res_type in ("dns", "ecs", "eip", "clb", "alb", "sls", "ram", "cdn", "api", "oss", "rds", "waf", "tair", "polardb", "mongodb", "security_group", "sae"):
                if getattr(account.resources, res_type, False):
                    enabled_resources.append(res_type)
            result.append({
                "name": account.name,
                "display_name": account.display_name,
                "credential_env_prefix": account.credential_env_prefix,
                "enabled": account.enabled,
                "enabled_resources": enabled_resources,
            })
        print(_json.dumps(result, ensure_ascii=False, indent=2))
        return

    from rich.table import Table
    table = Table(title="阿里云账号", show_lines=True)
    table.add_column("名称", style="cyan")
    table.add_column("显示名", style="green")
    table.add_column("环境变量前缀", style="magenta")
    table.add_column("启用", style="yellow")
    table.add_column("资源类型", style="white")

    for account in accounts:
        enabled_resources = []
        for res_type in ("dns", "ecs", "eip", "clb", "alb", "sls", "ram", "cdn", "api", "oss", "rds", "waf", "tair", "polardb", "mongodb", "security_group", "sae"):
            if getattr(account.resources, res_type, False):
                enabled_resources.append(res_type)

        table.add_row(
            account.name,
            account.display_name,
            account.credential_env_prefix,
            "✓" if account.enabled else "✗",
            ", ".join(enabled_resources) if enabled_resources else "无",
        )

    console.print(table)


# ──────────────────────────────────────────────
# sync 命令
# ──────────────────────────────────────────────

@sync_app.command("account")
def sync_account_cmd(
    name: str = typer.Argument(help="账号名称"),
    resource: str = typer.Option(None, "--resource", "-r", help="只同步指定资源类型 (ecs/dns/eip/clb/alb/sls/ram/cdn/api/oss/rds/waf/tair/polardb/mongodb/security_group/sae)"),
    region: str = typer.Option(None, "--region", help="只同步指定地域（仅对有地域的资源有效）"),
) -> None:
    """同步指定账号的资源"""
    load_dotenv_if_exists()
    logger = setup_logging()

    db_url = get_database_url()
    engine = get_engine(db_url)
    init_db(engine)  # 自动补齐缺失列
    session = get_session(engine)

    accounts = load_accounts()
    sync_account(name, session, accounts, resource_filter=resource, region_filter=region)


@sync_app.command("all")
def sync_all_cmd(
    resource: str = typer.Option(None, "--resource", "-r", help="只同步指定资源类型 (ecs/dns/eip/clb/alb/sls/ram/cdn/api/oss/rds/waf/tair/polardb/mongodb/security_group/sae)"),
) -> None:
    """同步所有已启用的账号"""
    load_dotenv_if_exists()
    logger = setup_logging()

    db_url = get_database_url()
    engine = get_engine(db_url)
    init_db(engine)  # 自动补齐缺失列
    session = get_session(engine)

    accounts = load_accounts()
    sync_all(session, accounts, resource_filter=resource)


# ──────────────────────────────────────────────
# query 命令
# ──────────────────────────────────────────────

@query_app.command("ip")
def query_ip(
    value: str = typer.Argument(help="要查询的 IP 地址"),
    json_output: bool = typer.Option(False, "--json", "-j", help="以 JSON 格式输出"),
    chain: bool = typer.Option(False, "--chain", help="显示完整确定性链路详情（超过5条时默认折叠）"),
    chain_limit: int = typer.Option(0, "--limit", help="链路显示数量限制（0=全部，配合--chain）"),
) -> None:
    """查询 IP 地址相关的所有资源"""
    _do_query(value, json_output, chain, chain_limit)


@query_app.command("domain")
def query_domain(
    value: str = typer.Argument(help="要查询的域名"),
    json_output: bool = typer.Option(False, "--json", "-j", help="以 JSON 格式输出"),
    chain: bool = typer.Option(False, "--chain", help="显示完整确定性链路详情（超过5条时默认折叠）"),
    chain_limit: int = typer.Option(0, "--limit", help="链路显示数量限制（0=全部，配合--chain）"),
    exact: bool = typer.Option(False, "--exact", "-e", help="精确匹配（不做模糊搜索）"),
) -> None:
    """查询域名相关的所有资源"""
    _do_query(value, json_output, chain, chain_limit, exact=exact)


@query_app.command("resource")
def query_resource(
    value: str = typer.Argument(help="要查询的资源ID或任意信息"),
    json_output: bool = typer.Option(False, "--json", "-j", help="以 JSON 格式输出"),
    chain: bool = typer.Option(False, "--chain", help="显示完整确定性链路详情（超过5条时默认折叠）"),
    chain_limit: int = typer.Option(0, "--limit", help="链路显示数量限制（0=全部，配合--chain）"),
    exact: bool = typer.Option(False, "--exact", "-e", help="精确匹配（不做模糊搜索）"),
) -> None:
    """查询资源ID或任意信息相关的所有资源"""
    _do_query(value, json_output, chain, chain_limit, exact=exact)


@query_app.command("detail")
def query_detail_cmd(
    value: str = typer.Argument(help="资源ID (如 i-xxx, rm-xxx, r-xxx 等)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="以 JSON 格式输出"),
) -> None:
    """查看指定资源的完整详细信息"""
    _do_detail(value, json_output)


@query_app.command("list", help="列出所有账号下指定类型的资源聚合列表 (ecs/dns/eip/clb/alb/cdn/waf/api/oss/rds/tair/polardb/mongodb/security_group/sae/sls/ram)")
def query_list_cmd(
    resource_type: str = typer.Argument(help="资源类型 (ecs/dns/eip/clb/...)"),
    json_output: bool = typer.Option(False, "--json", "-j", help="以 JSON 格式输出"),
    account: str = typer.Option("", "--account", "-a", help="按账户显示名过滤"),
    region: str = typer.Option("", "--region", "-r", help="按地域过滤"),
) -> None:
    """列出所有账号下指定类型的资源聚合列表"""
    if resource_type not in VALID_RESOURCE_TYPES:
        console.print(f"[red]✗ 不支持的资源类型: {resource_type}[/red]")
        console.print(f"[cyan]支持的类型: {', '.join(VALID_RESOURCE_TYPES)}[/cyan]")
        raise typer.Exit(code=1)

    load_dotenv_if_exists()
    db_url = get_database_url()
    engine = get_engine(db_url)
    init_db(engine)
    session = get_session(engine)

    items = list_resources(session, resource_type, account_name=account, region_id=region)

    if json_output:
        print(format_list_json(resource_type, items))
    else:
        format_list_text(resource_type, items)


def _do_query(value: str, json_output: bool, show_chain: bool = False, chain_limit: int = 0, exact: bool = False) -> None:
    """通用查询处理函数"""
    load_dotenv_if_exists()
    db_url = get_database_url()
    engine = get_engine(db_url)
    init_db(engine)  # 自动补齐缺失列
    session = get_session(engine)

    result = do_query(session, value, exact=exact)

    if json_output:
        print(format_results_json(result))
    else:
        format_results_text(result, show_chain=show_chain, chain_limit=chain_limit)


def _do_detail(value: str, json_output: bool) -> None:
    """资源详情处理函数"""
    load_dotenv_if_exists()
    db_url = get_database_url()
    engine = get_engine(db_url)
    init_db(engine)  # 自动补齐缺失列
    session = get_session(engine)

    result = do_query_detail(session, value)

    if result is None:
        console.print(f"[yellow]⚠ 未找到资源 '{value}'[/yellow]")
    elif json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        format_detail_text(result)


if __name__ == "__main__":
    app()
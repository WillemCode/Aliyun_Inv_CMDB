"""数据库模型定义 — 28 张表"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ──────────────────────────────────────────────
# 1. cloud_accounts — 账号信息
# ──────────────────────────────────────────────
class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(64), nullable=False, unique=True)
    display_name = Column(String(128), nullable=False)
    credential_env_prefix = Column(String(64), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 2. resources_raw — 阿里云原始返回
# ──────────────────────────────────────────────
class ResourceRaw(Base):
    __tablename__ = "resources_raw"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "resource_type", "region_id", "resource_id",
            name="uq_resources_raw",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    resource_type = Column(String(32), nullable=False)  # ecs / dns / eip / clb / alb
    region_id = Column(String(32), nullable=False)
    resource_id = Column(String(128), nullable=False)
    resource_name = Column(String(256), nullable=True)
    raw_json = Column(JSON, nullable=True)
    source_api = Column(String(128), nullable=True)  # DescribeInstances / DescribeDomainRecords 等
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 3. ecs_instances — ECS 实例
# ──────────────────────────────────────────────
class EcsInstance(Base):
    __tablename__ = "ecs_instances"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "instance_id",
            name="uq_ecs_instances",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    zone_id = Column(String(64), nullable=True)
    instance_id = Column(String(64), nullable=False)
    instance_name = Column(String(256), nullable=True)
    status = Column(String(32), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    private_ips_json = Column(JSON, nullable=True)  # list[str]
    public_ips_json = Column(JSON, nullable=True)    # list[str]
    eip_address = Column(String(64), nullable=True)
    nat_ip_address = Column(String(64), nullable=True)  # SNAT 外网 IP
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 4. dns_records — DNS 解析记录
# ──────────────────────────────────────────────
class DnsRecord(Base):
    __tablename__ = "dns_records"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "record_id",
            name="uq_dns_records",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    record_id = Column(String(64), nullable=False)
    domain_name = Column(String(256), nullable=False)
    rr = Column(String(128), nullable=True)
    fqdn = Column(String(512), nullable=True)
    record_type = Column(String(16), nullable=True)  # A / AAAA / CNAME / MX / TXT 等
    value = Column(Text, nullable=True)
    ttl = Column(Integer, nullable=True)
    status = Column(String(32), nullable=True)
    line = Column(String(64), nullable=True)   # 解析线路（default/telecom/unicom/mobile 等）
    weight = Column(Integer, nullable=True)    # 权重（轮询负载均衡时的权重值）
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 5. eip_addresses — EIP 弹性公网 IP
# ──────────────────────────────────────────────
class EipAddress(Base):
    __tablename__ = "eip_addresses"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "allocation_id",
            name="uq_eip_addresses",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    allocation_id = Column(String(64), nullable=False)
    ip_address = Column(String(64), nullable=True)
    status = Column(String(32), nullable=True)
    instance_type = Column(String(64), nullable=True)
    instance_id = Column(String(128), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 6. load_balancers — 负载均衡（CLB + ALB）
# ──────────────────────────────────────────────
class LoadBalancer(Base):
    __tablename__ = "load_balancers"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "lb_type", "lb_id",
            name="uq_load_balancers",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    lb_type = Column(String(8), nullable=False)  # clb / alb
    region_id = Column(String(32), nullable=False)
    lb_id = Column(String(64), nullable=False)
    lb_name = Column(String(256), nullable=True)
    status = Column(String(32), nullable=True)
    address = Column(String(128), nullable=True)
    address_type = Column(String(32), nullable=True)
    dns_name = Column(String(256), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 7. backend_servers — 负载均衡后端服务器
# ──────────────────────────────────────────────
class BackendServer(Base):
    __tablename__ = "backend_servers"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "lb_type", "region_id", "lb_id", "server_group_id", "backend_resource_id",
            name="uq_backend_servers",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    lb_type = Column(String(8), nullable=False)  # clb / alb
    region_id = Column(String(32), nullable=False)
    lb_id = Column(String(64), nullable=False)
    server_group_id = Column(String(64), nullable=False, default="")
    backend_resource_id = Column(String(64), nullable=False)
    backend_ip = Column(String(64), nullable=True)
    port = Column(Integer, nullable=True)
    weight = Column(Integer, nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 7b. lb_listeners — 负载均衡监听器（前端端口/协议 → 后端端口/服务器组）
# ──────────────────────────────────────────────
class LbListener(Base):
    __tablename__ = "lb_listeners"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "lb_type", "region_id", "lb_id", "listener_port", "listener_protocol",
            name="uq_lb_listeners",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    lb_type = Column(String(8), nullable=False)  # clb / alb
    region_id = Column(String(32), nullable=False)
    lb_id = Column(String(64), nullable=False)
    listener_port = Column(Integer, nullable=False)  # 前端端口
    listener_protocol = Column(String(16), nullable=False)  # 前端协议: tcp/udp/http/https
    backend_server_port = Column(Integer, nullable=True)  # 后端端口（默认组才有）
    vserver_group_id = Column(String(64), nullable=True)  # 关联的 vServerGroup ID
    forward_port = Column(Integer, nullable=True)  # HTTP→HTTPS 重定向目标端口
    listener_forward = Column(String(8), nullable=True)  # "on" 表示 HTTP 重定向到 HTTPS
    status = Column(String(16), nullable=True)
    description = Column(String(256), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 7c. lb_vserver_groups — 虚拟服务器组元数据（名称等）
# ──────────────────────────────────────────────
class LbVServerGroup(Base):
    __tablename__ = "lb_vserver_groups"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "lb_type", "region_id", "lb_id", "vserver_group_id",
            name="uq_lb_vserver_groups",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    lb_type = Column(String(8), nullable=False)  # clb / alb
    region_id = Column(String(32), nullable=False)
    lb_id = Column(String(64), nullable=False)
    vserver_group_id = Column(String(64), nullable=False)
    vserver_group_name = Column(String(256), nullable=True)
    server_count = Column(Integer, nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 7d. lb_forwarding_rules — HTTP/HTTPS 域名转发规则
# ──────────────────────────────────────────────
class LbForwardingRule(Base):
    __tablename__ = "lb_forwarding_rules"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "lb_type", "region_id", "lb_id",
            "listener_port", "listener_protocol", "rule_id",
            name="uq_lb_forwarding_rules",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    lb_type = Column(String(8), nullable=False)
    region_id = Column(String(32), nullable=False)
    lb_id = Column(String(64), nullable=False)
    listener_port = Column(Integer, nullable=False)
    listener_protocol = Column(String(16), nullable=False)
    rule_id = Column(String(64), nullable=False)
    rule_name = Column(String(256), nullable=True)
    domain = Column(String(256), nullable=True)  # 前端域名
    url = Column(String(256), nullable=True)  # 前端URL路径
    vserver_group_id = Column(String(64), nullable=True)  # 转发目标服务器组
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 8. ip_addresses — 统一 IP 查询表（有索引）
# ──────────────────────────────────────────────
class IpAddress(Base):
    __tablename__ = "ip_addresses"
    __table_args__ = (
        Index("ix_ip_addresses_ip", "ip"),
        UniqueConstraint(
            "account_name", "resource_type", "resource_id", "ip", "ip_type",
            name="uq_ip_addresses",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=True)
    resource_type = Column(String(32), nullable=False)  # ecs / eip / clb / alb / dns_record / backend
    resource_id = Column(String(128), nullable=False)
    resource_name = Column(String(256), nullable=True)
    ip = Column(String(64), nullable=False)
    ip_type = Column(String(32), nullable=False)  # public / private / eip / lb_address / dns_value / backend
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 9. sls_projects — SLS 日志项目
# ──────────────────────────────────────────────
class SlsProject(Base):
    __tablename__ = "sls_projects"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "project_name",
            name="uq_sls_projects",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    project_name = Column(String(128), nullable=False)
    description = Column(String(512), nullable=True)
    status = Column(String(32), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 10. sls_logstores — SLS 日志库
# ──────────────────────────────────────────────
class SlsLogstore(Base):
    __tablename__ = "sls_logstores"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "project_name", "logstore_name",
            name="uq_sls_logstores",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    project_name = Column(String(128), nullable=False)
    logstore_name = Column(String(128), nullable=False)
    ttl = Column(Integer, nullable=True)
    shard_count = Column(Integer, nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 11. lb_log_configs — CLB/ALB 的访问日志 SLS 配置
# ──────────────────────────────────────────────
class LbLogConfig(Base):
    __tablename__ = "lb_log_configs"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "lb_type", "region_id", "lb_id",
            name="uq_lb_log_configs",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    lb_type = Column(String(8), nullable=False)  # clb / alb
    region_id = Column(String(32), nullable=False)
    lb_id = Column(String(64), nullable=False)
    lb_name = Column(String(256), nullable=True)
    log_project = Column(String(128), nullable=True)  # SLS project 名
    log_store = Column(String(128), nullable=True)    # SLS logstore 名
    log_type = Column(String(32), nullable=True)      # layer7 / layer4
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 12. ram_users — RAM 用户
# ──────────────────────────────────────────────
class RamUser(Base):
    __tablename__ = "ram_users"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "user_id",
            name="uq_ram_users",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    user_id = Column(String(64), nullable=False)
    user_name = Column(String(128), nullable=False)
    display_name = Column(String(256), nullable=True)
    email = Column(String(256), nullable=True)
    mobile_phone = Column(String(64), nullable=True)
    comments = Column(String(512), nullable=True)
    create_date = Column(String(64), nullable=True)
    update_date = Column(String(64), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 13. ram_access_keys — RAM AccessKey
# ──────────────────────────────────────────────
class RamAccessKey(Base):
    __tablename__ = "ram_access_keys"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "user_name", "access_key_id",
            name="uq_ram_access_keys",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    user_name = Column(String(128), nullable=False)
    access_key_id = Column(String(64), nullable=False)
    ak_name = Column(String(256), nullable=True)  # AK 名称/描述
    status = Column(String(32), nullable=True)  # Active / Inactive
    create_date = Column(String(64), nullable=True)
    expiration_time = Column(String(64), nullable=True)  # AK 到期时间
    last_used_date = Column(String(64), nullable=True)  # AK 最后使用时间（来自 GetAccessKeyLastUsed）
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)

    def __repr__(self):
        return f"<RamAccessKey({self.account_name}/{self.user_name}/{self.access_key_id})>"
# ──────────────────────────────────────────────
class RamUserPolicy(Base):
    __tablename__ = "ram_user_policies"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "user_name", "policy_name", "policy_type",
            name="uq_ram_user_policies",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    user_name = Column(String(128), nullable=False)
    policy_name = Column(String(128), nullable=False)
    policy_type = Column(String(32), nullable=False)  # Custom / System
    description = Column(String(512), nullable=True)
    default_version = Column(String(32), nullable=True)
    attach_date = Column(String(64), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 15. cdn_domains — CDN 加速域名
# ──────────────────────────────────────────────
class CdnDomain(Base):
    __tablename__ = "cdn_domains"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "domain_name",
            name="uq_cdn_domains",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    domain_name = Column(String(256), nullable=False)
    domain_id = Column(String(64), nullable=True)
    cname = Column(String(256), nullable=True)
    cdn_type = Column(String(32), nullable=True)  # web / download / media / live
    domain_status = Column(String(32), nullable=True)  # online / offline / configuring
    coverage = Column(String(32), nullable=True)  # domestic / overseas / global
    origin_type = Column(String(128), nullable=True)  # oss / ip / domain / custom (逗号分隔)
    origin_address = Column(Text, nullable=True)  # 回源地址列表 (JSON)
    ssl_protocol = Column(String(16), nullable=True)  # on / off
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 16. api_gateways — API 网关（传统 CloudAPI + 云原生 MSE 网关）
# ──────────────────────────────────────────────
class ApiGateway(Base):
    __tablename__ = "api_gateways"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "api_type", "group_id",
            name="uq_api_gateways",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    api_type = Column(String(16), nullable=False)  # cloudapi / mse_gateway
    region_id = Column(String(32), nullable=False)
    group_id = Column(String(64), nullable=False)
    group_name = Column(String(256), nullable=True)
    description = Column(String(512), nullable=True)
    base_path = Column(String(256), nullable=True)
    sub_domain = Column(String(256), nullable=True)
    status = Column(String(32), nullable=True)
    instance_id = Column(String(64), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 17. oss_buckets — OSS 存储桶
# ──────────────────────────────────────────────
class OssBucket(Base):
    __tablename__ = "oss_buckets"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "bucket_name",
            name="uq_oss_buckets",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    bucket_name = Column(String(256), nullable=False)
    region = Column(String(64), nullable=True)
    storage_class = Column(String(32), nullable=True)  # Standard / IA / Archive / ColdArchive
    access_control = Column(String(32), nullable=True)  # private / public-read / public-read-write
    creation_date = Column(String(64), nullable=True)
    endpoint = Column(String(256), nullable=True)
    extranet_endpoint = Column(String(256), nullable=True)
    intranet_endpoint = Column(String(256), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 18. rds_instances — RDS 数据库实例
# ──────────────────────────────────────────────
class RdsInstance(Base):
    __tablename__ = "rds_instances"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "instance_id",
            name="uq_rds_instances",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    zone_id = Column(String(64), nullable=True)
    instance_id = Column(String(64), nullable=False)
    instance_name = Column(String(256), nullable=True)
    engine = Column(String(32), nullable=True)  # MySQL / PostgreSQL / SQLServer / MariaDB
    engine_version = Column(String(32), nullable=True)
    instance_type = Column(String(32), nullable=True)  # Primary / Readonly / Temp
    instance_class = Column(String(64), nullable=True)
    status = Column(String(32), nullable=True)
    connection_string = Column(String(256), nullable=True)  # 内网连接地址
    port = Column(String(16), nullable=True)
    public_connection_string = Column(String(256), nullable=True)  # 外网连接地址
    public_port = Column(String(16), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    vswitch_id = Column(String(64), nullable=True)
    category = Column(String(32), nullable=True)  # Basic / HighAvailability / Finance / AlwaysOn
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 19. waf_domains — WAF 防护域名
# ──────────────────────────────────────────────
class WafDomain(Base):
    __tablename__ = "waf_domains"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "domain_name",
            name="uq_waf_domains",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    domain_name = Column(String(256), nullable=False)
    instance_id = Column(String(64), nullable=True)
    cname = Column(String(256), nullable=True)  # WAF CNAME
    cluster_type = Column(String(32), nullable=True)
    access_type = Column(String(32), nullable=True)
    http_port = Column(String(128), nullable=True)
    https_port = Column(String(128), nullable=True)
    source_ips_json = Column(JSON, nullable=True)  # 回源 IP 列表
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 20. tair_instances — Tair/Redis 实例
# ──────────────────────────────────────────────
class TairInstance(Base):
    __tablename__ = "tair_instances"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "instance_id",
            name="uq_tair_instances",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    zone_id = Column(String(64), nullable=True)
    instance_id = Column(String(64), nullable=False)
    instance_name = Column(String(256), nullable=True)
    instance_type = Column(String(32), nullable=True)  # Tair_rdb / Tair_memcache / Redis / Memcache
    instance_class = Column(String(64), nullable=True)
    instance_status = Column(String(32), nullable=True)
    engine_version = Column(String(32), nullable=True)
    connection_domain = Column(String(256), nullable=True)  # 内网连接地址
    port = Column(Integer, nullable=True)
    public_domain = Column(String(256), nullable=True)  # 外网连接地址
    public_port = Column(Integer, nullable=True)
    bandwidth = Column(String(64), nullable=True)
    capacity = Column(String(64), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    vswitch_id = Column(String(64), nullable=True)
    charge_type = Column(String(32), nullable=True)  # PrePaid / PostPaid
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 21. polardb_clusters — PolarDB 集群
# ──────────────────────────────────────────────
class PolarDBCluster(Base):
    __tablename__ = "polardb_clusters"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "cluster_id",
            name="uq_polardb_clusters",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    zone_id = Column(String(64), nullable=True)
    cluster_id = Column(String(64), nullable=False)
    cluster_description = Column(String(256), nullable=True)
    dbtype = Column(String(32), nullable=True)  # MySQL / PostgreSQL / Oracle
    dbversion = Column(String(32), nullable=True)
    engine = Column(String(32), nullable=True)
    category = Column(String(32), nullable=True)  # Normal / Serverless
    cluster_status = Column(String(32), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    vswitch_id = Column(String(64), nullable=True)
    pay_type = Column(String(32), nullable=True)
    private_connection_string = Column(String(256), nullable=True)  # 内网连接地址
    public_connection_string = Column(String(256), nullable=True)  # 外网连接地址
    connection_port = Column(String(16), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    memory_size = Column(Integer, nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 22. mongodb_instances — MongoDB 实例
# ──────────────────────────────────────────────
class MongoDBInstance(Base):
    __tablename__ = "mongodb_instances"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "instance_id",
            name="uq_mongodb_instances",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    zone_id = Column(String(64), nullable=True)
    instance_id = Column(String(64), nullable=False)
    instance_description = Column(String(256), nullable=True)
    dbinstance_type = Column(String(32), nullable=True)  # sharding / replicate / standalone
    dbinstance_class = Column(String(64), nullable=True)
    dbinstance_status = Column(String(32), nullable=True)
    engine = Column(String(32), nullable=True)
    engine_version = Column(String(32), nullable=True)
    network_type = Column(String(32), nullable=True)  # VPC / Classic
    vpc_id = Column(String(64), nullable=True)
    charge_type = Column(String(32), nullable=True)
    storage_type = Column(String(32), nullable=True)
    private_connection = Column(String(256), nullable=True)  # 内网连接地址
    public_connection = Column(String(256), nullable=True)  # 外网连接地址
    connection_port = Column(String(16), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 23. security_groups — 安全组
# ──────────────────────────────────────────────
class SecurityGroup(Base):
    __tablename__ = "security_groups"
    __table_args__ = (
        UniqueConstraint(
            "account_name", "region_id", "security_group_id",
            name="uq_security_groups",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    security_group_id = Column(String(64), nullable=False)
    security_group_name = Column(String(256), nullable=True)
    security_group_type = Column(String(32), nullable=True)  # normal / enterprise
    description = Column(String(512), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    inner_access_policy = Column(String(32), nullable=True)  # Accept / Drop
    rule_count = Column(Integer, nullable=True)
    raw_json = Column(JSON, nullable=True)  # 含 Permissions 规则列表
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 24. apig_domains — 云原生API网关域名（接入域名 + 自定义绑定域名）
# ──────────────────────────────────────────────
class ApigDomain(Base):
    __tablename__ = "apig_domains"
    __table_args__ = (
        Index("ix_apig_domains_domain_name", "domain_name"),
        UniqueConstraint(
            "account_name", "region_id", "gateway_id", "domain_id",
            name="uq_apig_domains",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    gateway_id = Column(String(64), nullable=False)
    domain_id = Column(String(64), nullable=False)
    domain_name = Column(String(512), nullable=False)
    domain_type = Column(String(16), nullable=True)  # default 接入域名 / custom 自定义绑定域名
    network_type = Column(String(16), nullable=True)  # Internet 公网 / Intranet 内网 / ""
    protocol = Column(String(16), nullable=True)  # HTTP / HTTPS
    cert_identifier = Column(String(256), nullable=True)  # SSL证书ID（自定义HTTPS域名）
    force_https = Column(Boolean, nullable=True)  # 是否强制HTTPS
    status = Column(String(32), nullable=True)  # Published / UnPublished
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 25. apig_apis — 云原生API网关下的API
# ──────────────────────────────────────────────
class ApigApi(Base):
    __tablename__ = "apig_apis"
    __table_args__ = (
        Index("ix_apig_apis_gateway_id", "gateway_id"),
        UniqueConstraint(
            "account_name", "region_id", "gateway_id", "api_id",
            name="uq_apig_apis",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    gateway_id = Column(String(64), nullable=False)
    api_id = Column(String(64), nullable=False)  # http_api_id
    api_name = Column(String(256), nullable=True)
    api_type = Column(String(32), nullable=True)  # Http / Rest / Websocket / AI / HttpIngress
    base_path = Column(String(256), nullable=True)
    description = Column(String(512), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 26. apig_routes — 云原生API网关下的路由
# ──────────────────────────────────────────────
class ApigRoute(Base):
    __tablename__ = "apig_routes"
    __table_args__ = (
        Index("ix_apig_routes_gateway_id", "gateway_id"),
        Index("ix_apig_routes_api_id", "api_id"),
        UniqueConstraint(
            "account_name", "region_id", "gateway_id", "api_id", "route_id",
            name="uq_apig_routes",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    gateway_id = Column(String(64), nullable=False)
    api_id = Column(String(64), nullable=False)
    route_id = Column(String(64), nullable=False)
    route_name = Column(String(256), nullable=True)
    path = Column(String(512), nullable=True)  # 路径（如 /api/callback）
    path_type = Column(String(16), nullable=True)  # Exact / Prefix / Regex
    methods = Column(JSON, nullable=True)  # HTTP方法列表 ["GET","POST"]
    domain_names = Column(String(1024), nullable=True)  # 逗号分隔的绑定域名
    description = Column(String(512), nullable=True)
    deploy_status = Column(String(32), nullable=True)  # Deployed / NotDeployed 等
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 27. sae_namespaces — SAE 命名空间
# ──────────────────────────────────────────────
class SaeNamespace(Base):
    __tablename__ = "sae_namespaces"
    __table_args__ = (
        Index("ix_sae_namespaces_short_id", "namespace_short_id"),
        UniqueConstraint(
            "account_name", "region_id", "namespace_id",
            name="uq_sae_namespaces",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    namespace_id = Column(String(128), nullable=False)  # 如 cn-hangzhou:chuandaodev
    namespace_short_id = Column(String(64), nullable=True)  # 短ID 如 chuandaodev — 用于关联 APIG 后端
    namespace_name = Column(String(256), nullable=True)
    namespace_description = Column(String(512), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    tenant_id = Column(String(128), nullable=True)
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)


# ──────────────────────────────────────────────
# 28. sae_apps — SAE 应用
# ──────────────────────────────────────────────
class SaeApp(Base):
    __tablename__ = "sae_apps"
    __table_args__ = (
        Index("ix_sae_apps_app_name", "app_name"),
        UniqueConstraint(
            "account_name", "region_id", "namespace_id", "app_id",
            name="uq_sae_apps",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    account_name = Column(String(64), nullable=False)
    account_display_name = Column(String(128), nullable=False)
    region_id = Column(String(32), nullable=False)
    namespace_id = Column(String(128), nullable=False)
    app_id = Column(String(64), nullable=False)
    app_name = Column(String(256), nullable=True)
    app_type = Column(String(32), nullable=True)  # Image / FatJar / War
    programming_language = Column(String(32), nullable=True)  # golang / java / php
    status = Column(String(32), nullable=True)  # RUNNING / STOPPED 等
    running_instances = Column(Integer, nullable=True)
    instance_count = Column(Integer, nullable=True)
    cpu = Column(Integer, nullable=True)  # CPU (m)
    memory = Column(Integer, nullable=True)  # 内存 (MB)
    image_url = Column(String(1024), nullable=True)
    app_description = Column(String(512), nullable=True)
    vpc_id = Column(String(64), nullable=True)
    service_url = Column(String(512), nullable=True)  # 内部访问地址 {app_name}.{short_id}.svc.cluster.local.{region}
    raw_json = Column(JSON, nullable=True)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False)
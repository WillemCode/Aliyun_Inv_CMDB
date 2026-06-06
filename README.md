<h1 align="center">
  <a href="https://github.com/WillemCode">
    <img src="https://avatars.githubusercontent.com/u/203067186?v=4" width="150" height="150" alt="banner" /><br>
  </a>
</h1>

# 阿里云多账号资源同步与查询工具（CMDB）

本地工具，通过阿里云 SDK 2.0 将多个账号的云资源同步到 SQLite 数据库，支持按任意信息查询资源及其全链路关联。

新增账号只需修改 YAML 配置和 `.env`，**不需要写任何代码**——同步、查询、链路关联全部自动生效。

## 功能特点

- 🔄 **多账号同步** — 新增账号仅改配置，17 种资源类型一键同步
- 🌍 **自动地域探测** — 自动扫描每个账号哪些地域有资源，跳过空地域
- 🔍 **通用查询** — IP、域名、资源ID、AK、备注、项目名……任意输入自动查找
- 🔗 **全链路发现** — DNS→CDN/WAF/APIG→LB→ECS→数据库 嵌套树式链路追踪
- 🔗 **链路折叠** — 链路 ≤5 条自动展示，>5 条默认折叠摘要，`--chain` 展开详情
- 🎯 **精确匹配** — `--exact` 参数只做完全匹配，避免模糊搜索返回过多结果
- 📋 **资源列表** — `query list` 按类型浏览全部资源（ECS、域名、RDS 等），支持按账户/地域过滤
- 📋 **资源详情** — 单个资源完整详情（含内外网地址、安全组规则、磁盘、监听器等）
- 🛡️ **安全组查询** — 安全组作为独立资源，含入/出方向规则完整展示
- 🎧 **LB 监听器/转发规则** — CLB 监听器、vServerGroup、域名转发规则独立展示
- 📊 **JSON 输出** — 所有查询支持 `--json`，方便 Agent/程序调用
- 🧹 **IP 查询去重** — IP 查询时命中资源不再重复展示 DNS 记录（已在下方 DNS 表格中展示）
- 🔐 **安全设计** — AK/SK 仅从环境变量读取，所有 API 调用均为只读
- 🔧 **自动迁移** — 模型新增字段自动 ALTER TABLE 补齐，无需手动迁移

## 支持的云资源（17 种）

| 资源类型 | 说明 | 额外 API 调用 |
|---------|------|--------------|
| ECS 实例 | 含私网/公网/EIP/NAT IP + 多 ENI + 磁盘 + 安全组 | DescribeDisks + DescribeSecurityGroups + DescribeNetworkInterfaces |
| DNS 云解析 | 域名自动发现 + 解析记录 | 无 |
| EIP 弹性公网 IP | 绑定类型与实例 | 无 |
| CLB 传统型负载均衡 | VIP + 后端服务器 + 监听器 + vServerGroup + 转发规则 + SLS 日志配置 | DescribeLoadBalancerAttribute + DescribeListeners + DescribeAccessLogsDownloadAttribute |
| ALB 应用型负载均衡 | DNS 名称 + 后端服务器组 | 无 |
| SLS 日志服务 | 项目 + 日志库 + CLB/ALB 日志配置 | 无 |
| RAM 用户 | 用户信息 + AK 最后使用时间 + 用户最后登录 + MFA 信息 | GetAccessKeyLastUsed + GetUser + GetUserMFAInfo |
| CDN 加速域名 | CNAME + 回源地址 + SSL | 无 |
| API 网关 | CloudAPI + MSE 云原生网关 + APIG 子资源（域名/API/路由） | ListDomains + ListHttpApis + ListHttpApiRoutes |
| OSS 对象存储 | 内外网 Endpoint + ACL | 无 |
| RDS 关系型数据库 | 内网连接 + 外网连接 | DescribeDBInstanceNetInfo |
| WAF 防护域名 | CNAME + 回源 IP + SSL | DescribeDomain |
| Tair/Redis | 内网连接域名 + 外网域名 + 端口 | DescribeDBInstanceNetInfo |
| PolarDB 集群 | 内外网连接地址 + 端口 | DescribeDBClusterEndpoints |
| MongoDB/DDS | 内外网连接地址（副本集 + 分片集群） | DescribeReplicaSetRole + DescribeShardingNetworkAddress |
| 安全组 | 名称 + 类型 + VPC + 入出方向规则 | DescribeSecurityGroupAttribute |
| SAE 应用 | 命名空间 + 应用 + service_url + 状态推断 | DescribeNamespaces + ListApplications（手动分页） |

> 💡 数据库类产品（RDS、PolarDB、Tair、MongoDB）和安全组在同步时会额外调用 API 获取连接地址和规则，因此同步耗时比其他产品稍长。CLB 同步时会额外获取监听器、vServerGroup 和 SLS 日志配置。

## 安装部署

### 前置要求

- Python 3.11+
- 阿里云 RAM 子账号的 AK/SK（建议只授予只读权限）

### 1. 克隆项目

```bash
git clone <仓库地址>
cd CMDB
```

### 2. 创建虚拟环境 & 安装依赖

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

> ⚠️ 阿里云 SDK 包较多（18 个），首次安装可能需要 1~2 分钟。

### 3. 验证安装

```bash
aliyun-inv --help
```

如果看到命令帮助信息，说明安装成功。

### 4. 配置 AK/SK 凭据

复制 `.env.example` 为 `.env`，填入各账号的 AK/SK：

```bash
cp .env.example .env
```

`.env` 格式：

```bash
# 每个账号对应一个 PREFIX，程序自动读取 {PREFIX}_ACCESS_KEY_ID 和 {PREFIX}_ACCESS_KEY_SECRET
# PREFIX 必须与 config/accounts.yaml 中的 credential_env_prefix 一致

# 账号1
XXXXXX_ACCESS_KEY_ID=LTAI5t...
XXXXXX_ACCESS_KEY_SECRET=xxxx...

# 账号2
YYYYYY_ACCESS_KEY_ID=LTAI5t...
YYYYYY_ACCESS_KEY_SECRET=xxxx...

# 域名账号
ZZZZZZ_ACCESS_KEY_ID=LTAI5t...
ZZZZZZ_ACCESS_KEY_SECRET=xxxx...

# 数据库路径（默认，可修改）
ALIYUN_INVENTORY_DATABASE_URL=sqlite:///data/aliyun_inventory.db
```

> ⚠️ `.env` 包含 AK/SK 密钥，**绝对不能提交到 Git**。项目 `.gitignore` 已包含 `.env`。

### 5. 配置账号

复制 `config/accounts.example.yaml` 为 `config/accounts.yaml`：

```bash
cp config/accounts.example.yaml config/accounts.yaml
```

按实际账号信息修改 `config/accounts.yaml`：

```yaml
accounts:
  - name: abc@xyz.com      # 账号标识名（唯一）
    display_name: A阿里云         # 显示名称
    credential_env_prefix: xxxxxx  # 对应 .env 中 AK/SK 的前缀
    enabled: true
    resources:
      ecs: true                # 简写格式：直接布尔值
      dns: true
      eip: true
      clb: true
      alb: true
      sls: true
      ram: true
      cdn: true
      api: true
      oss: true
      rds: true
      waf: true
      tair: true
      polardb: true
      mongodb: true
      security_group: true
      sae: true

  - name: xyz@abc.com        # 域名账号，只同步 DNS 和 RAM
    display_name: B阿里云
    credential_env_prefix: YYYYYYY
    enabled: true
    resources:
      dns: true
      ram: true
      ecs: false                # 未启用资源可不写，默认 false
      # ... 其他资源默认 false
```

配置说明：

| 字段 | 必填 | 说明 |
|------|------|------|
| `name` | ✅ | 账号标识名，唯一，用于数据库中区分不同账号的资源 |
| `display_name` | ✅ | 显示名称，查询结果中展示的中文名 |
| `credential_env_prefix` | ✅ | 对应 `.env` 中 AK/SK 的前缀，如 `XXXXXXX` → `XXXXXXX_ACCESS_KEY_ID` |
| `enabled` | ✅ | 是否启用同步，`false` 则跳过此账号 |
| `resources.<type>` | ✅ | 各资源类型是否启用同步，支持两种格式：`true` 或 `{enabled: true}`，未列出默认 `false` |

> 💡 **地域和域名会自动扫描**：不需要在配置中手动指定地域列表（程序自动探测有资源的地域），DNS 域名也会自动发现。

### 6. 初始化数据库

```bash
aliyun-inv db init
```

此命令会创建所有数据库表，并自动补齐已有表中缺失的新增列（自动迁移）。

> 首次运行会在 `data/` 目录下创建 `aliyun_inventory.db` 文件。

## 使用指南

### 查看账号列表

```bash
aliyun-inv accounts list
aliyun-inv accounts list --json
```

输出一个表格，展示所有账号的名称、显示名、AK前缀、启用状态和资源类型。`--json` 输出包含相同信息的 JSON 数组。

### 同步资源

#### 同步所有账号的全部资源

```bash
aliyun-inv sync all
```

> ⚠️ 全量同步耗时取决于账号数量和资源规模，典型场景约 5~10 分钟。

#### 同步所有账号的指定资源类型

```bash
aliyun-inv sync all --resource rds
aliyun-inv sync all --resource ecs
aliyun-inv sync all --resource security_group
aliyun-inv sync all --resource sae
```

> 💡 支持 17 种资源类型：`ecs` `dns` `eip` `clb` `alb` `sls` `ram` `cdn` `api` `oss` `rds` `waf` `tair` `polardb` `mongodb` `security_group` `sae`

#### 同步单个账号

```bash
aliyun-inv sync account abc@xyz.com
```

#### 同步单个账号的指定资源类型

```bash
aliyun-inv sync account abc@xyz.com --resource rds
aliyun-inv sync account abc@xyz.com --resource sae
```

#### 同步单个账号的指定地域

```bash
aliyun-inv sync account abc@xyz.com --resource ecs --region cn-hangzhou
```

> 💡 同步采用 **upsert** 机制：已有资源会更新，新增资源会插入，不会重复创建。每次同步更新 `last_seen_at` 和 `raw_json`。

### 查询资源

查询命令支持 5 种子命令：

| 子命令 | 输入类型 | 自动识别规则 | 常用选项 |
|--------|---------|-------------|---------|
| `query ip <IP>` | IP 地址 | IPv4/IPv6 格式 | `--json`, `--chain`, `--limit` |
| `query domain <域名>` | 域名 | FQDN 格式 | `--json`, `--exact`, `--chain`, `--limit` |
| `query resource <任意>` | 自动判断 | 资源 ID → IP → 域名 → 自由文本 | `--json`, `--exact`, `--chain`, `--limit` |
| `query detail <资源ID>` | 资源详情 | 仅精确匹配单个资源 | `--json` |
| `query list <类型>` | 资源列表 | 按类型浏览全部资源 | `--json`, `--account`, `--region` |

#### 查看 IP

```bash
aliyun-inv query ip 1.2.3.4
aliyun-inv query ip 1.2.3.4 --json
aliyun-inv query ip 1.1.1.1 --chain       # 链路超过5条时，强制展开完整链路详情
aliyun-inv query ip 1.1.1.1 --chain --limit 5  # 只展示前5条链路
```

> 💡 IP 查询的命中资源只展示 ECS、EIP、LB 等实际资源，DNS 解析记录在下方的专用表格中单独展示，不会重复出现在命中资源中。

#### 查询域名

```bash
aliyun-inv query domain www.example.com
aliyun-inv query domain www.example.com --json
aliyun-inv query domain abc@xyz.com --exact     # 精确匹配，只返回该完整域名
aliyun-inv query domain xyz@abc.com --chain       # 链路超过5条时展开详情
aliyun-inv query domain xyz@abc.com --chain --limit 3  # 只展示前3条链路
```

#### 查询资源 ID

```bash
aliyun-inv query resource i-xxxx          # ECS 实例 ID
aliyun-inv query resource lb-xxxx         # CLB/ALB ID
aliyun-inv query resource rm-xxxx         # RDS 实例 ID
aliyun-inv query resource pc-xxxx         # PolarDB 集群 ID
aliyun-inv query resource dds-xxxx        # MongoDB 实例 ID
aliyun-inv query resource r-xxxx          # Tair 实例 ID
aliyun-inv query resource sg-xxxx         # 安全组 ID
aliyun-inv query resource d-xxxx          # 磁盘 ID（找到关联的 ECS 实例）
aliyun-inv query resource eip-xxxx        # EIP ID
aliyun-inv query resource LTAIxxxx        # AccessKey ID（找到关联的 RAM 用户）
```

> 💡 `sg-xxx` 搜索安全组时会同时显示安全组本身和绑定了该安全组的 ECS 实例。`d-xxx` 磁盘 ID 搜索会找到挂载该磁盘的 ECS 实例。`LTAIxxx` AK ID 会找到关联的 RAM 用户。

#### 通用文本搜索

```bash
aliyun-inv query resource web-01          # 按实例名称
aliyun-inv query resource 生产            # 按描述/备注
aliyun-inv query resource project  # 按项目名（同时匹配 OSS bucket、SLS project 等）
aliyun-inv query resource 10.0.1.10       # 按私网 IP（自动识别为 IP）
aliyun-inv query resource www.example.com # 按域名（自动识别为域名）
aliyun-inv query resource xyz@abc.com --exact  # 精确匹配，只返回完全等于该值的资源
aliyun-inv query resource 1.1.1.1 --chain   # 链路超过5条时，强制展开完整链路详情
aliyun-inv query resource 1.1.1.1 --chain --limit 5  # 只展示前5条链路
```

#### 资源详情

```bash
aliyun-inv query detail i-xxxx            # ECS 完整详情（含安全组 + 磁盘子表格）
aliyun-inv query detail lb-xxxx           # CLB 详情（含监听器 + vServerGroup + 转发规则）
aliyun-inv query detail rm-xxxx           # RDS 完整详情
aliyun-inv query detail pc-xxxx           # PolarDB 完整详情
aliyun-inv query detail sg-xxxx           # 安全组详情（含入/出方向规则子表格）
aliyun-inv query detail <SAE app_id>      # SAE 应用详情（含关联的 APIG 路由子表格）
aliyun-inv query detail <APIG group_id>   # APIG 网关详情（含域名 + API + 路由子表格）
aliyun-inv query detail i-xxxx --json     # JSON 格式输出
```

> 💡 `detail` 命令展示资源的所有重要字段，包括从 raw_json 中提取的创建时间、到期时间、付费类型等。支持 `_raw:` 前缀字段从原始 API 返回中提取任意字段。

**详情子表格说明**：

| 资源类型 | 子表格内容 |
|---------|-----------|
| ECS | 安全组列表（ID/名称/类型） + 块存储磁盘（ID/类型/类别/大小/设备/删除策略/加密/性能等级） |
| CLB | 监听器列表（协议/端口/后端端口/状态） + vServerGroup（ID/名称/服务器数） + 转发规则（域名/URL/监听器） |
| 安全组 | 入/出方向规则（方向/策略/协议/端口/源地址/优先级/网卡/描述） |
| SAE 应用 | 关联的 APIG 路由列表（路由名/路径/方法/后端(SAE)） |
| APIG 网关 | 接入域名（类型/域名/网络/协议/SSL/强制HTTPS/状态） + API列表 + 路由列表 |

#### 资源列表

按资源类型浏览所有账号下的聚合列表：

```bash
aliyun-inv query list ecs              # 列出所有 ECS 实例
aliyun-inv query list dns              # 列出所有域名（按域名聚合，显示记录数和启用/禁用数）
aliyun-inv query list rds              # 列出所有 RDS 数据库
aliyun-inv query list clb              # 列出所有 CLB 负载均衡
aliyun-inv query list eip              # 列出所有 EIP
aliyun-inv query list oss              # 列出所有 OSS 存储桶
aliyun-inv query list cdn              # 列出所有 CDN 加速域名
aliyun-inv query list sls              # 列出所有 SLS 项目
aliyun-inv query list ram              # 列出所有 RAM 用户
```

支持按账户和地域过滤：

```bash
aliyun-inv query list ecs --account xyz@abc.com              # 夺冠账户的 ECS（支持账户名/显示名模糊匹配）
aliyun-inv query list rds --region cn-hangzhou        # 杭州地域的 RDS
aliyun-inv query list ecs --account xyz@abc.com --region cn-beijing  # 组合过滤
aliyun-inv query list dns --json                      # JSON 格式输出
aliyun-inv query list ecs --json                      # JSON 格式输出
```

> 💡 `dns` 类型展示的是**域名**（按域名聚合），不是单条解析记录。每个域名显示记录总数、启用数和禁用数。如需查看某域名的具体解析记录，请用 `query domain <域名>` 命令。

支持的 17 种资源类型：`ecs` `dns` `eip` `clb` `alb` `cdn` `waf` `api` `oss` `rds` `tair` `polardb` `mongodb` `security_group` `sae` `sls` `ram`

## 查询结果示例

### 文本输出 — 通用查询

```txt
查询: project (类型: resource_id)

                                    命中资源
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ 账号     ┃ 地域     ┃ 资源类型 ┃ 资源ID    ┃ 资源名称 ┃ 内网地址  ┃ 外网地址 ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ 餐赞阿里… │ oss-cn-… │ OSS      │ project… │ project… │ oss-cn-h… │ oss-cn-… │
│ 餐赞阿里… │ cn-hang… │ SLS      │ project… │ project… │           │          │
│ 夺冠阿里… │ cn-beij… │ SLS      │ project… │ project… │           │          │
└──────────┴──────────┴──────────┴───────────┴──────────┴───────────┴──────────┘
```

### 文本输出 — 域名查询（带链路树）

```txt
查询: www.abc.com (类型: domain)

                                    命中资源
┏━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ 账号     ┃ 地域     ┃ 资源类型 ┃ 资源ID    ┃ 资源名称 ┃ 内网地址  ┃ 外网地址 ┃
┡━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ 阿里… │ global   │ DNS      │ 123456    │ www.xd… │           │ 1.2.3.4  │
│ 阿里… │ cn-beij… │ CLB      │ lb-xxxx   │ 项目… │           │ 1.2.3.4  │
└──────────┴──────────┴──────────┴───────────┴──────────┴───────────┴──────────┘

可能链路 [dns_to_lb]:
www.abc.com
  └ CLB 平台负载 / lb-xxxx / A阿里云 / cn-beijing / IP: 1.2.3.4
     └ ECS 后端 / i-xxxx1 / B阿里云 / cn-beijing / IP: 10.0.x.x
     └ ECS 后端 / i-xxxx2 / C阿里云 / cn-beijing / IP: 10.0.x.x
```

### 文本输出 — APIG 链路（DNS→APIG→SAE）

```txt
查询: abc@xyz.com (类型: domain)

可能链路 [dns_to_sae]:
abc@xyz.com
  └ 云原生API网关 gw-xxxx / A阿里云 / cn-beijing
     └ 路由: 小程序-获取用户信息 → SAE后端(wechat-miniapp)
     └ 路由: 小程序-支付 → SAE后端(wechat-miniapp)
```

### JSON 输出

```bash
aliyun-inv query ip 1.2.3.4 --json
```

```json
{
  "query": {
    "type": "ip",
    "value": "1.2.3.4"
  },
  "matched_resources": [
    {
      "resource_type": "ecs",
      "resource_id": "i-xxxx",
      "resource_name": "web-01",
      "private_address": "10.0.1.10",
      "public_address": "1.2.3.4",
      "security_groups": [
        {"security_group_id": "sg-xxx", "security_group_name": "web-sg", "security_group_type": "normal"}
      ],
      "disks": [
        {"disk_id": "d-xxx", "type": "system", "category": "cloud_essd", "size": 200, "device": "/dev/xvda"}
      ]
    }
  ],
  "dns_records": [...],
  "backends": [...],
  "lb_listeners": [...],
  "lb_log_configs": [...],
  "chain_trees": [...],
  "warnings": []
}
```

## 内外网地址对照表

不同资源类型的内网/外网地址取值来源：

| 资源类型 | 内网地址 | 外网地址 |
|---------|---------|---------|
| ECS | 私网 IP 列表（含多 ENI 辅助 IP） | 公网 IP + EIP |
| RDS | connection_string:port | public_connection_string:public_port |
| PolarDB | private_connection_string:connection_port | public_connection_string:connection_port |
| Tair | connection_domain:port | public_domain:public_port |
| MongoDB | private_connection:connection_port | public_connection:connection_port |
| EIP | — | ip_address |
| CLB | address（内网型） | address（公网型 VIP）或 EIP |
| ALB | dns_name（VPC 内） | dns_name 或 address |
| OSS | intranet_endpoint | extranet_endpoint |
| CDN | origin_address | cname |
| WAF | source_ips（回源 IP） | cname |
| DNS | — | value |
| API Gateway | private_domain | public_domain / sub_domain |
| SAE | service_url | — |

> ⚠️ 数据库类产品的外网地址需要**开启外网访问**才有值。CLB 内网型负载均衡的外网地址来自绑定的 EIP。

## 链路发现

查询结果中的"可能链路"基于以下关联规则自动构建（嵌套树式结构）：

| 链路模式 | 关联方式 | 类型标签 |
|---------|---------|---------|
| DNS → CDN | CNAME 指向 CDN 域名 | `dns_to_cdn` |
| DNS → WAF | CNAME 指向 WAF 域名 | `dns_to_waf` |
| DNS → LB | A 记录指向 LB VIP，或 CNAME 指向 ALB dns_name | `dns_to_lb` |
| DNS → APIG → SAE | CNAME 指向 alicloudapi.com，通过 APIG 域名表精确查找网关 → 路由 → SAE 后端 | `dns_to_sae` |
| CDN → LB/ECS/OSS | 回源地址关联 | — |
| WAF → LB/EIP | 回源 IP 关联 | — |
| LB → ECS | 后端服务器关联 | — |
| ECS → LB | 反向查找（ECS 作为哪些 LB 的后端） | — |
| SAE → APIG → DNS | SAE 应用名匹配路由后端 → 反向到 DNS 记录 | `sae_to_dns` |
| LB → SLS | CLB/ALB 日志配置关联 | — |

> 💡 链路发现**跨账号自动关联**——比如 A 账号的 DNS 指向 B 账号的 LB，依然能发现完整链路。VPC 关联的 DB 不再自动挂载（因为所有资源基本在同一 VPC，挂载是噪音）。链路数量 ≤5 条时自动完整展示，>5 条时默认折叠为摘要，需加 `--chain` 参数展开详情。

### 链路发现核心机制

1. **DNS→APIG 精确查找**：CNAME 值匹配 `alicloudapi.com` 时，优先通过 `apig_domains` 表精确查找网关（比 sub_domain 模糊匹配更准确）
2. **APIG→SAE 后端解析**：从路由 raw_json 的 Backend.Services 中解析 SAE 后端格式（`{app_name}-{namespace_short_id}.sl-{uid}-{region}...`）
3. **SAE→DNS 反向链路**：从 SAE 应用名反向查找 APIG 路由后端 → APIG 域名 → DNS 记录
4. **LB 内网型 EIP 补全**：内网型 CLB 的公网地址来自绑定的 EIP（instance_type=SlbInstance）
5. **去重机制**：同一资源在主表和 ip_addresses 表都有记录时只保留主表版本；后端查找也只处理一次
6. **IP 查询 DNS 去重**：IP 查询时命中资源过滤掉 DNS 类型（`dns_record`），DNS 记录在下方专用表格展示
7. **链路折叠**：链路树 ≤5 条自动完整展示，>5 条默认折叠为数量摘要，`--chain` 展开详情，`--chain --limit N` 限制数量

## 数据库表结构（31 张）

| 表名 | 说明 | 主键/唯一键 |
|------|------|------------|
| cloud_accounts | 账号信息 | name |
| resources_raw | 阿里云原始返回 | account_name + resource_type + region_id + resource_id |
| ecs_instances | ECS 实例详情 | account_name + region_id + instance_id |
| dns_records | DNS 解析记录 | account_name + record_id |
| eip_addresses | EIP 弹性公网 IP | account_name + region_id + allocation_id |
| load_balancers | 负载均衡（CLB + ALB） | account_name + region_id + lb_type + lb_id |
| backend_servers | LB 后端服务器 | account_name + lb_type + region_id + lb_id + server_group_id + backend_resource_id |
| lb_listeners | CLB 监听器 | account_name + lb_type + region_id + lb_id + listener_port + listener_protocol |
| lb_vserver_groups | LB vServerGroup | account_name + lb_type + region_id + lb_id + vserver_group_id |
| lb_forwarding_rules | CLB 转发规则 | account_name + lb_type + region_id + lb_id + listener_port + listener_protocol + rule_id |
| ip_addresses | 统一 IP 查询表（有索引） | account_name + resource_type + resource_id + ip + ip_type |
| sls_projects | SLS 日志项目 | account_name + region_id + project_name |
| sls_logstores | SLS 日志库 | account_name + region_id + project_name + logstore_name |
| lb_log_configs | LB 访问日志 SLS 配置 | account_name + lb_type + region_id + lb_id |
| ram_users | RAM 用户 | account_name + user_id |
| ram_access_keys | RAM AccessKey | account_name + user_name + access_key_id |
| ram_user_policies | RAM 用户授权策略 | account_name + user_name + policy_name + policy_type |
| cdn_domains | CDN 加速域名 | account_name + domain_name |
| api_gateways | API 网关（CloudAPI + MSE/APIG） | account_name + region_id + api_type + group_id |
| oss_buckets | OSS 存储桶 | account_name + bucket_name |
| rds_instances | RDS 数据库实例 | account_name + region_id + instance_id |
| waf_domains | WAF 防护域名 | account_name + region_id + domain_name |
| tair_instances | Tair/Redis 实例 | account_name + region_id + instance_id |
| polardb_clusters | PolarDB 集群 | account_name + region_id + cluster_id |
| mongodb_instances | MongoDB/DDS 实例 | account_name + region_id + instance_id |
| security_groups | 安全组（含规则） | account_name + region_id + security_group_id |
| apig_domains | APIG 域名（接入+自定义绑定） | account_name + region_id + gateway_id + domain_id |
| apig_apis | APIG API | account_name + region_id + gateway_id + api_id |
| apig_routes | APIG 路由 | account_name + region_id + gateway_id + api_id + route_id |
| sae_namespaces | SAE 命名空间 | account_name + region_id + namespace_id |
| sae_apps | SAE 应用 | account_name + region_id + app_id |

> 💡 每张表都有 `raw_json`（JSON 列）存储阿里云 API 的原始返回数据，以及 `last_seen_at` 记录最后同步时间。新增字段时数据库自动迁移（ALTER TABLE ADD COLUMN），无需手动操作。

### ECS raw_json 增强字段

ECS 的 `raw_json` 中额外包含同步时获取的增强信息：

- **Disks** — 磁盘列表（来自 DescribeDisks API），含磁盘 ID、类型、类别、大小、设备路径、删除策略、加密、性能等级
- **SecurityGroups** — 安全组详情（来自 DescribeSecurityGroups API），含安全组 ID、名称、类型、描述、VPC
- **NetworkInterfaces** — 多 ENI 信息（来自 DescribeNetworkInterfaces），含辅助私网 IP

安全组的 `raw_json` 包含 `Permissions`（入/出方向规则列表）。

## 新增账号（零代码）

新增阿里云账号完全不需要修改代码，只需两步：

1. **在 `.env` 中添加 AK/SK**：
```bash
NEW_ACCOUNT_ACCESS_KEY_ID=LTAI5t...
NEW_ACCOUNT_ACCESS_KEY_SECRET=xxxx...
```

2. **在 `config/accounts.yaml` 中添加账号配置**：
```yaml
  - name: new-account@company.com
    display_name: 新账号名称
    credential_env_prefix: NEW_ACCOUNT
    enabled: true
    resources:
      ecs: true
      dns: true
      # ... 按需启用
```

然后运行 `aliyun-inv sync all`，新账号的资源会自动同步、查询、链路关联全部生效。

> 💡 跨账号链路也能自动发现——比如 A 账号的 DNS CNAME 指向 B 账号的 APIG，依然能构建完整链路树。

## 新增资源类型（需写代码）

如果将来阿里云推出新的资源类型（如 NAT Gateway、VPC 等），需要：

1. 在 `models.py` 中添加 SQLAlchemy 模型
2. 在 `collectors/` 中添加新的 Collector 类（继承 `BaseCollector`）
3. 在 `sync.py` 的 `COLLECTOR_MAP` 中注册
4. 在 `config.py` 的 `ResourceConfig` 中添加字段
5. 在 `query.py` 中添加搜索逻辑和 `_to_dict` 函数
6. 在 `query_list.py` 中添加列表查询 handler 和 `VALID_RESOURCE_TYPES` 注册
7. 在 `output.py` 的 `TYPE_DISPLAY` + `LIST_COLUMNS` + `LIST_TYPE_TITLES` 中添加配置
8. 在 `relationship.py` 中添加链路关联（如果有）
9. 在 `aliyun_client.py` 中添加 SDK Client + models import
10. 在 `pyproject.toml` 中添加 SDK 依赖包
11. 运行 `aliyun-inv db init` 自动建表

这是一次性的开发工作，完成后所有账号都能同步和查询该资源类型。

## 给 Agent/程序调用

所有查询命令都支持 `--json` / `-j` 输出，可以直接被程序或 AI Agent 调用：

```bash
aliyun-inv query ip 1.2.3.4 --json
aliyun-inv query domain www.example.com --json
aliyun-inv query resource i-xxxx --json
aliyun-inv query resource sg-xxxx --json
aliyun-inv query list ecs --json                    # 所有 ECS 列表（JSON）
aliyun-inv query list dns --json                    # 所有域名列表（JSON）
aliyun-inv query list rds --json --account 夺冠     # 夺冠账户的 RDS（JSON）
aliyun-inv query list ecs --json --region cn-beijing  # 北京地域 ECS（JSON）
aliyun-inv query resource chuandao-overflow --json
aliyun-inv query resource m.duoguan.com --exact --json     # 精确匹配 + JSON
aliyun-inv query resource 59.110.50.251 --chain --json      # 展开链路 + JSON
aliyun-inv query detail rm-xxxx --json
aliyun-inv query detail sg-xxxx --json
aliyun-inv query detail <SAE app_id> --json
aliyun-inv query detail <APIG group_id> --json
```

## 安全注意事项

⚠️ **请务必遵守以下安全原则：**

1. **不要使用主账号 AK/SK** — 建议使用 RAM 子账号的只读权限 AK/SK
2. **建议使用 RAM 只读权限** — 最小权限原则，以下权限策略参考：

   ```json
   {
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ecs:Describe*",
           "alidns:Describe*",
           "vpc:Describe*",
           "slb:Describe*",
           "alb:List*",
           "sls:List*",
           "sls:Get*",
           "ram:Describe*",
           "ram:Get*",
           "ram:List*",
           "cdn:Describe*",
           "cloudapi:Describe*",
           "mse:List*",
           "mse:Get*",
           "oss:List*",
           "oss:Get*",
           "rds:Describe*",
           "waf-openapi:Describe*",
           "kvstore:Describe*",
           "polardb:Describe*",
           "dds:Describe*",
           "sae:List*",
           "sae:Describe*"
         ],
         "Resource": "*"
       }
     ],
     "Version": "1"
   }
   ```

3. **不要提交 `.env`** — `.env` 包含 AK/SK，绝对不能提交到 Git（`.gitignore` 已包含）
4. **不要打印 AK/SK** — 程序不会在输出中显示 AK/SK
5. **只做读取操作** — 本工具不会对任何云资源做修改/创建/删除操作，所有 API 调用均为 Describe/List/Get 类型
6. **数据仅存本地** — SQLite 数据库文件仅在本地存储，不会发送到任何外部服务

## 常见问题

### 同步很慢怎么办？

- 用 `--resource` 参数只同步需要的资源类型：`aliyun-inv sync all --resource rds`
- 用 `--region` 参数只同步指定地域：`aliyun-inv sync account prod-a --resource ecs --region cn-hangzhou`
- 地域探测会自动发现有资源的地域，跳过空地域
- 数据库类产品（RDS/PolarDB/Tair/MongoDB）和安全组因需额外 API 获取连接地址和规则，耗时更长
- CLB 因需获取监听器、vServerGroup 和 SLS 日志配置，耗时比 ALB 长

### 查询不到数据库的外网地址？

- 数据库类产品需要**先在阿里云控制台开启外网访问**才有外网连接地址
- 确认已执行过 `aliyun-inv sync all --resource rds` 等同步命令，外网地址是在同步时通过额外 API 获取的
- 已有数据需要重新同步才能获取新增的外网地址字段：先同步一次即可自动填充

### 查询不到安全组？

- 确认已执行 `aliyun-inv sync account <name> --resource security_group` 同步安全组
- 安全组是独立资源，未绑定 ECS 的安全组不会在 ECS 同步时出现，需要单独同步
- 同步后可用 `aliyun-inv query resource sg-xxx` 搜索，或 `aliyun-inv query detail sg-xxx` 查看详情（含规则）

### 查询不到 ECS 的所有 IP？

- ECS Collector 会提取主网卡私网 IP + 多 ENI 辅助私网 IP + NAT IP
- 确认已重新同步 ECS：`aliyun-inv sync all --resource ecs`（旧数据不含多 ENI IP）
- `query detail <ECS instance_id>` 会展示完整 IP 信息

### 搜索磁盘 ID 或安全组 ID 找不到 ECS？

- `aliyun-inv query resource d-xxx` 会搜索挂载该磁盘的 ECS 实例
- `aliyun-inv query resource sg-xxx` 会搜索安全组本身 + 绑定了该安全组的 ECS 实例
- 确保已同步 ECS 和安全组

### 模型新增字段后如何更新数据库？

- 直接运行 `aliyun-inv db init` 即可，自动 ALTER TABLE 补齐缺失列
- 或运行任何 `sync` / `query` 命令，也会自动执行 `init_db` 补齐
- 不需要手动执行 SQL 迁移脚本

### 查询结果太多怎么办？

- **精确匹配**：使用 `--exact` / `-e` 参数，只返回完全等于查询值的记录，不做模糊搜索：
  ```bash
  aliyun-inv query resource abc@xyz.com --exact   # 只返回 abc@xyz.com，不返回其他 xyz.com 子域名
  aliyun-inv query domain xyz@abc.com --exact       # 只返回 xyz@abc.com 的解析记录
  ```
- **链路折叠**：当链路数量超过 5 条时，默认只显示摘要（如"确定性链路: 101 条"），使用 `--chain` 展开完整详情：
  ```bash
  aliyun-inv query resource 1.1.1.1           # 链路超过5条 → 显示摘要
  aliyun-inv query resource 2.2.2.2 --chain   # 展开全部链路
  aliyun-inv query resource 3.3.3.3 --chain --limit 5  # 只展示前5条链路
  ```
- **链路 ≤5 条时自动展示**，不需要 `--chain` 参数

### 同步报错 "AK/SK 未配置"？

- 检查 `.env` 中的环境变量名是否与 `config/accounts.yaml` 中的 `credential_env_prefix` 一致
- 例如 `credential_env_prefix: XXXXX` → 需要 `XXXXX_ACCESS_KEY_ID` 和 `XXXXX_ACCESS_KEY_SECRET`

### 如何在定时任务中使用？

```bash
# crontab 示例：每天凌晨 2 点全量同步
0 2 * * * cd /path/to/CMDB && source .venv/bin/activate && aliyun-inv sync all >> /var/log/aliyun-inv-sync.log 2>&1
```

### SAE 同步注意事项？

- SAE 分页参数是 `current_page/page_size`（不兼容通用的 `PageNumber/PageSize`），需手动分页
- SAE 应用 `status` 需推断：`RUNNING` if `running_instances > 0`
- SAE SDK 使用 `name_space_short_id`（注意不是 `namespace_short_id`）

## 技术栈

- **Python 3.11+**
- **SQLite + SQLAlchemy 2.0** — 本地数据库，自动迁移
- **Typer** — CLI 命令框架
- **Rich** — 终端富文本输出（表格、面板、树形图）
- **Pydantic 2.0** — 配置数据验证
- **阿里云 SDK 2.0 (Tea SDK)** — 20 个服务 SDK

### SDK 包列表

| 服务 | SDK 包名 |
|------|---------|
| ECS | alibabacloud-ecs20140526 |
| DNS | alibabacloud-alidns20150109 |
| VPC/EIP | alibabacloud-vpc20160428 |
| CLB | alibabacloud-slb20140515 |
| ALB | alibabacloud-alb20200616 |
| SLS | alibabacloud-sls20201230 |
| RAM | alibabacloud-ram20150501 |
| CDN | alibabacloud-cdn20180510 |
| CloudAPI | alibabacloud-cloudapi20160714 |
| MSE 云原生网关 | alibabacloud-mse20190531 |
| APIG | alibabacloud-apig20240327 |
| SAE | alibabacloud-sae20190506 |
| OSS | oss2 |
| RDS | alibabacloud-rds20140815 |
| WAF | alibabacloud-waf-openapi20190910 |
| Tair/KVStore | alibabacloud-r_kvstore20150101 |
| PolarDB | alibabacloud-polardb20170801 |
| MongoDB/DDS | alibabacloud-dds20151201 |
| Tea 基础包 | alibabacloud-tea-openapi |

## 项目目录

```
CMDB/
  pyproject.toml          — 项目配置 + SDK 依赖（20 个）
  README.md               — 本文档
  .env.example            — AK/SK 配置模板
  .env                    — AK/SK 实际配置（不提交 Git）
  .gitignore              — Git 忽略规则
  config/
    accounts.yaml         — 账号配置（需手动创建）
    accounts.example.yaml — 账号配置模板
  data/
    aliyun_inventory.db   — SQLite 数据库（运行时自动创建）
  src/
    aliyun_inventory/
      __init__.py
      cli.py              — CLI 命令入口（Typer 应用）
      config.py           — 账号配置加载 & AK/SK 环境变量（Pydantic）
      db.py               — 数据库引擎、会话 & 自动迁移（ALTER TABLE ADD COLUMN）
      models.py           — 31 张 SQLAlchemy 模型定义
      aliyun_client.py    — SDK 客户端工厂 + 地域探测 + 分页辅助
      collectors/
        __init__.py
        base.py           — Collector 基类（upsert/save_raw/save_ip/save_log_config）
        ecs.py            — ECS 收集器（含磁盘 + 安全组 + 多 ENI + NAT IP）
        dns.py            — DNS 收集器（域名自动发现）
        eip.py            — EIP 收集器
        clb.py            — CLB 收集器（含后端服务器 + 监听器 + vServerGroup + 转发规则 + SLS 日志配置）
        alb.py            — ALB 收集器（含后端服务器组）
        sls.py            — SLS 收集器（项目 + 日志库 + CLB/ALB 日志配置）
        ram.py            — RAM 收集器（用户 + AK + AK最后使用时间 + MFA信息）
        cdn.py            — CDN 收集器
        api.py            — API 网关收集器（CloudAPI + MSE/APIG + 子资源）
        oss.py            — OSS 收集器
        rds.py            — RDS 收集器（含内外网连接地址）
        waf.py            — WAF 收集器（含 CNAME + 回源 IP）
        tair.py           — Tair 收集器（含内外网连接地址）
        polardb.py        — PolarDB 收集器（含内外网连接地址）
        mongodb.py        — MongoDB 收集器（副本集 + 分片集群连接地址）
        security_group.py — 安全组收集器（含入/出方向规则）
        sae.py            — SAE 收集器（命名空间 + 应用 + 手动分页）
      sync.py             — 同步引擎（17 个 Collector 注册）
      relationship.py     — 链路发现引擎（嵌套树式，含 APIG→SAE 反向链路）
      query.py            — 通用查询引擎 + query_detail（含去重 + SLS 搜索 + LB 监听器）
      query_list.py       — 资源列表查询引擎（17 种类型的聚合列表 + 过滤）
      output.py           — Rich 文本/JSON/detail/list 输出格式化（含子表格 + 链路树 + 列表表格）
```

## 已知 SDK 字段坑

阿里云 SDK 2.0 有些字段名和 API 文档不一致，项目已踩坑并验证过的：

| 服务 | 问题 | 正确字段名 |
|------|------|-----------|
| EIP | 文档写 EipAddress，SDK 是 `ip_address` | `ip_address` ✅ |
| CLB | 没有 `dns_name` 属性 | 用 `getattr` 安全取值 |
| CLB 日志 | `DescribeAccessLogs` API 不在 SDK 中 | 用 `DescribeAccessLogsDownloadAttribute` |
| SLS | `list_logstore` 是错的 | `list_log_stores` ✅（有复数 s） |
| RDS | `dbinstance_net_type` 属性不存在 | `iptype` ✅ |
| Tair | body 结构是 `net_info_items.instance_net_info` | 不是 `dbinstance_net_infos.dbinstance_net_info` |
| Tair | `dbinstance_net_type` 值是数字 "2"/"0" | 不能用来判断内外网，用 `iptype` |
| MongoDB | `connection_type` 返回 None | `network_type` ✅ |
| SAE | 分页参数不兼容通用 `PageNumber/PageSize` | `current_page/page_size`（手动分页） |
| SAE | SDK 用 `name_space_short_id` | 不是 `namespace_short_id` |

## License

MIT

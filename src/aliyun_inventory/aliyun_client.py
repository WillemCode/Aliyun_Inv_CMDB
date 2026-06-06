"""阿里云 SDK 2.0 客户端工厂 — 创建各服务客户端、探测有资源的地域、发现域名"""

import json
import logging
from typing import Any, Callable, Optional

from alibabacloud_tea_openapi import models as open_api_models

from alibabacloud_ecs20140526.client import Client as EcsClient
from alibabacloud_ecs20140526 import models as ecs_models
from alibabacloud_alidns20150109.client import Client as DnsClient
from alibabacloud_alidns20150109 import models as dns_models
from alibabacloud_vpc20160428.client import Client as VpcClient
from alibabacloud_vpc20160428 import models as vpc_models
from alibabacloud_slb20140515.client import Client as SlbClient
from alibabacloud_slb20140515 import models as slb_models
from alibabacloud_alb20200616.client import Client as AlbClient
from alibabacloud_alb20200616 import models as alb_models
from alibabacloud_sls20201230.client import Client as SlsClient
from alibabacloud_sls20201230 import models as sls_models
from alibabacloud_ram20150501.client import Client as RamClient
from alibabacloud_ram20150501 import models as ram_models
from alibabacloud_cdn20180510.client import Client as CdnClient
from alibabacloud_cdn20180510 import models as cdn_models
from alibabacloud_cloudapi20160714.client import Client as CloudApiClient
from alibabacloud_cloudapi20160714 import models as cloudapi_models
from alibabacloud_mse20190531.client import Client as MseClient
from alibabacloud_mse20190531 import models as mse_models
from alibabacloud_rds20140815.client import Client as RdsClient
from alibabacloud_rds20140815 import models as rds_models
from alibabacloud_waf_openapi20190910.client import Client as WafClient
from alibabacloud_waf_openapi20190910 import models as waf_models
from alibabacloud_r_kvstore20150101.client import Client as KvStoreClient
from alibabacloud_r_kvstore20150101 import models as kv_models
from alibabacloud_polardb20170801.client import Client as PolarDBClient
from alibabacloud_polardb20170801 import models as polar_models
from alibabacloud_dds20151201.client import Client as DdsClient
from alibabacloud_dds20151201 import models as dds_models
from alibabacloud_apig20240327.client import Client as ApigClient
from alibabacloud_sae20190506.client import Client as SaeClient

_logger = logging.getLogger(__name__)


def _create_config(ak: str, sk: str, region_id: str) -> open_api_models.Config:
    """创建 SDK 2.0 配置对象"""
    config = open_api_models.Config(
        access_key_id=ak,
        access_key_secret=sk,
    )
    config.region_id = region_id
    return config


class AliyunClientFactory:
    """阿里云 SDK 客户端工厂，管理客户端缓存和自动发现

    核心设计：不遍历所有地域，而是先探测哪些地域有资源，
    只对有资源的地域做完整数据拉取。
    """

    def __init__(self, ak: str, sk: str) -> None:
        self.ak = ak
        self.sk = sk
        self._client_cache: dict[str, Any] = {}
        # 缓存各资源类型的有资源地域
        self._active_regions_cache: dict[str, list[str]] = {}
        self._domains_cache: Optional[list[str]] = None

    def create_client(self, service: str, region_id: str) -> Any:
        """根据服务名和 region 创建 SDK Client，带缓存"""
        cache_key = f"{service}:{region_id}"
        if cache_key in self._client_cache:
            return self._client_cache[cache_key]

        config = _create_config(self.ak, self.sk, region_id)

        client_map: dict[str, Callable] = {
            "ecs": EcsClient,
            "dns": DnsClient,
            "vpc": VpcClient,
            "slb": SlbClient,
            "alb": AlbClient,
            "sls": SlsClient,
            "ram": RamClient,
            "cdn": CdnClient,
            "cloudapi": CloudApiClient,
            "mse": MseClient,
            "rds": RdsClient,
            "waf": WafClient,
            "kvstore": KvStoreClient,
            "polardb": PolarDBClient,
            "dds": DdsClient,
            "apig": ApigClient,
            "sae": SaeClient,
        }

        client_class = client_map.get(service)
        if not client_class:
            raise ValueError(f"未知的服务类型: {service}")

        # DNS 是全局服务，不需要按 region 区分 endpoint
        if service == "dns":
            config.endpoint = "alidns.aliyuncs.com"

        # SLS 需要设置特殊的 endpoint 格式
        if service == "sls":
            config.endpoint = f"{region_id}.log.aliyuncs.com"

        # RAM 是全局服务
        if service == "ram":
            config.endpoint = "ram.aliyuncs.com"

        # CDN 是全局服务
        if service == "cdn":
            config.endpoint = "cdn.aliyuncs.com"

        # CloudAPI 全局服务
        if service == "cloudapi":
            config.endpoint = "apigateway.cn-hangzhou.aliyuncs.com"

        # 云原生 API 网关 (APIG) 按地域区分
        if service == "apig":
            config.endpoint = f"apig.{region_id}.aliyuncs.com"

        # WAF 全局服务
        if service == "waf":
            config.endpoint = "wafopenapi.cn-hangzhou.aliyuncs.com"

        # SAE 按地域区分
        if service == "sae":
            config.endpoint = f"sae.{region_id}.aliyuncs.com"

        client = client_class(config)
        self._client_cache[cache_key] = client
        return client

    # ──────────────────────────────────────────────
    # 获取所有可用地域（基础方法）
    # ──────────────────────────────────────────────

    def _get_all_regions(self) -> list[str]:
        """获取阿里云所有可用地域 ID 列表（使用 DescribeRegions）"""
        try:
            config = _create_config(self.ak, self.sk, "cn-hangzhou")
            client = EcsClient(config)
            request = ecs_models.DescribeRegionsRequest()
            response = client.describe_regions(request)
            return [r.region_id for r in response.body.regions.region]
        except Exception as e:
            _logger.error("获取地域列表失败", exc_info=True)
            return [
                "cn-hangzhou", "cn-shanghai", "cn-beijing",
                "cn-shenzhen", "cn-hongkong", "cn-chengdu",
                "cn-qingdao", "cn-guangzhou", "cn-nanjing",
                "cn-fuzhou", "cn-heyuan", "ap-southeast-1",
            ]

    # ──────────────────────────────────────────────
    # 探测哪些地域有资源（核心方法）
    # ──────────────────────────────────────────────

    def discover_active_regions(self, resource_type: str) -> list[str]:
        """探测账号在哪些地域有指定类型的资源

        策略：对所有可用地域做轻量级探测（PageSize=1 / MaxResults=1），
        只返回 TotalCount > 0 的地域，避免遍历空地域浪费 API 调用。

        Args:
            resource_type: 资源类型 (ecs / eip / clb / alb)

        Returns:
            有资源的地域 ID 列表
        """
        if resource_type in self._active_regions_cache:
            return self._active_regions_cache[resource_type]

        all_regions = self._get_all_regions()
        _logger.info("探测 %s 有资源的地域... (共 %d 个可用地域)", resource_type, len(all_regions))

        active_regions = []

        for region_id in all_regions:
            try:
                count = self._probe_region(resource_type, region_id)
                if count > 0:
                    active_regions.append(region_id)
            except Exception:
                # 探测失败的地域跳过（可能是权限不足或服务未开通）
                continue

        _logger.info(
            "%s: %d/%d 个地域有资源 (%s)",
            resource_type, len(active_regions), len(all_regions), ", ".join(active_regions),
        )

        self._active_regions_cache[resource_type] = active_regions
        return active_regions

    def _probe_region(self, resource_type: str, region_id: str) -> int:
        """对单个地域做轻量级探测，返回该地域该资源的总数

        使用 PageSize=1 / MaxResults=1 的请求，只取 TotalCount，
        不拉实际数据，最大限度减少 API 开销。
        """
        if resource_type == "ecs":
            client = self.create_client("ecs", region_id)
            request = ecs_models.DescribeInstancesRequest(
                region_id=region_id,
                page_number=1,
                page_size=1,
            )
            response = client.describe_instances(request)
            return response.body.total_count

        elif resource_type == "eip":
            client = self.create_client("vpc", region_id)
            request = vpc_models.DescribeEipAddressesRequest(
                region_id=region_id,
                page_number=1,
                page_size=1,
            )
            response = client.describe_eip_addresses(request)
            return response.body.total_count

        elif resource_type == "clb":
            client = self.create_client("slb", region_id)
            request = slb_models.DescribeLoadBalancersRequest(
                region_id=region_id,
                page_number=1,
                page_size=1,
            )
            response = client.describe_load_balancers(request)
            return response.body.total_count

        elif resource_type == "alb":
            client = self.create_client("alb", region_id)
            request = alb_models.ListLoadBalancersRequest(
                max_results=1,
            )
            response = client.list_load_balancers(request)
            # ALB 没有 total_count，用返回列表长度判断
            lbs = response.body.load_balancers or []
            return len(lbs)

        elif resource_type == "rds":
            client = self.create_client("rds", region_id)
            request = rds_models.DescribeDBInstancesRequest(
                region_id=region_id,
                page_number=1,
                page_size=1,
            )
            response = client.describe_dbinstances(request)
            return response.body.total_record_count

        elif resource_type == "tair":
            client = self.create_client("kvstore", region_id)
            request = kv_models.DescribeInstancesRequest(
                region_id=region_id,
                page_number=1,
                page_size=1,
            )
            response = client.describe_instances(request)
            return response.body.total_count

        elif resource_type == "polardb":
            client = self.create_client("polardb", region_id)
            request = polar_models.DescribeDBClustersRequest(
                region_id=region_id,
            )
            response = client.describe_dbclusters(request)
            return response.body.total_record_count

        elif resource_type == "mongodb":
            client = self.create_client("dds", region_id)
            request = dds_models.DescribeDBInstancesRequest(
                region_id=region_id,
            )
            response = client.describe_dbinstances(request)
            return response.body.total_count

        else:
            return 0

    # ──────────────────────────────────────────────
    # DNS 域名发现（全局服务，无地域）
    # ──────────────────────────────────────────────

    def discover_domains(self) -> list[str]:
        """自动发现账号下的所有域名（使用 DNS DescribeDomains）"""
        if self._domains_cache is not None:
            return self._domains_cache

        try:
            client = self.create_client("dns", "cn-hangzhou")  # DNS 全局服务
            all_domains = []
            page_number = 1
            while True:
                request = dns_models.DescribeDomainsRequest(
                    page_number=page_number,
                    page_size=100,
                )
                response = client.describe_domains(request)
                domains = response.body.domains.domain
                all_domains.extend([d.domain_name for d in domains])
                total = response.body.total_count
                if len(all_domains) >= total or not domains:
                    break
                page_number += 1

            _logger.info("发现 %d 个域名", len(all_domains))
            self._domains_cache = all_domains
            return all_domains
        except Exception as e:
            _logger.error("发现域名失败", exc_info=True)
            self._domains_cache = []
            return []


# ──────────────────────────────────────────────
# 分页辅助函数
# ──────────────────────────────────────────────

def paginate_page_number(
    client: Any,
    method_name: str,
    request_class: Any,
    extra_params: dict[str, Any] = None,
    page_size: int = 100,
    list_extractor: Callable = None,
) -> list[Any]:
    """使用 PageNumber/PageSize 分页遍历所有结果

    page_size=0 时表示不传 page_size/page_number 参数（PolarDB/DDS 等
    不支持分页参数的服务，一次返回所有结果）。
    """
    all_items = []
    page_number = 1

    while True:
        params = {}
        if page_size > 0:
            params["page_number"] = page_number
            params["page_size"] = page_size
        if extra_params:
            params.update(extra_params)

        request = request_class(**params)

        try:
            method = getattr(client, method_name)
            response = method(request)
        except Exception as e:
            error_msg = str(e)
            # 服务未开通类错误（CDN/WAF 等 403）— 简洁提示，不打印堆栈
            service_not_opened_markers = (
                "CdnServiceNotFound", "does not open CDN service",
                "WafServiceNotFound", "does not open WAF service", "NotOpenedWaf",
                "ServiceNotFound", "ServiceNotActivated", "NotActivated",
            )
            is_service_not_opened = any(marker in error_msg for marker in service_not_opened_markers)
            if is_service_not_opened:
                _logger.info("分页请求 %s: 服务未开通", method_name)
            else:
                _logger.warning("分页请求 %s 第 %d 页失败", method_name, page_number, exc_info=True)
            break

        items = list_extractor(response) if list_extractor else []
        all_items.extend(items)

        if not items:
            break

        # 不分页模式（page_size=0）：一次取完即退出
        if page_size == 0:
            break

        if len(items) < page_size:
            break

        page_number += 1

    return all_items


def paginate_next_token(
    client: Any,
    method_name: str,
    request_class: Any,
    extra_params: dict[str, Any] = None,
    max_results: int = 100,
    list_extractor: Callable = None,
) -> list[Any]:
    """使用 NextToken/MaxResults 分页遍历所有结果（适用于 ALB）"""
    all_items = []
    next_token = ""

    while True:
        params = {"max_results": max_results, "next_token": next_token}
        if extra_params:
            params.update(extra_params)

        request = request_class(**params)

        try:
            method = getattr(client, method_name)
            response = method(request)
        except Exception as e:
            error_msg = str(e)
            service_not_opened_markers = (
                "CdnServiceNotFound", "does not open CDN service",
                "WafServiceNotFound", "does not open WAF service", "NotOpenedWaf",
                "ServiceNotFound", "ServiceNotActivated", "NotActivated",
            )
            is_service_not_opened = any(marker in error_msg for marker in service_not_opened_markers)
            if is_service_not_opened:
                _logger.info("分页请求 %s: 服务未开通", method_name)
            else:
                _logger.warning("分页请求 %s 失败", method_name, exc_info=True)
            break

        items = list_extractor(response) if list_extractor else []
        all_items.extend(items)

        # ALB 响应中 next_token 在 body 里
        new_token = getattr(response.body, "next_token", None)
        if not new_token or not items:
            break

        next_token = new_token

    return all_items


def model_to_dict(model: Any) -> dict:
    """将 SDK 2.0 模型对象转换为字典（用于 raw_json 存储）

    SDK 2.0 的模型对象有 to_map() 方法，可以转换为字典。
    """
    try:
        if hasattr(model, "to_map"):
            return model.to_map()
        # fallback: 尝试直接序列化
        return json.loads(json.dumps(model, default=str))
    except Exception:
        return {"_raw_error": "无法序列化模型对象"}
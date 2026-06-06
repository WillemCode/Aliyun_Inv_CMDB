"""API Collector — 收集传统 API 网关(CloudAPI) + 云原生 API 网关(APIG) + MSE Gateway"""

from typing import Any

from alibabacloud_cloudapi20160714 import models as cloudapi_models
from alibabacloud_apig20240327 import models as apig_models
from alibabacloud_mse20190531 import models as mse_models

from .base import BaseCollector
from ..aliyun_client import AliyunClientFactory, paginate_page_number, model_to_dict
from ..config import AccountConfig
from ..models import ApiGateway, ApigDomain, ApigApi, ApigRoute


class ApiCollector(BaseCollector):
    """API 网关收集器

    收集三种类型的 API 网关：
    1. 传统 API 网关 (CloudAPI) — DescribeApiGroups 按地域获取 API 分组
    2. 云原生 API 网关 (APIG) — ListGateways 获取云原生网关实例
    3. MSE Gateway (微服务引擎网关) — ListGateway 获取 MSE 网关实例
    """

    def collect(self) -> None:
        """收集 API 网关资源"""
        total_cloudapi = 0
        total_apig = 0
        total_mse = 0

        # 第一步：传统 API 网关（CloudAPI）— 需要按地域收集
        try:
            total_cloudapi = self._collect_cloudapi()
        except Exception as e:
            self.logger.warning("传统 API 网关收集失败", exc_info=True)

        # 第二步：云原生 API 网关（APIG）— 按地域收集
        try:
            total_apig = self._collect_apig_gateways()
        except Exception as e:
            self.logger.warning("云原生 API 网关收集失败", exc_info=True)

        # 第三步：MSE Gateway（微服务引擎网关）— 按地域收集
        try:
            total_mse = self._collect_mse_gateways()
        except Exception as e:
            self.logger.warning("MSE 网关收集失败", exc_info=True)

        self.session.commit()
        self.logger.info(
            "账号 %s API 同步完成: CloudAPI %d 个分组, APIG %d 个网关, MSE %d 个网关",
            self.account.display_name, total_cloudapi, total_apig, total_mse,
        )

    # ──────────────────────────────────────────────
    # 传统 API 网关 (CloudAPI)
    # ──────────────────────────────────────────────

    def _collect_cloudapi(self) -> int:
        """收集传统 API 网关的 API 分组"""
        # CloudAPI 需要按地域收集，常见地域
        api_regions = [
            "cn-hangzhou", "cn-shanghai", "cn-beijing", "cn-shenzhen",
            "cn-qingdao", "cn-chengdu", "cn-hongkong", "ap-southeast-1",
        ]

        # 也探测有 ECS 的地域
        ecs_regions = self.client_factory.discover_active_regions("ecs")
        all_regions = set(api_regions + ecs_regions)

        total = 0
        for region_id in all_regions:
            try:
                count = self._collect_cloudapi_region(region_id)
                if count > 0:
                    self.logger.info("地域 %s: %d 个 CloudAPI 分组", region_id, count)
                total += count
            except Exception:
                continue

        return total

    def _collect_cloudapi_region(self, region_id: str) -> int:
        """收集单个地域的 CloudAPI 分组"""
        try:
            client = self.client_factory.create_client("cloudapi", region_id)
        except Exception:
            return 0

        groups = paginate_page_number(
            client=client,
            method_name="describe_api_groups",
            request_class=cloudapi_models.DescribeApiGroupsRequest,
            page_size=50,
            list_extractor=lambda resp: (
                resp.body.api_group_attributes.api_group_attribute
                if resp.body.api_group_attributes else []
            ),
        )

        for group in groups:
            try:
                self._save_cloudapi_group(group, region_id)
            except Exception as e:
                self.logger.warning("保存 CloudAPI 分组 %s 失败: %s", group.group_name, e)
                continue

        self.session.commit()
        return len(groups)

    def _save_cloudapi_group(self, group: Any, region_id: str) -> None:
        """保存单个 CloudAPI 分组"""
        raw_dict = model_to_dict(group)

        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "api_type": "cloudapi",
            "group_id": group.group_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "group_name": group.group_name or "",
            "description": group.description or "",
            "base_path": group.base_path or "",
            "sub_domain": group.sub_domain or "",
            "status": group.billing_status or group.illegal_status or "",
            "instance_id": group.instance_id or "",
            "vpc_id": "",
            "raw_json": raw_dict,
        }
        self.upsert(ApiGateway, unique_keys, values)

        # 写入 resources_raw
        self.save_raw(
            resource_type="api_cloudapi",
            region_id=region_id,
            resource_id=group.group_id,
            resource_name=group.group_name,
            raw_json=raw_dict,
            source_api="DescribeApiGroups",
        )

    # ──────────────────────────────────────────────
    # 云原生 API 网关 (APIG)
    # ──────────────────────────────────────────────

    def _collect_apig_gateways(self) -> int:
        """收集云原生 API 网关实例"""
        apig_regions = [
            "cn-hangzhou", "cn-beijing", "cn-shanghai", "cn-shenzhen",
            "cn-chengdu", "cn-hongkong", "ap-southeast-1",
        ]

        # 也探测有 ECS 的地域
        ecs_regions = self.client_factory.discover_active_regions("ecs")
        all_regions = set(apig_regions + ecs_regions)

        total = 0
        for region_id in all_regions:
            try:
                count = self._collect_apig_region(region_id)
                if count > 0:
                    self.logger.info("地域 %s: %d 个 APIG 网关", region_id, count)
                total += count
            except Exception:
                continue

        return total

    def _collect_apig_region(self, region_id: str) -> int:
        """收集单个地域的 APIG 网关实例"""
        try:
            client = self.client_factory.create_client("apig", region_id)
        except Exception:
            return 0

        # APIG ListGateways 使用分页
        all_gateways = []
        page_number = 1
        page_size = 50

        while True:
            try:
                req = apig_models.ListGatewaysRequest(
                    page_number=page_number,
                    page_size=page_size,
                )
                resp = client.list_gateways(req)
                data = resp.body.data
                items = data.items or [] if data else []
                all_gateways.extend(items)

                total_size = data.total_size or 0 if data else 0
                if len(all_gateways) >= total_size or not items:
                    break
                page_number += 1
            except Exception as e:
                self.logger.warning("APIG ListGateways 地域 %s 失败", region_id, exc_info=True)
                break

        for gw in all_gateways:
            try:
                self._save_apig_gateway(gw, region_id, client)
            except Exception as e:
                gw_name = getattr(gw, "name", "") or getattr(gw, "gateway_id", "")
                self.logger.warning("保存 APIG 网关 %s 失败: %s", gw_name, e)
                continue

        self.session.commit()
        return len(all_gateways)

    def _save_apig_gateway(self, gw: Any, region_id: str, client: Any) -> None:
        """保存单个云原生 API 网关实例"""
        raw_dict = model_to_dict(gw)

        # APIG SDK 字段名注意：name (不是 gateway_name), vpc (不是 vpc_id)
        gateway_id = gw.gateway_id or ""
        gateway_name = gw.name or ""
        gateway_edition = gw.gateway_edition or ""
        gateway_type = gw.gateway_type or ""
        status = gw.status or ""
        # gw.vpc 是 SDK 对象（ListGatewaysResponseBodyDataItemsVpc），需要提取 vpcId
        vpc_obj = getattr(gw, "vpc", None)
        if vpc_obj and hasattr(vpc_obj, "vpc_id"):
            vpc_id = vpc_obj.vpc_id or ""
        elif vpc_obj and isinstance(vpc_obj, dict):
            vpc_id = vpc_obj.get("vpcId", vpc_obj.get("vpc_id", ""))
        else:
            vpc_id = str(vpc_obj) if vpc_obj else ""

        # 从 sub_domain_infos 提取公网/内网接入域名（而不是 NLB 地址）
        sub_domain_infos = gw.sub_domain_infos or []
        sub_domains_internet = []
        sub_domains_intranet = []
        for sdi in sub_domain_infos:
            sdi_network = getattr(sdi, "network_type", "") or ""
            sdi_name = getattr(sdi, "name", "") or ""
            if sdi_network == "Internet":
                sub_domains_internet.append(sdi_name)
            elif sdi_network == "Intranet":
                sub_domains_intranet.append(sdi_name)
        sub_domain = ", ".join(sub_domains_internet) if sub_domains_internet else ""

        # 写入 ApiGateway 表
        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "api_type": "apig",
            "group_id": gateway_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "group_name": gateway_name,
            "description": gateway_edition,
            "base_path": "",
            "sub_domain": sub_domain,
            "status": status,
            "instance_id": gateway_edition,
            "vpc_id": vpc_id,
            "raw_json": raw_dict,
        }
        self.upsert(ApiGateway, unique_keys, values)

        # 写入 resources_raw
        self.save_raw(
            resource_type="api_apig",
            region_id=region_id,
            resource_id=gateway_id,
            resource_name=gateway_name,
            raw_json=raw_dict,
            source_api="ListGateways",
        )

        # 写入 ip_addresses 表 — 公网 NLB IPv4 地址
        load_balancers = gw.load_balancers or []
        for lb in load_balancers:
            if lb.address_type == "Internet":
                ipv4_list = getattr(lb, "ipv_4addresses", []) or []
                for ip in ipv4_list:
                    self.upsert_ip(
                        resource_type="apig",
                        resource_id=gateway_id,
                        resource_name=gateway_name,
                        ip=ip,
                        ip_type="apig_public",
                        region_id=region_id,
                    )
            elif lb.address_type == "Intranet":
                # 内网地址也写入
                intranet_ips = getattr(lb, "ipv_4addresses", []) or []
                for ip in intranet_ips:
                    self.upsert_ip(
                        resource_type="apig",
                        resource_id=gateway_id,
                        resource_name=gateway_name,
                        ip=ip,
                        ip_type="apig_private",
                        region_id=region_id,
                    )

        # 收集子资源：域名、API、路由
        try:
            self._collect_apig_domains(gw, gateway_id, gateway_name, region_id, client)
        except Exception as e:
            self.session.rollback()
            self.logger.warning("获取 APIG %s 域名失败: %s", gateway_id, e)

        try:
            self._collect_apig_apis(gw, gateway_id, gateway_name, region_id, client)
        except Exception as e:
            self.session.rollback()
            self.logger.warning("获取 APIG %s API/路由失败: %s", gateway_id, e)

    def _collect_apig_domains(
        self, gw: Any, gateway_id: str, gateway_name: str, region_id: str, client: Any,
    ) -> None:
        """收集 APIG 网关的域名（接入域名 + 自定义绑定域名）"""
        # 1. 保存接入域名 (sub_domain_infos) 为 "default" 类型
        sub_domain_infos = gw.sub_domain_infos or []
        for idx, sdi in enumerate(sub_domain_infos):
            sdi_name = getattr(sdi, "name", "") or ""
            sdi_network = getattr(sdi, "network_type", "") or ""
            sdi_protocol = getattr(sdi, "protocol", "") or ""
            if not sdi_name:
                continue
            # 接入域名没有 domain_id，用 gateway_id + 索引生成唯一 ID
            sdi_id = f"{gateway_id}-sdi-{idx}"
            self.upsert(ApigDomain, {
                "account_name": self.account.name,
                "region_id": region_id,
                "gateway_id": gateway_id,
                "domain_id": sdi_id,
            }, {
                "account_display_name": self.account.display_name,
                "domain_name": sdi_name,
                "domain_type": "default",
                "network_type": sdi_network,
                "protocol": sdi_protocol,
                "cert_identifier": "",
                "force_https": None,
                "status": "",
                "raw_json": model_to_dict(sdi),
            })

        # 2. 保存自定义绑定域名 (ListDomains) 为 "custom" 类型
        try:
            domains = paginate_page_number(
                client=client,
                method_name="list_domains",
                request_class=apig_models.ListDomainsRequest,
                extra_params={"gateway_id": gateway_id},
                page_size=50,
                list_extractor=lambda resp: resp.body.data.items or [],
            )
        except Exception as e:
            self.logger.warning("APIG ListDomains %s 失败: %s", gateway_id, e)
            return

        for dm in domains:
            dm_id = dm.domain_id or ""
            dm_name = dm.name or ""
            dm_protocol = getattr(dm, "protocol", "") or ""
            dm_status = getattr(dm, "status", "") or ""
            dm_cert = getattr(dm, "cert_identifier", "") or ""
            dm_force_https = getattr(dm, "force_https", None)

            self.upsert(ApigDomain, {
                "account_name": self.account.name,
                "region_id": region_id,
                "gateway_id": gateway_id,
                "domain_id": dm_id,
            }, {
                "account_display_name": self.account.display_name,
                "domain_name": dm_name,
                "domain_type": "custom",
                "network_type": "",
                "protocol": dm_protocol,
                "cert_identifier": dm_cert,
                "force_https": dm_force_https,
                "status": dm_status,
                "raw_json": model_to_dict(dm),
            })

            self.save_raw(
                resource_type="apig_domain",
                region_id=region_id,
                resource_id=dm_id,
                resource_name=dm_name,
                raw_json=model_to_dict(dm),
                source_api="ListDomains",
            )

    def _collect_apig_apis(
        self, gw: Any, gateway_id: str, gateway_name: str, region_id: str, client: Any,
    ) -> None:
        """收集 APIG 网关下的 API 和路由"""
        try:
            apis = paginate_page_number(
                client=client,
                method_name="list_http_apis",
                request_class=apig_models.ListHttpApisRequest,
                extra_params={"gateway_id": gateway_id},
                page_size=50,
                list_extractor=lambda resp: resp.body.data.items or [],
            )
        except Exception as e:
            self.logger.warning("APIG ListHttpApis %s 失败: %s", gateway_id, e)
            return

        for api_item in apis:
            # ListHttpApis 返回 HttpApiInfoByName，其中 versioned_http_apis 包含详细信息
            versions = getattr(api_item, "versioned_http_apis", None) or []
            if not versions:
                continue

            # 使用第一个版本的信息
            v = versions[0]
            http_api_id = getattr(v, "http_api_id", "") or ""
            api_name = getattr(v, "name", "") or getattr(api_item, "name", "") or ""
            api_type = getattr(v, "type", "") or getattr(api_item, "type", "") or ""
            api_base_path = getattr(v, "base_path", "") or ""
            api_description = getattr(v, "description", "") or ""

            if not http_api_id:
                continue

            self.upsert(ApigApi, {
                "account_name": self.account.name,
                "region_id": region_id,
                "gateway_id": gateway_id,
                "api_id": http_api_id,
            }, {
                "account_display_name": self.account.display_name,
                "api_name": api_name,
                "api_type": api_type,
                "base_path": api_base_path,
                "description": api_description,
                "raw_json": model_to_dict(v),
            })

            self.save_raw(
                resource_type="apig_api",
                region_id=region_id,
                resource_id=http_api_id,
                resource_name=api_name,
                raw_json=model_to_dict(v),
                source_api="ListHttpApis",
            )

            # 收集该 API 下的路由
            try:
                self._collect_apig_routes(
                    http_api_id, api_name, gateway_id, gateway_name, region_id, client,
                )
            except Exception as e:
                self.logger.warning("获取 API %s 路由失败: %s", api_name, e)

    def _collect_apig_routes(
        self,
        http_api_id: str,
        api_name: str,
        gateway_id: str,
        gateway_name: str,
        region_id: str,
        client: Any,
    ) -> None:
        """收集单个 API 下的路由"""
        # ListHttpApiRoutes 需要 http_api_id 作为路径参数，不能用 paginate_page_number
        all_routes = []
        page_number = 1
        page_size = 50

        while True:
            try:
                req = apig_models.ListHttpApiRoutesRequest(
                    gateway_id=gateway_id,
                    page_number=page_number,
                    page_size=page_size,
                )
                resp = client.list_http_api_routes(http_api_id, req)
                data = resp.body.data
                items = data.items or [] if data else []
                all_routes.extend(items)

                total_size = data.total_size or 0 if data else 0
                if len(all_routes) >= total_size or not items:
                    break
                page_number += 1
            except Exception as e:
                self.logger.warning("APIG ListHttpApiRoutes %s 失败: %s", http_api_id, e)
                break

        for route in all_routes:
            try:
                route_id = getattr(route, "route_id", "") or ""
                route_name = getattr(route, "name", "") or ""
                route_description = getattr(route, "description", "") or ""
                deploy_status = getattr(route, "deploy_status", "") or ""

                # 提取路径匹配信息
                match_info = getattr(route, "match", None)
                path_value = ""
                path_type = ""
                methods_list = []
                if match_info:
                    path_obj = getattr(match_info, "path", None)
                    if path_obj:
                        path_value = getattr(path_obj, "value", "") or ""
                        path_type = getattr(path_obj, "type", "") or ""
                    methods_list = list(getattr(match_info, "methods", None) or [])

                # 提取绑定域名列表
                domain_infos = getattr(route, "domain_infos", None) or []
                domain_names_list = [
                    getattr(di, "name", "") for di in domain_infos if getattr(di, "name", "")
                ]
                domain_names_str = ", ".join(domain_names_list)

                self.upsert(ApigRoute, {
                    "account_name": self.account.name,
                    "region_id": region_id,
                    "gateway_id": gateway_id,
                    "api_id": http_api_id,
                    "route_id": route_id,
                }, {
                    "account_display_name": self.account.display_name,
                    "route_name": route_name,
                    "path": path_value,
                    "path_type": path_type,
                    "methods": methods_list,
                    "domain_names": domain_names_str,
                    "description": route_description,
                    "deploy_status": deploy_status,
                    "raw_json": model_to_dict(route),
                })

                self.save_raw(
                    resource_type="apig_route",
                    region_id=region_id,
                    resource_id=route_id,
                    resource_name=route_name,
                    raw_json=model_to_dict(route),
                    source_api="ListHttpApiRoutes",
                )
            except Exception as e:
                self.logger.warning("保存 APIG 路由 %s 失败: %s", getattr(route, "route_id", "?"), e)
                continue
    # ──────────────────────────────────────────────

    def _collect_mse_gateways(self) -> int:
        """收集 MSE 微服务引擎网关实例"""
        mse_regions = [
            "cn-hangzhou", "cn-shanghai", "cn-beijing", "cn-shenzhen",
            "cn-chengdu", "cn-hongkong", "ap-southeast-1",
        ]

        # 也探测有 ECS 的地域
        ecs_regions = self.client_factory.discover_active_regions("ecs")
        all_regions = set(mse_regions + ecs_regions)

        total = 0
        for region_id in all_regions:
            try:
                count = self._collect_mse_region(region_id)
                if count > 0:
                    self.logger.info("地域 %s: %d 个 MSE 网关", region_id, count)
                total += count
            except Exception:
                continue

        return total

    def _collect_mse_region(self, region_id: str) -> int:
        """收集单个地域的 MSE 网关实例"""
        try:
            client = self.client_factory.create_client("mse", region_id)
        except Exception:
            return 0

        # ListGateway 分页获取
        all_gateways = []
        page_number = 1
        page_size = 50

        while True:
            try:
                request = mse_models.ListGatewayRequest(
                    page_number=page_number,
                    page_size=page_size,
                )
                response = client.list_gateway(request)
                result = response.body.data.result if response.body.data else []
                all_gateways.extend(result)

                total_size = response.body.data.total_size or 0
                if len(all_gateways) >= total_size or not result:
                    break
                page_number += 1
            except Exception as e:
                self.logger.warning("MSE ListGateway 地域 %s 失败", region_id, exc_info=True)
                break

        for gateway in all_gateways:
            try:
                self._save_mse_gateway(gateway, region_id)
            except Exception as e:
                self.logger.warning("保存 MSE 网关 %s 失败: %s", gateway.name, e)
                continue

        self.session.commit()
        return len(all_gateways)

    def _save_mse_gateway(self, gateway: Any, region_id: str) -> None:
        """保存单个 MSE 网关实例"""
        raw_dict = model_to_dict(gateway)

        gateway_unique_id = gateway.gateway_unique_id or ""
        gateway_name = gateway.name or ""

        unique_keys = {
            "account_name": self.account.name,
            "region_id": region_id,
            "api_type": "mse_gateway",
            "group_id": gateway_unique_id,
        }
        values = {
            **unique_keys,
            "account_display_name": self.account.display_name,
            "group_name": gateway_name,
            "description": "",
            "base_path": "",
            "sub_domain": gateway.gateway_entry or "",
            "status": gateway.status_desc or gateway.status or "",
            "instance_id": gateway.instance_id or "",
            "vpc_id": gateway.vpc_id or "",
            "raw_json": raw_dict,
        }
        self.upsert(ApiGateway, unique_keys, values)

        # 写入 resources_raw
        self.save_raw(
            resource_type="api_mse",
            region_id=region_id,
            resource_id=gateway_unique_id,
            resource_name=gateway_name,
            raw_json=raw_dict,
            source_api="ListGateway",
        )
# -*- coding: utf-8 -*-
# OCI管理工具 - 终极完整版 (v16.8 - 路径回退 + 导入导出功能)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinter.font as tkfont
from datetime import datetime, timezone
import oci
from oci.core.models import (CreateVcnDetails, CreateSubnetDetails, CreateInternetGatewayDetails,
                             UpdateRouteTableDetails, RouteRule, CreatePublicIpDetails, CreateIpv6Details,
                             LaunchInstanceDetails, CreateVnicDetails, InstanceSourceViaImageDetails,
                             LaunchInstanceShapeConfigDetails, UpdateSecurityListDetails, EgressSecurityRule,
                             IngressSecurityRule,
                             UpdateInstanceDetails, UpdateBootVolumeDetails, UpdateInstanceShapeConfigDetails,
                             AddVcnIpv6CidrDetails, UpdateSubnetDetails, GetPublicIpByPrivateIpIdDetails)
from oci.exceptions import ServiceError
import os
import sys
import time
import threading
import json
import secrets
import string
import base64
import logging
import tempfile
import requests
import re
from pypinyin import lazy_pinyin

# --- 路径设置：回归 ~/.oci_manager_config (最稳妥方案) ---
USER_HOME = os.path.expanduser("~")
CONFIG_DIR = os.path.join(USER_HOME, ".oci_manager_config")

# 确保目录存在
if not os.path.exists(CONFIG_DIR):
    try:
        os.makedirs(CONFIG_DIR)
    except Exception:
        pass

    # --- 文件路径定义 ---
PROFILES_FILENAME = "oci_profiles.json"
SETTINGS_FILENAME = "oci_gui_settings.json"
LOG_FILENAME = "oci_gui_manager.log"
CLOUDFLARE_CONFIG_FILENAME = "cloudflare_settings.json"

PROFILES_FILE_PATH = os.path.join(CONFIG_DIR, PROFILES_FILENAME)
SETTINGS_FILE_PATH = os.path.join(CONFIG_DIR, SETTINGS_FILENAME)
LOG_FILE_PATH = os.path.join(CONFIG_DIR, LOG_FILENAME)
CLOUDFLARE_CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, CLOUDFLARE_CONFIG_FILENAME)

# --- 默认SSH公钥 ---
DEFAULT_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDuxGi8wfpz+Us1flHLhTFErH0MkejwK68vMomuW1toccSBTl0VK/aTV7zn2KB6B0rWc6cZoK6m02ZW8dieTa4x0CBDl7FxlyqJhOlfyIWJ7/qh3NlEFJ5l/17KeugUYSJxck9rKMsyZgjrPoWQub48CQLFgqxwDNUavAGeJIkxELDTIxPJQNpZOBrAGcQeWNAfwznwOME7lbXPQhPlI26O7gFRA1+9zekwxy3x8/axrr9ygzOLAMgGsK3tM/NF4QHTivrH8Gj8QpkSEVTTEIE2SV2varAgzP3vwwogQ7OSiIW5rr2pdkX9/ZTcVaV9qEDL+GOhcOCkDMbqsF/d/7vt ssh-key-2025-09-27"

# --- 日志设置 ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='a')


# --- 辅助函数 ---
def center_window(window):
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    parent = window.master
    x = parent.winfo_x() + (parent.winfo_width() // 2) - (width // 2)
    y = parent.winfo_y() + (parent.winfo_height() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')
    window.deiconify()


def get_user_data(password, startup_script=None):
    default_script = """
echo "Waiting for apt lock to be released..."
while fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1 ; do
   echo "Another apt/dpkg process is running. Waiting 10 seconds..."
   sleep 10
done

echo "Starting package installation with retries..."
for i in 1 2 3; do
  apt-get update && apt-get install -y curl wget unzip git socat cron && break
  echo "APT commands failed (attempt $i/3), retrying in 15 seconds..."
  sleep 15
done
"""
    script_parts = [
        "#cloud-config",
        "chpasswd:",
        "  expire: False",
        "  list:",
        f"    - ubuntu:{password}",
        "runcmd:",
        "  - \"sed -i -e '/^#*PasswordAuthentication/s/^.*$/PasswordAuthentication yes/' /etc/ssh/sshd_config\"",
        "  - 'rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf'",
        "  - \"sed -i -e '/^#*PermitRootLogin/s/^.*$/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config\"",
        f"  - [ bash, -c, {json.dumps(default_script)} ]",
    ]
    if startup_script and startup_script.strip():
        script_parts.append(f"  - [ bash, -c, {json.dumps(startup_script.strip())} ]")
    script_parts.append("  - systemctl restart sshd || service sshd restart || service ssh restart")
    script = "\n".join(script_parts)
    return base64.b64encode(script.encode('utf-8')).decode('utf-8')


def load_cloudflare_config():
    if not os.path.exists(CLOUDFLARE_CONFIG_FILE_PATH):
        return {}
    try:
        with open(CLOUDFLARE_CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}


def save_cloudflare_config(config):
    try:
        with open(CLOUDFLARE_CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
        logging.info(f"Cloudflare config saved to {CLOUDFLARE_CONFIG_FILE_PATH}")
    except Exception as e:
        logging.error(f"Failed to save Cloudflare config: {e}")


def _update_cloudflare_dns(subdomain, ip_address, record_type='A', logger=None):
    if logger is None:
        logger = logging.getLogger(__name__)

    cf_config = load_cloudflare_config()
    api_token = cf_config.get('api_token')
    zone_id = cf_config.get('zone_id')
    domain = cf_config.get('domain')

    if not all([api_token, zone_id, domain]):
        msg = "Cloudflare 未配置，跳过 DNS 更新。"
        logger.warning(msg)
        return msg

    full_domain = f"{subdomain}.{domain}"
    api_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    try:
        search_params = {'type': record_type, 'name': full_domain}
        response = requests.get(api_url, headers=headers, params=search_params, timeout=15)
        response.raise_for_status()
        search_result = response.json()

        dns_payload = {
            'type': record_type,
            'name': full_domain,
            'content': ip_address,
            'ttl': 60,
            'proxied': False
        }

        if search_result['result']:
            record_id = search_result['result'][0]['id']
            update_url = f"{api_url}/{record_id}"
            response = requests.put(update_url, headers=headers, json=dns_payload, timeout=15)
            action_log = "更新"
        else:
            response = requests.post(api_url, headers=headers, json=dns_payload, timeout=15)
            action_log = "创建"

        response.raise_for_status()
        result_data = response.json()

        if result_data['success']:
            msg = f"✅ 成功 {action_log} Cloudflare DNS 记录: {full_domain} -> {ip_address}"
            logger.info(msg)
            return msg
        else:
            errors = result_data.get('errors', [{'message': '未知错误'}])
            error_msg = ', '.join([e['message'] for e in errors])
            msg = f"❌ {action_log} Cloudflare DNS 记录失败: {error_msg}"
            logger.error(msg)
            return msg

    except requests.RequestException as e:
        msg = f"❌ 更新 Cloudflare DNS 时发生网络错误: {e}"
        logger.error(msg)
        return msg
    except Exception as e:
        msg = f"❌ 更新 Cloudflare DNS 时发生未知错误: {e}"
        logger.error(msg)
        return msg


# --- 后端OCI操作 ---
def get_detailed_instances(compute_client, virtual_network_client, block_storage_client, compartment_id, logger):
    instance_list_for_gui = []
    logger.info(f"开始获取区间 {compartment_id} 中的实例详情...")
    try:
        instances = oci.pagination.list_call_get_all_results(compute_client.list_instances,
                                                             compartment_id=compartment_id).data
        if not instances: return [], "在指定区间未找到实例。"
        for instance in instances:
            duration_str = "N/A"
            if instance.time_created:
                try:
                    diff = datetime.now(timezone.utc) - instance.time_created
                    duration_str = f"{diff.days}天 {diff.seconds // 3600}小时"
                except:
                    pass

            instance_data = {"display_name": instance.display_name, "id": instance.id,
                             "lifecycle_state": instance.lifecycle_state, "region": instance.region,
                             "availability_domain": instance.availability_domain, "shape": instance.shape,
                             "time_created": instance.time_created.strftime(
                                 '%Y-%m-%d %H:%M:%S') if instance.time_created else "N/A",
                             "duration": duration_str,
                             "ocpus": instance.shape_config.ocpus if instance.shape_config else "N/A",
                             "memory_in_gbs": instance.shape_config.memory_in_gbs if instance.shape_config else "N/A",
                             "private_ip": "获取中...", "public_ip": "获取中...", "ipv6_address": "获取中...",
                             "vnic_id": None, "subnet_id": None, "boot_volume_id": None,
                             "boot_volume_size_gb": "获取中...", "vpus_per_gb": "N/A",
                             "compartment_id": instance.compartment_id, "freeform_tags": instance.freeform_tags or {},
                             "defined_tags": instance.defined_tags or {}}
            try:
                if instance.lifecycle_state not in ['TERMINATED', 'TERMINATING']:
                    vnic_attachments = oci.pagination.list_call_get_all_results(compute_client.list_vnic_attachments,
                                                                                compartment_id=instance.compartment_id,
                                                                                instance_id=instance.id).data
                    if vnic_attachments:
                        primary_vnic_attachment = vnic_attachments[0]
                        instance_data["vnic_id"] = primary_vnic_attachment.vnic_id
                        instance_data["subnet_id"] = primary_vnic_attachment.subnet_id
                        try:
                            vnic_details = virtual_network_client.get_vnic(vnic_id=instance_data["vnic_id"]).data
                            instance_data["private_ip"] = vnic_details.private_ip or "N/A";
                            instance_data["public_ip"] = vnic_details.public_ip or "N/A (或未分配)"
                        except ServiceError as vnic_err:
                            if vnic_err.status != 404: logger.error(f"  - 获取VNIC详情 (IPv4) 错误: {vnic_err}")
                        instance_data["ipv6_address"] = "无"
                        try:
                            list_ipv6_response = virtual_network_client.list_ipv6s(vnic_id=instance_data["vnic_id"])
                            if list_ipv6_response.data: instance_data["ipv6_address"] = list_ipv6_response.data[
                                                                                            0].ip_address or "获取到空值"
                        except ServiceError as ipv6_err:
                            if ipv6_err.status != 404: logger.error(f"  - 获取IPv6列表错误: {ipv6_err}")
                    boot_vol_attachments = oci.pagination.list_call_get_all_results(
                        compute_client.list_boot_volume_attachments, availability_domain=instance.availability_domain,
                        compartment_id=instance.compartment_id, instance_id=instance.id).data
                    if boot_vol_attachments:
                        boot_volume_id = boot_vol_attachments[0].boot_volume_id;
                        instance_data["boot_volume_id"] = boot_volume_id;
                        boot_vol = block_storage_client.get_boot_volume(boot_volume_id=boot_volume_id).data;
                        instance_data["boot_volume_size_gb"] = f"{int(boot_vol.size_in_gbs)}";
                        instance_data["vpus_per_gb"] = boot_vol.vpus_per_gb
            except ServiceError as se:
                if se.status == 404:
                    logger.warning(f"获取实例 {instance.display_name} 的详情时资源未找到 (可能正在终止)。")
                else:
                    logger.error(f"获取实例 {instance.display_name} 详情时发生ServiceError: {se}")
            except Exception as e:
                logger.exception(f"为实例获取网络/卷详情时出错: {e}")
            instance_list_for_gui.append(instance_data)
        logger.info(f"成功加载 {len(instance_list_for_gui)} 个实例的详情。")
        return instance_list_for_gui, f"成功加载 {len(instance_list_for_gui)} 个实例。"
    except Exception as e:
        error_msg = f"列出实例时发生错误: {e}";
        logger.exception(error_msg);
        return [], error_msg


def backend_instance_action(compute_client, instance_id, action, logger):
    action_upper = action.upper()
    logger.info(f"发送实例操作 '{action_upper}' 到实例 {instance_id}...")

    action_map = {
        "START": ("START", "RUNNING"),
        "STOP": ("STOP", "STOPPED"),
        "SOFTRESET": ("SOFTRESET", "RUNNING")
    }

    if action_upper not in action_map:
        return False, f"未知的内部操作: {action_upper}"

    oci_action, target_state = action_map[action_upper]

    try:
        compute_client.instance_action(instance_id=instance_id, action=oci_action)
        logger.info(f"命令 '{oci_action}' 已发送, 等待实例进入 '{target_state}' 状态...")
        waiter_result = oci.wait_until(
            compute_client,
            compute_client.get_instance(instance_id),
            'lifecycle_state',
            target_state,
            max_wait_seconds=400,
            succeed_on_not_found=False
        )
        logger.info(f"实例 {instance_id} 已成功进入 '{waiter_result.data.lifecycle_state}' 状态。")
        return True, f"实例已成功完成 '{action_upper}' 操作！"
    except oci.exceptions.Waiters.TimeoutError:
        logger.error(f"等待实例进入 '{target_state}' 状态超时。")
        return False, f"操作超时：实例未能在规定时间内进入 '{target_state}' 状态。"
    except Exception as e:
        logger.error(f"实例操作 '{action_upper}' 失败: {e}", exc_info=True)
        return False, f"实例操作失败: {e}"


def backend_start_instance(compute_client, instance_id, logger):
    return backend_instance_action(compute_client, instance_id, "START", logger)


def backend_stop_instance(compute_client, instance_id, logger):
    return backend_instance_action(compute_client, instance_id, "STOP", logger)


def backend_restart_instance(compute_client, instance_id, logger):
    return backend_instance_action(compute_client, instance_id, "SOFTRESET", logger)


def backend_terminate_instance(compute_client, instance_id, preserve_boot_volume, logger):
    logger.warning(f"发送终止命令到实例 {instance_id} (保留启动卷: {preserve_boot_volume})...")
    try:
        compute_client.terminate_instance(instance_id=instance_id,
                                          preserve_boot_volume=preserve_boot_volume);
        logger.info("终止命令已发送，等待实例进入 TERMINATED 状态...")
        oci.wait_until(
            compute_client,
            compute_client.get_instance(instance_id),
            'lifecycle_state',
            'TERMINATED',
            max_wait_seconds=300,
            succeed_on_not_found=True
        )
        return True, "实例已成功终止。"
    except oci.exceptions.Waiters.TimeoutError:
        logger.error("等待实例进入 'TERMINATED' 状态超时。")
        return False, "终止操作超时。"
    except Exception as e:
        if isinstance(e, ServiceError) and e.status == 404:
            return True, "实例已成功终止。"
        logger.error(f"终止实例失败: {e}", exc_info=True)
        return False, f"终止失败: {e}"


def backend_change_public_ip(vnet_client, compute_client, instance_id, compartment_id, logger):
    logger.info(f"开始为实例 {instance_id} 更换公网IP...")
    try:
        instance = compute_client.get_instance(instance_id).data
        if instance.lifecycle_state != 'RUNNING':
            return False, "错误：更换IP需要实例处于“正在运行(RUNNING)”状态。"

        instance_name = instance.display_name

        vnic_attachments = oci.pagination.list_call_get_all_results(
            compute_client.list_vnic_attachments,
            compartment_id=compartment_id,
            instance_id=instance_id
        ).data
        if not vnic_attachments:
            raise Exception("找不到实例的网络接口卡(VNIC)。")
        vnic_id = vnic_attachments[0].vnic_id
        logger.info(f"找到 VNIC ID: {vnic_id}")

        private_ips = oci.pagination.list_call_get_all_results(vnet_client.list_private_ips, vnic_id=vnic_id).data
        primary_private_ip = next((p for p in private_ips if p.is_primary), None)
        if not primary_private_ip:
            raise Exception("在VNIC上未找到主私有IP。")
        logger.info(f"找到主私有IP ID: {primary_private_ip.id}")

        try:
            pub_ip_details = GetPublicIpByPrivateIpIdDetails(private_ip_id=primary_private_ip.id)
            existing_pub_ip = vnet_client.get_public_ip_by_private_ip_id(pub_ip_details).data

            if existing_pub_ip.lifetime == "EPHEMERAL":
                logger.info(f"正在删除旧的临时公网IP: {existing_pub_ip.ip_address}")
                vnet_client.delete_public_ip(existing_pub_ip.id)
                time.sleep(5)
            else:
                return False, f"无法更换IP：当前公网IP ({existing_pub_ip.ip_address}) 是一个保留IP，无法自动删除。"
        except ServiceError as e:
            if e.status == 404:
                logger.info("实例当前没有绑定公网IP，将直接创建新的。")
            else:
                raise

        logger.info("正在创建新的临时公网IP...")
        new_pub_ip_details = CreatePublicIpDetails(
            compartment_id=compartment_id,
            lifetime="EPHEMERAL",
            private_ip_id=primary_private_ip.id
        )
        new_pub_ip = vnet_client.create_public_ip(new_pub_ip_details).data
        logger.info(f"成功创建新IP: {new_pub_ip.ip_address}")

        dns_update_msg = _update_cloudflare_dns(instance_name, new_pub_ip.ip_address, 'A', logger)

        final_message = f"✅ 更换IP成功，新IP: {new_pub_ip.ip_address}\n{dns_update_msg}"
        return True, final_message

    except Exception as e:
        logger.error(f"更换IP失败: {e}", exc_info=True)
        return False, f"❌ 更换IP失败: {e}"


def backend_full_ipv6_setup_and_assign(vnet_client, vnic_id, instance_name, log_ui_callback, logger):
    try:
        logger.info(f"开始为 VNIC {vnic_id} 执行全自动 IPv6 配置流程...");
        log_ui_callback("步骤 1/5: 正在获取网络资源...", 'INFO');
        vnic = vnet_client.get_vnic(vnic_id).data;
        subnet = vnet_client.get_subnet(vnic.subnet_id).data;
        vcn = vnet_client.get_vcn(subnet.vcn_id).data
        if not vcn.ipv6_cidr_blocks: log_ui_callback("步骤 2/5: VCN 未开启IPv6，正在自动开启...",
                                                     'INFO'); details = AddVcnIpv6CidrDetails(
            is_oracle_gua_allocation_enabled=True); vnet_client.add_ipv6_vcn_cidr(vcn_id=vcn.id,
                                                                                  add_vcn_ipv6_cidr_details=details); oci.wait_until(
            vnet_client, vnet_client.get_vcn(vcn.id), 'lifecycle_state', 'AVAILABLE',
            max_wait_seconds=300); vcn = vnet_client.get_vcn(vcn.id).data; logger.info(
            f"VCN {vcn.id} 已成功开启IPv6: {vcn.ipv6_cidr_blocks}")
        if not subnet.ipv6_cidr_block: log_ui_callback("步骤 3/5: 子网未分配IPv6地址段，正在自动分配...",
                                                       'INFO'); vcn_ipv6_cidr = vcn.ipv6_cidr_blocks[
            0]; subnet_ipv6_cidr = vcn_ipv6_cidr.replace('/56', '/64'); details = UpdateSubnetDetails(
            ipv6_cidr_block=subnet_ipv6_cidr); vnet_client.update_subnet(subnet.id, details); oci.wait_until(
            vnet_client, vnet_client.get_subnet(subnet.id), 'lifecycle_state', 'AVAILABLE',
            max_wait_seconds=300); logger.info(f"子网 {subnet.id} 已成功分配IPv6: {subnet_ipv6_cidr}")
        log_ui_callback("步骤 4/5: 正在检查并更新路由表与安全规则...", 'INFO');
        route_table = vnet_client.get_route_table(vcn.default_route_table_id).data;
        igws = oci.pagination.list_call_get_all_results(vnet_client.list_internet_gateways,
                                                        compartment_id=vcn.compartment_id, vcn_id=vcn.id).data
        if not igws: raise Exception("未找到互联网网关。")
        igw_id = igws[0].id
        if not any(rule.destination == '::/0' for rule in route_table.route_rules): new_rules = list(
            route_table.route_rules); new_rules.append(
            oci.core.models.RouteRule(destination='::/0', network_entity_id=igw_id)); vnet_client.update_route_table(
            route_table.id, UpdateRouteTableDetails(route_rules=new_rules)); logger.info(
            f"已为路由表 {route_table.id} 添加IPv6默认路由。")
        security_list = vnet_client.get_security_list(vcn.default_security_list_id).data
        if not any(rule.destination == '::/0' for rule in security_list.egress_security_rules): new_egress_rules = list(
            security_list.egress_security_rules); new_egress_rules.append(
            oci.core.models.EgressSecurityRule(destination='::/0', protocol='all')); vnet_client.update_security_list(
            security_list.id,
            oci.core.models.UpdateSecurityListDetails(egress_security_rules=new_egress_rules)); logger.info(
            f"已为安全列表 {security_list.id} 添加出站IPv6规则。")
        log_ui_callback("步骤 5/5: 网络配置完成，正在分配IPv6地址...", 'INFO');
        new_ipv6 = vnet_client.create_ipv6(oci.core.models.CreateIpv6Details(vnic_id=vnic_id)).data;

        dns_update_msg = _update_cloudflare_dns(instance_name, new_ipv6.ip_address, 'AAAA', logger)

        msg = f"✅ 已成功分配IPv6地址: {new_ipv6.ip_address}\n{dns_update_msg}";
        logger.info(msg);
        return True, msg
    except Exception as e:
        error_msg = f"一键开启并分配 IPv6 失败: {e}";
        logger.exception(error_msg);
        return False, error_msg


def backend_open_firewall_full(vnet_client, subnet_id, logger, log_ui_callback):
    try:
        log_ui_callback("步骤 1/3: 正在获取子网和安全列表信息...", "INFO")
        if not subnet_id: return False, "无法确定子网，请确保账号配置了默认子网或选中了实例。"
        subnet = vnet_client.get_subnet(subnet_id).data
        if not subnet.security_list_ids: return False, "子网没有关联任何安全列表。"
        security_list_id = subnet.security_list_ids[0];
        security_list = vnet_client.get_security_list(security_list_id).data;
        log_ui_callback(f"步骤 2/3: 正在为安全列表 '{security_list.display_name}' 添加入站规则...", "INFO");
        egress_rules = security_list.egress_security_rules
        new_ingress_rules = [
            oci.core.models.IngressSecurityRule(protocol='all', source='0.0.0.0/0', is_stateless=False),
            oci.core.models.IngressSecurityRule(protocol='all', source='::/0', is_stateless=False)]
        update_details = oci.core.models.UpdateSecurityListDetails(ingress_security_rules=new_ingress_rules,
                                                                   egress_security_rules=egress_rules)
        vnet_client.update_security_list(security_list_id, update_details);
        log_ui_callback("步骤 3/3: 防火墙规则已成功更新！", "INFO")
        return True, "✅ 防火墙已完全开放 (IPv4 和 IPv6 的所有协议端口均已放行)。"
    except Exception as e:
        logger.error(f"一键开放防火墙失败: {e}", exc_info=True);
        return False, f"❌ 开放防火墙失败: {e}"


def backend_update_instance_full(compute_client, bs_client, instance_id, changes, logger):
    try:
        logger.info(f"开始更新实例 {instance_id} (需要关机)...")
        instance = compute_client.get_instance(instance_id).data

        if instance.lifecycle_state != 'STOPPED':
            return False, "错误：必须先将实例关机才能进行修改。"

        update_args = {}
        if changes.get('requires_restart'):
            update_args['shape_config'] = UpdateInstanceShapeConfigDetails(
                ocpus=changes.get('ocpus'),
                memory_in_gbs=changes.get('memory')
            )

        if update_args:
            update_details = UpdateInstanceDetails(**update_args)
            compute_client.update_instance(instance_id, update_details)
            logger.info("更新实例(配置)请求已发送，等待完成...")
            oci.wait_until(compute_client, compute_client.get_instance(instance_id),
                           'lifecycle_state', 'STOPPED', max_wait_seconds=600)
            logger.info("实例配置更新完成。")

        if changes.get('boot_volume_size_gb') or changes.get('vpus_per_gb'):
            boot_vol_attachments = oci.pagination.list_call_get_all_results(
                compute_client.list_boot_volume_attachments,
                instance.availability_domain,
                instance.compartment_id,
                instance_id=instance.id).data
            if not boot_vol_attachments:
                return False, "找不到此实例的引导卷。"

            boot_volume_id = boot_vol_attachments[0].boot_volume_id
            bv_update_details = {}
            if changes.get('boot_volume_size_gb'):
                bv_update_details['size_in_gbs'] = changes['boot_volume_size_gb']
            if changes.get('vpus_per_gb'):
                bv_update_details['vpus_per_gb'] = changes['vpus_per_gb']

            if bv_update_details:
                bs_client.update_boot_volume(boot_volume_id,
                                             oci.core.models.UpdateBootVolumeDetails(**bv_update_details))
                logger.info("更新引导卷请求已发送，等待完成...")
                oci.wait_until(bs_client, bs_client.get_boot_volume(boot_volume_id),
                               'lifecycle_state', 'AVAILABLE', max_wait_seconds=600)
                logger.info("引导卷更新完成。")

        return True, "实例更新成功！请在主界面手动启动实例。"
    except Exception as e:
        logger.exception("更新实例时发生错误。")
        return False, f"更新时发生错误: {e}"


def backend_update_display_name(compute_client, instance_id, new_name, logger):
    try:
        logger.info(f"正在为实例 {instance_id} 更新名称为 '{new_name}'...")
        details = UpdateInstanceDetails(display_name=new_name)
        compute_client.update_instance(instance_id, details)
        time.sleep(3)
        logger.info("实例名称更新请求已成功发送。")
        return True, "实例名称更新成功！"
    except Exception as e:
        logger.exception(f"更新实例名称失败: {e}")
        return False, f"更新实例名称失败: {e}"


def backend_fetch_subnets(vnet_client, compartment_id, logger):
    try:
        logger.info(f"正在为区间 {compartment_id} 获取子网列表...")
        all_subnets = oci.pagination.list_call_get_all_results(
            vnet_client.list_subnets,
            compartment_id=compartment_id
        ).data
        logger.info(f"成功获取到 {len(all_subnets)} 个子网。")
        subnet_details = [(subnet.display_name, subnet.id) for subnet in all_subnets]
        return subnet_details, None
    except oci.exceptions.ServiceError as e:
        logger.error(f"获取子网列表时API出错: {e}", exc_info=True)
        return None, f"OCI API 错误: {e.message}\n请检查配置和网络连接。"
    except Exception as e:
        logger.error(f"获取子网列表时发生未知错误: {e}", exc_info=True)
        return None, f"发生未知错误: {e}"


def backend_create_instance(clients, profile_config, details, subnet_id, log_ui_callback, logger):
    try:
        compute_client, identity_client, vnet_client = clients['compute'], clients['identity'], clients['vnet'];
        tenancy_ocid, ssh_key = profile_config['tenancy'], profile_config.get('default_ssh_public_key')

        if not ssh_key or not subnet_id: raise Exception("账号配置缺少默认SSH公钥或未能获取子网ID。")

        log_ui_callback("正在获取可用域...", 'INFO');
        ad_name = identity_client.list_availability_domains(tenancy_ocid).data[0].name;
        os_name, os_version = details['os_name_version'].split('-');
        shape = details['shape'];
        log_ui_callback(f"正在为 {os_name} {os_version} 查找兼容镜像...", 'INFO');
        images = oci.pagination.list_call_get_all_results(compute_client.list_images, tenancy_ocid,
                                                          operating_system=os_name, operating_system_version=os_version,
                                                          shape=shape, sort_by="TIMECREATED", sort_order="DESC").data
        if not images: raise Exception(f"未找到适用于 {os_name} {os_version} (配置: {shape}) 的兼容镜像")

        instance_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(16));

        user_script = details.get('startup_script', '')
        user_data_encoded = get_user_data(instance_password, user_script);

        instance_name = details.get('display_name_prefix', 'instance');
        shape_config = oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=details.get('ocpus'),
                                                                        memory_in_gbs=details.get(
                                                                            'memory_in_gbs')) if "Flex" in shape else None;

        launch_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=tenancy_ocid,
            availability_domain=ad_name,
            shape=shape,
            display_name=instance_name,
            create_vnic_details=oci.core.models.CreateVnicDetails(subnet_id=subnet_id, assign_public_ip=True),
            metadata={"ssh_authorized_keys": ssh_key, "user_data": user_data_encoded},
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=images[0].id,
                boot_volume_size_in_gbs=details['boot_volume_size']),
            shape_config=shape_config
        )

        log_ui_callback(f"正在启动实例 '{instance_name}'...", 'INFO');
        instance = compute_client.launch_instance(launch_details).data;
        log_ui_callback(f"实例 '{instance.display_name}' 正在置备，等待其进入 'RUNNING' 状态...", 'INFO');
        oci.wait_until(compute_client, compute_client.get_instance(instance.id), 'lifecycle_state', 'RUNNING',
                       max_wait_seconds=600);

        dns_update_msg = ""
        if details.get('auto_bind_domain'):
            log_ui_callback(f"实例运行成功，正在获取公网IP并绑定域名...", 'INFO');
            try:
                vnic_attachments = oci.pagination.list_call_get_all_results(compute_client.list_vnic_attachments,
                                                                            compartment_id=tenancy_ocid,
                                                                            instance_id=instance.id).data
                if vnic_attachments:
                    vnic = vnet_client.get_vnic(vnic_attachments[0].vnic_id).data
                    public_ip = vnic.public_ip
                    if public_ip:
                        dns_update_msg = _update_cloudflare_dns(instance.display_name, public_ip, 'A', logger)
                    else:
                        dns_update_msg = "未能获取到公网IP，跳过域名绑定。"
                else:
                    dns_update_msg = "未能获取到VNIC，跳过域名绑定。"
            except Exception as ip_err:
                dns_update_msg = f"获取IP或绑定域名时出错: {ip_err}"
            log_ui_callback(dns_update_msg, 'INFO')

        msg = f"🎉 实例 '{instance.display_name}' 已成功创建并运行!\n- 登陆用户名: ubuntu\n- 密码: {instance_password}\n{dns_update_msg}";
        return True, msg
    except ServiceError as e:
        msg = f"❌ 实例创建失败! \n- 原因: 资源不足或请求过于频繁 ({e.code})，请更换区域或稍后再试。" if e.status == 429 or "TooManyRequests" in e.code or "Out of host capacity" in str(
            e.message) or "LimitExceeded" in e.code else f"❌ 实例创建失败! \n- OCI API 错误: {e.message}";
        return False, msg
    except Exception as e:
        return False, f"❌ 实例创建失败! \n- 程序内部错误: {e}"


# --- 对话框类 ---
class CreateInstanceDialog(tk.Toplevel):
    def __init__(self, parent, callback):
        super().__init__(parent);
        self.transient(parent);
        self.callback = callback;
        self.title("创建新实例");
        self.geometry("550x620");
        main_frame = ttk.Frame(self, padding="10");
        main_frame.pack(expand=True, fill=tk.BOTH);

        basic_frame = ttk.Frame(main_frame)
        basic_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(basic_frame, text="实例名称:").grid(row=0, column=0, sticky=tk.W, pady=2);
        self.name_var = tk.StringVar(value="instance");
        ttk.Entry(basic_frame, textvariable=self.name_var).grid(row=0, column=1, sticky=tk.EW, pady=2);

        ttk.Label(basic_frame, text="操作系统:").grid(row=1, column=0, sticky=tk.W, pady=2);
        self.os_var = tk.StringVar(value="Canonical Ubuntu-22.04");
        os_options = ["Canonical Ubuntu-22.04", "Canonical Ubuntu-20.04", "Oracle Linux-9"];
        ttk.Combobox(basic_frame, textvariable=self.os_var, values=os_options, state="readonly").grid(row=1, column=1,
                                                                                                      sticky=tk.EW,
                                                                                                      pady=2);
        ttk.Label(basic_frame, text="实例规格 (Shape):").grid(row=2, column=0, sticky=tk.W, pady=2);
        self.shape_var = tk.StringVar(value="VM.Standard.A1.Flex");
        shape_options = ["VM.Standard.A1.Flex", "VM.Standard.E2.1.Micro"];
        self.shape_combo = ttk.Combobox(basic_frame, textvariable=self.shape_var, values=shape_options,
                                        state="readonly");
        self.shape_combo.grid(row=2, column=1, sticky=tk.EW, pady=2);
        self.shape_combo.bind("<<ComboboxSelected>>", self.toggle_flex_options);

        basic_frame.columnconfigure(1, weight=1)

        self.flex_frame = ttk.LabelFrame(main_frame, text="ARM Flex 配置", padding="5");
        self.flex_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.flex_frame, text="OCPU 数量:").grid(row=0, column=0, padx=5, pady=2);
        self.ocpu_var = tk.IntVar(value=4);
        ttk.Spinbox(self.flex_frame, from_=1, to=4, textvariable=self.ocpu_var, width=5).grid(row=0, column=1, padx=5,
                                                                                              pady=2);
        ttk.Label(self.flex_frame, text="内存 (GB):").grid(row=1, column=0, padx=5, pady=2);
        self.memory_var = tk.IntVar(value=24);
        ttk.Spinbox(self.flex_frame, from_=1, to=24, textvariable=self.memory_var, width=5).grid(row=1, column=1,
                                                                                                 padx=5, pady=2);

        disk_frame = ttk.Frame(main_frame)
        disk_frame.pack(fill=tk.X, pady=5)
        ttk.Label(disk_frame, text="磁盘大小 (GB):").grid(row=0, column=0, sticky=tk.W, pady=2);
        self.volume_size_var = tk.IntVar(value=50);
        ttk.Spinbox(disk_frame, from_=50, to=200, increment=10, textvariable=self.volume_size_var).grid(row=0, column=1,
                                                                                                        sticky=tk.EW,
                                                                                                        pady=2);
        disk_frame.columnconfigure(1, weight=1)

        script_frame = ttk.LabelFrame(main_frame, text="开机脚本 (可选)", padding="5")
        script_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.script_text = scrolledtext.ScrolledText(script_frame, height=8, wrap=tk.WORD, undo=True)
        self.script_text.pack(fill=tk.BOTH, expand=True)
        ttk.Label(script_frame, text="实例启动时将自动执行此脚本。常用依赖会自动安装。", foreground="gray").pack(
            anchor=tk.W)

        self.auto_bind_domain_var = tk.BooleanVar(value=False)
        cf_check = ttk.Checkbutton(main_frame, text="自动绑定 Cloudflare 域名 (需先在主界面设置)",
                                   variable=self.auto_bind_domain_var)
        cf_check.pack(anchor=tk.W, pady=5)

        button_frame = ttk.Frame(self, padding=(0, 5, 0, 10));
        button_frame.pack(fill=tk.X);
        ttk.Button(button_frame, text="确认创建", command=self.submit).pack(side=tk.RIGHT, padx=10);
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT);

        self.toggle_flex_options();
        self.after(100, lambda: center_window(self));
        self.grab_set()

    def toggle_flex_options(self, event=None):
        if "Flex" in self.shape_var.get():
            [child.configure(state='normal') for child in self.flex_frame.winfo_children()]
        else:
            [child.configure(state='disabled') for child in self.flex_frame.winfo_children()]

    def submit(self):
        details = {
            "display_name_prefix": self.name_var.get(),
            "os_name_version": self.os_var.get(),
            "shape": self.shape_var.get(),
            "boot_volume_size": self.volume_size_var.get(),
            "startup_script": self.script_text.get("1.0", tk.END).strip(),
            "auto_bind_domain": self.auto_bind_domain_var.get()
        };
        if "Flex" in details['shape']:
            details["ocpus"] = self.ocpu_var.get();
            details["memory_in_gbs"] = self.memory_var.get()
        self.callback(details);
        self.destroy()


class EditInstanceDialog(tk.Toplevel):
    def __init__(self, parent, instance_details, callback):
        super().__init__(parent);
        self.transient(parent);
        self.instance_id = instance_details['id'];
        self.callback = callback;
        self.title(f"编辑实例: {instance_details.get('display_name', 'N/A')}");
        self.geometry("450x300");
        main_frame = ttk.Frame(self, padding="10");
        main_frame.pack(expand=True, fill=tk.BOTH);
        ttk.Label(main_frame, text="实例显示名称:").pack(fill=tk.X, padx=5, pady=2);
        self.name_var = tk.StringVar(value=instance_details.get('display_name', ''));
        name_frame = ttk.Frame(main_frame);
        name_frame.pack(fill=tk.X, padx=5, pady=(0, 10));
        ttk.Entry(name_frame, textvariable=self.name_var).pack(side=tk.LEFT, expand=True, fill=tk.X);
        ttk.Button(name_frame, text="保存名称", command=self.save_name).pack(side=tk.LEFT, padx=(5, 0));
        ttk.Separator(main_frame, orient='horizontal').pack(fill=tk.X, pady=5);
        self.flex_frame = ttk.LabelFrame(main_frame, text="CPU与内存 (需先关机)", padding="5");
        self.flex_frame.pack(fill=tk.X, padx=5, pady=5);
        ttk.Label(self.flex_frame, text="OCPU:").grid(row=0, column=0, sticky=tk.W, padx=5);
        self.ocpu_var = tk.IntVar(value=instance_details.get('ocpus', 1));
        ttk.Spinbox(self.flex_frame, from_=1, to=4, textvariable=self.ocpu_var, width=5).grid(row=0, column=1);
        ttk.Label(self.flex_frame, text="内存(GB):").grid(row=0, column=2, sticky=tk.W, padx=5);
        self.memory_var = tk.IntVar(value=instance_details.get('memory_in_gbs', 1));
        ttk.Spinbox(self.flex_frame, from_=1, to=24, textvariable=self.memory_var, width=5).grid(row=0, column=3);
        ttk.Button(self.flex_frame, text="保存配置", command=self.save_shape).grid(row=0, column=4, padx=(10, 0));
        self.flex_frame.columnconfigure(5, weight=1);
        if "Flex" not in instance_details.get('shape', ''): [child.configure(state='disabled') for child in
                                                             self.flex_frame.winfo_children()]
        boot_vol_frame = ttk.LabelFrame(main_frame, text="引导卷 (需先关机)", padding="5");
        boot_vol_frame.pack(fill=tk.X, padx=5, pady=5);
        ttk.Label(boot_vol_frame, text="大小(GB):").grid(row=0, column=0, sticky=tk.W, padx=5);
        self.size_var = tk.IntVar(value=int(instance_details.get('boot_volume_size_gb', 50)));
        ttk.Spinbox(boot_vol_frame, from_=50, to=500, textvariable=self.size_var, width=5).grid(row=0, column=1);
        ttk.Button(boot_vol_frame, text="保存大小", command=self.save_size).grid(row=0, column=2, padx=(5, 0));
        ttk.Label(boot_vol_frame, text="性能(VPU):").grid(row=1, column=0, sticky=tk.W, padx=5);
        self.vpu_var = tk.IntVar(value=instance_details.get('vpus_per_gb', 10));
        ttk.Spinbox(boot_vol_frame, from_=10, to=120, increment=10, textvariable=self.vpu_var, width=5).grid(row=1,
                                                                                                             column=1);
        ttk.Button(boot_vol_frame, text="保存性能", command=self.save_vpu).grid(row=1, column=2, padx=(5, 0));
        ttk.Button(main_frame, text="关闭窗口", command=self.destroy).pack(pady=10);
        self.after(100, lambda: center_window(self));
        self.grab_set()

    def save_name(self):
        self.callback(self.instance_id, {'display_name': self.name_var.get()}, dialog_to_close=self)
        messagebox.showinfo("请求已提交", "名称更新请求已提交，请稍后刷新列表。", parent=self.master)

    def save_shape(self):
        self.callback(self.instance_id,
                      {'requires_restart': True, 'ocpus': self.ocpu_var.get(), 'memory': self.memory_var.get()},
                      dialog_to_close=self)
        messagebox.showinfo("请求已提交", "配置更新请求已提交，请稍后刷新列表。", parent=self.master)

    def save_size(self):
        self.callback(self.instance_id, {'boot_volume_size_gb': self.size_var.get()}, dialog_to_close=self)
        messagebox.showinfo("请求已提交", "引导卷大小更新请求已提交，请稍后刷新列表。", parent=self.master)

    def save_vpu(self):
        self.callback(self.instance_id, {'vpus_per_gb': self.vpu_var.get()}, dialog_to_close=self)
        messagebox.showinfo("请求已提交", "引导卷性能更新请求已提交，请稍后刷新列表。", parent=self.master)


class EditProfileDialog(tk.Toplevel):
    def __init__(self, parent, alias, profile_data, callback):
        super().__init__(parent);
        self.transient(parent);
        self.title(f"编辑账号: {alias}" if alias else "添加新账号");
        self.geometry("600x480");
        self.original_alias = alias;
        self.callback = callback;
        self.new_key_content = profile_data.get('key_content')

        main_frame = ttk.Frame(self, padding="10");
        main_frame.pack(expand=True, fill=tk.BOTH);

        ttk.Label(main_frame, text="账号别名:").pack(anchor=tk.W);
        self.alias_var = tk.StringVar(value=alias or "");
        ttk.Entry(main_frame, textvariable=self.alias_var).pack(fill=tk.X, pady=(0, 5));

        ttk.Label(main_frame, text="配置信息 (user, fingerprint, tenancy, region):").pack(anchor=tk.W);
        self.config_text = tk.Text(main_frame, height=5);
        config_items = {k: v for k, v in profile_data.items() if k in ['user', 'fingerprint', 'tenancy', 'region']};
        self.config_text.insert('1.0', '\n'.join([f"{k}={v}" for k, v in config_items.items()]));
        self.config_text.pack(fill=tk.BOTH, expand=True, pady=(0, 5));

        ttk.Label(main_frame, text="默认SSH公钥 (留空将使用内置密钥):").pack(anchor=tk.W);
        self.ssh_text = tk.Text(main_frame, height=4);
        self.ssh_text.insert('1.0', profile_data.get('default_ssh_public_key', ''));
        self.ssh_text.pack(fill=tk.BOTH, expand=True, pady=(0, 2));
        ssh_info_label = ttk.Label(main_frame, foreground="gray",
                                   text="此处填写OCI官网获取或自己生成的SSH密钥对中的公钥 (ssh-rsa...)")
        ssh_info_label.pack(anchor=tk.W, pady=(0, 10))

        pem_frame = ttk.Frame(main_frame);
        pem_frame.pack(fill=tk.X, pady=5);

        self.pem_path_var = tk.StringVar()
        if self.original_alias and self.new_key_content:
            self.pem_path_var.set("<私钥已存在，如需更新请重新上传>")

        button_text = "更新 PEM 文件..." if alias else "上传 PEM 文件..."
        upload_btn = ttk.Button(pem_frame, text=button_text, command=self.select_pem)

        path_entry = ttk.Entry(pem_frame, textvariable=self.pem_path_var, state="readonly")

        pem_frame.columnconfigure(1, weight=1)
        upload_btn.grid(row=0, column=0, sticky="ns")
        path_entry.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        button_frame = ttk.Frame(self);
        button_frame.pack(fill=tk.X, padx=10, pady=10);
        ttk.Button(button_frame, text="保存更改", command=self.save_changes).pack(side=tk.RIGHT);
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5);

        self.after(100, lambda: center_window(self));
        self.grab_set()

    def select_pem(self):
        filepath = filedialog.askopenfilename(title="选择 PEM 私钥文件",
                                              filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filepath:
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    self.new_key_content = f.read()
                self.pem_path_var.set(filepath)
            except Exception as e:
                messagebox.showerror("读取错误", f"无法读取文件: {e}", parent=self)

    def save_changes(self):
        new_alias = self.alias_var.get().strip()
        if not new_alias: messagebox.showerror("错误", "账号别名不能为空。", parent=self); return
        if not self.original_alias and not self.new_key_content: messagebox.showerror("错误",
                                                                                      "添加新账号时必须上传PEM私钥文件。",
                                                                                      parent=self); return
        new_profile_data = {};
        config_lines = self.config_text.get('1.0', tk.END).strip().split('\n')
        for line in config_lines:
            if '=' in line: key, val = line.split('=', 1); new_profile_data[key.strip()] = val.strip()

        new_profile_data['default_ssh_public_key'] = self.ssh_text.get('1.0', tk.END).strip()

        if self.new_key_content: new_profile_data['key_content'] = self.new_key_content
        self.callback(self.original_alias, new_alias, new_profile_data);
        self.destroy()


class SetProxyDialog(tk.Toplevel):
    def __init__(self, parent, alias, profile_data, callback):
        super().__init__(parent)
        self.transient(parent)
        self.title(f"为账号 '{alias}' 设置代理")
        self.geometry("500x180")
        self.alias = alias
        self.callback = callback

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(main_frame, text=f"请输入账号 '{alias}' 使用的代理地址：").pack(anchor=tk.W, pady=(0, 5))
        ttk.Label(main_frame, text="格式: http://host:port 或 socks5://user:pass@host:port", foreground="gray").pack(
            anchor=tk.W, pady=(0, 10))

        self.proxy_var = tk.StringVar(value=profile_data.get('proxy', ''))
        ttk.Entry(main_frame, textvariable=self.proxy_var).pack(fill=tk.X)

        button_frame = ttk.Frame(self)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="保存", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="清除", command=self.clear).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.after(100, lambda: center_window(self))
        self.grab_set()

    def save(self):
        proxy_url = self.proxy_var.get().strip()
        self.callback(self.alias, proxy_url)
        self.destroy()

    def clear(self):
        self.proxy_var.set("")


class SelectSubnetDialog(tk.Toplevel):
    def __init__(self, parent, subnet_list):
        super().__init__(parent)
        self.transient(parent)
        self.title("选择一个子网")
        self.geometry("600x400")
        self.selected_subnet_id = None

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(main_frame, text="已找到多个子网，请选择一个用于后续操作：").pack(anchor=tk.W, pady=5)

        list_frame = ttk.Frame(main_frame)
        list_frame.pack(expand=True, fill=tk.BOTH)

        self.listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE)
        self.subnet_map = {}
        for display_name, subnet_id in subnet_list:
            unique_name = f"{display_name} (...{subnet_id[-6:]})"
            self.listbox.insert(tk.END, unique_name)
            self.subnet_map[unique_name] = subnet_id

        self.listbox.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="确认", command=self.on_ok).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)

        self.listbox.bind("<Double-1>", lambda e: self.on_ok())
        self.after(100, lambda: center_window(self))
        self.grab_set()
        self.wait_window()

    def on_ok(self):
        selection = self.listbox.curselection()
        if selection:
            selected_item = self.listbox.get(selection[0])
            self.selected_subnet_id = self.subnet_map[selected_item]
        self.destroy()


class CloudflareSettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.transient(parent)
        self.title("Cloudflare 设置")
        self.geometry("500x250")

        self.cf_config = load_cloudflare_config()

        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(main_frame, text="Cloudflare API 令牌:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.api_token_var = tk.StringVar(value=self.cf_config.get('api_token', ''))
        ttk.Entry(main_frame, textvariable=self.api_token_var, show='*').grid(row=0, column=1, sticky=tk.EW, pady=5)

        ttk.Label(main_frame, text="Zone ID:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.zone_id_var = tk.StringVar(value=self.cf_config.get('zone_id', ''))
        ttk.Entry(main_frame, textvariable=self.zone_id_var).grid(row=1, column=1, sticky=tk.EW, pady=5)

        ttk.Label(main_frame, text="主域名 (例如 example.com):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.domain_var = tk.StringVar(value=self.cf_config.get('domain', ''))
        ttk.Entry(main_frame, textvariable=self.domain_var).grid(row=2, column=1, sticky=tk.EW, pady=5)

        main_frame.columnconfigure(1, weight=1)

        button_frame = ttk.Frame(self)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="保存", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.after(100, lambda: center_window(self))
        self.grab_set()
        self.wait_window()

    def save(self):
        new_config = {
            'api_token': self.api_token_var.get().strip(),
            'zone_id': self.zone_id_var.get().strip(),
            'domain': self.domain_var.get().strip()
        }
        if not all(new_config.values()):
            messagebox.showwarning("输入不完整", "所有字段都必须填写。", parent=self)
            return

        save_cloudflare_config(new_config)
        messagebox.showinfo("成功", "Cloudflare 设置已保存。", parent=self)
        self.destroy()


# --- 主应用类 ---
class OciInstanceManagerApp:
    def __init__(self, root):
        self.root = root;
        self.root.title("OCI 本地化管理工具 (v16.8 - 完整功能版)");
        self.root.geometry("1500x800");
        self.logger = logging.getLogger(__name__);
        self.logger.info("--- OCI 应用启动 ---");
        style = ttk.Style();

        default_style_name = ttk.LabelFrame().winfo_class()
        style.layout("RedBold.TLabelFrame", style.layout(default_style_name))
        style.configure("BlackBold.TLabel", font=(None, 12, 'bold'))
        style.configure("RedBold.TLabel", foreground="red", font=(None, 12, 'bold'))

        style.configure("Connected.TLabel", foreground="red", font=(None, 12, 'bold'))

        default_font = tkfont.nametofont(style.lookup("TButton", "font"))
        bold_font = default_font.copy()
        bold_font.configure(weight="bold")

        style.layout("Red.TButton", style.layout("TButton"))
        style.configure("Red.TButton", foreground="red", font=bold_font)

        self.oci_config, self.identity_client, self.compute_client, self.virtual_network_client, self.block_storage_client = None, None, None, None, None;
        self.is_connected, self.connected_profile_alias, self.selected_profile_alias = False, None, None;
        self.all_profiles_data, self.last_used_alias, self.instance_data, self.selected_instance_ocid = {}, None, {}, None;
        self.profile_order = []
        self.session_subnet_id = None

        self.connected_alias_var = tk.StringVar(value="当前未连接")

        self.load_settings_from_file();
        self.load_profiles_from_file();
        self.create_top_bar();
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=5);
        main_pane.pack(expand=True, fill=tk.BOTH, padx=10, pady=(0, 5));
        left_frame = ttk.Frame(main_pane, padding=(0, 5));
        self.create_account_list_view(left_frame);
        main_pane.add(left_frame, width=360);
        right_frame = ttk.Frame(main_pane, padding=(5, 5));
        self.create_instance_view(right_frame);
        main_pane.add(right_frame);
        self.create_action_buttons();
        self.create_log_viewer();
        self.create_status_bar();
        self.update_account_list();
        if not self.all_profiles_data: self.log_ui("未找到账号配置。请使用 '导入账号' 或 '添加账号' 功能。", level='WARN')
        self.toggle_controls(connected=False, profiles_exist=bool(self.all_profiles_data), selection_valid=False)

    # 增强JSON读取能力
    def load_profiles_from_file(self):
        try:
            if os.path.exists(PROFILES_FILE_PATH):
                with open(PROFILES_FILE_PATH, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "profiles" in data and isinstance(data["profiles"], dict):
                        self.all_profiles_data = data["profiles"]
                        self.logger.info("检测到Web端JSON格式，已成功加载 profiles 数据。")
                        if "profile_order" in data and isinstance(data["profile_order"], list):
                            self.profile_order = data["profile_order"]
                            self.logger.info("已从Web端JSON同步 profile_order。")
                    else:
                        self.all_profiles_data = data
                self.logger.info(f"从 {PROFILES_FILE_PATH} 加载了 {len(self.all_profiles_data)} 个账号配置。")
            else:
                self.all_profiles_data = {}
        except Exception as e:
            self.logger.error(f"加载账号配置文件 {PROFILES_FILE_PATH} 错误: {e}", exc_info=True)
            self.all_profiles_data = {}

    def save_profiles_to_file(self):
        try:
            with open(PROFILES_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.all_profiles_data, f, indent=4, ensure_ascii=False)
            self.logger.info(f"账号配置已保存到 {PROFILES_FILE_PATH}。")
        except Exception as e:
            self.logger.error(f"保存账号配置文件 {PROFILES_FILE_PATH} 错误: {e}", exc_info=True)

    def load_settings_from_file(self):
        try:
            if os.path.exists(SETTINGS_FILE_PATH):
                with open(SETTINGS_FILE_PATH, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    self.last_used_alias = settings.get("last_profile_alias")
                    self.profile_order = settings.get("profile_order", [])
        except Exception as e:
            self.logger.error(f"加载设置文件 {SETTINGS_FILE_PATH} 错误: {e}", exc_info=True)

    def save_settings_to_file(self):
        try:
            settings = {
                "last_profile_alias": self.last_used_alias,
                "profile_order": self.profile_order
            }
            with open(SETTINGS_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=4)
        except Exception as e:
            self.logger.error(f"保存设置文件 {SETTINGS_FILE_PATH} 错误: {e}", exc_info=True)

    def log_ui(self, message, level='INFO'):
        log_level = level.upper();
        if log_level == 'INFO':
            self.logger.info(message)
        elif log_level in ('WARN', 'WARNING'):
            self.logger.warning(message)
        elif log_level == 'ERROR':
            self.logger.error(message)
        self.update_status(message)
        if hasattr(self, 'log_viewer') and self.log_viewer:
            log_entry = f"{time.strftime('%H:%M:%S')} - {message}\n";
            try:
                self.log_viewer.config(state=tk.NORMAL);
                self.log_viewer.insert(tk.END,
                                       log_entry);
                self.log_viewer.yview(
                    tk.END);
                self.log_viewer.config(state=tk.DISABLED)
            except tk.TclError:
                pass

    def update_status(self, text):
        def update():
            if hasattr(self, 'status_label') and self.status_label.winfo_exists(): self.status_label.config(text=text)

        if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, update)

    def toggle_controls(self, connected, profiles_exist, selection_valid):
        instance_state, vnic_id = None, None
        if selection_valid and self.selected_instance_ocid in self.instance_data:
            details = self.instance_data[self.selected_instance_ocid]
            instance_state = details.get('lifecycle_state')
            vnic_id = details.get('vnic_id')

        def update_states():
            if not (hasattr(self, 'root') and self.root.winfo_exists()): return
            edit_delete_state = 'normal' if profiles_exist and self.selected_profile_alias else 'disabled'
            self.edit_profile_button.config(state=edit_delete_state)
            self.delete_profile_button.config(state=edit_delete_state)
            self.connect_button.config(state='normal' if profiles_exist and self.selected_profile_alias else 'disabled')

            self.create_instance_button.config(state='normal' if connected else 'disabled')
            self.firewall_button.config(state='normal' if connected else 'disabled')

            action_base = 'normal' if connected and selection_valid else 'disabled'
            self.edit_instance_button.config(state=action_base)
            self.restart_button.config(state=action_base)
            self.terminate_button.config(state=action_base)
            self.start_button.config(
                state='normal' if connected and selection_valid and instance_state == 'STOPPED' else 'disabled')
            self.stop_button.config(
                state='normal' if connected and selection_valid and instance_state == 'RUNNING' else 'disabled')
            self.change_ip_button.config(state=self.stop_button['state'])
            self.assign_ipv6_button.config(
                state='normal' if connected and selection_valid and vnic_id and instance_state == 'RUNNING' else 'disabled')

        if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, update_states)

    def _get_or_choose_subnet(self):
        if self.session_subnet_id:
            return self.session_subnet_id

        if not self.is_connected:
            messagebox.showwarning("未连接", "请先连接到一个账号。", parent=self.root)
            return None

        self.log_ui("正在自动获取子网列表...", "INFO")
        subnets, error = backend_fetch_subnets(self.virtual_network_client, self.oci_config['tenancy'], self.logger)

        if error:
            messagebox.showerror("获取子网失败", error, parent=self.root)
            return None

        if not subnets:
            messagebox.showinfo("未找到子网", "在当前账号的根分区下未找到任何子网。", parent=self.root)
            return None

        chosen_subnet_id = None
        if len(subnets) == 1:
            chosen_subnet_id = subnets[0][1]
            self.log_ui(f"已自动选择唯一的子网: {subnets[0][0]}", "INFO")
        else:
            dialog = SelectSubnetDialog(self.root, subnets)
            chosen_subnet_id = dialog.selected_subnet_id

        if chosen_subnet_id:
            self.session_subnet_id = chosen_subnet_id
            return chosen_subnet_id
        else:
            self.log_ui("用户取消了子网选择。", "WARN")
            return None

    def create_top_bar(self):
        label_container = ttk.Frame(self.root)
        label1 = ttk.Label(label_container, text="账号管理 ", style="BlackBold.TLabel")
        label1.pack(side=tk.LEFT)
        label2 = ttk.Label(label_container, text="(单击选中，双击代理，拖拽排序)", style="RedBold.TLabel")
        label2.pack(side=tk.LEFT)
        top_bar_frame = ttk.LabelFrame(self.root, labelwidget=label_container, padding=(10, 5))
        top_bar_frame.pack(pady=5, padx=10, fill=tk.X)

        connected_label = ttk.Label(top_bar_frame, textvariable=self.connected_alias_var, style="Connected.TLabel")
        connected_label.pack(side=tk.RIGHT, padx=10)

        ttk.Button(top_bar_frame, text="添加账号", command=self.add_profile).pack(side=tk.LEFT, padx=(0, 5))
        self.edit_profile_button = ttk.Button(top_bar_frame, text="编辑选中账号", command=self.edit_profile,
                                              state='disabled')
        self.edit_profile_button.pack(side=tk.LEFT, padx=5)
        self.delete_profile_button = ttk.Button(top_bar_frame, text="删除选中账号", command=self.delete_profile,
                                                state='disabled')
        self.delete_profile_button.pack(side=tk.LEFT, padx=5)

        self.cf_button = ttk.Button(top_bar_frame, text="Cloudflare设置", command=self.show_cloudflare_settings)
        self.cf_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(top_bar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        self.connect_button = ttk.Button(top_bar_frame, text="连接选中账号", command=self.connect_oci_thread,
                                         state='disabled')
        self.connect_button.pack(side=tk.LEFT, padx=5)

    def create_action_buttons(self):
        action_frame = ttk.Frame(self.root, padding=(10, 5))
        action_frame.pack(pady=5, padx=10, fill=tk.X)
        action_frame.columnconfigure(0, weight=1)
        action_frame.columnconfigure(1, weight=0)
        action_frame.columnconfigure(2, weight=7)

        left_button_frame = ttk.Frame(action_frame)
        left_button_frame.grid(row=0, column=0, sticky="ew")

        self.create_instance_button = ttk.Button(left_button_frame, text="创建实例",
                                                 command=self.show_create_instance_dialog, state='disabled')
        self.create_instance_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.firewall_button = ttk.Button(left_button_frame, text="一键开放防火墙",
                                          command=self.confirm_and_open_firewall,
                                          state='disabled')
        self.firewall_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        ttk.Separator(action_frame, orient='vertical').grid(row=0, column=1, sticky="ns", padx=10, pady=2)

        expand_button_frame = ttk.Frame(action_frame)
        expand_button_frame.grid(row=0, column=2, sticky="ew")

        self.start_button = ttk.Button(expand_button_frame, text="启动",
                                       command=lambda: self.confirm_and_run_action("start"),
                                       state='disabled')
        self.start_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.restart_button = ttk.Button(expand_button_frame, text="重启",
                                         command=lambda: self.confirm_and_run_action("restart"), state='disabled')
        self.restart_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.edit_instance_button = ttk.Button(expand_button_frame, text="编辑实例",
                                               command=self.show_edit_instance_dialog,
                                               state='disabled')
        self.edit_instance_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.change_ip_button = ttk.Button(expand_button_frame, text="更换公网IP",
                                           command=lambda: self.confirm_and_run_action("change_ip"), state='disabled')
        self.change_ip_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.assign_ipv6_button = ttk.Button(expand_button_frame, text="一键开启IPv6",
                                             command=lambda: self.confirm_and_run_action("assign_ipv6"),
                                             state='disabled')
        self.assign_ipv6_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.stop_button = ttk.Button(expand_button_frame, text="关机",
                                      command=lambda: self.confirm_and_run_action("stop"),
                                      state='disabled', style="Red.TButton")
        self.stop_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

        self.terminate_button = ttk.Button(expand_button_frame, text="终止",
                                           command=lambda: self.confirm_and_run_action("terminate"), state='disabled',
                                           style="Red.TButton")
        self.terminate_button.pack(side=tk.LEFT, padx=2, expand=True, fill=tk.X)

    # --- 账户列表创建，配置排序和颜色Tag ---
    def create_account_list_view(self, parent_frame):
        view_frame = ttk.LabelFrame(parent_frame, text="账户列表", padding=(5, 5));
        view_frame.pack(expand=True, fill=tk.BOTH);

        self.account_treeview = ttk.Treeview(view_frame, columns=('alias', 'duration'), show='headings',
                                             selectmode='browse');

        self.account_treeview.heading('alias', text='账户名称',
                                      command=lambda: self.sort_account_column('alias', False))
        self.account_treeview.column('alias', width=100, anchor=tk.CENTER);

        self.account_treeview.heading('duration', text='租户创建时间',
                                      command=lambda: self.sort_account_column('duration', False))
        self.account_treeview.column('duration', width=200, anchor=tk.CENTER);

        self.account_treeview.tag_configure("oddrow", background="white")
        self.account_treeview.tag_configure("evenrow", background="#F2F2F2")
        self.account_treeview.tag_configure('connected', background='lightblue')

        vsb = ttk.Scrollbar(view_frame, orient="vertical", command=self.account_treeview.yview);
        self.account_treeview.configure(yscrollcommand=vsb.set);
        self.account_treeview.grid(row=0, column=0, sticky='nsew');
        vsb.grid(row=0, column=1, sticky='ns');
        view_frame.grid_rowconfigure(0, weight=1);
        view_frame.grid_columnconfigure(0, weight=1);
        self.account_treeview.bind('<<TreeviewSelect>>', self.on_profile_select)
        self.account_treeview.bind('<Double-1>', self.show_proxy_dialog)

        self.account_treeview.bind("<ButtonPress-1>", self.on_drag_start)
        self.account_treeview.bind("<B1-Motion>", self.on_drag_motion)
        self.account_treeview.bind("<ButtonRelease-1>", self.on_drag_stop)

        # --- 新增: 导入导出按钮区域 ---
        btn_frame = ttk.Frame(view_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=5)

        ttk.Button(btn_frame, text="导入账号", command=self.import_accounts).pack(side=tk.LEFT, expand=True, fill=tk.X,
                                                                                  padx=2)
        ttk.Button(btn_frame, text="导出账号", command=self.export_accounts).pack(side=tk.LEFT, expand=True, fill=tk.X,
                                                                                  padx=2)

    # --- 导入/导出 功能逻辑 ---
    def import_accounts(self):
        filepath = filedialog.askopenfilename(title="选择要导入的账号文件", filetypes=[("JSON Files", "*.json")])
        if not filepath: return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            new_profiles = {}
            new_order = []

            # 兼容新旧格式
            if "profiles" in data:
                new_profiles = data["profiles"]
                new_order = data.get("profile_order", [])
            else:
                new_profiles = data

            if not new_profiles:
                messagebox.showwarning("无效文件", "所选文件不包含有效的账号数据。")
                return

            # 合并数据
            self.all_profiles_data.update(new_profiles)

            # 合并排序
            if new_order:
                existing_order_set = set(self.profile_order)
                for item in new_order:
                    if item not in existing_order_set:
                        self.profile_order.append(item)

            # 保存到本地配置
            self.save_profiles_to_file()
            self.save_settings_to_file()
            self.update_account_list()
            messagebox.showinfo("导入成功", f"成功导入了 {len(new_profiles)} 个账号配置。")
        except Exception as e:
            messagebox.showerror("导入失败", f"文件读取错误: {e}")

    def export_accounts(self):
        filepath = filedialog.asksaveasfilename(title="导出账号配置", defaultextension=".json",
                                                filetypes=[("JSON Files", "*.json")],
                                                initialfile="oci_profiles_backup.json")
        if not filepath: return
        try:
            export_data = {
                "profiles": self.all_profiles_data,
                "profile_order": self.profile_order
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("导出成功", f"账号配置已成功备份到:\n{filepath}")
        except Exception as e:
            messagebox.showerror("导出失败", f"无法写入文件: {e}")

    def create_instance_view(self, parent_frame):
        instance_pane = tk.PanedWindow(parent_frame, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=5)
        instance_pane.pack(expand=True, fill=tk.BOTH)

        list_frame = ttk.LabelFrame(instance_pane, text="实例列表 (单击查看详情)", padding=(5, 5))
        instance_pane.add(list_frame, height=200)

        columns = ('name', 'status', 'public_ip', 'ipv6_address', 'config', 'time_created')
        self.instance_treeview = ttk.Treeview(list_frame, columns=columns, show='headings', selectmode='browse',
                                              height=6)

        col_widths = {'name': 120, 'status': 80, 'public_ip': 120, 'ipv6_address': 220, 'config': 180,
                      'time_created': 150}
        col_display = {'name': '显示名称', 'status': '状态', 'public_ip': '公网IP', 'ipv6_address': 'IPv6 地址',
                       'config': '配置(核/内存/磁盘)',
                       'time_created': '实例创建时间'}

        for col in columns:
            self.instance_treeview.heading(col, text=col_display[col])
            self.instance_treeview.column(col, width=col_widths[col], anchor=tk.CENTER)

        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.instance_treeview.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.instance_treeview.xview)
        self.instance_treeview.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.instance_treeview.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)

        self.instance_treeview.bind('<<TreeviewSelect>>', self.on_instance_select)

        details_frame = ttk.LabelFrame(instance_pane, text="实例详细信息", padding=(5, 5))
        instance_pane.add(details_frame, height=300)

        self.instance_details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, state=tk.DISABLED,
                                                               font=("Consolas", 11))
        self.instance_details_text.pack(expand=True, fill=tk.BOTH)

    def create_log_viewer(self):
        log_frame = ttk.LabelFrame(self.root, text="操作日志", padding=(5, 5));
        log_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True);
        self.log_viewer = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD, state=tk.DISABLED);
        self.log_viewer.pack(expand=True, fill=tk.BOTH)

    def create_status_bar(self):
        self.status_label = ttk.Label(self.root, text="未连接", relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2));
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- 排序辅助方法（拼音+数字） ---
    def get_account_sort_key(self, col, value):
        """辅助排序：如果是时间列，提取数字；如果是名称列，转拼音排序"""
        if col == "duration":
            # 提取 "8天" 中的 "8"
            match = re.match(r"(\d+)天", value)
            if match:
                return int(match.group(1))
            # 处理 "- (未来)" 或其他格式
            if "未来" in value: return -1
            return 999999  # 无日期的排在最后
        else:
            # 使用 lazy_pinyin 将 "阿布扎比" 转换为 ['a', 'bu', 'zha', 'bi']
            if not value:
                return ""
            try:
                # 将汉字转换为拼音字符串 (例如: "阿布扎比" -> "abuzhabi")
                pinyin_str = "".join(lazy_pinyin(value))
                return pinyin_str.lower()
            except Exception:
                return value.lower()

    def sort_account_column(self, col, reverse):
        """执行账户列表排序"""
        l = [(self.account_treeview.set(k, col), k) for k in self.account_treeview.get_children('')]
        l.sort(key=lambda x: self.get_account_sort_key(col, x[0]), reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.account_treeview.move(k, '', index)

        # 排序后刷新斑马纹
        self.refresh_account_colors()

        # 绑定反向排序
        self.account_treeview.heading(col, command=lambda: self.sort_account_column(col, not reverse))

    def refresh_account_colors(self):
        """重新计算斑马纹，保持 Connected 高亮"""
        for i, item_id in enumerate(self.account_treeview.get_children()):
            if item_id == self.connected_profile_alias:
                self.account_treeview.item(item_id, tags=('connected',))
            else:
                tag = "evenrow" if i % 2 == 0 else "oddrow"
                self.account_treeview.item(item_id, tags=(tag,))

    # --- 账户列表更新逻辑 (包含新的日期格式与斑马纹) ---
    def update_account_list(self):
        current_selection = self.account_treeview.selection()

        for item in self.account_treeview.get_children(): self.account_treeview.delete(item)

        all_aliases = set(self.all_profiles_data.keys())
        final_order = [alias for alias in self.profile_order if alias in all_aliases]
        new_aliases = sorted([alias for alias in all_aliases if alias not in final_order])
        final_order.extend(new_aliases)

        last_used_item_id = None
        if self.last_used_alias in final_order:
            last_used_item_id = self.last_used_alias
        elif current_selection and current_selection[0] in final_order:
            last_used_item_id = current_selection[0]

        for i, alias in enumerate(final_order):
            # 获取该账号的 registration_date 并计算时长
            profile_data = self.all_profiles_data.get(alias, {})
            reg_date_str = profile_data.get('registration_date')
            duration_display = ""

            if reg_date_str:
                try:
                    reg_date = datetime.strptime(reg_date_str, "%Y-%m-%d").date()
                    today = datetime.now().date()
                    delta = today - reg_date
                    days = delta.days
                    if days < 0:
                        duration_display = f"{days}天 (未来)"
                    else:
                        duration_display = f"{days}天 ({reg_date.year}年{reg_date.month}月{reg_date.day}日)"
                except Exception:
                    duration_display = "格式错误"
            else:
                duration_display = "-"

            # --- 设置初始 Tag (斑马纹或已连接状态) ---
            tags = ()
            if alias == self.connected_profile_alias:
                tags = ('connected',)
            else:
                tags = ('evenrow',) if i % 2 == 0 else ('oddrow',)

            # 插入数据
            self.account_treeview.insert('', tk.END, iid=alias, values=(alias, duration_display), tags=tags)

        if last_used_item_id:
            self.account_treeview.selection_set(last_used_item_id)
            self.account_treeview.focus(last_used_item_id)

        if list(self.account_treeview.get_children()) != self.profile_order:
            self.profile_order = list(self.account_treeview.get_children())
            self.save_settings_to_file()

    def on_profile_select(self, event=None):
        selected_items = self.account_treeview.selection()
        if selected_items:
            self.selected_profile_alias = selected_items[0];
            self.logger.info(
                f"在列表中选中账号: {self.selected_profile_alias}")
        else:
            self.selected_profile_alias = None
        self.toggle_controls(self.is_connected, bool(self.all_profiles_data), self.selected_instance_ocid is not None)

    def on_instance_select(self, event=None):
        selected_items = self.instance_treeview.selection()
        is_valid_selection = len(selected_items) == 1

        if is_valid_selection:
            self.selected_instance_ocid = selected_items[0]
            details_data = self.instance_data.get(self.selected_instance_ocid, {})

            lines = [
                f"名称:         {details_data.get('display_name', 'N/A')}",
                f"状态:         {details_data.get('lifecycle_state', 'N/A')}",
                f"OCID:         {details_data.get('id', 'N/A')}",
                "-" * 30,
                f"公网 IP:      {details_data.get('public_ip', 'N/A')}",
                f"私有 IP:      {details_data.get('private_ip', 'N/A')}",
                f"IPv6 地址:    {details_data.get('ipv6_address', 'N/A')}",
                f"子网 OCID:    {details_data.get('subnet_id', 'N/A')}",
                f"VNIC OCID:    {details_data.get('vnic_id', 'N/A')}",
                "-" * 30,
                f"配置:         {details_data.get('shape', 'N/A')}",
                f"  OCPU:       {details_data.get('ocpus', 'N/A')}",
                f"  内存(GB):   {details_data.get('memory_in_gbs', 'N/A')}",
                f"  引导卷:     {details_data.get('boot_volume_size_gb', 'N/A')} GB ({details_data.get('vpus_per_gb', 'N/A')} VPU/GB)",
                f"可用域:       {details_data.get('availability_domain', 'N/A')}",
                f"创建时间:     {details_data.get('time_created', 'N/A')} (已运行 {details_data.get('duration', 'N/A')})",
                f"区域:         {details_data.get('region', 'N/A')}",
                f"区间 OCID:    {details_data.get('compartment_id', 'N/A')}",
                "-" * 30,
                "自由格式标签:"
            ]
            free_tags = details_data.get('freeform_tags', {})
            lines.extend([f"  {k}: {v}" for k, v in free_tags.items()]) if free_tags else lines.append("  无")
            lines.append("定义格式标签:")
            def_tags = details_data.get('defined_tags', {})
            if def_tags:
                for ns, tags in def_tags.items():
                    lines.append(f"  命名空间: {ns}")
                    lines.extend([f"    {k}: {v}" for k, v in tags.items()])
            else:
                lines.append("  无")

            details_string = "\n".join(lines)

            self.instance_details_text.config(state=tk.NORMAL)
            self.instance_details_text.delete('1.0', tk.END)
            self.instance_details_text.insert('1.0', details_string)
            self.instance_details_text.config(state=tk.DISABLED)
        else:
            self.selected_instance_ocid = None
            self.instance_details_text.config(state=tk.NORMAL)
            self.instance_details_text.delete('1.0', tk.END)
            self.instance_details_text.insert('1.0', "请在上方列表中选择一个实例以查看详情。")
            self.instance_details_text.config(state=tk.DISABLED)

        self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data),
                             selection_valid=is_valid_selection)

    def confirm_and_run_action(self, action_type, dialog_to_close=None):
        if not self.selected_instance_ocid: messagebox.showwarning("未选择实例", "请先在列表中选择一个实例。",
                                                                   parent=self.root); return
        details = self.instance_data[self.selected_instance_ocid];
        instance_name, instance_id = details.get("display_name", "N/A"), details["id"];
        vnic_id = details.get("vnic_id");
        backend_function, args, action_description, confirm_message = None, [], "", "";
        requires_confirmation = True

        action_map = {
            "start": (backend_start_instance, [self.compute_client, instance_id, self.logger], "启动实例",
                      f"确定要启动实例 '{instance_name}' 吗？"),
            "stop": (backend_stop_instance, [self.compute_client, instance_id, self.logger], "关机实例",
                     f"确定要关机实例 '{instance_name}' 吗？"),
            "restart": (backend_restart_instance, [self.compute_client, instance_id, self.logger], "重启实例",
                        f"确定要重启实例 '{instance_name}' 吗？"),
            "terminate": (backend_terminate_instance, [self.compute_client, instance_id, True, self.logger], "终止实例",
                          f"警告：此操作不可逆。\n确定要终止实例 '{instance_name}' 吗？"),
            "assign_ipv6": (
                backend_full_ipv6_setup_and_assign,
                [self.virtual_network_client, vnic_id, instance_name, self.log_ui, self.logger],
                "一键开启IPv6",
                f"此操作将为实例 '{instance_name}' 自动完成所有必要的IPv6网络配置。\n\n确定要继续吗？"),
            "change_ip": (backend_change_public_ip,
                          [self.virtual_network_client, self.compute_client, instance_id, self.oci_config['tenancy'],
                           self.logger],
                          "更换公网IP",
                          f"确定要为实例 '{instance_name}' 更换公网IP吗？\n\n注意：此操作需要实例处于“正在运行(RUNNING)”状态。")
        }
        if action_type in action_map:
            backend_function, args, action_description, confirm_message = action_map[action_type]
        else:
            self.log_ui(f"未知的操作类型: {action_type}", "ERROR");
            return
        if requires_confirmation and not messagebox.askyesno("确认操作", confirm_message,
                                                             parent=self.root): self.log_ui(
            f"操作 '{action_description}' 已被用户取消。", level='INFO'); return
        if backend_function: self.log_ui(f"正在为实例 '{instance_name}' 执行 '{action_description}' 操作...",
                                         level='INFO'); self.toggle_controls(connected=True, profiles_exist=True,
                                                                             selection_valid=False); thread = threading.Thread(
            target=self.run_backend_action, args=(backend_function, args, action_description, dialog_to_close),
            daemon=True); thread.start()

    def run_backend_action(self, backend_func, func_args, action_description, dialog_to_close=None):
        self.logger.info(f"后台线程：开始执行 '{action_description}'...");
        try:
            success, message = backend_func(*func_args);
            self.logger.info(
                f"后台线程：'{action_description}' 执行完成。Success={success}, Message={message}")
        except Exception as e:
            success, message = False, f"后台线程在执行 '{action_description}' 时发生意外错误: {e}";
            self.logger.exception(
                message)
        if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, self.update_gui_after_action, success,
                                                                               message, action_description,
                                                                               dialog_to_close)

    def update_gui_after_action(self, success, message, action_description, dialog_to_close=None):
        is_selection_still_valid = self.selected_instance_ocid in self.instance_data
        if hasattr(self, 'root') and self.root.winfo_exists():
            if success:
                self.log_ui(f"操作 '{action_description}' 成功: {message}", level='INFO');
                if dialog_to_close and dialog_to_close.winfo_exists():
                    dialog_to_close.destroy()
                messagebox.showinfo(
                    "操作成功", message, parent=self.root);
                self.log_ui("将在3秒后自动刷新实例列表...",
                            level='INFO');
                self.root.after(3000,
                                self.refresh_list_thread)
            else:
                self.log_ui(f"操作 '{action_description}' 失败: {message}", level='ERROR');
                messagebox.showerror(
                    "操作失败", message, parent=dialog_to_close or self.root);
                self.toggle_controls(connected=self.is_connected,
                                     profiles_exist=bool(
                                         self.all_profiles_data),
                                     selection_valid=is_selection_still_valid)

    def connect_oci_thread(self):
        if not self.selected_profile_alias: messagebox.showwarning("未选择账号", "请在列表中选择一个要连接的账号。",
                                                                   parent=self.root); return
        profile_config = self.all_profiles_data.get(self.selected_profile_alias)
        if not profile_config: messagebox.showerror("错误", f"找不到别名为 '{self.selected_profile_alias}' 的配置数据。",
                                                    parent=self.root); return
        if self.is_connected:
            if self.selected_profile_alias == self.connected_profile_alias:
                messagebox.showinfo("已连接", f"您当前已经连接到 '{self.selected_profile_alias}'。",
                                    parent=self.root);
                return
            else:
                self.disconnect_oci()
        self.log_ui(f"正在连接账号 '{self.selected_profile_alias}'...", level='INFO');
        self.toggle_controls(False, False, False);
        thread = threading.Thread(target=self.connect_oci_backend, args=(profile_config, self.selected_profile_alias),
                                  daemon=True);
        thread.start()

    def connect_oci_backend(self, profile_config, selected_alias):
        temp_key_file = None
        try:
            sdk_config = profile_config.copy()

            # --- 1. 处理代理配置 ---
            proxy_url = sdk_config.get("proxy", "").strip()
            if not proxy_url:
                if "proxy" in sdk_config:
                    del sdk_config["proxy"]
            else:
                # OCI SDK 不会自动读取这个字段，但我们保留它用于后续注入
                sdk_config["proxy"] = proxy_url
                self.log_ui(f"账号 '{selected_alias}' 将通过代理 {proxy_url} 进行连接...", level='INFO')
                self.logger.info(f"Connecting account '{selected_alias}' using proxy: {proxy_url}")

            # --- 2. 处理私钥文件 ---
            if 'key_content' in sdk_config and sdk_config['key_content']:
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".pem",
                                                 encoding='utf-8') as tf:
                    tf.write(sdk_config['key_content'])
                    temp_key_file = tf.name
                sdk_config['key_file'] = temp_key_file
                self.logger.info(f"已将 key_content 写入临时文件: {temp_key_file}")

            # --- 3. 初始化 Identity 客户端并注入代理 ---
            identity_client_temp = oci.identity.IdentityClient(sdk_config)

            # ✨✨✨ 关键修复：在验证连接前就注入代理 ✨✨✨
            if proxy_url:
                proxies = {'http': proxy_url, 'https': proxy_url}
                if hasattr(identity_client_temp, 'base_client') and hasattr(identity_client_temp.base_client, 'session'):
                    identity_client_temp.base_client.session.proxies = proxies
                    self.logger.info(f"已为 IdentityClient 注入代理: {proxy_url}")

            # 执行认证测试 (此时已走代理)
            user_info = identity_client_temp.get_user(user_id=sdk_config["user"])
            self.logger.info(f"认证成功！用户: {user_info.data.description}")

            # --- 4. 初始化其他客户端并注入代理 ---
            self.oci_config = sdk_config
            self.identity_client = identity_client_temp
            self.compute_client = oci.core.ComputeClient(sdk_config)
            self.virtual_network_client = oci.core.VirtualNetworkClient(sdk_config)
            self.block_storage_client = oci.core.BlockstorageClient(sdk_config)

            # 遍历并注入代理给其余客户端
            if proxy_url:
                proxies = {'http': proxy_url, 'https': proxy_url}
                clients_to_patch = [
                    self.compute_client,
                    self.virtual_network_client,
                    self.block_storage_client
                ]
                for client in clients_to_patch:
                    if hasattr(client, 'base_client') and hasattr(client.base_client, 'session'):
                        client.base_client.session.proxies = proxies
                        self.logger.info(f"已为 {client.__class__.__name__} 注入代理。")

            self.is_connected = True
            self.connected_profile_alias = selected_alias

            # ✨✨✨ [新增] 检查并自动获取注册时间 ✨✨✨
            # 如果内存中没有 registration_date，或者值为 None/空，则启动线程去获取
            current_profile = self.all_profiles_data.get(selected_alias, {})
            if not current_profile.get('registration_date'):
                thread = threading.Thread(
                    target=self.fetch_and_save_tenancy_date,
                    args=(selected_alias, self.identity_client, sdk_config['tenancy']),
                    daemon=True
                )
                thread.start()
            # ✨✨✨ [结束] ✨✨✨

            def succeed_on_main():
                self.connected_alias_var.set(f"当前连接账号: {selected_alias}")
                self.log_ui(f"认证成功！已连接到 '{selected_alias}'。", level='INFO')
                self.last_used_alias = selected_alias
                self.save_settings_to_file()
                # 刷新整个列表以更新颜色/状态
                self.update_account_list()
                self.toggle_controls(connected=True, profiles_exist=True, selection_valid=False)
                self.refresh_list_thread()

            if hasattr(self, 'root') and self.root.winfo_exists():
                self.root.after(0, succeed_on_main)

        except Exception as e:
            self.is_connected = False
            error_msg = f"连接账号 '{selected_alias}' 失败: {e}"
            self.logger.error(error_msg, exc_info=True)

            def fail_on_main():
                messagebox.showerror("连接失败", error_msg, parent=self.root)
                self.log_ui(error_msg, level='ERROR')
                self.toggle_controls(connected=False, profiles_exist=bool(self.all_profiles_data), selection_valid=False)

            if hasattr(self, 'root') and self.root.winfo_exists():
                self.root.after(0, fail_on_main)
        finally:
            if temp_key_file and os.path.exists(temp_key_file):
                try:
                    os.remove(temp_key_file)
                    self.logger.info(f"已清理临时密钥文件: {temp_key_file}")
                except OSError as e:
                    self.logger.error(f"清理临时密钥文件失败: {e}")

    def fetch_and_save_tenancy_date(self, alias, identity_client, tenancy_id):
        """后台线程：获取并保存租户创建时间"""
        try:
            self.logger.info(f"正在后台获取账号 '{alias}' 的注册时间...")
            # 调用 OCI API 获取根区间信息（即租户信息）
            compartment = identity_client.get_compartment(compartment_id=tenancy_id).data
            created_at = compartment.time_created

            # 格式化日期
            date_str = created_at.strftime('%Y-%m-%d')

            # 更新内存数据
            if alias in self.all_profiles_data:
                self.all_profiles_data[alias]['registration_date'] = date_str
                # 保存到文件
                self.save_profiles_to_file()
                self.logger.info(f"成功获取并保存 {alias} 的注册时间: {date_str}")

                # 刷新界面显示
                if hasattr(self, 'root') and self.root.winfo_exists():
                    self.root.after(0, self.update_account_list)
        except Exception as e:
            self.logger.error(f"获取账号 {alias} 的注册时间失败: {e}")

    def disconnect_oci(self):
        if not self.is_connected: return
        self.logger.info(f"正在断开与账号 '{self.connected_profile_alias}' 的连接。");
        self.connected_alias_var.set("当前未连接")

        # 断开时，刷新列表以恢复该账号的普通颜色（奇偶色）
        self.connected_profile_alias = None
        self.update_account_list()

        self.oci_config, self.identity_client, self.compute_client, self.virtual_network_client, self.block_storage_client = None, None, None, None, None;
        self.is_connected = False;
        self.instance_data.clear();
        self.selected_instance_ocid = None
        self.session_subnet_id = None
        try:
            for item in self.instance_treeview.get_children(): self.instance_treeview.delete(item)
        except tk.TclError:
            pass
        self.log_ui("已断开连接。", level='INFO');
        self.toggle_controls(connected=False, profiles_exist=bool(self.all_profiles_data), selection_valid=False)

    def add_profile(self):
        EditProfileDialog(self.root, None, {}, self.handle_edit_profile)

    def edit_profile(self):
        if not self.selected_profile_alias: messagebox.showwarning("未选择", "请在列表中选择要编辑的账号。"); return
        profile_data = self.all_profiles_data.get(self.selected_profile_alias);
        if profile_data: EditProfileDialog(self.root, self.selected_profile_alias, profile_data,
                                           self.handle_edit_profile)

    def handle_edit_profile(self, original_alias, new_alias, new_data):
        # 检查传入的公钥是否为空，如果为空则使用默认值
        if not new_data.get('default_ssh_public_key'):
            new_data['default_ssh_public_key'] = DEFAULT_SSH_KEY

        # 保留现有的代理设置
        existing_proxy = self.all_profiles_data.get(original_alias, {}).get('proxy')
        # 保留现有的注册日期 (如果存在)
        existing_reg_date = self.all_profiles_data.get(original_alias, {}).get('registration_date')

        # 合并新旧数据
        if original_alias is None:  # 这是新添加的账号
            full_new_data = new_data
        else:  # 这是编辑现有账号
            full_new_data = self.all_profiles_data.get(original_alias, {}).copy()
            full_new_data.update(new_data)

        # 确保代理设置不丢失
        if existing_proxy:
            full_new_data['proxy'] = existing_proxy
        # 确保注册日期不丢失
        if existing_reg_date:
            full_new_data['registration_date'] = existing_reg_date

        # 删除旧的子网ID，以便下次连接时重新获取
        if 'default_subnet_ocid' in full_new_data:
            del full_new_data['default_subnet_ocid']

        # 如果别名改变，删除旧的配置
        if original_alias and original_alias != new_alias and original_alias in self.all_profiles_data:
            del self.all_profiles_data[original_alias]

        # 保存新的配置
        self.all_profiles_data[new_alias] = full_new_data
        self.save_profiles_to_file()
        self.update_account_list()
        self.save_profile_order()
        self.log_ui(f"账号 '{new_alias}' 已成功保存。", "INFO")
        messagebox.showinfo("成功", f"账号 '{new_alias}' 已保存。")

    def delete_profile(self):
        if not self.selected_profile_alias: messagebox.showwarning("未选择", "请在列表中选择要删除的账号。"); return
        if messagebox.askyesno("确认删除", f"确定要永久删除账号配置 '{self.selected_profile_alias}' 吗？"):
            if self.is_connected and self.connected_profile_alias == self.selected_profile_alias: self.disconnect_oci()

            del self.all_profiles_data[self.selected_profile_alias];

            self.save_profiles_to_file();
            self.update_account_list();
            self.save_profile_order()

            self.log_ui(f"账号 '{self.selected_profile_alias}' 已被删除。", level='INFO')

    def refresh_list_thread(self):
        if not self.is_connected: return
        self.log_ui(f"正在为账号 '{self.connected_profile_alias}' 获取实例列表...", level='INFO');
        self.toggle_controls(connected=True, profiles_exist=True, selection_valid=False);
        thread = threading.Thread(target=self.refresh_list_backend, daemon=True);
        thread.start()

    def refresh_list_backend(self):
        compartment_id = self.oci_config.get("tenancy");
        instances, message = get_detailed_instances(self.compute_client, self.virtual_network_client,
                                                    self.block_storage_client, compartment_id, self.logger)
        if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, self.update_treeview, instances,
                                                                               message)

    def update_treeview(self, instances, message):
        self.log_ui(message, level='INFO' if instances or "未找到实例" in message else 'ERROR');
        self.selected_instance_ocid = None

        if hasattr(self, 'instance_details_text') and self.instance_details_text.winfo_exists():
            self.instance_details_text.config(state=tk.NORMAL)
            self.instance_details_text.delete('1.0', tk.END)
            self.instance_details_text.insert('1.0', "请在上方列表中选择一个实例以查看详情。")
            self.instance_details_text.config(state=tk.DISABLED)

        try:
            if hasattr(self, 'instance_treeview') and self.instance_treeview.winfo_exists():
                for item in self.instance_treeview.get_children(): self.instance_treeview.delete(item)
                self.instance_data.clear()
                if instances:
                    instances.sort(key=lambda x: x.get('display_name', '').lower())
                    for inst_data in instances:
                        config_str = f"{inst_data.get('ocpus', '?')}c/{inst_data.get('memory_in_gbs', '?')}g/{inst_data.get('boot_volume_size_gb', '?')}g"
                        status = inst_data.get('lifecycle_state', 'UNKNOWN')
                        tree_values = (
                            inst_data.get('display_name', 'N/A'),
                            status,
                            inst_data.get('public_ip', 'N/A'),
                            inst_data.get('ipv6_address', 'N/A'),
                            config_str,
                            inst_data.get('time_created', 'N/A')
                        )
                        self.instance_treeview.insert('', tk.END, iid=inst_data['id'], values=tree_values,
                                                      tags=(status,))
                        self.instance_data[inst_data['id']] = inst_data
                    self.instance_treeview.tag_configure('RUNNING', foreground='green')
                    self.instance_treeview.tag_configure('STOPPED', foreground='red')
                    self.instance_treeview.tag_configure('STARTING', foreground='orange')
                    self.instance_treeview.tag_configure('STOPPING', foreground='orange')
        except tk.TclError as e:
            self.logger.warning(f"更新 Treeview 时出错 (可能在关闭应用时发生): {e}")
        finally:
            if hasattr(self, 'root') and self.root.winfo_exists(): self.toggle_controls(connected=self.is_connected,
                                                                                        profiles_exist=bool(
                                                                                            self.all_profiles_data),
                                                                                        selection_valid=False)

    def show_edit_instance_dialog(self):
        if not self.selected_instance_ocid: messagebox.showwarning("未选择", "请选择一个实例进行编辑。",
                                                                   parent=self.root); return
        details = self.instance_data[self.selected_instance_ocid];
        EditInstanceDialog(self.root, details, self.handle_update_instance)

    def handle_update_instance(self, instance_id, changes, dialog_to_close=None):
        self.log_ui(f"准备更新实例 {instance_id}...", "INFO");
        if 'display_name' in changes:
            thread = threading.Thread(target=self.run_backend_action, args=(
                backend_update_display_name,
                [self.compute_client, instance_id, changes['display_name'], self.logger],
                "更新实例名称", dialog_to_close), daemon=True)
        else:
            thread = threading.Thread(target=self.run_backend_action, args=(
                backend_update_instance_full,
                [self.compute_client, self.block_storage_client, instance_id, changes, self.logger],
                "更新实例配置", dialog_to_close), daemon=True)
        thread.start()

    def show_create_instance_dialog(self):
        CreateInstanceDialog(self.root, self.handle_create_instance)

    def handle_create_instance(self, details):
        subnet_id = self._get_or_choose_subnet()
        if not subnet_id:
            return

        self.log_ui(f"正在提交创建实例 '{details['display_name_prefix']}' 的请求...", "INFO");
        clients = {'compute': self.compute_client, 'identity': self.identity_client,
                   'vnet': self.virtual_network_client};

        thread = threading.Thread(target=self.run_backend_action, args=(
            backend_create_instance, [clients, self.oci_config, details, subnet_id, self.log_ui, self.logger],
            "创建实例"),
                                  daemon=True);
        thread.start()

    def confirm_and_open_firewall(self):
        if not self.is_connected: messagebox.showwarning("未连接", "请先连接账号。", parent=self.root); return

        subnet_id = self._get_or_choose_subnet()
        if not subnet_id:
            return

        if not messagebox.askyesno("确认操作",
                                   f"警告：此操作将修改子网 (...{subnet_id[-8:]}) 关联的安全组规则。\n它会替换所有入站规则，以允许所有IPv4和IPv6流量。\n\n您确定要开放防火墙吗？",
                                   parent=self.root):
            self.log_ui("一键开放防火墙操作已取消。", "INFO");
            return

        args = [self.virtual_network_client, subnet_id, self.logger, self.log_ui]
        thread = threading.Thread(target=self.run_backend_action,
                                  args=(backend_open_firewall_full, args, "一键开放防火墙"), daemon=True)
        thread.start()

    def show_proxy_dialog(self, event=None):
        selected_items = self.account_treeview.selection()
        if not selected_items:
            return
        alias = selected_items[0]
        profile_data = self.all_profiles_data.get(alias, {})
        SetProxyDialog(self.root, alias, profile_data, self.handle_proxy_update)

    def show_cloudflare_settings(self):
        CloudflareSettingsDialog(self.root)

    def handle_proxy_update(self, alias, proxy_url):
        self.all_profiles_data[alias]['proxy'] = proxy_url
        self.save_profiles_to_file()
        if proxy_url:
            msg = f"已为账号 '{alias}' 设置代理: {proxy_url}"
        else:
            msg = f"已清除账号 '{alias}' 的代理设置。"
        self.log_ui(msg, "INFO")
        messagebox.showinfo("代理设置成功", msg, parent=self.root)

    def on_drag_start(self, event):
        item = self.account_treeview.identify_row(event.y)
        if item:
            self.account_treeview.selection_set(item)
            self._drag_data = {"item": item, "moved": False}

    def on_drag_motion(self, event):
        if not hasattr(self, '_drag_data'):
            return
        self._drag_data["moved"] = True
        dest_item = self.account_treeview.identify_row(event.y)
        if dest_item and dest_item != self._drag_data["item"]:
            self.account_treeview.move(self._drag_data["item"], '', self.account_treeview.index(dest_item))

    def on_drag_stop(self, event):
        if hasattr(self, '_drag_data'):
            was_moved = self._drag_data.get("moved", False)
            del self._drag_data
            if was_moved:
                self.save_profile_order()
                # 拖拽结束后，必须刷新斑马纹，否则颜色会乱
                self.refresh_account_colors()

    def save_profile_order(self):
        current_order = self.account_treeview.get_children()
        if list(current_order) != self.profile_order:
            self.profile_order = list(current_order)
            self.save_settings_to_file()
            self.log_ui("账户顺序已保存。", "INFO")


# --- 主程序执行 ---
if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()
    try:
        style = ttk.Style(root)
        style.theme_use('clam')
    except tk.TclError:
        pass

    app = OciInstanceManagerApp(root)


    def center_main_window(window, width, height):
        window.update_idletasks()
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')
        window.deiconify()


    center_main_window(root, 1500, 1050)
    root.mainloop()
    logging.info("--- OCI 应用退出 ---")

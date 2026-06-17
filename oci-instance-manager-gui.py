# -*- coding: utf-8 -*-
# OCI管理工具 - 终极完整版 (V17 - 完整功能版)
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
                              AttachBootVolumeDetails,
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
import random
import paramiko
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
SSH_PROFILES_FILENAME = "ssh_profiles.json"

PROFILES_FILE_PATH = os.path.join(CONFIG_DIR, PROFILES_FILENAME)
SETTINGS_FILE_PATH = os.path.join(CONFIG_DIR, SETTINGS_FILENAME)
LOG_FILE_PATH = os.path.join(CONFIG_DIR, LOG_FILENAME)
CLOUDFLARE_CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, CLOUDFLARE_CONFIG_FILENAME)
SSH_PROFILES_FILE_PATH = os.path.join(CONFIG_DIR, SSH_PROFILES_FILENAME)

# --- 遗留兼容SSH公钥 (仅用于兼容登录通过旧版本创建的实例) ---
LEGACY_DEFAULT_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDuxGi8wfpz+Us1flHLhTFErH0MkejwK68vMomuW1toccSBTl0VK/aTV7zn2KB6B0rWc6cZoK6m02ZW8dieTa4x0CBDl7FxlyqJhOlfyIWJ7/qh3NlEFJ5l/17KeugUYSJxck9rKMsyZgjrPoWQub48CQLFgqxwDNUavAGeJIkxELDTIxPJQNpZOBrAGcQeWNAfwznwOME7lbXPQhPlI26O7gFRA1+9zekwxy3x8/axrr9ygzOLAMgGsK3tM/NF4QHTivrH8Gj8QpkSEVTTEIE2SV2varAgzP3vwwogQ7OSiIW5rr2pdkX9/ZTcVaV9qEDL+GOhcOCkDMbqsF/d/7vt ssh-key-2025-09-27"

LEGACY_DEFAULT_SSH_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7sRovMH6c/lLNX5Ry4UxRKx9DJHo8CuvLzKJrltbaHHEgU5d
FSv2k1e859igegdK1nOnGaCuptNmVvHYnk2uMdAgQ5excZcqiYTpX8iFie/6odzZ
RBSeZf9eynroFGEicXJPayjLMmYI6z6FkLm+PAkCxYKscAzVGrwBniSJMRCw0yMT
yUDaWTgawBnEHljQH8M58DjBO5W1z0IT5SNuju4BUQNfvc3pMMct8fP2sa6/coMz
iwDIBrCt7TPzReEB04r6x/Bo/EKZEhFU0xCBNkldr2qwIMz978MKIEOzkoiFua69
qXZF/f2U3FWlfahAy/hjoXDgpAzG6rBf3f+77QIDAQABAoIBAA7WBQzXH/qjnq9U
1jytxDe+xzv7UQMJyj/fhW753df2joqn70a8GmOU/xFU6sIwwJvkrpkvQv4gtdCc
BHHwF7o52XD5wWlyecH29t1TXPpxZYLRpNQDIZIeG3cil4sbCGqnx+GIgZLz6usn
6y3oxk/kRQs3j5ycX4Piv+/IpP53kU7iLT7FqkE2C/U68KqOXdYdgKgHBpds4M8W
6YX3OOS2omVIATXcMTlTDxwJpXgrS/amK5lba9A7wLKLeIOEAFE5eQ9XHZi4bQRp
jqpQTWpm6cAE0UplzggXKO/lAAV4QZCB14FAuHnHnfaHfYgTMHtUW/B26HgusJDF
elZ6zs0CgYEA93aXmSla4JkbNuUhoGySJyV/z1nlNZoiJx53RTMAkqtzu/gfCe92
SNog+J8eo8uHVgY7QxY2flow8+bxYLYwXnrp0jy5vlPSP5Gkf2mnWBKdI6ut3eYM
4Jb1x+3qcNRQU/vCSeIpFXXfi9jYlE/31tMRS3vZ2BR44vjrXgs0kK8CgYEA9wEF
LZe7Q2LTtElhNNaJnkxExqoCtkmv5LE8uycEywUDtnJ6Y4tXHjzbUJNsghJ54foS
T+pY1JPYZW1Csc5idOzEEYWOpO9ZeHd5hw1Qr3ab71j1tRjFpRrRMTUBawXRdSxq
TsuTI1LdVn3/PqUTRBt53ivF30pXJztID9HkTCMCgYB0jEQl/JYyhamNlyjZN4k2
KrEhZUNQlYFUT0L5MmYordtaQifMNB3PffxdXAPAPRFGcLTkiceshqnblX9Ff0kU
lmsde0A35Z52FhAVehs4nbuomyjOA5U5CaBEQ0dRUI1soHwG9B9JXjSk1sJaR7eA
U/QnSvN0k1/D9lxT9I8TPQKBgQCT8BR93ibWkVZi4KBL2ULLgLqgkirVqwSiYFUT
cqc4QWSb3azX+hjPj3t7oxCWRyKg6foVyzIw/+vXs70Caa4mgbhdFjT9LC3WLRio
fp0Yul1i2VEwigm2fX1Vj32t7+on19ZEI0GZIoRWzVgW2R/U5u/y1RzKQ+g3IxZi
A0BNKQKBgQCshMPapdzBhmbkPbk5/WM/ijiuMxAL3DF0+ffAJgdC9ywJc9kafq6k
grxg2nmKYnT4Zhwfo4gOa/M22wO2psec6gOJvZ/rCLPPppLwo/EExTWai8aMFuw9
ZxUzR6OnxbGE8N2eZpRAHMnxmUJc8e2hZ+Chthnwfo5+bazHnxhm1Q==
-----END RSA PRIVATE KEY-----"""

class GlobalSSHKeyManager:
    def __init__(self, config_dir):
        self.key_file = os.path.join(config_dir, "global_ssh_key.json")
        self.pub_key = ""
        self.priv_key = ""
        self.load_keys()

    def load_keys(self):
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.pub_key = data.get("public_key", "")
                    self.priv_key = data.get("private_key", "")
            except:
                pass
        
        if not self.pub_key or not self.priv_key:
            self.generate_and_save_keys()

    def generate_and_save_keys(self):
        try:
            import paramiko
            import io
            key = paramiko.RSAKey.generate(2048)
            priv_io = io.StringIO()
            key.write_private_key(priv_io)
            self.priv_key = priv_io.getvalue()
            self.pub_key = f"{key.get_name()} {key.get_base64()} oci-manager-global-key"
            self.save_keys()
        except Exception as e:
            logging.error(f"Failed to generate global SSH keys: {e}")

    def save_keys(self):
        try:
            with open(self.key_file, 'w', encoding='utf-8') as f:
                json.dump({"public_key": self.pub_key, "private_key": self.priv_key}, f, indent=4)
        except Exception as e:
            logging.error(f"Failed to save global SSH keys: {e}")

    def update_keys(self, pub_key, priv_key):
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.save_keys()

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
                              "boot_volume_attachment_id": None, "boot_volume_attachments": [],
                              "available_boot_volumes": [],
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
                        boot_volume_infos = []
                        for attachment in boot_vol_attachments:
                            boot_volume_id = attachment.boot_volume_id
                            boot_info = {"attachment_id": attachment.id, "boot_volume_id": boot_volume_id,
                                         "lifecycle_state": getattr(attachment, 'lifecycle_state', 'N/A')}
                            try:
                                boot_vol = block_storage_client.get_boot_volume(boot_volume_id=boot_volume_id).data
                                boot_info.update({"display_name": boot_vol.display_name or "未命名引导卷",
                                                  "size_in_gbs": int(boot_vol.size_in_gbs),
                                                  "vpus_per_gb": boot_vol.vpus_per_gb,
                                                  "boot_volume_state": boot_vol.lifecycle_state})
                            except Exception as bv_err:
                                logger.warning(f"  - 获取引导卷 {boot_volume_id} 详情失败: {bv_err}")
                            boot_volume_infos.append(boot_info)
                        instance_data["boot_volume_attachments"] = boot_volume_infos
                        first_boot = boot_volume_infos[0]
                        instance_data["boot_volume_attachment_id"] = first_boot.get("attachment_id")
                        instance_data["boot_volume_id"] = first_boot.get("boot_volume_id")
                        instance_data["boot_volume_size_gb"] = f"{first_boot.get('size_in_gbs', 'N/A')}"
                        instance_data["vpus_per_gb"] = first_boot.get("vpus_per_gb", "N/A")

                    try:
                        all_ad_attachments = oci.pagination.list_call_get_all_results(
                            compute_client.list_boot_volume_attachments,
                            availability_domain=instance.availability_domain,
                            compartment_id=instance.compartment_id).data
                        all_attached_ids = {a.boot_volume_id for a in all_ad_attachments}
                        all_boot_volumes = oci.pagination.list_call_get_all_results(
                            block_storage_client.list_boot_volumes,
                            availability_domain=instance.availability_domain,
                            compartment_id=instance.compartment_id).data
                        instance_data["available_boot_volumes"] = [
                            {"id": bv.id, "display_name": bv.display_name or "未命名引导卷",
                             "size_in_gbs": int(bv.size_in_gbs), "vpus_per_gb": bv.vpus_per_gb,
                             "lifecycle_state": bv.lifecycle_state, "availability_domain": bv.availability_domain}
                            for bv in all_boot_volumes
                            if bv.id not in all_attached_ids and bv.lifecycle_state == 'AVAILABLE'
                        ]
                    except Exception as list_bv_err:
                        logger.warning(f"  - 获取可附加引导卷列表失败: {list_bv_err}")
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


def backend_detach_boot_volume(compute_client, instance_id, logger):
    try:
        logger.info(f"开始从实例 {instance_id} 分离引导卷...")
        instance = compute_client.get_instance(instance_id).data
        if instance.lifecycle_state != 'STOPPED':
            return False, "错误：分离引导卷前必须先将实例关机。"

        boot_vol_attachments = oci.pagination.list_call_get_all_results(
            compute_client.list_boot_volume_attachments,
            availability_domain=instance.availability_domain,
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        if not boot_vol_attachments:
            return False, "当前实例没有已附加的引导卷。"

        attachment = boot_vol_attachments[0]
        logger.info(f"找到引导卷附件 {attachment.id}，引导卷 {attachment.boot_volume_id}，正在分离...")
        compute_client.detach_boot_volume(boot_volume_attachment_id=attachment.id)
        oci.wait_until(
            compute_client,
            compute_client.get_boot_volume_attachment(attachment.id),
            'lifecycle_state',
            'DETACHED',
            max_wait_seconds=600,
            succeed_on_not_found=True
        )
        return True, f"引导卷已成功分离。\n引导卷 OCID：{attachment.boot_volume_id}\n请保存此 OCID，后续可用于重新附加。"
    except ServiceError as e:
        if e.status == 404:
            return True, "引导卷附件已不存在，视为分离成功。"
        logger.exception(f"分离引导卷失败: {e}")
        return False, f"分离引导卷失败: {e}"
    except Exception as e:
        logger.exception(f"分离引导卷失败: {e}")
        return False, f"分离引导卷失败: {e}"


def backend_attach_boot_volume(compute_client, instance_id, boot_volume_id, logger):
    try:
        boot_volume_id = (boot_volume_id or '').strip()
        if not boot_volume_id:
            return False, "错误：请输入要附加的引导卷 OCID。"

        logger.info(f"开始将引导卷 {boot_volume_id} 附加到实例 {instance_id}...")
        instance = compute_client.get_instance(instance_id).data
        if instance.lifecycle_state != 'STOPPED':
            return False, "错误：附加引导卷前必须先将实例关机。"

        existing_attachments = oci.pagination.list_call_get_all_results(
            compute_client.list_boot_volume_attachments,
            availability_domain=instance.availability_domain,
            compartment_id=instance.compartment_id,
            instance_id=instance.id
        ).data
        if existing_attachments:
            return False, "当前实例已经有引导卷，请先分离现有引导卷后再附加。"

        attach_details = AttachBootVolumeDetails(
            instance_id=instance_id,
            boot_volume_id=boot_volume_id
        )
        attachment = compute_client.attach_boot_volume(attach_details).data
        logger.info(f"附加引导卷请求已发送，附件 OCID: {attachment.id}，等待 ATTACHED...")
        waiter_result = oci.wait_until(
            compute_client,
            compute_client.get_boot_volume_attachment(attachment.id),
            'lifecycle_state',
            'ATTACHED',
            max_wait_seconds=600
        )
        return True, f"引导卷已成功附加。\n附件状态：{waiter_result.data.lifecycle_state}\n请返回主界面启动实例。"
    except Exception as e:
        logger.exception(f"附加引导卷失败: {e}")
        return False, f"附加引导卷失败: {e}"


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


def backend_create_instance(clients, profile_config, details, subnet_id, log_ui_callback, logger, stop_event=None):
    rush_mode = details.get('rush_mode', False)
    rush_interval_max = max(5, min(30, int(details.get('rush_interval', 5))))
    attempt = 0

    compute_client, identity_client, vnet_client = clients['compute'], clients['identity'], clients['vnet'];
    
    tenancy_ocid = profile_config['tenancy']
    ssh_key = profile_config.get('default_ssh_public_key')
    if not ssh_key or not ssh_key.strip():
        ssh_key = details.get('global_ssh_public_key')

    if not ssh_key or not subnet_id:
        return False, "❌ 实例创建失败! \n- 程序内部错误: 账号配置缺少默认SSH公钥或未能获取子网ID。"

    while True:
        if stop_event and stop_event.is_set():
            return False, f"抢机任务已停止（共尝试 {attempt} 次）。"
        attempt += 1
        try:
            if rush_mode:
                log_ui_callback(f"抢机模式第 {attempt} 次尝试创建实例...", 'INFO')

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

            public_ip = "N/A"
            private_ip = "N/A"
            vnic_ocid = "N/A"
            try:
                log_ui_callback("实例运行成功，正在获取IP信息...", 'INFO')
                vnic_attachments = oci.pagination.list_call_get_all_results(compute_client.list_vnic_attachments,
                                                                            compartment_id=tenancy_ocid,
                                                                            instance_id=instance.id).data
                if vnic_attachments:
                    vnic = vnet_client.get_vnic(vnic_attachments[0].vnic_id).data
                    vnic_ocid = vnic.id or "N/A"
                    public_ip = vnic.public_ip or "N/A"
                    private_ip = vnic.private_ip or "N/A"
                else:
                    log_ui_callback("未能获取到VNIC，IP信息暂不可用。", 'WARN')
            except Exception as ip_err:
                log_ui_callback(f"获取实例IP信息时出错: {ip_err}", 'WARN')

            dns_update_msg = ""
            if details.get('auto_bind_domain'):
                log_ui_callback(f"实例运行成功，正在绑定域名...", 'INFO');
                if public_ip and public_ip != "N/A":
                    try:
                        dns_update_msg = _update_cloudflare_dns(instance.display_name, public_ip, 'A', logger)
                    except Exception as ip_err:
                        dns_update_msg = f"绑定域名时出错: {ip_err}"
                else:
                    dns_update_msg = "未能获取到公网IP，跳过域名绑定。"
                log_ui_callback(dns_update_msg, 'INFO')

            msg = (
                f"\U0001f389 实例 '{instance.display_name}' 已成功创建并运行!\n"
                f"- 实例名称: {instance.display_name}\n"
                f"- 实例 OCID: {instance.id}\n"
                f"- 公网 IP: {public_ip}\n"
                f"- 私有 IP: {private_ip}\n"
                f"- VNIC OCID: {vnic_ocid}\n"
                f"- 登陆用户名: ubuntu\n"
                f"- 密码: {instance_password}\n"
                f"- 系统: {details.get('os_name_version', 'N/A')}\n"
                f"- 规格: {shape}\n"
                f"- 磁盘: {details.get('boot_volume_size', 'N/A')} GB\n"
                f"{dns_update_msg}"
            );
            return True, msg
        except ServiceError as e:
            error_code = str(getattr(e, 'code', '') or '')
            error_message = str(getattr(e, 'message', '') or e)
            is_capacity_or_limit_error = (
                    getattr(e, 'status', None) == 429
                    or "TooManyRequests" in error_code
                    or "LimitExceeded" in error_code
                    or "Out of host capacity" in error_message
                    or "capacity" in error_message.lower()
            )
            msg = f"❌ 实例创建失败! \n- 原因: 资源不足或请求过于频繁 ({error_code or getattr(e, 'status', 'Unknown')})，抢机模式会继续尝试。" if is_capacity_or_limit_error else f"❌ 实例创建失败! \n- OCI API 错误: {error_message}";
            if rush_mode:
                wait_seconds = random.randint(5, rush_interval_max)
                log_ui_callback(f"{msg}\n抢机模式将在 {wait_seconds} 秒后继续尝试（随机范围 5-{rush_interval_max} 秒）...", 'WARN')
                if stop_event and stop_event.wait(wait_seconds):
                    return False, f"抢机任务已停止（共尝试 {attempt} 次）。"
                if not stop_event:
                    time.sleep(wait_seconds)
                continue
            return False, msg
        except Exception as e:
            msg = f"❌ 实例创建失败! \n- 程序内部错误: {e}"
            if rush_mode:
                wait_seconds = random.randint(5, rush_interval_max)
                log_ui_callback(f"{msg}\n抢机模式将在 {wait_seconds} 秒后继续尝试（随机范围 5-{rush_interval_max} 秒）...", 'WARN')
                if stop_event and stop_event.wait(wait_seconds):
                    return False, f"抢机任务已停止（共尝试 {attempt} 次）。"
                if not stop_event:
                    time.sleep(wait_seconds)
                continue
            return False, msg


# --- 对话框类 ---
class CreateInstanceDialog(tk.Toplevel):
    def __init__(self, parent, callback, compute_client=None, tenancy=None):
        super().__init__(parent);
        self.transient(parent);
        self.callback = callback;
        self.compute_client = compute_client
        self.tenancy = tenancy
        self.title("创建新实例");
        self.geometry("550x680");
        main_frame = ttk.Frame(self, padding="10");
        main_frame.pack(expand=True, fill=tk.BOTH);

        basic_frame = ttk.Frame(main_frame)
        basic_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(basic_frame, text="实例名称:").grid(row=0, column=0, sticky=tk.W, pady=2);
        self.name_var = tk.StringVar(value="instance");
        ttk.Entry(basic_frame, textvariable=self.name_var).grid(row=0, column=1, sticky=tk.EW, pady=2);

        ttk.Label(basic_frame, text="操作系统:").grid(row=1, column=0, sticky=tk.W, pady=2);
        self.os_var = tk.StringVar(value="Canonical Ubuntu-24.04");
        os_options = ["Canonical Ubuntu-24.04", "Canonical Ubuntu-22.04", "Oracle Linux-9"];
        self.os_combo = ttk.Combobox(basic_frame, textvariable=self.os_var, values=os_options, state="readonly")
        self.os_combo.grid(row=1, column=1, sticky=tk.EW, pady=2);
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

        rush_frame = ttk.Frame(main_frame)
        rush_frame.pack(fill=tk.X, pady=5)
        self.rush_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rush_frame, text="抢机模式（创建失败后不间断重试）",
                        variable=self.rush_mode_var).pack(side=tk.LEFT)
        ttk.Label(rush_frame, text="随机间隔上限(秒):").pack(side=tk.LEFT, padx=(12, 4))
        self.rush_interval_var = tk.IntVar(value=15)
        ttk.Spinbox(rush_frame, from_=5, to=30, textvariable=self.rush_interval_var, width=5).pack(side=tk.LEFT)

        button_frame = ttk.Frame(self, padding=(0, 5, 0, 10));
        button_frame.pack(fill=tk.X);
        ttk.Button(button_frame, text="确认创建", command=self.submit).pack(side=tk.RIGHT, padx=10);
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT);

        self.toggle_flex_options();
        self.after(100, lambda: center_window(self));
        self.grab_set()

        if self.compute_client and self.tenancy:
            self._fetch_latest_ubuntu_versions()

    def _fetch_latest_ubuntu_versions(self):
        def fetch():
            try:
                images = self.compute_client.list_images(
                    compartment_id=self.tenancy,
                    operating_system="Canonical Ubuntu",
                    sort_by="TIMECREATED",
                    sort_order="DESC",
                    limit=50
                ).data
                versions = []
                for img in images:
                    if img.operating_system_version not in versions:
                        versions.append(img.operating_system_version)
                    if len(versions) >= 2:
                        break
                
                if versions:
                    self.after(0, self._update_os_options, versions)
            except Exception as e:
                print(f"获取最新 Ubuntu 版本失败: {e}")

        import threading
        thread = threading.Thread(target=fetch, daemon=True)
        thread.start()

    def _update_os_options(self, ubuntu_versions):
        new_options = [f"Canonical Ubuntu-{v}" for v in ubuntu_versions]
        new_options.append("Oracle Linux-9")
        self.os_combo.config(values=new_options)
        
        if self.os_var.get() not in new_options:
            self.os_var.set(new_options[0])

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
            "auto_bind_domain": self.auto_bind_domain_var.get(),
            "rush_mode": self.rush_mode_var.get(),
            "rush_interval": max(5, min(30, self.rush_interval_var.get()))
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
        self.boot_volume_attachments = instance_details.get('boot_volume_attachments') or []
        self.available_boot_volumes = instance_details.get('available_boot_volumes') or []
        self.boot_attachment_options = {}
        self.available_boot_volume_options = {}
        self.title(f"编辑实例: {instance_details.get('display_name', 'N/A')}");
        self.geometry("900x700");
        self.minsize(820, 660)

        main_frame = ttk.Frame(self, padding=(18, 16));
        main_frame.pack(expand=True, fill=tk.BOTH);
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        ttk.Label(main_frame, text="实例显示名称:").grid(row=0, column=0, sticky=tk.W, pady=(0, 8));
        self.name_var = tk.StringVar(value=instance_details.get('display_name', ''));
        name_frame = ttk.Frame(main_frame);
        name_frame.grid(row=1, column=0, sticky=tk.EW, pady=(0, 16));
        name_frame.columnconfigure(0, weight=1)
        name_frame.columnconfigure(1, minsize=180)
        ttk.Entry(name_frame, textvariable=self.name_var).grid(row=0, column=0, sticky=tk.EW, ipady=3);
        ttk.Button(name_frame, text="保存名称", command=self.save_name).grid(row=0, column=1, sticky=tk.EW,
                                                                               padx=(12, 0));

        ttk.Separator(main_frame, orient='horizontal').grid(row=2, column=0, sticky=tk.EW, pady=(0, 18));

        content_frame = ttk.Frame(main_frame)
        content_frame.grid(row=3, column=0, sticky=tk.NSEW)
        content_frame.columnconfigure(0, weight=1)
        content_frame.rowconfigure(1, weight=1)

        self.flex_frame = ttk.LabelFrame(content_frame, text="CPU与内存 (需先关机)", padding=(16, 14));
        self.flex_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 16));
        for col, weight in ((1, 1), (3, 1), (4, 0)):
            self.flex_frame.columnconfigure(col, weight=weight)

        ttk.Label(self.flex_frame, text="OCPU:").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=4);
        self.ocpu_var = tk.IntVar(value=instance_details.get('ocpus', 1));
        ttk.Spinbox(self.flex_frame, from_=1, to=4, textvariable=self.ocpu_var, width=8).grid(row=0, column=1,
                                                                                              sticky=tk.EW,
                                                                                              padx=(0, 16), pady=4);
        ttk.Label(self.flex_frame, text="内存(GB):").grid(row=0, column=2, sticky=tk.W, padx=(0, 8), pady=4);
        self.memory_var = tk.IntVar(value=instance_details.get('memory_in_gbs', 1));
        ttk.Spinbox(self.flex_frame, from_=1, to=24, textvariable=self.memory_var, width=8).grid(row=0, column=3,
                                                                                                 sticky=tk.EW,
                                                                                                 padx=(0, 16), pady=4);
        ttk.Button(self.flex_frame, text="保存配置", command=self.save_shape).grid(row=0, column=4, sticky=tk.EW,
                                                                                   ipadx=18, pady=4);
        if "Flex" not in instance_details.get('shape', ''): [child.configure(state='disabled') for child in
                                                             self.flex_frame.winfo_children()]

        boot_vol_frame = ttk.LabelFrame(content_frame, text="引导卷 (需先关机)", padding=(16, 14));
        boot_vol_frame.grid(row=1, column=0, sticky=tk.NSEW);
        boot_vol_frame.columnconfigure(1, weight=1)
        boot_vol_frame.columnconfigure(2, minsize=180)
        ttk.Label(boot_vol_frame, text="大小(GB):").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=(4, 12));
        self.size_var = tk.IntVar(value=int(instance_details.get('boot_volume_size_gb', 50)));
        ttk.Spinbox(boot_vol_frame, from_=50, to=500, textvariable=self.size_var, width=8).grid(row=0, column=1,
                                                                                                sticky=tk.EW,
                                                                                                padx=(0, 16),
                                                                                                pady=(4, 12));
        ttk.Button(boot_vol_frame, text="保存大小", command=self.save_size).grid(row=0, column=2, sticky=tk.EW,
                                                                                 pady=(4, 12));
        ttk.Label(boot_vol_frame, text="性能(VPU):").grid(row=1, column=0, sticky=tk.W, padx=(0, 8), pady=(4, 12));
        self.vpu_var = tk.IntVar(value=instance_details.get('vpus_per_gb', 10));
        ttk.Spinbox(boot_vol_frame, from_=10, to=120, increment=10, textvariable=self.vpu_var, width=8).grid(row=1,
                                                                                                             column=1,
                                                                                                             sticky=tk.EW,
                                                                                                             padx=(0, 16),
                                                                                                             pady=(4, 12));
        ttk.Button(boot_vol_frame, text="保存性能", command=self.save_vpu).grid(row=1, column=2, sticky=tk.EW,
                                                                                 pady=(4, 12));

        ttk.Separator(boot_vol_frame, orient='horizontal').grid(row=2, column=0, columnspan=3, sticky=tk.EW,
                                                               pady=(2, 12))

        ttk.Label(boot_vol_frame, text="当前已附加引导卷:").grid(row=3, column=0, sticky=tk.W, padx=(0, 8), pady=(4, 8))
        attached_values = []
        for idx, item in enumerate(self.boot_volume_attachments, 1):
            label = f"{idx}. {item.get('display_name', '未命名')} | {item.get('size_in_gbs', 'N/A')}GB | {item.get('boot_volume_id', '')}"
            attached_values.append(label)
            self.boot_attachment_options[label] = item
        if not attached_values:
            attached_values = ["未检测到已附加引导卷"]
        self.selected_attached_boot_var = tk.StringVar(value=attached_values[0])
        self.attached_boot_combo = ttk.Combobox(boot_vol_frame, textvariable=self.selected_attached_boot_var,
                                               values=attached_values, state="readonly")
        self.attached_boot_combo.grid(row=3, column=1, columnspan=2, sticky=tk.EW, pady=(4, 8))

        ttk.Label(boot_vol_frame, text="可附加已分离引导卷:").grid(row=4, column=0, sticky=tk.W, padx=(0, 8), pady=(4, 8))
        available_values = []
        for idx, item in enumerate(self.available_boot_volumes, 1):
            label = f"{idx}. {item.get('display_name', '未命名')} | {item.get('size_in_gbs', 'N/A')}GB | {item.get('lifecycle_state', 'N/A')} | {item.get('id', '')}"
            available_values.append(label)
            self.available_boot_volume_options[label] = item
        if not available_values:
            available_values = ["当前可用域没有已分离的可附加引导卷"]
        self.selected_available_boot_var = tk.StringVar(value=available_values[0])
        self.available_boot_combo = ttk.Combobox(boot_vol_frame, textvariable=self.selected_available_boot_var,
                                                values=available_values, state="readonly")
        self.available_boot_combo.grid(row=4, column=1, sticky=tk.EW, padx=(0, 16), pady=(4, 8))
        ttk.Button(boot_vol_frame, text="附加所选引导卷", command=self.attach_boot_volume).grid(row=4, column=2,
                                                                                                 sticky=tk.EW,
                                                                                                 pady=(4, 8))

        boot_action_frame = ttk.Frame(boot_vol_frame)
        boot_action_frame.grid(row=5, column=0, columnspan=3, sticky=tk.EW, pady=(6, 0))
        boot_action_frame.columnconfigure(0, weight=1)
        boot_action_frame.columnconfigure(1, weight=1)
        ttk.Button(boot_action_frame, text="复制所选已附加引导卷OCID", command=self.copy_boot_volume_id).grid(
            row=0, column=0, sticky=tk.EW, padx=(0, 8))
        ttk.Button(boot_action_frame, text="分离所选引导卷", command=self.detach_boot_volume,
                   style="Red.TButton").grid(row=0, column=1, sticky=tk.EW)
        ttk.Label(boot_vol_frame, foreground="gray",
                  text="提示：分离/附加前必须先关机；可附加列表只显示同一可用域内已分离且 AVAILABLE 的引导卷。操作成功后请刷新实例列表。").grid(
            row=6, column=0, columnspan=3, sticky=tk.W, pady=(10, 0))

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, sticky=tk.EW, pady=(18, 0))
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, minsize=190)
        button_frame.columnconfigure(2, weight=1)
        ttk.Button(button_frame, text="关闭窗口", command=self.destroy).grid(row=0, column=1, sticky=tk.EW);
        self.after(100, lambda: center_window(self));
        self.grab_set()

    def _get_selected_attached_boot_volume(self):
        return self.boot_attachment_options.get(self.selected_attached_boot_var.get())

    def _get_selected_available_boot_volume(self):
        return self.available_boot_volume_options.get(self.selected_available_boot_var.get())

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

    def copy_boot_volume_id(self):
        selected = self._get_selected_attached_boot_volume()
        if not selected:
            messagebox.showwarning("无引导卷OCID", "当前未选择已附加的引导卷。", parent=self)
            return
        boot_volume_id = selected.get('boot_volume_id')
        self.clipboard_clear()
        self.clipboard_append(boot_volume_id)
        messagebox.showinfo("已复制", "所选引导卷OCID已复制到剪贴板。", parent=self)

    def detach_boot_volume(self):
        selected = self._get_selected_attached_boot_volume()
        if not selected:
            messagebox.showwarning("无引导卷", "当前实例未检测到或未选择已附加的引导卷。", parent=self)
            return
        boot_volume_id = selected.get('boot_volume_id')
        attachment_id = selected.get('attachment_id')
        if not messagebox.askyesno(
                "确认分离引导卷",
                "此操作会从已关机实例上分离你选中的引导卷。\n\n"
                f"引导卷名称：{selected.get('display_name', '未命名')}\n"
                f"引导卷OCID：\n{boot_volume_id}\n\n确定继续吗？",
                parent=self):
            return
        self.callback(self.instance_id, {'detach_boot_volume_attachment_id': attachment_id}, dialog_to_close=self)
        messagebox.showinfo("请求已提交", "分离引导卷请求已提交，请稍后刷新列表。", parent=self.master)

    def attach_boot_volume(self):
        selected = self._get_selected_available_boot_volume()
        if not selected:
            messagebox.showerror("未选择", "当前没有可附加的已分离引导卷，请先刷新实例列表确认。", parent=self)
            return
        boot_volume_id = selected.get('id')
        if not messagebox.askyesno(
                "确认附加引导卷",
                "此操作会把所选已分离引导卷附加到当前已关机实例。\n\n"
                f"引导卷名称：{selected.get('display_name', '未命名')}\n"
                f"大小：{selected.get('size_in_gbs', 'N/A')}GB\n"
                f"引导卷OCID：\n{boot_volume_id}\n\n确定继续吗？",
                parent=self):
            return
        self.callback(self.instance_id, {'attach_boot_volume_id': boot_volume_id}, dialog_to_close=self)
        messagebox.showinfo("请求已提交", "附加引导卷请求已提交，请稍后刷新列表。", parent=self.master)

    def attach_boot_volume(self):
        boot_volume_id = self.attach_boot_volume_var.get().strip()
        if not boot_volume_id:
            messagebox.showerror("输入错误", "请输入要附加的引导卷OCID。", parent=self)
            return
        if not messagebox.askyesno(
                "确认附加引导卷",
                "此操作会把指定引导卷附加到当前已关机实例。\n\n"
                f"引导卷OCID：\n{boot_volume_id}\n\n确定继续吗？",
                parent=self):
            return
        self.callback(self.instance_id, {'attach_boot_volume_id': boot_volume_id}, dialog_to_close=self)
        messagebox.showinfo("请求已提交", "附加引导卷请求已提交，请稍后刷新列表。", parent=self.master)


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

        ttk.Label(main_frame, text="账号专用 SSH 公钥 (留空将使用全局默认密钥):").pack(anchor=tk.W);
        self.ssh_text = tk.Text(main_frame, height=4);
        self.ssh_text.insert('1.0', profile_data.get('default_ssh_public_key', ''));
        self.ssh_text.pack(fill=tk.BOTH, expand=True, pady=(0, 2));
        ssh_info_label = ttk.Label(main_frame, foreground="gray",
                                   text="此处填写您自己生成的SSH公钥。如果留空，则在创建实例时自动注入本程序的全局默认公钥。")
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


class RegionSelectDialog(tk.Toplevel):
    def __init__(self, parent, subscribed_regions, unsubscribed_regions, current_region, change_callback, subscribe_callback):
        super().__init__(parent)
        self.transient(parent)
        self.title("区域管理")
        self.geometry("450x520")
        self.change_callback = change_callback
        self.subscribe_callback = subscribe_callback
        self.selected_region = current_region
        self.unsubscribed_regions = unsubscribed_regions

        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(expand=True, fill=tk.BOTH)
        
        if len(subscribed_regions) > 1:
            switch_frame = ttk.Frame(notebook, padding="10")
            notebook.add(switch_frame, text="已订阅区域")
            ttk.Label(switch_frame, text=f"当前区域: {current_region}\n点击下方按钮切换区域：").pack(anchor=tk.W, pady=5)
            
            switch_list_frame = ttk.Frame(switch_frame)
            switch_list_frame.pack(expand=True, fill=tk.BOTH, pady=10)
            for r in subscribed_regions:
                btn_text = f"{r} (当前)" if r == current_region else r
                btn = ttk.Button(switch_list_frame, text=btn_text, command=lambda reg=r: self.on_switch(reg))
                btn.pack(expand=True, fill=tk.BOTH, pady=6)

        sub_frame = ttk.Frame(notebook, padding="10")
        notebook.add(sub_frame, text="订阅新区域")
        
        ttk.Label(sub_frame, text="点击下方一个区域进行订阅 (需要账号配额支持)：").pack(anchor=tk.W, pady=5)
        
        sub_list_frame = ttk.Frame(sub_frame)
        sub_list_frame.pack(expand=True, fill=tk.BOTH)
        
        canvas = tk.Canvas(sub_list_frame, borderwidth=0, highlightthickness=0)
        try:
            if hasattr(parent, 'theme_colors'):
                canvas.configure(bg=parent.theme_colors["bg"])
        except:
            pass
            
        scrollbar = ttk.Scrollbar(sub_list_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        
        def _configure_canvas(event):
            canvas.itemconfigure(canvas_window, width=event.width)
        canvas.bind('<Configure>', _configure_canvas)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        canvas.configure(yscrollincrement=1)
        def _on_mousewheel(event):
            if not canvas.winfo_exists(): return
            if sys.platform == 'darwin':
                canvas.yview_scroll(int(-1 * event.delta), "units")
            else:
                if hasattr(event, 'num') and event.num == 4:
                    canvas.yview_scroll(-30, "units")
                elif hasattr(event, 'num') and event.num == 5:
                    canvas.yview_scroll(30, "units")
                else:
                    direction = -1 if event.delta > 0 else 1
                    canvas.yview_scroll(direction * 30, "units")

        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)

        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)
        
        scrollable_frame.columnconfigure(0, weight=1)
        
        for i, r in enumerate(unsubscribed_regions):
            btn = ttk.Button(scrollable_frame, text=f"{r.name} ({r.key})", command=lambda reg=r: self.on_subscribe(reg))
            btn.grid(row=i, column=0, sticky="nsew", padx=4, pady=4)

        def on_close():
            _unbind_mousewheel(None)
            self.destroy()

        self.protocol("WM_DELETE_WINDOW", on_close)
        ttk.Button(main_frame, text="关闭窗口", command=on_close).pack(pady=(10, 0))

        self.after(100, lambda: center_window(self))
        self.grab_set()

    def on_switch(self, region):
        self.selected_region = region
        self.change_callback(self.selected_region)
        self.destroy()
        
    def on_subscribe(self, region):
        if messagebox.askyesno("确认订阅", f"确定要订阅区域 {region.name} ({region.key}) 吗？\n如果账号没有足够配额，订阅将会失败。", parent=self):
            self.subscribe_callback(region.name, region.key)
            self.destroy()


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


class GlobalSSHKeyDialog(tk.Toplevel):
    def __init__(self, parent, key_manager):
        super().__init__(parent)
        self.transient(parent)
        self.title("全局默认 SSH 密钥设置")
        self.geometry("600x500")
        self.key_manager = key_manager
        
        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="全局默认 SSH 公钥 (自动注入到新实例):").pack(anchor=tk.W)
        self.pub_text = scrolledtext.ScrolledText(main_frame, height=5, wrap=tk.WORD)
        self.pub_text.insert("1.0", self.key_manager.pub_key)
        self.pub_text.pack(fill=tk.X, pady=(2, 10))
        
        ttk.Label(main_frame, text="全局默认 SSH 私钥 (用于自动免密登录):").pack(anchor=tk.W)
        self.priv_text = scrolledtext.ScrolledText(main_frame, height=10, wrap=tk.WORD)
        self.priv_text.insert("1.0", self.key_manager.priv_key)
        self.priv_text.pack(fill=tk.BOTH, expand=True, pady=(2, 10))
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="一键生成新密钥对", command=self.generate_new).pack(side=tk.LEFT)
        ttk.Button(btn_frame, text="保存设置", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        
        self.after(100, lambda: center_window(self))
        self.grab_set()

    def generate_new(self):
        if messagebox.askyesno("确认生成", "生成新密钥对将覆盖当前文本框中的内容。如果您之前的实例使用了旧密钥，您可能需要手动保留旧私钥以便连接老实例。\n\n确定要生成新密钥对吗？", parent=self):
            try:
                import paramiko
                import io
                key = paramiko.RSAKey.generate(2048)
                priv_io = io.StringIO()
                key.write_private_key(priv_io)
                priv_pem = priv_io.getvalue()
                pub_ssh = f"{key.get_name()} {key.get_base64()} oci-manager-global-key"
                
                self.pub_text.delete("1.0", tk.END)
                self.pub_text.insert("1.0", pub_ssh)
                
                self.priv_text.delete("1.0", tk.END)
                self.priv_text.insert("1.0", priv_pem)
            except Exception as e:
                messagebox.showerror("生成失败", f"生成密钥失败: {e}", parent=self)

    def save(self):
        pub = self.pub_text.get("1.0", tk.END).strip()
        priv = self.priv_text.get("1.0", tk.END).strip()
        if not pub or not priv:
            messagebox.showwarning("内容不完整", "公钥和私钥均不能为空。", parent=self)
            return
        
        self.key_manager.update_keys(pub, priv)
        messagebox.showinfo("成功", "全局 SSH 密钥已保存。", parent=self)
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


class SSHConfigDialog(tk.Toplevel):
    def __init__(self, parent, instance_id, public_ip, callback, global_key_manager=None):
        super().__init__(parent)
        self.transient(parent)
        self.title("SSH 连接设置")
        self.geometry("480x430")
        self.instance_id = instance_id
        self.callback = callback
        self.global_key_manager = global_key_manager

        main_frame = ttk.Frame(self, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text=f"正在配置目标 IP: {public_ip}", font=("PingFang SC", 10, "bold")).pack(anchor=tk.W, pady=(0, 10))

        user_frame = ttk.Frame(main_frame)
        user_frame.pack(fill=tk.X, pady=5)
        ttk.Label(user_frame, text="登录用户名:").pack(side=tk.LEFT)
        self.user_var = tk.StringVar(value="ubuntu")
        ttk.Entry(user_frame, textvariable=self.user_var, width=15).pack(side=tk.LEFT, padx=10)

        ttk.Label(main_frame, text="认证方式:").pack(anchor=tk.W, pady=(10, 5))
        self.auth_mode_var = tk.StringVar(value="global_key")
        
        auth_frame = ttk.Frame(main_frame)
        auth_frame.pack(fill=tk.X, pady=2)
        ttk.Radiobutton(auth_frame, text="全局密钥", variable=self.auth_mode_var, value="global_key", command=self.toggle_auth).grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Radiobutton(auth_frame, text="自定义密钥", variable=self.auth_mode_var, value="key", command=self.toggle_auth).grid(row=0, column=1, sticky=tk.W, padx=10, pady=2)
        ttk.Radiobutton(auth_frame, text="密码认证", variable=self.auth_mode_var, value="password", command=self.toggle_auth).grid(row=0, column=2, sticky=tk.W, padx=10, pady=2)

        self.cred_frame = ttk.Frame(main_frame)
        self.cred_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 5))
        
        self.password_frame = ttk.Frame(self.cred_frame)
        ttk.Label(self.password_frame, text="登录密码:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(self.password_frame, textvariable=self.password_var, show="*").pack(fill=tk.X, pady=2)
        
        self.key_frame = ttk.Frame(self.cred_frame)
        ttk.Label(self.key_frame, text="私钥内容 (直接粘贴):").pack(anchor=tk.W)
        self.key_text = scrolledtext.ScrolledText(self.key_frame, height=6, wrap=tk.WORD)
        self.key_text.pack(fill=tk.BOTH, expand=True, pady=2)
        
        self.toggle_auth()

        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="保存并连接", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)

        self.after(100, lambda: center_window(self))
        self.grab_set()

    def toggle_auth(self):
        self.password_frame.pack_forget()
        self.key_frame.pack_forget()
        
        if self.auth_mode_var.get() == "password":
            self.password_frame.pack(fill=tk.X)
        elif self.auth_mode_var.get() == "key":
            self.key_frame.pack(fill=tk.BOTH, expand=True)

    def save(self):
        config = {
            "user": self.user_var.get().strip(),
            "auth_mode": "key"
        }
        mode = self.auth_mode_var.get()
        if mode == "password":
            config["auth_mode"] = "password"
            config["password"] = self.password_var.get()
        elif mode == "global_key":
            config["key"] = self.global_key_manager.priv_key if self.global_key_manager else ""
        else:
            config["key"] = self.key_text.get("1.0", tk.END).strip()
            
        self.callback(self.instance_id, config)
        self.destroy()


class SSHTerminalFrame(ttk.Frame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.channel = None
        self.ssh_client = None
        self.on_close_callback = None
        
        self.text = tk.Text(self, bg="#1e1e1e", fg="#d4d4d4", font=("Menlo", 10), insertbackground="white", bd=0, highlightthickness=0)
        self.text.pack(fill=tk.BOTH, expand=True)
        
        self.disconnect_icon = tk.Label(self.text, text="🔗", fg="#16a34a", cursor="hand2", font=("Segoe UI Symbol", 18), bg="#1e1e1e")
        self.disconnect_icon.place(relx=1.0, x=-12, y=10, anchor="ne")
        self.disconnect_icon.bind("<Button-1>", lambda e: self.close_terminal())
        self.disconnect_tooltip = None
        self.disconnect_icon.bind("<Enter>", self.show_tooltip)
        self.disconnect_icon.bind("<Leave>", self.hide_tooltip)
        
        self.text.bind("<Key>", self.on_key_press)
        self.text.bind("<Up>", lambda e: "break")
        self.text.bind("<Down>", lambda e: "break")
        self.text.bind("<Left>", lambda e: "break")
        self.text.bind("<Right>", lambda e: "break")
        
        self.text.bind("<<Copy>>", self.on_copy)
        self.text.bind("<<Paste>>", self.on_paste)
        
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="复制", command=self.on_copy)
        self.context_menu.add_command(label="粘贴", command=self.on_paste)
        
        if sys.platform == "darwin":
            self.text.bind("<Button-2>", self.show_context_menu)
            self.text.bind("<Control-Button-1>", self.show_context_menu)
        else:
            self.text.bind("<Button-3>", self.show_context_menu)

        self.ansi_escape = re.compile(r'\x1B(?:\[[0-?]*[ -/]*[@-~]|\][0-9]+;.*?(?:\x07|\x1B\\)|[@-Z\\-_])')

    def _parse_key(self, key_str):
        import io
        import paramiko
        try:
            return paramiko.RSAKey.from_private_key(io.StringIO(key_str))
        except:
            try:
                return paramiko.Ed25519Key.from_private_key(io.StringIO(key_str))
            except:
                try:
                    return paramiko.ECDSAKey.from_private_key(io.StringIO(key_str))
                except:
                    raise Exception("无法解析私钥格式。")

    def show_tooltip(self, event=None):
        if self.disconnect_tooltip is None or not self.disconnect_tooltip.winfo_exists():
            self.disconnect_tooltip = tk.Toplevel(self)
            self.disconnect_tooltip.withdraw()
            self.disconnect_tooltip.overrideredirect(True)
            self.disconnect_tooltip.attributes("-topmost", True)
            tk.Label(self.disconnect_tooltip, text="断开连接并返回", bg="#111827", fg="#ffffff", padx=8, pady=4,
                     font=("Microsoft YaHei UI", 10), relief=tk.SOLID, bd=1).pack()
        
        x = event.x_root + 12
        y = event.y_root + 16
        self.disconnect_tooltip.geometry(f"+{x}+{y}")
        self.disconnect_tooltip.deiconify()
        self.disconnect_tooltip.lift()

    def hide_tooltip(self, event=None):
        if self.disconnect_tooltip is not None and self.disconnect_tooltip.winfo_exists():
            self.disconnect_tooltip.withdraw()

    def close_terminal(self):
        self.hide_tooltip()
        self.disconnect()
        self.pack_forget()
        if self.on_close_callback:
            self.on_close_callback()
            
    def disconnect(self):
        if self.channel:
            self.channel.close()
        if self.ssh_client:
            self.ssh_client.close()
        self.channel = None
        self.ssh_client = None
        if hasattr(self, 'on_disconnect_callback') and self.on_disconnect_callback:
            self.on_disconnect_callback()
        
    def cancel_motd_filter(self):
        if getattr(self, 'filtering_motd', False):
            self.filtering_motd = False
            self.text.insert(tk.END, self.motd_buffer)
            self.text.see(tk.END)

    def connect(self, ip, config):
        self.disconnect()
        self.current_ip = ip
        self.current_user = config.get("user", "ubuntu")
        self.filtering_motd = True
        self.motd_buffer = ""
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, f"正在连接到 {ip}...\n")
        self.motd_timeout_id = self.text.after(30000, self.cancel_motd_filter)
        
        def _connect():
            try:
                self.ssh_client = paramiko.SSHClient()
                self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                auth_mode = config.get("auth_mode")
                if auth_mode == "password":
                    self.ssh_client.connect(ip, username=config.get("user"), password=config.get("password"), timeout=10)
                elif auth_mode == "auto_keys":
                    keys = config.get("keys", [])
                    connected = False
                    last_err = None
                    for key_str in keys:
                        if not key_str: continue
                        try:
                            pkey = self._parse_key(key_str)
                            self.ssh_client.connect(ip, username=config.get("user"), pkey=pkey, timeout=10)
                            connected = True
                            
                            config["auth_mode"] = "key"
                            config["key"] = key_str
                            if hasattr(self, 'on_auto_connect_success_callback') and self.on_auto_connect_success_callback:
                                self.text.after(0, lambda c=config: self.on_auto_connect_success_callback(c))
                            break
                        except paramiko.AuthenticationException as e:
                            last_err = e
                            continue
                        except Exception as e:
                            last_err = e
                            continue
                    if not connected:
                        raise last_err or Exception("所有自动尝试的私钥均认证失败。")
                else:
                    pkey = self._parse_key(config.get("key", ""))
                    self.ssh_client.connect(ip, username=config.get("user"), pkey=pkey, timeout=10)
                
                self.channel = self.ssh_client.invoke_shell(term='xterm', width=160, height=40)
                self.channel.settimeout(0.0)
                
                if hasattr(self, 'on_connect_success_callback') and self.on_connect_success_callback:
                    self.text.after(0, self.on_connect_success_callback)
                
                threading.Thread(target=self.receive_loop, daemon=True).start()
                
            except Exception as e:
                err_msg = str(e)
                self.text.after(0, lambda: self.text.insert(tk.END, f"\n连接失败: {err_msg}\n"))
                if hasattr(self, 'on_connect_failed_callback') and self.on_connect_failed_callback:
                    self.text.after(0, lambda: self.on_connect_failed_callback(err_msg))
                
        threading.Thread(target=_connect, daemon=True).start()
        
    def receive_loop(self):
        import select
        while self.channel and not self.channel.closed:
            try:
                r, _, _ = select.select([self.channel], [], [], 0.5)
                if r:
                    data = self.channel.recv(4096)
                    if not data:
                        break
                    text = data.decode('utf-8', errors='replace')
                    # 转换常见的 ANSI 左移光标指令为退格，防止被正则表达式清除导致无法连续删除
                    # 使用正则匹配带参数的光标移动指令，如 \x1b[1D
                    text = re.sub(r'\x1b\[\d*D', '\b', text)
                    text = re.sub(r'\x1b\[\d*K', '', text)
                    clean_text = self.ansi_escape.sub('', text)
                    self.text.after(0, self.append_text, clean_text)
            except Exception as e:
                break
        
        if hasattr(self, 'on_disconnect_callback') and self.on_disconnect_callback:
            self.text.after(0, self.on_disconnect_callback)
        
    def append_text(self, text):
        if getattr(self, 'filtering_motd', False):
            for char in text:
                if char == '\x08' or char == '\b':
                    if self.motd_buffer:
                        self.motd_buffer = self.motd_buffer[:-1]
                elif char == '\r':
                    pass
                elif ord(char) < 32 and char not in ('\n', '\t'):
                    pass
                else:
                    self.motd_buffer += char
            
            user = getattr(self, 'current_user', 'ubuntu')
            # 匹配常见提示符，如 ubuntu@hostname:~$ 或 root@hostname:/# 
            prompt_match = re.search(fr'({user}@[a-zA-Z0-9_.-]+:[^\n]*?[\$#]\s*)$', self.motd_buffer)
            if prompt_match:
                self.filtering_motd = False
                if hasattr(self, 'motd_timeout_id'):
                    self.text.after_cancel(self.motd_timeout_id)
                self.text.delete("1.0", tk.END)
                self.text.insert(tk.END, prompt_match.group(1))
            elif len(self.motd_buffer) > 30000:
                self.cancel_motd_filter()
            return

        clean_text = ""
        for char in text:
            if char == '\x08' or char == '\b':
                if clean_text:
                    clean_text = clean_text[:-1]
                else:
                    self.text.delete("end-2c")
            elif char == '\r':
                pass
            elif ord(char) < 32 and char not in ('\n', '\t'):
                pass
            else:
                clean_text += char
        if clean_text:
            self.text.insert(tk.END, clean_text)
        self.text.see(tk.END)
        
    def show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def on_copy(self, event=None):
        try:
            selected_text = self.text.get(tk.SEL_FIRST, tk.SEL_LAST)
            self.clipboard_clear()
            self.clipboard_append(selected_text)
        except tk.TclError:
            pass
        return "break"

    def on_paste(self, event=None):
        if self.channel and not self.channel.closed:
            try:
                clipboard_data = self.clipboard_get()
                if clipboard_data:
                    clipboard_data = clipboard_data.replace('\r\n', '\r').replace('\n', '\r')
                    self.channel.send(clipboard_data)
            except tk.TclError:
                pass
        return "break"

    def on_key_press(self, event):
        if not self.channel or self.channel.closed:
            return "break"
            
        if event.keysym in ("Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R", "Meta_L", "Meta_R", "Super_L", "Super_R"):
            return "break"

        is_ctrl = (event.state & 0x0004) != 0
        is_cmd = (event.state & 0x0008) != 0 or (event.state & 0x20000) != 0

        # 处理复制粘贴快捷键
        if is_cmd and event.keysym.lower() == 'c':
            self.on_copy()
            return "break"
        if is_cmd and event.keysym.lower() == 'v':
            self.on_paste()
            return "break"

        # 处理终端中常见的 Ctrl 快捷键
        if is_ctrl:
            if event.keysym.lower() == 'c':
                self.channel.send('\x03')
                return "break"
            if event.keysym.lower() == 'd':
                self.channel.send('\x04')
                return "break"
            if event.keysym.lower() == 'z':
                self.channel.send('\x1a')
                return "break"
            if event.keysym.lower() == 'l':
                self.channel.send('\x0c')
                return "break"
            if event.keysym.lower() == 'v':
                self.on_paste()
                return "break"
            
        if event.keysym in ("BackSpace", "Delete"):
            self.channel.send("\x7f")
            return "break"
            
        if event.keysym == "Return":
            self.channel.send("\r")
            return "break"
            
        if event.char:
            self.channel.send(event.char)
            
        return "break"


class IAMManagerWindow(tk.Toplevel):
    def __init__(self, parent, identity_client, tenancy_ocid, logger):
        super().__init__(parent)
        self.transient(parent)
        self.title("IAM 身份与用户安全管理")
        self.geometry("900x500")
        self.identity_client = identity_client
        self.tenancy_ocid = tenancy_ocid
        self.logger = logger
        
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # 顶部工具栏
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(toolbar, text="刷新列表", command=self.refresh_users).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(toolbar, text="新建用户", command=self.create_user).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(toolbar, text="重置登录密码", command=self.reset_password).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(toolbar, text="强制清除 2FA", command=self.clear_2fa).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(toolbar, text="更新邮箱", command=self.update_email).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        
        # 用户列表 (隐藏描述和OCID列以优化显示，但保留数据用于逻辑操作)
        columns = ('name', 'description', 'email', 'state', 'created', 'id')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', displaycolumns=('name', 'email', 'state', 'created'))
        self.tree.heading('name', text='用户名')
        self.tree.heading('email', text='邮箱')
        self.tree.heading('state', text='状态')
        self.tree.heading('created', text='创建时间')
        
        self.tree.column('name', width=150, anchor=tk.CENTER)
        self.tree.column('email', width=250, anchor=tk.CENTER)
        self.tree.column('state', width=100, anchor=tk.CENTER)
        self.tree.column('created', width=200, anchor=tk.CENTER)
        
        vsb = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        
        self.tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.after(100, lambda: center_window(self))
        self.grab_set()
        
        # 初次加载
        threading.Thread(target=self.refresh_users_backend, daemon=True).start()

    def _get_selected_user_id(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("提示", "请先在列表中选择一个用户", parent=self)
            return None, None
        item = self.tree.item(selection[0])
        return item['values'][0], item['values'][5] # name, id

    def refresh_users(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        threading.Thread(target=self.refresh_users_backend, daemon=True).start()

    def refresh_users_backend(self):
        try:
            users = oci.pagination.list_call_get_all_results(
                self.identity_client.list_users, 
                compartment_id=self.tenancy_ocid
            ).data
            
            self.after(0, self.update_tree, users)
        except Exception as e:
            self.logger.error(f"获取用户列表失败: {e}", exc_info=True)
            self.after(0, lambda: messagebox.showerror("错误", f"获取用户列表失败:\n{e}", parent=self))
            
    def update_tree(self, users):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for u in users:
            created = u.time_created.strftime('%Y-%m-%d %H:%M:%S') if u.time_created else 'N/A'
            self.tree.insert('', tk.END, values=(
                u.name, 
                u.description or "无", 
                u.email or "未绑定", 
                u.lifecycle_state, 
                created, 
                u.id
            ))
            
    def create_user(self):
        dialog = tk.Toplevel(self)
        dialog.transient(self)
        dialog.title("新建用户")
        dialog.geometry("350x250")
        
        ttk.Label(dialog, text="用户名:").pack(anchor=tk.W, padx=10, pady=(10, 0))
        name_var = tk.StringVar()
        name_entry = ttk.Entry(dialog, textvariable=name_var)
        name_entry.pack(fill=tk.X, padx=10, pady=2)
        
        ttk.Label(dialog, text="描述:").pack(anchor=tk.W, padx=10, pady=(5, 0))
        desc_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=desc_var).pack(fill=tk.X, padx=10, pady=2)
        
        ttk.Label(dialog, text="邮箱 (可选):").pack(anchor=tk.W, padx=10, pady=(5, 0))
        email_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=email_var).pack(fill=tk.X, padx=10, pady=2)
        
        def on_submit():
            name = name_var.get().strip()
            if not name:
                messagebox.showwarning("错误", "用户名不能为空", parent=dialog)
                return
            
            try:
                details = oci.identity.models.CreateUserDetails(
                    compartment_id=self.tenancy_ocid,
                    name=name,
                    description=desc_var.get().strip() or "Created via GUI",
                    email=email_var.get().strip() or None
                )
                self.identity_client.create_user(details)
                messagebox.showinfo("成功", f"用户 '{name}' 创建成功！", parent=dialog)
                dialog.destroy()
                self.refresh_users()
            except Exception as e:
                messagebox.showerror("错误", f"创建失败:\n{e}", parent=dialog)
                
        ttk.Button(dialog, text="创建", command=on_submit).pack(pady=15)
        center_window(dialog)
        self.grab_release()
        dialog.grab_set()
        name_entry.focus_set()
        self.wait_window(dialog)
        self.grab_set()
        
    def reset_password(self):
        name, user_id = self._get_selected_user_id()
        if not user_id: return
        
        if messagebox.askyesno("确认", f"确定要重置用户 '{name}' 的登录密码吗？", parent=self):
            try:
                res = self.identity_client.create_or_reset_ui_password(user_id).data
                msg = f"密码重置成功！\n请务必妥善保存以下一次性密码:\n\n{res.password}"
                
                pw_dialog = tk.Toplevel(self)
                pw_dialog.transient(self)
                pw_dialog.title("新密码生成成功")
                pw_dialog.geometry("400x200")
                ttk.Label(pw_dialog, text="密码重置成功！请务必妥善保存生成的一次性密码：", padding=10).pack()
                pw_text = tk.Text(pw_dialog, height=2, font=("Menlo", 12))
                pw_text.pack(padx=10, fill=tk.X)
                pw_text.insert("1.0", res.password)
                pw_text.config(state=tk.DISABLED)
                ttk.Button(pw_dialog, text="关闭", command=pw_dialog.destroy).pack(pady=10)
                center_window(pw_dialog)
                self.grab_release()
                pw_dialog.grab_set()
                pw_dialog.focus_set()
                self.wait_window(pw_dialog)
                self.grab_set()
                
            except ServiceError as e:
                if "IdentityDomains" in str(e) or e.status == 404:
                    messagebox.showerror("不支持", "操作失败: 甲骨文已将您的租户迁移至新型 Identity Domains，传统 IAM 接口不兼容此操作。", parent=self)
                else:
                    messagebox.showerror("错误", f"重置失败:\n{e.message}", parent=self)
            except Exception as e:
                messagebox.showerror("错误", f"重置失败:\n{e}", parent=self)

    def clear_2fa(self):
        name, user_id = self._get_selected_user_id()
        if not user_id: return
        
        if messagebox.askyesno("确认", f"确定要清除用户 '{name}' 的所有 2FA 设备绑定吗？", parent=self):
            try:
                devices = oci.pagination.list_call_get_all_results(
                    self.identity_client.list_mfa_totp_devices, 
                    user_id=user_id
                ).data
                if not devices:
                    messagebox.showinfo("提示", "该用户当前没有绑定任何 2FA 验证器。", parent=self)
                    return
                    
                for d in devices:
                    self.identity_client.delete_mfa_totp_device(user_id=user_id, mfa_totp_device_id=d.id)
                messagebox.showinfo("成功", f"成功清除了 {len(devices)} 个 2FA 绑定的设备！用户下次登录将无需验证码。", parent=self)
            except ServiceError as e:
                if "IdentityDomains" in str(e) or e.status == 404:
                    messagebox.showerror("不支持", "操作失败: 甲骨文已将您的租户迁移至新型 Identity Domains，传统 IAM 接口不兼容此操作。", parent=self)
                else:
                    messagebox.showerror("错误", f"清除失败:\n{e.message}", parent=self)
            except Exception as e:
                messagebox.showerror("错误", f"清除失败:\n{e}", parent=self)

    def update_email(self):
        name, user_id = self._get_selected_user_id()
        if not user_id: return
        
        dialog = tk.Toplevel(self)
        dialog.transient(self)
        dialog.title(f"更新邮箱 - {name}")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="新邮箱:").pack(anchor=tk.W, padx=10, pady=(15, 0))
        email_var = tk.StringVar()
        email_entry = ttk.Entry(dialog, textvariable=email_var)
        email_entry.pack(fill=tk.X, padx=10, pady=2)
        
        def on_submit():
            new_email = email_var.get().strip()
            if not new_email:
                messagebox.showwarning("错误", "邮箱不能为空", parent=dialog)
                return
            
            try:
                details = oci.identity.models.UpdateUserDetails(email=new_email)
                self.identity_client.update_user(user_id, details)
                messagebox.showinfo("成功", f"邮箱已成功更新为: {new_email}", parent=dialog)
                dialog.destroy()
                self.refresh_users()
            except ServiceError as e:
                if "IdentityDomains" in str(e) or e.status == 404:
                    messagebox.showerror("不支持", "操作失败: 甲骨文已将您的租户迁移至新型 Identity Domains，传统 IAM 接口不兼容此操作。", parent=dialog)
                else:
                    messagebox.showerror("错误", f"更新失败:\n{e.message}", parent=dialog)
            except Exception as e:
                messagebox.showerror("错误", f"更新失败:\n{e}", parent=dialog)
                
        ttk.Button(dialog, text="更新", command=on_submit).pack(pady=15)
        center_window(dialog)
        self.grab_release()
        dialog.grab_set()
        email_entry.focus_set()
        self.wait_window(dialog)
        self.grab_set()


# --- 主应用类 ---
class OciInstanceManagerApp:
    def __init__(self, root):
        self.root = root;
        self.root.title("OCI 本地化管理工具 (V17 - 完整功能版)");
        self.root.geometry("1500x800");
        self.logger = logging.getLogger(__name__);
        self.logger.info("--- OCI 应用启动 ---");
        self.configure_modern_theme()

        self.ssh_key_manager = GlobalSSHKeyManager(CONFIG_DIR)

        self.oci_config, self.identity_client, self.compute_client, self.virtual_network_client, self.block_storage_client = None, None, None, None, None;
        self.is_connected, self.connected_profile_alias, self.selected_profile_alias = False, None, None;
        self.all_profiles_data, self.last_used_alias, self.instance_data, self.selected_instance_ocid = {}, None, {}, None;
        self.profile_order = []
        self.session_subnet_id = None
        self.ssh_profiles = {}
        self.rush_tasks = {}
        self.rush_tasks_lock = threading.Lock()
        self.rush_progress_window = None
        self.disconnect_tooltip = None
        self.disconnect_tooltip_label = None
        self.ssh_disconnect_tooltip = None

        self.connected_alias_var = tk.StringVar(value="当前未连接")

        self.load_settings_from_file();
        self.load_profiles_from_file();
        self.load_ssh_profiles();
        self.create_top_bar();
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.FLAT, sashwidth=7,
                                  bg=self.theme_colors["border"], bd=0, relief=tk.FLAT);
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

    def configure_modern_theme(self):
        """配置浅色现代风 UI 主题；只影响界面样式，不改变 OCI 业务逻辑。"""
        self.theme_colors = {
            "bg": "#f4f7fb",
            "panel": "#ffffff",
            "panel_alt": "#eef4fb",
            "card": "#f8fbff",
            "border": "#d7e2ee",
            "accent": "#2563eb",
            "accent_hover": "#1d4ed8",
            "accent_soft": "#dbeafe",
            "success": "#16a34a",
            "warning": "#d97706",
            "danger": "#dc2626",
            "danger_hover": "#b91c1c",
            "danger_pressed": "#991b1b",
            "danger_soft": "#fee2e2",
            "text": "#1f2937",
            "muted": "#64748b",
            "disabled": "#94a3b8",
            "row_odd": "#ffffff",
            "row_even": "#f7fafc",
            "selected": "#bfdbfe",
            "selected_text": "#0f172a",
            "entry": "#ffffff",
            "log_bg": "#fbfdff",
        }
        c = self.theme_colors
        self.root.configure(bg=c["bg"])

        # 注意：ttk.Style 引用 tkfont.Font 对象时，如果 Font 对象只是局部变量，
        # 函数结束后可能被 Python 回收，macOS/Tk 会回退到系统默认字体。
        # 因此这里把所有自定义字体保存到 self.ui_fonts，保证整个窗口生命周期内有效。
        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family="PingFang SC", size=10)
        text_font = tkfont.nametofont("TkTextFont")
        text_font.configure(family="Menlo", size=10)
        # 统一 Tk 内置命名字体为 10 号，覆盖 ttk、tk.Text/Listbox/菜单等常见控件。
        for named_font in ("TkMenuFont", "TkHeadingFont", "TkCaptionFont", "TkSmallCaptionFont", "TkIconFont", "TkTooltipFont"):
            try:
                tkfont.nametofont(named_font).configure(family="PingFang SC", size=10)
            except tk.TclError:
                pass
        self.ui_fonts = {
            "default": default_font,
            "text": text_font,
            "heading": tkfont.Font(root=self.root, family="PingFang SC", size=10, weight="bold"),
            "button": tkfont.Font(root=self.root, family="PingFang SC", size=10, weight="bold"),
            "red_button": tkfont.Font(root=self.root, family="PingFang SC", size=10, weight="bold"),
            "icon_button": tkfont.Font(root=self.root, family="Segoe UI Symbol", size=18, weight="bold"),
            "tree": tkfont.Font(root=self.root, family="PingFang SC", size=10),
            "tree_heading": tkfont.Font(root=self.root, family="PingFang SC", size=10, weight="bold"),
        }
        heading_font = self.ui_fonts["heading"]
        button_font = self.ui_fonts["button"]
        red_button_font = self.ui_fonts["red_button"]
        icon_button_font = self.ui_fonts["icon_button"]
        tree_font = self.ui_fonts["tree"]
        tree_heading_font = self.ui_fonts["tree_heading"]

        # 同步传统 tk 控件和 ttk 控件的默认字体，避免只有 Text/ScrolledText 生效。
        self.root.option_add("*Font", default_font)
        self.root.option_add("*Menu.Font", default_font)
        self.root.option_add("*Text.Font", text_font)
        self.root.option_add("*Listbox.Font", default_font)
        self.root.option_add("*Button.Font", default_font)

        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass

        style.configure(".", background=c["bg"], foreground=c["text"], fieldbackground=c["entry"],
                        font=default_font, bordercolor=c["border"], lightcolor=c["panel"], darkcolor=c["border"])
        style.configure("TFrame", background=c["bg"], relief=tk.FLAT)
        style.configure("TLabelframe", background=c["panel"], foreground=c["accent"], borderwidth=1,
                        relief=tk.SOLID, padding=10)
        style.configure("TLabelframe.Label", background=c["bg"], foreground=c["accent"], font=heading_font)
        style.configure("TLabel", background=c["bg"], foreground=c["text"], font=default_font)
        style.configure("BlackBold.TLabel", background=c["bg"], foreground=c["text"], font=heading_font)
        style.configure("RedBold.TLabel", background=c["bg"], foreground=c["accent"], font=heading_font)
        style.configure("Connected.TLabel", background=c["panel"], foreground=c["danger"], font=heading_font)


        style.configure("TButton", background=c["card"], foreground=c["text"], borderwidth=3,
                        relief=tk.RAISED, focusthickness=1, focuscolor=c["accent_soft"],
                        padding=(18, 9), font=button_font)
        style.configure("TEntry", fieldbackground=c["entry"], foreground=c["text"], font=default_font)
        style.configure("TCombobox", fieldbackground=c["entry"], foreground=c["text"], font=default_font)
        style.configure("TCheckbutton", background=c["bg"], foreground=c["text"], font=default_font)
        style.configure("TSpinbox", fieldbackground=c["entry"], foreground=c["text"], font=default_font)
        style.map("TButton",
                  background=[('active', c["accent_soft"]), ('pressed', "#c7d2fe"), ('disabled', "#eef2f7")],
                  foreground=[('active', c["accent_hover"]), ('pressed', c["accent_hover"]), ('disabled', c["disabled"])],
                  bordercolor=[('active', c["accent"]), ('pressed', c["accent_hover"]), ('disabled', c["border"])],
                  relief=[('pressed', tk.SUNKEN), ('active', tk.RAISED)])
        style.configure("Red.TButton", background=c["card"], foreground=c["danger"], font=red_button_font,
                        borderwidth=3, relief=tk.RAISED, padding=(18, 9))
        style.map("Red.TButton",
                  background=[('active', c["danger_soft"]), ('pressed', "#fecaca"), ('disabled', "#eef2f7")],
                  foreground=[('active', c["danger_hover"]), ('pressed', c["danger_pressed"]), ('disabled', c["disabled"])],
                  bordercolor=[('active', c["danger"]), ('pressed', c["danger_pressed"]), ('disabled', c["border"])],
                  relief=[('pressed', tk.SUNKEN), ('active', tk.RAISED)])
        style.configure("DisconnectIcon.TButton", background=c["card"], foreground=c["danger"], font=icon_button_font,
                        borderwidth=2, relief=tk.RAISED, padding=(6, 2))
        style.map("DisconnectIcon.TButton",
                  background=[('active', c["danger_soft"]), ('pressed', "#fecaca"), ('disabled', "#eef2f7")],
                  foreground=[('active', c["danger_hover"]), ('pressed', c["danger_pressed"]), ('disabled', c["disabled"])],
                  bordercolor=[('active', c["danger"]), ('pressed', c["danger_pressed"]), ('disabled', c["border"])],
                  relief=[('pressed', tk.SUNKEN), ('active', tk.RAISED)])

        style.configure("Treeview", background=c["row_odd"], foreground=c["text"], fieldbackground=c["row_odd"],
                        borderwidth=1, rowheight=36, font=tree_font)
        style.configure("Treeview.Heading", background=c["panel_alt"], foreground=c["text"], relief=tk.RAISED,
                        font=tree_heading_font, padding=(8, 9))
        style.map("Treeview", background=[('selected', c["selected"])], foreground=[('selected', c["selected_text"])])
        style.map("Treeview.Heading", background=[('active', c["accent_soft"])], foreground=[('active', c["accent_hover"])])

        style.configure("Vertical.TScrollbar", background="#e2e8f0", troughcolor=c["panel"], bordercolor=c["panel"],
                        arrowcolor=c["muted"], relief=tk.FLAT)
        style.configure("Horizontal.TScrollbar", background="#e2e8f0", troughcolor=c["panel"], bordercolor=c["panel"],
                        arrowcolor=c["muted"], relief=tk.FLAT)
        style.configure("TSeparator", background=c["border"])
        style.configure("Status.TLabel", background="#eaf2ff", foreground=c["accent"], font=("PingFang SC", 10),
                        padding=(10, 6))
                        
        style.configure("Account.TButton", font=default_font, padding=(10, 8), background=c["card"], foreground=c["text"], anchor=tk.W)
        style.configure("AccountSelected.TButton", font=heading_font, padding=(10, 8), background=c["selected"], foreground=c["selected_text"], anchor=tk.W)
        style.configure("AccountConnected.TButton", font=heading_font, padding=(10, 8), background=c["accent_soft"], foreground=c["accent_hover"], anchor=tk.W)

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

    def load_ssh_profiles(self):
        try:
            if os.path.exists(SSH_PROFILES_FILE_PATH):
                with open(SSH_PROFILES_FILE_PATH, 'r', encoding='utf-8') as f:
                    self.ssh_profiles = json.load(f)
            else:
                self.ssh_profiles = {}
        except Exception as e:
            self.logger.error(f"加载 SSH 配置文件错误: {e}", exc_info=True)
            self.ssh_profiles = {}

    def save_ssh_profiles(self):
        try:
            with open(SSH_PROFILES_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.ssh_profiles, f, indent=4)
        except Exception as e:
            self.logger.error(f"保存 SSH 配置文件错误: {e}", exc_info=True)

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
            self.delete_profile_button.config(state=edit_delete_state)
            self.connect_button.config(state='normal' if profiles_exist and self.selected_profile_alias else 'disabled')
            if hasattr(self, 'disconnect_button'):
                color = self.theme_colors["danger"] if connected else self.theme_colors["disabled"]
                self.disconnect_button.config(fg=color, cursor="hand2" if connected else "arrow")

            self.create_instance_button.config(state='normal' if connected else 'disabled')
            self.firewall_button.config(state='normal' if connected else 'disabled')
            self.region_select_button.config(state='normal' if connected else 'disabled')
            if hasattr(self, 'iam_manage_button'):
                self.iam_manage_button.config(state='normal' if connected else 'disabled')
            if not connected:
                self.region_select_button.config(text="选择区域")

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
        c = self.theme_colors
        label_container = ttk.Frame(self.root)
        label1 = ttk.Label(label_container, text="账号管理 ", style="BlackBold.TLabel")
        label1.pack(side=tk.LEFT)
        top_bar_frame = ttk.LabelFrame(self.root, labelwidget=label_container, padding=(10, 5))
        top_bar_frame.pack(pady=5, padx=10, fill=tk.X)

        self.disconnect_button = tk.Label(top_bar_frame, text="⚡", fg=c["danger"], bg=c["panel"],
                                          cursor="hand2", font=("Segoe UI Symbol", 18, "bold"))
        self.disconnect_button.bind("<Button-1>", self.on_disconnect_icon_click)
        self.disconnect_button.bind("<Enter>", self.on_disconnect_icon_enter)
        self.disconnect_button.bind("<Motion>", self.on_disconnect_icon_motion)
        self.disconnect_button.bind("<Leave>", self.on_disconnect_icon_leave)
        self.disconnect_button.pack(side=tk.RIGHT, padx=(12, 10))
        connected_label = ttk.Label(top_bar_frame, textvariable=self.connected_alias_var, style="Connected.TLabel")
        connected_label.pack(side=tk.RIGHT, padx=(10, 12))

        ttk.Button(top_bar_frame, text="添加账号", command=self.add_profile).pack(side=tk.LEFT, padx=(0, 5))
        self.delete_profile_button = ttk.Button(top_bar_frame, text="删除选中账号", command=self.delete_profile,
                                                state='disabled')
        self.delete_profile_button.pack(side=tk.LEFT, padx=5)

        self.cf_button = ttk.Button(top_bar_frame, text="Cloudflare设置", command=self.show_cloudflare_settings)
        self.cf_button.pack(side=tk.LEFT, padx=5)

        self.connect_button = ttk.Button(top_bar_frame, text="设置代理", command=self.show_proxy_dialog,
                                         state='disabled')
        self.connect_button.pack(side=tk.LEFT, padx=5)

        self.global_ssh_button = ttk.Button(top_bar_frame, text="全局SSH密钥", command=self.show_global_ssh_dialog)
        self.global_ssh_button.pack(side=tk.LEFT, padx=5)
        
        self.iam_manage_button = ttk.Button(top_bar_frame, text="身份与用户安全", command=self.show_iam_manager, state='disabled')
        self.iam_manage_button.pack(side=tk.LEFT, padx=5)

        ttk.Separator(top_bar_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        
        self.region_select_button = ttk.Button(top_bar_frame, text="选择区域", command=self.show_region_select_dialog, state='disabled')
        self.region_select_button.pack(side=tk.LEFT, padx=5)
        
        self.rush_progress_button = ttk.Button(top_bar_frame, text="抢机进度", command=self.show_rush_progress_window, state='disabled')
        self.rush_progress_button.pack(side=tk.LEFT, padx=5)

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

    def _bind_canvas_mousewheel(self, canvas):
        canvas.configure(yscrollincrement=1)
        def _on_mousewheel(event):
            if not canvas.winfo_exists(): return
            if sys.platform == 'darwin':
                canvas.yview_scroll(int(-1 * event.delta), "units")
            else:
                if hasattr(event, 'num') and event.num == 4:
                    canvas.yview_scroll(-30, "units")
                elif hasattr(event, 'num') and event.num == 5:
                    canvas.yview_scroll(30, "units")
                else:
                    direction = -1 if event.delta > 0 else 1
                    canvas.yview_scroll(direction * 30, "units")

        def _bind_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)
            canvas.bind_all("<Button-4>", _on_mousewheel)
            canvas.bind_all("<Button-5>", _on_mousewheel)

        def _unbind_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            canvas.unbind_all("<Button-4>")
            canvas.unbind_all("<Button-5>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

    # --- 账户列表创建，配置排序和颜色Tag ---
    def create_account_list_view(self, parent_frame):
        view_frame = ttk.LabelFrame(parent_frame, text="账户列表", padding=(5, 5));
        view_frame.pack(expand=True, fill=tk.BOTH);

        sort_frame = ttk.Frame(view_frame)
        sort_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(sort_frame, text="名称排序 ↕", command=lambda: self.sort_account_column('alias')).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(sort_frame, text="时间排序 ↕", command=lambda: self.sort_account_column('duration')).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.account_canvas = tk.Canvas(view_frame, borderwidth=0, highlightthickness=0)
        try:
            self.account_canvas.configure(bg=self.theme_colors["bg"])
        except:
            pass

        vsb = ttk.Scrollbar(view_frame, orient="vertical", command=self.account_canvas.yview)
        self.account_scrollable_frame = ttk.Frame(self.account_canvas)

        self.account_scrollable_frame.bind(
            "<Configure>",
            lambda e: self.account_canvas.configure(scrollregion=self.account_canvas.bbox("all"))
        )

        self.account_canvas_window = self.account_canvas.create_window((0, 0), window=self.account_scrollable_frame, anchor="nw")

        def _configure_canvas(event):
            self.account_canvas.itemconfigure(self.account_canvas_window, width=event.width)
        self.account_canvas.bind('<Configure>', _configure_canvas)

        self.account_canvas.configure(yscrollcommand=vsb.set)
        self.account_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._bind_canvas_mousewheel(self.account_canvas)

        # --- 新增: 导入导出按钮区域 ---
        btn_frame = ttk.Frame(view_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        ttk.Button(btn_frame, text="导入账号", command=self.import_accounts).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        ttk.Button(btn_frame, text="导出账号", command=self.export_accounts).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        self.sort_reverse = {"alias": False, "duration": False}
        self.account_buttons = {}

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
        c = self.theme_colors
        instance_pane = tk.PanedWindow(parent_frame, orient=tk.VERTICAL, sashrelief=tk.FLAT, sashwidth=7,
                                      bg=c["border"], bd=0, relief=tk.FLAT)
        instance_pane.pack(expand=True, fill=tk.BOTH)

        list_frame = ttk.LabelFrame(instance_pane, text="实例列表 (单击查看详情，双击连接ssh)", padding=(5, 5))
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
        self.instance_treeview.bind('<Double-1>', self.on_instance_double_click)

        self.details_frame = ttk.LabelFrame(instance_pane, text="实例详细信息", padding=(5, 5))
        instance_pane.add(self.details_frame, height=300)

        self.instance_details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.WORD, state=tk.DISABLED,
                                                               font=("Menlo", 10), bg=c["entry"], fg=c["text"],
                                                               insertbackground=c["accent"], relief=tk.SOLID,
                                                               bd=0, padx=12, pady=10)
        self.instance_details_text.pack(expand=True, fill=tk.BOTH)

        self.ssh_terminal_frame = SSHTerminalFrame(self.details_frame)
        self.ssh_terminal_frame.on_close_callback = self.show_instance_details
        self.ssh_terminal_frame.on_connect_success_callback = self.on_ssh_connect_success
        self.ssh_terminal_frame.on_disconnect_callback = self.on_ssh_disconnect

    def create_log_viewer(self):
        c = self.theme_colors
        log_frame = ttk.LabelFrame(self.root, text="操作日志", padding=(5, 5));
        log_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=True);
        self.log_viewer = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD, state=tk.DISABLED,
                                                    font=("Menlo", 10), bg=c["log_bg"], fg=c["success"],
                                                    insertbackground=c["accent"], relief=tk.SOLID,
                                                    bd=0, padx=12, pady=10);
        self.log_viewer.pack(expand=True, fill=tk.BOTH)

    def create_status_bar(self):
        self.status_label = ttk.Label(self.root, text="未连接", anchor=tk.W, style="Status.TLabel");
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- 排序辅助方法（拼音+数字） ---
    def get_account_sort_key(self, col, value):
        if col == "duration":
            return int(value) if isinstance(value, (int, float)) else -999999
        else:
            if not value: return ""
            try:
                pinyin_str = "".join(lazy_pinyin(str(value)))
                return pinyin_str.lower()
            except Exception:
                return str(value).lower()

    def sort_account_column(self, col):
        reverse = self.sort_reverse.get(col, False)
        
        def get_val(alias):
            if col == "alias":
                return alias
            elif col == "duration":
                profile_data = self.all_profiles_data.get(alias, {})
                reg_date_str = profile_data.get('registration_date')
                if reg_date_str:
                    try:
                        reg_date = datetime.strptime(reg_date_str, "%Y-%m-%d").date()
                        today = datetime.now().date()
                        return (today - reg_date).days
                    except: pass
                return -999999
            return ""

        self.profile_order.sort(key=lambda a: self.get_account_sort_key(col, get_val(a)), reverse=reverse)
        self.sort_reverse[col] = not reverse
        self.update_account_list()

    def refresh_account_colors(self):
        if not hasattr(self, 'account_buttons'): return
        for alias, btn in self.account_buttons.items():
            is_connected = (alias == self.connected_profile_alias)
            is_selected = (alias == self.selected_profile_alias)
            
            style = "Account.TButton"
            if is_connected:
                style = "AccountConnected.TButton"
            elif is_selected:
                style = "AccountSelected.TButton"
                
            btn.configure(style=style)

    # --- 账户列表更新逻辑 (包含新的日期格式与斑马纹) ---
    def update_account_list(self):
        for child in self.account_scrollable_frame.winfo_children():
            child.destroy()
        self.account_buttons = {}

        all_aliases = set(self.all_profiles_data.keys())
        final_order = [alias for alias in self.profile_order if alias in all_aliases]
        new_aliases = sorted([alias for alias in all_aliases if alias not in final_order])
        final_order.extend(new_aliases)

        if self.last_used_alias in final_order and not self.selected_profile_alias:
            self.selected_profile_alias = self.last_used_alias
        elif self.selected_profile_alias not in final_order:
            self.selected_profile_alias = None

        target_pixels = 300
        
        for i, alias in enumerate(final_order):
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
                        duration_display = f"{days}天 ({reg_date.year}/{reg_date.month}/{reg_date.day})"
                except Exception:
                    duration_display = "格式错误"
            else:
                duration_display = "-"

            is_connected = (alias == self.connected_profile_alias)
            is_selected = (alias == self.selected_profile_alias)
            
            name_text = alias + (" (已连接)" if is_connected else "")
            
            font_to_use = self.ui_fonts["heading"] if is_connected or is_selected else self.ui_fonts["default"]
            space_width = font_to_use.measure(" ")
            name_w = font_to_use.measure(name_text)
            time_w = font_to_use.measure(duration_display)
            
            space_pixels = target_pixels - name_w - time_w
            if space_pixels < space_width * 2:
                space_pixels = space_width * 2
                
            spaces_count = int(space_pixels / space_width)
            btn_text = f"{name_text}{' ' * spaces_count}{duration_display}"
            
            style = "Account.TButton"
            if is_connected:
                style = "AccountConnected.TButton"
            elif is_selected:
                style = "AccountSelected.TButton"

            btn = ttk.Button(self.account_scrollable_frame, text=btn_text, style=style)
            btn.pack(fill=tk.X, pady=4, padx=4)

            btn.bind("<Button-1>", lambda e, a=alias: self.on_account_click(e, a))
            btn.bind("<Double-1>", lambda e, a=alias: self.on_account_double_click(e, a))

            btn.bind("<ButtonPress-1>", lambda e, a=alias: self.on_drag_start(e, a), add="+")
            btn.bind("<B1-Motion>", self.on_drag_motion)
            btn.bind("<ButtonRelease-1>", self.on_drag_stop)

            self.account_buttons[alias] = btn

        if self.profile_order != final_order:
            self.profile_order = final_order
            self.save_settings_to_file()
            
        self.toggle_controls(self.is_connected, bool(self.all_profiles_data), self.selected_instance_ocid is not None)

    def on_account_click(self, event, alias):
        self.selected_profile_alias = alias
        self.logger.info(f"在列表中选中账号: {self.selected_profile_alias}")
        self.refresh_account_colors()
        self.toggle_controls(self.is_connected, bool(self.all_profiles_data), self.selected_instance_ocid is not None)

    def on_account_double_click(self, event, alias):
        self.on_account_click(event, alias)
        self.connect_oci_thread()

    def on_drag_start(self, event, alias):
        self._drag_data = {"alias": alias, "moved": False}

    def on_drag_motion(self, event):
        if not hasattr(self, "_drag_data"): return
        self._drag_data["moved"] = True
        for alias, btn in self.account_buttons.items():
            if btn.winfo_rooty() <= event.y_root <= btn.winfo_rooty() + btn.winfo_height():
                if alias != self._drag_data["alias"]:
                    idx1 = self.profile_order.index(self._drag_data["alias"])
                    idx2 = self.profile_order.index(alias)
                    self.profile_order.remove(self._drag_data["alias"])
                    self.profile_order.insert(idx2, self._drag_data["alias"])
                    for a in self.profile_order:
                        if a in self.account_buttons:
                            self.account_buttons[a].pack_forget()
                            self.account_buttons[a].pack(fill=tk.X, pady=4, padx=4)
                    break

    def on_drag_stop(self, event):
        if hasattr(self, "_drag_data"):
            was_moved = self._drag_data.get("moved", False)
            del self._drag_data
            if was_moved:
                self.save_settings_to_file()
                self.log_ui("账户顺序已保存。", "INFO")


    def show_instance_details(self):
        if hasattr(self, 'ssh_terminal_frame') and self.ssh_terminal_frame.winfo_ismapped():
            self.ssh_terminal_frame.pack_forget()
        if hasattr(self, 'instance_details_text') and not self.instance_details_text.winfo_ismapped():
            self.instance_details_text.pack(expand=True, fill=tk.BOTH)
        if hasattr(self, 'details_frame'):
            self.details_frame.config(text="实例详细信息")

    def on_ssh_connect_success(self):
        pass

    def on_ssh_disconnect(self):
        pass

    def close_ssh_terminal(self):
        if hasattr(self, 'ssh_terminal_frame'):
            self.ssh_terminal_frame.close_terminal()

    def on_instance_double_click(self, event=None):
        selected_items = self.instance_treeview.selection()
        if len(selected_items) != 1: return
        instance_id = selected_items[0]
        details = self.instance_data.get(instance_id, {})
        public_ip = details.get('public_ip', 'N/A')
        
        if public_ip == 'N/A' or not public_ip or public_ip == '获取中...':
            messagebox.showwarning("无公网 IP", "该实例没有可用的公网 IP，无法进行 SSH 连接。", parent=self.root)
            return
            
        if instance_id not in self.ssh_profiles:
            profile_data = self.all_profiles_data.get(self.connected_profile_alias, {})
            
            keys_to_try = []
            
            # 1. 如果账户里上传了 API PEM 文件，尝试将其作为 SSH 私钥 (有的用户用同一个)
            api_private_key = profile_data.get('key_content')
            if not api_private_key and profile_data.get('key_file'):
                try:
                    with open(profile_data['key_file'], 'r', encoding='utf-8') as f:
                        api_private_key = f.read()
                except: pass
            
            if api_private_key:
                keys_to_try.append(api_private_key)
                
            # 2. 尝试全局动态密钥
            if self.ssh_key_manager.priv_key:
                keys_to_try.append(self.ssh_key_manager.priv_key)

            if keys_to_try:
                auto_config = {
                    "user": "ubuntu",
                    "auth_mode": "auto_keys",
                    "keys": keys_to_try
                }
                self.connect_ssh(instance_id, public_ip, auto_config, is_auto=True)
            else:
                SSHConfigDialog(self.root, instance_id, public_ip, self.save_ssh_config_and_connect, self.ssh_key_manager)
        else:
            self.connect_ssh(instance_id, public_ip, self.ssh_profiles[instance_id])

    def save_ssh_config_and_connect(self, instance_id, config, connect_after=True):
        self.ssh_profiles[instance_id] = config
        self.save_ssh_profiles()
        if connect_after:
            details = self.instance_data.get(instance_id, {})
            public_ip = details.get('public_ip', 'N/A')
            self.connect_ssh(instance_id, public_ip, config)
        
    def connect_ssh(self, instance_id, ip, config, is_auto=False):
        if hasattr(self, 'instance_details_text') and self.instance_details_text.winfo_ismapped():
            self.instance_details_text.pack_forget()
        if hasattr(self, 'details_frame'):
            self.details_frame.config(text=f"SSH 终端: {ip}")
        if hasattr(self, 'ssh_terminal_frame') and not self.ssh_terminal_frame.winfo_ismapped():
            self.ssh_terminal_frame.pack(expand=True, fill=tk.BOTH)
            
        def on_fail(err):
            if is_auto:
                self.close_ssh_terminal()
                SSHConfigDialog(self.root, instance_id, ip, self.save_ssh_config_and_connect, self.ssh_key_manager)
            else:
                if messagebox.askyesno("SSH连接失败", f"连接失败：{err}\n\n这通常是由于密码错误或私钥格式不正确导致的。\n是否需要重新配置该实例的 SSH 登录凭据？", parent=self.root):
                    self.close_ssh_terminal()
                    SSHConfigDialog(self.root, instance_id, ip, self.save_ssh_config_and_connect, self.ssh_key_manager)

        def on_auto_success(success_config):
            if is_auto:
                self.save_ssh_config_and_connect(instance_id, success_config, connect_after=False)

        self.ssh_terminal_frame.on_connect_failed_callback = on_fail
        self.ssh_terminal_frame.on_auto_connect_success_callback = on_auto_success
        self.ssh_terminal_frame.connect(ip, config)

    def on_instance_select(self, event=None):
        self.show_instance_details()
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
                f"  引导卷OCID: {details_data.get('boot_volume_id', 'N/A')}",
                f"  引导卷附件: {details_data.get('boot_volume_attachment_id', 'N/A')}",
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

    def connect_oci_thread(self, event=None):
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
                if hasattr(self, 'region_select_button'):
                    self.region_select_button.config(text=f"区域: {self.oci_config.get('region', '未知')}")
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

    def on_disconnect_icon_click(self, event=None):
        if self.is_connected:
            self.disconnect_oci()

    def on_disconnect_icon_enter(self, event=None):
        self.show_disconnect_tooltip(event)

    def on_disconnect_icon_motion(self, event=None):
        self.show_disconnect_tooltip(event)

    def on_disconnect_icon_leave(self, event=None):
        self.hide_disconnect_tooltip()

    def show_disconnect_tooltip(self, event=None):
        text = "断开" if self.is_connected else "未连接"
        if self.disconnect_tooltip is None or not self.disconnect_tooltip.winfo_exists():
            self.disconnect_tooltip = tk.Toplevel(self.root)
            self.disconnect_tooltip.withdraw()
            self.disconnect_tooltip.overrideredirect(True)
            self.disconnect_tooltip.attributes("-topmost", True)
            self.disconnect_tooltip_label = tk.Label(
                self.disconnect_tooltip,
                text=text,
                bg="#111827",
                fg="#ffffff",
                padx=8,
                pady=4,
                font=("Microsoft YaHei UI", 10),
                relief=tk.SOLID,
                bd=1
            )
            self.disconnect_tooltip_label.pack()
        else:
            self.disconnect_tooltip_label.config(text=text)

        x = (event.x_root if event else self.root.winfo_pointerx()) + 12
        y = (event.y_root if event else self.root.winfo_pointery()) + 16
        self.disconnect_tooltip.geometry(f"+{x}+{y}")
        self.disconnect_tooltip.deiconify()
        self.disconnect_tooltip.lift()

    def hide_disconnect_tooltip(self):
        if self.disconnect_tooltip is not None and self.disconnect_tooltip.winfo_exists():
            self.disconnect_tooltip.withdraw()

    def add_profile(self):
        EditProfileDialog(self.root, None, {}, self.handle_edit_profile)

    def edit_profile(self):
        if not self.selected_profile_alias: messagebox.showwarning("未选择", "请在列表中选择要编辑的账号。"); return
        profile_data = self.all_profiles_data.get(self.selected_profile_alias);
        if profile_data: EditProfileDialog(self.root, self.selected_profile_alias, profile_data,
                                           self.handle_edit_profile)

    def handle_edit_profile(self, original_alias, new_alias, new_data):
        # 如果传入的公钥为空，我们保留为空字符串，表示使用全局默认密钥
        if not new_data.get('default_ssh_public_key'):
            new_data['default_ssh_public_key'] = ""

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
                    c = self.theme_colors
                    self.instance_treeview.tag_configure('RUNNING', foreground=c['success'], background=c['row_odd'])
                    self.instance_treeview.tag_configure('STOPPED', foreground=c['danger'], background=c['row_odd'])
                    self.instance_treeview.tag_configure('STARTING', foreground=c['warning'], background=c['row_odd'])
                    self.instance_treeview.tag_configure('STOPPING', foreground=c['warning'], background=c['row_odd'])
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
        elif changes.get('detach_boot_volume'):
            thread = threading.Thread(target=self.run_backend_action, args=(
                backend_detach_boot_volume,
                [self.compute_client, instance_id, self.logger],
                "分离引导卷", dialog_to_close), daemon=True)
        elif changes.get('attach_boot_volume_id'):
            thread = threading.Thread(target=self.run_backend_action, args=(
                backend_attach_boot_volume,
                [self.compute_client, instance_id, changes['attach_boot_volume_id'], self.logger],
                "附加引导卷", dialog_to_close), daemon=True)
        else:
            thread = threading.Thread(target=self.run_backend_action, args=(
                backend_update_instance_full,
                [self.compute_client, self.block_storage_client, instance_id, changes, self.logger],
                "更新实例配置", dialog_to_close), daemon=True)
        thread.start()

    def show_create_instance_dialog(self):
        tenancy = self.config.get('tenancy') if hasattr(self, 'config') else None
        compute_client = self.compute_client if hasattr(self, 'compute_client') else None
        CreateInstanceDialog(self.root, self.handle_create_instance, compute_client, tenancy)

    def handle_create_instance(self, details):
        details['global_ssh_public_key'] = self.ssh_key_manager.pub_key
        subnet_id = self._get_or_choose_subnet()
        if not subnet_id:
            return

        self.log_ui(f"正在提交创建实例 '{details['display_name_prefix']}' 的请求...", "INFO");
        clients = {'compute': self.compute_client, 'identity': self.identity_client,
                   'vnet': self.virtual_network_client};

        task_id = f"{int(time.time() * 1000)}-{random.randint(1000, 9999)}"
        stop_event = threading.Event()
        with self.rush_tasks_lock:
            self.rush_tasks[task_id] = {
                "checked": False,
                "alias": self.connected_profile_alias or "当前账号",
                "name": details.get('display_name_prefix', 'instance'),
                "rush": bool(details.get('rush_mode')),
                "status": "运行中",
                "started_at": time.strftime('%H:%M:%S'),
                "message": "已提交，等待后台执行...",
                "stop_event": stop_event,
                "thread": None
            }
            
        if hasattr(self, 'rush_progress_button'):
            self.rush_progress_button.config(state='normal')
            
        self.refresh_rush_progress_tree()

        args = [clients, self.oci_config.copy(), details, subnet_id, self.log_ui, self.logger, stop_event]
        thread = threading.Thread(target=self.run_create_instance_task,
                                  args=(task_id, backend_create_instance, args), daemon=True);
        with self.rush_tasks_lock:
            if task_id in self.rush_tasks:
                self.rush_tasks[task_id]["thread"] = thread
        thread.start()

    def run_create_instance_task(self, task_id, backend_func, func_args):
        self.logger.info(f"后台线程：开始执行创建实例任务 {task_id}...")
        try:
            success, message = backend_func(*func_args)
        except Exception as e:
            success, message = False, f"后台线程在执行创建实例时发生意外错误: {e}"
            self.logger.exception(message)

        with self.rush_tasks_lock:
            task = self.rush_tasks.get(task_id)
            if task:
                task["status"] = "成功" if success else ("已停止" if task["stop_event"].is_set() else "失败")
                task["message"] = message

        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.after(0, self.refresh_rush_progress_tree)
            self.root.after(0, self.update_gui_after_action, success, message, "创建实例", None)

    def show_rush_progress_window(self):
        if self.rush_progress_window and self.rush_progress_window.winfo_exists():
            self.rush_progress_window.lift()
            self.refresh_rush_progress_tree()
            return

        win = tk.Toplevel(self.root)
        self.rush_progress_window = win
        win.title("抢机进度")
        win.geometry("1200x650")
        win.minsize(1000, 560)
        win.transient(self.root)

        frame = ttk.Frame(win, padding=10)
        frame.pack(expand=True, fill=tk.BOTH)
        style = ttk.Style(win)
        style.configure("Rush.Treeview", rowheight=34, font=("Microsoft YaHei UI", 11))
        style.configure("Rush.Treeview.Heading", font=("Microsoft YaHei UI", 10, "bold"))
        columns = ('checked', 'alias', 'name', 'mode', 'status', 'started_at', 'message')
        self.rush_progress_tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse',
                                               style="Rush.Treeview")
        headings = {'checked': '选择', 'alias': '账号', 'name': '实例名', 'mode': '模式', 'status': '状态',
                    'started_at': '开始时间', 'message': '最新消息'}
        widths = {'checked': 70, 'alias': 130, 'name': 130, 'mode': 70, 'status': 85, 'started_at': 90,
                  'message': 520}
        for col in columns:
            self.rush_progress_tree.heading(col, text=headings[col])
            self.rush_progress_tree.column(col, width=widths[col], anchor=tk.CENTER if col != 'message' else tk.W)
        self.rush_progress_tree.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        self.rush_progress_tree.bind('<Button-1>', self.on_rush_progress_click)
        self.rush_progress_tree.bind('<Double-1>', self.on_rush_progress_double_click)

        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.rush_progress_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rush_progress_tree.configure(yscrollcommand=scrollbar.set)

        button_frame = ttk.Frame(win, padding=(10, 0, 10, 10))
        button_frame.pack(fill=tk.X)
        ttk.Button(button_frame, text="停止勾选任务", command=self.stop_checked_rush_tasks,
                   style="Red.TButton").pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="清除已结束", command=self.clear_finished_rush_tasks).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="刷新", command=self.refresh_rush_progress_tree).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="关闭", command=win.destroy).pack(side=tk.LEFT, padx=5)
        self.refresh_rush_progress_tree()
        self.after_safe_center(win)

    def clear_finished_rush_tasks(self):
        with self.rush_tasks_lock:
            tasks_to_delete = []
            for task_id, task in self.rush_tasks.items():
                if task.get('status') in ("成功", "失败", "已停止"):
                    tasks_to_delete.append(task_id)
            for task_id in tasks_to_delete:
                del self.rush_tasks[task_id]
            has_tasks = len(self.rush_tasks) > 0

        self.refresh_rush_progress_tree()
        if hasattr(self, 'rush_progress_button'):
            self.rush_progress_button.config(state='normal' if has_tasks else 'disabled')

    def after_safe_center(self, win):
        try:
            win.after(100, lambda: center_window(win))
        except tk.TclError:
            pass

    def refresh_rush_progress_tree(self):
        if not hasattr(self, 'rush_progress_tree') or not self.rush_progress_tree.winfo_exists():
            return
        for item in self.rush_progress_tree.get_children():
            self.rush_progress_tree.delete(item)
        with self.rush_tasks_lock:
            task_items = list(self.rush_tasks.items())
        for task_id, task in task_items:
            mode = "抢机" if task.get('rush') else "创建"
            values = ("✅" if task.get('checked') else "⬜", task.get('alias', ''), task.get('name', ''), mode,
                      task.get('status', ''), task.get('started_at', ''), task.get('message', ''))
            self.rush_progress_tree.insert('', tk.END, iid=task_id, values=values)

    def on_rush_progress_click(self, event):
        if not hasattr(self, 'rush_progress_tree'):
            return
        clicked_column = self.rush_progress_tree.identify_column(event.x)
        task_id = self.rush_progress_tree.identify_row(event.y)
        if not task_id:
            return
        if clicked_column != '#1':
            return
        with self.rush_tasks_lock:
            if task_id in self.rush_tasks:
                self.rush_tasks[task_id]['checked'] = not self.rush_tasks[task_id].get('checked', False)
        self.refresh_rush_progress_tree()

    def on_rush_progress_double_click(self, event):
        if not hasattr(self, 'rush_progress_tree'):
            return
        task_id = self.rush_progress_tree.identify_row(event.y)
        if not task_id:
            return
        with self.rush_tasks_lock:
            task = self.rush_tasks.get(task_id, {}).copy()
        if task.get('status') != "成功":
            messagebox.showinfo("任务详情", "该任务尚未成功完成，暂无抢机完成详情。", parent=self.rush_progress_window or self.root)
            return
        detail = task.get('message') or "暂无详细信息。"
        messagebox.showinfo("抢机完成详情", detail, parent=self.rush_progress_window or self.root)

    def stop_single_rush_task(self, task_id):
        stopped = False
        task_name = ""
        with self.rush_tasks_lock:
            task = self.rush_tasks.get(task_id)
            if task and task.get('status') in ("运行中", "停止中"):
                task['stop_event'].set()
                task['status'] = "停止中"
                task_name = task.get('name', '') or task.get('alias', '') or task_id
                stopped = True
        self.refresh_rush_progress_tree()
        if stopped:
            self.log_ui(f"已请求停止抢机/创建任务：{task_name}", "WARN")
        else:
            self.log_ui("该任务当前不可停止。", "INFO")

    def stop_checked_rush_tasks(self):
        stopped = 0
        with self.rush_tasks_lock:
            for task in self.rush_tasks.values():
                if task.get('checked') and task.get('status') == "运行中":
                    task['stop_event'].set()
                    task['status'] = "停止中"
                    stopped += 1
        self.refresh_rush_progress_tree()
        self.log_ui(f"已请求停止 {stopped} 个抢机/创建任务。", "WARN")

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
        if not self.selected_profile_alias:
            return
        alias = self.selected_profile_alias
        profile_data = self.all_profiles_data.get(alias, {})
        SetProxyDialog(self.root, alias, profile_data, self.handle_proxy_update)

    def show_region_select_dialog(self):
        if not self.is_connected: return
        try:
            self.log_ui("正在获取区域信息...", "INFO")
            tenancy_id = self.oci_config['tenancy']
            subscriptions = self.identity_client.list_region_subscriptions(tenancy_id).data
            subscribed_region_names = [sub.region_name for sub in subscriptions]
            
            all_regions = self.identity_client.list_regions().data
            unsubscribed_regions = [r for r in all_regions if r.name not in subscribed_region_names]
            
        except Exception as e:
            messagebox.showerror("获取失败", f"获取区域信息失败: {e}", parent=self.root)
            return
            
        if len(subscribed_region_names) <= 1:
            messagebox.showinfo("提示", "尚未订阅其他区域\n\n您可以在接下来的窗口中订阅新区域。", parent=self.root)

        RegionSelectDialog(self.root, subscribed_region_names, unsubscribed_regions, self.oci_config['region'], self.change_region, self.subscribe_region)

    def subscribe_region(self, region_name, region_key):
        try:
            self.log_ui(f"正在订阅区域: {region_name} ({region_key})...", "INFO")
            details = oci.identity.models.CreateRegionSubscriptionDetails(region_key=region_key)
            self.identity_client.create_region_subscription(details, self.oci_config['tenancy'])
            self.log_ui(f"订阅区域 {region_name} 的请求已提交。通常需要几分钟才能生效。", "INFO")
            messagebox.showinfo("订阅成功", f"订阅区域 {region_name} 的请求已成功提交。\n请等待几分钟后刷新区域列表即可使用。", parent=self.root)
        except Exception as e:
            self.log_ui(f"订阅区域失败: {e}", "ERROR")
            messagebox.showerror("订阅失败", f"订阅区域失败: {e}", parent=self.root)

    def change_region(self, new_region):
        if not new_region or new_region == self.oci_config['region']:
            return
        
        self.log_ui(f"正在切换区域到: {new_region}...", "INFO")
        self.oci_config['region'] = new_region
        
        # 重新创建 clients
        proxy_url = self.oci_config.get("proxy", "").strip()
        proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
        
        try:
            self.compute_client = oci.core.ComputeClient(self.oci_config)
            self.virtual_network_client = oci.core.VirtualNetworkClient(self.oci_config)
            self.block_storage_client = oci.core.BlockstorageClient(self.oci_config)
            
            if proxies:
                for client in [self.compute_client, self.virtual_network_client, self.block_storage_client]:
                    if hasattr(client, 'base_client') and hasattr(client.base_client, 'session'):
                        client.base_client.session.proxies = proxies

            if hasattr(self, 'region_select_button'):
                self.region_select_button.config(text=f"区域: {new_region}")

            # 清除子网缓存
            self.session_subnet_id = None
            
            self.log_ui(f"已成功切换到区域: {new_region}", "INFO")
            # 刷新实例列表
            self.refresh_list_thread()
        except Exception as e:
            self.log_ui(f"切换区域失败: {e}", "ERROR")
            messagebox.showerror("切换区域失败", f"发生错误: {e}", parent=self.root)

    def show_cloudflare_settings(self):
        CloudflareSettingsDialog(self.root)

    def show_global_ssh_dialog(self):
        GlobalSSHKeyDialog(self.root, self.ssh_key_manager)

    def show_iam_manager(self):
        if not self.is_connected: return
        tenancy_ocid = self.oci_config['tenancy']
        IAMManagerWindow(self.root, self.identity_client, tenancy_ocid, self.logger)

    def handle_proxy_update(self, alias, proxy_url):
        self.all_profiles_data[alias]['proxy'] = proxy_url
        self.save_profiles_to_file()
        if proxy_url:
            msg = f"已为账号 '{alias}' 设置代理: {proxy_url}"
        else:
            msg = f"已清除账号 '{alias}' 的代理设置。"
        self.log_ui(msg, "INFO")
        messagebox.showinfo("代理设置成功", msg, parent=self.root)



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

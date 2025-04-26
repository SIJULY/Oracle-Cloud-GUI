# -*- coding: utf-8 -*-
# Enhanced Version with Start/Stop, Copy, Logging, Details View (incl. Tags/IPv6)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import oci
import os
import sys
import time
import threading
import configparser # Only needed for profile import now
import json
import secrets # For random password generation
import string  # For password character set
import base64  # For cloud-init user_data encoding
import logging # For enhanced logging

# --- Determine script directory and file paths ---
try: script_path = os.path.abspath(__file__)
except NameError: script_path = os.path.abspath(sys.argv[0])
script_dir = os.path.dirname(script_path)
# print(f"脚本运行目录: {script_dir}") # Logged later

PROFILES_FILENAME = "oci_gui_profiles.json"
SETTINGS_FILENAME = "oci_gui_settings.json"
LOG_FILENAME = "oci_gui_manager.log"
DEFAULT_CONFIG_FILENAME_FOR_IMPORT = "config"
PROFILES_FILE_PATH = os.path.join(script_dir, PROFILES_FILENAME)
SETTINGS_FILE_PATH = os.path.join(script_dir, SETTINGS_FILENAME)
LOG_FILE_PATH = os.path.join(script_dir, LOG_FILENAME)
DEFAULT_OCI_CONFIG_PATH = os.path.expanduser("~/.oci/config")

# --- Setup Logging ---
# Setup basic configuration for file logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename=LOG_FILE_PATH,
                    filemode='a') # Append mode

# --- Backend OCI 操作函数 ---
# (No changes needed in backend functions for this fix)
def get_detailed_instances(compute_client, virtual_network_client, block_storage_client, compartment_id, logger):
    """Fetches detailed instance information including IPs, boot vol size, tags, and basic IPv6."""
    instance_list_for_gui = []
    logger.info(f"开始获取区间 {compartment_id} 中的实例详情...")
    try:
        list_instances_response = compute_client.list_instances(compartment_id=compartment_id)
        instances = list_instances_response.data
        if not instances:
            logger.info("在指定区间未找到实例。")
            return [], "在指定区间未找到实例。"

        for instance in instances:
            instance_data = {
                "display_name": instance.display_name,
                "id": instance.id,
                "lifecycle_state": instance.lifecycle_state,
                "region": instance.region,
                "availability_domain": instance.availability_domain,
                "shape": instance.shape,
                "time_created": instance.time_created.strftime('%Y-%m-%d %H:%M:%S') if instance.time_created else "N/A",
                "ocpus": instance.shape_config.ocpus if instance.shape_config else "N/A",
                "memory_in_gbs": instance.shape_config.memory_in_gbs if instance.shape_config else "N/A",
                "private_ip": "获取中...",
                "public_ip": "获取中...",
                "ipv6_address": "获取中...", # Added for IPv6
                "vnic_id": None,
                "subnet_id": None, # Added for potential future use (like sec lists)
                "boot_volume_size_gb": "获取中...",
                "compartment_id": instance.compartment_id,
                "freeform_tags": instance.freeform_tags or {}, # Added for Tags
                "defined_tags": instance.defined_tags or {}  # Added for Tags
            }
            # logger.debug(f"正在处理实例: {instance.display_name} ({instance.id})")

            # Get Network Info (VNIC, IPs, Subnet)
            try:
                vnic_attachments = compute_client.list_vnic_attachments(
                    compartment_id=instance.compartment_id,
                    instance_id=instance.id
                ).data
                if vnic_attachments:
                    primary_vnic_attachment = vnic_attachments[0]  # Assuming primary VNIC is first
                    instance_data["vnic_id"] = primary_vnic_attachment.vnic_id
                    instance_data["subnet_id"] = primary_vnic_attachment.subnet_id
                    logger.debug(
                        f"  - 实例 {instance.display_name}: 找到 VNIC Attachment (VNIC ID: {instance_data['vnic_id']}, Subnet ID: {instance_data['subnet_id']})")

                    # Get VNIC details mainly for Private/Public IPv4
                    try:
                        vnic_details = virtual_network_client.get_vnic(vnic_id=instance_data["vnic_id"]).data
                        instance_data["private_ip"] = vnic_details.private_ip or "N/A"
                        instance_data["public_ip"] = vnic_details.public_ip or "N/A (或未分配)"
                        logger.debug(
                            f"  - VNIC详情 (IPv4): PrivateIP={instance_data['private_ip']}, PublicIP={instance_data['public_ip']}")
                    except oci.exceptions.ServiceError as vnic_err:
                        if vnic_err.status == 404:
                            instance_data["private_ip"], instance_data["public_ip"] = "VNIC不存在", "VNIC不存在"
                            logger.warning(
                                f"  - 获取 VNIC 详情时 VNIC {instance_data['vnic_id']} 未找到 (404): {vnic_err}")
                        else:
                            instance_data["private_ip"], instance_data["public_ip"] = "获取错误", "获取错误"
                            logger.error(f"  - 获取 VNIC 详情 (IPv4) 错误: {vnic_err}")
                    except Exception as vnic_exc:
                        instance_data["private_ip"], instance_data["public_ip"] = "获取意外错误", "获取意外错误"
                        logger.exception(f"  - 获取 VNIC 详情 (IPv4) 意外错误: {vnic_exc}")

                    # --- NEW: Get IPv6 address using list_ipv6s ---
                    instance_data["ipv6_address"] = "无"  # Default to None/Without
                    try:
                        logger.debug(f"  - 尝试调用 list_ipv6s for VNIC {instance_data['vnic_id']}...")
                        list_ipv6_response = virtual_network_client.list_ipv6s(vnic_id=instance_data["vnic_id"])
                        ipv6_objects = list_ipv6_response.data
                        if ipv6_objects:
                            # Take the first IPv6 address found associated with the VNIC
                            first_ipv6 = ipv6_objects[0]
                            instance_data[
                                "ipv6_address"] = first_ipv6.ip_address or "获取到空值"  # Get the actual IP address
                            logger.info(
                                f"  - 成功获取到 IPv6 地址: {instance_data['ipv6_address']} (来自 IPv6 对象 {first_ipv6.id})")
                        else:
                            logger.info(f"  - VNIC {instance_data['vnic_id']} 未找到关联的 IPv6 对象。")
                            instance_data["ipv6_address"] = "无"  # Explicitly set to None/Without if no objects found
                    except oci.exceptions.ServiceError as ipv6_err:
                        # Permissions needed: IPV6_READ
                        if ipv6_err.status in [401, 403]:
                            logger.error(
                                f"  - 获取 IPv6 列表错误 (权限不足 IPV6_READ?): {ipv6_err.status} {ipv6_err.code} - {ipv6_err.message}")
                            instance_data["ipv6_address"] = "权限错误"
                        elif ipv6_err.status == 404:
                            # Should not happen if VNIC exists, but handle defensively
                            logger.warning(
                                f"  - 获取 IPv6 列表时 VNIC {instance_data['vnic_id']} 未找到 (404): {ipv6_err}")
                            instance_data["ipv6_address"] = "VNIC不存在(IPv6)"
                        else:
                            logger.error(f"  - 获取 IPv6 列表错误: {ipv6_err}")
                            instance_data["ipv6_address"] = "获取错误(IPv6)"
                    except Exception as ipv6_exc:
                        logger.exception(f"  - 获取 IPv6 列表意外错误: {ipv6_exc}")
                        instance_data["ipv6_address"] = "获取意外错误(IPv6)"
                    # --- END NEW IPv6 Handling ---

                else:  # No VNIC attachments found
                    instance_data["private_ip"], instance_data["public_ip"], instance_data[
                        "ipv6_address"] = "无VNIC附件", "无VNIC附件", "无VNIC附件"
                    logger.warning(f"  - 实例 {instance.display_name} 未找到 VNIC 附件。")
            except Exception as net_error:  # Catch errors during vnic attachment listing
                logger.exception(f"  - 获取 VNIC 附件时发生意外错误 ({instance.display_name}): {net_error}")
                instance_data["private_ip"], instance_data["public_ip"], instance_data[
                    "ipv6_address"] = "获取错误", "获取错误", "获取错误"
                # --- End of the replaced network info fetching block ---

                # --- Get Boot Volume Size (Keep this part as it was) ---
            try:
                # ... (your existing boot volume code) ...
                boot_vol_attachments = compute_client.list_boot_volume_attachments(
                    availability_domain=instance.availability_domain,
                    compartment_id=instance.compartment_id,
                    instance_id=instance.id
                ).data
                if boot_vol_attachments:
                    boot_volume_id = boot_vol_attachments[0].boot_volume_id
                    boot_vol = block_storage_client.get_boot_volume(boot_volume_id=boot_volume_id).data
                    instance_data["boot_volume_size_gb"] = f"{int(boot_vol.size_in_gbs)} GB"
                else:
                    instance_data["boot_volume_size_gb"] = "无启动卷附件"
            except oci.exceptions.ServiceError as bv_error:
                if bv_error.status == 404:
                    instance_data["boot_volume_size_gb"] = "启动卷不存在"
                else:
                    logger.error(f"  - 获取启动卷大小错误 ({instance.display_name}): {bv_error}")
                    instance_data["boot_volume_size_gb"] = "获取错误"
            except Exception as bv_error:
                logger.error(f"  - 获取启动卷大小意外错误 ({instance.display_name}): {bv_error}")
                instance_data["boot_volume_size_gb"] = "获取错误"
                # --- End Boot Volume Size ---

            instance_list_for_gui.append(instance_data)

        logger.info(f"成功加载 {len(instance_list_for_gui)} 个实例的详情。")
        return instance_list_for_gui, f"成功加载 {len(instance_list_for_gui)} 个实例。"
    except oci.exceptions.ServiceError as e:
        error_msg = f"获取实例列表失败: {e.status} {e.code} - {e.message}\n请检查权限和区间OCID。"
        logger.error(error_msg)
        return [], error_msg
    except Exception as e:
        error_msg = f"获取实例列表时发生意外错误: {e}"
        logger.exception(error_msg) # Log stack trace for unexpected errors
        return [], error_msg

# **** CORRECTED: Use update_private_ip instead of update_vnic ****
# **** FINAL ATTEMPT: Use create/delete public_ip API ****
# **** FINAL ATTEMPT: Use create/delete public_ip API ****
def backend_change_public_ip(virtual_network_client, vnic_id, compartment_id, logger): # Ensure compartment_id is accepted
    """ Backend logic: Change public IP using get/delete/create PublicIp operations """
    logger.info(f"开始更换 VNIC {vnic_id} 的公网 IP (通过操作PublicIp对象)...")
    primary_private_ip_id = None
    try:
        # 1. Find the Primary Private IP OCID attached to the VNIC
        logger.info(f"  - 查找 VNIC {vnic_id} 的主私有 IP...")
        list_private_ips_response = oci.pagination.list_call_get_all_results(
            virtual_network_client.list_private_ips,
            vnic_id=vnic_id
        )
        primary_private_ip = None
        if list_private_ips_response.data:
            for private_ip_obj in list_private_ips_response.data:
                if private_ip_obj.is_primary:
                    primary_private_ip = private_ip_obj; break
        if not primary_private_ip:
            msg = f"未能在 VNIC {vnic_id} 上找到主私有 IP。"
            logger.error(msg)
            return False, msg
        primary_private_ip_id = primary_private_ip.id
        logger.info(f"  - 找到主私有 IP OCID: {primary_private_ip_id}")

        # 2. Find and Delete Existing *Ephemeral* Public IP associated with the Private IP
        logger.info(f"  - 查找当前关联的公网 IP (私有 IP: {primary_private_ip_id})...")
        existing_public_ip = None
        try:
            get_public_ip_details = oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=primary_private_ip_id)
            existing_public_ip_response = virtual_network_client.get_public_ip_by_private_ip_id(get_public_ip_details)
            existing_public_ip = existing_public_ip_response.data
            logger.info(f"  - 找到现有公网 IP: {existing_public_ip.ip_address} (OCID: {existing_public_ip.id}, Lifetime: {existing_public_ip.lifetime})")

            if existing_public_ip and existing_public_ip.lifetime == oci.core.models.PublicIp.LIFETIME_EPHEMERAL:
                logger.info(f"  - 步骤 1: 删除现有的临时公网 IP {existing_public_ip.id}...")
                virtual_network_client.delete_public_ip(existing_public_ip.id)
                logger.info("  - 删除请求已发送，等待 5 秒...")
                time.sleep(5) # Add delay for deletion propagation
            elif existing_public_ip:
                logger.warning(f"  - 注意：找到的公网 IP ({existing_public_ip.ip_address}) 不是临时的 (Lifetime={existing_public_ip.lifetime})，不会自动删除。继续尝试创建新的。")
                # Proceed to create, OCI might handle replacement or error out if not allowed.

        except oci.exceptions.ServiceError as get_pub_ip_error:
            if get_pub_ip_error.status == 404:
                logger.info("  - 未找到当前关联的公网 IP，继续创建新的...")
            else:
                logger.error(f"  - 查找现有公网IP时出错: {get_pub_ip_error}")
                raise # Re-raise error if it's not 404

        # 3. Create a new Ephemeral Public IP and assign it to the Private IP
        logger.info(f"  - 步骤 2: 创建新的临时公网 IP 并关联到私有 IP {primary_private_ip_id}...")
        # Use the passed compartment_id (likely tenancy root)
        create_public_ip_details = oci.core.models.CreatePublicIpDetails(
            compartment_id=compartment_id,
            lifetime=oci.core.models.PublicIp.LIFETIME_EPHEMERAL,
            private_ip_id=primary_private_ip_id
        )
        create_public_ip_response = virtual_network_client.create_public_ip(create_public_ip_details)
        new_public_ip_obj = create_public_ip_response.data
        new_public_ip_address = new_public_ip_obj.ip_address
        logger.info(f"  - 新公网 IP 创建请求已发送。新 IP 地址: {new_public_ip_address} (OCID: {new_public_ip_obj.id})")
        logger.info("  - 等待 IP 分配稳定 (10 秒)...")
        time.sleep(10) # Add delay for allocation

        return True, f"IP 更换请求已发送 (通过操作PublicIp)。新公网IP: {new_public_ip_address}"

    except oci.exceptions.ServiceError as e:
        error_msg = f"更换 IP (操作PublicIp)失败: {e.status} {e.code} - {e.message}"
        if e.status in [401, 403, 404]:
            error_msg += "\n请检查 'manage public-ips', 'use private-ips' 等权限及相关 OCID。"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"更换 IP (操作PublicIp) 时发生意外错误: {e}"
        logger.exception(error_msg)
        return False, error_msg

def backend_instance_action(compute_client, instance_id, action, logger):
    """Performs START, STOP, SOFTRESET actions on an instance."""
    action_upper = action.upper()
    logger.info(f"发送实例操作 '{action_upper}' 命令到实例 {instance_id}...")
    try:
        compute_client.instance_action(instance_id=instance_id, action=action_upper)
        msg = f"实例 {action_upper} 命令已发送。"
        logger.info(msg)
        # Add a small delay after sending action command
        time.sleep(5)
        return True, msg
    except oci.exceptions.ServiceError as e:
        error_msg = f"实例 {action_upper} 失败: {e.status} {e.code} - {e.message}\n请检查权限和实例 ID。"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"实例 {action_upper} 时发生意外错误: {e}"
        logger.exception(error_msg)
        return False, error_msg

# Wrapper functions for specific actions calling the generic one
def backend_start_instance(compute_client, instance_id, logger):
    return backend_instance_action(compute_client, instance_id, "START", logger)

def backend_stop_instance(compute_client, instance_id, logger):
    return backend_instance_action(compute_client, instance_id, "STOP", logger)

def backend_restart_instance(compute_client, instance_id, logger):
    return backend_instance_action(compute_client, instance_id, "SOFTRESET", logger)


def backend_terminate_instance(compute_client, instance_id, preserve_boot_volume, logger):
    logger.warning(f"发送实例终止命令到实例 {instance_id} (保留启动卷: {preserve_boot_volume})...")
    try:
        compute_client.terminate_instance(instance_id=instance_id, preserve_boot_volume=preserve_boot_volume)
        msg = f"实例终止命令已发送。"
        logger.info(msg)
        # Add a longer delay after termination
        time.sleep(10)
        return True, msg
    except oci.exceptions.ServiceError as e:
        error_msg = f"终止失败: {e.status} {e.code} - {e.message}\n请检查权限和实例 ID。"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"终止时发生意外错误: {e}"
        logger.exception(error_msg)
        return False, error_msg

def backend_list_subnets(vnet_client, compartment_id, logger):
    subnets = []; error = None
    if not compartment_id:
        msg = "未提供有效的区间OCID来列出子网。"
        logger.error(msg)
        return [], msg
    try:
        logger.info(f"后台：正在列出区间 '{compartment_id}' 中的子网...")
        list_subnets_response = oci.pagination.list_call_get_all_results(
            vnet_client.list_subnets,
            compartment_id=compartment_id,
            lifecycle_state='AVAILABLE'
        )
        for subnet in list_subnets_response.data:
            subnets.append({
                "display_name": subnet.display_name,
                "cidr": subnet.cidr_block,
                "id": subnet.id
            })
        logger.info(f"后台：找到 {len(subnets)} 个可用子网。")
    except oci.exceptions.ServiceError as e:
        error = f"获取子网列表失败: {e.status} {e.code} - {e.message}\n请检查'use subnets'权限和区间OCID。"
        logger.error(error)
    except Exception as e:
        error = f"获取子网列表意外错误: {e}"
        logger.exception(error)
    return subnets, error

def backend_find_image_ocid(compute_client, os_name, os_version, shape_name, logger):
    try:
        tenancy_id = compute_client.base_client.config.get('tenancy')
        if not tenancy_id:
             msg = "无法从当前配置中获取 Tenancy OCID。"
             logger.error(msg)
             return None, msg
        logger.info(f"查找镜像: os='{os_name}', version='{os_version}', shape='{shape_name}' (在租户 {tenancy_id} 中搜索)")
        list_images_response = oci.pagination.list_call_get_all_results(
            compute_client.list_images,
            compartment_id=tenancy_id, # Search in tenancy root for platform images
            operating_system=os_name,
            operating_system_version=os_version,
            shape=shape_name,
            sort_by="TIMECREATED",
            sort_order="DESC",
            lifecycle_state = oci.core.models.Image.LIFECYCLE_STATE_AVAILABLE
        )
        if list_images_response.data:
            latest_image = list_images_response.data[0]
            logger.info(f"在租户根区间找到镜像: {latest_image.display_name} ({latest_image.id})")
            return latest_image.id, None
        else:
            error_msg = f"在租户根区间未找到与 '{os_name} {os_version} ({shape_name})' 兼容的可用平台镜像。"
            logger.warning(error_msg)
            return None, error_msg
    except oci.exceptions.ServiceError as e:
        error_msg = f"查找镜像失败: {e.status} {e.code} - {e.message}"
        if e.status in [401, 403, 404]:
            error_msg += "\n请检查是否拥有在租户根区间 'inspect images' 的权限。"
        logger.error(error_msg)
        return None, error_msg
    except Exception as e:
        error_msg = f"查找镜像时发生意外错误: {e}"
        logger.exception(error_msg)
        return None, error_msg

def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+=-`~[]{};:,.<>?"
    password = ''.join(secrets.choice(characters) for i in range(length))
    return password

def generate_cloud_init_userdata(root_password):
    cloud_config = f"""#cloud-config
password: {root_password}
chpasswd: {{ expire: False }}
ssh_pwauth: True
runcmd:
  - sed -i 's/^PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config
  - sed -i 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  - systemctl restart sshd || service sshd restart || service ssh restart
"""
    return base64.b64encode(cloud_config.encode('utf-8')).decode('utf-8')

def backend_create_instance(compute_client, identity_client, details, logger):
    logger.info("开始创建实例流程...")
    try:
        profile_defaults = details['profile_defaults']
        # ** Use tenancy OCID as the compartment for creating instances **
        # This aligns with the behavior of listing instances from tenancy root.
        # If compartment-specific creation is needed later, this needs adjustment.
        tenancy_ocid = profile_defaults.get('tenancy')
        if not tenancy_ocid:
            msg = "账号配置中缺少必需的 'tenancy' OCID。"
            logger.error(msg)
            return False, msg
        compartment_id = tenancy_ocid
        logger.info(f"将使用区间 OCID: {compartment_id} (租户根区间)")

        logger.info("自动查找可用域...")
        ads, error = [], None
        try:
            list_ads_response = oci.pagination.list_call_get_all_results(
                identity_client.list_availability_domains,
                compartment_id=tenancy_ocid # ADs are listed under tenancy
            )
            ads = list_ads_response.data
            logger.debug(f"找到的可用域: {[ad.name for ad in ads]}")
        except Exception as ad_err:
            error = f"无法列出可用域: {ad_err}"
            logger.error(error)

        if error or not ads:
            return False, error or "无法自动确定可用域。"

        # Simple strategy: use the first AD found
        ad_name = ads[0].name
        logger.info(f"自动选择第一个可用域: {ad_name}")

        # Get Subnet and SSH Key from defaults
        subnet_id = profile_defaults.get('default_subnet_ocid')
        if not subnet_id:
            msg = "账号配置中缺少必需的 'default_subnet_ocid'。"
            logger.error(msg)
            return False, msg
        logger.info(f"使用默认子网 OCID: ...{subnet_id[-12:]}")

        ssh_key = profile_defaults.get('default_ssh_public_key')
        if not ssh_key:
            msg = "账号配置中缺少必需的 'default_ssh_public_key'。"
            logger.error(msg)
            return False, msg
        logger.info(f"使用默认 SSH 公钥。")

        # Find Image OCID
        image_ocid, error = backend_find_image_ocid(
            compute_client, details['os_name'], details['os_version'], details['shape'], logger
        )
        if error or not image_ocid:
             msg = f"查找镜像失败: {error or '未找到兼容镜像'}"
             logger.error(msg)
             return False, msg
        logger.info(f"使用镜像 OCID: {image_ocid}")

        # Prepare Cloud-Init for root password
        root_password = generate_random_password()
        user_data_encoded = generate_cloud_init_userdata(root_password)
        logger.info("已生成随机 Root 密码并通过 cloud-init 设置。")

        # Prepare Launch Details (common parts)
        base_name_for_init = details.get('display_name_prefix', 'Instance')
        launch_details = oci.core.models.LaunchInstanceDetails(
            compartment_id=compartment_id,
            availability_domain=ad_name,
            shape=details['shape'],
            display_name=base_name_for_init, # Will be updated in loop
            create_vnic_details=oci.core.models.CreateVnicDetails(
                subnet_id=subnet_id,
                assign_public_ip=True # Always assign public IP in simplified mode
                # assign_ipv6_ip=False # Default, add UI later if needed
            ),
            metadata={
                "ssh_authorized_keys": ssh_key,
                "user_data": user_data_encoded
            },
            source_details=oci.core.models.InstanceSourceViaImageDetails(
                image_id=image_ocid,
                boot_volume_size_in_gbs=details['boot_volume_size']
            ),
            shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                ocpus=details.get('ocpus'),
                memory_in_gbs=details.get('memory_in_gbs')
            ) if details.get('ocpus') or details.get('memory_in_gbs') else None
        )

        # Launch instances
        created_instances_info = []
        base_name = details.get('display_name_prefix', 'Instance')
        instance_count = details.get('instance_count', 1)
        all_success = True
        error_messages = []

        for i in range(instance_count):
            instance_name = f"{base_name}-{i+1}" if instance_count > 1 else base_name
            launch_details.display_name = instance_name # Set specific name for this instance
            logger.info(f"尝试创建实例 {i+1}/{instance_count}: {instance_name}")
            try:
                launch_response = compute_client.launch_instance(launch_details)
                instance_ocid = launch_response.data.id
                logger.info(f"  -> 请求已发送。实例 OCID: {instance_ocid}")
                created_instances_info.append({"name": instance_name, "ocid": instance_ocid})
            except oci.exceptions.ServiceError as e:
                all_success = False
                error_msg = f"创建 '{instance_name}' 失败: {e.status} {e.code} - {e.message}"
                error_messages.append(error_msg)
                logger.error(f"  -> 失败: {error_msg}")
                break # Stop creating more instances if one fails
            except Exception as e:
                all_success = False
                error_msg = f"创建 '{instance_name}' 意外错误: {e}"
                error_messages.append(error_msg)
                logger.exception(f"  -> 失败: {error_msg}") # Log stack trace
                break # Stop creating more instances if one fails

            # Small delay between instance creation requests
            if i < instance_count - 1:
                time.sleep(3)

        # Format result message
        if created_instances_info:
            success_msg = "实例创建请求已发送:\n" + "\n".join([f"- {info['name']} (OCID: ...{info['ocid'][-12:]})" for info in created_instances_info])
            success_msg += f"\n\n*** 重要: 请立即保存以下生成的 Root 密码！ ***\n\nRoot 密码: {root_password}\n"
            if not all_success:
                success_msg += "\n\n但后续实例创建因错误中止:\n" + "\n".join(error_messages)
            logger.info("部分或全部实例创建请求成功。")
            return True, success_msg
        else:
            if not error_messages:
                error_messages.append("未知错误导致无法创建任何实例。")
            final_error_msg = "所有实例创建均失败:\n" + "\n".join(error_messages)
            logger.error(final_error_msg)
            return False, final_error_msg

    except Exception as e:
        error_msg = f"创建实例准备阶段出错: {e}"
        logger.exception(error_msg) # Log stack trace for setup errors
        return False, error_msg
# --- End Backend Functions ---

# --- Add this new backend function ---

# --- 在全局函数区域 ---

# --- Replace the old backend_assign_ipv6_to_vnic with this new version ---

def backend_assign_ipv6_to_vnic(virtual_network_client, vnic_id, subnet_id, logger):
    """
    Assigns an IPv6 address to an existing VNIC using the create_ipv6 API.
    Requires the subnet_id to determine the IPv6 CIDR block.
    """
    logger.info(f"开始为 VNIC {vnic_id} (子网 {subnet_id}) 分配 IPv6 (使用 create_ipv6 API)...")

    if not subnet_id:
        msg = f"错误：缺少子网 ID (Subnet ID)，无法确定 IPv6 分配范围。"
        logger.error(msg)
        return False, msg

    try:
        # 1. Get Subnet details to find the IPv6 CIDR block
        logger.info(f"  - 步骤 1: 获取子网 {subnet_id} 的详细信息...")
        subnet = virtual_network_client.get_subnet(subnet_id).data
        subnet_ipv6_cidr = subnet.ipv6_cidr_block
        logger.info(f"  - 子网 IPv6 CIDR: {subnet_ipv6_cidr}")

        if not subnet_ipv6_cidr:
            msg = f"错误：子网 {subnet_id} 未配置 IPv6 CIDR 块，无法分配 IPv6 地址。\n请先在 OCI 控制台为该子网分配 IPv6 CIDR。"
            logger.error(msg)
            return False, msg

        # 2. Prepare details for the create_ipv6 API call
        #    We provide the vnic_id and the subnet's IPv6 CIDR.
        #    OCI should automatically assign an available address from this CIDR.
        create_ipv6_details = oci.core.models.CreateIpv6Details(
            vnic_id=vnic_id,
            ipv6_subnet_cidr=subnet_ipv6_cidr
            # display_name=f"ipv6-{vnic_id[-6:]}" # Optional: Set a display name
        )
        logger.info(f"  - 步骤 2: 准备调用 create_ipv6 API...")
        logger.debug(f"  - CreateIpv6Details: {create_ipv6_details}")

        # 3. Call the create_ipv6 API
        create_ipv6_response = virtual_network_client.create_ipv6(create_ipv6_details)
        new_ipv6_address = create_ipv6_response.data.ip_address
        new_ipv6_ocid = create_ipv6_response.data.id

        msg = f"已成功为 VNIC {vnic_id} 请求创建 IPv6 地址。\n新 IPv6 地址: {new_ipv6_address} (OCID: {new_ipv6_ocid})\n请稍后刷新列表查看，并在操作系统内配置网络。"
        logger.info(msg)
        # Give some time for assignment
        time.sleep(5)
        return True, msg

    except oci.exceptions.ServiceError as e:
        error_msg = f"为 VNIC {vnic_id} 创建 IPv6 失败: {e.status} {e.code} - {e.message}"
        if e.status == 409 and 'Maximum number of IPv6 addresses per VNIC exceeded' in e.message:
             error_msg += "\n提示：该 VNIC 已达到 IPv6 地址数量上限。"
             logger.error(f"VNIC {vnic_id} 创建 IPv6 失败 - 已达上限: {e.message}")
        elif e.status == 400 and ('No available addresses' in e.message or 'CIDR block is full' in e.message):
             error_msg += f"\n提示：子网 {subnet_ipv6_cidr if 'subnet_ipv6_cidr' in locals() else subnet_id} 中已无可用 IPv6 地址。"
             logger.error(f"VNIC {vnic_id} 创建 IPv6 失败 - 子网无可用地址: {e.message}")
        elif e.status in [401, 403, 404]:
            error_msg += "\n请检查权限 (需要 IPV6_CREATE, SUBNET_READ) 以及 VNIC/Subnet OCID 是否正确。"
            logger.error(f"VNIC {vnic_id} 创建 IPv6 失败 - 权限或OCID问题: {e.status} {e.code} - {e.message}")
        else:
            logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"为 VNIC {vnic_id} 创建 IPv6 时发生意外错误: {e}"
        logger.exception(f"为 VNIC {vnic_id} 创建 IPv6 时发生意外 ({type(e).__name__}): {e}")
        return False, error_msg

# --- End of the new backend_assign_ipv6_to_vnic function ---

# --- End of new backend function ---


# --- Dialog Classes ---
# ImportDialog (Corrected - Removed Optional Fields)
class ImportDialog(tk.Toplevel):
     # ...(Same as previous version)...
     def __init__(self, parent, original_profiles_from_ini, existing_aliases_in_use, callback, logger):
        super().__init__(parent); self.transient(parent); self.title("导入档案并设置别名/默认值"); self.geometry("650x400"); # Adjusted height
        self.original_profiles = original_profiles_from_ini; self.existing_aliases_in_use = set(existing_aliases_in_use); self.callback = callback; self.profile_widgets = {}; self.logger = logger
        canvas = tk.Canvas(self); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview); scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        content_frame = ttk.Frame(canvas, padding="10"); content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))); canvas.create_window((0, 0), window=content_frame, anchor="nw"); canvas.configure(yscrollcommand=scrollbar.set)
        ttk.Label(content_frame, text="为要导入的档案设置别名和必需的默认值:").grid(row=0, column=0, columnspan=4, pady=(0, 10), sticky='w'); row_idx = 1
        for i, profile in enumerate(self.original_profiles):
            widgets = {};
            if i > 0: ttk.Separator(content_frame, orient='horizontal').grid(row=row_idx, column=0, columnspan=4, sticky='ew', pady=5); row_idx += 1
            import_var = tk.BooleanVar(value=True); widgets['import_var'] = import_var; ttk.Label(content_frame, text=f"原始档案名: [{profile}]").grid(row=row_idx, column=0, columnspan=4, padx=5, pady=3, sticky='w'); row_idx += 1
            ttk.Label(content_frame, text="导入?").grid(row=row_idx, column=0, padx=5, pady=3, sticky='e'); chk = ttk.Checkbutton(content_frame, variable=import_var); chk.grid(row=row_idx, column=1, padx=5, pady=3, sticky='w')
            ttk.Label(content_frame, text="设置别名*:").grid(row=row_idx, column=2, padx=5, pady=3, sticky='e'); alias_entry = ttk.Entry(content_frame, width=30); alias_entry.insert(0, profile); widgets['alias_entry'] = alias_entry; alias_entry.grid(row=row_idx, column=3, padx=5, pady=3, sticky='w'); row_idx += 1
            ttk.Label(content_frame, text="默认子网 OCID*:").grid(row=row_idx, column=0, columnspan=2, padx=5, pady=3, sticky='e'); subnet_entry = ttk.Entry(content_frame, width=50); widgets['subnet_entry'] = subnet_entry; subnet_entry.grid(row=row_idx, column=2, columnspan=2, padx=5, pady=3, sticky='w'); row_idx += 1
            ttk.Label(content_frame, text="默认SSH公钥*:").grid(row=row_idx, column=0, columnspan=2, padx=5, pady=3, sticky='e'); ssh_entry = ttk.Entry(content_frame, width=50); widgets['ssh_entry'] = ssh_entry; ssh_entry.grid(row=row_idx, column=2, columnspan=2, padx=5, pady=3, sticky='w'); row_idx += 1
            self.profile_widgets[profile] = widgets
        ttk.Label(content_frame, text="* 为使用简化版'创建实例'功能，'设置别名'、'默认子网 OCID' 和 '默认SSH公钥' 是必需的。", foreground="blue").grid(row=row_idx, column=0, columnspan=4, pady=(10, 5), sticky='w'); row_idx += 1
        button_frame = ttk.Frame(content_frame); button_frame.grid(row=row_idx, column=0, columnspan=4, pady=(15, 0))
        import_button = ttk.Button(button_frame, text="导入选中档案", command=self.import_selected); import_button.pack(side="left", padx=10)
        cancel_button = ttk.Button(button_frame, text="取消", command=self.destroy); cancel_button.pack(side="left", padx=10)
        self.grab_set(); self.wait_window()
     def import_selected(self):
        self.logger.info("开始处理导入对话框的选择...")
        profiles_to_import_full_data = {}; aliases_in_use_this_dialog = set(); has_duplicate = False; missing_required_defaults = []; existing_aliases_in_app = set(self.existing_aliases_in_use)
        for original_name, widgets in self.profile_widgets.items():
            if widgets['import_var'].get():
                alias = widgets['alias_entry'].get().strip() or original_name; subnet = widgets['subnet_entry'].get().strip(); ssh_key = widgets['ssh_entry'].get().strip()
                if not alias:
                    messagebox.showwarning("别名无效", f"档案 '{original_name}' 的别名不能为空。", parent=self); return
                if alias in aliases_in_use_this_dialog:
                    messagebox.showwarning("别名重复", f"别名 '{alias}' 在本次导入中被多次使用。", parent=self); has_duplicate = True; break
                aliases_in_use_this_dialog.add(alias)
                if not subnet or not ssh_key:
                    self.logger.warning(f"档案 '{original_name}' (别名 '{alias}') 缺少默认子网或SSH密钥。")
                    missing_required_defaults.append(alias)
                profiles_to_import_full_data[alias] = { "original_name": original_name, "defaults": { "default_subnet_ocid": subnet or None, "default_ssh_public_key": ssh_key or None } }
        if has_duplicate:
            self.logger.warning("导入中止，因为在对话框中发现重复别名。")
            return
        if missing_required_defaults:
            self.logger.warning(f"以下别名缺少默认值: {missing_required_defaults}")
            if not messagebox.askyesno("缺少默认值", f"以下别名缺少必要的默认子网或SSH公钥，将无法使用简化创建功能:\n - {', '.join(missing_required_defaults)}\n\n仍要导入吗 (后续可编辑补充)?", parent=self):
                 profiles_to_import_full_data = {a: d for a, d in profiles_to_import_full_data.items() if a not in missing_required_defaults}
                 if not profiles_to_import_full_data:
                     self.logger.info("没有可导入的档案了 (用户取消或过滤后为空)。")
                     self.destroy(); return
        conflicts = [alias for alias in profiles_to_import_full_data if alias in existing_aliases_in_app]
        if conflicts:
             self.logger.warning(f"发现与现有配置冲突的别名: {conflicts}")
             if not messagebox.askyesno("确认覆盖?", f"以下别名已存在:\n - {', '.join(conflicts)}\n\n确定要覆盖吗？", icon='warning', parent=self):
                 profiles_to_import_full_data = {a: d for a, d in profiles_to_import_full_data.items() if a not in conflicts}
                 if not profiles_to_import_full_data:
                     self.logger.info("没有可导入的档案了 (用户取消覆盖或过滤后为空)。")
                     self.destroy(); return
        if self.callback:
            self.logger.info(f"准备回调主程序处理导入数据: {list(profiles_to_import_full_data.keys())}")
            self.callback(profiles_to_import_full_data)
        self.destroy()

# EditProfileDialog (Corrected - Removed Optional Fields, Adjusted Layout)
class EditProfileDialog(tk.Toplevel):
    # 确保这个方法定义在 EditProfileDialog 类内部，并且缩进正确
    def __init__(self, parent, alias, profile_data, vnet_client, callback, logger):
        super().__init__(parent); self.transient(parent); self.title(f"编辑账号: {alias}");

        # --- 不再设置固定尺寸 ---
        # self.geometry("700x500"); # Removed

        self.resizable(True, True) # 允许调整大小
        self.profile_data_original = profile_data.copy(); self.alias_original = alias; self.callback = callback
        self.vnet_client = vnet_client; self.entries = {}; self.subnets_map = {}; self.logger=logger
        self.selected_subnet_ocid_var = tk.StringVar()

        # --- 移除 Canvas 和 Scrollbar，直接创建 content_frame ---
        # canvas = tk.Canvas(self); scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        # scrollbar.pack(side=tk.RIGHT, fill=tk.Y); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        # content_frame = ttk.Frame(canvas, padding="10"); # 原来父控件是 canvas
        # content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))) # 不再需要
        # canvas.create_window((0, 0), window=content_frame, anchor="nw"); # 不再需要
        # canvas.configure(yscrollcommand=scrollbar.set) # 不再需要

        # --- 直接在 self (Toplevel窗口) 中创建 content_frame ---
        content_frame = ttk.Frame(self, padding="10")
        # --- 让 content_frame 充满窗口 ---
        content_frame.pack(expand=True, fill='both') # 使用 pack 而不是 grid

        # --- Widgets (放入 content_frame，这部分逻辑不变，但注意父控件是 content_frame) ---
        ttk.Label(content_frame, text=f"编辑账号配置和默认值 (别名: {alias})").grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky='w')
        fields = [ ('user', 'User OCID*:', 60, True), ('fingerprint', '指纹*:', 60, True), ('tenancy', 'Tenancy OCID*:', 60, True), ('region', '区域*:', 30, True), ('key_file', '密钥文件路径*:', 50, True), ('passphrase', '密钥密码(可选):', 30, False) ]
        row_idx = 1
        for key, label, width, req_conn in fields:
            ttk.Label(content_frame, text=label).grid(row=row_idx, column=0, sticky=tk.E, padx=5, pady=3)
            entry = ttk.Entry(content_frame, width=width); entry.insert(0, self.profile_data_original.get(key) or ""); entry.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=3); self.entries[key] = entry
            if key == 'key_file': browse = ttk.Button(content_frame, text="浏览...", command=lambda e=entry: self.browse_edit_key(e)); browse.grid(row=row_idx, column=2, padx=5, sticky='w')
            if key == 'tenancy': entry.bind("<FocusOut>", lambda event, k=key: self.load_subnets_for_edit()); entry.bind("<Return>", lambda event, k=key: self.load_subnets_for_edit())
            row_idx += 1
        ttk.Label(content_frame, text="默认子网 OCID**:").grid(row=row_idx, column=0, sticky=tk.E, padx=5, pady=3)
        self.subnet_combobox = ttk.Combobox(content_frame, textvariable=self.selected_subnet_ocid_var, state='disabled', width=48, values=[" "]); # 宽度可能需要调整
        self.subnet_combobox.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=3)
        self.load_subnet_button = ttk.Button(content_frame, text="加载/刷新子网", command=self.load_subnets_for_edit);
        self.load_subnet_button.grid(row=row_idx, column=2, padx=5, sticky='w')
        self.entries["default_subnet_ocid"] = self.selected_subnet_ocid_var
        row_idx += 1
        ttk.Label(content_frame, text="默认SSH公钥**:").grid(row=row_idx, column=0, sticky=tk.NE, padx=5, pady=3)
        # --- 使用普通的 Text 可能更适合自适应高度，但 ScrolledText 也可以，只是滚动条通常不会出现 ---
        self.ssh_key_text = scrolledtext.ScrolledText(content_frame, width=60, height=5, wrap=tk.WORD); # height=5 可能还是会影响计算
        # 或者尝试普通 Text:
        # self.ssh_key_text = tk.Text(content_frame, width=60, height=5, wrap=tk.WORD)
        self.ssh_key_text.insert("1.0", self.profile_data_original.get("default_ssh_public_key") or "");
        self.ssh_key_text.grid(row=row_idx, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=3);
        self.entries["default_ssh_public_key"] = self.ssh_key_text; row_idx +=1
        ttk.Label(content_frame, text="* OCI连接必需字段.", foreground="gray").grid(row=row_idx, column=1, columnspan=2, sticky='w', padx=5, pady=2); row_idx += 1
        ttk.Label(content_frame, text="** 使用简化'创建实例'功能必需字段.", foreground="blue").grid(row=row_idx, column=1, columnspan=2, sticky='w', padx=5, pady=2); row_idx += 1
        button_frame = ttk.Frame(content_frame); button_frame.grid(row=row_idx, column=0, columnspan=3, pady=(15, 5))
        save_button = ttk.Button(button_frame, text="保存更改", command=self.save_changes); save_button.pack(side="left", padx=10)
        cancel_button = ttk.Button(button_frame, text="取消", command=self.destroy); cancel_button.pack(side="left", padx=10)
        # --- 让 content_frame 的列可以拉伸 ---
        content_frame.columnconfigure(1, weight=1)

        # --- Initial Subnet Load Trigger ---
        # Attempt initial load only if connected *and* tenancy is present
        if self.vnet_client and self.entries.get('tenancy').get().strip():
            self.load_subnets_for_edit(initial=True)
        elif self.vnet_client: # Connected but no tenancy typed yet
            self.subnet_combobox.config(values=["请输入Tenancy OCID后加载"], state='disabled'); self.load_subnet_button.config(state='normal')
        else: # Not connected
           self.subnet_combobox.config(values=["需先连接才能加载"], state='disabled'); self.load_subnet_button.config(state='disabled')

        # --- 窗口显示和等待 ---
        self.grab_set(); self.wait_window()

# --- End of EditProfileDialog.__init__ replacement ---

    def browse_edit_key(self, entry_widget):
        # Ensure correct indentation for the method
        filepath = filedialog.askopenfilename(title="选择私钥文件", filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filepath: entry_widget.delete(0, tk.END); entry_widget.insert(0, filepath)
        self.logger.info(f"在编辑对话框中选择了密钥文件: {filepath}")

    def load_subnets_for_edit(self, initial=False):
        # Ensure correct indentation for the method
        if not self.vnet_client:
             if not initial: msg = "请先在主窗口连接此账号，才能加载子网列表。"; self.logger.warning(msg); messagebox.showwarning("未连接", msg, parent=self)
             else: self.logger.info("编辑对话框：未连接，无法自动加载子网。")
             return
        comp_ocid = self.entries['tenancy'].get().strip()
        if not comp_ocid:
             if not initial: msg = "请输入 Tenancy OCID 以加载子网。"; self.logger.warning(msg); messagebox.showwarning("缺少信息", msg, parent=self)
             else: self.logger.info("编辑对话框：Tenancy OCID 为空，无法自动加载子网。")
             self.subnet_combobox.config(values=["请输入Tenancy OCID"], state='disabled'); self.selected_subnet_ocid_var.set('')
             return
        self.logger.info(f"编辑对话框：请求加载区间 '{comp_ocid}' 的子网列表...")
        self.subnet_combobox.config(values=["正在加载..."], state='disabled'); self.selected_subnet_ocid_var.set("正在加载...")
        self.load_subnet_button.config(state='disabled')
        # --- Ensure 'load_subnets_backend' method exists below ---
        thread = threading.Thread(target=self.load_subnets_backend, args=(comp_ocid, initial), daemon=True); thread.start()

    # --- THIS METHOD MUST EXIST AND BE CORRECTLY INDENTED ---
    def load_subnets_backend(self, compartment_id, initial):
        # Ensure correct indentation for the method
        subnets, error = backend_list_subnets(self.vnet_client, compartment_id, self.logger)
        subnet_display_list = []; self.subnets_map.clear(); cb_state = 'disabled'; selected_val = ''
        if error:
            if not initial: self.after(0, lambda err=error: messagebox.showerror("获取子网错误", err, parent=self))
            else: self.logger.error(f"编辑对话框初始化时获取子网错误: {error}")
            subnet_display_list = ["加载错误"]
        elif subnets:
            for subnet in subnets: display_name = f"{subnet['display_name']} ({subnet['cidr']})"; subnet_display_list.append(display_name); self.subnets_map[display_name] = subnet['id']
            cb_state = 'readonly'
            saved_subnet_ocid = self.profile_data_original.get('default_subnet_ocid'); found_match = False
            if saved_subnet_ocid:
                for disp, ocid in self.subnets_map.items():
                     if ocid == saved_subnet_ocid: selected_val = disp; found_match = True; self.logger.info(f"编辑对话框：预选子网基于已保存的OCID: {disp}"); break
            current_selection = self.selected_subnet_ocid_var.get()
            if not found_match and current_selection in self.subnets_map: selected_val = current_selection; found_match = True; self.logger.info(f"编辑对话框：保持当前选择的子网: {selected_val}")
            if not found_match and subnet_display_list: sorted_list = sorted(subnet_display_list); selected_val = sorted_list[0]; self.logger.info(f"编辑对话框：无匹配或当前选择无效，默认选择第一个子网: {selected_val}")
        else:
            subnet_display_list = ["未找到可用子网"]
            if not initial: self.logger.warning(f"编辑对话框：在区间 '{compartment_id}' 中未找到可用子网。"); self.after(0, lambda cid=compartment_id: messagebox.showinfo("无子网", f"在区间 '{cid}' 中未找到可用子网。", parent=self))
            else: self.logger.info(f"编辑对话框初始化：在区间 '{compartment_id}' 中未找到可用子网。")
        # --- Schedule UI updates safely ---
        def update_ui():
            if not self.winfo_exists(): self.logger.warning("编辑对话框已在更新子网列表前关闭，取消UI更新。"); return
            try:
                self.subnet_combobox.config(values=sorted(subnet_display_list), state=cb_state)
                self.selected_subnet_ocid_var.set(selected_val)
                self.load_subnet_button.config(state='normal')
                self.logger.info("编辑对话框：子网下拉列表UI已更新。")
            except tk.TclError as e: self.logger.error(f"更新编辑对话框UI时捕获到 TclError (可能控件仍被销毁): {e}")
            except Exception as e_generic: self.logger.exception(f"更新编辑对话框UI时发生意外错误: {e_generic}")
        self.after(0, update_ui) # Schedule the nested function

    def save_changes(self):
        # Ensure correct indentation for the method
        self.logger.info(f"尝试保存对账号 '{self.alias_original}' 的更改...")
        updated_data = {}
        for key, widget in self.entries.items():
            if key == "default_subnet_ocid": display_value = widget.get(); selected_ocid = self.subnets_map.get(display_value); updated_data[key] = selected_ocid; self.logger.debug(f"  - default_subnet_ocid: Display='{display_value}', OCID='{selected_ocid}'")
            elif key == "default_ssh_public_key": value = widget.get("1.0", tk.END).strip(); updated_data[key] = value if value else None; self.logger.debug(f"  - default_ssh_public_key: {'已设置' if value else '空'}")
            elif key not in ["default_compartment_ocid", "default_ad_name"]: value = widget.get().strip(); updated_data[key] = value if value else None; log_val = value if key not in ['passphrase'] else ('****' if value else '空'); self.logger.debug(f"  - {key}: {log_val}")
        required_keys = ['user', 'fingerprint', 'tenancy', 'region', 'key_file']
        missing = [k for k in required_keys if not updated_data.get(k)]
        if missing: msg = f"必需字段 ({', '.join(missing)}) 不能为空。"; self.logger.error(f"保存失败: {msg}"); messagebox.showerror("缺少信息", msg, parent=self); return
        updated_data.pop("default_compartment_ocid", None); updated_data.pop("default_ad_name", None)
        if self.callback: self.logger.info(f"保存成功，回调主程序更新账号 '{self.alias_original}'。"); self.callback(self.alias_original, updated_data)
        self.destroy()

# CreateInstanceDialog (No changes needed)
class CreateInstanceDialog(tk.Toplevel):
    # Ensure class definition starts at correct indentation level (usually none if at top level)

    # Correct __init__ accepting all required parameters
    def __init__(self, parent, compute_client, identity_client, profile_data, callback, logger):
        # Ensure method indentation is correct (Level 1 within class)
        super().__init__(parent); self.transient(parent); self.title("创建新实例 (简化模式)");
        # Removed fixed geometry to allow auto-sizing, you can add it back if preferred
        # self.geometry("500x380");
        self.resizable(False, False) # Dialog usually not resizable

        # Store arguments
        self.parent = parent # Store parent reference if needed
        self.compute_client = compute_client
        self.identity_client = identity_client
        self.profile_data = profile_data
        self.callback = callback
        self.logger = logger

        # Instance variables for widgets and state
        self.selected_shape = tk.StringVar()
        self.instance_type = tk.StringVar(value="AMD") # Default architecture
        self.os_choice_var = tk.StringVar()
        self.assign_ipv6_var = tk.BooleanVar(value=False) # For the IPv6 checkbox

        # --- Build the UI ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(expand=True, fill="both") # Pack the main frame
        row_idx = 0

        # Instance Architecture Radio Buttons
        ttk.Label(main_frame, text="实例架构:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        type_frame = ttk.Frame(main_frame)
        type_frame.grid(row=row_idx, column=1, columnspan=2, sticky=tk.W, padx=5, pady=3)
        ttk.Radiobutton(type_frame, text="AMD Micro (E2.1)", variable=self.instance_type, value="AMD", command=self.update_shape_fields).pack(side=tk.LEFT)
        ttk.Radiobutton(type_frame, text="ARM Flex (A1)", variable=self.instance_type, value="ARM", command=self.update_shape_fields).pack(side=tk.LEFT, padx=10)
        row_idx += 1

        # OS Selection Combobox
        ttk.Label(main_frame, text="操作系统:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        os_options = ["Oracle Linux (最新)", "Ubuntu 22.04 (最新)", "Ubuntu 20.04 (最新)"]
        self.os_combobox = ttk.Combobox(main_frame, textvariable=self.os_choice_var, values=os_options, state='readonly', width=25)
        self.os_choice_var.set(os_options[0]) # Default OS
        self.os_combobox.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3)
        row_idx += 1

        # OCPU Entry
        ttk.Label(main_frame, text="CPU 核心数:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        self.ocpu_entry = ttk.Entry(main_frame, width=10, state='disabled') # Initial state
        self.ocpu_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3)
        row_idx += 1

        # Memory Entry
        ttk.Label(main_frame, text="内存 (GB):").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        self.memory_entry = ttk.Entry(main_frame, width=10, state='disabled') # Initial state
        self.memory_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3)
        row_idx += 1

        # Boot Volume Entry
        ttk.Label(main_frame, text="引导卷大小 (GB):").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        self.boot_vol_entry = ttk.Entry(main_frame, width=10)
        self.boot_vol_entry.insert(0, "50") # Default size
        self.boot_vol_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3)
        row_idx += 1

        # Name Prefix Entry
        ttk.Label(main_frame, text="名称前缀(可选):").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        self.name_prefix_entry = ttk.Entry(main_frame, width=30)
        self.name_prefix_entry.insert(0, "Instance") # Default prefix
        self.name_prefix_entry.grid(row=row_idx, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=3)
        row_idx += 1

        # Instance Count Entry
        ttk.Label(main_frame, text="创建数量:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        self.count_entry = ttk.Entry(main_frame, width=10)
        self.count_entry.insert(0, "1") # Default count
        self.count_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3)
        row_idx += 1

        # IPv6 Checkbutton
        self.ipv6_check = ttk.Checkbutton(main_frame, text="分配 IPv6 地址 (需子网支持)", variable=self.assign_ipv6_var)
        self.ipv6_check.grid(row=row_idx, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5)
        row_idx += 1

        # Login Method Info Label
        ttk.Label(main_frame, text="登录方式:", foreground="blue").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3)
        ttk.Label(main_frame, text="将启用Root密码登录(随机生成)", foreground="red").grid(row=row_idx, column=1, columnspan=2, sticky=tk.W, padx=5, pady=3)
        row_idx += 1

        # Action Buttons Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=row_idx, column=0, columnspan=3, pady=(15, 0))
        create_button = ttk.Button(button_frame, text="创建实例", command=self.create_instance_thread)
        create_button.pack(side="left", padx=10)
        cancel_button = ttk.Button(button_frame, text="取消", command=self.destroy)
        cancel_button.pack(side="left", padx=10)

        # --- Final setup ---
        self.update_shape_fields() # Set initial state based on default radio button
        self.grab_set()
        self.wait_window()

    # Method to update OCPU/Memory fields based on architecture choice
    def update_shape_fields(self):
        # Ensure correct indentation (Level 1 within class)
        instance_type = self.instance_type.get()
        is_arm = (instance_type == "ARM")
        shape_state = 'normal' if is_arm else 'disabled'
        shape = "VM.Standard.A1.Flex" if is_arm else "VM.Standard.E2.1.Micro"

        self.selected_shape.set(shape)
        self.ocpu_entry.config(state=shape_state)
        self.memory_entry.config(state=shape_state)

        # Set default values when switching
        if is_arm:
            self.ocpu_entry.delete(0, tk.END); self.ocpu_entry.insert(0, "1")
            self.memory_entry.delete(0, tk.END); self.memory_entry.insert(0, "6")
        else: # AMD Micro
            self.ocpu_entry.delete(0, tk.END); self.ocpu_entry.insert(0, "1")
            self.memory_entry.delete(0, tk.END); self.memory_entry.insert(0, "1") # E2 Micro has 1GB RAM

    # Method to validate inputs and start the backend thread
    def create_instance_thread(self):
        # Ensure correct indentation (Level 1 within class)
        self.logger.info("验证创建实例对话框输入...")
        details = {'profile_defaults': self.profile_data}
        details['display_name_prefix'] = self.name_prefix_entry.get().strip() or "Instance"
        try: details['instance_count'] = int(self.count_entry.get().strip()); assert details['instance_count'] >= 1
        except: messagebox.showerror("输入错误", "数量必须是大于或等于1的整数。", parent=self); return

        details['shape'] = self.selected_shape.get()
        os_choice = self.os_choice_var.get()
        if "Ubuntu 22.04" in os_choice: details['os_name'], details['os_version'] = "Canonical Ubuntu", "22.04"
        elif "Ubuntu 20.04" in os_choice: details['os_name'], details['os_version'] = "Canonical Ubuntu", "20.04"
        else: details['os_name'], details['os_version'] = "Oracle Linux", "9" # Default Oracle Linux
        self.logger.info(f"选定操作系统: {details['os_name']} {details['os_version']}")

        if self.instance_type.get() == "ARM":
            try:
                 details['ocpus'] = float(self.ocpu_entry.get().strip())
                 details['memory_in_gbs'] = float(self.memory_entry.get().strip())
                 assert details['ocpus'] > 0 and details['memory_in_gbs'] > 0
                 assert details['memory_in_gbs'] >= details['ocpus']
                 self.logger.info(f"ARM Flex 配置: {details['ocpus']} OCPUs, {details['memory_in_gbs']} GB RAM")
            except (ValueError, AssertionError): messagebox.showerror("输入错误", "ARM实例的CPU核心数和内存(GB)必须是正数，且内存通常需大于等于核心数。", parent=self); return
        else: # AMD Micro
             details['ocpus'], details['memory_in_gbs'] = None, None
             self.logger.info(f"AMD Micro 配置由 Shape {details['shape']} 决定。")

        try:
             details['boot_volume_size'] = int(self.boot_vol_entry.get().strip())
             assert details['boot_volume_size'] >= 50
             self.logger.info(f"引导卷大小: {details['boot_volume_size']} GB")
        except (ValueError, AssertionError): messagebox.showerror("输入错误", f"引导卷大小必须是大于或等于50的整数。", parent=self); return

        details['assign_ipv6'] = self.assign_ipv6_var.get() # Get IPv6 checkbox value
        self.logger.info(f"是否请求分配 IPv6: {details['assign_ipv6']}")

        required_defaults = ['default_subnet_ocid', 'default_ssh_public_key']
        missing_defaults = [k for k in required_defaults if not self.profile_data.get(k)]
        if missing_defaults: msg = f"当前账号配置缺少必要的默认值:\n - {', '.join(missing_defaults)}\n请返回主窗口 '编辑选中账号' 进行设置。"; self.logger.error(f"创建实例前检查失败: {msg}"); messagebox.showerror("缺少配置", msg, parent=self); return

        self.logger.info("输入验证通过。准备在后台线程中创建实例...")
        self.destroy() # Close dialog
        thread = threading.Thread(target=self.create_instance_backend, args=(details,), daemon=True); thread.start()

    # Corrected backend method that calls the callback directly
    def create_instance_backend(self, details):
        # Ensure correct indentation (Level 1 within class)
        success, message = backend_create_instance(self.compute_client, self.identity_client, details, self.logger)
        # Directly call the callback function passed during initialization.
        # It (handle_create_instance_result) will run in the main app context and handle UI updates.
        if self.callback:
            self.logger.info(f"实例创建后台任务完成. Success={success}. 直接调用回调函数。")
            self.callback(success, message)
        else:
             self.logger.warning("实例创建后台任务完成，但未找到回调函数。")

# --- End of CreateInstanceDialog class ---
# Password Display Dialog (No change needed)
class PasswordDisplayDialog(tk.Toplevel):
     # ...(Same as before)...
     def __init__(self, parent, password, logger):
         super().__init__(parent); self.transient(parent); self.title("实例 Root 密码"); self.geometry("400x150"); self.resizable(False, False)
         self.logger = logger
         main_frame = ttk.Frame(self, padding="15"); main_frame.pack(expand=True, fill="both")
         ttk.Label(main_frame, text="*** 重要 ***", foreground="red", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 5))
         ttk.Label(main_frame, text="实例创建请求已发送。请立即复制并保存下方生成的Root密码！\n此密码仅显示一次。", wraplength=360).pack(pady=(0,10))
         pass_frame = ttk.Frame(main_frame); pass_frame.pack(pady=5); ttk.Label(pass_frame, text="Root 密码:").pack(side=tk.LEFT, padx=(0,5)); pass_entry = ttk.Entry(pass_frame, width=30); pass_entry.insert(0, password); pass_entry.config(state='readonly'); pass_entry.pack(side=tk.LEFT)
         ok_button = ttk.Button(main_frame, text="我已保存，关闭", command=self.destroy); ok_button.pack(pady=(10,0))
         self.logger.info("显示 Root 密码对话框。")
         self.grab_set(); self.wait_window()
         self.logger.info("Root 密码对话框已关闭。")


# --- Main Application Class ---
# (Structure mostly same, calls updated methods)
# --- Main Application Class ---
# --- Main Application Class ---
# -*- coding: utf-8 -*-
# 请确保这个类定义之前的 import, 常量, backend 函数, Dialog 类都存在且正确

# --- Main Application Class ---
# --- Replace your ENTIRE existing OciInstanceManagerApp class with this ---
class OciInstanceManagerApp:
    PROFILES_FILE = PROFILES_FILE_PATH
    SETTINGS_FILE = SETTINGS_FILE_PATH
    LOG_FILE = LOG_FILE_PATH

    # --- Initialization ---
    def __init__(self, root):
        # Ensure correct indentation for __init__ (Level 1 within class)
        self.root = root
        self.root.title("OCI 实例管理器 (JSON存储-增强版)")
        self.root.geometry("1200x800") # Increased size for details/log

        # --- Logging Setup ---
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.log_text_handler = None # Placeholder for potential GUI handler
        self.logger.info("--- OCI Instance Manager Application Starting ---")
        self.logger.info(f"脚本运行目录: {script_dir}")
        self.logger.info(f"配置文件路径: {self.PROFILES_FILE}")
        self.logger.info(f"设置文件路径: {self.SETTINGS_FILE}")
        self.logger.info(f"日志文件路径: {self.LOG_FILE}")

        # --- State Variables ---
        self.oci_config = None; self.identity_client = None; self.compute_client = None; self.virtual_network_client = None; self.block_storage_client = None
        self.is_connected = False; self.connected_profile_alias = None
        self.profile_alias_var = tk.StringVar(); self.all_profiles_data = {}
        self.last_used_alias = None; self.instance_data = {}; self.selected_instance_ocid = None

        # --- Load Data ---
        self.load_settings_from_file(); self.load_profiles_from_file()

        # --- GUI Creation ---
        self.create_config_frame()

        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=5)
        main_pane.pack(expand=True, fill=tk.BOTH, padx=10, pady=(0,5))

        left_frame = ttk.Frame(main_pane, padding=(0, 5))
        self.create_instance_view(left_frame)
        main_pane.add(left_frame) # Add without weight

        right_frame = ttk.Frame(main_pane, padding=(5, 5))
        self.create_instance_details_view(right_frame)
        main_pane.add(right_frame) # Add without weight

        self.create_action_buttons() # Create buttons
        self.create_log_viewer()     # Create log viewer
        self.create_status_bar()     # Create status bar

        # --- Initial State ---
        self.update_combobox_from_profiles() # Populate dropdown
        if self.all_profiles_data:
             self.log_ui("未连接。请选择账号并连接。", level='INFO')
        else:
            self.log_ui("未找到账号配置。请使用 '添加账号' 功能导入。", level='WARN')

        # Set initial control states AFTER UI is built and profiles loaded
        self.toggle_controls(connected=False, profiles_exist=bool(self.all_profiles_data), selection_valid=False)

    # --- Persistence Methods ---
    def load_profiles_from_file(self):
        # Ensure correct indentation (Level 1 within class)
        try:
            if os.path.exists(self.PROFILES_FILE):
                with open(self.PROFILES_FILE, 'r', encoding='utf-8') as f:
                    self.all_profiles_data = json.load(f)
                    self.logger.info(f"从 {self.PROFILES_FILE} 加载了 {len(self.all_profiles_data)} 个账号配置。")
            else:
                self.logger.warning(f"账号配置文件 {self.PROFILES_FILE} 不存在。")
                self.all_profiles_data = {}
        except (IOError, json.JSONDecodeError) as e:
            self.logger.error(f"加载账号配置文件 {self.PROFILES_FILE} 错误: {e}", exc_info=True)
            messagebox.showerror("加载错误", f"无法加载账号配置文件:\n{e}")
            self.all_profiles_data = {}

    def save_profiles_to_file(self):
        # Ensure correct indentation (Level 1 within class)
        try:
            with open(self.PROFILES_FILE, 'w', encoding='utf-8') as f:
                 json.dump(self.all_profiles_data, f, indent=4, ensure_ascii=False)
            self.logger.info(f"账号配置已保存到 {self.PROFILES_FILE}。")
        except IOError as e:
            self.logger.error(f"保存账号配置文件 {self.PROFILES_FILE} 错误: {e}", exc_info=True)
            messagebox.showerror("保存错误", f"无法保存账号配置文件:\n{e}")

    def load_settings_from_file(self):
        # Ensure correct indentation (Level 1 within class)
        try:
            if os.path.exists(self.SETTINGS_FILE):
                with open(self.SETTINGS_FILE, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                    self.last_used_alias = settings.get("last_profile_alias")
                    self.logger.info(f"从 {self.SETTINGS_FILE} 加载设置。上次使用账号: {self.last_used_alias or '无'}")
            else:
                 self.logger.info(f"设置文件 {self.SETTINGS_FILE} 不存在。")
                 self.last_used_alias = None
        except (IOError, json.JSONDecodeError) as e:
             self.logger.error(f"加载设置文件 {self.SETTINGS_FILE} 错误: {e}", exc_info=True)
             self.last_used_alias = None

    def save_settings_to_file(self, profile_alias):
        # Ensure correct indentation (Level 1 within class)
        settings = {"last_profile_alias": profile_alias }
        try:
            with open(self.SETTINGS_FILE, 'w', encoding='utf-8') as f:
                 json.dump(settings, f, indent=4, ensure_ascii=False)
            self.logger.info(f"设置已保存到 {self.SETTINGS_FILE}。当前账号: {profile_alias}")
        except IOError as e:
            self.logger.error(f"保存设置文件 {self.SETTINGS_FILE} 错误: {e}", exc_info=True)

    # --- Logging & UI Update Methods ---
    def log_ui(self, message, level='INFO'):
        # Ensure correct indentation (Level 1 within class)
        """Logs to file, status bar, and log text widget."""
        # Log to file/console via logger object
        if level.upper() == 'INFO': self.logger.info(message)
        elif level.upper() == 'WARN' or level.upper() == 'WARNING': self.logger.warning(message)
        elif level.upper() == 'ERROR': self.logger.error(message)
        elif level.upper() == 'DEBUG': self.logger.debug(message)
        else: self.logger.info(message)

        # Update status bar
        self.update_status(message)

        # Update log text widget
        if hasattr(self, 'log_viewer') and self.log_viewer: # Check if log viewer exists
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"{timestamp} - {level.upper()} - {message}\n"
            try:
                self.log_viewer.config(state=tk.NORMAL)
                self.log_viewer.insert(tk.END, log_entry)
                self.log_viewer.yview(tk.END) # Auto-scroll
                self.log_viewer.config(state=tk.DISABLED)
            except tk.TclError as e:
                self.logger.error(f"更新日志查看器时出错: {e}")

    def update_status(self, text):
        # Ensure correct indentation (Level 1 within class)
        """Updates the status bar label."""
        def update():
            # Check if status_label still exists before configuring
            if hasattr(self, 'status_label') and self.status_label.winfo_exists():
                self.status_label.config(text=text)
                # self.root.update_idletasks() # update_idletasks can sometimes cause issues, rely on mainloop
        # Schedule the update on the main Tkinter thread
        if hasattr(self, 'root') and self.root.winfo_exists():
             self.root.after(0, update)

    def toggle_controls(self, connected, profiles_exist, selection_valid):
        # Ensure correct indentation (Level 1 within class)
        """Updates the state of various buttons and controls based on app state."""
        instance_state = None
        vnic_id = None
        if selection_valid and self.selected_instance_ocid in self.instance_data:
            instance_details = self.instance_data[self.selected_instance_ocid]
            instance_state = instance_details.get('lifecycle_state')
            vnic_id = instance_details.get('vnic_id')

        def update_states():
            # Check if root window still exists
            if not (hasattr(self, 'root') and self.root.winfo_exists()):
                self.logger.warning("toggle_controls: Root window closed, skipping UI updates.")
                return

            # Update controls safely, checking if attribute exists first
            try:
                # Profile controls
                if hasattr(self, 'add_profile_button'): self.add_profile_button.config(state='normal')
                edit_delete_state = 'normal' if profiles_exist and self.profile_alias_var.get() else 'disabled'
                if hasattr(self, 'edit_profile_button'): self.edit_profile_button.config(state=edit_delete_state)
                if hasattr(self, 'delete_profile_button'): self.delete_profile_button.config(state=edit_delete_state)
                if hasattr(self, 'profiles_combobox'): self.profiles_combobox.config(state='readonly' if profiles_exist else 'disabled')
                if hasattr(self, 'connect_button'): self.connect_button.config(state='normal' if profiles_exist and not connected else 'disabled')

                # General action controls
                refresh_state = 'normal' if connected else 'disabled'
                if hasattr(self, 'refresh_button'): self.refresh_button.config(state=refresh_state)
                can_create = False
                if connected and self.connected_profile_alias:
                    profile_data = self.all_profiles_data.get(self.connected_profile_alias, {})
                    if profile_data.get('default_subnet_ocid') and profile_data.get('default_ssh_public_key'): can_create = True
                if hasattr(self, 'create_instance_button'): self.create_instance_button.config(state='normal' if can_create else 'disabled')

                # Instance-specific action controls
                action_state_base = 'normal' if connected and selection_valid else 'disabled'
                if hasattr(self, 'change_ip_button'): self.change_ip_button.config(state=action_state_base)
                if hasattr(self, 'restart_button'): self.restart_button.config(state=action_state_base)
                if hasattr(self, 'terminate_button'): self.terminate_button.config(state=action_state_base)
                can_start = connected and selection_valid and instance_state == 'STOPPED'
                can_stop = connected and selection_valid and instance_state == 'RUNNING'
                if hasattr(self, 'start_button'): self.start_button.config(state='normal' if can_start else 'disabled')
                if hasattr(self, 'stop_button'): self.stop_button.config(state='normal' if can_stop else 'disabled')
                can_assign_ipv6 = connected and selection_valid and vnic_id and instance_state == 'RUNNING'
                if hasattr(self, 'assign_ipv6_button'): self.assign_ipv6_button.config(state='normal' if can_assign_ipv6 else 'disabled')

            except tk.TclError as e:
                 self.logger.error(f"更新控件状态时出错 (可能窗口已关闭): {e}")
            except Exception as e_generic:
                self.logger.exception(f"更新控件状态时发生意外错误: {e_generic}")


        # Schedule the state update safely
        if hasattr(self, 'root') and self.root.winfo_exists():
            self.root.after(0, update_states)

    # --- GUI Creation Methods ---
    def create_config_frame(self):
        # Ensure correct indentation (Level 1 within class)
        config_frame = ttk.LabelFrame(self.root, text="账号配置管理 (存储于 "+PROFILES_FILENAME+")", padding=(10, 5))
        config_frame.pack(pady=5, padx=10, fill=tk.X)
        ttk.Label(config_frame, text="选择账号(别名):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.profiles_combobox = ttk.Combobox(config_frame, textvariable=self.profile_alias_var, state='disabled', width=30)
        self.profiles_combobox.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        self.profiles_combobox.bind('<<ComboboxSelected>>', self.on_profile_selected)
        self.connect_button = ttk.Button(config_frame, text="使用选中账号连接", command=self.connect_oci_thread, state='disabled')
        self.connect_button.grid(row=0, column=2, padx=5, pady=5)
        button_frame_mgmt = ttk.Frame(config_frame)
        button_frame_mgmt.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        self.add_profile_button = ttk.Button(button_frame_mgmt, text="添加账号 (从INI导入)", command=self.import_profile_from_ini)
        self.add_profile_button.pack(side=tk.LEFT, padx=(0,5))
        self.edit_profile_button = ttk.Button(button_frame_mgmt, text="编辑选中账号", command=self.edit_profile, state='disabled')
        self.edit_profile_button.pack(side=tk.LEFT, padx=5)
        self.delete_profile_button = ttk.Button(button_frame_mgmt, text="删除选中账号", command=self.delete_profile, state='disabled')
        self.delete_profile_button.pack(side=tk.LEFT, padx=5)
        config_frame.columnconfigure(1, weight=1)

    def create_instance_view(self, parent_frame):
        # Ensure correct indentation (Level 1 within class)
        view_frame = ttk.LabelFrame(parent_frame, text="实例列表", padding=(5, 5))
        view_frame.pack(expand=True, fill=tk.BOTH)
        columns = ('name', 'status', 'public_ip', 'config', 'ad', 'created')
        self.instance_treeview = ttk.Treeview(view_frame, columns=columns, show='headings', selectmode='browse')
        col_widths = {'name': 180, 'status': 80, 'public_ip': 130, 'config': 180, 'ad': 180, 'created': 150}
        col_display = {'name': '显示名称', 'status': '状态', 'public_ip': '公网IP', 'config': '配置(核/内存/磁盘)', 'ad': '可用域', 'created': '创建时间'}
        for col in columns:
            self.instance_treeview.heading(col, text=col_display[col])
            self.instance_treeview.column(col, width=col_widths[col], anchor=tk.W if col != 'status' else tk.CENTER)
        vsb = ttk.Scrollbar(view_frame, orient="vertical", command=self.instance_treeview.yview)
        hsb = ttk.Scrollbar(view_frame, orient="horizontal", command=self.instance_treeview.xview)
        self.instance_treeview.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.instance_treeview.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        view_frame.grid_rowconfigure(0, weight=1)
        view_frame.grid_columnconfigure(0, weight=1)
        self.instance_treeview.bind('<<TreeviewSelect>>', self.on_instance_select)
        self.instance_treeview.bind('<Button-3>', self.show_context_menu)

    def create_instance_details_view(self, parent_frame):
        # Ensure correct indentation (Level 1 within class)
        details_frame = ttk.LabelFrame(parent_frame, text="选中实例详情", padding=(5,5))
        details_frame.pack(expand=True, fill=tk.BOTH)
        self.details_text = scrolledtext.ScrolledText(
            details_frame, wrap=tk.WORD, state=tk.DISABLED, height=10,
            font=("Consolas", 9) # Monospaced font
        )
        self.details_text.pack(expand=True, fill=tk.BOTH, padx=2, pady=2)

    def create_action_buttons(self):
        # Ensure correct indentation (Level 1 within class)
        action_frame = ttk.Frame(self.root, padding=(10, 5))
        action_frame.pack(pady=5, padx=10, fill=tk.X)
        self.refresh_button = ttk.Button(action_frame, text="刷新列表", command=self.refresh_list_thread)
        self.refresh_button.pack(side=tk.LEFT, padx=5)
        self.create_instance_button = ttk.Button(action_frame, text="创建实例", command=self.show_create_instance_dialog, state='disabled')
        self.create_instance_button.pack(side=tk.LEFT, padx=5)
        ttk.Separator(action_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        self.start_button = ttk.Button(action_frame, text="启动实例", command=lambda: self.confirm_and_run_action("start"), state='disabled')
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(action_frame, text="停止实例", command=lambda: self.confirm_and_run_action("stop"), state='disabled')
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.restart_button = ttk.Button(action_frame, text="重启实例", command=lambda: self.confirm_and_run_action("restart"), state='disabled')
        self.restart_button.pack(side=tk.LEFT, padx=5)
        self.assign_ipv6_button = ttk.Button(action_frame, text="分配 IPv6", command=lambda: self.confirm_and_run_action("assign_ipv6"), state='disabled')
        self.assign_ipv6_button.pack(side=tk.LEFT, padx=5)
        self.change_ip_button = ttk.Button(action_frame, text="更换公网IP", command=lambda: self.confirm_and_run_action("change_ip"), state='disabled')
        self.change_ip_button.pack(side=tk.LEFT, padx=5)
        self.terminate_button = ttk.Button(action_frame, text="终止实例", command=lambda: self.confirm_and_run_action("terminate"), state='disabled')
        self.terminate_button.pack(side=tk.LEFT, padx=5)

    def create_log_viewer(self):
        # Ensure correct indentation (Level 1 within class)
        log_frame = ttk.LabelFrame(self.root, text="操作日志", padding=(5,5))
        log_frame.pack(pady=5, padx=10, fill=tk.BOTH, expand=False) # Dont expand vertically
        self.log_viewer = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
        self.log_viewer.pack(expand=True, fill=tk.BOTH)

    def create_status_bar(self):
        # Ensure correct indentation (Level 1 within class)
        self.status_label = ttk.Label(self.root, text="未连接", relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Context Menu & Clipboard ---
    def show_context_menu(self, event):
        # Ensure correct indentation (Level 1 within class)
        """Displays a right-click context menu for the selected instance."""
        selection = self.instance_treeview.identify_row(event.y)
        if not selection: return
        self.instance_treeview.selection_set(selection)
        self.on_instance_select()
        if not self.selected_instance_ocid or self.selected_instance_ocid not in self.instance_data: return

        instance_details = self.instance_data[self.selected_instance_ocid]
        menu = tk.Menu(self.root, tearoff=0)
        ocid = instance_details.get('id', '')
        public_ip = instance_details.get('public_ip', '')
        private_ip = instance_details.get('private_ip', '')

        # Build menu content
        copy_items_added = False
        if ocid: menu.add_command(label=f"复制实例 OCID (...{ocid[-12:]})", command=lambda: self.copy_to_clipboard(ocid, "实例 OCID")); copy_items_added = True
        if public_ip and "N/A" not in public_ip and "获取" not in public_ip and "无" not in public_ip: menu.add_command(label=f"复制公网 IP ({public_ip})", command=lambda: self.copy_to_clipboard(public_ip, "公网 IP")); copy_items_added = True
        if private_ip and "N/A" not in private_ip and "获取" not in private_ip and "无" not in private_ip: menu.add_command(label=f"复制私有 IP ({private_ip})", command=lambda: self.copy_to_clipboard(private_ip, "私有 IP")); copy_items_added = True
        if copy_items_added: menu.add_separator()

        action_items_added = False
        if hasattr(self, 'start_button') and self.start_button['state'] == 'normal': menu.add_command(label="启动实例", command=lambda: self.confirm_and_run_action("start")); action_items_added = True
        if hasattr(self, 'stop_button') and self.stop_button['state'] == 'normal': menu.add_command(label="停止实例", command=lambda: self.confirm_and_run_action("stop")); action_items_added = True
        if hasattr(self, 'restart_button') and self.restart_button['state'] == 'normal': menu.add_command(label="重启实例", command=lambda: self.confirm_and_run_action("restart")); action_items_added = True
        if hasattr(self, 'assign_ipv6_button') and self.assign_ipv6_button['state'] == 'normal': menu.add_command(label="分配 IPv6", command=lambda: self.confirm_and_run_action("assign_ipv6")); action_items_added = True
        if hasattr(self, 'change_ip_button') and self.change_ip_button['state'] == 'normal': menu.add_command(label="更换公网 IP", command=lambda: self.confirm_and_run_action("change_ip")); action_items_added = True
        if hasattr(self, 'terminate_button') and self.terminate_button['state'] == 'normal': menu.add_command(label="终止实例...", command=lambda: self.confirm_and_run_action("terminate")); action_items_added = True

        # Show menu only if it has items
        if copy_items_added or action_items_added:
            try: menu.tk_popup(event.x_root, event.y_root)
            finally: menu.grab_release()
        else:
             self.logger.info("右键菜单为空 (无可用复制项或操作)，未显示。")

    def copy_to_clipboard(self, text_to_copy, item_name):
        # Ensure correct indentation (Level 1 within class)
        """Clears clipboard and adds the specified text."""
        if not text_to_copy: self.log_ui(f"无法复制空的 {item_name}", level='WARN'); return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text_to_copy)
            self.log_ui(f"{item_name} 已复制到剪贴板。", level='INFO')
        except tk.TclError:
            self.log_ui("无法访问剪贴板。", level='ERROR'); messagebox.showerror("剪贴板错误", "无法访问系统剪贴板。")

    # --- Profile Management Methods ---
    def update_combobox_from_profiles(self):
        # Ensure correct indentation (Level 1 within class)
        aliases = sorted(list(self.all_profiles_data.keys()))
        if hasattr(self, 'profiles_combobox') and self.profiles_combobox.winfo_exists():
             self.profiles_combobox.config(values=aliases)
        else: self.logger.error("无法更新 profiles_combobox，控件不存在。"); return

        profiles_exist = bool(aliases); selected_alias_to_set = ''
        if profiles_exist:
             if self.last_used_alias and self.last_used_alias in aliases: selected_alias_to_set = self.last_used_alias
             elif aliases: selected_alias_to_set = aliases[0]
             self.profiles_combobox.config(state='readonly')
        else: self.profiles_combobox.config(state='disabled')
        self.profile_alias_var.set(selected_alias_to_set)
        self.on_profile_selected() # Update button states based on selection

    def import_profile_from_ini(self):
        # Ensure correct indentation (Level 1 within class)
        self.log_ui("启动从 INI 文件导入账号流程...", level='INFO')
        default_ini = DEFAULT_OCI_CONFIG_PATH if os.path.exists(DEFAULT_OCI_CONFIG_PATH) else script_dir
        ini_path = filedialog.askopenfilename(title="选择包含档案的 OCI 配置文件 (.ini 或 config)", initialdir=os.path.dirname(default_ini), filetypes=(("Config/INI", "*.ini"), ("Config files", "config"), ("All files", "*.*")))
        if not ini_path: self.log_ui("用户取消了文件选择。", level='INFO'); return
        self.logger.info(f"用户选择了 INI 文件: {ini_path}"); config_parser = configparser.ConfigParser()
        try:
            try: config_parser.read(ini_path, encoding='utf-8')
            except UnicodeDecodeError: self.logger.warning(f"无法以 UTF-8 读取 {ini_path}，尝试默认编码。"); config_parser.read(ini_path)
            original_profiles = config_parser.sections()
            has_default_content = 'DEFAULT' in config_parser and bool(config_parser['DEFAULT'])
            if has_default_content and 'DEFAULT' not in original_profiles: self.logger.info("检测到有内容的 [DEFAULT] 节，将其添加到档案列表。"); original_profiles.insert(0, 'DEFAULT')
            if not original_profiles: msg = f"文件 '{os.path.basename(ini_path)}' 中未找到有效的档案节头 ([PROFILE_NAME])。"; self.log_ui(msg, level='WARN'); messagebox.showinfo("无档案", msg); return
            self.logger.info(f"在 {ini_path} 中找到原始档案名: {original_profiles}")
            ImportDialog(self.root, original_profiles, list(self.all_profiles_data.keys()), lambda import_map: self.process_imported_profiles(import_map, ini_path), self.logger)
        except configparser.Error as e: msg = f"读取配置文件 '{os.path.basename(ini_path)}' 时出错:\n{e}"; self.log_ui(msg, level='ERROR'); self.logger.error(f"ConfigParser错误: {e}", exc_info=True); messagebox.showerror("文件解析错误", msg)
        except Exception as e: msg = f"处理导入时发生未知错误:\n{e}"; self.log_ui(msg, level='ERROR'); self.logger.exception(f"导入时未知错误: {e}"); messagebox.showerror("导入错误", msg)

    def process_imported_profiles(self, profiles_to_import_full_data, source_ini_path):
        # Ensure correct indentation (Level 1 within class)
        if not profiles_to_import_full_data: self.log_ui("没有选择要导入的档案。", level='INFO'); return
        self.log_ui("正在导入选中的档案配置...", level='INFO'); newly_added = 0; updated = 0; errors = []; profiles_changed = False
        for alias, import_data in profiles_to_import_full_data.items():
            original_name = import_data["original_name"]; defaults = import_data["defaults"]
            self.logger.info(f"处理导入: 原始名='{original_name}', 别名='{alias}'")
            try:
                cfg = oci.config.from_file(file_location=source_ini_path, profile_name=original_name)
                profile_data = { "user": cfg.get("user"), "fingerprint": cfg.get("fingerprint"), "tenancy": cfg.get("tenancy"), "region": cfg.get("region"), "key_file": cfg.get("key_file"), "passphrase": cfg.get("passphrase") if "passphrase" in cfg else None }
                required_keys_found = ["user", "fingerprint", "tenancy", "region", "key_file"]
                if not all(k in profile_data and profile_data[k] for k in required_keys_found): errors.append(f"档案 '{original_name}' (别名 '{alias}') 基础配置不完整，跳过。"); self.logger.warning(f"跳过导入档案 '{original_name}' (别名 '{alias}') - 基础配置不完整。"); continue
                profile_data.update(defaults)
                if alias in self.all_profiles_data: updated += 1; self.logger.info(f"将更新现有别名 '{alias}'。")
                else: newly_added += 1; self.logger.info(f"将添加新别名 '{alias}'。")
                self.all_profiles_data[alias] = profile_data; profiles_changed = True
            except (oci.exceptions.ProfileNotFound, KeyError, ValueError) as e: error_msg = f"读取或解析档案 '{original_name}' (来自 {os.path.basename(source_ini_path)}) 出错: {e}"; errors.append(error_msg); self.logger.error(error_msg)
            except Exception as e: error_msg = f"导入档案 '{original_name}' 时发生意外错误: {e}"; errors.append(error_msg); self.logger.exception(error_msg)
        if profiles_changed: self.save_profiles_to_file(); self.update_combobox_from_profiles()
        final_message = f"导入完成。新增: {newly_added}, 更新: {updated}。\n\n提示：请通过 '编辑选中账号' 确认或补充默认值，特别是子网和SSH密钥。"
        if errors: final_message += "\n\n发生错误:\n" + "\n".join(errors); self.log_ui(f"档案导入完成，但有错误。新增: {newly_added}, 更新: {updated}, 错误: {len(errors)}", level='WARN'); messagebox.showwarning("导入完成（有错误）", final_message)
        else: self.log_ui(f"档案导入成功完成。新增: {newly_added}, 更新: {updated}", level='INFO'); messagebox.showinfo("导入完成", final_message)
        self.update_status("档案导入操作结束。")

    def edit_profile(self):
        # Ensure correct indentation (Level 1 within class)
        selected_alias = self.profile_alias_var.get();
        if not selected_alias: messagebox.showwarning("未选择", "请选择要编辑的账号别名。"); return
        if selected_alias not in self.all_profiles_data: self.log_ui(f"尝试编辑但找不到别名 '{selected_alias}' 的数据。", level='ERROR'); messagebox.showerror("错误", f"找不到别名 '{selected_alias}' 的配置数据。请检查 {self.PROFILES_FILE}。"); return
        self.log_ui(f"打开编辑对话框以编辑账号 '{selected_alias}'...", level='INFO')
        profile_data_to_edit = self.all_profiles_data.get(selected_alias, {})
        vnet_client_for_edit = self.virtual_network_client if self.is_connected and self.connected_profile_alias == selected_alias else None
        if self.is_connected and not vnet_client_for_edit: self.logger.warning(f"当前连接的账号 ({self.connected_profile_alias}) 与要编辑的账号 ({selected_alias}) 不同，编辑窗口中将无法加载子网。"); messagebox.showwarning("连接不匹配", f"当前连接账号与编辑账号不同，无法在此编辑窗口加载子网列表。", parent=self.root)
        elif not self.is_connected: self.logger.info("应用未连接，编辑窗口中将无法加载子网。")
        EditProfileDialog(self.root, selected_alias, profile_data_to_edit, vnet_client_for_edit, self.save_edited_profile, self.logger)

    def save_edited_profile(self, alias, updated_data):
        # Ensure correct indentation (Level 1 within class)
        self.log_ui(f"正在保存对账号 '{alias}' 的编辑...", level='INFO')
        self.all_profiles_data[alias] = updated_data; self.save_profiles_to_file(); self.update_combobox_from_profiles()
        if alias in self.all_profiles_data: self.profile_alias_var.set(alias)
        messagebox.showinfo("成功", f"账号 '{alias}' 的配置已更新。"); self.log_ui(f"账号 '{alias}' 已更新。", level='INFO')
        self.on_profile_selected()

    def delete_profile(self):
        # Ensure correct indentation (Level 1 within class)
        selected_alias = self.profile_alias_var.get()
        if not selected_alias: messagebox.showwarning("未选择", "请选择要删除的账号别名。"); return
        if selected_alias not in self.all_profiles_data: self.log_ui(f"尝试删除但找不到别名 '{selected_alias}' 的数据。", level='ERROR'); messagebox.showerror("错误", f"找不到别名 '{selected_alias}' 的数据。"); return
        self.logger.warning(f"请求删除账号配置 '{selected_alias}'...")
        if messagebox.askyesno("确认删除", f"确定要永久删除账号配置 '{selected_alias}' 吗？\n此操作无法撤销。", icon='warning'):
            self.logger.info(f"用户确认删除账号 '{selected_alias}'。"); del self.all_profiles_data[selected_alias]; self.save_profiles_to_file(); self.update_combobox_from_profiles()
            if self.is_connected and self.connected_profile_alias == selected_alias: self.logger.warning(f"删除的账号 '{selected_alias}' 是当前连接的账号，将断开连接。"); self.disconnect_oci()
            self.log_ui(f"账号 '{selected_alias}' 已删除。", level='INFO'); messagebox.showinfo("删除成功", f"账号 '{selected_alias}' 已被删除。")
        else: self.log_ui("用户取消了删除操作。", level='INFO')

    def on_profile_selected(self, event=None):
        # Ensure correct indentation (Level 1 within class)
        selected_alias = self.profile_alias_var.get()
        self.toggle_controls(self.is_connected, bool(self.all_profiles_data), self.selected_instance_ocid is not None)

    # --- Connection Logic ---
    def connect_oci_thread(self):
        # Ensure correct indentation (Level 1 within class)
        selected_alias = self.profile_alias_var.get()
        if not selected_alias: messagebox.showwarning("未选择账号", "请选择要连接的账号。"); return
        profile_config = self.all_profiles_data.get(selected_alias)
        if not profile_config: self.log_ui(f"尝试连接但找不到别名 '{selected_alias}' 的配置数据。", level='ERROR'); messagebox.showerror("错误", f"找不到别名 '{selected_alias}' 的配置数据。"); return
        # Disable controls immediately
        if hasattr(self,'connect_button'): self.connect_button.config(state='disabled')
        if hasattr(self,'profiles_combobox'): self.profiles_combobox.config(state='disabled')
        if hasattr(self,'add_profile_button'): self.add_profile_button.config(state='disabled')
        if hasattr(self,'edit_profile_button'): self.edit_profile_button.config(state='disabled')
        if hasattr(self,'delete_profile_button'): self.delete_profile_button.config(state='disabled')
        self.log_ui(f"正在连接账号 '{selected_alias}' ...", level='INFO')
        thread = threading.Thread(target=self.connect_oci_backend, args=(profile_config, selected_alias), daemon=True); thread.start()

    def connect_oci_backend(self, profile_config, selected_alias):
        # Ensure correct indentation (Level 1 within class)
        profiles_exist = bool(self.all_profiles_data)
        try:
            required_keys = ['user', 'fingerprint', 'tenancy', 'region', 'key_file']
            missing_keys = [k for k in required_keys if not profile_config.get(k)]
            if missing_keys: raise ValueError(f"账号基础配置不完整，缺少: {', '.join(missing_keys)}。")
            sdk_config = profile_config.copy()
            # Log connection attempt details (already done in previous version)
            self.logger.info(f"使用以下配置尝试连接 (别名: {selected_alias}):"); # ... (log details) ...
            try:
                identity_client_temp = oci.identity.IdentityClient(sdk_config); compute_client_temp = oci.core.ComputeClient(sdk_config)
                vnet_client_temp = oci.core.VirtualNetworkClient(sdk_config); bs_client_temp = oci.core.BlockstorageClient(sdk_config)
                self.logger.info("OCI 客户端对象已初步初始化。")
            except Exception as client_init_error: self.logger.error(f"初始化 OCI 客户端时出错: {client_init_error}", exc_info=True); raise ValueError(f"初始化OCI客户端失败，请检查密钥文件路径和格式: {client_init_error}")
            self.logger.info(f"尝试调用 get_user API (User ID: {sdk_config['user']}) 以验证认证...")
            user_info = identity_client_temp.get_user(user_id=sdk_config["user"]); self.logger.info(f"认证成功！获取到用户信息: {user_info.data.description}")
            self.oci_config = sdk_config; self.identity_client = identity_client_temp; self.compute_client = compute_client_temp
            self.virtual_network_client = vnet_client_temp; self.block_storage_client = bs_client_temp
            self.is_connected = True; self.connected_profile_alias = selected_alias
            def succeed_on_main(): # Nested function ok
                 self.log_ui(f"认证成功！已使用账号 '{selected_alias}' 连接到区域 {self.oci_config.get('region', 'N/A')}。", level='INFO')
                 self.save_settings_to_file(selected_alias); self.last_used_alias = selected_alias
                 self.toggle_controls(connected=True, profiles_exist=profiles_exist, selection_valid=False)
                 if hasattr(self, 'root') and self.root.winfo_exists(): self.refresh_list_thread() # Refresh only if root exists
            if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, succeed_on_main)
        except (KeyError, ValueError, oci.exceptions.ConfigFileNotFound, oci.exceptions.InvalidPrivateKey, oci.exceptions.MissingPrivateKeyPassphrase) as config_e:
             self.is_connected = False; self.oci_config = None; self.clients = None; error_title="配置错误"; error_msg = f"账号 '{selected_alias}' 配置错误:\n{config_e}\n请编辑账号检查配置，特别是密钥文件路径和密码。"
             self.logger.error(f"连接失败 ({selected_alias}) - 配置错误: {config_e}", exc_info=True)
             def fail_on_main_config(): # Nested function ok
                if hasattr(self, 'root') and self.root.winfo_exists(): messagebox.showerror(error_title, error_msg, parent=self.root)
                self.log_ui(f"连接失败 (账号: {selected_alias}) - 配置问题。", level='ERROR')
                self.toggle_controls(connected=False, profiles_exist=profiles_exist, selection_valid=False) # Safely toggle controls
                # Safely re-enable controls
                if hasattr(self,'profiles_combobox'): self.profiles_combobox.config(state='readonly' if profiles_exist else 'disabled')
                if hasattr(self,'connect_button'): self.connect_button.config(state='normal' if profiles_exist else 'disabled')
                if hasattr(self,'add_profile_button'): self.add_profile_button.config(state='normal')
                edit_delete_state = 'normal' if profiles_exist and self.profile_alias_var.get() else 'disabled'
                if hasattr(self,'edit_profile_button'): self.edit_profile_button.config(state=edit_delete_state)
                if hasattr(self,'delete_profile_button'): self.delete_profile_button.config(state=edit_delete_state)
             if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, fail_on_main_config)
        except oci.exceptions.ServiceError as service_e:
             self.is_connected = False; self.oci_config = None; self.clients = None; error_title="认证/服务错误"; error_msg = f"连接 OCI 时出错 (账号: {selected_alias}):\n代码: {service_e.code}, 状态: {service_e.status}\n消息: {service_e.message}\n请检查用户OCID、指纹、API密钥和权限。"
             self.logger.error(f"连接失败 ({selected_alias}) - 服务错误: Status={service_e.status}, Code={service_e.code}, Message={service_e.message}", exc_info=False)
             def fail_on_main_service(): # Nested function ok
                if hasattr(self, 'root') and self.root.winfo_exists(): messagebox.showerror(error_title, error_msg, parent=self.root)
                self.log_ui(f"连接失败 (账号: {selected_alias}) - 服务/认证错误。", level='ERROR')
                self.toggle_controls(connected=False, profiles_exist=profiles_exist, selection_valid=False)
                # Safely re-enable controls
                if hasattr(self,'profiles_combobox'): self.profiles_combobox.config(state='readonly' if profiles_exist else 'disabled')
                if hasattr(self,'connect_button'): self.connect_button.config(state='normal' if profiles_exist else 'disabled')
                if hasattr(self,'add_profile_button'): self.add_profile_button.config(state='normal')
                edit_delete_state = 'normal' if profiles_exist and self.profile_alias_var.get() else 'disabled'
                if hasattr(self,'edit_profile_button'): self.edit_profile_button.config(state=edit_delete_state)
                if hasattr(self,'delete_profile_button'): self.delete_profile_button.config(state=edit_delete_state)
             if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, fail_on_main_service)
        except Exception as e:
             self.is_connected = False; self.oci_config = None; self.clients = None; error_title="意外连接错误"; error_msg = f"连接时发生意外错误 (账号: {selected_alias}):\n{e}"
             self.logger.exception(f"连接失败 ({selected_alias}) - 意外错误: {e}")
             def fail_on_main_unexpected(): # Nested function ok
                if hasattr(self, 'root') and self.root.winfo_exists(): messagebox.showerror(error_title, error_msg, parent=self.root)
                self.log_ui(f"连接失败 (账号: {selected_alias}) - 意外错误。", level='ERROR')
                self.toggle_controls(connected=False, profiles_exist=profiles_exist, selection_valid=False)
                # Safely re-enable controls
                if hasattr(self,'profiles_combobox'): self.profiles_combobox.config(state='readonly' if profiles_exist else 'disabled')
                if hasattr(self,'connect_button'): self.connect_button.config(state='normal' if profiles_exist else 'disabled')
                if hasattr(self,'add_profile_button'): self.add_profile_button.config(state='normal')
                edit_delete_state = 'normal' if profiles_exist and self.profile_alias_var.get() else 'disabled'
                if hasattr(self,'edit_profile_button'): self.edit_profile_button.config(state=edit_delete_state)
                if hasattr(self,'delete_profile_button'): self.delete_profile_button.config(state=edit_delete_state)
             if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, fail_on_main_unexpected)

    def disconnect_oci(self):
        # Ensure correct indentation (Level 1 within class)
        """Gracefully disconnects and resets state."""
        if not self.is_connected: return
        self.logger.info(f"断开与账号 '{self.connected_profile_alias}' 的连接。")
        self.oci_config = None; self.identity_client = None; self.compute_client = None
        self.virtual_network_client = None; self.block_storage_client = None
        self.is_connected = False; self.connected_profile_alias = None
        self.instance_data.clear(); self.selected_instance_ocid = None
        try:
            if hasattr(self, 'instance_treeview') and self.instance_treeview.winfo_exists():
                for item in self.instance_treeview.get_children(): self.instance_treeview.delete(item)
            self.update_instance_details_view(None) # Safely update details view
        except tk.TclError as e: self.logger.warning(f"断开连接时清理UI出错: {e}")
        profiles_exist = bool(self.all_profiles_data)
        self.log_ui("已断开连接。", level='INFO')
        self.toggle_controls(connected=False, profiles_exist=profiles_exist, selection_valid=False)

    # --- Instance Listing / Selection / Action Handling Methods ---
    def refresh_list_thread(self):
        # Ensure correct indentation (Level 1 within class)
        if not self.is_connected or not self.oci_config: messagebox.showwarning("未连接", "请先连接账号。", parent=self.root); return
        self.log_ui(f"正在为账号 '{self.connected_profile_alias}' 获取实例列表...", level='INFO')
        profiles_exist = bool(self.all_profiles_data)
        self.toggle_controls(connected=True, profiles_exist=profiles_exist, selection_valid=False);
        if hasattr(self, 'refresh_button'): self.refresh_button.config(state='disabled')
        action_buttons = ['start_button', 'stop_button', 'restart_button', 'assign_ipv6_button', 'change_ip_button', 'terminate_button']
        for btn_name in action_buttons:
             if hasattr(self, btn_name): getattr(self, btn_name).config(state='disabled')
        thread = threading.Thread(target=self.refresh_list_backend, daemon=True); thread.start()

    def refresh_list_backend(self):
        # Ensure correct indentation (Level 1 within class)
        compartment_id = self.oci_config.get("tenancy")
        if not compartment_id:
            self.log_ui("错误：无法获取租户OCID以列出实例。", level='ERROR')
            if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, lambda: self.toggle_controls(self.is_connected, bool(self.all_profiles_data), False))
            return
        instances, message = get_detailed_instances(self.compute_client, self.virtual_network_client, self.block_storage_client, compartment_id, self.logger)
        if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, self.update_treeview, instances, message)

    def update_treeview(self, instances, message):
        # Ensure correct indentation (Level 1 within class)
        self.log_ui(message, level='INFO' if instances or "未找到" in message else 'ERROR')
        self.selected_instance_ocid = None
        self.update_instance_details_view(None) # Safely update/clear details
        try:
             if hasattr(self, 'instance_treeview') and self.instance_treeview.winfo_exists():
                 # Clear existing items
                 for item in self.instance_treeview.get_children(): self.instance_treeview.delete(item)
                 self.instance_data.clear()
                 # Populate new items
                 if instances:
                    instances.sort(key=lambda x: x.get('display_name', '').lower())
                    for inst_data in instances:
                        config_str = f"{inst_data.get('ocpus','?')} 核 / {inst_data.get('memory_in_gbs','?')} GB / {inst_data.get('boot_volume_size_gb','?')}"
                        status = inst_data.get('lifecycle_state', 'UNKNOWN')
                        tree_values = (inst_data.get('display_name', 'N/A'), status, inst_data.get('public_ip', 'N/A'), config_str, inst_data.get('availability_domain', 'N/A'), inst_data.get('time_created', 'N/A'))
                        self.instance_treeview.insert('', tk.END, iid=inst_data['id'], values=tree_values, tags=(status,))
                        self.instance_data[inst_data['id']] = inst_data
                    # Configure tags after population
                    self.instance_treeview.tag_configure('RUNNING', foreground='green'); self.instance_treeview.tag_configure('STOPPED', foreground='red')
                    self.instance_treeview.tag_configure('STARTING', foreground='orange'); self.instance_treeview.tag_configure('STOPPING', foreground='orange')
                    self.instance_treeview.tag_configure('TERMINATING', foreground='gray'); self.instance_treeview.tag_configure('TERMINATED', foreground='gray')
             else: self.logger.error("更新 treeview 失败，控件不存在。")
        except tk.TclError as e: self.logger.warning(f"更新 Treeview 时出错: {e}")
        finally:
            # Always toggle controls after attempt, check if root exists
            if hasattr(self, 'root') and self.root.winfo_exists():
                 self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=False)
                 if hasattr(self, 'refresh_button') and self.refresh_button.winfo_exists():
                      self.refresh_button.config(state='normal' if self.is_connected else 'disabled')

    def on_instance_select(self, event=None):
        # Ensure correct indentation (Level 1 within class)
        try:
             if not (hasattr(self, 'instance_treeview') and self.instance_treeview.winfo_exists()): return
             selected_items = self.instance_treeview.selection()
             is_valid_selection = len(selected_items) == 1
             if is_valid_selection:
                new_selection_id = selected_items[0]
                if new_selection_id != self.selected_instance_ocid: # Update only if selection changed
                    self.selected_instance_ocid = new_selection_id
                    instance_details_data = self.instance_data.get(self.selected_instance_ocid)
                    self.update_instance_details_view(instance_details_data)
             elif self.selected_instance_ocid is not None: # Selection cleared
                self.selected_instance_ocid = None
                self.update_instance_details_view(None)
             # Always update controls based on current state
             self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=is_valid_selection)
        except tk.TclError as e: self.logger.warning(f"处理实例选择时出错: {e}")

    def update_instance_details_view(self, details_data):
        # Ensure correct indentation (Level 1 within class)
        """Updates the scrolled text widget with formatted instance details."""
        try:
             if not (hasattr(self, 'details_text') and self.details_text.winfo_exists()): return
             self.details_text.config(state=tk.NORMAL)
             self.details_text.delete('1.0', tk.END)
             if details_data:
                lines = [ f"名称:       {details_data.get('display_name', 'N/A')}", f"状态:       {details_data.get('lifecycle_state', 'N/A')}", f"OCID:       {details_data.get('id', 'N/A')}", "-" * 30, f"公网 IP:    {details_data.get('public_ip', 'N/A')}", f"私有 IP:    {details_data.get('private_ip', 'N/A')}", f"IPv6 地址:  {details_data.get('ipv6_address', 'N/A')}", f"子网 OCID:  {details_data.get('subnet_id', 'N/A')}", f"VNIC OCID:  {details_data.get('vnic_id', 'N/A')}", "-" * 30, f"配置:       {details_data.get('shape', 'N/A')}", f"  OCPU:     {details_data.get('ocpus', 'N/A')}", f"  内存(GB): {details_data.get('memory_in_gbs', 'N/A')}", f"  引导卷:   {details_data.get('boot_volume_size_gb', 'N/A')}", f"可用域:     {details_data.get('availability_domain', 'N/A')}", f"创建时间:   {details_data.get('time_created', 'N/A')}", f"区域:       {details_data.get('region', 'N/A')}", f"区间 OCID:  {details_data.get('compartment_id', 'N/A')}", "-" * 30, "标签 (自由格式):" ]
                free_tags = details_data.get('freeform_tags', {}); lines.extend([f"  {k}: {v}" for k,v in free_tags.items()]) if free_tags else lines.append("  无")
                lines.append("标签 (定义格式):")
                def_tags = details_data.get('defined_tags', {});
                if def_tags:
                    for ns, tags in def_tags.items(): lines.append(f"  命名空间: {ns}"); lines.extend([f"    {k}: {v}" for k,v in tags.items()])
                else: lines.append("  无")
                self.details_text.insert('1.0', "\n".join(lines))
             else: self.details_text.insert('1.0', "<- 请在左侧列表中选择一个实例以查看详情")
             self.details_text.config(state=tk.DISABLED)
        except tk.TclError as e: self.logger.warning(f"更新实例详情视图时出错: {e}")

    # --- Action Handling ---
    def confirm_and_run_action(self, action_type):
        # Ensure correct indentation (Level 1 within class)
        """Handles confirmation and initiates backend actions for selected instance."""
        if not self.selected_instance_ocid: messagebox.showwarning("未选择", "请先在列表中选择一个实例。", parent=self.root); return
        if self.selected_instance_ocid not in self.instance_data:
            self.log_ui(f"执行操作 '{action_type}' 失败：选择的实例 OCID ({self.selected_instance_ocid}) 数据丢失。", level='ERROR'); messagebox.showerror("内部错误", "选择的实例数据丢失，请尝试刷新列表。", parent=self.root); return
        details = self.instance_data[self.selected_instance_ocid]
        instance_name = details.get("display_name", self.selected_instance_ocid); instance_id = details["id"]; vnic_id = details.get("vnic_id"); subnet_id = details.get("subnet_id"); instance_state = details.get("lifecycle_state")
        confirm_message, backend_function, args, requires_confirmation = "", None, [], True; action_description = action_type

        try:
            if action_type == "start":
                 action_description = "启动实例"; backend_function, args = backend_start_instance, [self.compute_client, instance_id, self.logger]
                 if instance_state != 'STOPPED': messagebox.showwarning("状态无效", f"实例 '{instance_name}' 当前状态为 {instance_state}，无法启动。", parent=self.root); return
                 confirm_message = f"确定要启动实例 '{instance_name}' 吗？"
            elif action_type == "stop":
                 action_description = "停止实例"; backend_function, args = backend_stop_instance, [self.compute_client, instance_id, self.logger]
                 if instance_state != 'RUNNING': messagebox.showwarning("状态无效", f"实例 '{instance_name}' 当前状态为 {instance_state}，无法停止。", parent=self.root); return
                 confirm_message = f"确定要停止实例 '{instance_name}' 吗？\n(注意：停止会释放临时公网IP，除非它是预留IP)"
            elif action_type == "assign_ipv6":
                action_description = "分配 IPv6 地址"; backend_function = backend_assign_ipv6_to_vnic
                if not vnic_id: self.log_ui(f"无法为实例 '{instance_name}' 分配 IPv6，因为它没有有效的 VNIC ID。", level='ERROR'); messagebox.showerror("缺少信息", f"实例 '{instance_name}' 未找到 VNIC ID，无法分配 IPv6。\n请刷新列表或检查实例配置。", parent=self.root); return
                if not subnet_id: self.log_ui(f"无法为实例 '{instance_name}' 分配 IPv6，因为它没有有效的 Subnet ID。", level='ERROR'); messagebox.showerror("缺少信息", f"实例 '{instance_name}' 未找到关联的 Subnet ID，无法分配 IPv6。\n请刷新列表或检查实例配置。", parent=self.root); return
                if instance_state != 'RUNNING': messagebox.showwarning("状态提示", f"实例 '{instance_name}' 当前状态为 {instance_state}。\n建议在实例运行时分配 IPv6 地址。", parent=self.root)
                confirm_message = f"确定要为实例 '{instance_name}' 的 VNIC ({vnic_id[-12:]}) 自动分配一个 IPv6 地址吗？\n\n请确保：\n1. 该实例所在的子网 ({subnet_id[-12:]}) 已启用 IPv6 并分配了 /64 CIDR。\n2. 你有创建 IPv6 和读取子网的权限 (IPV6_CREATE, SUBNET_READ)。\n3. 该 VNIC 当前未分配 IPv6 (如果已分配，此操作可能失败)。\n\n分配后请在操作系统内配置网络。"
                args = [self.virtual_network_client, vnic_id, subnet_id, self.logger]
            elif action_type == "change_ip":
                 action_description = "更换公网 IP"; backend_function = backend_change_public_ip
                 if not vnic_id: self.log_ui(f"无法为实例 '{instance_name}' 更换 IP，因为它没有有效的 VNIC ID。", level='ERROR'); messagebox.showerror("缺少信息", f"实例 '{instance_name}' 未找到 VNIC ID，无法更换 IP。\n请刷新列表或检查实例配置。", parent=self.root); return
                 if instance_state != 'RUNNING': messagebox.showwarning("状态提示", f"实例 '{instance_name}' 当前不是 RUNNING 状态 ({instance_state})。\n更换 IP 可能需要实例运行，操作可能会失败。", parent=self.root)
                 compartment_id_for_pubip = self.oci_config.get("tenancy") if self.oci_config else None
                 if not compartment_id_for_pubip: self.log_ui("更换 IP 失败：无法获取当前账号的 Tenancy OCID。", level='ERROR'); messagebox.showerror("配置错误", "无法获取当前账号的 Tenancy OCID 以执行操作。", parent=self.root); return
                 args = [self.virtual_network_client, vnic_id, compartment_id_for_pubip, self.logger]
                 confirm_message = f"确定更换实例 '{instance_name}' 的公网 IP 吗？\n\n这将尝试:\n1. 删除当前关联的 *临时* 公网 IP (如果存在)。\n2. 创建一个新的 *临时* 公网 IP 并关联。\n\n(需要 'manage public-ips' 和 'use private-ips' 等权限)"
            elif action_type == "restart":
                 action_description = "重启实例"; backend_function, args = backend_restart_instance, [self.compute_client, instance_id, self.logger]
                 if instance_state != 'RUNNING': messagebox.showwarning("状态无效", f"实例 '{instance_name}' 当前状态为 {instance_state}，无法重启。", parent=self.root); return
                 confirm_message = f"确定要重启实例 '{instance_name}' 吗？\n(将执行 SOFTRESET 操作)"
            elif action_type == "terminate":
                 action_description = "终止实例"; requires_confirmation = False; backend_function = backend_terminate_instance
                 if instance_state == 'TERMINATED': messagebox.showinfo("状态无效", f"实例 '{instance_name}' 已经被终止了。", parent=self.root); return
                 self.logger.warning(f"用户请求终止实例 {instance_name} ({instance_id})")
                 if not messagebox.askyesno("终止确认", f"!!! 警告: 终止实例 '{instance_name}' 操作无法撤销 !!!\n\n确定要继续吗？\n(需要 'manage instance-family' 权限)", icon='warning', parent=self.root): self.log_ui(f"终止实例 '{instance_name}' 操作已取消。", level='INFO'); return
                 preserve_boot = messagebox.askyesno("保留启动卷?", f"终止实例 '{instance_name}' 时是否保留其关联的启动卷？\n\n选“是”将保留启动卷，之后可用于创建新实例。\n选“否”将永久删除启动卷和其中数据。", default=messagebox.NO, parent=self.root)
                 self.logger.info(f"用户选择保留启动卷: {preserve_boot}")
                 if not messagebox.askyesno("最终确认", f"最终确认：终止实例 '{instance_name}'\n(保留启动卷: {'是' if preserve_boot else '否'})\n\n此操作不可逆！", icon='error', parent=self.root): self.log_ui(f"终止实例 '{instance_name}' 操作已最终取消。", level='INFO'); return
                 args = [self.compute_client, instance_id, preserve_boot, self.logger]
            else: self.log_ui(f"未知的操作类型请求: {action_type}", level='ERROR'); messagebox.showerror("内部错误", f"未知的操作类型: {action_type}", parent=self.root); return
        except Exception as setup_error: self.log_ui(f"准备执行操作 '{action_description}' 时出错: {setup_error}", level='ERROR'); self.logger.exception(f"准备操作 '{action_description}' 时出错"); messagebox.showerror("准备操作错误", f"准备执行操作时发生错误:\n{setup_error}", parent=self.root); return

        if requires_confirmation:
             self.logger.info(f"为操作 '{action_description}' 请求用户确认...")
             user_confirmed = messagebox.askyesno("确认操作", confirm_message, parent=self.root)
             if not user_confirmed: self.log_ui(f"操作 '{action_description}' 已被用户取消。", level='INFO'); return
             self.logger.info(f"用户已确认执行操作 '{action_description}'。")

        self.log_ui(f"正在为实例 '{instance_name}' 执行 '{action_description}' 操作...", level='INFO');
        # Safely disable controls
        try:
             self.toggle_controls(connected=True, profiles_exist=bool(self.all_profiles_data), selection_valid=False)
             if hasattr(self, 'refresh_button'): self.refresh_button.config(state='disabled')
        except tk.TclError: self.logger.warning("禁用控件时出错 (窗口可能已关闭)")

        if backend_function is None:
             self.log_ui(f"内部错误：未为操作 '{action_description}' 分配后端函数。", level='ERROR'); messagebox.showerror("内部错误", "未能确定要执行的操作函数。", parent=self.root)
             # Safely re-enable controls
             try:
                 self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=(self.selected_instance_ocid is not None))
                 if hasattr(self, 'refresh_button'): self.refresh_button.config(state='normal' if self.is_connected else 'disabled')
             except tk.TclError: pass # Ignore errors if window closed
             return

        thread = threading.Thread(target=self.run_backend_action, args=(backend_function, args, action_description), daemon=True); thread.start()

    def run_backend_action(self, backend_func, func_args, action_description):
        # Ensure correct indentation (Level 1 within class)
        self.logger.info(f"后台线程：开始执行 '{action_description}'...")
        try: success, message = backend_func(*func_args); self.logger.info(f"后台线程：'{action_description}' 执行完成。Success={success}, Message={message}")
        except Exception as e: error_msg = f"执行 '{action_description}' 时后台线程发生意外错误: {e}"; self.logger.exception(error_msg); success, message = False, error_msg
        # Schedule GUI update only if root window still exists
        if hasattr(self, 'root') and self.root.winfo_exists(): self.root.after(0, self.update_gui_after_action, success, message, action_description)
        else: self.logger.warning(f"后台线程完成 '{action_description}'，但根窗口已关闭，跳过UI更新。")

    def update_gui_after_action(self, success, message, action_description):
        # Ensure correct indentation (Level 1 within class)
        """Updates the GUI (status, messagebox, controls) after a backend action completes."""
        was_terminate_success = action_description == "终止实例" and success
        # Check if selected_instance_ocid still exists in potentially updated instance_data
        is_selection_still_potentially_valid = (self.selected_instance_ocid in self.instance_data) and not was_terminate_success

        # Show message box only if root exists
        if hasattr(self, 'root') and self.root.winfo_exists():
            if success:
                self.log_ui(f"操作 '{action_description}' 成功: {message}", level='INFO'); messagebox.showinfo("操作成功", message, parent=self.root)
                self.log_ui("将在几秒后自动刷新实例列表...", level='INFO')
                self.root.after(3000, self.refresh_list_thread) # Start refresh thread
            else:
                self.log_ui(f"操作 '{action_description}' 失败: {message}", level='ERROR'); messagebox.showerror("操作失败", message, parent=self.root)
                # Re-enable controls after failure if root exists
                self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=is_selection_still_potentially_valid)
                if self.is_connected and hasattr(self, 'refresh_button'): self.refresh_button.config(state='normal')
        else:
             self.logger.warning(f"操作 '{action_description}' 完成 (Success={success})，但根窗口已关闭，跳过消息框和控件更新。")


    # --- Create Instance Methods ---
    def show_create_instance_dialog(self):
        # Ensure correct indentation (Level 1 within class)
        if not self.is_connected or not self.oci_config: messagebox.showwarning("未连接", "请先连接账号才能创建实例。", parent=self.root); return
        selected_alias = self.connected_profile_alias; profile_data = self.all_profiles_data.get(selected_alias)
        if not profile_data: self.log_ui(f"无法创建实例，找不到当前连接账号 '{selected_alias}' 的配置。", level='ERROR'); messagebox.showerror("配置错误", f"无法获取当前连接账号 '{selected_alias}' 的配置数据。", parent=self.root); return
        required_defaults = ['default_subnet_ocid', 'default_ssh_public_key']
        missing_defaults = [k for k in required_defaults if not profile_data.get(k)]
        if missing_defaults: msg = f"账号 '{selected_alias}' 配置缺少必要的默认值，无法使用简化创建功能:\n - {', '.join(missing_defaults)}\n\n请先 '编辑选中账号' 进行设置。"; self.log_ui(f"创建实例前检查失败: {msg}", level='WARN'); messagebox.showerror("缺少默认值", msg, parent=self.root); return
        self.log_ui("打开创建实例对话框...", level='INFO')
        CreateInstanceDialog(self.root, self.compute_client, self.identity_client, profile_data, self.handle_create_instance_result, self.logger)

    def handle_create_instance_result(self, success, message):
        # Ensure correct indentation (Level 1 within class)
        """ Callback from CreateInstanceDialog's backend thread."""
        # Check if root exists before showing dialogs/refreshing
        if not (hasattr(self, 'root') and self.root.winfo_exists()):
             self.logger.warning("创建实例回调触发，但根窗口已关闭。")
             return

        if success:
            self.log_ui(f"创建实例请求发送成功。", level='INFO'); password = None; pw_text_start = "Root 密码: "
            if pw_text_start in message:
                 try: start_index = message.index(pw_text_start) + len(pw_text_start); end_index = message.find('\n', start_index); password = message[start_index:end_index if end_index != -1 else len(message)].strip()
                 except Exception as e: self.logger.error(f"解析创建实例结果中的密码时出错: {e}"); password = None
            if password: self.logger.info("从创建结果中提取到 Root 密码，准备显示对话框。"); PasswordDisplayDialog(self.root, password, self.logger)
            else: self.logger.warning("无法从创建实例成功消息中提取 Root 密码，显示完整消息。"); messagebox.showinfo("创建请求已发送", message, parent=self.root)
            self.log_ui("将在几秒后自动刷新实例列表...", level='INFO'); self.root.after(5000, self.refresh_list_thread)
        else:
             self.log_ui(f"创建实例失败: {message}", level='ERROR'); messagebox.showerror("创建实例失败", message, parent=self.root)
             self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=(self.selected_instance_ocid is not None))

# --- End of OciInstanceManagerApp class ---

# --- Run the Application ---
# Make sure the rest of your script (imports, backend functions, dialog classes,
# and this if __name__ == "__main__": block) are outside the class definition
# and correctly structured.

if __name__ == "__main__":
    root = tk.Tk()
    try: # Optional: Set theme
        style = ttk.Style(root); available_themes = style.theme_names()
        # Prefer modern themes if available
        preferred_themes = ['clam', 'alt', 'default', 'vista', 'xpnative'] # Adjusted order
        for theme in preferred_themes:
            if theme in available_themes:
                 try: style.theme_use(theme); logging.info(f"使用了 ttk 主题: {theme}"); break
                 except tk.TclError: logging.warning(f"尝试设置 ttk 主题 '{theme}' 失败。")
        else: logging.info("无法设置偏好的 ttk 主题，使用默认主题。")
    except Exception as e: logging.error(f"设置 ttk 主题时出错: {e}", exc_info=True) # Log traceback for theme errors

    app = OciInstanceManagerApp(root)
    root.mainloop()
    logging.info("--- OCI Instance Manager Application Exited ---")
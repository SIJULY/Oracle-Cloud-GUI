# -*- coding: utf-8 -*-
# Final Corrected Version (Fixed action_name typo in confirm_and_run_action)
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

# --- Determine script directory and file paths ---
try: script_path = os.path.abspath(__file__)
except NameError: script_path = os.path.abspath(sys.argv[0])
script_dir = os.path.dirname(script_path)
print(f"脚本运行目录: {script_dir}")

PROFILES_FILENAME = "oci_gui_profiles.json"; SETTINGS_FILENAME = "oci_gui_settings.json"; DEFAULT_CONFIG_FILENAME_FOR_IMPORT = "config"
PROFILES_FILE_PATH = os.path.join(script_dir, PROFILES_FILENAME); SETTINGS_FILE_PATH = os.path.join(script_dir, SETTINGS_FILENAME)
DEFAULT_OCI_CONFIG_PATH = os.path.expanduser("~/.oci/config")


# --- Backend OCI 操作函数 ---
# (No changes needed in backend functions for this fix)
def get_detailed_instances(compute_client, virtual_network_client, block_storage_client, compartment_id):
    instance_list_for_gui = []
    try:
        list_instances_response = compute_client.list_instances(compartment_id=compartment_id)
        instances = list_instances_response.data
        if not instances: return [], "在指定区间未找到实例。"
        for instance in instances:
            instance_data = { "display_name": instance.display_name, "id": instance.id, "lifecycle_state": instance.lifecycle_state, "region": instance.region, "availability_domain": instance.availability_domain, "shape": instance.shape, "time_created": instance.time_created.strftime('%Y-%m-%d %H:%M:%S') if instance.time_created else "N/A", "ocpus": instance.shape_config.ocpus if instance.shape_config else "N/A", "memory_in_gbs": instance.shape_config.memory_in_gbs if instance.shape_config else "N/A", "private_ip": "获取中...", "public_ip": "获取中...", "vnic_id": None, "boot_volume_size_gb": "获取中...", "compartment_id": instance.compartment_id }
            try: # Get IP/VNIC
                vnic_attachments = compute_client.list_vnic_attachments(compartment_id=instance.compartment_id, instance_id=instance.id).data
                if vnic_attachments: instance_data["vnic_id"] = vnic_attachments[0].vnic_id; vnic_details = virtual_network_client.get_vnic(vnic_id=instance_data["vnic_id"]).data; instance_data["private_ip"] = vnic_details.private_ip or "N/A"; instance_data["public_ip"] = vnic_details.public_ip or "N/A (或未分配)"
                else: instance_data["private_ip"], instance_data["public_ip"] = "无VNIC附件", "无VNIC附件"
            except Exception as ip_error: print(f"  - 获取 IP/VNIC 警告 ({instance.display_name}): {ip_error}"); instance_data["private_ip"], instance_data["public_ip"] = "获取错误", "获取错误"
            try: # Get Boot Vol Size
                boot_vol_attachments = compute_client.list_boot_volume_attachments(availability_domain=instance.availability_domain, compartment_id=instance.compartment_id, instance_id=instance.id).data
                if boot_vol_attachments: boot_volume_id = boot_vol_attachments[0].boot_volume_id; boot_vol = block_storage_client.get_boot_volume(boot_volume_id=boot_volume_id).data; instance_data["boot_volume_size_gb"] = f"{int(boot_vol.size_in_gbs)} GB"
                else: instance_data["boot_volume_size_gb"] = "无启动卷附件"
            except Exception as bv_error: print(f"  - 获取启动卷大小警告 ({instance.display_name}): {bv_error}"); instance_data["boot_volume_size_gb"] = "获取错误"
            instance_list_for_gui.append(instance_data)
        return instance_list_for_gui, f"成功加载 {len(instance_list_for_gui)} 个实例。"
    except oci.exceptions.ServiceError as e: return [], f"获取实例列表失败: {e.status} {e.code} - {e.message}\n请检查权限和区间OCID。"
    except Exception as e: return [], f"获取实例列表时发生意外错误: {e}"

# **** CORRECTED: Use update_private_ip instead of update_vnic ****
# **** FINAL ATTEMPT: Use create/delete public_ip API ****
# **** FINAL ATTEMPT: Use create/delete public_ip API ****
def backend_change_public_ip(virtual_network_client, vnic_id, compartment_id): # Ensure compartment_id is accepted
    """ Backend logic: Change public IP using get/delete/create PublicIp operations """
    print(f"开始更换 VNIC {vnic_id} 的公网 IP (通过操作PublicIp对象)...")
    primary_private_ip_id = None
    try:
        # 1. Find the Primary Private IP OCID attached to the VNIC
        print(f"  - 查找 VNIC {vnic_id} 的主私有 IP...")
        list_private_ips_response = oci.pagination.list_call_get_all_results(
            virtual_network_client.list_private_ips,
            vnic_id=vnic_id
        )
        primary_private_ip = None
        if list_private_ips_response.data:
            for private_ip_obj in list_private_ips_response.data:
                if private_ip_obj.is_primary:
                    primary_private_ip = private_ip_obj; break
        if not primary_private_ip: return False, f"未能在 VNIC {vnic_id} 上找到主私有 IP。"
        primary_private_ip_id = primary_private_ip.id
        print(f"  - 找到主私有 IP OCID: {primary_private_ip_id}")

        # 2. Find and Delete Existing *Ephemeral* Public IP associated with the Private IP
        print(f"  - 查找当前关联的公网 IP (私有 IP: {primary_private_ip_id})...")
        existing_public_ip = None
        try:
            get_public_ip_details = oci.core.models.GetPublicIpByPrivateIpIdDetails(private_ip_id=primary_private_ip_id)
            existing_public_ip_response = virtual_network_client.get_public_ip_by_private_ip_id(get_public_ip_details)
            existing_public_ip = existing_public_ip_response.data
            print(f"  - 找到现有公网 IP: {existing_public_ip.ip_address} (OCID: {existing_public_ip.id}, Lifetime: {existing_public_ip.lifetime})")

            if existing_public_ip and existing_public_ip.lifetime == oci.core.models.PublicIp.LIFETIME_EPHEMERAL:
                print(f"  - 步骤 1: 删除现有的临时公网 IP {existing_public_ip.id}...")
                virtual_network_client.delete_public_ip(existing_public_ip.id)
                print("  - 删除请求已发送，等待 5 秒...")
                time.sleep(5)
            elif existing_public_ip:
                print(f"  - 注意：找到的公网 IP ({existing_public_ip.ip_address}) 不是临时的，不会自动删除。")

        except oci.exceptions.ServiceError as get_pub_ip_error:
            if get_pub_ip_error.status == 404: print("  - 未找到当前关联的公网 IP，继续...")
            else: raise

        # 3. Create a new Ephemeral Public IP and assign it to the Private IP
        print(f"  - 步骤 2: 创建新的临时公网 IP 并关联到私有 IP {primary_private_ip_id}...")
        # Use the passed compartment_id (likely tenancy root)
        create_public_ip_details = oci.core.models.CreatePublicIpDetails(
            compartment_id=compartment_id,
            lifetime=oci.core.models.PublicIp.LIFETIME_EPHEMERAL,
            private_ip_id=primary_private_ip_id
        )
        create_public_ip_response = virtual_network_client.create_public_ip(create_public_ip_details)
        new_public_ip_obj = create_public_ip_response.data
        new_public_ip_address = new_public_ip_obj.ip_address
        print(f"  - 新公网 IP 创建请求已发送。新 IP 地址: {new_public_ip_address} (OCID: {new_public_ip_obj.id})")
        print("  - 等待 IP 分配稳定...")
        time.sleep(10)

        return True, f"IP 更换请求已发送 (通过操作PublicIp)。新公网IP: {new_public_ip_address}"

    except oci.exceptions.ServiceError as e:
        error_msg = f"更换 IP (操作PublicIp)失败: {e.status} {e.code} - {e.message}"
        if e.status in [401, 403, 404]: error_msg += "\n请检查 'manage public-ips', 'use private-ips' 等权限及相关 OCID。"
        return False, error_msg
    except Exception as e:
        return False, f"更换 IP (操作PublicIp) 时发生意外错误: {e}"

def backend_restart_instance(compute_client, instance_id):
    try:
        compute_client.instance_action(instance_id=instance_id, action="SOFTRESET"); return True, f"实例重启(SOFTRESET)命令已发送。"
    except oci.exceptions.ServiceError as e: return False, f"重启失败: {e.status} {e.code} - {e.message}\n请检查权限和实例 ID。"
    except Exception as e: return False, f"重启时发生意外错误: {e}"

def backend_terminate_instance(compute_client, instance_id, preserve_boot_volume):
    try:
        compute_client.terminate_instance(instance_id=instance_id, preserve_boot_volume=preserve_boot_volume); return True, f"实例终止命令已发送。"
    except oci.exceptions.ServiceError as e: return False, f"终止失败: {e.status} {e.code} - {e.message}\n请检查权限和实例 ID。"
    except Exception as e: return False, f"终止时发生意外错误: {e}"

def backend_list_subnets(vnet_client, compartment_id):
    subnets = []; error = None
    if not compartment_id: return [], "未提供有效的区间OCID来列出子网。"
    try:
        print(f"后台：正在列出区间 '{compartment_id}' 中的子网...")
        list_subnets_response = oci.pagination.list_call_get_all_results(vnet_client.list_subnets, compartment_id=compartment_id, lifecycle_state='AVAILABLE')
        for subnet in list_subnets_response.data: subnets.append({"display_name": subnet.display_name, "cidr": subnet.cidr_block, "id": subnet.id})
        print(f"后台：找到 {len(subnets)} 个子网。")
    except oci.exceptions.ServiceError as e: error = f"获取子网列表失败: {e.status} {e.code} - {e.message}\n请检查'use subnets'权限和区间OCID。"; print(error)
    except Exception as e: error = f"获取子网列表意外错误: {e}"; print(error)
    return subnets, error

def backend_find_image_ocid(compute_client, os_name, os_version, shape_name):
    try:
        tenancy_id = compute_client.base_client.config.get('tenancy')
        if not tenancy_id: return None, "无法从当前配置中获取 Tenancy OCID。"
        print(f"查找镜像: os='{os_name}', version='{os_version}', shape='{shape_name}' (在租户 {tenancy_id} 中搜索)")
        list_images_response = oci.pagination.list_call_get_all_results(compute_client.list_images, compartment_id=tenancy_id, operating_system=os_name, operating_system_version=os_version, shape=shape_name, sort_by="TIMECREATED", sort_order="DESC", lifecycle_state = oci.core.models.Image.LIFECYCLE_STATE_AVAILABLE)
        if list_images_response.data:
            latest_image = list_images_response.data[0]; print(f"在租户根区间找到镜像: {latest_image.display_name} ({latest_image.id})"); return latest_image.id, None
        else: error_msg = f"在租户根区间未找到与 '{os_name} {os_version} ({shape_name})' 兼容的可用平台镜像。"; print(error_msg); return None, error_msg
    except oci.exceptions.ServiceError as e:
        error_msg = f"查找镜像失败: {e.status} {e.code} - {e.message}";
        if e.status in [401, 403, 404]: error_msg += "\n请检查是否拥有在租户根区间 'inspect images' 的权限。"
        print(error_msg); return None, error_msg
    except Exception as e: error_msg = f"查找镜像时发生意外错误: {e}"; print(error_msg); return None, error_msg

def generate_random_password(length=16):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+=-`~[]{};:,.<>?"; password = ''.join(secrets.choice(characters) for i in range(length)); return password
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

def backend_create_instance(compute_client, identity_client, details):
    try:
        profile_defaults = details['profile_defaults']; tenancy_ocid = profile_defaults['tenancy']
        compartment_id = tenancy_ocid; print(f"使用区间 OCID: {compartment_id}") # Always use tenancy
        print("自动查找可用域..."); ads, error = [], None
        try: list_ads_response = oci.pagination.list_call_get_all_results(identity_client.list_availability_domains, compartment_id=tenancy_ocid); ads = list_ads_response.data
        except Exception as ad_err: error = f"无法列出可用域: {ad_err}"
        if error or not ads: return False, error or "无法自动确定可用域。"
        ad_name = ads[0].name; print(f"自动选择第一个可用域: {ad_name}")
        subnet_id = profile_defaults.get('default_subnet_ocid')
        if not subnet_id: return False, "账号配置中缺少必需的 'default_subnet_ocid'。" ; print(f"使用默认子网 OCID: {subnet_id}")
        ssh_key = profile_defaults.get('default_ssh_public_key')
        if not ssh_key: return False, "账号配置中缺少必需的 'default_ssh_public_key'。"; print(f"使用默认 SSH 公钥。")
        image_ocid, error = backend_find_image_ocid(compute_client, details['os_name'], details['os_version'], details['shape']) # Correct call signature
        if error or not image_ocid: return False, f"查找镜像失败: {error}"
        print(f"使用镜像 OCID: {image_ocid}")
        root_password = generate_random_password(); user_data_encoded = generate_cloud_init_userdata(root_password); print("已生成随机 Root 密码并通过 cloud-init 设置。")
        base_name_for_init = details.get('display_name_prefix', 'Instance')
        launch_details = oci.core.models.LaunchInstanceDetails( compartment_id=compartment_id, availability_domain=ad_name, shape=details['shape'], display_name=base_name_for_init, create_vnic_details=oci.core.models.CreateVnicDetails(subnet_id=subnet_id, assign_public_ip=True), metadata={"ssh_authorized_keys": ssh_key, "user_data": user_data_encoded}, source_details=oci.core.models.InstanceSourceViaImageDetails(image_id=image_ocid, boot_volume_size_in_gbs=details['boot_volume_size']), shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(ocpus=details.get('ocpus'), memory_in_gbs=details.get('memory_in_gbs')) if details.get('ocpus') or details.get('memory_in_gbs') else None)
        created_instances_info = []; base_name = details.get('display_name_prefix', 'Instance'); instance_count = details.get('instance_count', 1); all_success = True; error_messages = []
        for i in range(instance_count):
            instance_name = f"{base_name}-{i+1}" if instance_count > 1 else base_name; launch_details.display_name = instance_name
            print(f"尝试创建实例 {i+1}/{instance_count}: {instance_name}")
            try: launch_response = compute_client.launch_instance(launch_details); instance_ocid = launch_response.data.id; print(f"  -> 请求已发送。OCID: {instance_ocid}"); created_instances_info.append({"name": instance_name, "ocid": instance_ocid});
            except oci.exceptions.ServiceError as e: all_success = False; error_msg = f"创建 '{instance_name}' 失败: {e.status} {e.code} - {e.message}"; error_messages.append(error_msg); print(f"  -> 失败: {error_msg}"); break
            except Exception as e: all_success = False; error_msg = f"创建 '{instance_name}' 意外错误: {e}"; error_messages.append(error_msg); print(f"  -> 失败: {error_msg}"); break
            if i < instance_count - 1: time.sleep(2)
        if created_instances_info:
            success_msg = "实例创建请求已发送:\n" + "\n".join([f"- {info['name']} (OCID: ...{info['ocid'][-12:]})" for info in created_instances_info])
            success_msg += f"\n\n*** 重要: 请立即保存以下生成的 Root 密码！ ***\n\nRoot 密码: {root_password}\n"
            if not all_success: success_msg += "\n\n但后续实例创建因错误中止:\n" + "\n".join(error_messages)
            return True, success_msg
        else:
            if not error_messages: error_messages.append("未知错误导致无法创建任何实例。")
            return False, "所有实例创建均失败:\n" + "\n".join(error_messages)
    except Exception as e: error_msg = f"创建实例准备阶段出错: {e}"; print(error_msg); return False, error_msg
# --- End Backend Functions ---


# --- Dialog Classes ---
# ImportDialog (Corrected - Removed Optional Fields)
class ImportDialog(tk.Toplevel):
     # ...(Same as previous version)...
     def __init__(self, parent, original_profiles_from_ini, existing_aliases_in_use, callback):
        super().__init__(parent); self.transient(parent); self.title("导入档案并设置别名/默认值"); self.geometry("650x400"); # Adjusted height
        self.original_profiles = original_profiles_from_ini; self.existing_aliases_in_use = set(existing_aliases_in_use); self.callback = callback; self.profile_widgets = {}
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
        profiles_to_import_full_data = {}; aliases_in_use_this_dialog = set(); has_duplicate = False; missing_required_defaults = []; existing_aliases_in_app = set(self.existing_aliases_in_use)
        for original_name, widgets in self.profile_widgets.items():
            if widgets['import_var'].get():
                alias = widgets['alias_entry'].get().strip() or original_name; subnet = widgets['subnet_entry'].get().strip(); ssh_key = widgets['ssh_entry'].get().strip()
                if alias in aliases_in_use_this_dialog: messagebox.showwarning("别名重复", f"别名 '{alias}' 在本次导入中被多次使用。", parent=self); has_duplicate = True; break
                aliases_in_use_this_dialog.add(alias)
                if not subnet or not ssh_key: missing_required_defaults.append(alias)
                profiles_to_import_full_data[alias] = { "original_name": original_name, "defaults": { "default_subnet_ocid": subnet or None, "default_ssh_public_key": ssh_key or None } }
        if has_duplicate: return
        if missing_required_defaults:
            if not messagebox.askyesno("缺少默认值", f"以下别名缺少必要的默认子网或SSH公钥，将无法使用简化创建功能:\n - {', '.join(missing_required_defaults)}\n\n仍要导入吗 (后续可编辑补充)?", parent=self):
                 profiles_to_import_full_data = {a: d for a, d in profiles_to_import_full_data.items() if a not in missing_required_defaults}
                 if not profiles_to_import_full_data: print("没有可导入的档案了。"); self.destroy(); return
        conflicts = [alias for alias in profiles_to_import_full_data if alias in existing_aliases_in_app]
        if conflicts:
             if not messagebox.askyesno("确认覆盖?", f"以下别名已存在:\n - {', '.join(conflicts)}\n\n确定要覆盖吗？", icon='warning', parent=self):
                 profiles_to_import_full_data = {a: d for a, d in profiles_to_import_full_data.items() if a not in conflicts}
                 if not profiles_to_import_full_data: print("没有可导入的档案了。"); self.destroy(); return
        if self.callback: self.callback(profiles_to_import_full_data)
        self.destroy()

# EditProfileDialog (Corrected - Removed Optional Fields, Adjusted Layout)
class EditProfileDialog(tk.Toplevel):
     def __init__(self, parent, alias, profile_data, vnet_client, callback):
         super().__init__(parent); self.transient(parent); self.title(f"编辑账号: {alias}");
         self.geometry("700x500"); # Adjusted height
         self.resizable(True, True)
         self.profile_data_original = profile_data.copy(); self.alias_original = alias; self.callback = callback
         self.vnet_client = vnet_client; self.entries = {}; self.subnets_map = {};
         self.selected_subnet_ocid_var = tk.StringVar()
         canvas = tk.Canvas(self); scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
         scrollbar.pack(side=tk.RIGHT, fill=tk.Y); canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
         content_frame = ttk.Frame(canvas, padding="10"); content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
         canvas.create_window((0, 0), window=content_frame, anchor="nw"); canvas.configure(yscrollcommand=scrollbar.set)
         ttk.Label(content_frame, text=f"编辑账号配置和默认值 (别名: {alias})").grid(row=0, column=0, columnspan=3, pady=(0, 10), sticky='w')
         fields = [ ('user', 'User OCID*:', 60, True), ('fingerprint', '指纹*:', 60, True), ('tenancy', 'Tenancy OCID*:', 60, True), ('region', '区域*:', 30, True), ('key_file', '密钥文件路径*:', 50, True), ('passphrase', '密钥密码(可选):', 30, False) ]
         row_idx = 1
         for key, label, width, req_conn in fields:
             ttk.Label(content_frame, text=label).grid(row=row_idx, column=0, sticky=tk.E, padx=5, pady=3)
             entry = ttk.Entry(content_frame, width=width); entry.insert(0, self.profile_data_original.get(key) or ""); entry.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=3); self.entries[key] = entry
             if key == 'key_file': browse = ttk.Button(content_frame, text="浏览...", command=lambda e=entry: self.browse_edit_key(e)); browse.grid(row=row_idx, column=2, padx=5, sticky='w')
             if key == 'tenancy': entry.bind("<FocusOut>", lambda e, k=key: self.load_subnets_for_edit()); entry.bind("<Return>", lambda e, k=key: self.load_subnets_for_edit())
             row_idx += 1
         ttk.Label(content_frame, text="默认子网 OCID**:").grid(row=row_idx, column=0, sticky=tk.E, padx=5, pady=3)
         self.subnet_combobox = ttk.Combobox(content_frame, textvariable=self.selected_subnet_ocid_var, state='disabled', width=48, values=[" "]);
         self.subnet_combobox.grid(row=row_idx, column=1, sticky=tk.EW, padx=5, pady=3)
         self.load_subnet_button = ttk.Button(content_frame, text="加载/刷新子网", command=self.load_subnets_for_edit);
         self.load_subnet_button.grid(row=row_idx, column=2, padx=5, sticky='w')
         self.entries["default_subnet_ocid"] = self.selected_subnet_ocid_var
         row_idx += 1
         ttk.Label(content_frame, text="默认SSH公钥**:").grid(row=row_idx, column=0, sticky=tk.NE, padx=5, pady=3)
         self.ssh_key_text = scrolledtext.ScrolledText(content_frame, width=60, height=5, wrap=tk.WORD); self.ssh_key_text.insert("1.0", self.profile_data_original.get("default_ssh_public_key") or ""); self.ssh_key_text.grid(row=row_idx, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=3); self.entries["default_ssh_public_key"] = self.ssh_key_text; row_idx +=1
         ttk.Label(content_frame, text="* OCI连接必需字段.", foreground="gray").grid(row=row_idx, column=1, columnspan=2, sticky='w', padx=5, pady=2); row_idx += 1
         ttk.Label(content_frame, text="** 使用简化'创建实例'功能必需字段.", foreground="blue").grid(row=row_idx, column=1, columnspan=2, sticky='w', padx=5, pady=2); row_idx += 1
         button_frame = ttk.Frame(content_frame); button_frame.grid(row=row_idx, column=0, columnspan=3, pady=(15, 5))
         save_button = ttk.Button(button_frame, text="保存更改", command=self.save_changes); save_button.pack(side="left", padx=10)
         cancel_button = ttk.Button(button_frame, text="取消", command=self.destroy); cancel_button.pack(side="left", padx=10)
         content_frame.columnconfigure(1, weight=1)
         if self.vnet_client: self.load_subnets_for_edit(initial=True)
         else: self.subnet_combobox.config(values=["需先连接才能加载"], state='disabled'); self.load_subnet_button.config(state='disabled')
         self.grab_set(); self.wait_window()
     def browse_edit_key(self, entry_widget):
        filepath = filedialog.askopenfilename(title="选择私钥文件", filetypes=(("PEM files", "*.pem"), ("All files", "*.*")))
        if filepath: entry_widget.delete(0, tk.END); entry_widget.insert(0, filepath)
     def load_subnets_for_edit(self, initial=False):
        if not self.vnet_client:
             if not initial: messagebox.showwarning("未连接", "请先在主窗口连接此账号，才能加载子网列表。", parent=self)
             return
        comp_ocid = self.entries['tenancy'].get().strip()
        if not comp_ocid:
             if not initial: messagebox.showwarning("缺少信息", "请输入 Tenancy OCID 以加载子网。", parent=self)
             self.subnet_combobox.config(values=[], state='disabled'); self.selected_subnet_ocid_var.set('')
             return
        self.subnet_combobox.config(values=["正在加载..."], state='disabled'); self.selected_subnet_ocid_var.set("正在加载...")
        thread = threading.Thread(target=self.load_subnets_backend, args=(comp_ocid, initial), daemon=True); thread.start()
     def load_subnets_backend(self, compartment_id, initial):
        subnets, error = backend_list_subnets(self.vnet_client, compartment_id); subnet_display_list = []; self.subnets_map.clear(); cb_state='disabled'; selected_val=''
        if error:
            if not initial: self.after(0, lambda: messagebox.showerror("获取子网错误", error, parent=self))
            else: print(f"编辑对话框初始化时获取子网错误: {error}")
        elif subnets:
            for subnet in subnets: display_name = f"{subnet['display_name']} ({subnet['cidr']})"; subnet_display_list.append(display_name); self.subnets_map[display_name] = subnet['id']
            cb_state='readonly'; saved_subnet_ocid = self.profile_data_original.get('default_subnet_ocid'); found_match = False
            if saved_subnet_ocid:
                for disp, ocid in self.subnets_map.items():
                     if ocid == saved_subnet_ocid: selected_val = disp; found_match = True; break
            current_selection = self.selected_subnet_ocid_var.get()
            if not found_match and current_selection in self.subnets_map: selected_val = current_selection; found_match = True
            if not found_match and subnet_display_list: selected_val = sorted(subnet_display_list)[0]
        else:
            if not initial: self.after(0, lambda: messagebox.showinfo("无子网", f"在区间 '{compartment_id}' 中未找到可用子网。", parent=self))
        self.after(0, lambda: self.subnet_combobox.config(values=sorted(subnet_display_list), state=cb_state))
        self.after(0, lambda: self.selected_subnet_ocid_var.set(selected_val))
     def save_changes(self):
         updated_data = {}
         for key, widget in self.entries.items():
             if key == "default_subnet_ocid": display_value = widget.get(); updated_data[key] = self.subnets_map.get(display_value)
             elif key == "default_ssh_public_key": value = widget.get("1.0", tk.END).strip(); updated_data[key] = value if value else None
             elif key not in ["default_compartment_ocid", "default_ad_name"]: # Exclude removed keys
                 value = widget.get().strip(); updated_data[key] = value if value else None
         required_keys = ['user', 'fingerprint', 'tenancy', 'region', 'key_file']
         missing = [k for k in required_keys if not updated_data.get(k)]
         if missing: messagebox.showerror("缺少信息", f"必需字段 ({', '.join(missing)}) 不能为空。", parent=self); return
         updated_data.pop("default_compartment_ocid", None); updated_data.pop("default_ad_name", None) # Ensure removed keys are gone
         if self.callback: self.callback(self.alias_original, updated_data)
         self.destroy()

# CreateInstanceDialog (No changes needed)
class CreateInstanceDialog(tk.Toplevel):
     # ...(Same as before)...
     def __init__(self, parent, compute_client, identity_client, profile_data, callback):
        super().__init__(parent); self.transient(parent); self.title("创建新实例 (简化模式)"); self.geometry("500x350"); self.resizable(False, False)
        self.compute_client = compute_client; self.identity_client = identity_client;
        self.profile_data = profile_data; self.callback = callback
        self.selected_shape = tk.StringVar(); self.instance_type = tk.StringVar(value="AMD"); self.os_choice_var = tk.StringVar()
        main_frame = ttk.Frame(self, padding="10"); main_frame.pack(expand=True, fill="both"); row_idx = 0
        ttk.Label(main_frame, text="实例架构:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); type_frame = ttk.Frame(main_frame); type_frame.grid(row=row_idx, column=1, columnspan=2, sticky=tk.W, padx=5, pady=3); ttk.Radiobutton(type_frame, text="AMD Micro (E2.1)", variable=self.instance_type, value="AMD", command=self.update_shape_fields).pack(side=tk.LEFT); ttk.Radiobutton(type_frame, text="ARM Flex (A1)", variable=self.instance_type, value="ARM", command=self.update_shape_fields).pack(side=tk.LEFT, padx=10); row_idx += 1
        ttk.Label(main_frame, text="操作系统:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); os_options = ["Oracle Linux (最新)", "Ubuntu 22.04 (最新)", "Ubuntu 20.04 (最新)"]; self.os_combobox = ttk.Combobox(main_frame, textvariable=self.os_choice_var, values=os_options, state='readonly', width=25); self.os_choice_var.set(os_options[0]); self.os_combobox.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3); row_idx += 1
        ttk.Label(main_frame, text="CPU 核心数:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); self.ocpu_entry = ttk.Entry(main_frame, width=10, state='disabled'); self.ocpu_entry.insert(0, "1"); self.ocpu_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3); row_idx += 1
        ttk.Label(main_frame, text="内存 (GB):").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); self.memory_entry = ttk.Entry(main_frame, width=10, state='disabled'); self.memory_entry.insert(0, "6"); self.memory_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3); row_idx += 1
        ttk.Label(main_frame, text="引导卷大小 (GB):").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); self.boot_vol_entry = ttk.Entry(main_frame, width=10); self.boot_vol_entry.insert(0, "50"); self.boot_vol_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3); row_idx += 1
        ttk.Label(main_frame, text="名称前缀(可选):").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); self.name_prefix_entry = ttk.Entry(main_frame, width=30); self.name_prefix_entry.insert(0, "Instance"); self.name_prefix_entry.grid(row=row_idx, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=3); row_idx += 1
        ttk.Label(main_frame, text="创建数量:").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); self.count_entry = ttk.Entry(main_frame, width=10); self.count_entry.insert(0, "1"); self.count_entry.grid(row=row_idx, column=1, sticky=tk.W, padx=5, pady=3); row_idx += 1
        ttk.Label(main_frame, text="登录方式:", foreground="blue").grid(row=row_idx, column=0, sticky=tk.W, padx=5, pady=3); ttk.Label(main_frame, text="将启用Root密码登录(随机生成)", foreground="red").grid(row=row_idx, column=1, columnspan=2, sticky=tk.W, padx=5, pady=3); row_idx += 1
        button_frame = ttk.Frame(main_frame); button_frame.grid(row=row_idx, column=0, columnspan=3, pady=(15, 0)); create_button = ttk.Button(button_frame, text="创建实例", command=self.create_instance_thread); create_button.pack(side="left", padx=10); cancel_button = ttk.Button(button_frame, text="取消", command=self.destroy); cancel_button.pack(side="left", padx=10)
        self.update_shape_fields(); self.grab_set(); self.wait_window()
     def update_shape_fields(self):
        type = self.instance_type.get(); shape_state = 'normal' if type == "ARM" else 'disabled'; shape = "VM.Standard.A1.Flex" if type == "ARM" else "VM.Standard.E2.1.Micro"
        self.selected_shape.set(shape); self.ocpu_entry.config(state=shape_state); self.memory_entry.config(state=shape_state)
     def create_instance_thread(self):
        details = {'profile_defaults': self.profile_data}
        details['display_name_prefix'] = self.name_prefix_entry.get().strip() or "Instance"
        try: details['instance_count'] = int(self.count_entry.get().strip()); assert details['instance_count'] >= 1
        except: messagebox.showerror("输入错误", "数量须>=1", parent=self); return
        details['shape'] = self.selected_shape.get()
        os_choice = self.os_choice_var.get()
        if "Ubuntu 22.04" in os_choice: details['os_name'], details['os_version'] = "Canonical Ubuntu", "22.04"
        elif "Ubuntu 20.04" in os_choice: details['os_name'], details['os_version'] = "Canonical Ubuntu", "20.04"
        else: details['os_name'], details['os_version'] = "Oracle Linux", "9"
        if self.instance_type.get() == "ARM":
            try: details['ocpus'] = float(self.ocpu_entry.get().strip()); details['memory_in_gbs'] = float(self.memory_entry.get().strip()); assert details['ocpus'] > 0 and details['memory_in_gbs'] > 0
            except: messagebox.showerror("输入错误", f"ARM CPU/内存须为正数", parent=self); return
        else: details['ocpus'], details['memory_in_gbs'] = None, None
        try: details['boot_volume_size'] = int(self.boot_vol_entry.get().strip()); assert details['boot_volume_size'] >= 50
        except: messagebox.showerror("输入错误", f"引导卷大小须>=50", parent=self); return
        required_defaults = ['default_subnet_ocid', 'default_ssh_public_key']
        missing_defaults = [k for k in required_defaults if not self.profile_data.get(k)]
        if missing_defaults: messagebox.showerror("缺少配置", f"当前账号配置缺少默认值:\n - {', '.join(missing_defaults)}\n请先 '编辑选中账号' 设置。", parent=self); return
        print("准备创建实例 (使用账号默认值)..."); self.destroy()
        thread = threading.Thread(target=self.create_instance_backend, args=(details,), daemon=True); thread.start()
     def create_instance_backend(self, details):
        success, message = backend_create_instance(self.compute_client, self.identity_client, details)
        if self.callback: self.callback(success, message)

# Password Display Dialog (No change needed)
class PasswordDisplayDialog(tk.Toplevel):
     # ...(Same as before)...
     def __init__(self, parent, password):
         super().__init__(parent); self.transient(parent); self.title("实例 Root 密码"); self.geometry("400x150"); self.resizable(False, False)
         main_frame = ttk.Frame(self, padding="15"); main_frame.pack(expand=True, fill="both")
         ttk.Label(main_frame, text="*** 重要 ***", foreground="red", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 5))
         ttk.Label(main_frame, text="实例创建请求已发送。请立即复制并保存下方生成的Root密码！\n此密码仅显示一次。", wraplength=360).pack(pady=(0,10))
         pass_frame = ttk.Frame(main_frame); pass_frame.pack(pady=5); ttk.Label(pass_frame, text="Root 密码:").pack(side=tk.LEFT, padx=(0,5)); pass_entry = ttk.Entry(pass_frame, width=30); pass_entry.insert(0, password); pass_entry.config(state='readonly'); pass_entry.pack(side=tk.LEFT)
         ok_button = ttk.Button(main_frame, text="我已保存，关闭", command=self.destroy); ok_button.pack(pady=(10,0))
         self.grab_set(); self.wait_window()


# --- Main Application Class ---
# (Structure mostly same, calls updated methods)
class OciInstanceManagerApp:
    PROFILES_FILE = PROFILES_FILE_PATH
    SETTINGS_FILE = SETTINGS_FILE_PATH

    def __init__(self, root):
        # ...(Initialize state variables)...
        self.root = root; self.root.title("OCI 实例管理器 (JSON存储-创建实例版)"); self.root.geometry("1100x700")
        self.oci_config = None; self.identity_client = None; self.compute_client = None; self.virtual_network_client = None; self.block_storage_client = None
        self.is_connected = False; self.connected_profile_alias = None
        self.profile_alias_var = tk.StringVar(); self.all_profiles_data = {} # Main store: {alias: {config+defaults}}
        self.last_used_alias = None; self.instance_data = {}; self.selected_instance_ocid = None

        self.load_settings_from_file(); self.load_profiles_from_file()
        self.create_config_frame(); self.create_instance_view(); self.create_action_buttons(); self.create_status_bar()
        self.update_combobox_from_profiles(); # Populate combobox AFTER loading profiles
        if self.all_profiles_data: self.update_status("未连接。请选择账号并连接。")
        else: self.update_status("未找到账号配置。请使用 '添加账号' 功能导入。")
        self.toggle_controls(connected=False, profiles_exist=bool(self.all_profiles_data), selection_valid=False)

    # ...(Persistence Methods - load/save_profiles, load/save_settings - Same)...
    def load_profiles_from_file(self):
        try:
            if os.path.exists(self.PROFILES_FILE):
                with open(self.PROFILES_FILE, 'r', encoding='utf-8') as f: self.all_profiles_data = json.load(f); print(f"加载 {len(self.all_profiles_data)} 个账号配置。")
            else: print("账号配置文件不存在。"); self.all_profiles_data = {}
        except (IOError, json.JSONDecodeError) as e: print(f"加载账号配置错误: {e}"); messagebox.showerror("加载错误", f"无法加载账号配置文件:\n{e}"); self.all_profiles_data = {}
    def save_profiles_to_file(self):
        try:
            with open(self.PROFILES_FILE, 'w', encoding='utf-8') as f: json.dump(self.all_profiles_data, f, indent=4, ensure_ascii=False); print(f"账号配置已保存。")
        except IOError as e: print(f"保存账号配置错误: {e}"); messagebox.showerror("保存错误", f"无法保存账号配置文件:\n{e}")
    def load_settings_from_file(self):
        try:
            if os.path.exists(self.SETTINGS_FILE):
                with open(self.SETTINGS_FILE, 'r', encoding='utf-8') as f: settings = json.load(f); self.last_used_alias = settings.get("last_profile_alias"); print(f"加载设置。")
            else: print("设置文件不存在。"); self.last_used_alias = None
        except (IOError, json.JSONDecodeError) as e: print(f"加载设置错误: {e}"); self.last_used_alias = None
    def save_settings_to_file(self, profile_alias):
        settings = {"last_profile_alias": profile_alias }
        try:
            with open(self.SETTINGS_FILE, 'w', encoding='utf-8') as f: json.dump(settings, f, indent=4, ensure_ascii=False); print(f"设置已保存。")
        except IOError as e: print(f"保存设置错误: {e}")

    # ...(GUI Update and Toggle - toggle_controls, update_status - Same)...
    def update_status(self, text):
        def update(): self.status_label.config(text=text); self.root.update_idletasks()
        self.root.after(0, update)
    def toggle_controls(self, connected, profiles_exist, selection_valid):
        def update_states():
            self.add_profile_button.config(state='normal')
            edit_delete_state = 'normal' if profiles_exist and self.profile_alias_var.get() else 'disabled'
            self.edit_profile_button.config(state=edit_delete_state); self.delete_profile_button.config(state=edit_delete_state)
            self.profiles_combobox.config(state='readonly' if profiles_exist else 'disabled'); self.connect_button.config(state='normal' if profiles_exist and not connected else 'disabled')
            refresh_state = 'normal' if connected else 'disabled'; action_state = 'normal' if connected and selection_valid else 'disabled'
            self.refresh_button.config(state=refresh_state); self.create_instance_button.config(state=refresh_state)
            self.change_ip_button.config(state=action_state); self.restart_button.config(state=action_state); self.terminate_button.config(state=action_state)
        self.root.after(0, update_states)

    # ...(GUI Creation Methods - create_config_frame, create_instance_view, create_action_buttons, create_status_bar - Same)...
    def create_config_frame(self):
        config_frame = ttk.LabelFrame(self.root, text="账号配置管理 (存储于 "+PROFILES_FILENAME+")", padding=(10, 5)); config_frame.pack(pady=5, padx=10, fill=tk.X)
        ttk.Label(config_frame, text="选择账号(别名):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.profiles_combobox = ttk.Combobox(config_frame, textvariable=self.profile_alias_var, state='disabled', width=30); self.profiles_combobox.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5); self.profiles_combobox.bind('<<ComboboxSelected>>', self.on_profile_selected)
        self.connect_button = ttk.Button(config_frame, text="使用选中账号连接", command=self.connect_oci_thread, state='disabled'); self.connect_button.grid(row=0, column=2, padx=5, pady=5)
        button_frame_mgmt = ttk.Frame(config_frame); button_frame_mgmt.grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=5)
        self.add_profile_button = ttk.Button(button_frame_mgmt, text="添加账号 (从INI导入)", command=self.import_profile_from_ini); self.add_profile_button.pack(side=tk.LEFT, padx=(0,5))
        self.edit_profile_button = ttk.Button(button_frame_mgmt, text="编辑选中账号", command=self.edit_profile, state='disabled'); self.edit_profile_button.pack(side=tk.LEFT, padx=5)
        self.delete_profile_button = ttk.Button(button_frame_mgmt, text="删除选中账号", command=self.delete_profile, state='disabled'); self.delete_profile_button.pack(side=tk.LEFT, padx=5)
        config_frame.columnconfigure(1, weight=1)
    def create_instance_view(self):
        view_frame = ttk.Frame(self.root, padding=(10, 5)); view_frame.pack(expand=True, fill=tk.BOTH, padx=10)
        columns = ('name', 'status', 'public_ip', 'config', 'ad', 'created', 'ocid'); self.instance_treeview = ttk.Treeview(view_frame, columns=columns, show='headings', selectmode='browse')
        col_widths = {'name': 160, 'status': 80, 'public_ip': 120, 'config': 160, 'ad': 180, 'created': 150, 'ocid': 250}; col_display = {'name': '显示名称', 'status': '状态', 'public_ip': '公网IP', 'config': '配置(核/内存/磁盘)', 'ad': '可用域', 'created': '创建时间', 'ocid': '实例 OCID'}
        for col in columns: self.instance_treeview.heading(col, text=col_display[col]); self.instance_treeview.column(col, width=col_widths[col], anchor=tk.W if col != 'status' else tk.CENTER)
        vsb = ttk.Scrollbar(view_frame, orient="vertical", command=self.instance_treeview.yview); hsb = ttk.Scrollbar(view_frame, orient="horizontal", command=self.instance_treeview.xview); self.instance_treeview.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.instance_treeview.grid(row=0, column=0, sticky='nsew'); vsb.grid(row=0, column=1, sticky='ns'); hsb.grid(row=1, column=0, sticky='ew')
        view_frame.grid_rowconfigure(0, weight=1); view_frame.grid_columnconfigure(0, weight=1); self.instance_treeview.bind('<<TreeviewSelect>>', self.on_instance_select)
    def create_action_buttons(self):
        action_frame = ttk.Frame(self.root, padding=(10, 5)); action_frame.pack(pady=5, padx=10, fill=tk.X)
        self.refresh_button = ttk.Button(action_frame, text="刷新列表", command=self.refresh_list_thread); self.refresh_button.pack(side=tk.LEFT, padx=5)
        self.create_instance_button = ttk.Button(action_frame, text="创建实例", command=self.show_create_instance_dialog, state='disabled'); self.create_instance_button.pack(side=tk.LEFT, padx=5)
        self.change_ip_button = ttk.Button(action_frame, text="更换公网IP", command=lambda: self.confirm_and_run_action("change_ip")); self.change_ip_button.pack(side=tk.LEFT, padx=5)
        self.restart_button = ttk.Button(action_frame, text="重启实例", command=lambda: self.confirm_and_run_action("restart")); self.restart_button.pack(side=tk.LEFT, padx=5)
        self.terminate_button = ttk.Button(action_frame, text="终止实例", command=lambda: self.confirm_and_run_action("terminate")); self.terminate_button.pack(side=tk.LEFT, padx=5)
    def create_status_bar(self):
        self.status_label = ttk.Label(self.root, text="未连接", relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2)); self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Profile Management Methods ---
    def update_combobox_from_profiles(self):
        # ...(Refreshes combobox from self.all_profiles_data, selects last used)...
        aliases = sorted(list(self.all_profiles_data.keys()))
        self.profiles_combobox.config(values=aliases)
        profiles_exist = bool(aliases); selected_alias_to_set = ''
        if profiles_exist:
             if self.last_used_alias and self.last_used_alias in aliases: selected_alias_to_set = self.last_used_alias
             else: selected_alias_to_set = aliases[0]
             self.profiles_combobox.config(state='readonly');
             if not self.is_connected: self.update_status("账号列表已加载。请选择账号并连接。")
        else:
             self.profiles_combobox.config(state='disabled');
             if not self.is_connected: self.update_status("未找到账号配置。请使用 '添加账号' 功能导入。")
        self.profile_alias_var.set(selected_alias_to_set)
        # Let toggle_controls handle overall state after this runs in __init__ or other updates

    def import_profile_from_ini(self):
        # ...(Shows ImportDialog, calls process_imported_profiles)...
        default_ini = DEFAULT_OCI_CONFIG_PATH if os.path.exists(DEFAULT_OCI_CONFIG_PATH) else script_dir
        ini_path = filedialog.askopenfilename(title="选择包含档案的 OCI 配置文件 (.ini 或 config)", initialdir=os.path.dirname(default_ini), filetypes=(("Config/INI", "*.ini"), ("Config files", "config"), ("All files", "*.*")))
        if not ini_path: return
        config_parser = configparser.ConfigParser();
        try:
            config_parser.read(ini_path); original_profiles = config_parser.sections(); has_default_content = 'DEFAULT' in config_parser and bool(config_parser['DEFAULT'])
            if has_default_content and 'DEFAULT' not in original_profiles: original_profiles.insert(0, 'DEFAULT')
            if not original_profiles: messagebox.showinfo("无档案", f"文件 '{os.path.basename(ini_path)}' 中未找到档案节头。"); return
            ImportDialog(self.root, original_profiles, list(self.all_profiles_data.keys()), lambda import_map: self.process_imported_profiles(import_map, ini_path))
        except configparser.Error as e: messagebox.showerror("文件解析错误", f"读取配置文件 '{os.path.basename(ini_path)}' 时出错:\n{e}")
        except Exception as e: messagebox.showerror("导入错误", f"处理导入时未知错误:\n{e}")

    def process_imported_profiles(self, profiles_to_import_full_data, source_ini_path):
         # (Callback from ImportDialog - structure is {alias: {original_name:..., defaults:{...}}})
         if not profiles_to_import_full_data: print("没有选择要导入的档案。"); return
         self.update_status("正在导入档案配置..."); newly_added = 0; updated = 0; errors = []; profiles_changed = False
         for alias, import_data in profiles_to_import_full_data.items():
             original_name = import_data["original_name"]; defaults = import_data["defaults"]
             try: # Overwrite check handled in dialog
                 cfg = oci.config.from_file(file_location=source_ini_path, profile_name=original_name)
                 profile_data = { "user": cfg.get("user"), "fingerprint": cfg.get("fingerprint"), "tenancy": cfg.get("tenancy"), "region": cfg.get("region"), "key_file": cfg.get("key_file"), "passphrase": cfg.get("passphrase") }
                 if not all(k in profile_data and profile_data[k] for k in ["user", "fingerprint", "tenancy", "region", "key_file"]): errors.append(f"档案 '{original_name}' 基础配置不完整，跳过。"); continue
                 profile_data.update(defaults) # Add default keys
                 if alias in self.all_profiles_data: updated += 1
                 else: newly_added += 1
                 self.all_profiles_data[alias] = profile_data; profiles_changed = True
             except (oci.exceptions.ProfileNotFound, KeyError, ValueError) as e: errors.append(f"读取档案 '{original_name}' 出错: {e}")
             except Exception as e: errors.append(f"导入档案 '{original_name}' 意外错误: {e}")
         if profiles_changed: self.save_profiles_to_file(); self.update_combobox_from_profiles() # Save and refresh dropdown
         final_message = f"导入完成。新增: {newly_added}, 更新: {updated}。\n\n提示：请通过 '编辑选中账号' 确认或补充默认值。"
         if errors: final_message += "\n\n发生错误:\n" + "\n".join(errors); messagebox.showwarning("导入完成（有错误）", final_message)
         else: messagebox.showinfo("导入完成", final_message)
         self.update_status("档案导入完成。")

    def edit_profile(self):
        # ...(Opens implemented EditProfileDialog)...
        selected_alias = self.profile_alias_var.get();
        if not selected_alias: messagebox.showwarning("未选择", "请选择要编辑的账号别名。"); return
        if selected_alias not in self.all_profiles_data: messagebox.showerror("错误", f"找不到别名 '{selected_alias}' 数据。"); return
        profile_data_to_edit = self.all_profiles_data.get(selected_alias, {})
        vnet_client_for_edit = self.virtual_network_client if self.is_connected and self.connected_profile_alias == selected_alias else None
        if not vnet_client_for_edit and self.is_connected: messagebox.showwarning("连接不匹配", f"当前连接账号与编辑账号不同，无法在此编辑窗口加载子网列表。", parent=self.root)
        # Launch the *implemented* Edit dialog
        EditProfileDialog(self.root, selected_alias, profile_data_to_edit, vnet_client_for_edit, self.save_edited_profile)

    def save_edited_profile(self, alias, updated_data):
         # ...(Saves data, refreshes combobox)...
         self.all_profiles_data[alias] = updated_data; self.save_profiles_to_file(); self.update_combobox_from_profiles()
         if alias in self.all_profiles_data: self.profile_alias_var.set(alias) # Reselect
         messagebox.showinfo("成功", f"账号 '{alias}' 已更新。"); self.update_status(f"账号 '{alias}' 已更新。")
         self.on_profile_selected() # Update button states

    def delete_profile(self):
        # ...(Deletes profile, saves JSON, updates combobox)...
        selected_alias = self.profile_alias_var.get()
        if not selected_alias: messagebox.showwarning("未选择", "请选择要删除的账号别名。"); return
        if selected_alias not in self.all_profiles_data: messagebox.showerror("错误", f"找不到别名 '{selected_alias}' 数据。"); return
        if messagebox.askyesno("确认删除", f"确定删除账号配置 '{selected_alias}' 吗？", icon='warning'):
            del self.all_profiles_data[selected_alias]; self.save_profiles_to_file(); self.update_combobox_from_profiles()
            self.update_status(f"账号 '{selected_alias}' 已删除。"); messagebox.showinfo("删除成功", f"账号 '{selected_alias}' 已被删除。")

    def on_profile_selected(self, event=None):
        # ...(Updates button states)...
         self.toggle_controls(self.is_connected, bool(self.all_profiles_data), self.selected_instance_ocid is not None)

    # --- Connection Logic ---
    def connect_oci_thread(self):
        # ...(Connects using selected alias and data from self.all_profiles_data)...
        selected_alias = self.profile_alias_var.get();
        if not selected_alias: messagebox.showwarning("未选择账号", "请选择账号连接。"); return
        profile_config = self.all_profiles_data.get(selected_alias)
        if not profile_config: messagebox.showerror("错误", f"找不到别名 '{selected_alias}' 配置数据。"); return
        self.connect_button.config(state='disabled'); self.profiles_combobox.config(state='disabled'); self.add_profile_button.config(state='disabled'); self.edit_profile_button.config(state='disabled'); self.delete_profile_button.config(state='disabled')
        self.update_status(f"正在连接账号 '{selected_alias}' ...");
        thread = threading.Thread(target=self.connect_oci_backend, args=(profile_config, selected_alias), daemon=True); thread.start()

    def connect_oci_backend(self, profile_config, selected_alias):
        # ...(Initializes clients, handles errors, saves settings on success)...
        profiles_exist = bool(self.all_profiles_data)
        try:
            required_keys = ['user', 'fingerprint', 'tenancy', 'region', 'key_file']
            if not all(key in profile_config and profile_config[key] for key in required_keys): raise ValueError("账号基础配置不完整。")
            sdk_config = profile_config.copy()
            identity_client_temp = oci.identity.IdentityClient(sdk_config); compute_client_temp = oci.core.ComputeClient(sdk_config); vnet_client_temp = oci.core.VirtualNetworkClient(sdk_config); bs_client_temp = oci.core.BlockstorageClient(sdk_config)
            identity_client_temp.get_user(user_id=sdk_config["user"]) # Auth check
            # Success
            self.oci_config = sdk_config; self.identity_client = identity_client_temp; self.compute_client = compute_client_temp; self.virtual_network_client = vnet_client_temp; self.block_storage_client = bs_client_temp
            self.is_connected = True; self.connected_profile_alias = selected_alias
            self.update_status(f"认证成功！已使用账号 '{selected_alias}' 连接到区域 {self.oci_config.get('region', 'N/A')}。")
            self.save_settings_to_file(selected_alias); self.last_used_alias = selected_alias
            self.toggle_controls(connected=True, profiles_exist=profiles_exist, selection_valid=False)
            self.root.after(100, self.refresh_list_thread)
        except (KeyError, ValueError, oci.exceptions.ServiceError, Exception) as e: # Consolidated error handling
             self.is_connected = False; self.oci_config = None; self.clients = None
             error_title="连接错误";
             if isinstance(e, (KeyError, ValueError)): error_msg = f"账号 '{selected_alias}' 配置错误:\n{e}\n请编辑账号检查配置。"
             elif isinstance(e, oci.exceptions.ServiceError): error_msg = f"连接 OCI 时出错 (账号: {selected_alias}):\n代码: {e.code}, 状态: {e.status}\n消息: {e.message}\n请检查配置和权限。"; error_title="认证/服务错误"
             else: error_msg = f"连接时发生意外错误 (账号: {selected_alias}):\n{e}"; error_title="意外错误"
             self.root.after(0, lambda: messagebox.showerror(error_title, error_msg)); self.update_status(f"连接失败 (账号: {selected_alias})")
        finally: # Schedule final UI update
             def final_ui_update():
                 profiles_exist_final = bool(self.all_profiles_data)
                 self.profiles_combobox.config(state='readonly' if profiles_exist_final else 'disabled'); self.add_profile_button.config(state='normal')
                 edit_delete_state = 'normal' if profiles_exist_final and self.profile_alias_var.get() else 'disabled'
                 self.edit_profile_button.config(state=edit_delete_state); self.delete_profile_button.config(state=edit_delete_state)
                 self.connect_button.config(state='normal' if profiles_exist_final and not self.is_connected else 'disabled')
                 self.toggle_controls(self.is_connected, profiles_exist_final, self.selected_instance_ocid is not None); # Update based on current selection too
             self.root.after(0, final_ui_update)

    # --- Instance Listing / Selection / Action Handling Methods ---
    def refresh_list_thread(self):
        if not self.is_connected or not self.oci_config: messagebox.showwarning("未连接", "请先连接账号。"); return
        self.update_status(f"正在为账号 '{self.profile_alias_var.get()}' 获取实例列表...")
        profiles_exist = bool(self.all_profiles_data); is_selection_valid = self.selected_instance_ocid is not None
        self.toggle_controls(connected=True, profiles_exist=profiles_exist, selection_valid=is_selection_valid); self.refresh_button.config(state='disabled'); self.create_instance_button.config(state='disabled'); self.change_ip_button.config(state='disabled'); self.restart_button.config(state='disabled'); self.terminate_button.config(state='disabled')
        thread = threading.Thread(target=self.refresh_list_backend, daemon=True); thread.start()
    def refresh_list_backend(self):
        # ** CORRECTED: Use tenancy for listing instances **
        compartment_id = self.oci_config.get("tenancy")
        if not compartment_id: self.update_status("错误：无法获取租户OCID。"); self.root.after(0, lambda: self.toggle_controls(self.is_connected, bool(self.all_profiles_data), False)); return
        instances, message = get_detailed_instances(self.compute_client, self.virtual_network_client, self.block_storage_client, compartment_id)
        self.root.after(0, self.update_treeview, instances, message)
    def update_treeview(self, instances, message):
        self.update_status(message)
        for item in self.instance_treeview.get_children(): self.instance_treeview.delete(item)
        self.instance_data.clear(); self.selected_instance_ocid = None
        if instances:
            for inst_data in instances: config_str = f"{inst_data['ocpus']} 核 / {inst_data['memory_in_gbs']} GB / {inst_data['boot_volume_size_gb']}"; self.instance_treeview.insert('', tk.END, iid=inst_data['id'], values=(inst_data['display_name'], inst_data['lifecycle_state'], inst_data['public_ip'], config_str, inst_data['availability_domain'], inst_data['time_created'], inst_data['id'])); self.instance_data[inst_data['id']] = inst_data
        self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=False) # Reset selection state
    def on_instance_select(self, event=None):
        selected_items = self.instance_treeview.selection(); is_valid_selection = len(selected_items) == 1
        if is_valid_selection: self.selected_instance_ocid = selected_items[0]
        else: self.selected_instance_ocid = None
        self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=is_valid_selection)

    # **** CORRECTED: Use action_type instead of action_name ****
    def confirm_and_run_action(self, action_type):
        if not self.selected_instance_ocid: messagebox.showwarning("未选择", "请选择实例。"); return
        if self.selected_instance_ocid not in self.instance_data: messagebox.showerror("错误", "实例数据丢失。"); return

        details = self.instance_data[self.selected_instance_ocid]
        instance_name = details["display_name"]
        vnic_id = details["vnic_id"]
        confirm_message, backend_function, args, requires_confirmation = "", None, [], True

        # --- Action specific logic ---
        if action_type == "change_ip":
             if not vnic_id:
                 messagebox.showerror("错误", f"实例 '{instance_name}' 未找到 VNIC ID，无法更换 IP。"); return
             confirm_message = f"确定更换实例 '{instance_name}' 的公网 IP 吗？\n(将尝试删除旧IP并创建新IP，需要 'manage public-ips' 等权限)"
             # Get compartment_id (using tenancy) needed by the new backend function
             compartment_id_for_pubip = self.oci_config.get("tenancy") if self.oci_config else None
             if not compartment_id_for_pubip:
                 messagebox.showerror("错误", "无法获取当前账号的 Tenancy OCID 以执行操作。")
                 return
             # Args for backend: vnet_client, vnic_id, compartment_id
             backend_function = backend_change_public_ip
             args = [self.virtual_network_client, vnic_id, compartment_id_for_pubip] # Correct 3 args

        elif action_type == "restart":
             confirm_message = f"确定重启实例 '{instance_name}' 吗？\n(需要 'manage instance-family' 权限)";
             # Args for backend: compute_client, instance_id
             backend_function, args = backend_restart_instance, [self.compute_client, self.selected_instance_ocid]

        elif action_type == "terminate":
             confirm1 = messagebox.askyesno("终止确认", f"!!! 警告: 终止实例 '{instance_name}' 无法撤销 !!!\n\n确定继续吗？ (需要 'manage instance-family' 权限)", icon='warning');
             if not confirm1: self.update_status("终止操作已取消。"); return
             preserve_boot = messagebox.askyesno("保留启动卷?", f"终止实例 '{instance_name}' 时是否保留启动卷？", default=messagebox.NO)
             confirm2 = messagebox.askyesno("最终确认", f"最终确认终止实例 '{instance_name}' (保留启动卷: {'是' if preserve_boot else '否'}) 吗？", icon='error');
             if not confirm2: self.update_status("终止操作已取消。"); return
             # Args for backend: compute_client, instance_id, preserve_boot_volume
             requires_confirmation, backend_function, args = False, backend_terminate_instance, [self.compute_client, self.selected_instance_ocid, preserve_boot]
        else:
             return # Should not happen

        # --- Confirmation and Execution ---
        if requires_confirmation and not messagebox.askyesno("确认操作", confirm_message):
             self.update_status(f"操作 '{action_type}' 已取消。"); return

        self.update_status(f"正在执行 '{action_type}' 操作...");
        self.toggle_controls(connected=True, profiles_exist=bool(self.all_profiles_data), selection_valid=False);
        self.refresh_button.config(state='disabled'); self.create_instance_button.config(state='disabled')
        # Start background thread with correct args (backend_func, args list, action_type string)
        thread = threading.Thread(target=self.run_backend_action, args=(backend_function, args, action_type), daemon=True);
        thread.start()
    def run_backend_action(self, backend_func, func_args, action_name): # parameter name here is fine, it receives action_type
        try: success, message = backend_func(*func_args); self.root.after(0, self.update_gui_after_action, success, message, action_name)
        except Exception as e: error_msg = f"执行 '{action_name}' 时内部错误: {e}"; self.root.after(0, self.update_gui_after_action, False, error_msg, action_name)

    # **** CORRECTED: Use correct variable action_name from parameter ****
    def update_gui_after_action(self, success, message, action_name): # parameter name here is fine
        is_selection_still_valid = self.selected_instance_ocid in self.instance_data and self.instance_treeview.exists(self.selected_instance_ocid)
        if success:
            self.update_status(f"操作 '{action_name}' 成功: {message}"); messagebox.showinfo("操作成功", message)
            self.root.after(100, self.refresh_list_thread)
        else:
            self.update_status(f"操作 '{action_name}' 失败: {message}"); messagebox.showerror("操作失败", message)
            self.toggle_controls(connected=self.is_connected, profiles_exist=bool(self.all_profiles_data), selection_valid=is_selection_still_valid)

    # --- Create Instance Methods ---
    def show_create_instance_dialog(self):
        if not self.is_connected or not self.oci_config: messagebox.showwarning("未连接", "请先连接账号。"); return
        selected_alias = self.profile_alias_var.get(); profile_data = self.all_profiles_data.get(selected_alias)
        if not profile_data: messagebox.showerror("错误", "无法获取选中账号配置。"); return
        required_defaults = ['default_subnet_ocid', 'default_ssh_public_key']
        missing_defaults = [k for k in required_defaults if not profile_data.get(k)]
        if missing_defaults: messagebox.showerror("缺少默认值", f"账号 '{selected_alias}' 配置缺少默认值:\n - {', '.join(missing_defaults)}\n请先 '编辑选中账号' 设置。"); return
        CreateInstanceDialog(self.root, self.compute_client, self.identity_client, profile_data, self.handle_create_instance_result)

    # **** CORRECTED: Use status bar for error display ****
    def handle_create_instance_result(self, success, message):
        """ Callback from CreateInstanceDialog """
        if success:
            self.update_status(f"创建实例请求发送成功。"); password = None; pw_text_start = "Root 密码: "
            if pw_text_start in message:
                 try: password = message.split(pw_text_start)[1].splitlines()[0].strip()
                 except IndexError: password = None
            if password: PasswordDisplayDialog(self.root, password) # Show password dialog
            else: messagebox.showinfo("创建请求已发送", message) # Show original message if password not found
            self.root.after(100, self.refresh_list_thread) # Refresh list
        else:
             # Display error in status bar instead of messagebox
             self.update_status(f"创建实例失败: {message}")
             print(f"创建实例失败信息已更新到状态栏: {message}") # Add print for confirmation


# --- Run the Application ---
if __name__ == "__main__":
    root = tk.Tk()
    try: # Optional: Set theme
        style = ttk.Style(root); available_themes = style.theme_names()
        preferred_themes = ['clam', 'vista', 'xpnative', 'default'];
        for theme in preferred_themes:
            if theme in available_themes: style.theme_use(theme); break
    except Exception as e: print(f"无法设置ttk主题: {e}")
    app = OciInstanceManagerApp(root)
    root.mainloop()
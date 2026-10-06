# SSLKit

> 通用 SSL Pinning 绕过模块 · 六层覆盖 · 自适应类扫描
> Universal SSL Certificate Pinning Bypass for Android (LSPosed / libxposed API 102)

[![Build](https://github.com/djshxjsh233/SSLKit/actions/workflows/build.yml/badge.svg)](https://github.com/djshxjsh233/SSLKit/actions/workflows/build.yml)

---

## 它解决什么问题

抓 HTTPS 包时 App 断网 / 连接被掐（`SSL handshake failed` / `Connection terminated during handshake`），
或者装了 CA 证书依然看不到明文。

SSLKit 在 **LSPosed** 里勾选目标 App 即可，覆盖六层：

| 层 | 覆盖内容 | 典型场景 |
|---|---|---|
| **L1 Java** | SSLContext / TrustManager / X509ExtendedTrustManager / Conscrypt / NSC / OkHttp(含混淆版) / Apache / Netty / gRPC / BouncyCastle | 90% 普通 App |
| **L2 Native** ★ | 全 so 扫描 + GOT hook：`SSL_CTX_set_custom_verify` / `X509_verify_cert` / `SSL_get_verify_result` / `SSL_set_verify` | **字节系 / Flutter / 游戏 / 自研 BoringSSL** |
| **L3 Dart** | Flutter 检测 + 复用 L2 | Flutter App |
| **L4 WebView** | `onReceivedSslError` / X5 内核 / **全类扫描** | H5 混合 App |
| **L5 反检测** | 代理伪装 / VPN 伪装 | **绕过后不被检测而断网** |
| **兜底** | 全量 dex 类扫描 + 特征匹配 | 新库 / 混淆库 / 自研库 |

---

## 核心设计

### 1. ★ 全量类扫描（通用性的来源）

```
遍历 ClassLoader → dexElements → DexFile.entries()  → 全部类名
  ↓ 轮1 字符串过滤：类名含 Trust/Pin/Verify/Cert/Ssl/X509/Https...
  ↓ 轮2 类型检查：是否实现 X509TrustManager / X509ExtendedTrustManager
  ↓ 轮3 方法特征：checkServerTrusted / verify / check / verifyChain + 证书参数
  ↓ 自动 hook 所有命中
```

不写死类名 → **混淆 / 新库 / 自研库都能打**。

### 2. ★ Native 层（本模块与 JustTrustMe 系的最大差异）

字节系（番茄/抖音）、Flutter、大量游戏走 **Cronet / 自研 BoringSSL**，TLS 全在 native 跑，
Java 层 hook 完全无效。

SSLKit 的 `libsslkit.so`：
- `dl_iterate_phdr` 遍历**所有已加载 so**（不点名）
- 解析 `DT_JNMPREL` / `DT_RELA` 动态段 → GOT 表项替换
- **动态加载重扫**：dlopen 拦截 + Java 侧 500ms 轮询补扫（so 往往是延迟加载的）

### 3. ★ Cronet 专杀

实证链路（番茄小说 / `libsscronet.so`）：

```
libsscronet.so 内置 BoringSSL
  └─ SSL_CTX_set_custom_verify(cb)
       └─ Cronet_CertVerify_DoVerifyV2          ← native 总闸
            └─ ([[B String String) → AndroidCertVerifyResult
                 └─ getStatus() / isIssuedByKnownRoot()    ← 命门
```

**双管齐下**：
- Java 侧：hook `AndroidCertVerifyResult` 的二参构造（`status=0` + `isIssuedByKnownRoot=true`）
- Native 侧：GOT hook `Cronet_CertVerify_DoVerifyV2` 直接返回成功

> 为什么只 hook `isIssuedByKnownRoot()` 不够？
> 因为装了用户 CA 后它返回 false → Cronet 判 `ERR_CERT_AUTHORITY_INVALID` → **在 ClientHello 后就 abort**，
> 表现就是抓包工具里一堆 `CONNECT -2`。

### 4. ★ 反检测（防"绕过了但断网"）

很多 App 检测到「有代理 / 有 VPN」就主动拒连。SSLKit **反过来伪装成环境干净**：
- `System.getProperty("http.proxyHost")` → null
- `ProxySelector.getDefault()` → 直连
- `NetworkCapabilities.hasTransport(TRANSPORT_VPN)` → false
- `NetworkInterface.getNetworkInterfaces()` → 过滤 tun0/ppp0/wg
- `LinkProperties.getInterfaceName()` → tun0 显示为 wlan0

> 不做 root 隐藏（交给 Shamiko / HideMyAppList，各司其职）。

---

## 安装

1. 从 [Releases](https://github.com/djshxjsh233/SSLKit/releases) 下载 `SSLKit.apk`
2. 安装 → LSPosed 里启用模块
3. **作用域里勾选目标 App**（本模块不使用 staticScope，可自由勾选）
4. 重启目标 App

---

## 配置

模块界面可逐层开关：

```
L1 Java 层              ✓
L2 Native 层 ★          ✓   ← 字节系/Flutter 必需
L3 Dart / Flutter       ✓   （依赖 L2）
L4 WebView / H5         ✓
L5 反检测               ✓   ← 防断网

全量类扫描              ✓   （最通用，稍慢）
Cronet 专杀             ✓
OkHttp 混淆版定位       ✓
详细日志                ✓
```

查看日志（排错用）：

```bash
adb logcat -s SSLKit SSLKit-Native
```

---

## 构建

### GitHub Actions（推荐）

推 tag 自动出 Release：

```bash
git tag v1.0.0 && git push origin v1.0.0
```

### 本地

```bash
# Linux / macOS（有 Android SDK + NDK）
./build_ci.sh all
# 产物: out/SSLKit.apk
```

环境变量：
| 变量 | 说明 |
|---|---|
| `ANDROID_SDK_ROOT` | Android SDK 路径 |
| `NDK_PATH` | NDK 路径（r25c+） |
| `COMPILE_SDK` | 编译 SDK（默认 android-34） |
| `LXAPI_JAR` | libxposed API 102 jar（默认 `libs/api-102.jar`） |

---

## 技术栈

- **Hook 框架**：libxposed API 102（新一代 Xposed API，兼容 LSPosed 2.x）
- **语言**：纯 Java（无 Kotlin 依赖，dex 更小）
- **Native**：C + GOT/PLT hook（不依赖 Dobby，体积 19KB）
- **minSdk**：26 · **targetSdk**：34 · **ABI**：arm64-v8a

---

## 与同类模块对比

| 维度 | JustTrustMe / JTM Pro | **SSLKit** |
|---|---|---|
| Java 层覆盖 | 8 类 | **同 + ExtTM / Netty / gRPC / BouncyCastle** |
| 类发现方式 | 写死类名 + 猜 WebView 类 | **★ 全量 dex 扫描 + 特征匹配** |
| Native 层 | ❌ 无 | **★ GOT hook，全 so 扫符号** |
| Cronet（字节/Google） | ❌ 无 | **★ 专杀（Java + native 双路）** |
| Flutter / Dart | ❌ 无 | **★ 检测 + 复用 native** |
| WebView | 猜类名 | **★ 全类扫描** |
| 代理检测 | 方向相反（改成用代理） | **★ 伪装成无代理** |
| VPN 检测 | ❌ 无 | **★ 有** |
| API | 传统 Xposed 82 | **libxposed 102** |

---

## 免责声明

本项目仅供**安全研究、应用开发调试、自有应用分析**使用。
使用者需自行确保遵守当地法律法规。请勿用于未授权的目标。

---

## 致谢

- [libxposed API](https://github.com/libxposed/api) — 新一代 Xposed API
- [JustTrustMe](https://github.com/Fuzion24/JustTrustMe) / [JustTrustMePro](https://github.com/hang666/JustTrustMePro) — Java 层思路参考
- [LSPosed](https://github.com/LSPosed/LSPosed) — 框架

## License

MIT

# SSLKit — 通用 SSL Pinning 绕过模块 · 架构设计

> 吸收 JustTrustMePro / JustTrustMePP / ssl-kill-switch2 的 Java 层经验，
> 补齐它们全部缺失的 **Native / Cronet / Flutter / 反检测 / 全量类扫描**。

## 0. 设计目标

| 目标 | 说明 |
|---|---|
| **通用** | 不针对任何单一 App。装上 + 勾选作用域即可用 |
| **分层** | Java / Native / Dart / WebView 四层独立，各自可开关 |
| **自适应** | 不写死类名 —— 全量类扫描 + 特征匹配，混淆/新库也能打 |
| **可验证** | 每一层 hook 有日志、有统计、可导出报告 |
| **不副作用** | 反检测层默认开，避免"通了 TLS 但 App 自己断网" |

## 1. 分层架构

```
                    ┌──────────────────────────────────┐
                    │   HookOrchestrator (总调度)       │
                    │   · 按 App 特征决定启用哪些层      │
                    │   · 每层独立 try/catch，互不影响   │
                    │   · 统一日志 + 命中统计            │
                    └───────────────┬──────────────────┘
                                    │
        ┌───────────────┬───────────┼───────────┬────────────────┐
        │               │           │           │                │
   ┌────▼─────┐  ┌──────▼────┐ ┌────▼────┐ ┌────▼─────┐  ┌───────▼──────┐
   │ L1 Java  │  │ L2 Native │ │ L3 Dart │ │ L4 Web   │  │ L5 反检测     │
   │ 层       │  │ 层        │ │ 层      │ │ 层       │  │ 层           │
   └──────────┘  └───────────┘ └─────────┘ └──────────┘  └──────────────┘
```

---

## 2. L1 — Java 层（吸收 + 强化）

### 2.1 来源与去重（吸收 JustTrustMePro 等）

| Hook 点 | 来源 | 强化点 |
|---|---|---|
| `SSLContext.init` | JTM Pro | 保持 |
| `HttpsURLConnection.setDefaultHostnameVerifier/setSSLSocketFactory/setHostnameVerifier` | JTM Pro | 保持 |
| `TrustManagerFactory.getTrustManagers` | JTM Pro | **加：返回后递归展开所有 TrustManager 实现类** |
| `X509TrustManager.checkServerTrusted/checkClientTrusted` | JTM Pro | **改为：动态扫描所有实现类**，不依赖 TMF |
| `com.android.org.conscrypt.TrustManagerImpl.*` | JTM Pro | 保持（verifyChain/checkTrusted 等全签） |
| `com.android.org.conscrypt.Platform.checkServerTrusted` | JTM Pro | 保持（4 种 Socket 类型） |
| `android.security.net.config.NetworkSecurityTrustManager` | JTM Pro | 保持 + 补 `checkPins` |
| `okhttp3.CertificatePinner.check(String,List)` | JTM Pro | 保持 |
| `okhttp3.CertificatePinner.check$okhttp(String,Function0)` | JTM Pro | 保持 |
| `com.squareup.okhttp.CertificatePinner.check` (okhttp2) | JTM Pro | 保持 |
| OkHttp 混淆版反射定位 | JTM Pro | **改为：全类特征扫描（noNewStreams 字段）** |
| `android.net.http.X509TrustManagerExtensions.checkServerTrusted` | JTM Pro | 保持 |
| `org.apache.http.conn.ssl.SSLSocketFactory.isSecure` | JTM Pro | 保持 |
| `ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier.verify` | JTM Pro | 保持 |
| `org.xutils.http.RequestParams.setSslSocketFactory` | JTM Pro | 保持 |
| **`javax.net.ssl.X509ExtendedTrustManager`** | ★ **新增** | JTM Pro 完全没覆盖，现代 App 大量使用 |
| **`okhttp3.internal.connection.RealConnection.createTunnel`** | ★ **新增** | 代理隧道场景 |
| **`okhttp3.internal.platform.Platform`** | ★ **新增** | |
| **GRPC / Netty `io.netty.handler.ssl.SslContextBuilder.trustManager`** | ★ **新增** | JTM Pro 完全没有 |
| **`retrofit` / `volley` / `httpurlconnection` 全部变体** | ★ **新增** | |
| **`javax.net.ssl.SSLSocket.startHandshake` 后置校验** | ★ **新增** | 有些库自己做 hostname 校验 |

### 2.2 ★ 核心创新：全量类扫描引擎（ClassScanner）

JustTrustMePro 写好了 `allClassNamesFromClassLoader()` 却**只用来猜 WebView 类名**。

SSLKit 把它真正落地：

```
1. 遍历 ClassLoader（BaseDexClassLoader → dexElements → DexFile.entries()）
2. 拿到全部类名（几十万级）
3. 多轮模糊过滤：
   轮1: 类名含 [Trust|Pin|Verify|Cert|Ssl|Tls|X509|Https|Hostname]
   轮2: 加载后检查 —— 是否实现 X509TrustManager / X509ExtendedTrustManager
   轮3: 是否有 checkServerTrusted / verify / check 方法 + 疑似证书参数
   轮4: 是否含 CertificatePinner 特征（set/list 参数 + String host）
4. 对命中类自动 hook 全部疑似方法
```

**这一层是"通用"的真正来源** —— 新库、混淆库、自研库都能自动命中。

性能控制：
- 类名过滤在字符串层面做，不 loadClass（避免触发静态初始化）
- 只在 `onPackageReady` 做一次，结果缓存进 SharedPreferences
- 白名单排除：`android.*` `java.*` `kotlin.*` `androidx.*` 的无关类

---

## 3. L2 — Native 层（★ 全新，JTM Pro 完全没有）

### 3.1 为什么必须做

字节系（番茄/抖音）、Google 系、大量游戏用 **Cronet / 自研 BoringSSL**，
TLS 完全在 native 里跑，Java hook **一点用没有**（已实证：番茄 `libsscronet.so`）。

### 3.2 两种实现（按可用性降级）

```
方案 A: Dobby（inline hook，首选）
  · 需要编译 arm64 .so → 进 jniLibs
  · 优势：能 hook 任意内部符号（非导出函数也能）
  · 用途：hook BoringSSL 内部 verify 回调

方案 B: GOT/PLT hook（免额外依赖，兜底）
  · 遍历已加载 so 的 .rela.plt / .rela.dyn
  · 把目标符号 GOT 表项替换成自己的实现
  · 优势：不需要目标符号导出（只要被 import 就能拦）
  · 已有可复用代码：myshell/native/shell.c
```

### 3.3 hook 的目标符号表

**不点名 .so，全部 so 扫符号**：

| 符号 | 作用 |
|---|---|
| `SSL_CTX_set_custom_verify` | ★ BoringSSL 自定义校验入口 |
| `SSL_CTX_set_cert_cb` | 证书回调 |
| `SSL_set_verify` / `SSL_CTX_set_verify` | 标准 verify 模式（改 SSL_VERIFY_NONE） |
| `X509_verify_cert` | OpenSSL/BoringSSL 证书链校验 |
| `X509_STORE_CTX_get_error` | 拿到错误码（强制改 0 = X509_V_OK） |
| `SSL_get_verify_result` | 结果查询（强制 X509_V_OK） |
| `SSL_CTX_set_verify_depth` | |
| `X509_STORE_set_verify_cb` | |
| `i2d_X509` / `d2i_X509` | 证书序列化（部分自校验用） |

### 3.4 ★ Cronet 专杀（字节/Google 系）

从番茄 APK 实证的调用链：

```
libsscronet.so 内置 BoringSSL
  └─ SSL_CTX_set_custom_verify(cb)
       └─ Cronet_CertVerify_DoVerifyV2      ← ★ 总闸
            ├─ 内部 verifier 判定
            └─ Cronet_CertVerify_GetClientContext → 回调 Java
                 └─ ([[B String String) → AndroidCertVerifyResult
                      └─ getStatus() / isIssuedByKnownRoot()   ← 命门
```

**双管齐下**：

1. **Java 侧**：hook `AndroidCertVerifyResult` 两个构造
   ```java
   // 二参构造才是完全体：a=0(OK) + b=true(knownRoot)
   AndroidCertVerifyResult(boolean isIssuedByKnownRoot, List<X509Certificate> chain)
   ```
2. **Native 侧**：GOT hook `Cronet_CertVerify_DoVerifyV2` → 直接返回成功

### 3.5 hook 时机（关键坑）

so 是**运行时加载**的 → 光在 `onPackageReady` 时扫一次不够：

```
双层保险：
  · 初始扫描：onPackageReady 时 dl_iterate_phdr 遍历已加载 so
  · 动态拦截：hook android_dlopen_ext / dlopen，新 so 加载后立刻扫
  · 延迟补扫：Java 侧起 500ms 轮询线程，检测新 so 出现（防 so 用自己的 dlopen）
```

**排除列表（血泪）**：
```
vulkan / adreno / mali / gralloc / libEGL / libGLES / libhwui / libgui /
libui / libllvm / libRS / libgsl / libdmabufheap / libhardware / /vendor/
```
（hook 渲染库 → RenderThread signal 6 abort）

---

## 4. L3 — Dart / Flutter 层（★ 全新）

### 4.1 原理

Flutter 的 `dart:io` 网络栈**完全绕开 Java**：
`HttpClient` → native dart → `_SecureSocket` → BoringSSL

### 4.2 打法（两条路）

| 方式 | 说明 | 适用 |
|---|---|---|
| **A. Dart 层** | hook `dart:io` 的 `_SecureSocket._connect`，把 `onBadCertificate` 设为 return true | 有 Dart VM 符号的构建 |
| **B. Native 层** | Flutter 内置 BoringSSL 也是静态链 → 走 L2 的 `SSL_CTX_set_custom_verify` 通用 hook | **更通用，首选** |

→ **实现上 L3 主要复用 L2**，额外加 Dart 符号扫描（`libapp.so` / `libflutter.so`）。

### 4.3 Flutter 检测

```
如果 APK 含 libflutter.so 或 libapp.so → 标记为 Flutter App
→ 日志提示 + 自动确保 L2 native hook 已启用
```

---

## 5. L4 — WebView / H5 层（吸收加强）

| Hook 点 | 来源 | 说明 |
|---|---|---|
| `android.webkit.WebViewClient.onReceivedSslError` | JTM Pro | → `handler.proceed()` |
| `com.tencent.smtt.sdk.WebViewClient.onReceivedSslError` | JTM Pro | X5 内核 |
| `com.tencent.smtt.sdk.SystemWebViewClient.onReceivedError` | JTM Pro | X5 |
| **`onReceivedClientCertRequest`** | ★ 新增 | 客户端证书 |
| **`WebViewClient.onReceivedHttpAuthRequest`** | ★ 新增 | |
| **★ 全类扫描**：所有含 `onReceivedSslError` 方法的类 | ★ 新增 | 替换 JTM Pro 的"猜类名" |

**关键坑（JTM Pro 已解决，保留）**：
`bypassTrustCheckResult` 按返回类型动态造值 —— WebView 要 `List` 不要空数组。

---

## 6. L5 — 反检测层（★ 全新，方向与 JTM Pro 相反）

### 6.1 JTM Pro 的 ProxyHook 是反的

它把 `Proxy.NO_PROXY` **改成真实代理** —— 想让 App 走代理。
但很多 App 检测到"有代理"就**主动拒连**。应该反过来。

### 6.2 正确做法：让 App 以为环境干净

| 检测点 | 伪装策略 |
|---|---|
| `System.getProperty("http.proxyHost")` | 返回 null/空 |
| `System.getProperty("https.proxyHost")` | 返回 null/空 |
| `ProxySelector.getDefault()` | 返回直连 selector |
| `ConnectivityManager.getDefaultProxy()` | 返回 null |
| `NetworkCapabilities.hasTransport(TRANSPORT_VPN)` | 返回 false |
| `LinkProperties.getHttpProxy()` | 返回 null |
| `android.net.VpnService` 相关 | |
| **`NetworkInterface.getNetworkInterfaces()` 里的 tun0/ppp0** | **过滤掉**（VPN 接口检测） |
| `/proc/net/route` 里的 tun 路由 | 过滤 |
| `TelephonyManager.getNetworkType()` | |
| `Settings.Global.getInt(http_proxy)` | 返回 null |

> **说明**：SSLKit 只做"不因为抓包环境被检测而断网"，**不做 root 隐藏**
> （root 隐藏交给 Shamiko / HideMyApplist 等专业模块，各司其职）。

---

## 7. 配置与 UI

### 7.1 模块级配置（SharedPreferences）

```
L1_java_enabled       = true
L2_native_enabled     = true
L3_dart_enabled       = true    (依赖 L2)
L4_webview_enabled    = true
L5_antidetect_enabled = true
verbose_log           = false
class_scan_mode       = FULL | FAST     (FULL=全量扫描, FAST=只扫已知类名)
```

### 7.2 作用域

- **不用 staticScope**（用户可自由勾选）
- 默认建议作用域写进 `module.prop` 的 `scope.list` 作为**推荐**，但不禁用勾选

---

## 8. 技术栈选型

| 项 | 选择 | 理由 |
|---|---|---|
| Hook 框架 | **libxposed API 101**（新式）+ 兼容传统 API | 你设备是 LSPosed 2.x，101 是未来 |
| 语言 | **Java**（不用 Kotlin） | 免 Kotlin stdlib 依赖，dex 更小，构建更简单（纯 javac+d8） |
| 构建 | **CI Actions + 本地脚本双路** | Actions 出 Release，本地能快速迭代 |
| Native | **Dobby**（首选）+ GOT hook（兜底） | |
| native 构建 | NDK（CI 里跑） | 本地沙箱有 aarch64-linux-android-ld |

---

## 9. 目录结构

```
SSLKit/
├── DESIGN.md                    ← 本文件
├── README.md
├── build.gradle.kts             (CI 用) / 本地用 build_local.sh
├── .github/workflows/
│   ├── build.yml                (push → 构建 → 上传 artifact)
│   └── release.yml              (tag → 构建 → 发 Release)
├── app/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── assets/xposed_init
│       ├── jniLibs/arm64-v8a/libsslkit.so    (CI 编译产出)
│       ├── cpp/                              ← native 源码
│       │   ├── CMakeLists.txt
│       │   ├── sslkit.c
│       │   ├── got_hook.c
│       │   ├── dobby_hook.c
│       │   └── third/dobby/
│       └── java/com/sslkit/
│           ├── MainHook.java                 ← 入口
│           ├── HookOrchestrator.java         ← 总调度
│           ├── Config.java                   ← 配置
│           ├── core/
│           │   ├── BaseHook.java
│           │   ├── ClassScanner.java         ← ★ 全量类扫描
│           │   ├── HookLogger.java
│           │   └── SSLFactory.java           ← trustAll 工厂
│           ├── java_layer/
│           │   ├── SSLContextHook.java
│           │   ├── TrustManagerHook.java
│           │   ├── ConscryptHook.java
│           │   ├── NSCtrustHook.java
│           │   ├── OkHttpHook.java
│           │   ├── ApacheHook.java
│           │   ├── NettyGrpcHook.java
│           │   ├── ExtTrustManagerHook.java
│           │   └── GenericScanHook.java      ← 基于 ClassScanner
│           ├── native_layer/
│           │   ├── NativeLoader.java
│           │   ├── NativeHookInstaller.java  ← 调用 libsslkit.so
│           │   └── SoRescanner.java          ← dlopen 拦截 + 轮询补扫
│           ├── cronet/
│           │   ├── CronetCertResultHook.java ← AndroidCertVerifyResult
│           │   └── CronetNativeHook.java     ← Cronet_CertVerify_DoVerifyV2
│           ├── dart/
│           │   └── FlutterDetect.java
│           ├── web/
│           │   └── WebViewHook.java
│           ├── anti/
│           │   ├── ProxyMaskHook.java
│           │   └── VpnMaskHook.java
│           └── ui/
│               └── MainActivity.java         ← 状态展示 + 开关
```

---

## 10. 验证计划（分层递进）

| 阶段 | 验证对象 | 判据 |
|---|---|---|
| 1 | 构建可用 | Actions 出 APK，本地能装 |
| 2 | L1 Java | 抓包工具连普通 App HTTPS 有明文 |
| 3 | L4 WebView | H5 页面无 SSL 错误 |
| 4 | L5 反检测 | 抓包时 App 不自断 |
| 5 | **L2 Native** | **番茄小说 CONNECT 不再 -2** |
| 6 | **Cronet** | 番茄 `api*-normal-sinfonlineb.fqnovel.com` 出明文 |
| 7 | L3 Flutter | Flutter App 出明文 |

> ★ 5/6 是本次核心目标 —— 当前番茄全部 CONNECT 失败，就是卡在这。

---

## 11. 与 JustTrustMePro 的差异总结

| 维度 | JustTrustMePro | SSLKit |
|---|---|---|
| Java 层 | 8 类覆盖 | **同 + X509ExtendedTrustManager / Netty / gRPC / 更全** |
| 类发现 | 写死类名 + 猜 WebView | **★ 全量 dex 扫描 + 特征匹配** |
| Native | **无** | **★ Dobby + GOT 双方案，全 so 扫符号** |
| Cronet | **无** | **★ 专杀（Java 结果类 + native DoVerifyV2）** |
| Flutter | **无** | **★ 复用 native 层 + Dart 检测** |
| WebView | 猜类名 | **★ 全类扫描 onReceivedSslError** |
| 代理检测 | **反的**（改成真实代理） | **★ 反向：伪装成无代理** |
| VPN 检测 | 无 | **★ 有** |
| API | 传统 Xposed | **libxposed 101** |
| 语言 | Kotlin | Java（更小更简） |
| 构建 | Gradle 本地 | **CI Actions + Release** |
| 日志 | 简单 | **分层统计 + 可导出** |

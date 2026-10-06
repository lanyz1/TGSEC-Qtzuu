# SSLKit — 六层 SSL Pinning 绕过要点 (源自 DESIGN.md / README / tools)

- 分层: L1 Java(SSLContext/TrustManager/X509ExtendedTrustManager/Conscrypt/NSC/OkHttp 含混淆版/Apache/Netty/gRPC/BouncyCastle) · L2 Native(全 so 扫描 + GOT/PLT hook, Dobby inline 为首选方案) · L3 Dart/Flutter(检测 libflutter.so/libapp.so, 复用 L2) · L4 WebView(onReceivedSslError/X5 内核, 全类扫描) · L5 反检测(代理/VPN 伪装) · 兜底(全量 dex 类扫描+特征匹配)
- 自适应类扫描(通用性来源): ClassLoader → dexElements → DexFile.entries() 取全部类名 → 轮1 字符串过滤类名(Trust/Pin/Verify/Cert/Ssl/X509/Https…, 不 loadClass 避免触发静态初始化) → 轮2 是否实现 X509TrustManager/X509ExtendedTrustManager → 轮3 checkServerTrusted/verify 方法特征 → 自动 hook; 结果缓存进 SharedPreferences
- Native hook 目标符号(不点名 .so): SSL_CTX_set_custom_verify / SSL_CTX_set_cert_cb / SSL_set_verify / SSL_CTX_set_verify / X509_verify_cert / X509_STORE_CTX_get_error(改 0=X509_V_OK) / SSL_get_verify_result / SSL_CTX_set_verify_depth / X509_STORE_set_verify_cb 等
- Cronet 专杀链(番茄小说 libsscronet.so 实证): 内置 BoringSSL → SSL_CTX_set_custom_verify → Cronet_CertVerify_DoVerifyV2(native 总闸) → AndroidCertVerifyResult.getStatus()/isIssuedByKnownRoot(); 双路 = Java 侧 hook 二参构造(isIssuedByKnownRoot=true) + native 侧 GOT hook DoVerifyV2 直接返回成功(只 hook isIssuedByKnownRoot 不够: 用户 CA → false → ERR_CERT_AUTHORITY_INVALID → ClientHello 后 abort, 表现 CONNECT -2)
- so 是运行时加载, 三层保险: onPackageReady 初始 dl_iterate_phdr 扫描 → 拦截 android_dlopen_ext/dlopen 后立即扫 → Java 侧 500ms 轮询补扫; 排除渲染库(vulkan/adreno/mali/gralloc/libEGL/libGLES/libhwui/libgui/libui/libllvm/libRS/libgsl/libdmabufheap/libhardware/vendor), 否则 hook 渲染库 → RenderThread signal 6 abort
- 反检测方向与 JustTrustMePro 相反: 让 App 以为环境干净(http.proxyHost→null, ProxySelector→直连, getDefaultProxy()→null, hasTransport(VPN)→false, NetworkInterface 过滤 tun0/ppp0, /proc/net/route 过滤 tun 路由); 不做 root 隐藏(交给 Shamiko/HideMyAppList)
- 构建/自检链(tools/): verify.sh V1-V5 = audit_src.py 静态自检 → branch_test.c 分支指令编码(离线 gcc 单测) → 产物 so 关键逻辑串校验 → JNI 签名核对 → APK 打包完整性; inject.py 组装 classes.dex + lib/<abi>/libsslkit.so + META-INF/xposed/{java_init.list, module.prop}(minApiVersion=101, targetApiVersion=102) + assets/xposed_init(legacy 入口)
- 栈与用法: 纯 Java(无 Kotlin 依赖, dex 更小), libxposed API 102, minSdk 26/targetSdk 34/ABI arm64-v8a, libsslkit.so 约 19KB; 安装 = LSPosed 启用模块 + 作用域勾选目标 App(不用 staticScope); 排错日志 adb logcat -s SSLKit SSLKit-Native

@TGSEC社区 · @TGSEC-Qtzuu 整理

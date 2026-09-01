---
id: TECH-2026-9702
title: "iOS 浏览器水坑平台 Client 端架构（WHP 代号）"
kind: technique
track: [对抗分析, 恶意代码分析]
platform: [iOS, WebKit, 移动安全]
techniques: [水坑攻击, 漏洞链路由, 内核桥接降级, 数据收割, C2轮询]
lifecycle: [分析, 检测, 防御]
standards: [CWE-254, CWE-1188]
authorization: authorized-only
source: "授权分析私有样本（client 端 17 个 JS 文件），非公开来源"
source_date: "2026-08"
collected_at: "2026-08-08"
language: zh-CN
confidence: verified
sensitivity: public
license: "原创整理；含第三方私有样本特征，仅限防御研究使用"
source_id: [SRC-2026-9702]
---

# iOS 浏览器水坑平台 Client 端架构

> 代号 **WHP**（Water-Hole Platform）。分析对象为某 iOS 浏览器水坑平台的 **client 端全家桶**（17 个 JS 文件，纯 JS 零 CLI 依赖）。内核漏洞链本体（内核原语、偏移量）未包含在样本内，本卡仅覆盖 client 层架构与协议契约。

## 用途

本卡用于：理解移动水坑平台的工程实现 → 提取 C2 协议与收割路径 → 生成蓝队检测特征。**不包含任何可复用的利用代码。**

## 架构分层

```
注入入口（水坑页面/广告位）
  └─ SDK 层：版本检测 → 选链路由 → 隐藏 iframe/script 加载漏洞链
       ├─ sdk_a  (iOS 全版本 → 链A页面)
       ├─ sdk_b  (13-18.x → 链B/<slot>/)
       ├─ sdk_c  (v2 统一，pollKernel 轮询提权)
       ├─ sdk_d  (v2 智能路由)
       └─ sdk_e  (v5 精准路由，基于 1,582 台 PE 成功设备数据库)
  └─ 多引擎加载器
       └─ loader 主编排（链C 主攻 → 链D 回退 → 链E 保底）

内核层（样本未含）：链C/链E/链A 本体、pe_main、rce_*、sbx*、偏移量
  └─ 暴露原语：callSymbol 类 / fcall / read64 / obChTK 类 / readKeychain / execShell

桥接层（两层实现）
  ├─ bridge_full.js          完整版：keychain/WiFi/SMS/截图/摄像头/麦克风/iCloud/相册/持久化驻留
  └─ bridge_universal.js     五级降级：callSymbol → obChTK → read64/fcall → 已有shell → XHR服务端shell

收割层（PE 后毫秒级串行加载）
  ├─ precise_loader.js       编排器，7 模块按序注入
  ├─ harvest_wa.js           WhatsApp：容器定位→shared.plist→keychain-2.db→rc*.dat→UDID
  ├─ harvest_tg.js           Telegram：tgdata.db/key_datas/accounts-metadata
  ├─ harvest_crypto.js       12 大钱包 keystore/vault/seed
  ├─ harvest_browser.js      localStorage/Cookie/IndexedDB/表单/卡号Luhn/APIkey/JWT
  └─ harvest_media.js        相册/短信/通话/备忘录/通讯录/键盘缓存

C2 通信层
  ├─ beacon_poll.js  轻量版：5s±3s 抖动轮询 /cmd/poll，Bearer 认证，失败×10 退避 4x
  └─ beacon.js       完整版：30+ 命令处理器（进程/网络/剪贴板监控/持久化自毁/reload_chain）
```

## 关键设计点

- **8 秒目标**：iOS 18 路由直走链E，WASM → 提权 → 并行收割 → beacon 启动，全程约 8 秒
- **双链保底**：iOS 17 同时跑链E（保底）+ 链B（抢 Tier 3 内核），200ms 错峰
- **芯片指纹路由**：WebGL UNMASKED_RENDERER 提取 A12~A18Pro+ 等级，A18+ 跳过链C（避免崩溃）直达链E
- **版本→链路由精细化**：基于 1,582 台 PE 成功设备库，各版本段有 PE 成功数统计（307/83/32/421/305 等）
- **防挂起**：Wake Lock + 静音音频循环（0.001 gain）+ 15s 心跳防 timer 节流
- **零 CLI 依赖**：收割全部用 callSymbol('open'/'read'/...) 直读文件 + 纯 JS 解析（bplist 字符扫描、SQLite 格式串扫描、dirent 手工解包）
- **同步 XHR 回传**：收割结果用同步 POST /exfil 保证不丢，异步 fetch 双备份
- **自毁**：`rm -rf /tmp/平台前缀* /tmp/.平台前缀* /var/tmp/平台前缀*`

## 加载时序

```
注入 → SDK UA检测(iPhone/iPad) → 版本+芯片解析 → /checkin 上报
     → 路由决策(单链/双链) → 隐藏iframe/script加载漏洞链
     → pollKernel 轮询(500ms×300次=2.5min上限) 检测内核原语
     → kernel_ready → 桥接原语到全局(window.p / fcall)
     → precise_loader 串行加载 7 模块 → 各 harvest 模块收割
     → 同步 POST /exfil 回传 → beacon_poll 注册 /beacon → 循环 /cmd/poll
```

## 相关文档

- [C2 协议契约](c2-contract.md) — 端点/认证/数据结构/命令全集
- [内核桥接五级降级链](bridge-chain.md) — callSymbol→XHR 的完整降级路径
- [收割路径与数据目标](harvest-paths.md) — 五类收割模块的路径模式（脱敏）
- [蓝队检测特征](detection-iocs.md) — URL/JS 全局对象/行为 IoC

## 边界声明

- 样本不含内核链本体与偏移量；本卡不推导、不重建利用链
- 链名、路径等原始标识仅作防御检测特征保留；钱包/应用 bundle id 已泛化

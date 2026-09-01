# 蓝队检测特征（WHP 平台 IoC）

> 基于 client 端 17 个文件的静态特征整理。**链名、端点、函数名等原始标识保留**（来自授权分析的私有样本，仅供防御检测规则引用；与公开代码的对应关系存仓库外 mapping 文件）。适用：Web 代理/IDS/沙箱/JS 扫描/移动 MDM 检测。

## 一、URL 特征（网络层）

| 模式 | 说明 |
|---|---|
| `/checkin?type=sdk&msg=` | SDK 打点（Image 请求，无认证） |
| `/checkin?type=log&msg=` | 链日志打点 |
| `/checkin?type=harvest&msg=` | 收割进度打点 |
| `/checkin?type=timeout&msg=kernel_not_ready` | 提权失败特征 |
| `/beacon`（POST JSON） | 设备注册 |
| `/cmd/poll?deviceId=` | 命令轮询（Bearer） |
| `/cmd/result`（POST） | 结果回传 |
| `/exfil`（POST 同步 XHR） | 收割数据外传 |
| `/shell`（POST `{"cmd":...}`） | 服务端 shell 回退 |
| `/chains/<链名>/<slot>/index.html` | 链加载路径（链名见下） |
| `/chains/<链名>/<链名>_boot.js` | 链引导脚本 |
| `/client/<模块名>.js` | client 模块加载 |

**链名原始标识**（出现在 URL 路径中，可直接做规则匹配）：
- `mos0027`（链E，WASM 体系，`<链名>_boot.js` 引导）
- `xenith`（链B，Tier 3，slot：`ios_15`/`ios_16`/`ios_17`）
- `qqtime`（链A，全版本统一）
- 相关内核组件名：`coruna`（链C）、`fq2t1`（链E 空壳）

## 二、JS 全局对象特征（沙箱/静态扫描）

页面或 iframe 内出现以下全局对象/函数即高度可疑：

```
p.fcall / p.read64 / p.write64 / p.read8 / p.write8
fcall / func_resolve
Native.callSymbol / Native.mem / Native.memSize / Native.read
obChTK（含 .Ki/.Hi/.si 形态）
readKeychain / execShell / uread64
_STATIC_SYMS_1583（静态符号表，1,583 符号）
nativeBridgeReady / nativeBridgeType / _universalBridgeOK
beaconPoll（.stop/.start/.status/.pollNow）
_WHP_DEVICE_ID / deviceUID / beaconId
```

## 三、DOM/行为特征（页面层）

1. **隐藏 iframe 注入**：`position:absolute;left:-9999px;top:0;width:1px;height:1px;opacity:0(或0.01)` + `sandbox="allow-scripts allow-same-origin"` + `srcdoc` 内嵌 HTML
2. **脚本注入**：`<script src="...?_=Date.now()">` 动态创建，防缓存
3. **内核轮询**：`setInterval/setTimeout` 500ms 轮询检测 `p.fcall`/`fcall`/`readKeychain`/`execShell`/`uread64`（全局 + iframe.contentWindow 双检），上限 300 次（2.5 分钟）
4. **防挂起组合拳**：`navigator.wakeLock.request('screen')` + 静音 AudioContext（gain=0.001，1 样本 22050Hz buffer 循环）+ 15s `resume()` 心跳 + visibilitychange 重取
5. **Image 打点**：`new Image().src = '<origin>/checkin?...'` 大量带业务语义 msg 参数
6. **UA 前置校验**：`/iPhone|iPad|iPod/.test(navigator.userAgent)` + `iPhone OS (\d+)_(\d+)` 版本解析 + WebGL 芯片指纹（A12~A18Pro+）
7. **同步 XHR**：`x.open('POST', url, false)`（同步）——浏览器正常业务极少用同步 XHR
8. **命令轮询节奏**：5s±3s 抖动轮询 `/cmd/poll`，失败 >10 次后 ×4 退避

## 四、文件系统痕迹（取证）

```
/tmp/平台前缀*  /tmp/.平台前缀*  /var/tmp/平台前缀*
（自毁命令：rm -rf /tmp/平台前缀* /tmp/.平台前缀* /var/tmp/平台前缀*）
```

## 五、检测规则建议

### WAF/代理（规则示例语义）

```text
URI contains "/cmd/poll" OR "/cmd/result" OR "/exfil" OR "/shell"
AND Header Authorization == "Bearer <非标准长密钥>"
→ 告警：疑似移动 C2

URI matches "/chains/(mos0027|xenith|qqtime)/" 
→ 告警：疑似水坑漏洞链加载

URI contains "/checkin?type=" AND query contains "kernel_ready"
→ 高警：疑似提权成功
```

### JS 静态扫描（Semgrep/手工）

```yaml
patterns:
  - pattern: new Image().src = $X + '/checkin?type='
  - pattern: left:-9999px;width:1px;height:1px
  - pattern: sandbox='allow-scripts allow-same-origin'
  - pattern: $X = new AudioContext(); ... gain.value = 0.001
```

### 沙箱行为（动态）

- 检测静音音频循环 + Wake Lock 组合
- 检测 500ms 高频轮询全局对象
- 检测同步 XHR 到 `/exfil`

## 六、绕过提示（检测方视角）

- SDK 文件按需混淆/动态拼接，静态特征会漂移；**网络层端点特征最稳定**（协议契约难改）
- deviceId 无持久性（UA hash + 时间戳），跨会话同一设备会生成不同 ID → 按 UA+IP 聚类而非按 deviceId 去重
- `/checkin` 无认证，可被伪造投毒（攻击者可用任意 deviceId 上报，干扰统计）

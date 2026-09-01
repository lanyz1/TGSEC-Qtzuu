# WHP C2 协议契约

> 来源：`beacon_poll.js`（轻量版轮询器，500 行）+ `beacon.js`（完整版，1468 行）逆向整理。全部端点经代码交叉验证。

## 端点总表

| 端点 | 方法 | 用途 | 触发方 |
|---|---|---|---|
| `/checkin?type=<t>&msg=<m>&t=<ts>` | GET | 打点上报（sdk/log/harvest/timeout），Image 请求，无认证 | SDK/loader/harvest |
| `/beacon` | POST | 设备注册（beacon 在线登记） | beacon_poll 启动时 |
| `/cmd/poll?deviceId=<id>&_=<ts>` | GET | 拉取待执行命令 | 轮询循环 5s±3s |
| `/cmd/result` | POST | 回传命令执行结果 | 每个命令执行后 |
| `/exfil` | POST | 收割数据回传（同步 XHR） | harvest 模块 |
| `/shell` | POST | 服务端 shell 回退（execSync） | bridge 第 5 级降级 |
| `/chains/<chain>/<slot>/index.html` | GET | 漏洞链页面/引导脚本 | SDK 加载链 |
| `/client/<module>.js` | GET | client 模块（bridge/harvest/beacon） | loader 串行加载 |

## 认证

- 轮询与上报：`Authorization: Bearer <共享密钥>`（HTTP 头，密钥在 client 端明文配置）
- `/checkin` 与链加载：无认证（Image/script/iframe 请求，浏览器无法自定义头）
- 敏感面：`/cmd/poll`、`/cmd/result`、`/exfil`、`/shell` 依赖 Bearer；`/checkin`、`/chains/`、`/client/` 无保护

## 数据结构

### 注册（POST /beacon）

```json
{
  "deviceId": "iPhone14,2_17.4_a1b2c3d4_1723000000",
  "stage": "beacon_poll",
  "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 ...)",
  "extra": { "hasCmdPoll": true, "hasNativeBridge": true }
}
```

响应可返回服务端分配的 `deviceId`，client 用其覆盖本地 ID（`globalThis._WHP_DEVICE_ID`）。

### 轮询响应（GET /cmd/poll）

```json
{ "cmds": [ { "cmdId": "c1", "type": "exec_shell", "args": { "cmd": "id" } } ] }
```

### 结果回传（POST /cmd/result）

```json
{
  "cmdId": "c1",
  "deviceId": "iPhone14,2_...",
  "type": "exec_shell",
  "output": "uid=0(root)...",
  "status": "done",
  "ts": 1723000123
}
```

`status` 判定：output 含 `"error"` 字符串 → `failed`，否则 `done`。

## deviceId 生成逻辑（无持久 ID 时）

优先级：`_WHP_DEVICE_ID` → `deviceUID` → `beaconId` 全局变量 → 兜底指纹：

```
<机型>_<iOS版本>_<UA哈希hex>_<时间戳>     例：iPhone14,2_17.4_1a2b3c4d_1723000000
```

UA 哈希为 32 位滚动 hash（非加密），同一设备同会话内稳定，跨会话可漂移。

## 命令全集（beacon_poll 轻量版）

| type | 功能 | 依赖原语 |
|---|---|---|
| `eval_js` | WebKit 进程内任意 JS 执行 | 无 |
| `exec_shell` | 任意命令执行 | nativeExecShell |
| `read_file` | 读文件（默认 512KB 上限） | nativeReadFile |
| `list_files` | 列目录 | nativeListDir |
| `file_search` | find 按文件名模式搜（root 默认 /private/var/mobile，head -200） | shell |
| `dump_keychain` | Keychain 条目（前 500 条） | readKeychain |
| `dump_wifi` | WiFi 密码 | readWifiPasswords |
| `dump_contacts` | 通讯录 | readContacts |
| `dump_sms` | 短信 | readSMS |
| `screenshot` | 截图 | nativeScreenshot |
| `camera_snap` | 摄像头拍照 | nativeCameraSnap |
| `mic_record` | 麦克风录音（默认 5s） | nativeMicRecord |
| `dump_icloud_token` | iCloud token | readICloudToken |
| `dump_photos` | 相册 | readPhotos |
| `dump_email` | 邮件 | readEmail |
| `dump_notes` | 备忘录 | dumpNotes |
| `list_installed_apps` | 已安装应用列表 | listInstalledApps |
| `install_persist` | 持久化驻留 | nativeInstallPersist |
| `list_processes` | ps aux | shell |
| `kill_process` | kill -9 <pid> | shell |
| `network_connections` | netstat -an | shell |
| `sqlite_query` | sqlite3 任意查询（db+query） | shell |
| `clipboard_read` | pbpaste 剪贴板 | shell |
| `self_destruct` | 停轮询 + 清理临时文件 | shell |
| `ping` | 存活探测 | 无 |
| `reload_chain` | 1s 后跳回漏洞链页 reload | 无 |

未知 type 默认回退：若 args 含 `cmd` 则直接 shell 执行（即服务端任意 type 都可达到 RCE）。

## beacon.js 完整版补充能力

- 同构端点：`/beacon`、`/cmd/poll`、`/cmd/result`、`/exfil`
- 增加：剪贴板监控、进程/网络监控、持久化自毁、`reload_chain`（清缓存 → 跳链页 → 重载最新模块）
- 系统文件探测：`/etc/passwd`、`/etc/shadow`、`/private/etc/`、`/private/var/mobile/tmp/`、`/usr/bin/`、`/usr/sbin/`、`/var/mobile/tmp/`

## 轮询时序参数

| 参数 | 值 |
|---|---|
| 基础间隔 | 5000ms |
| 抖动 | ±3000ms（防 herd） |
| 失败退避 | 连续失败 >10 次 → 间隔 ×4 |
| 首轮延迟 | 1000~3000ms 随机 |
| 命令结果输出上限 | exec_shell 65536 字符 |

## 防挂起机制（iOS WebView 存活保障）

1. `navigator.wakeLock.request('screen')`，释放后 1s 重取
2. 静音 AudioContext 循环（gain=0.001，22050Hz 1 样本 buffer）
3. 15s 心跳：`audioCtx.state === 'suspended'` 时 `resume()`
4. `visibilitychange` 时重新获取 Wake Lock + 重启音频

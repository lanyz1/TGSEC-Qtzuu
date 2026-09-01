# 收割路径与数据目标（脱敏版）

> 来源：`precise_loader.js`（编排器 v6）+ 五个 harvest 模块逆向整理。PE 后毫秒级全量瞬时收割，7 模块**串行**加载（onerror 继续，不阻塞）。应用 bundle id 已泛化为代号（真实映射存仓库外 mapping 文件）。

## 编排顺序（precise_loader v6）

```
0. native_bridge_universal.js  基础桥接层（必须先加载）
1. harvest_wa.js               WhatsApp 全量身份（纯 JS SQLite+bplist）
2. harvest_tg.js               Telegram 身份（tgdata.db + key_datas + keychain）
3. harvest_crypto.js           加密货币钱包私钥（keystore/vault/seed）
4. harvest_browser.js          浏览器凭据（纯浏览器 API，无需 shell）
5. harvest_media.js            相册+隐私文件（DCIM/sms.db/通话记录）
6. beacon.js                   命令轮询（含补收割命令）
```

每个模块通过 `<script src="/client/<module>.js?_=<ts>">` 加载，`onload/onerror` 都推进索引，最后上报 `DONE: <ok>/<count> loaded in <ms>ms`。

## ① WhatsApp（harvest_wa）

路径模式（iOS 沙盒 container）：

```
<container>/.com.apple.mobile_container_manager.metadata.plist
<container>/Library/Preferences/group.*.shared.plist      ← 群组容器
<container>/Library/Preferences/<主app>.plist
/private/var/Keychains/keychain-2.db                      ← 系统 Keychain
/var/root/Library/Preferences/com.apple.MobileDevice.plist ← UDID
/var/mobile/Library/Preferences/com.apple.MobileDevice.plist
```

目标：身份（UDID、注册信息）+ keychain 条目 + `rc*.dat` 会话数据。

## ② Telegram（harvest_tg）

目标文件：`tgdata.db`、`key_datas`、`accounts-metadata`、keychain 条目。

## ③ 加密货币钱包（harvest_crypto）

> 覆盖 12 类钱包。bundle id 已泛化（wallet-a ~ wallet-l），真实映射存仓库外 mapping 文件。

| 泛化代号 | 数据形态 |
|---|---|
| wallet-a | `Documents/<代号>-wallet-data/seed` + `wallet.dat` |
| wallet-b | `Documents/<代号>-wallet/mnemonic.enc` + `wallet.json` |
| wallet-c | `Documents/<代号>/key.json` |
| wallet-d | `Documents/<代号>.wallet/info.seco` + `seed.seco` + `wallet.state` |
| wallet-e | `Documents/<代号>-wallet/identity` + `wallet.db` |
| wallet-f | `Documents/<代号>-wallet-sdk/`（目录收割） |
| wallet-g | `Documents/<代号>-wallet/`（目录收割） |
| wallet-h | `Documents/persist-root/engine*` + `vault` |
| 通用 | `Documents/accounts.db`、`Documents/app.json`、`Documents/storage/`、`Documents/wallets/`、`keychain-2.db`、`keychain-3.db` |

攻击价值排序：**seed / mnemonic / key.json / vault**（直接可转走资金）> identity/wallet.db（需解密）。

## ④ 浏览器全量（harvest_browser）

纯浏览器 API（无需 shell）：localStorage、Cookie、IndexedDB、表单数据、卡号（Luhn 校验）、API Key、JWT。WebKit 进程内可直接读。

## ⑤ 媒体与隐私（harvest_media）

DCIM 相册、`sms.db`（短信）、通话记录、备忘录、通讯录、键盘缓存。

## 回传机制

- **主通道**：同步 XHR `POST /exfil`（同步保证不丢）
- **备份通道**：异步 fetch 双备份
- 数据量大时分块（b64 编码）

## 自毁痕迹

```
rm -rf /tmp/平台前缀* /tmp/.平台前缀* /var/tmp/平台前缀*
```

## 防御启示

- 检测点：沙盒内对这些路径的异常访问（尤其 `keychain-2.db`、`*.plist` 批量读 + 外传）
- 优先级最高的止损目标：`seed/mnemonic/vault` 类文件被读即代表私钥已失窃，需立即转移资金

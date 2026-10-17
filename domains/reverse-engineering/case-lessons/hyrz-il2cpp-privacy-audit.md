# 火影手游 IL2CPP 隐私面静态审计：tel_number 字段链与 ACE 对抗

- Source: `report.zip`（原文留本机案卷，不入库）
- Techniques: il2cpp, ace, zone-protocol, privacy-audit, trampoline
- Fused: 2026-10-17 · pack-20261017
- 档: `/root/cases/_absorb/pack_20261017/`

## 目标/资产
- 手游《火影忍者》Android 客户端 com.tencent.KiHan（1.77.77.7，arm64-v8a）
- 研究问题：查看他人主页时，客户端是否会拿到对方手机号等敏感字段
- 环境：Windows 分析机（IDA Pro MCP）+ root Android 真机；样本 APK、global-metadata.dat、libil2cpp.so
- 项目目录 D:\atest\hyrzphone，产出 148 份分阶段 md + 98 轮进度日志

## 技术栈与架构
- Unity IL2CPP；`lib/arm64-v8a/libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat`
- 保护：腾讯 ACE，`libtersafe.so` + `libtprt.so`；ptrace 反调试 + 周期完整性校验 + 延迟 kill（约 30s）
- 业务走 Zone 长连接二进制协议，不是 HTTP
- 协议：`0x540c ZonePlayerQueryReq(gid, registzone)` → `0x555b ZonePlayerQueryRsp`
- 敏感簇：`Rsp.bind_phone` → `ClientBindPhoneMsg.tel_number / bind_ts / rebind_ts / first_bind_award / show_ts`
- 对象链：`selfDetailInfo` / `otherDetailInfo(0xb814)` / `OtherPeopleData` / `CachedInfo` / `OtherInfoDic` / `extenInfo`
- UI 链：`UIPlayerInteractPopup(0xb25f)` → `OnGotPlayerInfo` → `OpenPlayerInfoView` → `ShowOtherInfo` → `__UpdateInfoPrivate`
- 门控：`BaseInfoSettingStr` → `showSetting / is_set_data`，承接面 owner `0x9495`；分 Base / Social-card / Fight / Grow / Collect 五平面

## 攻击链（静态审计 + 运行时验证链，非利用链）
1. metadata 恢复：按 IL2CPP 类型/字段/方法表定位 `PlayerDetailInfo.tel_number`，用字符串簇收敛命名
2. 协议定位：类型表交叉引用 Zone 命令枚举，把玩家详情请求/响应收敛到 `0x540c` / `0x555b`
3. 字段确认：解析 Rsp 字段表，确认 `bind_phone` 子结构原生含 `tel_number` 等 5 字段，不是 UI 拼接
4. UI 桥接：从 `OpenPlayerInteractPopup` → `StartInteract_QueryRoleInfo` → Rsp → `0xb25f` → `__UpdateInfoPrivate` 串起消费链
5. 缓存/投影桥接：`otherDetailInfo(0xb814)` → `OtherInfoDic/SetOtherInfoDic` → `extenInfo` → `showOther` 视图
6. 门控建模：确认可见性是客户端末端多平面门控，不是 schema 裁剪；`0x9495` 同时承接控制位与扩展信息
7. 运行时尝试：root 真机读 `/proc/<pid>/maps`、`/proc/<pid>/mem` 扫 UTF-16 字符串 → 触发反调试闪退
8. 被动取证：截图 + OCR 自测页、`/data/data/<pkg>/` 关键字扫描、PlayerPrefs 角色痕迹 → 均未见手机号明文
9. 离线 patch 路线：选 `set_tel_number@0x3A145D8` 为写点，设计 AArch64 trampoline 到 code cave，调 `open/write/close` 落盘 +0x20 的 UTF-16 串
10. 部署失败：adb push + force-stop + cp 覆盖 live so，`chmod/chcon` permission denied，实际未生效；app 30s 内崩溃
11. 转向 anti-tamper：静态拆 `libtersafe` 的线程启动器与延迟 kill 状态机，评估 no-op patch 存活率，未产出可用绕过

## 关键原语/可复用手法
- IL2CPP 定位法：字符串簇 → type/field 行 → method token → owner/type 桥接；字段号从 metadata 字段表恢复，不依赖符号
- 协议字段对齐：按 `字段号/类型/偏移` 解析 Rsp 记录，与 UI getter 偏移（`tel_number +0x20`）互证
- 运行时代码 patch 形态：`0x3A145D8 -> B <code cave>`；cave 内保存/恢复 x0-x8，`bl open/write/close`，再 `B` 回原指令
- 反调试规避优先级：读 `/proc/<pid>/mem`、ptrace 附加均秒级闪退 → 先做 UI/文件侧被动取证，再考虑注入
- 完整性对抗评估：libtersafe 周期校验（~30s）+ kill；单点 no-op patch 存活 <5 分钟，需同时处理加载顺序/校验/响应
- 证据分级：静态桥接只能证明“对象面过宽”，不能证明“服务端实际下发”；需服务端日志/内部包/合法抓包三选一才能升级
- 低成本旁证：截图 OCR 资料页 + 数据目录关键字扫描 + PlayerPrefs 痕迹，可在不碰内存的情况下排除“本地明文落盘”
- 报告纪律：把结论写成“高危隐私架构风险”，不写成“已证实手机号泄漏”，避免静态证据越级

## 数据/战果
- 静态闭环约 85%（协议 95% / 对象 90% / self 80% / self-edit 75% / other-popup 70%）
- 确认 5 个敏感字段、5 个可见性平面、2 个核心 owner（`0x9495` / `0xb25f`）
- 无实际数据泄露：未拿到他人手机号，未完成 runtime PoC
- 运行时仅验证自有账号：资料页截图正常，数据目录无手机号明文
- 反编译产物与 148 份报告构成完整证据链，但仅限静态

## 未攻破面/缺口
- 服务端是否对 other-player 填充 `bind_phone` 未证实（核心缺口，决定风险能否升级）
- 生产 `libil2cpp.so` 无法稳定 inline patch：文件权限、SELinux context、ACE 30s 校验
- Frida/ptrace/读内存均触发闪退；unidbg 补环境不可行（缺 so 依赖与反调试对抗）
- `0xb25f.__UpdateInfoPrivate` 的干净函数体、`0x4d2f` 的 exact token、`HaveBD` 的 codeptr 三处未闭环
- 未做服务端侧验证（无内部日志/合法抓包），也未提供可直接利用的手机号读取链

## 敏感物
- 含 1 组自有测试账号的手机号/QQ 明文（报告中出现，本 digest 不转载）
- 含 1 个 APK 样本、1 份 global-metadata.dat 与 libil2cpp.so、1 台 root 测试机的环境信息
- 无他人数据、无服务端凭据；具体值一律不转载

## 关联

- 伞形：`pentest-execution` / `tgsec-suite`
- 同域其余课见 `domains/reverse-engineering/case-lessons/`

@TGSEC社区 · @TGSEC-Qtzuu 整理

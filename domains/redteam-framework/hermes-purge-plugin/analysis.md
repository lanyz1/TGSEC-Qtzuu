# Hermes 红队台账插件 purge — 要点

- 形态: Hermes Agent 插件(plugin.yaml: manifest_version 2 / api_version 1), 装载于 `~/.hermes/plugins/purge/`, 台账数据在 `~/.hermes/purge/`(删插件不影响数据), 纯标准库(python3≥3.8), MIT 许可
- 九类台账族: 资产 / 漏洞 / 凭据 / WebShell / 隧道 / 会话与访问 / 攻击链 / 攻击文件 / 得分点(25 项可改); 按目标分开存、原子写
- 工具(`provides_tools`): `purge_status` / `purge_roles` / `purge_role_prompt` / `purge_preflight` / `purge_objective` / `purge_report` / `purge_scan` / `purge_record`
- 钩子(`provides_hooks`): `pre_tool_call` / `pre_llm_call` / `on_session_start`
- 配置(config_schema): `guard_enabled`(默认 true, 红线闸: 高危命令 rm -rf /、mkfs、dd of=/dev/sd* 等在红队模式下拦截), `block_target_in_repo`(默认 true, 拦密钥/靶标名写进仓库或推送), `layer_marker`(默认 "", doctor 用来判断提示层是否真的进系统提示), `scope_file`(默认 "", 额外目标清单文件)
- 角色骨架 `roles.d/`: plan(指挥)/ recon(信息收集)/ assess(资产梳理)/ vuln-scan(漏洞发现)/ exploit(漏洞利用)/ internal(内网渗透); 目录默认为空, 由使用者按自己的方法论填, 存盘即生效(`purge_role_prompt("recon")` 读取)
- 关键流程: `purge_preflight`(动手前体检: 目标清单/授权线索/敏感域) → `purge_objective`(立目标卡+红队模式开关) → 记账 → `purge_report`(阶段复盘落盘); `purge_doctor`/`purge_status` 自检验证能力层是否生效
- 安装: `bash install.sh`(装到 `~/.hermes/plugins/purge/`, 已存在则备份为 `purge.bak_<时间戳>`); 手动: `cp *.py *.yaml` + `cp -r roles.d` → `hermes gateway restart`; 验收 `hermes config get plugins.entries.purge`
- 本卡仅收录(未在本机安装); 仓内尚有 guard.py/ledger.py/state.py/tools.py 等实现文件(未随卡收录)

@TGSEC社区 · @TGSEC-Qtzuu 整理

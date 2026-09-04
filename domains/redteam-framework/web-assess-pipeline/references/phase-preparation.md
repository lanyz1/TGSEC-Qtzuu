# 准备阶段 SOP

目标：理解需求、初始化项目目录、启动并验证代理、建立会话池，为威胁建模做好准备。
脚本路径以 skill 内 `scripts/` 为准；数据写到工作目录 `pentest-data/`。

## 0. 前置检查（开工必备，任一不满足即阻塞）

### 0.1 子代理注册

漏洞挖掘阶段调度 `pentest-vuln-miner`、威胁收敛阶段调度 `pentest-bypass-miner`，两者须先注册为可调度子代理。
开工前**校验二者均出现在当前可用子代理类型列表中**（可调度性的权威判据）：

- 两者都在 → 通过，继续后续准备。
- 任一缺失 → **阻塞**，不进入后续阶段，通知用户修复：确认 `.codex/agents/pentest-vuln-miner.toml` 与
  `.codex/agents/pentest-bypass-miner.toml` 均存在，重启会话使其被扫描注册；修复并重新校验通过后再继续。

### 0.2 mitmproxy

代理依赖 mitmproxy。先确认可用：

```powershell
python -c "import mitmproxy; print(mitmproxy.__version__)"
```

报 ImportError 则安装（首次使用必做）：

```powershell
python -m pip install -r .agents\skills\pentest-web-assess-pipeline\scripts\proxy\requirements.txt
```

## 1. 项目目录初始化

用 `init_project.py` 完成 project-id 推导、建目录、登记项目清单、初始化配置/状态文件。

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\init_project.py --target http://www.TGSEC.com:8080/
# 可选：--project <自定义id>  --security-level high|medium|low  --proxy-port 24304
```

脚本行为（幂等 + 断点）：

- 由 target 的 hostname[:port] 推导 project-id（`.`/`:`→`-`、转小写）；非法字符会要求用 `--project` 指定。
- 建 `pentest-data/{id}/` 及子目录 `js-files/`、`permission-matrix/`、`proxy-logs/`、`sessions/`。
- 登记根级 `index.json`；命中同名同 target → 输出「续测」并给出应跳转的 `phase`；同名不同 target → 报冲突。
- 新建时写 `config.json`、`state.json`。

**补全 config.json**（脚本只写占位，必须据用户输入补全，见 [data-schemas.md](data-schemas.md)）：

- `scope`：安全边界——允许进行安全测试的范围；用户未明确则取 target 路径下全部（不进行安全测试的部分可以结合 `exclude`进行排除），规则语法见 `scripts/proxy/README.md`。
- `exclude`：范围内需排除的 URL（以用户指定为准，如有些地址允许访问但不进行安全测试，则需排除，不记录URL日志）；语法同 scope，默认空。
- `proxy_port`：代理监听端口（默认 24304）；用户指定则以用户指定为准。
- `test_accounts`：测试账号（role/username/password/login_url）；未提供留空，不阻塞。
- `goals` / `constraints` / `security_level`：目标成果、约束条件、安全等级（默认 `high`）。
- `work_guidelines`：工作守则——用户在下发任务或交流中输入 `# 工作守则` 标记时，将该标记之后的**全部内容完整写入**本字段（准备阶段及后续任意时刻均可触发，多次下发则追加保全既有条目）；未提供留 `""`。**最高优先级**，全程所有阶段与子代理严格遵守。

> 安全边界语义（high/medium/low）见 SKILL.md，全程严格遵守；工作守则（`work_guidelines`）**最高优先级**，全程严格遵守。

## 2. 启动代理服务器

代理把所有请求按 URL 分类落盘到 `pentest-data/{id}/proxy-logs/`，是后续清单与参数分析的数据源。
**后台运行**（长驻服务）：

```powershell
python .agents\skills\pentest-web-assess-pipeline\scripts\proxy\start.py `
  --config pentest-data\{id}\config.json `
  --log-dir pentest-data\{id}\proxy-logs
```

- `--config` 让代理直接读 `config.json` 的 `scope`/`exclude`（及 `scope_regex`/`exclude_regex`）与 `proxy_port`。
- 启动失败（端口占用等）→ 如果是之前本技能遗留的python进程则kill后重启，否则提示用户处理。
- 首次启动会在 mitmproxy 默认 CA 目录 生成 CA 证书 `mitmproxy-ca-cert.pem`。

## 3. 校验 playwright 走代理

广度阶段用 playwright 浏览页面，其流量**必须经代理**才会被记录。playwright MCP 的代理需在 MCP 配置中设置，
skill 无法自动修改，须**检查并提示用户**：

1. 提示用户确认 playwright MCP server 启动参数含：
   `--proxy-server http://127.0.0.1:24304 --ignore-https-errors`（端口与 `config.proxy_port` 一致，默认 24304）。
2. **验证**：用 playwright 访问一次目标页（`browser_navigate`），随后检查
   `pentest-data\{id}\proxy-logs\url_index.jsonl` 是否新增该 URL。
   - 有新增 → 代理链路正常。
   - 无新增 → 流量未经代理，提示用户修正 MCP 配置后重启 MCP，再次验证；未通过不进入广度阶段。

## 4. 建立会话池

基于 `config.json.test_accounts`，用 playwright 逐账号登录，把凭证写入 `sessions.json`
（结构见 [data-schemas.md](data-schemas.md)），供后续以不同角色身份快速测试（尤其权限矩阵）：

1. 始终写入一条 `role=unauthenticated` 的未登录基线（用于权限矩阵对照）。
2. 每个账号：`browser_navigate` 到 `login_url` → `browser_fill_form` 填账号密码 → 提交 → 确认登录成功。
   - 导出会话：用 `browser_evaluate_unsafe` 读取 `document.cookie` / `localStorage`，或导出 playwright storageState
     到 `sessions/{session_id}-{role}.json`，并把关键凭证摘要写入 `auth`。
   - 登录失败 → `login_status=failed`，在 `notes` 记原因（不阻塞，可继续其它账号）。
   - 可以查看代理服务器生成的日志获取登录请求和cookie等信息辅助建立会话池
3. 目标系统有注册功能时，在执行阶段尝试注册账号并加入会话池（如果已有的同角色测试账号少于2个且具备注册条件的，优先尝试注册账号使每个角色测试账号达到2个）。
4. 未提供任何账号 → 仅保留 unauthenticated 基线，不阻塞，后续以匿名身份建模。

完成准备阶段后，更新 `state.json`：`phase=2`、`phase_status.preparation=completed`、`breadth=in_progress`。

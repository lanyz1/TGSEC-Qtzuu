# TGSEC 安全知识库（小白也能用）

> @TGSEC社区 · @TGSEC-Qtzuu 整理  
> 给 **Grok / Claude / Cursor / Hermes** 等 AI 用的安全学习与授权评估资料库。

**👉 新手只看一个文件：[`START.md`](START.md)**

---

## 30 秒上手

1. **下载**（Win 一行）  
   ```powershell
   irm https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-windows.ps1 | iex
   ```
2. **用 AI 打开**文件夹 `security-suite`
3. **对 AI 说**  
   ```text
   请先读 START.md、AGENTS.md、ROUTING.md、MASTER.md，用简单中文带我。
   ```

Linux/Mac：
```bash
curl -fsSL https://cdn.jsdelivr.net/gh/lanyz1/TGSEC-Qtzuu@master/scripts/install-linux.sh | bash
```

---

## 里面有什么（不用一次看完）

| 你想… | 打开 |
|--------|------|
| 小白入口 | **`START.md`** |
| 任务→读哪个文件夹 | **`ROUTING.md`** |
| 全部主题地图 | **`MASTER.md`** |
| 具体资料 | **`domains/`**（按网站注入、登录、支付、手机 APP…分类） |
| AI 完整规则 | `AGENTS.md` |

**不需要**会 Hermes、不需要会命令行才能「让 AI 读资料」。  
会打开文件夹 + 会复制一句话就行。

---

## 文件夹结构（极简）

```text
START.md          ← 小白从这开始
ROUTING.md        ← 说人话关键词 → 去哪个目录
MASTER.md         ← 主题地图
AGENTS.md         ← 给 AI 的完整说明
domains/          ← 所有知识正文
scripts/          ← 一键安装（可选）
```

---

## 重要说明

- 仅供 **学习、授权评估、CTF、自己的靶场**。  
- 不要拿去打未授权的网站。  
- 详细法律声明见文末。

---

## 更新

```text
进入 security-suite 文件夹 → git pull
```

---

## 声明

本套件仅供合法授权的安全测试、CTF 训练、学术研究与防护研究使用。使用者需遵守所在地法律法规。

@TGSEC社区 · @TGSEC-Qtzuu 整理

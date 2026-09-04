# Security Skill Trigger Matrix

系统只把每个 skill 的 description 前 ~57 字塞进目录。触发靠**具体名词**，不靠 “needing”。

| 用户话里的词 | skill_view |
|-------------|------------|
| 渗透/打点/深挖/继续/攻击链/pivot | pentest-execution |
| APK/IPA/jadx/Frida/逆向/脱壳/Hook | reverse-skill |
| SQLi/XSS/SSRF/JWT/IDOR/未授权 | hack-skills + web-sec |
| 主题域/知识库/攻击面 | tgsec-suite |
| 0day/产品RCE/CVE exploit | 0day-exploit-library |
| 博彩/游戏/代理BFLA | gambling-platform-pentest |
| OODA/自动渗透agent | stopen |
| 假设驱动/状态机红队 | black-cat-redteam |
| bug bounty/披露报告 | claude-bughunter |
| 中文手法卡片 | secatlas |
| payload大全 | about-security |
| 吸收仓库/融合知识库 | security-kb-ingest |
| iOS26.6/65343/KASLR/盗U研判 | reverse-skill + ios-kernel-cve/ANALYSIS.md |

## 强制顺序

1. skill_view(匹配伞形)
2. 若 reverse-skill → master-route.sh
3. read_file PRIMARY 或 domains/<面>/
4. 再写脚本/打点

@TGSEC社区 · @TGSEC-Qtzuu 整理

| Fastjson/Shiro/Log4j/Spring 专项 | tgsec-suite → web-injection/playbook-6000 |
| 组件名+版本先搜洞 | tgsec-suite → recon/component-vuln-intel |
| 授权Web威胁建模三阶段 | redteam-framework/pentest-lyan-workflow |
| hunter offensive 类名 | 对应域 hunter-6000/ |

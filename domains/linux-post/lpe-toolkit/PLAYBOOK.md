# Linux 多架构内核 LPE 编排

要点：
1. 先收集 `uname -r` / 发行版 / 架构
2. 按内核版本过滤候选（见 README / toolkit 逻辑）
3. 多 arch 预编译产物按需构建（`build-exploits.sh` / Makefile），**不要无脑跑全量**
4. 用误报 marker / 成功条件校验，避免假阳性
5. 二进制 exploit 本体未入库（体积大）；需要时按 INDEX 从构建脚本生成

与现有 `PEN-Linux-LPE.md` / `linux-privilege-escalation` 交叉使用。

---
@TGSEC社区 · @TGSEC-Qtzuu 整理

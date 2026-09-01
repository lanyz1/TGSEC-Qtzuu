---
id: TECH-2026-1804
title: "in-toto 与 SLSA 构建来源证明"
kind: technique
track:
  - 源码审计_供应链与DevSecOps
platform:
  - 源码审计_供应链与DevSecOps
techniques:
  - 供应链
  - 构建来源证明
  - 制品签名
lifecycle:
  - 执行
  - 防御削弱
  - 检测与缓解映射
standards:
  - in-toto-Attestation-Framework-1.2
  - in-toto-Statement-v1
  - SLSA-1.2
  - SLSA-Provenance-v1
authorization: public
confidence: verified
sensitivity: public
source_id:
  - SRC-2026-1809
  - SRC-2026-1810
  - SRC-2026-1811
---

# 定义

构建来源证明是与制品绑定、可认证的结构化声明，用来描述制品从哪些输入、通过哪个构建定义和构建器产生。in-toto 提供通用证明分层，SLSA 定义递增的供应链保证、推荐的来源谓词和验证要求。

## 边界

- 属于本技术：证明封装、制品摘要绑定、谓词类型、源码与构建输入、构建器身份、构建参数、信任根和验证期望。
- 不属于本技术：自动证明源代码无恶意逻辑、构建平台运营者绝对可信、依赖没有漏洞、消费者选择了正确包名。
- 容易混淆：证明存在与证明可信、签名有效与构建器受信任、可复现构建与来源证明、SLSA Build 等级与软件总体安全等级。

## in-toto 四层模型

### Predicate

保存某一类声明的具体元数据，例如 SLSA Build Provenance、SBOM 或漏洞扫描结果。

### Statement

把 Predicate 绑定到一个或多个制品。Statement v1 的关键字段为：

- `_type`：`https://in-toto.io/Statement/v1`
- `subject`：目标制品集合，每个对象必须带摘要
- `predicateType`：标识 Predicate Schema 的 URI
- `predicate`：具体声明内容

Statement 只按摘要匹配 subject；若内容类型或名称也属于策略条件，验证者必须额外检查。

### Envelope

负责序列化和认证，例如 DSSE envelope。Envelope 的签名认证 Statement，但不会替代 Statement 内部的对象和类型检查。

### Bundle

聚合一个或多个证明及其验证材料。Bundle 解决携带与分发问题，不替代策略判断。

in-toto Attestation Framework 的发布版本可为 1.2，而 Statement 类型 URI 仍为 v1；URI 的主版本表达 Statement Schema 兼容边界，不能按框架发布号机械改写。

## SLSA 1.2 的轨道概念

SLSA 1.2 包含 Build 与 Source 轨道。等级只对特定轨道及其威胁模型有意义，因此应写：

- `SLSA Build L1`
- `SLSA Build L2`
- `SLSA Build L3`

而不是脱离上下文写“SLSA 3”。

### Build L0

没有 SLSA Build 保证。

### Build L1

存在描述制品如何构建的 provenance，主要提高可见性并减少过程错误；单纯存在的声明仍可能被伪造。

### Build L2

来源由托管构建平台生成并签名，重点缓解构建完成后制品或 provenance 被篡改。

### Build L3

使用经过加固的构建平台，进一步保护构建过程和 provenance 生成免受外部攻击者影响。它不自动覆盖构建平台自身被攻陷或恶意内部人员。

## SLSA Build Provenance v1

推荐 predicate type：

`https://slsa.dev/provenance/v1`

主要结构：

- `buildDefinition`
  - `buildType`：定义如何解释构建流程和参数的类型 URI
  - `externalParameters`：由租户或外部调用者控制的参数
  - `internalParameters`：受可信构建平台控制、主要用于调试或事件响应的参数
  - `resolvedDependencies`：本次构建解析到的输入依赖
- `runDetails`
  - `builder.id`：可信构建平台及其安全属性的身份
  - 本次运行的元数据和证明生成信息

`builder.id` 不是普通显示字符串。若同一平台存在安全属性不同的运行模式，应使用不同 ID，并由文档说明其范围、声明等级和字段完整性。

## 验证三阶段

### 阶段 1：验证证明适用于目标制品

1. 使用预配置的信任根验证 Envelope 签名。
2. 重新计算制品摘要并匹配 Statement `subject`。
3. 确认 `predicateType` 是受支持的 SLSA provenance 类型。
4. 用签名身份与 `builder.id` 查询本地信任映射，得到验证者实际认可的最高 Build 等级。

构建器自己声称 L3，不代表验证者必须信任到 L3。

### 阶段 2：与包级期望比较

至少比较：

- 允许的构建器身份；
- 规范源码仓库；
- `buildType`；
- `externalParameters`。

未知的外部参数应默认导致验证失败，除非策略显式定义其安全范围。否则攻击者可借新增参数改变构建行为而绕过旧验证器。

### 阶段 3：按需递归检查依赖

可继续检查 `resolvedDependencies` 及其证明或 Verification Summary Attestation。依赖递归通常需要明确的深度、例外和最低等级策略；不能因部分依赖没有证明就悄悄把未知当通过。

## 期望从哪里来

- **消费者维护**：消费者独立定义可信构建器、源码和参数，控制力最强但维护成本高。
- **生态维护**：包仓库在上传时验证并公布期望，可让全部消费者受益。
- **生产者声明**：需要认证的变更渠道和防单方篡改控制。
- **源码定义**：把包名不可变绑定到源码仓库，并在受审查源码中定义构建配置。
- **首次使用信任**：记录第一版后监控变化，部署简单但不能发现首版已被污染。

期望是针对“包名/产品”的策略，provenance 是针对“具体制品摘要”的证据，二者作用域不同。

## 威胁与能力边界

- 验证上传时 provenance 可降低仓库接收异常制品的概率，但若仓库之后被攻陷，消费端再次验证更有价值。
- Build L2 重点保护构建后篡改；Build L3 加固构建过程，但仍需审慎选择构建平台。
- SLSA 不自动解决仿冒包、拼写抢注或消费者选择错误包的问题。
- `resolvedDependencies` 的存在不代表所有传递依赖都已完整、递归验证。
- 来源证明可记录恶意源码被“正确构建”的事实；源码审查和 Source 轨道控制仍不可少。
- 可复现构建能提供独立比对信号，但不会说明谁批准了源码、由哪个受信任构建器发布。

## 安全验证

用本地虚构证明完成以下场景：

1. 合法制品、合法签名、可信构建器和符合预期参数应通过。
2. 替换制品但保留原证明，应因 `subject.digest` 不匹配失败。
3. 保持签名有效但换成未授权构建器，应因信任映射失败。
4. 把源码仓库换成同名 fork，应因规范仓库期望失败。
5. 增加未知 `externalParameters` 字段，应默认失败。
6. 修改 `predicateType`，即使 JSON 结构类似也应失败。
7. 仅在仓库上传时验证后，再模拟消费端验证，确认两层策略都能独立工作。

停止点：本地策略对受控正反例做出稳定决策即可；不需要触发任何第三方真实构建或发布。

## 检测与排查

- provenance 的 target digest 与下载制品不一致。
- `builder.id` 存在，但没有对应信任文档或本地等级映射。
- 构建器切换、源码仓库变化或外部参数新增未触发告警。
- 证明由 CI 任务本身生成和签名，而非受信任控制平面，导致租户可伪造。
- 策略只允许某组织，却未约束仓库、工作流和受保护引用。
- 同一包的新版本来源突然转向 fork。
- 上传端显示“已验证”，消费端却无法取得原始证明或策略版本。

## 修复与回归

- 为每类构建定义稳定、可审计的 `buildType`。
- 最小化 `externalParameters`，把复杂构建逻辑放入受审查源码配置。
- 由构建平台可信控制平面生成并签署 provenance。
- 维护签名身份与 `builder.id → 最高认可等级` 映射。
- 对源码、构建器、参数和策略变更执行审批与差异告警。
- 同时在仓库上传和关键消费点验证。
- 保存原证明、验证结果、策略 URI/摘要和验证器版本。
- 回归覆盖目标替换、fork、未知参数、错误类型、未受信构建器及依赖证明缺失。

## 标准映射

- in-toto Attestation Framework 1.2
- in-toto Statement v1
- SLSA 1.2 Build / Source Tracks
- SLSA Build Provenance v1
- Sigstore/DSSE 可作为认证 Envelope 与验证材料实现

## 核心要点

- 可泛化模式：**证据绑定制品，信任根认证证据，期望决定证据是否可接受**。
- 容易误判的反例：来源证明签名有效，但构建器或源码不在允许列表。
- 检测信号：摘要错配、构建器漂移、fork、未知外部参数、策略版本缺失。
- 思考问题：为什么 provenance 存在仍不足以阻止供应链篡改？
- 常见误区：“SLSA Build L3 证明软件没有漏洞。”

## 关联来源

- [公开来源索引](公开来源索引.md)
- `SRC-2026-1809`、`SRC-2026-1810`、`SRC-2026-1811`

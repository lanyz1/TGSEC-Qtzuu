# 源码审计 SAST 工具链

SAST 工具适合扩大覆盖面和发现重复模式，但不能替代人工数据流确认。代码审计结论仍以 Source→Sink 证据链为准：工具结果只能作为候选线索，必须回到代码中验证可达性、可控性、过滤链和真实影响。

---

## 1. 工具选择决策

| 场景 | 优先工具 | 用途 |
|---|---|---|
| 多语言项目初筛 | Semgrep / Opengrep | 快速发现危险 API、框架误用、已知模式 |
| 大型企业项目质量门禁 | SonarQube | 安全热点、代码质量和趋势跟踪 |
| PHP taint analysis | Psalm | PHP 数据流与 taint 分析 |
| GitHub / 多语言深度查询 | CodeQL | 构建数据库后运行安全 query 和自定义 query |
| 依赖和开源组件风险 | Snyk / OSV / dependency scanner | 识别已知 CVE 和供应链风险 |

使用顺序建议：
1. 先跑轻量规则获得候选 sink 和入口。
2. 再按语言审计 pipeline 做路由映射和权限建模。
3. 对工具命中的路径补齐 Source→Sink 证据。
4. 只把可达、可控、影响明确的结果写入“已确认漏洞”。

---

## 2. Semgrep / Opengrep

Semgrep 适合快速编写和调整规则，寻找“长得像代码”的漏洞模式。对框架项目，优先使用官方规则和可信第三方规则做初筛，再为目标项目补充定制规则。

```bash
python3 -m pip install semgrep
semgrep --config auto .
semgrep --config p/security-audit .
semgrep --config rules/ --json --output semgrep-results.json .
```

Docker 方式：

```bash
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep --config auto /src
```

常用规则来源：
- `semgrep/semgrep-rules`
- `trailofbits/semgrep-rules`
- 目标语言或框架社区维护的规则集

结果处理：
- 把命中的 sink、文件、行号加入审计候选清单。
- 对高噪声规则降级为“提示”，不要直接转成漏洞。
- 对重复命中归并为同一模式，避免报告刷屏。

---

## 3. SonarQube

SonarQube 更适合持续审计和团队协作场景。它的 Security Hotspots 需要人工确认，不等同于已确认漏洞。

```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
```

扫描示例：

```bash
docker run --rm \
  -e SONAR_HOST_URL="http://127.0.0.1:9000" \
  -v "${PWD}:/usr/src" \
  sonarsource/sonar-scanner-cli \
  -Dsonar.projectKey=target-project \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://127.0.0.1:9000 \
  -Dsonar.token=SONAR_TOKEN
```

扫描前先清理无效符号链接和明显无关目录，避免工具在 vendor、build、dist 中产生大量噪声。

---

## 4. Psalm（PHP）

Psalm 适合 PHP 项目的类型检查和 taint analysis，可作为 `php-audit-pipeline` 的候选路径来源。

```bash
composer require --dev vimeo/psalm
./vendor/bin/psalm --init
./vendor/bin/psalm --taint-analysis
./vendor/bin/psalm --report=results.sarif
```

使用要点：
- 先确认项目能正常安装依赖和 autoload。
- 对框架入口、Controller、Request 对象建立 sources 认识。
- SARIF 结果适合导入查看器，但报告结论仍需人工复核。

---

## 5. CodeQL

CodeQL 适合需要跨文件、跨函数查询复杂数据流的项目。成本比 Semgrep 高，但对大型代码库和定制 query 更有价值。

```bash
codeql resolve languages
codeql database create codeql-db --language=java --source-root .
codeql database analyze codeql-db github/security-queries \
  --format=sarif-latest --output=codeql-results.sarif --download
```

常见流程：
1. 确认语言和构建方式，编译型语言需要能成功构建。
2. 创建 CodeQL database。
3. 运行官方 security queries。
4. 对关键业务 sink 编写或调整自定义 query。
5. 将结果回填到人工审计证据链。

---

## 6. Snyk / 依赖扫描

Snyk 这类工具更偏依赖和供应链风险，也可覆盖部分 SAST 能力。适合回答“项目用了哪些已知有漏洞的组件”，不适合直接证明业务逻辑漏洞。

```bash
snyk auth
snyk test
snyk code test
snyk code test --json | snyk-to-html -o snyk-code.html
```

Docker 示例：

```bash
docker run -it \
  -e "SNYK_TOKEN=TOKEN" \
  -v "${PWD}:/project" \
  snyk/snyk:gradle test --org=my-org-name
```

---

## 7. 结果分级与复核

工具输出进入报告前必须分级：

| 状态 | 含义 | 是否写入漏洞详情 |
|---|---|---|
| 候选 | 工具命中危险模式，但未确认入口或可控性 | 否 |
| 待验证 | 入口和 sink 存在，但过滤链/权限/运行条件未确认 | 可放审计备注 |
| 已确认 | Source→Sink 完整、可达、可控、影响明确 | 是 |
| 误报 | 不可达、不可控、已有有效防护或工具误判 | 否 |

复核重点：
- Source 是否来自用户、外部请求、文件、消息队列或不可信服务。
- Sink 是否真的执行危险行为，而不是测试代码或死代码。
- Sanitizer 是否覆盖所有路径，是否存在编码/类型/上下文绕过。
- 权限检查是否在到达 sink 前生效。
- 漏洞影响是否能被业务上下文放大或限制。

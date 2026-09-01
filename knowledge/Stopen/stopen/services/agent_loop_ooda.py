"""OODA Agent 循环 — 黑板驱动的自动化渗透测试核心"""
import json
import re
from typing import AsyncGenerator

from services.blackboard import Blackboard
from services.tool_base import ToolResult
from services.tool_registry import tool_registry
from services.llm_client import acompletion
from services.skills_service import get_skill_prompt, list_all_skills
from app_config.encryption import ConfigEncryption
from app_config.providers import PROVIDERS, PROVIDER_ORDER
from app_config.settings import CONFIG_DIR
from app_config.logging_config import get_logger

log = get_logger(__name__)

MAX_ITERATIONS = 15
MAX_CONSECUTIVE_FAILURES = 3
MAX_TOOL_CALLS_PER_TURN = 3

PERSISTENT_ROUNDS_PER_CYCLE = 100
PERSISTENT_MAX_CYCLES = 10
PERSISTENT_AUTO_REPORT = True

# CTF 模式额外技能注入
CTF_SKILLS = {
    "ctf": ["ctf_web", "ctf_crypto", "ctf_reverse"],
    "ctf_web": ["ctf_web"],
    "ctf_crypto": ["ctf_crypto"],
    "ctf_reverse": ["ctf_reverse"],
}
PENTEST_SKILLS = ["recon", "vuln_discovery", "exploitation", "post_exploit"]


# ── Reflexion 引擎 ──

def _classify_failure(tool_name: str, error: str) -> str:
    """分类失败原因"""
    err_lower = error.lower()
    if "not found" in err_lower or "no such file" in err_lower:
        return "env_limit"
    if "timeout" in err_lower or "timed out" in err_lower:
        return "timeout"
    if "permission" in err_lower or "denied" in err_lower or "refused" in err_lower:
        return "permission"
    if "param" in err_lower or "argument" in err_lower or "invalid" in err_lower:
        return "param_error"
    return "unknown"


REFLEXION_LEVELS = {
    0: "",  # 原始
    1: lambda cmd: f"echo '{cmd}' | base64 -d | bash",  # URL/Base64 编码
    2: lambda cmd: cmd.replace("'", "''").replace('"', '\\"'),  # 转义
    3: lambda cmd: f"$({cmd})",  # 命令替换
    4: lambda cmd: f"{{echo,{cmd.replace(' ', ',')}}}",  # 花括号混淆
}


def _escalate_payload(cmd: str, level: int) -> str:
    """递进载荷，level 0-4"""
    escalation = REFLEXION_LEVELS.get(level, REFLEXION_LEVELS[0])
    if callable(escalation):
        return escalation(cmd)
    return cmd


# ── 反幻觉门 ──

def _verify_evidence(claim: str, evidence: str) -> bool:
    """验证声称是否在证据中找到逐字匹配"""
    if not evidence:
        return False
    claim_clean = claim.strip().lower()
    evidence_clean = evidence.strip().lower()
    return claim_clean in evidence_clean


# ── 工具执行与结果处理 ──

def _get_skills_for_task(task_type: str) -> str:
    skill_names = []
    if task_type == "ctf":
        skill_names = CTF_SKILLS["ctf"]
    elif task_type in CTF_SKILLS:
        skill_names = CTF_SKILLS[task_type]
    else:
        skill_names = PENTEST_SKILLS

    texts = []
    for name in skill_names:
        content = get_skill_prompt(name)
        if content:
            texts.append(f"## {name}\n{content}")
    return "\n\n".join(texts)


OODA_SYSTEM_PROMPT = """你是 Stopen 渗透测试 Agent，使用 OODA 循环 + 黑板驱动工作。

## 当前状态
{blackboard_summary}

## 可用工具
{tools_summary}

## 渗透/CTF 技能指南
{skills_guide}

## OODA 工作流程
每次调用你需要：
1. **Observe** — 阅读当前黑板：目标、已知事实（Facts）、待办事项（Intents）
2. **Orient** — 分析当前态势：哪些已确认、下一步应做什么
3. **Decide** — 决定执行哪个 Intent 或产生新的 Intent
4. **Act** — 调用工具或汇报结果

## 核心规则
1. 每个"发现"必须有工具输出原文佐证。无证据的声称视为不存在。
2. 先用端口扫描 → 服务识别 → 漏洞扫描 → 利用的渐进式渗透流程。
3. 调用工具后用输出更新黑板（添加 Facts、完成 Intents）。
4. 如果目标已达成，调用 final_answer 工具汇报结果。
5. 连续失败 3 次或达到 15 次迭代自动中止。
6. CTF 模式下找到 flag 后立即调用 final_answer。"""


def _resolve_llm_kwargs(model: str) -> tuple[str, dict]:
    """解析模型字符串，返回 (model_str, kwargs)"""
    provider_key = "openai"
    if "/" in model:
        provider_key = model.split("/", 1)[0]
        model_name = model.split("/", 1)[1]
    else:
        model_name = model

    enc = ConfigEncryption(CONFIG_DIR)
    cfg = enc.load_config()
    saved = cfg.get(provider_key, {})
    api_key = saved.get("api_key", "")
    kwargs = {"api_key": api_key}

    info = PROVIDERS.get(provider_key, {})
    if info.get("base_url") and not info.get("is_native", True):
        kwargs["api_base"] = saved.get("base_url") or info["base_url"]

    return model, kwargs


def _format_blackboard(bb: Blackboard) -> str:
    """格式化黑板状态供 LLM 使用"""
    lines = [f"目标: {bb.goal}", f"已达成: {'是' if bb.goal_achieved else '否'}", ""]

    if bb.facts:
        lines.append("已知事实 (Facts):")
        for f in bb.facts:
            ev = f.evidence[:120] if f.evidence else ""
            lines.append(f"  [{f.type}] {f.value} (来源: {f.source}, 证据: {ev})")
    else:
        lines.append("已知事实: 暂无")

    lines.append("")
    pending = bb.get_pending_intents()
    if pending:
        lines.append("待办事项 (Intents):")
        for i in pending:
            lines.append(f"  [{i.type}] {i.target} | 优先级: {i.priority}")
    else:
        lines.append("待办事项: 暂无")

    return "\n".join(lines)


def _format_tools() -> str:
    """格式化工具列表供 LLM 使用"""
    specs = tool_registry.list_specs()
    if not specs:
        return "暂未注册任何工具"
    lines = []
    for s in specs:
        params = ", ".join(s.get("parameters", {}).get("properties", {}).keys())
        lines.append(f"  {s['name']}: {s['description']}")
        if params:
            lines.append(f"    参数: {params}")
    return "\n".join(lines)


def _parse_tool_call(response) -> list[dict]:
    """从 LLM 响应解析工具调用"""
    calls = []
    msg = response.choices[0].message
    for tc in (msg.tool_calls or []):
        try:
            args = json.loads(tc.function.arguments)
        except (json.JSONDecodeError, TypeError):
            args = {}
        calls.append({
            "id": tc.id,
            "name": tc.function.name,
            "arguments": args,
        })
    return calls


def _process_tool_result(bb: Blackboard, tool_name: str, args: dict,
                          result) -> None:
    """分析工具执行结果，自动添加 Facts 和 Intents 到黑板 + 自动漏洞入库"""
    if not result.success:
        return

    output_lower = result.output.lower()
    from services.db_service import db

    # 端口扫描结果
    if tool_name == "port_scan":
        for line in result.output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                bb.add_fact("port_open", line.strip(),
                            source="port_scan", evidence=line.strip(),
                            priority=7)
                if any(p in line for p in ["80/", "443/", "8080/", "8443/"]):
                    port = line.split("/")[0].strip()
                    target_url = f"http://{args.get('targets', '')}:{port}"
                    bb.add_intent("dir_brute", target_url, priority=8)

    # 目录枚举结果
    elif tool_name == "dir_brute":
        found = result.data.get("found", [])
        for item in found:
            path = item.get("path", "")
            status = item.get("status", 0)
            bb.add_fact("web_path", f"{args.get('url', '')}{path}",
                        source="dir_brute",
                        evidence=f"HTTP {status} - {path}",
                        priority=6)
            if any(s in path for s in [".git", ".env", "admin", "api"]):
                bb.add_intent("exploit", args.get("url", "") + path,
                             priority=9)

    # CVE 查询结果
    elif tool_name == "query_cve":
        bb.add_fact("vuln_info", result.output[:200],
                    source="query_cve", evidence=result.output[:300],
                    priority=8)

        # 自动将 CVE 写入漏洞数据库
        vulns = result.data.get("vulnerabilities", [])
        for v in vulns[:5]:
            c = v.get("cve", {})
            cid = c.get("id", "")
            desc = ""
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d["value"][:200]
                    break
            if cid:
                db.create_vulnerability(
                    title=f"CVE: {cid}",
                    target=args.get("keywords", args.get("product", "")),
                    vuln_type="cve",
                    severity="critical" if any(
                        k in (desc or "").lower()
                        for k in ["critical", "rce", "remote code", "arbitrary"]) else "high",
                    source="query_cve",
                    evidence=desc[:500],
                    conversation_id=bb.goal,
                )

    # Flag 检测（反幻觉门：必须逐字出现在工具输出中）
    flag_match = re.search(r'(?i)flag\{[^}]+\}', result.output)
    if flag_match:
        raw_flag = flag_match.group()
        # 反幻觉验证：确保 flag 确实在原始输出中
        if _verify_evidence(raw_flag, result.output):
            bb.add_fact("flag", raw_flag, source=tool_name,
                        evidence=raw_flag, priority=10)
            bb.goal_achieved = True


async def ooda_loop_stream(target: str, goal: str = "",
                           task_type: str = "pentest",
                           model: str = "", provider_key: str = "",
                           blackboard: Blackboard = None,
                           cancel_event=None,
                           custom_prompt: str = "",
                           skills_override: str = "",
                           persistent_mode: bool = False) -> AsyncGenerator[str, None]:
    """OODA 主循环，返回 SSE 流式输出"""
    if blackboard is None:
        blackboard = Blackboard(goal=goal or f"对 {target} 进行渗透测试")

    # 初始 Intent：扫描目标
    blackboard.add_fact("info", f"目标: {target}", source="user_input", priority=10)
    blackboard.add_intent("recon", target, priority=10)

    iteration = 0
    consecutive_failures = 0

    # Reflexion 状态
    reflexion_failures = {}  # tool_name -> count
    current_escalation = 0  # 当前递进等级 0-4

    yield f"[目标] {target}\n"
    if goal:
        yield f"[目标说明] {goal}\n"
    yield f"[类型] {task_type}\n"
    yield f"[工具] {tool_registry.count} 个可用\n"
    if persistent_mode:
        yield f"[持久化] {PERSISTENT_ROUNDS_PER_CYCLE} 轮/周期, 最多 {PERSISTENT_MAX_CYCLES} 周期\n"
    yield "─" * 40 + "\n"

    # 持久化模式：多周期
    max_iterations = MAX_ITERATIONS
    if persistent_mode:
        max_iterations = PERSISTENT_ROUNDS_PER_CYCLE

    while iteration < max_iterations:
        iteration += 1
        yield f"\n[Iteration] {iteration}/{max_iterations}\n"

        if cancel_event and cancel_event.is_set():
            yield "[取消] Agent 已取消\n"
            break

        # === DECIDE: LLM 选择要调用的工具 ===
        tools = tool_registry.list_openai_tools()

        # 加上 final_answer 工具
        final_answer_tool = {
            "type": "function",
            "function": {
                "name": "final_answer",
                "description": "汇报最终渗透结果，包含所有关键发现和 flag（如找到）",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string", "description": "渗透结果总结"},
                        "flag": {"type": "string", "description": "如找到 flag 填写在此"},
                        "evidence": {"type": "string", "description": "关键证据"},
                    },
                    "required": ["summary"],
                },
            },
        }
        tools.append(final_answer_tool)

        bb_summary = _format_blackboard(blackboard)
        tools_summary = _format_tools()
        skills_guide = _get_skills_for_task(task_type)
        # 如果角色指定了技能覆盖，使用角色技能
        if skills_override:
            texts = []
            for name in skills_override.split(","):
                name = name.strip()
                if name:
                    content = get_skill_prompt(name)
                    if content:
                        texts.append(f"## {name}\n{content}")
            if texts:
                skills_guide = "\n\n".join(texts)
        system_prompt = OODA_SYSTEM_PROMPT.format(
            blackboard_summary=bb_summary,
            tools_summary=tools_summary,
            skills_guide=skills_guide,
        )

        llm_messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"请对 {target} 执行下一步操作。"},
        ]

        try:
            yield "[思考] 思考中...\n"
            log.info(f"Iter {iteration}: calling LLM for decision")

            resolved_model, llm_kwargs = _resolve_llm_kwargs(model)
            resp = await acompletion(
                model=resolved_model,
                messages=llm_messages,
                tools=tools,
                **llm_kwargs,
            )
        except Exception as e:
            yield f"[LLM失败] LLM 调用失败: {e}\n"
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                yield f"[中止] 连续 {MAX_CONSECUTIVE_FAILURES} 次失败，自动停止\n"
                break
            continue

        # 解析 LLM 输出
        msg = resp.choices[0].message
        text = msg.content or ""

        if text:
            yield f"[思考] {text}\n"

        tool_calls = _parse_tool_call(resp)
        if not tool_calls and not text:
            yield "[异常] LLM 未产生任何输出，重试...\n"
            consecutive_failures += 1
            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                break
            continue

        consecutive_failures = 0
        if not tool_calls:
            # LLM 只说了话没调工具，继续
            continue

        # === ACT: 执行工具调用 ===
        for tc in tool_calls[:MAX_TOOL_CALLS_PER_TURN]:
            if tc["name"] == "final_answer":
                yield "\n[完成] Agent 完成！\n"
                blackboard.goal_achieved = True
                summary = tc["arguments"].get("summary", "")
                flag = tc["arguments"].get("flag", "")
                if flag:
                    yield f"[Flag] {flag}\n"
                yield f"[摘要] {summary}\n"
                return

            yield f"[调用] {tc['name']}({json.dumps(tc['arguments'], ensure_ascii=False)})\n"

            try:
                result = await tool_registry.execute(tc["name"], tc["arguments"])
            except Exception as e:
                result = ToolResult.fail(f"工具执行异常: {e}")

            if result.success:
                yield f"[OK] {result.output[:500]}\n"
                reflexion_failures.pop(tc["name"], None)
                current_escalation = 0

                # === OBSERVE: 分析结果，添加 Facts ===
                _process_tool_result(blackboard, tc["name"], tc["arguments"], result)
                consecutive_failures = 0
            else:
                yield f"[失败] {result.error[:200]}\n"
                consecutive_failures += 1

                # Reflexion: 记录失败并递进
                fail_type = _classify_failure(tc["name"], result.error)
                reflexion_failures[tc["name"]] = reflexion_failures.get(tc["name"], 0) + 1
                if reflexion_failures[tc["name"]] >= 2:
                    current_escalation = min(current_escalation + 1, 4)
                    yield f"[Reflexion] 失败递进 L{current_escalation}: 换攻击面/混淆\n"

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES and not persistent_mode:
                    break

            # 检查目标是否已达成
            if blackboard.goal_achieved:
                yield "\n[完成] 目标已达成！\n"
                if persistent_mode:
                    yield "[报告] 周期报告已生成\n"
                return

    # 达到迭代上限
    if persistent_mode:
        yield f"\n[中止] 周期达到迭代上限 ({PERSISTENT_ROUNDS_PER_CYCLE}), 生成周期报告...\n"
        # 持久化模式: 序列化黑板状态 (简化: 输出最终状态)
        from services.report_service import generate_report
        report = generate_report(
            task_id=target[:8],
            target=target,
            task_type=task_type,
            findings=[f.to_dict() for f in blackboard.facts],
        )
        yield f"[报告] {report.get('path', '')}\n"
    yield f"\n[中止] 达到迭代上限，Agent 结束\n"
    yield f"\n[黑板] 最终黑板状态:\n"
    yield f"  Facts: {len(blackboard.facts)} 条\n"
    yield f"  Intents: {len(blackboard.intents)} 条 (待处理: {len(blackboard.get_pending_intents())})\n"

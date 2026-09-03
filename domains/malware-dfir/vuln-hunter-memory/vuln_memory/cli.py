"""vulnmem —— 四层记忆系统命令行。

Claude Code 在挖洞工作流中通过本 CLI 与记忆系统交互；所有需要"思考"
的命令只输出 prompt，Claude Code 自行执行后把结果回写对应 commit-* 命令。

用法:
  python -m vuln_memory.cli <cmd> [options]
  python vulnmem.py <cmd> [options]        # 等价入口

所有命令输出 JSON，便于 Claude Code 解析。
大段多行内容可用 --content "-" 从 stdin 读，或 --file PATH 读文件。

命令一览:
  add                写入原始观察到瞬时层
  classify           产出 LOP 深浅分级 prompt   (Claude Code 执行后调 commit-classify)
  commit-classify    回写带【LOW】【HIGH】标记的文本
  fusion             产出场景融合 prompt         (执行后调 commit-fusion)
  commit-fusion      回写场景摘要 -> 入短时层
  save-short         直接存一段短时记忆
  recall-short       短时向量召回
  distill            产出实体关系蒸馏 prompt     (执行后调 commit-kg)
  commit-kg          把蒸馏 JSON 数组写回图谱
  recall-long        长时图谱召回
  recall             短时+长时综合召回 -> 挖洞上下文
  reinforce          记忆强化：召回+强化摘要 prompt
  expire-clean       清理短时过期/衰减权重
  status             查看各层记忆状态
  save-state         保存挖洞项目工作流状态（断点续挖）
  load-state         载入上次保存的项目状态
  sessions          列出所有保存过状态的会话
"""
import argparse
import json
import os
import sys

# Windows 控制台默认 cp936，会破坏中文 I/O。强制 stdin/stdout 走 UTF-8。
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def _read_content(args):
    if getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8") as f:
            return f.read()
    if args.content == "-" or args.content is None:
        # 从 stdin 原始字节读，按 UTF-8 解码，避免 cp936 误码/代理字符
        raw = sys.stdin.buffer.read() if hasattr(sys.stdin, "buffer") else sys.stdin.read()
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return raw
    return args.content


def main(argv=None):
    p = argparse.ArgumentParser(prog="vulnmem", description="四层记忆系统 CLI")
    sp = p.add_subparsers(dest="cmd", required=True)

    def add_content(a, help="内容；'-' 读 stdin；默认 stdin"):
        a.add_argument("--content", help=help, default=None)
        a.add_argument("--file", help="从文件读内容", default=None)

    # add
    a = sp.add_parser("add", help="写入原始观察到瞬时层")
    a.add_argument("--session", required=True)
    a.add_argument("--role", default="user")
    add_content(a)
    a.add_argument("--img", help="视空画板多模态描述(可选)", default=None)
    a.set_defaults(fn=cmd_add)

    # classify
    a = sp.add_parser("classify", help="产出 LOP 深浅分级 prompt")
    a.add_argument("--session", required=True)
    a.set_defaults(fn=cmd_classify)

    # commit-classify
    a = sp.add_parser("commit-classify", help="回写分级标记文本")
    a.add_argument("--session", required=True)
    add_content(a, help="带【LOW】【HIGH】标记的文本")
    a.set_defaults(fn=cmd_commit_classify)

    # fusion
    a = sp.add_parser("fusion", help="产出场景融合 prompt")
    a.add_argument("--session", required=True)
    a.set_defaults(fn=cmd_fusion)

    # commit-fusion
    a = sp.add_parser("commit-fusion", help="回写场景摘要入短时层")
    a.add_argument("--session", required=True)
    add_content(a, help="场景摘要")
    a.set_defaults(fn=cmd_commit_fusion)

    # save-short
    a = sp.add_parser("save-short", help="直接存短时记忆")
    a.add_argument("--session", default="default")
    add_content(a)
    a.set_defaults(fn=cmd_save_short)

    # recall-short
    a = sp.add_parser("recall-short", help="短时向量召回")
    a.add_argument("--query", required=True)
    a.add_argument("--top-k", type=int, default=3)
    a.add_argument("--session", default=None)
    a.set_defaults(fn=cmd_recall_short)

    # distill
    a = sp.add_parser("distill", help="产出实体关系蒸馏 prompt")
    a.set_defaults(fn=cmd_distill)

    # commit-kg
    a = sp.add_parser("commit-kg", help="把蒸馏 JSON 数组写回图谱")
    add_content(a, help="实体关系 JSON 数组")
    a.set_defaults(fn=cmd_commit_kg)

    # recall-long
    a = sp.add_parser("recall-long", help="长时图谱召回")
    a.add_argument("--query", required=True)
    a.set_defaults(fn=cmd_recall_long)

    # recall (combined)
    a = sp.add_parser("recall", help="短时+长时综合召回 -> 挖洞上下文")
    a.add_argument("--session", required=True)
    a.add_argument("--query", required=True)
    a.add_argument("--top-k", type=int, default=3)
    a.set_defaults(fn=cmd_recall)

    # reinforce
    a = sp.add_parser("reinforce", help="记忆强化：召回+强化摘要 prompt")
    a.add_argument("--query", required=True)
    a.set_defaults(fn=cmd_reinforce)

    # expire-clean
    a = sp.add_parser("expire-clean", help="清理短时过期+衰减权重")
    a.set_defaults(fn=cmd_expire_clean)

    # status
    a = sp.add_parser("status", help="查看各层记忆状态")
    a.add_argument("--session", required=True)
    a.set_defaults(fn=cmd_status)

    # save-state
    a = sp.add_parser("save-state", help="保存挖洞项目工作流状态")
    a.add_argument("--session", required=True)
    add_content(a, help="项目状态 JSON 对象")
    a.set_defaults(fn=cmd_save_state)

    # load-state
    a = sp.add_parser("load-state", help="载入上次保存的项目状态")
    a.add_argument("--session", required=True)
    a.set_defaults(fn=cmd_load_state)

    # sessions
    a = sp.add_parser("sessions", help="列出所有保存过状态的会话")
    a.set_defaults(fn=cmd_sessions)

    args = p.parse_args(argv)
    out = args.fn(args)
    print(json.dumps(out, ensure_ascii=False, indent=2))


# ---------------------- 命令实现 ----------------------
def _agent(session):
    from .agent import HumanLikeMemoryAgent
    return HumanLikeMemoryAgent(session)


def cmd_add(a):
    ag = _agent(a.session)
    return ag.observe(a.role, _read_content(a), img_info=a.img)


def cmd_classify(a):
    return _agent(a.session).classify()


def cmd_commit_classify(a):
    return _agent(a.session).commit_classify(_read_content(a))


def cmd_fusion(a):
    return _agent(a.session).fusion()


def cmd_commit_fusion(a):
    return _agent(a.session).commit_fusion(_read_content(a))


def cmd_save_short(a):
    from .shortterm import ShortTermMem
    return ShortTermMem().save_memory(_read_content(a), session=a.session)


def cmd_recall_short(a):
    from .shortterm import ShortTermMem
    return ShortTermMem().recall_memory(a.query, top_k=a.top_k, session=a.session)


def cmd_distill(a):
    from .longterm import LongTermMem
    return LongTermMem().distill_prompt()


def cmd_commit_kg(a):
    from .longterm import LongTermMem
    return LongTermMem().commit_kg(_read_content(a))


def cmd_recall_long(a):
    from .longterm import LongTermMem
    return LongTermMem().kg_recall(a.query)


def cmd_recall(a):
    return _agent(a.session).recall(a.query, top_k=a.top_k)


def cmd_reinforce(a):
    from .longterm import LongTermMem
    return LongTermMem().reinforce(a.query)


def cmd_expire_clean(a):
    from .shortterm import ShortTermMem
    s = ShortTermMem()
    s.auto_expire_clean()
    s.decay_weights()
    return {"expired_cleaned": True, "remaining": len(s.all_contents())}


def cmd_status(a):
    return _agent(a.session).status()


def cmd_save_state(a):
    import json as _json
    raw = _read_content(a)
    try:
        state = _json.loads(raw)
    except Exception as e:
        return {"ok": False, "error": f"需为 JSON 对象: {e}"}
    return _agent(a.session).save_state(state)


def cmd_load_state(a):
    return _agent(a.session).load_state()


def cmd_sessions(a):
    from .backends import ProjectStore
    return {"sessions": ProjectStore().list_sessions()}


if __name__ == "__main__":
    main()

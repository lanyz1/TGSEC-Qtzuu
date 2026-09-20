"""Forge · 载荷拼接器核心引擎。与 UI 解耦，可单独 import。"""

try:
    import yaml as _yaml  # noqa: F401
except ImportError:
    # 用 SystemExit 而不是让 ModuleNotFoundError 冒上去：使用者看到的第一屏
    # 应该是「装什么」而不是一串 traceback。这是给人用的工具，不是库。
    raise SystemExit(
        "缺少依赖 PyYAML。装一条命令即可：\n"
        "\n"
        "    pip install pyyaml\n"
        "\n"
        "本工具只依赖这一个包。"
    ) from None

from .engine import (  # noqa: F401
    DEFAULTS,
    RuleError,
    filter_templates,
    generate,
    load_rules,
    make_state,
    relax_suggestions,
    version_match,
)

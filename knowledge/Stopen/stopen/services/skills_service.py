"""技能系统"""
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"


def get_skill_prompt(skill_name: str) -> str:
    """读取技能文件内容"""
    path = SKILLS_DIR / f"{skill_name}.md"
    if path.exists():
        return path.read_text(encoding="utf-8")
    return ""


def list_all_skills() -> list[str]:
    if not SKILLS_DIR.exists():
        return []
    return sorted(f.stem for f in SKILLS_DIR.glob("*.md"))

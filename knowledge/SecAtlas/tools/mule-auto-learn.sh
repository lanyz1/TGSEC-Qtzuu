#!/bin/bash
# mule-auto-learn — 黑骡自动学习器
# 从SecAtlas仓库提取新知，更新本地知识库

set -e
LOCAL_REPO="/tmp/SecAtlas"
HERMES_ROOT="/root/.hermes"

cd "$LOCAL_REPO"
git pull origin main -q 2>/dev/null

echo "🧠 黑骡自动学习器"

# === 同步技术卡到本地 ===
new_tech=0
for cat_dir in blackmule/techniques/*/; do
    cat_name=$(basename "$cat_dir")
    mkdir -p "$HERMES_ROOT/techniques/$cat_name"
    for f in "$cat_dir"*.yaml; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        if [ ! -f "$HERMES_ROOT/techniques/$cat_name/$base" ]; then
            cp "$f" "$HERMES_ROOT/techniques/$cat_name/$base"
            new_tech=$((new_tech + 1))
        fi
    done
done

# === 同步案例到本地 ===
new_cases=0
for case_dir in blackmule/cases/*/; do
    type_name=$(basename "$case_dir")
    mkdir -p "$HERMES_ROOT/cases/$type_name"
    for f in "$case_dir"*.yaml; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        if [ ! -f "$HERMES_ROOT/cases/$type_name/$base" ]; then
            cp "$f" "$HERMES_ROOT/cases/$type_name/$base"
            new_cases=$((new_cases + 1))
        fi
    done
done

# === 提取指纹规则更新 pentest-cases skill ===
# 从所有案例中提取 fingerprint_triggers
echo "--- 指纹规则提取 ---"
python3 -c "
import yaml, os, glob

triggers = []
for f in glob.glob('$LOCAL_REPO/blackmule/cases/**/*.yaml', recursive=True):
    try:
        with open(f) as fh:
            data = yaml.safe_load(fh)
            if data and 'fingerprint_triggers' in data:
                for t in data['fingerprint_triggers']:
                    if t not in triggers:
                        triggers.append(t)
    except:
        pass

print(f'共提取 {len(triggers)} 条指纹规则')
for t in triggers[-5:]:
    print(f'  - {t}')
" 2>/dev/null || echo "  (无新规则)"

# === 学习统计 ===
tech_count=$(find "$HERMES_ROOT/techniques" -name '*.yaml' 2>/dev/null | wc -l)
case_count=$(find "$HERMES_ROOT/cases" -name '*.yaml' 2>/dev/null | wc -l)

echo ""
echo "=== 本地知识库 ==="
echo "  技术卡: $tech_count 张 (新增 $new_tech)"
echo "  案例:   $case_count 份 (新增 $new_cases)"

if [ $new_tech -gt 0 ] || [ $new_cases -gt 0 ]; then
    echo "🎉 学完了新知识!"
else
    echo "✅ 知识库已最新"
fi

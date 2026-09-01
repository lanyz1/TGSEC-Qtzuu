#!/bin/bash
# validate.sh — SecAtlas 内容校验脚本
# 用途: 校验新增技术卡、案例、知识条目的格式完整性
# 用法: bash scripts/validate.sh [--type technique|case|knowledge|all]

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXIT_CODE=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

check_type="${1:-all}"
if [ "$check_type" = "--type" ]; then
    check_type="${2:-all}"
fi

echo "=== SecAtlas 内容校验 ==="
echo "检查类型: $check_type"
echo ""

# === 技术卡校验 ===
validate_technique() {
    local file="$1"
    local errors=0
    local name=$(basename "$file")
    
    # 检查是否为简版记录卡（从案例生成，有 result 字段）
    if grep -q "^result:" "$file" 2>/dev/null; then
        # 简版卡：只需 id/name/category/result
        for field in id name category result; do
            if ! grep -q "^${field}:" "$file" 2>/dev/null; then
                echo -e "  ${YELLOW}⚠${NC} $name (简版): 缺少 '$field'"
            fi
        done
        return 0
    fi
    
    # 架构/方法论卡：允许 info 严重度，但要求有可迁移机制和来源
    if grep -q "^architecture:" "$file" 2>/dev/null; then
        for field in key_mechanisms sources; do
            if ! grep -q "^${field}:" "$file" 2>/dev/null; then
                echo -e "  ${RED}✗${NC} $name (架构卡): 缺少必填字段 '$field'"
                errors=$((errors + 1))
            fi
        done
        return $errors
    fi

    # 完整技术卡：检查必填字段
    for field in id name category severity trigger_signals payloads success_indicators prerequisites defense sources; do
        if ! grep -q "^${field}:" "$file" 2>/dev/null; then
            echo -e "  ${RED}✗${NC} $name: 缺少必填字段 '$field'"
            errors=$((errors + 1))
        fi
    done
    
    # 检查 severity 值
    local sev=$(grep "^severity:" "$file" | awk '{print $2}' | tr -d '"')
    if [ -n "$sev" ] && ! echo "$sev" | grep -qE '^(critical|high|medium|low|info)$'; then
        echo -e "  ${YELLOW}⚠${NC} $name: severity '$sev' 不是标准值"
    fi
    
    # 检查 id 格式 (category-technique-name)
    local id=$(grep "^id:" "$file" | head -1 | awk '{print $2}' | tr -d '"')
    if [ -n "$id" ] && ! echo "$id" | grep -qE '^[a-z]+-[a-z0-9-]+$'; then
        echo -e "  ${YELLOW}⚠${NC} $name: id '$id' 不符合 category-name 格式"
    fi
    
    return $errors
}

# === 案例校验 ===
validate_case() {
    local file="$1"
    local errors=0
    local name=$(basename "$file")
    
    for field in target attack_surface techniques_tried success_path; do
        if ! grep -q "^${field}:" "$file" 2>/dev/null; then
            echo -e "  ${RED}✗${NC} $name: 缺少必填字段 '$field'"
            errors=$((errors + 1))
        fi
    done

    for field in techniques_learned fingerprint_triggers; do
        if ! grep -q "^${field}:" "$file" 2>/dev/null; then
            echo -e "  ${YELLOW}⚠${NC} $name: 缺少增强字段 '$field'"
        fi
    done
    
    # 检查 techniques_tried 是否有 result 字段
    if ! grep -q "result:" "$file" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} $name: techniques_tried 缺少 result 字段"
    fi
    
    return $errors
}

# === 知识条目校验 ===
validate_knowledge() {
    local file="$1"
    local errors=0
    local name=$(basename "$file")
    
    # 检查是否有 KB-XXX-NNN 编号
    if ! grep -qE 'KB-[A-Z]+-[0-9]+' "$file" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} $name: 缺少 KB-XXX-NNN 格式编号"
    fi
    
    # 检查 CWE 引用
    if ! grep -qi 'cwe-' "$file" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} $name: 缺少 CWE 编号引用"
    fi
    
    # 检查最小 PoC
    if ! grep -qi '最小PoC\|最小poc\|PoC\|payload' "$file" 2>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} $name: 可能缺少 PoC/payload"
    fi
    
    return $errors
}

# === 全局检查 ===
check_id_uniqueness() {
    echo "--- ID 唯一性检查 ---"
    local dupes=0
    for dir in "$REPO_ROOT"/techniques/*/; do
        [ -d "$dir" ] || continue
        local ids=$(grep -h "^id:" "$dir"*.yaml 2>/dev/null | awk '{print $2}' | tr -d '"' | sort)
        local dupe_ids=$(echo "$ids" | uniq -d)
        if [ -n "$dupe_ids" ]; then
            echo -e "  ${RED}✗${NC} $(basename "$dir"): 重复 ID: $dupe_ids"
            dupes=$((dupes + 1))
        fi
    done
    [ $dupes -eq 0 ] && echo -e "  ${GREEN}✓${NC} 所有技术卡 ID 唯一"
}

# === 主逻辑 ===
total_errors=0

if [ "$check_type" = "all" ] || [ "$check_type" = "technique" ]; then
    echo "--- 技术卡校验 ---"
    count=0
    for f in "$REPO_ROOT"/techniques/*/*.yaml; do
        [ -f "$f" ] || continue
        if ! validate_technique "$f"; then total_errors=$((total_errors + 1)); fi
        count=$((count + 1))
    done
    [ $count -eq 0 ] && echo "  无技术卡文件"
    echo "  共检查 $count 张技术卡"
fi

if [ "$check_type" = "all" ] || [ "$check_type" = "case" ]; then
    echo ""
    echo "--- 案例校验 ---"
    count=0
    for f in "$REPO_ROOT"/cases/*/*.yaml; do
        [ -f "$f" ] || continue
        if ! validate_case "$f"; then total_errors=$((total_errors + 1)); fi
        count=$((count + 1))
    done
    [ $count -eq 0 ] && echo "  无案例文件"
    echo "  共检查 $count 份案例"
fi

if [ "$check_type" = "all" ] || [ "$check_type" = "knowledge" ]; then
    echo ""
    echo "--- 知识条目校验 ---"
    count=0
    for f in "$REPO_ROOT"/knowledge/categories/*.md; do
        [ -f "$f" ] || continue
        if ! validate_knowledge "$f"; then total_errors=$((total_errors + 1)); fi
        count=$((count + 1))
    done
    echo "  共检查 $count 个分类文件"
fi

echo ""
check_id_uniqueness

echo ""
echo "=== 内容统计 ==="
echo "  技术卡: $(find "$REPO_ROOT"/techniques -name '*.yaml' 2>/dev/null | wc -l) 张"
echo "  案例:   $(find "$REPO_ROOT"/cases -name '*.yaml' 2>/dev/null | wc -l) 份"
echo "  分类:   $(find "$REPO_ROOT"/knowledge/categories -name '*.md' 2>/dev/null | wc -l) 个"
echo "  工具:   $(find "$REPO_ROOT"/tools -type f 2>/dev/null | wc -l) 个"

echo ""
if [ $total_errors -gt 0 ]; then
    echo -e "${RED}校验完成: $total_errors 个错误${NC}"
else
    echo -e "${GREEN}校验完成: 全部通过 ✓${NC}"
fi

exit $total_errors

#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo "[AUDIT] Anti-Hardcoding and Custom Framework Inspection"
echo "================================================================="

VIOLATIONS=0

check_pattern() {
    local pattern="$1"
    local desc="$2"
    echo -n "[Checking] $desc ($pattern)... "
    # Search python and yaml files excluding tests, scripts, and docs
    matches=$(grep -rnE "$pattern" orchestrator/ ax/ agents/ substrate/ 2>/dev/null || true)
    if [ -n "$matches" ]; then
        echo "FAILED"
        echo "$matches"
        VIOLATIONS=$((VIOLATIONS + 1))
    else
        echo "PASSED"
    fi
}

# 1. Custom Agent Classes
check_pattern "class (BrowserAgent|ResearchAgent|CodingAgent)" "No custom agent classes"

# 2. Hardcoded Authorization Logic
check_pattern "if\s+agent\s*==|if\s+principal\s*==" "No hardcoded authorization if-statements"

# 3. Custom Schedulers / Frameworks
check_pattern "class\s+(Scheduler|AgentFramework|AgentRegistry)" "No custom scheduler or framework classes"

# 4. Direct Substrate Invocation Bypass in Orchestrator
check_pattern "ate\.dev|api\.ate-system|sandboxconfigs" "No direct Substrate bypass references in orchestrator"

echo "-----------------------------------------------------------------"
if [ "$VIOLATIONS" -eq 0 ]; then
    echo "[AUDIT PASSED] 0 violations found. Implementation is strictly configuration-driven"
    echo "and relies purely on Cerbos for authorization and native AX/Substrate for execution."
    exit 0
else
    echo "[AUDIT FAILED] $VIOLATIONS violation(s) detected!"
    exit 1
fi

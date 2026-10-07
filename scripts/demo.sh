#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo " REFERENCE ARCHITECTURE DEMO: AUTHORIZATION AT RUNTIME BOUNDARY "
echo "================================================================="

echo ""
echo "#################################################################"
echo " PATH A: AUTHORIZED EXECUTION (Browser Agent)"
echo " User Task: 'Visit website and extract title'"
echo " Principal: 'orchestrator-agent' -> Agent: 'browser-agent'"
echo " Expected:  Cerbos = ALLOW -> AX = ACCEPTED -> Substrate Worker"
echo "#################################################################"
PYTHONPATH=. python3 orchestrator/orchestrator.py "Visit website and extract title"

echo ""
echo "#################################################################"
echo " PATH B: DENIED EXECUTION (Restricted Agent)"
echo " User Task: 'Execute privileged secret task'"
echo " Principal: 'orchestrator-agent' -> Agent: 'restricted-agent'"
echo " Expected:  Cerbos = DENY -> AX = REJECTED -> ZERO Workloads"
echo "#################################################################"
PYTHONPATH=. python3 orchestrator/orchestrator.py "Execute privileged secret task"

echo ""
echo ">> Verifying zero workloads created in AX/Substrate for denied request:"
ACTIVE_TASKS=$(./bin/ax get tasks | wc -l)
if [ "$ACTIVE_TASKS" -le 1 ]; then
    echo "[+] CONFIRMED: Substrate active task count is 0. Zero workloads materialized."
else
    echo "[-] WARNING: Unexpected tasks found in AX."
fi

echo ""
echo "#################################################################"
echo " PATH C: DYNAMIC AGENT SELECTION (Research Agent)"
echo " User Task: 'Research topic and gather intel'"
echo " Principal: 'orchestrator-agent' -> Agent: 'research-agent'"
echo " Expected:  Dynamic selection without orchestration code change"
echo "#################################################################"
PYTHONPATH=. python3 orchestrator/orchestrator.py "Research topic and gather intel"

echo ""
echo "================================================================="
echo " DEMO COMPLETED SUCCESSFULLY "
echo "================================================================="

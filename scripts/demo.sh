#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo " REFERENCE ARCHITECTURE DEMO: TWO-LAYER AGENT & TOOL AUTHORIZATION"
echo "================================================================="

echo ""
echo "#################################################################"
echo " [LAYER 1] GATE 1: WORKLOAD ADMISSION EVALUATION"
echo " User Task: 'Execute privileged secret task'"
echo " Principal: 'orchestrator-agent' -> Agent: 'restricted-agent'"
echo " Expected:  Cerbos = DENY -> AX = REJECTED -> ZERO Workloads"
echo "#################################################################"
PYTHONPATH=. python3 orchestrator/orchestrator.py "Execute privileged secret task" || true

echo ""
echo "#################################################################"
echo " [LAYER 2] GATE 2: GOVERNED TOOL INVOCATION (Approved Navigation)"
echo " Running Agent: 'browser-agent' (browser-worker)"
echo " Tool: 'browser_navigate' -> Destination: 'http://localhost:8089'"
echo " Expected: Tool Gateway PEP validates URL, Cerbos = ALLOW -> Page Scraped"
echo "#################################################################"
PYTHONPATH=. python3 agents/browser_cli.py --url http://localhost:8089

echo ""
echo "#################################################################"
echo " [LAYER 2] GATE 2: ADVERSARIAL SSRF DEFENSE (Unapproved Host)"
echo " Running Agent: 'browser-agent'"
echo " Tool: 'fetch_url' -> Destination: 'http://evil-attacker.com:8089'"
echo " Expected: Gateway pre-validates host allowlist -> REJECTED_PEP"
echo " Invariant: ZERO outbound network calls made"
echo "#################################################################"
PYTHONPATH=. python3 -c '
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest

gateway = ToolGatewayPEP()
ctx = TaskExecutionContext(task_id="demo-task-01", agent_id="browser-agent", roles=["browser-worker"]).sign()
req = ToolInvocationRequest("demo-ssrf-01", ctx, "fetch_url", "request", {"url": "http://evil-attacker.com:8089", "method": "GET"})
res = gateway.invoke(req)
print(f"Decision: {res.decision} (Code: {res.code})")
print(f"Error:    {res.error}")
print(f"Outbound network calls made: {gateway.network_call_count}")
assert gateway.network_call_count == 0
'

echo ""
echo "#################################################################"
echo " [LAYER 2] GATE 2: ADVERSARIAL SSRF DEFENSE (Cloud Metadata IP)"
echo " Running Agent: 'browser-agent'"
echo " Tool: 'fetch_url' -> Destination: 'http://169.254.169.254/latest/meta-data/'"
echo " Expected: Gateway rejects link-local metadata IP -> REJECTED_PEP"
echo " Invariant: ZERO outbound network calls made"
echo "#################################################################"
PYTHONPATH=. python3 -c '
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest

gateway = ToolGatewayPEP()
ctx = TaskExecutionContext(task_id="demo-task-02", agent_id="browser-agent", roles=["browser-worker"]).sign()
req = ToolInvocationRequest("demo-meta-01", ctx, "fetch_url", "request", {"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"})
res = gateway.invoke(req)
print(f"Decision: {res.decision} (Code: {res.code})")
print(f"Error:    {res.error}")
print(f"Outbound network calls made: {gateway.network_call_count}")
assert gateway.network_call_count == 0
'

echo ""
echo "#################################################################"
echo " [LAYER 2] GATE 2: FILESYSTEM CONTAINMENT (Directory Traversal)"
echo " Running Agent: 'browser-agent'"
echo " Tool: 'filesystem_write' -> Path: '../../etc/shadow'"
echo " Expected: Canonical containment fails -> REJECTED_PEP"
echo " Invariant: ZERO filesystem mutations made"
echo "#################################################################"
PYTHONPATH=. python3 -c '
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest

gateway = ToolGatewayPEP()
ctx = TaskExecutionContext(task_id="demo-task-03", agent_id="browser-agent", roles=["browser-worker"]).sign()
req = ToolInvocationRequest("demo-fs-01", ctx, "filesystem_write", "write", {"path": "../../etc/shadow", "content": "attack"})
res = gateway.invoke(req)
print(f"Decision: {res.decision} (Code: {res.code})")
print(f"Error:    {res.error}")
print(f"Filesystem writes made: {gateway.filesystem_write_count}")
assert gateway.filesystem_write_count == 0
'

echo ""
echo "#################################################################"
echo " [LAYER 2] GATE 2: AGENT CAPABILITY GATE (Restricted Agent)"
echo " Running Agent: 'restricted-agent'"
echo " Tool: 'fetch_url' -> Catalog allowed_tools: []"
echo " Expected: Catalog capability gate blocks tool -> CATALOG_DENIED"
echo "#################################################################"
PYTHONPATH=. python3 -c '
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest

gateway = ToolGatewayPEP()
ctx = TaskExecutionContext(task_id="demo-task-04", agent_id="restricted-agent", roles=["restricted-worker"]).sign()
req = ToolInvocationRequest("demo-cap-01", ctx, "fetch_url", "request", {"url": "http://localhost:8089", "method": "GET"})
res = gateway.invoke(req)
print(f"Decision: {res.decision} (Code: {res.code})")
print(f"Error:    {res.error}")
assert res.code == "CATALOG_DENIED"
'

echo ""
echo "================================================================="
echo " DUAL-LAYER DEMO COMPLETED SUCCESSFULLY "
echo "================================================================="

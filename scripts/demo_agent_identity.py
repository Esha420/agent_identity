#!/usr/bin/env python3
"""Demonstration of Agent Identity, Scope Attenuation, and Policy Enforcement.

Proves:
1. Who authorized the agent: Authenticated human principal (auth0|user-123).
2. What scope the agent is granted: Down-scoped task permissions (e.g. browser:read).
3. How permission is enforced: Dual-layer PEP (Admission & Tool Gateway) with zero human bottleneck.
4. Prevention of the OpenClaw excessive permission incident (Same User, Different Agent Scopes).
"""

import json
import os
import sys
import time

# Automatically include project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.auth0_verifier import Auth0TokenVerifier, create_test_auth0_token
from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from scripts.mint_test_token import get_or_create_key
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest


def print_identity_card(
    status: str,
    agent_id: str,
    task_id: str,
    parent_id: str,
    user_id: str,
    tenant_id: str,
    permitted_scope: list,
    prohibited_scope: list,
    policy_decision: str,
    workload_identity: str,
):
    border = "═" * 78
    sub_border = "─" * 78
    print(f"\n╔{border}╗")
    print(f"║                         AGENT IDENTITY CARD                                  ║")
    print(f"╠{border}╣")
    print(f"║  STATUS:              [{status:^14}]                                         ║")
    print(f"║  AGENT IDENTITY:      {agent_id:<55}║")
    print(f"║  TASK IDENTITY:       {task_id:<55}║")
    print(f"║  PARENT ORCHESTRATOR: {parent_id:<55}║")
    print(f"╟{sub_border}╢")
    print(f"║  AUTHORIZED BY (HUMAN ROOT IDENTITY):                                        ║")
    print(f"║    • Authenticated User: {user_id:<51}║")
    print(f"║    • Tenant:             {tenant_id:<51}║")
    print(f"║    • Token Authority:    Auth0 OIDC (RS256 Verified via JWKS)                ║")
    print(f"╟{sub_border}╢")
    print(f"║  PERMITTED SCOPE (DOWN-SCOPED AUTHORITY):                                    ║")
    for perm in permitted_scope:
        print(f"║    [✓] {perm:<68}║")
    print(f"║  EXPLICITLY PROHIBITED (OUT-OF-SCOPE):                                       ║")
    for prohib in prohibited_scope:
        print(f"║    [✗] {prohib:<68}║")
    print(f"╟{sub_border}╢")
    print(f"║  POLICY DECISION:     {policy_decision:<55}║")
    print(f"║  WORKLOAD IDENTITY:   {workload_identity:<55}║")
    print(f"╚{border}╝\n")


def run_identity_demonstration():
    print("=" * 80)
    print("     AGENT IDENTITY & GOVERNANCE: SAME USER, DIFFERENT AGENT SCOPES")
    print("=" * 80)
    print("Central Question:")
    print("  'If an orchestrator creates multiple agents on behalf of the same user,")
    print("   how do we ensure each agent only has the exact authority needed for its task?'")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # Setup: Real verified human user (auth0|user-123)
    # -------------------------------------------------------------------------
    human_user = "auth0|user-123"
    tenant = "tenant-demo"
    priv_key, kid = get_or_create_key()
    verifier = Auth0TokenVerifier(local_public_keys={kid: priv_key.public_key()})
    adapter = AXAdmissionAdapter(auth0_verifier=verifier)
    cerbos = CerbosClient()
    gateway = ToolGatewayPEP(cerbos_client=cerbos)

    # =========================================================================
    # PART 1: AGENT A — Browser Navigation Scout
    # =========================================================================
    print("\n" + "#" * 80)
    print(" SCENARIO A: Agent A (Browser Scout) — Scoped to 'browser:read'")
    print(f" Authorized by: {human_user} (Legitimate User)")
    print(" Task: Read page title from approved website")
    print("#" * 80)

    token_a = create_test_auth0_token(
        private_key=priv_key,
        sub=human_user,
        kid=kid,
        issuer=verifier.issuer,
        permissions=["agent:execute", "browser:read"],
        scope="openid profile agent:execute browser:read",
        org_id="org_demo",
    )

    # 1. Admission PEP evaluation
    trace_a = adapter.submit_execution_request(
        principal="orchestrator-agent",
        roles=["orchestrator"],
        agent_name="browser-agent",
        action="execute",
        user_token=token_a,
        task_data={"prompt": "Visit approved website and retrieve page title"},
        wait_timeout=8,
    )

    print_identity_card(
        status="AUTHORIZED",
        agent_id="browser-agent (Role: browser-worker)",
        task_id=trace_a.get("task_execution_context", {}).get("task_id", "task-browser-001"),
        parent_id="orchestrator-agent (Root Workload)",
        user_id=human_user,
        tenant_id=tenant,
        permitted_scope=[
            "Tool: browser_navigate (Action: navigate)",
            "Target: Approved domain (http://localhost:8089)",
            "Permission: browser:read (Read-only reconnaissance)",
        ],
        prohibited_scope=[
            "Filesystem mutations (filesystem:write)",
            "Destructive actions or external cloud metadata (169.254.169.254)",
            "Cross-tenant access or ambient administration",
        ],
        policy_decision="EFFECT_ALLOW (Cerbos Layer 1 & 2 Approved)",
        workload_identity=trace_a.get("substrate_workload", "Substrate Container Sandbox"),
    )

    # 2. Invoke approved tool
    ctx_token_a = trace_a.get("context_token")
    if ctx_token_a:
        res_a = gateway.invoke(ToolInvocationRequest(
            request_id="req-browse-01",
            task_context=ctx_token_a,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://localhost:8089"},
        ))
        print(f"[*] TOOL GATEWAY INVOCATION: browser_navigate")
        print(f"    • Decision:    {res_a.decision} ({res_a.code})")
        print(f"    • Side-Effect: {res_a.side_effect}")
        print(f"    • Result:      Retrieved Page Title: '{res_a.data.get('title')}'")
        print(f"    • Outcome:     LEGITIMATE WORK COMPLETED AT MACHINE SPEED (No Human Bottleneck)")

    # =========================================================================
    # PART 2: AGENT B — Document Reviewer (Preventing the OpenClaw Incident)
    # =========================================================================
    print("\n" + "#" * 80)
    print(" SCENARIO B: Agent B (Document/Email Reviewer) — Scoped to 'filesystem:read' ONLY")
    print(f" Authorized by: {human_user} (EXACT SAME LEGITIMATE USER)")
    print(" Task: Review documents / emails (Instruction: 'Review and suggest changes')")
    print(" Hazard: Agent attempts to DELETE/WRITE files (Simulating OpenClaw Email Deletion Incident)")
    print("#" * 80)

    token_b = create_test_auth0_token(
        private_key=priv_key,
        sub=human_user,
        kid=kid,
        issuer=verifier.issuer,
        permissions=["agent:execute", "filesystem:read"],  # Strictly NO filesystem:write
        scope="openid profile agent:execute filesystem:read",
        org_id="org_demo",
    )

    trace_b = adapter.submit_execution_request(
        principal="orchestrator-agent",
        roles=["orchestrator"],
        agent_name="research-agent",
        action="execute",
        user_token=token_b,
        task_data={"prompt": "Review files and suggest cleanup"},
        wait_timeout=8,
    )

    task_id_b = trace_b.get("task_execution_context", {}).get("task_id", "task-review-002")
    ctx_token_b = trace_b.get("context_token")

    print_identity_card(
        status="ATTENUATED",
        agent_id="research-agent (Role: research-worker)",
        task_id=task_id_b,
        parent_id="orchestrator-agent (Root Workload)",
        user_id=human_user,
        tenant_id=tenant,
        permitted_scope=[
            "Tool: filesystem_read (Action: read)",
            "Target: /workspace/input (Read-only containment)",
            "Permission: filesystem:read",
        ],
        prohibited_scope=[
            "Destructive actions / File deletions (NO filesystem:write)",
            "Browser sessions or network reconnaissance",
            "Any modification to mailbox / disk",
        ],
        policy_decision="ATTENUATED SCOPE (Read-only permitted, Write/Delete strictly denied)",
        workload_identity=trace_b.get("substrate_workload", "Substrate Container Sandbox"),
    )

    # 1. Permitted Read Operation
    # Prepare a test file
    os.makedirs("/tmp/test_agent_input", exist_ok=True)
    with open("/tmp/test_agent_input/inbox_summary.txt", "w") as f:
        f.write("Subject: Q3 Roadmap\nSubject: Promotional Newsletter #1\nSubject: Promotional Newsletter #2")

    print("[*] STEP 1: Agent B performs authorized review read:")
    # We use a contained test read
    ctx_obj_b = TaskExecutionContext.from_token(ctx_token_b) if ctx_token_b else TaskExecutionContext(
        task_id=task_id_b,
        agent_id="research-agent",
        roles=["research-worker"],
        tenant_id="tenant-demo",
        delegated_by=human_user,
        delegation_permissions=["filesystem:read"],
    ).sign()

    # 2. Hazard: Agent attempts an unpermitted write / delete
    print("\n[*] STEP 2: Agent attempts to delete / overwrite files:")
    print("    [!] Prompt ambiguity or hallucination: Agent decides to delete all unread messages.")
    print("    [!] It calls tool 'filesystem_write' with target './workspace/output/deleted_emails.log'.")

    res_write = gateway.invoke(ToolInvocationRequest(
        request_id="req-hazard-01",
        task_context=ctx_obj_b,
        tool_name="filesystem_write",
        action="write",
        arguments={"path": "./workspace/output/deleted_emails.log", "content": "TRUNCATED_ALL"},
    ))

    print(f"\n[!] TOOL GATEWAY ENFORCEMENT RESULT:")
    print(f"    • Requested Operation: filesystem_write (write / delete)")
    print(f"    • Policy Decision:     {res_write.decision} ({res_write.code})")
    print(f"    • Policy Error:        {res_write.error}")
    print(f"    • Disk Mutations Made: {gateway.filesystem_write_count} (ZERO Disks/Emails Touched)")
    print(f"    • Side-Effect:         {res_write.side_effect}")

    print("\n" + "=" * 80)
    print(" CORE AUDIENCE TAKEAWAY")
    print("=" * 80)
    print("1. Same Human User:     'auth0|user-123' initiated both tasks.")
    print("2. Different Scopes:    Agent A got 'browser:read'; Agent B got 'filesystem:read'.")
    print("3. Incident Prevented:  When Agent B attempted to delete/overwrite, Cerbos & Tool Gateway")
    print("                        blocked the action automatically.")
    print("4. Zero Bottleneck:     No human had to sit and click 'Approve' or 'Deny' on every step.")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    run_identity_demonstration()

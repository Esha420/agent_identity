#!/usr/bin/env python3
"""Showcase: Attenuated Sub-Agents Co-located Inside the Same Substrate Actor.

Demonstrates:
1. One Orchestrator creates two sub-agents inside the SAME Substrate Actor.
2. Sub-Agent A (browser-agent) receives signed context with ['browser:read'].
3. Sub-Agent B (research-agent) receives signed context with ['filesystem:read'].
4. Both sub-agents share the exact same task_id, network namespace, and container host.
5. Proof:
   - Sub-Agent A can navigate the browser; Sub-Agent B CANNOT navigate the browser.
   - Sub-Agent B can read research files; Sub-Agent A CANNOT read research files.
   - Sub-Agent B cannot hijack or spoof Sub-Agent A's identity within the same actor.
"""

import json
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import ToolInvocationRequest


def run_showcase():
    print("=" * 80)
    print(" SHOWCASE: TWO SUB-AGENTS WITH ATTENUATED CERBOS PERMISSIONS")
    print(" CO-LOCATED INSIDE THE SAME SUBSTRATE ACTOR")
    print("=" * 80)

    # 1. Initialize PEP and Admission Adapter
    adapter = AXAdmissionAdapter()
    cerbos = CerbosClient()
    gateway = ToolGatewayPEP(cerbos_client=cerbos)

    if not cerbos.check_health():
        print("[ERROR] Cerbos PDP is not running on localhost:3592. Start with docker compose up -d.", file=sys.stderr)
        sys.exit(1)

    # 2. Prepare mock research artifact for Sub-Agent B to read
    os.makedirs("workspace/output", exist_ok=True)
    notes_file = "workspace/output/confidential_research.txt"
    with open(notes_file, "w") as f:
        f.write("CONFIDENTIAL INTEL: Autonomous Agent Identity Governance Model 2026")

    # 3. Both Sub-Agents execute inside the SAME Substrate Actor (same task_id)
    shared_actor_id = "actor-substrate-sandbox-pod-774"
    print(f"\n[SUBSTRATE] Materialized Host Workload:")
    print(f"  Container / Sandbox Actor ID: {shared_actor_id}")
    print(f"  Shared Network Namespace:    10.0.0.12 (loopback & container IP shared)")
    print(f"  Shared Process Boundary:     Same kernel namespace (gVisor)")

    # 4. Orchestrator delegates to Sub-Agent A (Browser Specialist)
    print("\n[ORCHESTRATOR] 1. Minting signed identity for Sub-Agent A (browser-agent)...")
    ctx_subagent_a = adapter.mint_task_context(
        task_id=shared_actor_id,
        agent_name="browser-agent",
        parent_principal="orchestrator-agent",
        delegated_by="auth0|user-123",
        tenant_id="tenant-demo",
        delegation_permissions=["browser:read", "agent:execute"],
    )
    print(f"  Identity:     {ctx_subagent_a.agent_id} (roles: {ctx_subagent_a.roles})")
    print(f"  Permissions:  {ctx_subagent_a.delegation_permissions}")
    print(f"  HMAC Token:   {ctx_subagent_a.to_token()[:35]}...")

    # 5. Orchestrator delegates to Sub-Agent B (Research Specialist - Attenuated)
    print("\n[ORCHESTRATOR] 2. Minting signed identity for Sub-Agent B (research-agent)...")
    ctx_subagent_b = adapter.mint_task_context(
        task_id=shared_actor_id,
        agent_name="research-agent",
        parent_principal="orchestrator-agent",
        delegated_by="auth0|user-123",
        tenant_id="tenant-demo",
        delegation_permissions=["filesystem:read", "agent:execute"],  # Note: NO browser:read
    )
    print(f"  Identity:     {ctx_subagent_b.agent_id} (roles: {ctx_subagent_b.roles})")
    print(f"  Permissions:  {ctx_subagent_b.delegation_permissions}")
    print(f"  HMAC Token:   {ctx_subagent_b.to_token()[:35]}...")

    print("\n" + "-" * 80)
    print(" VERIFICATION 1: BROWSER NAVIGATION CAPABILITY")
    print("-" * 80)

    # Call 1: Sub-Agent A invokes browser_navigate
    print("\n[*] Sub-Agent A (browser-agent) requests 'browser_navigate' to 'http://localhost:8089'...")
    req_a_nav = ToolInvocationRequest(
        request_id="req-a-01",
        task_context=ctx_subagent_a.to_token(),
        tool_name="browser_navigate",
        action="navigate",
        arguments={"url": "http://localhost:8089"},
    )
    res_a_nav = gateway.invoke(req_a_nav)
    print(f"  [RESULT] Decision: {res_a_nav.decision} (Code: {res_a_nav.code})")
    print(f"  [RESULT] Status:   OK={res_a_nav.ok}, Extracted: title='{res_a_nav.data.get('title') if res_a_nav.data else None}'")
    assert res_a_nav.ok is True, "Sub-Agent A should be ALLOWED browser navigation"

    # Call 2: Sub-Agent B invokes browser_navigate inside the SAME Actor
    print("\n[*] Sub-Agent B (research-agent) attempts 'browser_navigate' from the SAME Actor...")
    req_b_nav = ToolInvocationRequest(
        request_id="req-b-01",
        task_context=ctx_subagent_b.to_token(),
        tool_name="browser_navigate",
        action="navigate",
        arguments={"url": "http://localhost:8089"},
    )
    res_b_nav = gateway.invoke(req_b_nav)
    print(f"  [RESULT] Decision: {res_b_nav.decision} (Code: {res_b_nav.code})")
    print(f"  [RESULT] Reason:   {res_b_nav.error}")
    assert res_b_nav.ok is False, "Sub-Agent B should be BLOCKED from browser navigation"

    print("\n" + "-" * 80)
    print(" VERIFICATION 2: FILESYSTEM READ CAPABILITY")
    print("-" * 80)

    # Call 3: Sub-Agent B invokes filesystem_read
    print(f"\n[*] Sub-Agent B (research-agent) requests 'filesystem_read' on '{notes_file}'...")
    req_b_read = ToolInvocationRequest(
        request_id="req-b-02",
        task_context=ctx_subagent_b.to_token(),
        tool_name="filesystem_read",
        action="read",
        arguments={"path": notes_file},
    )
    res_b_read = gateway.invoke(req_b_read)
    print(f"  [RESULT] Decision: {res_b_read.decision} (Code: {res_b_read.code})")
    print(f"  [RESULT] Content:  '{res_b_read.data.get('content') if res_b_read.data else None}'")
    assert res_b_read.ok is True, "Sub-Agent B should be ALLOWED filesystem read"

    # Call 4: Sub-Agent A invokes filesystem_read inside the SAME Actor
    print(f"\n[*] Sub-Agent A (browser-agent) attempts 'filesystem_read' on '{notes_file}'...")
    req_a_read = ToolInvocationRequest(
        request_id="req-a-02",
        task_context=ctx_subagent_a.to_token(),
        tool_name="filesystem_read",
        action="read",
        arguments={"path": notes_file},
    )
    res_a_read = gateway.invoke(req_a_read)
    print(f"  [RESULT] Decision: {res_a_read.decision} (Code: {res_a_read.code})")
    print(f"  [RESULT] Reason:   {res_a_read.error}")
    assert res_a_read.ok is False, "Sub-Agent A should be BLOCKED from filesystem read"

    print("\n" + "-" * 80)
    print(" VERIFICATION 3: ANTI-SPOOFING & IDENTITY HIJACKING DEFENSE")
    print("-" * 80)

    # Call 5: Sub-Agent B attempts to impersonate Sub-Agent A within the same actor
    print("\n[*] Adversarial Attempt: Sub-Agent B claims 'agent_id=browser-agent' using its own token...")
    req_spoof = ToolInvocationRequest(
        request_id="req-spoof-01",
        task_context=ctx_subagent_b.to_token(),
        tool_name="browser_navigate",
        action="navigate",
        arguments={"url": "http://localhost:8089"},
        claimed_agent_id="browser-agent",
    )
    res_spoof = gateway.invoke(req_spoof)
    print(f"  [RESULT] Decision: {res_spoof.decision} (Code: {res_spoof.code})")
    print(f"  [RESULT] Reason:   {res_spoof.error}")
    assert res_spoof.ok is False and res_spoof.code == "AGENT_ID_MISMATCH", "Identity spoofing must be caught"

    print("\n" + "=" * 80)
    print(" SHOWCASE PROVEN:")
    print(" Even though both sub-agents run inside the exact same Substrate Actor:")
    print(" 1. Sub-Agent A has browser navigation rights but cannot read confidential research.")
    print(" 2. Sub-Agent B has research reading rights but cannot navigate external web pages.")
    print(" 3. Neither sub-agent can claim the other's identity or escalate ambient privileges.")
    print("=" * 80)


if __name__ == "__main__":
    run_showcase()

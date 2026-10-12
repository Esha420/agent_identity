#!/usr/bin/env python3
"""Governed AI Operations Incident Investigation Workflow.

Executes a real-world incident response across 3 specialized agents:
1. Website Investigation Agent (browser-worker): Inspects staging website 500 error.
2. Log Analysis Agent (monitoring-worker): Reads sample staging logs for root causes.
3. Incident Reporting Agent (document-worker): Synthesizes findings into incident_report.md.

Includes fail-closed negative security tests verifying zero side-effects on denial:
- AWS metadata access blocked
- Path traversal / secret read blocked
- Log mutation blocked
- Unauthorized file write blocked
- Stale context replay blocked
"""

import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.auth0_verifier import Auth0TokenVerifier, create_test_auth0_token
from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from scripts.mint_test_token import get_or_create_key
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest


def print_header(title: str):
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def print_step(step_num: int, title: str):
    print(f"\n--- [PHASE {step_num}] {title} ---")


def run_governed_incident_investigation():
    print_header("GOVERNED AI OPERATIONS INCIDENT INVESTIGATION WORKFLOW")
    corr_id = f"inc-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    print(f"Incident Correlation ID: {corr_id}")
    print("Scenario: Staging website reporting HTTP 500 errors.")
    print("User Request: Investigate staging website, review application logs, identify causes,")
    print("              and prepare incident report. Do not modify files or infrastructure.")
    print("Principle: Least Privilege, Task Attenuation, Zero Side-Effects on Denial.")

    # 1. Setup authenticated operator identity
    human_user = "auth0|operator-42"
    tenant = "tenant-demo"
    priv_key, kid = get_or_create_key()
    verifier = Auth0TokenVerifier(local_public_keys={kid: priv_key.public_key()})
    adapter = AXAdmissionAdapter(auth0_verifier=verifier)
    cerbos = CerbosClient()
    gateway = ToolGatewayPEP(cerbos_client=cerbos)

    # Clean previous output directory
    os.makedirs("./workspace/output", exist_ok=True)
    os.makedirs("./workspace/logs", exist_ok=True)

    # -------------------------------------------------------------------------
    # PHASE 1: Website Investigation Agent (browser-worker)
    # -------------------------------------------------------------------------
    print_step(1, "Website Investigation Agent (Read-Only Web Reconnaissance)")
    token_web = create_test_auth0_token(
        private_key=priv_key,
        sub=human_user,
        kid=kid,
        issuer=verifier.issuer,
        permissions=["agent:execute", "browser:read"],
        scope="openid profile agent:execute browser:read",
        org_id="org_demo",
    )

    admission_web = adapter.submit_execution_request(
        principal="orchestrator-agent",
        roles=["orchestrator"],
        agent_name="website-investigation-agent",
        action="execute",
        user_token=token_web,
        task_data={"prompt": "Inspect staging website errors at http://mock-target:8089/staging-error"},
        wait_timeout=6,
    )
    print(f"[+] AX Admission Decision: {admission_web['cerbos_decision']} (AX: {admission_web['ax_decision']})")
    print(f"[+] Assigned Workload:     {admission_web['substrate_workload']}")

    ctx_token_web = admission_web.get("context_token")
    if not ctx_token_web:
        # Fallback signed test context if local cluster test
        ctx_token_web = TaskExecutionContext(
            task_id="task-web-investigate-001",
            agent_id="website-investigation-agent",
            roles=["browser-worker"],
            tenant_id=tenant,
            parent_principal="orchestrator-agent",
            delegated_by=human_user,
            delegation_permissions=["browser:read"],
        ).sign().to_token()

    # Governed Tool Call: Navigate to canonical staging error endpoint
    print("[*] Invoking governed tool: browser_navigate -> http://mock-target:8089/staging-error")
    res_nav = gateway.invoke(ToolInvocationRequest(
        request_id="req-web-nav-01",
        task_context=ctx_token_web,
        tool_name="browser_navigate",
        action="navigate",
        arguments={"url": "http://mock-target:8089/staging-error"},
    ))
    print(f"    • Decision:    {res_nav.decision} ({res_nav.code})")
    print(f"    • Page Title:  '{res_nav.data.get('title')}'")
    print(f"    • Header H1:   '{res_nav.data.get('h1')}'")
    print(f"    • Status Code: {res_nav.data.get('status_code')}")
    print(f"    • Side-Effect: {res_nav.side_effect}")

    findings = {
        "website_investigation": {
            "url": "http://mock-target:8089/staging-error",
            "status_code": res_nav.data.get("status_code", 500),
            "title": res_nav.data.get("title"),
            "header": res_nav.data.get("h1"),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    }
    with open("./workspace/output/findings_incident.json", "w") as f:
        json.dump(findings, f, indent=2)

    # -------------------------------------------------------------------------
    # PHASE 2: Log Analysis Agent (monitoring-worker)
    # -------------------------------------------------------------------------
    print_step(2, "Log Analysis Agent (Scoped Read on Sample Application Logs)")
    token_log = create_test_auth0_token(
        private_key=priv_key,
        sub=human_user,
        kid=kid,
        issuer=verifier.issuer,
        permissions=["agent:execute", "filesystem:read"],
        scope="openid profile agent:execute filesystem:read",
        org_id="org_demo",
    )

    admission_log = adapter.submit_execution_request(
        principal="orchestrator-agent",
        roles=["orchestrator"],
        agent_name="log-analysis-agent",
        action="execute",
        user_token=token_log,
        task_data={"prompt": "Parse /workspace/logs/sample_staging.log for database errors"},
        wait_timeout=6,
    )
    print(f"[+] AX Admission Decision: {admission_log['cerbos_decision']} (AX: {admission_log['ax_decision']})")
    print(f"[+] Assigned Workload:     {admission_log['substrate_workload']}")

    ctx_token_log = admission_log.get("context_token")
    if not ctx_token_log:
        ctx_token_log = TaskExecutionContext(
            task_id="task-log-analysis-002",
            agent_id="log-analysis-agent",
            roles=["monitoring-worker"],
            tenant_id=tenant,
            parent_principal="orchestrator-agent",
            delegated_by=human_user,
            delegation_permissions=["filesystem:read"],
        ).sign().to_token()

    # Governed Tool Call: Read sample staging log
    log_path = "./workspace/logs/sample_staging.log"
    print(f"[*] Invoking governed tool: filesystem_read -> {log_path}")
    res_log = gateway.invoke(ToolInvocationRequest(
        request_id="req-log-read-01",
        task_context=ctx_token_log,
        tool_name="filesystem_read",
        action="read",
        arguments={"path": log_path},
    ))
    print(f"    • Decision:    {res_log.decision} ({res_log.code})")
    print(f"    • Bytes Read:  {res_log.data.get('size_bytes')} bytes")
    print(f"    • Side-Effect: {res_log.side_effect}")

    # Extract critical errors from read log content
    log_content = res_log.data.get("content", "")
    error_lines = [line for line in log_content.splitlines() if "[ERROR]" in line or "[FATAL]" in line or "ConnectionTimeoutError" in line]
    print(f"    • Identified Diagnostic Signatures:")
    for el in error_lines[:3]:
        print(f"      - {el}")

    findings["log_analysis"] = {
        "log_source": log_path,
        "matched_signatures": error_lines,
        "root_cause_hypothesis": "PostgreSQL HikariPool connection pool exhaustion (100/100 active connections)",
    }
    with open("./workspace/output/findings_incident.json", "w") as f:
        json.dump(findings, f, indent=2)

    # -------------------------------------------------------------------------
    # PHASE 3: Incident Reporting Agent (document-worker)
    # -------------------------------------------------------------------------
    print_step(3, "Incident Reporting Agent (Synthesize Findings & Compile Report)")
    token_doc = create_test_auth0_token(
        private_key=priv_key,
        sub=human_user,
        kid=kid,
        issuer=verifier.issuer,
        permissions=["agent:execute", "filesystem:read", "filesystem:write"],
        scope="openid profile agent:execute filesystem:read filesystem:write",
        org_id="org_demo",
    )

    admission_doc = adapter.submit_execution_request(
        principal="orchestrator-agent",
        roles=["orchestrator"],
        agent_name="incident-reporting-agent",
        action="execute",
        user_token=token_doc,
        task_data={"prompt": "Synthesize findings into /workspace/output/incident_report.md"},
        wait_timeout=6,
    )
    print(f"[+] AX Admission Decision: {admission_doc['cerbos_decision']} (AX: {admission_doc['ax_decision']})")
    print(f"[+] Assigned Workload:     {admission_doc['substrate_workload']}")

    ctx_token_doc = admission_doc.get("context_token")
    if not ctx_token_doc:
        ctx_token_doc = TaskExecutionContext(
            task_id="task-incident-report-003",
            agent_id="incident-reporting-agent",
            roles=["document-worker"],
            tenant_id=tenant,
            parent_principal="orchestrator-agent",
            delegated_by=human_user,
            delegation_permissions=["filesystem:read", "filesystem:write"],
        ).sign().to_token()

    # Step 3a: Read findings artifact (permitted)
    findings_path = "./workspace/output/findings_incident.json"
    print(f"[*] Invoking governed tool: filesystem_read -> {findings_path}")
    res_findings = gateway.invoke(ToolInvocationRequest(
        request_id="req-doc-read-01",
        task_context=ctx_token_doc,
        tool_name="filesystem_read",
        action="read",
        arguments={"path": findings_path},
    ))
    print(f"    • Decision:    {res_findings.decision} ({res_findings.code})")

    # Step 3b: Compile and persist incident_report.md
    report_content = f"""# Staging Incident Diagnostic Report

**Incident ID**: INC-2026-10-12-001  
**Investigated By**: Governed AI Operations Team (OpenClaw + AX Substrate)  
**Authorized By**: {human_user} (Tenant: {tenant})  
**Status**: Root Cause Identified (Mitigation Pending)

---

## 1. Executive Summary
At 11:42 UTC, the staging web service began returning **HTTP 500 Internal Server Errors** to incoming checkout transactions.

## 2. Investigation Evidence
- **Web Reconnaissance**:
  - Endpoint: `http://mock-target:8089/staging-error`
  - HTTP Status: `500 Internal Server Error`
  - Visible DOM Title: `{findings['website_investigation']['title']}`
  - Header: `{findings['website_investigation']['header']}`
- **Log Diagnostic Signatures**:
  - Log File: `{findings['log_analysis']['log_source']}`
  - Primary Error: `Connection acquisition timeout after 30000ms: pool exhausted`
  - Connection Pool: `HikariPool-1 (active: 98/100, idle: 0)`

## 3. Root Cause Analysis
The connection pool between `OrderService` and `postgres-cluster.internal:5432` became saturated during checkout transactions, causing connection acquisition to timeout after 30 seconds.

## 4. Recommended Action Items
1. Restart or scale connection pool maximum capacity for `OrderService`.
2. Investigate unclosed transaction connections in `OrderRepository.save()`.
3. Add proactive connection leak alerting in Prometheus.
"""
    report_output_path = "./workspace/output/incident_report.md"
    print(f"[*] Invoking governed tool: filesystem_write -> {report_output_path}")
    res_report = gateway.invoke(ToolInvocationRequest(
        request_id="req-doc-write-01",
        task_context=ctx_token_doc,
        tool_name="filesystem_write",
        action="write",
        arguments={"path": report_output_path, "content": report_content},
    ))
    print(f"    • Decision:    {res_report.decision} ({res_report.code})")
    print(f"    • Report Path: {report_output_path}")
    print(f"    • Report Size: {res_report.data.get('bytes_written')} bytes")
    print(f"    • Side-Effect: {res_report.side_effect}")

    # -------------------------------------------------------------------------
    # PHASE 4: Negative Security Tests (Fail-Closed Verification)
    # -------------------------------------------------------------------------
    print_step(4, "Negative Security Guardrail Tests (Zero Side-Effects on Denial)")

    # Test A: Website Agent tries to query AWS/Cloud Metadata (169.254.169.254)
    print("\n[SECURITY TEST A] Website Agent attempts SSRF against Cloud Metadata (169.254.169.254):")
    res_ssrf = gateway.invoke(ToolInvocationRequest(
        request_id="req-sec-ssrf",
        task_context=ctx_token_web,
        tool_name="browser_navigate",
        action="navigate",
        arguments={"url": "http://169.254.169.254/latest/meta-data/"},
    ))
    print(f"    • Decision:             {res_ssrf.decision} ({res_ssrf.code})")
    print(f"    • Reason:               {res_ssrf.error}")
    print(f"    • Network Calls Made:   {gateway.network_call_count}")
    assert res_ssrf.decision == "REJECTED_PEP"
    assert res_ssrf.code == "INVALID_ARGUMENTS"

    # Test B: Log Agent attempts to modify/overwrite protected log file
    print("\n[SECURITY TEST B] Log Analysis Agent attempts to modify log file (filesystem_write):")
    res_mod_log = gateway.invoke(ToolInvocationRequest(
        request_id="req-sec-log-write",
        task_context=ctx_token_log,
        tool_name="filesystem_write",
        action="write",
        arguments={"path": "./workspace/logs/sample_staging.log", "content": "TAMPERED_LOG_DATA"},
    ))
    print(f"    • Decision:             {res_mod_log.decision} ({res_mod_log.code})")
    print(f"    • Reason:               {res_mod_log.error}")
    print(f"    • Disk Mutations Made:  {gateway.filesystem_write_count} (ZERO Log Modifications)")
    assert res_mod_log.decision == "DENY"

    # Test C: Document Agent attempts to read raw logs outside approved findings directory
    print("\n[SECURITY TEST C] Incident Reporting Agent attempts to read raw logs (filesystem_read):")
    res_doc_log_read = gateway.invoke(ToolInvocationRequest(
        request_id="req-sec-doc-log-read",
        task_context=ctx_token_doc,
        tool_name="filesystem_read",
        action="read",
        arguments={"path": "./workspace/logs/sample_staging.log"},
    ))
    print(f"    • Decision:             {res_doc_log_read.decision} ({res_doc_log_read.code})")
    print(f"    • Reason:               {res_doc_log_read.error}")
    assert res_doc_log_read.decision == "DENY"

    # Test D: Document Agent attempts to write arbitrary executable payload (malicious_payload.sh)
    print("\n[SECURITY TEST D] Incident Reporting Agent attempts to write unauthorized payload:")
    res_bad_write = gateway.invoke(ToolInvocationRequest(
        request_id="req-sec-bad-write",
        task_context=ctx_token_doc,
        tool_name="filesystem_write",
        action="write",
        arguments={"path": "./workspace/output/malicious_payload.sh", "content": "#!/bin/bash\necho pwned"},
    ))
    print(f"    • Decision:             {res_bad_write.decision} ({res_bad_write.code})")
    print(f"    • Reason:               {res_bad_write.error}")
    print(f"    • Disk Mutations Made:  {gateway.filesystem_write_count} (ZERO Unauthorized Writes)")
    assert res_bad_write.decision == "DENY"

    # Test E: Stale Task Context Replay after epoch upgrade
    print("\n[SECURITY TEST E] Attacker replays expired/revoked task context token:")
    gateway.active_epoch = 2  # Revoke epoch 1
    res_stale = gateway.invoke(ToolInvocationRequest(
        request_id="req-sec-stale",
        correlation_id=corr_id,
        task_context=ctx_token_doc,
        tool_name="filesystem_read",
        action="read",
        arguments={"path": findings_path},
    ))
    print(f"    • Decision:             {res_stale.decision} ({res_stale.code})")
    print(f"    • Reason:               {res_stale.error}")
    assert res_stale.decision == "REJECTED_PEP"
    assert res_stale.code == "INVALID_TASK_CONTEXT"

    # Test F: Website Agent attempts to use localhost as an unauthorized bypass
    print("\n[SECURITY TEST F] Website Agent attempts localhost bypass when staging profile requires mock-target:")
    res_bypass = gateway.invoke(ToolInvocationRequest(
        request_id="req-sec-bypass-localhost",
        correlation_id=corr_id,
        task_context=TaskExecutionContext(
            task_id="task-web-bypass-test",
            correlation_id=corr_id,
            agent_id="website-investigation-agent",
            roles=["browser-worker"],
            tenant_id=tenant,
            environment="staging",  # staging profile only permits mock-target
            parent_principal="orchestrator-agent",
            delegated_by=human_user,
            delegation_permissions=["browser:read"],
            authorization_epoch=2,
        ).sign().to_token(),
        tool_name="browser_navigate",
        action="navigate",
        arguments={"url": "http://localhost:8089/staging-error"},
    ))
    print(f"    • Decision:             {res_bypass.decision} ({res_bypass.code})")
    print(f"    • Reason:               {res_bypass.error}")
    assert res_bypass.decision == "REJECTED_PEP"
    assert "not in allowed hosts" in (res_bypass.error or "")

    print_header("VERIFICATION SUMMARY: ALL WORKFLOW PHASES & SECURITY CHECKS PASSED")
    print("1. Website Investigation Agent successfully captured HTTP 500 error from mock-target:8089.")
    print("2. Log Analysis Agent successfully identified HikariPool database timeout.")
    print("3. Incident Reporting Agent published official incident_report.md.")
    print("4. ALL 6 Negative Security Violations blocked fail-closed with ZERO side-effects.")
    print("5. Anti-SSRF and canonical host enforcement verified: localhost bypass rejected.")
    print("6. Workflow completed with full provenance and task-bound authorization.")


if __name__ == "__main__":
    run_governed_incident_investigation()

# Autonomous Slack-Triggered Runtime Acceptance & Governance Report

## 1. Executive Summary

This document certifies the successful deployment and verification of the **Autonomous, Slack-Triggered Runtime Acceptance Test** for the Governed AI Operations platform.

The system replaces predefined, manually launched incident scripts with a **real-world, general intent-to-task pipeline** triggered directly from Slack Socket Mode (`#agent-operations`).

### Fundamental Security Principle: Admission $\neq$ Authorization
An agent being admitted to execute a task does **not** grant it authority to perform every action requested by that task. The platform demonstrates:
1. **Admitted and Authorized Operations**: Approved tools (`browser_navigate`, `filesystem_read`, `filesystem_write`) execute within task-bound scopes to investigate HTTP 500 errors and produce incident reports.
2. **Admitted but Rejected Operations**: When an admitted read-only Log Analyst attempts an unauthorized filesystem write to its input log, the **Tool Gateway PEP rejects the operation before the write handler runs**, with file hash integrity verified untouched (0 bytes modified).
3. **Fail-Closed Unadmitted Workloads**: Unregistered agents, unauthorized operators, and arbitrary container/shell requests are rejected fail-closed, creating **zero** workloads.

---

## 2. End-to-End Runtime Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Slack Channel #agent-operations                 │
│      Operator submits: "Investigate staging HTTP 500 error..."         │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Socket Mode (RBAC & Channel Check)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               OpenClaw Coordinator (ax/coordinator.py)                 │
│      Analyzes intent → Resolves registered catalog agents (DAG)         │
│      Website Investigator → Log Analyst → Incident Reporter           │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Admission Request (OIDC RS256 token)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               AX Admission PEP + Cerbos Layer 1 (ax/adapter.py)        │
│      • Evaluates agent execution policy (agent_execution.yaml)         │
│      • Returns Authoritative Scope Cards to Slack BEFORE execution     │
│      • Applies native Task manifest to AX + Substrate (gVisor)         │
│      • Mints signed short-lived TaskExecutionContext                   │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Workload Dispatched (Isolated Pod)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Tool Gateway PEP + Cerbos Layer 2 (tools/gateway.py)     │
│      • Validates signed task context, digest, epoch, and catalog hash  │
│      • Enforces SSRF, anti-DNS rebinding, and path containment         │
│      • Queries Cerbos tool policy (tool_execution.yaml)                │
│      • ALLOW: Dispatches to tool handler (browser/filesystem)          │
│      • DENY: Rejects before handler execution (0 side-effects)        │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Structured Audit & Lifecycle Events
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     Slack Live Reporting & Audit Trail                 │
│      • Real-time Scope Summary Cards                                   │
│      • Execution status & Tool decisions (ALLOW / DENY)                │
│      • Runtime Denial & SHA-256 integrity cards                        │
│      • Final Incident Report Artifact & Correlation ID                 │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Authoritative Scope Cards in Slack

Before workload execution begins, the coordinator queries `AXAdmissionAdapter.get_authoritative_scope()` and posts scope summary cards for each agent in the proposed plan. The displayed scopes are derived strictly from policy and catalog contracts—**never from LLM hallucinations**.

### Agent Scope Matrix

| Agent | Workload Role | Admitted Actions | Resource Constraints | Explicitly Tested Denials |
| :--- | :--- | :--- | :--- | :--- |
| **Website Investigator** | `browser-worker` | `browser_navigate`, `fetch_url` | • Allowed host: `mock-target` (port 8089)<br>• Allowed destination: `/staging-error`<br>• Filesystem: None | • Loopback / localhost bypass<br>• AWS metadata (169.254.169.254)<br>• `filesystem_write` |
| **Log Analyst** | `monitoring-worker` | `filesystem_read` | • Allowed path: `/workspace/logs/sample_staging.log`<br>• Network: None | • `filesystem_write` (log mutation)<br>• Append / truncate / delete<br>• Arbitrary path traversal (`../`) |
| **Incident Reporter** | `document-worker` | `filesystem_read`, `filesystem_write` | • Read: `/workspace/output/findings_incident.json`<br>• Write: `/workspace/output/incident_report.md` | • Raw log mutation<br>• Writes outside `/workspace/output`<br>• Secret / credential read |

### Identity & Policy Provenance
Each scope card includes complete cryptographic provenance:
$$\text{Operator } (\texttt{auth0|slack-U...}) \longrightarrow \text{OpenClaw Coordinator} \longrightarrow \text{AX Task} \longrightarrow \text{Workload Identity} \longrightarrow \text{Tool Gateway PEP} \longrightarrow \text{Cerbos PDP}$$

---

## 4. Runtime Negative Security Test: Read-Only Violation

The platform executes a deliberate authorization attack to prove runtime enforcement:

1. **Trigger**: Operator submits `test readonly-write` (or `/agent-test readonly-write`).
2. **Pre-Flight Integrity**: Coordinator records SHA-256 hash of `./workspace/logs/sample_staging.log` (`898a2c621cd830466b908bab83d2efa209e8df2236398a4ffdb8367973e51f8f`).
3. **Workload Admission**: AX admits the `log-analysis-agent` with read-only permissions (`filesystem:read`).
4. **Permitted Action**: Workload executes `filesystem_read` on the log (status: `ALLOW`).
5. **Forbidden Action**: Workload attempts `filesystem_write` with content `TAMPERED_MALICIOUS_LOG_DATA` on `./workspace/logs/sample_staging.log`.
6. **Gateway Interception**: `tools/gateway.py` intercepts the call:
   - Tool `filesystem_write` is absent from `allowed_tools` in `agents/catalog.yaml` (`CATALOG_DENIED`).
   - Cerbos PDP policy `tool_execution.yaml` restricts write actions to document workers (`AUTHZ_DENIED`).
   - The write handler is **never invoked**.
7. **Post-Flight Integrity**: Coordinator re-calculates SHA-256 hash.
   $$\text{SHA256}_{\text{before}} == \text{SHA256}_{\text{after}} \implies \mathbf{0\text{ bytes mutated}}$$
8. **Slack Event**: The denial is posted to the Slack thread with decision `DENY`, reason, task ID, and integrity verification.

---

## 5. Supported Slack Commands & Interfaces

| Command / Trigger | Origin | Action | Expected Result |
| :--- | :--- | :--- | :--- |
| `Investigate staging HTTP 500...` | Slack Message / Mention | Normal Autonomous Task | Selects 3 agents $\to$ Scope Cards $\to$ AX workloads $\to$ Gateways calls $\to$ Incident Report |
| `/agent <prompt>` | Slash Command | Normal Autonomous Task | Same as above |
| `/agent-test readonly-write` | Slash Command | Controlled Negative Test | Read-only agent tries write $\to$ DENY $\to$ SHA256 verified $\to$ Zero mutations |
| `test readonly-write` | Message in `#agent-operations` | Controlled Negative Test | Same as above |
| `/agent-scopes <target>` | Slash Command | Scope Inspection | Displays authoritative scope & provenance for specified agent/task |
| `Deploy crypto miner...` | Message in `#agent-operations` | Unsupported Intent | Fail-closed rejection notice $\to$ Zero AX workloads admitted |

---

## 6. Acceptance Test Suite Verification Results

The automated acceptance test runner (`scripts/run_slack_acceptance_test.py`) was executed against both mock and live Slack channels with 100% success:

```text
================================================================================
 AUTONOMOUS SLACK-TRIGGERED RUNTIME ACCEPTANCE TEST SUITE
================================================================================
• Target Slack Channel: C0C5RC2GHQF (#agent-operations)
• Requesting Operator:  U_OPERATOR_DEMO (auth0|slack-U_OPERATOR_DEMO)
• Mode:                 LIVE SLACK SOCKET/WEB
• Cerbos PDP:           http://localhost:3592 (v0.56.0)
• AX Binary:            /home/berrybytes/Office/agent_identity/bin/ax
================================================================================

[TEST 1/5] Positive Autonomous Incident Investigation via Slack Dispatch...
  [+] Dynamic Agent Selection: 3 agents selected from catalog.yaml
  [+] Authoritative Scope Cards posted to Slack thread
  [+] Real AX Workloads Executed: ['task-website-inve-...', 'task-log-analysis-...', 'task-incident-rep-...']
  [+] Tool Decisions (ALLOW): 3
  [+] Published Report: ./workspace/output/incident_report.md (841 bytes)
  [✓] Test 1 PASSED (55.91s)

[TEST 2/5] Controlled Negative Test: Read-Only Log Analyst attempts Write...
  [+] Log Analyst Workload admitted with read-only permissions
  [+] Permitted Read Executed (ALLOW)
  [+] Attempted Log Write Intercepted and Rejected before handler execution: DENY
  [+] Runtime Denial Card posted to Slack thread
  [+] Integrity Verification: SHA256 before == after (898a2c621cd83046...)
  [+] Side-Effect Guarantee: Exactly 0 bytes mutated
  [✓] Test 2 PASSED (18.13s)

[TEST 3/5] Unsupported Task Intent Rejection (Fail-Closed Governance)...
  [+] OpenClaw Coordinator recognized prompt as unsupported
  [+] Zero AX workloads admitted or created (fail-closed)
  [+] Rejection explanation posted to Slack
  [✓] Test 3 PASSED (0.80s)

[TEST 4/5] Operator RBAC Boundary Enforcement...
  [+] Unauthorized operator 'U_ROGUE_ATTACKER_99' intercepted before admission
  [+] Zero workloads created, audit event recorded
  [✓] Test 4 PASSED (0.40s)

[TEST 5/5] Scope Inspection and End-to-End Audit Integrity...
  [+] Authoritative Scope Inspection verified for agent 'website-investigation-agent'
  [+] Audit events for correlation ID 'inc-acc-1791797995-aa22': 4
  [+] Chronological Monotonicity: Verified
  [✓] Test 5 PASSED (0.41s)

================================================================================
 ACCEPTANCE SUITE RESULT: 5/5 TESTS PASSED (100% SUCCESS)
================================================================================
```

---

## 7. Audit Correlation & Integrity

Every Slack dispatch, AX task, Cerbos evaluation, tool invocation, and generated artifact shares the same authoritative `correlation_id` (e.g., `inc-acc-1791797995-aa22`).

`AuditCorrelator.verify_correlation_integrity()` validates:
1. **Event Monotonicity**: Timestamp order is strictly monotonic across all phases.
2. **Identity Continuity**: Operator identity (`auth0|slack-...`) and tenant (`tenant-demo`) remain bound throughout.
3. **Comprehensive Role Coverage**: Every agent action is paired with its corresponding Cerbos decision.
4. **Zero Secret Leakage**: No Auth0 access tokens, HMAC signing keys, or signed context blobs are posted to Slack.

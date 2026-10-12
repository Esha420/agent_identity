# Production Hardening & Operational Readiness Specification

**Governed AI Operations Team: Production Milestone Report**  
**Version**: 1.0.0 (Hardened Release)  
**Date**: October 2026  
**Status**: Verified & Ready for Production Operations  

---

## 1. Executive Summary

This release delivers the **Production Hardening and Operational Readiness** milestone for the Governed AI Operations Team. Building upon the working prototype of OpenClaw, Google AX, Agent Substrate (gVisor), and Cerbos PDP, this release resolves target evaluation ambiguities, enforces strict Slack RBAC and channel boundaries, validates workload resilience, cryptographically links audit events across all components, and establishes reproducible image-pinned deployments with automated rollback.

---

## 2. Hardened Architecture & Security Invariants

### 2.1 Browser Target Canonicalization & Anti-Bypass Enforcement
- **Discrepancy Resolved**: The website investigation agent previously requested `http://localhost:8089/staging-error`. While functional for local debugging, generic loopback (`localhost`, `127.0.0.1`) in allowlists introduces SSRF bypass risks against other host/node services.
- **Hardened Mechanism**:
  1. The target URL is strictly evaluated against the canonical endpoint `http://mock-target:8089/staging-error`.
  2. The staging profile in `tools/catalog.yaml` permits only `mock-target` (`allowed_hosts: ["mock-target"]`).
  3. Any attempt by an agent to substitute `localhost` or `127.0.0.1` is **immediately rejected fail-closed** by the Tool Gateway PEP (`REJECTED_PEP: Hostname 'localhost' not in allowed hosts`).
  4. Internal DNS / host resolution (`tools/security.py:HOST_RESOLVER_MAPPINGS`) resolves `mock-target` to the container IP / local port forward while preserving the canonical Host header and passing through comprehensive anti-SSRF checks (blocking cloud metadata `169.254.169.254` and DNS rebinding).

### 2.2 Slack Operational Governance & Channel Boundaries
- **Channel Restriction**: The Slack Socket Mode gateway (`scripts/slack_incident_listener.py`) validates that requests originate exclusively from designated operational channels (default: `C0C5RC2GHQF` `#agent-operations`). Invocations from unauthorized channels or direct messages are rejected fail-closed with audit code `FORBIDDEN_CHANNEL`.
- **Operator RBAC**: Slack user IDs (e.g. `U_OPERATOR_DEMO`) are authenticated and checked against the authorized operator registry. Authorized operators are bound to trusted Auth0 subjects (`auth0|slack-<user_id>`) with explicit delegation scopes. Unauthorized Slack users are denied with `FORBIDDEN_OPERATOR` before any agent workload is created.
- **Safe Content Handling**: The `sanitize_slack_text()` engine strips illegal control characters/null bytes and enforces Slack Block Kit length boundaries (2,800 characters) to prevent markdown injection or message drop failures.

### 2.3 Workload Resilience & Lifecycle Governance
- **Target Error Capture**: When the staging site returns HTTP 500, the tool gateway captures the status code and diagnostic DOM/header evidence as structured diagnostic payload rather than throwing an unhandled exception.
- **Transient Failure Retries**: Operations support exponential backoff on transient errors while immediately terminating on permanent policy denials (`DENY`, `REJECTED_PEP`).
- **Immediate Task Revocation**: An operator can invoke `gateway.revoke_task(task_id)` at any time. Any subsequent tool invocation by that task is instantly rejected with `INVALID_TASK_CONTEXT`.
- **Epoch Rotation**: Calling `gateway.revoke_epoch(new_epoch)` instantly invalidates all active execution leases minted under prior epochs.

### 2.4 End-to-End Audit Trail Correlation
Every incident workflow generates an immutable `correlation_id` (e.g., `inc-1791794032-6563eb`) that is propagated across:
1. **Slack Integration**: Root card and thread update metadata.
2. **AX Task Admission**: Labels and admission execution context.
3. **Workload Context**: Cryptographically signed `TaskExecutionContext.correlation_id`.
4. **Tool Gateway PEP**: Every `ToolInvocationRequest` and `AuditEvent`.
5. **Cerbos PDP**: Principal and resource attribute payloads.
6. **Artifact Output**: Persistent markdown header in `/workspace/output/incident_report.md`.

The `AuditCorrelator` engine (`tools/audit.py`) validates chronological monotonicity, completeness, and absence of orphan events.

---

## 3. Cryptographically Pinned Release Artifacts

All runtime components are pinned to immutable cryptographic digests:

| Component | Pinned Identifier | Digest / Version |
|---|---|---|
| **Cerbos PDP** | `ghcr.io/cerbos/cerbos:0.56.0` | `sha256:540643bc67ba628011a150ad1d3370f285daa38995be5cd7a4be181da902bec1` |
| **OpenClaw Agent** | `localhost:5001/openclaw-agent` | `sha256:3a00eb8df2f127b46e926dcea420ade1d46f8723b0ec7abb4b3610637569f7d9` |
| **Browser Agent** | `localhost:5001/browser-agent` | `sha256:8abae590b3dcf422089e17b4219c0c7136fd84384ea228af1e66381d5ced4f8f` |
| **Mock Target** | `python:3.11-alpine` | Containerized HTTP 200/500 diagnostic server |

---

## 4. Operational Runbook

### 4.1 Running Pre-Flight Verification & Deployment
To run the automated deployment and test suite:
```bash
./scripts/deploy_and_verify.sh
```
This script automatically:
1. Backs up active configuration to `backups/release_preflight/`.
2. Validates image digests.
3. Compiles Cerbos policies (26/26 tests).
4. Executes all multi-layer test suites (105+ unit and integration tests).
5. Executes the real 3-agent incident workflow against `mock-target:8089`.
6. Saves release evidence to `evidence/release_validation_report.json` and `evidence/release_validation_report.md`.

### 4.2 Automated Rollback Procedure
If any verification gate fails or an operational rollback is required:
```bash
./scripts/deploy_and_verify.sh --rollback
```
This restores the saved configurations, restarts the Cerbos container, and compiles the restored policies.

### 4.3 Running the Live Slack Operations Daemon
To run the Socket Mode listener for real-time Slack interactions:
```bash
python3 scripts/slack_incident_listener.py
```
To post an automated investigation test run to `#agent-operations`:
```bash
python3 scripts/slack_incident_listener.py --demo-post
```

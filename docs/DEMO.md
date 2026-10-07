# Operator Walkthrough & Demo Guide

This guide provides exact, reproducible steps for operators to demonstrate the reference architecture.

---

## 1. Quick Operator Walkthrough

### Step 1: Environment Setup
Initialize the local Cerbos PDP container, mock target, and verify cluster connectivity:
```bash
./scripts/setup.sh
```
*Expected Output:*
```
[+] Core prerequisites detected (docker, kubectl, python3).
[+] Native AX control plane and Substrate (ATE) cluster verified.
[+] Cerbos PDP is HEALTHY and SERVING on http://localhost:3592
[+] Compiling and validating Cerbos policies...
7 tests executed [7 OK]
[SETUP COMPLETED] Lab is fully initialized and ready.
```

---

### Step 2: Automated Verification
Run the complete automated test suite (including Cerbos policy tests, fail-closed tests, and dynamic policy switches):
```bash
./scripts/verify.sh
```
*Expected Output:*
```
Ran 23 tests in ~130s
OK
[VERIFICATION SUCCESS] All authorization, AX, Substrate, and end-to-end integration tests PASSED.
```

---

### Step 3: Run Interactive Demonstration
Execute the two primary paths (Authorized and Denied) plus Dynamic Capability Selection:
```bash
./scripts/demo.sh
```

#### What You Will See:

**PATH A: Authorized Execution**
```
[ORCHESTRATOR] Received User Task: 'Visit website and extract title'
[ORCHESTRATOR] Plan: 1. Resolved agent 'browser-agent'. 2. Request execution via AX.
--------------------------------------------------------------------------------
Request ID:       req-xxxx
Principal:        orchestrator-agent (roles: ['orchestrator'])
Target Agent:     browser-agent
Action:           execute
Cerbos Decision:  ALLOW
AX Decision:      ACCEPTED
Substrate State:  actor:task-browser-xxxx (ip: 10.244.0.28, phase: Running)
Execution Status: COMPLETED
Result:           {"task_name": "...", "worker_ip": "10.244.0.28", "phase": "Running", ...}
--------------------------------------------------------------------------------
```

**PATH B: Denied Execution**
```
[ORCHESTRATOR] Received User Task: 'Execute privileged secret task'
[ORCHESTRATOR] Plan: 1. Resolved agent 'restricted-agent'. 2. Request execution via AX.
--------------------------------------------------------------------------------
Request ID:       req-yyyy
Principal:        orchestrator-agent (roles: ['orchestrator'])
Target Agent:     restricted-agent
Action:           execute
Cerbos Decision:  DENY
AX Decision:      REJECTED
Substrate State:  NO WORKLOAD CREATED
Execution Status: DENIED
Result:           "Authorization denied by policy: DENY"
--------------------------------------------------------------------------------
[+] CONFIRMED: Substrate active task count is 0. Zero workloads materialized.
```

---

### Step 4: Run Anti-Hardcoding Audit
Verify that no custom agent framework classes or hardcoded authorization statements exist:
```bash
./scripts/audit_anti_hardcoding.sh
```
*Expected Output:*
```
[AUDIT PASSED] 0 violations found.
```

---

### Step 5: Teardown
Clean up containers and ephemeral tasks cleanly:
```bash
./scripts/teardown.sh
```

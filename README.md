# Multi-Agent Authorization + AX/Substrate Reference Architecture

A minimal, reproducible reference architecture demonstrating policy-driven authorization at the boundary between orchestration intent and isolated workload execution.

```
                          USER
                           │
                           ▼
               ┌──────────────────────┐
               │  ORCHESTRATOR AGENT  │ (Ultra-Thin Planner)
               │  • Understand task   │
               │  • Select capability │
               │  • Select agent      │
               └──────────┬───────────┘
                          │
                          │ Execution Request:
                          │ {principal, agent, action, task}
                          ▼
               ┌──────────────────────┐
               │    AX ADMISSION      │
               │       BOUNDARY       │
               └──────────┬───────────┘
                          │
                          │ Authorization Request:
                          │ (Principal, Resource, Action, Context)
                          ▼
               ┌──────────────────────┐
               │      CERBOS PDP      │
               │  (Policy Decision)   │
               └──────────┬───────────┘
                          │
                     ┌────┴────┐
                     │         │
                   ALLOW      DENY / ERROR (Fail-Closed)
                     │         │
                     ▼         X (Zero AX Tasks / Zero Substrate Workloads)
               ┌──────────┐
               │    AX    │ (Native Google AX Controller)
               │ Materialize Task
               └────┬─────┘
                    │
                    ▼
            ┌─────────────────┐
            │ AGENT SUBSTRATE │ (ATE Substrate Worker Pool)
            │ Isolated gVisor │
            │ Worker Sandbox  │
            └───────┬─────────┘
                    │
                    ▼
            ┌─────────────────┐
            │ EXISTING AGENT  │ (Awesome-Agents Container Image)
            │ Unmodified Exec │
            └───────┬─────────┘
                    │
                    ▼
                 RESULT
                    │
                    ▼
               ORCHESTRATOR
```

---

## What This Project Demonstrates

1. **Separation of Identity & Authorization**:
   - The Orchestrator declares its logical identity (`orchestrator-agent`).
   - Cerbos acts as the dedicated **Policy Decision Point (PDP)** evaluating what that identity is allowed to do.
2. **Native Runtime Boundary (Google AX)**:
   - AX intercepts execution intent and acts as the gatekeeper. Workloads are materialized into the execution substrate *only* upon authorization approval.
3. **Fail-Closed Security Guarantee**:
   - Denied or errored requests result in **zero AX tasks** and **zero Substrate workloads**.
4. **Isolated Workload Execution (Agent Substrate / ATE)**:
   - Approved agents run inside isolated gVisor sandbox worker pods.
5. **No Custom Agents**:
   - Uses upstream, unmodified agent containers from [kyrolabs/awesome-agents](https://github.com/kyrolabs/awesome-agents). Agent selection is 100% configuration-driven.

---

## Why Cerbos?

- **Identity ≠ Authorization**: Having an identity does not confer implicit access. Cerbos decouples policy logic from application code.
- **Dynamic Policy Updates**: Policies can be updated or revoked without modifying or recompiling orchestration code.

---

## Policies in Scope

The authorization policies governing agent workload execution are located in:
📁 **[`cerbos/policies/agent_execution.yaml`](cerbos/policies/agent_execution.yaml)**

### Policy Overview: Resource `agent` (v1)

```yaml
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: "default"
  resource: "agent"
  rules:
    # 1. ALLOW orchestrator to execute approved agents
    - actions: ["execute"]
      effect: EFFECT_ALLOW
      roles:
        - orchestrator
      condition:
        match:
          expr: request.resource.id in ["browser-agent", "research-agent"]

    # 2. DENY execution of sensitive/restricted agents
    - actions: ["execute"]
      effect: EFFECT_DENY
      roles:
        - orchestrator
      condition:
        match:
          expr: request.resource.id == "restricted-agent"

    # 3. DENY administrative/destructive operations
    - actions: ["admin", "delete"]
      effect: EFFECT_DENY
      roles: ["*"]
```

### Policy Evaluation Rules Matrix

| Caller Principal | Role | Target Resource (Agent) | Action | Policy Decision | Workload Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `orchestrator-agent` | `orchestrator` | `browser-agent` | `execute` | **`EFFECT_ALLOW`** | Materialized into Substrate sandbox |
| `orchestrator-agent` | `orchestrator` | `research-agent` | `execute` | **`EFFECT_ALLOW`** | Materialized into Substrate sandbox |
| `orchestrator-agent` | `orchestrator` | `restricted-agent` | `execute` | **`EFFECT_DENY`** | **Blocked** (0 workloads created) |
| `untrusted-agent` | `untrusted` | `browser-agent` | `execute` | **`EFFECT_DENY`** | **Blocked** (0 workloads created) |
| `attacker-agent` | `anonymous` | `browser-agent` | `execute` | **`EFFECT_DENY`** | **Blocked** (0 workloads created) |
| `orchestrator-agent` | `orchestrator` | `browser-agent` | `delete` | **`EFFECT_DENY`** | **Blocked** (0 workloads created) |
| `orchestrator-agent` | `orchestrator` | `browser-agent` | `admin` | **`EFFECT_DENY`** | **Blocked** (0 workloads created) |

Unit tests validating these exact rules are in:
📁 **[`cerbos/tests/agent_execution_test.yaml`](cerbos/tests/agent_execution_test.yaml)**

---

## Why Native AX & Agent Substrate?

- **No Bespoke Runtimes**: Interfaces directly with the native Google AX control plane (`ax-server`, `ax-controller`, `bin/ax`) and ATE Substrate worker pools.
- **Lifecycle Management**: AX manages task scheduling, reconciliation, and actor cleanup inside Substrate gVisor sandboxes.

---

## Quick Start

### 1. Setup Environment
```bash
./scripts/setup.sh
```

### 2. Run Automated Verification (All 23 Tests)
```bash
./scripts/verify.sh
```

### 3. Run Interactive Demonstration
```bash
./scripts/demo.sh
```

### 4. Anti-Hardcoding Audit
```bash
./scripts/audit_anti_hardcoding.sh
```

### 5. Cleanup
```bash
./scripts/teardown.sh
```

---

## Expected Trace Output

### Path A: Authorized Request (`browser-agent`)
```
--------------------------------------------------------------------------------
Request ID:       req-c58881cd
Principal:        orchestrator-agent (roles: ['orchestrator'])
Target Agent:     browser-agent
Action:           execute
Cerbos Decision:  ALLOW
AX Decision:      ACCEPTED
Substrate State:  actor:task-browser-agen-c3d8ab (ip: 10.244.0.28, phase: Running)
Execution Status: COMPLETED
Result:           {"task_name": "task-browser-agen-c3d8ab", "worker_ip": "10.244.0.28", "phase": "Running", "capability": ["browser", "web", "dom-extraction"]}
--------------------------------------------------------------------------------
```

### Path B: Denied Request (`restricted-agent`)
```
--------------------------------------------------------------------------------
Request ID:       req-807869ac
Principal:        orchestrator-agent (roles: ['orchestrator'])
Target Agent:     restricted-agent
Action:           execute
Cerbos Decision:  DENY
AX Decision:      REJECTED
Substrate State:  NO WORKLOAD CREATED
Execution Status: DENIED
Result:           "Authorization denied by policy: DENY"
--------------------------------------------------------------------------------
```

---

## Project Structure

```
.
├── README.md
├── Makefile
├── docker-compose.yaml
├── .env.example
├── .gitignore
├── bin/
│   └── ax                             # Native Google AX CLI
├── docs/
│   ├── ARCHITECTURE.md                # System and runtime architecture
│   ├── INVESTIGATION.md               # Environment and candidate agent investigation
│   ├── DECISIONS.md                   # Architecture Decision Records
│   ├── SECURITY_MODEL.md              # Security model and trust boundaries
│   ├── TEST_PLAN.md                   # Test matrix and expected results
│   ├── DEMO.md                        # Operator demo walkthrough
│   └── VERIFICATION_REPORT.md         # Final verification report
├── cerbos/
│   ├── cerbos.yaml                    # Cerbos PDP configuration
│   ├── policies/
│   │   └── agent_execution.yaml       # Declarative authorization policies
│   └── tests/
│       └── agent_execution_test.yaml  # Cerbos compiler test suite
├── orchestrator/
│   ├── orchestrator.py                # Ultra-thin planner and execution dispatcher
│   └── config/
│       └── capabilities.yaml          # Declarative capability-to-agent mapping
├── ax/
│   ├── adapter.py                     # Thin AX admission adapter enforcing Cerbos checks
│   └── cerbos_client.py               # Cerbos PDP client with fail-closed semantics
├── agents/
│   ├── catalog.yaml                   # Upstream agent images, commands, digests
│   ├── Dockerfile.browser             # Browser agent container packaging
│   └── browser_cli.py                 # Upstream browser CLI
├── tests/
│   ├── test_cerbos_policy.py          # Cerbos policy contract tests
│   ├── test_authorization.py          # Authorization and identity propagation tests
│   ├── test_execution_flow.py         # Substrate execution and zero-workload denial tests
│   ├── test_policy_dynamic_switch.py  # Dynamic policy revocation and restoration tests
│   ├── test_fail_closed.py            # Fail-closed invariant tests
│   └── test_security_boundaries.py    # Security boundary and bypass tests
└── scripts/
    ├── setup.sh                       # Environment setup script
    ├── verify.sh                      # Test verification runner
    ├── demo.sh                        # Interactive demo runner
    ├── teardown.sh                    # Teardown script
    └── audit_anti_hardcoding.sh       # Anti-hardcoding static audit script
```

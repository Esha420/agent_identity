# Multi-Agent Dual-Layer Authorization Reference Architecture

A minimal, reproducible reference architecture demonstrating policy-driven authorization at two distinct boundaries:
1. **Layer 1: Workload Admission Gate (AX Admission PEP)**: Intercepts orchestrator intent before materializing agent workloads into an isolated execution sandbox.
2. **Layer 2: Runtime Tool Invocation Gate (Tool Gateway PEP)**: Intercepts every concrete tool call (`fetch_url`, `browser_navigate`, `filesystem_read`, `filesystem_write`) made by the running agent inside the sandbox.

```text
USER / OIDC
    │
    ▼
ORCHESTRATOR
    │ requested capability only
    ▼
AX ADMISSION PEP (ax/adapter.py)
├── verify workload identity (attestation & credentials)
├── resolve trusted catalog
├── derive principal attributes
├── authorize with Cerbos PDP (Resource: agent, Action: execute)
├── submit immutable AX task (ax apply)
└── mint signed TaskExecutionContext (only after AX acceptance)
    │
    ▼
AX / SUBSTRATE TASK (Isolated Sandbox)
    │
    ▼
BROWSER AGENT
    │ tool intent + arguments only
    ▼
TOOL GATEWAY PEP (tools/gateway.py)
├── verify context signature, issuer, audience, lease, & epoch
├── verify task binding & derive caller identity from context
├── catalog capability gate & tool set hash integrity
├── normalize arguments (URL & canonical path)
├── validate network (A/AAAA, anti-SSRF, IP classification)
├── call Cerbos PDP (Resource: tool, Action: per-call operation)
└── invoke handler only on ALLOW (zero side-effects on denial)
```

---

## What This Project Demonstrates

1. **Two-Layer Policy-Driven Authorization**:
   - **Workload Admission (Layer 1)**: Starting an agent workload requires explicit authorization from Cerbos. Denied requests result in **zero AX tasks and zero Substrate workloads**.
   - **Runtime Tool Governance (Layer 2)**: Running an agent does *not* confer blanket network, browser, or filesystem permissions. Every tool invocation is authenticated, validated, and authorized dynamically before execution.
2. **Defense-in-Depth Argument Normalization & Containment**:
   - **Anti-SSRF Protection**: Normalizes URLs, blocks userinfo credentials, enforces host allowlists, performs DNS resolution, and rejects private/loopback/cloud-metadata IPs (`169.254.169.254`).
   - **Filesystem Containment**: Replaces brittle string prefix checks with canonical path resolution and strict root containment (`Path.relative_to()`), defeating path traversal (`../`) and prefix spoofing (`/workspace-evil`).
   - **Separated Roots**: Read operations (`filesystem_read`) and write operations (`filesystem_write`) are strictly segregated.
3. **Immutable Task Context Binding**:
   - Layer 2 requests must present an immutable `TaskExecutionContext` (`task_id`, `tenant_id`, `parent_principal`, `delegated_by`, `environment`). Cerbos policies enforce exact identity and task binding.
4. **Per-Invocation Dynamic Revocation**:
   - Agent admission is evaluated once at workload creation.
   - Tool permissions are evaluated on **every single call**. Updating policies revokes access immediately for already-running workloads.
5. **Zero Side-Effects Guarantee on Denial**:
   - Denied tool calls guarantee `outbound_network_calls == 0`, `bytes_sent == 0`, and `filesystem_mutations == 0`. Workloads do not crash; structured denial responses are returned and audited.
6. **Bypass Resistance**:
   - In-process Tool Gateway PEP demonstrates application-level governance. The container sandbox and egress network boundaries ensure external commands cannot bypass gateway policies.

---

## Agent-Level vs. Tool-Level Authorization

| Dimension | Decision 1: Workload Admission Gate | Decision 2: Tool Invocation Gate |
| :--- | :--- | :--- |
| **Enforcement Point** | AX Admission Adapter (`ax/adapter.py`) | Tool Gateway PEP (`tools/gateway.py`) |
| **Principal** | `orchestrator-agent` (roles: `["orchestrator"]`) | Running agent, e.g. `browser-agent` (roles: `["browser-worker"]`) |
| **Principal Attributes** | `{ "tenant_id": "...", "delegated_by": "user-123" }` | Immutable TaskExecutionContext: `{ "task_id": "...", "tenant_id": "...", "parent_principal": "orchestrator-agent", "delegated_by": "user-123", "authorization_epoch": 1 }` |
| **Resource Kind** | `agent` | `tool` |
| **Resource ID** | `browser-agent`, `research-agent`, `restricted-agent` | `fetch_url`, `browser_navigate`, `filesystem_read`, `filesystem_write` |
| **Resource Attributes** | Catalog metadata (`capability`, `sensitivity`) | Dynamic trusted facts supplied from catalog (`allowed_hosts`, `allowed_methods`, `allowed_path_roots`, `side_effect`) |
| **Actions** | `execute` | `request`, `navigate`, `read`, `write` |
| **Context Evaluated** | Environment, task prompt | Normalized host, port, scheme, `resolved_ip_is_public`, canonical path, `path_is_contained`, task & tenant bindings |
| **Denial Outcome** | **Fail-closed: 0 AX tasks, 0 workloads created** | **Fail-closed: 0 network calls, 0 disk mutations, structured error returned, workload continues** |
| **Revocation Timing** | Admission is checked once at startup | **Checked per invocation**. Revoking policy blocks the next tool call immediately |

---

## Policies in Scope

Declarative YAML policies governing agent workloads and tool executions are located in:
- 📁 **[`cerbos/policies/agent_execution.yaml`](cerbos/policies/agent_execution.yaml)**: Governs Layer 1 agent workload admission.
- 📁 **[`cerbos/policies/tool_execution.yaml`](cerbos/policies/tool_execution.yaml)**: Governs Layer 2 runtime tool invocation.

Unit tests validating these policies via the Cerbos compiler are located in:
- 📁 **[`cerbos/tests/agent_execution_test.yaml`](cerbos/tests/agent_execution_test.yaml)**
- 📁 **[`cerbos/tests/tool_execution_test.yaml`](cerbos/tests/tool_execution_test.yaml)**

---

## Quick Start

### 1. Setup Environment
```bash
./scripts/setup.sh
```

### 2. Run Automated Verification Suite (52 Tests)
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

## Project Structure

```
.
├── README.md
├── Makefile
├── docker-compose.yaml
├── .env.example
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
│   │   ├── agent_execution.yaml       # Layer 1 Workload admission policies
│   │   └── tool_execution.yaml        # Layer 2 Runtime tool policies
│   └── tests/
│       ├── agent_execution_test.yaml  # Cerbos compiler test suite for agents
│       └── tool_execution_test.yaml   # Cerbos compiler test suite for tools
├── orchestrator/
│   ├── orchestrator.py                # Ultra-thin planner and execution dispatcher
│   └── config/
│       └── capabilities.yaml          # Declarative capability-to-agent mapping
├── ax/
│   ├── adapter.py                     # AX admission adapter enforcing Cerbos checks
│   └── cerbos_client.py               # Cerbos PDP client with fail-closed semantics
├── tools/
│   ├── catalog.yaml                   # Authoritative tool catalog (hosts, paths, profiles)
│   ├── schema.py                      # Canonical schemas: TaskExecutionContext, ToolRequest, AuditEvent
│   ├── security.py                    # SSRF prevention, IP classification, canonical filesystem containment
│   └── gateway.py                     # Tool Gateway PEP engine enforcing per-call authorization
├── agents/
│   ├── catalog.yaml                   # Agent catalog declaring capability gate & allowed_tools
│   ├── tool_client.py                 # Governed tool client interface for agent processes
│   └── browser_cli.py                 # Governed browser automation agent CLI
├── tests/
│   ├── test_cerbos_policy.py          # Layer 1 Cerbos policy contract tests
│   ├── test_authorization.py          # Layer 1 Identity propagation tests
│   ├── test_fail_closed.py            # Layer 1 Fail-closed tests
│   ├── test_security_boundaries.py    # Layer 1 Security boundary tests
│   ├── test_tool_authorization.py     # Layer 2 Tool policy contract tests
│   ├── test_tool_gateway.py           # Layer 2 Tool Gateway PEP integration & anti-SSRF tests
│   ├── test_tool_policy_dynamic_switch.py # Layer 2 Per-invocation policy revocation tests
│   ├── test_execution_flow.py         # Substrate execution and zero-workload denial tests
│   └── test_policy_dynamic_switch.py  # Layer 1 Dynamic policy revocation tests
└── scripts/
    ├── setup.sh                       # Environment setup script
    ├── verify.sh                      # Test verification runner (compile + Python suites)
    ├── demo.sh                        # Interactive dual-layer demo runner
    ├── teardown.sh                    # Teardown script
    └── audit_anti_hardcoding.sh       # Anti-hardcoding static audit script
```

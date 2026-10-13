# Multi-Agent Dual-Layer Authorization Reference Architecture
## Production-Grade AI Agent Governance with Google AX, Agent Substrate, and Cerbos PDP

[![Cerbos Policy Tests](https://img.shields.io/badge/Cerbos-v0.56.0%20Verified-blue.svg)](https://cerbos.dev)
[![Python Tests](https://img.shields.io/badge/Tests-89%20Passing-brightgreen.svg)]()
[![Security Boundary](https://img.shields.io/badge/Security-Dual--Layer%20PEP%2FPDP-orange.svg)]()
[![MCP Compliance](https://img.shields.io/badge/MCP-JSON--RPC%202.0%20Governed-purple.svg)]()

---

## 1. Executive Summary & Core Philosophy

This repository is a production-grade, reproducible reference architecture implementing **end-to-end, policy-driven authorization for autonomous AI multi-agent systems**.

Modern LLM-powered autonomous agents introduce severe security risks when granted ambient access to tools, network endpoints, and execution environments. Common failure modes include prompt injections manipulating agents into unintended actions, confused deputy attacks where agents access resources on behalf of unauthorized callers, ambient tool privilege creep, and severe runtime vulnerabilities such as Server-Side Request Forgery (SSRF), DNS rebinding, and directory traversal.

To eliminate these vulnerabilities, this project enforces two inviolable architectural axioms:

> ### Axiom 1: Admission $\neq$ Authorization
> Admitting an agent to execute a task **never** confers ambient or blanket permission to use every tool, network destination, or file path associated with that agent. Admission allows the workload to materialize into an isolated execution sandbox; every subsequent tool call is independently authenticated, validated, and authorized at runtime.

> ### Axiom 2: Strict PDP / PEP Decoupling
> Agent-internal instructions and prompt-based guardrails are **not** security boundaries. The **Policy Decision Point (PDP)** (Cerbos) centrally evaluates declarative policies against verified identity and resource context. An unavoidable, external **Policy Enforcement Point (PEP)** (AX Admission PEP at Layer 1; Tool Gateway PEP / MCP Server at Layer 2) intercepts every intent and concrete operation, blocking unauthorized calls with a mathematical **zero side-effects guarantee**.

---

## 2. The Problems This Implementation Solves

Traditional agent deployments suffer from critical architectural weaknesses. This reference architecture addresses and neutralizes each one:

| Vulnerability / Anti-Pattern | Traditional Vulnerability | How This Architecture Solves It |
| :--- | :--- | :--- |
| **In-Agent "Guardrails" Fallacy** | Relying on system prompts or in-agent "Global Policy" instructions to prevent forbidden actions. Easily bypassed via jailbreaks and indirect prompt injection. | **Externalized Enforcement**: The agent container has no authority. An external `ToolGatewayPEP` intercepts every tool invocation before it reaches any handler or network socket. |
| **Confused Deputy & Identity Spoofing** | Agents self-assert identity, user IDs, or tenant IDs in request parameters, spoofing elevated privileges. | **Cryptographic Context Binding**: Callers cannot assert identity. Workload attributes are extracted strictly from an HMAC-signed `TaskExecutionContext` minted by the admission gate. |
| **Ambient Tool Privileges** | Granting an admitted agent unrestricted access to all tools registered in an MCP server. | **Per-Invocation Dynamic Authorization**: Tool execution is authorized per call against concrete arguments, URLs, HTTP methods, and canonical file paths. |
| **SSRF & DNS Rebinding (TOCTOU)** | Naive regex or domain allowlisting that fails against DNS rebinding, private IP ranges, loopbacks, or cloud metadata endpoints (`169.254.169.254`). | **Multi-Tier Network Pipeline**: Syntactic URL validation, credential stripping, DNS A/AAAA record resolution, IP classification, and redirect re-validation (`GovernedRedirectHandler`). |
| **Path Traversal & Prefix Spoofing** | Checking path string prefixes (`/workspace`), allowing traversal (`/workspace/../etc/passwd`) or sibling prefix spoofing (`/workspace-evil`). | **Canonical Containment**: Resolves paths via `.resolve()` and validates containment strictly with `Path.relative_to()`. Strictly segregates read and write roots. |
| **The In-JWT Policy Anti-Pattern** | Attempting to dynamically generate policy code and attach it into JWT tokens per request, bloating tokens and violating separation of concerns. | **Clean Token vs. Policy Separation**: Tokens hold authenticated identity claims and cryptographic delegation grants; central Cerbos policy stores hold approved rules evaluated against request context. |
| **Lack of Revocation** | Workloads running long tasks retain privileges even after admin policies change or credentials are compromised. | **Immediate Multi-Granular Revocation**: Policy edits take effect on the very next invocation. Supports instantaneous epoch revocation and task ID blacklisting. |

---

## 3. Revised End-to-End Architecture

The platform cleanly separates the **ingress / user mapping boundary**, the **orchestration plane**, the **workload admission gate (Layer 1)**, the **isolated execution sandbox**, the **runtime tool enforcement gateway (Layer 2)**, and the **central Cerbos PDP**:

```text
SLACK / TELEGRAM (Ingress Interface)
    │
    ▼
INGRESS & TRUSTED MAPPING (auth/auth0_verifier.py)
├── Authenticate Operator via Identity Provider (Auth0 / OIDC)
├── Extract verified user claims (sub, org_id, permissions)
└── Prevent LLM hallucination of user_id, tenant, or roles
    │
    ▼
OPENCLAW ORCHESTRATOR (ax/coordinator.py)
├── Analyze user intent into declarative task DAG
├── Map capabilities strictly to registered catalog agents (agents/catalog.yaml)
└── Derive authoritative Scope Summary Cards BEFORE execution
    │
    ▼
============================== LAYER 1: WORKLOAD ADMISSION GATE ==============================
AX ADMISSION PEP (ax/adapter.py)
├── 1. Verify orchestrator workload credentials & tenant isolation
├── 2. Resolve target agent, immutable image digest, and command from catalog
├── 3. Query Cerbos PDP for Layer 1 authorization (Resource: agent, Action: execute)
├── 4. Fail-closed rejection: On DENY, create ZERO tasks, ZERO containers
├── 5. Submit immutable task manifest to Google AX Control Plane (bin/ax apply -f ...)
├── 6. Receive authoritative AX task identity from control plane
└── 7. Mint short-lived, HMAC-signed TaskExecutionContext (bound to AX task & image digest)
    │
    ▼
GOOGLE AX CONTROL PLANE & AGENT SUBSTRATE
├── Reconciles task manifest and schedules workload onto isolated worker
└── Executes agent inside an isolated gVisor container sandbox (read-only rootfs)
    │
    ▼
CONTAINERIZED SPECIALIZED AGENTS
├── Browser Agent / Website Investigator
├── Log Analysis Agent (SRE Specialist)
├── Incident Reporter (Document Specialist)
└── Research Agent (OpenClaw Specialist)
    │
    │ [Agent submits: tool intent, action, concrete arguments, & signed TaskExecutionContext token]
    ▼
============================== LAYER 2: RUNTIME TOOL GATEWAY PEP =============================
TOOL GATEWAY PEP & MCP SERVER (tools/gateway.py & tools/mcp_server.py)
├── 1. Verify HMAC signature, issuer, audience, lease expiration, & authorization epoch
├── 2. Derive task_id, agent_id, tenant_id, delegated_by strictly from verified token
├── 3. Reject claimed/spoofed identity mismatches in arguments (TASK_ID_MISMATCH)
├── 4. Verify catalog allowed_tools and tool-set SHA-256 hash integrity
├── 5. Input Normalization:
│      • URLs: strip userinfo credentials, enforce protocol & port allowlists
│      • DNS: resolve A/AAAA records, classify IPs, block SSRF & cloud metadata (169.254.169.254)
│      • Filesystem: resolve canonical paths, enforce strict root containment (Path.relative_to)
├── 6. Query Cerbos PDP for Layer 2 authorization (Resource: tool, Action: per-call operation)
├── 7. ALLOW: Execute tool handler / forward to MCP server with zero credential exposure
└── 8. DENY: Fail closed immediately (0 network calls, 0 disk mutations, emit structured audit)
    │
    ▼
CENTRAL CERBOS PDP (cerbos:3592)
├── Evaluates Layer 1 policies: cerbos/policies/agent_execution.yaml
└── Evaluates Layer 2 policies: cerbos/policies/tool_execution.yaml
```

---

## 4. The 6 Architectural Pillars

### Pillar 1: Separation of Authentication (IdP) from Authorization (Cerbos PDP)
* **The Principle**: Authentication establishes *who you are*; authorization determines *what you may do*.
* **Implementation**: The Identity Provider (Auth0 / OIDC) authenticates the user and issues an RS256-signed JWT. [`auth/auth0_verifier.py`](auth/auth0_verifier.py) validates the token signature, issuer, audience, and expiration using public keys/JWKS. It derives trusted principal attributes (`user_id`, `tenant_id`, `permissions`).
* **Boundary**: Cerbos is **never** used as an OAuth server or IdP. Cerbos receives verified identity claims as principal attributes and evaluates whether that principal is authorized for the requested resource and action. Slack and Telegram users are mapped deterministically to tenant boundaries—the LLM is completely forbidden from inventing user IDs or roles.

### Pillar 2: Strict Decoupling of Tokens vs. Policies
* **The Principle**: Tokens must carry identity and scoped delegation context—**not** embedded policy logic or dynamic policy code.
* **Implementation**: The system mints a compact, HMAC-SHA256-signed [`TaskExecutionContext`](tools/schema.py). It binds:
  ```json
  {
    "task_id": "task-browser-agen-355f35",
    "agent_id": "browser-agent",
    "roles": ["browser-worker"],
    "tenant_id": "tenant-demo",
    "parent_principal": "orchestrator-agent",
    "delegated_by": "auth0|user-123",
    "agent_image_digest": "sha256:8abae590b3dcf422...",
    "allowed_tool_set_hash": "e3b0c44298fc1c14...",
    "authorization_epoch": 1,
    "expires_at": 1775836800
  }
  ```
* **Evaluation**: Approved authorization rules live exclusively in the central Cerbos policy store (`cerbos/policies/`). The Tool Gateway evaluates incoming requests against these central policies using attributes derived from the token. Tokens are never rewritten or injected with executable policy rules during tool calls.

### Pillar 3: Externalized Enforcement vs. In-Agent Illusions
* **The Principle**: Enforceable rules must live outside the agent. Agent-local instructions are guidance, not security boundaries.
* **Implementation**: The running container has zero access to policy files or HMAC signing keys. The tool client submits only tool intent and arguments to `ToolGatewayPEP`. The invariant enforced across all layers is:
  $$\text{Execute} \iff \text{Global Policy Permitted} \land \text{Agent Permitted} \land \text{User Authority Permitted} \land \text{Task Scope Permitted}$$
* **Parental Consent Semantics**: When using Cerbos scoped policies, `SCOPE_PERMISSIONS_REQUIRE_PARENTAL_CONSENT_FOR_ALLOWS` ensures child scopes cannot expand permissions beyond the parent policy.

### Pillar 4: Unavoidable Tool Enforcement Gateway (PEP)
* **The Principle**: No agent tool call can reach handlers, network sockets, or backend systems without traversing an enforcement gate that validates concrete arguments.
* **Implementation**: [`tools/gateway.py`](tools/gateway.py) and [`tools/mcp_server.py`](tools/mcp_server.py) intercept all calls:
  1. **SSRF & DNS Defense**: Resolves all A and AAAA records via `socket.getaddrinfo`. If **any** returned IP belongs to loopback, private, multicast, or cloud metadata ranges (`169.254.169.254`), the request is rejected immediately before any HTTP connection is attempted.
  2. **HTTP Redirect Interception**: `GovernedRedirectHandler` re-validates all HTTP 3xx redirect destinations against the full DNS/SSRF pipeline, preventing DNS rebinding.
  3. **Canonical Filesystem Containment**: File paths are normalized via `.resolve()`, stripped of traversal sequences (`../`), and verified strictly within segregated roots (`/workspace/input` for reads, `/workspace/output` for writes).
  4. **Zero Side-Effects Guarantee**: Denied calls guarantee `outbound_network_calls == 0`, `bytes_sent == 0`, and `filesystem_mutations == 0`.

### Pillar 5: Separation of Task Execution from Policy Publication
* **The Principle**: Proposing or requesting a task must never grant or publish new authority.
* **Two Distinct Lifecycles**:
  1. **Ordinary Task Path**: Operator Prompt $\rightarrow$ OpenClaw analyzes intent $\rightarrow$ matches registered catalog template $\rightarrow$ existing Cerbos policies authorize $\rightarrow$ AX executes task $\rightarrow$ Tool Gateway enforces per call.
  2. **Policy Change Path**: Policy proposal $\rightarrow$ static validation & unit testing (`cerbos compile --tests`) $\rightarrow$ administrative review & cryptographic signing $\rightarrow$ deployment to Cerbos policy store.
* Workload agents have zero credentials to modify or publish policies.

### Pillar 6: Disambiguating the Runtime (AX + Agent Substrate)
* **The Principle**: Distinguish declarative agent templates from runtime task sessions.
* **Implementation**:
  - **Agent Templates**: Declarative specifications in [`agents/catalog.yaml`](agents/catalog.yaml) declaring the immutable container image digest, default entrypoint command, and allowed tool capabilities.
  - **Task Sessions (Actors)**: Ephemeral, task-specific sessions materialized on Agent Substrate workers using native Google AX manifests (`apiVersion: ax.v1alpha1`, `kind: Task`).
  - **Attenuated Co-located Sub-Agents**: Multiple specialized sub-agents running inside the same Substrate sandbox pod receive distinct, attenuated `TaskExecutionContext` tokens. Sub-Agent A (browser) cannot invoke filesystem tools, and Sub-Agent B (log reader) cannot navigate the browser ([`scripts/showcase_shared_actor.py`](scripts/showcase_shared_actor.py)).

---

## 5. Dual-Layer Authorization Contract Details

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        LAYER 1: WORKLOAD ADMISSION GATE                                │
│                        Enforcement Point: ax/adapter.py                                │
└────────────────────────────────────────────────────────────────────────────────────────┘
 • Principal:       orchestrator-agent (roles: ["orchestrator"])
 • Resource:        agent (id: browser-agent, log-analysis-agent, restricted-agent)
 • Action:          execute
 • Policy File:     cerbos/policies/agent_execution.yaml
 • Attributes:      tenant_id, user_id, permissions (from verified Auth0 OIDC token)
 • Denial Outcome:  FAIL-CLOSED: 0 AX tasks created, 0 containers created.

                                     │
                                     ▼ Task Accepted & Token Minted
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        LAYER 2: RUNTIME TOOL INVOCATION GATE                           │
│                        Enforcement Point: tools/gateway.py & tools/mcp_server.py       │
└────────────────────────────────────────────────────────────────────────────────────────┘
 • Principal:       Running agent (id: browser-agent, roles: ["browser-worker"])
 • Resource:        tool (id: fetch_url, browser_navigate, filesystem_read, filesystem_write)
 • Action:          request, navigate, read, write
 • Policy File:     cerbos/policies/tool_execution.yaml
 • Attributes:      Extracted strictly from TaskExecutionContext:
                    task_id, tenant_id, parent_principal, delegated_by, epoch, tool_hash
 • Concrete Facts:  Normalized URL, port, scheme, ip_valid, canonical_path, path_contained
 • Denial Outcome:  FAIL-CLOSED: 0 network calls, 0 disk bytes modified. Workload continues.
```

---

## 6. Repository Structure & File Mapping

```
.
├── auth/
│   └── auth0_verifier.py             # Auth0 RS256 token verification, JWKS & tenant isolation
├── ax/
│   ├── adapter.py                    # Layer 1 AX Admission PEP connecting orchestrator & Cerbos
│   ├── cerbos_client.py              # Fail-closed HTTP client for Cerbos PDP
│   └── coordinator.py                # OpenClaw Intent-to-Task DAG planner & scope generator
├── bin/
│   └── ax                            # Native Google AX CLI binary
├── cerbos/
│   ├── cerbos.yaml                   # Cerbos PDP daemon configuration
│   ├── policies/
│   │   ├── agent_execution.yaml      # Layer 1 Workload admission policies
│   │   └── tool_execution.yaml       # Layer 2 Runtime tool policies
│   └── tests/
│       ├── agent_execution_test.yaml # Cerbos compiler unit test suite for agents
│       └── tool_execution_test.yaml  # Cerbos compiler unit test suite for tools
├── tools/
│   ├── catalog.yaml                  # Authoritative tool catalog (hosts, ports, paths, profiles)
│   ├── schema.py                     # Canonical schemas: TaskExecutionContext, ToolRequest, AuditEvent
│   ├── security.py                   # Anti-SSRF, DNS classification, and canonical path containment
│   ├── gateway.py                    # Layer 2 Tool Gateway PEP enforcing per-invocation authorization
│   ├── mcp_server.py                 # Governed Model Context Protocol (MCP) JSON-RPC 2.0 server
│   └── audit.py                      # Correlation ID tracer and structured audit correlator
├── agents/
│   ├── catalog.yaml                  # Declarative agent templates with image digests & allowed_tools
│   ├── tool_client.py                # In-workload client submitting signed tool requests
│   └── browser_cli.py                # Governed browser automation CLI
├── scripts/
│   ├── setup.sh                      # Environment initialization & container startup
│   ├── verify.sh                     # Complete automated verification suite runner
│   ├── demo.sh                       # Interactive authorization walkthrough
│   ├── showcase_shared_actor.py      # Attenuated sub-agents in shared Substrate actor
│   ├── slack_incident_listener.py    # Production Slack Socket Mode gateway
│   ├── run_slack_acceptance_test.py  # End-to-end Slack autonomous acceptance test
│   └── audit_anti_hardcoding.sh      # Static analysis checking for hardcoded credentials/bypasses
└── tests/
    ├── test_auth0_oidc.py            # OIDC token validation & cryptographic signature tests
    ├── test_user_delegation_auth0.py # Anti-spoofing and multi-tenant delegation tests
    ├── test_cerbos_policy.py         # Layer 1 policy contract tests
    ├── test_tool_authorization.py    # Layer 2 tool policy contract tests
    ├── test_tool_gateway.py          # Anti-SSRF, DNS rebinding, and path containment integration
    ├── test_tool_policy_dynamic_switch.py # Per-invocation dynamic revocation tests
    └── test_complete_authorization_enforcement.py # End-to-end multi-layer invariant tests
```

---

## 7. Verification & Empirical Proof

### 1. Complete Test Suite Execution (89 Passing Tests)
Every security boundary and policy contract is verified continuously:
```bash
./scripts/verify.sh
```
```text
=================================================================
[VERIFY] Running Complete Automated Verification Suite
=================================================================
[Step 1/3] Compiling Cerbos policies and running PDP unit tests...
SUCCESS: Compiled 2 policies and ran 2 test suites (0 errors)

[Step 2/3] Running Layer 1 Admission & Layer 2 Tool Gateway test suites...
Ran 89 tests in 8.775s
OK

=================================================================
[VERIFICATION SUCCESS] All policy, admission, tool governance,
and fail-closed security tests PASSED.
=================================================================
```

### 2. Proof of Runtime Enforcement: Read-Only Violation Test
To empirically prove that admission does not grant ambient authority, the test suite executes an active attack where an admitted read-only Log Analyst attempts a filesystem write:
1. Operator submits `test readonly-write` via Slack Socket Mode.
2. Coordinator computes SHA-256 hash of `./workspace/logs/sample_staging.log` (`898a2c621c...`).
3. AX admits `log-analysis-agent` with role `monitoring-worker` and read permissions.
4. Agent executes `filesystem_read` on the log (Status: `ALLOW`).
5. Agent attempts `filesystem_write` with malicious payload to `./workspace/logs/sample_staging.log`.
6. `ToolGatewayPEP` intercepts the call:
   - Tool `filesystem_write` is absent from `allowed_tools` in `agents/catalog.yaml` (`CATALOG_DENIED`).
   - Cerbos PDP policy `tool_execution.yaml` forbids write actions for `monitoring-worker` (`AUTHZ_DENIED`).
   - Tool handler is **never invoked**.
7. Coordinator recalculates hash:
   $$\text{SHA256}_{\text{before}} == \text{SHA256}_{\text{after}} \implies \mathbf{0\text{ bytes mutated}}$$
8. Denial event with correlation ID and zero-mutation proof is posted back to Slack thread.

---

## 8. Quick Start

### 1. Setup Environment
Start the Cerbos PDP and mock target containers:
```bash
./scripts/setup.sh
```

### 2. Run Verification Suite
Run the 89-test verification suite covering Cerbos compilation, OIDC tokens, anti-SSRF, and dynamic revocation:
```bash
./scripts/verify.sh
```

### 3. Run Co-Located Attenuated Sub-Agents Demo
Demonstrate two sub-agents sharing the same Substrate sandbox pod with independent, attenuated permissions:
```bash
python3 scripts/showcase_shared_actor.py
```

### 4. Run Governed Slack Operations Acceptance Suite
Run the automated Slack Socket Mode acceptance tests:
```bash
python3 scripts/run_slack_acceptance_test.py
```

### 5. Launch Governed MCP Tool Server
Start the MCP JSON-RPC 2.0 tool gateway on port 8095:
```bash
python3 tools/mcp_server.py
```

---

## 9. License & References

- [Cerbos Dynamic Authorization for AI Agents & MCP Servers](https://www.cerbos.dev/blog/dynamic-authorization-for-ai-agents-guide-to-fine-grained-permissions-mcp-servers)
- [Fine-Grained Authorization for AI Gateways](https://www.cerbos.dev/blog/fine-grained-authorization-for-ai-gateways)
- [Cerbos Scoped Policies & Parental Consent](https://docs.cerbos.dev/cerbos/latest/policies/scope_permissions)
- [Agent Substrate Architecture](https://kagent.dev/docs/kagent/1.x/about/architecture/agent-substrate/)

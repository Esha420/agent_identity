# Security Model: Multi-Agent Dual-Layer Authorization Architecture

## 1. Core Security Entities

- **Principal**:
  - *Layer 1*: Logical identity initiating agent workload execution (`orchestrator-agent` with roles `["orchestrator"]`).
  - *Layer 2*: Running agent identity (`browser-agent` with roles `["browser-worker"]`) carrying an immutable, cryptographically signed `TaskExecutionContext` (`task_id`, `tenant_id`, `parent_principal`, `delegated_by`, `environment`, `agent_image_digest`, `allowed_tool_set_hash`, `issuer`, `audience`, `authorization_epoch`).
- **Resource**:
  - *Layer 1*: Target agent capability (`browser-agent`, `research-agent`, `restricted-agent` of kind `agent`).
  - *Layer 2*: Target tool invocation (`fetch_url`, `browser_navigate`, `filesystem_read`, `filesystem_write` of kind `tool`).
- **Action**:
  - *Layer 1*: `execute` (admin actions like `delete`, `admin` are strictly blocked).
  - *Layer 2*: `request`, `navigate`, `read`, `write`.
- **Context**:
  - *Layer 1*: Verified tenant, delegated user, task metadata.
  - *Layer 2*: Normalized hostname, port, scheme, verified IP classification flag, canonical path containment flag, and task identity bindings.

---

## 2. Dual Authorization Boundaries

```text
  [Orchestrator Intent] ──>  [Layer 1 Admission PEP]  ──>  [Isolated Sandbox Workload]  ──>  [Layer 2 Tool Gateway PEP]  ──>  [System I/O]
                                     │ (Authorize Workload)                                          │ (Authorize Concrete Call)
                                     ▼                                                               ▼
                                Cerbos PDP                                                      Cerbos PDP
                           (agent_execution.yaml)                                          (tool_execution.yaml)
```

### Fail-Closed Execution Invariants

#### Layer 1 (Workload Admission Gate):
```text
Authorization = ALLOW           ──>  AX creates Task  ──>  Substrate executes workload
Authorization = DENY            ──>  AX rejects       ──>  ZERO AX Tasks / ZERO Substrate Workloads
Authorization = UNKNOWN / ERROR ──>  AX rejects       ──>  ZERO AX Tasks / ZERO Substrate Workloads
```

#### Layer 2 (Runtime Tool Governance Gate):
```text
Authorization = ALLOW           ──>  Tool executes    ──>  Governed network / disk I/O
Authorization = DENY            ──>  Tool blocked     ──>  ZERO outbound network calls / ZERO file writes
Authorization = UNKNOWN / ERROR ──>  Tool blocked     ──>  ZERO outbound network calls / ZERO file writes
```

---

## 3. Tool Failure & Violation Model

| Failure Type | Gateway Decision | Code | Tool Runs? | Workload Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Malformed Arguments** | `REJECTED_PEP` | `INVALID_ARGUMENTS` | No | Workload continues safely |
| **Tool Absent in Agent Catalog** | `DENY` | `CATALOG_DENIED` | No | Workload continues safely |
| **SSRF / Forbidden Host / IP** | `REJECTED_PEP` | `INVALID_ARGUMENTS` | No | Workload continues safely |
| **Path Traversal / Escape** | `REJECTED_PEP` | `INVALID_ARGUMENTS` | No | Workload continues safely |
| **Cerbos Policy Denial** | `DENY` | `AUTHZ_DENIED` | No | Workload continues safely |
| **Cerbos PDP Unreachable** | `ERROR_FAIL_CLOSED` | `AUTHZ_DENIED` | No | Workload continues safely |
| **Task Context Tampering / Bad Signature** | `REJECTED_PEP` | `INVALID_TASK_CONTEXT` | No | Workload continues safely |
| **Expired Context Lease** | `REJECTED_PEP` | `INVALID_TASK_CONTEXT` | No | Workload continues safely |
| **Revoked Authorization Epoch** | `REJECTED_PEP` | `INVALID_TASK_CONTEXT` | No | Workload continues safely |
| **Spoofed Task / Agent ID in Arguments** | `REJECTED_PEP` | `TASK_ID_MISMATCH` / `AGENT_ID_MISMATCH` | No | Workload continues safely |
| **Handler Execution Error** | `ALLOW` | `EXECUTION_ERROR` | Attempted | Workload reports error |

---

## 4. Identity-Provenance Verification Matrix

The test suite in [`tests/test_identity_provenance.py`](file:///home/esha/Office/agent_identity/tests/test_identity_provenance.py) verifies the complete identity provenance chain across both layers:

| # | Test Scenario | Evaluated Layer | Enforcement Point | Expected Result |
| :---: | :--- | :--- | :--- | :--- |
| **1** | Orchestrator supplies forged role | Layer 1 | AX Admission PEP / Workload Attestation | `REJECTED_PEP` (0 AX tasks, 0 workloads) |
| **2** | Orchestrator supplies another tenant | Layer 1 | AX Admission PEP / Workload Attestation | `REJECTED_PEP` (0 AX tasks, 0 workloads) |
| **3** | Orchestrator supplies forged delegated_by | Layer 1 | AX Admission PEP / Workload Attestation | `REJECTED_PEP` (0 AX tasks, 0 workloads) |
| **4** | Requested agent differs from catalog resolution | Layer 1 | Trusted Agent Catalog Resolver | `REJECTED_UNKNOWN_AGENT` (0 workloads) |
| **5** | AX task image differs from catalog digest | Layer 1 | Catalog Image Integrity Verifier | `REJECTED_IMAGE_MISMATCH` (0 workloads) |
| **6** | Tool request claims another task ID | Layer 2 | Tool Gateway PEP Explicit Identity Check | `TASK_ID_MISMATCH` (0 network calls) |
| **7** | Tool request claims another agent ID | Layer 2 | Tool Gateway PEP Explicit Identity Check | `AGENT_ID_MISMATCH` (0 network calls) |
| **8** | Expired context lease | Layer 2 | Tool Gateway Cryptographic Verifier | `INVALID_TASK_CONTEXT` (0 network calls) |
| **9** | Wrong audience context (`billing-gateway`) | Layer 2 | Tool Gateway Cryptographic Verifier | `INVALID_TASK_CONTEXT` (0 network calls) |
| **10** | Invalid context signature (tampered payload) | Layer 2 | Tool Gateway Cryptographic Verifier | `INVALID_TASK_CONTEXT` (0 network calls) |
| **11** | Revoked authorization epoch | Layer 2 | Tool Gateway Epoch Tracker | `INVALID_TASK_CONTEXT` (0 network calls) |
| **12** | Correct agent but wrong tenant | Layer 2 | Cerbos PDP Dynamic Policy Evaluator | `AUTHZ_DENIED` (0 network calls) |
| **13** | Correct task but wrong delegated user | Layer 2 | Cerbos PDP Dynamic Policy Evaluator | `AUTHZ_DENIED` (0 network calls) |

---

## 5. Bypass Resistance & Defense in Depth

In an agentic environment, an in-process application gateway (`ToolGatewayPEP`) enforces policy compliance for governed code paths. However, a compromised or adversarial agent container could attempt unmediated host calls (`socket.create_connection`, `wget`, `raw open()`).

To guarantee defense-in-depth, this architecture relies on a multi-tier defense:

1. **Application Layer (Tool Gateway PEP)**:
   - Validates caller authentication, task bindings, host allowlists, DNS resolution, and canonical filesystem containment before invoking handlers.
   - Provides structured error responses and comprehensive audit logs.
2. **Runtime Sandbox Layer (Agent Substrate / gVisor)**:
   - Workloads run inside isolated gVisor sandboxes (`gvisor-default`), intercepting system calls and preventing container escape into host kernel space.
3. **Network Egress Boundary Layer (Substrate / Cluster Policy)**:
   - The sandbox network namespace is restricted by default. Workloads cannot reach cloud metadata endpoints (`169.254.169.254`), private cluster APIs (`api.ate-system.svc`), or unallowlisted egress destinations directly.
4. **Filesystem Immutability Layer**:
   - The container filesystem root (`/`, `/app`) is mounted read-only. Only ephemeral task workspaces (`/workspace/output`) are writable.

> [!NOTE]
> Application-level enforcement (`Tool Gateway PEP` $\rightarrow$ Cerbos $\rightarrow$ handler) provides fine-grained, contextual policy validation. Runtime-level enforcement (gVisor sandbox, packet-level network egress fencing, and read-only container root) provides defense against bypass through alternate binaries or raw system calls.

---

## 6. Auth0 OIDC Identity Assurance & Delegation Security

The identity layer introduces verified end-user provenance via Auth0 OIDC tokens while ensuring the external token is contained at the boundary:

### Security Boundaries
1. **Token Termination Boundary**:
   - The Auth0 user access token (`Bearer <auth0-jwt>`) is validated exclusively at the AX Admission PEP (`ax/adapter.py`).
   - The token is **never** injected into the container workload environment or the minted task context.
   - If an agent container is compromised, it cannot exfiltrate the user's Auth0 identity token or use it against external cloud services.
2. **Anti-Forging Guarantees**:
   - Caller cannot assert `delegated_by` or `tenant_id` in request payloads; these values are derived strictly from cryptographically verified Auth0 claims (`sub`, `org_id`).
   - If a caller supplies conflicting claims in the request body, the Admission PEP detects tampering and rejects immediately (`REJECTED_PEP`).
3. **Coarse Scope vs. Fine-Grained Authorization**:
   - Auth0 scope `agent:execute` authorizes the caller to request agent admission consideration only.
   - Cerbos Layer 1 authorizes whether that specific user and orchestrator combination may execute the selected agent.
   - Tool Gateway PEP + Cerbos Layer 2 authorizes each individual tool operation (e.g. `fetch_url`, `browser_navigate`) at runtime.
4. **Auth0 Verification Test Matrix**:
   - Verified across [`tests/test_auth0_oidc.py`](file:///home/esha/Office/agent_identity/tests/test_auth0_oidc.py) (12 unit tests) and [`tests/test_user_delegation_auth0.py`](file:///home/esha/Office/agent_identity/tests/test_user_delegation_auth0.py) (12 integration tests):
     - Valid RS256 token verification
     - Invalid signature rejection
     - Expired token rejection
     - Issuer / audience mismatch rejection
     - Unsupported algorithm (`HS256`, `none`) rejection
     - Missing `sub` rejection
     - Missing `agent:execute` scope rejection
     - Organization / tenant mismatch rejection
     - Revoked user rejection
     - Zero token leakage into agent sandbox
     - Runtime tool permission governance with user delegation permissions

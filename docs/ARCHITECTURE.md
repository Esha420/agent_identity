# Architecture: Multi-Agent Dual-Layer Authorization + AX/Substrate

## 1. Trust Boundaries & Flow Architecture

```text
USER / OIDC
    │
    ▼
ORCHESTRATOR (workload intent only)
    │ requested capability only
    ▼
================================ LAYER 1: WORKLOAD ADMISSION ================================
AX ADMISSION PEP (ax/adapter.py)
├── 1. Verify workload identity (orchestrator attestation, roles, tenant, delegation)
├── 2. Resolve requested capability & agent from trusted catalog
├── 3. Resolve immutable image digest & command from catalog (verify integrity)
├── 4. Ask Cerbos for Layer 1 authorization (Resource: agent, Action: execute)
├── 5. Submit immutable task specification to AX (ax apply)
├── 6. Receive authoritative AX task identity
└── 7. Mint short-lived, HMAC-signed TaskExecutionContext (bound to AX task & image digest)
    │
    ▼
AX / SUBSTRATE TASK (Isolated Sandbox)
    │
    ▼
BROWSER AGENT WORKLOAD (Containerized Actor)
    │ tool intent + arguments only (presents signed context token)
    ▼
================================ LAYER 2: RUNTIME TOOL GATEWAY ===============================
TOOL GATEWAY PEP (tools/gateway.py)
├── 1. Verify HMAC signature, issuer, audience, lease expiration, & authorization epoch
├── 2. Derive task_id, agent_id, tenant_id, delegated_by, image_digest strictly from verified context
├── 3. Check for spoofed/claimed identity mismatches in agent arguments (reject immediately)
├── 4. Agent catalog capability gate & tool set hash integrity verification
├── 5. Input normalization (syntactic URL check, userinfo rejection, canonical path resolution)
├── 6. DNS resolution (A and AAAA records), IP classification, anti-SSRF & cloud metadata block
├── 7. Query Cerbos PDP for Layer 2 authorization (Resource: tool, Action: per-call operation)
├── 8. Safe handler execution with redirect re-validation (GovernedRedirectHandler)
└── 9. Emit structured audit event (zero side-effects on any denial)
```

---

## 2. The 12 Architectural Baseline Principles

1. **The orchestrator supplies intent, not authority**: The orchestrator may request an execution, but it cannot define its own roles, tenant, or delegated authority.
2. **The admission PEP derives identity from verified credentials**: The AX Admission PEP verifies caller workload credentials against trusted directories/attestation and derives authoritative principal attributes.
3. **The catalog resolves the immutable agent image and command**: Agent definitions, container images, image digests, and runtime commands are resolved strictly from declarative, trusted catalogs (`agents/catalog.yaml`).
4. **AX task identity is authoritative**: Task identities (`task_id`) are generated and accepted authoritatively by the AX control plane—never pre-assigned by untrusted orchestrators or self-asserted by agents.
5. **The admission PEP mints a signed, short-lived task context**: `TaskExecutionContext` is minted exclusively by the AX Admission PEP *after* AX accepts the task.
6. **The gateway derives identity from that context**: The Tool Gateway PEP never trusts self-asserted agent identity arguments; all identity attributes are unpacked from the verified, signed context.
7. **The agent submits tool intent and arguments only**: The running agent submits only tool name, action, and arguments along with its signed task context token.
8. **Every tool invocation is normalized and authorized**: Normalization (URL parsing, path canonicalization) occurs before authorization, and Cerbos PDP evaluates every concrete call.
9. **The gateway connects only to validated network destinations**: All resolved IPs (IPv4 and IPv6) are classified; private, loopback, link-local, multicast, and metadata addresses are strictly blocked.
10. **The agent cannot reach handlers or unrestricted network paths directly**: Multi-tier defense ensures the Python gateway provides application-level enforcement while sandbox egress policy and read-only container filesystems prevent bypass.
11. **Layer 2 authorization is evaluated per invocation**: Selecting or admitting an agent workload does not grant ambient tool privileges. Every concrete tool operation is authorized dynamically at runtime.
12. **Revocation affects the next invocation**: Policy modifications in Cerbos or epoch upgrades take immediate effect on the very next tool call made by active workloads.

---

## 3. Safe Sequence for Context Minting

```text
Orchestrator Request (Intent)
         ↓
1. Verify orchestrator workload credential (roles, tenant, delegation)
         ↓
2. Resolve requested capability and agent from trusted catalog
         ↓
3. Resolve image digest and command from catalog & verify digest integrity
         ↓
4. Ask Cerbos for Layer 1 authorization
         ↓
5. Submit immutable task specification to AX (ax apply)
         ↓
6. Obtain authoritative AX task identity (task accepted by control plane)
         ↓
7. Create short-lived, signed TaskExecutionContext (bound to AX task ID & image digest)
         ↓
8. Inject only required context into task (via environment variable TASK_CONTEXT_TOKEN)
         ↓
9. Tool Gateway verifies context signature and lease on every invocation
```

> [!IMPORTANT]
> The admission service will **never** mint an execution context for a task that AX has not accepted. If Layer 1 authorization is denied, or if `ax apply` fails, ZERO contexts are minted, ZERO AX tasks exist, and ZERO workloads touch Substrate.

---

## 4. Canonical `TaskExecutionContext` Structure

The execution context is cryptographically signed using HMAC-SHA256 (`ax-pep-trusted-hmac-key`) and serialized into a compact URL-safe base64 token. A plain JSON object passed through environment variables is only metadata; signing turns it into a verifiable capability credential.

| Field | Type | Purpose |
| :--- | :--- | :--- |
| `task_id` | `str` | Authoritative AX task identity assigned by the control plane. |
| `agent_id` | `str` | Logical agent name resolved from catalog (e.g. `browser-agent`). |
| `roles` | `List[str]` | Authoritative roles derived by PEP (e.g. `["browser-worker"]`). |
| `capability` | `str` | Binds the task to the requested capability (e.g. `browser`). |
| `tenant_id` | `str` | Authoritative tenant boundary (e.g. `tenant-demo`). |
| `parent_principal`| `str` | Workload that requested admission (`orchestrator-agent`). |
| `delegated_by` | `str` | Human user or service on whose behalf the task executes (`user-123`). |
| `agent_image_digest`| `str` | Cryptographic SHA256 image digest binding authorization to container image. |
| `environment` | `str` | Runtime profile (`test` or `production`). |
| `policy_scope` | `str` | Records tenant/environment policy scope used. |
| `allowed_tool_set_hash`| `str` | SHA256 digest of catalog's allowed tool set to detect runtime tampering. |
| `issuer` | `str` | Trusted admission component (`ax-admission-pep`). |
| `audience` | `str` | Target gateway identifier (`tool-gateway`), preventing cross-gateway replay. |
| `nonce` | `str` | Cryptographic random nonce preventing context replay. |
| `authorization_epoch` | `int` | Monotonically increasing epoch supporting immediate revocation. |
| `issued_at` | `int` | Unix timestamp of minting. |
| `expires_at` | `int` | Unix timestamp of lease expiration (short-lived lease, e.g. 1 hour). |
| `context_id` | `str` | Unique context identifier (`ctx-01J...`). |
| `signature` | `str` | HMAC-SHA256 signature computed over canonical JSON payload. |

---

## 5. Explicit Task Identity Derivation at Tool Gateway

To eliminate confused-deputy vulnerabilities, the Tool Gateway PEP adheres to strict derivation:
- The agent request contains:
  ```json
  {
    "context_token": "eyJ0YXNrX2lkIj...",
    "tool": "fetch_url",
    "action": "request",
    "arguments": {
      "url": "https://example.com/docs",
      "method": "GET"
    }
  }
  ```
- The Gateway unpacks and cryptographically verifies `TaskExecutionContext`.
- If the agent attempts to inject self-asserted `task_id`, `agent_id`, or `tenant_id` into arguments or request fields, the Gateway detects the discrepancy and **rejects the call immediately** (`TASK_ID_MISMATCH` / `AGENT_ID_MISMATCH`).
- The Gateway derives caller attributes (`task_id`, `agent_id`, `tenant_id`, `delegated_by`, `image_digest`, `epoch`) **strictly from the verified context**, passing them as trusted principal attributes to Cerbos PDP.

---

## 6. DNS, Redirect, and Connection Pinning Flow

Domain allowlisting alone is vulnerable to DNS rebinding (TOCTOU). The gateway enforces the following multi-step pipeline:

```text
Parse and normalize URL
        ↓
Reject userinfo credentials (user:pass@host)
        ↓
Exact hostname & scheme allowlist check (against active profile)
        ↓
Resolve A and AAAA records (socket.getaddrinfo)
        ↓
Classify every resolved address
        ↓
If ANY returned address is private, loopback, link-local, multicast,
reserved, or cloud metadata (169.254.169.254) ──> REJECT REQUEST IMMEDIATELY
        ↓
Connect to validated destination preserving original Host/SNI headers
        ↓
Intercept HTTP 3xx redirects (GovernedRedirectHandler)
        ↓
Revalidate every redirect location against the full security pipeline
```

---

## 7. Gateway Boundary: Cooperative vs. Enforced

The architecture provides two complementary defense layers:

1. **Application-Level Enforcement (Governed Code Paths)**:
   - `AgentToolClient` $\rightarrow$ `ToolGatewayPEP` $\rightarrow$ Cerbos PDP $\rightarrow$ Tool Handlers.
   - Provides granular parameter normalization, catalog gating, and audit logging.
2. **Runtime-Level Enforcement (Defense Against Bypass)**:
   - What if an agent executes arbitrary Python, invokes `curl`, or opens raw sockets?
   - **Sandbox isolation (gVisor)**: Intercepts raw kernel calls and prevents host escapes.
   - **Network egress policy**: The sandbox network namespace blocks unauthorized outbound connections, private IP ranges, and cloud metadata endpoints at the packet/firewall layer.
   - **Read-only filesystem**: Root `/` is mounted read-only; only `/workspace/output` is writable.
   - **No access to credentials**: Policy files and PEP HMAC keys remain outside the sandbox filesystem.

---

## 8. Revocation Semantics

Revocation is supported at multiple granularities:
- **Per-Call Dynamic Policy Revocation**: Cerbos PDP is queried synchronously on every tool call. Editing a policy file or updating Cerbos rules takes effect on the very next invocation by active workloads.
- **Epoch Revocation**: The gateway maintains an `active_epoch` counter. Upgrading the epoch immediately invalidates all execution contexts issued under prior epochs (`INVALID_TASK_CONTEXT`).
- **Targeted Task Revocation**: The gateway tracks a `revoked_tasks` blacklist to kill authorization for specific compromised workloads immediately.

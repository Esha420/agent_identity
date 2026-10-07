# Security Model: Multi-Agent Authorization Architecture

## 1. Core Security Entities

- **Principal**: Logical identity of the entity initiating the agent execution request (e.g. `orchestrator-agent` with roles `["orchestrator"]`).
- **Resource**: The target agent capability being accessed (e.g. `browser-agent`, `research-agent`, `restricted-agent` of kind `agent`).
- **Action**: The operation requested (e.g. `execute`). Privileged administrative actions (`admin`, `delete`, `modify-policy`) are strictly blocked.
- **Context**: Dynamic contextual attributes passed along with the request (e.g. `{"environment": "lab", "capability": "browser"}`).

---

## 2. Who Does What?

| Responsibility Question | Designated Component | Security Guarantee |
| :--- | :--- | :--- |
| **Who decides?** | **Cerbos PDP** | Evaluates declarative policies against `(Principal, Resource, Action, Context)`. Decoupled from application code. |
| **Who authorizes?** | **AX Admission Boundary** | Intercepts all requests, queries Cerbos, and enforces **FAIL-CLOSED** gatekeeping. |
| **Who launches?** | **Google AX Controller** | Transforms authorized intent into a native AX `Task` resource (`ax.v1alpha1`). |
| **Who executes?** | **Agent Substrate (ATE)** | Runs the upstream agent inside an isolated gVisor sandbox worker pod (`10.244.0.x`). |

---

## 3. Trust Boundaries & Fail-Closed Invariant

```
  [Untrusted Zone]          [Admission Gate]           [Enforcement Zone]        [Isolation Zone]
   User Intent    ──>  Orchestrator Agent  ──>  AX Admission Boundary  ──>  Agent Substrate (ATE)
                            (Claims ID)                 │ (Queries Cerbos)         (gVisor Sandbox)
                                                        ▼
                                                  Cerbos PDP
                                            (ALLOW / DENY / ERROR)
```

### Fail-Closed Execution Invariant
```
Authorization = ALLOW           ──>  AX creates Task  ──>  Substrate executes
Authorization = DENY            ──>  AX rejects       ──>  ZERO Substrate Workloads
Authorization = UNKNOWN / ERROR ──>  AX rejects       ──>  ZERO Substrate Workloads
```
Under no circumstances does an unverified, errored, or timed-out authorization check permit task creation.

---

## 4. Bypass Considerations

- **Substrate Direct Invocation**: Substrate endpoints (`api.ate-system.svc.cluster.local:443`) are network-isolated inside the cluster mesh and require mTLS / internal cluster authority. Orchestrators outside the cluster boundary cannot communicate directly with the Substrate API.
- **Runtime Enclave**: Agents execute in gVisor sandboxes, preventing container escape into the cluster control plane.

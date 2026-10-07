# Phase 1: Environment & System Investigation Report

## 1. Native AX Environment Findings

### 1.1 Discovery & Verification
- **Control Plane**: Google AX (`github.com/google/ax`, API version `ax.v1alpha1`) running in namespace `ax-system`.
  - Deployment `ax-server`: HTTP/gRPC API listener exposing port 8080.
  - Deployment `ax-controller`: Autonomous agent execution controller reconciling tasks and synchronizing state to Redis (`ax-redis.ax-system.svc.cluster.local:6379`).
- **CLI Utility**: Native binary `ax` (`v1alpha1 standalone redis engine`), copied to `bin/ax`.
  - Commands verified: `ax apply -f <file>`, `ax get tasks`, `ax describe task <name>`, `ax delete task <name>`, `ax ctx`.
- **Resource Definition**:
  ```yaml
  apiVersion: ax.v1alpha1
  kind: Task
  metadata:
    name: <task-name>
  spec:
    image: <image-url>@sha256:<digest>
    command: [<executable>, <arg1>, ...]
  ```
- **Critical Requirement Discovered**:
  - Task images **MUST be pinned by SHA-256 digest** (e.g. `localhost:5001/agent@sha256:...`). Applying an unpinned image tag triggers an `InvalidArgument` rejection (`must be pinned by digest (changing the image invalidates snapshots)`).

---

## 2. Native Agent Substrate (ATE) Findings

### 2.1 Architecture & Control Path
- **Substrate Endpoint**: `api.ate-system.svc.cluster.local:443` (Authority: `api.ate-system.svc`).
- **Execution Workers**: `ax-system/deployment/worker-pool` (3 ready replicas).
- **Isolation Mechanism**: gVisor sandbox container runtime (`sandboxconfigs.ate.dev/gvisor-default`).
- **Lifecycle Integration**:
  - When `ax apply` submits a valid `Task`, `ax-controller` contacts Substrate to ensure an `ActorTemplate` matching the image digest.
  - Substrate launches the actor inside an isolated gVisor worker pod (`10.244.0.x`).
  - Workload executes inside the sandbox and phase transitions to `Running` -> `Completed`.
  - Workload deletion gracefully removes the Substrate actor and template.

---

## 3. Cerbos Authorization Engine Findings

### 3.1 Engine & API Contract
- **Version**: Cerbos 0.56.0 (`ghcr.io/cerbos/cerbos:latest`).
- **Mode**: Policy Decision Point (PDP) exposing HTTP REST (`/api/check/resources`) and gRPC (:3593).
- **Health Endpoint**: `GET /_cerbos/health` returns `{"status": "CERBOS_STATUS_OK"}`.
- **Evaluation Mechanism**: Evaluates declarative YAML policies against principal, resource, action, and context attributes.
- **Fail-Closed Semantics**: If Cerbos is unreachable, unhealthy, or returns `EFFECT_DENY`, the boundary rejects the request immediately.

---

## 4. Awesome-Agents Evaluation Matrix

We surveyed open-source agents from [kyrolabs/awesome-agents](https://github.com/kyrolabs/awesome-agents) against a 9-point criteria rubric:

| Evaluation Rubric | Candidate 1: OpenClaw Agent | Candidate 2: Browser-Use / Agent-E | Candidate 3: Smolagents Web |
| :--- | :--- | :--- | :--- |
| **Upstream Repo** | `openclaw/openclaw` | `EmergenceAI/Agent-E` / `browser-use` | `huggingface/smolagents` |
| **Category** | Autonomous Task & Research Agent | Autonomous Browser Agent | Web Tools Agent |
| **License** | Apache 2.0 / MIT | Apache 2.0 / MIT | Apache 2.0 |
| **Containerization** | Containerized with `ax-task-runner` | Containerized with Playwright & `ax-task-runner` | Python container |
| **Runtime Requirements** | Python 3.12, lightweight (<150MB) | Python 3.11+, Headless browser (<512MB) | Python 3.11+, <256MB |
| **Input Mechanism** | Env vars (`ROLE`, `TASK_NAME`) & CLI args | CLI args (`--url`, `--goal`) & Env vars | CLI & function args |
| **Output Mechanism** | Structured JSON file & exit code | Structured JSON output (`title`, `url`, `status`) | Text / JSON output |
| **Browser / OS Deps** | Linux network stack, curl, python | Headless Chromium, Playwright | Requests, BeautifulSoup |
| **Credential Deps** | None for offline/local research | None for local/mock target pages | Requires LLM key if not mocked |
| **Substrate Compatibility**| **100% verified** in ATE gVisor sandbox | **100% compatible** when pinned by digest | Compatible |

### Agent Selection Decision
- **Primary Agent (Browser Capability)**: **Browser Agent** (`browser-agent`), packaged with headless browser automation tools, accepting target URL and producing deterministic JSON output (page title, navigation status).
- **Secondary Agent (Research Capability)**: **OpenClaw Research Agent** (`research-agent`), packaged with research tool execution pipeline, producing structured research intelligence artifacts.
- **Selection Rationale**:
  - Provides two distinct, realistic capabilities from awesome-agents.
  - Enables full verification of **Dynamic Agent Selection** and **Policy Modification / Inversion** without modifying orchestration code.

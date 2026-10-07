# Reference Architecture: Multi-Agent Authorization + AX/Substrate

## 1. Logical Architecture

```
                          USER
                           │
                           ▼
               ┌──────────────────────┐
               │  ORCHESTRATOR AGENT  │
               │  (Ultra-Thin Planner)│
               │  • Task understanding│
               │  • Capability match  │
               │  • Agent selection   │
               └──────────┬───────────┘
                          │
                          │ Execution Request:
                          │ {principal, agent, action, task, context}
                          ▼
               ┌──────────────────────┐
               │    AX ADMISSION      │
               │       BOUNDARY       │
               └──────────┬───────────┘
                          │
                          │ Evaluate Authorization:
                          │ (Principal, Resource, Action, Context)
                          ▼
               ┌──────────────────────┐
               │     CERBOS PDP       │
               │  Policy Decision     │
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

## 2. Core Separation of Concerns

1. **Orchestrator**:
   - Parses the user goal.
   - Determines the required capability (`browser`, `research`).
   - Resolves the candidate agent identifier (`browser-agent`, `research-agent`) from declarative configuration.
   - Emits an execution request to AX.
   - **Never** invokes Substrate or Docker directly; does not make authorization decisions.

2. **AX Admission Boundary**:
   - Acts as the runtime gatekeeper.
   - Constructs a Cerbos CheckResources payload.
   - Enforces **fail-closed** behavior: only if Cerbos explicitly returns `EFFECT_ALLOW` does AX materialize the `Task` resource via native `ax apply`.

3. **Cerbos PDP**:
   - Standalone policy decision engine.
   - Evaluates caller principal (e.g. `orchestrator-agent`), resource attributes, action (`execute`), and contextual factors.
   - Contains all authorization logic in declarative YAML.

4. **Native AX & Agent Substrate (ATE)**:
   - AX schedules the `Task` and reconciles it against the ATE Substrate.
   - Substrate provisions an isolated gVisor worker sandbox.
   - The selected open-source agent runs inside the sandbox and outputs results.

---

## 3. Trust Boundaries & Bypass Prevention

- **Boundary 1 (User -> Orchestrator)**: Untrusted external intent translated into structured plan.
- **Boundary 2 (Orchestrator -> AX)**: Authentication boundary. The orchestrator declares its logical identity (`orchestrator-agent`).
- **Boundary 3 (AX -> Cerbos)**: Authorization boundary. Cerbos verifies permissions.
- **Boundary 4 (AX -> Substrate)**: Workload isolation boundary. Only authenticated and authorized workloads are materialized into the Substrate gVisor sandboxes.
- **Bypass Resistance**: Orchestrator has no network or RBAC access to Substrate endpoints (`api.ate-system.svc`). Substrate worker pools only accept workload creation instructions from the AX controller.

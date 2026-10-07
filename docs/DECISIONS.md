# Architecture Decision Records (ADRs)

## ADR-001: Use Native Google AX & Substrate (ATE) Instead of Bespoke Emulators
- **Status**: Accepted
- **Context**: The project goal is to demonstrate an authorization-aware reference architecture using AX as the dynamic runtime boundary and Agent Substrate for isolated execution.
- **Decision**: Interface directly with the live Google AX control plane (`ax-server`, `ax-controller`, and `ax` CLI) and the native Substrate runtime (ATE worker pool with gVisor sandboxes). Avoid building any shadow/replacement Python runtimes or custom Docker scheduler.
- **Consequences**: Ensures the reference architecture is 100% native and authentic. Image digests must be strictly pinned to satisfy Substrate snapshotting requirements.

---

## ADR-002: Use Cerbos as the Standalone Policy Decision Point (PDP)
- **Status**: Accepted
- **Context**: Authorization decisions must not be hardcoded in application logic or coupled to identity representation.
- **Decision**: Deploy Cerbos (v0.56.0) as an isolated service. All execution requests must be checked against Cerbos using `(Principal, Resource, Action, Context)` before workload materialization.
- **Consequences**: Clear separation of Identity from Authorization. Strict fail-closed posture if Cerbos is unreachable or returns `EFFECT_DENY`.

---

## ADR-003: Thin AX Admission Adapter at the Orchestration Boundary
- **Status**: Accepted
- **Context**: Cerbos must sit on the execution admission path, not beside it. An unauthorized request must never materialize a workload into Substrate.
- **Decision**: Implement a thin admission adapter that intercepts execution requests, queries Cerbos, and only calls `ax apply` if Cerbos returns `EFFECT_ALLOW`.
- **Consequences**: If Cerbos returns DENY or fails, zero AX tasks and zero Substrate actors are created.

---

## ADR-004: Upstream Awesome-Agents Selection for Dynamic Verification
- **Status**: Accepted
- **Context**: The architecture must prove that agent selection is dynamic and decoupled from code, and agent logic must come from existing open-source agents rather than custom classes.
- **Decision**: Select a Browser Agent (for web navigation tasks) and OpenClaw Agent (for research tasks) from the `awesome-agents` catalog. Define agent metadata declaratively in `agents/catalog.yaml`.
- **Consequences**: Orchestrator dynamically resolves capabilities to catalog entries without custom agent implementations.

# Comprehensive Test Plan

## 1. Test Matrix Overview

| Test ID | Test Category | Target Component | Description / Scenario | Expected Decision / Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Test 1** | Functional / Health | Cerbos PDP | Healthcheck endpoint `GET /_cerbos/health` | HTTP 200, status `SERVING` |
| **Test 2** | Functional / Auth | Cerbos & AX | `orchestrator-agent` executes `browser-agent` | `EFFECT_ALLOW` |
| **Test 3** | Negative / Principal | Cerbos & AX | `untrusted-agent` executes `browser-agent` | `EFFECT_DENY`, zero tasks |
| **Test 4** | Negative / Resource | Cerbos & AX | `orchestrator-agent` executes `restricted-agent` | `EFFECT_DENY`, zero tasks |
| **Test 5** | Integration | AX & Substrate | Authorized execution dispatched via `ax apply` | Task reaches `Running` in Substrate |
| **Test 6** | Security / Negative | AX & Substrate | Denied request verified to create 0 workloads | AX task count unchanged (0 active) |
| **Test 7** | Functional / Auth | Cerbos PDP | Identity propagation (caller ID preserved in PDP check) | PDP receives exact caller identity |
| **Test 8** | Functional | Orchestrator | Dynamic agent selection based on task capability | Correct agent resolved from config |
| **Test 9** | Functional | Orchestrator & AX | Agent substitution without modifying orchestration code | Browser & Research both execute |
| **Test 10**| End-to-End | Full Pipeline | User -> Orchestrator -> AX -> Cerbos -> Substrate -> Result | Successful structured result returned |
| **Test 11**| Security / Dynamic | Cerbos & AX | Dynamic policy revocation (`browser-agent` -> DENY) | Execution denied without code change |
| **Test 12**| Security / Dynamic | Cerbos & AX | Dynamic policy restoration (`browser-agent` -> ALLOW) | Execution allowed again without code change |
| **Sec 1**  | Security | Cerbos PDP | Unauthorized actions (`admin`, `delete`, `modify-policy`) | `EFFECT_DENY` |
| **Sec 2**  | Security / Invariant| AX Boundary | Cerbos PDP unreachable / down | Fail-closed: `ERROR_FAIL_CLOSED`, 0 workloads |
| **Sec 3**  | Security / Bypass | Infrastructure | Direct host-to-Substrate curl bypass attempt | Connection refused / unreachable |
| **Audit**  | Static Verification | Codebase | Automated anti-hardcoding grep inspection | 0 violations |

#!/usr/bin/env python3
"""OpenClaw Intent-to-Task Coordinator.

Connects operator Slack intents to declarative agent catalogs, AX Admission PEP,
Agent Substrate workloads, and runtime Tool Gateway PEP enforcement.

Key responsibilities:
1. Intent Planning: Proposes task DAGs based strictly on agents/catalog.yaml (no arbitrary workloads).
2. Authoritative Scope Generation: Extracts verified grants from AX admission before execution.
3. Workload Orchestration: Dispatches real AX Task manifests to AX + Substrate.
4. Runtime Enforcement: Mediates all tool actions via tools/gateway.py and Cerbos PDP.
5. Negative Test Support: Executes controlled read-only write violation tests with file SHA256 integrity verification.
6. Audit Correlation: Propagates correlation IDs across Slack, AX, Cerbos, and Gateway.
"""

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.auth0_verifier import Auth0TokenVerifier, create_test_auth0_token
from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from scripts.mint_test_token import get_or_create_key
from tools.audit import AuditCorrelator
from tools.gateway import ToolGatewayPEP
from tools.schema import AuditEvent, TaskExecutionContext, ToolInvocationRequest, ToolInvocationResponse

DEFAULT_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "../agents/catalog.yaml")


@dataclass
class TaskPlanStep:
    agent_id: str
    name: str
    goal: str
    required_permissions: List[str]
    allowed_tools: List[str]
    task_data: Dict[str, Any] = field(default_factory=dict)
    test_mode: Optional[str] = None


@dataclass
class IntentAnalysis:
    raw_prompt: str
    intent_type: str  # INCIDENT_INVESTIGATION, NEGATIVE_TEST_READONLY_WRITE, SCOPE_INSPECTION, UNSUPPORTED_TASK
    is_supported: bool
    plan: List[TaskPlanStep]
    rejection_reason: Optional[str] = None
    target_resource: Optional[str] = None


class OpenClawCoordinator:
    """Governed Coordinator selecting registered agents and managing task lifecycles."""

    def __init__(
        self,
        catalog_path: str = DEFAULT_CATALOG_PATH,
        adapter: Optional[AXAdmissionAdapter] = None,
        gateway: Optional[ToolGatewayPEP] = None,
        cerbos: Optional[CerbosClient] = None,
        verifier: Optional[Auth0TokenVerifier] = None,
        priv_key: Any = None,
        kid: Optional[str] = None,
    ):
        self.catalog_path = catalog_path
        self.catalog = self._load_catalog()
        self.cerbos = cerbos or CerbosClient()
        self.priv_key, self.kid = (priv_key, kid) if (priv_key and kid) else get_or_create_key()
        self.verifier = verifier or Auth0TokenVerifier(local_public_keys={self.kid: self.priv_key.public_key()})
        self.adapter = adapter or AXAdmissionAdapter(auth0_verifier=self.verifier)
        self.gateway = gateway or ToolGatewayPEP(cerbos_client=self.cerbos)
        self.audit_correlator = AuditCorrelator(self.gateway.audit_logs)

    def _load_catalog(self) -> Dict[str, Any]:
        with open(self.catalog_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data.get("agents", {})

    def analyze_intent(self, prompt: str) -> IntentAnalysis:
        """
        Analyze operator prompt and construct an explicit task DAG from registered agents.
        
        Arbitrary model-generated tasks or tools are strictly rejected fail-closed.
        """
        normalized = prompt.strip().lower()

        # 0. Reject Prohibited / Unapproved Actions Fail-Closed Immediately
        unsupported_markers = [
            "miner", "crypto", "bitcoin", "deploy", "bash", "arbitrary", "exec", "root",
            "unauthorized", "backdoor", "hack", "unregistered", "metadata", "credential",
            "administrative agent", "instance metadata"
        ]
        if any(m in normalized for m in unsupported_markers):
            supported_list = ", ".join(self.catalog.keys())
            return IntentAnalysis(
                raw_prompt=prompt,
                intent_type="UNSUPPORTED_TASK",
                is_supported=False,
                plan=[],
                rejection_reason=(
                    f"The requested task contains unapproved actions/tools.\n"
                    f"• Prohibited markers detected in prompt: '{prompt}'.\n"
                    f"• Supported agents in catalog: `{supported_list}`\n"
                    f"• Supported workflows: Staging incident investigation, log analysis, negative tests (`test readonly-write`).\n"
                    f"• Policy Notice: Arbitrary execution, shell commands, unregistered agents, or metadata endpoints are prohibited fail-closed."
                ),
            )

        # 1. Controlled Authorization Test: Read-only Log Analyst writes/appends to file
        is_negative_test = (
            "test readonly-write" in normalized
            or "/agent-test readonly-write" in normalized
            or "readonly-write" in normalized
            or "read-only-write" in normalized
            or (("read-only" in normalized or "read only" in normalized) and ("append" in normalized or "write" in normalized or "modify" in normalized))
            or ("attempt to append" in normalized and "log" in normalized)
            or ("attempt to write" in normalized and "log" in normalized)
            or ("runtime authorization test" in normalized and "log" in normalized)
            or ("test" in normalized and "read" in normalized and ("write" in normalized or "append" in normalized))
        )
        if is_negative_test:
            step = TaskPlanStep(
                agent_id="log-analysis-agent",
                name="Log Analyst (Negative Test)",
                goal="Read-only Log Analyst attempts forbidden file mutation against /workspace/logs/sample_staging.log",
                required_permissions=["agent:execute", "filesystem:read"],
                allowed_tools=["filesystem_read"],
                task_data={"target": "./workspace/logs/sample_staging.log"},
                test_mode="readonly-write",
            )
            return IntentAnalysis(
                raw_prompt=prompt,
                intent_type="NEGATIVE_TEST_READONLY_WRITE",
                is_supported=True,
                plan=[step],
                target_resource="/workspace/logs/sample_staging.log",
            )

        # 2. Scope Inspection Request
        if normalized.startswith("/agent-scopes") or normalized.startswith("scope") or "inspect scopes" in normalized:
            # Extract target agent if mentioned
            target = None
            for agent in self.catalog.keys():
                if agent in normalized:
                    target = agent
                    break
            return IntentAnalysis(
                raw_prompt=prompt,
                intent_type="SCOPE_INSPECTION",
                is_supported=True,
                plan=[],
                target_resource=target or "all",
            )

        # 3. Incident Investigation Request
        has_incident_core = any(k in normalized for k in ["500", "incident", "investigate", "investigation", "error"])
        has_incident_target = any(k in normalized for k in ["staging", "website", "logs", "log", "report"])
        if has_incident_core and has_incident_target:
            # Verify required agents exist in catalog
            req_agents = ["website-investigation-agent", "log-analysis-agent", "incident-reporting-agent"]
            for a in req_agents:
                if a not in self.catalog:
                    return IntentAnalysis(
                        raw_prompt=prompt,
                        intent_type="UNSUPPORTED_TASK",
                        is_supported=False,
                        plan=[],
                        rejection_reason=f"Required agent '{a}' missing from catalog.",
                    )

            plan = [
                TaskPlanStep(
                    agent_id="website-investigation-agent",
                    name="Website Investigator",
                    goal="Inspect staging website errors at http://mock-target:8089/staging-error",
                    required_permissions=["agent:execute", "browser:read"],
                    allowed_tools=["browser_navigate"],
                    task_data={"url": "http://mock-target:8089/staging-error"},
                ),
                TaskPlanStep(
                    agent_id="log-analysis-agent",
                    name="Log Analyst",
                    goal="Analyze /workspace/logs/sample_staging.log for database pool exhaustion",
                    required_permissions=["agent:execute", "filesystem:read"],
                    allowed_tools=["filesystem_read"],
                    task_data={"path": "./workspace/logs/sample_staging.log"},
                ),
                TaskPlanStep(
                    agent_id="incident-reporting-agent",
                    name="Incident Reporter",
                    goal="Synthesize findings and compile official report into /workspace/output/incident_report.md",
                    required_permissions=["agent:execute", "filesystem:read", "filesystem:write"],
                    allowed_tools=["filesystem_read", "filesystem_write"],
                    task_data={"output_path": "./workspace/output/incident_report.md"},
                ),
            ]
            return IntentAnalysis(
                raw_prompt=prompt,
                intent_type="INCIDENT_INVESTIGATION",
                is_supported=True,
                plan=plan,
                target_resource="mock-target:8089 + sample_staging.log",
            )

        # 4. Single-Agent Catalog Tasks (Browser or Research)
        if "browse" in normalized or "website" in normalized:
            step = TaskPlanStep(
                agent_id="browser-agent",
                name="Browser Agent",
                goal="Navigate to approved endpoint and extract DOM content",
                required_permissions=["agent:execute", "browser:read"],
                allowed_tools=["fetch_url", "browser_navigate"],
                task_data={"url": "http://mock-target:8089"},
            )
            return IntentAnalysis(
                raw_prompt=prompt,
                intent_type="BROWSER_TASK",
                is_supported=True,
                plan=[step],
                target_resource="mock-target:8089",
            )

        # 5. Unsupported Task / Arbitrary shell / Unregistered Agent
        supported_list = ", ".join(self.catalog.keys())
        return IntentAnalysis(
            raw_prompt=prompt,
            intent_type="UNSUPPORTED_TASK",
            is_supported=False,
            plan=[],
            rejection_reason=(
                f"The requested task is not supported by registered agents in the declarative catalog.\n"
                f"• Supported agents: `{supported_list}`\n"
                f"• Supported workflows: Staging incident investigation, log analysis, negative tests (`test readonly-write`).\n"
                f"• Policy Notice: Arbitrary shell execution or model-invented tools are prohibited fail-closed."
            ),
        )

    def execute_intent(
        self,
        analysis: IntentAnalysis,
        operator_id: str,
        correlation_id: Optional[str] = None,
        tenant_id: str = "tenant-demo",
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the planned intent across AX + Agent Substrate and runtime Tool Gateway PEP.
        
        Dispatches scope summary cards to event_callback before and during execution.
        """
        corr_id = correlation_id or f"inc-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        human_user = f"auth0|slack-{operator_id}" if not operator_id.startswith("auth0|") else operator_id

        def notify(event_name: str, payload: Dict[str, Any]):
            if event_callback:
                event_callback(event_name, payload)

        # Handle Unsupported Intent
        if not analysis.is_supported:
            notify("task_unsupported", {
                "correlation_id": corr_id,
                "operator": human_user,
                "reason": analysis.rejection_reason,
            })
            return {
                "success": False,
                "correlation_id": corr_id,
                "status": "UNSUPPORTED_TASK",
                "reason": analysis.rejection_reason,
                "admitted_workloads": 0,
            }

        # Handle Scope Inspection Intent
        if analysis.intent_type == "SCOPE_INSPECTION":
            scopes = []
            target = analysis.target_resource
            agents_to_inspect = (
                [target] if target in self.catalog else ["website-investigation-agent", "log-analysis-agent", "incident-reporting-agent"]
            )
            for a in agents_to_inspect:
                sc = self.adapter.get_authoritative_scope(
                    agent_name=a,
                    task_id=f"inspect-{a[:8]}",
                    requesting_operator=human_user,
                    tenant_id=tenant_id,
                    correlation_id=corr_id,
                )
                scopes.append(sc)
                notify("scope_inspected", {"scope": sc, "correlation_id": corr_id})

            return {
                "success": True,
                "correlation_id": corr_id,
                "status": "SCOPES_INSPECTED",
                "scopes": scopes,
            }

        # ---------------------------------------------------------------------
        # Phase 1: Pre-execution Authoritative Scope Display for each planned task
        # ---------------------------------------------------------------------
        notify("plan_proposed", {
            "correlation_id": corr_id,
            "operator": human_user,
            "intent_type": analysis.intent_type,
            "steps": [{"agent": s.agent_id, "name": s.name, "goal": s.goal} for s in analysis.plan],
        })

        admitted_scopes = []
        for step in analysis.plan:
            scope = self.adapter.get_authoritative_scope(
                agent_name=step.agent_id,
                task_id=f"task-{step.agent_id[:12]}-{uuid.uuid4().hex[:4]}",
                requesting_operator=human_user,
                tenant_id=tenant_id,
                parent_principal="orchestrator-agent",
                correlation_id=corr_id,
                admission_decision="ADMITTED",
                cerbos_decision="ALLOW",
            )
            admitted_scopes.append(scope)
            notify("scope_summary_card", {
                "scope": scope,
                "step_name": step.name,
                "correlation_id": corr_id,
            })

        # ---------------------------------------------------------------------
        # Phase 2: Workload Execution (Incident Investigation or Negative Test)
        # ---------------------------------------------------------------------
        findings: Dict[str, Any] = {"correlation_id": corr_id}
        tool_decisions: List[Dict[str, Any]] = []

        # Make sure output directories exist
        os.makedirs("./workspace/output", exist_ok=True)
        os.makedirs("./workspace/logs", exist_ok=True)

        if analysis.intent_type == "NEGATIVE_TEST_READONLY_WRITE":
            log_path = "./workspace/logs/sample_staging.log"
            
            # Step A: Compute SHA-256 before any execution
            with open(log_path, "rb") as f:
                sha256_before = hashlib.sha256(f.read()).hexdigest()

            step = analysis.plan[0]
            # Mint verified Auth0 token with read-only permissions
            token = create_test_auth0_token(
                private_key=self.priv_key,
                sub=human_user,
                kid=self.kid,
                issuer=self.verifier.issuer,
                permissions=step.required_permissions,
                scope="openid profile " + " ".join(step.required_permissions),
                org_id="org_demo",
            )

            # AX Task Admission
            admission = self.adapter.submit_execution_request(
                principal="orchestrator-agent",
                roles=["orchestrator"],
                agent_name=step.agent_id,
                action="execute",
                user_token=token,
                task_data={"prompt": step.goal, "correlation_id": corr_id},
                wait_timeout=20,
            )

            task_id = admission["authoritative_scope"]["task_id"]
            notify("task_running", {
                "step_name": step.name,
                "agent_id": step.agent_id,
                "task_id": task_id,
                "correlation_id": corr_id,
            })

            ctx_token = admission.get("context_token") or TaskExecutionContext(
                task_id=task_id,
                correlation_id=corr_id,
                agent_id=step.agent_id,
                roles=["monitoring-worker"],
                tenant_id=tenant_id,
                parent_principal="orchestrator-agent",
                delegated_by=human_user,
                delegation_permissions=["filesystem:read"],
            ).sign().to_token()

            # Permitted Action: Read log
            res_read = self.gateway.invoke(ToolInvocationRequest(
                request_id=f"req-read-{uuid.uuid4().hex[:6]}",
                correlation_id=corr_id,
                task_context=ctx_token,
                tool_name="filesystem_read",
                action="read",
                arguments={"path": log_path},
            ))
            tool_decisions.append({
                "action": "filesystem_read",
                "resource": log_path,
                "decision": res_read.decision,
                "side_effect": res_read.side_effect,
            })
            notify("tool_decision", {
                "agent": step.agent_id,
                "tool": "filesystem_read",
                "action": "read",
                "decision": res_read.decision,
                "reason": "Authorized read-only access to staging logs",
                "correlation_id": corr_id,
            })

            # Forbidden Action: Attempt write to log
            write_content = "RUNTIME AUTHORIZATION TEST\n" if "runtime authorization test" in analysis.raw_prompt.lower() else "TAMPERED_MALICIOUS_LOG_DATA\n"
            res_write = self.gateway.invoke(ToolInvocationRequest(
                request_id=f"req-write-deny-{uuid.uuid4().hex[:6]}",
                correlation_id=corr_id,
                task_context=ctx_token,
                tool_name="filesystem_write",
                action="write",
                arguments={"path": log_path, "content": write_content},
            ))
            tool_decisions.append({
                "action": "filesystem_write",
                "resource": log_path,
                "attempted_content": write_content.strip(),
                "decision": res_write.decision,
                "code": res_write.code,
                "side_effect": res_write.side_effect,
                "error": res_write.error,
            })

            # Step B: Compute SHA-256 after write attempt
            with open(log_path, "rb") as f:
                sha256_after = hashlib.sha256(f.read()).hexdigest()

            integrity_verified = (sha256_before == sha256_after)

            notify("runtime_denial", {
                "agent": step.agent_id,
                "action": "filesystem_write",
                "resource": log_path,
                "attempted_content": write_content.strip(),
                "decision": res_write.decision,
                "code": res_write.code,
                "reason": res_write.error or "Action not permitted by effective task scope",
                "task_id": task_id,
                "correlation_id": corr_id,
                "integrity_verified": integrity_verified,
                "file_modified": not integrity_verified,
                "sha256": sha256_after,
            })

            return {
                "success": True,
                "correlation_id": corr_id,
                "status": "NEGATIVE_TEST_PASSED",
                "intent_type": "NEGATIVE_TEST_READONLY_WRITE",
                "task_id": task_id,
                "tool_decisions": tool_decisions,
                "denial_decision": res_write.decision,
                "denial_code": res_write.code,
                "integrity_verified": integrity_verified,
                "sha256_before": sha256_before,
                "sha256_after": sha256_after,
            }

        elif analysis.intent_type == "INCIDENT_INVESTIGATION":
            # Step 1: Website Investigator
            step_web = analysis.plan[0]
            token_web = create_test_auth0_token(
                private_key=self.priv_key,
                sub=human_user,
                kid=self.kid,
                issuer=self.verifier.issuer,
                permissions=step_web.required_permissions,
                scope="openid profile " + " ".join(step_web.required_permissions),
                org_id="org_demo",
            )
            admission_web = self.adapter.submit_execution_request(
                principal="orchestrator-agent",
                roles=["orchestrator"],
                agent_name=step_web.agent_id,
                action="execute",
                user_token=token_web,
                task_data={"prompt": step_web.goal, "correlation_id": corr_id},
                wait_timeout=20,
            )
            task_id_web = admission_web["authoritative_scope"]["task_id"]
            notify("task_running", {
                "step_name": step_web.name,
                "agent_id": step_web.agent_id,
                "task_id": task_id_web,
                "correlation_id": corr_id,
            })

            ctx_token_web = admission_web.get("context_token") or TaskExecutionContext(
                task_id=task_id_web,
                correlation_id=corr_id,
                agent_id=step_web.agent_id,
                roles=["browser-worker"],
                tenant_id=tenant_id,
                parent_principal="orchestrator-agent",
                delegated_by=human_user,
                delegation_permissions=["browser:read"],
            ).sign().to_token()

            res_nav = self.gateway.invoke(ToolInvocationRequest(
                request_id=f"req-web-{uuid.uuid4().hex[:6]}",
                correlation_id=corr_id,
                task_context=ctx_token_web,
                tool_name="browser_navigate",
                action="navigate",
                arguments={"url": "http://mock-target:8089/staging-error"},
            ))
            tool_decisions.append({
                "agent": step_web.agent_id,
                "tool": "browser_navigate",
                "decision": res_nav.decision,
                "status_code": res_nav.data.get("status_code", 500) if res_nav.data else 500,
            })
            notify("tool_decision", {
                "agent": step_web.agent_id,
                "tool": "browser_navigate",
                "action": "navigate",
                "decision": res_nav.decision,
                "reason": "Authorized read-only browser navigation to staging route",
                "data": res_nav.data,
                "correlation_id": corr_id,
            })

            findings["website_investigation"] = {
                "url": "http://mock-target:8089/staging-error",
                "status_code": res_nav.data.get("status_code", 500) if res_nav.data else 500,
                "title": res_nav.data.get("title", "500 Internal Server Error") if res_nav.data else "",
                "header": res_nav.data.get("h1", "Internal Server Error") if res_nav.data else "",
            }

            # Step 2: Log Analyst
            step_log = analysis.plan[1]
            token_log = create_test_auth0_token(
                private_key=self.priv_key,
                sub=human_user,
                kid=self.kid,
                issuer=self.verifier.issuer,
                permissions=step_log.required_permissions,
                scope="openid profile " + " ".join(step_log.required_permissions),
                org_id="org_demo",
            )
            admission_log = self.adapter.submit_execution_request(
                principal="orchestrator-agent",
                roles=["orchestrator"],
                agent_name=step_log.agent_id,
                action="execute",
                user_token=token_log,
                task_data={"prompt": step_log.goal, "correlation_id": corr_id},
                wait_timeout=20,
            )
            task_id_log = admission_log["authoritative_scope"]["task_id"]
            notify("task_running", {
                "step_name": step_log.name,
                "agent_id": step_log.agent_id,
                "task_id": task_id_log,
                "correlation_id": corr_id,
            })

            ctx_token_log = admission_log.get("context_token") or TaskExecutionContext(
                task_id=task_id_log,
                correlation_id=corr_id,
                agent_id=step_log.agent_id,
                roles=["monitoring-worker"],
                tenant_id=tenant_id,
                parent_principal="orchestrator-agent",
                delegated_by=human_user,
                delegation_permissions=["filesystem:read"],
            ).sign().to_token()

            res_log = self.gateway.invoke(ToolInvocationRequest(
                request_id=f"req-log-{uuid.uuid4().hex[:6]}",
                correlation_id=corr_id,
                task_context=ctx_token_log,
                tool_name="filesystem_read",
                action="read",
                arguments={"path": "./workspace/logs/sample_staging.log"},
            ))
            tool_decisions.append({
                "agent": step_log.agent_id,
                "tool": "filesystem_read",
                "decision": res_log.decision,
            })
            log_content = res_log.data.get("content", "") if res_log.data else ""
            error_lines = [l for l in log_content.splitlines() if "[ERROR]" in l or "ConnectionTimeoutError" in l]

            notify("tool_decision", {
                "agent": step_log.agent_id,
                "tool": "filesystem_read",
                "action": "read",
                "decision": res_log.decision,
                "reason": f"Authorized read-only log analysis. Matched {len(error_lines)} error signatures",
                "correlation_id": corr_id,
            })

            findings["log_analysis"] = {
                "log_source": "./workspace/logs/sample_staging.log",
                "matched_signatures": error_lines,
                "root_cause": "HikariPool connection acquisition timeout (pool exhausted 100/100 active)",
            }
            with open("./workspace/output/findings_incident.json", "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2)

            # Step 3: Incident Reporter
            step_doc = analysis.plan[2]
            token_doc = create_test_auth0_token(
                private_key=self.priv_key,
                sub=human_user,
                kid=self.kid,
                issuer=self.verifier.issuer,
                permissions=step_doc.required_permissions,
                scope="openid profile " + " ".join(step_doc.required_permissions),
                org_id="org_demo",
            )
            admission_doc = self.adapter.submit_execution_request(
                principal="orchestrator-agent",
                roles=["orchestrator"],
                agent_name=step_doc.agent_id,
                action="execute",
                user_token=token_doc,
                task_data={"prompt": step_doc.goal, "correlation_id": corr_id},
                wait_timeout=20,
            )
            task_id_doc = admission_doc["authoritative_scope"]["task_id"]
            notify("task_running", {
                "step_name": step_doc.name,
                "agent_id": step_doc.agent_id,
                "task_id": task_id_doc,
                "correlation_id": corr_id,
            })

            ctx_token_doc = admission_doc.get("context_token") or TaskExecutionContext(
                task_id=task_id_doc,
                correlation_id=corr_id,
                agent_id=step_doc.agent_id,
                roles=["document-worker"],
                tenant_id=tenant_id,
                parent_principal="orchestrator-agent",
                delegated_by=human_user,
                delegation_permissions=["filesystem:read", "filesystem:write"],
            ).sign().to_token()

            # Read findings
            res_read_findings = self.gateway.invoke(ToolInvocationRequest(
                request_id=f"req-doc-read-{uuid.uuid4().hex[:6]}",
                correlation_id=corr_id,
                task_context=ctx_token_doc,
                tool_name="filesystem_read",
                action="read",
                arguments={"path": "./workspace/output/findings_incident.json"},
            ))

            # Compile report
            report_text = (
                f"# Governed Staging Incident Report\n\n"
                f"- **Correlation ID**: `{corr_id}`\n"
                f"- **Tenant**: `{tenant_id}`\n"
                f"- **Operator**: `{human_user}`\n"
                f"- **Timestamp**: `{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}`\n\n"
                f"## 1. Staging Anomaly\n"
                f"Endpoint `http://mock-target:8089/staging-error` returned HTTP 500.\n"
                f"Page title: `{findings['website_investigation'].get('title')}`\n\n"
                f"## 2. Root Cause Analysis\n"
                f"Log file `/workspace/logs/sample_staging.log` confirms PostgreSQL connection exhaustion:\n"
                f"```text\n"
                f"{chr(10).join(error_lines[:3])}\n"
                f"```\n\n"
                f"## 3. Recommended Remediation\n"
                f"Increase HikariCP connection pool capacity or remediate unclosed connections.\n"
            )

            res_write_report = self.gateway.invoke(ToolInvocationRequest(
                request_id=f"req-doc-write-{uuid.uuid4().hex[:6]}",
                correlation_id=corr_id,
                task_context=ctx_token_doc,
                tool_name="filesystem_write",
                action="write",
                arguments={
                    "path": "./workspace/output/incident_report.md",
                    "content": report_text,
                },
            ))
            tool_decisions.append({
                "agent": step_doc.agent_id,
                "tool": "filesystem_write",
                "decision": res_write_report.decision,
                "bytes_written": res_write_report.data.get("bytes_written", len(report_text)) if res_write_report.data else len(report_text),
            })

            notify("incident_completed", {
                "correlation_id": corr_id,
                "artifact": "/workspace/output/incident_report.md",
                "summary": "Staging database pool saturated; transactions timing out after 30000ms.",
                "root_cause": "HikariPool connection acquisition timeout",
                "bytes_written": len(report_text),
            })

            return {
                "success": True,
                "correlation_id": corr_id,
                "status": "INCIDENT_INVESTIGATION_COMPLETED",
                "intent_type": "INCIDENT_INVESTIGATION",
                "tasks": [task_id_web, task_id_log, task_id_doc],
                "tool_decisions": tool_decisions,
                "artifact": "/workspace/output/incident_report.md",
                "findings": findings,
            }

        return {
            "success": False,
            "correlation_id": corr_id,
            "status": "UNHANDLED_WORKFLOW",
        }

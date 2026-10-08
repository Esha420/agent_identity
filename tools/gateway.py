"""Tool Gateway PEP (Policy Enforcement Point).

Intercepts every runtime tool invocation within the agent workload execution boundary.
Enforces authentication, catalog gating, SSRF defenses, canonical filesystem containment,
and Cerbos PDP policy authorization with zero side-effects on denial.
"""

import hashlib
from html.parser import HTMLParser
import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional
import urllib.error
import urllib.request
import uuid
import yaml

from ax.cerbos_client import CerbosClient
from tools.schema import (
    AuditEvent,
    TaskExecutionContext,
    ToolInvocationRequest,
    ToolInvocationResponse,
)
from tools.security import (
    SecurityValidationError,
    normalize_and_validate_path,
    normalize_and_validate_url,
    validate_task_context,
)

DEFAULT_TOOLS_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "catalog.yaml")
DEFAULT_AGENTS_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "../agents/catalog.yaml")


class GovernedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Prevents SSRF and DNS rebinding attacks across HTTP 3xx redirects.
    
    Intercepts every redirect, normalizes the target URL, verifies domain allowlists,
    resolves A and AAAA DNS records, and blocks redirects to private or cloud metadata IPs.
    """
    def __init__(self, profile_config: Dict[str, Any], profile_name: str, max_redirects: int = 3):
        super().__init__()
        self.profile_config = profile_config
        self.profile_name = profile_name
        self.max_redirects = max_redirects
        self.redirects_followed = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirects_followed += 1
        if self.redirects_followed > self.max_redirects:
            raise SecurityValidationError(f"Too many HTTP redirects (exceeded limit of {self.max_redirects})")
        # Validate redirect target against security policy
        norm = normalize_and_validate_url(newurl, self.profile_config, self.profile_name)
        return super().redirect_request(req, fp, code, msg, headers, norm["normalized_url"])


class _SimpleTitleH1Parser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.h1 = ""
        self._in_title = False
        self._in_h1 = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in_title = True
        elif tag.lower() == "h1":
            self._in_h1 = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False
        elif tag.lower() == "h1":
            self._in_h1 = False

    def handle_data(self, data):
        if self._in_title and not self.title:
            self.title = data.strip()
        elif self._in_h1 and not self.h1:
            self.h1 = data.strip()


class ToolGatewayPEP:
    """Runtime Policy Enforcement Point mediating all agent tool invocations."""

    def __init__(
        self,
        cerbos_client: Optional[CerbosClient] = None,
        tools_catalog_path: str = DEFAULT_TOOLS_CATALOG_PATH,
        agents_catalog_path: str = DEFAULT_AGENTS_CATALOG_PATH,
        audit_sink: Optional[Callable[[AuditEvent], None]] = None,
        active_epoch: int = 1,
        expected_audience: str = "tool-gateway",
        expected_issuer: str = "ax-admission-pep",
    ):
        self.cerbos = cerbos_client or CerbosClient()
        self.tools_catalog_path = tools_catalog_path
        self.agents_catalog_path = agents_catalog_path
        self.tools_catalog = self._load_tools_catalog()
        self.agents_catalog = self._load_agents_catalog()
        self.audit_sink = audit_sink
        self.active_epoch = active_epoch
        self.expected_audience = expected_audience
        self.expected_issuer = expected_issuer
        self.revoked_tasks = set()
        self.revoked_epochs = set()

        # Observability and side-effect tracking for test assertions
        self.network_call_count = 0
        self.filesystem_read_count = 0
        self.filesystem_write_count = 0
        self.audit_logs: List[AuditEvent] = []

    def revoke_task(self, task_id: str):
        """Immediately revoke authorization for a specific task ID."""
        self.revoked_tasks.add(task_id)

    def revoke_epoch(self, epoch: int):
        """Immediately revoke contexts issued under prior authorization epochs."""
        self.active_epoch = epoch

    def _load_tools_catalog(self) -> Dict[str, Any]:
        with open(self.tools_catalog_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("tools", {})

    def _load_agents_catalog(self) -> Dict[str, Any]:
        with open(self.agents_catalog_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("agents", {})

    def record_audit(self, event: AuditEvent):
        self.audit_logs.append(event)
        if self.audit_sink:
            self.audit_sink(event)

    def invoke(self, req: ToolInvocationRequest) -> ToolInvocationResponse:
        """
        Mediate, pre-validate, authorize, and execute a tool invocation request.
        
        Zero Side-Effects Guarantee:
        If authentication fails, catalog capability is absent, normalization fails,
        or Cerbos returns anything other than ALLOW, ZERO network calls or filesystem
        mutations will take place.
        """
        req_id = req.request_id or f"tool-req-{uuid.uuid4().hex[:8]}"

        # Unpack token if passed as serialized string
        if isinstance(req.task_context, str):
            try:
                ctx = TaskExecutionContext.from_token(req.task_context)
            except Exception as e:
                event = AuditEvent(
                    request_id=req_id,
                    tool=req.tool_name,
                    action=req.action,
                    decision="REJECTED_PEP",
                    code="INVALID_TASK_CONTEXT",
                    reason=f"Failed to deserialize context token: {e}",
                    side_effect="none",
                )
                self.record_audit(event)
                return ToolInvocationResponse(
                    ok=False,
                    code="INVALID_TASK_CONTEXT",
                    request_id=req_id,
                    tool=req.tool_name,
                    decision="REJECTED_PEP",
                    side_effect="none",
                    error=f"Context token deserialization failed: {e}",
                )
        else:
            ctx = req.task_context

        # -------------------------------------------------------------
        # Step 1: Authenticate Workload & Validate Task Context
        # -------------------------------------------------------------
        try:
            if not ctx:
                raise SecurityValidationError("Missing TaskExecutionContext")
            if ctx.task_id in self.revoked_tasks:
                raise SecurityValidationError(f"Task '{ctx.task_id}' has been revoked")
            if ctx.authorization_epoch in self.revoked_epochs:
                raise SecurityValidationError(f"Authorization epoch {ctx.authorization_epoch} has been revoked")

            validate_task_context(
                ctx,
                expected_agent=ctx.agent_id,
                expected_audience=self.expected_audience,
                expected_issuer=self.expected_issuer,
                required_epoch=self.active_epoch,
            )
        except SecurityValidationError as e:
            event = AuditEvent(
                request_id=req_id,
                task_id=getattr(ctx, "task_id", "unknown"),
                agent_id=getattr(ctx, "agent_id", "unknown"),
                tenant_id=getattr(ctx, "tenant_id", "unknown"),
                delegated_by=getattr(ctx, "delegated_by", "unknown"),
                tool=req.tool_name,
                action=req.action,
                decision="REJECTED_PEP",
                code="INVALID_TASK_CONTEXT",
                reason=str(e),
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="INVALID_TASK_CONTEXT",
                request_id=req_id,
                tool=req.tool_name,
                decision="REJECTED_PEP",
                side_effect="none",
                error=f"Task execution context invalid: {e}",
            )

        # -------------------------------------------------------------
        # Step 1b: Explicit Identity Verification (Derive from Verified Context)
        # The agent supplies only tool intent and arguments. Identity is derived
        # strictly from ctx. If caller claims another task_id or agent_id, reject!
        # -------------------------------------------------------------
        claimed_task = req.claimed_task_id or req.arguments.get("task_id")
        if claimed_task and claimed_task != ctx.task_id:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="REJECTED_PEP",
                code="TASK_ID_MISMATCH",
                reason=f"Claimed task ID '{claimed_task}' does not match authoritative context '{ctx.task_id}'",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="TASK_ID_MISMATCH",
                request_id=req_id,
                tool=req.tool_name,
                decision="REJECTED_PEP",
                side_effect="none",
                error=f"Claimed task ID '{claimed_task}' does not match context '{ctx.task_id}'",
            )

        claimed_agent = req.claimed_agent_id or req.arguments.get("agent_id")
        if claimed_agent and claimed_agent != ctx.agent_id:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="REJECTED_PEP",
                code="AGENT_ID_MISMATCH",
                reason=f"Claimed agent ID '{claimed_agent}' does not match authoritative context '{ctx.agent_id}'",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="AGENT_ID_MISMATCH",
                request_id=req_id,
                tool=req.tool_name,
                decision="REJECTED_PEP",
                side_effect="none",
                error=f"Claimed agent ID '{claimed_agent}' does not match context '{ctx.agent_id}'",
            )

        # -------------------------------------------------------------
        # Step 2: Agent Catalog Capability Gate & Integrity Checks
        # -------------------------------------------------------------
        if ctx.agent_id not in self.agents_catalog:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="DENY",
                code="UNKNOWN_AGENT",
                reason=f"Agent '{ctx.agent_id}' not found in agent catalog",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="UNKNOWN_AGENT",
                request_id=req_id,
                tool=req.tool_name,
                decision="DENY",
                side_effect="none",
                error=f"Agent '{ctx.agent_id}' is not registered in catalog",
            )

        agent_meta = self.agents_catalog[ctx.agent_id]
        allowed_tools = agent_meta.get("allowed_tools", [])
        if req.tool_name not in allowed_tools:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="DENY",
                code="CATALOG_DENIED",
                reason=f"Tool '{req.tool_name}' not permitted in agent catalog for '{ctx.agent_id}'",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="CATALOG_DENIED",
                request_id=req_id,
                tool=req.tool_name,
                decision="DENY",
                side_effect="none",
                error=f"Tool '{req.tool_name}' is not in allowed_tools for '{ctx.agent_id}'",
            )

        # Verify tool set hash integrity
        expected_tool_hash = hashlib.sha256(
            json.dumps(sorted(allowed_tools)).encode("utf-8")
        ).hexdigest()
        if ctx.allowed_tool_set_hash and ctx.allowed_tool_set_hash != expected_tool_hash:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="DENY",
                code="CATALOG_INTEGRITY_FAILED",
                reason="Context allowed_tool_set_hash does not match active catalog resolution",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="CATALOG_INTEGRITY_FAILED",
                request_id=req_id,
                tool=req.tool_name,
                decision="DENY",
                side_effect="none",
                error="Context tool set hash does not match active catalog",
            )

        # Verify image digest integrity
        cat_image = agent_meta.get("runtime", {}).get("image", "")
        cat_digest = cat_image.split("@")[-1] if "@" in cat_image else ""
        if cat_digest and ctx.agent_image_digest and ctx.agent_image_digest != cat_digest:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="DENY",
                code="IMAGE_INTEGRITY_FAILED",
                reason="Context agent_image_digest does not match active catalog digest",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="IMAGE_INTEGRITY_FAILED",
                request_id=req_id,
                tool=req.tool_name,
                decision="DENY",
                side_effect="none",
                error="Context image digest does not match active catalog",
            )

        # -------------------------------------------------------------
        # Step 3: Tool Catalog Verification
        # -------------------------------------------------------------
        if req.tool_name not in self.tools_catalog:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                tool=req.tool_name,
                action=req.action,
                decision="DENY",
                code="UNKNOWN_TOOL",
                reason=f"Tool '{req.tool_name}' not defined in tool catalog",
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="UNKNOWN_TOOL",
                request_id=req_id,
                tool=req.tool_name,
                decision="DENY",
                side_effect="none",
                error=f"Tool '{req.tool_name}' is not defined in tool catalog",
            )

        tool_meta = self.tools_catalog[req.tool_name]
        profile_name = ctx.environment or "test"
        tool_profiles = tool_meta.get("profiles", {})
        profile_config = tool_profiles.get(profile_name, tool_profiles.get("test", {}))

        # -------------------------------------------------------------
        # Step 4: Normalization & Pre-Validation Engine
        # -------------------------------------------------------------
        norm_data: Dict[str, Any] = {}
        try:
            if req.tool_name in ["fetch_url", "browser_navigate"]:
                url = req.arguments.get("url", "")
                method = req.arguments.get("method", "GET").upper()
                norm_data = normalize_and_validate_url(url, profile_config, profile_name)
                norm_data["method"] = method

            elif req.tool_name == "filesystem_read":
                path = req.arguments.get("path", "")
                norm_data = normalize_and_validate_path(
                    path, tool_meta.get("allowed_path_roots", ["/workspace/input"])
                )

            elif req.tool_name == "filesystem_write":
                path = req.arguments.get("path", "")
                norm_data = normalize_and_validate_path(
                    path, tool_meta.get("allowed_path_roots", ["/workspace/output"])
                )
        except SecurityValidationError as e:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                tool=req.tool_name,
                action=req.action,
                decision="REJECTED_PEP",
                code="INVALID_ARGUMENTS",
                reason=str(e),
                side_effect="none",
                metadata={"arguments": req.arguments},
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="INVALID_ARGUMENTS",
                request_id=req_id,
                tool=req.tool_name,
                decision="REJECTED_PEP",
                side_effect="none",
                error=f"Argument validation failed: {e}",
            )

        # -------------------------------------------------------------
        # Step 5: Cerbos PDP Evaluation (Layer 2 Gate)
        # -------------------------------------------------------------
        resource_attr = {
            "task_id": ctx.task_id,
            "tenant_id": ctx.tenant_id,
            "delegated_by": ctx.delegated_by,
            "delegation_issuer": getattr(ctx, "delegation_issuer", "https://your-tenant.us.auth0.com/"),
            "delegation_permissions": list(getattr(ctx, "delegation_permissions", [])),
            "side_effect": tool_meta.get("side_effect", "none"),
        }

        if req.tool_name in ["fetch_url", "browser_navigate"]:
            resource_attr.update({
                "method": norm_data.get("method", "GET"),
                "host": norm_data.get("host", ""),
                "scheme": norm_data.get("scheme", ""),
                "port": norm_data.get("port", 80),
                "ip_valid": norm_data.get("ip_valid", False),
                "allowed_methods": profile_config.get("allowed_methods", ["GET"]),
                "allowed_hosts": profile_config.get("allowed_hosts", []),
                "allowed_schemes": profile_config.get("allowed_schemes", []),
                "allowed_ports": profile_config.get("allowed_ports", []),
            })
        elif req.tool_name in ["filesystem_read", "filesystem_write"]:
            resource_attr.update({
                "path_contained": norm_data.get("path_contained", False),
                "canonical_path": norm_data.get("canonical_path", ""),
            })

        principal_attr = {
            "task_id": ctx.task_id,
            "tenant_id": ctx.tenant_id,
            "parent_principal": ctx.parent_principal,
            "delegated_by": ctx.delegated_by,
            "delegation_issuer": getattr(ctx, "delegation_issuer", "https://your-tenant.us.auth0.com/"),
            "delegation_permissions": list(getattr(ctx, "delegation_permissions", [])),
            "agent_image_digest": ctx.agent_image_digest,
            "environment": ctx.environment,
            "authorization_epoch": ctx.authorization_epoch,
        }

        allowed, decision, raw = self.cerbos.authorize(
            request_id=req_id,
            principal_id=ctx.agent_id,
            roles=ctx.roles,
            resource_id=req.tool_name,
            resource_kind="tool",
            action=req.action,
            principal_attr=principal_attr,
            resource_attr=resource_attr,
        )

        if not allowed or decision != "ALLOW":
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                tool=req.tool_name,
                action=req.action,
                decision=decision,
                code="AUTHZ_DENIED",
                reason=f"Cerbos policy decision: {decision}",
                side_effect="none",
                metadata={"resource_attr": resource_attr},
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="AUTHZ_DENIED",
                request_id=req_id,
                tool=req.tool_name,
                decision=decision,
                side_effect="none",
                error=f"Authorization denied by policy: {decision}",
            )

        # -------------------------------------------------------------
        # Step 6: Authorized Tool Execution (ALLOW Only)
        # -------------------------------------------------------------
        try:
            if req.tool_name == "fetch_url":
                res_data = self._execute_fetch_url(norm_data, req.arguments, profile_config, profile_name)
                side_effect = "read"
            elif req.tool_name == "browser_navigate":
                res_data = self._execute_browser_navigate(norm_data, req.arguments, profile_config, profile_name)
                side_effect = "read"
            elif req.tool_name == "filesystem_read":
                res_data = self._execute_filesystem_read(norm_data, req.arguments)
                side_effect = "read"
            elif req.tool_name == "filesystem_write":
                res_data = self._execute_filesystem_write(norm_data, req.arguments)
                side_effect = "mutated"
            else:
                raise RuntimeError(f"Unhandled tool handler: {req.tool_name}")

            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="ALLOW",
                code="SUCCESS",
                reason="Authorized and successfully executed",
                side_effect=side_effect,
            )
            self.record_audit(event)

            return ToolInvocationResponse(
                ok=True,
                code="SUCCESS",
                request_id=req_id,
                tool=req.tool_name,
                decision="ALLOW",
                side_effect=side_effect,
                data=res_data,
            )
        except Exception as e:
            event = AuditEvent(
                request_id=req_id,
                task_id=ctx.task_id,
                agent_id=ctx.agent_id,
                tenant_id=ctx.tenant_id,
                delegated_by=ctx.delegated_by,
                tool=req.tool_name,
                action=req.action,
                decision="ALLOW_EXECUTION_ERROR",
                code="EXECUTION_ERROR",
                reason=str(e),
                side_effect="none",
            )
            self.record_audit(event)
            return ToolInvocationResponse(
                ok=False,
                code="EXECUTION_ERROR",
                request_id=req_id,
                tool=req.tool_name,
                decision="ALLOW",
                side_effect="none",
                error=f"Tool handler error: {e}",
            )

    # -----------------------------------------------------------------
    # Safe Internal Execution Handlers
    # -----------------------------------------------------------------

    def _execute_fetch_url(
        self,
        norm_data: Dict[str, Any],
        args: Dict[str, Any],
        profile_config: Optional[Dict[str, Any]] = None,
        profile_name: str = "test",
    ) -> Dict[str, Any]:
        """Execute HTTP request against the normalized URL with redirect inspection."""
        target_url = norm_data["normalized_url"]
        self.network_call_count += 1

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "AgentIdentity-GovernedTool/1.0"},
            method=norm_data.get("method", "GET"),
        )
        p_cfg = profile_config or {}
        opener = urllib.request.build_opener(
            GovernedRedirectHandler(p_cfg, profile_name)
        )
        with opener.open(req, timeout=5.0) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            return {
                "url": target_url,
                "status_code": resp.status,
                "content": content,
            }

    def _execute_browser_navigate(
        self,
        norm_data: Dict[str, Any],
        args: Dict[str, Any],
        profile_config: Optional[Dict[str, Any]] = None,
        profile_name: str = "test",
    ) -> Dict[str, Any]:
        """Navigate to URL and extract page title & h1 content with redirect inspection."""
        target_url = norm_data["normalized_url"]
        self.network_call_count += 1

        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "AgentIdentity-BrowserTool/1.0"},
            method="GET",
        )
        p_cfg = profile_config or {}
        opener = urllib.request.build_opener(
            GovernedRedirectHandler(p_cfg, profile_name)
        )
        with opener.open(req, timeout=5.0) as resp:
            html_text = resp.read().decode("utf-8", errors="replace")
            parser = _SimpleTitleH1Parser()
            parser.feed(html_text)

            return {
                "status": "COMPLETED",
                "url": target_url,
                "title": parser.title or "No Title Found",
                "h1": parser.h1 or "",
                "status_code": resp.status,
            }

    def _execute_filesystem_read(self, norm_data: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
        """Read content from the strictly contained canonical path."""
        target_path = norm_data["canonical_path"]
        self.filesystem_read_count += 1

        if not os.path.exists(target_path):
            raise FileNotFoundError(f"File not found: {target_path}")

        with open(target_path, "r", encoding="utf-8") as f:
            content = f.read()

        return {
            "path": target_path,
            "content": content,
            "size_bytes": len(content),
        }

    def _execute_filesystem_write(self, norm_data: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
        """Write content into the strictly contained canonical path."""
        target_path = norm_data["canonical_path"]
        content = args.get("content", "")
        self.filesystem_write_count += 1

        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)

        return {
            "path": target_path,
            "bytes_written": len(content),
            "status": "WRITTEN",
        }

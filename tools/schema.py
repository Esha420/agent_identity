"""Canonical data schemas, cryptographic contracts, and execution contexts for Tool Governance."""

import base64
from dataclasses import asdict, dataclass, field
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional
import uuid

DEFAULT_SIGNING_KEY = "ax-pep-trusted-hmac-key-2026"


@dataclass(frozen=True)
class TaskExecutionContext:
    """
    Immutable, cryptographically verifiable task execution context.
    
    Minted EXCLUSIVELY by the AX Admission PEP upon Layer 1 authorization approval
    and authoritative AX task creation. Injected into the sandbox workload.
    """
    task_id: str
    agent_id: str
    roles: List[str]
    capability: str = "browser"
    tenant_id: str = "tenant-demo"
    parent_principal: str = "orchestrator-agent"
    delegated_by: str = "user-123"
    delegation_issuer: str = "https://your-tenant.us.auth0.com/"
    delegation_permissions: List[str] = field(default_factory=list)
    agent_image_digest: str = "sha256:8abae590b3dcf422089e17b4219c0c7136fd84384ea228af1e66381d5ced4f8f"
    environment: str = "test"  # "test" | "production"
    policy_scope: str = "default"
    allowed_tool_set_hash: str = ""
    issuer: str = "ax-admission-pep"
    audience: str = "tool-gateway"
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    authorization_epoch: int = 1
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int = field(default_factory=lambda: int(time.time()) + 3600)
    context_id: str = field(default_factory=lambda: f"ctx-{uuid.uuid4().hex[:12]}")
    signature: str = ""

    def _canonical_payload(self) -> bytes:
        """Create canonical representation of signed fields for HMAC signing."""
        data = {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "roles": sorted(list(self.roles)),
            "capability": self.capability,
            "tenant_id": self.tenant_id,
            "parent_principal": self.parent_principal,
            "delegated_by": self.delegated_by,
            "delegation_issuer": self.delegation_issuer,
            "delegation_permissions": sorted(list(self.delegation_permissions)),
            "agent_image_digest": self.agent_image_digest,
            "environment": self.environment,
            "policy_scope": self.policy_scope,
            "allowed_tool_set_hash": self.allowed_tool_set_hash,
            "issuer": self.issuer,
            "audience": self.audience,
            "nonce": self.nonce,
            "authorization_epoch": self.authorization_epoch,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "context_id": self.context_id,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, secret_key: str = DEFAULT_SIGNING_KEY) -> "TaskExecutionContext":
        """Compute HMAC-SHA256 signature and return a new signed context instance."""
        sig = hmac.new(secret_key.encode("utf-8"), self._canonical_payload(), hashlib.sha256).hexdigest()
        # Create new instance with signature populated
        field_dict = {f: getattr(self, f) for f in self.__dataclass_fields__ if f != "signature"}
        field_dict["signature"] = sig
        return TaskExecutionContext(**field_dict)

    def verify_signature(self, secret_key: str = DEFAULT_SIGNING_KEY) -> bool:
        """Cryptographically verify the context signature against the trusted admission key."""
        if not self.signature:
            return False
        expected_sig = hmac.new(
            secret_key.encode("utf-8"), self._canonical_payload(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)

    def is_expired(self, current_time: Optional[int] = None) -> bool:
        """Check if the execution lease has expired."""
        now = current_time if current_time is not None else int(time.time())
        return now > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["roles"] = list(self.roles)
        res["delegation_permissions"] = list(self.delegation_permissions)
        return res

    def to_token(self) -> str:
        """Serialize signed context to compact URL-safe base64 token."""
        raw = json.dumps(self.to_dict()).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8")

    @classmethod
    def from_token(cls, token_str: str) -> "TaskExecutionContext":
        """Deserialize context token from compact base64."""
        raw = base64.urlsafe_b64decode(token_str.encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))
        known_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def to_principal_payload(self) -> Dict[str, Any]:
        """Format as Cerbos principal payload."""
        return {
            "id": self.agent_id,
            "roles": list(self.roles),
            "attr": {
                "task_id": self.task_id,
                "tenant_id": self.tenant_id,
                "parent_principal": self.parent_principal,
                "delegated_by": self.delegated_by,
                "delegation_issuer": self.delegation_issuer,
                "delegation_permissions": list(self.delegation_permissions),
                "agent_image_digest": self.agent_image_digest,
                "environment": self.environment,
                "capability": self.capability,
                "policy_scope": self.policy_scope,
                "authorization_epoch": self.authorization_epoch,
                "context_id": self.context_id,
                "issuer": self.issuer,
                "audience": self.audience,
            },
        }


@dataclass
class ToolInvocationRequest:
    """
    Invocation request submitted by an agent workload to the Tool Gateway PEP.
    
    The agent submits only tool intent and arguments along with its signed task context.
    The agent does NOT self-assert identity, tenant, or roles. If claimed_task_id or
    claimed_agent_id are provided, the PEP validates that they match the verified context.
    """
    request_id: str
    task_context: Any  # TaskExecutionContext or token str
    tool_name: str
    action: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    claimed_task_id: Optional[str] = None
    claimed_agent_id: Optional[str] = None


@dataclass
class ToolInvocationResponse:
    """Structured response returned by the Tool Gateway PEP to the agent."""
    ok: bool
    code: str  # "SUCCESS", "INVALID_REQUEST", "CATALOG_DENIED", "AUTHZ_DENIED", "EXPIRED", "INVALID_TASK_CONTEXT", "ERROR_FAIL_CLOSED"
    request_id: str
    tool: str
    decision: str  # "ALLOW", "DENY", "REJECTED_PEP", "ERROR_FAIL_CLOSED"
    side_effect: str  # "none", "read", "mutated"
    data: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "request_id": self.request_id,
            "tool": self.tool,
            "decision": self.decision,
            "side_effect": self.side_effect,
            "data": self.data,
            "error": self.error,
        }


@dataclass
class AuditEvent:
    """Operator-facing audit log entry recorded for every tool evaluation."""
    timestamp: float = field(default_factory=time.time)
    request_id: str = ""
    task_id: str = ""
    agent_id: str = ""
    tenant_id: str = ""
    delegated_by: str = ""
    tool: str = ""
    action: str = ""
    decision: str = ""
    code: str = ""
    reason: str = ""
    side_effect: str = "none"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "delegated_by": self.delegated_by,
            "tool": self.tool,
            "action": self.action,
            "decision": self.decision,
            "code": self.code,
            "reason": self.reason,
            "side_effect": self.side_effect,
            "metadata": self.metadata,
        }

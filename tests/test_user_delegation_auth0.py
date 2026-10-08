"""End-to-End User Delegation and Auth0 Integration Test Suite.

Verifies the complete identity-to-execution pipeline:
Auth0 OIDC User Token -> Orchestrator Intent -> AX Admission PEP -> Cerbos Layer 1
-> Substrate Sandbox -> Minted Task Context -> Tool Gateway PEP -> Cerbos Layer 2.

Ensures:
1. Authority is derived from verified Auth0 token, never caller body.
2. The raw Auth0 token terminates at Admission PEP and is NEVER forwarded to agent.
3. Cerbos Layer 1 governs agent execution; Cerbos Layer 2 governs runtime tools.
"""

import subprocess
import time
import unittest
from unittest import mock

from ax.adapter import AXAdmissionAdapter
from ax.auth0_verifier import (
    Auth0TokenVerifier,
    create_test_auth0_token,
    generate_test_keypair,
)
from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest


class TestUserDelegationAuth0(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cerbos = CerbosClient()
        if not cls.cerbos.check_health():
            raise RuntimeError("Cerbos PDP must be healthy at http://localhost:3592")

        # Generate keypair for test Auth0 issuer
        cls.priv_key, cls.pub_key, cls.kid, _ = generate_test_keypair(kid="auth0-integration-key")
        cls.domain = "identity-test.us.auth0.com"
        cls.issuer = f"https://{cls.domain}/"
        cls.audience = "https://agent-admission.example.com"

        cls.auth0_verifier = Auth0TokenVerifier(
            domain=cls.domain,
            issuer=cls.issuer,
            audience=cls.audience,
            local_public_keys={cls.kid: cls.pub_key},
            tenant_mapping={
                "org_demo": "tenant-demo",
                "org_acme": "tenant-acme",
            },
        )

        cls.adapter = AXAdmissionAdapter(auth0_verifier=cls.auth0_verifier)
        cls.gateway = ToolGatewayPEP(cerbos_client=cls.cerbos)

    def _mint_user_token(
        self,
        sub: str = "auth0|user-123",
        permissions: list = None,
        org_id: str = "org_demo",
        expires_in: int = 3600,
    ) -> str:
        perms = permissions if permissions is not None else ["agent:execute", "browser:read"]
        return create_test_auth0_token(
            private_key=self.priv_key,
            sub=sub,
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
            permissions=perms,
            scope=" ".join(["openid", "profile"] + perms),
            org_id=org_id,
            expires_in=expires_in,
        )

    def _mock_ax_subprocess(self):
        """Returns standard mocked AX CLI process outputs for offline tests."""
        return [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="task created\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="Phase: Running\nWorker IP: 10.0.0.5\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="deleted\n", stderr=""),
        ]

    # =========================================================================
    # Layer 1: Auth0 Token to AX Workload Admission
    # =========================================================================

    @mock.patch("subprocess.run")
    def test_01_user_can_execute_browser_agent(self, mock_run):
        """Scenario: User with valid token can execute browser agent -> AX task accepted."""
        mock_run.side_effect = self._mock_ax_subprocess()
        user_token = self._mint_user_token(sub="auth0|user-123", permissions=["agent:execute", "browser:read"])

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token,
        )

        self.assertEqual(trace["cerbos_decision"], "ALLOW")
        self.assertEqual(trace["ax_decision"], "ACCEPTED")
        self.assertIn("task_execution_context", trace)
        task_ctx = trace["task_execution_context"]
        self.assertEqual(task_ctx["delegated_by"], "auth0|user-123")
        self.assertEqual(task_ctx["tenant_id"], "tenant-demo")
        self.assertIn("browser:read", task_ctx["delegation_permissions"])

    def test_02_user_cannot_execute_restricted_agent(self):
        """Scenario: User cannot execute restricted agent -> Cerbos Layer 1 DENY."""
        user_token = self._mint_user_token(sub="auth0|user-123", permissions=["agent:execute"])

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="restricted-agent",
            action="execute",
            user_token=user_token,
        )

        self.assertEqual(trace["cerbos_decision"], "DENY")
        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")

    def test_03_missing_agent_execute_permission_denied(self):
        """Scenario: User lacking 'agent:execute' scope -> Admission rejected by PEP."""
        token_no_perm = self._mint_user_token(
            sub="auth0|user-viewer",
            permissions=["task:read"],  # Missing agent:execute
        )

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token_no_perm,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("missing required permission", str(trace["agent_result"]).lower())

    def test_04_user_from_another_tenant_denied(self):
        """Scenario: User from another tenant -> Multi-tenant boundary violation denied."""
        token_acme = self._mint_user_token(
            sub="auth0|acme-user",
            permissions=["agent:execute"],
            org_id="org_acme",  # maps to tenant-acme, but orchestrator is tenant-demo
        )

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token_acme,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("does not match", str(trace["agent_result"]))

    def test_05_forged_delegated_by_in_request_body_rejected(self):
        """Scenario: Forged delegated_by in request body differs from token -> Rejected."""
        user_token = self._mint_user_token(sub="auth0|user-123")

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token,
            context={"delegated_by": "auth0|forged-victim-999"},  # Attempted forgery
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("forged delegated_by", str(trace["agent_result"]))

    def test_06_forged_tenant_in_request_body_rejected(self):
        """Scenario: Forged tenant in request body differs from token -> Rejected."""
        user_token = self._mint_user_token(sub="auth0|user-123", org_id="org_demo")

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token,
            context={"tenant_id": "tenant-evil-override"},  # Attempted forgery
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("forged tenant", str(trace["agent_result"]))

    def test_07_untrusted_orchestrator_identity_rejected(self):
        """Scenario: Valid user token but wrong orchestrator identity -> Rejected."""
        user_token = self._mint_user_token(sub="auth0|user-123")

        trace = self.adapter.submit_execution_request(
            principal="attacker-fake-orchestrator",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("untrusted orchestrator", str(trace["agent_result"]).lower())

    @mock.patch("subprocess.run")
    def test_08_user_token_never_forwarded_to_agent(self, mock_run):
        """Scenario: Auth0 user token MUST NEVER be forwarded to the agent sandbox."""
        mock_run.side_effect = self._mock_ax_subprocess()
        user_token = self._mint_user_token(sub="auth0|user-123")

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token,
        )

        self.assertEqual(trace["ax_decision"], "ACCEPTED")

        # 1. Verify token is NOT in task context dictionary
        task_ctx_dict = trace["task_execution_context"]
        for key, val in task_ctx_dict.items():
            self.assertNotEqual(val, user_token, f"Token leaked into context field: {key}")
            if isinstance(val, str):
                self.assertNotIn(user_token, val, f"Token substring leaked into context field: {key}")

        # 2. Verify token is NOT in context_token
        self.assertNotIn(user_token, trace["context_token"])

    def test_09_revoked_auth0_user_denied(self):
        """Scenario: Revoked Auth0 user cannot admit workloads."""
        revoked_user = "auth0|revoked-user-456"
        token = self._mint_user_token(sub=revoked_user)

        # Revoke user in verifier
        self.auth0_verifier.revoke_subject(revoked_user)

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("revoked", str(trace["agent_result"]).lower())

    # =========================================================================
    # Layer 2: Tool Gateway Runtime Enforcement with Minted Delegation Context
    # =========================================================================

    @mock.patch("subprocess.run")
    def test_10_valid_user_authorized_tool_allowed(self, mock_run):
        """Scenario: Minted context carrying 'browser:read' -> Tool Gateway ALLOWS fetch_url."""
        mock_run.side_effect = self._mock_ax_subprocess()
        user_token = self._mint_user_token(
            sub="auth0|user-123",
            permissions=["agent:execute", "browser:read"],
        )

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token,
        )
        self.assertEqual(trace["ax_decision"], "ACCEPTED")

        # Agent uses minted context token to invoke fetch_url at Tool Gateway
        context_token = trace["context_token"]
        tool_req = ToolInvocationRequest(
            request_id="tool-req-001",
            task_context=context_token,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://127.0.0.1:8089/index.html"},
        )

        resp = self.gateway.invoke(tool_req)
        self.assertTrue(resp.ok)
        self.assertEqual(resp.decision, "ALLOW")
        self.assertEqual(resp.code, "SUCCESS")

    @mock.patch("subprocess.run")
    def test_11_valid_user_unauthorized_tool_denied(self, mock_run):
        """Scenario: User token had only 'agent:execute' (no 'browser:read') -> Tool call DENIED."""
        mock_run.side_effect = self._mock_ax_subprocess()
        user_token_no_tool = self._mint_user_token(
            sub="auth0|user-restricted-tools",
            permissions=["agent:execute"],  # Note: missing browser:read
        )

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=user_token_no_tool,
        )
        self.assertEqual(trace["ax_decision"], "ACCEPTED")

        # Agent tries to execute fetch_url with context lacking browser:read permission
        context_token = trace["context_token"]
        tool_req = ToolInvocationRequest(
            request_id="tool-req-002",
            task_context=context_token,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://127.0.0.1:8089/index.html"},
        )

        resp = self.gateway.invoke(tool_req)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.decision, "DENY")
        self.assertEqual(resp.code, "AUTHZ_DENIED")

    def test_12_expired_task_context_denied_at_gateway(self):
        """Scenario: Expired task context lease -> Tool call denied by PEP with INVALID_TASK_CONTEXT."""
        # Create an expired task context
        expired_context = TaskExecutionContext(
            task_id="task-expired-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="auth0|user-123",
            delegation_permissions=["browser:read"],
            expires_at=int(time.time()) - 100,  # Expired in the past
        ).sign()

        tool_req = ToolInvocationRequest(
            request_id="tool-req-003",
            task_context=expired_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://127.0.0.1:8089/index.html"},
        )

        resp = self.gateway.invoke(tool_req)
        self.assertFalse(resp.ok)
        self.assertEqual(resp.code, "INVALID_TASK_CONTEXT")
        self.assertIn("expired", resp.error.lower())
        self.assertEqual(resp.decision, "REJECTED_PEP")


if __name__ == "__main__":
    unittest.main()

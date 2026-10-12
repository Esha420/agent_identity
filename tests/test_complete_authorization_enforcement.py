"""Complete End-to-End Authorization & Enforcement Test Suite.

Verifies all seven security properties outlined in Phase 7:
1. Valid token and authorized user.
2. Invalid signature, wrong audience, and expired token.
3. Forged subject and forged tenant tampering prevention.
4. Cross-tenant access isolation.
5. Restricted agent denied before AX and Substrate execution.
6. Missing or insufficient delegated permissions fail closed at Tool Gateway.
7. Unauthorized browser, SSRF metadata, or directory traversal fail closed.
8. Policy service unavailable fails closed.
9. Denied requests produce exactly zero AX tasks and zero Substrate workloads.
"""

import json
import os
import subprocess
import sys
import unittest
from unittest import mock

# Automatically include project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.auth0_verifier import (
    Auth0TokenVerifier,
    create_test_auth0_token,
    generate_test_keypair,
)
from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest
from tools.mcp_server import MCPToolHandler


class TestCompleteAuthorizationEnforcement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cerbos = CerbosClient()
        if not cls.cerbos.check_health():
            raise RuntimeError("Cerbos PDP must be running and healthy at http://localhost:3592")

        # Set up cryptographic key pairs for trusted Auth0 issuer and attacker
        cls.priv_key, cls.pub_key, cls.kid, _ = generate_test_keypair(kid="auth0-e2e-key")
        cls.attacker_priv, cls.attacker_pub, cls.attacker_kid, _ = generate_test_keypair(kid="attacker-rogue-key")

        cls.domain = "dev-fj2vequ1z3jj2hbu.us.auth0.com"
        cls.issuer = f"https://{cls.domain}/"
        cls.audience = "https://agent-admission.example.com"

        cls.verifier = Auth0TokenVerifier(
            domain=cls.domain,
            issuer=cls.issuer,
            audience=cls.audience,
            local_public_keys={cls.kid: cls.pub_key},
            tenant_mapping={
                "org_demo": "tenant-demo",
                "org_acme": "tenant-acme",
            },
        )

        cls.adapter = AXAdmissionAdapter(auth0_verifier=cls.verifier)
        cls.gateway = ToolGatewayPEP(cerbos_client=cls.cerbos)
        cls.mcp_handler = MCPToolHandler(gateway=cls.gateway)

    def _create_token(
        self,
        sub: str = "auth0|user-123",
        permissions: list = None,
        audience: str = None,
        issuer: str = None,
        priv_key: any = None,
        kid: str = None,
        org_id: str = "org_demo",
        expires_in: int = 3600,
    ) -> str:
        perms = permissions if permissions is not None else ["agent:execute", "browser:read", "filesystem:read", "filesystem:write"]
        return create_test_auth0_token(
            private_key=priv_key or self.priv_key,
            sub=sub,
            kid=kid or self.kid,
            issuer=issuer or self.issuer,
            audience=audience or self.audience,
            permissions=perms,
            scope=" ".join(["openid", "profile"] + perms),
            org_id=org_id,
            expires_in=expires_in,
        )

    def _mock_ax_success(self):
        return [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="task created\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="Phase: Running\nWorker IP: 10.244.0.50\n", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="deleted\n", stderr=""),
        ]

    # -------------------------------------------------------------------------
    # Property 1: Valid token and authorized user -> Full execution permitted
    # -------------------------------------------------------------------------
    @mock.patch("subprocess.run")
    def test_01_valid_token_authorized_execution(self, mock_run):
        mock_run.side_effect = self._mock_ax_success()
        token = self._create_token()

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["cerbos_decision"], "ALLOW")
        self.assertEqual(trace["ax_decision"], "ACCEPTED")
        self.assertIn("actor:task-browser-agen", trace["substrate_workload"])
        self.assertEqual(trace["status"], "COMPLETED")
        self.assertIn("context_token", trace)

        # Now test that the minted context allows runtime tool invocation
        ctx_token = trace["context_token"]
        tool_res = self.gateway.invoke(ToolInvocationRequest(
            request_id="tool-req-01",
            task_context=ctx_token,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://localhost:8089"},
        ))
        self.assertTrue(tool_res.ok)
        self.assertEqual(tool_res.decision, "ALLOW")

    # -------------------------------------------------------------------------
    # Property 2: Invalid signature, wrong audience, and expired token
    # -------------------------------------------------------------------------
    def test_02_invalid_signature_rejected(self):
        # Signed with attacker's key but claims trusted kid
        token = self._create_token(priv_key=self.attacker_priv, kid=self.kid)

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("Auth0 token verification failed", trace["agent_result"])

    def test_03_wrong_audience_rejected(self):
        token = self._create_token(audience="https://unrelated-thirdparty-api.com")

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    def test_04_expired_token_rejected(self):
        token = self._create_token(expires_in=-120)

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    # -------------------------------------------------------------------------
    # Property 3: Forged subject and tenant tampering prevention
    # -------------------------------------------------------------------------
    def test_05_forged_subject_in_request_rejected(self):
        token = self._create_token(sub="auth0|alice")

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
            context={"delegated_by": "auth0|bob-spoofed"},
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("forged delegated_by", trace["agent_result"])

    def test_06_forged_tenant_in_request_rejected(self):
        token = self._create_token(org_id="org_demo")  # Maps to tenant-demo

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
            context={"tenant_id": "tenant-other-forged"},
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("forged tenant", trace["agent_result"])

    # -------------------------------------------------------------------------
    # Property 4: Cross-tenant access isolation
    # -------------------------------------------------------------------------
    def test_07_cross_tenant_access_rejected(self):
        # User belongs to tenant-acme, but orchestrator workload is tenant-demo
        token = self._create_token(org_id="org_acme")

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")
        self.assertIn("does not match Auth0 user tenant", trace["agent_result"])

    # -------------------------------------------------------------------------
    # Property 5: Restricted agent denied before AX and Substrate execution
    # -------------------------------------------------------------------------
    def test_08_restricted_agent_blocked_before_execution(self):
        token = self._create_token()

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="restricted-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["cerbos_decision"], "DENY")
        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    # -------------------------------------------------------------------------
    # Property 6: Missing / insufficient delegated permissions fail closed
    # -------------------------------------------------------------------------
    def test_09_missing_agent_execute_scope_denied(self):
        # User lacks agent:execute
        token = self._create_token(permissions=["browser:read"])

        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    def test_10_tool_gateway_scope_attenuation(self):
        # Admitted with browser:read only, attempts filesystem:write
        ctx = TaskExecutionContext(
            task_id="task-scope-test-01",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            delegated_by="auth0|user-limited",
            delegation_permissions=["browser:read"],  # No filesystem:write!
        ).sign()

        # 1. browser:read is allowed
        res_allowed = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-nav-01",
            task_context=ctx,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://localhost:8089"},
        ))
        self.assertTrue(res_allowed.ok)
        self.assertEqual(res_allowed.decision, "ALLOW")

        # 2. filesystem:write is denied with ZERO disk writes
        writes_before = self.gateway.filesystem_write_count
        res_denied = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-write-01",
            task_context=ctx,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": "./workspace/output/out.txt", "content": "malicious"},
        ))
        self.assertFalse(res_denied.ok)
        self.assertEqual(res_denied.decision, "DENY")
        self.assertEqual(self.gateway.filesystem_write_count, writes_before)

    # -------------------------------------------------------------------------
    # Property 7: Unauthorized browser, SSRF metadata, path traversal blocked
    # -------------------------------------------------------------------------
    def test_11_ssrf_cloud_metadata_blocked(self):
        ctx = TaskExecutionContext(
            task_id="task-ssrf-01",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            delegated_by="user-123",
        ).sign()

        net_calls_before = self.gateway.network_call_count
        res = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-ssrf",
            task_context=ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://169.254.169.254/latest/meta-data/"},
        ))
        self.assertFalse(res.ok)
        self.assertEqual(res.decision, "REJECTED_PEP")
        self.assertEqual(self.gateway.network_call_count, net_calls_before)

    def test_12_path_traversal_blocked(self):
        ctx = TaskExecutionContext(
            task_id="task-traversal-01",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            delegated_by="user-123",
        ).sign()

        writes_before = self.gateway.filesystem_write_count
        res = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-traversal",
            task_context=ctx,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": "../../etc/shadow", "content": "bad"},
        ))
        self.assertFalse(res.ok)
        self.assertEqual(res.decision, "REJECTED_PEP")
        self.assertEqual(self.gateway.filesystem_write_count, writes_before)

    # -------------------------------------------------------------------------
    # Property 8: Policy service unavailable fails closed
    # -------------------------------------------------------------------------
    def test_13_policy_service_unavailable_fails_closed(self):
        broken_cerbos = CerbosClient(base_url="http://localhost:59999")  # Unreachable port
        broken_adapter = AXAdmissionAdapter(cerbos_url="http://localhost:59999", auth0_verifier=self.verifier)
        token = self._create_token()

        trace = broken_adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            user_token=token,
        )

        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    # -------------------------------------------------------------------------
    # Property 9: MCP tool server routes and enforces policies identically
    # -------------------------------------------------------------------------
    def test_14_mcp_tool_handler_governance(self):
        tools = self.mcp_handler.list_tools()
        tool_names = [t["name"] for t in tools]
        self.assertIn("fetch_url", tool_names)
        self.assertIn("browser_navigate", tool_names)
        self.assertIn("filesystem_read", tool_names)
        self.assertIn("filesystem_write", tool_names)

        # Unauthenticated call rejected
        res_unauth = self.mcp_handler.call_tool("fetch_url", {"url": "http://localhost:8089"}, "")
        self.assertFalse(res_unauth.ok)
        self.assertEqual(res_unauth.code, "UNAUTHENTICATED")


if __name__ == "__main__":
    unittest.main()

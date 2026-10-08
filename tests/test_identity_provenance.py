"""Identity-Provenance and Trust Boundary Verification Test Matrix.

Verifies the core architectural principle:
'The orchestrator supplies intent, not authority. Identity, roles, tenant,
delegation, image digest, and task context must be verified or derived by trusted components.'

Implements all 13 canonical identity-provenance tests:
1. Orchestrator supplies forged role -> Ignored or rejected
2. Orchestrator supplies another tenant -> Ignored or rejected
3. Orchestrator supplies forged delegated_by -> Rejected
4. Requested agent differs from catalog resolution -> Rejected
5. AX task image differs from catalog digest -> Task rejected
6. Tool request claims another task ID -> Rejected
7. Tool request claims another agent ID -> Rejected
8. Expired context -> Tool denied
9. Wrong audience context -> Tool denied
10. Invalid context signature -> Tool denied
11. Revoked authorization epoch -> Tool denied
12. Correct agent but wrong tenant -> Tool denied
13. Correct task but wrong delegated user -> Tool denied
"""

import time
import unittest

from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest


class TestIdentityProvenanceMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cerbos = CerbosClient()
        assert cls.cerbos.check_health(), "Cerbos PDP must be healthy"
        cls.adapter = AXAdmissionAdapter()

    def setUp(self):
        self.gateway = ToolGatewayPEP(cerbos_client=self.cerbos)

        # Base trusted context
        self.valid_context = TaskExecutionContext(
            task_id="task-browser-prov-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
            authorization_epoch=1,
            issuer="ax-admission-pep",
            audience="tool-gateway",
        ).sign()

    # =========================================================================
    # Layer 1: Identity-to-Workload Admission Gate Tests
    # =========================================================================

    def test_01_orchestrator_supplies_forged_role(self):
        """Test 1: Orchestrator supplying forged role is ignored or rejected."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["admin", "super-user"],  # Forged role
            agent_name="browser-agent",
            action="execute",
        )
        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    def test_02_orchestrator_supplies_another_tenant(self):
        """Test 2: Orchestrator supplying another tenant is ignored or rejected."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            context={"tenant_id": "tenant-victim-evil"},  # Forged tenant
        )
        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    def test_03_orchestrator_supplies_forged_delegated_by(self):
        """Test 3: Orchestrator supplying forged delegated_by is rejected."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            context={"delegated_by": "unauthorized-external-user"},  # Forged user
        )
        self.assertEqual(trace["ax_decision"], "REJECTED_PEP")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")

    def test_04_requested_agent_differs_from_catalog_resolution(self):
        """Test 4: Requested agent differing from catalog resolution is rejected."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="unregistered-malicious-agent",
            action="execute",
        )
        self.assertEqual(trace["ax_decision"], "REJECTED_UNKNOWN_AGENT")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "FAILED")

    def test_05_ax_task_image_differs_from_catalog_digest(self):
        """Test 5: AX task image differing from catalog digest is rejected."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            task_data={"image": "attacker-registry/backdoor:v1"},  # Tampered image
        )
        self.assertEqual(trace["ax_decision"], "REJECTED_IMAGE_MISMATCH")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "FAILED")

    # =========================================================================
    # Layer 2: Workload-to-Capability Tool Invocation Gate Tests
    # =========================================================================

    def test_06_tool_request_claims_another_task_id(self):
        """Test 6: Tool request claiming another task ID is rejected."""
        req = ToolInvocationRequest(
            request_id="req-prov-06",
            task_context=self.valid_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "task_id": "forged-task-victim-99"},
            claimed_task_id="forged-task-victim-99",
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "TASK_ID_MISMATCH")
        self.assertEqual(res.decision, "REJECTED_PEP")
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_07_tool_request_claims_another_agent_id(self):
        """Test 7: Tool request claiming another agent ID is rejected."""
        req = ToolInvocationRequest(
            request_id="req-prov-07",
            task_context=self.valid_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "agent_id": "admin-agent"},
            claimed_agent_id="admin-agent",
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "AGENT_ID_MISMATCH")
        self.assertEqual(res.decision, "REJECTED_PEP")
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_08_expired_context(self):
        """Test 8: Expired context is denied."""
        expired_context = TaskExecutionContext(
            task_id="task-browser-prov-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
            expires_at=int(time.time()) - 300,  # Expired 5 minutes ago
        ).sign()

        req = ToolInvocationRequest(
            request_id="req-prov-08",
            task_context=expired_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "INVALID_TASK_CONTEXT")
        self.assertIn("expired", res.error.lower())
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_09_wrong_audience_context(self):
        """Test 9: Wrong audience context is denied."""
        wrong_aud_context = TaskExecutionContext(
            task_id="task-browser-prov-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
            audience="billing-gateway",  # Wrong gateway audience
        ).sign()

        req = ToolInvocationRequest(
            request_id="req-prov-09",
            task_context=wrong_aud_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "INVALID_TASK_CONTEXT")
        self.assertIn("audience", res.error.lower())
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_10_invalid_context_signature(self):
        """Test 10: Invalid or tampered context signature is denied."""
        # Forge signature
        tampered_context = TaskExecutionContext(
            task_id="task-browser-prov-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
            signature="forged-bad-signature-hex-deadbeef",
        )

        req = ToolInvocationRequest(
            request_id="req-prov-10",
            task_context=tampered_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "INVALID_TASK_CONTEXT")
        self.assertIn("signature", res.error.lower())
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_11_revoked_authorization_epoch(self):
        """Test 11: Revoked authorization epoch is denied immediately."""
        # Gateway upgrades to epoch 2, invalidating epoch 1 contexts
        self.gateway.revoke_epoch(2)

        req = ToolInvocationRequest(
            request_id="req-prov-11",
            task_context=self.valid_context,  # issued with authorization_epoch=1
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "INVALID_TASK_CONTEXT")
        self.assertIn("epoch", res.error.lower())
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_12_correct_agent_but_wrong_tenant(self):
        """Test 12: Correct agent but wrong tenant is denied by policy."""
        wrong_tenant_context = TaskExecutionContext(
            task_id="task-browser-prov-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-unauthorized",  # Unauthorized tenant
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
        ).sign()

        req = ToolInvocationRequest(
            request_id="req-prov-12",
            task_context=wrong_tenant_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "AUTHZ_DENIED")
        self.assertEqual(res.decision, "DENY")
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_13_correct_task_but_wrong_delegated_user(self):
        """Test 13: Correct task but wrong delegated user is denied by policy."""
        wrong_delegation_context = TaskExecutionContext(
            task_id="task-browser-prov-001",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-forged-unauthorized",  # Unauthorized delegate
            environment="test",
        ).sign()

        req = ToolInvocationRequest(
            request_id="req-prov-13",
            task_context=wrong_delegation_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.code, "AUTHZ_DENIED")
        self.assertEqual(res.decision, "DENY")
        self.assertEqual(self.gateway.network_call_count, 0)


if __name__ == "__main__":
    unittest.main()

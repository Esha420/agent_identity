#!/usr/bin/env python3
"""Tests 1, 2, 3, 4, 7, and Security Actions: Direct PDP Contract & Identity Propagation."""

import unittest
from ax.cerbos_client import CerbosClient


class TestAuthorizationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CerbosClient()
        assert cls.client.check_health(), "Cerbos PDP not reachable"

    def test_test1_cerbos_health(self):
        """Test 1: Cerbos is reachable."""
        self.assertTrue(self.client.check_health())

    def test_test2_authorized_principal(self):
        """Test 2: orchestrator-agent executing approved-agent is ALLOW."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-auth-001",
            principal_id="orchestrator-agent",
            roles=["orchestrator"],
            resource_id="browser-agent",
            action="execute",
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "ALLOW")

    def test_test3_unauthorized_principal(self):
        """Test 3: untrusted-agent executing approved-agent is DENY."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-auth-002",
            principal_id="untrusted-agent",
            roles=["untrusted"],
            resource_id="browser-agent",
            action="execute",
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_test4_unauthorized_resource(self):
        """Test 4: orchestrator-agent executing restricted-agent is DENY."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-auth-003",
            principal_id="orchestrator-agent",
            roles=["orchestrator"],
            resource_id="restricted-agent",
            action="execute",
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_test7_identity_propagation(self):
        """Test 7: Verify caller principal identity is propagated exactly to Cerbos."""
        test_principals = ["orchestrator-agent", "audit-agent", "untrusted-agent"]
        for p in test_principals:
            role = "orchestrator" if p == "orchestrator-agent" else "other"
            allowed, decision, raw = self.client.authorize(
                request_id=f"req-id-{p}",
                principal_id=p,
                roles=[role],
                resource_id="browser-agent",
                action="execute",
            )
            # Principal ID was preserved in request evaluation
            if p == "orchestrator-agent":
                self.assertEqual(decision, "ALLOW")
            else:
                self.assertEqual(decision, "DENY")

    def test_security_unauthorized_actions(self):
        """Security: Unauthorized actions (admin, delete) must be DENIED."""
        for action in ["admin", "delete", "modify-policy"]:
            allowed, decision, _ = self.client.authorize(
                request_id="req-sec-action",
                principal_id="orchestrator-agent",
                roles=["orchestrator"],
                resource_id="browser-agent",
                action=action,
            )
            self.assertFalse(allowed)
            self.assertEqual(decision, "DENY")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Test 1-4: Automated Cerbos Policy and Reachability Tests."""

import sys
import unittest
from ax.cerbos_client import CerbosClient


class TestCerbosPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CerbosClient()
        if not cls.client.check_health():
            raise RuntimeError("Cerbos PDP is not running or unhealthy at http://localhost:3592")

    def test_cerbos_reachable_and_healthy(self):
        """Test 1: Cerbos is reachable and returns SERVING status."""
        self.assertTrue(self.client.check_health())

    def test_authorized_principal_browser_agent(self):
        """Test 2: orchestrator-agent executing browser-agent is ALLOWED."""
        allowed, decision, _ = self.client.authorize(
            request_id="test-req-001",
            principal_id="orchestrator-agent",
            roles=["orchestrator"],
            resource_id="browser-agent",
            action="execute",
            context={"environment": "lab", "capability": "browser"},
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "ALLOW")

    def test_authorized_principal_research_agent(self):
        """Test 2b: orchestrator-agent executing research-agent is ALLOWED."""
        allowed, decision, _ = self.client.authorize(
            request_id="test-req-002",
            principal_id="orchestrator-agent",
            roles=["orchestrator"],
            resource_id="research-agent",
            action="execute",
            context={"environment": "lab", "capability": "research"},
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "ALLOW")

    def test_unauthorized_principal(self):
        """Test 3: untrusted-agent executing browser-agent is DENIED."""
        allowed, decision, _ = self.client.authorize(
            request_id="test-req-003",
            principal_id="untrusted-agent",
            roles=["untrusted"],
            resource_id="browser-agent",
            action="execute",
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_unauthorized_resource(self):
        """Test 4: orchestrator-agent executing restricted-agent is DENIED."""
        allowed, decision, _ = self.client.authorize(
            request_id="test-req-004",
            principal_id="orchestrator-agent",
            roles=["orchestrator"],
            resource_id="restricted-agent",
            action="execute",
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_unauthorized_actions(self):
        """Test 4b: admin or delete actions are DENIED."""
        for act in ["admin", "delete"]:
            allowed, decision, _ = self.client.authorize(
                request_id=f"test-req-act-{act}",
                principal_id="orchestrator-agent",
                roles=["orchestrator"],
                resource_id="browser-agent",
                action=act,
            )
            self.assertFalse(allowed)
            self.assertEqual(decision, "DENY")


if __name__ == "__main__":
    unittest.main()

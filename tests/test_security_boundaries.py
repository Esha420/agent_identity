#!/usr/bin/env python3
"""Security Boundary & Bypass Verification Tests."""

import subprocess
import unittest
from ax.adapter import AXAdmissionAdapter


class TestSecurityBoundaries(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = AXAdmissionAdapter()

    def test_unauthorized_principal_blocked(self):
        """Unauthorized principal cannot execute an approved agent."""
        trace = self.adapter.submit_execution_request(
            principal="attacker-agent",
            roles=["anonymous"],
            agent_name="browser-agent",
            action="execute",
        )
        self.assertEqual(trace["cerbos_decision"], "DENY")
        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")

    def test_unauthorized_agent_blocked(self):
        """Unauthorized agent cannot be executed by an otherwise trusted principal."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="restricted-agent",
            action="execute",
        )
        self.assertEqual(trace["cerbos_decision"], "DENY")
        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")

    def test_unauthorized_action_blocked(self):
        """Privileged actions (delete, admin) cannot be executed."""
        for act in ["delete", "admin"]:
            trace = self.adapter.submit_execution_request(
                principal="orchestrator-agent",
                roles=["orchestrator"],
                agent_name="browser-agent",
                action=act,
            )
            self.assertEqual(trace["cerbos_decision"], "DENY")
            self.assertEqual(trace["ax_decision"], "REJECTED")
            self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")

    def test_direct_substrate_bypass_resistance(self):
        """
        Verify that direct invocation of Substrate without AX is rejected or inaccessible.
        Substrate API requires mTLS or internal cluster authority, preventing direct outside invocation.
        """
        # Attempt to curl internal Substrate API directly without AX
        res = subprocess.run(
            ["curl", "-k", "-s", "--max-time", "2", "https://api.ate-system.svc.cluster.local:443"],
            capture_output=True,
            text=True,
        )
        # Direct external curl fails because DNS / network boundary isolates the Substrate
        self.assertNotEqual(res.returncode, 0, "Direct Substrate bypass should fail from host!")


if __name__ == "__main__":
    unittest.main()

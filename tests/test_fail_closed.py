#!/usr/bin/env python3
"""Fail-Closed Security Verification: Cerbos Unreachable -> Execution Blocked -> Zero Workloads."""

import subprocess
import unittest
from ax.adapter import AXAdmissionAdapter


class TestFailClosedSecurity(unittest.TestCase):
    def test_fail_closed_when_cerbos_unreachable(self):
        """Verify that when Cerbos PDP is unavailable, the adapter fails closed."""
        # Point adapter to an invalid / unreachable PDP endpoint
        offline_adapter = AXAdmissionAdapter(cerbos_url="http://localhost:59999")

        # Capture active tasks in AX before request
        tasks_before = subprocess.run([offline_adapter.ax_bin, "get", "tasks"], capture_output=True, text=True).stdout

        # Attempt to run an otherwise approved agent with orchestrator identity
        trace = offline_adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
        )

        tasks_after = subprocess.run([offline_adapter.ax_bin, "get", "tasks"], capture_output=True, text=True).stdout

        self.assertEqual(trace["cerbos_decision"], "ERROR_FAIL_CLOSED")
        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")
        self.assertEqual(tasks_after, tasks_before, "A task was materialized despite Cerbos failure!")


if __name__ == "__main__":
    unittest.main()

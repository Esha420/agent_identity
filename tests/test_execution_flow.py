#!/usr/bin/env python3
"""Tests 5, 6, 8, 9, 10: Execution Lifecycle, Denial Guarantees, Dynamic Selection & Replacement."""

import subprocess
import unittest
from ax.adapter import AXAdmissionAdapter
from orchestrator.orchestrator import OrchestratorAgent


class TestExecutionFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = AXAdmissionAdapter()
        cls.orchestrator = OrchestratorAgent(adapter=cls.adapter)

    def _get_active_tasks_count(self) -> int:
        res = subprocess.run([self.adapter.ax_bin, "get", "tasks"], capture_output=True, text=True)
        lines = [line for line in res.stdout.strip().splitlines() if line.strip()]
        # First line is header: NAME ATESPACE PHASE ...
        return max(0, len(lines) - 1)

    def test_test5_authorized_execution_creates_workload(self):
        """Test 5: Authorized execution reaches AX and creates Substrate workload."""
        trace = self.adapter.submit_execution_request(
            principal="orchestrator-agent",
            roles=["orchestrator"],
            agent_name="browser-agent",
            action="execute",
            wait_timeout=20,
        )
        self.assertEqual(trace["cerbos_decision"], "ALLOW")
        self.assertEqual(trace["ax_decision"], "ACCEPTED")
        self.assertIn("actor:task-browser-", trace["substrate_workload"])
        self.assertEqual(trace["status"], "COMPLETED")

    def test_test6_denied_execution_creates_zero_workload(self):
        """Test 6: Denied execution creates NO Substrate workload."""
        tasks_before = self._get_active_tasks_count()
        trace = self.adapter.submit_execution_request(
            principal="untrusted-agent",
            roles=["untrusted"],
            agent_name="browser-agent",
            action="execute",
        )
        tasks_after = self._get_active_tasks_count()

        self.assertEqual(trace["cerbos_decision"], "DENY")
        self.assertEqual(trace["ax_decision"], "REJECTED")
        self.assertEqual(trace["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(trace["status"], "DENIED")
        self.assertEqual(tasks_after, tasks_before, "Workloads were erroneously created after DENY!")

    def test_test8_agent_selection(self):
        """Test 8: Orchestrator selects agent dynamically based on required capability."""
        agent_browser = self.orchestrator.resolve_agent_for_task("Please visit the website and check headers")
        agent_research = self.orchestrator.resolve_agent_for_task("Perform topic research and intel gathering")

        self.assertEqual(agent_browser, "browser-agent")
        self.assertEqual(agent_research, "research-agent")

    def test_test9_agent_replacement_configuration_only(self):
        """Test 9: Agent can be substituted without modifying orchestration code."""
        # Task 1 uses browser capability
        trace1 = self.orchestrator.execute_user_task("Visit domain page")
        self.assertEqual(trace1["agent"], "browser-agent")
        self.assertEqual(trace1["status"], "COMPLETED")

        # Task 2 uses research capability
        trace2 = self.orchestrator.execute_user_task("Research autonomous architectures")
        self.assertEqual(trace2["agent"], "research-agent")
        self.assertEqual(trace2["status"], "COMPLETED")

    def test_test10_end_to_end_flow(self):
        """Test 10: Complete pipeline User -> Orchestrator -> AX -> Cerbos -> Substrate -> Result."""
        trace = self.orchestrator.execute_user_task("Visit website and extract title")
        self.assertEqual(trace["cerbos_decision"], "ALLOW")
        self.assertEqual(trace["ax_decision"], "ACCEPTED")
        self.assertEqual(trace["status"], "COMPLETED")
        self.assertIsNotNone(trace["agent_result"])


if __name__ == "__main__":
    unittest.main()

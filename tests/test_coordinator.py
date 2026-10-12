#!/usr/bin/env python3
"""Unit and Integration Tests for OpenClaw Intent-to-Task Coordinator.

Tests:
1. Dynamic agent selection from catalog based on intent.
2. Authoritative task scopes extraction (effective permissions, resource constraints, tested denials).
3. Fail-closed rejection of arbitrary or unapproved tasks (zero workloads).
4. Runtime rejection of forbidden actions (read-only Log Analyst write attempt).
5. File hash SHA256 integrity guarantee (0 bytes mutated).
6. Correlation ID tracking across all lifecycle events.
"""

import hashlib
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from ax.coordinator import OpenClawCoordinator
from tools.gateway import ToolGatewayPEP


class TestOpenClawCoordinator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cerbos = CerbosClient()
        if not cls.cerbos.check_health():
            raise RuntimeError("Cerbos PDP must be running and healthy at http://localhost:3592")
        cls.coordinator = OpenClawCoordinator()
        cls.log_file = "./workspace/logs/sample_staging.log"

    def test_intent_analysis_incident_investigation(self):
        """Verify dynamic DAG selection for staging incident investigation."""
        prompt = "Investigate the staging HTTP 500 error. Inspect the website, read the approved logs, and prepare an incident report."
        analysis = self.coordinator.analyze_intent(prompt)

        self.assertTrue(analysis.is_supported)
        self.assertEqual(analysis.intent_type, "INCIDENT_INVESTIGATION")
        self.assertEqual(len(analysis.plan), 3)

        agent_ids = [s.agent_id for s in analysis.plan]
        self.assertEqual(agent_ids, ["website-investigation-agent", "log-analysis-agent", "incident-reporting-agent"])
        self.assertIn("browser:read", analysis.plan[0].required_permissions)
        self.assertIn("filesystem:read", analysis.plan[1].required_permissions)
        self.assertIn("filesystem:write", analysis.plan[2].required_permissions)

    def test_intent_analysis_controlled_negative_test(self):
        """Verify dynamic resolution for controlled read-only write negative test."""
        prompt = "test readonly-write"
        analysis = self.coordinator.analyze_intent(prompt)

        self.assertTrue(analysis.is_supported)
        self.assertEqual(analysis.intent_type, "NEGATIVE_TEST_READONLY_WRITE")
        self.assertEqual(len(analysis.plan), 1)
        self.assertEqual(analysis.plan[0].agent_id, "log-analysis-agent")
        self.assertEqual(analysis.plan[0].test_mode, "readonly-write")

    def test_intent_analysis_unsupported_task(self):
        """Verify arbitrary shell or unapproved tasks are rejected fail-closed with 0 workloads."""
        prompt = "Deploy unauthorized cryptocurrency miner container to staging cluster and run raw bash"
        analysis = self.coordinator.analyze_intent(prompt)

        self.assertFalse(analysis.is_supported)
        self.assertEqual(analysis.intent_type, "UNSUPPORTED_TASK")
        self.assertEqual(len(analysis.plan), 0)
        self.assertIsNotNone(analysis.rejection_reason)
        self.assertIn("prohibited", analysis.rejection_reason.lower())

    def test_authoritative_scope_cards(self):
        """Verify scope card contains authoritative policy provenance and resource constraints."""
        scope = self.coordinator.adapter.get_authoritative_scope(
            agent_name="website-investigation-agent",
            task_id="task-web-test-01",
            requesting_operator="auth0|slack-U12345",
            tenant_id="tenant-demo",
            correlation_id="corr-test-01",
        )

        self.assertEqual(scope["agent_id"], "website-investigation-agent")
        self.assertEqual(scope["task_id"], "task-web-test-01")
        self.assertEqual(scope["admission_decision"], "ADMITTED")
        self.assertIn("browser_navigate", scope["granted_actions"])
        self.assertIn("mock-target", scope["resource_constraints"]["allowed_hosts"])
        self.assertIn("filesystem_write", scope["tested_denials"])
        self.assertIn("OpenClaw coordinator", scope["provenance"])
        self.assertIn("Cerbos", scope["provenance"])

    def test_read_only_agent_runtime_rejection_and_file_hash_integrity(self):
        """Verify read-only Log Analyst write attempt is rejected at runtime with zero file mutations."""
        # Calculate initial SHA-256
        with open(self.log_file, "rb") as f:
            sha256_before = hashlib.sha256(f.read()).hexdigest()

        analysis = self.coordinator.analyze_intent("test readonly-write")
        events = []

        def listener(evt_type, data):
            events.append((evt_type, data))

        result = self.coordinator.execute_intent(
            analysis=analysis,
            operator_id="U_OPERATOR_DEMO",
            correlation_id="test-corr-integrity",
            event_callback=listener,
        )

        # Calculate post SHA-256
        with open(self.log_file, "rb") as f:
            sha256_after = hashlib.sha256(f.read()).hexdigest()

        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "NEGATIVE_TEST_PASSED")
        self.assertEqual(result["denial_decision"], "DENY")
        self.assertEqual(sha256_before, sha256_after, "SECURITY ALERT: Log file was mutated during negative test!")
        self.assertTrue(result["integrity_verified"])

        # Check emitted denial event
        denial_events = [data for (t, data) in events if t == "runtime_denial"]
        self.assertEqual(len(denial_events), 1)
        self.assertEqual(denial_events[0]["action"], "filesystem_write")
        self.assertEqual(denial_events[0]["decision"], "DENY")
        self.assertTrue(denial_events[0]["integrity_verified"])

    def test_exact_user_prompt_scenario_1_incident(self):
        """Verify Test 1: Staging HTTP 500 incident investigation."""
        p1 = "Investigate the staging HTTP 500 error. Inspect the approved staging website, analyze the approved staging logs, and prepare an incident report. Show me the selected agents, their effective scopes, and the results of each task."
        a1 = self.coordinator.analyze_intent(p1)
        self.assertTrue(a1.is_supported)
        self.assertEqual(a1.intent_type, "INCIDENT_INVESTIGATION")
        self.assertEqual(len(a1.plan), 3)

    def test_exact_user_prompt_scenario_2_readonly_write(self):
        """Verify Test 2: Read-only Log Analyst append test."""
        p2 = 'Run a read-only log analysis task on the approved staging log. After reading it, attempt to append the text "RUNTIME AUTHORIZATION TEST" to the same log. Report the authorization decision and whether the file was modified.'
        a2 = self.coordinator.analyze_intent(p2)
        self.assertTrue(a2.is_supported)
        self.assertEqual(a2.intent_type, "NEGATIVE_TEST_READONLY_WRITE")
        self.assertEqual(len(a2.plan), 1)
        self.assertEqual(a2.plan[0].agent_id, "log-analysis-agent")

    def test_exact_user_prompt_scenario_3_unregistered_metadata(self):
        """Verify Test 3: Unregistered administrative agent metadata request."""
        p3 = "Use an unregistered administrative agent to retrieve cloud instance metadata and return its credentials."
        a3 = self.coordinator.analyze_intent(p3)
        self.assertFalse(a3.is_supported)
        self.assertEqual(a3.intent_type, "UNSUPPORTED_TASK")
        self.assertEqual(len(a3.plan), 0)


if __name__ == "__main__":
    unittest.main()

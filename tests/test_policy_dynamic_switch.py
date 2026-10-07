#!/usr/bin/env python3
"""Tests 11 & 12: Dynamic Policy Modification and Restoration proving policy-driven authorization."""

import os
import shutil
import subprocess
import time
import unittest
from ax.adapter import AXAdmissionAdapter
from orchestrator.orchestrator import OrchestratorAgent

POLICY_PATH = os.path.join(os.path.dirname(__file__), "../cerbos/policies/agent_execution.yaml")
BACKUP_POLICY_PATH = os.path.join(os.path.dirname(__file__), "../cerbos/policies/agent_execution.yaml.bak")

# Restricted policy where browser-agent is explicitly DENIED while research-agent remains ALLOWED
REVOKED_BROWSER_POLICY = """---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: "default"
  resource: "agent"
  rules:
    - actions: ["execute"]
      effect: EFFECT_ALLOW
      roles:
        - orchestrator
      condition:
        match:
          expr: request.resource.id in ["research-agent"]

    - actions: ["execute"]
      effect: EFFECT_DENY
      roles:
        - orchestrator
      condition:
        match:
          expr: request.resource.id in ["browser-agent", "restricted-agent"]

    - actions: ["admin", "delete"]
      effect: EFFECT_DENY
      roles: ["*"]
"""


class TestPolicyDynamicSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = AXAdmissionAdapter()
        cls.orchestrator = OrchestratorAgent(adapter=cls.adapter)
        # Backup original policy
        shutil.copyfile(POLICY_PATH, BACKUP_POLICY_PATH)

    @classmethod
    def tearDownClass(cls):
        # Restore backup policy on cleanup
        if os.path.exists(BACKUP_POLICY_PATH):
            shutil.copyfile(BACKUP_POLICY_PATH, POLICY_PATH)
            os.remove(BACKUP_POLICY_PATH)
            subprocess.run(["docker", "compose", "restart", "cerbos"], capture_output=True, check=False)
            time.sleep(1.0)

    def test_test11_and_test12_policy_switch_and_restoration(self):
        """Test 11 & 12: Revoke browser-agent permission via policy, test denial, then restore."""
        # 1. Baseline: browser-agent is allowed
        t0 = self.orchestrator.execute_user_task("Visit website", target_agent="browser-agent")
        self.assertEqual(t0["cerbos_decision"], "ALLOW")
        self.assertEqual(t0["status"], "COMPLETED")

        # Apply dynamic policy modification (revoke browser-agent)
        print("\n[POLICY UPDATE] Dynamically modifying Cerbos policy: revoking browser-agent...")
        with open(POLICY_PATH, "w") as f:
            f.write(REVOKED_BROWSER_POLICY)

        # Reload Cerbos container
        subprocess.run(["docker", "compose", "restart", "cerbos"], capture_output=True, check=True)
        time.sleep(1.0)

        # 3. Test 11 Verification: browser-agent is now DENIED with ZERO workloads
        t1 = self.orchestrator.execute_user_task("Visit website", target_agent="browser-agent")
        self.assertEqual(t1["cerbos_decision"], "DENY")
        self.assertEqual(t1["ax_decision"], "REJECTED")
        self.assertEqual(t1["substrate_workload"], "NO WORKLOAD CREATED")
        self.assertEqual(t1["status"], "DENIED")

        # 4. In the same modified policy, research-agent remains ALLOWED
        t2 = self.orchestrator.execute_user_task("Research topic", target_agent="research-agent")
        self.assertEqual(t2["cerbos_decision"], "ALLOW")
        self.assertEqual(t2["status"], "COMPLETED")

        # Test 12: Policy restoration
        print("\n[POLICY RESTORATION] Restoring original Cerbos policy...")
        shutil.copyfile(BACKUP_POLICY_PATH, POLICY_PATH)
        subprocess.run(["docker", "compose", "restart", "cerbos"], capture_output=True, check=True)
        time.sleep(1.0)

        # 6. Test 12 Verification: browser-agent works again
        t3 = self.orchestrator.execute_user_task("Visit website", target_agent="browser-agent")
        self.assertEqual(t3["cerbos_decision"], "ALLOW")
        self.assertEqual(t3["ax_decision"], "ACCEPTED")
        self.assertEqual(t3["status"], "COMPLETED")


if __name__ == "__main__":
    unittest.main()

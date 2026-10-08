"""Test Per-Invocation Dynamic Policy Revocation for Running Workloads."""

import os
import shutil
import subprocess
import time
import unittest

from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest

TOOL_POLICY_PATH = os.path.join(os.path.dirname(__file__), "../cerbos/policies/tool_execution.yaml")
BACKUP_TOOL_POLICY_PATH = os.path.join(os.path.dirname(__file__), "../cerbos/policies/tool_execution.yaml.bak")

REVOKED_TOOL_POLICY = """---
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: "default"
  resource: "tool"
  rules:
    # fetch_url explicitly revoked for all roles
    - actions: ["navigate", "read", "write"]
      effect: EFFECT_ALLOW
      roles:
        - browser-worker
      condition:
        match:
          all:
            of:
              - expr: request.resource.attr.task_id == request.principal.attr.task_id
"""


class TestToolPolicyDynamicSwitch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CerbosClient()
        assert cls.client.check_health(), "Cerbos PDP not reachable"
        shutil.copyfile(TOOL_POLICY_PATH, BACKUP_TOOL_POLICY_PATH)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(BACKUP_TOOL_POLICY_PATH):
            shutil.copyfile(BACKUP_TOOL_POLICY_PATH, TOOL_POLICY_PATH)
            os.remove(BACKUP_TOOL_POLICY_PATH)
            subprocess.run(["docker", "compose", "restart", "cerbos"], capture_output=True, check=False)
            time.sleep(1.0)

    def test_per_invocation_revocation_on_active_task(self):
        """Proves that policy revocation immediately blocks subsequent calls on active workloads."""
        gateway = ToolGatewayPEP(cerbos_client=self.client)
        active_ctx = TaskExecutionContext(
            task_id="task-running-long-lived-01",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
        ).sign()

        # 1. Baseline: fetch_url is permitted for running task
        req1 = ToolInvocationRequest(
            request_id="req-call-01",
            task_context=active_ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res1 = gateway.invoke(req1)
        self.assertTrue(res1.ok)
        self.assertEqual(res1.decision, "ALLOW")

        # 2. Dynamic Policy Modification: Revoke fetch_url
        print("\n[TOOL POLICY UPDATE] Dynamically revoking fetch_url permission...")
        with open(TOOL_POLICY_PATH, "w") as f:
            f.write(REVOKED_TOOL_POLICY)

        subprocess.run(["docker", "compose", "restart", "cerbos"], capture_output=True, check=True)
        time.sleep(1.0)

        # 3. Invocation 2: Same active task now immediately blocked!
        req2 = ToolInvocationRequest(
            request_id="req-call-02",
            task_context=active_ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res2 = gateway.invoke(req2)
        self.assertFalse(res2.ok)
        self.assertEqual(res2.decision, "DENY")
        self.assertEqual(res2.code, "AUTHZ_DENIED")

        # 4. Policy Restoration
        print("\n[TOOL POLICY RESTORATION] Restoring original tool policy...")
        shutil.copyfile(BACKUP_TOOL_POLICY_PATH, TOOL_POLICY_PATH)
        subprocess.run(["docker", "compose", "restart", "cerbos"], capture_output=True, check=True)
        time.sleep(1.0)

        # 5. Invocation 3: Restored policy immediately re-authorizes active task
        req3 = ToolInvocationRequest(
            request_id="req-call-03",
            task_context=active_ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res3 = gateway.invoke(req3)
        self.assertTrue(res3.ok)
        self.assertEqual(res3.decision, "ALLOW")


if __name__ == "__main__":
    unittest.main()

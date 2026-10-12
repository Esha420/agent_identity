"""Tests for Workload Resilience, Lifecycle, Retries, Suspension, and Cryptographic Revocation."""

import time
import unittest
from unittest.mock import MagicMock

from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest, ToolInvocationResponse
from tools.security import SecurityValidationError


def execute_with_retry(invoke_fn, max_retries: int = 3, base_delay: float = 0.01):
    """Resilient invocation wrapper with exponential backoff on transient errors."""
    attempts = 0
    while True:
        attempts += 1
        res = invoke_fn()
        # If response is ok or has permanent authorization denial, return immediately
        if res.ok or res.decision in ["DENY", "REJECTED_PEP"]:
            return res, attempts
        if attempts >= max_retries:
            return res, attempts
        time.sleep(base_delay * (2 ** (attempts - 1)))


class TestWorkloadResilienceAndLifecycle(unittest.TestCase):
    def setUp(self):
        self.cerbos = CerbosClient()
        self.gateway = ToolGatewayPEP(cerbos_client=self.cerbos, active_epoch=1)
        self.human_user = "auth0|operator-resilience"
        self.tenant = "tenant-demo"
        self.ctx = TaskExecutionContext(
            task_id="task-resilience-001",
            correlation_id="inc-resilience-corr-1",
            agent_id="website-investigation-agent",
            roles=["browser-worker"],
            tenant_id=self.tenant,
            environment="staging",
            delegated_by=self.human_user,
            delegation_permissions=["browser:read", "filesystem:read", "filesystem:write"],
            authorization_epoch=1,
        )
        self.ctx_token = self.ctx.sign().to_token()

    def test_workload_captures_http_500_diagnostic_gracefully(self):
        """Verify that target failure (HTTP 500) is captured as diagnostic data without crashing."""
        req = ToolInvocationRequest(
            request_id="req-resil-500",
            correlation_id="inc-resilience-corr-1",
            task_context=self.ctx_token,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://mock-target:8089/staging-error"},
        )
        res = self.gateway.invoke(req)
        self.assertTrue(res.ok)
        self.assertEqual(res.data.get("status_code"), 500)
        self.assertIn("Database Connection Pool Exhausted", res.data.get("h1", ""))

    def test_transient_failure_retry_backoff_success(self):
        """Verify retry logic succeeds after transient failures."""
        call_count = 0

        def flaky_tool_call():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                # Simulate transient error (e.g. gateway timeout)
                return ToolInvocationResponse(
                    ok=False,
                    code="TRANSIENT_NETWORK_TIMEOUT",
                    request_id="req-retry",
                    tool="browser_navigate",
                    decision="ERROR_FAIL_CLOSED",
                    side_effect="none",
                    error="Temporary connection reset",
                )
            # Succeeded on 3rd attempt
            return self.gateway.invoke(ToolInvocationRequest(
                request_id="req-retry-success",
                correlation_id="inc-resilience-corr-1",
                task_context=self.ctx_token,
                tool_name="browser_navigate",
                action="navigate",
                arguments={"url": "http://mock-target:8089/staging-error"},
            ))

        res, attempts = execute_with_retry(flaky_tool_call, max_retries=3, base_delay=0.01)
        self.assertEqual(attempts, 3)
        self.assertTrue(res.ok)
        self.assertEqual(res.data.get("status_code"), 500)

    def test_permanent_denial_does_not_waste_retries(self):
        """Verify that security policy denials (DENY) are not retried endlessly."""
        denied_req = ToolInvocationRequest(
            request_id="req-no-retry-deny",
            correlation_id="inc-resilience-corr-1",
            task_context=self.ctx_token,
            tool_name="filesystem_write",  # website-investigation-agent cannot write
            action="write",
            arguments={"path": "./workspace/output/hack.sh", "content": "echo pwned"},
        )
        res, attempts = execute_with_retry(lambda: self.gateway.invoke(denied_req), max_retries=5)
        self.assertEqual(attempts, 1)
        self.assertFalse(res.ok)
        self.assertEqual(res.decision, "DENY")

    def test_immediate_task_revocation(self):
        """Verify explicit revocation of a task ID halts all further execution with zero side-effects."""
        req = ToolInvocationRequest(
            request_id="req-revoked-task",
            correlation_id="inc-resilience-corr-1",
            task_context=self.ctx_token,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://mock-target:8089/staging-error"},
        )
        # Pre-check: before revocation, request succeeds
        res_before = self.gateway.invoke(req)
        self.assertTrue(res_before.ok)

        # Immediate Task Revocation
        self.gateway.revoke_task("task-resilience-001")

        # Post-check: request immediately rejected
        res_after = self.gateway.invoke(req)
        self.assertFalse(res_after.ok)
        self.assertEqual(res_after.decision, "REJECTED_PEP")
        self.assertEqual(res_after.code, "INVALID_TASK_CONTEXT")
        self.assertIn("has been revoked", res_after.error)

    def test_epoch_revocation_invalidates_prior_contexts(self):
        """Verify rotating the authorization epoch invalidates all leases issued under prior epochs."""
        req = ToolInvocationRequest(
            request_id="req-revoked-epoch",
            correlation_id="inc-resilience-corr-1",
            task_context=self.ctx_token,  # Issued under epoch 1
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://mock-target:8089/staging-error"},
        )
        # Rotate epoch to 2
        self.gateway.revoke_epoch(2)

        res = self.gateway.invoke(req)
        self.assertFalse(res.ok)
        self.assertEqual(res.decision, "REJECTED_PEP")
        self.assertEqual(res.code, "INVALID_TASK_CONTEXT")
        self.assertIn("Task authorization epoch 1 is revoked", res.error)


if __name__ == "__main__":
    unittest.main()

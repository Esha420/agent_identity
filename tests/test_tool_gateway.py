"""Integration and Adversarial Security Verification Tests for ToolGatewayPEP."""

import json
import os
import shutil
import tempfile
import time
import unittest

from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest


class TestToolGatewayPEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CerbosClient()
        assert cls.client.check_health(), "Cerbos PDP not reachable"
        cls.test_dir = tempfile.mkdtemp(prefix="agent_sec_test_")
        cls.workspace_input = os.path.join(cls.test_dir, "workspace", "input")
        cls.workspace_output = os.path.join(cls.test_dir, "workspace", "output")
        os.makedirs(cls.workspace_input, exist_ok=True)
        os.makedirs(cls.workspace_output, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def setUp(self):
        self.gateway = ToolGatewayPEP(cerbos_client=self.client)
        # Create standard task execution context for tests
        self.ctx = TaskExecutionContext(
            task_id="task-browser-integration-01",
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
        ).sign()

    def test_test1_allowed_fetch_url(self):
        """Test 1: Governed HTTP GET against approved mock-target succeeds."""
        req = ToolInvocationRequest(
            request_id="req-fetch-01",
            task_context=self.ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res = self.gateway.invoke(req)

        self.assertTrue(res.ok)
        self.assertEqual(res.decision, "ALLOW")
        self.assertEqual(res.code, "SUCCESS")
        self.assertEqual(res.side_effect, "read")
        self.assertEqual(self.gateway.network_call_count, 1)
        self.assertIn("Example Domain", res.data["content"])

    def test_test2_zero_side_effect_on_denied_host(self):
        """Test 2: Requesting unauthorized host is blocked with zero outbound calls."""
        req = ToolInvocationRequest(
            request_id="req-fetch-02",
            task_context=self.ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://evil-attacker.com:8089", "method": "GET"},
        )
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(self.gateway.network_call_count, 0, "Network call made for denied host!")
        self.assertEqual(res.side_effect, "none")
        self.assertIn("INVALID_ARGUMENTS", res.code)

    def test_test3_zero_side_effect_on_denied_method(self):
        """Test 3: Requesting POST method on read-only fetch_url is blocked with 0 network calls."""
        req = ToolInvocationRequest(
            request_id="req-fetch-03",
            task_context=self.ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "POST"},
        )
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(self.gateway.network_call_count, 0, "Network call made for forbidden method!")
        self.assertEqual(res.side_effect, "none")

    def test_test4_ssrf_userinfo_rejected(self):
        """Test 4: URL containing userinfo credentials (user:pass@host) is rejected."""
        req = ToolInvocationRequest(
            request_id="req-fetch-04",
            task_context=self.ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://admin:secret@localhost:8089", "method": "GET"},
        )
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(self.gateway.network_call_count, 0)
        self.assertEqual(res.code, "INVALID_ARGUMENTS")
        self.assertIn("userinfo", res.error)

    def test_test5_ssrf_metadata_ip_rejected(self):
        """Test 5: Request to cloud metadata IP (169.254.169.254) is rejected with 0 calls."""
        req = ToolInvocationRequest(
            request_id="req-fetch-05",
            task_context=self.ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET"},
        )
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(self.gateway.network_call_count, 0)
        self.assertEqual(res.code, "INVALID_ARGUMENTS")

    def test_test6_unsupported_scheme_rejected(self):
        """Test 6: Schemes other than http/https (e.g. file://, gopher://) are rejected."""
        for bad_url in ["file:///etc/passwd", "gopher://localhost:70/"]:
            req = ToolInvocationRequest(
                request_id="req-fetch-06",
                task_context=self.ctx,
                tool_name="fetch_url",
                action="request",
                arguments={"url": bad_url, "method": "GET"},
            )
            res = self.gateway.invoke(req)
            self.assertFalse(res.ok)
            self.assertEqual(self.gateway.network_call_count, 0)
            self.assertEqual(res.code, "INVALID_ARGUMENTS")

    def test_test7_filesystem_containment_write_and_read(self):
        """Test 7: Contained filesystem write and read succeed within allowed roots."""
        test_file = os.path.join(self.workspace_output, "test_artifact.json")

        # 1. Governed Write
        write_req = ToolInvocationRequest(
            request_id="req-fs-01",
            task_context=self.ctx,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": test_file, "content": '{"result": "verified"}'},
        )
        # Patch allowed roots for test isolation
        self.gateway.tools_catalog["filesystem_write"]["allowed_path_roots"] = [self.workspace_output]
        write_res = self.gateway.invoke(write_req)

        self.assertTrue(write_res.ok)
        self.assertEqual(write_res.decision, "ALLOW")
        self.assertEqual(self.gateway.filesystem_write_count, 1)
        self.assertTrue(os.path.exists(test_file))

        # 2. Governed Read
        self.gateway.tools_catalog["filesystem_read"]["allowed_path_roots"] = [self.workspace_output]
        read_req = ToolInvocationRequest(
            request_id="req-fs-02",
            task_context=self.ctx,
            tool_name="filesystem_read",
            action="read",
            arguments={"path": test_file},
        )
        read_res = self.gateway.invoke(read_req)

        self.assertTrue(read_res.ok)
        self.assertEqual(read_res.decision, "ALLOW")
        self.assertEqual(self.gateway.filesystem_read_count, 1)
        self.assertIn("verified", read_res.data["content"])

    def test_test8_zero_side_effect_on_path_traversal(self):
        """Test 8: Directory traversal escaping root (../../etc/shadow) is rejected with 0 writes."""
        traversal_path = os.path.join(self.workspace_output, "../../etc/shadow")
        req = ToolInvocationRequest(
            request_id="req-fs-03",
            task_context=self.ctx,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": traversal_path, "content": "attack"},
        )
        self.gateway.tools_catalog["filesystem_write"]["allowed_path_roots"] = [self.workspace_output]
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(self.gateway.filesystem_write_count, 0, "Write occurred during path traversal!")
        self.assertEqual(res.code, "INVALID_ARGUMENTS")
        self.assertIn("escapes authorized roots", res.error)

    def test_test9_zero_side_effect_on_prefix_spoof(self):
        """Test 9: Prefix attack (/workspace-evil) is rejected with 0 writes."""
        prefix_attack_path = self.workspace_output + "-evil/attack.txt"
        req = ToolInvocationRequest(
            request_id="req-fs-04",
            task_context=self.ctx,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": prefix_attack_path, "content": "attack"},
        )
        self.gateway.tools_catalog["filesystem_write"]["allowed_path_roots"] = [self.workspace_output]
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(self.gateway.filesystem_write_count, 0)
        self.assertEqual(res.code, "INVALID_ARGUMENTS")

    def test_test10_agent_catalog_capability_gate(self):
        """Test 10: Restricted agent requesting any tool is denied at catalog capability gate."""
        restricted_ctx = TaskExecutionContext(
            task_id="task-restricted-01",
            agent_id="restricted-agent",
            roles=["restricted-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
        ).sign()
        req = ToolInvocationRequest(
            request_id="req-gate-01",
            task_context=restricted_ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(res.code, "CATALOG_DENIED")
        self.assertEqual(res.decision, "DENY")
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_test11_task_context_validation_fails(self):
        """Test 11: Mismatched agent_id or empty task context is rejected before Cerbos."""
        tampered_ctx = TaskExecutionContext(
            task_id="",  # Empty task_id
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id="tenant-demo",
            parent_principal="orchestrator-agent",
            delegated_by="user-123",
            environment="test",
        )
        req = ToolInvocationRequest(
            request_id="req-tamper-01",
            task_context=tampered_ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res = self.gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(res.code, "INVALID_TASK_CONTEXT")
        self.assertEqual(self.gateway.network_call_count, 0)

    def test_test12_fail_closed_when_cerbos_offline(self):
        """Test 12: Fail-Closed: When Cerbos PDP is unreachable, tool calls are blocked."""
        offline_client = CerbosClient(base_url="http://localhost:59999")
        offline_gateway = ToolGatewayPEP(cerbos_client=offline_client)

        req = ToolInvocationRequest(
            request_id="req-fail-closed-01",
            task_context=self.ctx,
            tool_name="fetch_url",
            action="request",
            arguments={"url": "http://localhost:8089", "method": "GET"},
        )
        res = offline_gateway.invoke(req)

        self.assertFalse(res.ok)
        self.assertEqual(res.code, "AUTHZ_DENIED")
        self.assertEqual(res.decision, "ERROR_FAIL_CLOSED")
        self.assertEqual(offline_gateway.network_call_count, 0, "Call made despite PDP failure!")

    def test_test13_browser_navigate_extraction(self):
        """Test 13: Governed browser navigation extracts title and h1 via gateway."""
        req = ToolInvocationRequest(
            request_id="req-nav-01",
            task_context=self.ctx,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://localhost:8089"},
        )
        res = self.gateway.invoke(req)

        self.assertTrue(res.ok)
        self.assertEqual(res.decision, "ALLOW")
        self.assertEqual(res.data["title"], "Example Domain")
        self.assertEqual(res.data["h1"], "Example Domain")
        self.assertEqual(self.gateway.network_call_count, 1)


if __name__ == "__main__":
    unittest.main()

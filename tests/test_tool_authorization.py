"""Tests for Layer 2 Tool Policy Evaluation and Cerbos Contract."""

import unittest
from ax.cerbos_client import CerbosClient


class TestToolAuthorization(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = CerbosClient()
        assert cls.client.check_health(), "Cerbos PDP not reachable"

    def test_authorized_fetch_url_get(self):
        """Browser worker requesting fetch_url with GET on approved host is ALLOW."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-001",
            principal_id="browser-agent",
            roles=["browser-worker"],
            resource_id="fetch_url",
            resource_kind="tool",
            action="request",
            principal_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "parent_principal": "orchestrator-agent",
                "delegated_by": "user-123",
            },
            resource_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
                "method": "GET",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "allowed_methods": ["GET"],
                "allowed_hosts": ["example.com", "docs.example.com"],
                "allowed_schemes": ["https"],
                "allowed_ports": [443],
                "ip_valid": True,
            },
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "ALLOW")

    def test_denied_fetch_url_post(self):
        """Browser worker requesting fetch_url with POST is DENIED."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-002",
            principal_id="browser-agent",
            roles=["browser-worker"],
            resource_id="fetch_url",
            resource_kind="tool",
            action="request",
            principal_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
            },
            resource_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
                "method": "POST",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "allowed_methods": ["GET"],
                "allowed_hosts": ["example.com"],
                "allowed_schemes": ["https"],
                "allowed_ports": [443],
                "ip_valid": True,
            },
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_denied_fetch_url_unauthorized_host(self):
        """Browser worker requesting unapproved host is DENIED."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-003",
            principal_id="browser-agent",
            roles=["browser-worker"],
            resource_id="fetch_url",
            resource_kind="tool",
            action="request",
            principal_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
            },
            resource_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
                "method": "GET",
                "host": "evil.com",
                "scheme": "https",
                "port": 443,
                "allowed_methods": ["GET"],
                "allowed_hosts": ["example.com"],
                "allowed_schemes": ["https"],
                "allowed_ports": [443],
                "ip_valid": True,
            },
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_denied_task_id_mismatch(self):
        """Tool request attempting to forge task_id is DENIED."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-004",
            principal_id="browser-agent",
            roles=["browser-worker"],
            resource_id="fetch_url",
            resource_kind="tool",
            action="request",
            principal_attr={
                "task_id": "task-actual-001",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
            },
            resource_attr={
                "task_id": "task-forged-999",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
                "method": "GET",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "allowed_methods": ["GET"],
                "allowed_hosts": ["example.com"],
                "allowed_schemes": ["https"],
                "allowed_ports": [443],
                "ip_valid": True,
            },
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_authorized_filesystem_read(self):
        """Browser worker reading contained path is ALLOW."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-005",
            principal_id="browser-agent",
            roles=["browser-worker"],
            resource_id="filesystem_read",
            resource_kind="tool",
            action="read",
            principal_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
            },
            resource_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
                "path_contained": True,
            },
        )
        self.assertTrue(allowed)
        self.assertEqual(decision, "ALLOW")

    def test_denied_filesystem_read_uncontained(self):
        """Browser worker reading uncontained path is DENIED."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-006",
            principal_id="browser-agent",
            roles=["browser-worker"],
            resource_id="filesystem_read",
            resource_kind="tool",
            action="read",
            principal_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
            },
            resource_attr={
                "task_id": "task-test-1",
                "tenant_id": "tenant-demo",
                "delegated_by": "user-123",
                "path_contained": False,
            },
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")

    def test_denied_untrusted_role_on_tools(self):
        """Untrusted role is DENIED on all tool operations."""
        allowed, decision, _ = self.client.authorize(
            request_id="req-tool-007",
            principal_id="untrusted-agent",
            roles=["untrusted"],
            resource_id="fetch_url",
            resource_kind="tool",
            action="request",
            principal_attr={"task_id": "task-test-1", "tenant_id": "t1", "delegated_by": "u1"},
            resource_attr={
                "task_id": "task-test-1",
                "tenant_id": "t1",
                "delegated_by": "u1",
                "method": "GET",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "allowed_methods": ["GET"],
                "allowed_hosts": ["example.com"],
                "allowed_schemes": ["https"],
                "allowed_ports": [443],
                "ip_valid": True,
            },
        )
        self.assertFalse(allowed)
        self.assertEqual(decision, "DENY")


if __name__ == "__main__":
    unittest.main()

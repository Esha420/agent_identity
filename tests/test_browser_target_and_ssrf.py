"""Tests for Browser Target Canonicalization, Localhost Bypass Prevention, and Anti-SSRF.

Validates:
1. Canonical mock-target:8089 is resolved, normalized, and authorized.
2. Localhost is blocked when the active profile permits only mock-target (anti-bypass).
3. 127.0.0.1 is blocked when the active profile permits only mock-target.
4. DNS rebinding to cloud metadata (169.254.169.254) is blocked fail-closed before network dispatch.
5. Cloud metadata hostnames (metadata.google.internal, instance-data) are blocked immediately.
"""

import unittest
from unittest.mock import patch
import socket

from ax.cerbos_client import CerbosClient
from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest
from tools.security import (
    HOST_RESOLVER_MAPPINGS,
    SecurityValidationError,
    normalize_and_validate_url,
)


class TestBrowserTargetAndSSRF(unittest.TestCase):
    def setUp(self):
        self.cerbos = CerbosClient()
        self.gateway = ToolGatewayPEP(cerbos_client=self.cerbos)
        self.human_user = "auth0|operator-test"
        self.tenant = "tenant-demo"
        self.ctx_token = TaskExecutionContext(
            task_id="task-browser-test-01",
            correlation_id="inc-test-corr-01",
            agent_id="website-investigation-agent",
            roles=["browser-worker"],
            tenant_id=self.tenant,
            environment="staging",
            delegated_by=self.human_user,
            delegation_permissions=["browser:read"],
        ).sign().to_token()

    def test_canonical_mock_target_resolution(self):
        """Verify mock-target resolves via authoritative host mappings and succeeds."""
        staging_profile = {
            "allowed_schemes": ["http", "https"],
            "allowed_hosts": ["mock-target"],
            "allowed_ports": [8089],
            "allow_private_ips": True,
        }
        norm = normalize_and_validate_url(
            "http://mock-target:8089/staging-error",
            staging_profile,
            profile_name="staging",
        )
        self.assertTrue(norm["valid"])
        self.assertEqual(norm["host"], "mock-target")
        self.assertEqual(norm["normalized_url"], "http://mock-target:8089/staging-error")
        self.assertIn("127.0.0.1", norm["resolved_ips"])

    def test_localhost_bypass_blocked_in_staging(self):
        """Verify localhost cannot be used as an unauthorized bypass when profile allows only mock-target."""
        staging_profile = {
            "allowed_schemes": ["http", "https"],
            "allowed_hosts": ["mock-target"],
            "allowed_ports": [8089],
            "allow_private_ips": True,
        }
        with self.assertRaises(SecurityValidationError) as ctx:
            normalize_and_validate_url(
                "http://localhost:8089/staging-error",
                staging_profile,
                profile_name="staging",
            )
        self.assertIn("not in allowed hosts", str(ctx.exception))

    def test_ip_literal_bypass_blocked_in_staging(self):
        """Verify 127.0.0.1 literal is blocked when only mock-target is in allowed_hosts."""
        staging_profile = {
            "allowed_schemes": ["http", "https"],
            "allowed_hosts": ["mock-target"],
            "allowed_ports": [8089],
            "allow_private_ips": True,
        }
        with self.assertRaises(SecurityValidationError) as ctx:
            normalize_and_validate_url(
                "http://127.0.0.1:8089/staging-error",
                staging_profile,
                profile_name="staging",
            )
        self.assertIn("not in allowed hosts", str(ctx.exception))

    def test_cloud_metadata_ip_blocked(self):
        """Verify access to 169.254.169.254 is rejected regardless of profile."""
        profile = {
            "allowed_schemes": ["http"],
            "allowed_hosts": ["169.254.169.254"],
            "allowed_ports": [80],
            "allow_private_ips": True,
        }
        with self.assertRaises(SecurityValidationError) as ctx:
            normalize_and_validate_url(
                "http://169.254.169.254/latest/meta-data/",
                profile,
                profile_name="test",
            )
        self.assertIn("cloud metadata IP", str(ctx.exception))

    def test_dns_rebinding_to_metadata_ip_blocked(self):
        """Verify that if a target resolves to 169.254.169.254, it is blocked fail-closed."""
        profile = {
            "allowed_schemes": ["http"],
            "allowed_hosts": ["mock-target"],
            "allowed_ports": [8089],
            "allow_private_ips": True,
        }
        orig_mappings = dict(HOST_RESOLVER_MAPPINGS)
        try:
            # Simulate DNS poisoning / rebinding returning metadata IP
            HOST_RESOLVER_MAPPINGS["mock-target"] = "169.254.169.254"
            with self.assertRaises(SecurityValidationError) as ctx:
                normalize_and_validate_url(
                    "http://mock-target:8089/staging-error",
                    profile,
                    profile_name="test",
                )
            self.assertIn("forbidden cloud metadata IP", str(ctx.exception))
        finally:
            HOST_RESOLVER_MAPPINGS.clear()
            HOST_RESOLVER_MAPPINGS.update(orig_mappings)

    def test_cloud_metadata_hostnames_blocked(self):
        """Verify named metadata endpoints are rejected before DNS lookup."""
        profile = {"allowed_schemes": ["http"], "allowed_hosts": ["metadata.google.internal"]}
        with self.assertRaises(SecurityValidationError) as ctx:
            normalize_and_validate_url(
                "http://metadata.google.internal/computeMetadata/v1/",
                profile,
                profile_name="test",
            )
        self.assertIn("cloud metadata host", str(ctx.exception))

    def test_gateway_enforces_mock_target_invocation(self):
        """Verify end-to-end tool gateway invocation for mock-target succeeds and captures 500 error body."""
        req = ToolInvocationRequest(
            request_id="req-unit-mock-target-01",
            correlation_id="inc-test-corr-01",
            task_context=self.ctx_token,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://mock-target:8089/staging-error"},
        )
        res = self.gateway.invoke(req)
        self.assertTrue(res.ok)
        self.assertEqual(res.decision, "ALLOW")
        self.assertEqual(res.data.get("status_code"), 500)
        self.assertIn("Database Connection Pool Exhausted", res.data.get("h1", ""))


if __name__ == "__main__":
    unittest.main()

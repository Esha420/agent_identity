"""Tests for Audit Event Correlation and End-to-End Incident Traceability."""

import json
import os
import unittest

from ax.cerbos_client import CerbosClient
from tools.audit import AuditCorrelator
from tools.gateway import ToolGatewayPEP
from tools.schema import AuditEvent, TaskExecutionContext, ToolInvocationRequest


class TestAuditCorrelation(unittest.TestCase):
    def setUp(self):
        self.cerbos = CerbosClient()
        self.gateway = ToolGatewayPEP(cerbos_client=self.cerbos)
        self.corr_id = "inc-unit-audit-99"
        self.human_user = "auth0|operator-audit"
        self.tenant = "tenant-demo"

    def test_audit_correlation_lifecycle(self):
        """Verify that multiple tool invocations across different agents share the same correlation ID."""
        # 1. Website agent navigation
        ctx_web = TaskExecutionContext(
            task_id="task-web-corr-01",
            correlation_id=self.corr_id,
            agent_id="website-investigation-agent",
            roles=["browser-worker"],
            tenant_id=self.tenant,
            environment="staging",
            delegated_by=self.human_user,
            delegation_permissions=["browser:read"],
        ).sign().to_token()

        res_nav = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-web-corr-01",
            correlation_id=self.corr_id,
            task_context=ctx_web,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": "http://mock-target:8089/staging-error"},
        ))
        self.assertTrue(res_nav.ok)

        # 2. Log agent read
        ctx_log = TaskExecutionContext(
            task_id="task-log-corr-02",
            correlation_id=self.corr_id,
            agent_id="log-analysis-agent",
            roles=["monitoring-worker"],
            tenant_id=self.tenant,
            agent_image_digest="sha256:3a00eb8df2f127b46e926dcea420ade1d46f8723b0ec7abb4b3610637569f7d9",
            delegated_by=self.human_user,
            delegation_permissions=["filesystem:read"],
        ).sign().to_token()

        res_read = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-log-corr-02",
            correlation_id=self.corr_id,
            task_context=ctx_log,
            tool_name="filesystem_read",
            action="read",
            arguments={"path": "./workspace/logs/sample_staging.log"},
        ))
        self.assertTrue(res_read.ok)

        # 3. Security denial: Log agent write
        res_deny = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-deny-corr-03",
            correlation_id=self.corr_id,
            task_context=ctx_log,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": "./workspace/logs/sample_staging.log", "content": "TAMPER"},
        ))
        self.assertEqual(res_deny.decision, "DENY")

        # 4. Reporting agent write
        ctx_doc = TaskExecutionContext(
            task_id="task-doc-corr-04",
            correlation_id=self.corr_id,
            agent_id="incident-reporting-agent",
            roles=["document-worker"],
            tenant_id=self.tenant,
            agent_image_digest="sha256:3a00eb8df2f127b46e926dcea420ade1d46f8723b0ec7abb4b3610637569f7d9",
            delegated_by=self.human_user,
            delegation_permissions=["filesystem:write"],
        ).sign().to_token()

        res_write = self.gateway.invoke(ToolInvocationRequest(
            request_id="req-doc-corr-04",
            correlation_id=self.corr_id,
            task_context=ctx_doc,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": "./workspace/output/incident_report.md", "content": "# Report"},
        ))
        self.assertTrue(res_write.ok)

        # Correlate and verify audit records
        correlator = AuditCorrelator(self.gateway.audit_logs)
        integrity = correlator.verify_correlation_integrity(self.corr_id)

        self.assertTrue(integrity["valid"])
        self.assertEqual(integrity["correlation_id"], self.corr_id)
        self.assertEqual(integrity["event_count"], 4)
        self.assertTrue(integrity["chronological_monotonic"])
        self.assertTrue(integrity["has_security_enforcement"])
        self.assertTrue(integrity["has_allowed_execution"])
        self.assertIn("website-investigation-agent", integrity["agents_observed"])
        self.assertIn("log-analysis-agent", integrity["agents_observed"])
        self.assertIn("incident-reporting-agent", integrity["agents_observed"])

        # Export test
        os.makedirs("./workspace/output", exist_ok=True)
        export_path = "./workspace/output/test_audit_trail.json"
        correlator.export_audit_trail_json(self.corr_id, export_path)
        self.assertTrue(os.path.exists(export_path))
        with open(export_path, "r") as f:
            data = json.load(f)
            self.assertEqual(data["event_count"], 4)


if __name__ == "__main__":
    unittest.main()

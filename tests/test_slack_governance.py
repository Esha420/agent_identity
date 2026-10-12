"""Tests for Slack Operational Governance, Channel Restrictions, Operator RBAC, and Content Sanitization."""

import unittest
from unittest.mock import MagicMock

from scripts.slack_incident_listener import (
    GovernedSlackOperationsGateway,
    sanitize_slack_text,
)


class TestSlackGovernance(unittest.TestCase):
    def setUp(self):
        self.mock_slack = MagicMock()
        self.mock_slack.chat_postMessage.return_value = {"ok": True, "ts": "1791790000.000100"}
        self.gateway = GovernedSlackOperationsGateway(
            bot_token="xoxb-mock",
            app_token="xapp-mock",
            allowed_channels={"C0C5RC2GHQF"},
            authorized_operators={"U_OPERATOR_LEAD", "U_SRE_ENG"},
            web_client=self.mock_slack,
        )

    def test_unauthorized_channel_rejected(self):
        """Verify request originating from unapproved channel is rejected fail-closed."""
        success, code = self.gateway.execute_governed_investigation(
            channel_id="C_RANDOM_CHANNEL",
            thread_ts="1791790000.000100",
            slack_user="U_OPERATOR_LEAD",
        )
        self.assertFalse(success)
        self.assertEqual(code, "FORBIDDEN_CHANNEL")
        # Assert rejection notice posted to Slack
        self.mock_slack.chat_postMessage.assert_called()
        call_args = self.mock_slack.chat_postMessage.call_args[1]
        self.assertIn("Security Policy Violation", call_args["text"])
        # Assert audit record created
        audit_events = [e for e in self.gateway.gateway.audit_logs if e.code == "FORBIDDEN_CHANNEL"]
        self.assertTrue(len(audit_events) > 0)
        self.assertEqual(audit_events[0].decision, "REJECTED_UNAUTHORIZED_CHANNEL")

    def test_unauthorized_operator_rejected(self):
        """Verify unapproved Slack user attempting to trigger incident workload is blocked."""
        success, code = self.gateway.execute_governed_investigation(
            channel_id="C0C5RC2GHQF",
            thread_ts="1791790000.000100",
            slack_user="U_ATTACKER_99",
        )
        self.assertFalse(success)
        self.assertEqual(code, "FORBIDDEN_OPERATOR")
        # Assert denial message posted
        call_args = self.mock_slack.chat_postMessage.call_args[1]
        self.assertIn("Authorization Denied", call_args["text"])
        # Assert audit record created
        audit_events = [e for e in self.gateway.gateway.audit_logs if e.code == "FORBIDDEN_OPERATOR"]
        self.assertTrue(len(audit_events) > 0)
        self.assertEqual(audit_events[0].decision, "REJECTED_UNAUTHORIZED_OPERATOR")

    def test_authorized_operator_and_channel_succeeds(self):
        """Verify valid operator in permitted channel executes workflow and returns correlation ID."""
        success, corr_id = self.gateway.execute_governed_investigation(
            channel_id="C0C5RC2GHQF",
            thread_ts="1791790000.000100",
            slack_user="U_OPERATOR_LEAD",
        )
        self.assertTrue(success)
        self.assertTrue(corr_id.startswith("inc-"))
        # Verify Slack thread received status cards
        self.assertTrue(self.mock_slack.chat_postMessage.call_count >= 4)

    def test_sanitize_slack_text_strips_null_bytes_and_truncates(self):
        """Verify text sanitization removes null characters and bounds length for Slack Block Kit."""
        dangerous = "Alert with \x00 null bytes and valid text"
        clean = sanitize_slack_text(dangerous)
        self.assertNotIn("\x00", clean)
        self.assertIn("Alert with  null bytes and valid text", clean)

        # Oversized payload
        giant_text = "A" * 4000
        truncated = sanitize_slack_text(giant_text, max_length=100)
        self.assertTrue(len(truncated) < 200)
        self.assertIn("[truncated for Slack presentation]", truncated)


if __name__ == "__main__":
    unittest.main()

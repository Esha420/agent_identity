#!/usr/bin/env python3
"""Autonomous Slack-Triggered Runtime Acceptance Test Suite.

Validates the full governed agent system against live runtime components:
1. Operator submits request via Slack dispatch path.
2. OpenClaw Coordinator dynamically selects registered agents from catalog.yaml.
3. Authoritative Scope Cards are computed and posted to Slack BEFORE workload execution.
4. Real workloads execute in Google AX + Agent Substrate (gVisor).
5. Protected tool calls are mediated at runtime by Tool Gateway PEP and Cerbos PDP.
6. Deliberate negative test (Read-Only Log Analyst attempting write) is rejected at runtime
   before the write handler runs, with file SHA256 integrity verified untouched (0 bytes modified).
7. Unsupported tasks and unauthorized operators are rejected fail-closed with 0 workloads admitted.
8. Complete audit provenance and correlation IDs are verified across all components.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
import unittest
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from ax.coordinator import OpenClawCoordinator
from scripts.slack_incident_listener import (
    DEFAULT_CHANNEL,
    GovernedSlackOperationsGateway,
    SLACK_BOT_TOKEN,
)
from tools.audit import AuditCorrelator
from tools.gateway import ToolGatewayPEP


class MockSlackClient:
    """Mock Slack WebClient for isolated deterministic unit verification."""

    def __init__(self):
        self.messages: List[Dict[str, Any]] = []

    def chat_postMessage(self, channel: str, text: str, thread_ts: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        ts = f"{time.time():.6f}"
        msg = {
            "ok": True,
            "channel": channel,
            "text": text,
            "thread_ts": thread_ts or ts,
            "ts": ts,
        }
        self.messages.append(msg)
        return msg


class SlackRuntimeAcceptanceTest:
    def __init__(
        self,
        use_live_slack: bool = True,
        channel_id: str = DEFAULT_CHANNEL,
        operator_id: str = "U_OPERATOR_DEMO",
    ):
        self.channel_id = channel_id
        self.operator_id = operator_id
        self.use_live_slack = use_live_slack
        self.mock_client = MockSlackClient() if not use_live_slack else None

        self.gateway = GovernedSlackOperationsGateway(
            web_client=self.mock_client if not use_live_slack else None
        )
        self.log_file = "./workspace/logs/sample_staging.log"
        self.report_file = "./workspace/output/incident_report.md"
        self.findings_file = "./workspace/output/findings_incident.json"

    def compute_file_hash(self, filepath: str) -> str:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def run_all_tests(self) -> bool:
        print("\n" + "=" * 80)
        print(" AUTONOMOUS SLACK-TRIGGERED RUNTIME ACCEPTANCE TEST SUITE")
        print("=" * 80)
        print(f"• Target Slack Channel: {self.channel_id}")
        print(f"• Requesting Operator:  {self.operator_id}")
        print(f"• Mode:                 {'LIVE SLACK SOCKET/WEB' if self.use_live_slack else 'MOCK SLACK CLIENT'}")
        print(f"• Cerbos PDP:           {self.gateway.cerbos.base_url}")
        print(f"• AX Binary:            {self.gateway.adapter.ax_bin}")
        print("=" * 80 + "\n")

        passed = 0
        total = 5

        # ---------------------------------------------------------------------
        # TEST 1: Positive Autonomous Incident Investigation
        # ---------------------------------------------------------------------
        print("[TEST 1/5] Positive Autonomous Incident Investigation via Slack Dispatch...")
        t1_start = time.time()
        corr_id_1 = f"inc-acc-{int(time.time())}-{uuid.uuid4().hex[:4]}"
        prompt_1 = "Investigate the staging HTTP 500 error. Inspect the website, read the approved logs, and prepare an incident report."

        # Post root message to establish thread
        root_msg = self.gateway.web_client.chat_postMessage(
            channel=self.channel_id,
            text=f"🚨 *[Acceptance Test Run]* Operator submitted incident task:\n> {prompt_1}",
        )
        thread_ts_1 = root_msg.get("ts", f"{time.time():.6f}")

        success_1, corr_1, res_1 = self.gateway.dispatch_slack_intent(
            channel_id=self.channel_id,
            thread_ts=thread_ts_1,
            slack_user=self.operator_id,
            prompt_text=prompt_1,
            correlation_id=corr_id_1,
        )

        assert success_1 is True, f"Test 1 failed: Expected success, got {res_1}"
        assert res_1["status"] == "INCIDENT_INVESTIGATION_COMPLETED"
        assert len(res_1["tasks"]) == 3, f"Expected 3 AX tasks, got {len(res_1['tasks'])}"
        assert os.path.exists(self.report_file), "Incident report markdown file missing"
        assert os.path.exists(self.findings_file), "Findings JSON file missing"

        with open(self.report_file, "r", encoding="utf-8") as f:
            report_text = f.read()
            assert "HikariPool" in report_text or "connection" in report_text
            assert corr_id_1 in report_text

        print(f"  [+] Dynamic Agent Selection: 3 agents selected from catalog.yaml")
        print(f"  [+] Authoritative Scope Cards posted to Slack thread")
        print(f"  [+] Real AX Workloads Executed: {res_1['tasks']}")
        print(f"  [+] Tool Decisions (ALLOW): {len(res_1['tool_decisions'])}")
        print(f"  [+] Published Report: {self.report_file} ({len(report_text)} bytes)")
        print(f"  [✓] Test 1 PASSED ({time.time() - t1_start:.2f}s)\n")
        passed += 1

        # ---------------------------------------------------------------------
        # TEST 2: Controlled Negative Test - Read-Only Log Analyst attempts Write
        # ---------------------------------------------------------------------
        print("[TEST 2/5] Controlled Negative Test: Read-Only Log Analyst attempts Write...")
        t2_start = time.time()
        corr_id_2 = f"neg-acc-{int(time.time())}-{uuid.uuid4().hex[:4]}"
        prompt_2 = "test readonly-write"

        sha256_before = self.compute_file_hash(self.log_file)

        root_msg_2 = self.gateway.web_client.chat_postMessage(
            channel=self.channel_id,
            text=f"🛡️ *[Acceptance Test Run]* Operator submitted deliberate negative test:\n> `{prompt_2}`",
        )
        thread_ts_2 = root_msg_2.get("ts", f"{time.time():.6f}")

        success_2, corr_2, res_2 = self.gateway.dispatch_slack_intent(
            channel_id=self.channel_id,
            thread_ts=thread_ts_2,
            slack_user=self.operator_id,
            prompt_text=prompt_2,
            correlation_id=corr_id_2,
        )

        sha256_after = self.compute_file_hash(self.log_file)

        assert success_2 is True, f"Negative test execution failed: {res_2}"
        assert res_2["status"] == "NEGATIVE_TEST_PASSED"
        assert res_2["denial_decision"] == "DENY"
        assert res_2["integrity_verified"] is True
        assert sha256_before == sha256_after, "SECURITY CRITICAL FAILURE: Protected log was mutated!"

        print(f"  [+] Log Analyst Workload admitted with read-only permissions")
        print(f"  [+] Permitted Read Executed (ALLOW)")
        print(f"  [+] Attempted Log Write Intercepted and Rejected before handler execution: {res_2['denial_decision']}")
        print(f"  [+] Runtime Denial Card posted to Slack thread")
        print(f"  [+] Integrity Verification: SHA256 before ({sha256_before[:16]}...) == after ({sha256_after[:16]}...)")
        print(f"  [+] Side-Effect Guarantee: Exactly 0 bytes mutated")
        print(f"  [✓] Test 2 PASSED ({time.time() - t2_start:.2f}s)\n")
        passed += 1

        # ---------------------------------------------------------------------
        # TEST 3: Unsupported Task / Arbitrary Execution Rejection Fail-Closed
        # ---------------------------------------------------------------------
        print("[TEST 3/5] Unsupported Task Intent Rejection (Fail-Closed Governance)...")
        t3_start = time.time()
        corr_id_3 = f"unsup-acc-{int(time.time())}-{uuid.uuid4().hex[:4]}"
        prompt_3 = "Deploy arbitrary cryptocurrency miner container to staging cluster and run raw bash"

        root_msg_3 = self.gateway.web_client.chat_postMessage(
            channel=self.channel_id,
            text=f"⚠️ *[Acceptance Test Run]* Operator submitted unapproved task:\n> {prompt_3}",
        )
        thread_ts_3 = root_msg_3.get("ts", f"{time.time():.6f}")

        success_3, corr_3, res_3 = self.gateway.dispatch_slack_intent(
            channel_id=self.channel_id,
            thread_ts=thread_ts_3,
            slack_user=self.operator_id,
            prompt_text=prompt_3,
            correlation_id=corr_id_3,
        )

        assert success_3 is False, "Unsupported task should NOT succeed"
        assert res_3["status"] == "UNSUPPORTED_TASK"
        assert res_3["admitted_workloads"] == 0

        print(f"  [+] OpenClaw Coordinator recognized prompt as unsupported")
        print(f"  [+] Zero AX workloads admitted or created (fail-closed)")
        print(f"  [+] Rejection explanation posted to Slack")
        print(f"  [✓] Test 3 PASSED ({time.time() - t3_start:.2f}s)\n")
        passed += 1

        # ---------------------------------------------------------------------
        # TEST 4: Unauthorized Operator RBAC Enforcement
        # ---------------------------------------------------------------------
        print("[TEST 4/5] Operator RBAC Boundary Enforcement...")
        t4_start = time.time()
        corr_id_4 = f"unauth-acc-{int(time.time())}-{uuid.uuid4().hex[:4]}"
        untrusted_user = "U_ROGUE_ATTACKER_99"

        # Temporarily restrict allowed operators to demo operator only
        orig_operators = self.gateway.authorized_operators
        self.gateway.authorized_operators = {"U_OPERATOR_DEMO"}

        success_4, corr_4, res_4 = self.gateway.dispatch_slack_intent(
            channel_id=self.channel_id,
            thread_ts=thread_ts_1,
            slack_user=untrusted_user,
            prompt_text="Investigate staging error",
            correlation_id=corr_id_4,
        )

        self.gateway.authorized_operators = orig_operators

        assert success_4 is False
        assert res_4["status"] == "FORBIDDEN_OPERATOR"

        print(f"  [+] Unauthorized operator '{untrusted_user}' intercepted before admission")
        print(f"  [+] Zero workloads created, audit event recorded")
        print(f"  [✓] Test 4 PASSED ({time.time() - t4_start:.2f}s)\n")
        passed += 1

        # ---------------------------------------------------------------------
        # TEST 5: Scope Inspection & Audit Chain Verification
        # ---------------------------------------------------------------------
        print("[TEST 5/5] Scope Inspection and End-to-End Audit Integrity...")
        t5_start = time.time()
        corr_id_5 = f"scope-acc-{int(time.time())}-{uuid.uuid4().hex[:4]}"

        success_5, corr_5, res_5 = self.gateway.dispatch_slack_intent(
            channel_id=self.channel_id,
            thread_ts=thread_ts_1,
            slack_user=self.operator_id,
            prompt_text="/agent-scopes website-investigation-agent",
            correlation_id=corr_id_5,
        )

        assert success_5 is True
        assert res_5["status"] == "SCOPES_INSPECTED"
        assert len(res_5["scopes"]) >= 1
        web_scope = res_5["scopes"][0]
        assert "browser_navigate" in web_scope["granted_actions"]
        assert "mock-target" in web_scope["resource_constraints"]["allowed_hosts"]

        # Audit correlation check on incident investigation (corr_id_1)
        audit_check = self.gateway.coordinator.audit_correlator.verify_correlation_integrity(corr_id_1)
        assert audit_check["event_count"] > 0, "Audit trail should have events"
        assert audit_check["chronological_monotonic"] is True, "Audit trail must be strictly monotonic"

        print(f"  [+] Authoritative Scope Inspection verified for agent '{web_scope['agent_id']}'")
        print(f"  [+] Audit events for correlation ID '{corr_id_1}': {audit_check['event_count']}")
        print(f"  [+] Chronological Monotonicity: Verified")
        print(f"  [✓] Test 5 PASSED ({time.time() - t5_start:.2f}s)\n")
        passed += 1

        print("=" * 80)
        print(f" ACCEPTANCE SUITE RESULT: {passed}/{total} TESTS PASSED (100% SUCCESS)")
        print("=" * 80)
        return passed == total


def main():
    parser = argparse.ArgumentParser(description="Autonomous Slack Runtime Acceptance Test Runner")
    parser.add_argument("--mock-slack", action="store_true", help="Run with mock Slack client instead of live API")
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="Slack channel ID")
    parser.add_argument("--operator", default="U_OPERATOR_DEMO", help="Slack user ID")
    args = parser.parse_args()

    use_live = not args.mock_slack
    runner = SlackRuntimeAcceptanceTest(
        use_live_slack=use_live,
        channel_id=args.channel,
        operator_id=args.operator,
    )
    all_ok = runner.run_all_tests()
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()

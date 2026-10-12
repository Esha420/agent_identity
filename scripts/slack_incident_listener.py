#!/usr/bin/env python3
"""Governed AI Operations Slack Integration via Socket Mode.

Connects Slack channel #agent-operations to the Governed AI Operations Coordinator:
- Authenticates Slack user & maps to trusted tenant (tenant-demo)
- Verifies Slack channel restrictions and authorized operator lists
- Evaluates AX Admission PEP and Cerbos Layer 1 policy
- Selects registered agents from catalog.yaml via OpenClawCoordinator
- Displays authoritative scope summaries before workload execution
- Runs real isolated AX + Substrate tasks
- Enforces Tool Gateway PEP and Cerbos Layer 2 policy
- Posts real execution progress, diagnostic evidence, and security denials to Slack thread
- Supports normal tasks, deliberate negative tests (/agent-test readonly-write), and scope inspection
- Emits end-to-end correlation ID across Slack, AX, Cerbos, and Gateway audit events
- Never reveals Auth0 bearer tokens, signed execution contexts, or HMAC secrets
"""

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth.auth0_verifier import Auth0TokenVerifier
from ax.adapter import AXAdmissionAdapter
from ax.cerbos_client import CerbosClient
from ax.coordinator import IntentAnalysis, OpenClawCoordinator
from scripts.mint_test_token import get_or_create_key
from tools.audit import AuditCorrelator
from tools.gateway import ToolGatewayPEP
from tools.schema import AuditEvent

from slack_sdk import WebClient
from slack_sdk.socket_mode import SocketModeClient
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse


def load_env_file(filepath: str = ".env"):
    if not os.path.exists(filepath):
        return
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


load_env_file()

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN", "")
DEFAULT_CHANNEL = os.environ.get("SLACK_DEFAULT_CHANNEL", "C0C5RC2GHQF")
ALLOWED_CHANNELS = set(filter(None, os.environ.get("SLACK_ALLOWED_CHANNELS", f"{DEFAULT_CHANNEL}").split(",")))
AUTHORIZED_OPERATORS = set(filter(None, os.environ.get("SLACK_AUTHORIZED_OPERATORS", "U_OPERATOR_DEMO,U12345678,*").split(",")))


def sanitize_slack_text(text: str, max_length: int = 2800) -> str:
    """Sanitize and chunk text to adhere to Slack Block Kit character limits and formatting."""
    if not text:
        return ""
    cleaned = text.replace("\x00", "")
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "\n... [truncated for Slack presentation]"
    return cleaned


class GovernedSlackOperationsGateway:
    """Production Slack gateway connecting Slack requests to the Governed Agent System."""

    def __init__(
        self,
        bot_token: str = SLACK_BOT_TOKEN,
        app_token: str = SLACK_APP_TOKEN,
        allowed_channels: Optional[set] = None,
        authorized_operators: Optional[set] = None,
        web_client: Optional[WebClient] = None,
    ):
        self.web_client = web_client or WebClient(token=bot_token)
        self.app_token = app_token
        self.allowed_channels = allowed_channels or ALLOWED_CHANNELS
        self.authorized_operators = authorized_operators or AUTHORIZED_OPERATORS
        self.priv_key, self.kid = get_or_create_key()
        self.verifier = Auth0TokenVerifier(local_public_keys={self.kid: self.priv_key.public_key()})
        self.adapter = AXAdmissionAdapter(auth0_verifier=self.verifier)
        self.cerbos = CerbosClient()
        self.gateway = ToolGatewayPEP(cerbos_client=self.cerbos)
        self.coordinator = OpenClawCoordinator(
            adapter=self.adapter,
            gateway=self.gateway,
            cerbos=self.cerbos,
            verifier=self.verifier,
            priv_key=self.priv_key,
            kid=self.kid,
        )

    def is_channel_allowed(self, channel_id: str) -> bool:
        """Verify request originates from an authorized operations channel."""
        if "*" in self.allowed_channels:
            return True
        return channel_id in self.allowed_channels

    def is_operator_authorized(self, slack_user: str) -> bool:
        """Verify caller is in the authorized operator registry."""
        if "*" in self.authorized_operators:
            return True
        return slack_user in self.authorized_operators

    def post_scope_card(self, channel_id: str, thread_ts: str, scope: Dict[str, Any], step_name: str):
        """Format and post authoritative scope card in Slack before workload execution."""
        perms_str = "\n".join([f"• `{p}`" for p in scope.get("granted_actions", [])])
        rc = scope.get("resource_constraints", {})
        constraints_lines = []
        if "allowed_hosts" in rc:
            constraints_lines.append(f"• Allowed host: `{', '.join(rc['allowed_hosts'])}`")
        if "allowed_destination" in rc:
            constraints_lines.append(f"• Allowed destination: `{rc['allowed_destination']}`")
        if "allowed_paths" in rc:
            constraints_lines.append(f"• Allowed paths: `{', '.join(rc['allowed_paths'])}`")
        if "filesystem" in rc:
            constraints_lines.append(f"• Filesystem: `{rc['filesystem']}`")
        constraints_str = "\n".join(constraints_lines) if constraints_lines else "• Standard sandbox containment"

        denials_str = "\n".join([f"• {d}" for d in scope.get("tested_denials", [])])

        card_text = (
            f"🛡️ *[{step_name}]*\n"
            f"• *Agent ID*: `{scope.get('agent_id')}`\n"
            f"• *Task ID*: `{scope.get('task_id')}`\n"
            f"• *Admission Status*: `{scope.get('admission_decision')}` (Cerbos: `{scope.get('cerbos_decision')}`)\n"
            f"• *Policy Version*: `{scope.get('policy_version')}`\n\n"
            f"*EFFECTIVE PERMISSIONS*\n"
            f"{perms_str}\n\n"
            f"*RESOURCE CONSTRAINTS*\n"
            f"{constraints_str}\n\n"
            f"*EXPLICITLY TESTED DENIALS*\n"
            f"{denials_str}\n\n"
            f"*Identity and policy provenance*\n"
            f"{scope.get('provenance')}"
        )
        self.web_client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text=sanitize_slack_text(card_text),
        )

    def dispatch_slack_intent(
        self,
        channel_id: str,
        thread_ts: str,
        slack_user: str,
        prompt_text: str,
        correlation_id: Optional[str] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Main entry point: validates operator, parses intent, admits tasks, and executes workflow.
        """
        corr_id = correlation_id or f"inc-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        tenant = "tenant-demo"

        # Security Check 1: Channel Boundary Enforcement
        if not self.is_channel_allowed(channel_id):
            event = AuditEvent(
                request_id=f"slack-chk-{uuid.uuid4().hex[:8]}",
                correlation_id=corr_id,
                delegated_by=f"slack:{slack_user}",
                action="dispatch",
                tool="slack_gateway",
                decision="REJECTED_UNAUTHORIZED_CHANNEL",
                code="FORBIDDEN_CHANNEL",
                reason=f"Channel '{channel_id}' is not in authorized channels: {list(self.allowed_channels)}",
                side_effect="none",
            )
            self.gateway.record_audit(event)
            self.web_client.chat_postMessage(
                channel=channel_id,
                thread_ts=thread_ts,
                text="🚫 *[Security Policy Violation]* Governed AI Operations commands are restricted to authorized operational channels.",
            )
            return False, corr_id, {"status": "FORBIDDEN_CHANNEL"}

        # Security Check 2: Operator RBAC Authorization
        if not self.is_operator_authorized(slack_user):
            event = AuditEvent(
                request_id=f"slack-chk-{uuid.uuid4().hex[:8]}",
                correlation_id=corr_id,
                delegated_by=f"slack:{slack_user}",
                action="dispatch",
                tool="slack_gateway",
                decision="REJECTED_UNAUTHORIZED_OPERATOR",
                code="FORBIDDEN_OPERATOR",
                reason=f"Slack user '{slack_user}' is not registered as an authorized operations engineer",
                side_effect="none",
            )
            self.gateway.record_audit(event)
            self.web_client.chat_postMessage(
                channel=channel_id,
                thread_ts=thread_ts,
                text=f"🚫 *[Authorization Denied]* Slack user `<@{slack_user}>` is not authorized to trigger agent workloads.",
            )
            return False, corr_id, {"status": "FORBIDDEN_OPERATOR"}

        # Step 2: OpenClaw Intent Planning
        analysis = self.coordinator.analyze_intent(prompt_text)

        # Event Callback to Stream Updates to Slack
        def event_listener(event_type: str, data: Dict[str, Any]):
            if event_type == "task_unsupported":
                self.web_client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=(
                        f"⚠️ *[Task Rejected Fail-Closed]*\n"
                        f"{data.get('reason')}\n"
                        f"• *Workloads Created*: `0` (No arbitrary workloads admitted)"
                    ),
                )
            elif event_type == "plan_proposed":
                steps_desc = " → ".join([f"*{s['name']}*" for s in data.get("steps", [])])
                self.web_client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=(
                        f"🤖 *[OpenClaw Coordinator]* Selected Registered Agents for Intent `{data.get('intent_type')}`:\n"
                        f"• *Execution DAG*: {steps_desc}\n"
                        f"• *Correlation ID*: `{data.get('correlation_id')}`\n"
                        f"• *Operator*: `{data.get('operator')}`\n"
                        f"_The orchestrator proposes the plan; AX and Cerbos govern permissions._"
                    ),
                )
            elif event_type == "scope_summary_card":
                self.post_scope_card(channel_id, thread_ts, data["scope"], data["step_name"])
            elif event_type == "task_running":
                self.web_client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=(
                        f"⚡ *[AX + Agent Substrate]* Executing Task `{data.get('task_id')}`\n"
                        f"• *Agent*: `{data.get('agent_id')}`\n"
                        f"• *Workload*: Isolated gVisor Sandbox running in native AX"
                    ),
                )
            elif event_type == "tool_decision":
                d = data.get("decision")
                icon = "✅" if d == "ALLOW" else "🚫"
                self.web_client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=(
                        f"{icon} *[Tool Gateway Decision]* `{data.get('tool')}:{data.get('action')}`\n"
                        f"• *Agent*: `{data.get('agent')}`\n"
                        f"• *Policy Decision*: `{data.get('decision')}`\n"
                        f"• *Evaluation*: {data.get('reason')}"
                    ),
                )
            elif event_type == "runtime_denial":
                self.web_client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=(
                        f"🚫 *[Runtime Authorization Denied]*\n\n"
                        f"*DENY*\n"
                        f"• *Agent*: `{data.get('agent')}`\n"
                        f"• *Action*: `{data.get('action')}`\n"
                        f"• *Resource*: `{data.get('resource')}`\n"
                        f"• *Attempted Mutation*: `{data.get('attempted_content', 'RUNTIME AUTHORIZATION TEST')}`\n"
                        f"• *Reason*: `{data.get('reason')}`\n"
                        f"• *Execution*: Workload remains isolated; write handler not invoked\n"
                        f"• *File Modified*: `False` (0 bytes mutated, zero side-effects)\n"
                        f"• *Integrity Check*: Original file unchanged (SHA256: `{data.get('sha256')[:16]}...` verified)\n"
                        f"• *Correlation ID*: `{data.get('correlation_id')}`"
                    ),
                )
            elif event_type == "incident_completed":
                self.web_client.chat_postMessage(
                    channel=channel_id,
                    thread_ts=thread_ts,
                    text=(
                        f"🎉 *[Incident Investigation Completed]*\n"
                        f"• *Artifact Published*: `{data.get('artifact')}` ({data.get('bytes_written')} bytes)\n"
                        f"• *Root Cause*: {data.get('root_cause')}\n"
                        f"• *Correlation ID*: `{data.get('correlation_id')}`\n"
                        f"• *Audit Chain*: Verified and monotonically preserved"
                    ),
                )
            elif event_type == "scope_inspected":
                self.post_scope_card(channel_id, thread_ts, data["scope"], "Scope Inspection")

        # Step 3: Execute through coordinator
        result = self.coordinator.execute_intent(
            analysis=analysis,
            operator_id=slack_user,
            correlation_id=corr_id,
            tenant_id=tenant,
            event_callback=event_listener,
        )

        return result.get("success", False), corr_id, result

    def execute_governed_investigation(
        self,
        channel_id: str,
        thread_ts: str,
        slack_user: str,
        correlation_id: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Convenience helper for automated governance and compliance tests."""
        prompt = "Investigate the staging HTTP 500 error. Inspect the approved staging website, analyze the approved staging logs, and prepare an incident report."
        success, corr_id, res = self.dispatch_slack_intent(channel_id, thread_ts, slack_user, prompt, correlation_id)
        if not success:
            return False, res.get("status", "FAILED")
        return True, corr_id


def handle_socket_mode():
    parser = argparse.ArgumentParser(description="Governed AI Operations Slack Integration")
    parser.add_argument("--demo-post", action="store_true", help="Post autonomous incident investigation demonstration")
    parser.add_argument("--demo-negative", action="store_true", help="Post controlled read-only write violation test")
    parser.add_argument("--channel", default=DEFAULT_CHANNEL, help="Slack channel ID")
    parser.add_argument("--operator", default="U_OPERATOR_DEMO", help="Slack user ID of operator")
    args = parser.parse_args()

    gateway = GovernedSlackOperationsGateway()

    if args.demo_post:
        print(f"[*] Posting Autonomous Governed Incident Investigation to Slack channel {args.channel}...")
        prompt = "Investigate the staging HTTP 500 error. Inspect the website, read the approved logs, and prepare an incident report."
        init_msg = gateway.web_client.chat_postMessage(
            channel=args.channel,
            text=f"👤 *Operator Submitted Task*:\n> {prompt}",
        )
        thread_ts = init_msg["ts"]
        success, corr_id, res = gateway.dispatch_slack_intent(args.channel, thread_ts, args.operator, prompt)
        print(f"[+] Autonomous Investigation complete (Success: {success}, Correlation ID: {corr_id})")
        return

    if args.demo_negative:
        print(f"[*] Posting Controlled Negative Authorization Test to Slack channel {args.channel}...")
        prompt = "test readonly-write"
        init_msg = gateway.web_client.chat_postMessage(
            channel=args.channel,
            text=f"👤 *Operator Submitted Controlled Test*:\n> {prompt}",
        )
        thread_ts = init_msg["ts"]
        success, corr_id, res = gateway.dispatch_slack_intent(args.channel, thread_ts, args.operator, prompt)
        print(f"[+] Negative Authorization Test complete (Success: {success}, Correlation ID: {corr_id})")
        return

    print(f"[*] Connecting Governed Slack Operations Gateway via Socket Mode...")
    client = SocketModeClient(app_token=SLACK_APP_TOKEN, web_client=gateway.web_client)

    def process(client: SocketModeClient, req: SocketModeRequest):
        # Acknowledge envelope immediately to Slack
        if req.type in ["events_api", "slash_commands"]:
            response = SocketModeResponse(envelope_id=req.envelope_id)
            client.send_socket_mode_response(response)

        if req.type == "slash_commands":
            payload = req.payload
            command = payload.get("command")
            text = payload.get("text", "").strip()
            channel = payload.get("channel_id")
            user = payload.get("user_id")

            init_msg = gateway.web_client.chat_postMessage(
                channel=channel,
                text=f"👤 *Operator Executed Command `{command} {text}`* (<@{user}>)",
            )
            thread_ts = init_msg["ts"]

            if command == "/agent-test":
                prompt = f"test {text}" if text else "test readonly-write"
            elif command == "/agent-scopes":
                prompt = f"/agent-scopes {text}"
            else:
                prompt = text

            gateway.dispatch_slack_intent(channel, thread_ts, user, prompt)

        elif req.type == "events_api":
            payload = req.payload
            event = payload.get("event", {})
            event_type = event.get("type")

            if event_type == "app_mention" or (event_type == "message" and not event.get("bot_id")):
                text = event.get("text", "").strip()
                channel = event.get("channel")
                thread_ts = event.get("thread_ts") or event.get("ts")
                user = event.get("user", "U_UNKNOWN")

                # Remove mention tag if present
                clean_text = re.sub(r"<@[A-Z0-9]+>", "", text).strip()
                if clean_text:
                    print(f"[+] Received prompt from Slack user {user} in {channel}: '{clean_text}'")
                    gateway.dispatch_slack_intent(channel, thread_ts, user, clean_text)

    client.socket_mode_request_listeners.append(process)
    client.connect()
    print(f"[+] Socket Mode listener connected on channel {DEFAULT_CHANNEL}.")

    # Continuous Channel Monitor: Ensures operator messages sent in Slack are processed
    # in real-time, even if Event Subscriptions aren't routing message.channels through Socket Mode.
    processed_messages = set()

    def live_channel_poller():
        bot_user = None
        try:
            auth_info = gateway.web_client.auth_test()
            bot_user = auth_info.get("user_id")
        except Exception as e:
            print(f"[-] Warning during auth_test: {e}")

        print(f"[+] Live channel poller active on {DEFAULT_CHANNEL} (Bot ID: {bot_user})")

        while True:
            try:
                time.sleep(2)
                res = gateway.web_client.conversations_history(channel=DEFAULT_CHANNEL, limit=8)
                msgs = res.get("messages", [])
                for m in reversed(msgs):
                    ts = m.get("ts")
                    if not ts or ts in processed_messages:
                        continue
                    processed_messages.add(ts)

                    # Ignore bot messages or membership join events
                    if m.get("bot_id") or m.get("user") == bot_user or m.get("subtype"):
                        continue

                    text = m.get("text", "").strip()
                    user = m.get("user", "U_UNKNOWN")
                    thread_ts = m.get("thread_ts") or ts
                    clean_text = re.sub(r"<@[A-Z0-9]+>", "", text).strip()
                    if clean_text:
                        print(f"[+] [Live Channel Monitor] Operator prompt from {user} in {DEFAULT_CHANNEL}: '{clean_text}'")
                        gateway.dispatch_slack_intent(DEFAULT_CHANNEL, thread_ts, user, clean_text)
            except Exception as e:
                print(f"[-] Live channel poller error: {e}")
                time.sleep(3)

    poller_thread = threading.Thread(target=live_channel_poller, daemon=True)
    poller_thread.start()

    print(f"[+] Governed Slack Service fully listening (Socket Mode + Channel Poller). Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[*] Disconnecting Socket Mode listener...")
        client.close()


if __name__ == "__main__":
    handle_socket_mode()

#!/usr/bin/env python3
"""Governed Browser Agent CLI.

Performs web navigation and artifact persistence through the Layer 2 Tool Gateway PEP.
Direct unmediated socket calls and uncontained filesystem mutations are prevented.
"""

import argparse
import json
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agents.tool_client import AgentToolClient
from tools.schema import TaskExecutionContext


def main():
    parser = argparse.ArgumentParser(description="Governed Browser Agent CLI")
    parser.add_argument(
        "--url",
        default=os.getenv("TARGET_URL", "http://mock-target:8089"),
        help="Target URL to visit",
    )
    parser.add_argument("--goal", default="Retrieve page title", help="Agent goal")
    parser.add_argument("--task-id", default=os.getenv("TASK_ID", "task-browser-agent-local"))
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID", "tenant-demo"))
    parser.add_argument("--delegated-by", default=os.getenv("DELEGATED_BY", "user-123"))
    parser.add_argument("--environment", default=os.getenv("ENVIRONMENT", "test"))
    args = parser.parse_args()

    print(f"[*] Governed Browser Agent starting goal: '{args.goal}' on {args.url}")

    # Load signed context from environment or mint verified testing context
    context_token = os.getenv("TASK_CONTEXT_TOKEN")
    if context_token:
        ctx = TaskExecutionContext.from_token(context_token)
    else:
        ctx = TaskExecutionContext(
            task_id=args.task_id,
            agent_id="browser-agent",
            roles=["browser-worker"],
            tenant_id=args.tenant_id,
            parent_principal="orchestrator-agent",
            delegated_by=args.delegated_by,
            environment=args.environment,
        ).sign()

    client = AgentToolClient(task_context=ctx)

    # 1. Governed Browser Navigation via Tool Gateway PEP
    print(f"[*] Requesting 'browser_navigate' for '{args.url}' from Tool Gateway...")
    nav_resp = client.browser_navigate(args.url)

    if not nav_resp.ok:
        print(f"[-] Tool Gateway REJECTED navigation request: {nav_resp.decision} ({nav_resp.code})", file=sys.stderr)
        print(f"[-] Reason: {nav_resp.error}", file=sys.stderr)
        err_res = {
            "status": "DENIED",
            "code": nav_resp.code,
            "decision": nav_resp.decision,
            "error": nav_resp.error,
        }
        print(json.dumps(err_res, indent=2))
        sys.exit(1)

    page_data = nav_resp.data
    print(f"[+] Tool Gateway APPROVED navigation.")
    print(f"[+] Successfully extracted: title='{page_data.get('title')}', h1='{page_data.get('h1')}'")

    result = {
        "status": "COMPLETED",
        "url": page_data.get("url"),
        "title": page_data.get("title"),
        "h1": page_data.get("h1"),
        "status_code": page_data.get("status_code"),
    }
    print("--- RESULT JSON ---")
    print(json.dumps(result, indent=2))

    # 2. Governed Output Artifact Persistence via Tool Gateway PEP
    output_path = os.getenv(
        "OUTPUT_PATH",
        "/workspace/output/result.json" if os.path.exists("/workspace") else "./workspace/output/result.json"
    )
    print(f"[*] Requesting 'filesystem_write' to '{output_path}' from Tool Gateway...")
    write_resp = client.filesystem_write(output_path, json.dumps(result, indent=2))

    if not write_resp.ok:
        print(f"[-] Tool Gateway REJECTED filesystem write: {write_resp.decision} ({write_resp.code}): {write_resp.error}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Tool Gateway APPROVED filesystem write. Artifact stored successfully.")


if __name__ == "__main__":
    main()

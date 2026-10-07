#!/usr/bin/env python3
"""Ultra-thin Orchestrator Agent resolving user goals and submitting execution requests to AX."""

import argparse
import os
import sys
from typing import Any, Dict, Optional
import yaml

from ax.adapter import AXAdmissionAdapter

DEFAULT_CAPABILITIES_PATH = os.path.join(
    os.path.dirname(__file__), "config/capabilities.yaml"
)


class OrchestratorAgent:
    """Ultra-thin orchestrator: plans, selects capability, and delegates to AX."""

    def __init__(
        self,
        principal: str = "orchestrator-agent",
        roles: Optional[list] = None,
        capabilities_path: str = DEFAULT_CAPABILITIES_PATH,
        adapter: Optional[AXAdmissionAdapter] = None,
    ):
        self.principal = principal
        self.roles = roles or ["orchestrator"]
        self.capabilities_path = capabilities_path
        self.capabilities = self._load_capabilities()
        self.adapter = adapter or AXAdmissionAdapter()

    def _load_capabilities(self) -> Dict[str, Any]:
        with open(self.capabilities_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("capabilities", {})

    def resolve_agent_for_task(self, prompt: str) -> Optional[str]:
        """Dynamically resolve required agent based on prompt keywords and capability mapping."""
        prompt_lower = prompt.lower()
        for cap_name, cap_meta in self.capabilities.items():
            for kw in cap_meta.get("keywords", []):
                if kw in prompt_lower:
                    return cap_meta.get("agent")
        # Default fallback if specified
        return None

    def execute_user_task(
        self,
        prompt: str,
        target_agent: Optional[str] = None,
        action: str = "execute",
    ) -> Dict[str, Any]:
        print(f"\n[ORCHESTRATOR] Received User Task: '{prompt}'")

        # Step 1: Select agent dynamically
        selected_agent = target_agent or self.resolve_agent_for_task(prompt)
        if not selected_agent:
            print("[ORCHESTRATOR] Could not resolve capability for task.", file=sys.stderr)
            return {"status": "FAILED", "error": "No capability matched"}

        print(f"[ORCHESTRATOR] Plan: 1. Resolved agent '{selected_agent}'. 2. Request execution via AX.")

        # Step 2: Formulate generic execution request
        execution_request = {
            "principal": self.principal,
            "roles": self.roles,
            "agent": selected_agent,
            "action": action,
            "task": {"prompt": prompt},
            "context": {"environment": "lab", "source": "orchestrator"},
        }

        # Step 3: Delegate to AX runtime boundary
        print(f"[ORCHESTRATOR] Submitting execution request to AX for '{selected_agent}'...")
        trace = self.adapter.submit_execution_request(
            principal=execution_request["principal"],
            roles=execution_request["roles"],
            agent_name=execution_request["agent"],
            action=execution_request["action"],
            task_data=execution_request["task"],
            context=execution_request["context"],
        )

        if trace["status"] == "COMPLETED":
            print(f"[ORCHESTRATOR] Task completed successfully via '{selected_agent}'.")
        else:
            print(f"[ORCHESTRATOR] Task execution terminated with status: {trace['status']}.")

        return trace


def main():
    parser = argparse.ArgumentParser(description="Orchestrator Agent CLI")
    parser.add_argument("prompt", nargs="?", default="Visit website and retrieve page title", help="User task prompt")
    parser.add_argument("--principal", default="orchestrator-agent", help="Caller principal ID")
    parser.add_argument("--role", default="orchestrator", help="Caller role")
    parser.add_argument("--agent", default=None, help="Explicit target agent override")
    args = parser.parse_args()

    orchestrator = OrchestratorAgent(principal=args.principal, roles=[args.role])
    orchestrator.execute_user_task(prompt=args.prompt, target_agent=args.agent)


if __name__ == "__main__":
    main()

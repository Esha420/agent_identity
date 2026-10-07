#!/usr/bin/env python3
"""Thin AX Admission Adapter connecting Orchestrator intent, Cerbos PDP, and native AX/Substrate."""

import json
import os
import subprocess
import tempfile
import time
import uuid
from typing import Any, Dict, Optional, Tuple
import yaml

from ax.cerbos_client import CerbosClient

DEFAULT_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "../agents/catalog.yaml")
DEFAULT_AX_BIN = os.path.join(os.path.dirname(__file__), "../bin/ax")


class AXAdmissionAdapter:
    """Thin admission adapter enforcing Cerbos policy checks before native AX task creation."""

    def __init__(
        self,
        cerbos_url: Optional[str] = None,
        catalog_path: str = DEFAULT_CATALOG_PATH,
        ax_bin: str = DEFAULT_AX_BIN,
    ):
        self.cerbos = CerbosClient(base_url=cerbos_url) if cerbos_url else CerbosClient()
        self.catalog_path = catalog_path
        self.ax_bin = ax_bin
        self.catalog = self._load_catalog()

    def _load_catalog(self) -> Dict[str, Any]:
        with open(self.catalog_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("agents", {})

    def submit_execution_request(
        self,
        principal: str,
        roles: list,
        agent_name: str,
        action: str = "execute",
        task_data: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        wait_timeout: int = 40,
    ) -> Dict[str, Any]:
        """
        Admit, authorize, and materialize agent execution workload into native AX.
        
        FAIL-CLOSED: If Cerbos returns anything other than EFFECT_ALLOW,
        ZERO tasks are submitted to AX and ZERO workloads touch Substrate.
        """
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        task_data = task_data or {}
        context = context or {}

        # Step 1: Authorization Decision via Cerbos PDP
        allowed, decision, cerbos_raw = self.cerbos.authorize(
            request_id=req_id,
            principal_id=principal,
            roles=roles,
            resource_id=agent_name,
            action=action,
            context=context,
        )

        trace = {
            "request_id": req_id,
            "principal": principal,
            "roles": roles,
            "agent": agent_name,
            "action": action,
            "context": context,
            "cerbos_decision": decision,
            "ax_decision": "PENDING",
            "substrate_workload": "NONE",
            "agent_result": None,
            "status": "UNKNOWN",
        }

        # Step 2: Enforce Authorization Gate
        if not allowed or decision != "ALLOW":
            trace["ax_decision"] = "REJECTED"
            trace["substrate_workload"] = "NO WORKLOAD CREATED"
            trace["agent_result"] = f"Authorization denied by policy: {decision}"
            trace["status"] = "DENIED"
            self._print_trace(trace)
            return trace

        # Step 3: Authorized Path -> Resolve agent from declarative catalog
        if agent_name not in self.catalog:
            trace["ax_decision"] = "REJECTED_UNKNOWN_AGENT"
            trace["substrate_workload"] = "NO WORKLOAD CREATED"
            trace["agent_result"] = f"Agent '{agent_name}' not found in catalog"
            trace["status"] = "FAILED"
            self._print_trace(trace)
            return trace

        agent_meta = self.catalog[agent_name]
        image = agent_meta["runtime"]["image"]
        base_cmd = list(agent_meta["runtime"]["command"])

        # Append task-specific args if requested
        if "args" in task_data:
            base_cmd.extend(task_data["args"])

        trace["ax_decision"] = "ACCEPTED"
        task_name = f"task-{agent_name[:12]}-{uuid.uuid4().hex[:6]}"

        # Step 4: Materialize workload into native AX via 'ax apply'
        task_manifest = {
            "apiVersion": "ax.v1alpha1",
            "kind": "Task",
            "metadata": {
                "name": task_name,
                "atespace": "default",
            },
            "spec": {
                "image": image,
                "command": base_cmd,
            },
        }

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
                yaml.dump(task_manifest, tf)
                tf_path = tf.name

            # Native AX CLI invocation
            apply_res = subprocess.run(
                [self.ax_bin, "apply", "-f", tf_path],
                capture_output=True,
                text=True,
                check=False,
            )
            os.remove(tf_path)

            if apply_res.returncode != 0:
                trace["substrate_workload"] = "FAILED_APPLY"
                trace["agent_result"] = f"ax apply failed: {apply_res.stderr.strip()}"
                trace["status"] = "ERROR"
                self._print_trace(trace)
                return trace

            trace["substrate_workload"] = f"created:{task_name}"

            # Step 5: Await reconciliation on Substrate worker
            start_time = time.time()
            final_phase = "Pending"
            worker_ip = None

            while time.time() - start_time < wait_timeout:
                desc_res = subprocess.run(
                    [self.ax_bin, "describe", "task", task_name],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                output = desc_res.stdout
                for line in output.splitlines():
                    if line.startswith("Phase:"):
                        final_phase = line.split(":", 1)[1].strip()
                    if line.startswith("Worker IP:"):
                        worker_ip = line.split(":", 1)[1].strip()

                if final_phase in ["Running", "Completed", "Failed"]:
                    break
                time.sleep(1.5)

            trace["substrate_workload"] = f"actor:{task_name} (ip: {worker_ip or 'assigned'}, phase: {final_phase})"
            trace["status"] = "COMPLETED" if final_phase in ["Running", "Completed"] else "FAILED"
            trace["agent_result"] = {
                "task_name": task_name,
                "worker_ip": worker_ip,
                "phase": final_phase,
                "capability": agent_meta.get("capabilities", []),
            }

            # Graceful cleanup of task in AX & Substrate
            subprocess.run([self.ax_bin, "delete", "task", task_name], capture_output=True, check=False)

        except Exception as e:
            trace["status"] = "ERROR"
            trace["agent_result"] = str(e)

        self._print_trace(trace)
        return trace

    def _print_trace(self, t: Dict[str, Any]):
        sep = "-" * 80
        print(sep)
        print(f"Request ID:       {t['request_id']}")
        print(f"Principal:        {t['principal']} (roles: {t.get('roles', [])})")
        print(f"Target Agent:     {t['agent']}")
        print(f"Action:           {t['action']}")
        print(f"Cerbos Decision:  {t['cerbos_decision']}")
        print(f"AX Decision:      {t['ax_decision']}")
        print(f"Substrate State:  {t['substrate_workload']}")
        print(f"Execution Status: {t['status']}")
        print(f"Result:           {json.dumps(t['agent_result'])}")
        print(sep)


if __name__ == "__main__":
    adapter = AXAdmissionAdapter()
    print("Testing Authorized Execution:")
    adapter.submit_execution_request(
        principal="orchestrator-agent",
        roles=["orchestrator"],
        agent_name="browser-agent",
        action="execute",
    )
    print("\nTesting Denied Execution:")
    adapter.submit_execution_request(
        principal="untrusted-agent",
        roles=["untrusted"],
        agent_name="browser-agent",
        action="execute",
    )

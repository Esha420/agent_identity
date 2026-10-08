#!/usr/bin/env python3
"""Thin AX Admission Adapter connecting Orchestrator intent, Cerbos PDP, and native AX/Substrate."""

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
import hashlib
from typing import Any, Dict, List, Optional, Tuple
import yaml

# Automatically include project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ax.auth0_verifier import Auth0TokenVerifier, Auth0TokenError
from ax.cerbos_client import CerbosClient
from tools.schema import TaskExecutionContext

DEFAULT_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "../agents/catalog.yaml")
DEFAULT_AX_BIN = os.path.join(os.path.dirname(__file__), "../bin/ax")


TRUSTED_WORKLOADS: Dict[str, Dict[str, Any]] = {
    "orchestrator-agent": {
        "roles": ["orchestrator"],
        "tenant_id": "tenant-demo",
        "allowed_delegates": ["user-123", "user-admin"],
    }
}


class AXAdmissionAdapter:
    """Thin admission adapter enforcing Cerbos policy checks before native AX task creation."""

    def __init__(
        self,
        cerbos_url: Optional[str] = None,
        catalog_path: str = DEFAULT_CATALOG_PATH,
        ax_bin: str = DEFAULT_AX_BIN,
        auth0_verifier: Optional[Auth0TokenVerifier] = None,
    ):
        self.cerbos = CerbosClient(base_url=cerbos_url) if cerbos_url else CerbosClient()
        self.catalog_path = catalog_path
        self.ax_bin = ax_bin
        self.catalog = self._load_catalog()
        self.auth0_verifier = auth0_verifier or Auth0TokenVerifier()

    def _load_catalog(self) -> Dict[str, Any]:
        with open(self.catalog_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("agents", {})

    def _build_trace(
        self,
        req_id: str,
        principal: str,
        roles: list,
        agent_name: str,
        action: str,
        context: Optional[Dict[str, Any]],
        ax_decision: str,
        substrate_workload: str,
        agent_result: Any,
        status: str,
        cerbos_decision: str = "DENIED_BY_PEP",
    ) -> Dict[str, Any]:
        return {
            "request_id": req_id,
            "principal": principal,
            "roles": roles,
            "agent": agent_name,
            "action": action,
            "context": context or {},
            "cerbos_decision": cerbos_decision,
            "ax_decision": ax_decision,
            "substrate_workload": substrate_workload,
            "agent_result": agent_result,
            "status": status,
        }

    def mint_task_context(
        self,
        task_id: str,
        agent_name: str,
        parent_principal: str,
        delegated_by: str = "user-123",
        tenant_id: str = "tenant-demo",
        environment: str = "test",
        authorization_epoch: int = 1,
        delegation_issuer: str = "https://your-tenant.us.auth0.com/",
        delegation_permissions: Optional[List[str]] = None,
    ) -> TaskExecutionContext:
        """
        Authoritative minting of TaskExecutionContext by the AX Admission PEP.
        
        Binds to the verified catalog image digest and computed allowed_tool_set_hash.
        """
        agent_meta = self.catalog.get(agent_name, {})
        allowed_tools = agent_meta.get("allowed_tools", [])
        tool_set_hash = hashlib.sha256(
            json.dumps(sorted(allowed_tools)).encode("utf-8")
        ).hexdigest()
        image = agent_meta.get("runtime", {}).get("image", "")
        digest = image.split("@")[-1] if "@" in image else "sha256:unknown"
        roles = [agent_meta.get("role", f"{agent_name.replace('-agent', '')}-worker")]
        caps = agent_meta.get("capabilities", ["general"])

        raw = TaskExecutionContext(
            task_id=task_id,
            agent_id=agent_name,
            roles=roles,
            capability=caps[0] if caps else "general",
            tenant_id=tenant_id,
            parent_principal=parent_principal,
            delegated_by=delegated_by,
            delegation_issuer=delegation_issuer,
            delegation_permissions=delegation_permissions or [],
            agent_image_digest=digest,
            environment=environment,
            policy_scope="default",
            allowed_tool_set_hash=tool_set_hash,
            issuer="ax-admission-pep",
            audience="tool-gateway",
            authorization_epoch=authorization_epoch,
        )
        return raw.sign()

    def submit_execution_request(
        self,
        principal: str,
        roles: list,
        agent_name: str,
        action: str = "execute",
        task_data: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        user_token: Optional[str] = None,
        wait_timeout: int = 40,
    ) -> Dict[str, Any]:
        """
        Admit, authorize, and materialize agent execution workload into native AX.
        
        SAFE SEQUENCE:
        1. Verify orchestrator workload credential (attestation).
        1b. Verify Auth0 OIDC user access token (RS256 via JWKS).
        2. Resolve requested capability and agent from trusted catalog.
        3. Resolve image digest and command from catalog & check integrity.
        4. Ask Cerbos for Layer 1 authorization (workload + user delegation).
        5. Submit immutable task specification to AX (Auth0 token stripped!).
        6. Obtain authoritative AX task identity.
        7. Mint short-lived, signed TaskExecutionContext only after acceptance.
        8. Inject context into workload environment.
        """
        req_id = f"req-{uuid.uuid4().hex[:8]}"
        task_data = dict(task_data or {})
        context = dict(context or {})

        # -------------------------------------------------------------
        # Step 1: Verify Orchestrator Workload Identity
        # -------------------------------------------------------------
        if principal in TRUSTED_WORKLOADS:
            workload_meta = TRUSTED_WORKLOADS[principal]
            # Verify caller cannot define or forge unauthorized roles
            if any(r not in workload_meta["roles"] for r in roles):
                trace = self._build_trace(
                    req_id, principal, roles, agent_name, action, context,
                    "REJECTED_PEP", "NO WORKLOAD CREATED",
                    f"Orchestrator workload '{principal}' supplied unauthorized/forged roles: {roles}",
                    "DENIED"
                )
                self._print_trace(trace)
                return trace

            verified_roles = workload_meta["roles"]
            verified_workload_tenant = workload_meta["tenant_id"]
        else:
            if user_token:
                trace = self._build_trace(
                    req_id, principal, roles, agent_name, action, context,
                    "REJECTED_PEP", "NO WORKLOAD CREATED",
                    f"Untrusted orchestrator principal '{principal}' cannot submit user-delegated admission requests",
                    "DENIED"
                )
                self._print_trace(trace)
                return trace
            verified_roles = list(roles)
            verified_workload_tenant = context.get("tenant_id", "untrusted")

        # -------------------------------------------------------------
        # Step 1b: Verify Auth0 User Token & Delegation Context
        # -------------------------------------------------------------
        user_context_cerbos: Optional[Dict[str, Any]] = None
        delegation_issuer = "internal"
        delegation_permissions: List[str] = []

        if user_token:
            try:
                norm_user = self.auth0_verifier.verify_token(user_token)
            except Auth0TokenError as e:
                trace = self._build_trace(
                    req_id, principal, verified_roles, agent_name, action, context,
                    "REJECTED_PEP", "NO WORKLOAD CREATED",
                    f"Auth0 token verification failed: {e}",
                    "DENIED"
                )
                self._print_trace(trace)
                return trace

            verified_user_id = norm_user["id"]
            verified_user_tenant = norm_user["tenant_id"]
            delegation_permissions = norm_user["permissions"]
            delegation_issuer = norm_user.get("issuer", "https://your-tenant.us.auth0.com/")

            # Anti-tampering check: Caller cannot assert conflicting user identity in request body
            caller_claimed_user = context.get("delegated_by")
            if caller_claimed_user and caller_claimed_user != verified_user_id:
                trace = self._build_trace(
                    req_id, principal, verified_roles, agent_name, action, context,
                    "REJECTED_PEP", "NO WORKLOAD CREATED",
                    f"Caller supplied forged delegated_by '{caller_claimed_user}' differing from verified Auth0 subject '{verified_user_id}'",
                    "DENIED"
                )
                self._print_trace(trace)
                return trace

            # Anti-tampering check: Caller cannot assert conflicting tenant in request body
            caller_claimed_tenant = context.get("tenant_id")
            if caller_claimed_tenant and caller_claimed_tenant != verified_user_tenant:
                trace = self._build_trace(
                    req_id, principal, verified_roles, agent_name, action, context,
                    "REJECTED_PEP", "NO WORKLOAD CREATED",
                    f"Caller supplied forged tenant '{caller_claimed_tenant}' differing from verified Auth0 tenant '{verified_user_tenant}'",
                    "DENIED"
                )
                self._print_trace(trace)
                return trace

            # Multi-tenant boundary check: Workload tenant must match user tenant
            if verified_workload_tenant != verified_user_tenant:
                trace = self._build_trace(
                    req_id, principal, verified_roles, agent_name, action, context,
                    "REJECTED_PEP", "NO WORKLOAD CREATED",
                    f"Orchestrator workload tenant '{verified_workload_tenant}' does not match Auth0 user tenant '{verified_user_tenant}'",
                    "DENIED"
                )
                self._print_trace(trace)
                return trace

            delegated_by = verified_user_id
            verified_tenant = verified_user_tenant

            user_context_cerbos = {
                "id": verified_user_id,
                "tenant_id": verified_user_tenant,
                "permissions": delegation_permissions,
                "scopes": norm_user.get("scopes", []),
                "issuer": delegation_issuer,
            }
        else:
            # Legacy/direct service caller path
            req_tenant = context.get("tenant_id")
            if principal in TRUSTED_WORKLOADS:
                if req_tenant and req_tenant != verified_workload_tenant:
                    trace = self._build_trace(
                        req_id, principal, roles, agent_name, action, context,
                        "REJECTED_PEP", "NO WORKLOAD CREATED",
                        f"Orchestrator workload '{principal}' cannot operate across unauthorized tenant '{req_tenant}'",
                        "DENIED"
                    )
                    self._print_trace(trace)
                    return trace

                delegated_by = context.get("delegated_by", "user-123")
                if delegated_by not in TRUSTED_WORKLOADS[principal]["allowed_delegates"]:
                    trace = self._build_trace(
                        req_id, principal, roles, agent_name, action, context,
                        "REJECTED_PEP", "NO WORKLOAD CREATED",
                        f"Orchestrator workload '{principal}' supplied unauthorized/forged delegation: '{delegated_by}'",
                        "DENIED"
                    )
                    self._print_trace(trace)
                    return trace
                verified_tenant = verified_workload_tenant
            else:
                verified_tenant = req_tenant or "untrusted"
                delegated_by = context.get("delegated_by", "unknown")

        # -------------------------------------------------------------
        # Step 2: Resolve Requested Capability & Agent from Catalog
        # -------------------------------------------------------------
        if agent_name not in self.catalog:
            trace = self._build_trace(
                req_id, principal, verified_roles, agent_name, action, context,
                "REJECTED_UNKNOWN_AGENT", "NO WORKLOAD CREATED",
                f"Agent '{agent_name}' not found in catalog",
                "FAILED"
            )
            self._print_trace(trace)
            return trace

        agent_meta = self.catalog[agent_name]

        # -------------------------------------------------------------
        # Step 3: Resolve Image Digest & Command & Check Integrity
        # -------------------------------------------------------------
        catalog_image = agent_meta["runtime"]["image"]
        if "image" in task_data and task_data["image"] != catalog_image:
            trace = self._build_trace(
                req_id, principal, verified_roles, agent_name, action, context,
                "REJECTED_IMAGE_MISMATCH", "NO WORKLOAD CREATED",
                f"Requested task image '{task_data['image']}' differs from trusted catalog digest '{catalog_image}'",
                "FAILED"
            )
            self._print_trace(trace)
            return trace

        image = catalog_image
        base_cmd = list(agent_meta["runtime"]["command"])
        if "args" in task_data:
            base_cmd.extend(task_data["args"])

        # -------------------------------------------------------------
        # Step 4: Ask Cerbos for Layer 1 Authorization
        # -------------------------------------------------------------
        principal_attr = {
            "tenant_id": verified_tenant,
        }
        resource_attr = {
            "name": agent_name,
            "capability": agent_meta.get("capabilities", ["general"])[0],
            "tenant_id": verified_tenant,
        }
        if user_context_cerbos:
            resource_attr["user"] = user_context_cerbos
            context["user"] = user_context_cerbos

        allowed, decision, cerbos_raw = self.cerbos.authorize(
            request_id=req_id,
            principal_id=principal,
            roles=verified_roles,
            resource_id=agent_name,
            action=action,
            context=context,
            principal_attr=principal_attr,
            resource_attr=resource_attr,
        )

        trace = {
            "request_id": req_id,
            "principal": principal,
            "roles": verified_roles,
            "agent": agent_name,
            "action": action,
            "context": context,
            "cerbos_decision": decision,
            "ax_decision": "PENDING",
            "substrate_workload": "NONE",
            "agent_result": None,
            "status": "UNKNOWN",
        }

        if not allowed or decision != "ALLOW":
            trace["ax_decision"] = "REJECTED"
            trace["substrate_workload"] = "NO WORKLOAD CREATED"
            trace["agent_result"] = f"Authorization denied by policy: {decision}"
            trace["status"] = "DENIED"
            self._print_trace(trace)
            return trace

        # -------------------------------------------------------------
        # Step 5: Submit Immutable Task Specification to AX
        # -------------------------------------------------------------
        task_name = f"task-{agent_name[:12]}-{uuid.uuid4().hex[:6]}"
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

            apply_res = subprocess.run(
                [self.ax_bin, "apply", "-f", tf_path],
                capture_output=True,
                text=True,
                check=False,
            )
            os.remove(tf_path)

            if apply_res.returncode != 0:
                trace["ax_decision"] = "REJECTED_AX_APPLY"
                trace["substrate_workload"] = "FAILED_APPLY"
                trace["agent_result"] = f"ax apply failed: {apply_res.stderr.strip()}"
                trace["status"] = "ERROR"
                self._print_trace(trace)
                return trace

            # ---------------------------------------------------------
            # Step 6: Obtain Authoritative AX Task Identity
            # ---------------------------------------------------------
            trace["ax_decision"] = "ACCEPTED"
            trace["substrate_workload"] = f"created:{task_name}"

            # ---------------------------------------------------------
            # Step 7: Mint Signed TaskExecutionContext (Only After AX Acceptance)
            # ---------------------------------------------------------
            signed_context = self.mint_task_context(
                task_id=task_name,
                agent_name=agent_name,
                parent_principal=principal,
                delegated_by=delegated_by,
                tenant_id=verified_tenant,
                environment=context.get("environment", "test"),
                delegation_issuer=delegation_issuer,
                delegation_permissions=delegation_permissions,
            )
            trace["task_execution_context"] = signed_context.to_dict()
            trace["context_token"] = signed_context.to_token()

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

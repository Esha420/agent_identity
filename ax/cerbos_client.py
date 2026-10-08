"""Cerbos Policy Decision Point client enforcing fail-closed authorization."""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_CERBOS_URL = os.getenv("CERBOS_HTTP_URL", "http://localhost:3592")


class CerbosClient:
    """Client for interacting with Cerbos PDP."""

    def __init__(self, base_url: str = DEFAULT_CERBOS_URL, timeout: float = 3.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def check_health(self) -> bool:
        """Check if Cerbos PDP is healthy and serving."""
        try:
            req = urllib.request.Request(
                f"{self.base_url}/_cerbos/health",
                headers={"Accept": "application/json"},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") == "SERVING"
        except Exception:
            return False

    def authorize(
        self,
        request_id: str,
        principal_id: str,
        roles: List[str],
        resource_id: str,
        resource_kind: str = "agent",
        action: str = "execute",
        context: Dict[str, Any] = None,
        principal_attr: Optional[Dict[str, Any]] = None,
        resource_attr: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Evaluate authorization for a given principal, resource, and action.
        
        Returns:
            Tuple of (is_allowed: bool, decision: str, raw_response: dict)
            Guaranteed FAIL-CLOSED on error or timeout.
        """
        context = context or {}
        p_attr = principal_attr if principal_attr is not None else context
        r_attr = resource_attr if resource_attr is not None else {"name": resource_id, **context}

        payload = {
            "requestId": request_id,
            "principal": {
                "id": principal_id,
                "roles": roles,
                "attr": p_attr,
            },
            "resources": [
                {
                    "resource": {
                        "id": resource_id,
                        "kind": resource_kind,
                        "attr": r_attr,
                    },
                    "actions": [action],
                }
            ],
        }

        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/check/resources",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return False, "ERROR_FAIL_CLOSED", {"error": f"HTTP status {resp.status}"}

                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])
                if not results:
                    return False, "DENY", {"error": "Empty evaluation result"}

                first_res = results[0]
                actions = first_res.get("actions", {})
                effect = actions.get(action, "EFFECT_DENY")

                if effect == "EFFECT_ALLOW":
                    return True, "ALLOW", data
                else:
                    return False, "DENY", data

        except urllib.error.URLError as e:
            # FAIL-CLOSED: PDP unreachable / connection refused / timeout
            return False, "ERROR_FAIL_CLOSED", {"error": f"Cerbos unreachable: {e}"}
        except Exception as e:
            # FAIL-CLOSED: Unhandled parse or socket error
            return False, "ERROR_FAIL_CLOSED", {"error": f"Authorization error: {e}"}

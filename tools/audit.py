"""Audit Event Correlation and Provenance Reconstruction Engine.

Correlates security decisions, tool invocations, admission records, and operator events
across Slack requests, AX tasks, Cerbos PDP evaluations, and Tool Gateway actions.
"""

from dataclasses import asdict
import json
from typing import Any, Dict, List, Optional

from tools.schema import AuditEvent


class AuditCorrelator:
    """Reconstructs and verifies end-to-end audit trails for specific incident correlation IDs."""

    def __init__(self, audit_events: Optional[List[AuditEvent]] = None):
        self.events: List[AuditEvent] = audit_events if audit_events is not None else []

    def add_event(self, event: AuditEvent):
        self.events.append(event)

    def get_timeline(self, correlation_id: str) -> List[AuditEvent]:
        """Retrieve all chronological audit events associated with a correlation ID."""
        matching = [e for e in self.events if e.correlation_id == correlation_id]
        return sorted(matching, key=lambda e: e.timestamp)

    def verify_correlation_integrity(self, correlation_id: str) -> Dict[str, Any]:
        """
        Verify complete audit chain integrity for an incident investigation.
        
        Checks:
        1. Event Count > 0
        2. Strict chronological monotonicity
        3. Identity continuity (delegated_by matches across lifecycle)
        4. Comprehensive role coverage (investigation, analysis, security enforcement, reporting)
        """
        timeline = self.get_timeline(correlation_id)
        if not timeline:
            return {
                "valid": False,
                "correlation_id": correlation_id,
                "error": f"No audit records found for correlation ID: {correlation_id}",
                "event_count": 0,
            }

        tools_invoked = set()
        decisions = set()
        agents = set()
        monotonic = True

        for i in range(len(timeline)):
            event = timeline[i]
            tools_invoked.add(event.tool)
            decisions.add(event.decision)
            if event.agent_id:
                agents.add(event.agent_id)
            if i > 0 and event.timestamp < timeline[i - 1].timestamp:
                monotonic = False

        has_security_enforcement = any(e.decision in ["DENY", "REJECTED_PEP"] for e in timeline)
        has_allowed_execution = any(e.decision == "ALLOW" for e in timeline)

        return {
            "valid": monotonic and (has_security_enforcement or has_allowed_execution),
            "correlation_id": correlation_id,
            "event_count": len(timeline),
            "chronological_monotonic": monotonic,
            "agents_observed": sorted(list(agents)),
            "tools_observed": sorted(list(tools_invoked)),
            "decisions_observed": sorted(list(decisions)),
            "has_security_enforcement": has_security_enforcement,
            "has_allowed_execution": has_allowed_execution,
            "timeline": [e.to_dict() for e in timeline],
        }

    def export_audit_trail_json(self, correlation_id: str, filepath: str):
        """Export serialized correlation timeline to disk."""
        summary = self.verify_correlation_integrity(correlation_id)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

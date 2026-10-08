"""Agent Tool Client providing structured, governed tool access through the Tool Gateway PEP."""

import os
from typing import Any, Dict, Optional
import uuid

from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest, ToolInvocationResponse


class AgentToolClient:
    """Client used by agent scripts inside the workload to request governed tool execution."""

    def __init__(
        self,
        task_context: Optional[TaskExecutionContext] = None,
        gateway: Optional[ToolGatewayPEP] = None,
    ):
        self.gateway = gateway or ToolGatewayPEP()
        self.task_context = task_context or self._load_default_context()

    def _load_default_context(self) -> TaskExecutionContext:
        """Infer or load task context from environment."""
        return TaskExecutionContext(
            task_id=os.getenv("TASK_ID", f"task-{uuid.uuid4().hex[:8]}"),
            agent_id=os.getenv("AGENT_ID", "browser-agent"),
            roles=[os.getenv("AGENT_ROLE", "browser-worker")],
            tenant_id=os.getenv("TENANT_ID", "tenant-demo"),
            parent_principal=os.getenv("PARENT_PRINCIPAL", "orchestrator-agent"),
            delegated_by=os.getenv("DELEGATED_BY", "user-123"),
            environment=os.getenv("ENVIRONMENT", "test"),
        )

    def fetch_url(self, url: str, method: str = "GET") -> ToolInvocationResponse:
        """Request governed HTTP fetch through Tool Gateway PEP."""
        req = ToolInvocationRequest(
            request_id=f"tool-fetch-{uuid.uuid4().hex[:8]}",
            task_context=self.task_context,
            tool_name="fetch_url",
            action="request",
            arguments={"url": url, "method": method},
        )
        return self.gateway.invoke(req)

    def browser_navigate(self, url: str) -> ToolInvocationResponse:
        """Request governed browser navigation through Tool Gateway PEP."""
        req = ToolInvocationRequest(
            request_id=f"tool-nav-{uuid.uuid4().hex[:8]}",
            task_context=self.task_context,
            tool_name="browser_navigate",
            action="navigate",
            arguments={"url": url},
        )
        return self.gateway.invoke(req)

    def filesystem_read(self, path: str) -> ToolInvocationResponse:
        """Request governed filesystem read through Tool Gateway PEP."""
        req = ToolInvocationRequest(
            request_id=f"tool-read-{uuid.uuid4().hex[:8]}",
            task_context=self.task_context,
            tool_name="filesystem_read",
            action="read",
            arguments={"path": path},
        )
        return self.gateway.invoke(req)

    def filesystem_write(self, path: str, content: str) -> ToolInvocationResponse:
        """Request governed filesystem write through Tool Gateway PEP."""
        req = ToolInvocationRequest(
            request_id=f"tool-write-{uuid.uuid4().hex[:8]}",
            task_context=self.task_context,
            tool_name="filesystem_write",
            action="write",
            arguments={"path": path, "content": content},
        )
        return self.gateway.invoke(req)

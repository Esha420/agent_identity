"""Model Context Protocol (MCP) Streamable HTTP & JSON-RPC Tool Server.

Exposes only catalog-governed tools (fetch_url, browser_navigate, filesystem_read, filesystem_write)
behind the ToolGatewayPEP boundary with mandatory Bearer token verification and zero side-effects on denial.
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List, Optional
import urllib.parse
import yaml

# Automatically include project root in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools.gateway import ToolGatewayPEP
from tools.schema import TaskExecutionContext, ToolInvocationRequest, ToolInvocationResponse
from ax.cerbos_client import CerbosClient

DEFAULT_CATALOG_PATH = os.path.join(os.path.dirname(__file__), "catalog.yaml")


class MCPToolHandler:
    """Core MCP Tool Registry and Invocation Processor."""

    def __init__(
        self,
        gateway: Optional[ToolGatewayPEP] = None,
        catalog_path: str = DEFAULT_CATALOG_PATH,
    ):
        self.gateway = gateway or ToolGatewayPEP()
        self.catalog_path = catalog_path
        self.tools = self._load_catalog()

    def _load_catalog(self) -> Dict[str, Any]:
        with open(self.catalog_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("tools", {})

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return MCP-compliant tool definitions from authoritative catalog."""
        result = []
        for name, meta in self.tools.items():
            result.append({
                "name": name,
                "description": meta.get("description", ""),
                "action": meta.get("action", ""),
                "side_effect": meta.get("side_effect", "none"),
                "inputSchema": {
                    "type": "object",
                    "properties": meta.get("schema", {}),
                },
            })
        return result

    def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        context_token: str,
        request_id: Optional[str] = None,
    ) -> ToolInvocationResponse:
        """Route tool invocation through ToolGatewayPEP with strict context verification."""
        if not context_token:
            return ToolInvocationResponse(
                ok=False,
                code="UNAUTHENTICATED",
                request_id=request_id or "mcp-req",
                tool=name,
                decision="REJECTED_PEP",
                side_effect="none",
                error="Missing required Bearer TaskExecutionContext token",
            )

        tool_meta = self.tools.get(name, {})
        action = tool_meta.get("action", "execute")

        req = ToolInvocationRequest(
            request_id=request_id,
            task_context=context_token,
            tool_name=name,
            action=action,
            arguments=arguments,
        )

        return self.gateway.invoke(req)


class MCPHTTPServerHandler(BaseHTTPRequestHandler):
    handler_instance: Optional[MCPToolHandler] = None

    def _send_json(self, status: int, data: Any):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/tools" or parsed.path == "/mcp/v1/tools":
            tools = self.handler_instance.list_tools()
            self._send_json(200, {"tools": tools})
        elif parsed.path == "/health":
            self._send_json(200, {"status": "ok", "service": "mcp-tool-server"})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            req_data = json.loads(body)
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON payload: {e}"})
            return

        # Extract Bearer token from Authorization header or payload
        auth_hdr = self.headers.get("Authorization", "")
        token = ""
        if auth_hdr.startswith("Bearer "):
            token = auth_hdr.split("Bearer ", 1)[1].strip()
        elif "context_token" in req_data:
            token = req_data.get("context_token", "")

        # Support JSON-RPC 2.0 or direct REST tool dispatch
        if "method" in req_data:
            method = req_data.get("method")
            rpc_id = req_data.get("id", 1)
            if method == "tools/list":
                tools = self.handler_instance.list_tools()
                self._send_json(200, {"jsonrpc": "2.0", "id": rpc_id, "result": {"tools": tools}})
            elif method == "tools/call":
                params = req_data.get("params", {})
                name = params.get("name")
                args = params.get("arguments", {})
                tok = token or params.get("context_token", "")
                resp = self.handler_instance.call_tool(name, args, tok, request_id=f"rpc-{rpc_id}")
                if resp.ok:
                    self._send_json(200, {"jsonrpc": "2.0", "id": rpc_id, "result": resp.to_dict()})
                else:
                    self._send_json(403 if resp.decision == "DENY" else 400, {
                        "jsonrpc": "2.0",
                        "id": rpc_id,
                        "error": {"code": -32000, "message": resp.error, "data": resp.to_dict()}
                    })
            else:
                self._send_json(400, {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32601, "message": f"Method '{method}' not found"}})
            return

        # Direct REST: /tools/{name}/invoke
        if parsed.path.startswith("/tools/") and parsed.path.endswith("/invoke"):
            tool_name = parsed.path.split("/tools/")[1].split("/invoke")[0]
            args = req_data.get("arguments", {})
            resp = self.handler_instance.call_tool(tool_name, args, token, request_id=req_data.get("request_id"))
            self._send_json(200 if resp.ok else 403, resp.to_dict())
            return

        self._send_json(404, {"error": "Not Found"})


def create_mcp_server(port: int = 8095) -> HTTPServer:
    handler = MCPToolHandler()
    MCPHTTPServerHandler.handler_instance = handler
    server = HTTPServer(("0.0.0.0", port), MCPHTTPServerHandler)
    return server


if __name__ == "__main__":
    port = int(os.getenv("MCP_PORT", 8095))
    server = create_mcp_server(port)
    print(f"[*] MCP Tool Gateway Server listening on port {port}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down MCP Server.")
        server.server_close()

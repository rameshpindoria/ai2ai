"""Stdio MCP server for provider A's Claude Code agent. It is the ONLY thing Claude Code can reach.
It holds no keys: every tool call is forwarded to the provider runtime's local bridge (127.0.0.1 + session secret),
which uses the SDK (and the provider's agent key) to talk to the customer's edge.
Env: AI2AI_BRIDGE_URL, AI2AI_BRIDGE_SECRET."""
import json
import os
import sys
import urllib.request

PROTOCOL_FALLBACK = "2025-06-18"
_OBJ = {"type": "object", "properties": {}, "additionalProperties": False}
TOOLS = [
    {"name": "list_operations",
     "description": "List the operations available in the customer's environment, with their class "
                    "(read / reversible / security / destructive / egress) and parameters.", "inputSchema": _OBJ},
    {"name": "read", "description": "Run a read operation and get the result (customer data, wrapped as untrusted).",
     "inputSchema": {"type": "object", "properties": {"op": {"type": "string"}, "args": {"type": "object"}},
                     "required": ["op"]}},
    {"name": "request_change",
     "description": "Request ONE reversible change. The customer's human sees the exact change and approves or declines "
                    "it with their passkey. This call waits for the decision.",
     "inputSchema": {"type": "object", "properties": {"op": {"type": "string"}, "args": {"type": "object"},
                                                      "reason": {"type": "string"}}, "required": ["op", "args", "reason"]}},
    {"name": "escalate_to_human",
     "description": "Hand the issue to a person when the right fix is above what you are allowed to do, or unclear.",
     "inputSchema": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]}},
    {"name": "report_resolution",
     "description": "Finish the job: a short summary plus findings for the customer's report.",
     "inputSchema": {"type": "object", "properties": {"summary": {"type": "string"}, "findings": {"type": "array", "items": {
         "type": "object", "properties": {"severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                                          "text": {"type": "string"}}, "required": ["severity", "text"]}}},
                     "required": ["summary"]}},
]
TOOL_NAMES = {t["name"] for t in TOOLS}


class McpCore:
    def __init__(self, forward):
        self.forward = forward

    def handle(self, msg):
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            return None
        if method == "initialize":
            v = (msg.get("params") or {}).get("protocolVersion") or PROTOCOL_FALLBACK
            return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": v, "capabilities": {"tools": {}},
                                                           "serverInfo": {"name": "ai2ai-provider-a", "version": "1.0"}}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": mid, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
        if method == "tools/call":
            p = msg.get("params") or {}
            if p.get("name") not in TOOL_NAMES:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
            try:
                out = self.forward(p["name"], p.get("arguments") or {})
            except Exception as exc:
                out = {"text": f"runtime error: {exc}", "is_error": True}
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": out["text"]}],
                                                           "isError": bool(out["is_error"])}}
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def http_forward(url, secret):
    def forward(tool, args):
        req = urllib.request.Request(url, method="POST", data=json.dumps({"tool": tool, "args": args}).encode(),
                                     headers={"Content-Type": "application/json", "X-Bridge-Secret": secret})
        with urllib.request.urlopen(req, timeout=900) as r:
            return json.loads(r.read())
    return forward


def main():
    core = McpCore(http_forward(os.environ["AI2AI_BRIDGE_URL"], os.environ["AI2AI_BRIDGE_SECRET"]))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            out = core.handle(json.loads(line))
        except json.JSONDecodeError:
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if out is not None:
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()

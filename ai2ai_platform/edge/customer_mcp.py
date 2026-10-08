"""Customer-side MCP server: lets the customer's OWN AI assistant (e.g. Claude) use the platform.

Tools: find_providers, request_service, job_status, get_result. There is deliberately no approve tool: drafting a
Work Order returns a link, and only a signed-in person with their passkey can approve it on the edge.
Env: AI2AI_CENTRE_URL, AI2AI_EDGE_URL, AI2AI_ASSISTANT_TOKEN (scoped: draft + read only).
Run with: python -m ai2ai_platform.edge.customer_mcp
Text written by providers (listings, summaries, findings, escalation reasons) is wrapped as untrusted before it
reaches the customer's assistant."""
import json
import os
import sys

from ..core.untrusted import wrap_untrusted

PROTOCOL_FALLBACK = "2025-06-18"
TOOLS = [
    {"name": "find_providers", "description": "Find verified providers for an IT issue described in plain words.",
     "inputSchema": {"type": "object", "properties": {"issue": {"type": "string"},
                                                      "level": {"type": "string", "enum": ["D1", "D2"]}},
                     "required": ["issue"]}},
    {"name": "request_service",
     "description": "Draft a Work Order for a provider's agent. It is NOT approved: a person must approve it with their "
                    "passkey at the link returned.",
     "inputSchema": {"type": "object", "properties": {"agent_id": {"type": "string"}, "ticket": {"type": "string"},
                                                      "level": {"type": "string", "enum": ["D1", "D2"]}},
                     "required": ["agent_id", "ticket"]}},
    {"name": "job_status", "description": "Status of a job, including any change waiting for a person's approval.",
     "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}},
    {"name": "get_result", "description": "Findings, changes made and the signed receipt summary of a finished job.",
     "inputSchema": {"type": "object", "properties": {"job_id": {"type": "string"}}, "required": ["job_id"]}},
]
TOOL_NAMES = {t["name"] for t in TOOLS}


def make_forward(http, centre_url, edge_url, token):
    auth = {"Authorization": f"Bearer {token}"}

    def forward(tool, args):
        if tool == "find_providers":
            r = http.get(f"{centre_url}/api/v1/match", params={"q": args.get("issue", ""), "level": args.get("level", "D2")})
            m = r.json().get("matches", [])
            if not m:
                return {"text": "No verified provider offers this yet.", "is_error": False}
            listing = [{"agent_id": x["agent_id"], "title": x["title"], "provider": x["provider"], "level": x["level"],
                        "badges": x["badges"], "price_text": x["price_text"]} for x in m[:5]]
            return {"text": "Verified providers (titles and prices are written by providers):\n"
                            + wrap_untrusted(listing, source="marketplace-listings"), "is_error": False}
        if tool == "request_service":
            r = http.post(f"{edge_url}/edge/api/assistant/jobs", headers=auth,
                          json={"agent_id": args.get("agent_id", ""), "ticket": args.get("ticket", ""),
                                "level": args.get("level", "D2")})
            if r.status_code != 201:
                return {"text": f"Could not draft: {r.json().get('detail')}", "is_error": True}
            j = r.json()
            return {"text": f"Work Order {j['wo_id']} drafted (job {j['id']}). It is NOT approved. A person must open "
                            f"{j['approve_at']} and approve it with their passkey. You cannot approve it.",
                    "is_error": False}
        if tool in ("job_status", "get_result"):
            r = http.get(f"{edge_url}/edge/api/assistant/jobs/{args.get('job_id', '')}", headers=auth)
            if r.status_code != 200:
                return {"text": f"Not available: {r.json().get('detail')}", "is_error": True}
            v = r.json()
            if tool == "job_status":
                text = f"Status: {v['status']} with {v['provider']} at {v['level']}."
                if v["pending"]:
                    text += (" Waiting for a person to approve: " + ", ".join(p["op"] for p in v["pending"])
                             + ". Details chosen by the provider's agent:\n"
                             + wrap_untrusted([{"op": p["op"], "args": p["args"]} for p in v["pending"]],
                                              source="provider-agent"))
                if v["escalated"]:
                    text += " Escalated to a person. The provider's reason:\n" + wrap_untrusted(
                        v["escalation_reason"], source="provider-agent")
                return {"text": text, "is_error": False}
            if not v["receipt"]:
                return {"text": "No result yet.", "is_error": False}
            rec = v["receipt"]["payload"]
            st = rec["provider_statement"]["payload"]
            changes = [f"Change made (recorded by the customer's edge): {c['op']}" for c in rec["changes_made"]]
            if changes:
                changes.append("Details of those changes (arguments chosen by the provider's agent):\n"
                               + wrap_untrusted([{"op": c["op"], "args": c["args"]} for c in rec["changes_made"]],
                                                source="provider-agent"))
            report = {"summary": st.get("summary", ""), "findings": st.get("findings", [])}
            return {"text": "\n".join(changes or ["No changes were made."])
                            + "\nThe provider's own report (written by the provider's agent):\n"
                            + wrap_untrusted(report, source="provider-agent"), "is_error": False}
        return {"text": f"Unknown tool {tool}", "is_error": True}
    return forward


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
                                                           "serverInfo": {"name": "ai2ai-customer", "version": "1.0"}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
        if method == "tools/call":
            p = msg.get("params") or {}
            if p.get("name") not in TOOL_NAMES:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
            try:
                out = self.forward(p["name"], p.get("arguments") or {})
            except Exception as exc:
                out = {"text": f"error: {exc}", "is_error": True}
            return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": out["text"]}],
                                                           "isError": out["is_error"]}}
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}


def main():
    import httpx
    core = McpCore(make_forward(httpx.Client(timeout=30), os.environ["AI2AI_CENTRE_URL"].rstrip("/"),
                                os.environ["AI2AI_EDGE_URL"].rstrip("/"), os.environ["AI2AI_ASSISTANT_TOKEN"]))
    for line in sys.stdin:
        if line.strip():
            out = core.handle(json.loads(line))
            if out is not None:
                sys.stdout.write(json.dumps(out) + "\n")
                sys.stdout.flush()


if __name__ == "__main__":
    main()

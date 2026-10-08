"""Provider-side A2A v1.0.1 server (part of the SDK). A provider runs it on ITS OWN infrastructure so the customer's
edge can push a job directly instead of the provider polling the centre.

- GET  /.well-known/agent-card.json   provider-signed (org key) A2A card built from the provider's listing
- POST /a2a                           JSON-RPC: SendMessage, GetTask, CancelTask

Security:
- Every call must carry an `AI2AI-Caller` header: an envelope signed by the customer edge's BROKER key over
  {type: A2ACall, method, ref, nonce, ts}. ref = the Work Order id (SendMessage) or the task id (GetTask/CancelTask).
- The provider never trusts a caller-supplied address. It asks the centre (signed with its org key) for the job's
  registered edge URL and broker public key, and only for jobs routed to this provider.
- Task ids are random; each task is bound to the edge broker key that created it.
- Work still cannot start unless the edge issues a token, i.e. a human approved the Work Order with a passkey."""
import json
import secrets
import threading
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..core.a2a import (A2A_VERSION, ALLOWED, EXTENSION_REQUIRED, EXTENSION_URI, INTERRUPTED, INVALID_PARAMS,
                        INVALID_REQUEST, METHOD_NOT_FOUND, TASK_NOT_CANCELABLE, TASK_NOT_FOUND, TERMINAL,
                        UNSUPPORTED_OPERATION, VERSION_NOT_SUPPORTED, TaskStateMachine, card_from_listing, rpc_error,
                        sign_card)
from ..core.crypto import SignatureError, verify_with_public
from .client import EdgeSession, JobContext, SdkError

UNAUTHENTICATED = -32010  # application-defined: caller signature missing or invalid
MAX_SKEW = 120


class _Task:
    def __init__(self, wo_id, context_id, edge_url, broker_kid, broker_pub):
        self.id = "task-" + secrets.token_urlsafe(12)
        self.wo_id, self.context_id, self.edge_url = wo_id, context_id, edge_url
        self.broker_kid, self.broker_pub = broker_kid, broker_pub
        self.sm = TaskStateMachine()
        self.sm.move("TASK_STATE_SUBMITTED")
        self.ctx, self.outcome, self.done = None, None, False  # outcome: rejected | failed | canceled


def create_provider_a2a_app(org_key, agent_id, agent_key, agent, bundle, http_for_edge, public_url, centre,
                            poll_interval=0.2):
    """centre: an sdk.client.CentreClient for this provider (used for trusted job lookups)."""
    app = FastAPI(title="Provider A2A endpoint", docs_url=None, redoc_url=None, openapi_url=None)
    tasks, by_wo, seen, lock = {}, {}, {}, threading.Lock()
    threads, stopping = [], threading.Event()

    @app.get("/.well-known/agent-card.json")
    def card():
        return sign_card(card_from_listing(bundle, f"{public_url}/a2a"), org_key)

    def caller(request, method, ref, broker_kid, broker_pub):
        try:
            env = json.loads(request.headers.get("AI2AI-Caller", ""))
            p = verify_with_public(env, broker_pub, expected_kid=broker_kid)
        except (ValueError, SignatureError, TypeError):
            return "caller signature missing or invalid"
        if p.get("type") != "A2ACall" or p.get("method") != method or p.get("ref") != ref:
            return "caller signature does not match this call"
        n, ts = p.get("nonce"), p.get("ts")
        if not isinstance(n, str) or not isinstance(ts, (int, float)) or abs(time.time() - ts) > MAX_SKEW:
            return "stale caller signature"
        now = time.time()
        with lock:
            for k in [k for k, t in seen.items() if now - t > 4 * MAX_SKEW]:
                del seen[k]
            if n in seen:
                return "replayed call"
            seen[n] = now
        return None

    def state_of(t: _Task):
        if t.outcome == "canceled":
            new = "TASK_STATE_CANCELED"
        elif t.outcome == "rejected":
            new = "TASK_STATE_REJECTED"
        elif t.outcome == "failed":
            new = "TASK_STATE_FAILED"
        elif t.done:
            new = "TASK_STATE_COMPLETED"
        elif t.ctx is not None and t.ctx.waiting_for_approval:
            new = "TASK_STATE_INPUT_REQUIRED"
        elif t.ctx is not None:
            new = "TASK_STATE_WORKING"
        else:
            new = t.sm.state
        if new != t.sm.state and new not in ALLOWED.get(t.sm.state, set()) \
                and "TASK_STATE_WORKING" in ALLOWED.get(t.sm.state, set()) and new in ALLOWED["TASK_STATE_WORKING"]:
            t.sm.move("TASK_STATE_WORKING")  # a status check can miss the brief working state in between
        t.sm.move(new)
        return new

    MESSAGES = {"TASK_STATE_REJECTED": "The customer's edge did not grant access to this Work Order.",
                "TASK_STATE_FAILED": "The job stopped before completing.",
                "TASK_STATE_CANCELED": "The job was cancelled."}

    def task_json(t: _Task):
        st = state_of(t)
        out = {"id": t.id, "contextId": t.context_id,
               "status": {"state": st, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
               "metadata": {"workOrderId": t.wo_id}}
        if st == "TASK_STATE_INPUT_REQUIRED":
            out["status"]["message"] = {"messageId": f"msg-{t.id}-approval", "role": "ROLE_AGENT", "taskId": t.id,
                                        "contextId": t.context_id, "extensions": [EXTENSION_URI],
                                        "parts": [{"text": "Waiting for the customer to approve a change with their passkey."},
                                                  {"data": {"approvalUrl": f"{t.edge_url}/edge/"},
                                                   "mediaType": "application/json"}]}
        if st in MESSAGES:
            out["status"]["message"] = {"messageId": f"msg-{t.id}-end", "role": "ROLE_AGENT", "taskId": t.id,
                                        "contextId": t.context_id, "parts": [{"text": MESSAGES[st]}]}
        if st == "TASK_STATE_COMPLETED" and t.ctx is not None and t.ctx.receipt:
            out["artifacts"] = [{"artifactId": "receipt", "name": "AI2AI signed receipt", "extensions": [EXTENSION_URI],
                                 "parts": [{"data": t.ctx.receipt, "mediaType": "application/json"}]}]
        return out

    def run(t: _Task):
        try:
            session = EdgeSession(http_for_edge(t.edge_url), t.edge_url, agent_key, t.wo_id, poll_interval=poll_interval)
            t.ctx = JobContext(session)
            t.ctx.stop_requested = stopping.is_set()
        except SdkError:
            t.outcome = "rejected"
            return
        try:
            agent.handle(t.ctx)
            if not t.ctx.completed:
                t.ctx.complete("agent finished without a summary")
            t.done = True
        except SdkError as exc:
            t.outcome = "canceled" if ("cancel" in str(exc) or "kill switch" in str(exc)) else "failed"

    @app.post("/a2a")
    async def rpc(request: Request):
        try:
            req = await request.json()
        except Exception:
            return JSONResponse(rpc_error(None, -32700, "Parse error"))
        mid = req.get("id") if isinstance(req, dict) else None
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
            return JSONResponse(rpc_error(mid, INVALID_REQUEST, "Invalid Request"))
        if request.headers.get("A2A-Version") != A2A_VERSION:
            return JSONResponse(rpc_error(mid, VERSION_NOT_SUPPORTED, "VersionNotSupportedError",
                                          {"supported": [A2A_VERSION]}))
        method, params = req["method"], req.get("params") or {}
        if method == "SendMessage":
            exts = [e.strip() for e in request.headers.get("A2A-Extensions", "").split(",") if e.strip()]
            if EXTENSION_URI not in exts:
                return JSONResponse(rpc_error(mid, EXTENSION_REQUIRED, "ExtensionSupportRequiredError",
                                              {"required": EXTENSION_URI}))
            msg = params.get("message") or {}
            data = next((p.get("data") for p in msg.get("parts", []) if isinstance(p, dict) and isinstance(p.get("data"), dict)), None)
            if not msg.get("messageId") or msg.get("role") != "ROLE_USER" or not data or not data.get("workOrderId") \
                    or data.get("agentId") != agent_id:
                return JSONResponse(rpc_error(mid, INVALID_PARAMS, "Invalid params",
                                              {"reason": "need messageId, ROLE_USER and a data part with workOrderId "
                                                         "and this agent's agentId"}))
            wo_id = str(data["workOrderId"])
            try:
                facts = centre.lookup(wo_id)  # trusted: edge URL + broker key from the centre's registry
            except SdkError:
                return JSONResponse(rpc_error(mid, INVALID_PARAMS, "Invalid params",
                                              {"reason": "this Work Order is not routed to this provider"}))
            if facts["agent_id"] != agent_id:
                return JSONResponse(rpc_error(mid, INVALID_PARAMS, "Invalid params", {"reason": "wrong agent"}))
            why = caller(request, "SendMessage", wo_id, facts["broker_kid"], facts["broker_public_key"])
            if why:
                return JSONResponse(rpc_error(mid, UNAUTHENTICATED, "Unauthenticated", {"reason": why}))
            with lock:
                t = tasks.get(by_wo.get(wo_id))
                if t is None:
                    t = _Task(wo_id, msg.get("contextId") or f"ctx-{secrets.token_urlsafe(8)}",
                              facts["edge_url"].rstrip("/"), facts["broker_kid"], facts["broker_public_key"])
                    tasks[t.id], by_wo[wo_id] = t, t.id
                    th = threading.Thread(target=run, args=(t,), daemon=True)
                    threads.append(th)
                    th.start()
            if not (params.get("configuration") or {}).get("returnImmediately"):
                end = time.time() + 30
                while time.time() < end and state_of(t) not in TERMINAL | INTERRUPTED:
                    time.sleep(0.05)
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {"task": task_json(t)}})
        if method in ("GetTask", "CancelTask"):
            t = tasks.get(str(params.get("id", "")))
            if t is None:
                return JSONResponse(rpc_error(mid, TASK_NOT_FOUND, "TaskNotFoundError"))
            why = caller(request, method, t.id, t.broker_kid, t.broker_pub)
            if why:  # only the edge that created the task may read or cancel it
                return JSONResponse(rpc_error(mid, TASK_NOT_FOUND, "TaskNotFoundError"))
            if method == "GetTask":
                return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": task_json(t)})
            if state_of(t) in TERMINAL:
                return JSONResponse(rpc_error(mid, TASK_NOT_CANCELABLE, "TaskNotCancelableError"))
            if t.ctx is not None:
                t.ctx.stop_requested = True
            t.outcome = t.outcome or "canceled"
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": task_json(t)})
        if method in ("SendStreamingMessage", "SubscribeToTask", "GetExtendedAgentCard"):
            return JSONResponse(rpc_error(mid, UNSUPPORTED_OPERATION, "UnsupportedOperationError"))
        return JSONResponse(rpc_error(mid, METHOD_NOT_FOUND, "Method not found"))

    def shutdown(timeout=10):
        """Ask every running job to stop, then wait for its thread (call on service stop; tests call it)."""
        stopping.set()
        for t in list(tasks.values()):
            if t.ctx is not None:
                t.ctx.stop_requested = True
        for th in list(threads):
            th.join(timeout)

    app.state.tasks = tasks
    app.state.shutdown = shutdown
    return app

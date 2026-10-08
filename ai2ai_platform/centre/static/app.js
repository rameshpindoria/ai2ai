// Centre client. All text goes in with textContent, never as HTML.
const $ = s => document.querySelector(s);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };

async function api(path, body, csrf, method) {
  const headers = {"Content-Type": "application/json"};
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const r = await fetch(path, {method: method || "POST", headers, body: JSON.stringify(body || {}), credentials: "same-origin"});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof j.detail === "string" ? j.detail : "Request failed (" + r.status + ")");
  return j;
}
async function get(path) {
  const r = await fetch(path, {credentials: "same-origin"});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof j.detail === "string" ? j.detail : "Request failed (" + r.status + ")");
  return j;
}
function formData(form) { return Object.fromEntries(new FormData(form).entries()); }
function item(list, main, sub, actions) {
  const li = el("li", "item");
  const t = el("div", "item-text"); t.append(el("strong", null, main)); if (sub) t.append(el("span", "muted", sub));
  li.append(t);
  if (actions) { const a = el("div", "item-actions"); actions.forEach(x => a.append(x)); li.append(a); }
  list.append(li);
}
function empty(list, text) { list.replaceChildren(el("li", "muted", text)); }
function badge(text, kind) { return el("span", "badge " + (kind || ""), text); }

function wireAuthForms() {
  const err = $("#form-error");
  const login = $("#login-form");
  if (login) login.addEventListener("submit", async e => {
    e.preventDefault(); err.textContent = "";
    try { await api("/api/v1/auth/login", formData(login)); location.href = "/app"; } catch (x) { err.textContent = x.message; }
  });
  const signup = $("#signup-form");
  if (signup) signup.addEventListener("submit", async e => {
    e.preventDefault(); err.textContent = "";
    const d = formData(signup); if (!d.business_reg) delete d.business_reg;
    try { await api("/api/v1/auth/signup", d); await api("/api/v1/auth/login", {email: d.email, password: d.password}); location.href = "/app"; }
    catch (x) { err.textContent = x.message; }
  });
  const out = $("#logout");
  if (out) out.addEventListener("click", async () => { try { await api("/api/v1/auth/logout", {}, out.dataset.csrf); } finally { location.href = "/login"; } });
}

// ---------------- customer ----------------
async function customer(csrf, role) {
  let edgeUrl = null;
  try { edgeUrl = (await get("/api/v1/customer/edge")).base_url; } catch (x) { /* members may not see it */ }
  $("#edge-status").textContent = edgeUrl ? "Your edge: " + edgeUrl + ". Approvals and job details live there." :
    "No edge registered yet. Your administrator registers it once; jobs then run through it.";
  const ef = $("#edge-form");
  if (ef && !edgeUrl) {
    ef.hidden = false;
    ef.addEventListener("submit", async e => {
      e.preventDefault();
      try { await api("/api/v1/customer/edge", {base_url: $("#edge-url").value.trim(), broker_public_key: $("#edge-key").value.trim()}, csrf); location.reload(); }
      catch (x) { $("#dash-error").textContent = x.message; }
    });
  }
  $("#match-form").addEventListener("submit", async e => {
    e.preventDefault();
    const level = $("#match-level").value;
    const list = $("#matches"); list.replaceChildren();
    try {
      const r = await get("/api/v1/match?q=" + encodeURIComponent($("#q").value) + "&level=" + level);
      $("#match-cats").textContent = "Looks like: " + r.categories.slice(0, 3).join(", ");
      if (!r.matches.length) return empty(list, "No verified provider offers this yet.");
      r.matches.forEach(m => {
        const go = el("a", "button primary", "Request on my edge");
        let edge = null;
        try { edge = new URL(edgeUrl); } catch (x) { edge = null; }
        if (edge && (edge.protocol === "https:" || edge.protocol === "http:")) {
          go.href = edge.origin + "/edge/new?agent=" + encodeURIComponent(m.agent_id) + "&level=" + encodeURIComponent(level);
        } else { go.removeAttribute("href"); go.setAttribute("aria-disabled", "true"); }
        const meta = m.provider + " · " + m.level + " · " + (m.price_text || "price on request") + " · " + m.completed_jobs + (m.completed_jobs === 1 ? " job" : " jobs") + " completed";
        item(list, m.title, meta, [...m.badges.map(b => badge(b + " ✓", "ok")), go]);
      });
    } catch (x) { $("#dash-error").textContent = x.message; }
  });
  const jl = $("#cust-jobs");
  const jobs = await get("/api/v1/customer/jobs");
  if (!jobs.length) empty(jl, "No jobs yet.");
  jobs.forEach(j => item(jl, j.wo_id, j.status + (j.outcome && j.outcome !== j.status ? " · " + j.outcome : "") + " · " + j.level,
    [badge(j.receipt_digest ? "receipt " + j.receipt_digest.slice(0, 10) : "no receipt yet", j.receipt_digest ? "ok" : "")]));
}

// ---------------- provider ----------------
async function provider(csrf) {
  const refresh = async () => {
    const p = await get("/api/v1/provider/profile");
    $("#prov-status").textContent = "Status: " + p.status + (p.review_note ? " · note: " + p.review_note : "") +
      (p.business_reg ? " · Reg. " + p.business_reg : " · add your business registration number");
    const ev = $("#evidence"); ev.replaceChildren(); if (!p.evidence.length) empty(ev, "No evidence yet.");
    p.evidence.forEach(e => item(ev, e.kind, e.reference + " · " + e.issuer + " · expires " + e.expires_on));
    const ks = $("#keys"); ks.replaceChildren(); if (!p.keys.length) empty(ks, "No keys yet.");
    p.keys.forEach(k => item(ks, k.purpose, k.kid, [badge(k.revoked ? "revoked" : "active", k.revoked ? "bad" : "ok")]));
    p.credentials.forEach(c => item(ev, "Verified: " + c.kind, c.id, [badge(c.revoked ? "revoked" : "valid", c.revoked ? "bad" : "ok")]));
    $("#submit-review").disabled = !["draft", "rejected"].includes(p.status);
    const agents = await get("/api/v1/provider/agents");
    const al = $("#agents"); al.replaceChildren(); if (!agents.length) empty(al, "No agents yet.");
    const sel = $("#svc-agent"); sel.replaceChildren();
    agents.forEach(a => {
      const w = el("button", null, "Withdraw");
      w.disabled = a.status === "withdrawn";
      w.onclick = async () => { await api("/api/v1/provider/agents/" + a.id + "/withdraw", {}, csrf); refresh(); };
      item(al, a.name + " " + a.version, a.id, [badge(a.status, a.status === "listed" ? "ok" : ""), w]);
      if (a.status !== "withdrawn") { const o = el("option", null, a.name + " " + a.version); o.value = a.id; sel.append(o); }
    });
    const sv = await get("/api/v1/provider/services");
    const sl = $("#services"); sl.replaceChildren(); if (!sv.length) empty(sl, "No services yet.");
    sv.forEach(s => item(sl, s.title, s.category + " · " + s.level + " · " + (s.price_text || "")));
    const us = await get("/api/v1/provider/usage");
    const ul = $("#usage"); ul.replaceChildren(); if (!us.length) empty(ul, "No jobs yet.");
    us.forEach(u => item(ul, u.agent_id, u.jobs + " jobs · " + u.completed + " completed · " + u.canceled + " canceled · " + u.changes + " changes"));
  };
  const guard = fn => async e => { e.preventDefault(); $("#dash-error").textContent = ""; try { await fn(); await refresh(); } catch (x) { $("#dash-error").textContent = x.message; } };
  $("#evidence-form").addEventListener("submit", guard(() => api("/api/v1/provider/evidence", {kind: $("#ev-kind").value, reference: $("#ev-ref").value, issuer: $("#ev-issuer").value, expires_on: $("#ev-exp").value}, csrf)));
  $("#key-form").addEventListener("submit", guard(() => api("/api/v1/provider/keys", {purpose: $("#key-purpose").value, public_key: $("#key-pub").value.trim()}, csrf)));
  $("#submit-review").addEventListener("click", guard(() => api("/api/v1/provider/submit", {}, csrf)));
  $("#agent-form").addEventListener("submit", guard(() => api("/api/v1/provider/agents", {card: JSON.parse($("#card-json").value)}, csrf)));
  $("#service-form").addEventListener("submit", guard(() => api("/api/v1/provider/services", {agent_id: $("#svc-agent").value, title: $("#svc-title").value, category: $("#svc-cat").value.trim(), level: $("#svc-level").value, price_text: $("#svc-price").value}, csrf)));
  await refresh();
}

// ---------------- platform admin ----------------
async function admin(csrf) {
  const refresh = async () => {
    const pend = await get("/api/v1/admin/providers?status=submitted");
    const pl = $("#pending-providers"); pl.replaceChildren(); if (!pend.length) empty(pl, "Nothing waiting.");
    pend.forEach(p => {
      const ok = el("button", "primary", "Approve"), no = el("button", null, "Reject");
      const note = el("input"); note.placeholder = "Reason if rejecting"; note.setAttribute("aria-label", "Rejection reason");
      ok.onclick = async () => { await api("/api/v1/admin/providers/" + p.org_id + "/decision", {decision: "approve"}, csrf); refresh(); };
      no.onclick = async () => { await api("/api/v1/admin/providers/" + p.org_id + "/decision", {decision: "reject", note: note.value || "Evidence could not be verified"}, csrf); refresh(); };
      item(pl, p.name + (p.business_reg ? " · Reg. " + p.business_reg : ""), p.evidence.map(e => e.kind + " " + e.reference + " (" + e.issuer + ", " + e.expires_on + ")").join("; "), [note, ok, no]);
    });
    const orgs = await get("/api/v1/admin/orgs");
    const ol = $("#orgs"); ol.replaceChildren();
    orgs.forEach(o => {
      const b = el("button", null, o.status === "active" ? "Suspend" : "Reactivate");
      b.disabled = o.kind === "platform";
      b.onclick = async () => { await api("/api/v1/admin/orgs/" + o.id + "/status", {status: o.status === "active" ? "suspended" : "active"}, csrf); refresh(); };
      item(ol, o.name, o.kind + " · " + o.users + " users", [badge(o.status, o.status === "active" ? "ok" : "bad"), b]);
    });
    const us = await get("/api/v1/admin/usage");
    const ul = $("#admin-usage"); ul.replaceChildren(); if (!us.length) empty(ul, "No jobs yet.");
    us.forEach(u => item(ul, u.agent_id, u.jobs + " jobs · " + u.completed + " completed · " + u.changes + " changes"));
    const au = await get("/api/v1/admin/audit");
    $("#audit-status").textContent = (au.chain_ok ? "Chain intact" : "CHAIN BROKEN at #" + au.first_bad_seq) + " · " + au.events.length + " recent events";
  };
  await refresh();
}

document.addEventListener("DOMContentLoaded", () => {
  wireAuthForms();
  const d = $("#dash");
  if (!d) return;
  const run = {customer, provider, platform: admin}[d.dataset.kind];
  run(d.dataset.csrf, d.dataset.role).catch(x => { $("#dash-error").textContent = x.message; });
});

// Customer edge client: passkey ceremonies (WebAuthn) and the live job view. Text only via textContent.
const $ = s => document.querySelector(s);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const b64uToBuf = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0)).buffer;
const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
let CSRF = "";

async function post(path, body) {
  const headers = {"Content-Type": "application/json"};
  if (CSRF) headers["X-CSRF-Token"] = CSRF;
  const r = await fetch(path, {method: "POST", headers, body: JSON.stringify(body || {}), credentials: "same-origin"});
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
function showError(x) { const e = $("#form-error"); if (e) e.textContent = x.message || String(x); }

function assertionJSON(a) {
  return {id: a.id, rawId: bufToB64u(a.rawId), type: a.type,
    response: {clientDataJSON: bufToB64u(a.response.clientDataJSON), authenticatorData: bufToB64u(a.response.authenticatorData),
      signature: bufToB64u(a.response.signature), userHandle: a.response.userHandle ? bufToB64u(a.response.userHandle) : null},
    clientExtensionResults: {}};
}
async function passkeyAssert(optionsPath) {
  const o = JSON.parse((await post(optionsPath)).options);
  o.challenge = b64uToBuf(o.challenge);
  (o.allowCredentials || []).forEach(c => c.id = b64uToBuf(c.id));
  return assertionJSON(await navigator.credentials.get({publicKey: o}));
}

async function enrol(code) {
  const o = JSON.parse((await post("/edge/api/enrol/options", {code})).options);
  o.challenge = b64uToBuf(o.challenge); o.user.id = b64uToBuf(o.user.id);
  (o.excludeCredentials || []).forEach(c => c.id = b64uToBuf(c.id));
  const c = await navigator.credentials.create({publicKey: o});
  await post("/edge/api/enrol/finish", {code, credential: {id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
    response: {clientDataJSON: bufToB64u(c.response.clientDataJSON), attestationObject: bufToB64u(c.response.attestationObject)},
    clientExtensionResults: {}}});
  await login();
}
async function login() {
  const o = JSON.parse((await post("/edge/api/login/options")).options);
  o.challenge = b64uToBuf(o.challenge);
  const a = await navigator.credentials.get({publicKey: o});
  await post("/edge/api/login/finish", {credential: assertionJSON(a)});
  location.href = "/edge/";
}

async function jobsPage() {
  const list = $("#jobs");
  const jobs = await get("/edge/api/jobs");
  if (!jobs.length) list.replaceChildren(el("li", "muted", "No jobs yet. Choose a provider on the marketplace to start one."));
  jobs.forEach(j => {
    const li = el("li", "item");
    const a = el("a", null, j.wo_id + " · " + j.provider); a.href = "/edge/jobs/" + j.id;
    const t = el("div", "item-text"); t.append(a, el("span", "muted", j.ticket));
    li.append(t, el("span", "badge", j.status + " · " + j.level));
    list.append(li);
  });
}

async function newPage(root) {
  $("#level").value = root.dataset.level === "D1" ? "D1" : "D2";
  let jobId = null;
  $("#ticket-form").addEventListener("submit", async e => {
    e.preventDefault();
    try {
      const r = await post("/edge/api/jobs", {agent_id: root.dataset.agent, ticket: $("#ticket").value, level: $("#level").value});
      jobId = r.id;
      const wo = r.work_order, dl = $("#wo-fields"); dl.replaceChildren();
      [["Provider", wo.provider_name], ["Agent version", wo.agent_version], ["Level", wo.level],
       ["Agent may", wo.allowed_classes.join(" and ") + " actions"], ["Approvals", wo.approvers.join(" + ")],
       ["Valid until", new Date(wo.window_end * 1000).toLocaleString()], ["Work Order", wo.wo_id]]
        .forEach(([k, v]) => dl.append(el("dt", null, k), el("dd", null, String(v))));
      $("#wo-review").hidden = false; $("#ticket-form").hidden = true;
    } catch (x) { showError(x); }
  });
  $("#approve-wo").addEventListener("click", async () => {
    try {
      const cred = await passkeyAssert("/edge/api/jobs/" + jobId + "/approve/options");
      await post("/edge/api/jobs/" + jobId + "/approve", {credential: cred});
      location.href = "/edge/jobs/" + jobId;
    } catch (x) { showError(x); }
  });
}

async function jobPage(root) {
  const id = root.dataset.job;
  const seen = new Set();
  const render = async () => {
    const v = await get("/edge/api/jobs/" + id);
    $("#job-title").textContent = v.wo_id + " · " + v.provider;
    $("#job-status").textContent = v.status + (v.escalated ? " · escalated to a person" : "");
    $("#job-ticket").textContent = v.ticket;
    $("#job-meta").textContent = "Level " + v.level + " · agent " + v.agent.version + (v.escalation_reason ? " · " + v.escalation_reason : "");
    $("#kill").disabled = ["completed", "canceled", "rejected"].includes(v.status);
    $("#undo").disabled = !v.changes.some(c => c.status === "applied");
    $("#pending-card").hidden = !v.pending.length;
    const pl = $("#pending");
    const key = v.pending.map(p => p.command_hash).join();
    if (pl.dataset.key !== key) {
      pl.dataset.key = key; pl.replaceChildren();
      v.pending.forEach(p => {
        const li = el("li", "item");
        const t = el("div", "item-text"); t.append(el("strong", null, p.diff), el("span", "muted mono", "command " + p.command_hash.slice(0, 16) + "…"));
        const ok = el("button", "stamp", "Approve with passkey"), no = el("button", null, "Decline");
        ok.onclick = async () => { try { const c = await passkeyAssert("/edge/api/jobs/" + id + "/stepups/" + p.command_hash + "/options"); await post("/edge/api/jobs/" + id + "/stepups/" + p.command_hash + "/approve", {credential: c}); render(); } catch (x) { showError(x); } };
        no.onclick = async () => { try { await post("/edge/api/jobs/" + id + "/stepups/" + p.command_hash + "/decline"); render(); } catch (x) { showError(x); } };
        const a = el("div", "item-actions"); a.append(ok, no); li.append(t, a); pl.append(li);
      });
    }
    const cl = $("#changes"); cl.replaceChildren();
    if (!v.changes.length) cl.append(el("li", "muted", "No changes made."));
    v.changes.forEach(c => { const li = el("li", "item"); li.append(el("span", null, c.op + " " + JSON.stringify(c.args)), el("span", "badge " + (c.status === "applied" ? "ok" : "bad"), c.status.replace("_", " "))); cl.append(li); });
    $("#receipt").textContent = v.receipt ? "Signed receipt issued · " + v.receipt.payload.changes_made.length + " change(s) · audit root " + v.receipt.payload.audit_root.slice(0, 16) + "…" : "Issued when the job ends.";
    $("#chain").textContent = v.chain.ok ? "Hash chain intact · " + v.audit.length + " entries" : "CHAIN BROKEN at entry #" + v.chain.bad_seq;
    const al = $("#audit");
    v.audit.slice(al.children.length).forEach(e => { const li = el("li", e.outcome); li.textContent = e.actor + " · " + e.event + (e.detail ? " · " + e.detail : ""); al.append(li); });
  };
  $("#kill").addEventListener("click", async () => { try { await post("/edge/api/jobs/" + id + "/kill"); render(); } catch (x) { showError(x); } });
  $("#undo").addEventListener("click", async () => { try { await post("/edge/api/jobs/" + id + "/rollback"); render(); } catch (x) { showError(x); } });
  await render();
  setInterval(() => render().catch(showError), 1500);
}

document.addEventListener("DOMContentLoaded", () => {
  const csrfHolder = document.querySelector("[data-csrf]");
  if (csrfHolder) CSRF = csrfHolder.dataset.csrf;
  const lb = $("#passkey-login"); if (lb) lb.addEventListener("click", () => login().catch(showError));
  const en = $("#enrol-page"); if (en) $("#passkey-enrol").addEventListener("click", () => enrol(en.dataset.code).catch(showError));
  if ($("#jobs-page")) jobsPage().catch(showError);
  const np = $("#new-page"); if (np) newPage(np).catch(showError);
  const jp = $("#job-page"); if (jp) jobPage(jp).catch(showError);
});

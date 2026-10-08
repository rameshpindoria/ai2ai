# Part 2: Delegated Execution Profile v0.1 (dispatched agents acting inside a requester's environment)

Status: **Draft v0.1**, October 2026. Open for comment. This is an extension to the AI2AI Secure Profile (Part 1, `01-secure-profile.md`). It is not legal, insurance or security-certification advice. Spec references were checked on 3 Oct 2026 unless marked "(not re-fetched)".

Evidence tags: **[F]** fact, with a source URL. **[I]** inference or design judgement. **[U]** unverified or uncertain. Key words follow BCP 14. Extension URI: `https://ai2ai.example/ext/dx/v1`. The examples in this document show ES256. The reference implementation currently signs with EdDSA (Ed25519). Algorithm agility will be handled by a suite registry that is still to be written (open issue).

---

## 0. Scenario, roles and stance

A **Requester** asks for a service (laptop, M365, network, books, website, cloud admin). A verified **Provider** dispatches an AI agent that **acts inside the Requester's environment**; humans on both sides approve risky steps. The profile names **roles, not "the platform"**, so that no single operator is required.

| Role | Controlled by | Job |
|---|---|---|
| Requester IdP | Requester | Issues all access (Entra, Okta, Google). Provider never holds long-lived credentials. |
| Requester Broker (RB) | Requester (self-hosted or chosen vendor) | Classifies operations, enforces the Work Order, renders approvals, holds the kill switch, streams the log. |
| Runner | Requester-installed | On-device enforcement for endpoints and servers that are not OAuth resource servers. |
| Provider | Provider | Employs the accountable humans, operates the agent, carries insurance. |
| Dispatched Agent (DA) | Provider | Model, tools and harness, declared in a signed manifest. |
| Transparency Service (TS) | Neutral third party | Anchors manifests, credentials and session receipts (SCITT). |
| Credential Issuer | Auditor, insurer or registry | Issues verifiable credentials about the Provider. |

**Design stance [I]:** this is *more* tractable than Part 1's agent-to-agent commerce: every enforcement point (IdP, broker, Runner, egress) sits with the party at risk, so most MUSTs can be *enforced and observed* rather than merely requested of a counterparty.

---

## 1. Threat model

| ID | Threat | Real-world anchor | Primary controls |
|---|---|---|---|
| T1 | **Supply chain**: the provider's tooling is compromised and pushes to every customer | Kaseya VSA, 2 Jul 2021: fewer than 60 direct MSP customers but up to about 1,500 downstream businesses hit with REvil ransomware [F] https://www.cisa.gov/news-events/alerts/2021/07/02/kaseya-vsa-supply-chain-ransomware-attack, [F] https://en.wikipedia.org/wiki/Kaseya_VSA_ransomware_attack | No provider push channel; Runner pinned by the Requester; Sigstore/SLSA verification (§2.2, DX-A-6) |
| T2 | **RMM or remote-access exploit** | ConnectWise ScreenConnect authentication bypass CVE-2024-1709 was exploited at scale [F] (not re-fetched) https://nvd.nist.gov/vuln/detail/CVE-2024-1709 | No inbound listener; outbound-only Runner; per-session credentials |
| T3 | **Credential theft and standing access** | Five-Eyes advisory: attackers target MSPs to exploit "provider-customer network trust relationships" [F] https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-131a | JIT, sender-constrained tokens with a TTL of 5 minutes or less; no shared passwords (§3) |
| T4 | **Over-privilege** | Legacy Microsoft DAP gave broad standing admin; GDAP replaced it with granular, time-bound roles [F] https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction | RAR scope per Work Order; PIM activation inside the envelope |
| T5 | **Prompt injection from the target system**: ticket text, email bodies, file names, event logs, web pages | Agent Card poisoning (Part 1 G5) [F] https://www.keysight.com/blogs/en/tech/nwvs/2026/03/12/agent-card-poisoning | Origin-assigned taint; RB classifies operations, not the agent (§4.3) |
| T6 | **Destructive or irreversible actions** (purge, wipe, sending mail, revoking MFA) | [I] | Action classes, step-up approval, snapshot rule (§4) |
| T7 | **Data exfiltration** | [I] | Egress allow-list at RB and Runner; data-class caps (§4.4) |
| T8 | **Persistence or backdoors** (new admin, app registration, scheduled task, OAuth consent grant) | [I] | `SECURITY` class always requires step-up; post-job diff audit (§5.4) |
| T9 | **Rogue provider or insider** | [I] | Two-person rule at D3; requester-side log; insurance and dispute evidence (§6) |
| T10 | **Impersonation and tech-support scams** | US victims reported USD 2.13 bn in tech-support-scam losses in 2025 (47,794 complaints) [F] https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf | Requester-initiated only; provider verified out of band; no inbound "your PC is infected" flow (§3.1 DX-WO-1) |
| T11 | **Model or tool substitution mid-job** | [I] | The manifest digest is bound into the token and every receipt |
| T12 | **Approval fatigue or social engineering of the approving human** | Part 1 §5 | Plain-language diffs rendered by the RB; rate limits; cool-offs |

---

## 2. Provider trust

### 2.1 Organisation identity and credentials

- **DX-P-1** The Provider MUST meet Part 1 ID-1..ID-3 at L2: a signed Agent Card, an Org Key, and legal-entity verification.
- **DX-P-2** Certification evidence MUST be W3C Verifiable Credentials 2.0 (Recommendation, 15 May 2025) [F] https://www.w3.org/TR/vc-data-model-2.0/ with Bitstring Status List [F] https://www.w3.org/news/2025/the-verifiable-credentials-2-0-family-of-specifications-is-now-a-w3c-recommendation/: `ISO27001Certificate` (certification body), `SOC2Type2Report` (auditor; report hash and period only), `CyberLiabilityInsurance` (insurer; limit, expiry, AI-agent operations covered or not).
- **DX-P-3** Few auditors or insurers issue VCs today [U]. An **attestation bridge** MAY wrap a signed-PDF hash in a VC marked as a bridge; D3 MUST prefer issuer-signed VCs where they exist.
- **DX-P-4** Reputation MUST derive only from Requester-countersigned completion receipts (§5), one count per Requester per period (anti-Sybil) [I].
- **DX-P-5** Credential, Org Key and manifest revocation MUST be checked at Work Order acceptance **and** every token issuance; the RB **fails closed** at D2/D3 [I].

### 2.2 Signed agent manifest

- **DX-M-1** Each Dispatched Agent MUST have a manifest registered as a SCITT Signed Statement (RFC 9943, Proposed Standard, June 2026 [F] https://datatracker.ietf.org/doc/rfc9943/; COSE Receipts RFC 9942 [F] (search result, not re-fetched) https://datatracker.ietf.org/wg/scitt/). It declares: harness digest with SLSA provenance (Build L3 for D3 [F] (not re-fetched) https://slsa.dev/spec/v1.1/); in-toto attestations and Sigstore signatures over harness and every tool; SBOM; model id/version and inference vendor; tools with operation ids (for RB classification, §4.1); required egress.
- **DX-M-2** The RB MUST refuse a session whose running manifest digest differs from the Work Order's; a model or tool change needs a new Work Order (T11).

---

## 3. Consent and scope

### 3.1 The Work Order

The Work Order is profiled onto **OAuth 2.0 Rich Authorization Requests**: it is an `authorization_details` object of type `https://ai2ai.example/ext/dx/v1/work-order` (RFC 9396 [F] https://www.rfc-editor.org/rfc/rfc9396). It is not a parallel construct.

- **DX-WO-1 (anti-scam)** A Work Order MUST be initiated by the Requester through the Requester's own channel (their RB, IdP portal, or a listing they navigated to). A Provider MUST NOT cold-initiate a Work Order, session or Runner install. The RB shows the Provider's verified legal name, never provider-supplied display text.
- **DX-WO-2** A Requester human MUST approve it with a Part 1 HAA whose WebAuthn ceremony runs against **the Requester's own IdP or RB as relying party**. The relying party is therefore the credential's registrar, so the "trust my platform" problem disappears for Requester approvals [I]. Provider-side approvals remain provider-RP assertions, backed by signature and insurance, not independently verifiable.
- **DX-WO-3** Fields: targets, action classes, data classes, egress allow-list, window, max cost, level, manifest digest, named approvers, rollback requirements.

### 3.2 Access issuance

- **DX-A-1** All access MUST be issued by the Requester IdP. The Provider MUST NOT hold standing credentials, shared passwords or long-lived API keys.
- **DX-A-2** Tokens MUST be sender-constrained: DPoP (RFC 9449 [F] https://www.rfc-editor.org/rfc/rfc9449) or mTLS (RFC 8705 [F] https://www.rfc-editor.org/rfc/rfc8705). The key is held by the DA harness.
- **DX-A-3** Delegation MUST use Token Exchange (RFC 8693 [F] https://www.rfc-editor.org/rfc/rfc8693) with an `act` chain Requester human → Provider org → DA (WIMSE workload id), carrying Work Order id and manifest digest. UCAN/Biscuit MAY add offline attenuation. Aligns with IETF agent-auth work (draft-klrc-aiagent-auth-00 [F] https://www.ietf.org/archive/id/draft-klrc-aiagent-auth-00.html; successor draft-ietf-wimse-aims [U] https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/).
- **DX-A-4** Access-token TTL MUST be 5 min or less at D2/D3, refreshed only via the RB. Caution [F]: Entra CAE-aware sessions can carry access tokens "up to 28 hours", critical-event revocation can lag up to 15 min, and CAE does not support Guest accounts (https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation). Short TTL plus RB mediation is the guarantee; CAE is a bonus [I].
- **DX-A-5** GDAP relationships last 1–730 days [F] https://learn.microsoft.com/en-us/partner-center/customers/gdap-introduction, so GDAP is an **envelope**, never "short-lived access". Each Work Order MUST trigger a JIT role activation (e.g. PIM) expiring with it; envelope SHOULD be 1 day, MUST be 30 days or less at D3 [I].
- **DX-A-6** Endpoints and servers are not OAuth resource servers, so a **Runner** enforces locally. It is installed and version-pinned by the Requester; accepts no provider-pushed updates (Requester channel only, Sigstore/SLSA-verified); opens no inbound port; executes only allow-listed operations under a session-scoped DPoP token. The Runner is the Kaseya-class surface, so its update path belongs to the Requester [I].

---

## 4. Execution guardrails

### 4.1 Action classes, classified by the Requester Broker

| Class | Examples | Approval |
|---|---|---|
| `READ` | Get-config, read logs, list users | Work Order HAA only |
| `REVERSIBLE` | Restart service, change a setting with a captured prior value | Provider operator, per batch |
| `DESTRUCTIVE` | Delete, purge, wipe, reimage, send external mail, anything without a verified undo | Step-up: Requester human, per action |
| `SECURITY` | Create or alter an admin, MFA, conditional access, app consent, firewall, scheduled task, service install | Step-up: Requester human + Provider human (two-person) |
| `FINANCIAL` | Purchase a licence, change billing, make a payment | Step-up HAA with amount (Part 1 SPEND) |

- **DX-X-1** The RB MUST classify every operation from a **requester-side policy table** keyed on tool + operation id + target (e.g. `graph:DELETE /users/{id}`). The agent's self-declared class MUST be ignored (else the sender-asserted-taint error). **Unknown operations default to `DESTRUCTIVE`.**
- **DX-X-2** Free-form shell/eval is `SECURITY` by default; D2+ SHOULD use parameterised, allow-listed tools.
- **DX-X-3** No verified rollback means `DESTRUCTIVE`, whatever the nominal class (sent email, hard delete, accessed external link, rotated key).

### 4.2 Plan-first, step-up and the approval binding

- **DX-S-1** Before any non-`READ` action the DA MUST submit a plan: ordered operations, expected diff, rollback, blast-radius estimate.
- **DX-S-2** The RB MUST render approvals from the operation object as a **plain-language diff** in fixed fields (target, change, what can't be undone, rollback); raw PowerShell/SQL MAY be shown, never as the primary display. Channel: CIBA back-channel to the approver's device with `binding_message` as visual interlock (OpenID CIBA Core 1.0, Final [F] https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html). A Secure-Payment-Confirmation-style browser-rendered display is the strongest WYSIWYS (W3C CRD, 2 Jul 2026, payments-only today [F] https://www.w3.org/TR/secure-payment-confirmation/); non-payment use is [U].
- **DX-S-3** The attestation MUST hash the **exact executable operation** (command, canonical args, target, pre-state hash, plan id). The RB executes only an exact hash match, once.
- **DX-S-4** D3 approvals rely on Requester conditional access with phishing-resistant MFA, not authenticator attestation (synced passkeys usually carry none) [I].

### 4.3 Untrusted content from the target system

- **DX-U-1** Everything read from the target (tickets, email, files, filenames, logs, registry, web pages, tool output) is labelled `untrusted-external` by the DA harness at read time (assigned from provenance, never asserted by the content) [I].
- **DX-U-2** Untrusted content MUST NOT expand the plan, targets, egress or class; any derived new operation needs fresh plan approval.
- **DX-U-3** Safety does not depend on the model resisting injection: an injected instruction can at most *propose* an operation that the RB classifies, gates or refuses. This is the testable substitute for Part 1 CH-3 [I].

### 4.4 Rollback, egress, persistence, blast radius, sandboxing

- **DX-R-1** At D2+, `REVERSIBLE`/`DESTRUCTIVE` actions MUST follow a captured pre-state (config export, snapshot, mailbox hold, zone export); its hash goes into step-up and receipt, and the RB verifies it exists before releasing the token.
- **DX-E-1** Egress MUST be limited to the Work Order allow-list; bulk reads above the data-class cap trigger step-up.
- **DX-E-2** **No persistence.** No accounts, keys, app registrations, consent grants, scheduled tasks, services, startup items or remote-access tools unless the Work Order names them; any created MUST appear in the receipt for removal or hand-over.
- **DX-E-3** Blast-radius limits: targets per operation (e.g. 1 device or 10 users at D2), operations per minute, canary-first for fleet actions [I].
- **DX-B-1** The DA harness runs at the Provider; only the Runner and RB touch the Requester. Interactive desktop control is D3-only and recorded.

---

## 5. Observability and accountability

- **DX-O-1** **Session log.** The RB writes an append-only, hash-chained log (seq, `prevHash`, event) of every operation request/result, RB classification, DA decision summary and approval/denial, streamed live to the Requester. Chaining per session, not per context, avoids Part 1 MI-2's multi-device problem [I].
- **DX-O-2** **Anchoring.** Session-start, every step-up and the completion receipt MUST be registered as SCITT Signed Statements, with COSE receipts kept (RFC 9943/9942).
- **DX-O-3** **Completion receipt** (§7.3), RB-signed and Provider-countersigned: changes with pre/post hashes, rollback handles, artefacts created/removed, egress totals, tokens used and their revocation.
- **DX-O-4** **Kill switch**, a MUST on the Requester-controlled RB and IdP: drop all RB sessions and Runner channels; revoke refresh tokens and deactivate the JIT role; block the DA's DPoP key. Issued access tokens may survive to their 5-min TTL (CAE shortens this where supported); the profile does **not** claim instant revocation at every resource server [I, grounded in the CAE page]. Unlike Part 1 ST-1, stopping needs no cooperation from the other party.
- **DX-O-5** **Post-job audit.** Within 1 h of completion or kill, the RB compares IdP/audit-log queries with the receipt: no residual role assignment, no new principals or consents, executed operations equal logged ones. Any difference is a **reportable discrepancy** [I].

---

## 6. Liability, reputable-provider requirements and conformance

**Relation to Part 1 levels:** D1 requires L1 or above. D2 and D3 require L2 or above. Regulated targets (health, finance) also require L3.

| Requirement | D1 Read-only diagnostics | D2 Reversible changes | D3 Privileged admin |
|---|---|---|---|
| Allowed classes | `READ` | + `REVERSIBLE`, `DESTRUCTIVE` (step-up) | + `SECURITY`, `FINANCIAL` (two-person) |
| Provider evidence | Verified org | + ISO 27001 or SOC 2 Type 2 VC | Both, + issuer-signed insurance VC |
| Minimum cyber/PI insurance [U, needs broker input] | Recommended | Covering AI-agent operations | Higher limit, named Requester as interested party |
| Manifest | Signed, SBOM | + Sigstore + in-toto | + SLSA Build L3 |
| Token TTL / envelope | 15 min / job | 5 min / 1 day | 5 min / 30 days or less, with JIT activation |
| Snapshot before change | n/a | MUST | MUST + tested restore |
| Interactive desktop | No | No | Yes, recorded |
| Incident notice / log retention [I, proposed] | 72 h / 90 days | 24 h / 1 year | 4 h / 7 years |
| SLA | Response target | + rollback-on-request time | + named human on call |

- **DX-L-1** The Provider MUST keep an incident-response plan, notify Requesters of suspected harness, model-vendor or key compromise, and revoke affected manifests at the TS.
- **DX-L-2** Disputes are settled on evidence (log, SCITT receipts, step-ups, post-job audit), presentable to an insurer or arbiter by selective disclosure.
- **DX-L-3** Conflict of interest: the profile MUST be implementable with a self-hosted RB and any SCITT-conformant TS; a hosted operator MAY offer these, never as the only option.

**Testable versus auditable MUSTs.** Black-box testable: token scope/TTL, sender-constraint, RB classification and default-deny, approval-hash binding, egress blocks, kill-switch latency, post-job audit, receipt signatures. Audit-only: DA-side taint labelling, no hidden model calls, Provider IR duties. The suite plants an injection corpus on a target fixture (poisoned tickets, filenames, email bodies); a pass means **zero** unapproved non-`READ` operations executed, which is observable, not that the model ignored the injection.

---

## 7. JSON examples

### 7.1 Work Order (RAR `authorization_details` entry, wrapped in a Requester HAA)

```json
{
  "type": "https://ai2ai.example/ext/dx/v1/work-order",
  "workOrderId": "wo-2026-10-03-0042",
  "conformance": "D2",
  "requester": { "org": "org:requester.example", "approver": "human:requester.example/a.ng" },
  "provider": { "org": "org:itfix.example", "legalVerification": "urn:ai2ai:verif:L2:51ac...",
                "credentials": ["urn:vc:iso27001:itfix:2026", "urn:vc:cyberins:itfix:2026"] },
  "agent": { "id": "spiffe://itfix.example/agent/m365-helpdesk",
             "manifestDigest": "sha256-a91f...e2", "manifestReceipt": "scitt:ts.example:9f3c..." },
  "problem": "Shared mailbox 'accounts@' not receiving external mail",
  "locations": ["https://graph.microsoft.com", "https://outlook.office365.com"],
  "targets": ["mailbox:accounts@requester.example", "exo:transport-rules"],
  "actionClasses": ["READ", "REVERSIBLE", "DESTRUCTIVE"],
  "dataClasses": { "allowed": ["business"], "personalBodyAccess": false, "maxEgressMB": 5 },
  "egressAllow": ["api.itfix.example", "inference.vendor.example"],
  "window": { "notBefore": "2026-10-03T10:00:00Z", "notAfter": "2026-10-03T14:00:00Z" },
  "maxCost": { "amount": "180.00", "currency": "USD" },
  "approvers": { "requesterStepUp": ["human:requester.example/a.ng"],
                 "providerOperator": ["human:itfix.example/r.cole"] },
  "rollback": { "snapshotRequired": true },
  "tokenPolicy": { "ttlSeconds": 300, "binding": "DPoP", "jitRole": "Exchange Recipient Administrator" },
  "nonce": "b64u:Wm9r...", "iat": "2026-10-03T09:52:10Z"
}
```

### 7.2 Step-up approval attestation for a destructive command

```json
{
  "typ": "ai2ai-dx-stepup+jws",
  "operation": {
    "workOrderId": "wo-2026-10-03-0042", "planId": "plan-7", "step": 3,
    "rbClass": "DESTRUCTIVE", "agentDeclaredClass": "REVERSIBLE",
    "tool": "exo-pwsh", "opId": "Remove-TransportRule",
    "canonicalArgs": { "Identity": "Block-External-To-Accounts", "Confirm": false },
    "opHash": "sha256-3c7e...10",
    "target": "exo:transport-rules/Block-External-To-Accounts",
    "preStateHash": "sha256-88b2...4d", "snapshotRef": "rb:snap/exo-rules/2026-10-03T10:41:07",
    "display": {
      "what": "Delete mail-flow rule 'Block-External-To-Accounts'",
      "effect": "External senders will reach accounts@ again",
      "irreversible": "Rule is deleted; restorable only from the exported snapshot",
      "blastRadius": "1 rule, 1 mailbox"
    },
    "nonce": "b64u:Q2l...", "iat": "2026-10-03T10:41:20Z", "exp": "2026-10-03T10:46:20Z"
  },
  "cibaBindingMessage": "WO42-S3-7KQ",
  "approver": { "principal": "human:requester.example/a.ng", "idp": "https://login.requester.example" },
  "webauthn": { "authenticatorData": "b64u:...", "clientDataJSON": "b64u:...", "signature": "b64u:..." },
  "rbSig": { "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InJiLTIwMjYtMTAifQ", "signature": "..." }
}
```

`agentDeclaredClass` is recorded for the audit and is never used for gating.

### 7.3 Completion receipt

```json
{
  "typ": "ai2ai-dx-receipt+jws",
  "workOrderId": "wo-2026-10-03-0042", "outcome": "RESOLVED",
  "session": { "start": "2026-10-03T10:02:11Z", "end": "2026-10-03T10:58:40Z",
               "logHeadHash": "sha256-f0e1...", "entries": 214 },
  "changes": [
    { "step": 3, "opHash": "sha256-3c7e...10", "target": "exo:transport-rules/Block-External-To-Accounts",
      "pre": "sha256-88b2...4d", "post": "sha256-absent", "rollback": "rb:snap/exo-rules/2026-10-03T10:41:07",
      "stepUp": "sha256-6d1a..." }
  ],
  "created": [], "removed": [],
  "egress": { "totalKB": 412, "destinations": ["api.itfix.example", "inference.vendor.example"] },
  "access": { "tokensIssued": 19, "maxTtlSeconds": 300, "jitRoleDeactivated": "2026-10-03T10:58:52Z",
              "postJobAudit": { "at": "2026-10-03T11:20:03Z", "residualAssignments": 0,
                                "newPrincipals": 0, "discrepancies": 0 } },
  "cost": { "amount": "120.00", "currency": "USD" },
  "scitt": { "ts": "ts.example", "receipt": "cose-receipt:b64u:..." },
  "rbSig": { "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InJiLTIwMjYtMTAifQ", "signature": "..." },
  "providerCountersig": { "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Iml0Zml4LTIwMjYifQ", "signature": "..." }
}
```

---

## 8. Residual risk and what to pilot first

**Unsolved or only partly solved:**
- **The RB becomes the crown jewel**: a compromised broker approves anything. Trust shifts from Provider to RB vendor; self-hosting helps, a verified approval path is future work [I].
- **Incomplete classification tables**: default-deny is safe but noisy; API coverage (Graph, Google Admin, AWS, accounting, hosting panels) is ongoing work [I].
- **Semantic harm inside allowed operations**: an approved reversible change can still be the wrong fix; approval fatigue persists (Part 1 §5).
- **Endpoint reality**: revocation does not reach an offline Runner mid-job; local admin can't be scoped as finely as an API [I].
- **Model-vendor data path**: target data sent for inference sits outside both parties; only contract, residency and zero-retention terms constrain it [U].
- **Ecosystem gaps**: few VC-issuing auditors/insurers, SPC payments-only, CAE vendor-specific and not instant; insurer appetite for AI-agent admin [U].
- **Liability allocation** among Provider, model vendor and RB vendor after a bad *approved* action [U, per jurisdiction]; **collusion** of rogue Provider and Requester insider defeats two-person approval.

**Pilot first (lowest blast radius):**
1. **D1 read-only M365 health check**: read-scoped Graph token (RAR → token exchange → DPoP, 5-min TTL) producing report, log and receipt. Proves issuance, logging, kill switch and post-job audit with no write path.
2. **D1 laptop diagnostics** via a Requester-installed Runner with a read-only allow-list; proves pinning and no-inbound.
3. **D2 single reversible change** with snapshot and step-up on one test mailbox, run against the planted-injection corpus; target zero unapproved writes.
4. Hold D3 until a self-hosted RB, an issuer-signed insurance VC and an independent review of the approval path exist.

**Open issues (to verify) [U]:** RFC 9942 status and number; SLSA spec version; CVE-2024-1709 details; draft-ietf-wimse-aims lineage; insurer VC availability; extension of SPC to non-payment confirmations; GDAP minimum duration and PIM support for partner roles.

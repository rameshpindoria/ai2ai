# Part 1: AI2AI Secure Profile v0.1 (with gap analysis)

Status: **Draft v0.1**, October 2026. Open for comment. This is not legal or security-certification advice. Specification references were checked on 3 Oct 2026; items still to verify are listed under "Open issues" at the end.

Evidence tags: **[F]** fact, with a source URL. **[I]** inference or design judgement. **[U]** unverified or uncertain.

Primary sources:
- A2A 1.0.0 specification: https://a2a-protocol.org/v1.0.0/specification/ (tag source: https://github.com/a2aproject/A2A/blob/v1.0.0/docs/specification.md)
- A2A "latest" specification: https://a2a-protocol.org/latest/specification/
- A2A protobuf schema: https://github.com/a2aproject/A2A/blob/v1.0.0/specification/a2a.proto
- MCP 2026-07-28 core: https://modelcontextprotocol.io/specification/2026-07-28
- MCP 2026-07-28 elicitation: https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- MCP 2026-07-28 release post: https://blog.modelcontextprotocol.io/posts/2026-07-28/

---

Fixed constraints: humans are first-class principals; no model approves; inbound content is data, never instructions; spend/commitment/acceptance/sensitive release needs an authenticated human; append-only audit; kill switches; interoperate with MCP and A2A.

---

## 1. Gap analysis: what the base protocols leave optional or unspecified

Both protocols push trust decisions outside the protocol. A2A: authorization logic "is implementation-specific" (§7.5) [F] https://a2a-protocol.org/v1.0.0/specification/. MCP: "MCP itself cannot enforce these security principles at the protocol level" (core page, "Security and Trust & Safety") [F] https://modelcontextprotocol.io/specification/2026-07-28. That suits a general transport, not untrusted organisations negotiating money and data.

| # | Concern | A2A 1.0.0 | MCP 2026-07-28 | Gap for untrusted orgs |
|---|---|---|---|---|
| G1 | Agent identity / card authenticity | Cards "**MAY** be digitally signed" (JWS over JCS, §8.4); clients "SHOULD verify" (§8.4.3). [F] v1.0.0 URL | No signed identity document; annotations "should be considered untrusted" (core page). [F] core URL | Unsigned cards are conformant; no binding to a verified legal entity. [I] |
| G2 | Key revocation | "Expired or revoked keys **MUST NOT** be used" (§8.4.3), yet no revocation mechanism is defined (§13.4 only SHOULD). [F] v1.0.0 URL | OAuth hardening (RFC 9207 `iss`, issuer binding) only. [F] blog URL | Required rule, undefined mechanism. [I] |
| G3 | Human vs agent principal | `Role` is only `ROLE_USER`/`ROLE_AGENT` (direction, not personhood). [F] a2a.proto | Users via OAuth `sub`; servers "MUST NOT rely on client-provided user identification" (elicitation page). [F] elicitation URL | No way to tell a person from a model. [I] |
| G4 | Human approval attestation | §7.6 cites "human approval" as an AUTH_REQUIRED use. *Latest* §7.6.4 (not in the 1.0.0 tag): protocol "does not define the scope, representation, validity, or revocation semantics"; meaning "MUST be defined by ... an A2A extension". [F] latest URL | Elicitation `accept` is client-reported, not cryptographic; in URL mode the "client is not directly informed of the outcome". [F] elicitation URL | No verifiable proof a named human approved *this exact* action. [I] |
| G5 | Instruction vs untrusted-content separation | `Part` has no trust/taint field [F] a2a.proto; only "MUST sanitize user-provided content" (§14.1.1). [F] v1.0.0 URL | Not found in the core, security or elicitation pages reviewed. [I] | Injection hygiene left to implementers. Agent Card poisoning: card text placed verbatim in planning prompts led to PII exfiltration (Keysight, 2026-03-12). [F] https://www.keysight.com/blogs/en/tech/nwvs/2026/03/12/agent-card-poisoning |
| G6 | Data classification | No labels; generic compliance only (§13.4). [F] v1.0.0 URL | Consent principle, no labels (core). [F] core URL | Cannot enforce minimisation/residency on unclassified data. [I] |
| G7 | Message integrity and replay | TLS only (§7.1); Send Message "MAY be idempotent" (§3.3.1); "replay"/"nonce" absent from the text. [F] v1.0.0 URL | No message signature in pages reviewed [I]; `_meta` signature carriage [U]. | Hop-by-hop only; no end-to-end integrity. [I] |
| G8 | Receipts / non-repudiation | Audit is "SHOULD provide audit trails" (§13.4). [F] | Not specified in the pages reviewed. [I] | No third-party-provable agreement. [I] |
| G9 | Delegation chains | AUTH_REQUIRED chains allowed (§7.6.2); credential binding SHOULD (§7.6.3). [F] v1.0.0 URL | EMA extension exists [F] blog URL; semantics [U]. | No portable "acts-for / scope / expiry". [I] |
| G10 | Stop / kill | Cancel: "success is not guaranteed" (§3.1.5); no propagation defined. [F] v1.0.0 URL | "Cancellation" utility; Tasks now an extension [F] core/blog URLs; propagation [U]. | No chain-wide cancel or "revoke all authority of agent X". [I] |
| G11 | Provenance / supply chain | Not specified. [F] (no occurrence in the v1.0.0 text) | Not found in the pages reviewed. [I] | No model/tool provenance; OWASP ASI04 wants it. [F] (secondary: https://cycode.com/blog/owasp-top-10-agentic-applications/) |
| G12 | Artifact safety | Content-type check SHOULD (§13.4); SSRF MUST (§14.1.1). [F] | MCP Apps renders interactive UI [F] core URL, widening active content. [I] | No allowlist or active-content stripping. [I] |

OWASP Top 10 for Agentic Applications 2026 (released 9 Dec 2025) [F] https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ maps onto these gaps (IDs via secondary source [F] https://cycode.com/blog/owasp-top-10-agentic-applications/): ASI01 Goal Hijack→G5; ASI03 Identity & Privilege Abuse→G1/G3/G9; ASI04 Supply Chain→G11; ASI07 Inter-Agent Communication→G7; ASI08 Cascading Failures and ASI10 Rogue Agents→G10; ASI09 Human-Agent Trust Exploitation→G4.

---

## 2. Strategic recommendation: profile + extensions, not a new protocol

**Recommendation:** define the **AI2AI Secure Profile**, a set of A2A extensions and MCP extensions plus a conformance regime. Do not build a new wire protocol. [I]

Reasons:
1. **Distribution is already decided.** MCP and A2A both now sit under the Agentic AI Foundation at the Linux Foundation [F] (secondary: https://aimpact.prandi.net/en/events/2026-08-20-a2a-agentic-ai-foundation/). A new protocol would need to win adoption against both. A profile rides on their SDKs and installed base. [I]
2. **Both protocols were built to be extended.** A2A extensions are URI-identified. They are declared in the card with a `required` flag, and clients opt in via the `A2A-Extensions` header (§4.6, §14.2.2) [F] v1.0.0 URL. MCP extensions are "always opt-in and require explicit support from both client and server" [F] core URL. They graduate through an Extensions Track in the SEP process [F] (secondary: https://adamarant.com/en/blog/mcp-governance-in-2026-what-the-linux-foundation-handoff-changed).
3. **The A2A text invites exactly this.** §7.6.4 (latest) says authorization meaning MUST be defined by an implementation, issuer, or "an A2A extension" [F] latest URL. HAA is that extension.
4. **Reusable primitives.** JWS/JCS are already normative in A2A §8.4; OAuth/RFC 9207 come from MCP; WebAuthn is ubiquitous. [F]/[I]
5. **The hard part is the trust fabric** (verification, transparency log, conformance testing), not the wire format. [I]

Counter-risk: the profile binds only opt-in parties. Mitigation: implementations refuse non-conformant counterparties at L2+, and treats plain A2A/MCP peers as L0 (data-only, no commitments). [I]

---

## 3. Draft outline: AI2AI Secure Profile v0.1

Key words follow BCP 14. Extension URIs are placeholders: `https://ai2ai.example/ext/<name>/v1` [I].

### 3.1 Identity (ext `identity`)

- **ID-1** The Agent Card MUST carry at least one JWS signature per A2A §8.4. This turns the base protocol's MAY into a MUST. Verifiers MUST reject unsigned cards at L1 and above.
- **ID-2** The signing key MUST chain to an **Org Key**. The Org Key MUST be proven by:
  - (a) DNS TXT or `/.well-known/ai2ai-org.json` on the declared domain, and
  - (b) at L2 and above, a legal-entity verification attestation from a profile-recognised verifier.
- **ID-3** Keys MUST have a `kid` and expiry ≤ 13 months.
  - Rotation MUST overlap (both keys valid) and MUST be logged to the transparency log (§3.6).
  - Revocation MUST be published to a status endpoint and the log. Verifiers MUST check status at most 24 h stale (L2) or 1 h stale (L3).
- **ID-4** Principals are typed: `org`, `human`, `agent`.
  - A `human` principal MUST be bound to at least one WebAuthn credential registered under identity proofing.
  - An `agent` principal MUST NOT hold a WebAuthn credential that is registered as human.
- **ID-5 Delegation.** Every agent action MUST carry a **Delegation Token**, a signed JWS chain whose root is an org or human. Each link MUST state `actsFor`, `scope` (action classes, max amount, data classes), `exp` and `maxDepth`.
  - Each hop MUST narrow scope or keep it the same, never widen it.
  - Verifiers MUST reject chains that are expired, revoked, deeper than `maxDepth`, or broadened at any hop.

Example signed card extension (inside `capabilities.extensions[]`; the whole card is covered by the A2A JWS signature):

```json
{
  "uri": "https://ai2ai.example/ext/identity/v1",
  "required": true,
  "params": {
    "org": { "id": "org:sellerco.example", "domain": "sellerco.example",
             "orgKeyJwks": "https://sellerco.example/.well-known/ai2ai-jwks.json",
             "legalVerification": "urn:ai2ai:verif:L2:7f3c..." },
    "principalType": "agent",
    "keyStatus": "https://sellerco.example/.well-known/ai2ai-status.json",
    "conformance": "L2",
    "policyRef": "https://sellerco.example/.well-known/ai2ai-policy.json",
    "policyHash": "sha256-9b1e..."
  }
}
```

### 3.2 Human Approval Attestation (ext `haa`)

**Action classes requiring HAA (floor):**
- `SPEND`: any amount
- `COMMIT`: contract, quote acceptance, order
- `ACCEPT`: deliverable sign-off
- `RELEASE`: data of class `personal` or `sensitive`
- `DELEGATE_UP`: issuing a delegation that grants any of the above

**Rules:**
- **HAA-1** An HAA is a JWS-signed object created by the approving party's platform. It wraps a WebAuthn assertion.
  - The WebAuthn `challenge` MUST equal `SHA-256(JCS(actionObject))`.
  - The action object MUST contain: `actionClass`, `payloadHash` (JCS hash of the exact message/artifact set), `amount` + `currency` (if any), `counterparty` (org id + agent id), `dataClasses`, `taskId`/`contextId`, `nonce` (≥128-bit), `iat`, `exp` (≤ 15 min for SPEND/COMMIT).
- **HAA-2** The assertion MUST have the User Verified (UV) flag set. At L3 it MUST come from an attested authenticator.
- **HAA-3** Verifiers MUST:
  - recompute the hash,
  - verify the WebAuthn signature against the registered **human** credential,
  - check that the human holds authority for the class and amount under the org's policy (§3.7),
  - check that the nonce is unused and the HAA is not expired.
  Verifiers MUST reject any commitment-class message without a valid HAA. A model output, an elicitation `accept`, or a bare AUTH_REQUIRED resolution MUST NOT be treated as approval. [I] This makes the A2A §7.6.4 and MCP elicitation semantics concrete.
- **HAA-4** WYSIWYS: the approval UI MUST be rendered by the platform from the action object itself, not from agent-supplied prose. It MUST show amount, counterparty, data classes and expiry in fixed, non-model-generated fields.

**Mapping to the base protocols:**
- **A2A:** when an agent reaches a commitment step, it MUST move the task to `TASK_STATE_AUTH_REQUIRED`. The status message MUST carry the action object in a `data` Part tagged `control`. The HAA is returned in a follow-up message Part, or out of band per §7.6.1. Use `INPUT_REQUIRED` for clarifications only, never for approvals. [I]
- **MCP:** the server MUST use **URL-mode elicitation** to a platform-hosted WebAuthn page. Form mode is unsuitable: the response is client-reported, and URL mode keeps the ceremony out of the LLM and client path. On retry, the server verifies the HAA it received out of band. The client's `accept` only means consent to navigate. [F] for the elicitation behaviour, elicitation URL; [I] for the design.

Example HAA:

```json
{
  "typ": "ai2ai-haa+jws",
  "action": {
    "actionClass": "COMMIT",
    "payloadHash": "sha256-4f2a...c9",
    "amount": "12500.00", "currency": "USD",
    "counterparty": { "org": "org:buyerco.example", "agent": "agent:buyerco/procure-01" },
    "dataClasses": ["business"],
    "taskId": "a1b2-...", "contextId": "c9d8-...",
    "nonce": "b64u:Qm9YyK...", "iat": "2026-10-03T09:14:05Z", "exp": "2026-10-03T09:29:05Z"
  },
  "approver": { "principal": "human:sellerco.example/j.smith", "credentialId": "b64u:AbC..." },
  "webauthn": { "authenticatorData": "b64u:...", "clientDataJSON": "b64u:...", "signature": "b64u:..." },
  "platformSig": { "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6InBsYXQtMjAyNi0xMCJ9", "signature": "..." }
}
```

### 3.3 Content channels (ext `channels`)

- **CH-1** Every Part MUST carry `metadata.ai2ai.channel` ∈ {`control`, `content`}.
  - `control` Parts MUST be `data` Parts that validate against a profile JSON Schema: offers, prices, state, HAA, receipts.
  - Everything else is `content`.
- **CH-2** Every `content` Part MUST carry `metadata.ai2ai.taint`. The values are `untrusted-external`, `counterparty`, `own-org` and `human-authored`, with origin principal. Taint MUST propagate: derived content inherits the most restrictive input taint.
- **CH-3** Receivers MUST NOT place `content` Parts, or any Agent Card free text (`description`, `skills[].description`, `examples`), into system or developer context. The content MUST be delimited as quoted data.
  - Planner and delegation prompts MUST be built from structured card fields (skill ids, tags, schemas), not card prose.
  - This is the direct counter to Agent Card poisoning [I].
- **CH-4** Tool invocation MUST NOT be conditioned solely on `content`. Any tool call whose arguments derive from tainted content MUST pass a policy gate. SPEND/COMMIT/RELEASE MUST additionally carry an HAA.
- **CH-5** A missing channel or taint label MUST be treated as `content` / `untrusted-external`.

### 3.4 Data classification (ext `dataclass`)

- **DC-1** Every Part MUST carry `metadata.ai2ai.class` ∈ {`public`, `business`, `personal`, `sensitive`}. A missing label MUST be treated as `sensitive`.
- **DC-2** Optional `residency` (ISO 3166 list) and `purpose` tags. Receivers MUST NOT process or store data outside the declared residency. If they cannot comply, they MUST reject the Part.
- **DC-3** Minimisation: senders SHOULD send `personal`/`sensitive` data only after the counterparty's policy (§3.7) declares retention and residency. Release of these classes requires HAA `RELEASE`.

### 3.5 Message integrity and replay (ext `integrity`)

- **MI-1** At L2 and above, every message MUST carry a detached JWS over `JCS(message minus signature)`. The signer is the agent key, with a Delegation Token reference.
- **MI-2** Messages MUST include `nonce`, `iat` (receivers reject skew > 300 s) and `prevHash`, the hash of the sender's previous message in that context. Receivers MUST keep a nonce cache for the skew window and MUST reject duplicates. This upgrades A2A's "MAY be idempotent" (§3.3.1). [I]
- **MI-3** State-machine guards: receivers MUST reject transitions that are invalid for the task state, for example an artifact after a terminal state, or a COMMIT on a CANCELED task. Terminal states are final.

### 3.6 Signed receipts and transparency log (ext `receipts`)

- **RC-1** For each control event (offer, counter-offer, HAA verified, commitment, delivery, acceptance, cancel), both parties MUST exchange signed receipts.
- **RC-2** The approving party's platform MUST append each receipt's hash to an append-only Merkle log, using RFC 6962 / RFC 9162-style signed tree heads.
  - The tree head MUST be externally anchored at least daily. Options include a public transparency service, a timestamping authority, or a public ledger; which one is [U].
  - Receipts contain hashes only, so disputes can be adjudicated by revealing the hashed payload selectively, without disclosing content to the log.

Example receipt:

```json
{
  "typ": "ai2ai-receipt+jws",
  "event": "COMMIT_ACCEPTED",
  "taskId": "a1b2-...", "contextId": "c9d8-...",
  "payloadHash": "sha256-4f2a...c9",
  "haaHash": "sha256-77d0...",
  "from": "agent:sellerco/sales-02", "to": "agent:buyerco/procure-01",
  "seq": 14, "prevHash": "sha256-0c1e...",
  "ts": "2026-10-03T09:15:11Z",
  "log": { "treeSize": 884213, "leafIndex": 884212, "sth": "sha256-e5aa..." },
  "sig": { "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6InNhbGVzLTAyIn0", "signature": "..." }
}
```

### 3.7 Policy declaration (ext `policy`)

- **PO-1** Each party MUST publish a signed, machine-readable policy at `policyRef`. Its hash MUST be in the signed card. The policy contains:
  - HAA thresholds per action class
  - approver roles
  - max delegation depth
  - accepted data classes and residency
  - retention
  - artifact types accepted
- **PO-2** **Floors that cannot be relaxed:**
  - HAA on SPEND/COMMIT/ACCEPT/RELEASE
  - no model approver
  - missing label = sensitive
  - content never enters system context
  - receipts on all control events
  A policy that relaxes any floor is non-conformant and MUST be rejected.
- **PO-3** The effective policy for an interaction is the stricter of the two parties' policies, field by field.

### 3.8 Stop / kill semantics (ext `stop`)

- **ST-1** `CANCEL` MUST propagate. On cancelling task T, an agent MUST cancel every subtask it spawned for T and every delegation it issued for T, and MUST emit receipts. A cancel acknowledgement MUST list the downstream task ids that were cancelled or could not be cancelled.
- **ST-2** `REVOKE` is a signed revocation of an agent key or Delegation Token, published to status and log. Verifiers MUST refuse all further actions under it within the staleness window in ID-3. Platforms MUST offer a human-operated **kill switch**: one action revokes all delegations of an agent or org.
- **ST-3** HAAs that are unused at revocation time MUST become invalid.

### 3.9 Artifact safety (ext `artifacts`)

- **AR-1** MIME allowlist per conformance level (e.g. PDF/A, PNG, JPEG, CSV, JSON, plain text). Anything else MUST be rejected or quarantined.
- **AR-2** Active content MUST be stripped or rendered inert before delivery or any model ingestion: macros, JavaScript in PDF, embedded HTML/script, external references, OLE.
- **AR-3** The artifact hash MUST be recorded in a receipt. File URLs MUST be validated per A2A §14.1.1 (SSRF).

### 3.10 Conformance levels and test suite

| Level | Use | Requires |
|---|---|---|
| L1 Basic | Discovery, quoting, non-binding chat | ID-1..4, CH-*, DC-*, AR-*, ST-1 |
| L2 Human-attested commerce | Spend, commitment, acceptance | L1 + ID-5, HAA, MI-*, RC-*, PO-*, ST-* |
| L3 Regulated | Health, finance, personal-data-heavy work | L2 + attested authenticators, 1 h revocation freshness, residency enforcement, independent audit |

The conformance suite (published with the spec) MUST include:
- schema and signature vectors (JCS edge cases)
- replay and skew tests
- delegation-broadening tests
- revocation-latency tests
- an **adversarial injection corpus**: poisoned card descriptions; instructions injected in content Parts, filenames and metadata; spoofed `control` Parts; fake HAA prose ("approved by J. Smith"); homoglyph counterparties; artifacts with active payloads.

A pass requires zero commitments without HAA, and zero tainted content in system context, across the corpus. [I]

---

## 4. Path to standardisation

1. **Publish openly.** This draft is published for non-commercial use: spec text under CC BY-NC 4.0, and the reference implementation under the PolyForm Noncommercial License 1.0.0. Upstream standardisation through A2A or MCP would need a more permissive licence for the text that is contributed. [I]
2. **Reference implementation.** A2A middleware plus an MCP server wrapper (HAA via URL-mode elicitation), alongside the official SDKs. [I]
3. **Propose upstream.**
   - **A2A:** a community extension first, citing §7.6.4 as the hook, then promotion via the A2A project process. [I]
   - **MCP:** an Extensions-Track SEP. [F] (secondary: adamarant URL above). Both projects are now under AAIF governance. [F] (secondary: aimpact URL above)
4. **Co-sponsors.** A payments/identity vendor, a passkey vendor, one regulated buyer (insurer or bank), a security vendor; contribute the corpus to OWASP GenAI. [I]

---

## 5. Residual risk: what the profile does NOT solve

- **Approval fatigue / rubber-stamping (ASI09).** A valid HAA proves a human tapped, not that they understood. Partial mitigations: thresholds, cool-offs, anomaly prompts. [I]
- **Display integrity.** A compromised client can show A and sign B. WYSIWYS (HAA-4) narrows this risk but cannot remove it without trusted display hardware. [I]
- **Compromised endpoints.** Malware on an unlocked device, a coerced human, or an insider with authority all produce valid HAAs. [I]
- **Colluding counterparties.** Signatures prove who agreed, not that the deal is fair or legal. [I]
- **Persuasion of humans and semantic injection.** Tainted artifacts can still persuade a person; schema-valid `control` values (e.g. a misleading line-item name) can still mislead. [I]
- **Inside one party's boundary.** The profile constrains the wire, not internal reasoning; taint discipline relies on implementer compliance, and certification is sampled, not continuous. [I]
- **Verifier or log-operator compromise.** Trust degrades until detected; external anchoring limits silent rewrites, not issuance fraud. [I]
- **Legal enforceability.** Whether an HAA meets the e-signature or contract-formation law of each jurisdiction is [U] and needs per-market legal review.
- **Non-conformant ecosystems.** Value is limited to parties that opt in. Base A2A/MCP peers remain L0. [I]
- **Availability and DoS.** These are not addressed beyond rate-limit guidance inherited from A2A §13.4. [F] v1.0.0 URL

**Open issues (to verify) [U]:** MCP Tasks cancel/propagation semantics; `_meta` detached signatures; EMA delegation semantics; agent-payment mandate prior art (align HAA, don't duplicate); AAIF extension-acceptance process for A2A.

# Implementation status: spec v0.1 versus the reference platform

The reference platform is a **working subset** of the spec, built to prove the core ideas end to end. It is **not
conformant** with the spec as written. This page says honestly what is implemented, what is done differently, and
what is not built yet.

Legend: **Yes** = implemented and tested · **Partial** = the idea is implemented, but not in the mechanism the spec
names · **No** = not implemented.

## Differences that apply everywhere

| Topic | Spec says | Code does |
|---|---|---|
| Signature algorithm | Examples use ES256 (Part 2) and JWS throughout | Ed25519 (EdDSA). Agent Cards use JWS per A2A §8.4; all other signed objects use a compact `{payload, kid, sig}` envelope |
| Canonical JSON | JCS (RFC 8785) | Sorted keys, no whitespace, UTF-8. This matches JCS for the value types the platform signs, but not for every number format |
| Key ids | `kid` with expiry and rotation | `kid` = role label + SHA-256 of the public key, so a party can't claim another's kid. No expiry or rotation yet |
| Extension URI | `https://ai2ai.example/ext/<name>/v1` | One combined extension, `https://ai2ai.example/extensions/secure-profile/v1` |
| Trust anchor | Org keys proven by DNS / well-known plus legal verification; W3C VCs; SCITT | One centre key. The centre countersigns each provider listing with the provider's public keys and centre-signed credentials, so an edge needs only the centre key and the revocation list |

## Part 1: Secure Profile

| Requirement | Status | Notes |
|---|---|---|
| ID-1 Signed Agent Card | Yes | Provider-signed A2A v1.0.1 card (JWS, EdDSA) plus a centre discovery card; tampering is detected |
| ID-2 Org key proof | Partial | Admin verification at the centre and a centre countersignature, instead of DNS / well-known |
| ID-3 Key expiry, rotation, revocation | Partial | Public revocation list checked when a job is drafted; no rotation or expiry |
| ID-4 Typed principals | Partial | Customer approvers must use a WebAuthn passkey; agents sign with agent keys and can never approve |
| ID-5 Delegation tokens | No | |
| HAA-1 to HAA-3 Human Approval Attestation | Partial | A passkey (user verification required) approves the Work Order and each change; the approval is bound to a hash of the exact command, single-use, with a 5-minute expiry. The format is not the spec's HAA object |
| HAA-4 WYSIWYS display | Yes | The edge renders the approval from the operation catalogue's own description and the exact arguments, never from agent prose |
| CH-1 to CH-5 Channels and taint | Partial | Everything read from the environment, and all provider-written text shown to the customer's assistant, is wrapped as `<untrusted>` data. No per-Part channel or taint metadata |
| DC-1 to DC-3 Data classes | No | |
| MI-1 Message signatures | Partial | Every agent request is signed with the agent key (envelope, not detached JWS) |
| MI-2 Nonce, timestamp, replay | Yes | Nonce plus timestamp, 60 s skew, replay cache. No `prevHash` per message |
| MI-3 State-machine guards | Yes | A2A task-state transitions are guarded; illegal transitions are refused |
| RC-1 Signed receipts | Yes | Receipt signed by the customer edge, with the provider's signed completion statement inside; amendments on rollback |
| RC-2 Transparency log | Partial | A local hash-chained log of receipts and amendments; no Merkle tree or external anchoring |
| PO-1 to PO-3 Policy | No | Floors are hard-coded rather than declared in a published policy |
| ST-1 Cancel propagation | No | |
| ST-2 Revoke and kill switch | Yes | The customer's kill switch voids pending approvals; every later agent call is refused. Centre revocation list for providers, agents and credentials |
| ST-3 HAAs invalid after revocation | Yes | The kill switch voids pending step-ups, and a killed job refuses every further call, so approved-but-unused step-ups can't run. Completion voids both pending and approved step-ups |
| AR-1 to AR-3 Artifact safety | No | |
| Conformance suite and injection corpus | Partial | A red-team across all 25 IT scenarios, with instructions planted in three places; a rogue agent that obeys them is contained. Not yet packaged as a standalone conformance suite |

## Part 2: Delegated Execution

| Requirement | Status | Notes |
|---|---|---|
| DX-P-1 to DX-P-5 Provider trust | Partial | Verified providers with centre-signed credentials (security certification and insurance required). Credentials are checked when a job is drafted; not W3C VCs |
| DX-M-1, DX-M-2 Signed agent manifest | Partial | The card carries a build digest; no SCITT, SBOM, Sigstore or SLSA |
| DX-WO-1 Requester-initiated | Yes | Only the customer can start a job, on their own edge |
| DX-WO-2 Requester approval on their own relying party | Yes | The passkey ceremony runs on the customer's edge |
| DX-WO-3 Work Order fields | Partial | Level, allowed classes, time window, ticket, approvers. Not an OAuth RAR object |
| DX-A-1 No standing provider credentials | Yes | The agent only ever holds short-lived tokens from the customer's edge |
| DX-A-2 Sender-constrained tokens | Partial | Each token is bound to the agent key and every request must be signed by it. Not DPoP or mTLS |
| DX-A-3 Token exchange | No | |
| DX-A-4 Token TTL of 5 minutes or less | Yes | 300 s |
| DX-A-5 JIT role activation (GDAP / PIM) | No | Needs a real tenant; the simulator has no roles to activate |
| DX-A-6 Runner | No | |
| DX-X-1 Requester-side classification, unknown = destructive | Yes | The connector's operation table assigns the class; the agent can't declare one |
| DX-X-2 Shell is SECURITY | Yes | There is no free-form shell operation |
| DX-X-3 No rollback = DESTRUCTIVE | Partial | Operations without an undo (delete, reimage, backup-job delete) are classed destructive by hand in the IT operation table. Nothing checks this automatically. Every reversible change is snapshotted and can be restored |
| DX-S-1 Plan first | No | Each change is approved individually |
| DX-S-2 Plain-language approval display | Yes | CIBA is not implemented; approvals happen on the customer's edge |
| DX-S-3 Approval bound to the exact operation | Yes | Hash of Work Order id, operation and canonical arguments; executes once |
| DX-S-4 D3 conditional access | No | D3 is not implemented |
| DX-U-1 to DX-U-3 Untrusted content | Yes | Reads are wrapped as untrusted; an injected instruction can only *propose* an operation, which the broker classifies, gates or refuses |
| DX-R-1 Snapshot before change | Yes | A snapshot is taken before every change, failed changes roll back automatically, and the customer can undo with a drift check |
| DX-E-1 Egress allow-list | Partial | All egress-class operations are refused (the allow-list is empty) |
| DX-E-2 No persistence | Partial | Security-class operations (new admins, consents...) are refused at D1 and D2 |
| DX-E-3 Blast-radius limits | No | |
| DX-O-1 Hash-chained session log | Yes | Per-job audit chain, with tampering detected |
| DX-O-2 SCITT anchoring | No | Local transparency log only |
| DX-O-3 Completion receipt | Yes | Operations allowed and denied, changes with before and after digests, rollbacks, end-state digest, audit root |
| DX-O-4 Kill switch | Yes | |
| DX-O-5 Post-job audit | No | |
| Levels D1 / D2 / D3 | D1, D2 | D3 (security and financial classes with a two-person rule) is not implemented. An optional provider-technician co-sign on step-ups is |

## What would close the biggest gaps

1. Emit the spec's HAA object (JWS, `actionClass`, `payloadHash`, nonce, expiry) from the existing passkey step-up.
2. Move the envelopes to JWS with JCS, and add an ES256 suite alongside EdDSA.
3. A real connector, such as a Microsoft Graph sandbox tenant, to exercise DX-A-2 to DX-A-5 for real.
4. Package the red-team corpus as a standalone conformance suite.

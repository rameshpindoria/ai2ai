# Example: IT support demo, step by step

![The demo, start to finish](../../docs/demo.gif)

This walkthrough runs the whole platform on your own computer and takes you through one real job, start to finish.

- **You** play the customer: someone at a small office whose printer has stopped working.
- **The provider's agent** diagnoses and fixes the problem. By default it is *RuleBook*, a rules-only agent with no
  AI model, so the demo needs no API keys.
- Every change waits for **your** passkey approval. You can undo it or stop the job at any time.

Everything runs on `localhost`, and all data is fictional. The "office" is a simulated IT estate.

## What you need

- Python 3.12
- A browser with passkey support, and a way to create a passkey on this device (Windows Hello, Touch ID, a security
  key or your phone)
- Ports 8800 and 8810 free

## 1. Start the demo

From the repository root:

    pip install -r requirements.txt
    python scripts/demo_stack.py --scenario S07 --minutes 60

This starts three separate processes, the same split a real deployment uses:

| Process | Address | Plays the part of |
|---|---|---|
| Centre | http://localhost:8800 | the marketplace operator |
| Customer edge | http://localhost:8810 | the customer's own system: passkeys, broker, approvals |
| Provider runtime | (no web page) | the provider's agent, polling for work |

It also creates a verified provider with a listed agent, a customer account and a registered edge. It puts the
**S07 "print queue stalled"** fault into the simulated office.

When it is ready, it prints something like this:

```json
{
 "centre": "http://localhost:8800",
 "edge": "http://localhost:8810",
 "password": "Demo-Password-2026",
 "customer": "kim@customer.demo",
 "approver_enrol_url": "http://localhost:8810/edge/enrol?code=...",
 "ticket_to_type": "Nobody in the office can print. Jobs just sit in the queue on the office printer.",
 ...
}
```

The same details are saved to `demo.json` in the demo data folder: `%LOCALAPPDATA%\ai2ai-platform\demo` on Windows,
`~/ai2ai-platform/demo` elsewhere. That folder is wiped each time the demo starts.

## 2. Set up your passkey (customer edge)

1. Open the **`approver_enrol_url`** from the output.
2. On **Set up your passkey**, click **Create passkey** and approve it with your device.

This passkey is how you, the customer, approve everything from here on. It is a real passkey for `localhost`, so
you can delete it from your device's passkey settings afterwards.

## 3. Find a provider (centre)

1. Go to **http://localhost:8800** and sign in as `kim@customer.demo` with the password from the output.
2. Under **Get an IT issue fixed**, describe the problem:

   > Nobody in the office can print. Jobs just sit in the queue on the office printer.

3. Click **Find providers**. The centre matches your words to a category and shows the verified provider, with its
   badges (security certification, insurance).
4. Click **Request on my edge**. You are taken to **your own edge**. The centre never sees the details you type next.

## 4. Approve the Work Order (customer edge)

1. Under **Describe the issue**, paste the same problem text.
2. Leave **What may the agent do?** at *Diagnose and fix (you approve each change)*, which is level D2.
3. Click **Prepare Work Order** and review it: the provider, the level, the allowed action classes and the time
   window.
4. Click **Approve with passkey**.

The edge has now checked the provider's signed listing against the centre's key and the revocation list. Your
approval is recorded as a signed Work Order.

## 5. Watch the agent work, and approve its change

The job page updates as the agent works:

- **Audit log:** every read the agent makes. Results go back to the agent wrapped as *untrusted* data.
- **Approval needed:** when the agent wants to change something, you see the exact operation in plain words. In
  this scenario it is clearing the stalled print queue. Click **Approve with passkey**, or **Decline**.
- **Changes:** what was changed, with a snapshot taken first. A change that fails its check is rolled back
  automatically.
- **Receipt:** when the agent finishes, a receipt signed by your edge, with the provider's signed statement inside.

You are in control the whole time:

- **Undo last change** restores the snapshot.
- **Stop this job now** is the kill switch. The agent's next request is refused.

## 6. Try more

- **Other faults:** restart with another scenario, for example `--scenario S01` (account locked out) or
  `--scenario S14` (trojan found on a staff PC). Four scenarios are security-sensitive (S02, S10, S24, S25), and the
  agent must hand those to a human instead of fixing them. List them all with:

      python -c "from ai2ai_platform.usecases.it_support.scenarios import SCENARIOS; [print(s.id, s.title) for s in SCENARIOS]"

- **A real AI agent:** `--agent claude` uses Claude Code (this needs the `claude` CLI, signed in). Its built-in
  tools are switched off, and it can reach your edge only through the platform's MCP bridge.
- **The provider's and operator's view:** sign in at http://localhost:8800 as the provider (`pat@provider.demo`) or
  the platform admin (`admin@ai2ai.demo`), with the same password.

## What this demo shows

| You saw | Spec requirement |
|---|---|
| Only the customer can start a job, on their own edge | DX-WO-1 |
| The Work Order and each change approved by passkey, bound to the exact command | HAA-1 to HAA-3, DX-S-3 |
| The approval text comes from the operation catalogue, not from the agent | HAA-4, DX-S-2 |
| Reads wrapped as untrusted data | CH-3, DX-U-1 |
| Snapshot before change, automatic rollback, undo | DX-R-1 |
| Kill switch that needs no cooperation from the provider | ST-2, DX-O-4 |
| Signed receipt and hash-chained audit log | RC-1, DX-O-1, DX-O-3 |

What is and isn't implemented is listed in [`docs/IMPLEMENTATION-STATUS.md`](../../docs/IMPLEMENTATION-STATUS.md).

## Stop the demo

Press **Ctrl+C** in the terminal, or let the `--minutes` timer run out.

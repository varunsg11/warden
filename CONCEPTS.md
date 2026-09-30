# Concepts

The ideas behind Warden, each tied to the code that implements it. This is the
"why," meant to be read alongside the source.

---

### Indirect prompt injection
Malicious instructions that arrive through **data the agent consumes** (a document,
a web page, a tool result) rather than through the user's own message (that would be
*direct* injection). To an LLM, the system prompt, the user turn, and a retrieved
document are one flat token stream — there is no structural boundary marking "this
part is data, not a command." The indirect variety is the unsolved one because the
attacker only needs to influence content the agent will later read.
→ [`warden/corpus/docs/ticket_9981_POISONED.txt`](src/warden/corpus/docs/ticket_9981_POISONED.txt), consumed via [`search_docs`](src/warden/pipeline/tools.py).

### Confused deputy
A component with legitimate authority (the "deputy") is tricked into using it on
an attacker's behalf. Our refund agent may legitimately issue refunds; the injection
doesn't steal that authority, it **borrows** it. The agent isn't hacked — it's
confused about *whose* instruction it's following.
→ [`refund_node`](src/warden/pipeline/agents.py).

### Least privilege & just-in-time (JIT) access
Grant the minimum authority needed, and only for as long as it's needed. For agents
this can't be a static role, because agents switch tasks constantly — so authority is
issued **per task, per turn**. A `summarize` task carries no refund authority at all.
→ [`policy.py`](src/warden/governance/policy.py) (keyed by task), [`issuer.py`](src/warden/governance/issuer.py).

### Ambient authority
The danger of an agent inheriting broad, standing permissions it can use without
asking. Capabilities are the antidote: **no authority exists except the token handed
out for this specific call.** When the fooled refund agent proposes a call it holds no
capability for, it's denied at the first check.
→ the `capability_present` check in [`gate.py`](src/warden/governance/gate.py).

### Agent as a first-class principal
Rather than borrowing a human's or service account's broad credentials, each agent
role gets its **own identity and its own scoped, signed manifest**. Authority is
explicit and attributable.
→ [`Supervisor.issue_all`](src/warden/governance/issuer.py).

### Authorization outside the reasoning loop
The single sentence that justifies the whole architecture (per the Coalition for
Secure AI's 2026 guidance): the layer that decides *"is this allowed?"* must sit
**outside** the agent's reasoning. An in-context guard — or an "LLM-as-judge" — is
injectable by the same attack it's meant to stop, because persuasive text can talk it
out of blocking. Warden's decisions are made by ordinary Python.
→ the entire [`warden/governance/`](src/warden/governance/) package contains no LLM call.

### Capabilities & un-forgeability (Ed25519)
A capability is a signed permission slip: `c = (tool, params, scope, ttl, nonce,
issuer, signature)`. The signature gives **integrity** (change one byte and it fails)
and **authenticity** (only the Supervisor's private key can mint one). The gate holds
only the *public* key, so it can verify but never forge — the untrusted side can check,
not create.
→ [`capability.py`](src/warden/governance/capability.py), [`signing.py`](src/warden/governance/signing.py).

### TOCTOU & capability expiry
Time-of-check to time-of-use: a permission valid when granted must not stay valid
forever. Every capability carries a `ttl`, and the gate re-checks expiry at the moment
of use, not just at issue time.
→ `Capability.is_expired`, the `not_expired` check in [`gate.py`](src/warden/governance/gate.py).

### Defense in depth (gate + drift)
Two independent lines. The **gate** catches calls that are *out of bounds*. The
**drift detector** catches calls that are *in bounds but abnormal* — a refund the
policy permits yet unlike anything the business has ever done, or an email to a
never-seen domain (which the gate can't help with, because you can't allowlist every
legitimate recipient).
→ two stages in [`GatedToolRunner.authorize`](src/warden/pipeline/runner.py); [`drift.py`](src/warden/governance/drift.py).

### Why the drift detector is statistics, not an LLM
An LLM judge is injectable by the same prompt injection we're defending against — the
attacker could talk it out of flagging. Statistics can't be sweet-talked. Drift uses
novel-category and numeric-outlier rules, and its baseline is learned **offline from
clean traffic and never updated from live calls** — otherwise an attacker "boils the
frog," drifting the norm until the abnormal looks normal.
→ [`DriftDetector`](src/warden/governance/drift.py).

### Tamper-evident audit
In regulated settings least privilege becomes an **evidentiary obligation**, so the
log must be tamper-*evident*. Each record carries the hash of the one before it; alter
or delete any past line and every downstream hash stops matching.
→ [`audit.py`](src/warden/governance/audit.py) (`verify_chain`).

### Trusted vs. untrusted channels
The linchpin of the JIT design: the **task** comes from the trusted caller (the app,
representing the real user), while the **documents** come from an untrusted, attacker-
influenceable source. The injection controls the data channel but not the control
channel — so it can change what the agent *reads*, never what it's *authorized* to do.
→ the `task` argument threaded from the app through [`build_governed_pipeline`](src/warden/pipeline/graph.py).

### In-envelope attacks & provenance (taint tracking)
An envelope says which values are *allowed*. It can't say which one the *user meant*.
If the allowlist holds accounts 1234 and 5678 and the customer on 1234 asked for a
refund, an injection only has to steer the agent to 5678. That call passes the gate
and looks normal to drift. The tell is **provenance**: 1234 appears in the user's
request, and 5678 appears only in a retrieved document. Taint tracking (as in CaMeL and
FIDES) follows data from untrusted sources to sensitive sinks. Warden approximates it
deterministically. The session records trusted text (the request) and untrusted text
(every tool output), and a `from = "trusted"` rule requires a sensitive argument to
appear in trusted text. The price is utility: a value that legitimately came from a
document is denied as well.
→ [`provenance.py`](src/warden/governance/provenance.py), the `provenance_ok` check in [`gate.py`](src/warden/governance/gate.py).

### Fail closed
When a security check can't decide, it must deny, never allow. The gate turns any
internal error into a DENY. The schema validator rejects constraint keywords it doesn't
implement. A provenance rule with no provenance tracked denies. Drift flags a watched
feature it can't read. The policy loader refuses rules the gate doesn't enforce. Each
of these once had, or could have had, a quiet "skip" that an attacker would aim for,
such as a NaN amount that compared False against every bound.
→ [`gate.py`](src/warden/governance/gate.py), [`schema.py`](src/warden/governance/schema.py), [`policy_loader.py`](src/warden/governance/policy_loader.py), [`drift.py`](src/warden/governance/drift.py).

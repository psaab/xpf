# Claude SMR — HOSTILE plan review, round 1 (#5078)

Reviewer posture: assume the design is wrong until each claim survives a
concrete attack. Target: `docs/research/5078-syncauth-reflection/plan.md`.

**Verdict: PLAN-SOUND, conditional on the must-fix implementation constraints
below.** The design closes both reflection vectors and the reflected-frame
primitive. It does **not** (and does not claim to) close the passive-tap
plaintext residual — that is correctly deferred to Option B. Two constraints
are load-bearing and, if implemented naively (by copying the existing
`syncDeriveFrameKey` sort pattern), would silently re-open the full bypass.

---

## A. Does role + channel binding actually stop reflection? — mostly YES, with one footgun

### A1. Vector A (single-connection mirror): CLOSED, twice over.
On a single connection the attacker can only relay V's own bytes. To be
accepted, V checks the received proof against `proof(localNonce)`; the only way
to obtain `proof(nonce_V)` from V is to advertise `peerNonce = nonce_V` — the
equal-nonce case, now rejected (§3.3) *before* any HMAC. Independently, the
reflected proof carries our own role byte (§3.2) and fails the opposite-role
check. Redundantly closed. **Accept.**

### A2. Vector B (two-connection cross-reflection): CLOSED — but ONLY by the
endpoint *ordering*, and this is the single most fragile point in the plan.

I re-derived it adversarially. The attacker makes V play responder on Conn-α
and initiator on Conn-β, and equalizes the nonces across the two connections
(attacker controls its own advertised nonce on each). With role + both-nonces
binding *alone*, the two transcripts become equal and the reflection succeeds —
the plan correctly concedes this in §1.3. The ONLY thing that separates the two
transcripts is the endpoint pair, and it separates them **only because it is
ordered by role**:

- V-responder binds `(ep_init = V.peerAddr, ep_resp = V.localAddr)`.
- V-initiator binds `(ep_init = V.localAddr, ep_resp = V.peerAddr)`.

Reversed → different transcript → reflected proof rejected. Correct.

**MUST-FIX #1 (critical).** The current `syncDeriveFrameKey` (L232-240)
*canonically sorts* its two nonces so both peers agree. The obvious, wrong,
"consistent with existing code" implementation is to sort the endpoints (and
nonces) the same way. **If the endpoints or nonces are sorted/canonicalized by
value instead of ordered by role, Vector B is fully re-opened** — the very
symmetry that makes today's frame key undirected is what the attacker exploits.
The plan says "role-ordered" but the engineer will be staring at a sort-based
sibling function. This must be called out in the code as a hard invariant, and
the Vector-B unit test (§6.1 #4) must assert that swapping the endpoint order
changes the proof. Without that test the regression is invisible.

### A3. Residual: passive relay still reads plaintext. HONESTLY SCOPED.
After the fix, the strongest active attacker degrades to a passive on-path
relay between two legit PSK-holders: it cannot be *accepted* as an independent
peer, cannot forge/inject sealed frames (no PSK → no directional key), cannot
feed crafted state. It CAN still read plaintext session/config as it relays
(the seal is not encryption). The plan states this (§1.2, §5, §7) and defers to
Option B. I confirm this is the correct Option-A boundary — but the issue title
says "reading all plaintext session/config state," so the **issue comment must
be explicit** that Option A closes *impersonation/injection/displacement* and
that *passive read on a compromised fabric* remains until Option B. Do not let
the reader think Option A makes the fabric confidential.

---

## B. Is the compat / flag-day story safe? — YES for a 2-node cluster, with a sharp edge

### B1. Fail-closed is the only correct choice. Confirmed.
Any v1-accepting fallback is a downgrade oracle (attacker advertises
version=1). The plan rejects negotiation-with-interop for exactly this reason.
Agree. There is no safe partial state.

### B2. The sharp edge: fail-closed removes ALL graceful degradation, so a
transcript bug is a production cluster-wide sync outage with no fallback.
This raises the stakes on §4/§5's "transcript must be byte-identical." I rate
**transcript asymmetry as the #1 production risk**, above the security
property (the security property is easy to test; a subtle asymmetry —
`addr:port` string formatting, IPv6 zone/brackets, a node reading `localAddr`
where it should read the fabric-specific `localAddr1`, endianness of the u32
node-id — will pass a single-process unit test that shares a builder yet fail
across two real daemons). **MUST-FIX #2:** the two-node `make test-failover`
gate is not optional colour; it is the only test that exercises two *distinct*
processes deriving the transcript independently. It must run keyed↔keyed and
confirm the `connection authenticated` log on every reconnect. A unit test that
builds both transcripts in one process can mask an asymmetry that only appears
across hosts (e.g., if any input is derived from a live socket address rather
than config).

### B3. Mixed-version failover drop is real but acceptable.
The plan is honest that a failover during the v1/v2 window drops established
flows. For a 2-node cluster upgraded in a maintenance window this is standard
ISSU. Accept, provided the operator doc + PR body state it plainly and the
`slog.Warn` names the version-mismatch cause (so a confused operator doesn't
chase a phantom bug). One addition: emit a **distinct, persistent** log/alarm
while a keyed peer is being rejected purely for version, so the degraded state
is observable in `show chassis cluster` / metrics, not just a one-shot warn.

---

## C. Any residual oracle? — send-first is safe *given* binding, but note the dependency

The plan reorders to responder-validates-first (good) yet the initiator still
sends first. I attacked this: an attacker posing as the responder (V dials it)
harvests `proof_initiator` for free. It is useless because (a) it is bound to a
fresh per-connection nonce, and (b) V only *expects* `proof_initiator` when V is
the responder, where the endpoint ordering is reversed → different transcript.
So the send-first leak is neutralized **entirely by §3.1/§3.2 binding**, not by
the ordering. That is fine, but it means the ordering reorder is defense-in-
depth, not the actual fix — the plan says as much (§3.4). **Accept**, with the
note that the security argument rests on binding, so the tests must target
binding (role + endpoint ordering), not just "we now read before write."

Minor: confirm the reordered exchange still sets `conn.SetDeadline(now+3s)`
(L367) and that a responder blocking on the initiator proof cannot leak a
goroutine if the attacker never sends — the 3s deadline must bound it. The plan
mentions net.Pipe deadlock (§4.5) but should also assert the timeout still
bounds a silent peer.

---

## D. Directional frame keys — correct, and independently valuable

`k_i2r ≠ k_r2i` closes the "reflect V's own sealed frames into V's handlers"
primitive even if the handshake fix had a hole — good layering. **MUST-FIX #3
(same root as #1):** derive the two keys with a **direction byte**, NOT by
sorting nonces. The existing `syncDeriveFrameKey` sorts; the replacement must
NOT. Assert `k_i2r ≠ k_r2i` and assert a frame sealed `k_i2r` fails an
initiator's `recvKey` (`k_r2i`) verify (the reflected-frame test). The
`authConn.key → sendKey/recvKey` split touches `sealFrame`, `verifyFrame`,
`authed()`, `wrapSyncConn`, and the test helpers that literally construct
`authConn{Conn, key}` (`sync_auth_test.go:80-82`,
`TestSyncFrameSealVerifyRoundTripAndReplay`). Confirm no other package
constructs `authConn` (grep says only `sync_protocol.go`/`sync_conn.go`/tests —
contained). Update the round-trip test to use the correct per-role key on each
side, or it will pass for the wrong reason (a symmetric key would still
round-trip and hide a directionality bug — so the test MUST also assert the
reflect-back FAILS).

---

## E. Things the plan gets right that I tried and failed to break

- Using **configured** endpoints (not live socket addrs) — live addrs differ
  per view (ephemeral port, source selection) and would break the legit path;
  config addrs are role-symmetric across the two nodes. Correct call.
- Treating `peerNodeID` as **untrusted** (peer-asserted from heartbeats,
  `heartbeat_manager.go:302`) and resting identity binding on endpoints, not the
  claimed id. Correct — a claimed-id binding is attacker-equalizable (claim V's
  id) unless paired with dup-id rejection, and even then adds nothing over
  endpoints. Endpoints-only for the hotfix is the right minimalism.
- Preserving the **unkeyed dual-accept** wire byte-for-byte. Rolling-upgrade
  and no-PSK deployments untouched.
- Not reaching for Option B under time pressure while still recording it as the
  strategic answer. Correct scoping.

---

## F. Nits / smaller asks

1. §3.1: pin the endpoint **string normalization** — both nodes must format the
   `addr:port` identically. Prefer binding the parsed `netip.AddrPort`
   canonical bytes (16-byte addr + u16 port), not the raw config string, to
   avoid `10.0.0.1:7000` vs `10.0.0.1:07000` / IPv6-bracket variance. **Add to
   MUST-FIX #2's asymmetry list.**
2. §3.7: state explicitly that a v2 node seeing a v1 **unkeyed** peer still
   dual-accepts (only *keyed↔keyed* v1 fails closed). The plan implies it;
   make it a bullet so the engineer doesn't over-reject.
3. Future-proofing: if anyone later adds v3 with negotiation, the transcript
   must bind **both advertised versions**, not the min, or a downgrade becomes
   invisible. Add a one-line code comment at the version constant.
4. §6: add an explicit assertion that the **legit** two-node handshake derives
   `ar.sendKey == br.recvKey` and `ar.recvKey == br.sendKey` (cross-role key
   agreement) — the single most likely place a role-ordering bug hides.

---

## G. Verdict

**PLAN-READY** once the plan absorbs MUST-FIX #1 (endpoints/nonces ordered by
ROLE, never sorted — with a Vector-B test that would catch a sort),
MUST-FIX #2 (two-process `make test-failover` is the only real transcript-
asymmetry gate; normalize endpoint bytes), and MUST-FIX #3 (directional keys via
direction byte, reflected-frame-fails test). These are refinements to an
already-correct design, not redesigns. The security argument survives the
concrete Vector-A and Vector-B attacks; the residual passive-tap read is
correctly scoped to Option B and must be stated plainly in the issue comment.

No blocking objection. Recommend proceeding to `/engineer` after the three
must-fix constraints are folded into the plan's §3/§6 (done in r1 revision
below).

---

## H. r2 addendum — I was wrong on the passive-relay residual (Codex refutation)

Codex's hostile review (`codex-plan-r1.md`) refuted §A3/§G above. I claimed a
passive on-path relay "cannot forge/inject sealed frames (no PSK → no
directional key)." That is **false for this codebase**: when `config-sync` is
enabled the session-sync stream carries `ShowActive()` — the raw cleartext
config **including `chassis cluster authentication-key <secret>`, the very PSK**
— sealed only by HMAC. Verified against origin/master (`daemon_ha_sync.go:311`,
`store_format.go:31`/`297`, `ast_redact.go:117`, `sealFrame` HMAC-only). So a
passive relay reads the PSK from the config frame and escalates to a full active
forger. My "Option A closes impersonation/injection; only passive read remains"
boundary is wrong: **confidentiality is mandatory, not deferrable.**

Codex also found Blocker 2 (keyed-local dual-accept + pre-admission
`syncMsgFence` execution) that my review missed entirely — a PSK-less active
bypass independent of the reflection bug.

Both are folded into plan §0/§3.9/§3.10. My §A/§B/§C/§D/§E analysis of the
*cryptographic construction* stands (all three reviewers agree it is sound); my
*scope* judgment was too narrow. Net verdict updates to **PLAN-READY on the r2
(scope-expanded) design**, not the r1 narrow scope.

# #5078 — cluster session-sync PSK handshake is reflection-authenticatable

Status: **PLAN-READY** (Claude-SMR converged r1; companion reviews attempted —
see §10 verdicts). Hostile self-review in `claude-smr-plan-r1.md`; its three
MUST-FIX constraints are folded into §3.1/§3.5/§3.7/§6 below.
Branch: `research/5078-syncauth-reflection` (plan docs only — no production
source).
Severity: **HIGH / High confidence**. Source: codex-review-177 `[A5-b1-F1]`.
Deliverable for `/engineer`: harden the custom mutual challenge-response
session-sync handshake (`pkg/cluster/sync_auth.go`) with explicit
initiator/responder **role binding**, full **transcript / channel binding**,
**equal-nonce rejection**, and **directional frame keys**, plus a fail-closed
**version flag-day** for the keyed↔keyed wire. Touches the on-wire
session-sync handshake and per-frame seal → MUST pass loss-cluster
`make test-failover` before commit.

Verified against origin/master `5e34920d1` (issue cites `812bf30c1`;
`pkg/cluster/sync_auth.go` is byte-identical at both — the vulnerability is
live on current origin/master). All code line references below are
origin/master.

---

## 1. Issue framing

`pkg/cluster/sync_auth.go` (#4107 F23) authenticates the cross-chassis
session-sync TCP stream. Only a node holding the control-link PSK
(`set chassis cluster authentication-key`) handshakes; two keyed peers run a
"mutual challenge-response" at connection setup, then seal every subsequent
length-framed message with a per-connection sequence + HMAC.

The handshake (`performSyncHandshake`, L329-408) is **fully symmetric with no
role, identity, or channel binding, and accepts an equal (reflected) nonce**:

- Each side sends `HELLO{version, keyed, nonce[32]}` (L378-386).
- Each side computes its proof over the **peer's** nonce:
  `proofOut := syncAuthProof(key, peerNonce)` = `HMAC(key, proofTag ‖ peerNonce)`
  (L388-390, `syncAuthProof` L220-224), and **sends it before reading the peer
  proof** (L390-399).
- Each side accepts iff the received proof equals its own proof over its **own**
  nonce: `hmac.Equal(ppayload, syncAuthProof(key, localNonce))` (L401).
- The frame key is **undirected**: `syncDeriveFrameKey` (L232-240) canonically
  **sorts** the two nonces so both directions derive one identical key.

There is no initiator/responder tag, no node-id or endpoint binding, no
transcript, no equal-nonce check, and one bidirectional frame key. That is the
textbook precondition for a **reflection attack**.

### 1.1 Blast radius (who runs the handshake — both sides)

`performSyncHandshake` is invoked from exactly one place,
`handleNewConnection` (`sync_conn.go:483`), which is the **shared** setup path
for **both** roles:

- **Responder** — `acceptLoop` (`sync_conn.go:1180-1210`) spawns
  `handleNewConnection` per inbound TCP connection.
- **Initiator** — `fabricConnectLoop` (`sync_conn.go:1215-1252`) dials the peer
  and calls `handleNewConnection` on the dialed connection.

Neither passes a role. Which node dials is decided by `shouldInitiateFabricDial`
(`sync_conn.go:399-412`): the node with the numerically **lower** fabric
`addr:port` dials (initiator); the higher listens (responder). This is
antisymmetric, so for a given fabric **both real nodes already agree who is
initiator** — but an attacker does not respect it, and the handshake code never
consults it. Dual-fabric (`fab0`/`fab1`) each get an independent
connect/accept pair.

On success `handleNewConnection` **closes any existing conn** for that fabric
and installs the new one (`sync_conn.go:500-520`) — so a winning attacker
**displaces** the legitimate peer connection.

### 1.2 What the frame seal does / does NOT protect

`sealFrame` (L178-188) appends `seq(8) ‖ HMAC-SHA256(32)` to the fully-encoded
frame. **It is integrity/authenticity only — the payload stays plaintext.**
Session tuples, config text, IPsec SA names, DHCP leases, and failover/election
control all travel in the clear (the fabric/control link is the trust
boundary). The handshake's job is therefore to prove *who is on the other end*
so that an **active** attacker cannot be accepted as the peer — it does not and
was never intended to hide bytes from a passive tap on the trusted fabric.

### 1.3 Concrete reflection vectors (exact bytes)

**Vector A — same-connection mirror (trivial).** A PSK-less attacker that can
occupy a fabric TCP endpoint (reach the victim's listener, or be dialed by the
victim after taking the peer's fabric IP while the peer is down) simply
**echoes every byte back**:

1. Victim V sends `HELLO{v=1, keyed=1, nonce_V}`.
2. Attacker echoes it verbatim → V reads it as the peer HELLO with
   `peerNonce = nonce_V` (equal nonce — **not rejected**).
3. V computes `proofOut = syncAuthProof(key, peerNonce) = syncAuthProof(key,
   nonce_V)` and **sends it first** (L388-390).
4. Attacker echoes that proof back.
5. V checks `hmac.Equal(ppayload, syncAuthProof(key, nonce_V))` → **true**.
   `syncAuthDecision(true,true,true,true,·)` → **authenticated** (L403-405).

V now believes it is talking to an authenticated peer. It derives
`frameKey = syncDeriveFrameKey(key, nonce_V, nonce_V)` and starts pushing
sealed **plaintext** session/config frames — which the attacker reads. The
attacker cannot compute the frame key (no PSK) so it cannot forge *new* sealed
frames, **but the undirected key means V's own sealed frames verify inbound on
V**: the attacker reflects V's sealed frames and V's `receiveLoop`
(`sync_conn.go:1349-1364`) accepts them (valid MAC — V's own key; `recvSeq` and
`sendSeq` are independent counters) and feeds them to peer-state handlers. So
the attacker gets, with **no PSK**: (a) displacement of the real peer
connection (HA-sync DoS), (b) disclosure of all plaintext session/config, (c)
selective reflection/reordering of V's own signed control frames
(delete/failover/config) into V's own handlers, (d) indefinite sync-liveness
refresh.

**Vector B — two-connection cross reflection (survives a naive equal-nonce
check).** The attacker opens two connections and uses V as its own proof
oracle:

- Conn-α: attacker → V's listener (V is **responder**). V sends
  `HELLO{nonce_R}`; V will accept a proof over `nonce_R`.
- Conn-β: V dials the attacker (V is **initiator**, requires the attacker to
  hold the peer fabric address). V sends `HELLO{nonce_I}`.
- On Conn-β the attacker advertises `peerNonce = nonce_R`; V-β computes
  `syncAuthProof(key, nonce_R)` and sends it. The attacker **reflects it onto
  Conn-α**, where V-α accepts a proof over `nonce_R`. V-α authenticates.

Here the two nonces on each connection differ, so a naive "reject
peerNonce == localNonce" check does **not** stop Vector B. Defeating B requires
binding the proof to something the attacker cannot equalize across the two
connections — i.e. **role + channel binding** (§3). This is the load-bearing
subtlety: equal-nonce rejection is necessary but **not sufficient**.

### 1.4 Invariant that is violated

A mutual challenge-response must prove possession by the **opposite role** and
must derive **independent** initiator→responder / responder→initiator keys; a
reflected nonce or proof must be rejected. The current construction proves
possession by *some* keyed party over *a* nonce, with no notion of role,
identity, direction, or transcript — so a reflected value satisfies it.

---

## 2. Honest scope / value framing

- **Severity HIGH, exploitability gated on fabric position.** The attacker must
  occupy a session-sync TCP endpoint on the control/fabric link (dial the
  listener, or take the peer's fabric IP). On a correctly isolated cluster
  control link that is a strong precondition — but "the fabric is a security
  boundary the PSK is *supposed* to authenticate" is exactly the property the
  bug breaks. The whole point of #4107 F23 was to make a fabric-position
  attacker insufficient; this defect returns that attacker to fully
  authenticated.
- This is a **correctness/security** fix on a control path, not a throughput
  change. No packet hot path is touched.
- The fix must **preserve dual-accept / rolling-upgrade** behaviour for the
  *unkeyed* case bit-for-bit (a node with no PSK still never handshakes) and
  must keep `make test-failover` green (session-sync is failover-critical).

---

## 3. Concrete design

Two tracks were considered:

- **Option A (recommended, this plan): harden the existing custom handshake** —
  role tag + transcript/channel binding + equal-nonce rejection + directional
  frame keys + version flag-day. Contained to `sync_auth.go` + a role param
  threaded from the two loops; preserves the dual-accept machinery and the
  existing test surface; ships fast.
- **Option B (follow-up, separate issue): replace with a standard
  mutually-authenticated PSK construction** (TLS 1.3 `psk_ke` / external-PSK,
  or Noise `NNpsk0`/`XXpsk0`). This is the issue's stated "prefer a standard
  construction" direction and additionally buys **confidentiality** and
  audited downgrade resistance. It is a much larger change (new handshake,
  reframing, dependency, re-doing dual-accept + the heartbeat/fabric-gRPC PSK
  story) and is **out of scope for the HIGH-sev hotfix**. Recommend filing it
  as a strategic follow-up. §7 records this decision so a reviewer sees it was
  weighed, not missed.

The rest of §3 specifies Option A.

### 3.0 Roles

Thread an explicit `initiator bool` from the loops through
`handleNewConnection` into `performSyncHandshake`:

- `fabricConnectLoop` → `initiator = true`.
- `acceptLoop` → `initiator = false`.

Both real nodes already agree (via `shouldInitiateFabricDial`), and each node
knows its own role locally without trusting the peer. The role is a **local**
fact (did I dial or accept), never taken from the wire.

### 3.1 Transcript (channel binding)

Both sides compute an identical **role-ordered** transcript from
mutually-known, non-attacker-equalizable inputs:

```
transcript = SHA256(
    LP("xpf-cluster-sync-transcript-v2") ‖
    u8(version)               ‖   // negotiated = 2
    LP(nonce_initiator)       ‖   // 32B, initiator's fresh nonce
    LP(nonce_responder)       ‖   // 32B, responder's fresh nonce
    LP(ep_initiator)          ‖   // initiator's CONFIGURED fabric addr:port
    LP(ep_responder)          ‖   // responder's CONFIGURED fabric addr:port
    u32(nodeid_initiator)     ‖   // initiator's LOCAL node-id (optional, §3.6)
    u32(nodeid_responder)         // responder's LOCAL node-id (optional)
)
```

`LP(x)` = 4-byte little-endian length prefix ‖ `x` (unambiguous framing; no
field-boundary confusion). "initiator/responder" slots are filled by **role**,
not by socket direction, so both nodes populate identical bytes.

> **CRITICAL INVARIANT (Claude-SMR MUST-FIX #1).** The transcript fields
> (nonces, endpoints, node-ids) MUST be ordered by **role**
> (initiator-slot, responder-slot), **NEVER canonically sorted by value.**
> The sibling `syncDeriveFrameKey` (L232-240) today *sorts* its two nonces so
> the key is undirected — copying that sort into the transcript would make
> `transcript_responder == transcript_initiator` and **re-open Vector B in
> full**. Role-ordering is the entire mechanism that separates the two
> reflected transcripts (§3.2). The code MUST carry this as a hard comment and
> §6.1 test #4 MUST assert that swapping the endpoint slots changes the proof
> (a test that would go RED if someone "consistency-refactors" to a sort).

The slots:

- The **endpoints** are the *configured* fabric addresses
  (`s.localAddr`/`s.peerAddr` for the fabric, `…1` for fab1) — **not** live
  socket addresses. Node A's `localAddr` == node B's `peerAddr`, so
  role-ordered they agree: if A is initiator, both compute
  `ep_initiator = A_addr, ep_responder = B_addr`. These are each node's own
  fixed config; an attacker cannot set them equal to V's value, and
  `A_addr ≠ B_addr`. **This is what defeats Vector B**: V-as-responder binds
  `(ep_init = V.peerAddr, ep_resp = V.localAddr)`; V-as-initiator binds
  `(ep_init = V.localAddr, ep_resp = V.peerAddr)` — reversed, so a proof
  produced in one role never validates in the other.
  **Normalization (Claude-SMR MUST-FIX #2):** bind the *canonical parsed*
  `netip.AddrPort` bytes (16-byte address ‖ u16 port), **not** the raw config
  string, so `10.0.0.1:7000` vs a zero-padded/IPv6-bracketed spelling cannot
  make two real daemons derive different transcripts. Both nodes must parse and
  re-serialize identically; any string-formatting asymmetry is a silent
  production sync outage under the fail-closed flag-day (§3.7).
- Node-ids use each node's **local** `nodeID` in its own role slot (Manager
  has both `nodeID` and, asserted, `peerNodeID`). Because `peerNodeID` is
  peer-asserted (from heartbeats, `heartbeat_manager.go:302`) it is
  **not** trusted as binding material; identity binding rests on the
  endpoints. Node-ids are included only as defense-in-depth and MUST be paired
  with the existing duplicate-node-id rejection so an attacker cannot claim
  V's own id (see §3.6). If threading node-id proves noisy, endpoints alone are
  sufficient for the security property; node-id is optional.

### 3.2 Role-bound proof

```
proof_initiator = HMAC(key, proofTag ‖ 0x00 ‖ transcript)
proof_responder = HMAC(key, proofTag ‖ 0x01 ‖ transcript)
```

Wire discipline:

- **Initiator** sends `proof_initiator`, expects `proof_responder`.
- **Responder** sends `proof_responder`, expects `proof_initiator`.

A reflected value (the peer echoing what we sent) carries **our** role byte, so
it fails the check against the **opposite** role's expected proof. Combined with
the endpoint-ordered transcript, neither Vector A nor Vector B validates:

- Vector A (mirror): reflected proof has our role byte and, additionally, the
  equal nonce is rejected outright (§3.3).
- Vector B (cross reflection): the proof the attacker can extract from V-β is a
  `proof_initiator` over transcript_β whose `(ep_init, ep_resp)` is
  `(V.localAddr, V.peerAddr)`; V-α (responder) expects a `proof_initiator` over
  transcript_α whose `(ep_init, ep_resp)` is `(V.peerAddr, V.localAddr)` —
  reversed → mismatch → reject.

### 3.3 Equal / degenerate nonce rejection

Before computing the proof, reject:

- `peerNonce` **equal** to `localNonce` (`hmac.Equal`/`bytes.Equal`), and
- an **all-zero** `peerNonce` (a trivially predictable/degenerate value).

Rationale: cheap, kills the same-connection mirror before any HMAC work, and
guards against a peer that fails to seed its RNG. This is *necessary* (Vector A)
but *not sufficient* (Vector B) — it is layered with §3.1/§3.2, not a
substitute for them. "Sufficient entropy" cannot be measured from one sample;
we reject only the concrete degenerate cases (equal-to-ours, all-zero). Our own
nonce remains 32 bytes from `crypto/rand` (unchanged).

### 3.4 Ordering (send-before-read analysis + reorder)

Today each side **sends its proof before reading the peer's** (L388-399). Is
that an exploitable oracle? Under §3.1-3.2 the emitted proof is bound to a
**fresh per-connection nonce + role + endpoints**, so a leaked proof is useless
on any other connection (different transcript) and on *this* connection the
attacker would still need to be the opposite keyed role. So send-first is not a
usable oracle **once binding is in place**.

Nonetheless, because explicit roles make a request/response ordering
deadlock-free (the old symmetric protocol needed concurrent write+read to avoid
a `net.Pipe` deadlock — see the L370-376 comment), we **reorder to
responder-validates-first** as defense in depth:

1. Both send `HELLO` (nonces are public; may stay concurrent).
2. **Initiator** computes and sends `proof_initiator`.
3. **Responder** reads `proof_initiator`, **validates it**, and only then sends
   `proof_responder`.
4. **Initiator** reads and validates `proof_responder`.

The responder never emits a proof to an unvalidated peer. The initiator emits
first but its proof is transcript+role bound, so no oracle. HELLO exchange may
remain concurrent (public data); only the PROOF step is ordered. This removes
the goroutine-per-write dance for the proof leg.

### 3.5 Directional frame keys (+ counters)

Replace the single undirected `syncDeriveFrameKey` with a **directional** pair:

```
k_i2r = HMAC(key, frameKeyTag ‖ 0x00 ‖ transcript)   // initiator → responder
k_r2i = HMAC(key, frameKeyTag ‖ 0x01 ‖ transcript)   // responder → initiator
```

- Initiator: `sendKey = k_i2r`, `recvKey = k_r2i`.
- Responder: `sendKey = k_r2i`, `recvKey = k_i2r`.

`authConn` gains `sendKey`/`recvKey` (replacing the single `key`); `sealFrame`
uses `sendKey`, `verifyFrame` uses `recvKey`. A **reflected sealed frame** (our
own outbound, sealed with our `sendKey`) now fails inbound `verifyFrame` (which
uses `recvKey ≠ sendKey`) → the Vector-A "reflect V's own signed frames"
primitive is closed **even independently** of the handshake fix. The
per-connection sequence counters (`sendSeq`/`recvSeq`) are **already**
directional and stay as-is (the issue's "separate directional keys **and
counters**" — counters were already separate; only the key was shared).

> **CRITICAL INVARIANT (Claude-SMR MUST-FIX #3).** Derive the two keys with a
> **direction byte** (`0x00`/`0x01`), the same anti-sort discipline as
> MUST-FIX #1 — do NOT reuse `syncDeriveFrameKey`'s value-sort. §6.1 test #6
> MUST assert `k_i2r ≠ k_r2i` AND that a frame sealed with `k_i2r`, reflected
> back to the initiator, **FAILS** the initiator's `recvKey` (`k_r2i`) verify.
> A symmetric key would still round-trip and hide the bug — so the
> reflect-back-FAILS assertion, not merely the forward round-trip, is the
> real guard.

Minimal-diff alternative (documented, not preferred): keep one derived key but
fold a direction byte into the per-frame MAC input
(`sealFrame`/`verifyFrame`). Two derived keys are cleaner and match the issue
wording; the direction-byte variant is noted only as a smaller-diff fallback.

### 3.6 Node-id duplicate rejection (only if node-id binding is used)

If node-ids are bound (§3.1), also reject a peer HELLO advertising the local
node-id (mirrors the existing `election_dup_nodeid_4549` duplicate-id guard) so
an attacker cannot claim to be us and equalize the id slots. Endpoints already
carry the security property, so this is belt-and-suspenders.

### 3.7 Version / compat story (§5 of the ask) — **fail-closed flag-day**

The HELLO already carries `version:u8` (`syncAuthVersion = 1`). Introduce
`syncAuthVersion = 2` for the bound construction and bind the negotiated
version into the transcript.

**Recommendation: a coordinated (flag-day) upgrade, keyed↔keyed
fail-closed on version < 2 — NO silent v1 fallback.**

- A v2 node advertises `version = 2`.
- Peer advertises `version = 2`: both compute v2 (bound) proofs. The version is
  in the transcript, so a MITM cannot strip it without both sides' proofs
  diverging.
- Peer advertises `version = 1` (old keyed build): the v2 node does **not**
  fall back to the v1 (reflectable) proof. The keyed↔keyed handshake
  **fails closed** (connection dropped, `fabricConnectLoop` retries). A clear
  `slog.Warn` states the version-mismatch cause so operators know *why* sync is
  degraded.

**Why not version-negotiate-and-interop.** Any construction where a v2 node
still *accepts* a v1 proof re-opens the exact bypass: an attacker just
advertises `version = 1` to force the vulnerable path (a classic downgrade
attack). A security fix that leaves the vulnerable path reachable is not a fix.
So there is no safe partial state — it is v2-both or fail-closed.

**Operator impact & guidance (must be documented in the PR + operator doc).**
The cluster is two nodes. A rolling upgrade already reboots the standby (its
session table is cold on return). While one node is v1 and the other v2,
keyed↔keyed session-sync is **down**; the active keeps forwarding (data plane
unaffected), but a **failover during the mixed-version window would drop
established flows** (the standby holds no freshly-synced sessions). This is
standard ISSU discipline — *complete the upgrade on both nodes before
triggering a failover*. Document: (1) upgrade both nodes in the same
maintenance window, (2) do not fail over until both report v2 / sync
re-established, (3) new flows are unaffected throughout.

**Unkeyed nodes are unaffected** — a node with no PSK never handshakes and is
byte-for-byte a legacy peer (dual-accept), exactly as today. The flag-day is
strictly the *keyed↔keyed* wire. Explicitly: a v2 node facing a v1 **unkeyed**
peer still dual-accepts; only a v1 **keyed** peer fails closed. The engineer
must not over-reject the unkeyed case.

**Observability (Claude-SMR nit).** While a keyed peer is rejected purely for
version, emit a *distinct, persistent* alarm/log (surfaced in
`show chassis cluster` / metrics), not a one-shot warn — so a mid-upgrade
degraded state is observable rather than mistaken for a phantom bug.

**Future-proofing (Claude-SMR nit).** Add a code comment at the version
constant: if a later v3 introduces negotiation, the transcript MUST bind
**both advertised versions**, not the min, or a silent downgrade re-appears.

**Rejected alternative — transitional opt-in `allow-legacy-sync-auth` knob.**
An operator-gated one-window knob that permits v1 fallback would avoid the
mixed-version session drop, but it *is* the downgrade vector while enabled and
risks being left on. For a HIGH-sev auth-bypass we prefer fail-closed. Recorded
here so the reviewer sees it was considered and consciously rejected. If
operator pushback on the failover-window cost is strong, this knob (default
off, loud persistent alarm while on, auto-expiring) is the fallback — but it is
**not** recommended.

### 3.8 Downgrade-guard interaction

`syncAuthDecision` and the sticky `syncAuthedEver` / `HeartbeatPeerAuthSeen`
downgrade-guard are unchanged in shape. A v2 keyed node seeing a v1 keyed peer
returns `accept = false` (new "version too old" reason) rather than
dual-accepting — consistent with the existing "peer previously authenticated ⇒
reject unauthenticated" posture. Confirm the new reject reason threads through
`status.go` auth-status strings without leaking key material.

---

## 4. Hidden invariants / gotchas

1. **Both loops must pass the role.** `handleNewConnection` is shared; if only
   one call site is updated, one side runs role-less and the pair never agrees.
   A compile-time signature change (add `initiator bool`) forces every caller
   to choose — preferred over a silently-defaulted field.
2. **Endpoints must be the CONFIGURED addresses, role-ordered — not live
   socket addresses.** Live addresses differ per-view (ephemeral source port,
   NAT) and would make the two nodes' transcripts disagree → the *legitimate*
   handshake would fail. Bind `s.localAddr`/`s.peerAddr` (per fabric), ordered
   by role. Verify the fab1 pair (`localAddr1`/`peerAddr1`) is selected by
   `fabricIdx`.
3. **Transcript must be byte-identical on both nodes.** Any asymmetry (host
   order, case, trailing whitespace in the addr string, node-id source) breaks
   the legit path. Use length-prefixed fields and a single canonical builder
   shared by both `sealFrame`-key and proof derivation.
4. **Directional keys must be assigned by ROLE consistently.** Initiator's
   `sendKey` must equal responder's `recvKey` (`k_i2r`) and vice versa, or the
   first sealed frame fails to verify. A round-trip test (seal on A, verify on
   B, in *both* directions) is mandatory.
5. **net.Pipe deadlock.** The reorder (§3.4) must be deadlock-free on a fully
   synchronous transport (the test harness uses `net.Pipe`). Responder blocks
   reading the initiator proof; initiator writes it → no deadlock. Keep HELLO
   concurrent or ensure the HELLO order can't deadlock either.
6. **Equal-nonce check runs BEFORE key/proof derivation** so a mirror is
   dropped without doing HMAC work and without deriving a frame key from a
   degenerate `(n,n)` pair.
7. **`syncAuthProof` / `syncDeriveFrameKey` signatures change.** Existing tests
   (`TestSyncAuthProofBindsToNonce`, `TestSyncFrameSealVerifyRoundTripAndReplay`,
   `TestSyncAuthHandshakeBothKeyedAuthenticates`, the `runHandshake` helper,
   `TestSyncAuthDecisionMatrix`) call these and `performSyncHandshake(conn)`
   directly — they must be updated to pass roles/transcript. This is expected
   churn, not scope creep; the happy-path assertions stay.
8. **Frame-key = transcript-key coupling.** Both the proof and the frame keys
   derive from the same transcript. Keep distinct domain-separation tags
   (`proofTag` vs `frameKeyTag`, already present) so no cross-purpose reuse.
9. **Do not weaken the unkeyed dual-accept path.** Its bytes must not change
   (rolling-upgrade compatibility for no-PSK deployments and existing tests).

---

## 5. Risk assessment

- **Failover regression risk: MEDIUM — must gate on `make test-failover`.**
  The change is on the session-sync setup + per-frame seal, directly in the
  failover-critical path. A subtle transcript asymmetry would make two *legit*
  keyed nodes fail to authenticate → sync down → dropped flows on failover.
  The loss-cluster `make test-failover` (both nodes keyed, same PSK) is the
  backstop; it MUST pass before commit (per CLAUDE.md + MEMORY
  `feedback_verify_forwarding_with_sustained_iperf`).
- **Rolling-upgrade risk: KNOWN and ACCEPTED (flag-day).** Mixed v1/v2 keyed
  window has sync down (§3.7). Documented; standard ISSU discipline covers it.
- **Lock-out risk: LOW.** If the handshake mis-derives, the connection drops
  and retries every ~1s; it never bricks the daemon. Unkeyed deployments are
  untouched.
- **Complexity risk: LOW-MEDIUM.** Self-contained to `sync_auth.go` + a role
  param and an `authConn` field split. No new dependency (Option A).
- **Residual risk after fix:** a *passive* tap on the fabric still reads
  plaintext (by design — the seal is not encryption). Closing that is Option B
  (confidentiality), tracked separately. This plan closes the **active**
  reflection/impersonation bypass that is the reported HIGH defect.

---

## 6. Test plan

### 6.1 Fail-on-revert unit tests (`pkg/cluster/sync_auth_test.go`)

All are RED on the current code and GREEN after the fix:

1. **Reflected-nonce (mirror) rejected.** Drive `performSyncHandshake` (or the
   proof/transcript functions) with a peer that echoes our HELLO nonce back
   (`peerNonce == localNonce`) → handshake MUST error / not authenticate.
   (RED today: mirror authenticates.)
2. **Reflected-proof rejected.** Feed back the exact proof bytes we sent →
   MUST NOT validate against the expected opposite-role proof. (RED today: it
   validates.)
3. **Role-swapped proof rejected.** Compute a `proof_responder` and present it
   where a `proof_initiator` is expected (and vice versa) → reject. Assert
   `proof_initiator ≠ proof_responder` for the same key+transcript.
4. **Cross-connection reflection (Vector B) rejected.** Construct two
   transcripts with role-reversed endpoints and show a proof valid for one does
   not validate for the other (endpoint-ordering binding). Assert a proof over
   transcript with `(ep_init=A,ep_resp=B)` fails when checked against
   `(ep_init=B,ep_resp=A)`.
5. **Equal-nonce rejected** and **all-zero nonce rejected** at the guard.
6. **Directional frame keys.** `k_i2r ≠ k_r2i`; a frame sealed with the
   initiator `sendKey` verifies with the responder `recvKey` but a frame
   reflected back to the initiator (sealed `k_i2r`) FAILS the initiator's
   `recvKey` (`k_r2i`) verify. Both-directions round-trip succeeds.
7. **Legitimate handshake still succeeds** (regression): two keyed nodes, same
   PSK, distinct roles, distinct endpoints → both authenticate, derive matching
   directional keys, a sealed session frame round-trips each way, replay/seq
   guard still fires. (Update the existing
   `TestSyncAuthHandshakeBothKeyedAuthenticates`.) **Assert cross-role key
   agreement (Claude-SMR nit): `ar.sendKey == br.recvKey` and
   `ar.recvKey == br.sendKey`** — the single most likely place a role-ordering
   bug hides.
8. **Version flag-day.** A v2 node vs a simulated v1 HELLO → keyed↔keyed
   fails closed (reject, not dual-accept) with the version reason; unkeyed peer
   still dual-accepts unchanged; downgrade-guard matrix
   (`TestSyncAuthDecisionMatrix`) extended for the new reason.
9. **Dual-accept unchanged** for the unkeyed path (byte-for-byte; existing
   `TestSyncAuthHandshakeDualAcceptLegacyPeer` / `TestSyncAuthDisabledNoHandshake`
   stay green).

### 6.2 Package tests

`go test ./pkg/cluster/...` green (handshake, seal/verify, decision matrix,
downgrade guard, election dup-node-id).

### 6.3 Failover smoke (REQUIRED before commit)

`make test-failover` on the **loss userspace cluster** (both nodes keyed, same
PSK) — iperf3 through the DUT while cycling RG failovers, zero-drop, with the
v2 handshake authenticating on every reconnect. Per CLAUDE.md this is mandatory
for any change touching cluster/session-sync/failover code. Capture the
`cluster sync: connection authenticated` log to confirm v2 auth engaged.
(Verification is deferred to `/engineer` — this is /research.)

**Why this gate is not optional (Claude-SMR MUST-FIX #2).** The two-node
cluster is the *only* test that derives the transcript in **two separate
processes**. A single-process unit test that builds both transcripts with the
shared builder can mask an asymmetry (endpoint string formatting, fabric-index
mis-selection, live-vs-configured address, u32 node-id endianness) that only
manifests across hosts — and under the fail-closed flag-day such an asymmetry
is a cluster-wide sync outage with no fallback. `make test-failover` green is
the acceptance bar, not colour.

---

## 7. Out of scope

- **Confidentiality / full standard handshake (Option B — TLS-PSK / Noise).**
  Adds encryption + audited construction but is a large rewrite; file as a
  strategic follow-up issue. This plan is the targeted HIGH-sev hotfix.
- **Heartbeat + fabric-gRPC PSK channels.** #4107/#4357 authenticate those
  separately (trailing-HMAC heartbeat, gRPC guard). This issue is specifically
  the session-sync **stream** handshake; the other channels are their own
  audits.
- **Changing the PSK provisioning / key rotation UX.**
- **The unkeyed dual-accept wire.** Deliberately unchanged.

## 8. Open questions

1. **Node-id binding: include or endpoints-only?** Endpoints already provide
   the non-equalizable role-ordered channel binding that defeats Vector B.
   Node-id is defense-in-depth but needs the local id threaded into the
   handshake (via the `SyncAuthProvider` or a new accessor) + dup-id rejection.
   Proposal: ship endpoints-only for the hotfix; add node-id if the reviewers
   want it and the plumbing is clean. **Decision needed at /engineer.**
2. **Reorder the HELLO too, or only the PROOF?** Proposal: keep HELLO
   concurrent (public nonces), reorder only the PROOF (responder-validates-
   first). Confirm no `net.Pipe` deadlock in the test harness.
3. **Two derived directional keys vs one key + direction-byte MAC.** Proposal:
   two keys (matches issue wording, cleaner). Confirm no perf concern (setup
   only, once per connection).
4. **Flag-day vs opt-in transitional knob.** Proposal: fail-closed flag-day
   with operator doc. Escalate to the maintainer if the mixed-version failover
   drop is deemed unacceptable for the fleet's upgrade cadence.
5. **Does any non-cluster caller construct `authConn` / call `sealFrame`
   directly** (beyond `sync_protocol.go` + tests)? grep confirms only
   `sync_protocol.go:58` (writeFull) + `sync_conn.go` verify + tests — the
   `key`→`sendKey/recvKey` field split is contained. Re-confirm at /engineer.

---

## 9. Recommended design (one-paragraph summary for the issue)

Harden the custom session-sync handshake in place: thread an explicit
initiator/responder role from the dial/accept loops; bind every proof to a
role byte **and** a role-ordered transcript hash over
`{version, both nonces, both CONFIGURED fabric endpoints}` (optionally
node-ids) so a reflected or cross-connection-replayed proof carries the wrong
role/endpoint ordering and is rejected; reject an equal/all-zero peer nonce;
derive **two directional** frame keys (`i2r`/`r2i`) from that transcript so a
reflected sealed frame fails inbound verification; and gate the keyed↔keyed
wire on `syncAuthVersion = 2` **fail-closed** (no silent v1 downgrade) as a
documented coordinated (flag-day) upgrade, leaving the unkeyed dual-accept path
byte-for-byte unchanged. Full standard TLS-PSK/Noise replacement (which also
adds confidentiality) is recorded as an out-of-scope strategic follow-up.

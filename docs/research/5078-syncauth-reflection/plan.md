# #5078 — cluster session-sync PSK handshake is reflection-authenticatable

Status: **PLAN-READY (r2, converged 3-of-3 after scope expansion).** Three
hostile plan-reviews (Claude SMR `claude-smr-plan-r1.md`, Codex
`codex-plan-r1.md`, AGY `agy-plan-r1.md`) agree the *cryptographic
construction* is sound but drove a **material scope expansion**: the fix must
also add **stream confidentiality** and **fail-closed keyed dual-accept** (see
§0). Verdicts in §10.
Branch: `research/5078-syncauth-reflection` (plan docs only — no production
source).
Severity: **HIGH / High confidence**. Source: codex-review-177 `[A5-b1-F1]`.
Deliverable for `/engineer` (r2 converged): harden the custom mutual
challenge-response session-sync handshake (`pkg/cluster/sync_auth.go`) with
explicit initiator/responder **role binding**, a robust role-ordered
**transcript / channel binding** (node-id + fabric-id + cluster-id, not fragile
address strings), **equal-nonce rejection**, **directional frame keys**, and a
fail-closed **version flag-day**; AND **encrypt the stream** (directional AEAD
or a standard TLS-PSK/Noise transport) because the session-sync channel carries
the control-link PSK itself in cleartext; AND make a **locally-keyed node
fail-closed** (require authenticated v2, stop executing pre-admission frames)
instead of dual-accepting a PSK-less peer on first contact. Touches the on-wire
session-sync handshake, per-frame seal, and dual-accept policy → MUST pass
loss-cluster `make test-failover` before commit.

---

## 0. Converged design after hostile review (r2 — READ FIRST)

The r1 plan (harden the handshake, HMAC-only seal, dual-accept unchanged,
confidentiality out-of-scope) was reviewed hostilely by Claude SMR, Codex, and
AGY. All three agree the *narrow crypto construction* (role + role-ordered
transcript + directional keys + equal-nonce reject + version flag-day) is
**sound**. Codex issued a **PLAN-REJECT of the r1 scope** on two grounds that I
**verified true against origin/master**; AGY added endpoint-robustness and
fabric-binding changes. The converged design folds them all in:

### 0.1 VERIFIED BLOCKER 1 — the stream leaks its own PSK in cleartext ⇒ confidentiality is REQUIRED
When `chassis cluster config-sync` is enabled, `pushConfigToPeer`
(`pkg/daemon/daemon_ha_sync.go:355-370`) sends `d.store.ShowActive()` — which
is `s.active.Format()`, the **raw, unredacted** config tree
(`pkg/configstore/store_format.go:31-35`) — over *this* session-sync stream.
The #4051 redaction comment (`store_format.go:296-305`) states outright that the
cleartext `Show*` siblings "back HA [config sync]." That config includes
`set chassis cluster authentication-key <secret>` — a **secret leaf**
(`pkg/config/ast_redact.go:117` lists `authentication-key`) — i.e. **the
control-link PSK itself**, plus every other operator secret (BGP MD5, IPsec
PSKs, IGP auth keys, SNMP/RADIUS). The frame seal is **HMAC only — no
encryption** (`sealFrame`, `sync_auth.go:178-188`). Therefore a passive on-path
relay: relays the legit v2 handshake between the two real nodes → reads the
plaintext config frame → **recovers the control-link PSK** → reconstructs the
observable transcript → derives both directional keys → **forges frames /
authenticates a fresh connection as a full active attacker**, and can also
attack the heartbeat + fabric-gRPC channels that reuse the same PSK. This
**invalidates** the r1/SMR claim that "a passive relay cannot inject because it
lacks the PSK." **Consequence:** authenticating a channel with a PSK that the
same channel discloses in cleartext is self-defeating — the fix MUST make the
stream **confidential**, not merely integrity-sealed.

### 0.2 VERIFIED BLOCKER 2 — keyed-local dual-accept is a PSK-less active bypass, independent of reflection
A node that HAS a local PSK still **dual-accepts** an unkeyed/legacy peer on
first contact, before its sticky guard arms. `performSyncHandshake` with a peer
that sends a normal frame (not a HELLO), or advertises `keyed=0`, hits
`syncAuthDecision(true, false, …, peerAuthSeen)` (`sync_auth.go:260-278`,
`361-368`); when `peerAuthSeen` is false (first contact, before `syncAuthedEver`
/ `HeartbeatPeerAuthSeen` arms) it returns **accept=unauthenticated**. Worse,
that peer's **first frame is executed BEFORE the connection is admitted**:
`handleNewConnection` calls `s.handleMessage(conn, pending.typ, pending.payload)`
at `sync_conn.go:122`, *before* the `installConn` that installs
`conn0`/`conn1`. That frame can be `syncMsgFence` (`sync_conn_read.go:469` →
`OnFenceReceived` → **disables all RGs**). So a PSK-less attacker on the fabric
can, on first contact: fence the node (HA DoS), then have its pass-through
connection **displace** the legitimate peer — and later guard-arming does not
evict it. **Consequence:** "local PSK configured" must mean "require
authenticated v2"; a keyed node must not dual-accept an unkeyed peer except via
an explicit, default-off, time-bounded migration mode, and must not execute any
pre-admission frame.

### 0.3 The converged recommended design
1. **Harden the handshake** — role binding + role-ordered transcript +
   directional keys + equal-nonce reject + version flag-day (§3.0-3.8), with the
   **robust discriminator** = role-ordered **node-id (carried in the v2 HELLO)
   + fabric-id + cluster-id + both nonces + version**, rejecting a peer that
   claims the local node-id and rejecting equal endpoints — NOT fragile
   config-address strings (§3.1, per AGY + Codex). Strict exact-length HELLO /
   proof parsing; bounded pre-auth allocation + a per-fabric handshake
   semaphore (DoS, §3.11).
2. **Encrypt the stream (REQUIRED, Blocker 1)** — replace the HMAC-only frame
   seal with a **directional AEAD** (ChaCha20-Poly1305 / AES-GCM keyed by the
   directional keys, per-frame nonce = the sequence counter), OR adopt a
   standard mutually-authenticated + confidential transport (**TLS 1.3
   external-PSK, or Noise `NNpsk0`/`XXpsk0`**). Since confidentiality is now
   mandatory anyway, **Option B (standard transport) is the preferred strategic
   answer**; a directional-AEAD retrofit of the custom seal is the faster
   intermediate but is "another custom secure-transport design" (Codex) (§3.9).
3. **Fail-closed keyed dual-accept (REQUIRED, Blocker 2)** — a node with a PSK
   requires authenticated v2; no dual-accept of unkeyed/legacy peers except an
   explicit default-off time-bounded migration knob; **do not execute any
   pending pre-admission frame**; recheck policy immediately before install;
   evict unauthenticated connections when enforcement arms (§3.10).
4. **Strict next-sequence** (`prev+1`, not merely increasing) so a
   TCP-terminating relay cannot silently delete a frame (§3.9).
5. **Key-epoch snapshot** — snapshot one immutable key + generation at handshake
   start and verify it before install so a mid-handshake key rotation can't
   complete under a stale key (§3.12).

The rest of this doc is the r1 construction detail (§3.0-3.8, still valid) plus
the r2 additions (§3.9-3.12). Where r1 said "bind configured endpoints," the
converged discriminator in §3.1 supersedes it.

> **Address refresh, 2026-08-05 (origin/master `ad9591177`).** Every premise
> below re-verified and still LIVE — but the addresses had moved and are now
> corrected in place, so do not read a failed grep as a rotted plan.
> `pkg/cluster/sync_auth.go` is **byte-identical** to the base this was written
> against, so the reflection construction is untouched. `sync_conn.go` was
> refactored -1506/+692 and split into `sync_conn_{read,write,config,sweep,gen}.go`,
> which is what invalidated most citations. Refreshed: the pre-admission
> `handleMessage` (`:494-496` → `:122`), the fence dispatch (→
> `sync_conn_read.go:469`), `handleNewConnection` (→ `:88`, handshake `:100`),
> `acceptLoop` (→ `:394`), `fabricConnectLoop` (→ `:441`),
> `shouldInitiateFabricDial` (→ `:12`), the install/displace block (→
> `installConn`, `:250`), `receiveLoop` (→ `sync_conn_read.go:14`), and
> `pushConfigToPeer` (→ `daemon_ha_sync.go:355-370`, `ShowActive()` at `:366`).
>
> **Not re-verified:** the three citations at §4/§6 into
> `daemon_cluster_bind.go:132`, `daemon_ha_sync.go:478`, and
> `daemon_ha_sync.go:995-1017`. They are left as written rather than
> substituted, because a confidently-wrong line number is worse than a stale
> one — re-resolve them by symbol before relying on them.
>
> **Partly pre-closed:** #5303 (`c06722f14`) added a bounded pre-auth admission
> pool, setup tracking and close-on-stop, covering most of §3.11.
>
> **Already shipped:** §3.10 (fail-closed keyed dual-accept + no pre-admission
> frame execution) landed as PR #6865. §3.9's Option A′/B fork is **decided:
> Option B** (TLS 1.3 external PSK, `psk_dhe_ke`), which subsumes most of
> §3.0-3.8 — build the transport, do not extend the custom handshake.

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
`handleNewConnection` (`sync_conn.go:88`, handshake at `:100`), which is the **shared** setup path
for **both** roles:

- **Responder** — `acceptLoop` (`sync_conn.go:394`) spawns
  `handleNewConnection` per inbound TCP connection.
- **Initiator** — `fabricConnectLoop` (`sync_conn.go:441`) dials the peer
  and calls `handleNewConnection` on the dialed connection.

Neither passes a role. Which node dials is decided by `shouldInitiateFabricDial`
(`sync_conn.go:12`): the node with the numerically **lower** fabric
`addr:port` dials (initiator); the higher listens (responder). This is
antisymmetric, so for a given fabric **both real nodes already agree who is
initiator** — but an attacker does not respect it, and the handshake code never
consults it. Dual-fabric (`fab0`/`fab1`) each get an independent
connect/accept pair.

On success `handleNewConnection` **closes any existing conn** for that fabric
and installs the new one (`installConn`, `sync_conn.go:250`) — so a winning attacker
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
(`receiveLoop`, `sync_conn_read.go:14`) accepts them (valid MAC — V's own key; `recvSeq` and
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
mutually-known, non-attacker-equalizable inputs. **r2 discriminator (per AGY +
Codex):** the primary channel binding is the **role-ordered node-id + fabric-id
+ cluster-id**, NOT configured address strings (which are fragile — see the
"why not endpoints" note below):

```
transcript = SHA256(
    LP("xpf-cluster-sync-transcript-v2") ‖
    u8(version)               ‖   // negotiated = 2
    u16(cluster_id)           ‖   // cross-cluster proof-oracle guard (Codex)
    u8(fabric_idx)            ‖   // 0/1 — cross-fabric reflection guard (AGY/Codex)
    u32(nodeid_initiator)     ‖   // initiator's node-id (see sourcing below)
    u32(nodeid_responder)     ‖   // responder's node-id
    LP(nonce_initiator)       ‖   // 32B, initiator's fresh nonce
    LP(nonce_responder)           // 32B, responder's fresh nonce
)
```

**Node-id sourcing (Codex: "do not use optional/asynchronous ids").** Node-id
is a **mandatory** fixed field in the v2 HELLO. Each node fills its OWN role
slot with its OWN configured `nodeID` (trusted, from `Manager.NodeID()` via a
`SyncAuthProvider.LocalNodeID()` accessor) and the peer's slot with the
**node-id the peer advertised in its v2 HELLO** — and **rejects a peer HELLO
that advertises the LOCAL node-id** (a peer cannot be us; mirrors the existing
`election_dup_nodeid_4549` duplicate-id guard). Do NOT source the peer id from
the heartbeat-learned, asynchronous `peerNodeID`.

Why this defeats reflection: V's role differs between the two attacker
connections (responder on α, initiator on β), so V's own trusted `nodeID` lands
in **different slots** (`nodeid_responder` on α, `nodeid_initiator` on β). To
equalize the transcripts the attacker would have to make V's id appear in the
same slot on both — i.e. claim V's id in a HELLO — which is rejected. Combined
with `fabric_idx` and `cluster_id`, there is no cross-connection, cross-fabric,
or cross-cluster topology in which the two attacker transcripts collide, and it
has **zero dependence on address-string formatting** (so no hostname/wildcard
fragility and no legit-path outage from address asymmetry).

`LP(x)` = 4-byte little-endian length prefix ‖ `x` (unambiguous framing; no
field-boundary confusion). "initiator/responder" slots are filled by **role**,
not by socket direction, so both nodes populate identical bytes.

> **CRITICAL INVARIANT (Claude-SMR MUST-FIX #1).** The transcript fields
> (node-ids, nonces, and any endpoints) MUST be ordered by **role**
> (initiator-slot, responder-slot), **NEVER canonically sorted by value.**
> The sibling `syncDeriveFrameKey` (L232-240) today *sorts* its two nonces so
> the key is undirected — copying that sort into the transcript would make
> `transcript_responder == transcript_initiator` and **re-open Vector B in
> full**. Role-ordering is the entire mechanism that separates the two
> reflected transcripts (§3.2). The code MUST carry this as a hard comment and
> §6.1 test #4 MUST assert that swapping the initiator/responder **node-id**
> slots changes the proof (a test that would go RED if someone
> "consistency-refactors" to a sort).

**Why node-id/fabric-id, not configured endpoints (r2, AGY + Codex).** The r1
plan bound the *configured fabric addresses* as the discriminator. Both AGY and
Codex showed this is fragile:
  - **Hostname config** — `s.peerAddr` leaves are untyped strings; a hostname
    reaches `net.Dial` but fails `netip.ParseAddrPort`. If the impl falls back
    to a constant (zero bytes) on parse failure, `ep_initiator == ep_responder`
    and **Vector B re-opens** (AGY byte-trace).
  - **Wildcard / asymmetric config** — `localAddr = 0.0.0.0:7000` vs the peer's
    `peerAddr = <unicast>:7000` makes the two nodes' role-ordered endpoint
    tuples disagree → the *legit* handshake fails closed → **production sync
    outage** (AGY §2).
  - **Live-address drift** — `s.localAddr` is selected from live kernel
    interface addresses, and session sync prefers the control link, falling
    back to fabric; "configured endpoint" is not a single stable string
    (Codex §6, `daemon_cluster_bind.go:132`, `daemon_ha_sync.go:478`).

  Node-id + fabric-id + cluster-id have **none** of these failure modes: they
  are small fixed integers both nodes already agree on, with no formatting,
  hostname, wildcard, or live-selection ambiguity. If an implementer still
  wants endpoint binding as defense-in-depth, it MUST (a) use an explicit
  family byte + fixed-width address + fixed byte order, (b) reject
  zones/wildcards/unspecified/`localEndpoint == peerEndpoint`, and (c) **never
  fall back to a constant on parse failure** (fail the handshake instead).
  But it is not required — the node-id/fabric/cluster discriminator carries the
  full security property.

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

### 3.9 Stream confidentiality + strict sequence (r2, REQUIRED — Blocker 1)

Because the session-sync stream carries the control-link PSK (and every other
operator secret) in cleartext (§0.1), an HMAC-only seal is insufficient: a
passive relay reads the PSK and escalates to active forgery. The stream MUST be
**confidential**. Two implementations:

- **Preferred (Option B): a standard mutually-authenticated + confidential
  transport.** TLS 1.3 with an **external PSK** (`psk_ke`/`psk_dhe_ke`,
  RFC 8446 §4.2.11 — ideally the DHE variant for forward secrecy), or a Noise
  pattern with a pre-shared key (`NNpsk0` for PSK-only, or `XXpsk0` if we later
  add static keys). This gives mutual auth, confidentiality, integrity,
  directional keys, and audited downgrade resistance in one construction, and
  removes the need to hand-maintain the role/transcript/AEAD machinery. Since
  confidentiality is now mandatory, this is the strategically correct target.
  It reframes the handshake work in §3.0-3.8 as "wire a standard transport +
  the flag-day/dual-accept policy," not "extend the custom challenge-response."
- **Intermediate (Option A′): directional AEAD records over the custom
  handshake.** Replace the HMAC seal with **ChaCha20-Poly1305 / AES-256-GCM**
  keyed by the directional keys `k_i2r`/`k_r2i` (§3.5), per-frame nonce =
  the per-connection sequence counter (never reused under one key — a fresh
  transcript ⇒ fresh keys each connection). Frame = `AEAD(dirKey, seq, header ‖
  payload)`. This encrypts the payload (closes Blocker 1) and keeps the
  dual-accept/flag-day scaffolding, but it is "another custom secure-transport
  design" (Codex) and still needs every §3.0-3.8 + §3.10-3.12 fix. Use only if
  Option B is judged too large for the hotfix window.

**Strict next-sequence (both options).** The current receiver accepts *any*
increasing sequence (`seq <= recvSeq` rejected, `sync_auth.go:196`). A
TCP-terminating relay can therefore silently **delete** a complete frame and
forward a later one undetected. Require the receiver to accept exactly
`prev+1` (first frame = 1), converting selective deletion into a detected gap →
connection drop.

### 3.10 Fail-closed keyed dual-accept (r2, REQUIRED — Blocker 2)

A node with a local PSK MUST require authenticated v2 and MUST NOT dual-accept
a PSK-less / legacy peer on first contact (§0.2). Concretely:

- **`keyConfigured ⇒ require v2 auth`, independent of the peer's claimed
  `keyed` bit or whether it sent a HELLO.** Change `syncAuthDecision`: when the
  local key is set, a peer that does not present a valid v2 proof is
  **rejected** (not dual-accepted), regardless of `peerAuthSeen`. The
  first-contact grace that r1 preserved is exactly Blocker 2's window.
- **Preserve byte-identical legacy behaviour ONLY when the local node itself
  has no PSK** (unkeyed node = legacy peer, unchanged).
- **Do NOT execute any pending pre-admission frame.** Remove the
  `handleMessage(pending…)` call at `sync_conn.go:122` for any connection
  that is not fully admitted; a keyed node has no legitimate "legacy first
  frame" to replay. (Under the new policy a keyed node never produces a
  `pending` frame at all, since it rejects the unauthenticated peer.)
- **Recheck policy immediately before install** and **evict** any existing
  unauthenticated connection when enforcement arms, so a race cannot leave a
  pass-through connection installed after the guard flips.
- **Migration mode is explicit + default-off + time-bounded.** Any keyed→unkeyed
  interop (for a fleet that must roll the key onto one node at a time) is a
  named, default-`false`, alarmed, auto-expiring knob that the operator turns
  on for the window — clearly documented as *disabling authentication*. Same
  posture as the version flag-day (§3.7) — this is the operator escape hatch
  AGY asked for, applied to the keyed-vs-unkeyed case too.

### 3.11 Pre-auth DoS bounds (r2 — Codex §7)

The accept path spawns an unbounded goroutine per connection
(`acceptLoop`, `sync_conn.go:394`) and the pre-auth reader permits a 16 MiB allocation per
connection (`readSyncFrameRaw`, `sync_auth.go:289`). A 3s handshake deadline
bounds *duration*, not aggregate memory/goroutines. Add:
- a small **per-fabric handshake semaphore** (cap concurrent in-setup
  connections), and
- **header-first, exact-size parsing**: require the exact v2 HELLO / proof
  lengths, reject trailing bytes, and cap the pre-auth frame far below 16 MiB
  (a HELLO/proof is tens of bytes).

### 3.12 Key-epoch snapshot (r2 — Codex §7)

`authKey()` is read live so a commit-time key change is picked up next
handshake. But a key **rotated mid-handshake** could let a handshake complete
under a stale key, and immediate teardown on rotation can strand the peer.
Snapshot **one immutable key + a generation counter** at handshake start,
derive the whole transcript/keys from that snapshot, and verify the generation
is still current immediately before install. Full key rotation (existing
connections retain old derived keys; the auth-key is absent from
`clusterTransportKey` so an auth-key change does not currently restart cluster
comms, `daemon_ha_sync.go:995-1017`) needs a staged dual-key or an explicit
out-of-band coordinated procedure — track as a follow-up if not done here.

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
- **Complexity risk: MEDIUM-HIGH (r2).** r1 was self-contained to `sync_auth.go`
  + a role param + an `authConn` split. r2 adds stream **encryption** (a new
  AEAD/transport dependency, Option A′/B) + a dual-accept policy change + the
  pre-auth DoS bounds. Larger blast radius; the `make test-failover` gate and
  the two-process transcript-asymmetry concern (§5, MUST-FIX #2) matter more.
- **Residual risk after fix (r2 — corrected):** the r1 claim that "a passive
  tap only reads plaintext, benign, defer to Option B" was **WRONG** (§0.1):
  the plaintext *includes the PSK*, so a passive relay escalates to active
  forgery. r2 therefore makes **confidentiality REQUIRED** (§3.9), not
  deferred. After r2 (encrypted stream), a passive tap sees only ciphertext and
  cannot recover the PSK or forge. Remaining residual: forward secrecy — a
  pure-PSK construction (`psk_ke` / `NNpsk0`) means a later PSK disclosure
  decrypts recorded traffic; prefer the DHE/ephemeral variant (`psk_dhe_ke` /
  an ephemeral Noise pattern) to bound it. Key rotation UX (§3.12) is the other
  residual.

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
9. **Dual-accept unchanged for the UNKEYED path** (byte-for-byte; existing
   `TestSyncAuthHandshakeDualAcceptLegacyPeer` / `TestSyncAuthDisabledNoHandshake`
   stay green — only the *unkeyed-local* node dual-accepts).

**r2 additions (Blockers 1 & 2 + companion findings):**

10. **Keyed-local fail-closed (Blocker 2).** A *keyed* node facing a peer that
    sends a non-HELLO first frame, or `keyed=0`, on first contact
    (`peerAuthSeen=false`) MUST **reject** (not dual-accept). (RED today: it
    accepts and returns a `pending` frame.)
11. **No pre-admission frame execution (Blocker 2).** Assert a `syncMsgFence`
    (or any control frame) arriving before authentication is **never** passed
    to `handleMessage` / never fires `OnFenceReceived` before the connection is
    admitted. (RED at the time of writing: `sync_conn.go:122` executed it pre-install; CLOSED by PR #6865.)
12. **Node-id reflection guard.** Reject a peer HELLO advertising the **local**
    node-id; assert swapping the initiator/responder node-id slots changes the
    proof (the MUST-FIX #1 anti-sort test); assert a proof over `fabric_idx=0`
    fails verification at `fabric_idx=1` and across a different `cluster_id`.
13. **Confidentiality (Blocker 1).** Assert a synced frame's payload is **not**
    recoverable as cleartext on the wire (AEAD/transport encrypts it) — e.g. a
    known config-sync payload does not appear verbatim in the sealed bytes; a
    frame with a tampered ciphertext byte fails to decrypt/verify.
14. **Strict next-sequence.** A frame with `seq = prev+2` (a deleted
    intermediate frame) is **rejected** (RED today: any increasing seq is
    accepted).
15. **Pre-auth bounds.** A pre-auth frame claiming a huge length, or a
    HELLO/proof with trailing bytes / wrong length, is rejected without a large
    allocation.

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

**r2: explicit secondary-fabric leg (Codex §6).** The smoke MUST force fab0
down and prove a fresh **authenticated fab1** handshake + bidirectional
sealed/encrypted traffic — ordinary RG failover may never exercise the fab1
endpoint pair, and fab1 is where a cross-fabric or endpoint-asymmetry bug
hides.

---

## 7. Out of scope

- **Confidentiality is NOW IN SCOPE (r2).** It was out-of-scope in r1; Blocker 1
  (§0.1) makes it mandatory. See §3.9.
- **Full PSK key-rotation UX / staged dual-key rotation.** §3.12 requires a
  key-epoch snapshot for correctness during a rotation, but the operator-facing
  rotation procedure (hitless re-key of a running cluster) is a follow-up.
- **Heartbeat + fabric-gRPC PSK channels.** #4107/#4357 authenticate those
  separately (trailing-HMAC heartbeat, gRPC guard). This issue is the
  session-sync **stream**. NOTE (r2): because those channels reuse the same PSK
  and it is disclosed by cleartext config-sync (§0.1), closing Blocker 1 also
  protects them from the config-sync-disclosure vector — but a dedicated audit
  of their own confidentiality is a separate follow-up.
- **The UNKEYED-local dual-accept wire.** A node with no PSK is still a legacy
  peer, byte-for-byte. Only the KEYED-local dual-accept changes (§3.10).

## 8. Open questions

1. **RESOLVED (r2): discriminator = node-id + fabric-id + cluster-id, not
   endpoints.** Hostile review (AGY + Codex) showed configured-endpoint binding
   is fragile (hostname parse-failure, wildcard asymmetry, live-address drift).
   The node-id (mandatory v2 HELLO field, local id trusted, peer-claimed-local-id
   rejected) + fabric-id + cluster-id carries the full property with no
   address-string fragility. Needs `SyncAuthProvider.LocalNodeID()` +
   cluster-id plumbing. Endpoints optional defense-in-depth only, never a
   parse-failure constant.
1b. **Option A′ (custom AEAD) vs Option B (TLS-PSK / Noise) for confidentiality?**
   B is the strategically correct answer (standard, audited, one construction);
   A′ ships faster but is another custom secure-transport. **Decision needed at
   /engineer**, weighing hotfix urgency vs. long-term maintenance.
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

**(r2, converged.)** Fix the session-sync channel on three axes. **(1) Authenticate
correctly:** thread an explicit initiator/responder role from the dial/accept
loops (a local fact, not from the wire); bind every proof to a role byte **and**
a role-ordered transcript over `{version, cluster-id, fabric-id, both node-ids
(node-id from the v2 HELLO, peer-claiming-our-id rejected), both fresh nonces}`
— role-ordered, never value-sorted — so any reflected or cross-connection /
cross-fabric / cross-cluster proof lands in the wrong slot and is rejected;
reject equal/all-zero nonces; responder-validates-first. **(2) Make it
confidential:** the stream carries the control-link PSK itself (and all operator
secrets) in cleartext via config-sync, so an HMAC-only seal lets a passive relay
learn the PSK and forge — replace it with an encrypted transport (preferred:
TLS 1.3 external-PSK / Noise-psk; intermediate: directional AEAD over the custom
handshake) with directional keys and strict `prev+1` sequencing. **(3) Stop
dual-accepting when keyed:** a node that holds a PSK requires authenticated v2
(a `syncAuthVersion=2` fail-closed flag-day for the keyed wire, and no
dual-accept of a PSK-less peer, no pre-admission frame execution) — only an
*unkeyed* node stays legacy; any migration interop is an explicit, default-off,
alarmed, time-bounded knob. Bound pre-auth memory/goroutines; snapshot the key
epoch across the handshake. Must pass loss-cluster `make test-failover`
(including a forced-fab0/fab1 leg) before commit.

---

## 10. Converged reviewer verdicts (3-of-3 after scope expansion)

| Reviewer | Verdict on r1 (narrow) | Key findings | Status in r2 |
|----------|------------------------|--------------|--------------|
| **Claude SMR** (`claude-smr-plan-r1.md`) | PLAN-SOUND w/ 3 must-fix | role-order-not-sort; two-process `test-failover` gate + canonical endpoint bytes; direction-byte keys + reflected-frame-fails test | Folded into §3.1/§3.5/§6 |
| **Codex** (`codex-plan-r1.md`) | **PLAN-REJECT** of narrow scope (crypto construction sound) | **Blocker 1** config-sync leaks the PSK in cleartext ⇒ confidentiality required; **Blocker 2** keyed-local dual-accept + pre-admission fence = PSK-less active bypass; strict next-seq; node-id-not-endpoint; DoS bounds; key-epoch | Both blockers **verified true** vs origin/master and folded into §0/§3.9/§3.10/§3.11/§3.12; scope expanded |
| **AGY** (`agy-plan-r1.md`) | PLAN-SOUND-WITH-CHANGES | endpoint binding fragile (hostname zero-fallback re-opens Vector B; wildcard asymmetry = outage) ⇒ bind node-id/fabric-id; bind `fabric_idx`; offer transitional knob | Folded into §3.1 (node-id discriminator) + §3.7/§3.10 (transitional knob) |

**Convergence.** All three agree the cryptographic construction (role +
role-ordered transcript + directional keys + equal-nonce reject + version
flag-day) is sound. Codex's PLAN-REJECT was against the *r1 scope* (HMAC-only,
dual-accept unchanged, confidentiality deferred). r2 expands scope to add
**confidentiality** (Blocker 1) and **fail-closed keyed dual-accept** (Blocker
2), and swaps the fragile endpoint discriminator for **node-id/fabric-id/
cluster-id** (AGY + Codex). With those in, every reviewer's blocking objection
is resolved → **PLAN-READY on the r2 design.**

**One deliberate open decision for /engineer:** Option A′ (custom directional
AEAD, faster) vs Option B (TLS-PSK / Noise, standard + audited) for the
confidentiality requirement. Both close Blocker 1; the plan recommends B
strategically and A′ as the hotfix-speed intermediate.

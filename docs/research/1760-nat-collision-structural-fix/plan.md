# #1760 — NAT reverse-key 1:N collision: structural fix

**Status:** SHELVED (PLAN-KILL) 2026-06-06 — operator decision. Round-2
3-way converged PLAN-NEEDS-MAJOR (Codex bordering-KILL, AGY MAJOR, Claude
SMR MINOR→MAJOR); §2 validated but a correct fix needs a full HA-protocol
redesign for a 0-incidence bug. Shelved: the #1762 counter keeps watching;
revisit only if `xpf_userspace_session_nat_reverse_key_collisions_total`
goes nonzero. §2 + §1.6 preserved as the design-of-record for any revisit.
**Branch:** `research/1760-nat-collision-counter`
**Issue:** #1760 (stage-1 counter shipped in #1762; this is stage-2)

---

## 1.5 Round-1 disposition (v2 changes)

All three reviewers **validated §2** (the architectural finding: `K` is the
full reply tuple, so colliding sessions are wire-indistinguishable and a
multi-valued index — Path C — is wrong). All three **killed the owner-RG
gating** I proposed for HA. Codex bordered PLAN-KILL on the unaddressed
shared-map + sync-replay + disposition gaps; AGY said MINOR; my SMR said
MAJOR on HA divergence. Net: the mechanism (install-time refusal) is sound
and worth shipping (AGY: slow-path-only, zero fast-path cost), but v1's
scope was incomplete. v2 disposition:

| r1 finding (reviewer) | v2 disposition |
|---|---|
| **Shared HA reverse map has the SAME single-valued bug** — `publish_shared_session` inserts reverse keys with plain `insert`; `lookup_shared_forward_nat_match` returns one (`shared_ops.rs:641,277`). A local `SessionTable` guard does NOT fix cluster lookup corruption (Codex 2). | **v2 extends the guard to the shared-publish path.** The install-time collision check must run before `publish_shared_session` too; a colliding session is neither installed locally NOR published to `shared_nat_sessions`. §5 rewritten to guard both maps. |
| **Owner-RG gating is UNSOUND** — non-owners intentionally keep synced sessions for standby/prewarm (`shared_ops.rs:148`, `ha.rs` prewarm) (Codex 3, AGY, Claude SMR). | **Dropped.** Replaced with **node-level refusal** + a determinism argument (§7): a refused session is *never published*, so the peer never learns it → **symmetric absence, not divergence**. The only divergence window is active/active or failover transition where both nodes independently install; there, drop-and-retry (§5) self-corrects once the table converges. |
| **HA refusal "replay reproduces refusal" not proven** — sync imports shared state then queues `UpsertSynced`; worker import depends on `synced_entry_allows_local_replace` (`ha.rs:266,318`, `upsert_synced.rs:28`) (Codex 3). | §7 now argues from the *publish* path: `UpsertSynced` only ever carries sessions the owner actually installed+published; a refused session produces no delta, so there is nothing to replay divergently. The guard is **not** applied on the `UpsertSynced` import path (synced sessions are authoritative — the owner already arbitrated). |
| **Caller disposition underdesigned** — install returns `bool`; on failure the packet path rolls back SNAT alloc but **continues into reverse-session work**, does not drop (`poll_descriptor/mod.rs:1227,1293,1376`) (Codex 4). | §5 specifies a real terminal outcome: a new `InstallOutcome::RefusedReverseKeyCollision` that the packet path treats as a **hard drop** — roll back SNAT allocation, skip reverse-session install, recycle the frame. Not "return false and continue." |
| **Liveness is not just `entries.get && !expired`** — no `is_expired` helper; expiry is inline `now-last_seen>expires_after`; TCP `closing` keeps the tuple 30s, half-open 300s (`mod.rs:437,567,1513`) (Codex 5). | §5 defines the exact predicate: refuse only if the incumbent is **present, not expired, not `closing`, and not peer-synced-unconfirmed**. A `closing`/half-open/unconfirmed incumbent is **displaceable** (TIME_WAIT-reuse must not be refused). |
| **Asymmetric lifecycle gap** — reverse entries register only in `key_to_handle`, not `nat_reverse_index`; a reverse entry whose forward was GC'd is missed (AGY 1). | §5 guard checks `nat_reverse_index.get(&k).or_else(|| key_to_handle.get(&k))`. |
| **Drop is correct; no-NAT fallback is wrong** — Junos: source-NAT port-allocation failure ⇒ session not created ⇒ packet dropped (Codex 6, AGY). | Confirmed; §5 disposition = drop (matches Junos PAT-exhaustion semantics). |
| **Path B (PAT) is not a casual follow-up** — touches allocation, checksum/port rewrite, flow-cache eligibility, ALGs, peer-visible behavior (`source.rs:431`, `allocator.rs:461`, `frame/*`) (Codex 7). | §4/§9 reworded: Path B is a **substantial separate feature**, explicitly out of scope, blast radius enumerated. |
| §2 / Path C rejection validated; ICMP id is inside the tuple not beside it (Codex 1, AGY 3). | No change — §2 stands. |

**Net:** v2 keeps Path A (install-time refusal) but makes it **node-level,
two-map (local + shared-publish), with a real drop disposition and a
precise displaceable-incumbent predicate**, and argues HA determinism from
the publish path. PLAN-KILL remains on the table if round-2 finds the
active/active divergence window unacceptable.

---

## 1. Issue framing

#1760 is the correctness residue of the #1758 research: the secondary
reverse indices (`nat_reverse_index`, `reverse_translated_index`) are
single-valued (one reverse key `K` → one `u32` handle). When two live
sessions derive the same `K`, the index holds only one; the per-refresh
re-assert (`index_forward_nat_key_parts`) is last-writer-wins arbitration,
and value-guarded removal on expiry can delete `K` while a second live
session still needs it — permanently breaking that session's reverse path.

Stage-1 (the `nat_reverse_key_collisions` telemetry counter) merged in
**#1762** (`da85a8127`): displacement detected at the `nat_reverse_index`
re-insert with a displaced-handle guard, exported per-worker + aggregate to
Prometheus. **Live incidence on the loss cluster: 0** (interface-SNAT
config, idle/steady-state scrape). The operator chose to engineer the
structural fix now despite 0 observed incidence (latent-bug hardening).

## 1.6 Round-2 disposition (v3) — converged PLAN-NEEDS-MAJOR

Round-2 (Codex `task-mq21h0of-mwuoqd`, AGY `adversarial-review-mq21h0zr-pvh7px`,
Claude SMR r2) did **not** reach PLAN-READY. Both external reviewers landed
PLAN-NEEDS-MAJOR; Codex twice stated PLAN-KILL is the honest call at 0 live
incidence. Two of my v2 design choices were **refuted**:

| v2 choice | Why it's wrong (reviewer) | Status |
|---|---|---|
| **"keep-both" for the active/active window** (my SMR r2 recommendation) | Keep-both is NOT convergence — it IS today's single-valued-overwrite corruption; `index_forward_nat_key_parts` overwrites the reverse index either way (Codex 3). | **Refuted.** Self-corrected. |
| **Displaceable-incumbent predicate** (closing/half-open/peer-synced displaceable) | **bpfrx offloads the fast path to BPF — userspace never sees SYN-ACK/ACK, so an established TCP session is indistinguishable from a SYN-only half-open one** (AGY). Treating half-open as displaceable would let live connections be displaced. `closing` is *deliberately* kept alive (immediate teardown collapses valid traffic, Codex 5). `SessionEntry` has no half-open/confirmed state to test (Codex 5). | **Refuted.** The predicate must collapse to **expiry-only** (displace only if expired). |
| **Prefer-synced self-correction via SYN retransmit** | No deterministic global winner ⇒ "A drops S1 for B's S2 while B drops S2 for A's S1" — swapped divergence (Codex 3). UDP has no retransmit ⇒ no recovery (Codex 3, AGY). | **Needs a deterministic cluster-wide tiebreaker** — undesigned. |
| **Shared-map liveness check** (§5b "different *live* entry") | `SyncedSessionEntry` carries no `last_seen`/timeout/`closing` (`worker/mod.rs:262`) — liveness is **undefinable** on the shared map; presence-only false-refuses prewarm entries (Codex 2). | Shared-map guard can only be **presence-based**, which is unsafe for prewarm. Open. |
| **Guard placement** | Must run **before** BPF publish + local commit, else partial state (BPF publish already happened before shared publish, `poll_descriptor:1247/1253`); the missing-neighbor path has the same continue-after-false bug (Codex 4). | Real control-flow rework required. |

**What survives:** §2 (Path C rejected — unanimous), the *existence* of the
shared-map surface (Codex 2, now in scope), and AGY's point that the
control-flow bug (failed install still proceeds to reverse-session work,
`poll_descriptor:1227`) is real and worth fixing independently.

**Honest conclusion.** A correct Path A is a genuine **HA-protocol
redesign**: expiry-only liveness (the only signal userspace has), a
deterministic cluster-wide arbitration winner (not keep-both, not
naive-prefer-synced), guard-before-commit ordering, and a presence-only
shared-map guard whose prewarm false-refusals are bounded. That is a large
effort for a bug with **0 observed incidence** (loss cluster, interface-SNAT).
Both reviewers put PLAN-KILL on the table. **Decision required** (not a
reviewer call): (A) commit to the HA-redesign round; (B) ship a reduced
**standalone-only** scope (local-table expiry-only guard, refusal **disabled
in clustered mode**) — fixes the single-node case, punts the cluster; or
(C) **PLAN-KILL / shelve** — keep the #1762 counter watching, revisit if
incidence becomes nonzero. The mechanism is slow-path-only and cheap, but
its correctness preconditions are not met by the current architecture
without the redesign in (A).

---

## 2. The decisive architectural finding (changes the recommended fix)

The issue's "recommended approach" floats a **multi-valued reverse index**.
**That is architecturally wrong**, and the plan must say so:

`reverse_wire_key(forward, nat)` (`session/key.rs:84`) emits a *complete*
`SessionKey` — all six fields (`addr_family, protocol, src_ip, dst_ip,
src_port, dst_port`) — i.e. the **exact L3/L4 5-tuple a reply packet
carries**. `reply_matches_forward_session` (`key.rs`) only checks
`reverse_wire_key(forward) == reply_key || reverse_canonical_key == reply_key`
— it introduces **no field beyond `K` itself**.

Therefore **two live sessions sharing `K` have byte-identical reply tuples
at L3/L4.** A reply matching `K` is *genuinely ambiguous on the wire*:
with a multi-valued index you would have ≥2 candidate forward sessions,
both pass `reply_matches_forward_session`, and **there is no packet field
to disambiguate**. The NAT has mapped two distinct internal flows onto one
identical external 5-tuple; replies are physically indistinguishable.

Worked reachability (confirms genuine ambiguity, not index limitation):
- **Interface-SNAT** (`nat/source.rs:431`): `rewrite_src_port = None` →
  `K.dst_port = src_port` preserved. Two internal hosts SNAT'd to the same
  external `src_ip` (interface addr) that happen to use the same source
  port toward the same dst:port collide. Reply tuple
  `(dst_ip, ext_src_ip, dst_port, src_port)` identical.
- **DNAT-shared-backend** (`nat/destination.rs:126`): one client, same
  source port, to two VIPs both DNAT'ing to one `backend:port`. `K =
  (backend, client, backend_port, client_port)` identical; the original
  VIP is **not** on the reply, so the firewall cannot recover which VIP
  the reply belongs to. *Most operationally likely.*
- **NAT64** (`nat64.rs:97`): round-robin pool v4 addr, no port → same shape.
- **Non-bijective static NAT** (`nat/static_nat.rs:70`): two originals → one
  translated → identical reverse tuple.
- **Pool-mode SNAT is immune** because `owner_by_translated`
  (`nat/allocator.rs:461`) refuses a duplicate live external tuple at
  allocation — i.e. it *already does install-time prevention*. The fix
  generalizes that immunity to the other modes.

**Conclusion:** the only correctness-preserving fix is to **prevent the
collision at install** — refuse the second session, or disambiguate it so
the two sessions get distinct external tuples (distinct `K`). The
single-valued index is not the bug; the bug is admitting a second session
that aliases an existing live external identity.

## 3. Current behavior to preserve / not break

- `find_forward_nat_match` (`mod.rs:613`) looks up `K`, then **verifies**
  with `reply_matches_forward_session`. A wrong-handle collision today
  therefore yields either a dropped reply (verify fails) or a mis-NAT
  (verify passes for the wrong session) — both are corruption. The fix
  must not regress the verify path.
- The displaced-handle guard added in #1762
  (`index_forward_nat_key_parts`, `mod.rs:1393`) already distinguishes a
  benign re-assert (`prev == handle`, S1 re-winning its own `K`) from a
  genuine collision (`prev = Some(other)`). This is the exact hook the fix
  reuses — but at **install**, not on every per-packet re-assert.
- The displaced/incumbent handle may be **stale** (expired, not yet GC'd).
  A counter can over-count harmlessly; a *refusal* must not drop a new
  flow for a dead incumbent. The fix MUST check incumbent liveness
  (`entries.get(handle)` present AND not expired) before refusing.
- HA sync: a refuse/disambiguate decision must be **deterministic across
  peers** (both nodes must make the same choice) or session-sync will
  diverge. Reverse-sync replays installs; the decision must replay
  identically. This is the highest-risk surface — §7.

## 4. Path options

**Path A — Install-time refusal (RECOMMENDED for v1).** At forward-NAT
session install, if `K = reverse_wire_key(key, nat)` is already owned by a
**different, live** handle, refuse the new session: do not install, drop
its trigger packet, increment `nat_reverse_key_refused_total`. Correct for
**all four modes**. Failure mode = the second flow fails to establish
(a clean, observable SYN drop) instead of silently corrupting both.
Smallest blast radius; no new allocator; deterministic (both HA peers see
the same incumbent and refuse identically *if* the incumbent is synced
before the second install — see §7 risk).

**Path B — Source-port disambiguation (PAT) for SNAT/NAT64.** On
collision, allocate a free source port so `K` becomes unique (what
pool-mode already does). Strict Junos interface-source-NAT parity (Junos
interface NAT *is* PAT). But: requires a port allocator for interface-mode
(currently portless), changes the on-wire source port (visible to peers,
MSS/ALG interactions), and **cannot help DNAT-shared-backend or static
NAT** (no source rewrite available there) — those still need Path A. So
Path B is *additive on top of* Path A, not a replacement.

**Path C — Multi-valued index. REJECTED** (see §2): cannot disambiguate
identical reply tuples; would institutionalize a guess.

**Recommendation: ship Path A now** (correct for all modes, minimal,
the failure mode is strictly better than today). Treat Path B as a
*separate, optional* Junos-parity follow-up for SNAT/NAT64 only, its own
issue, gated on whether refusal-drops are observed via the new counter.

## 5. Concrete design (Path A)

**v2: node-level, two-map guard with a displaceable-incumbent predicate.**

**(a) Local SessionTable install.** Pre-install guard in the **non-reverse,
NAT-present, NEW-handle** branch only (re-asserts of an existing handle are
exempt):

```rust
// in the install path BEFORE committing the new handle:
if !is_reverse && nat_rewrites_identity(&decision.nat) {
    let k = reverse_wire_key(key, decision.nat);
    // AGY-1 lifecycle gap: reverse entries live only in key_to_handle.
    let incumbent = self.nat_reverse_index.get(&k)
        .or_else(|| self.key_to_handle.get(&k)).copied();
    if let Some(h) = incumbent {
        if h != new_handle && self.is_displaceable_blocker(h, now) == false {
            self.nat_reverse_key_refused =
                self.nat_reverse_key_refused.saturating_add(1);
            return InstallOutcome::RefusedReverseKeyCollision;
        }
        // displaceable incumbent (dead / closing / half-open / unconfirmed)
        // → fall through, the new session takes K.
    }
}
```

- **Displaceable-incumbent predicate (Codex 5).** There is no `is_expired`
  helper today (expiry is inline `now - last_seen > expires_after`,
  `mod.rs:437`). Define `is_displaceable_blocker(h, now)` = **NOT** a
  blocker, i.e. the incumbent is displaceable, when ANY of: absent from the
  slab; expired (`now - last_seen > expires_after`); `closing == true`
  (FIN/RST seen, 30 s tuple, `mod.rs:567/1513`); half-open (SYN-only, not
  yet established); or peer-synced-but-unconfirmed
  (`origin.is_peer_synced()` and not locally confirmed). Only a
  **present, established, confirmed, unexpired** incumbent blocks. This
  prevents false refusals on TIME_WAIT reuse.
- `nat_rewrites_identity`: the NAT changes the external tuple so the reverse
  key is share-able (not a no-op). Pool-mode is already filtered upstream by
  `owner_by_translated` — this is a cheap second line.

**(b) Shared HA publish (Codex 2 — the v1 gap).** The same collision exists
in `shared_nat_sessions` (`publish_shared_session` plain-`insert`s reverse
keys, `shared_ops.rs:641`; `lookup_shared_forward_nat_match` returns one,
`:277`). The guard must therefore also run **before publishing** a forward
NAT session to the shared map: if `k` is already owned in the shared map by
a different live entry, **do not publish** (and, having refused locally in
(a), there is nothing to publish anyway — the two are consistent). The
guard is **NOT** applied on the `UpsertSynced` import path: synced sessions
are authoritative (the owner already arbitrated), so the importer installs
them verbatim (§7).

**(c) Caller disposition (Codex 4).** The current install returns `bool`
and the packet path rolls back SNAT alloc but **continues into
reverse-session work** (`poll_descriptor/mod.rs:1227/1293/1376`). v2 adds
`InstallOutcome::RefusedReverseKeyCollision`; the packet path treats it as a
**hard drop**: roll back the SNAT allocation, **skip** reverse-session
install, recycle the frame, return `XDP_DROP`-equivalent. No partial state.
Same disposition as Junos source-NAT port-allocation failure (session not
created → packet dropped).

**Counter.** Add `nat_reverse_key_refused` mirroring the #1762 counter end
to end: `SessionTable` field + accessor, worker snapshot
(`loop_body/mod.rs`), `worker_runtime` atomic, coordinator status,
`protocol/{binding,control}.rs`, Go `protocol.go`, Prometheus
`metrics_descriptors.go` (per-worker + aggregate), tests. (#1762 is the
exact template — same wiring, new name.)

## 6. Public API / invariants preserved

- No `SessionKey` / index *type* change (Path C avoided) → no
  reverse-lookup contract change, no HA wire-format change.
- `find_forward_nat_match` / `reply_matches_forward_session` untouched.
- `index_forward_nat_key_parts` re-assert semantics unchanged for
  non-colliding sessions (the overwhelming majority; counter is 0 live).
- The fix only ever *prevents* an install; it never changes an
  already-installed session's NAT.

## 7. Risk assessment

| Class | Level | Note |
|---|---|---|
| Behavioral regression | **MED** | A refusal drops a flow that today installs (and silently corrupts). Correct, but it IS a behavior change for the colliding case. Gate: counter shows refusals are as rare as collisions (0 live). |
| HA divergence | **MED** (was HIGH) | See the determinism argument below. Node-level refusal + publish-path gating reduces this from "divergent tables" to "a bounded, self-correcting active/active window." Still gated on `make test-failover` with collision injection. |
| Borrow/lifetime | LOW | Guard is a `get`/`or_else`/predicate before the `&mut` install; no aliasing. |
| Perf | LOW | One extra `FxHashMap::get` (+ the `key_to_handle` fallback) + predicate on the **install** slow path only (not per-packet). |
| Architectural mismatch | LOW | Path A generalizes the already-proven pool-mode `owner_by_translated` immunity. |

**HA determinism argument (v2 — replaces the dead owner-RG gating).**
The key realization: **a refused session is never published.** Sync deltas
(`UpsertSynced`) only ever carry sessions the owner actually installed and
published to `shared_nat_sessions`. So:

- *Steady state (one active node per RG):* only the active node installs new
  flows. It either admits S2 (publishes it → peer replays it) or refuses S2
  (publishes nothing → peer simply never has S2). Both nodes end with the
  **same** set — admit→both-have, refuse→neither-has. **No divergence.** The
  importer applies synced sessions verbatim (guard NOT run on import), so a
  synced S1 that aliases nothing on the peer installs cleanly.
- *Active/active or failover transition (both nodes install independently):*
  node A installs+publishes S1; before A's delta reaches B, B installs S2
  (collides) and, not yet seeing S1, **admits** S2. Now A has S1, B has S2.
  This is the residual window. It is **bounded and self-correcting**:
  (1) it requires two genuinely-colliding flows landing on two nodes inside
  one sync interval (rare — counter is 0 live); (2) when A's S1 delta
  arrives at B, the importer either keeps S1 alongside S2 (the pre-existing
  single-valued-overwrite behavior — no *worse* than today) or, with the
  guard, B can detect the conflict on import and drop its locally-admitted
  S2 in favor of the authoritative synced S1, converging deterministically;
  (3) the dropped flow's SYN retransmit re-installs against the now-converged
  table and gets a consistent verdict. **This is strictly better than
  today's symmetric silent dual-corruption**, never worse. The exact
  import-time conflict resolution (keep-both vs prefer-synced) is the one
  open design choice for round-2 (§10 Q2).

## 8. Test plan

- Unit (local table): S1 install→`K→S1`; S2 collides → **refused**, S1
  intact, counter=1. Displaceable variants — incumbent **expired**,
  **closing** (FIN/RST), **half-open**, **peer-synced-unconfirmed** → S2
  admitted, displaces (no false refusal). Re-assert variant (S1 re-install →
  no refusal). AGY-1 variant (reverse entry in `key_to_handle` only, forward
  GC'd → still caught). One per reachable mode (interface-SNAT, DNAT-shared,
  NAT64, static).
- Unit (shared map): collision at `publish_shared_session` → not published;
  `UpsertSynced` import is NOT guarded (synced session installs verbatim).
- Import-conflict resolution test: locally-admitted S2 + authoritative
  synced S1 on the same `K` → converges per the chosen rule (§10 Q2).
- Differential vs master: non-colliding workloads install identically
  (counter stays 0, no behavior change).
- `cargo test` full + 5× flake on new named tests; Go suite.
- **HA**: `make test-failover` with **collision injection across the
  failover** — assert tables converge (the §7 MED window self-corrects),
  no permanent divergence. v4 + v6. **Gating** per project rule (touches
  session-sync/failover).
- Smoke matrix on loss cluster (deploy wipes CoS — re-apply): v4/v6 ×
  push/reverse × CoS off/on. Confirm `refused` counter stays 0 under normal
  traffic (no false refusals).

## 9. Out of scope

- Path B (PAT disambiguation) — **substantial separate feature**, not a
  casual follow-up (Codex 7): adding a port allocator to interface-mode
  SNAT touches allocation (`source.rs:431`, `allocator.rs:461`),
  checksum/port rewrite (`frame/rewrite/mod.rs`), flow-cache eligibility,
  ALGs, and peer-visible on-wire behavior. Its own issue + `/research`.
- Multi-valued index (Path C) — rejected, §2.
- Changing pool-mode SNAT (already immune).

## 10. Open questions for adversarial review

1. *(round-1 resolved — §2 validated by all three; Path C stays rejected.)*
2. **(THE round-2 question)** Import-time conflict resolution for the
   active/active window (§7): when a node holding a locally-admitted S2
   imports an authoritative synced S1 on the same `K`, should it (a)
   keep-both (status quo single-valued overwrite — no worse than today), or
   (b) prefer-synced and drop the local S2 (deterministic convergence)?
   Is (b) safe given the importer must not itself create a new divergence?
   Owner-RG gating is OFF the table (round-1: non-owners keep synced for
   prewarm).
3. Is the §7 active/active window genuinely self-correcting via SYN
   retransmit, or are there flows (long-lived UDP, no retransmit) where the
   dropped side never recovers?
4. Is the displaceable-incumbent predicate (§5: expired/closing/half-open/
   peer-synced-unconfirmed are displaceable) complete, or is there a state
   where displacing the incumbent corrupts an in-flight reply?
5. Given live incidence is 0 + the residual active/active window, is Path A
   justified, or is PLAN-KILL (keep the #1762 counter watching, ship no
   code) the honest verdict? PLAN-KILL remains acceptable.

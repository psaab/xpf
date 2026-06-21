# #2170 — HA session-sync: a deferred/journaled delete can kill a same-key replacement session

Status: **PLAN-READY** (companion-free, hostile self-review in
`claude-smr-plan-r1.md`).
Branch: `research/2170-ha-deferred-delete`.
Deliverable for `/engineer`: a wire-protocol **install-generation guard** on
session deletes so the standby refuses a stale delete whose generation
predates the session it would remove. Touches `pkg/cluster` session-sync wire
protocol + apply path → MUST pass loss-cluster `make test-failover` before
commit.

---

## 1. Issue framing

#2163 (PR for #2121) made `flushDeleteJournal` re-journal (retain) un-sent
deletes on a full `sendCh` instead of silently dropping them. That converted a
silent-leak into bounded retention, but **deliberately widened** a pre-existing
correctness class that the PR explicitly deferred to a follow-up (this issue,
docs/pr/2121-flushdeletejournal-requeue/plan.md §"Residual exposure & the real
fix"):

> A journaled/deferred delete `D(K)` for session `S(K)` can be applied on the
> standby AFTER a NEW session `S'(K)` reusing the same 5-tuple `K` has been
> created and synced — killing the live replacement `S'`.

The structural fix named in that plan is a **wire generation / session-identity
guard**: stamp each synced session with a monotonic install generation and have
the receiver apply a delete only if the delete's generation is **not older than**
the generation of the entry it would remove (so a stale delete for the previous
incarnation `S` is ignored once `S'` is installed).

## 2. Honest scope/value framing

- **Severity: MEDIUM, latent.** It requires same-5-tuple reuse within a sync
  window where a delete for the old incarnation is still in flight / journaled.
  Low incidence, but real and now reachable from one more path (#2163).
- This is **not** a throughput/perf change. It is a correctness guard on a
  control path (session sync), not a packet hot path.
- The guard is the **only** structural fix. The two weaker alternatives (TTL on
  the journal; rely on the standby's own GC) are evaluated in §5 and rejected as
  the primary fix (one is kept as defense-in-depth).
- **PLAN-KILL was considered and rejected** — see §3.4. The race is real, NOT
  already prevented by any existing guard. The currently-plumbed `SessionID` is
  NOT usable as the generation (it is non-monotonic and collides on same-second
  reuse — §3.3), so "just compare SessionID" is wrong and would be a false fix.

## 3. The bug — exact mechanism, fully traced in code

### 3.1 The wire protocol is keyed by the 5-tuple ALONE for deletes

- `encodeDeleteV4` (sync_protocol.go:243) / `encodeDeleteV6` (:260) emit a
  **fixed 16 / 40-byte** payload containing only `SrcIP,DstIP,SrcPort,DstPort,
  Protocol`. No SessionID, no generation, no timestamp.
- `handleMessage` (sync_conn.go:901 `syncMsgDeleteV4`, :912 `syncMsgDeleteV6`)
  decodes only the 5-tuple (`len(payload) >= 16` / `>= 40`) and calls
  `deleteClusterSyncedV4(key)` / `...V6(key)`.

### 3.2 The apply side deletes whatever currently occupies the key

- `deleteClusterSyncedV4` (sync_conn.go:60) →
  `s.sessions.DeleteWithCompanionsV4(key, DeleteReasonClusterStale)`.
- `dataPlaneSessionStore.DeleteWithCompanionsV4` (session_store.go:468):
  `val, err := GetSessionV4(key)` then `DeleteKnownV4(key, val, reason)` — it
  removes **whatever entry is at `key` right now**, with **zero comparison** of
  identity (no SessionID, no generation, no created/last-seen check).
- In the userspace helper the same is true: `Manager.DeleteSession`
  (manager_ha.go:756) → `syncSessionV4Locked("delete", key, nil)` → the Rust
  helper `delete_synced_session(key)` (userspace-dp/src/afxdp/ha.rs:363) does
  `sessions.synced.get(&key)` and removes it — **keyed by `SessionKey` tuple,
  no identity check**. `SyncedSessionEntry` (worker/mod.rs:278) carries
  `key/decision/metadata/origin/protocol/tcp_flags` — **no install generation**.

### 3.3 The currently-synthesized `SessionID` cannot serve as the generation

The userspace delta path synthesizes the SessionID on the **sending** node:
`userspaceSessionFromDeltaV4` (daemon_ha_userspace.go:220) and `...V6` (:297):

```go
SessionID: uint64(now)<<16 | uint64(delta.Slot&0xffff),  // now = monotonic SECONDS
```

Three disqualifying properties:

1. **Non-monotonic / clock-resolution collision.** `now` has **1-second**
   resolution (`daemonMonotonicSeconds`, daemon_ha_userspace.go:66). The low 16
   bits are `delta.Slot` — the helper RX **slot index**, a *steering* artifact,
   not a per-session nonce. A flow that closes and a same-tuple flow that reopens
   **within the same second on the same slot** produce the **identical**
   SessionID. So `gen(S) == gen(S')` for exactly the case we must distinguish.
2. **Never reaches the standby anyway.** `SessionSyncRequest`
   (manager_ha.go:800 `buildSessionSyncRequestV4`, :865 V6) — the Go→Rust
   control message that installs a synced session — **does not carry SessionID
   at all**. The Rust `SyncedSessionEntry` has no SessionID field. So even on the
   install path the SessionID is dropped at the manager boundary; comparing it on
   delete is impossible without new plumbing.
3. **Not cross-node deterministic.** The `types.go:23` comment "unique ID, same
   on both cluster nodes" is a legacy-eBPF-era statement; in the userspace path
   the ID is node-local and synthesized, so the two nodes never agree on it.

Conclusion: the fix needs a **purpose-built monotonic install generation**
stamped at sync-send time, not the existing `SessionID`.

### 3.4 Can the deferred delete actually be applied after the replacement? (quantified — NOT a PLAN-KILL)

Timeline (all on `K` = a single 5-tuple), confirmed against code:

- **T0**: `S(K)` closes on primary → GC `OnDeleteV4` (daemon_run.go:754) /
  userspace "close" delta (daemon_ha_userspace.go:765) → `QueueDeleteV4(K)`.
  If `sendCh` is full **or** the peer is momentarily disconnected,
  `queueMessage` returns false → `journalDelete(D(K))` (sync_conn.go:518) — the
  delete is **retained in `s.deleteJournal`**, not yet applied on the standby.
- **T1**: a new connection `S'(K)` is created on the primary (same tuple — e.g.
  client reconnects, NAT reuses the port, a probe re-fires) → synced via
  `QueueSessionV4(K, …)` over a **healthy** `sendCh`. The standby installs
  `S'(K)` (`installClusterSyncedV4` → `PutClusterSyncedV4`).
- **T2**: reconnect (or `sendCh` drains) → `flushDeleteJournal` (sync_conn.go:200,
  called FIRST on reconnect, **before** OnPeerConnected/incremental resumes)
  replays the retained `D(K)` → standby applies `deleteClusterSyncedV4(K)` →
  **removes the live `S'(K)`**. TCP on that flow dies on the standby; after a
  failover the flow blackholes until re-established.

Ordering proof that the hazard is **cross-reconnect** specific: within a single
connection lifetime the delete and any later same-key install share the single
ordered `sendCh → sendLoop` path (FIFO), so a same-connection install after a
delete is correctly the newer message. The danger is precisely when `D(K)`
**survives in the journal across a disconnect** while `S'(K)` is synced on a
*different* (healthy) connection epoch, and the journal flush on the next
reconnect re-applies the stale delete out of causal order. #2163's
FIFO-prepend retains the delete across exactly this boundary, which is why it
widened the class.

This is reachable, not theoretical. **NOT a PLAN-KILL.**

### 3.5 Cross-ref #1760 (reverse-key collision, PLAN-KILLED) — different class

#1760 was about two *distinct, concurrently-live* sessions whose **reverse**
wire-keys collide (the reverse tuple is genuinely ambiguous → a multi-valued
index would be wrong; install-time refusal needs full TCP state the userspace
fast path doesn't have → shelved at 0 incidence). #2170 is different and
tractable: there is **at most one** live session per `K` at any instant; we are
disambiguating the **same key across time** (old incarnation `S` vs new `S'`),
which a monotonic per-key generation resolves cleanly. The #1760 shelving does
**not** apply here. (The forward-wire alias deletes in
daemon_ha_userspace.go:772-789 are a separate same-incarnation companion, also
covered by the same generation — §5.4.)

## 4. What's already shipped / relevant

- #2163 / PR (commit `d8e1ae5`): `flushDeleteJournal` retains the un-sent tail
  via `rejournalTail` (FIFO-prepend, bounded, `DeletesDropped` accounting). This
  is the path that surfaced the issue; the generation guard makes its retained
  deletes safe to replay.
- Bounded delete journal: `deleteJournalDefaultCap = 10000` (sync.go:359).
- Length-tolerant session decoder: `decodeSessionV4Payload` (sync_protocol.go:280)
  reads optional trailing blocks guarded by `if off+N <= len(payload)` — the
  payload has grown before (ReverseKey, ALG/Log, Fib*). **This is the
  forward-compat seam the fix uses.**
- Fixed-length delete decode (`len(payload) >= 16/40`) — extensible by appending
  a length-gated trailing field (old peers ignore extra bytes; the `>=` check
  already tolerates a longer payload).
- Sync wire format (docs/sync-protocol.md): 12-byte header (Magic/Type/Pad/Len),
  **no protocol-version negotiation**. Backward compat MUST be achieved by
  length-gated trailing fields, not a version bump. The header Pad (offset 5-7)
  is available but per-message length-gating is simpler and matches the existing
  decoder discipline.

## 5. Concrete design — phased, minimal-first

### Core idea

Introduce a **monotonic per-(node,key) install generation** `g`:

- The sending node stamps every **session sync** (`QueueSessionV4/V6`,
  bulk, fabric-alias) and every **delete** (`QueueDeleteV4/V6`) for key `K`
  with `g`, where `g` is **strictly increasing for successive installs of the
  same `K` on that node** (a fresh `S'(K)` gets a strictly higher `g` than the
  prior `S(K)`, and the delete `D(S)` carries `S`'s `g`).
- The receiving node stores `g` alongside the synced entry and **applies a
  delete only if `delete.g >= storedEntry.g`** (equivalently: ignore a delete
  whose `g` is strictly older than the currently-installed entry). A delete for
  a key it doesn't have is a no-op as today.

Result: `D(S)` carrying `g(S)` arriving after `S'(K)` (with `g(S') > g(S)`) is
**refused** — the live replacement survives. A genuine delete of `S'` carries
`g(S')` and matches/wins, so real deletes still work.

### 5.1 Generation source (the load-bearing decision)

The generation MUST be strictly monotonic per same-key install **regardless of
clock resolution**, so a same-second/same-slot reuse (§3.3) still gets a higher
`g`. Two viable sources, recommendation = **B**:

- **Option A — per-key sender-side counter.** A small map `K → lastGen`,
  `g = ++lastGen` on each install of `K`; the delete carries the `g` last
  assigned to `K`. PRO: minimal wire width, perfectly monotonic per key. CON:
  unbounded map growth keyed by 5-tuple (needs eviction tied to delete); a
  per-install map mutation on the sync path; cross-restart reset (a daemon
  restart resets `lastGen` to 0 → a post-restart `S'` could carry a *lower* `g`
  than a pre-restart journaled `D` — but a restart triggers a fresh
  cold-start/bulk that re-primes the standby, mitigating this; still a sharp
  edge).
- **Option B (RECOMMENDED) — a single process-wide strictly-monotonic
  counter, seeded from the wall/boot epoch.** `g = atomic.AddUint64(&genCtr, 1)`
  for **every** session install AND every delete-of-a-known-session, with the
  counter **initialized at daemon start to `bootEpochNanos`** (or
  `monotonicNanos()` at start) so it never regresses below a value the peer may
  already hold across this node's restarts within a boot, and is comparable to
  values a *peer* might send only via the **same-key** comparison (we never
  compare generations across different keys, so cross-node absolute ordering is
  NOT required — only per-key, per-sender monotonicity).
  - Critical correctness point: **generations are only ever compared for the
    SAME key from the SAME owner.** A delete for `K` and the install of `S'(K)`
    are produced by the **same primary node** (the RG owner) — the standby only
    receives, never mints competing generations for an owned key. So a single
    sender-local monotonic counter is sufficient; we do **not** need cross-node
    agreement on absolute generation values.
  - The delete path must learn the `g` of the session it is deleting. Both
    delete callers already have it available: the GC `OnDeleteV4`/userspace
    "close" delta fire **after** the session existed; the sender stamps the
    delete with `g = the generation it assigned when it last installed/synced
    that key`. Cleanest realization: keep the per-key `K → lastGenSent` map
    (small, evicted on delete-send), OR (simpler, see SMR) carry the generation
    **inside the close delta itself** so no sender-side map is needed.

  **Recommendation: Option B counter + carry the install generation back in the
  close path** so the delete is stamped with the exact `g` of the install it
  cancels, with no sender-side per-key map. The `/engineer` step picks the
  concrete carrier after confirming the close-delta plumbing (the helper knows
  the session it is closing and can echo its install generation — preferred), or
  falls back to a bounded `K->lastGen` map if echo plumbing is too invasive.

  **Why echo is strongly preferred (SMR B1, cross-owner edge):** after a
  failover the *new* primary mints generations from *its own* counter, unrelated
  to the old primary's. A delete the new primary sends for an *inherited* key
  (stored with the old owner's `g`) is an apples-to-oranges comparison. If the
  delete **echoes the generation the current owner last installed** for that
  key, it is always same-domain as the stored entry the owner itself installed,
  so the comparison is always valid. HARD REQUIREMENT: if a sender-side counter
  map (Option A) is used instead of echo, the new primary MUST re-stamp inherited
  keys to its own counter on the install/refresh that follows ownership change,
  *before* any delete it issues for those keys. Echo avoids this entirely and is
  the recommendation.

### 5.2 Wire encoding (backward compatible, length-gated)

- **Session messages**: append `Generation uint64` (8 bytes, LE) as a new
  trailing field after the current last field (`FibGen`) in
  `encodeSessionV4Payload`/`V6Payload`. `decodeSessionV4Payload`/`V6` read it
  under a new `if off+8 <= len(payload)` block (mirrors the existing
  optional-block pattern). Old peer ↔ new peer: old peer ignores the trailing 8
  bytes; new peer reading an old (shorter) payload sees `Generation == 0`.
- **Delete messages**: append `Generation uint64` (8 bytes, LE) after the
  5-tuple in `encodeDeleteV4` (16 → 24) / `encodeDeleteV6` (40 → 48). The
  handler's `len(payload) >= 16/40` check already tolerates the longer payload;
  add `if len(payload) >= 24/48 { gen = LE.Uint64(payload[16/40:]) }`.
- **Generation == 0 sentinel = "unknown / legacy".** The receiver applies the
  apply-guard ONLY when **both** the stored entry generation and the delete
  generation are non-zero. If either is 0 (legacy peer, or a bulk entry that
  predates the field), it falls back to **today's behavior** (unconditional
  key delete) — i.e. the fix is **strictly opt-in by both ends carrying a
  generation**, never weakening behavior against an old peer, and never
  spuriously refusing a delete when we lack the data to judge. (#1961 serde/
  omitempty discipline: the field is a plain `uint64`, default-0, no omitempty
  ambiguity on the binary wire; if any JSON control-message carrier is used to
  echo the generation, it MUST use `default`/explicit-0 not `omitempty`.)

### 5.3 Apply guard (receiver)

In `deleteClusterSyncedV4`/`V6` (or pushed into
`DeleteWithCompanionsV4`/`V6` with a generation arg — SMR weighs both):

```
existing := Get(key)              // already done by DeleteWithCompanions
if existing != nil &&
   existing.Generation != 0 &&
   deleteGen != 0 &&
   deleteGen < existing.Generation {
       // stale delete for a superseded incarnation — IGNORE, count it
       stats.DeletesStaleIgnored++
       return nil
}
// else: apply as today
```

- Equality (`deleteGen == existing.Generation`) **must apply** — that is the
  delete of the very session installed. Only **strictly older** is refused.
  **Warning (SMR C2): never write `<=` for refusal** — that makes a session
  undeletable by its own delete. (Echo of the #1745 "wrap-safe equality" lesson:
  here we DO need ordering, but only `<` vs `>=`; with a 64-bit counter seeded
  from boot nanos, wrap is a non-concern for any realistic uptime — document the
  assumption.)
- The userspace helper mirror (`delete_synced_session`) needs the same guard:
  store the generation on `SyncedSessionEntry` (new field, plumbed via
  `SessionSyncRequest`) and compare before removing. The Go `Manager.DeleteSession`
  must forward the delete generation to the helper.

**Guard placement (SMR D2 — authoritative seam):** put the authoritative guard
in the **cluster apply layer** (`deleteClusterSyncedV4`/`V6` in sync_conn.go),
comparing the delete generation against the currently-stored entry's generation
**before** calling `DeleteWithCompanionsV4/V6`. A refusal there short-circuits
**both** the BPF conntrack map delete (`bpfShim.DeleteSession`) and the Rust
helper delete — so the BPF C struct stays generation-free (no header change,
§10) while still being protected. The helper-side guard in
`delete_synced_session` is belt-and-suspenders for any delete that originates
helper-side. This is cleaner than pushing the guard into `DeleteWithCompanions`
(which has non-cluster callers without a generation).

**Install-side guard too (SMR C3 — close the delayed-stale-install variant):**
the install upsert (`PutClusterSyncedV4`/the helper `upsert_synced_session`)
must **refuse to overwrite a stored entry with a strictly-older-generation
install** (same `<` rule). Without this, a *delayed stale install* `S(K,g=1)`
arriving after `S'(K,g=2)` would roll the stored generation back to 1, after
which a stale `D(S,g=1)` would wrongly match and delete the live `S'`. Guarding
both install and delete by the same field+rule makes the per-key state
monotonic in generation and closes that variant. Cheap: same field, same
comparison.

### 5.4 Companions / aliases

The same generation must stamp **all** companions of one install so a delete
refusal is consistent: the synthesized reverse entry, the DNAT/NAT64 companion,
and the **forward-wire alias** (daemon_ha_userspace.go:745-789, fabric path).
All originate from the same delta/install event, so they share the install's
`g`. The reverse companion the standby synthesizes locally
(`synthesized_synced_reverse_entry`) must inherit the forward entry's `g`.

### 5.5 New counter(s)

- `SyncStats.DeletesStaleIgnored` (Go) and a Rust
  `SESSION_DELETE_STALE_IGNORED` counter — observability that the guard fired,
  and the metric that tells us the real-world incidence (currently unknown).

### Weaker alternatives (evaluated, NOT the primary fix)

- **Journal TTL / drop deletes older than N seconds.** Reduces the window but
  does not close it (a fast same-second reuse still races); picks an arbitrary
  N; and a TTL-dropped delete re-leaks the very session #2163 fixed. **Reject as
  primary.** MAY be added as cheap defense-in-depth (bound journal age) but is
  not required by this plan and is out of scope unless the engineer wants it.
- **Rely on the standby's own GC to clean a wrongly-deleted `S'`.** Wrong
  direction — GC removing `S'` is the *bug's symptom*, not a mitigation; the
  standby has no independent way to know `S'` is live (it does not forward owned
  traffic until failover).

## 6. API / interface preservation

- Wire format stays backward/forward compatible via length-gated trailing
  fields + the gen==0 legacy fallback (§5.2). A mixed-version cluster (one node
  upgraded) degrades to **today's exact behavior** for any pair where either end
  lacks a generation — no regression, no new failure mode during a rolling
  upgrade.
- `dataplane.SessionValue`/`SessionValueV6` gain a `Generation uint64` field
  (additive; C-struct mirroring NOT required — this field is userspace-sync-only,
  like `LogFlagUserspace*` bits; document it as not present in BPF headers).
- `SessionStore.DeleteWithCompanionsV4/V6` signature: prefer an additive
  `DeleteWithCompanionsGenV4(key, gen, reason)` (or a generation-carrying
  variant) over changing the existing signature, to avoid touching every
  non-cluster caller (bulk reconcile, GC) that has no generation — SMR §pick.
- `SessionSyncRequest` (Go→Rust) gains a `Generation uint64 json:"generation,
  default"` field (no omitempty, #1961). Rust `SyncedSessionEntry` /
  control struct gain a `generation: u64` with `#[serde(default)]`.

## 7. Hidden invariants the change must preserve

1. **A real delete still deletes.** `deleteGen == existing.Generation` applies;
   a delete with no matching live entry is still a no-op.
2. **No weakening against old peers.** gen==0 on either side ⇒ today's
   unconditional delete; rolling upgrade safe.
3. **Bulk-sync resync still wins.** Cold-start bulk re-primes the standby; bulk
   entries either carry a generation (if both new) or fall back to gen==0
   behavior. The guard must not let a stale journaled delete survive a *bulk*
   that re-installed the session with a higher gen (it won't: bulk install bumps
   the stored gen, the old delete is then strictly older → refused).
4. **FIFO / single-sendCh ordering** unchanged (sync_conn.go invariants from
   #2163 plan §"Hidden invariants" 1-6 all preserved; the guard is receiver-side
   and adds no sender-side lock).
5. **Reverse/companion/alias consistency** (§5.4) — all share one `g`.
6. **Generation monotonic per (sender,key)** across a single boot; cross-boot
   regression is masked by the cold-start bulk re-prime (document, test).
7. **Helper parity + single authoritative seam**: the authoritative guard is in
   the cluster apply layer (`deleteClusterSynced*`); a refusal there short-
   circuits both the BPF conntrack map delete and the helper delete so the two
   cannot diverge (one keeps `S'`, the other drops it). The helper-side guard
   mirrors it for helper-originated deletes.
8. **Per-key generation monotonic in stored state**: both the install upsert and
   the delete are generation-guarded by the same `<` rule, so the stored
   generation for a key never regresses (closes the delayed-stale-install
   variant, SMR C3).

## 8. Risk assessment

| Risk | Severity | Mitigation |
|------|----------|-----------|
| Wrong generation source (collision) silently no-ops the fix | HIGH | §3.3/§5.1 — purpose-built monotonic counter, NOT the existing SessionID; regression test that same-second/same-slot reuse gets distinct `g`. |
| Guard refuses a *legitimate* delete (false retain → leak) | MED | Strict `<` only; equality applies; gen==0 fallback; new counter to watch; test the legit-delete path explicitly. |
| Mixed-version cluster regression during rolling upgrade | MED | gen==0 legacy fallback (§5.2/§7.2); test old↔new both directions. |
| Go/Rust guard divergence | MED | Plumb gen through `SessionSyncRequest`; parity test; the helper guard mirrors the Go guard exactly. |
| Cross-boot generation regression | LOW | Cold-start bulk re-prime; seed counter from boot nanos; document. |
| Unbounded sender-side per-key map (if Option A taken) | LOW | Recommend Option B (echo generation in close, no map); if map used, evict on delete-send + cap. |

## 9. Test plan

**Go unit (`pkg/cluster`):**
- `TestStaleDeleteIgnoredForReplacement`: install `S(K)` gen=1; install `S'(K)`
  gen=2 (overwrites, stored gen=2); apply `DeleteV4(K, gen=1)`; assert `S'`
  survives + `DeletesStaleIgnored == 1`. **Must fail against pre-fix** (today it
  deletes `S'`).
- `TestRealDeleteApplied`: install gen=2; delete gen=2 → removed.
- `TestLegacyPeerNoGenStillDeletes`: stored gen=0 OR delete gen=0 → unconditional
  delete (no regression).
- `TestJournalFlushReplayRefusesStaleDelete`: end-to-end with #2163 flush — a
  journaled `D(K,gen=1)` flushed after `S'(K,gen=2)` synced → `S'` survives.
- Wire round-trip: encode/decode session + delete with generation; old-length
  payload decodes to gen=0.
- `TestGenerationMonotonicSameSecondSameSlot` (the §3.3 trap): two installs of
  the same key in the same monotonic second on the same slot get strictly
  increasing `g`.
- `TestStaleInstallDoesNotRegressStoredGen` (SMR C3): install gen=2, then a
  delayed install gen=1 for the same key is refused (stored gen stays 2), so a
  subsequent stale `D(gen=1)` cannot delete the live entry.
- `TestFailoverDomainGenerationReStamp` (SMR B1, at least a unit-level model):
  after ownership change, the new owner's install of an inherited key re-stamps
  the stored generation to its own domain; a later delete it issues compares
  same-domain and applies; a stale cross-domain delete does not wrongly remove a
  live flow.

**Rust unit (`userspace-dp`):** `delete_synced_session` refuses a stale-gen
delete; `SyncedSessionEntry`/control serde round-trips `generation` with
`#[serde(default)]`; gen-0 fallback.

**Loss-cluster `make test-failover` (MANDATORY — touches session-sync/HA):**
the standard 14-iter zero-drop failover gate, to prove no failover/throughput
regression. Plus a targeted scenario if feasible: drive a same-tuple
reconnect-churn flow across an `em0` blip so a delete journals then replays
after a same-key re-sync, and assert the flow survives a subsequent failover
(no blackhole). At minimum, test-failover must be 14/0.

## 10. Out of scope (explicit)

- The #1760 reverse-key-collision class (distinct, shelved — §3.5).
- A protocol-version negotiation handshake (not needed; length-gating suffices).
- Mirroring the generation into the BPF C conntrack struct / headers (the field
  is userspace-sync-only, like `LogFlagUserspace*`).
- Replacing the synthesized `SessionID` scheme wholesale (orthogonal; we add a
  generation rather than fixing SessionID, to keep the change minimal).
- Journal TTL defense-in-depth (optional; engineer's discretion, not required).

## 11. Recommended approach (4-line synthesis)

Stamp every synced session install and every session delete with a **monotonic
per-sender install generation** carried as a length-gated trailing `uint64` on
the session AND delete wire messages (+ in the Go→Rust `SessionSyncRequest` and
the Rust `SyncedSessionEntry`). The standby/peer **applies a delete only if its
generation is not strictly older** than the generation of the entry it would
remove; gen==0 on either side falls back to today's unconditional delete (rolling-
upgrade safe). Do NOT reuse the existing `SessionID` — it is non-monotonic and
collides on same-second/same-slot reuse, so it would be a false fix.

# Plan of action — #5865: HA session sync installs semantically degraded sessions via lossy transports

## 1. Status

`DRAFT v4 — v3 + Codex r2 REVISE folds (producer model corrected; Phase 1 fully
specified; Phase 2 recast as an invariant contract + dedicated follow-up); pending
Codex r3 + Claude SMR r3 (AGY infra-blocked)`

Base: `origin/master` @ `b7343fda51b5`. Research-only branch
`research/5865-session-schema`. **No production code is touched in `/research`.**

**Convergence position (read first):** This issue is not a bounded bug — two
adversarial Codex rounds established it is a **multi-producer HA session-sync
completeness problem** requiring a scoped full-set resync protocol. The plan
therefore converges on a **phased roadmap**:

- **Phase 1 (Option B, bounded & fully specified below)** — additive JSON fields
  via a typed shared projection, a complete capability gate (binary + JSON,
  fail-closed), and export fail-closed. This closes the field gap (P2/P3), the
  mixed-version hole, and the silent export truncation. It is a de-risking
  increment; it does **not** close #5865.
- **Phase 2 (Option C, specified here as an INVARIANT CONTRACT)** — a scoped
  authoritative full-set resync protocol that subordinates the lossy producers.
  Because it entails wire-format decisions (a stable incarnation token) and a
  full resync/readiness state machine, it is **recommended to be executed as a
  dedicated follow-up research/design issue**, seeded by the contract in
  Section 7. #5865 stays open until Phase 2 lands.

## 2. Issue framing

#5865 reports the helper→daemon JSON/RPC fallback (`drain_session_deltas`) omits
five correctness fields (`policy_id`, `policy_counter_idx`, `app_timeout`,
`nat64`, `nat64_snat_v4`) the binary event stream carries, so a fallback-installed
session is mis-attributed, aged on the global timeout, and cannot rebuild the
NAT64 reverse BIB after failover. Verified true — and a symptom of a broader root
cause: **multiple session-install producers of differing fidelity, no single
authoritative metadata source, and no rule stopping a lossy producer from
overwriting a complete value.**

## 3. Root cause — the producer inventory (corrected per Codex r2)

A synced `SessionValue` on the standby can be written by these producers. Only the
binary paths are complete.

| # | Producer | Trigger | Complete? | Notes / evidence |
|---|---|---|---|---|
| P0 | **Binary bulk export** `export_all_sessions` / `snapshot_all_sessions_export` | cold-start / retry when available | **Complete fields**, but **live-OPEN snapshot only** | `ha.rs:685`; pushes via `push_delta_lossless`. Emits OPENs; a **lost CLOSE is not reconciled** — an empty/stale bulk skips stale-key deletion (Phase-2 concern). |
| P1 | **Binary event stream** incremental OPEN/CLOSE/UPDATE | per session event | **Complete** | `codec/session_sync.rs:17-194`; decode `eventstream.go:1052`; stamp `daemon_ha_userspace_convert.go:233-235,321-330` |
| P2 | **JSON `drain_session_deltas`** fallback + reconcile | 100 ms when stream down; **5 s reconcile even when connected** | **NO — omits all 5** | `binding.rs:1105`; `session_delta.rs:100`; `umem/mod.rs:1325`; `daemon_ha_userspace_stream.go:289-330` |
| P3 | **Owner-RG export** `export_owner_rg_sessions` + **automatic worker loss-resync** | FullResync / worker gap | **NO (JSON) + truncates >4096** | Walks each worker `SessionTable`, re-emits each OPEN to **both** the binary stream **and** the JSON pending buffer (`ha.rs:889-944`, `session_glue/mod.rs:497`); FullResync collects the **JSON** drain; Go requests `max=0` (`daemon_ha_userspace_export.go:51`); cap `mod.rs:375 =4096`, drop `umem/mod.rs:1329` |
| P4 | **Periodic cluster sweep** `syncSweep`→`ForEachV4/V6` over the **BPF-compat store** | 15 s / 60 s userspace, **rows created since last sweep** (`val.Created >= threshold`) | **PARTIAL** — keeps `PolicyID`; `app_timeout` hardcoded 0 (`publish_conntrack.rs:152,261`); `PolicyCounterIdx`/`Nat64SnatV4` **structurally absent** from the BPF ABI (`bpf_session_value.go:61` — `AppTimeout` **is** an ABI field, just zeroed); log/FIB flags cleared | `daemon_ha_sync.go:953`; cadence `manager.go:415`; walk+`stampInstallGenV4`+`encodeSessionV4` `sync_conn.go:822-852` |
| P5 | **Legacy bulk-sync fallback** | cold-start/retry when binary export unavailable/fails | **PARTIAL** (same reduced BPF-compat store) | not general reconnect replay |

**Corrected severity.** After the initial complete binary install (P1/P0), a new
session is degraded **once, shortly after creation** — by P2's reconcile drain
(when its accumulated delta is drained) and/or by P4's next post-create sweep
(`val.Created >= threshold`) — and then **remains degraded for its lifetime**
(nothing re-completes it; the binary stream only re-emits on a subsequent
OPEN/CLOSE/UPDATE). So this is **not** a per-tick flip-flop; it is a **persistent
degraded standby copy**, and any failover after the first degrade promotes
degraded state. The peer accepts the degraded write because each producer stamps a
**fresh, strictly-newer** generation (`stampInstallGenV4`, `QueueSessionV4`
non-coalescing `sync_conn.go:914,931`) and `installGenGuardV4` only rejects
strictly-older (`sync_conn.go:196,385`); `PutClusterSyncedSession` replaces the
whole value (`session_store.go:257`, BPF `UpdateAny`, Rust `install.rs:288`).

**NAT64 nuance.** Ordinary locally-created NAT64 sessions are generally **absent**
from the BPF-compat map (their reverse key is cross-family), so P4/P5 usually
**omit** them rather than overwrite them with an empty source. NAT64 degradation
therefore comes from **P2/P3 (JSON)** — which Phase 1 fixes.

**Two secondary defects (same root cause):**
- **Resurrection.** No coalescing: a binary `OPEN→CLOSE` leaves a delete
  tombstone at gen G+1; a delayed JSON `OPEN` at gen G+2 is newer and
  **resurrects** the closed key until its own close (or, if dropped at the 4096
  cap, until expiry).
- **Export truncation (P3).** `max=0` unbounded request into a 4096-cap queue →
  a FullResync of >4096 sessions **silently truncates and reports success**.

## 4. Honest scope/value framing

High-severity HA-correctness defect, blast radius wider than the title. PLAN-KILL
is **not** appropriate (producers are load-bearing and reachable). The value is
correct failover: attribution, aging, NAT64 return path, no resurrection, complete
resync, and a fail-closed mixed-version posture.

## 5. Design options

### Option A — one canonical versioned schema for all transports + full capability negotiation. Highest blast radius; structural drift-proofing; too large to land safely in one step. North star, not required for correctness.

### Option B — Phase 1: enrich the JSON producers + complete capability gate + export fail-closed. Fully specified in Section 6. Bounded, mergeable, closes P2/P3 field gap + mixed-version + truncation. **Necessary but not sufficient** (P4/P5 remain lossy).

### Option C — Phase 2: authoritative full-set resync protocol that subordinates P4/P5 and re-routes FullResync. Specified as an invariant contract in Section 7. Closes #5865.

### Recommendation — **land Phase 1 now; execute Phase 2 as a dedicated follow-up.** Phase 1 alone is a de-risking increment (it does not stop P4/P5 degrading ordinary v4/v6 sessions, though it does fix NAT64/attribution via the JSON path and closes the mixed-version + truncation holes). The durable win requires Phase 2, which is a resync-protocol redesign best scoped on its own.

## 6. Phase 1 — concrete design (Option B, bounded)

1. **Typed shared projection (not a string).** Introduce one canonical
   `SessionSyncMetadata { policy_id: u32, policy_counter_idx: u32,
   inactivity_secs: u32, nat64: bool, nat64_snat_v4: Option<Ipv4Addr> }` derived
   from `&SessionDecision`/`&SessionMetadata`. **Both** the binary encoder
   (`session_sync.rs:159-182`, replacing its inline logic — the raw-octet encoder
   consumes `Option<Ipv4Addr>`, not a string) **and** the JSON builder
   (`session_delta.rs:100`) call it. This is the shared-semantics subset of
   Option A that makes the two OPEN encoders un-driftable for these fields.
2. **`binding.rs`** — append 5 `#[serde(default)]` fields to `SessionDeltaInfo`
   (tags `policy_id`/`policy_counter_idx`/`app_timeout`/`nat64`/`nat64_snat_v4`),
   the JSON serializing `nat64_snat_v4` as the dotted-quad string (empty when
   `None`). Note the `0.0.0.0` vs empty representation difference vs. the binary
   decoder (final `SessionValue` identical).
3. **`session_delta.rs`** — populate from the shared projection. The constructor
   is shared by OPEN **and CLOSE** deltas, so JSON CLOSE gains the fields too; the
   **binary CLOSE frame is intentionally minimal and stays unchanged**.
4. **Export fail-closed (P3), not an additive flag.** Add per-worker export
   accounting (expected/emitted/collected, or an epoch) — a dropped-counter delta
   is **not** a completeness certificate (a worker with SessionTable rows but no
   live binding/RPC queue skips JSON pushes without incrementing the drop
   counter, then ACKs). On truncation/undercount the helper returns the existing
   RPC failure (`ok=false`, no usable partial), so an old daemon cannot ignore an
   additive flag. A binding **permanently** over 4096 must escalate to the binary
   bulk export (P0) or the daemon must enter **durable unready** with defined
   operator recovery — Phase 1 must state which (recommend: escalate to P0; if P0
   unavailable, unready).
5. **Complete capability gate + fail-closed** (Section 8).
6. **Fixture** — update `userspace-dp/tests/fixtures/protocol_wire_v1.json`
   (always-serialized fields).
7. **Docs** — `session/README.md:675-683,770`; tighten the overclaiming
   `protocol.go:2985-2996` comment.

## 7. Phase 2 — invariant contract (Option C, for a dedicated follow-up)

Any Phase-2 design MUST satisfy all of the following. These are requirements, not
a chosen mechanism.

**7.1 Replace the lost-OPEN backfill BEFORE suppressing P4.** A daemon→peer
`sendCh` overflow drops a P1/P2 OPEN, sets `syncBackfillNeeded`, and is still
ACKed upstream; **the sweep's install replay is currently the only retry**.
Suppressing P4's install replay while keeping only the delete journal **loses that
recovery**. Phase 2 must first provide an authoritative Rust-backed backfill —
e.g. withhold the upstream ACK on downstream admission failure, or trigger a
fenced authoritative full export — then subordinate/suppress P4/P5 installs (never
the delete journal / #3926 convergence).

**7.2 FullResync must be a full-SET reconciliation, not an OPEN snapshot.**
`export_all_sessions` (P0) emits live OPENs only; a **lost CLOSE** leaves the stale
peer key surviving, and the receiver skips stale reconciliation on an empty bulk.
Phase 2's resync protocol must define: full-set boundaries **including the empty
set**; owner-RG scope; concurrent OPEN/CLOSE ordering; **stale-key deletion**;
**peer application ACK before readiness**; and end-to-end downstream-overflow
handling.

**7.3 Execution hazard.** `handleEventStreamFullResync` runs synchronously on the
event-stream read loop; pushing the export back through that same stream can fill
buffers and time out (Go is blocked in the RPC instead of reading frames). Phase 2
must run the resync off the read loop.

**7.4 Resurrection needs a stable incarnation token.** Neither "generation from
create instant" nor "suppress reconcile OPENs vs live tombstones" alone
distinguishes a delayed event for incarnation A from a legitimate rapid
incarnation B. Phase 2 must carry a **stable incarnation token across P1/P2/P3
OPEN and CLOSE** (a wire decision — conflicts with "binary layout unchanged", so
it is a real Phase-2 format change), with **equal-incarnation duplicate OPENs
idempotent** (no refresh/replace). Required cases: `OPEN(A),CLOSE(A),delayed
OPEN(A)`→rejected; `OPEN(A),CLOSE(A),OPEN(B)`→B accepted; delayed A events after
B→B unmutated; across v4/v6/fabric aliases.

**7.5 End-to-end capability/readiness state machine** (see Section 8) covering
source-side and target-side, ACK-gated recovery, and node-to-node semantic
capability for mixed-base/ISSU.

## 8. Mixed-version / capability analysis (v1 rebuttal RETRACTED; gate completed per Codex r2)

The helper↔daemon transport is **not** same-version by construction: `system
dataplane binary <path>` is operator-configurable (`config/types_system.go:62`,
`schema_system.go:292`, exec `process.go:35`), readiness checks only ping/status
(`process.go:116`), and the daemon already handles an "OLDER local helper"
upgrade-lag window (`manager_ha.go:458-472`). Today a new daemon can spawn a
pre-fix helper and silently decode zeros.

The capability gate MUST:
- **Attest the complete semantic projection and gate ALL producers** — not JSON
  only. An old helper also emits **short binary P1 frames** lacking the semantic
  trailers, which the length-gated decoder currently admits as zeros. Gate binary
  OPEN/UPDATE, JSON drain, and JSON export.
- **Default closed** on unknown / missing / zero capability.
- **Bind to the current helper process / event-stream connection**; invalidate on
  restart, reconnect, or downgrade.
- **Run before a destructive drain RPC pops entries**, not after inspecting the
  response.
- **Revoke readiness on any refusal or failed FullResync** even if previously
  ready; the existing readiness **timeout must not release** this
  semantic-failure latch.
- **Recover only** via a capable helper + authoritative resync + downstream peer
  application + ACK.
- **Propagate source-side failure to target takeover readiness** — checking only
  the target's local helper is insufficient.
- **Address new-helper/old-daemon reverse skew** — prove the supported window
  already understands the keys, or negotiate the daemon-required schema.
- **Assign node-to-node semantic capability to a phase and test it** —
  mixed-base/ISSU is explicitly supported; length-gating gives decode, not
  semantic fail-closed (a missing field silently becomes the harmful zero).

Scope note: a helper old enough to omit JSON keys likely also omits the **binary**
trailers, so "refuse JSON, use binary" rescues nothing — the gate is "does the
helper emit the complete projection on the authoritative path?"; if not, **fail
closed on HA session sync entirely** (keep takeover/resync unready).

Phase 1 ships the gate for the helper↔daemon direction + default-closed +
drain-before-pop + readiness latch. The node-to-node ISSU semantic capability and
the source→target propagation land with Phase 2's state machine.

## 9. Hidden invariants

- **Units:** `app_timeout` seconds (`None→0`, else `ns/1e9` floored, saturating
  `u32::MAX`); Go applies without conversion (`convert.go:229,324`). Parity with
  `session_sync.rs:159-182`.
- **NAT64:** `nat64_snat_v4` non-empty only for `(nat64==true, rewrite_src==V4)`.
- **CLOSE:** JSON CLOSE gains the fields; **binary CLOSE stays minimal** — so
  binary↔JSON five-field parity is an **OPEN-only** property.
- **Whole value:** P4/P5 clear log/FIB flags too — the fix and tests must cover
  the whole `SessionValue`, not only the five issue fields.
- **Delete-journal / backfill:** never suppress #3926 delete convergence.

## 10. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED–HIGH (Phase 2) / LOW (Phase 1 fields) | Phase 2 touches live resync/backfill/readiness — the highest-risk area; must land its own smoke. |
| Lifetime / borrow-checker | LOW | Copies + typed projection borrows. |
| Performance | LOW | Off packet hot path. |
| Architectural mismatch | MED | Two transports remain post-Phase-1 (guarded by the typed projection + capability gate); full unification (A) deferred. |
| Silent fail-open | HIGH if unfixed | Export truncation + capability hole are themselves correctness defects; Phase 1 closes both. |

## 11. Test plan (smoke deferred — shim-ABI wall; forced-fallback failover is a merge precondition at `/engineer`)

**Phase 1**
- **Typed shared-projection golden test** — assert the binary encoder and JSON
  builder produce the same five-field projection across: `app_timeout`
  `None`/sub-second flooring/`u64::MAX` saturation; NAT64 false+V4 / true+missing
  or V6 / true+valid-V4. Binary-vs-JSON five-field parity is **OPEN-only**;
  separately test **JSON CLOSE population** and **unchanged binary CLOSE layout**.
- **`nat64` marker** asserted independently of `SessionValueV6` (which does not
  store the bool); include the `0.0.0.0` normalization case.
- **Go round-trip** — a JSON-decoded delta stamps a `SessionValue` identical (all
  five fields incl. `nat64`) to a binary-decoded delta from the same session.
- **Export fail-closed** — exact 4096/4097 boundaries, prefilled queues, multiple
  workers, no-live-binding/rebind: undercount ⇒ `ok=false`, no partial success.
- **Capability gate** — unknown startup state; absent/zero capability;
  binary-frame rejection; restart/downgrade invalidation; P2 and P3 refusal;
  readiness held across the readiness timeout; recovery only after peer ACK; mixed
  peer versions.
- **Whole `SessionValue`** incl. log/FIB flags; actual worker-SessionTable
  owner-RG export with nonzero sentinels.

**Phase 2 (dedicated follow-up)**
- Downstream send-queue overflow → authoritative OPEN backfill (no lost session).
- Lost-CLOSE FullResync → stale key deleted; empty-set reconciliation; owner-RG
  isolation; FullResync marker/barrier ordering; off-read-loop execution.
- Resurrection matrix (§7.4) across v4/v6/fabric; equal-incarnation idempotence.

**Deferred forced-fallback failover smoke (merge precondition):** stream
disconnected, `make test-failover` with policy counters, custom
`inactivity-timeout`, source + static NAT, NAT64, fabric, IPv4 **and** IPv6 —
assert the promoted node preserves attribution/aging/NAT64 and does not
re-degrade across a sweep tick.

## 12. Out of scope (explicitly)

- Full Option A codegen unification (north star; the typed projection is the
  pragmatic subset).
- Widening the BPF-compat `SessionValue` ABI to carry `PolicyCounterIdx` /
  `Nat64SnatV4` (Phase 2 subordinates/suppresses instead).
- Any eBPF dataplane path (retired, #1476).

## 13. Open questions for adversarial review

1. **Phase-1-alone value.** Given P4/P5 still degrade ordinary v4/v6 sessions,
   is Phase 1 worth landing alone as a de-risking + mixed-version + truncation +
   NAT64/attribution(JSON) fix, with #5865 kept open until Phase 2? Or must B+C
   land together?
2. **P4 backfill replacement (§7.1).** Is "withhold upstream ACK on downstream
   admission failure" the right lost-OPEN recovery, or a fenced authoritative full
   export, or both?
3. **FullResync protocol (§7.2).** Minimal correct full-set protocol with
   stale-key deletion + ACK-before-readiness + empty-set, off the read loop?
4. **Incarnation token (§7.4).** What is the minimal stable token, and is a binary
   OPEN/UPDATE/CLOSE format change acceptable to carry it?
5. **Capability/readiness state machine (§8).** Is the enumerated fail-closed
   posture complete, including source→target propagation and ISSU node-to-node
   semantic capability?
6. **Split correctness.** Is executing Phase 2 as a dedicated follow-up issue
   (seeded by §7's contract) the right structure, or must this single issue
   carry the entire design before any code lands?

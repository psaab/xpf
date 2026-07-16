# Plan of action — #5865: HA session sync installs semantically degraded sessions via lossy transports

## 1. Status

`DRAFT v2 — revised after Codex r1 PLAN-KILL; pending re-review (Codex + Claude SMR; AGY infra-blocked)`

Base: `origin/master` @ `b7343fda51b5`. Research-only branch
`research/5865-session-schema`. **No production code is touched in `/research`.**

**v1→v2 delta (why the scope grew):** Codex r1 PLAN-KILLed v1's "add 5 JSON
fields and you're done" framing. It surfaced — and this plan verified — that the
JSON fallback is only **one of three** degraded HA session-install producers, that
the mixed-version helper↔daemon scenario v1 dismissed is **reachable**, and that
the FullResync export **silently truncates**. v2 reframes the problem around the
full producer inventory and recommends a **phased** fix. Every factual claim
below was re-checked against the tree.

## 2. Issue framing

#5865 reports that the helper→daemon HA session-sync JSON/RPC fallback
(`drain_session_deltas`) omits five correctness fields (`policy_id`,
`policy_counter_idx`, `app_timeout`, `nat64`, `nat64_snat_v4`) that the binary
event stream carries, so a session installed via the fallback is mis-attributed,
aged on the global timeout, and cannot rebuild the NAT64 reverse BIB after
failover. That is real — but it is a **symptom of a broader root cause**: the
userspace HA path has **multiple session-install producers of differing
fidelity, no single authoritative metadata source, and no rule preventing a
lossy producer from overwriting a complete value.**

## 3. Root cause — the producer inventory (the core of v2)

On the userspace HA path a synced `SessionValue` on the standby can be written by
**five** producers. Only the binary event stream is complete.

| # | Producer | Trigger | Carries the 5 fields? | Evidence |
|---|---|---|---|---|
| P1 | **Binary event stream** (incremental OPEN/CLOSE) | every session open/close | **YES (complete)** | `event_stream/codec/session_sync.rs:17-194`; decode `eventstream.go:1052`; stamp `daemon_ha_userspace_convert.go:233-235,321-330` |
| P2 | **JSON `drain_session_deltas`** (fallback + reconcile) | 100 ms poll when stream down; **5 s reconcile even when connected** | **NO** — Rust `SessionDeltaInfo` lacks all 5 | `binding.rs:1105`; `session_delta.rs:100-175`; `umem/mod.rs:1325`; `daemon_ha_userspace_stream.go:289-330,412` |
| P3 | **JSON `export_owner_rg_sessions`** (FullResync) | helper replay-buffer trim / gap | **NO** (same struct) **+ silently truncates >4096** | `ha.rs:889-944`; `daemon_ha_userspace_export.go:51` passes `max=0`; cap `mod.rs:375 MAX_PENDING_SESSION_DELTAS=4096`, drop `umem/mod.rs:1329` |
| P4 | **Periodic cluster sweep** `syncSweep`→`ForEachV4/V6` over the **BPF-compat store** | 15 s active / 60 s idle in userspace | **PARTIAL** — keeps `PolicyID`, but `app_timeout=0`, no `PolicyCounterIdx`, no `Nat64SnatV4`, cleared log flags | `daemon_ha_sync.go:953 StartSyncSweep`; `manager.go:415` returns `true,15s,60s`; `sync_conn.go:778` walk+`stampInstallGenV4`+`encodeSessionV4`; degraded publish `bpf_map/publish_conntrack.rs:152,261` (`app_timeout: 0`); ABI limit `bpf_session_value.go:56`, `types.go:75` |
| P5 | **Legacy bulk-sync fallback** | reconnect replay | **PARTIAL** (same reduced BPF-compat store) | serializes `s.sessions` compat store, same source as P4 |

**Consequence 1 — the fix is NOT "add 5 JSON fields."** Even with P2/P3 fully
repaired, **P4 independently re-degrades every synced session every 15–60 s**:
each sweep row is read from the BPF-compat store (`app_timeout=0`, no counter, no
NAT64 source), `stampInstallGenV4` gives it a **fresh, newer** generation, and
the peer's `installGenGuardV4` accepts newer generations
(`sync_conn.go:196,385`), replacing the whole value
(`PutClusterSyncedSession`→`session_store.go:257`, BPF `UpdateAny`
`maps_session.go:69`, Rust `install.rs:288` removes-then-inserts). The BPF ABI
**structurally cannot** carry `PolicyCounterIdx`/`Nat64SnatV4`/a nonzero
`app_timeout`, so P4 cannot be "enriched" in place — it must be **re-sourced from
authoritative Rust state or suppressed** in userspace mode.

**Consequence 2 — steady-state, not fallback-only (severity, corrected).** P2's
`push_session_delta` is unconditional (capacity-gated only), P2's queue is
drained only by the JSON RPC, and the daemon runs the 5 s reconcile drain **even
while the binary stream is healthy**. `QueueSessionV4/V6` does **not coalesce by
key** (`sync_conn.go:914,931`): each call appends a distinct message with a fresh
generation. So the normal low-churn ordering is `binary OPEN (gen G, complete) →
JSON reconcile OPEN (gen G+1, zeroed) → peer accepts G+1 and replaces`. The
degradation is therefore **continuous risk for new/long-lived sessions**, not
merely a genuine-fallback event. Corrections to v1's wording: "within ≤5 s" is
**not** a bound (only 256 entries drain per tick; backlog/overflow can delay or
drop a duplicate); it is continuous *risk*, not deterministic degradation of
every session; and field state is **timing-dependent** (P4 may restore `PolicyID`
while leaving timeout/counter/NAT64 degraded).

**Consequence 3 — two secondary defects fall out of the same root cause:**
- **Resurrection (no coalescing).** A binary `OPEN`→`CLOSE` leaves a delete
  tombstone at gen G+1; a delayed JSON `OPEN` at gen G+2 is newer than the
  tombstone and **resurrects a closed session** on the peer until its own close
  crosses a batch boundary — or, if that close was dropped at the 4096 cap,
  until expiry.
- **Export truncation (P3).** `export_owner_rg_sessions` accumulates into the
  same 4096-cap pending queue and Go requests `max=0` (unbounded); a FullResync
  of >4096 sessions per binding **silently drops the excess and reports
  success** — a silent standby session loss on the exact recovery path meant to
  restore completeness.

## 4. Honest scope/value framing

This is a **High-severity HA-correctness defect** with a **larger blast radius
than the issue title implies**. The value is correctness of failover
(attribution, aging, NAT64 return path, no resurrection, complete resync). Given
the scope, PLAN-KILL is **not** appropriate (the fallback and sweep are both
load-bearing and reachable), but **decomposition is** — Section 6 recommends a
phased plan so a bounded Phase 1 can land while Phase 2 (the structural
producer-subordination) is scoped and smoked separately.

## 5. Design options (reframed around the full producer set)

### Option A — One canonical versioned schema for ALL transports + capability negotiation

A single versioned session-open projection that P1/P2/P3 derive from, the sweep
(P4/P5) re-sourced from authoritative Rust session state, and a helper-reported
session-delta capability version gating every JSON/compat producer.

- **Blast radius:** HIGHEST. Touches the binary codec, JSON struct, the
  BPF-compat publish path or its replacement, the sweep source, and Go decode.
- **Drift-prevention:** BEST (structural).
- **Effort/risk:** HIGH / HIGH. Correct end-state, but too large to land safely
  in one step for a High-severity fix.

### Option B — Enrich the JSON producers + capability gate + export fail-closed (Phase 1 building block)

- Add the five fields to the Rust `SessionDeltaInfo` (`binding.rs`) and populate
  them in `flush_session_deltas` (`session_delta.rs:100`) via a **shared
  conversion helper** that both the binary encoder and JSON builder call (so
  `inactivity_ns→secs` and `snat_v4` can never diverge). Closes **P2 and P3's
  field gap**.
- **Export overflow fail-closed (P3):** detect when a per-binding export hit the
  4096 cap (nonzero `session_delta_dropped` delta across the kick, or a returned
  truncation flag) and **fail the FullResync closed** — return an error so the
  daemon retries / escalates to a binary bulk export, rather than reporting a
  truncated success.
- **Capability gate + fail-closed (C4, see Section 8):** the helper reports a
  session-delta schema capability/version on `ping`/`status`; the daemon
  **refuses JSON HA admission/export from an incapable (older) helper** and keeps
  takeover/resync unready for that path instead of silently installing zeroed
  values.
- **Does NOT fix P4/P5.** On its own, Option B leaves the BPF-compat sweep
  re-degrading sessions. **Option B is necessary but not sufficient** — it must
  be paired with Option C's producer-subordination.

### Option C — Make the binary path authoritative; subordinate/suppress the lossy producers (Phase 2, the structural fix)

- **FullResync via the binary bulk export.** Route the owner-RG FullResync
  through the existing binary `export_all_sessions` / `snapshot_all_sessions_export`
  (#4054, pushes complete frames via `push_delta_lossless`) instead of the JSON
  RPC — complete fields, no 4096 truncation.
- **Subordinate P4/P5 in userspace mode.** The BPF-compat sweep install-replay
  and legacy bulk-sync are structurally lossy (BPF ABI can't hold the fields).
  In userspace mode, **suppress their session-INSTALL re-send** (the binary
  stream + binary bulk export already provide authoritative convergence) while
  **keeping the sweep's delete-journal/backfill convergence duties**
  (`sync_conn.go:778` #3926 delete-journal). Alternatively, if suppression is too
  risky, **subordinate their generation** so a sweep/bulk row can never supersede
  a fresher complete install for the same key (a per-key "authoritative-source"
  precedence), but suppression is cleaner.
- **Cross-transport generation/duplicate semantics (resurrection).** Define that
  a post-CLOSE duplicate OPEN cannot resurrect a tombstoned key (e.g. bind the
  delta's generation to the session's create instant rather than a fresh
  monotonic counter, or drop reconcile OPENs for keys with a live newer
  tombstone).
- **Effort/risk:** MED–HIGH / MED. The risk is proving the binary bulk export
  covers every reconnect/resync scenario the JSON path covers today.

### Recommendation — **Phased: B (Phase 1) then C (Phase 2)**, converging toward A's end-state

- **Phase 1 (bounded, ships first):** Option B — additive JSON fields (shared
  helper, fixture update), export-overflow fail-closed, helper capability gate +
  fail-closed. Closes P2/P3's field gap and the mixed-version hole. **Explicitly
  documented as partial:** it does not stop P4's re-degradation, so it must not
  be represented as closing #5865.
- **Phase 2 (closes the issue):** Option C — binary-authoritative FullResync +
  subordinate/suppress P4/P5 + resurrection semantics.
- Full Option A (codegen unification) is the north star but is **not required**
  to reach correctness; B+C reaches it with bounded, separately-smokeable steps.

The user decides at `/engineer` time whether to land Phase 1 alone first or drive
B+C together. **Phase 1 alone is a real improvement but leaves the issue open.**

## 6. Concrete design

### Phase 1 (Option B)
1. **`binding.rs`** — append 5 `#[serde(default)]` fields to `SessionDeltaInfo`:
   `policy_id: u32`, `policy_counter_idx: u32`, `app_timeout: u32` (seconds),
   `nat64: bool`, `nat64_snat_v4: String`, tags matching Go
   (`policy_id`/`policy_counter_idx`/`app_timeout`/`nat64`/`nat64_snat_v4`).
2. **Shared conversion helper** (new, in a module both callers import) computing
   `inactivity_secs(metadata) -> u32` and `snat_v4_string(decision) -> String`
   from a `&SessionDecision`/`&SessionMetadata`; call it from **both**
   `encode_session_open` (`session_sync.rs:159-182`, replacing the inline logic)
   **and** the JSON builder in `session_delta.rs:100`. This makes the two
   transports share one semantic projection (a slice of Option A's value).
3. **`session_delta.rs`** — populate the 5 fields from the shared helper. Note
   the constructor is shared by OPEN **and CLOSE** deltas, so the fields (and the
   `nat64_snat_v4` allocation) are written on close too — the v1 "alloc only on
   NAT64 opens" claim was wrong.
4. **Export overflow fail-closed** — thread a per-kick "dropped" signal from the
   worker export back through `wait_and_collect`/the RPC; the Go
   `exportUserspaceOwnerRGSessions*` treats truncation as an error.
5. **Capability gate** — extend the helper `status`/`ping` with a
   `session_delta_schema_version` (or a capability flag); Go refuses JSON
   admission/export when the helper is below the fix version (Section 8).
6. **Fixture** — `userspace-dp/tests/fixtures/protocol_wire_v1.json` must gain
   the always-serialized fields (else the wire fixture test fails).
7. **Docs** — `userspace-dp/src/session/README.md:675-683,770`; tighten the
   overclaiming `protocol.go:2985-2996` comment.

### Phase 2 (Option C)
8. Route FullResync (`handleEventStreamFullResync`) through binary
   `export_all_sessions` instead of `ExportOwnerRGSessions` JSON.
9. In userspace mode, suppress the P4 sweep install-replay and P5 bulk-sync
   session-INSTALL emission (keep delete-journal), OR add per-key source
   precedence so they cannot supersede a complete install.
10. Resurrection fix: post-CLOSE duplicate OPENs must not win against a live
    tombstone.

## 7. Public API preservation

- No control-verb removals. `SessionDeltaInfo` gains **additive** JSON keys
  (`serde(default)` / `omitempty`).
- New: a helper `session_delta_schema_version`/capability on `status` (additive),
  and a truncation signal on the export response (additive).
- Binary event-stream frame layout: **unchanged**.
- Node→node cluster wire: unchanged for the fields it already carries — but note
  (correcting v1) `PolicyID` is in the **fixed** V4/V6 payload, and only
  `AppTimeout`/`PolicyCounterIdx`/V6 `Nat64SnatV4` are additive **trailing**
  fields (`sync_protocol.go:431,548`).
- No Go **production** decode change for the field fix (Go already decodes/stamps);
  Phase-1 capability gate + export fail-closed **do** add Go production logic.

## 8. Mixed-version / capability analysis (v1 rebuttal RETRACTED)

**v1 was wrong.** The helper↔daemon transport is **not** same-version by
construction:
- `system dataplane binary <path>` is operator-configurable
  (`config/types_system.go:62`, `schema_system.go:292`), selected/executed at
  `process.go:35`; readiness checks only ping/status (`process.go:116`), not
  build identity or session-delta schema capability. The default binary search
  also considers cwd / repo build output / `PATH`.
- The codebase itself handles an **"OLDER local helper" upgrade-lag window**
  (`manager_ha.go:458-472`), keyed on the helper's reported snapshot protocol
  version — proof the daemon can transiently run a differently-versioned helper.

Therefore a new daemon can spawn a pre-fix helper that omits the JSON keys, and
today it would **silently decode the harmful zero values**. The correct handling
is the issue's requirement #3: a **helper-reported session-delta capability/
version**, and the daemon must **refuse JSON HA admission/export from an
incapable helper and keep takeover/resync unready** (fail closed) rather than
install zeroed metadata. Length-gating on the node→node wire gives *decode*
compatibility, **not** *semantic* fail-closed — a missing field silently becomes
the exact harmful zero. If mixed node **releases** are supported, the peer
semantic capability needs the same treatment; existing length checks do not
satisfy fail-closed. This capability gate is **in Phase 1**.

## 9. Hidden invariants the change must preserve

- **Units:** `app_timeout` is **seconds** (`None→0`, else `ns/1e9` floored,
  saturating `u32::MAX`); Go applies it without conversion
  (`convert.go:229,324`). Verified parity with `session_sync.rs:159-182`.
- **NAT64 derivation:** `nat64_snat_v4` non-empty only for
  `(nat64==true, rewrite_src==Some(V4))`; the reverse BIB datum not in the key.
  Note `0.0.0.0`: the JSON path yields `"0.0.0.0"` while the binary decoder maps
  all-zero octets to empty — final `SessionValue` semantics are identical, but a
  delta-level golden compare must account for the representation difference.
- **Delete-journal / backfill:** Phase-2 sweep subordination must preserve the
  #3926 connected-delete-journal flush and the backfill replay — suppress only
  the lossy INSTALL re-send, never the delete convergence.
- **Export completeness:** after the fail-closed change, a truncated export must
  never be treated as a complete resync.
- **Ordering / allocation:** the shared constructor writes the fields on OPEN and
  CLOSE; the `nat64_snat_v4` string alloc is off the packet hot path (drain path).

## 10. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | MED | Phase-2 sweep suppression + FullResync re-route touch live HA recovery paths; must prove the binary bulk export covers every reconnect/resync scenario. Phase-1 additive fields are LOW. |
| Lifetime / borrow-checker | LOW | Copies + one owned `String`; shared helper takes borrows. |
| Performance regression | LOW | Off packet hot path; one small string on NAT64 rows. |
| Architectural mismatch | MED | Two transports remain after Phase 1 (guarded by the shared projection + tests); full unification (A) deferred. Reviewers who require A must say why B+C's shared projection + capability gate is insufficient for a High-severity fix that must land safely. |
| Silent-truncation / fail-open | HIGH if unfixed | The export truncation and capability hole are themselves correctness defects; Phase 1 must close both, not just the field gap. |

## 11. Test plan (smoke deferral noted)

`make test-failover` and the HA smoke targets are **blocked by the loss-cluster
shim-ABI wall** (pinned cpumap=16 vs repo 256; verify-dataplane fail-closes every
cluster-deploy). Confidence therefore rests on tests + design review, with a
mandatory forced-fallback smoke recorded as a **merge precondition at
`/engineer`**, not a waiver:

- **Shared-projection golden test** — assert the binary encoder and JSON builder
  produce the **same semantic projection** for the 5 fields across a matrix:
  `app_timeout` `None`/sub-second flooring/`u64::MAX` saturation; NAT64
  false+V4-rewrite / true+missing-or-V6-rewrite / true+valid-V4; OPEN and CLOSE.
  (A field-name-list test alone is insufficient — it cannot detect a *new* binary
  field, so the guard must compare the shared projection both encoders call.)
- **Go round-trip** — a JSON-decoded delta stamps a `SessionValue`
  **byte-identical (on all 5 fields incl. `nat64`)** to a binary-decoded delta
  from the same session.
- **Sequence tests** — `binary OPEN → JSON reconcile OPEN` (no downgrade);
  `binary OPEN→CLOSE → delayed JSON OPEN` (no resurrection); **sweep after a
  complete install** (no re-degradation) — the P4 regression the whole plan
  turns on.
- **Export overflow** — a >4096-session owner-RG export **fails closed**, not
  truncates-and-succeeds.
- **Capability gate** — a helper reporting a pre-fix schema version causes the
  daemon to refuse JSON admission/export (no zeroed installs).
- **Fixture** — `protocol_wire_v1.json` updated; the Rust cargo suite + 30 Go
  packages pass.
- **Forced-fallback failover smoke (merge precondition, deferred):** with the
  binary stream disconnected, `make test-failover` carrying policy hit-counters,
  a custom per-application `inactivity-timeout`, source + static NAT, a NAT64
  flow, fabric forwarding, IPv4 **and** IPv6 — assert the promoted node preserves
  attribution, aging, and the NAT64 reverse path, with **no** re-degradation
  across a subsequent sweep tick.

## 12. Out of scope (explicitly)

- Full Option A codegen unification of the binary frame and JSON struct (deferred
  north star; B+C's shared projection is the pragmatic subset).
- Widening the BPF-compat `SessionValue` ABI to carry `PolicyCounterIdx` /
  `Nat64SnatV4` (Phase 2 re-sources or suppresses instead).
- Any eBPF dataplane path (retired, #1476).

## 13. Open questions for adversarial review (each invitable to further revision or PLAN-KILL of a sub-part)

1. **Phase split vs. all-at-once.** Is landing Phase 1 (additive JSON + capability
   gate + export fail-closed) alone acceptable given it does **not** close the
   issue (P4 still re-degrades), as long as it is documented as partial? Or must
   B+C land together so #5865 is never marked fixed prematurely?
2. **P4 subordination — suppress vs. precedence.** Is suppressing the
   userspace-mode sweep install-replay (keeping delete-journal) safe, i.e. do the
   binary stream + binary bulk export fully cover the sweep's "re-converge
   long-lived flows" purpose? Or is per-key source-precedence the safer choice?
3. **FullResync re-route.** Does the binary `export_all_sessions` (#4054) cover
   every reconnect/resync trigger that the JSON `export_owner_rg_sessions`
   currently serves (owner-RG scoping, ack sequencing)? If not, what is missing?
4. **Capability-gate fail-closed blast radius.** If the daemon refuses JSON HA
   admission from an incapable helper, what is the behavior during the legitimate
   transient upgrade-lag window (`manager_ha.go:458-472`) — does takeover/resync
   correctly stay "unready," and is that the desired posture vs. degraded-but-up?
5. **Resurrection semantics.** What is the minimal correct rule to stop a
   post-CLOSE duplicate OPEN from resurrecting a tombstoned key without breaking
   legitimate rapid reopen of the same 5-tuple? Generation-from-create-instant,
   or reconcile-OPEN suppression against live tombstones?
6. **Is A actually required?** Does the shared semantic projection (Section 6.2) +
   the sequence/golden tests give enough drift protection, or do reviewers insist
   on full codegen (Option A) despite the cost?

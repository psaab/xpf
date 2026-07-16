# Plan of action — #5865: HA session JSON fallback omits policy, timeout, and NAT64 state

## 1. Status

`DRAFT v1 — pending adversarial plan review (Codex + AGY + Claude SMR)`

Base: `origin/master` @ `b7343fda51b5`. Research-only branch
`research/5865-session-schema`. **No production code is touched in `/research`.**

## 2. Issue framing

The helper→daemon HA session-sync has two transports:

- **Binary event stream** (primary) — `EventFrame::encode_session_open`
  (`userspace-dp/src/event_stream/codec/session_sync.rs:17`) packs the
  admitting policy ID (#3056), per-rule counter index (#3073), per-application
  idle timeout (#3227), and the NAT64 marker + translated pool source (#4565)
  into length-gated trailing fields. The Go decoder
  (`pkg/dataplane/userspace/eventstream.go:1052 decodeSessionEvent`) reads them
  and `daemon_ha_userspace_convert.go:233-235,321-330` stamps them onto the
  synced `SessionValue`.
- **JSON/RPC fallback** (`drain_session_deltas`) — the Rust struct
  `SessionDeltaInfo` (`userspace-dp/src/protocol/binding.rs:1105`) **ends at the
  #2785 per-policy log flags**. It has no `policy_id`, `policy_counter_idx`,
  `app_timeout`, `nat64`, or `nat64_snat_v4`. The producer
  (`userspace-dp/src/afxdp/session_delta.rs:100-175`) correspondingly never
  sets them.

The Go `SessionDeltaInfo` (`pkg/dataplane/userspace/protocol.go:2941`) already
declares all five with matching JSON tags (`policy_id`, `policy_counter_idx`,
`app_timeout`, `nat64`, `nat64_snat_v4`) and its comment (`protocol.go:2985-2996`)
claims they are "decoded from the trailing fields of the binary open frame **AND
mirrored on the JSON RPC-fallback delta**." **That "mirrored on the JSON
fallback" claim is false** — the Rust struct cannot serialize those keys, so
every JSON-path delta decodes them as zero/empty. A session installed via the
fallback is stamped `PolicyID=0` / `PolicyCounterIdx=0` / `AppTimeout=0` (global
timeout) / no NAT64 reverse-BIB source.

The issue asks us to: (1) define one versioned canonical session-open schema and
generate both transports from it, or (2) add every correctness field to JSON — or
remove the fallback from HA admission, (3) negotiate capabilities/version and
fail closed rather than silently zero, (4) golden-test binary↔JSON equality, and
(5) run failover forced onto the fallback.

## 3. Honest scope/value framing

This is a **real HA-correctness defect**, not a perf tweak. After a failover, a
degraded synced session on the promoted node is mis-attributed (wrong/zero
policy on flow logs and hit counters), aged on the global per-protocol timeout
instead of the configured per-application `inactivity-timeout`, and — for NAT64
cross-family flows — cannot rebuild the reverse (v4→v6) BIB, so the return path
translates incorrectly or drops. The fix restores the exact correctness that
#3301 and #4565 built for the binary path but never completed for the JSON path.

The value is **correctness**, so the usual perf-kill clause is inverted: if
reviewers conclude the JSON fallback is genuinely never reachable in a real HA
deployment, PLAN-KILL is an acceptable verdict. Section 5 (Option D) proves it
**is** reachable — the fallback is load-bearing — so PLAN-KILL is **not**
expected to be the outcome.

### Severity is likely broader than "only when the binary path falls back"

`push_session_delta` (`userspace-dp/src/afxdp/umem/mod.rs:1325`) pushes into
`pending_session_deltas` **unconditionally** (only capacity-gated by
`MAX_PENDING_SESSION_DELTAS`); it is **not** gated on the binary event stream
being disconnected. The binary event-stream producer (`es.push_delta_lossless`)
pushes to a **separate** queue, so `pending_session_deltas` is drained **only**
by the JSON `drain_session_deltas` RPC. The daemon runs that drain **every 5 s as
a "reconciliation" even while the binary stream is connected**
(`daemon_ha_userspace_stream.go:289-311`, `drainUserspaceSessionDeltasWithConfig`
→ `DrainSessionDeltas`). Consequence: a session correctly synced by the binary
path is very likely **re-emitted degraded within ≤5 s by the reconcile drain and
re-queued to the peer** (`queueUserspaceSessionDeltas` → `QueueSessionV4/V6`),
overwriting the good `PolicyID`/`AppTimeout`/`Nat64SnatV4`. If confirmed, the
degradation is **continuous in steady state**, silently undoing #3301/#4565 on
the standby regardless of stream health. **This is the single most important
claim to verify (Section 11, Q1)** — it changes the impact statement from
"fallback-only" to "steady-state." Either way the fix (Section 5) is the same.

## 4. What's already shipped / partially built

- **Binary path is complete.** #2785 (log flags), #3301 (policy id / counter /
  timeout), #4565 (NAT64 marker + `snat_v4`) all land on
  `encode_session_open` (trailing, length-gated) and decode in
  `eventstream.go`.
- **Go `SessionDeltaInfo` already has all five fields** with the right JSON
  tags and the convert path already stamps them onto `SessionValue`
  (`daemon_ha_userspace_convert.go:233-235` V4, `:321-330` V6). **No Go decode
  change is required** for the core fix.
- **The node→node cluster wire already carries all five fields.**
  `pkg/cluster/sync_protocol.go` encodes/decodes `PolicyID` (`:129/:224`),
  `AppTimeout`+`PolicyCounterIdx` (`:181,:183/:275,:277`), and `Nat64SnatV4`
  (`:284`), each as **length-gated trailing fields** (`:98-99`), tolerant of a
  pre-#3301 peer. **No cluster-wire change is required.**
- **`SyncedSessionEntry` retains the full `decision` + `metadata`**
  (`userspace-dp/src/afxdp/worker/mod.rs:358-372`), so the owner-RG export
  re-emission path (`export_owner_rg_sessions` → `drain_session_deltas_from_live`,
  `ha.rs:889-944`) can reconstruct deltas whose `metadata.policy_id` /
  `metadata.policy_counter_idx` / `metadata.inactivity_timeout_ns` /
  `decision.nat.nat64` / `decision.nat.rewrite_src` are all present.

Net: **the only missing link is the five keys on the Rust `SessionDeltaInfo`
struct + populating them at construction.** Everything downstream already
consumes them.

## 5. Design options (multiple viable paths)

### Option A — One canonical versioned session-open schema (generate both transports)

Define a single schema (IDL or one canonical Rust struct) from which both the
binary frame and the JSON delta are generated/derived, so the two can never
drift again.

- **Blast radius:** HIGH. The binary frame is a hand-packed, fixed-offset,
  little-endian hot-path frame with length-gated trailing fields and flag bits;
  the JSON is serde. Unifying them means either a codegen step or a canonical
  struct that both serialize through — touching `codec/session_sync.rs`,
  `session_delta.rs`, `binding.rs`, `eventstream.go`, `protocol.go`, plus every
  golden test.
- **Drift-prevention:** BEST (structural).
- **Effort/risk:** HIGH / HIGH. For a **5-field, stable** delta whose two
  transports have deliberately divergent wire constraints (fixed-offset binary
  vs. serde JSON), full codegen unification is over-engineering.

### Option B — Additively mirror the five fields onto the JSON delta (RECOMMENDED)

Add the five fields to the Rust `SessionDeltaInfo` (`binding.rs`) with serde
renames matching the Go JSON tags, and populate them in `flush_session_deltas`
(`session_delta.rs:100`) exactly as `encode_session_open` does for the binary
frame:

```rust
// binding.rs SessionDeltaInfo (append, all #[serde(default)])
#[serde(rename = "policy_id", default)]         pub policy_id: u32,
#[serde(rename = "policy_counter_idx", default)] pub policy_counter_idx: u32,
#[serde(rename = "app_timeout", default)]        pub app_timeout: u32, // SECONDS
#[serde(rename = "nat64", default)]              pub nat64: bool,
#[serde(rename = "nat64_snat_v4", default)]      pub nat64_snat_v4: String,
```

```rust
// session_delta.rs, inside the SessionDeltaInfo { ... } literal
policy_id: delta.metadata.policy_id,
policy_counter_idx: delta.metadata.policy_counter_idx,
app_timeout: delta.metadata.inactivity_timeout_ns
    .map(|ns| u32::try_from(ns / 1_000_000_000).unwrap_or(u32::MAX)).unwrap_or(0),
nat64: delta.decision.nat.nat64,
nat64_snat_v4: match (delta.decision.nat.nat64, delta.decision.nat.rewrite_src) {
    (true, Some(IpAddr::V4(v4))) => v4.to_string(),
    _ => String::new(),
},
```

- **Blast radius:** LOW. ~5 struct fields + ~6 assignment lines in Rust; Go
  already decodes and stamps; cluster wire already carries. Updates the Rust
  `SessionDeltaInfo` doc-comment and the README claim.
- **Drift-prevention:** MODERATE by itself — pair it with the **golden
  binary↔JSON field-set parity test** (Section 9 / Option E) to get most of
  Option A's structural guarantee at a fraction of the cost.
- **Effort/risk:** LOW / LOW. This literally **completes the stated intent of
  #3301/#4565** ("… AND mirrored on the JSON RPC-fallback delta") that the Go
  comment already documents as done.

### Option C — Remove the JSON fallback from HA admission (binary is the only transport)

Make the binary event stream the sole HA session-install path: route the
FullResync owner-RG recovery through the binary bulk export
(`export_all_sessions` / `snapshot_all_sessions_export` already pushes binary
frames via `push_delta_lossless`, #4054) and drop the JSON reconnect/reconcile
drains from the sync path; fail closed (no sync) while the stream is down.

- **Blast radius:** MED–HIGH. The JSON drain is **load-bearing today** (Section
  5, Option D): reconnect polling at 100 ms and the FullResync owner-RG export
  both use it. Removing it needs a binary-native owner-RG resync and careful
  handling of the "stream not yet connected at startup" window.
- **Drift-prevention:** BEST (deletes the second transport → nothing to drift).
- **Fail-closed semantics:** refusing to sync while the stream is down is
  arguably *more* correct than syncing degraded sessions, but it worsens RPO
  during the outage window (no incremental sync until the stream reconnects).
- **Effort/risk:** MED–HIGH / MED. Attractive as **long-term hardening** but a
  poor fit for a High-severity correctness fix that must land safely. Recommend
  filing as a **follow-up** once the binary bulk-export path is proven, not
  blocking this fix.

### Recommendation

**Ship Option B + the golden parity test (Option E in Section 9), and file
Option C as a follow-up hardening issue.** Option B is the minimal,
end-to-end-complete correctness fix (everything downstream already consumes the
fields); the golden test structurally prevents the next field from drifting;
Option C's transport-deletion is real value but is a separate, riskier change
that should not gate the correctness fix.

## 6. Concrete design (Option B)

1. **`userspace-dp/src/protocol/binding.rs`** — append the five
   `#[serde(default)]` fields to `SessionDeltaInfo` (snippet above). Update the
   struct doc-comment to state that these mirror the binary open frame's
   #3301/#4565 trailing fields and that the daemon stamps them onto the synced
   `SessionValue`.
2. **`userspace-dp/src/afxdp/session_delta.rs`** — populate the five fields in
   the `SessionDeltaInfo { ... }` literal at `:100`, converting
   `inactivity_timeout_ns` → seconds (saturating) to match
   `encode_session_open`'s `inactivity_secs` (`session_sync.rs:163-167`), and
   deriving `nat64_snat_v4` from `decision.nat.rewrite_src` when
   `decision.nat.nat64` (mirroring `session_sync.rs:178-182`). Single source of
   the conversion logic — consider a shared helper so the binary and JSON paths
   compute `inactivity_secs` / `snat_v4` identically.
3. **No Go change for the core fix.** Optionally tighten the
   `protocol.go:2985-2996` comment (it currently over-claims parity) to note the
   parity is now real and guarded by the golden test.
4. **Docs:** update `userspace-dp/src/session/README.md:675-683,770` (the JSON
   RPC-fallback delta description) and note the parity invariant.

## 7. Public API preservation

- No RPC verb, control-message type, or wire-frame layout changes.
- `drain_session_deltas` / `export_owner_rg_sessions` responses gain keys in
  their `SessionDeltaInfo` elements — **purely additive JSON**. `#[serde(default)]`
  on the Rust side and `omitempty` on the Go side keep old/new decoders
  compatible in both directions.
- Binary event-stream frame layout: **unchanged**.
- Cluster node→node wire: **unchanged** (already carries the fields).
- Go `SessionDeltaInfo`, `SessionValue`, convert functions: **unchanged**.

## 8. Hidden invariants the change must preserve

- **Same-host, same-version IPC (load-bearing).** The daemon spawns the helper
  as a child of the *same build*; #1917 STOP→FLIP→START kills the helper before
  the new daemon starts. `session_sync.rs:108-115` already relies on this for
  the binary frame ("no record-version negotiation is required"). The JSON delta
  rides the same socket, so **adding fields needs no capability negotiation** —
  the serde(default)/omitempty discipline is belt-and-suspenders, not required
  for correctness. (See Section 10 for why this rebuts issue requirement #3.)
- **Units:** `app_timeout` is **seconds** on the wire (Go stamps
  `val.AppTimeout = delta.AppTimeout` with no conversion; the binary path
  divides ns→s). The JSON path must divide identically or the standby ages
  sessions 1e9× wrong.
- **NAT64 direction:** `nat64_snat_v4` is only meaningful on a v6-keyed
  (cross-family) session and is the *one* datum the standby cannot reconstruct
  from the synced forward key. Derive it from `decision.nat.rewrite_src` exactly
  as the binary path does; leave it empty otherwise.
- **Export re-emission fidelity:** the owner-RG export re-emits sessions from
  `SyncedSessionEntry` (`decision`+`metadata` retained). Confirm the re-emitted
  `SessionDelta` carries populated `metadata.policy_id` /
  `metadata.inactivity_timeout_ns` / `decision.nat.*` so the export path (not
  just the incremental path) benefits (Section 11, Q2).
- **Ordering / allocation:** construction stays on the existing drain path; no
  new hot-path allocation beyond the `nat64_snat_v4` string, which is only
  non-empty for NAT64 opens (same cost profile as the existing `nat_src_ip`
  string fields on the struct).

## 9. Risk assessment

| Class | Level | Notes |
|---|---|---|
| Behavioral regression | LOW | Purely additive fields; downstream already consumes them; no path currently reads a zero and depends on it. |
| Lifetime / borrow-checker | LOW | Values are copied out of `&delta`; one owned `String` for `nat64_snat_v4`. |
| Performance regression | LOW | One extra small `String` alloc only on NAT64 opens; other fields are `Copy`. Drain path is off the packet hot path. |
| Architectural mismatch | LOW–MED | Option B leaves two transports (accepted, guarded by golden test). If reviewers require structural unification, that is Option A and a larger change; the plan argues B+E is the right altitude. |

**Option E — golden parity test (ships with B):** add a Rust test asserting the
JSON `SessionDeltaInfo` serialized keys are a **superset** of the binary
open-frame's #3301/#4565 correctness fields (or a shared field-set constant that
both encoders reference), plus a Go round-trip test proving a JSON-decoded delta
stamps a `SessionValue` **byte-identical** (on PolicyID/PolicyCounterIdx/
AppTimeout/Nat64SnatV4) to a binary-decoded delta built from the same session.
This is the "fail-closed at build time" analog the issue asks for.

## 10. Mixed-version / capability negotiation analysis (issue requirement #3)

The issue frames this as a wire change "across a cluster that may run mixed
versions," invoking the #2239/#3931 lesson. **That lesson applies to the
node→node cluster wire, not to the helper→daemon JSON/binary transports.**

- **Helper→daemon (both transports):** same-host, same-version by construction
  (Section 8). There is no mixed-version scenario at matched versions; after the
  fix the fields are always present. A runtime capability handshake here would
  be machinery for a scenario that cannot occur. The correct "fail-closed"
  mechanism is the **build-time golden parity test** (Option E), i.e. a
  compile/test-time invariant per `docs/engineering-style.md`.
- **Node→node cluster wire:** already length-gated + `omitempty`
  (`sync_protocol.go:98-99`), already carries the five fields since #3301/#4565,
  and deliberately does **not** bump `SessionSyncWireVersion` for additive
  gated fields (`sync.go:21-36`). A pre-#3301 peer stops after the field it
  knows and treats absence as "unattributed / global timeout / not NAT64" — the
  same legitimate zero-value the code already tolerates. **No change and no new
  negotiation is required here.**

**Conclusion:** issue requirement #3 ("negotiate capabilities/version and fail
closed") is over-specified for the transport that carries the bug. The plan
satisfies its *intent* (never silently zero a required field) via Option B
(always populate) + Option E (build-time parity guard), and documents why a
runtime handshake is unnecessary. Reviewers who disagree should say which
concrete mixed-version scenario on the helper→daemon socket they believe is
reachable given the #1917 restart discipline.

## 11. Open questions for adversarial review (each invitable to PLAN-KILL)

1. **Steady-state vs. fallback-only (severity crux).** Does the 5 s reconcile
   drain (`daemon_ha_userspace_stream.go:289-311`) actually re-emit
   already-streamed deltas and cause `QueueSessionV4/V6` on the peer to
   **overwrite** a good binary-synced `SessionValue` with a zeroed one in steady
   state? Confirm the sender-side coalescing (last-write-wins by key) and the
   peer-side install replace-semantics (`SetClusterSyncedSessionV4`). If it
   does, the impact statement must escalate from "fallback-only" to
   "continuous." If some guard prevents it (e.g. `pending_session_deltas` is
   normally empty because the buffer is drained/dropped before 5 s, or the peer
   merges rather than replaces), the fix is still correct but the framing must
   soften.
2. **Export re-emission carries the metadata?** In the owner-RG export
   (`export_owner_rg_sessions` → worker re-emit → `drain_session_deltas_from_live`),
   does the re-emitted `SessionDelta` actually populate `metadata.policy_id` /
   `metadata.policy_counter_idx` / `metadata.inactivity_timeout_ns` and
   `decision.nat.nat64` / `decision.nat.rewrite_src` from the stored
   `SyncedSessionEntry`, or does the re-emit build a stripped delta? If stripped,
   Option B needs additional plumbing at the re-emit site and the "no other
   change" claim is wrong.
3. **Is Option B the right altitude, or is Option A mandatory?** Is a golden
   parity test (Option E) a sufficient structural guarantee against future
   drift, or do reviewers insist the two transports be generated from one schema
   (Option A) despite the 5-field, stable surface and divergent wire
   constraints?
4. **Should the fallback be removed instead (Option C)?** Is the JSON HA
   admission transport worth keeping at all, given the binary bulk-export path
   (#4054) exists? If reviewers prefer deletion, is a fail-closed
   "no-sync-while-stream-down" RPO regression acceptable, and does that belong in
   *this* issue or a follow-up?
5. **Units / NAT64 derivation parity.** Is `inactivity_timeout_ns → seconds`
   (saturating) and `nat64_snat_v4` from `decision.nat.rewrite_src` byte-for-byte
   what the binary path does? Any divergence silently corrupts aging or the
   reverse BIB. Should the conversion be factored into a shared helper so binary
   and JSON cannot diverge?
6. **PLAN-KILL check.** Is there any real deployment in which the JSON fallback
   is *never* taken (so this is dead code)? Section 5/Option D argues no
   (reconnect polling + FullResync export + no-event-stream DP all route through
   it). If a reviewer can show the fallback is unreachable in every supported
   configuration, PLAN-KILL is on the table.

## 12. Verification / smoke deferral

`make test-failover` (and the sibling HA smoke targets) are **blocked by the
loss-cluster shim-ABI wall** (pinned cpumap=16 vs. repo 256; verify-dataplane
fail-closes every cluster-deploy until a full reload crosses the bump). This
plan's confidence therefore rests on:

- **Golden binary↔JSON parity unit test** (Rust) — field-set superset / shared
  constant.
- **Go round-trip test** — a JSON-decoded `SessionDeltaInfo` stamps a
  `SessionValue` identical (on the five fields) to a binary-decoded one built
  from the same session; assert the fallback install is no longer degraded.
- **Design review** (this document).

When the shim-ABI wall clears, the `/engineer` implementation must run
`make test-failover` **forced onto the JSON fallback** (stream disconnected)
with: policy hit-counters, a custom per-application `inactivity-timeout`,
source + static NAT, a NAT64 flow, fabric forwarding, and both IPv4 and IPv6 —
asserting the promoted node preserves policy attribution, aging, and the NAT64
reverse path. This smoke is a **precondition of merge at `/engineer`**, recorded
here as a deferral, not a waiver.

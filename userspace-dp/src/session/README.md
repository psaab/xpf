# userspace-dp/src/session/

Userspace session table and timer-wheel garbage collector. Owned by the
coordinator; per-worker handles read and update under shared locks.

## Files

- `mod.rs` — `SessionTable`: slab-allocated `SessionEntry`s, three
  `FxHashMap`s indexing by canonical / forward / reverse key. Slab +
  integer-handle layout shipped in #964 Step 1.
- `key.rs` — `SessionKey`, `forward_wire_key` (ingress 5-tuple),
  `reverse_canonical_key` (post-NAT lookup), and
  `reply_matches_forward_session` (the predicate used to detect "this
  inbound packet matches an existing outbound flow").
- `entry.rs` — `SessionEntry`: decision, metadata, origin, timestamps,
  expiry tick, wheel bucket.
- `wheel.rs` — bucketed timer wheel (1 s per tick, 256 buckets). One
  sweep per second by the coordinator; lazy-delete on lookup picks up
  stragglers.
- `tests.rs` — co-located unit tests.

## Timeouts

| Class | Default |
|-------|---------|
| TCP   | 300 s |
| UDP   | 60 s |
| ICMP  | 60 s |
| TCP closing | 30 s |

Per-application overrides come from the typed config and land here as
per-entry `expires_after_ns`.

## GC

`SESSION_GC_INTERVAL_NS = 1_000_000_000` (1 s). Single-threaded sweep
walks the wheel bucket for the current tick; stale entries get
lazy-deleted on the next lookup if they slip past the sweep (e.g.
because they were re-bucketed mid-sweep).

## Why a slab + integer handles

Pre-#964 the table was `HashMap<Key, Arc<SessionEntry>>`. Reverse-NAT
and alias lookups now run 2.2–2.3× faster because integer handles are
cheap to compare and the slab layout fits more entries per cache line.
The owner-RG export path got a 2× regression on a rare HA codepath
that's documented in `project_964_step1_done.md` (memory).

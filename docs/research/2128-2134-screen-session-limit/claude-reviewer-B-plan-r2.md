# Hostile Claude plan reviewer B (hot-path + HA) — round 2 (against plan r2)

VERDICT: NEEDS-REVISION (one new MAJOR; all three r1 findings FIXED)

r1 findings status (all verified FIXED against worktree source):
1. r1 BLOCKER per-packet check — FIXED (relocation to :746 miss path;
   old check confirmed outside is_syn gate at screen/mod.rs:343-358).
2. r1 MAJOR demote decrement — FIXED. demote_owner_rg flips origin in
   place at install.rs:305; owner_rg_session_keys (lookup.rs:165-180)
   returns BOTH forward+reverse keys (index_forward_nat_key_parts adds
   any owner_rg_id>0 regardless of direction), so the !is_reverse count
   gate is load-bearing — plan §3.1 dec.2 specifies it.
3. r1 MAJOR promote increment + framing — FIXED. mod.rs:472; no
   double-count (is_promotable_synced = {SyncImport, SharedMaterialize};
   after promote origin=SharedPromote returns early at promote.rs:89).
   Promotions on the resolve path, not limit-checked.
4. r1 MAJOR unconditional OFF cost — FIXED. SessionTable has no
   Mutex/Arc; flag read locklessly; hook clean at setup.rs:122-124 +
   loop_body:318-320 (recomputed on every forwarding change).

NEW FINDINGS:
[MAJOR] Runtime OFF-transition leaves stale count maps — no
clear-on-disable. Removing limit-session at runtime flips
session_limit_active false, decrements stop, count maps FREEZE at stale
over-counted values; re-enable resumes from wrong values → spuriously
blocks an under-limit IP. Reachable by a routine config edit; the
existing ScreenState::update_profiles already enforces clear-discipline
(.retain). Change: clear both count maps on the ON→OFF transition; add a
test.

[MINOR] §3.5 audit not exhaustive — refresh_for_ha_transition
(mod.rs:546, called in-place from demote_owner_rgs.rs:68 +
refresh_owner_rgs.rs:74) omitted by name; benign (never assigns origin;
callers preserve direction) but must be enumerated to satisfy the
exhaustive bar. Same for shared_ops.rs:137/154/162 demote_shared flips
(shared maps, not SessionTable — never touch the counter).

[NIT] Increment placement: key/metadata are MOVED into the delta at
install.rs:160-169; capture src/dst (Copy) before the push.
[NIT] Demote decrement borrow ordering: snapshot Copy predicate inputs,
end the entry_by_key_mut borrow, then decrement.

Confirmed sound: increment-after-insert safety; bound 2×max_sessions;
NAT pre-NAT keying; take_synced_local/materialize route through
upsert_synced (uncounted); #2128 non-mutating read.

Fix the MAJOR (small, scoped) → PLAN-READY.

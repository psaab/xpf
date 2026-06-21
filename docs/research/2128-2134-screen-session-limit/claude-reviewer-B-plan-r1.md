# Hostile Claude plan reviewer B (hot-path + HA focus) — round 1 (against plan r1)

VERDICT: NEEDS-REVISION

Confirmed correct: #2134 no-op + #2128 leak; install choke-point
predicate byte-identical to the Open/Close-delta predicate; remove_entry
is the sole slab-delete sink; cancelled_keys RG-vacate is redirect-only
(no spurious decrement); NAT keys on pre-NAT tuple;
refresh_for_ha_transition never mutates origin; restore_entry dead in
prod; bound = 2×max_sessions (131072) evicted to empty.

Findings:

1. [MAJOR] Unconditional per-session-install cost when the feature is
   OFF. r1 gates increment/decrement only on the counted-class predicate,
   not on whether any zone configures limit-session. Today, unconfigured
   = zero session-limit cost. r1 would add 2 FxHashMap upserts to every
   install + 2 ops to every remove_entry for the ~99% of deployments with
   no limit-session — contradicting the #1357 codegen-sensitivity note
   kept at install.rs:106-112. Required: a "session-limit configured on
   any zone" flag, set at profile-update time, gating both increment and
   decrement; zero cost when false.

2. [MAJOR] §6.3 demote decrement must be concrete spec, not open
   question. CONFIRMED: demote_owner_rg (install.rs:295-310) flips
   entry.origin = SyncImport in place (line 305) without remove_entry;
   driven on every RG demotion. Leaks the count up → drops legitimate
   post-failover traffic. Required: decrement inside the existing
   `if !entry.origin.is_peer_synced()` guard, on the OLD origin before
   the assignment, keyed on key src/dst. Do NOT route demotion through
   remove+reinsert. Add a dedicated test (test-failover does NOT prove
   count integrity).

3. [MAJOR] §2.1 "single choke point" is wrong + promote increment must
   be specified. maybe_promote_synced_session → update_session in-place
   promote branch (mod.rs:472, new origin SharedPromote which is NOT
   is_peer_synced) creates a counted session off the install choke point.
   Required: increment in that branch; correct the framing to TWO
   increment + TWO decrement sites.

4. [MINOR] §6.3 audit incomplete — record the exhaustive in-place
   mutation checklist as closed, not an open reviewer question.

5. [MINOR] Mass-promotion post-failover semantics undocumented
   (promotion is packet-driven, not limit-checked; correct Junos
   behavior — document it).

6. [MINOR] test-failover does not verify count integrity; the
   differential/invariant test must drive promote/demote/take/refresh
   cycles.

7. [NIT] Stale file:line references (the #2005 split).
8. [NIT] Reverse-direction read semantics unanalyzed (one sentence).

Net: architecture correct and the core decrement-in-remove_entry /
increment-at-install survives every transition traced; fix findings 1-3
into concrete requirements and tighten 4-6, then PLAN-READY.

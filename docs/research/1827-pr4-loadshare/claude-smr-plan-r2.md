# Claude SMR hostile plan-review — #1827 PR-4 (weights/load-share), round 2

Reviewer: Claude (domain SMR). Subject: plan v2 (commit 7309e1391).
Posture: hostile re-verification of the v2 fold, with particular
suspicion of the rewritten §3.3 (the section that was materially wrong
in v1 — a second error there would invalidate the audit-of-record
claim).

## Re-verification of the v2 §3.3 rewrite

- `upsert_synced.rs:3-17` header comment + `:39-44`
  `lookup_forwarding_resolution_for_session(...)` + `:55-60`
  `entry.decision.resolution = re_resolved` — read in full this round;
  the receipt-time re-resolution claim is exact, including the
  "regardless of HA state — #326" scope and the standby behavior
  (skip HA enforcement, store ForwardCandidate).
- `session_glue/mod.rs:122-134` —
  `lookup_forwarding_resolution_for_synced_session` passes
  `allow_cached_fast_path = false`; packet-time lookup-first for
  peer-synced sessions confirmed. The NoRoute/MissingNeighbor branch
  falls BACK to the cached resolution (`mod.rs:114-117`) — i.e. a
  synced session whose local re-lookup fails keeps the owner's stale
  resolution rather than dropping. v2 does not mention this fallback;
  it does not change any conclusion (it is another determinism
  dependency, not a hash), but the §-of-record should not over-state
  "always lookup-first". MINOR — see F1.
- `manager_ha.go:744,1038-1061` Go-side normalization — confirmed; the
  receive path mirrors via the same `buildSessionSyncRequestV4` used at
  export, resolving against the LOCAL `m.lastSnapshot`.
- Cross-check of the strengthened-kill consequence: with re-resolution
  on receipt + on packet, a hypothetical hash runs on BOTH nodes for
  the same flow at different times with possibly different weight
  epochs (overlay actuations are per-node, primary-only publication per
  program plan §4.4). The transition-window invariant (v2 §7.3) is
  real and v1 missed it. Confirmed as stated.

## Re-verification of the other folds

- §3.1 narrowed negative + fabric_queue_hash scope
  (`worker/mod.rs:237-274`, `types/forwarding.rs:396-405` — modulo
  queue-count selection within one egress, not next-hop choice):
  accurate. Counter-example hunt now in the doc with the PBR
  table-override (`mod.rs:984-989` → `poll_descriptor/mod.rs:656-661`)
  and tunnel recursion (`mod.rs:1511-1527`): matches what I verified
  independently in r1.
- §3.2 additions (`types_routing.go:99-105`, `config_render.go:82-85`,
  `dataplane.go:391-397` StartFIBSync no-op,
  `ha-cluster-userspace.conf:231-233,259`): all verified r1/r2.
- §3.4.2 single-winner chain (`ipmon.go:351-358`,
  `types_system.go:339-359`, `routes.go:160-191`/`172-177`,
  `config_render.go:283-288`): verified.
- §5 close-out: docs amendment now mandatory with Codex-8's wording
  (kill by criteria, PR-1..3 complete the deliverables, parity
  load-balance unimplemented unless filed). Resolves SMR F5/Codex 8.
- §10: sort.Slice + divergence edges get one combined close-out note,
  no new issue unless triggered. Resolves SMR F6.
- SMR F3 (FRR weight knob unverified): now explicitly marked
  non-load-bearing and unverified. Resolved.
- SMR F4 steelman: consolidated in §2 with the four rebuttals. The
  strongest ship argument (asymmetric-capacity unclassifiable traffic)
  is now stated before it is rebutted. Resolved.

## Findings

**F1 (LOW).** §3.3 item 3 says packet-time resolution for synced
sessions is "lookup-first" but omits the NoRoute/MissingNeighbor
fallback to the cached (owner-derived) resolution
(`session_glue/mod.rs:114-117` via
`lookup_forwarding_resolution_for_session_with_cache`). One sentence
fixes the over-statement. Does not affect any conclusion or the kill.

**F2 (NIT).** §3.3 cites `protocol/control.rs:512-525` for the carried
fields; the span includes `neighbor_mac`/`src_mac` at `:521-525` —
fine — but the prose could note these carried values now serve as
fallback/bootstrap only (per F1 fallback), which is the accurate role
after the rewrite.

## On the kill

With §3.3 corrected, every leg of the kill rests on evidence verified
by at least two reviewers independently: (1) no dp ECMP selection —
triple-verified; (2) any load-share = new Rust hot-path program +
wire change + new HA invariants — §3.4.3/§7, now including the
transition-window invariant; (3) thin value at 2 uplinks — §2 steelman
+ §3.5 pinning + #840 precedent; (4) no Junos analog for weights. The
stage's own kill criteria are met in their strongest form. The
disposition (close #1827 completed-by-PR-1..3, mandatory docs
amendment, plan-kill label, edges recorded not absorbed) is complete
and honest.

## Verdict

**PLAN-READY** — endorsing Path D (PLAN-KILL the PR-4 stage, close
#1827 as completed by PR-1..3) with F1 folded as a one-sentence v2.1
edit (F2 optional). No structural findings remain.

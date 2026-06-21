# Claude SMR — hostile plan review, round 1 (against plan r1)

VERDICT: NEEDS-REVISION (concur with reviewers A + B; I add two
placement findings they under-explored)

I independently verified the two reviewers' BLOCKER/MAJOR findings
against the worktree base (8260727af) and they hold. I do NOT soft-pass:
r1 had a genuine functional showstopper (per-packet self-drop) and an
incorrect central thesis (single choke point). Beyond confirming theirs,
two additional findings:

## SMR-1 [MAJOR] The new-flow check must precede BOTH counted forward
install sites, not just the primary ForwardFlow.
There are two COUNTED forward installs on the session-miss slow path:
`SessionOrigin::ForwardFlow` (`poll_descriptor/mod.rs:1375`) AND
`SessionOrigin::LocalMiss` (`:907`, host-inbound local delivery). Both
satisfy the counted-class predicate, so both increment. The relocated
new-flow check (§3.2) must be positioned so it gates the path leading to
BOTH — not only the ForwardCandidate/forward-flow branch. The
ReverseFlow installs (`:1577`, `:536` cluster-peer-return fast path) and
the MissingNeighborSeed seed (`:2813`) are correctly NOT counted
(`is_reverse` / `is_transient_local_seed`), so they need neither check
nor count — but the implementer must verify the check is not accidentally
placed only on the ForwardFlow arm, leaving LocalMiss uncounted-but-also-
unchecked-against-the-limit. r2 §3.2 says "session-MISS path around
:746+" which is upstream of both — confirm at /engineer time the single
check site dominates both 907 and 1375. (Junos: source-ip-based
limit-session applies to host-inbound too; counting LocalMiss is
correct.)

## SMR-2 [MINOR] All-protocol coverage is a feature, not a bug — but
state it. Relocating the check to the session-miss install path (rather
than gating on `is_syn` like port_scan) means the limit correctly applies
to UDP and ICMP sessions, not just TCP — matching Junos (limit-session is
protocol-agnostic). This is BETTER than the obvious "just add an is_syn
gate" fix some reviewers might propose. r2 should state explicitly that
the new-flow check is reached for all protocols (verified: the
session-miss install region at :746+ is not TCP-gated; it keys on
`flow.forward_key.protocol` generically). A naive is_syn gate would
silently exempt UDP/ICMP floods from the limit.

## Confirmations (verified, no soft-pass)
- Profile reachability in the miss path: the per-zone screen profile is
  directly readable via `worker_ctx.forwarding.screen_profiles`
  (`types/forwarding.rs:70`, a `FastMap<String,ScreenProfile>`), so the
  new-flow check needs no new plumbing into ScreenState — RESOLVED
  reviewer-A's borrow concern entirely.
- demote_owner_rg in-place flip (`install.rs:305`) + update_session
  promote branch (`mod.rs:472`) are the ONLY two in-place counted-class
  transitions; remove_entry (`mod.rs:645`) is the sole slab-delete sink
  (the other `entries.remove` at `mod.rs:894` is the owner-RG index
  helper, not a session removal). Audit §3.5 is exhaustive as far as I
  can trace.
- The OFF-gate (reviewer B-1) is necessary and the #1357 codegen note at
  install.rs:106-112 makes it non-negotiable for a hot-path change.
- The per-packet self-drop (reviewer A-1) is real: the session-limit
  sub-check at screen/mod.rs:343-358 is OUTSIDE the is_syn block and
  stage_screen_check runs before the lookup — verified.

## Verdict
r1 → NEEDS-REVISION. The architecture (Path B) is correct; the mechanism
needed the three fixes (check-at-new-flow, two enumerated HA transitions,
OFF-gate) plus the two placement notes above. r2 should fold all of these
and re-cite against the worktree. I will re-review r2 hostilely.

# Claude SMR plan-review — #1760 stage-2, round 1 (v1 @ 10493704f)

**Verdict: PLAN-NEEDS-MAJOR** — on §7 (HA divergence), not on the core
diagnosis. The §2 architectural finding is correct and well-grounded; the
fix mechanism (Path A install-time refusal) is the right family. But the
plan ships a session-install behavior change on a 2-node HA cluster with
the divergence risk only *named*, not *designed out* — and per project
rule, anything touching session-sync/failover must be proven on
`make test-failover` before it's PLAN-READY. As written, Path A could
trade a silent latent bug for a loud split-brain.

## Validated (held up under hostile self-review)

- **§2 is airtight for the lookup that matters.** `find_forward_nat_match`
  (`mod.rs:613`) keys on `nat_reverse_index`, whose key is
  `reverse_wire_key` — the full 6-field reply tuple. Two sessions sharing
  it also share `reverse_canonical_key` (same inputs → same output; they
  differ only in ICMP-identifier *position*, and two ICMP flows with
  different identifiers don't collide in the first place). So there is no
  fourth field hiding in the alias keys that a multi-valued index could
  exploit. **Path C rejection stands.** (Reviewers should still independently
  check NAT64's addr_family flip — I believe it's covariant with the rest
  of the tuple, but it's the one place worth a second set of eyes.)
- **Path A generalizes a proven mechanism.** Pool-mode's
  `owner_by_translated` (`allocator.rs:461`) is exactly install-time
  refusal of a duplicate external identity; extending that posture to the
  portless modes is architecturally consistent, not novel.
- **Disposition (drop trigger SYN) is defensible** — it's the same as
  port-exhaustion in any NAPT: the flow fails to establish rather than
  corrupting a peer.

## MAJOR — §7 HA divergence is under-designed for a shipping change

The plan's own §7 marks this HIGH and §10-Q2 leaves it open. That's not
good enough to be PLAN-READY. The failure is concrete: node A owns RG0,
installs S1, the session-sync to node B is in flight; B (processing its own
traffic or a failover-transition packet) installs S2 whose `K` collides;
B's incumbent check does not yet see S1 → **A refuses S2, B admits S2** →
the two nodes' session tables permanently disagree on S2, and on failover
the survivor serves a table the peer never had.

Today's silent corruption is symmetric (both nodes corrupt the same way
because both run the same last-writer-wins arbitration on the same synced
stream). **Refusal is asymmetric** — it depends on local timing of who saw
the incumbent first — which is precisely what creates divergence. A fix
that is correct standalone but divergent under HA is a regression on the
property the cluster cares most about.

**Required before PLAN-READY:** make the decision deterministic across
peers. The candidate is **owner-RG-gating**: only the RG *owner* evaluates
the refuse/admit guard; the backup never independently installs a
NAT-forward session — it applies the owner's synced decision verbatim. For
that to hold the plan must show (against `afxdp/ha.rs` + `pkg/cluster`):
1. the backup truly only replays synced sessions for owned RGs (no
   independent dataplane install that could race),
2. the refuse outcome is either (a) never synced (S2 simply never exists,
   so nothing to diverge) or (b) synced as an explicit negative so replay
   is identical, and
3. during the bulk-sync hold / failover transition window, the guard is
   suppressed or owner-gated so a transitioning node doesn't refuse against
   a half-populated table.

Until that's written and `make test-failover` (with collision injection
across the failover) is in the test plan as a *gating* check, this is
PLAN-NEEDS-MAJOR.

## MEDIUM — incumbent-liveness false-refusal surface

`is_live = entries.get(h) && !is_expired(now)` may be too coarse. A
`peer_synced` or `closing` (FIN/RST-seen) incumbent is still "present and
unexpired" but its `K` may be effectively reclaimable — refusing a fresh
flow against a closing incumbent would drop a legitimate new connection
that reuses the just-freed tuple (the classic TIME_WAIT-reuse case).
The guard should treat `closing` / half-open / peer-synced-but-unconfirmed
incumbents as *displaceable*, not as blockers. Specify the exact predicate.

## MINOR — justification at 0 incidence

The operator chose to build despite 0 live collisions; that's their call
and I won't relitigate it. But the review consequence is that the bar for
the HA-safety proof is *higher*, not lower: we're accepting non-trivial
cluster risk to harden a bug nobody has observed, so the divergence design
must be airtight before code. If the HA design can't be made deterministic,
the honest outcome is PLAN-KILL (keep the #1762 counter watching, document
the latent bug) rather than shipping a cluster-destabilizing refusal.

## Recommendation

PLAN-NEEDS-MAJOR. Keep §2 and Path A. Before round 2: (1) concretize the
owner-RG-gated, replay-deterministic HA design in §5/§7 with code
references proving the backup never races an install; (2) tighten the
incumbent-liveness predicate to displace closing/half-open/peer-synced
incumbents; (3) elevate `make test-failover` with collision-across-failover
to a gating criterion in §8. If the HA determinism can't be shown, switch
the recommendation to PLAN-KILL.

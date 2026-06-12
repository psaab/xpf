# Claude SMR hostile plan review — #1884 r1 (plan v1, 4b9456c04)

Verdict: **PLAN-NEEDS-REVISION** — Path A is the right shape (B and C
fail the restart-adoption contract for the reasons the plan gives), but
two findings must be folded before implementation.

## SMR1-1 (MAJOR) — removal diff computed from the SUCCESS set leaks live links

A.1 computes deletions from `t.tunnels`, which the apply loop populates
only on per-tunnel SUCCESS (`t.tunnels = append(...)` at tunnel.go:190
and :301; every failure path `continue`s before it). Under the CURRENT
destructive code this cannot leak: the pre-loop delete
(tunnel.go:113-121) removes any existing link by NAME before each
attempt, so a failed apply leaves no link behind. Under Path A the
reuse branches have failure modes that leave a LIVE kernel link
untracked:

- A.3: existing non-TUN, `LinkDel` fails → warn + continue → old link
  alive, untracked.
- A.3: reuse path, then a later step fails in a way that `continue`s
  (plan sketch warns+continues on LinkAdd failure after a successful
  delete of a stale link — but also any future edit that adds a
  failure-continue after reuse) → reused link alive, untracked.
- A.6 legacy: invalid endpoints (tunnel.go:196-200) `continue` — under
  reuse-first, the PREVIOUS apply's link with the old attrs stays
  alive, untracked if this apply fails validation.

Then the tunnel is removed from config: A.1 iterates `t.tunnels`, the
name is absent, the link leaks forever (and keeps its addresses +
routes). Worked trace: apply N creates gr-0-0-0 (tracked); apply N+1
hits a transient `LinkDel`/netlink error → continue → untracked; apply
N+2 removes the tunnel from config → no deletion → orphaned TUN anchor
with stale addresses attracting traffic.

**Required revision:** compute the removal diff from the previous
DESIRED ownership set, not the success set. Keep `t.tunnels` as-is for
`GetStatus`, and add `t.ownedNames map[string]bool` = all non-WG names
from the LAST Apply (recorded unconditionally at entry, before the
loop). A.1 deletes `ownedNames \ desired`. Restart bootstrap: empty
ownedNames ⇒ deletes nothing, same adoption semantics.

## SMR1-2 (MAJOR) — A.7 overstates keepalive scope: anchors never had keepalives

The anchor branch `continue`s at tunnel.go:191, BEFORE the keepalive
start at tunnel.go:304 — keepalive probes exist ONLY on the legacy
non-anchor branch today. A.7 as written ("in the apply loop ...
(re)start via existing startKeepalive") reads as applying to all
branches; an implementer following it would silently ADD keepalive
probes (with LinkSetDown side effects on the anchor!) to the production
userspace path — a behavior change outside the issue's scope. Fold an
explicit scope sentence into A.7: keepalive reconcile applies to the
legacy branch only, preserving today's anchor-branch behavior (no
probes); A.1's removed-tunnel keepalive stop remains correct for both
(stop of a nonexistent runner is a no-op).

## SMR1-3 (MINOR) — bound the EEXIST retry explicitly

A.3's "one retry through the same lookup" must be spelled as: lookup →
(non-TUN ⇒ del) → add → on EEXIST do exactly ONE re-lookup, reuse if
TUN, else warn + continue. An unbounded loop is a hostile-race spin; the
#1706 `hiddenUntil` tests must be re-pointed at the new shape and must
still pass (Q5: the collapse is equivalent PROVIDED the re-lookup
operates on the kernel-fetched link — same invariant, simpler control
flow; the `goto` was only ever jumping over the create).

## SMR1-4 (MINOR) — reuse should require NonPersist == false

Kernel readback reconstructs persist state (netlink v1.3.1
parseTuntapData, IFLA_TUN_PERSIST). A non-persistent TUN with the
anchor's name (held alive only by some foreign fd) would pass the
Mode==TUN reuse check and then evaporate when that fd closes. The check
is one field; recreate on `NonPersist == true`.

## SMR1-5 (INFO) — legacy comparison normalization (answers Q4)

Both `gre` and `ip6gre` deserialize to `*Gretun` (netlink v1.3.1
link_linux.go:2130-2133) with `Type()` derived from `Local.To4()`
(link.go:1280-1285); `ipip`→`*Iptun`, `ip6tnl`→`*Ip6tnl`. So the
comparison is: concrete-type assert + `Type()` string equal (catches
v4↔v6 flips) + `net.IP.Equal(Local/Remote)` + defaulted TTL + IKey/OKey.
Do NOT compare encaplimit or flags — the post-create `ip ... encaplimit
none` exec (tunnel.go:259-269) mutates the device, and comparing it
would re-flap every ip6gre tunnel each commit (exactly the bug class
under repair). Pin IKey/OKey byte-order round-trip in a unit test.

## Answers to remaining open questions

- **Q1**: no caller relies on Apply-as-reset. `ClearTunnels` has zero
  callers (routing.go:148 wrapper only); `Close` uses `stopAll`
  (keepalives only). No PLAN-KILL trigger.
- **Q2**: safe for tunnel anchors — the daemon is the only writer of
  tunnel-link masters (networkd excludes daemon tunnel interfaces from
  unmanaged management), and the recreate it replaces also cleared the
  master. Unconditional unbind-on-empty-RI is the faithful translation.
- **Q3**: ~~keep LinkSetUp unconditional on reuse~~ **RETRACTED after
  AGY r1 cross-check** — my original answer claimed the retained runner
  "converges to the same steady state (re-marked down after
  MaxRetries)". That is false: `keepaliveLoop`'s down-transition guard
  is `if state.Up && state.Failures >= state.MaxRetries`
  (tunnel.go:587) — with a RETAINED runner `state.Up` is already false,
  so after Apply's unconditional `LinkSetUp` the link is stranded admin
  UP forever while probes keep failing. Today's clear-all masked this
  by resetting `state.Up = true` on every restart. Correct fix (AGY
  r1): on the legacy branch, skip `LinkSetUp` when a retained runner
  exists with `state.Up == false`. (Anchor branch unaffected —
  keepalives are legacy-only, SMR1-2.)
- **Q6**: Mode==TUN + NonPersist==false (SMR1-4) is sufficient; NO_PI
  matches between anchor and WG creations and ONE_QUEUE is an obsolete
  no-op the kernel doesn't report — a flags comparison buys nothing
  real.
- **Q7**: accept as documented residual; do NOT force MTU (no config
  field to express intent; clobbers operator-set MTU). The wg→gre
  same-name flip also requires the operator to have rewired the
  dataplane config anyway.

## What I could not break

- Set-diff + reuse-in-place vs FRR/route stability: reuse preserves
  ifindex, so kernel routes and FRR interface state survive untouched —
  the precise repro contract.
- Lock story: all new logic stays under `t.mu`; keepalive stop+drain
  reuses the #848 pattern verbatim.
- Cross-side: anchor delete remains the only Rust-visible signal; rare
  legitimate recreates ride #1881/#1887's tombstone→respawn.

# Claude SMR — hostile plan review r1 (#3611)

Reviewing `docs/research/3611-junos-host-self-zone/plan.md` against origin/master
`c18664f1b`. Posture: HOSTILE. The job is to break the plan's disposition, not
to bless it.

## Verdict: PLAN-DEFER (converges with the plan) — with two required sharpenings

I independently re-verified every load-bearing claim against source. The
enforceability finding is CORRECT and the DEFER disposition is defensible. But I
tried hard to push this to PLAN-KILL, and the reason it does NOT kill is narrow
and worth stating precisely so the user can overrule it.

## What I verified (not taking the plan's word)

1. **from-zone junos-host is genuinely indexed-but-inert.** `policy.rs:2880-2938`
   (`evaluate_junos_host_policy_l3_aware`) consults ONLY `zone_pair_index[(from_id,
   JUNOS_HOST_ZONE_ID)]` (to-zone junos-host) and `from_any_index[JUNOS_HOST_ZONE_ID]`
   (from-zone any → junos-host). It never keys `(JUNOS_HOST_ZONE_ID, to_id)`. The
   doc comment at 2835-2838 admits it. CONFIRMED H01.
2. **The premise is TRUE (unlike #3620).** XDP is an RX-only hook; there is no
   kernel XDP egress hook for locally-generated frames, and the TC egress path
   was retired (#1476). Host sockets (resolved/chrony/apt/strongSwan/HA-heartbeat/
   VRRP/gRPC-return) emit via the kernel TX path, never the XSK. The userspace
   dataplane structurally cannot see host-originated egress. CONFIRMED: not
   enforceable in userspace-dp.
3. **A real kernel mechanism exists.** `daemon_nft.go` already renders `hook
   input` base chains (`xpf_lo0` pri 0, `xpf_hostinbound` pri 10) with per-zone
   address/interface views, named DROP counters → Prometheus, atomic apply, and
   a lifeline exemption. A `hook output` mirror is the natural home for
   from-zone junos-host. CONFIRMED the mechanism is real and reuses existing
   plumbing (though `hook output` itself is genuinely new — no output/postrouting/
   forward chain exists anywhere in `pkg/`).
4. **M03 has two genuinely different halves.** Globals set `is_global` and go to
   `global_indices` (`policy.rs:2249-2250`), which the host gate never consults —
   so a `to-zone junos-host` global would indeed be inert if the reject were
   lifted without also indexing it. But the to-zone-junos-host direction DOES
   traverse LocalDelivery, so indexing global-scoped junos-host rules into the
   host gate is a bounded, low-risk userspace change. CONFIRMED the Piece B split.

## Why I could not push this to PLAN-KILL

The task framing invites KILL ("like #3620, may be not-applicable"). Three facts
block a clean KILL:

- **A real mechanism exists** (nft output chain), so "not applicable to this
  architecture" is false — it IS applicable, just in the kernel not the dataplane.
- **Junos genuinely enforces this direction** — it's a true parity gap, not a
  misread of SRX behavior (which is what killed #3620).
- **M03's to-zone-global half is cleanly userspace-enforceable and low-risk** — a
  blanket KILL would wrongly close a buildable, safe improvement.

A blanket KILL therefore over-closes. DEFER (design captured, build gated on
risk/demand) is the honest disposition.

## The strongest KILL argument (must be answered, now folded into the plan)

The single best reason NOT to build H01 is the **partial-fidelity footgun**: nft
cannot express the app catalog (multi-term/ALG apps). A `from-zone junos-host ...
then deny application <alg-app>` rendered to nft would silently enforce a LOOSER
rule (or none), giving the operator a false sense of security — exactly the
"security feature that silently does nothing" the issue warns about. I required
the plan to convert this into a **fail-closed commit gate** (§7 new invariant):
if Piece A is ever built, any from-zone junos-host rule whose application term
nft cannot represent MUST be rejected at commit, never silently loosened. With
that guard the footgun becomes a commit error, not a silent hole — which is what
keeps DEFER (rather than KILL) tenable. If the user judges the representable
subset (l4proto+ports+addr, no apps) too narrow to be honestly useful, KILL-
document-only is the correct overrule and I would not argue against it.

## Required sharpenings (both now in the plan)

1. **Fidelity fail-closed invariant** — DONE (§7). Non-negotiable if Piece A ships.
2. **Recommend the M03 to-zone-global slice as the near-term buildable unit** —
   the plan already isolates it in §5 Piece B and §11 Q5. I endorse splitting it
   into its own small issue: it needs no kernel work, no split-enforcement, and
   removes a real management-plane hole (operators duplicating per-zone pairs).

## Residual concerns (verify items for /engineer, not plan blockers)

- **OUTPUT-hook `oifname` reliability** (§8 / §11 Q2): must be confirmed that oif
  is populated for connected/routed/VRF(l3mdev)/reroute egress classes before
  committing to the output hook vs postrouting (postrouting loses `reject`
  toward the local socket). This is a real correctness unknown — flagged, not
  resolved. Correctly left for implementation-time verification.
- **Split-enforcement maintenance tax** (§8 Architectural mismatch, MED): to-zone
  in userspace-dp, from-zone in kernel nft is a genuine two-engine burden. Not a
  dead-end, but a standing cross-engine parity-test cost. Acceptable given the
  alternative (moving to-zone to nft too) would regress the richer userspace
  fidelity that already ships.
- **Lifeline sufficiency** (§11 Q4): the plan mandates lifeline-oifname-accept
  FIRST + ESP/AH + ICMP ND/PMTUD exemptions + policy-accept/no-catch-all. I agree
  this is necessary; whether it is SUFFICIENT (DNS/NTP the box itself depends on,
  rescue-path updates) is the dominant self-DoS risk and MUST be a live
  `make test-failover` + lifeline-regression gate at /engineer time.

## Anti-soft-pass check

Per the SMR soft-pass history, I re-examined whether I am rubber-stamping. I am
not: I attempted KILL, found the three specific blockers above, and forced one
new hard invariant (fidelity fail-closed) into the plan before converging. The
DEFER verdict is the outcome of a failed KILL attempt, not a default.

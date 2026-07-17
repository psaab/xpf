# Claude SMR — hostile plan review r1 (#5837)

**Verdict: REVISE.** The central finding is sound and correctly overturns the
issue's "just add a dnat_lookup" framing, but three substantive gaps must close
before PLAN-READY. I am deliberately not soft-passing.

## What the plan gets right (verified against code)
- **Central finding confirmed.** In the userspace-dp path the shim-visible
  `dnat_table` holds only dynamic flags=0 reverse-NAT entries; configured forward
  DNAT is not there. `pkg/dataplane/loader.go:407-408` — `SetDNATEntry` is a
  literal `return nil` no-op; `userspace-dp/README.md:177` — "STATIC DNAT-config
  entries (flags=1) are never published." So a bare shim lookup finds nothing; the
  publication step is genuinely required. This is the plan's load-bearing insight
  and it is correct.
- **Byte-order/key contract already aligned** (`compiler_nat.go:872-895`,
  `maps_helpers.go:8-30`, `lib.rs:861-902`). Good.
- **Option C/D rejections are correct** — C is not port-aware (kills SSH:22 next to
  DNAT:443); D breaks Junos parity (port-forward to interface addr is standard).

## Blocking gaps

### B1 — Unverified: does the helper's XSK pipeline apply DNAT *before* its own
local-delivery decision? (severity: HIGH — could make the fix inert)
The plan asserts "the helper's translation path needs no change" because
non-interface-address DNAT already works. But the bug is specifically **dst ==
interface address**. If the helper's XSK ingress pipeline has its OWN
"is-this-local / host-inbound" short-circuit (the #4539 LocalDelivery path) that
runs *before* `destination.rs` DNAT, then even after the shim correctly redirects
the first packet to XSK, the helper could locally-deliver it and reproduce the
bypass one layer down. `userspace-dp/src/afxdp/README.md:186` explicitly mentions
"late-stage static-NAT-external and DNAT-destination local-delivery" handling —
which suggests ordering matters and may already be correct, but the plan must
**prove** the helper does DNAT-match-before-local for dst==interface-addr, or the
whole shim change is necessary-but-not-sufficient. Add a section confirming the
helper's XSK stage order and, if it also short-circuits local first, scope the
helper fix in.

### B2 — ICMP echo-reply capture hazard (severity: MED — correctness regression)
The plan orders `dnat_intent_matches` *before* `is_icmp_to_interface_nat_local`.
That existing check deliberately passes ICMP **echo-reply (type 0 / 129)** to the
kernel so the kernel can match replies to a firewall-originated `ping` process
(lib.rs:1382-1404). If a DNAT/static rule exists on the interface address and its
intent entry is proto-wildcard or ICMP-scoped, the new intent check could steal an
inbound echo-reply from the kernel and hand it to XSK — breaking locally-originated
ping on that address. The plan's shim snippet uses `parsed.flow_dst_port`
generically; for ICMP the dnat key convention is the **identifier in src_port**
(see GRE path, lib.rs:830-835). Resolve: the intent check must be scoped so it
cannot capture echo-replies for firewall-originated flows, and the ICMP intent key
must use the same identifier convention as the publisher. Spell this out.

### B3 — Verifier framing is too optimistic (severity: MED — honesty/scoping)
The plan says Phase-1 exact-only is "plausibly affordable" *because the GRE branch
already carries an exact v4+v6 dnat lookup.* That reasoning is weak: the GRE branch
existing under budget only proves the *current* total is <1M — it says nothing about
remaining headroom. The v6-wildcard precedent (`lib.rs:882-891`) shows ONE extra
HASH lookup already pushed the program over the cap in a sibling classifier, i.e.
the program is demonstrably close to the edge. The plan should demote "plausibly
affordable" to "UNKNOWN until measured" and promote the **tail-call restructure**
from a footnote fallback to a co-equal Phase-1 possibility, with an explicit
decision gate: run `make generate`/`shimverify` on exact-only FIRST; if REJECT,
the restructure (or v4-exact-only scope reduction) is the plan, not an afterthought.

## Non-blocking nits
- **N1 — Soften the A-Go rejection.** The "two writers = race" concern is weaker than
  stated: Go writes flags=1 (config-time), helper writes flags=0 (session-time) —
  disjoint keys, and BPF hash updates to distinct keys are per-bucket safe. The real
  A-Go cost is *ownership clarity*, not data races, and A-Go **reuses the already-correct
  `compiler_nat.go` machinery** (less new code than a new helper reconcile). Present it
  as a genuine tradeoff, not a near-dismissal.
- **N2 — Source-scoped over-steering** relies on the helper's local-delivery for the
  non-matching-source case; note that reliance explicitly (ties to B1).
- **N3 — Map capacity:** static intent shares `dnat_table` (max=MAX_SESSIONS). Config
  rule count is tiny, but state the bound and that intent entries must not count against
  session headroom in any alarm/metric.

## Bottom line
The architecture is right and the issue's suggested fix is correctly diagnosed as
incomplete. But B1 (is the fix even sufficient without a helper-side ordering
guarantee?) is a potential inert-fix hole, B2 is a concrete local-delivery regression,
and B3 is a scoping-honesty fix. Close these three and this is PLAN-READY. Do not
merge-to-implement on the current draft.

---

## Post-review self-verification (folds into r2)

**B1 RESOLVED FAVORABLY.** Traced the helper cold path
(`userspace-dp/src/afxdp/poll_descriptor/mod.rs`): DNAT/static-DNAT is matched as
`pre_routing_dnat` (:1577-1601), the destination is rewritten to the internal host
in `effective_resolution_target` (:1673-1685), and `resolve_forwarding` (:3633) runs
on THAT translated target — so LocalDelivery is decided on the internal dst, not the
interface address. Policy is evaluated on the post-translation tuple (#2345 comment
:1685+). Conclusion: once the shim steers the first packet to XSK, the helper already
does DNAT-before-local-resolution. The fix is SUFFICIENT with no helper translation
change — B1 is not a blocker. r2 plan will add a §4a stating this with the line cites.

**B2 DOWNGRADED to design-clarification.** `compiler_nat.go:866-872` publishes DNAT
intent only for TCP/UDP (port-based → TCP; port-less → TCP+UDP); it does NOT emit
ICMP DNAT intent. So an inbound echo-reply cannot be captured by ordinary DNAT
intent. The only ICMP-capturing case is static-1:1 on the interface address, where
stealing all traffic (incl. ICMP) to the internal host is correct-per-config. r2:
require the intent publisher to preserve `is_icmp_to_interface_nat_local` echo-reply
handling for NON-translated addresses, and only emit ICMP intent where an ICMP-bearing
translation is actually configured. Not a blocker.

**B3 STANDS.** Verifier framing must be demoted to "UNKNOWN until measured"; tail-call
restructure promoted to a co-equal Phase-1 path with an explicit shimverify decision
gate. r2 will revise §2/§5/§9 accordingly.

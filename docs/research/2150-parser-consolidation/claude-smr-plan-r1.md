# Claude SMR — hostile self-review of the #2150 plan (round 1)

Reviewer stance: assume the plan is wrong until each claim survives the
source. Goal: either break the PLAN-READY verdict or harden it. Base
`ef8dbb266`.

## Verdict: PLAN-READY stands, as a REFACTOR + latent-correctness fix (not a live bug, not a PLAN-KILL). Five findings, all folded into the plan; none change the disposition.

---

### F1 (CRITICAL claim to break): "ARP/NDP never reach userspace" — is the steering proof actually airtight?

Attempted refutation: maybe a degraded/fallback path, cpumap-unavailable
path, or a raw AF_PACKET receive feeds ARP/NA into the XSK after all.

Verification:
- `pass_non_ip_l2_direct()` is hard `XDP_PASS` (lib.rs:941-946) — no
  cpumap, no XSK. Reached for every non-IP ethertype incl. ARP and the
  inner-TPID tail of a QinQ double tag (dispatch `_` arm, lib.rs:376).
- NDP types 133-137 are diverted on BOTH normal (lib.rs:537-539,
  `pass_local_control`) and degraded (lib.rs:964-965,
  `is_degraded_local_or_control`) paths. `pass_local_control` →
  `cpumap_or_pass` → kernel, never the XSK redirect (which only happens
  after lib.rs:626 `bpf_xdp_adjust_meta`, well below those returns).
- The only feeder of `poll_binding_process_descriptor` is the XSK rx ring
  (`poll_descriptor/mod.rs:172 binding.xsk.rx.receive`). `neighbor.rs` AF_PACKET
  is TX-only (probes), confirmed grep — it does not push into the XSK.

Result: the proof holds. **The issue's stated live mechanism (learning
fails while forwarding succeeds on the same wire frame) is REFUTED.** The
plan already says this in §3 and §11 — good. This is the single most
important thing to get on the record so a future reader doesn't "fix a
blackhole" that can't occur.

Residual doubt I could NOT close from code alone: whether any *non-shim*
ingress (e.g. an xdpgeneric fabric interface, or a future HA neighbor-sync
that injects learned frames) could route an ARP/NA into the pipeline. The
fabric path (`ingress_is_fabric`) still arrives via the XSK and still
carries IP frames (zone-encoded), not raw ARP. I found no injector. The
plan's §3 caveat ("becomes live the instant a steering change springs it")
correctly hedges this. ACCEPT.

### F2 (correctness): Is `parse_eth_offsets` really only used by learning?

`grep parse_eth_offsets` → only `classify_arp` (parser.rs:81) and
`parse_ndp_neighbor_advert` (parser.rs:131), both called only from
`poll_stages.rs:78/100`. Forwarding/screen/NAT use `meta.l3_offset` +
`frame_l3_offset`/`ethernet_l3`. So fixing `parse_eth_offsets` for 0x88a8
has ZERO forwarding-hot-path blast radius. The plan's "Option A is
low-risk, no forwarding delta" is correct. CONFIRMED.

### F3 (correctness): the bound-6-vs-8 decision could itself be a regression

Verified the walkers genuinely split: `frame/inspect.rs` uses `0..6`
(four sites), `screen/extract.rs` uses `0..8`, `icmp_embed/parse.rs` uses
`0..6`. The plan's §8 "standardize to 8" decision is the right default
(matches BPF MAX_EXT_HDRS / screen), BUT it is a *behavior change for the
forwarding/GRE walker*: a frame with 7-8 ext headers that the 6-bound
walker terminated early (returning `Some(offset)` pointing into the chain,
NOT at real L4) would now walk to the real L4. That changes the parsed L4
offset → could change session keying / NAT for such (pathological,
adversarial) frames.

This is a genuine hole in the plan's claim of "behavior-preserving". HARDEN:
the canary in PR-1 must include a 7-header and 8-header IPv6 chain and the
plan must explicitly accept-or-reject the bound change with a test. Safer
conservative default: **keep each caller's existing bound as a parameter to
`walk_ipv6_ext`** (forwarding=6, screen=8, embed=6) so the unification is
*provably* byte-identical, and file standardizing-the-bound as a separate
follow-up. I am updating the recommendation: PR-2 should PRESERVE per-caller
bounds (parameterized) rather than standardize, to keep "behavior-
preserving" literally true. Standardization → separate issue. (Plan §8
already lists "keep per-caller bounds as a parameter" as the fallback;
promote it to the DEFAULT.)

### F4 (scope): is pulling QinQ-double into the userspace parser justified, or scope-creep?

The userspace parser adding double-tag unwinding has NO reachable effect
(shim drops double-tags at lib.rs:1091-1099 single-`if` + `_` arm →
XDP_PASS). So it is pure latent/forward-looking. Argument FOR: it makes the
canary's "all parsers agree on every L2 shape" total, and removes the
"L2-c rejects QinQ / others don't" inconsistency. Argument AGAINST: it adds
parser surface for a shape the system can't actually forward → dead code
risk + a reviewer will (correctly) ask "why parse what we drop?".

Resolution: this is genuinely optional. The plan should make QinQ-double
unwinding an EXPLICIT toggle in PR-2, defaulted OFF unless the team wants
the canary to be total. Recommendation downgraded from "add it" to "offer
it; default to *resolving the disagreement on SINGLE 0x88a8 only*, and have
the canary assert all parsers either AGREE on the double-tag l3 OR uniformly
reject it" — uniform rejection is also a valid "agreement". Updating §6/§8
intent: the MUST is single-0x88a8 agreement; double-tag is a nice-to-have.

### F5 (contract): screen fail-closed (#2146/#2189) is the real danger

The screen walker's value is its `Err`-on-truncation fail-closed semantics
(the whole point of #2146/#2189). Any unification that flattens `Err` into
`None` re-opens the syn-frag IDS-evasion. The plan's §5.2/§8 already mandate
a 1:1 `WalkError::Truncated → ScreenParseError::TruncatedIpv6ExtChain` map
and re-running the exact screen tests. This is correct and is the
highest-priority review gate for PR-2. The engineer MUST verify the
existing `screen/tests.rs` truncated-chain / syn-frag-bypass tests pass
unchanged against the unified walker, and that the walker returns `Err`
(not `Ok` with `is_first_fragment=false`) on a HBH-overshoot. ACCEPT with
emphasis.

---

## Things the plan got RIGHT (survived hostile read)

- Correct refutation of the live mechanism with file:line steering proof.
- Correct identification of the two outright-wrong L2 parsers
  (`parse_eth_offsets` 0x88a8→inner-ethertype; `nat64::frame_l3_offset`
  0x88a8→untagged-l3=14) and the missing NDP ext-walk.
- Correctly keeps the Go VRRP walker (#2188) and the kernel shim parser out
  of scope — no cross-language/cross-verifier merge.
- Correctly reuses #2148 `packet_rel_l4_offset_and_protocol` as the base
  rather than writing a 4th walker.
- Hybrid Option C (canaries-first, behavior-preserving adapter swap) is the
  right risk posture for a hot-path refactor.

## Net adjustments folded back into plan.md

1. §8: PROMOTE "per-caller bound as parameter" to the DEFAULT (preserve
   6/8/6); standardizing to 8 → separate follow-up (F3).
2. §6/§8: QinQ-double unwinding is OPTIONAL; the hard requirement is
   single-0x88a8 agreement (or uniform rejection) across all parsers (F4).
3. §11: keep the explicit "live mechanism REFUTED, conclusion CORRECT"
   framing (F1) — this is the headline for the issue comment.

## Disposition

**PLAN-READY.** It is a refactor that folds in two real latent-correctness
fixes (single-0x88a8 L2 + NDP ext-walk). It is NOT a live blackhole and NOT
a PLAN-KILL. Recommended execution: Option C, behavior-preserving
(per-caller bounds), canaries first, mandatory screen-fail-closed
re-validation + iperf3/failover smoke for the hot-path PR.

# Claude SMR hostile plan-review — r1

Reviewing `docs/research/1648-bringup-readiness/plan.md` v1 as domain SMR
(XDP/AF_XDP + Linux networking), CPU-arch/design, and SW-design-patterns.
Hostile by mandate: I verified every load-bearing code claim against source
before accepting it. First-pass "looks good" is a yellow flag — findings below.

## Verdict: PLAN-NEEDS-MINOR

Gate-B-first structure is correct and the honesty gate is properly placed. The
KEY CORRECTION (XDP_DROP not XDP_PASS) is verified correct. But there are three
real gaps the plan must close before it is Gate-B-ready, plus one verified-stale
risk I caught in my own §2.4 wording.

## Verified-correct claims (with quoted evidence)

1. **Transit SYN during ctrl-disabled = XDP_DROP, not XDP_PASS.** Confirmed.
   `try_xdp_userspace` `:345` `if ctrl.enabled == 0 ... return
   degraded_ctrl_disabled_action(ctx, ctrl)`. In that fn `:884` `if
   is_degraded_local_or_control(...) { return pass_local_control(...) }` else
   `:887 drop_degraded_transit(...)`. `is_degraded_local_or_control` `:910`
   returns false for a plain transit TCP SYN (not early-filter `:916`, not NDP
   `:919`, not local-dest `:922`, not ESP-NAT `:925`, not GRE-local `:928`).
   `drop_degraded_transit` `:945 Ok(xdp_action::XDP_DROP)`. The issue body's
   XDP_PASS-then-kernel-drop hypothesis is wrong for transit. **The correction is
   load-bearing and right.**

2. **W-HB→W-XSK ordering inversion is real.** `worker/mod.rs:355
   touch_heartbeat(...)` (writes `USERSPACE_HEARTBEAT[slot]`) precedes
   `:472 register_binding_xsk(&binding, xsk_map_fd)` (which at `:733
   register_xsk_slot` populates `USERSPACE_XSK_MAP[slot]`). So the heartbeat gate
   (`lib.rs:425`) can pass while the XSK slot is still empty → redirect Err
   (`lib.rs:637`) → `drop_degraded_transit` `:652`. Reachable.

3. **Binding READY is written on Registered+Armed, NOT Bound.**
   `maps_sync.go:596 if binding.Registered && binding.Armed { flags =
   userspaceBindingReady }`, comment `:597-601` explicitly says don't wait for
   Bound. So READY can be set before the worker's XSK registration completes — the
   Go side and the worker race independently. This reinforces W-XSK as a live
   candidate.

4. **Shim is the selected entry program from load.** `loader.go:129` (in
   LoadUserspaceShim) and `:159` (in CompileUserspaceShim) both call
   SelectUserspaceXDPShimEntryProgram before attach. Confirmed.

## Findings (must fix before Gate-B)

### MINOR-1 — §2.4 overstates "idempotent on a fresh boot" for the program swap

My own §2.4 says the SwapToUserspaceXDPShimEntryProgram calls are "idempotent on
a fresh boot." I did NOT fully verify the attach lifecycle: `loader.go:165
attachUserspaceShimXDP` attaches at compile, but the FIRST ctrl-enable path
(`maps_sync.go:406-409`) only swaps `if
!m.bpfShim.UsingUserspaceXDPShimEntryProgram()`. Since the shim was selected at
load, `UsingUserspaceXDPShimEntryProgram()` is true (`loader.go:96`), so the swap
is skipped — consistent with "idempotent." BUT I have NOT confirmed there is no
window between interface-up and `attachUserspaceShimXDP` where a different program
(or none) is attached and the SYN is XDP_PASS'd by default kernel behavior. This
must be an EXPLICIT Gate-B question (it is, §9 Q1) — but §2.4's confident
"idempotent" wording should be softened to "appears idempotent; Gate-B Q1
confirms." Otherwise the plan asserts something it hasn't proven. Fix the wording.

### MINOR-2 — Gate-B B-2 reason-counter attribution is ambiguous across the poll cadence

The degraded-path counters (`USERSPACE_FALLBACK_STATS`) are CUMULATIVE and
shared across ALL packets, not just the target 5-tuple. During the bringup window
there is background traffic (VRRP, ARP, the iperf3 control-channel SYN itself,
retransmits). A delta of `transit_drop`+`binding_not_ready` between snapshots does
NOT prove the *iperf3 data SYN* was the one counted. B-2 already adds a
5-tuple-restricted eprintln, which is the real attributor — but the plan presents
the counter deltas as co-primary. Demote the cumulative counters to corroborating
evidence and make the 5-tuple eprintln (with the XDP action + gate state at the
drop instant) the PRIMARY pin. State this explicitly so Gate-B doesn't
over-trust a shared cumulative counter (the exact failure mode that let the
dump-race H-0 look plausible before Gate-R).

### MINOR-3 — The 1s-poll→1.007s-RTO correlation is asserted but not yet bounded

§2.5 W-CTRL says "a single 1s poll tick aligns exactly with the ~1.007s RTO." That
is a hypothesis, not a measurement, and it is suspiciously tidy (1.007s is the
*client's* TCP initial RTO, RFC 6298 ~1s — it would be ~1s regardless of whether
the gap is 50ms or 950ms, as long as the gap < 1s and the binding is ready by the
retransmit). So the ~1.007s recovery time does NOT by itself prove the gap is ~1s
or that the poll cadence is the cause. Gate-B B-5 must record the ACTUAL gap
(T_ctrl-enabled − T_first-cold-SYN, or T_XSK-registered − T_SYN) and not infer it
from the RTO. Add this as an explicit B-5 requirement: the RTO is the *recovery*
clock, not the *gap* clock. (This matters for Path 1.C: event-driven enable only
helps if the gap is actually dominated by the poll cadence; if the gap is the
worker's XSK-bind latency the poll cadence is irrelevant.)

## Design observations (non-blocking)

- Path 2.A (XDP_PASS during not-ready) is correctly flagged as fail-closed-
  weakening and contingent on Gate-B B-4 proving the kernel can resolve. Good.
  But note: even if the kernel CAN forward, doing so during the SNAT-not-ready
  window (the documented reason for the 3s/15s prewarm delay, maps_sync.go
  :300-310) would forward transit WITHOUT SNAT → return traffic blackholes. So
  Path 2.A is more dangerous than the plan states for the W-CTRL window
  specifically. Add this caveat to §5 Path 2.A.
- Path 1.A (gate Go READY on a helper XSKRegistered flag) is the cleanest fix IF
  Gate-B pins W-XSK or the W-HB→W-XSK inversion. It strictly tightens the
  fail-closed contract (READY ⇒ redirectable). Likely the favored path.
- Path 1.C is the only path that addresses W-CTRL's poll-cadence component, but
  per MINOR-3 we don't yet know the gap is poll-dominated. Defer 1.C until Gate-B.

## Bottom line

Gate-B-first is the right structure and the honesty gate (B-6) is correctly
mandatory. The XDP_DROP correction is verified and is the single most valuable
output of v1 (it refutes the issue body's framing). Three minors: soften the
"idempotent" claim (MINOR-1), make the 5-tuple eprintln the primary pin over
cumulative counters (MINOR-2), and measure the actual gap rather than inferring it
from the RTO (MINOR-3), plus the Path 2.A SNAT-blackhole caveat. With those, the
plan is Gate-B-ready. Favored path on current evidence: Path 1.A (if W-XSK) or
Path 1.C (only if Gate-B proves the gap is poll-dominated); Path 3 stays viable if
the cost of touching the fail-closed bringup path exceeds removing one deploy RTO.

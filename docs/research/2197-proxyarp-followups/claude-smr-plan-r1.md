# Claude SMR (hostile self-review) — #2197 plan, round 1

Companion-free converged review of `plan.md`. I attack my own plan as a
hostile reviewer would: every load-bearing claim is challenged against
source, and each item gets an explicit ship/defer/kill verdict with a reason.

Convergence target: each item is either PLAN-READY with a verified design,
PLAN-DEFER with a stated unblock condition, or PLAN-KILL with a reason.

---

## Finding F1 (MAJOR, item 1) — "mirror the v4 path" hides a v6/v4-mapped key hazard

**Claim under test:** §5 says add a parallel `NeighList(idx, AF_INET6)` pass
and key with `netip.AddrFromSlice(n.IP.To16())`.

**Attack:** the kernel can return v4-mapped (`::ffff:a.b.c.d`) forms, and
`To16()` on a v4 address yields a 16-byte v4-in-v6. If the v6 pass keys a v4
entry as v6, the stale-removal pass could see a phantom "desired-absent" v6
entry and `NeighDel` a live v4 pneigh, OR double-install.

**Verdict:** real hazard, **already mitigated in the plan** (R2: skip any v6
existing-entry whose `IP.To4() != nil`). But the plan must also guarantee the
DESIRED side cannot produce a v4-mapped key: the config parse uses
`netip.ParsePrefix` and the branch tests `addr.Is6() && !addr.Is4In6()`, so a
`::ffff:` literal is treated as v4 (correct — it stays in the v4 desired set).
**Resolution:** the design holds; the /engineer pass MUST add an explicit
test feeding a `::ffff:10.0.0.1` proxy address and asserting it installs as
AF_INET (not AF_INET6) — otherwise a v4-mapped literal would silently take
the v6 path and `NeighSet` it with the wrong family. Folded into §9 as a
required test. Item 1 stays **PLAN-READY**.

---

## Finding F2 (MAJOR, item 3) — §7.2's kernel-mechanism explanation is hand-wavy; is the verdict still safe?

**Claim under test:** §7.2 asserts the pneigh-only path cannot answer the
#2160 same-subnet (`rt.dst.dev == dev`) case, and hedges on the exact
mechanism ("the key practical fact is…").

**Attack:** a hostile reviewer will say "you're recommending DEFER on a
mechanism you admit you don't fully derive — maybe pneigh-only *does* answer
and you're keeping an unnecessary broad sysctl." If pneigh-only sufficed, the
whole item-3 narrowing would be a clean win and DEFER would be wrong.

**Counter-attack (the decisive evidence):** the verdict does NOT depend on
deriving the exact kernel branch. It rests on a *measured* fact from #2160:
**the pneigh (NTF_PROXY) entry was already installed in the pre-#2160 code,
and the same-subnet external address was NOT answered until the sysctl was
turned on.** That is an empirical falsification of "pneigh-only answers the
same-subnet case," independent of which branch the kernel uses. The plan
already states this (§7.2). So the DEFER verdict is *robust to my mechanism
uncertainty* — and that robustness is precisely why DEFER (not KILL, not a
speculative narrowing PR) is correct: shipping 3B on an unverified mechanism
is exactly the trap. **Verdict: PLAN-DEFER stands and is strengthened.** I
softened §7.2's overclaim to lean on the empirical falsification rather than
the branch reading. No code for item 3. Confirmed.

**Secondary:** I should not assert "both branches require `rt.dst.dev !=
dev`" as if I traced current mainline line numbers — the issue body cites
`arp.c:863` and the project's own proxyarp.go doc-comment cites the same. I
defer to those (the reviewer who filed #2197 was kernel-source-verified) and
frame my statements as consistent-with-the-issue rather than an independent
line-level trace. Adjusted tone in §7. Non-blocking.

---

## Finding F3 (MEDIUM, item 1) — does v6 proxy-NDP have an analogous
"same-subnet doesn't answer" trap that would make the v6 install *also*
insufficient (i.e., is item 1 actually a no-op like the sysctl-only state)?

**Claim under test:** §5 implies installing the v6 pneigh entry makes v6
static-NAT proxy work end-to-end.

**Attack:** if IPv6 NDP proxy has the same same-subnet limitation as v4 ARP
(`rt.dst.dev == dev` not answered), then adding the pneigh entry alone, like
the v4 case, might still not answer for a same-L2 external v6 address —
making item 1 a partial fix and the issue's "non-functional until wired"
framing incomplete.

**Analysis:** the issue body (kernel-source-verified) states the v6 reply
requires forwarding AND `proxy_ndp` AND an existing v6 pneigh entry
(`pndisc_is_router` / `pneigh_lookup` in `net/ipv6/ndisc.c`). Note the v6
path is gated on the **pneigh table lookup itself** (`pneigh_lookup`) — i.e.
v6 proxy-NDP is *inherently* per-address (it answers only if a matching
pneigh exists), unlike v4 where the broad `arp_fwd_proxy` path can answer
without any pneigh. This means:

1. The v6 install (item 1) IS the necessary-and-sufficient piece on the v6
   side for the listed address — there is no v6 analogue of the broad
   `arp_fwd_proxy` over-answer (so item 3's breadth concern is v4-only, which
   the existing docs already imply by scoping the breadth note to
   `proxy_arp`).
2. BUT the same-subnet (`rt.dst.dev == dev`) question: the plan's §7 same-
   subnet argument was about the v4 `arp_fwd_proxy` mechanism. For v6, since
   the answer is gated purely on `pneigh_lookup` + forwarding + `proxy_ndp`,
   the pneigh entry IS what makes it answer. The plan should NOT assume the
   v4 same-subnet failure transfers to v6 — they are different code paths.

**Verdict:** item 1 stays **PLAN-READY**, and this finding *improves* it: the
plan should state that v6 proxy-NDP is inherently per-address (no broad
over-answer path), so (a) item 1's pneigh install is the complete fix on the
v6 side, and (b) item 3's narrowing concern does not apply to v6 at all.
**Action:** add a sentence to §5 and §7 noting v6 is per-address by
construction (`pneigh_lookup`-gated), so the v6 install is sufficient and v6
has no breadth problem. This also means the v6 sysctl + pneigh combo is the
correct and narrow end state for v6 with no follow-up needed. Folded.

**Caveat I must keep honest:** I have NOT independently re-read
`net/ipv6/ndisc.c`; I am reasoning from the issue's kernel-verified summary +
the asymmetry that v6 has no `arp_fwd_proxy` equivalent. The live test in §9
(send a v6 NS, confirm the firewall answers after the install) is the
ground-truth gate. If the live test shows v6 same-subnet still doesn't
answer, item 1 escalates to needing the same sysctl-is-load-bearing
treatment as v4 — but the sysctl is *already* enabled today, so item 1 can
only improve the v6 state, never regress it. **Item 1 is monotonic: it adds a
required piece on top of an already-enabled sysctl.** Safe to ship; the live
test confirms completeness.

---

## Finding F4 (MEDIUM, item 2) — Trigger A may be dead code; Trigger B cadence

**Claim under test:** §6.2 Trigger A (post-`programRethMAC`) and §6.3
Trigger B (30s periodic).

**Attack 1 (Trigger A redundant):** the plan itself flags that the commit-time
2.6c reconcile already re-covers a commit-time link cycle, so Trigger A may be
dead code. Shipping dead code is a review reject.

**Verdict:** the plan already marks Trigger A "optional, verify-then-drop"
(§6.2, §6.5). Hostile-tighten: **default to NOT shipping Trigger A** unless
the /engineer audit finds a concrete `programRethMAC`-cycles-without-2.6c
path. The load-bearing fix is Trigger B. Adjusted §6.5 to make "do not ship
A by default" the explicit recommendation. Resolved.

**Attack 2 (Trigger B 30s is arbitrary / too slow):** a 30s blackhole for a
proxied address after a flap could drop real traffic.

**Counter:** proxy-ARP answers are cached by neighbors per their ARP/NDP
reachable time (typically tens of seconds); a flap that clears `proxy_arp`
does not instantly purge peer caches, so the practical exposure is shorter
than 30s, and a flap is already a disruptive event. 30s is a defensible
default; if operationally too slow, Trigger C (event-driven link-up) is the
documented escalation. **Verdict:** keep 30s as default, document the
Trigger-C escalation. Acceptable. Item 2 stays **PLAN-READY**.

**Attack 3 (new always-on goroutine on every daemon):** adds a goroutine even
on configs with no proxy-arp. *Counter:* one 30s ticker whose body is a map-
length check + return is negligible; matches the project's existing always-on
loops (neighbor resolution). Acceptable. Could alternatively start the loop
only when `len(ProxyARP) > 0` at boot — but that misses a runtime
enable-via-commit unless the loop is (re)started on apply. **Refinement:**
start it unconditionally (simplest, no apply-time lifecycle), body no-ops when
empty. Confirmed §6.3.

---

## Finding F5 (MINOR, item 1) — `ProxyARPAdded.Family` API change ripples

**Claim under test:** §5.4 adds `Family int` to `ProxyARPAdded`.

**Attack:** any other consumer of `ProxyARPAdded` breaks.

**Check:** the only consumer is the GARP loop in `daemon_apply.go:939-945`
(grep confirmed: `ProxyARPAdded` is referenced only in proxyarp.go and its
test). Adding a field is backward-compatible (zero value AF_UNSPEC=0 reads as
"unset"); the caller branches on `a.Family == unix.AF_INET6` to skip GARP.
**Verdict:** low ripple, single caller. Alternatively, omit v6 entries from
the returned slice entirely (no API change) — but then v6 adds are invisible
to logging/metrics. **Recommend the `Family` field** (observability > minimal
diff). Non-blocking; either is fine. Item 1 unaffected.

---

## Finding F6 (MINOR, item 2) — extracted `reconcileProxyARP` and the
`ifaceMap` RETH resolution must stay identical

**Attack:** the apply-path `ifaceMap` build (daemon_apply.go:916-934) does
RETH→physical resolution (`cfg.RethToPhysical()` + `config.LinuxIfName`) and
`net.InterfaceByName`. If the extracted method drops any of that, the periodic
reassert would resolve the wrong ifindex on RETH interfaces and silently
no-op (or worse, install on the wrong link).

**Verdict:** the extraction MUST move the resolution verbatim, not
reimplement it. The /engineer pass extracts the *exact* block into the method
and has both the apply path and the loop call it. A unit test should assert
the RETH-named entry resolves to the physical ifindex. Folded into §9.
Item 2 **PLAN-READY** with this constraint stated.

---

## Finding F7 (MINOR, all) — docs contract

CLAUDE.md mandates doc updates as part of the change. The plan lists
`feature-gaps.md` (Proxy NDP Partial→Done after PR-1; keep the v4 breadth
note for item 3 DEFER) and `phases.md` (ReconcileProxyARP v6 + periodic
reassert). Item 3 DEFER must be recorded (issue comment + optionally a parked
follow-up). **Verdict:** doc plan adequate; ensure the Proxy NDP row only
flips to Done *after* the live v6 NS test passes (F3 caveat). Folded into §9
gate.

---

## Convergence summary

| Item | Verdict | Unblock / condition |
|------|---------|---------------------|
| 1 — v6 pneigh install | **PLAN-READY** | implement PR-1; v6-mapped-literal test (F1) + RETH-resolve test + live v6-NS test gates the Partial→Done doc flip (F3) |
| 2 — periodic reassert | **PLAN-READY** | implement PR-2 with Trigger B only (drop Trigger A unless audit finds a real gap, F4); exact `ifaceMap` extraction (F6); `make test-failover` |
| 3 — narrow over-answer | **PLAN-DEFER** | the empirical #2160 falsification (pneigh-only does NOT answer same-subnet) makes dropping the sysctl unsafe (F2); v6 has no breadth problem at all (F3); revisit 3B only with a lab repro of a real over-answer + a verified different-device pneigh-only reply |

No item is PLAN-KILL (sub-option 3C `medium_id` is killed within item 3, but
item 3 itself is DEFER not KILL). Item 1 is a monotonic, ship-now MEDIUM
fix. Item 2 is a small, idempotent LOW fix. The plan is internally
consistent and the design claims are verified against the source in-tree and
the kernel facts cited in the (kernel-verified) issue. **Plan is converged
and PLAN-READY for items 1 & 2; item 3 PLAN-DEFER.**

### Edits folded back into plan.md from this SMR

- §5/§7: note v6 proxy-NDP is inherently per-address (`pneigh_lookup`-gated)
  → v6 install is the complete fix and v6 has no over-answer breadth (F3).
- §7.2: lean the DEFER verdict on the empirical #2160 falsification rather
  than an independent line-level kernel trace (F2).
- §6.5: default to NOT shipping Trigger A; Trigger B is the load-bearing fix
  (F4).
- §9: add required tests — v4-mapped-literal classification (F1), RETH
  ifindex resolution in the extracted method (F6), live v6-NS gate before the
  doc flip (F3/F7).

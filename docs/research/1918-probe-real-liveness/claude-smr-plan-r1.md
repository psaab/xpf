# Claude SMR — HOSTILE plan review r1 — #1918

Reviewer: Claude SMR (domain SME: dataplane/HA + Linux ICMP socket semantics + Go concurrency).
Posture: hostile. Goal is to break the plan, not bless it.

## Verdict: PLAN-NEEDS-WORK (r1)

The plan is directionally correct and well-anchored on a real in-tree precedent, but it has
**one load-bearing technical claim that is half-wrong as written**, one under-specified
correctness invariant, and two soft spots. None are fatal — this is fixable in one revision,
not a KILL.

---

## F1 (MAJOR) — The reply-matching predicate is described inconsistently across §5a, §7.5, R3

§5a says "require `echo.ID == want.ID && echo.Seq == want.Seq`". §7.5 says "stable `ID` (e.g.
derived from tunnel name hash, low 16 bits)". R3 then correctly walks this back: "Matching on a
self-chosen ID may therefore never match." These contradict each other. A reader implementing
§5a/§7.5 literally would ship a prober that **never matches** on datagram-ICMP and thus reports
every live peer as Dead → tears down every keepalive tunnel after MaxRetries. That is a worse
outage than the bug being fixed.

The kernel truth (Linux `net/ipv4/ping.c`): for `IPPROTO_ICMP` datagram ("ping") sockets the
kernel **overwrites** the echo `id` on send with the socket's bound source port
(`ping_v4_sendmsg`), and on the inbound path demuxes the reply by that id to deliver to the
right socket. `x/net/icmp` `ParseMessage` returns the id present in the received datagram — the
kernel does NOT restore the application's chosen id. So the application cannot match on a
self-chosen id. (`pkg/cluster/monitor.go` sidesteps this by matching only `parsed.Type` — which
is exactly the §5a defect this plan claims to fix, and is why §5a is internally inconsistent.)

**Required change:** make the match predicate authoritative and singular in §5a, §7.5, and R3:
match on **Seq** (kernel-transparent) AND a per-probe **nonce carried in `Echo.Data`** (echoed
back verbatim by an RFC-compliant responder). Drop ID from the predicate entirely (or keep it
as advisory-only with an explicit "do not require equality" note). The plan must NOT instruct
the implementer to require `echo.ID == want.ID`.

Caveat the implementer must verify (the plan should say so, R3 partially does): some middleboxes
/ responders do not echo `Echo.Data` faithfully for oversized payloads — keep the nonce small
(e.g. 8 bytes) and confirm round-trip on loopback before locking it. Seq alone is a weak match
under a shared socket; Seq+nonce is the floor.

## F2 (MAJOR) — "exactly one LinkSet* per transition" is asserted but the invariant that
guarantees it is not stated

Axis D and §4.3 promise "exactly one LinkSetDown/Up." The mechanism (compute under lock,
netlink outside) is necessary but NOT sufficient on its own to prove it. The actual invariant
is: **the netlink call must be gated on the `Up` value having *changed* this tick**, and `Up`
must be mutated (under the lock) in the same critical section that decides the transition, so a
second tick observing the already-changed `Up` does not re-fire. The current code already does
this via the `if !state.Up` / `if state.Up && Failures>=MaxRetries` guards — the plan must
preserve those edge guards, not just "move netlink outside the lock." If the implementer naively
snapshots "should be down" without flipping `Up` inside the lock, two ticks both see Up=true and
both fire LinkSetDown. State the invariant explicitly: *transition decision and the `Up` write
happen in one locked section; the netlink op is keyed to the decision, performed after unlock;
no re-read of `Up` between decision and netlink.*

Also: with netlink moved outside the lock, two ticks can't overlap (single goroutine loop), so
there's no concurrent-tick TOCTOU — but a concurrent `stopAll`/`startKeepalive` could cancel the
ctx between unlock and the netlink call. That's benign (the LinkSet just runs or the link is
being torn down anyway), but the plan should note the netlink call may run after cancel and that
this is acceptable (matches #848 drain semantics — done is closed only after the loop returns).

## F3 (MEDIUM) — C1 default is right, but the "recovery" path under C1 has a gap

C1 says on ProbeUnsupported: don't increment Failures, don't LinkSetUp/Down, set KeepaliveUp=nil.
Consider the sequence: peer dies (real ICMP, Dead×MaxRetries → Up=false, LinkSetDown fired) →
THEN the operator's privilege regresses (ping_group_range cleared on a config reload) →
subsequent probes return Unsupported. Under C1 we "hold the prior Up value" = false, set
KeepaliveUp=nil. But the link is already admin-down from the real failure. When the peer later
recovers, probes are still Unsupported, so we never LinkSetUp → the tunnel stays down forever
even though the peer is alive, purely because we lost probe privilege. The plan must specify:
on the Dead→(Unsupported) edge, does the link stay down? I think the correct rule is: C1's "hold
prior Up" is fine for status, but **Unsupported must not strand a link in admin-down** — either
(a) on entering a sustained-Unsupported regime, restore the link to up and rely on the FIB
(matching the pre-fix availability posture) with a loud status="unknown", or (b) document that
admin-down persists and require operator action. Pick one and write it. (a) is more consistent
with "Unsupported is a privilege problem, not a peer-death signal." This is the subtle case the
bool→enum refactor is supposed to handle cleanly; the plan currently under-specifies it.

## F4 (MINOR) — VRF socket reopen-per-probe interacts with R5 deadline budget

§7.1 / R2 open the socket per-probe (correct for late VRF device creation). But socket open +
SO_BINDTODEVICE + a possibly-cold ARP/ND on the tunnel adds latency inside the probe budget.
With interval=1s and deadline=min(800ms, interval/2)=500ms, a per-probe cold open could eat the
budget and yield false Dead. Mitigation to add: open the socket ONCE per keepalive goroutine
(cache it on the runner), reopen only on VRF-device-change or socket error. This also fixes the
"late VRF" case without paying per-tick. The plan's "open per-probe (cheap)" claim is too glib;
socket syscalls + bind are not free at 1 Hz × N tunnels.

## F5 (NIT) — factual: stale line numbers + the existing tests

The issue body cites `tunnel.go:1024-1050` / `978-1019`; the plan correctly notes the worktree
HEAD has these at 1025-1051 / 980-1021. Good. §8 correctly flags `routing_test.go:896,901`
`probeICMP("127.0.0.1")` as bug-encoding tests that must be rewritten — confirmed, those pass
today only because the socket opens, not because loopback "responds" to an echo that's never
sent. Keep that callout.

## What's right (so this isn't a drive-by KILL)

- A1 datagram-ICMP + auto-A2-raw-fallback is the correct mechanism ranking; rejecting exec-ping
  as primary is correct (fork-per-tick at N tunnels).
- B1 typed enum is the correct fix for the bool's information loss.
- D lock-scope fix is real and the secondary bug is genuine (verified `state.mu` held :991→:1019
  across LinkSetUp@:1001 / LinkSetDown@:1015).
- Rejecting the package split (E) for this bug fix is the right call.
- Scoping monitor.go's 5a fix as a follow-up (not in this PR) is correct PR discipline.

## Required for PLAN-READY

1. F1: single authoritative match predicate = Seq + Data-nonce, ID NOT required. Fix the
   §5a/§7.5/R3 contradiction.
2. F2: state the exactly-one-LinkSet* invariant explicitly (decision+Up-write in one locked
   section; netlink keyed to decision, after unlock; preserve edge guards).
3. F3: specify the Dead→Unsupported→recovery behavior so a privilege loss can't strand a link
   admin-down forever.
4. F4: cache the probe socket on the runner; reopen on VRF-change/error, not per-tick.

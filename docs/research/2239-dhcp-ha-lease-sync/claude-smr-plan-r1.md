# Claude-SMR hostile plan review — #2239 (DHCP HA lease sync) — round 1

Reviewer posture: adversarial. Goal is to FAIL the plan if a recommended path
is architecturally wrong, if the BACKUP-stops-Kea tension is hand-waved, or if a
hidden invariant is violated. Verdict at the end.

## Method

Verified every load-bearing claim against source in the worktree
(`origin/master` @ 828cceacb) and against the live `loss:xpf-userspace-fw0`
appliance. Attacked each path's central assumption.

---

## Attack 1 — Does PATH A actually contradict BACKUP-stops-Kea, or is the plan
inventing a contradiction to justify PATH C?

Checked `pkg/daemon/daemon_ha.go:1015-1031`. `clearRethServicesForRG` on BACKUP
enqueues `d.dhcpServer.ApplyAsync(nil, ...)`. `Manager.apply` with `cfg==nil`
sets `want4=want6=false` → `clearFamilyLocked` → `systemctl stop kea-dhcpN` +
removes the config file (`dhcpserver.go:215-240, 323-335`). So the BACKUP node's
Kea is genuinely STOPPED and its config REMOVED. Kea HA hot-standby (PATH A)
requires the standby's Kea to be RUNNING to receive synchronous lease updates
(ISC ARM: the primary parks the response until the standby acks the lease
update). These are mutually exclusive. The contradiction is REAL, not invented.

PATH A's only rescue is to INVERT BACKUP-stops-Kea — keep Kea up on the standby.
That is exactly the inversion the plan flags as a blocker. CONFIRMED: PATH A is
architecturally incompatible with the current model without a core behavior
inversion. The plan's rejection of A is SOUND.

Severity of getting this wrong: would have shipped an always-on second DHCP
server bound to RETH member interfaces that are DOWN/owned-by-the-MASTER, with
two independent "who serves" arbiters (VRRP and Kea HA heartbeat). Correctly
rejected.

## Attack 2 — Is PATH C's "standby holds state, seeds on takeover" actually a
real, precedented pattern in this codebase, or aspirational?

Verified against IPsec SA sync, which is the claimed precedent:
- Hold: `SessionSync.peerIPsecSAs` + `PeerIPsecSAs()` (`sync.go:240-241,
  752-758`). REAL.
- Periodic MASTER push: `syncIPsecSAPeriodic` (`daemon_ha.go:1237-1262`), 30s,
  gated `IsLocalPrimary(0)` + `cc.IPsecSASync`. REAL.
- Takeover re-apply: `reinitiateIPsecSAs` (`daemon_ha.go:1266-1281`), fired on
  becoming primary (`daemon_ha.go:335-336`). REAL.
- Wire: `encode/decodeIPsecSAPayload` (`sync_protocol.go:511-538`), send
  `QueueIPsecSA` (`sync.go:760-776`), receive `sync_conn.go:1280-1289`. REAL.

PATH C is a near-verbatim re-instantiation of a shipped, tested pattern, swapping
"connection names" for "lease records." NOT aspirational. The plan's structural
claim holds. The ONE material difference (the lease set is larger/structured and
must be re-anchored to local time) is explicitly addressed (§6 clock invariant,
§5 component 3/6). Accept.

## Attack 3 — The <60s clock-skew hazard. The plan claims PATH C is "immune."
Is that true, or is it papering over the same hazard?

The hazard in Kea HA (PATH A) is wall-clock divergence driving both servers to
the terminated state. The cluster channel here syncs MONOTONIC offset only
(`sync_conn.go:947-955 / 1368-1378`), NOT wall clock — verified. So if PATH C
shipped raw wall-clock lease expiry epochs, a skewed peer WOULD mis-age leases.
The plan's mitigation is to sync REMAINING LIFETIME and re-anchor to the local
clock at seed time (§6 clock invariant, §5 component 3). That genuinely removes
the wall-clock dependency: `expiry_local = now_local + remaining`. The peer's
wall clock never enters the promoting node's computation.

BUT — adversarial probe — remaining-lifetime is computed on the SENDER as
`expire_sender - now_sender`. If the SENDER's clock is wrong, `remaining` is
wrong even before transmission. Is that a hole?

Answer: it is the SAME error Kea itself already has locally — Kea computed
`expire = grant_time + valid_lifetime` on the (possibly skewed) MASTER, and the
client already holds that lifetime. Re-anchoring to the standby's clock at seed
preserves the REMAINING portion as the MASTER saw it, which is the correct
target (the client and the new server agree on remaining time). The only residual
error is sender-clock-vs-true-time, which is bounded by NTP discipline (chrony is
active) and is NOT the catastrophic both-nodes-terminated divergence of PATH A.
So "immune to the PATH A hazard" is accurate; "immune to all clock error" would
be overclaiming, and the plan does NOT claim that (§6 says "immune to peer
wall-clock skew", §10 Q6 keeps mutual NTP as defense-in-depth). Precise enough.
Accept, with Q6 correctly left open.

## Attack 4 — Duplicate allocation. The acceptance criterion is "the promoted
node will not hand the in-use address to a different client." Does PATH C
actually guarantee this, or only reduce the probability?

Trace the failure window (R5/R6). A lease granted on the MASTER in the last tick
before an abrupt (un-planned, no priority-0 goodbye) failover may NOT have
reached the standby. On takeover the promoted Kea is seeded with the
LAST-SYNCED set, which lacks that lease. The promoted node's pool now considers
that address FREE and could hand it to a new client → duplicate allocation.

This is a REAL residual gap in v1 (periodic-only push). The plan acknowledges it
(R5, "up-to-one-tick staleness") but the acceptance criterion is stated
unconditionally. Two honest positions:
1. v1 reduces the window to ≤ one push interval and the plan must NOT claim the
   criterion is fully met until an incremental on-grant push (or a pre-answer
   pull-from-peer) closes it.
2. The duplicate-allocation risk for a lease granted in the final tick is
   partially self-mitigating: the client holding that fresh lease will, on the
   server it now talks to (the promoted node), either renew (DHCPREQUEST for its
   known address → the promoted node, lacking a conflicting binding, can ACK and
   adopt it) or, if the promoted node already gave the address away, NAK. The
   window for an actual DOUBLE-grant is "new client DISCOVERs the same address
   between takeover and the original client's first renew." Small but nonzero.

FINDING (MINOR, must-fix-in-plan): the plan should DOWNGRADE the unconditional
"will not hand the in-use address" claim for v1 to "within the synced lease set"
and make the incremental on-grant push (Q1) a RECOMMENDED v1.1 follow-up rather
than purely future, OR add a takeover-time PULL of the peer's freshest leases
before Kea answers (the standby could request a final lease snapshot from the
departing MASTER is impossible on abrupt failure, so the periodic push is the
only source — which is why on-grant push matters more here than for IPsec). The
plan already routes this through Q1; acceptable as PLAN-READY provided the issue
comment and §10 flag that full criterion satisfaction needs the incremental push
or pre-seed-from-memfile-on-the-promoting-node's-own-persisted-leases. This is a
scoping precision fix, not an architectural defect. PATH C remains correct.

## Attack 5 — Is the Kea control socket / lease_cmds actually available, or does
PATH C assume a package that isn't installed?

Live-verified on `loss:xpf-userspace-fw0`: `kea-common 3.0.3` ships BOTH
`libdhcp_ha.so` AND `libdhcp_lease_cmds.so` under
`/usr/lib/x86_64-linux-gnu/kea/hooks/`. `kea-common` is a dependency of the
installed `kea-dhcp{4,6}-server`. NO new apt package. The plan's claim is TRUE.
R11 (hook missing) is correctly Low with a capability check + memfile fallback.

One adversarial note: the plan adds a `control-socket` to the generated Kea
config. Confirm this does not regress the existing `parseLeaseCSV` /
`parseActiveLeases` memfile readers (they read the file, unaffected by a socket)
— it does not. And confirm `persist=true` stays so single-node restart keeps
leases — the plan §6 explicitly preserves it. Accept.

## Attack 6 — Single-writer / dueling-writers. Could PATH C produce two nodes
both seeding/mutating the same RG's leases?

The push is gated on RG-MASTER and the memfile is MASTER-filtered
(`filterDHCPConfigForMasterRGs`, `daemon_ha.go:1036-1089`), so each node's lease
set is disjoint by RG ownership — the SAME property `ddnsWriterGateOpen` relies
on and that the DDNS README documents as making dueling writers impossible. Seed
runs only on the node that just became MASTER for that RG. No dueling writers.
The plan correctly reuses this proven invariant. Accept.

## Attack 7 — Control-socket contention (a CLAUDE.md hard rule). Does the new
loop risk starving session installs?

The plan's loop talks to (a) Kea's OWN unix socket and (b) the cluster TCP sync
channel — NEVER the userspace-helper control socket. The CLAUDE.md rule is about
the HELPER control socket. The DDNS loop documents the same isolation. So the
rule is respected. The remaining concern is the cluster sync CHANNEL cadence:
adding a 30s full-lease push to a channel that also carries session sync. A 30s
(or even 5-10s) coalesced full-set push is negligible vs the per-second session
sweep. Accept, with the caveat that Q1's tighter cadence / on-grant push must
keep the channel budget in mind (the plan says so).

---

## Did the plan pick the path that resolves BACKUP-stops-Kea cleanly?

YES. PATH C is the ONLY path of the three that:
- leaves `clearRethServicesForRG`'s authoritative stop UNCHANGED (standby Kea
  stays down),
- keeps a SINGLE arbiter of "who serves" (VRRP/RG),
- adds NO new always-on service / HTTP listener / DB,
- and answers the <60s clock hazard structurally (remaining-lifetime
  re-anchoring) rather than by adding a new wall-clock guarantee.

PATH A requires inverting BACKUP-stops-Kea + an HTTP REST surface + a new NTP
guarantee + a second serve-arbiter. PATH B adds a DB SPOF / second HA problem.
Both correctly rejected.

The BACKUP-stops-Kea resolution is concrete and precedented: hold peer lease
state in xpf (the `peerIPsecSAs` precedent), seed the freshly-started Kea on
takeover (the `reinitiateIPsecSAs` precedent). The standby holds STATE, not a
running service.

---

## Findings summary

- MAJOR: none.
- MINOR-1 (Attack 4): the unconditional "will not hand the in-use address to a
  different client" acceptance claim is only fully met once an incremental
  on-grant push (Q1) or a pre-answer seed-from-peer closes the last-tick window.
  v1 periodic push bounds but does not eliminate the window. The plan routes
  this through R5 + Q1 but should state explicitly in the issue comment that
  FULL criterion satisfaction depends on the incremental push follow-up. Plan
  text already honest in R5/§10; tighten the framing, not the architecture.
- NIT-1: §10 Q3 (seed timing) genuinely affects R6 closure — recommend the
  /engineer phase decide pre-seed-memfile-before-start (a) vs lease-add-after-
  start (b) early, because (a) more fully closes the duplicate-allocation window
  by ensuring Kea never answers before its lease DB is seeded.
- NIT-2: confirm Q5 (v6 PD/prefix-delegation leases) is either handled or
  explicitly scoped out of v1 before implementation, so a PD deployment is not
  silently un-synced.

## Verdict

**PLAN-APPROVED (PLAN-READY).** PATH C is architecturally correct and the only
path that resolves the BACKUP-stops-Kea tension cleanly. PATH A is correctly
rejected as incompatible with the authoritative-stop model; PATH B correctly
rejected as an unwanted DB/SPOF dependency. The one MINOR is a framing precision
on the duplicate-allocation acceptance claim (the v1 window), already tracked in
R5/Q1 — it does not change the chosen architecture. Proceed to /engineer with
Q1/Q3/Q5 resolved early.

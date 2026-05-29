# Claude SMR hostile plan-review — #1651 cold-resolve latency — Round 2

Reviewing plan v3 (after folding Codex-r1 + AGY-r1). SMR/domain seat.

## Verdict: PLAN-READY (Path C for latency + B3 negative-cache as the shippable deliverable; Path A conditional-KILL; spin off AGY findings 3/4)

The round-1 reviewers materially improved the plan without overturning its
empirical core. Adjudication of each finding:

### Codex-r1 MEDIUM (warmer also warms fabric peers) — ACCEPTED, folded (§2).
Factually correct: `coordinator/mod.rs:733` enqueues `(fabric.parent_ifindex,
fabric.peer_addr)`. My "route next-hops only" was incomplete. Does NOT
change the on-link-host conclusion (tested hosts are neither route
next-hops nor fabric peers, and `QUEUE` fired). Both Codex AND AGY
independently confirmed scope-link on-link hosts are warmer-immune. The
on-link cells remain the load-bearing evidence. Resolved.

### Codex-r1 LOW (raw counter snippets) — ACCEPTED, folded (§2).
Representative QUEUE/REDRIVE/DROP_TIMEOUT lines now in the doc.

### AGY-r1 CRITICAL (CAP_NET_RAW silent failure) — ACCEPTED as a documented
assumption + Path-A pro, REJECTED as a Path-C showstopper.
AGY is right that `trigger_kernel_arp_probe`'s `SOCK_RAW` would `EPERM`
under a cap-dropped deployment and silently no-op (`neighbor.rs:43-44`),
blocking all cold resolution. **But this is hostile-checked against the
actual deployment:** xpfd ships as a **root** appliance daemon — it
attaches XDP, owns every interface, opens AF_PACKET (VRRP receiver),
AF_NETLINK, and SOCK_RAW, and writes netlink routes. It already mandates
`CAP_NET_ADMIN`+`CAP_NET_RAW`; there is no cap-dropped mode in this
product. So the "100% of new connections blocked" scenario cannot occur in
the shipped model — it is a hypothetical for a deployment that does not
exist. I will not let a CRITICAL stand on a non-existent deployment. The
*legitimate* residue — that Path A is more robust because it needs no
per-probe raw syscall — is captured as a Path-A pro and a revisit trigger.
This is the correct severity adjudication: documented assumption, not
blocker.

### AGY-r1 HIGH (dead-host SYN storm starves `pending_neigh` → blocks live
cold connects) — ACCEPTED, ELEVATES B3 to the recommended deliverable.
This is the most valuable finding of the round and it is real:
`MAX_PENDING_NEIGH=4096` (`mod.rs:342`), full-queue connects dropped at the
`poll_descriptor/mod.rs:2644` gate without buffering/probing, 800 ms hold
per dead host ⇒ ~5,120 dead SYN/s saturates the queue and live cold
connects are dropped. This is an availability hazard orthogonal to the
operator's latency perception, and it is exactly the kind of thing a
negative cache (free the slot fast / don't re-occupy for known-dead hosts)
fixes cleanly without regressing live-but-slow. The plan now recommends B3
as the one code change worth shipping. This is a genuine improvement over
my r1 "B3 optional." Correctly elevated.
  - *Caveat I add (and the plan should keep in mind for /engineer):* a
    naive negative cache can itself be a hazard — a transiently-down host
    that comes back must not be cached-dead long enough to delay its real
    recovery connect. The negative-cache TTL must be short (sub-second to a
    few seconds) and ideally invalidated by any RTM_NEWNEIGH for that key.
    This is a /engineer design detail, flagged here so it isn't lost.

### AGY-r1 MEDIUM (dynamic-neighbor leak on replace) + LOW/MED (no SO_RCVBUF)
— ACCEPTED as REAL bugs but OUT OF SCOPE for #1651; spin off.
Both are neighbor-cache *correctness/robustness* bugs, not cold-resolve
*latency*. AGY's reasoning is sound (`coordinator/mod.rs:148-178`
`old_manager_keys` cannot evict monitor-learned dynamic entries;
`neighbor.rs:505-513` sets only `SO_RCVTIMEO`, no `SO_RCVBUF`, vs the Go
listener's 1 MiB at `daemon_neighbor_listener.go:132`). They did NOT
perturb Gate-M' (modest flush sizes, `Deleted` events observed). Folding
them into #1651 would scope-creep a latency issue into a cache-correctness
issue. The plan now lists them as spin-off issues. Correct disposition.

## Residual hostile check I ran myself
- **Could the 800 ms dead-host result itself be the queue-full drop rather
  than the timeout?** No — the dead-host sweep was 20 *sequential* connects
  (qlen=1 each per the QUEUE logs), nowhere near the 4096 cap, and each
  showed `DROP_TIMEOUT held_us≈800740 attempts=3` — the genuine timeout,
  not the full-queue gate. The DoS (Finding 2) is a *separate, concurrent*
  hazard, correctly characterized as such.
- **Is post-failover 6.5 ms vs the prior research's ~1.7 s a contradiction?**
  No — the prior 1.7 s was a *specific entry* racing the startup
  neighbor-dump (#1648), not a per-connect floor. My post-failover test hit
  a live target whose resolve completed promptly. #1648 remains the home
  for the startup-dump race. Consistent.

## Conclusion
v3 is PLAN-READY: the latency conclusion (Path C) is empirically solid and
survived two hostile rounds; the one shippable change (B3 negative cache)
is now correctly motivated by a real availability hazard; Path A is
correctly conditional-KILLed with the cap-constrained + high-RTT revisit
triggers documented; the two cache-correctness bugs are correctly spun off.
The only open external input is the §10 operator-environment/reachability
question, which is an information request, not a plan defect.

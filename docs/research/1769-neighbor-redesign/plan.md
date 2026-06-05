# #1769 — userspace-dp neighbor discovery/resolution redesign

Research plan (NOT an implementation). Codex-led adversarial review +
redesign. Stops at PLAN-READY / PLAN-KILL. The targeted stuck-state fix
(section 9) is separable and can be `/engineer`-ed independently of the
larger redesign (section 10).

Repo: `psaab/xpf`. Branch: `research/1769-neighbor-redesign`.
Live env: `loss:xpf-userspace-fw0/fw1`,
`BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env`.

---

## 1. Symptom (live, confirmed)

`iperf3 -c 172.16.80.200 -p 5208 -P12` HUNG on `loss:xpf-userspace-fw0`
(RG primary, master `ef40d1cae`): `Connection timed out`, 0 bytes, 0
bitrate — new-flow SYNs never made it out. Kernel HAD the neighbor
(`ip neigh`: `172.16.80.200 dev ge-0-0-2.80 lladdr ea:de:15:f5:66:70
DELAY`) but the dataplane could not forward the new flow. It degraded
INTO this state (#1766 ran 25 clean `-P12 5208` runs minutes earlier),
so it is a stuck-STATE regression, not a cold config issue.

Only neighbor metrics exported:
`xpf_userspace_neighbor_warm_disconnected_total` /
`..._warm_drops_total` (both 0). No pending-queue depth, no
resolution-failure/timeout counter, no negative-cache visibility, no
retry-rate. The stuck state is invisible to operators.

## 2. Root cause (validated against code + live recovery)

The destination `172.16.80.200` is **directly connected** on
`ge-0-0-2.80` (`ip route get` → `dev ge-0-0-2.80 src 172.16.80.8`), so
the forwarding next_hop is the target IP itself and resolution requires
an ARP entry for it on that VLAN sub-interface.

The dataplane resolves a neighbor MAC via two maps only
(`lookup_neighbor_entry`, `forwarding/mod.rs:1529`):

1. `state.neighbors` — the Go-pushed snapshot (static/connected
   neighbors at snapshot time).
2. `dynamic_neighbors` — a `ShardedNeighborMap` populated by:
   (a) the netlink monitor thread on `RTM_NEWNEIGH`
   (`neighbor.rs:280/562`), (b) `learn_dynamic_neighbor_from_packet` on
   an **inbound** packet whose L2 src is that neighbor
   (`neighbor_dispatch.rs:288`), (c) **Codex r1:** Go-manager neighbor
   updates that insert into both dynamic + forwarding maps
   (`coordinator/mod.rs:177,192`), and (d) **Codex r1:** ARP/NA
   classification in the RX path (`poll_stages.rs:80,103`). None of
   these fire for an outbound-only, directly-connected target whose
   kernel entry silently went away.

The kernel having a valid lladdr in **`DELAY`/`STALE`/`PROBE`** is NOT
sufficient — the dataplane only knows the MAC if one of those two events
populated `dynamic_neighbors` (or the snapshot carried it). There is NO
on-demand "read the kernel's current lladdr" path on the miss; the hot
path explicitly refuses to query (`forwarding/mod.rs:1544-1547`).

The stuck state is produced by the **interaction of the negative
neighbor cache with the loss of the dynamic entry**:

- When a `pending_neigh` entry times out
  (`PENDING_NEIGH_TIMEOUT_NS` 2s fallback / 800ms fast,
  `forwarding_build/mod.rs:422`) without resolving,
  `retry_pending_neigh` records `(egress_ifindex, next_hop)` in the
  per-binding negative cache (`neighbor_dispatch.rs:120-126`,
  `neg_neigh_record`), TTL `NEG_NEIGH_TTL_NS` = **3s**
  (`mod.rs:360`).
- Every subsequent cold SYN to that dst hits the `MissingNeighbor` arm
  and runs `neg_neigh_gate` **first** (`poll_descriptor/mod.rs:2038`).
  The gate fast-fails (recycle + `continue`, `:2053-2062`) UNLESS
  `is_resolved()` finds the entry in `state.neighbors` OR
  `dynamic_neighbors` (`:2042-2051`).
- **Critical:** the fast-fail `continue` happens BEFORE the ARP/NDP
  probe site (`:2097-2116`) and BEFORE the `pending_neigh` buffer
  (`:2341`). So while the negative entry is live, **no new ARP probe is
  ever fired** for that dst, and the packet is never buffered/retried.
- The SYN storm (12 parallel streams retransmitting) re-enters the
  blackout repeatedly: after each 3s TTL lapses, one buffered SYN
  re-probes, times out again (kernel lladdr never read), and re-arms a
  fresh 3s negative entry → repeated blackout *cycles*.

  **Codex r1 correction (accepted):** the cache is NOT refreshed on a
  fast-fail *hit* (`neg_neigh_active` only checks/evicts by TTL,
  `neg_neigh.rs:45-47`; `neg_neigh_record` runs ONLY on a real timeout,
  `neighbor_dispatch.rs:110,121`). So "self-sustaining / continuous
  refresh before expiry" is OVERSTATED — it is repeated 3s blackout
  cycles, not a never-lapsing entry. Candidate fix (iii) "don't refresh
  on hit" is a no-op (already true).

So once `dynamic_neighbors` loses (or never had) the entry AND the
negative cache is primed, in each blackout window the dataplane will:
- never re-probe (gate short-circuits before the probe),
- never buffer/retry (gate short-circuits before the buffer),
- re-arm the 3s blackout on the next timeout cycle, and
- only `is_resolved()` returning true can break the loop — which
  requires an **external** `RTM_NEWNEIGH` or an **inbound** packet from
  the dst. For an outbound-only iperf target on a directly-connected
  VLAN, neither is guaranteed; the only thing that broke it live was the
  kernel independently re-validating the neighbor and emitting a fresh
  `RTM_NEWNEIGH` minutes later.

### How `dynamic_neighbors` loses the entry in the first place

Two non-exclusive mechanisms, both to be confirmed/refined by Codex:

(a) **Transient FAILED/INCOMPLETE during kernel revalidation.**
`parse_neighbor_msg` treats `NUD_INCOMPLETE (0x01)` and
`NUD_FAILED (0x20)` on `RTM_NEWNEIGH` as REMOVE
(`neighbor.rs:344-358`), and `RTM_DELNEIGH (29)` as REMOVE (`:359`).
During kernel GC / a failed PROBE the kernel can momentarily emit
FAILED/INCOMPLETE or DELNEIGH, which deletes the dataplane entry. If the
kernel then re-resolves to DELAY/REACHABLE, that good `RTM_NEWNEIGH`
must be received to re-populate — and:

(b) **Dropped notification.** The monitor's steady-state loop swallows
`recv() <= 0` (`neighbor.rs:630-632`) and the full dump is **startup
only** (`initial_neighbor_dump` runs once, `:616`). #1658 added a 4 MiB
rcvbuf to reduce overflow, but ENOBUFS is still possible under a failover
/ churn burst and is silently ignored — a single dropped good
`RTM_NEWNEIGH` after a transient remove leaves `dynamic_neighbors`
permanently desynced from the kernel until the next event for that key.

The combination (a)+(b)+(self-sustaining negative cache) explains the
"25 clean runs then stuck, no restart, self-heals minutes later"
signature exactly.

## 3. Evidence captured (live, this session)

- Reproduced: at issue-file time the hang was live with the kernel in
  `DELAY`. By the time this session started, `ip neigh` showed
  `172.16.80.200 ... REACHABLE` and iperf3 `-P12 5208` PASSED (23.3
  Gbit/s, all 12 streams, 0 dropped) with **`NRestarts=0`** — i.e. the
  stuck state self-recovered with NO daemon restart when the kernel
  re-validated the neighbor (REACHABLE/STALE both forward fine).
- Re-confirmed post-recovery: v4 `-P12` 20.8 Gbit/s, v6 `-P4` 22.6
  Gbit/s. Current `ip neigh` shows the dst `STALE` and forwarding works
  — proving STALE is usable on the TX path and the hang is specific to
  the dataplane LACKING the entry, not to the kernel NUD state per se.
- `curl :8080/metrics | grep neigh` → only the two warm counters, both
  0. Confirms the observability gap.

## 4. What recovered it / restore status

No intervention was needed to restore service this session — the kernel
re-validated the neighbor (DELAY→REACHABLE→STALE) and emitted a fresh
`RTM_NEWNEIGH` that re-populated `dynamic_neighbors`, which made
`is_resolved()` true and evicted the negative entry on the next SYN. The
cluster is LEFT WORKING (v4+v6 iperf3 pass). For an operator stuck in
this state, the deterministic recoveries are: `ip neigh flush dev
ge-0-0-2.80` (forces re-resolution + RTM events), `systemctl restart
xpfd` (re-runs `initial_neighbor_dump`), or simply waiting one kernel
revalidation cycle. The redesign must remove the dependency on luck.

## 5. Code map (for the review)

- `userspace-dp/src/afxdp/neighbor.rs` — netlink monitor thread,
  `parse_neighbor_msg`, `initial_neighbor_dump`, `add_kernel_neighbor`,
  `trigger_kernel_arp_probe`, warmer loop, rcvbuf tuning.
- `userspace-dp/src/afxdp/neighbor_dispatch.rs` — `retry_pending_neigh`,
  `learn_dynamic_neighbor*`, probe schedule.
- `userspace-dp/src/afxdp/neg_neigh.rs` — negative cache + gate.
- `userspace-dp/src/afxdp/poll_descriptor/mod.rs:2012-2377` — the
  `MissingNeighbor` arm (gate → probe → session seed → buffer).
- `userspace-dp/src/afxdp/forwarding/mod.rs:1529` —
  `lookup_neighbor_entry` (snapshot then dynamic, no on-demand kernel
  read).
- `userspace-dp/src/afxdp/mod.rs:329-366` — timing constants.
- `userspace-dp/src/afxdp/sharded_neighbor.rs` — `dynamic_neighbors`.

## 6. The defects (to be hostile-reviewed)

D1. **Negative-cache short-circuits re-probing AND re-buffering** — the
gate `continue` is upstream of the probe and the buffer, so a primed
negative entry guarantees the dst is never nudged toward resolution
again. (`poll_descriptor/mod.rs:2053-2062` vs probe `:2097`, buffer
`:2341`.)

D2. **Negative cache is self-sustaining under storm** — re-recording on
each timeout + 3s TTL with storm interval << TTL means the suppression
never lapses while traffic continues. The "≤ one TTL window" claim in
the constant comment (`mod.rs:355`) is false under sustained retry.

D3. **No on-demand kernel lladdr read on miss** — `lookup_neighbor_entry`
refuses to consult the kernel (`:1544`). The kernel's known lladdr in
DELAY/STALE is unusable to the dataplane until an async event happens to
deliver it.

D4. **Silent netlink desync** — steady-state loop swallows `recv()<=0`
incl. ENOBUFS (`neighbor.rs:630`); full dump is startup-only; no
periodic re-sync; no drop counter. A single missed good RTM_NEWNEIGH
after a transient remove is permanent until the next per-key event.

D5. **Transient FAILED/INCOMPLETE/DELNEIGH deletes a usable entry** —
`parse_neighbor_msg` removes on FAILED/INCOMPLETE/DELNEIGH
(`:351-359`) with no grace/regrace, so a momentary kernel hiccup during
revalidation can drop a neighbor the kernel still effectively has.

D6. **Observability gap** — `neg_neigh_fast_fail` and `missing_neigh`
are incremented only in the debug telemetry struct
(`poll_descriptor:2054, 2013`), never exported to Prometheus; pending
depth, resolution timeouts, netlink drops, and negative-cache size are
not exported at all. (Go side: `pkg/dataplane/userspace/protocol.go`
exports only `SlowPathMissingNeighborPackets`.)

D7. **rtnl churn** — earlier profiling: `learn_dynamic_neighbor_from_packet`
+ `retry_pending_neigh` churn rtnl at steady state (probe re-fires +
per-packet learn). To be quantified and folded into the redesign.

## 7. Adversarial review (Codex lead) — open questions

- Is D1+D2 sufficient alone to wedge, or is the lost dynamic entry (D4/D5)
  a required precondition? (Trace a SYN with each combination.)
- Is the negative cache even the right primitive here vs. a bounded
  pending queue with backpressure? (#1651 motivation was dead-host SYN
  storm starvation — does the redesign preserve that defense?)
- Can `add_kernel_neighbor` / an on-demand `RTM_GETNEIGH` for a single
  key safely run off-hot-path to pull the kernel's current lladdr?
- Is a periodic targeted re-dump (or per-miss single-key GETNEIGH) cheap
  enough vs. the rtnl-churn concern (D7)?
- Race correctness of any "read kernel lladdr in DELAY/STALE and use it"
  change vs. the existing FAILED/INCOMPLETE remove semantics.

## 8. Redesign (Codex architect; AGY + Claude SMR converge)

To be authored by Codex. Must cover, at minimum:
- First-packet resolution that USES the kernel's lladdr when present
  (DELAY/STALE/PROBE) instead of holding — e.g. single-key on-demand
  `RTM_GETNEIGH` off the hot path, or an async resolver task keyed by the
  pending dst.
- Negative cache that cannot self-sustain under storm and never
  suppresses the re-probe path (decouple "don't buffer N copies" from
  "stop trying to resolve").
- pending_neigh lifecycle: bounded (have 4096), guaranteed drain, no
  leak across flow churn, fair under burst.
- retry/timeout with backoff that keeps nudging resolution.
- netlink mirror correctness: ENOBUFS detection + periodic/triggered
  re-dump + drop counter; grace handling of transient FAILED/DELNEIGH.
- counters: pending depth (gauge), resolution failures/timeouts, retry
  rate, negative-cache size, netlink drops, fast-fail count — exported
  to Prometheus.

## 9. IMMEDIATE stuck-state fix (separable, `/engineer 1769`)

Smallest change that removes the wedge without the full redesign.

**Codex r1 recommendation (lead architect, accepted):** the minimal
correct fix is a **targeted single-key `RTM_GETNEIGH`** on negative
fast-fail, rate-limited per `(ifindex, next_hop)`, that re-populates
`dynamic_neighbors` if the kernel returns a usable lladdr (anything
except FAILED/INCOMPLETE — matches existing usable-state policy
`forwarding/mod.rs:45`, `neighbor.rs:346`); plus fire the existing
ARP/NDP probe on a GET miss/unusable. Rationale:
- It directly attacks the strongest failure mode "kernel knows the
  lladdr, the userspace mirror does not" — which probe-only does NOT
  fix, because the TTL already reopens a probe window each cycle yet the
  dst stayed wedged live.
- It preserves the #1651 dead-host storm defense: packets still
  fast-fail (no `pending_neigh` slot consumed); only an off-hot-path,
  rate-limited GET is added.
- Candidate (iii) "don't refresh on hit" is dropped — Codex confirmed
  it's already true (`neg_neigh` not refreshed on hits).

Probe-only (candidate i alone) is smaller but weaker and was REJECTED by
Codex as insufficient for the observed live failure. The GET must run
off the hot path (e.g. queued to the existing warmer/resolver thread or
a dedicated single-key resolver), never inline in the worker poll loop.

## 10a. Codex r1 redesign refinements (lead architect, accepted)

Per-key neighbor **resolver state machine**, not packet-buffering alone:
- Lookup order unchanged (snapshot → dynamic), but a miss
  creates/updates per-key resolver state for `(egress_ifindex,
  next_hop)` (`forwarding/mod.rs:1535,1541`).
- Negative policy becomes "do not buffer duplicate SYNs", NOT "stop
  resolution": a negative-active key may drop duplicate packets, but the
  resolver GET/probe/backoff keeps running.
- Pending queue bounded per-key (one representative packet per key) under
  a fair global cap; today it admits every packet up to 4096
  (`poll_descriptor/mod.rs:2341`, `mod.rs:342`).
- Backoff coalesces all packet pressure into ONE in-flight GET/probe per
  key; today retry dedups probes only within a single sweep
  (`neighbor_dispatch.rs:81,152`).
- Netlink mirror: detect `recv` errors, count ENOBUFS, trigger
  full/targeted re-dump — startup-only dump + multicast is insufficient
  (`neighbor.rs:616,629`).
- Removal grace: a transient FAILED/INCOMPLETE marks the entry suspect
  and forces a GET/probe BEFORE deleting a previously usable lladdr;
  DELNEIGH removes immediately unless a same-key GET says usable.
- Export counters (Prometheus): pending depth, negative-cache size,
  fast-fail, resolver GET/probe attempts, timeouts, successful
  kernel-lladdr pulls, netlink ENOBUFS/dumps. Today only warm
  drops/disconnects are exported (`pkg/api/metrics_descriptors.go:782,788`);
  `neg_neigh_fast_fail` is debug-only (`types/runtime.rs:256`).

**Codex r1 correction (D7, accepted):** the "rtnl churn" wording was
imprecise — `retry_pending_neigh` fires ICMP sockets, not rtnl
(`neighbor.rs:36`, `neighbor_dispatch.rs:166`);
`learn_dynamic_neighbor_from_packet` only updates the in-memory map
(`neighbor_dispatch.rs:325,356`); the only rtnl WRITE path is
`add_kernel_neighbor` (`neighbor.rs:211,255`). The redesign's new
single-key GET adds rtnl traffic, so it MUST be rate-limited per key.

## 11. Verdict

- **Codex r1 (lead): PLAN-READY**, with conditions: fix the D2 wording,
  make targeted single-key `RTM_GETNEIGH` the immediate fix, preserve
  dead-host duplicate dropping, make ENOBUFS/re-dump/counters first-class
  in the redesign. (All folded into §2, §9, §10a above.)
- **AGY:** _pending._
- **Claude SMR:** _pending._

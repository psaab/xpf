# HA Failover Status

Date: 2026-05-21 (updated)

This is the single authoritative document for userspace dataplane HA failover.
It replaces the fragmented state across a dozen prior docs. Read this first;
refer to the others only for implementation-level detail.

## Goal

Failover should be:

1. VRRP moves the virtual MAC
2. New owner sends GARP/NA
3. Traffic continues forwarding through synced sessions

No activation-time repair, no re-resolution, no queue bring-up, no barrier
choreography. Sessions are synced continuously — the standby should already
be able to forward.

## Current Reality

The system is closer to this goal than it has ever been, but it is not there
yet. Here is what is true today:

- Sessions sync continuously via event stream (real-time) + bulk (startup)
- Synced sessions are resolved with local egress on receipt (#326), not at
  activation time
- Flow cache uses epoch-based invalidation (#327) — no transition-time scans
- Demotion is a single `update_ha_state(active=false)` call (#359) — no
  two-phase prepare + demote
- Activation is a single `update_ha_state(active=true)` call (#358) — no
  explicit refresh RPC
- Manual failover uses request/ack/commit protocol (PRs #395-#397) — not
  weight-zero heuristics
- Takeover readiness gates on proven userspace dataplane health (#391): the
  control socket + ping, forwarding armed, XSK liveness, session mirror health,
  AND — since #5273 — the local event-stream listener being bound
  (`EventStream.ListenerBound()`). The listener is the primary local
  helper-to-daemon push path feeding the peer-sync pipeline, so a node whose
  `net.Listen` failed to bind is denied takeover readiness rather than silently
  starting in the slower `DrainSessionDeltas` polling fallback. The gate keys on
  the listener being UP, not on the local helper currently being connected;
  transient stream disconnects are covered by polling
- The takeover readiness gate applies on COLD BOOT, not only when the peer is
  alive (#7161). `electSingleNode` previously gated on `m.peerAlive`, so the
  gate was fully enforced on the peer-alive path and fully bypassed on the
  peer-dead path — which is the path both a cold boot and a peer loss take. The
  condition is now `(m.peerAlive || !m.peerEverSeen)`:
  - **peer LOSS** (`peerEverSeen && !peerAlive`) keeps the fail-open. An
    established cluster had a working primary and it died; a survivor that
    refuses takeover is a TOTAL OUTAGE and may be the only node that can
    forward.
  - **cold BOOT** (`!peerEverSeen`) applies the gate. There is no established
    forwarding to preserve, and a not-ready node that promotes forwards nothing
    anyway — it claims the VIPs and the RG while unable to serve them, and
    denies the peer a clean takeover. This is #103 acceptance criterion 1.

  **POLICY CHANGE, declared:** a userspace-configured data RG with no published
  dataplane fail-closes in `checkUserspaceTakeoverReadinessFor`, so on a cold
  boot it now stays SECONDARY where it previously promoted. It forwards nothing
  either way; the difference is that it now says so instead of advertising
  itself primary for traffic it cannot carry.

  The prior in-code rationale ("sync readiness is impossible without a peer")
  was stale and has been replaced rather than narrowed: sync readiness is not a
  term in that conjunction at all. `IsReadyForTakeover` consults local
  interfaces, local VRRP and the local userspace dataplane — all determinable
  with no peer — and `fabricReady` is already forced true when the peer is down.

  **Degraded-promotion fallback** (`DefaultDegradedPromoteTimeout`, 2 min): after
  that much CONTINUOUS not-readiness a single node promotes anyway, with the
  reason surfaced on the election event and `DegradedPromoted` set, so a
  readiness bug can never cost the cluster both nodes. Two properties are
  load-bearing and are pinned by tests:
  - it is gated on NO peer condition — not `peerAlive`, not `peerEverSeen`, not
    sync connectivity. #110 shows the failure mode: `armSyncReadyTimer`'s
    callback bails on `!d.syncPeerConnected`, so its fallback never fires in
    exactly the peer-absent case it was written for. A fallback whose firing
    depends on the condition it compensates for is not a fallback.
  - it is armed at the DECLINE SITE in `electSingleNode`, not in `SetRGReady`. A
    cold-boot RG starts not-ready and may never see a readiness TRANSITION, so
    arming from the transition branch would leave it unarmed in precisely the
    case it exists for.
- Bounded startup promotion hold for `no-reth-vrrp` / `private-rg-election`
  (#7162). RETH VRRP mode has suppressed startup preemption since #466
  (`vrrp.Manager.SetSyncHold`, 30s, armed once at bringup, released by bulk
  session sync or its own timer). These modes had no equivalent —
  `checkNoRethTakeoverReadiness` was VIP ownership and nothing else — so a node
  could promote an RG before bulk sync delivered any conntrack/NAT state and
  every established flow reset on the transition.

  `Daemon.armNoRethSyncHold` (`pkg/daemon/daemon_ha_noreth_hold.go`) is the
  sibling: same 30s bound, armed at the same bringup site, consulted by
  `checkNoRethTakeoverReadiness`, released by bulk sync
  (`bulk-sync-complete`) or its own timer (`timeout-degraded`).

  **It is a bounded HOLD, not a `cluster.IsSyncReady()` conjunct, and the
  difference is the whole of #110.** `syncReady` has no bound while the
  session-sync channel is down (`armSyncReadyTimer` early-returns unless
  `syncPeerConnected`), and the election blocks a not-ready RG whenever the peer
  is alive — so a sync-flag conjunct blocks promotion INDEFINITELY when the peer
  is up on the control link with session sync down, which is exactly the
  degraded-peer case preemption exists for. Two properties keep this one
  bounded, and both are pinned by tests:
  - the timer callback consults NO peer condition — not `syncPeerConnected`, not
    `peerAlive`, not `IsSyncReady()`. A release that depended on the peer would
    be no release at all, because the peer being absent is why the hold is still
    held.
  - it is armed EXACTLY ONCE at bringup and never re-armed on reconnect, which
    keeps it a startup hold rather than a mid-life block.

  Releasing the hold DRIVES a reconcile (`triggerReconcile`). Readiness is
  recomputed per reconcile pass, so without that the RG would sit secondary until
  an unrelated event happened to trigger one — bounded in name only. The RETH
  sibling meets the same obligation with `triggerPreemptNow()`.

  **Deploy-tooling coupling (#7962).** `cluster-deploy`'s post-deploy primary
  reassert waits on this fallback, because on an idle cluster it is the only
  path to convergence: XSK liveness cannot self-prove on a node holding a data
  RG (`shouldAutoProveIdleStandbyXSKLocked` requires `!hasActiveDataRGLocked()`,
  and node0 holds RG1), and nothing is driving traffic. The reassert's budget
  was 30s against a 120s fallback, so it failed **by construction** on a
  restarted idle cluster — and both its passes and its failures were timing
  artifacts, indistinguishable from an HA regression in whatever branch happened
  to deploy next (#7688, #7939).

  The reassert now (a) PRIMES liveness with a little LAN→WAN traffic, which is
  what an operator does by hand and converges the common case in seconds rather
  than waiting out the fallback, and (b) falls back to a budget derived from
  `DefaultDegradedPromoteTimeout` only when priming was impossible — so a
  failing deploy is not routinely slower. `DEPLOY_REASSERT_FALLBACK_BUDGET_S`
  (`test/incus/deploy-lib.sh`) and this constant are coupled by
  `TestDeployReassertBudgetExceedsDegradedFallback7962`, which reads the shell
  default and fails if either side moves such that the budget stops covering the
  fallback.

  Its failure message now distinguishes the two states it used to crush into
  one: *traffic was driven and the dataplane still did not prove liveness* (a
  real signal) versus *traffic could not be driven, so the precondition was
  absent* (not an HA regression).

  Interaction with #7161: on a cold boot the readiness gate now applies, so the
  hold and the gate compose — the node holds secondary for the hold window, then
  promotes when readiness recomputes. The #7161 degraded-promotion fallback
  (2 min) is a strictly longer backstop, so the 30s hold is the binding
  constraint.

  **Observability:** `show chassis cluster information` gains a
  `Startup promotion hold:` block reporting the mode (`reth-vrrp` / `no-reth`),
  whether it is still holding, and how it ended. The RETH hold had recorded
  `bulk-sync-complete` / `timeout-degraded` since #466 and surfaced it NOWHERE,
  so an operator could not distinguish a normal startup from one that promoted
  degraded because sync never arrived — which is precisely the explanation for a
  flow reset after a boot. While the hold is active it also appears in the RG's
  `Takeover ready: no (...)` reasons.
- A manual failover into a node inside its startup promotion hold no longer
  leaves the RG owned by NEITHER node (#9452). `request chassis cluster failover
  redundancy-group N` demotes the local primary immediately; the peer's promotion
  then went through the bare readiness gate, so a request issued inside the
  bounded #7162 30s hold on a just-rejoined node was DEFERRED rather than
  refused — for 19s on the reproduction, up to the full 30s — with the CLI having
  already reported `Manual failover triggered`. Measured consequences in one
  `make test-failover` run: fw0 primary for none of RG0/1/2 at the check, and
  `ip neigh show proxy` EMPTY on both nodes for the pool-NAT address.

  The iperf3 average in the same run also fell from 22.5 to 18.1 Gbit/s, and that
  is a SEPARATE signal despite how well the arithmetic fits (~20-25s of a 120s
  stream carrying nothing). The fix refuted it: with the ownership gap closed to
  0-1s, two consecutive runs came back at 18.9 and 20.3, against
  `make harness-compare GATE=test-failover`'s `[21.375, 23.625]` green band — so
  closing the gap bought far less than the theory predicted, and the spread
  between two identical runs is a third of what is left. Tracked as #9484.

  The gate now has the third case it was missing, beside peer LOSS and cold
  BOOT: a peer that is ALIVE and reports NON-OWNERSHIP — `secondary-hold` (an
  explicit transfer-out) or weight 0 (a resignation, which election forces to
  secondary unconditionally). That case fails OPEN like peer loss, because the
  cold-boot argument does not apply (there IS established forwarding and it stops
  when the peer steps down) and there is no split-brain to weigh against it (the
  peer is not claiming the RG). A peer that is merely SECONDARY with weight > 0
  still HOLDS — that is the cold-boot shape. The promotion is marked
  `DegradedPromoted` and names its reason in the RG event history.

  **The 30s hold is in contract and was not changed.**
  `daemon_ha_noreth_hold.go` states it releases on its own timer regardless of
  sync or peer state, so this was never a hold-duration bug: with perfect NTP and
  a fast bulk sync, a manual failover within 30s of a peer restart still
  blackholed the RG.

  `test/incus/test-failover.sh` also stopped hiding the difference. The
  assertion was a fixed `sleep 5` plus a boolean, which cannot tell a REFUSED
  transfer from one still in flight — and lengthening the sleep would have
  reported a 30s blackhole as a pass. It is now a bounded poll that reports the
  elapsed seconds per RG, its failure text carries `rg_ownership_diagnosis`
  (both nodes' `Takeover ready:` / `Transfer ready:` / `Forwarding:` lines, the
  peer's view, and the election journal tail), and the `request` command's stderr
  is captured instead of discarded. Note which readiness term was false: on #9452
  `Transfer ready` was `yes` on both nodes for all three RGs and `Takeover ready`
  was the blocker, so a message carrying only the transfer-readiness reason would
  still have said nothing.
- Blackhole routes skipped in userspace mode (#354)
- Helper watchdog threshold aligned with sync cadence (#349)
- Reverse companions pre-installed via sync path (#310)
- BPF conntrack entries written for zone/interface display (fab9230c)
- Userspace counters aggregated into BPF global counters (#332)
- Shared sessions indexed by owner RG for O(1) demotion/activation (PRs
  #404-#406) — no full-table scans during failover
- Priority barrier channel for acks (PR #407) — barrier/bulk acks bypass
  session data in send queue
- Planned failover decoupled from bulk sync (PR #407) — barrier ack
  proves peer is current, no bulk-sync gate
- Transfer readiness surfaced separately from takeover readiness (PR #402)
- Manual/planned failover refuses a config-stale standby (#5563): transfer
  readiness now also gates on the config-sync generation. A standby that has
  received a newer config generation from the primary than it has successfully
  applied (`PeerConfigGen > AppliedConfigGen` in `TransferReadinessSnapshot`) is
  reported not transfer-ready, so `request chassis cluster failover` will not
  promote it onto a stale policy set (fail-open after a tightening commit,
  false-deny after a loosening one). A legitimate same-generation failover still
  proceeds; the unplanned/crash path is not gated. Surfaced in
  `show chassis cluster status` transfer-readiness reason as "standby config
  stale: applied gen=N behind peer committed gen=M"
- The untargeted failover, the batch form and `ForceSecondary` refuse a
  config-stale standby too (#9569). The #5563 gate above runs on the node that
  becomes primary, so only the node-targeted form reached it. The untargeted
  `request chassis cluster failover redundancy-group N` and the ISSU drain
  (`request system software in-service-upgrade`) demote the local node instead,
  and they now refuse while the standby's latest config-apply nack matches the
  newest generation this node sent. The error names the generation.
- (removed in #8573) HA configs that use per-pool source NAT `persistent-nat`
  used to be refused userspace forwarding entirely, on the #1449 reasoning that
  leases are helper-local and not HA-synchronized. Measured on the loss
  userspace cluster, they are synchronized; the disarm is gone. The residual is
  narrower and is described under "Persistent SNAT Lease Boundary"

## What Works

Manual failover with `request chassis cluster failover redundancy-group 1
node N` successfully moves RGs between nodes. Sessions are synced, SNAT is
applied on the new owner, traffic continues. Validated with iperf3 4-stream
tests showing 27M SNAT packets on the new owner after failover.

The key fixes that made this work:

| Commit | Fix |
|--------|-----|
| ba1c4304 | Async bulk ack + HA sync throttle — bulk sync completes reliably |
| 7417144e | Re-resolve synced sessions with owner_rg_id=0 |
| 71b80b3d | refresh_for_ha_activation bypasses synced guard — SNAT works |
| a21018f3 | Epoch flow cache, resolve on receipt, owner_rg_id at sender |
| dcc59c67 | Unified synced flag → origin-based collision detection |
| PRs #395-397 | Explicit RG transfer protocol (request/ack/commit) |
| PRs #404-406 | Owner RG indexes — O(1) demotion/activation |
| PR #407 | Priority barrier channel + decouple failover from bulk sync |

### Failover command/action grammar — one strict parser (#5810, #5851)

The manual-failover command and its wire action string are validated by a
single, side-effect-free grammar in `pkg/clusterfailover`. Every entry point —
the remote CLI (`cmd/cli/request.go`), the in-process CLI
(`pkg/cli/cli_request_chassis.go`), the gRPC loopback handler
(`pkg/grpcapi/server_diag_system_action.go`), and the fabric-allowlist
interceptor (`pkg/grpcapi/server.go` `parseProxiedFailoverAction`) — routes
through `clusterfailover.ParseCommand` (operator tokens) or
`clusterfailover.ParseAction` (wire string) and acts on the SAME typed
operation. Callers never assemble or partially parse the privileged action
string ad hoc.

The grammar is closed. Exactly four forms are accepted:

| Operation | Command | Wire action |
|-----------|---------|-------------|
| Plain RG failover (untargeted) | `redundancy-group <rg>` | `cluster-failover:<rg>` |
| Targeted RG failover | `redundancy-group <rg> node <0\|1>` | `cluster-failover:<rg>:node<0\|1>` |
| Data failover | `data node <0\|1>` | `cluster-failover-data:node<0\|1>` |
| Reset | `reset redundancy-group <rg>` | `cluster-failover-reset:<rg>` |

`<rg>` is a non-negative decimal group ID; `<0|1>` is a supported chassis node.
Unknown, missing, misspelled, duplicate, signed, whitespace-laden, or trailing
tokens — and an empty `:node` suffix — are rejected with usage/`InvalidArgument`
BEFORE any cluster method or peer dial. This closes the class where a truncated
automation variable or a typo (`redundancy-group 1 nod 0`, `redundancy-group 1
node`, or the gRPC `cluster-failover:1:node`) silently degraded to the broader
untargeted `ManualFailover(<rg>)`, moving ownership in an unintended direction.

The loopback handler and the fabric interceptor now share this parser, so they
can never disagree on which action strings are well-formed. The fabric gate may
still deny a valid but local-only form (plain RG failover, reset) by policy —
only the two node-targeted forms are proxyable — but that denial is a policy
choice, never a divergent parse. Shared accept/reject token-vector tables live
in `pkg/clusterfailover/grammarvectors` and are exercised by all four layers'
tests so the verdicts cannot drift.

## Persistent SNAT Lease Boundary

**#8573: the admission boundary is LIFTED.** A chassis cluster whose source-NAT
rules reference a pool with `persistent-nat` now forwards. The gate that refused
it, and the reason string it reported —

```
userspace persistent-nat source pool leases are not HA-synchronized
```

— are both deleted, along with the #8447 commit advisory that announced them.

### Why it was there, and why it is not

#1449 closed as an admission boundary rather than partial lease replay: leases
were held to be helper-local allocator state that the helper does not
synchronize or replay to the peer, so the dataplane declined to forward rather
than forward with semantics it could not honour. #8447 then found that the
refusal was *silent* — the interfaces stay up, the config commits cleanly, and
the failure presents as a connectivity problem rather than a NAT one — and made
it visible at commit, at disarm, and as a metric.

What neither could do was check the premise, because the gate disarmed the
forwarding a check would have needed. #8573 was filed to unblock exactly that,
and the answer is that the premise had stopped being true. Three sync routes had
landed underneath it (#7360, #8132, #8121 — the census below), and their
exhaustiveness is bound by a test rather than left in prose.

**Measured on the loss userspace cluster, with the gate lifted on both nodes**
and a rule-referenced `persistent-nat` pool committed:

| | result |
|---|---|
| both nodes armed | `FWDD State Online`, pool SNAT allocating sequentially into the pool range |
| lease reaches the standby | identical identity on both nodes — same source tuple, same translated address and port, same pool |
| lease survives failover | present on both nodes after a manual RG0 failover |
| lease is HONOURED after failback | node1 allocated a translated identity; node0 imported it with the remaining timeout intact; after failback node0 translated the SAME source identity to the SAME translated identity node1 had chosen |

The last row is the whole of what persistent NAT promises, and it is the one a
lease that merely *arrived* would not satisfy.

### What the residuals are

Two, and both mean "this particular lease did not reach the standby" — never
"the standby forwards with semantics it cannot honour".

**The sync window.** A lease created on the active in the interval before the
next export/import cycle is not yet on the standby, so a failover inside that
window drops it — the flow gets a fresh translated identity instead of its
pinned one. That is a much narrower statement than "not HA-synchronized", and
it is the same window every other synced object lives with.

**A refused import.** A lease whose pool address the standby's config lacks,
whose port bit is already held there, or that arrived already expired, is
refused by design (#8121). Each refusal is correct: the standby mints its own
translation rather than install a duplicate or a wrong translated identity. The
helper logs one line per import BATCH naming the refusal classes —

```
xpf-dp: idle-lease import installed=N existing=N expired=N unknown_addr=N unknown_pool=N port_busy=N malformed=N
```

— and #8573 widened that line's trigger to fire on `unknown_addr` too. That is
the class meaning the two nodes disagree about a pool's address list, and it
previously logged NOTHING: a batch in which every lease was refused for it was
silent. That mattered less while the gate refused to forward these configs at
all; with the gate lifted it is the residual's main surface.

The other surface is the existing per-pool persistent-lease counters
(`show security nat source persistent-nat-table detail`, and the pool status table's
lease counts), which are per-node: comparing the two nodes shows whether the
standby is tracking the active. They are the right surface for a post-lift
world precisely because they are a *quantity to compare*, where the removed
reason string was a verdict with no gradations — it could say only "refused",
never "behind by three leases".

### What this does NOT say: pool-mode return traffic is separately broken

The gate is lifted on the strength of the LEASE measurement, and that
measurement was read from the session table and the persistent-NAT lease tables
on both nodes — deliberately not from throughput, because pool-mode source-NAT
return traffic on this cluster does not work at all, with or without
`persistent-nat`.

That is **#8621**, a different defect, and it is not attributable to this one:
it reproduces with `persistent-nat` removed from the pool, while interface-mode
SNAT from the same host to the same target got 7.44 Gbit/s at the same moment.
Root cause is a kernel proxy-ARP arm the pool address cannot reach — `ip route
get` for the pool address returns the egress interface itself, and all three
arms of `arp_process`'s proxy branch are gated on the route's device differing
from the ingress device — so the firewall never answers ARP for the pool
address and no return frame is ever addressed to it.

The distinction matters to an operator reading this section: **"HA persistent-NAT
is supported" is a statement about lease survival across a failover, not a
statement that pool-mode SNAT forwards end to end today.** Both are needed for
the feature to be usable, they are independent, and only the first is what
#8573 measured.

### What the operator sees now

Nothing. The configuration commits and forwards, which is the point. The
disarm machinery #8447 built is unchanged and still live for the capability
reasons that remain (a color-aware three-color policer, a SYN-cookie screen
profile with no root-authentication material): the WARN at disarm and
`xpf_dataplane_forwarding_supported` are both untouched, and are more
load-bearing now that a disarm is a rarer event an operator is even less likely
to be looking for.

The predicate `config.UsesPersistentSourceNATPool` SURVIVES the removal. It no
longer gates forwarding, but `ensurePersistentSourceNATProtocolLocked` reads it
to raise the required helper protocol version to
`MinProtocolPersistentSourceNAT` — so a wrong answer still ships persistent-NAT
config to a helper that cannot honour it. It stays keyed on the **rule**, not
the pool table: a `persistent-nat` pool no rule references translates nothing.

### What the standby DOES rebuild today (#7360, #8132, #8121)

This is the census the lift above rests on. The standby does not hold nothing —
it reconstructs a lease for every persistent session it imports, and receives
the idle ones explicitly.

**Reconstruction, not replay.** A lease is a property of the SOURCE; session
sync carries SESSIONS. So the standby does not receive leases — it derives them
from the imports that actually succeeded, in `reserve_synced_on_first_pool_owner`
(`userspace-dp/src/nat/source/synced.rs`). Deriving rather than carrying is the
load-bearing choice: the standby installs a strict subset of what the active
sends (reserve refusal, capacity, stale generation, discriminator withhold), so
a carried `active_flows` would credit the lease for sessions this node does not
hold — and a refcount that never reaches zero is never idle, so the lease would
never enter the expiry index and no GC path could reclaim it.

There are two reserve paths, and they needed separate fixes because they are
separate functions:

| path | selected by | reserve | fixed in |
|---|---|---|---|
| port-translating (PAT) | a translated port on the wire | `reserve_flow_maybe_persistent` | #7360 |
| address-only | `port no-translation`, or a port-less protocol (GRE/ESP/…) | `reserve_address_only_maybe_persistent` | #8132 |

**The two paths pin different things, and that changes what can fail.** Under
PAT the lease pins a `(address, port)` and the PORT is the fragile half — with
`address-persistent` the address survives a failover for free, because
`sticky_pool_index` is a pure function of `(src_ip, pool_len)` and both nodes
compute it. Under `port no-translation` the client keeps its own source port on
the wire, so there is no translated port at all: the lease pins an ADDRESS, and
the address is the whole promise. A test that asserts the address while
`address-persistent` is on measures the hash rather than the repair, which is
why the cells for both live on multi-address pools with that flag OFF and decoy
flows interleaved.

**The IDLE lease is rebuilt too, by a different route.** A lease whose flows
have all closed but whose inactivity window is still open has no session to be
derived from, so nothing above reaches it. #8121's `export_idle_leases` /
`import_idle_leases` verbs carry that population explicitly, and the chain is
wired end to end — allocator verbs, control handler, Go manager, cluster sync
payload, daemon hook — with the wire pinned across the two languages
(`idle_lease_wire` in `protocol_wire_v1.json`).

### The population is now claimed COMPLETE, and the claim is bound

Three routes, and between them every lease an active node holds:

| lease | route to the standby |
|---|---|
| has live flows, port-translating | rebuilt from the synced sessions (#7360) |
| has live flows, address-only | rebuilt from the synced sessions (#8132) |
| idle, inside its timeout | exported and imported (#8121) |

That is an exhaustiveness claim, and defining a population by a mechanism is a
CLAIM that the mechanism is the only route — which fails silently when a sixth
site appears that nobody classifies. So it is not left in prose:
`every_persistent_lease_creation_site_has_a_sync_route_8121` pins the five
production sites that create a lease, by enclosing function, and reds until a
new one is classified. It carries a positive control, because a scanner whose
pattern has rotted compares empty to empty and passes forever.

**What this bears on.** This census was written as an argument that the #1449
gate's stated reason no longer described the tree, deliberately stopping short
of re-deciding the gate — re-arming forwarding for a disarmed configuration
class is a user-facing availability change needing its own verification, not a
side effect of the work that removed its premise. #8573 ran that verification
and removed the gate.

The census is therefore no longer an argument *against* a gate. It is what holds
the gate's removal up, and its failure mode inverted with it: a sixth
unclassified insert site used to mean an argument was overstated, and now means
clustered persistent-NAT is forwarding with leases that do not survive a
failover. `every_persistent_lease_creation_site_has_a_sync_route_8121` is the
thing standing between those two states.

## What Was Fixed Recently

### P0: Barrier delivery during bulk sync — FIXED (PR #407)

Barrier acks and bulk acks now route through a dedicated priority channel
(`barrierCh`). The `sendLoop` drains `barrierCh` before `sendCh`, so acks
are never stuck behind bulk session data. Barrier requests still go through
`sendCh` to preserve ordering (the barrier must be after all queued sessions
so the ack proves the peer processed them).

### P2: Manual failover rejected during bulk sync — FIXED (PR #407)

Removed `syncPeerBulkPrimed` and `TransferReadiness` bulk-state checks from
the planned failover path. The barrier ack alone proves the peer is current.
Bulk sync is a startup concern, not a failover concern.

### P3: Split-RG readiness stuck — LIKELY FIXED

Root cause was barrier/bulk ack delivery stuck behind bulk data (P0). With
priority ack channel, acks should deliver promptly. Needs live validation
on split-RG cluster.

## What Still Needs Work

### Inherited translated tuples resolve as HA-inactive (was P1)

After failover, some inherited forward-wire tuples (translated 5-tuples
from SNAT) may resolve as `HAInactive` on the new owner. PRs #404-406
added owner RG indexes to shared session stores, which should improve
the lookup path. Needs live validation to confirm the fix.

**Status:** Likely improved, needs testing.

### Live validation of all fixes

The recent changes (priority barrier channel, owner RG indexes, planned
failover decoupled from bulk sync) have not been validated together with
a live `/failover-test` run. The individual pieces are tested but the
end-to-end flow needs validation.

### Throughput parity on fabric redirect path

When traffic is fabric-redirected (old owner → new owner via fabric link),
throughput is ~7 Gbps vs 15-17 Gbps for direct forwarding. This is a
hardware/topology limitation — fabric redirect adds an extra hop through
the virtio fabric interface. Traffic should converge to direct forwarding
on the new owner quickly.

## Architecture

### Session Sync Flow

```
Active node:
  helper creates session → event stream → daemon → session sync TCP → peer

Standby node:
  session sync TCP → daemon → SetClusterSyncedSessionV4 → helper UpsertSynced
  → resolve with local egress immediately (not at activation)
  → session is forwarding-ready in the helper's session table
```

#### Import refusals and the split-truth rollback (#6785)

The standby's install is transactional (#5305): the daemon snapshots the BPF
session row, writes it, mirrors to the helper, and RESTORES the snapshot if the
mirror fails — so a failed install never leaves a row for a session the helper
does not hold.

The helper can refuse an import for three SEMANTIC reasons, none of which are
faults:

| refusal | reason | issue |
|---|---|---|
| `stale-generation` | the stored entry is NEWER than the incoming one | #2170 |
| `capacity` | the aggregate synced-import entry ceiling is full | #5674 |
| `reserve` | the translated NAT tuple could not be reserved for this import | #6600 |

Before #6785 all three returned `ok = true`, so the daemon recorded a success
and left its BPF row behind — the exact split truth the transactional install
exists to prevent, on the one failure class it could not observe. The helper now
answers `ok = false` with a `synced-import-refused:<reason>` token, and the
existing rollback runs.

**A refusal is NOT a mirror failure, and the two must not be conflated.** A
transport failure means the helper session socket is sick and gates HA
takeover-readiness (#5247). A refusal comes from a HEALTHY helper answering
correctly — the peer sent something stale, or this node is at its own ceiling.
Gating takeover on a refusal would keep a working standby from ever taking over
once a peer oversubscribed it, which is worse than the divergence being fixed.
So a refusal:

- rolls back the local BPF row (no split truth),
- does **not** set the sticky session-mirror-failure flag,
- does **not** count toward the session-sync `Errors` total,
- counts into `Imports refused by helper`, rendered by
  `show chassis cluster information` only when non-zero.

That counter is health **debt**, not an error: the local state is consistent, but
the PEER believes it synced a session this node does not hold, and only the
peer's next full sync closes the gap. A persistently non-zero count means the
peer is oversubscribing this node.

### Failover Flow (Target)

```
1. CLI: request failover RG1 to node1
2. node0: barrier check (peer has all sessions)
3. node0: update_ha_state(RG1=false) — atomic demotion
   - bump RG epoch (flow cache auto-expires)
   - demote shared sessions
4. node0: VRRP sends priority-0 burst → node1 becomes MASTER
5. node1: VRRP MASTER → addVIPs → GARP/NA
6. node1: update_ha_state(RG1=true) — activation
   - sessions already resolved with local egress (from step above)
   - bump FIB generation
   - traffic starts flowing immediately
```

### Failover Flow (Current)

Steps 1-6 above are now the actual flow. Remaining differences from target:
- Some translated tuples may still resolve as HAInactive (needs validation)
- Neighbor warmup still runs async after activation (harmless — ARP/NDP
  for next-hops, not blocking the forwarding path)

### Watchdog heartbeat: map write every tick vs IPC on change/backstop (#2549)

The daemon runs a per-RG watchdog heartbeat (`pkg/daemon/daemon_ha_sync.go`)
on a 500ms ticker, writing a monotonic-seconds timestamp so a SIGKILL'd daemon
goes stale and the peer takes over. That timestamp lands in two places with
**different cadence requirements**, and `UpdateHAWatchdog`
(`pkg/dataplane/userspace/manager_ha.go`) decouples them:

- **Shim BPF `ha_watchdog` map write — EVERY tick (500ms), never throttled.**
  This is the kernel-visible liveness signal the BPF ~2s stale window compares
  against; it must stay fresh every tick. It is a cheap local map update, not a
  socket round-trip.
- **`update_ha_state` socket IPC — throttled.** The full HA-state JSON IPC over
  the shared Rust-helper control socket is the expensive part. Issuing it every
  tick is a 2/s-per-RG control-socket caller — exactly what the CLAUDE.md
  *Control socket contention* rule forbids (">1/s … will starve session installs
  during bulk sync"). It now fires only when:
  1. **An RG `Active` state CHANGES** (failover/failback) — published
     IMMEDIATELY. This is the load-bearing failover-timing path and is NEVER
     throttled. (The authoritative active-change publish is `UpdateRGActive`'s
     own direct `update_ha_state`; the heartbeat path also force-syncs on a
     detected per-RG `Active` delta as defense in depth.)
  2. **As a periodic BACKSTOP** — once the watchdog timestamp has advanced by
     `haWatchdogIPCBackstopSecs` (3s) since the last IPC for that RG, so the
     helper's view is refreshed well within its ~10s stale-lease window.

  Per-RG throttle state (`haWatchdogIPCSynced`, under `m.mu`) records the last
  timestamp/`Active` published per RG; the first heartbeat after startup/seed
  has no baseline and always syncs. The baseline is recorded BEFORE the send so
  a post-send error cannot cause a per-tick resync storm (the next ≤3s backstop
  retries), and `UpdateRGActive` records it too so the heartbeat does not
  redundantly re-fire right after a failover.

**Threshold rationale:** 3s gives a >3x margin under the helper's ~10s
stale-lease and drops the heartbeat's control-socket load from 2/s per RG to at
most ~0.33/s per RG (≈6x reduction), while the kernel-level liveness (the map
write) stays at the full 500ms cadence. Failover/failback timing is unchanged
because state changes bypass the throttle entirely.

**Live-config read every tick (#3917):** the heartbeat loop re-reads the
CURRENT redundancy-group set (`d.currentRedundancyGroups()` →
`d.store.ActiveConfig()`) on each tick rather than the `cc.RedundancyGroups`
snapshot captured when `startClusterComms` first ran. `startClusterComms` is
only restarted on a **transport-field** change (`clusterTransportKey`), so a
redundancy-group added by a day-2 commit would otherwise never receive a
watchdog write — its watchdog would stay stale and the dataplane would refuse
to forward for it. The loop is now gated on a published dataplane alone (no startup
RG-count precondition) so it also picks up the first RG added to a cluster that
booted with none.

### Peer fence reads the live config (#3917)

On a heartbeat timeout the surviving node sends a **fence** over the sync
channel; on receipt `OnFenceReceived` (`pkg/daemon/daemon_ha_sync.go`) must
deactivate `rg_active` for EVERY redundancy-group so the peer can own them
without a dual-active split-brain. The handler
(`d.fenceAllRedundancyGroups`) reads the CURRENT active config via
`d.currentRedundancyGroups()`, NOT the startup `cfg` closure. Before #3917 the
callback iterated the snapshot captured at `startClusterComms` time; because
comms are only restarted on a transport change, a day-2 redundancy-group was
absent from that snapshot and was **never fenced** — leaving it active on this
node while the peer also became active for it (split-brain dual-active, the
exact failure the fence exists to prevent). The handler is nil-safe in
config-only mode (no published dataplane) and when the config has no cluster stanza.

### Observing peer fencing (#72)

`show chassis cluster information` renders a **Peer fencing:** block whenever
`peer-fencing` is configured or a fence has ever fired on this node:

```
Peer fencing:
  Action: disable-rg
  Attempts:
    Aug 21 09:14:02  Fence disable-rg sent to peer
    Aug 21 09:31:47  Fence failed: peer not connected
```

`Action` is the CURRENTLY committed `set chassis cluster peer-fencing` value —
`disabled` when the leaf is absent — which can differ from the action the listed
attempts were recorded under, because the event history outlives a config
change. Each attempt line is one `handlePeerTimeout` fence decision and its
outcome.

### `disable-rg` — best-effort, unacknowledged

`SessionSync.SendFence` (`pkg/cluster/sync_failover.go`) writes `syncMsgFence`
and returns; nothing is sent back. A `sent to peer` line therefore means the
write reached the socket, not that the peer disabled its redundancy groups.
Local takeover is consequently NOT gated on the fence — `handlePeerTimeout`
runs `electSingleNode()` BEFORE it attempts the fence, so a dead peer (fence
unreachable) can never block the survivor from forwarding.

Attempt lines: `Fence disable-rg sent to peer`, `Fence failed: <err>` (the sync
channel was down — the node still takes over on the heartbeat timeout), or
`Fence skipped: sync not available` (no session-sync peer-fence function was
armed).

### `disable-rg-confirmed` — acknowledged, bounded, fail-open (#7147)

`set chassis cluster peer-fencing disable-rg-confirmed` sends a SEQUENCED fence
BEFORE the election and waits, bounded, for the peer to report what it
disabled. `SendFenceAwait` (`pkg/cluster/sync_fence_ack_7147.go`) writes
`syncMsgFence` carrying an 8-byte sequence number; the peer runs its fence and
replies `syncMsgFenceAck` (type 35) carrying that sequence, a status, and the
number of redundancy groups it drove to `rg_active=false` out of the number in
its live config.

**"Fenced" means peer-confirmed, not merely acknowledged.** The ack is written
only after the receiver's `fenceAllRedundancyGroups` has run, and only a
full-success result is reported as confirmed. A peer in config-only mode (no
published dataplane) replies `unavailable` rather than a vacuous success over
an empty RG set.

**The gate never withholds ownership.** Every negative outcome proceeds with the
takeover:

| Situation | Cost | Attempt line |
|---|---|---|
| Peer not connected | none — returns immediately | `Fence unconfirmed, took over anyway: peer not connected` |
| Peer predates #7147 | none — capability not advertised | `Fence unconfirmed, took over anyway: peer does not support fence acknowledgement` |
| Sync channel dropped mid-wait | none — waiter released at once | `Fence unconfirmed, took over anyway: session sync disconnected...` |
| Socket alive, peer silent | up to `FenceConfirmTimeout` (1 s) | `Fence unconfirmed, took over anyway: timed out after 1s...` |
| Peer partly fenced | none | `Fence NOT confirmed (peer disabled only 1/3 redundancy groups), took over anyway` |
| Peer confirmed | one fabric round trip | `Fence confirmed by peer (peer disabled 4/4 redundancy groups)` |

The only row that spends the timeout is one where the TCP socket is still up
but no ack comes back. The ordinary dead-peer takeover costs nothing extra,
because `SendFenceAwait` returns immediately when there is no active
connection — there is nothing to wait for.

A `Confirmations: received N, timed out N, sent to peer N` line accompanies
`Action` whenever the policy is armed or any ack traffic has occurred. Read
`timed out` as "takeovers that proceeded without the guarantee you selected";
it is the only place that number appears, since `Fences sent` counts a
confirmed and an unconfirmed takeover identically.

### What `disable-rg-confirmed` does NOT give you

**It reduces the split-brain window. It does not eliminate it, and the policy
name overclaims slightly — read this section, not the name.**

The residual is a partition in which the sync socket is LIVE BUT BLACKHOLED:
packets are being dropped, TCP has not yet timed out, so the connection is not
nil and the fence is written successfully, but no ack can come back. After
`FenceConfirmTimeout` this node takes over anyway while the peer may still be
alive and still forwarding. That is split-brain, and it is exactly the scenario
a fence exists to prevent.

**This is a deliberate trade, not an oversight.** The alternative — failing
CLOSED, refusing to take over without a confirmation — has the worse failure
mode for an appliance: a partition that never resolves leaves NOBODY
forwarding, and an HA pair that will not fail over has lost the property it
exists for. A bounded delay plus a smaller split-brain window is the trade on
offer here; a guarantee is not.

So an operator selecting this mode is buying:

- **confirmation when confirmation was available** — which is the common case,
  because the ack only has to arrive when the socket is genuinely healthy, and
  there a fabric round trip is milliseconds; and
- **ordering** in that case: this node does not claim the groups until the peer
  says it released them.

They are NOT buying "the peer is always confirmed down before I take over".

### Telling a confirmed fence from a fail-open — the event line is the only way

**The config knob cannot express the difference.** `Action: disable-rg-confirmed`
renders identically whether every takeover was confirmed or every one of them
fell open, so an operator reading only the configured action will assume the
stronger property. The `EventFence` attempt line is the discriminator, and it
is the ONLY one:

| Attempt line | What actually happened |
|---|---|
| `Fence confirmed by peer (peer disabled N/N redundancy groups)` | The peer reported that, at the instant it replied, it had driven `rg_active=false` for every RG in its live config. That is a DATAPLANE SUPPRESSION receipt — read the next subsection before reading it as a relinquishment. |
| `Fence unconfirmed, took over anyway: <reason>` | **No confirmation.** Takeover proceeded regardless. The reason names which path — not connected, peer predates #7147, disconnected mid-wait, or timed out. |
| `Fence NOT confirmed (<detail>), took over anyway` | The peer ANSWERED but reported it had not fully complied (partial, or no dataplane). |

The `Confirmations: received N, timed out N, sent to peer N` line summarises the
same thing in aggregate; `timed out` is the count of takeovers that proceeded
without the guarantee. Neither `Fences sent` nor the configured action
distinguishes them, which is why both surfaces exist.

### What a CONFIRMED fence does and does not give you (#9120)

A confirmed fence is narrower than the word suggests, and the gap is the part an
operator would misjudge, so it is stated here rather than left to be inferred
from the code. `fenceAllRedundancyGroups` drives `rg_active=false` on the
dataplane and re-arms the RG state machine. It does NOT:

- **release the VRRP virtual addresses.** The fenced node keeps every VIP, keeps
  answering ARP/ND for them, and keeps winning the VRRP election on the RETH
  members. Upstream L2 still steers that traffic at it and the dataplane drops
  it. A confirmed fence turns the peer into a BLACKHOLE, not into a node that
  has handed the addresses over. Traffic converges when the surviving node's own
  takeover moves the VIPs, not when the ack arrives.
- **demote the peer.** `clusterPri` is untouched: the fenced node still reports
  itself primary for those groups in `show chassis cluster status`, and an
  operator comparing the two nodes during a partition will see two primaries.
  That is expected and is not the sign of a failed fence.
- **hold.** `desired = clusterPri || allVrrpMaster`, and the fence changes
  neither input, so the next `reconcileRGState` pass on the fenced node
  re-drives `rg_active=true` (that re-arm is #6530's required behaviour — a
  fenced-then-recovered primary must not stay dark forever). **The suppression
  therefore lasts at most one reconcile interval** unless something else
  changes one of those inputs first: the peer observing the takeover over the
  sync channel, an operator, or a real crash.

What the gate genuinely buys is ORDERING — in the reachable-peer case it puts
the local takeover strictly after the peer's suppression, which closes the
window where both nodes forward the same flows. That is what
`disable-rg-confirmed` should be selected for. It is not a lease, and a longer
guarantee cannot be had without a fence that clears `clusterPri`, which needs a
bounded self-clearing timer of its own — an unbounded one converts a lost sync
channel into a no-primary outage. Pinned by
`TestFenceAckProvesDataplaneSuppressionOnly9120`.

**Mixed-version clusters are safe and need no coordinated upgrade.** Both wire
changes are additive: `syncMsgFenceAck` is a new type that an old peer skips
via the receive switch's missing `default` arm, and the fence sequence is
trailing data on an existing type whose old receiver reads no payload. A
fence-ack capability bit rides the trailing byte of `syncMsgPeerCapabilities`
(#6650). Neither `SessionSyncWireVersion` nor `CurrentHAProtocolVersion` is
bumped — bumping would push `GateMixedBaseSwap`'s single-point compatibility
window off the peer's version and refuse the rolling upgrade this has to
survive. A mixed pair degrades exactly to `disable-rg` behaviour on both sides.

Do not read this block as the **Install fence:** block that appears above it in
the same output — that one reports the bulk-sync install barrier sequence
(`LastFenceSeq`), an unrelated mechanism.

## What Was Eliminated

These mechanisms existed before the simplification work and have been
removed or bypassed:

| Mechanism | Removed in | Why |
|-----------|-----------|-----|
| `FlushFlowCaches` worker command | a21018f3 | Replaced by epoch-based invalidation |
| `refresh_owner_rgs` explicit RPC | 5ac423a3 | Sessions pre-resolved on receipt |
| `prepare_ha_demotion` two-phase | #359 | Demotion is atomic in update_ha_state |
| `SuppressedUntil` lease variant | #359 | No longer needed without prepare step |
| `syncPeerBulkPrimed` hard gate | e42c882e | Replaced by barrier-based readiness |
| Quiescence retry loop | a21018f3 | Single barrier is sufficient |
| Event stream drain/pause/resume | a21018f3 | Barrier proves delivery |
| Kernel session journal flush | a21018f3 | eBPF ctrl is disabled in userspace mode |
| `pendingRGTransitions` map | 5ac423a3 | Replaced by atomic bool |
| Blackhole routes (userspace mode) | 5ac423a3 | XDP shim + rg_active handles this |
| Weight=0 manual failover | PR #395 | Replaced by explicit transfer state |
| `synced: bool` field | dcc59c67 | Replaced by origin-based collision |
| `syncPeerBulkPrimed` failover gate | PR #407 | Barrier ack proves peer is current |
| `TransferReadiness` bulk-state check | PR #407 | Planned failover doesn't depend on bulk |
| Full-table scans on demotion/activation | PRs #404-406 | Owner RG indexes for O(1) lookups |
| `waitForSendQueueDrain` in barrier path | PR #407 | Priority channel for acks |

## Testing

### Automated

```bash
# Hardened RG move under load (the primary validator).
# Keep the run long enough to expose late collapses, move RG1 quickly in both
# directions, and keep all eight stream lines visible during the run.
BPFRX_CLUSTER_ENV=test/incus/loss-userspace-cluster.env \
IPERF_TARGET=172.16.80.200 \
TOTAL_CYCLES=12 CYCLE_INTERVAL=5 \
scripts/userspace-ha-failover-validation.sh --duration 600 --parallel 8
```

```bash
# Reverse-path coverage is also required. The validator currently exercises the
# source-sending path, so run a matching reverse iperf after the forward pass.
iperf3 -c 172.16.80.200 -P 8 -t 600 -R
```

### Manual CLI test

```bash
# Start long-running forward traffic and keep all per-stream lines visible.
iperf3 -c 172.16.80.200 -P 8 -t 600

# Rapidly move RG1 between fw0 and fw1 while traffic is active.
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"

# Verify: SNAT > 0 on the new owner, no stream wedges at 0, and the run
# recovers back to full throughput after each move.
cli -c "show chassis cluster data-plane statistics" | grep SNAT
```

```bash
# Repeat the same RG movement under reverse traffic. This exercises the return
# path ownership and catches failovers that only work when the host is sending.
iperf3 -c 172.16.80.200 -P 8 -t 600 -R

cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 1"
sleep 5
cli -c "request chassis cluster failover redundancy-group 1 node 0"
```

### Pass criteria

- All 8 iperf3 streams survive every RG move in both forward and reverse runs
- Zero per-stream zero-throughput intervals in both directions
- Zero aggregate zero-throughput intervals in both directions
- No permanently wedged stream after failback in either direction
- SNAT packets > 0 on new owner
- Session misses < 1000 on new owner
- RG moves to the requested node

## Remaining Work (Priority Order)

1. **Live validation** — run `/failover-test` with all recent fixes deployed
   to confirm end-to-end failover works with zero stream loss
2. **Validate translated tuple fix** — confirm PRs #404-406 resolved the
   HAInactive resolution for inherited forward-wire entries
3. **Validate split-RG** — confirm priority ack channel fixed split-RG
   readiness convergence
4. **Throughput parity** — hardware/topology limitation, not a software fix

## Superseded Documents

These docs contain historical investigation detail but should not be
read as current truth. This document supersedes all of them:

- `docs/archived/userspace-failover-hardening-plan.md`
- `docs/archived/userspace-failover-next-steps.md`
- `docs/archived/userspace-ha-failover-parity-plan.md`
- `docs/archived/failover-hardening-progress.md`
- `docs/archived/ha-failover-simplification-audit.md`
- `docs/archived/ha-simple-failover-design.md`
- `docs/archived/ha-failover-implementation-plan.md`
- `docs/archived/ha-forwarding-state-inventory.md`
- `docs/archived/userspace-forwarding-and-failover-gap-audit.md`

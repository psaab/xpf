# pkg/vrrp

Native VRRPv3 (RFC 5798) state machine. ~60 ms failover with 30 ms RETH
advertisements, IPv6 support, AF_PACKET RX fallback for VLAN
sub-interfaces, async GARP burst on `becomeMaster`, and sync-hold
preemption control for HA bulk session sync.

This is the package that drives chassis-cluster failover.

## Entry points

- `Manager` — `manager.go`. Owns every `Instance` goroutine, the event
  channel, and sync-hold state.
- `Instance` — `vrrp.go`. Per-RG config: interface, group ID, VIPs,
  priority, preempt, timers.
- `VRRPEvent` — `instance.go`. INIT / BACKUP / MASTER transitions.
- `NewManager()` — `manager.go`.
- `Start(ctx context.Context) error` — `manager.go`. **Returns
  immediately** after wiring `m.cancel`. Per-instance goroutines run
  independently and observe their own `stopCh`, **not** the parent
  context. Stop them via `Stop()`, which closes each instance's
  `stopCh`. **Reuse-safe (#2625):** `Start()` calls
  `resetRunStateLocked` under `m.mu` to re-allocate the run-scoped
  channels (`watcherStop`, `eventCh`), reset their `sync.Once` guards,
  and clear the singleton watcher latches (`watcherRunning`,
  `addrWatcherRunning`). A Manager that was `Stop()`ped can therefore be
  `Start()`ed again: the next `UpdateInstances` cleanly re-spawns the
  link/addr watchers instead of handing callers a closed `eventCh`
  (send-on-closed panic) or spawning watchers that immediately observe
  the already-closed `watcherStop` and exit. Production creates the
  Manager once and only `Stop()`s at shutdown (a daemon restart is a
  fresh process), so this is a latent-lifecycle guard — the cluster
  failover gate exercises only the single-run path; the reuse safety net
  is `manager_reuse_test.go`.
- `Stop()` — `manager.go`. Stops every instance, closes the run-scoped
  channels via their once-guards (captured under `m.mu` so a concurrent
  `Start()` cannot race a half-swapped channel), and cancels the
  context. The link/addr watchers each pin their run-generation
  `watcherStop` at spawn time, so closing it cancels precisely that
  generation's goroutines and their deferred latch-clear only resets the
  latch if it still belongs to that generation.
- `UpdateInstances(desired []*Instance) error` — `manager.go`.
  Diffs the running instance set against the desired set. A VIP change
  forces an instance restart, which is done **build-before-teardown**
  (#2156): the replacement's interface is resolved and its socket opened
  (the "proof" step) BEFORE the old instance is stopped and removed. A
  transient member-link failure (carrier flap, mid-rename by networkd)
  therefore leaves the old instance running and advertising its old VIPs
  rather than orphaning the RG out of election. Priority/preempt/track
  and the wire/timer/burst fields **advertise-interval** and
  **gratuitous-arp-count** update in-place (no restart, no master-down
  gap): the no-change gate compares `AdvertiseInterval` and `GARPCount`
  so a day-2 commit changing only `reth-advertise-interval` or
  `gratuitous-arp-count` is detected (not shortcut as no-change), and
  `updateConfig` copies both into the running instance's `cfg` (#5087).
  Neither needs an explicit timer poke — the MASTER advert timer
  re-arms via `advertTimer.Reset(vi.advertInterval())` on its next
  fire, the BACKUP master-down horizon re-reads `cfg.AdvertiseInterval`
  through `masterDownInterval()`, and the next failover's `sendGARP`
  re-reads `cfg.GARPCount`. Before #5087 the stale value persisted
  until an unrelated restart.
  **Ifindex drift (#2294):** before the no-change / in-place branch, a
  cheap tolerant `name→ifindex` probe compares the live kernel ifindex
  against the one the instance's sockets are bound to. A member netdev
  that is deleted+recreated or renamed (carrier/VLAN flap that fully
  removes and re-adds the link) gets a NEW ifindex while the xpf config
  stays byte-identical; without the probe the instance would keep its
  sockets bound to the STALE ifindex and go permanently silent
  (split-brain / blackhole). A drift forces the same
  build-before-teardown restart path so the instance rebinds to the new
  ifindex; a resolve failure is treated as "no drift" (a transient
  netlink hiccup never blocks a time-critical priority update — the
  build block already owns resolve-failure recovery). The probe runs
  every ~2s reconcile tick and is idempotent (unchanged ifindex → no
  restart, no churn). The restart preserves configured
  priority/preempt/tracking and re-applies sync-hold suppression, so a
  rebind cannot spuriously preempt or break the sync hold; RG role is
  driven separately by the cluster heartbeat / debounced priority.
  **Desired-vs-built record (#5641):** each pass recomputes
  `m.unbuiltDesired` — the desired keys with no live instance — so
  `RGVRRPReady` can refuse a partially-built RG (see the
  build-before-teardown invariant below).
- `RGVRRPReady(rgID int, hasRETH bool) (bool, []string)` — `manager.go`.
  Returns ready only when EVERY desired RETH key for the RG (VRID
  `100+rgID`) has a live instance AND at least one instance exists (or the
  RG has no RETH interfaces). A desired key that failed to build
  (resolve / socket / family capability) makes it `(false, reasons)`
  naming the un-built key (#5641).
- `ReleaseSyncHold()` — `manager.go`. No-arg; releases hold for all
  instances.
- `ResignRG(rgID int)` — `manager.go`. Forces this node out of master
  for the given redundancy group ID.

## File layout

- `manager.go` — redundancy-group coordinator: `Manager`, instance
  diff/lifecycle, sync-hold, RG force/resign helpers, socket helpers.
- `instance.go` — per-instance state machine core: the `vrrpInstance`
  struct, `newInstance`, config/preempt control, advert-interval and
  master-down/preempt-hold timing, the `run` loop and `stepBackup`,
  RX-driven state resolution (`handleBackupRx`/`handleMasterRx`/
  `resolveEqualPriorityMaster`), and the `becomeMaster`/`becomeBackup`
  transitions. Pure code-motion split (#5661) moved the cohesive
  sub-responsibilities below into sibling files (same `package vrrp`,
  no symbol renames):
  - `instance_addr.go` — local IPv4/IPv6 + VIP-set address resolution
    (`interfaceAddrs`, `get/setLocalIP`, `get/setLocalIPv6`,
    `vipAddrSet`, `canonAddr`, `resolveLocalIPv4`, `reresolveLocalAddrs`,
    `resolveIPv6LinkLocal`).
  - `instance_socket.go` — raw-socket lifecycle (`openSocket`,
    `openSocketWith`, `closeSockets`, `closeSocketDescriptors`,
    `clearSocketRefs`).
  - `instance_receive.go` — RX receivers + packet parse/enqueue
    (`receiver`, `receiverIPv6`, `receiverAfPacket`,
    `parseAfPacketIPv4`/`parseAfPacketIPv6`, `enqueuePacket`,
    `walkIPv6ExtHeaders`, `acceptArrivalIfindex`, `expectedIfindex`,
    `warnRXDrop`, `isTimeoutError`).
  - `instance_send.go` — advert/event send (`emitEvent`, `sendAdvert`,
    `sendPacket`, `sendPacketIPv6`).
  - `instance_garp.go` — gratuitous-ARP/NA burst + gateway probe
    (`sendGARP`, `garpSendAllowed`, `garpDampened`, `GatewayProbeTarget`,
    the `arpProbeFn`/`garpBurstFn`/`naBurstFn` seams, `minGARPInterval`).
  - `instance_vip.go` — netlink VIP add/remove actuation +
    stale-VIP reconcile (`addVIPsLocked`, `removeVIPs`,
    `removeVIPsLocked`, `nlLinkByName`/`nlAddrAdd`/`nlAddrDel`,
    `removeVIPsIfBackup`, `scheduleVIPRemoveReconcile`, `surfaceStaleVIP`,
    `vipActuationResult`).
- `advert_capacity.go` — per-family VIP cardinality guard (#6779):
  `splitVIPsByFamily` (the SSOT for how a configured VIP list is counted
  by family, shared with `sendAdvert`) and `checkAdvertCapacity` (whether
  that list can produce a legal advert). See "Advert capacity" below.
- `packet.go` — VRRPv3 advert parser/builder + IPv4/IPv6 checksums.
- `track.go` — interface tracking (#1814): the per-instance
  effective-priority primitives (`getPriority`, `setTrackDown`,
  `trackedInterface`) and the manager-side singleton link-watcher /
  poller (`runLinkWatcher`, `runLinkPoller`, `pollTrackedLinks`,
  `applyTrackedLinkState`, `seedTrackState`, `netlinkLinkState`,
  `linkAttrsUp`).
- `addrwatch.go` — advert-source re-resolution (#2528): the manager-side
  singleton ADDRESS-watcher (`runAddrWatcher`, `ensureAddrWatcherLocked`,
  `reresolveAddrFor`) that subscribes to `netlink.AddrSubscribe` and
  re-resolves `localIP`/`localIPv6` whenever an address changes on an
  interface a VRRP instance is bound to. Distinct from the link-watcher
  (which handles tracked-interface priority demotion) — different latch,
  different concern — but both share `m.watcherStop` cancellation.
- `vrrp.go` — `Instance` config type plus `CollectInstances` /
  `CollectRethInstances` config extraction.

## The send paths snapshot config under the lock (#8597)

`updateConfig` writes `Priority`, `Preempt`, `PreemptHoldTime`,
`AdvertiseInterval`, `GARPCount`, `TrackInterface` and `TrackPriorityCost`
under `vi.mu` on the MANAGER goroutine — the #5087 day-2 path, reached by any
commit that changes `reth-advertise-interval` or `gratuitous-arp-count`. Every
reader in `instance_preempt.go`, `track.go`, `manager.go` and
`instance_timing.go` snapshots under the lock (the #6230/#5718 discipline).
Four statements on the SEND paths did not, and `go test -race` reports two of
them at `instance_send.go:46` and `instance_garp.go:154` against
`instance.go:378-379`:

- `sendAdvert` read `cfg.AdvertiseInterval` in each of its v4 and v6 arms;
- `sendGARP` read `cfg.GARPCount`;
- `run()`'s startup log read `cfg.Priority` and `cfg.Preempt`.

`sendAdvert` takes ONE snapshot for both arms — `advertiseIntervalMS()` — not
one per arm. A read per arm silences the race detector completely and is still
wrong: a dual-stack instance sends its v4 and v6 adverts from one call, and a
writer landing between them makes the two families advertise different
`MaxAdverInt`. The peer derives its master-down interval from that field, so
the families would disagree about the failover horizon — the flapping shape
gemini-048 finding 06 describes. `TestOneAdvertCallUsesOneIntervalSnapshot_8597`
pins it deterministically, driving the write from inside the v4 arm through the
`sendPacketFn` seam rather than racing for the interleaving.

`advertiseIntervalMS` deliberately returns the RAW milliseconds rather than
reusing `advertInterval()`: that helper substitutes the 1000 ms default for a
non-positive value, and folding the default into the wire field would make a
misconfigured instance advertise a cadence it is not sending at.

`advertIntervalLocked` is NOT one of these sites despite looking like one — it
is documented as lock-held-by-caller and is reached from `recordMasterAdvert`
under `vi.mu.Lock`. A census of this class has to read the callers, not the
call.

## Configured priority is bounded before it is stored (#8597)

`instance_send.go` puts `uint8(priority)` on the wire while the local
state machine reads `vi.cfg.Priority` as an int (`instance_preempt.go`,
three sites; `track.go`'s `getPriority`). A configured value outside
[1,255] therefore made the local decision on a number the peer can never
see — and a configured 256 truncated onto **0**, which in VRRP is not a
low priority but the RFC 5798 RESIGNATION beacon this package uses to
hand mastership over (`manager.go` `ResignRG`). The node would advertise
"take over now" on every advert while believing itself the most preferred
candidate.

`clampConfigPriority` bounds the value at both config entry points —
`newInstance` and `updateConfig`; the day-2 commit path reaches only the
second, so a clamp on the constructor alone would let a running instance
acquire the value it was protected from at startup. The internal writes
in `manager.go` (`ResignRG` setting 0, `UpdateRGPriority` restoring from
cluster state) are deliberately NOT clamped: those are runtime sentinels,
not config.

The two clamp targets differ on purpose, and a single target would be
wrong in two distinct ways:

- **low -> 1, never 0** — clamping to 0 would install the resignation
  sentinel from config, which is the bug rather than a bound;
- **high -> 254, never 255** — 255 is the IP-ADDRESS-OWNER priority and
  carries semantics beyond "most preferred" (`preemptEnabled()` treats an
  owner as always-preempting; `track.go` exempts it from track-down
  demotion). Saturating to 255 would silently grant those properties to a
  config that only asked for a big number. An explicit 255 passes through
  untouched: that is how an operator declares the address owner.

Reachability is the tolerant ingress. The `vrrp-group ... priority` leaf
carries `ValidateInteger(1, 255)`, which the tolerant `Store.Load` /
`Store.SyncApply` path downgrades to a warning per #1960 — the same door
its chassis-cluster sibling travels (#8597 K17). gemini-review-048
finding 17 recorded this mechanism as real with its reachability
unestablished; `config_priority_domain_8597_test.go` drives both compile
paths rather than asserting it.

## Callers

`pkg/daemon`, `pkg/api`, `pkg/grpcapi`, `pkg/cli`.

## Dependencies

`pkg/config`, `pkg/cluster`.

## Failover timing (CLAUDE.md authoritative)

- ~60 ms with 30 ms RETH advertisements (masterDownInterval ~97 ms).
- Master_Adver_Interval adoption (#4061, RFC 5798 §6.1/§6.4.2): a BACKUP
  computes `Master_Down_Interval = 3×Master_Adver_Interval + Skew_Time`
  from the interval the **current master advertises**, learned from the
  received advert's Max Adver Int field (centiseconds on the wire, 10 ms
  units), NOT from its own `cfg.AdvertiseInterval`. `recordMasterAdvert`
  stores it in `masterAdverInterval` for every non-zero-priority advert;
  `masterDownInterval()` (and the #2082/#2850 staleness-horizon replicas
  `shouldPreemptObservedMaster`/`preemptingLiveLowerMaster`) use it, with
  the local interval as the pre-first-advert fallback. Skew_Time still uses
  the **local** priority (§6.1). When master and backup are configured with
  the SAME interval (the common case — RETH 30 ms both sides) the learned
  value equals the local one, so the ~60 ms failover is unchanged; a
  mismatch (a rolling `reth-advertise-interval` change, or a misconfig) no
  longer times the master out on the wrong cadence (a shorter local interval
  → premature failover/flapping; a longer one → delayed detection/loss).
- Learned-interval floor (#4548): `recordMasterAdvert` clamps the learned
  `Master_Adver_Interval` UP to `masterAdverFloor()` — the node's own
  configured `cfg.AdvertiseInterval`, with a 10 ms absolute backstop
  (`minLearnedMasterAdverInterval`, the schema minimum for
  `reth-advertise-interval`). RFC 5798 §6.1/§6.4.2 has no packet auth, so a
  buggy or misconfigured peer advertising `Max Adver Int=1` (10 ms) would
  otherwise collapse `masterDownInterval` (and the preempt-gate staleness
  horizons) to ~30 ms on a 30 ms RETH node and flap mastership on ordinary
  scheduling/network jitter. Only the LOW side is clamped: a SLOWER master
  (learned ≥ floor, the anti-premature-failover case above) is adopted
  unchanged, and a matching 30 ms advert equals the 30 ms floor so the
  fast-failover default is preserved exactly. Because the floor is the node's
  OWN interval, a legitimately-configured low-interval cluster (e.g.
  `reth-advertise-interval 10` on both nodes) is not over-clamped.
- Planned shutdown: 3× priority-0 advert burst → peer takeover ~1 ms.
- Heartbeat 200 ms, threshold 5 (1 s detection).
- Async GARP: first pair <1 ms; remaining sent at 50 ms intervals in a
  background goroutine. Critical path stays addVIPs → sendAdvert →
  emitEvent (sync), then `go sendGARP(false)` (async).
- Verified role publication (#5082 MASTER, #5482 BACKUP): a role is
  published via `emitEvent` only after the kernel VIP set agrees with it.
  The daemon consumes the event to flip `rg_active`, drop/inject
  blackholes, and start/stop per-RG services, so a role that diverges
  from the on-wire VIP state blackholes traffic. On the **MASTER** side
  `becomeMaster` is fail-closed: `addVIPsLocked` returns a structured
  `vipActuationResult`, and if any required VIP fails to actuate (or a
  concurrent demotion bumped `ownerGen`) it rolls back the partial adds,
  reverts to `StateBackup`, emits **BACKUP**, and returns `false` — it
  never advertises or emits MASTER for an ownership it cannot back. On
  the **BACKUP** side `becomeBackup` still emits BACKUP (we ARE stepping
  down — withholding it risks split-brain), but `removeVIPs` now returns
  its netlink failure and `surfaceStaleVIP` records it (a
  `vipRemoveFailures` counter + `vipDiverged` flag + Error log) and
  schedules a bounded async reconcile — so a swallowed removal no longer
  silently leaves this BACKUP still answering ARP for a VIP it lost
  (duplicate-address hazard vs the new master). Neither path adds latency
  on the clean case (the `vipMu` lock is uncontended), so the ~60 ms
  failover timing is unchanged.
  - **Already-absent AddrDel is NOT a divergence.** `removeVIPsLocked`
    treats ENODEV/ENOENT ("not found"/"no such") **and EADDRNOTAVAIL**
    ("cannot assign requested address", the common already-absent errno)
    as benign — the VIP was never on the interface. Without EADDRNOTAVAIL
    a fresh boot / restart-as-backup (whose run-startup BACKUP removal runs
    against VIPs that are not present) would set `vipDiverged` on EVERY
    clean boot and the reconcile would retry the still-absent address to
    exhaustion, leaving the operator-facing flag stuck TRUE — cry-wolfing
    the exact diagnostic this machinery provides. Detection is
    `errors.Is(err, unix.EADDRNOTAVAIL)` plus a belt-and-suspenders string
    match.
  - **The reconcile is re-promotion safe.** The stale-VIP reconcile runs on
    a background goroutine; `becomeMaster` runs `setState(MASTER)` (bumping
    `ownerGen`) BEFORE it takes `vipMu` to re-add the VIP. The reconcile
    therefore removes VIPs through `removeVIPsIfBackup(gen)`, which
    re-validates `state == BACKUP && ownerGen == gen` **UNDER `vipMu`**
    (mirroring `reconcileVIP`'s capture+recheck) and aborts
    (`errReconcileSuperseded`, no delete) on a racing re-promotion —
    otherwise the reconcile could strip the VIP a re-promoted MASTER just
    added (a MASTER self-blackhole). The old bare `removeVIPs` checked state
    OUTSIDE the lock, leaving a TOCTOU window between the check and the lock
    acquisition.
  - **A failed MASTER-side rollback is surfaced too (#9509).** Suppose
    `becomeMaster`'s fail-closed arm cannot delete a VIP it had added. The
    node would then publish BACKUP while holding that VIP, and nothing
    converges it: `ReconcileVIPs` acts only on a MASTER, and the master-down
    retry never fires while a healthy peer adverts.
    - The arm captures the rollback error and calls
      `surfaceStaleVIP(rollbackErr, "becomeMaster-rollback")` after
      `setState(StateBackup)` and after releasing `vipMu`. That order is
      required: the reconcile captures `ownerGen` when it is scheduled, and it
      takes the lock.
    - The call is unconditional, so a clean rollback clears a flag that an
      earlier, now-superseded reconcile left set.
    - `ReconcileVIPs`' own superseded rollback stays log-only. The only
      transition that can supersede it is `becomeBackup`, which then removes
      all configured VIPs and surfaces the result
      (`TestSupersededReconcileRollbackIsCoveredByBecomeBackup_9509`).
- GARP suppression gates: `sendGARP(force)` has two gates — a per-epoch
  dedup (`garpEpoch`/`lastGARPEpoch`, one burst per transition) and a
  500 ms time dampener (`lastGARPTime`/`garpDampened`, storm control for
  rapid flaps). `force=true` bypasses ONLY the dampener (the epoch dedup
  still applies). `becomeMaster` and the periodic path pass `force=false`;
  `ReconcileVIPs` passes `force=true` because the RETH MAC just changed and
  the correction GARP must not be swallowed by a routine burst that fired in
  the prior 500 ms (#2081). The decision lives in the network-free helper
  `garpSendAllowed`, which is unit-tested directly.
- Supplementary gateway ARP probe: after each IPv4 GARP burst, `sendGARP`
  also sends a directed ARP Request — VIP as the ARP sender (#2152) — to the
  subnet's first usable host (network address + 1, the most common gateway),
  so a router that ignores broadcast gratuitous ARP still re-binds the VIP.
  This is belt-and-suspenders: the broadcast GARP burst always fires; the
  directed probe is supplementary. The target comes from the network-free
  helper `GatewayProbeTarget`, which computes network+1 from the masked CIDR
  (`net.ParseCIDR`) — it returns `ok=false` to SKIP the directed probe on
  /31 (RFC 3021) and /32, where no in-subnet gateway host exists. Pre-#2377
  the target was the network address with its last octet forced to .1, which
  fell OUTSIDE the subnet for /25-or-longer prefixes whose network does not
  end in .0 (e.g. VIP 10.0.61.18/28 → 10.0.61.1, outside .16-.31).
  `GatewayProbeTarget` is exported so the daemon's direct-mode
  (private-rg-election / no-reth-vrrp) GARP path (`directSendGARPs` in
  `pkg/daemon`) reuses the identical derivation — that site had the same
  forced-.1 bug and was missed by #2377 (fixed in #3922).
- Burst follow-up abdication gate (#2867): the cluster burst helpers send the
  first GARP/NA frame synchronously, then fan the remaining `count-1` frames
  out over a detached goroutine spanning `(count-1)*50 ms`. `sendGARP` captures
  `garpEpoch` and passes a `stillMaster` predicate
  (`getState() == StateMaster && garpEpoch == captured`) into
  `cluster.SendGratuitousARPBurstGated` / `SendGratuitousIPv6BurstGated`. The
  follow-up loop re-reads that predicate before EVERY frame and stops the moment
  it returns false. Without the gate, a node that abdicates (master→backup on a
  link flap / rapid preemption / split-brain resolution) or whose burst is
  superseded by a newer one (epoch bump from `ReconcileVIPs` / a later
  `becomeMaster`) keeps broadcasting GARP/NA for VIPs it no longer owns —
  re-poisoning neighbor caches toward an abdicated node, the exact blackhole
  GARP exists to prevent. The gate is consulted only AFTER the synchronous first
  frame, so the immediate failover advert is never suppressed; a nil predicate
  (direct-mode re-announce, tests) keeps the original run-to-completion
  behavior.
- Event debounce 500 ms before priority updates.
- Sync hold: VRRP starts with `preempt=false`; released after bulk
  session sync (or 10 s timeout). `preemptNowCh` triggers instant
  preemption when sync completes early.
- Sync-hold preempt gate (#2082): the non-force `preemptNowCh` shortcut
  is peer-priority gated. `becomeMaster()` runs on the kick only when the
  node's **effective** priority is **strictly greater** than the last
  observed master's (RFC 5798 §6.4.2 — equal priority does NOT preempt;
  no IP tie-break, that resolves a MASTER-MASTER collision in
  `handleMasterRx`, not preemption). A lower-priority preempt-enabled node
  (e.g. a rejoining cluster Secondary at priority 100) therefore no longer
  transiently becomes a second MASTER on sync-hold release while a
  higher-priority peer is legitimately MASTER. `handleBackupRx` /
  `handleMasterRx` record each non-zero peer advert
  (`lastMasterPriority`/`lastMasterSeen`); priority-0 resignation adverts
  are not recorded (post-resign takeover flows through the ungated
  `masterDownTimer` path). Staleness — no master seen, or last seen older
  than `masterDownInterval` — is treated as "no live master", allowing
  cold-start / silent-master-death takeover. `ForceRGMaster` (force=true,
  cluster-authoritative Secondary→Primary promotion) bypasses the gate
  unchanged, so the ~60 ms failover path is untouched. The gate only
  governs the shortcut: a denied gate never stops `masterDownTimer`, so the
  normal RFC election still promotes the node when the real master dies.

## Preempt hold-time (#2850)

`vrrp-group <id> preempt { hold-time <seconds>; }` (Junos parity) delays a
higher-priority node reclaiming mastership from a still-live lower-priority
master, so dynamic routing (BGP/OSPF) converges before failback instead of
blackholing on takeover. Compiled to `Instance.PreemptHoldTime` (seconds);
0/unset = immediate preemption (the prior behavior, unchanged).

- **Where it applies** — ONLY to preemption of a *live* lower-priority
  master. The existing takeover path runs through `masterDownTimer` expiry
  (a preempt-enabled backup hearing a LOWER advert ignores it and lets the
  timer fire — see Interface tracking below). In `stepBackup`'s
  `masterDownTimer.C` case, when a hold-time is configured AND
  `preemptingLiveLowerMaster()` is true (a non-zero master advert was seen
  within `masterDownInterval` with priority strictly below our effective
  priority — the same snapshot math as the #2082 gate), the promotion is
  DEFERRED: a `preemptHoldTimer` is armed for hold-time seconds instead of
  calling `becomeMaster()`. When `preemptHoldTimer.C` fires, the node
  promotes.
- **What is NOT delayed** — a genuinely dead/silent master (no recent
  advert, or last seen beyond `masterDownInterval`) is takeover, not
  preemption — there is nothing forwarding to blackhole, so it promotes
  immediately. A graceful priority-0 resignation arms a one-shot
  `skipNextPreemptHold` in `handleBackupRx` so the imminent 1 ms
  `masterDownTimer` expiry promotes immediately (planned failover stays
  zero-delay).
- **Liveness watchdog — held master dies mid-hold (#4584)** — the master
  that was live when the hold armed can DIE *during* the hold. Arming the
  hold used to leave `masterDownTimer` idle (it fired to arm the hold, and
  `handleBackupRx` never resets it for a persisting lower advert), so the
  held VIP-owning master's silence went undetected until the (possibly very
  long) hold-time elapsed — up to ~hold-time of blackhole for a *dead*
  master, violating the "dead master → immediate takeover" invariant.
  `armPreemptHold` now ALSO (re)arms `masterDownTimer` for
  `masterDownInterval` as a liveness watchdog. On its fire while
  `preemptHoldArmed`, `stepBackup` checks `heldMasterIsStale()`: a stale
  held master (last advert beyond the master-down horizon → it went silent)
  disarms the hold and takes over NOW; a still-live one (adverts keep
  refreshing `lastMasterSeen` via `recordMasterAdvert`) re-arms the watchdog
  and lets the hold run to its natural expiry. `heldMasterIsStale` checks
  ONLY staleness — NOT the effective>master priority comparison — so a
  track-interface demotion below a *still-live* master does not trigger a
  spurious watchdog takeover; the natural-expiry re-validation
  (`shouldPreemptObservedMaster`, #2900) owns the demotion case. So a LIVE
  held master is still deferred to hold-time (preempt-hold intent preserved)
  while a DEAD one is taken over within ~one master-down horizon.
- **Cancellation** — while the hold is armed, a returning >= -priority
  master advert (`handleBackupRx`) resets `masterDownTimer` and
  stop-drains the hold (no longer a lower master to preempt). A
  coordinated/forced `preemptNowCh` promotion (#2082 / `ForceRGMaster`)
  also stop-drains the pending hold. A persisting lower-priority master
  leaves the armed hold running.
- **Scope** — interface-level `CollectInstances` VRRP groups. The RETH
  cluster path (`CollectRethInstances`) is driven by chassis-cluster RG
  preempt and is not wired to interface `preempt hold-time` (out of scope
  for #2850).

## Equal-priority tie-break — dual-stack family-consistency (#4376)

RFC 5798 §6.4.3 resolves a MASTER-MASTER collision at **equal priority** by
higher source IP. `handleMasterRx` runs this only against an equal-priority
peer advert (a higher-priority advert steps down unconditionally; priority-0
is a peer resignation). `resolveEqualPriorityMaster` performs the comparison.

A single instance is genuinely **dual-stack**: `CollectRethInstances` puts all
of a unit's v4+v6 addresses on ONE instance, and `sendAdvert` emits BOTH a v4
advert (source `getLocalIP`, the lowest primary v4) and a v6 advert (source
`getLocalIPv6`, the link-local) from two **unrelated** sources. The v4 and v6
orderings between two nodes can therefore **disagree**.

The tie-break must NOT key off whichever family's advert happened to arrive. If
it did, two equal-priority nodes with disagreeing orderings (A: higher-v4 /
lower link-local, B: lower-v4 / higher link-local) would each step down on the
**other** family's advert — A backs down on B's higher-v6, B backs down on A's
higher-v4 — so BOTH go BACKUP, both `masterDown` timers expire, both re-elect:
a permanent no-master oscillation (RG outage). Equal priority is reachable — a
simultaneous cold boot leaves both at 100, and a control/heartbeat-only
partition leaves both at 200.

Fix: **anchor the tie-break to ONE address family** so both nodes compare the
same pair of addresses. `hasIPv4VIP()` classifies the instance from its
**configured VIP families** (immutable per instance — a transient address flush
cannot flip the anchor):

- **v4-bearing** (dual-stack or v4-only): resolve the collision on **v4 adverts
  only**, comparing `getLocalIP()`. A v6-family advert is **ignored** for the
  tie-break (the peer's v4 advert drives the symmetric decision on both sides).
- **v6-only** (no v4 VIP): resolve on the **link-local v6** advert via
  `getLocalIPv6()`.

Secondary defect (same fix): when the anchored family's local source is **nil**
(unresolved — e.g. the #2528 RETH-MAC-flush window), the old code let
`peerHigher` stay false and **stayed MASTER by default** ("treat unresolved as
we-win"). It now **yields** (`becomeBackup`) to the actively advertising
equal-priority peer. This does not oscillate: a node that cannot resolve its own
source cannot put a valid same-family advert on the wire (`sendPacket` errors),
so the peer never receives an advert from it and only one side steps down; the
source re-resolves on the advert-send path and a healthy node re-elects cleanly.

## Instance identity — kernel name + family key (#5083)

`CollectInstances` (the generic, interface-level collector) must produce a
**kernel** interface name and a family-tagged identity, or instances get
silently dropped:

- **Kernel name** — the collector resolves each `Instance.Interface` to the
  Linux netdev via the SSOT `cfg.ResolveKernelIfName("<ifName>.<unit>")`. It
  previously stored the raw Junos name (`ge-0/0/0`) with no unit, so the
  manager's `net.InterfaceByName("ge-0/0/0")` failed and **no instance was
  ever built** for a slash-named interface. `ResolveKernelIfName` translates
  the slash form, applies reth resolution, and appends the unit's VLAN tag /
  unit-number suffix, so a VLAN sub-interface `ge-0/0/0.100` maps to the
  netdev `ge-0-0-0.100` and a non-zero unit gets its own device. This is the
  same SSOT resolver used by the DHCP / ip-monitoring name derivations, not a
  hand-rolled slash→dash substitution (which mishandles reth/unit).
- **Family in the key** — the manager `instanceKey` is
  `{iface, groupID, family}`. A **dual-stack** generic group configures an
  IPv4 `vrrp-group` under a `family inet` address AND an IPv6 `vrrp-group`
  under a `family inet6` address with the **same** VRID; `parseVRRPGroups`
  keys them separately (by address CIDR) so `CollectInstances` emits **one
  Instance per family**. These are two independent VRRP protocol instances
  (distinct multicast groups / adverts). Without `family` in the key they
  collided on `(interface, VRID)` and `UpdateInstances` last-wins **dropped a
  family**. The unit needs no separate key field — it is already encoded in the
  resolved kernel name (VLAN suffix / unit number), so two units sharing a VRID
  yield distinct `iface` values on their own.
- **Family is an election-domain boundary** — every raw-IP and AF_PACKET
  receive path converges on one admission helper. An `inet` instance rejects
  IPv6 adverts and an `inet6` instance rejects IPv4 adverts before they enter
  its state machine; only the historical empty-family RETH instance admits
  both. This is required when two generic instances share interface+VRID:
  identity-only map separation is insufficient if one family's advert can
  still reset or transition the other family's timers/state.
- **Socket readiness is complete or absent** — an IPv6-only instance opens no
  IPv4 raw socket, and any required IPv4/IPv6 socket failure rejects the new
  instance through the manager's build-before-teardown proof. In particular,
  an IPv6 socket failure is no longer warning-only: the manager cannot publish
  a nominally running `inet6` instance that is unable to advertise.
- **Collisions fail closed** — collection order is deterministic, and
  `UpdateInstances` rejects duplicate `{kernel interface, VRID, family}`
  identities before changing the live set or publishing desired interfaces.
  It also rejects an empty-family RETH instance sharing interface+VRID with a
  generic family: the RETH state machine consumes both wire families and would
  overlap either generic election despite having a different map key.
  The apply tail propagates that rejection as a commit error rather than
  accepting whichever map entry happened to win iteration order.
- **RETH is different** — `CollectRethInstances` deliberately leaves `Family`
  empty and puts a sub-interface's mixed v4+v6 VIPs on **one** instance (see the
  #4376 tie-break above), so RETH keys stay byte-identical to before. The
  `Family` split is a generic-collector concept only.
- **Display key** — `StateKey(iface, groupID, family)` is the single source of
  truth for the `VI_<iface>_<vrid>[_<family>]` string that `Manager.States()` /
  `RXDropStats()` index by and that `pkg/api` / `pkg/grpcapi` / `pkg/cli`
  reconstruct from a collected `Instance`. Empty family keeps the historical
  `VI_<iface>_<vrid>` form; a dual-stack instance appends `_inet` / `_inet6` so
  the two families never collide in those maps.
- **Event identity stays complete** — `VRRPEvent` and `InstanceStates` carry
  `Family`. Cluster ownership paths accept only empty-family implicit RETH
  events/instances, so a valid standalone generic VRID in the numeric
  `100+RG` range cannot be mistaken for a chassis-cluster redundancy group.

Regression coverage: `TestHandleMasterRx_DualStack_DisagreeingOrderings_ConvergeOneMaster`
(both converge to one master), `..._DualStack_IgnoresV6Advert`,
`..._V6Only_TieBreaksOnLinkLocal`, `..._NilLocal_DoesNotStayMaster` in
`vrrp_test.go`.

## Interface tracking (#1814)

Single-interface tracking per VRRP group:
`track-interface <if> { priority-cost <n>; }` (nested Junos form) or the
legacy flat sibling `track-priority-cost <n>`; nested wins when both are
present. Multiple `track-interface` statements in one group are rejected
at commit (strict) and first-wins with a warning on the tolerant
load/peer-sync compile paths.

- **Effective priority** — `getPriority()` (`track.go`) returns
  `Priority - TrackPriorityCost` clamped to **[1, 254]** while the
  tracked link is down. Tracking can never fabricate the priority-0
  resignation sentinel (priority 0 passes through unchanged), and
  **priority 255 (address owner) is exempt** — an owner stepping down
  while still holding the address invites duplicate-IP conflicts; the
  compiler warns instead.
- **Link watcher** — ONE singleton goroutine per Manager
  (`runLinkWatcher`, `track.go`), started lazily when an instance
  tracks an interface; latched under the manager mutex so
  `UpdateInstances` churn never spawns a second. Subscribes via
  `netlink.LinkSubscribe` with done-channel cancellation closed from
  `Stop()`; on subscribe failure it degrades to a 1 s poll. Initial
  state is seeded with `netlink.LinkByName` at instance create/update
  (a missing tracked interface counts as down). The tracked-ifname →
  instance mapping is re-read under lock per event. **On ANY exit
  (Stop()-driven cancellation or the poller fallback returning) the
  goroutine clears `watcherRunning` via `clearLinkWatcherLatch` (#2625),
  mirroring the addr-watcher (#2528)** — the latch is generation-gated
  on the pinned `watcherStop` so a lingering pre-Stop watcher never
  resets a fresh post-Start watcher's latch.
- **Takeover latency** — a demoted MASTER keeps advertising at the
  lower effective priority; a preempt-enabled backup hearing a LOWER
  advert ignores it and waits for masterDown expiry, so takeover lands
  in ~masterDownInterval (≈97 ms at 30 ms adverts, ≈3.3 s at 1 s
  adverts) per RFC 5798 — no forced abdication.
- **Cluster note** — tracking applies to standalone VRRP instances
  (`CollectInstances`). RETH instances (`CollectRethInstances`) never
  carry track config, and RETH VRRP is suppressed entirely under
  `no-reth-vrrp` / `PrivateRGElection` — no chassis-cluster interaction.
- `CollectInstances` normalizes `TrackInterface` from the Junos name
  (`ge-0/0/1`) to the Linux name (`ge-0-0-1`) so netlink matching works.

## Sockets

- IPv4: per-instance raw socket (proto 112) plus AF_PACKET fallback for
  VLAN sub-interfaces (the kernel's raw IP doesn't reliably receive
  multicast on VLANs).
- IPv6: separate raw socket; hop limit set to 255 per RFC.
- **`SO_BINDTODEVICE` is applied symmetrically across both families**
  via `maybeBindToDevice` (`manager.go`): the device bind is used on a
  plain interface for isolation but **SKIPPED on a VLAN sub-interface**
  (name contains `.`). Generic-XDP VLAN tag handling makes the kernel's
  interface association unpredictable, so pinning the raw socket to the
  VLAN sub-interface index can drop VRRP multicast. Before #2786 only the
  IPv4 path skipped — the IPv6 path bound unconditionally. Both
  `openPerInterfaceSocket` (v4) and `openIPv6Socket` (v6) now route their
  bind through the single `maybeBindToDevice` decision; IPv6 multicast
  egress is steered by `IPV6_MULTICAST_IF`, which does not depend on
  `SO_BINDTODEVICE`. **Scope of the RX impact:** in the normal path the
  IPv6 raw socket is send-only — VRRP RX is the shared AF_PACKET tap
  (`receiverAfPacket`, native-XDP env), which is independent of the v6
  socket's `SO_BINDTODEVICE`, so the unconditional bind was cosmetic for
  RX there. The genuine split-brain it repaired is the **AF_PACKET-unavailable
  fallback** (`receiverIPv6` reads IPv6 VRRP directly from the raw socket,
  `instance_receive.go`): there a VLAN-pinned `SO_BINDTODEVICE` could drop inbound
  multicast → the IPv6 instance misses peer adverts → both nodes hold
  MASTER. Aligning v4/v6 is correct hygiene on both paths and closes that
  fallback-path split-brain; `make test-failover` on the native-XDP loss
  cluster validates no-regression but does not exercise the fallback RX
  path this specifically repairs.
- **Arrival-interface filter on the raw-socket fallback (#2886).** Because
  `maybeBindToDevice` is a no-op on a VLAN sub-interface, two VLAN raw
  sockets on the same parent both bind to the wildcard address with NO
  device isolation, so the kernel delivers a proto-112 frame to *every*
  such socket. The fallback receivers (`receiver` / `receiverIPv6`) used
  to gate only on TTL, self-IP, and VRID — so two VLAN sub-interfaces
  (e.g. `reth0.50` / `reth0.80`) running instances with the **same VRID**
  cross-processed each other's adverts → false BACKUP transitions and
  split-brain flapping. Both fallback receivers now enable the per-packet
  interface control message (`ipv4.FlagInterface` / `ipv6.FlagInterface`),
  capture the arrival ifindex, and route it through
  `acceptArrivalIfindex(arrivalIfindex, vi.expectedIfindex())`: an advert
  whose arrival interface differs from the instance's bound interface is
  dropped. The check **fails open** when the platform reports no arrival
  interface (`ifindex == 0`) or the instance has no resolved interface, so
  it never regresses delivery — the VRID/TTL/self gates still apply. The
  IPv6 read goes through the `ipv6Recv` seam (an
  `ipv6.NewPacketConn(...).ReadFrom` wrapper in production) so tests can
  inject a synthetic arrival ifindex without `CAP_NET_RAW`. Only the
  AF_PACKET-unavailable fallback is affected; the default
  `receiverAfPacket` tap already binds to a single ifindex.
- **GTSM hop-limit gate on the raw-IPv6 fallback (#4549 F8).** RFC 5798
  §5.1.2.3 requires VRRPv3 advertisements to carry an IPv6 hop limit of
  255 so a routed (off-link) advert is rejected. The AF_PACKET path
  (`parseAfPacketIPv6`, reads `ip6[7]`) and the IPv4-raw path (`hdr.TTL`)
  already enforce this, but the raw `ip6:112` fallback socket strips the
  IPv6 header, so the hop limit is not in the payload. `receiverIPv6` now
  enables `ipv6.FlagHopLimit` (`IPV6_RECVHOPLIMIT`) alongside
  `FlagInterface`, reads the hop limit from the per-packet control
  message via the `ipv6Recv` seam, and drops any advert whose hop limit
  is not 255. The seam therefore returns `(n, ifindex, hopLimit, src,
  err)`. Exploitability is near-nil (VRRPv3 IPv6 uses link-local
  multicast `ff02::12`, unroutable off-link), so this is defense-in-depth
  parity with the other two receive paths.
- The AF_PACKET capture fd is created `SOCK_RAW|SOCK_CLOEXEC` so it is set
  close-on-exec atomically at creation (#2476). A raw `unix.Socket` does NOT
  inherit CLOEXEC the way Go `net` sockets do, so without this the raw VRRP
  capture fd would leak into every child the daemon execs (frr-reload.py,
  swanctl, dhcp helpers) — an fd leak and a security boundary (a child could
  read raw VRRP frames). The OR-into-type form avoids the fork race a separate
  `fcntl(FD_CLOEXEC)` would open.

### IPv6 advert address list — link-local first (#5089)

RFC 5798 §5.2.9 defines an advertisement's payload as the list of IPvX
address(es) "associated with the virtual router", and §5.1.1.2 requires an
IPv6 advert to be **sourced from the virtual router's link-local address**.
For IPv6 the conformant wire format places that link-local as **address[0]**,
followed by the configured global VIPs — a strict vSRX/keepalived-v3 peer can
reject an advert whose first address is a global VIP.

`sendPacketIPv6` (`instance_send.go`) resolves that link-local as `srcIP`
(`getLocalIPv6()`, with the #2258 lazy-resolve fallback), uses it as the outer
IPv6 source and the pseudo-header checksum source (#2644), **and now prepends
it to `pkt.IPAddresses` ahead of the configured VIPs** before `Marshal`. Three
invariants hold by construction:

- **address[0] == outer/checksum source.** The prepend reuses the exact `srcIP`
  fed to the checksum, so the first advertised address is guaranteed identical
  to the pinned outer source (`IPV6_PKTINFO`) — no independent resolution that
  could drift.
- **Count stays consistent.** `Marshal` derives the "Count IPvX Addr" wire byte
  from `len(IPAddresses)` (`packet.go`), so prepending bumps the count in
  lockstep with the payload length; the `MinAdvertAddrCount..MaxAdvertAddrCount`
  guard still applies. The prepend is exactly why the IPv6 CONFIGURED-VIP
  ceiling is 254 and not 255: a 255-VIP IPv6 config pushes the wire count to
  256 and `Marshal` rejects it. That rejection is now caught before it can
  matter — see "Advert capacity" below (#6779).
- **IPv4 is untouched.** The prepend lives only in the IPv6 send path; the
  IPv4 `sendPacket` builder advertises the configured VIPs verbatim.

Guarded by `TestSendPacketIPv6PrependsVirtualRouterLinkLocal` /
`TestSendPacketIPv6LinkLocalFirstWithMultipleVIPs`, which re-parse the captured
advert and assert address[0] is the link-local and the Count field includes it.

### Which interfaces own a redundancy group (#6781)

Both ownership modes ask the same question — "does this interface own RG N?" —
and before #6781 they answered it differently, each with its own reading:

| Reading | Used by | Blind spot |
|---|---|---|
| `RedundancyGroup > 0` alone | `CollectRethInstances` (VRRP-backed) | claims an interface that is not a reth at all |
| + `strings.HasPrefix(name, "reth")` | `RethVIPsForRG` (direct) | drops a structurally valid pair not spelled `reth*` |

**Both were wrong, in opposite directions**, and both shapes committed cleanly:

- `ge-0/0/5 redundant-ether-options redundancy-group 1`, nothing naming it as a
  `redundant-parent`. VRRP-backed synthesized an instance on it whose "VIPs"
  were the interface's OWN configured addresses — so they existed only while
  MASTER and were deleted on BACKUP. networkd generation
  (`pkg/dataplane/compiler_iface.go`) independently replaced that address with a
  `169.254.<rg>.<node>/32` link-local. Under `no-reth-vrrp` the direct collector
  skipped the interface, so the address was stripped and installed by **nobody,
  on both nodes**.
- `bond0` with `ge-0/0/1 gigether-options redundant-parent bond0` — a
  structurally valid redundant pair not spelled `reth*`. VRRP-backed resolved it
  correctly; the direct collector returned nothing, leaving that group with no
  VIPs at all.

`Config.RethRGOwners` (`pkg/config/reth_rg_owner.go`) is now the single source
of truth. An interface owns the group it carries when it is a
redundant-ethernet interface **structurally** (some port names it as their
`redundant-parent`) **or nominally** (spelled `reth*`). That is deliberately the
UNION of the two old readings minus their shared blind spot: it excludes only
the shape that was actively wrong and includes the shape one mode was dropping,
so nothing either mode previously owned stops being owned — in HA ownership code
a newly-excluded interface is an outage.

The `> 0` test lives at the CALLER, not in the predicate: the VRRP-backed
collector synthesizes instances only for groups above 0, while the direct
collector is legitimately queried FOR group 0. What an RG-0 query needs
protecting from is every unconfigured interface defaulting to 0 — and the
structural/nominal test already excludes those, which is what the old name
filter was really providing.

`validateRethRedundancyGroupStrict` (`pkg/config`) rejects the offending shape
at commit, with `lenientRethRGOwnership` for the tolerant load / peer-sync
path (#1960). A `reth*` with no members yet is deliberately NOT rejected — it is
an incompletely-wired declaration that both modes accepted before, and
narrowing it is not what #6781 is about.

**All eight readers now share it.** Besides the two ownership collectors and
networkd generation, the five `pkg/daemon` readers that decide RG membership for
stable RETH link-local add/remove, the direct-mode GARP / router-LL burst, DHCP
RG-scoping and BACKUP blackhole routes each carried their own name test. Left
alone they would have given a structurally valid pair VIPs from both ownership
modes and then no GARP, no stable link-local and no blackhole routes — VRRP
mastering an interface nothing else manages. `rethInterfacesMatchingRG`'s own
doc comment (#6520) already states the rule: *"Deriving the two from one walker
is not a style preference: a divergence between them is ALWAYS a bug."*

Bound by two tests, because a behavioural one alone is probe-bounded:
`reth_rg_parity_6781_test.go` asserts the two modes reach the same conclusion on
both shapes plus a control, and `reth_rg_ssot_6781_test.go` asserts they still
read it from one place (neither collector may compare `.RedundancyGroup` or
name-test for `"reth"` itself).

### Advert capacity — per-family VIP cardinality (#6779)

RFC 5798 §5.2.4 makes an advertisement's "Count IPvX Addr" a single byte, so
one advert carries at most **255** addresses of a family. `Marshal` REFUSES an
out-of-range count rather than truncating it (#5090). Combined with the IPv6
link-local prepend above, the ceiling on **configured** VIPs is:

| Family | Configured VIP ceiling | Why |
|---|---|---|
| IPv4 | 255 (`MaxAdvertAddrCount`) | no prepend — every slot is a configured VIP |
| IPv6 | 254 (`MaxAdvertAddrCount - 1`) | slot 0 is the mandatory link-local prepend |

`MaxConfiguredVIPs(isIPv6)` (`packet.go`) derives both from
`MaxAdvertAddrCount`, so the subtraction lives in one place.

**Why an oversized set was more than a malformed packet.** `sendAdvert`
discards a `Marshal` failure at `slog.Debug`, and `becomeMaster` claimed the
VIP set and published MASTER **before** calling it. An oversized family
therefore produced an owner that advertised **nothing**: the peer's
`masterDownTimer` expired and it promoted too — both nodes answering ARP for
the same VIPs — or, with the same config synced to both nodes, no node could
advertise and the VIPs were stranded. Note the failure is *silent* at a default
log level, so it presented as an unexplained dual-master.

Three layers now close it, and the cap is enforced at each:

1. **Commit** — `validateVRRPVIPCountStrict` (`pkg/config`) hard-rejects an
   over-capacity set at `commit` / `commit-check`, covering BOTH VIP sources:
   explicit `vrrp-group ... virtual-address`, and the RETH-derived instances
   where a redundancy-group interface's own unit addresses become the
   advertised set (`CollectRethInstances`). Per #1960 no-brick the tolerant
   load / peer-sync path downgrades it to a warning
   (`opts.lenientVRRPVIPCount`).
2. **Instance construction** — `UpdateInstances` refuses to build an
   instance whose VIP set cannot advertise, same doctrine as the #4573 VRID
   guard, so a leniently-loaded config leaves the group out of the election
   rather than seating a silent non-advertiser.
3. **Ownership** — `becomeMaster` consults `vi.advertCapacityErr` and returns
   false **before** `setState`/`addVIPs`, so the VIPs are never claimed. This is
   the #5082 "do not claim what you cannot back" rule applied to the advert
   instead of to VIP actuation. The predicate is computed once in `newInstance`
   (the configured VIP list is immutable per instance — a VIP change rebuilds
   it), so the ~97ms RETH retry path pays a nil check and the operator-facing
   `Error` is logged once, not per retry.

Because `pkg/vrrp` imports `pkg/config` and never the reverse, the cap is
necessarily spelled in both packages
(`config.MaxVRRPVirtualAddressesIPv4/IPv6`). They are NOT independently
maintained: `advert_capacity_agreement_6779_test.go` measures the largest count
the REAL `Marshal` accepts per family — driving IPv6 through the same
link-local prepend — and asserts the config constants equal exactly that, so a
wire-format change the constants did not follow fails the suite instead of
silently splitting the validator from the builder.

**The EMPTY (or entirely unparseable) VIP list is covered separately, at commit
only (#7577).** Such an instance also holds its group without advertising, but
it claims no addresses, so there is nothing for a second master to collide over
— a silent no-op group rather than a duplicate-address hazard.

`pkg/config`'s `validateVRRPVIPEmptyStrict` hard-rejects an explicit
`vrrp-group` with no parseable virtual address at commit / commit-check, with
the usual `#1960` lenient downgrade on the tolerant load / peer-sync path. Three
things about its scope are deliberate and load-bearing:

- **Explicit `vrrp-group` blocks ONLY.** `CollectRethInstances` already skips a
  RETH with no VIPs, so no instance is synthesized and there is nothing to claim
  a group. Extending the gate to RETH units would reject configuration that is
  correct today. `TestRethUnitWithNoAddressesIsNotRejected7577` pins this.
- **Reject-only.** `checkAdvertCapacity` deliberately does **not** carry the
  lower bound, so `UpdateInstances` and `becomeMaster` still accept a VIP-less
  instance. Adding it would change the behaviour of the 22 `pkg/vrrp` tests that
  construct VIP-less instances as a state-machine fixture — a behaviour change
  riding along with a bug fix — and its worst case is worse: a commit rejection
  fails loudly on a config the operator is editing, while a runtime refusal
  removes a group from the election on a node already running.
- **No runtime guard backs the lenient downgrade**, unlike the oversized case
  above. A leniently-loaded empty group therefore keeps today's behaviour rather
  than being held out of the election. That is intended — the tolerant path must
  not brick a node over a group that is merely inert.

The "advertisable" predicate is `countVRRPVIPFamilies`, the same split the send
path performs, so the gate cannot disagree with the sender about what counts as
an address (#6539 shared authority).

### RETH ownership modes and nil config slots (#6780)

A RETH redundancy group's ownership is resolved by one of TWO collectors,
depending on cluster mode — both in `vrrp.go`, both walking the same interface
tree:

| Mode | Collector | Selected when |
|---|---|---|
| VRRP-backed | `CollectRethInstances` | default (RETH VRRP instances synthesized) |
| Direct | `RethVIPsForRG` | `no-reth-vrrp` or `private-rg-election` |

Both dereferenced interface, unit, and (VRRP mode) redundancy-group map values
raw, so a present-but-nil slot would nil-deref on the HA ownership path. Their
in-file sibling `CollectInstances` already skipped nil interfaces and units, and
6 of the 8 RETH-ownership walks in `pkg/daemon` already skipped nil interfaces —
these two collectors were the outliers. They now skip nil slots too, as does
`rethInterfacesMatchingRG` (`pkg/daemon`), the third reading of RG membership.

**Reachability — stated honestly.** This is NOT a fix for a reachable panic. The
compiler cannot currently emit such a slot: each container has exactly one write
site and each stores a freshly-allocated pointer, persistence decodes the AST
(`*ConfigTree`) and recompiles, HA config-sync ships config TEXT, and nothing
deserializes a `*config.Config`. The widely-cited claim that "the tolerant /
HA-sync path may carry a nil entry (#3494/#5068)" traces to a circular chain —
#5068 cites the #3494 test, whose own header says "The strict compiler never
emits these nils" — and every nil slot in the repository is injected
synthetically by a test.

That invariant is now ENFORCED at the source by
`TestCompilerNeverEmitsNilConfigSlots` (`pkg/config`), which is where the class
can actually be prevented. The consumer-side guards are defence in depth behind
it: they cost nothing, are provably inert on every reachable config (the branch
is never taken), and make the highest-consequence path degrade rather than
panic if a future config ingress breaks the invariant.

### Receiver goroutine model

When AF_PACKET opens (`afPacketFD >= 0`), a single `receiverAfPacket()`
goroutine handles both IPv4 and IPv6 (it captures full link-layer frames
and dispatches by EtherType). When AF_PACKET is unavailable, `run()`
falls back to the raw-socket path and starts **two concurrent receiver
goroutines** — `receiver()` (IPv4 raw, proto 112) and, if an IPv6 socket
exists, `receiverIPv6()` (`ip6:112`). Both feed the same per-instance
`rxCh` and, on a full channel, both call `warnRXDrop()`. Every field
they share on that drop path is therefore concurrency-safe: `rxReceived`
and `rxDrops` are `atomic.Uint64`, and `lastDropWarn` (the once-per-10s
warning rate-limiter) is an `atomic.Int64` of Unix nanos updated with
`CompareAndSwap` — only the goroutine that swaps the stale timestamp logs
the warning, so a concurrent drop burst yields one log line per interval
(#2225, mirrors the `lastGARPTime` dampener). A plain `time.Time` here
was an unsynchronized read-modify-write across the two goroutines (a
`go test -race` data race).

The self-sent-advert filter is a second cross-goroutine hazard.
`localIP` / `localIPv6` are resolved once in `openSocket()` — **before**
any goroutine starts — but that resolution can come back empty (no IPv4
address assigned yet, or IPv6 DAD still running). In that case
`sendPacket()` / `sendPacketIPv6()` perform a one-shot **lazy-resolve
write** from the run-loop goroutine, while every receiver
(`receiver` / `receiverIPv6` / `parseAfPacketIPv4` / `parseAfPacketIPv6`)
reads the fields to drop self-sent adverts. With the fields as plain
`net.IP` this write/read was an unsynchronized data race (#2258, fires
at most once — only when the address was unresolved at socket-open).
They are now `atomic.Pointer[net.IP]` accessed solely via
`getLocalIP`/`setLocalIP` and `getLocalIPv6`/`setLocalIPv6` (a `nil`
pointer means unresolved). The lazy-resolve semantics are preserved —
the address still becomes available once it is resolvable — and the
packet hot path stays lock-free, mirroring the `lastDropWarn` atomic.

`advertInterval()` is a third cross-goroutine hazard (#6230). The
run-loop goroutine calls it on every advert-timer reset to read
`cfg.AdvertiseInterval`, while cfg writers (`updateConfig`) mutate `cfg`
under `vi.mu.Lock()`. The read was unlocked — a data race `go test
-race` flags — where every sibling accessor (`getState`,
`masterDownInterval`, `preemptHoldDuration`) already snapshots `cfg`
under `vi.mu`. It now RLocks like they do. The one caller that already
holds the write lock, `recordMasterAdvert` → `masterAdverFloor`, reads
via the lock-free `advertIntervalLocked` variant instead — re-taking the
RLock under the held `Lock()` would self-deadlock.

#### Source re-resolution on address change (#2528)

The lazy-resolve above only fires when the cached source is **nil**
(unresolved at socket-open). It does **not** handle a source that was
resolved once and then **changed or removed** while the instance runs —
the cached `localIP`/`localIPv6` stayed permanently stale. That stale
source is doubly harmful: the kernel silently rejects an advert whose
source is no longer on the interface (the RG goes silent), AND
self-filtering in `handleMasterRx` misclassifies our own adverts as a
peer's → false MASTER-MASTER conflict / split-brain. The realistic
trigger is the **RETH MAC reprogram cycle** (`programRethMAC`: link
DOWN → set MAC → UP flushes ALL kernel addresses; networkd
`KeepConfiguration=static` restores them, but with a 30 ms–1 s window
against the next 30 ms advert), plus a DAD-failed link-local re-add.

#### Self-frame filtering does not depend on the address snapshot (#6560)

The address re-resolution above narrows the stale-source window but
cannot close it, because `reresolveLocalAddrs` legitimately stores
**nil** when the interface has no non-VIP address of the family — which
is exactly what the flush window produces. Every self-check on the
receive path is written `lip != nil && src.Equal(lip)`, so **a nil
snapshot means ACCEPT**. Combined with the delivery paths below, a
MASTER could process its OWN advertisement, land on
`resolveEqualPriorityMaster`'s equal-priority branch, hit the
`localCmp == nil` arm, and `becomeBackup` — the "stepping down" log line
whose comment justifies the step-down by assuming the advert came from a
peer. In this case the "actively advertising equal-priority peer" is the
node itself.

Self-adverts really are delivered, by two independent mechanisms, and
neither was suppressed:

- **The AF_PACKET tap (primary path).** The capture socket is
  `ETH_P_ALL` — what tcpdump uses, and why tcpdump shows egress
  traffic. `dev_queue_xmit_nit` clones every outbound frame to each
  `ptype_all` tap with `skb->pkt_type = PACKET_OUTGOING`, and
  `packet_rcv` drops only `PACKET_LOOPBACK`. Adverts leave on the raw
  AF_INET/AF_INET6 sockets, but they egress the very netdev this socket
  is bound to. The cBPF filter cannot help: every instruction matches
  ethertype or IP protocol, there is no `SKF_AD_PKTTYPE` ancillary
  load, and a self-advert satisfies it exactly.
- **IP multicast loopback (fallback path).** The raw `ip4:112` /
  `ip6:112` sockets both send and `JoinGroup` 224.0.0.18 / ff02::12,
  and `IP_MULTICAST_LOOP` defaults to 1 — so the kernel cloned every
  advert we transmitted back into the socket that sent it.

Three fixes, none of which touch the state machine:

1. `PACKET_IGNORE_OUTGOING` on the AF_PACKET receiver, set **before**
   bind (an `ETH_P_ALL` socket is already capturing at creation, so
   setting it after bind would leave a window). Best-effort: it is
   Linux >= 4.20 and an older kernel logs and continues.
2. `receiverAfPacket` now keeps the `sockaddr_ll` that `Recvfrom`
   returns — it used to discard it as `_`, which made `sll_pkttype`
   structurally unavailable — and drops `PACKET_OUTGOING`. This is the
   belt that still holds on a kernel without (1).
3. `IP_MULTICAST_LOOP` / `IPV6_MULTICAST_LOOP` disabled on the fallback
   raw sockets. Both are per-SENDING-socket, so they suppress only the
   loopback of our own transmissions; a peer's advert arriving from the
   wire is unaffected.

An unclassifiable sockaddr **fails open** (treated as not-outgoing).
Dropping a frame we cannot classify would be a self-inflicted
master-down, which is strictly worse than the bug being fixed.

**The residual #6560 named is closed by #7334.** `resolveLocalIPv4` selects ONE
address (the lowest non-VIP), so a self-advert sent from address A bypassed the
comparison once the selected source had become B — a NON-nil snapshot that still
fails. `resolveEqualPriorityMaster` then compared `peerCmp` (our own OLD source
A) against `localCmp` (our own NEW source B) and stepped down whenever `A > B`:
a coin flip, and a self-inflicted master-down.

The four receive-path self-checks now consult `isLocalAddr`, which tests
membership in the interface's full non-VIP **address set** for the frame's
family. **The selection and the set are different things, deliberately:**

- the SEND source stays one deterministic address (the lowest), so it does not
  flip on unrelated secondary-address churn — that is #2528's whole point;
- the self-CHECK must recognise every address we might have sent from,
  including one the selection has since moved off.

Both are recomputed from a single `reresolveLocalAddrs` read, so the set can
never lag the selection.

**It fails OPEN on an unresolved set**, matching the posture #6560 established.
An empty set is exactly the #2528 RETH-MAC flush window — `programRethMAC` does
link DOWN, set MAC, UP, and DOWN flushes every kernel address. A frame we cannot
classify must still be able to be a peer's advert; dropping it would be the
self-inflicted master-down the change exists to prevent, so the fix's failure
direction is bounded by the same rule as the bug's.

The alternative #7334 lists — comparing the frame's source MAC against
`vi.iface.HardwareAddr` on the AF_PACKET path — was not taken. It covers only
that one path, whereas the address set covers all four call sites including the
raw-socket receivers, and it would introduce an L2 identity the package
currently does not use at all.

The manager now runs a singleton ADDRESS-watcher (`addrwatch.go`,
`runAddrWatcher`) subscribed via `netlink.AddrSubscribe`. On any address
add/del whose `LinkIndex` matches an instance's bound `iface.Index`, it
calls `reresolveLocalAddrs()`, which recomputes both sources from the
interface's **current** addresses (`resolveLocalIPv4` picks the lowest
non-VIP IPv4 deterministically; `resolveIPv6LinkLocal` picks the lowest
non-VIP **link-local** — VRRP IPv6 adverts use a `fe80::` source) and
stores them atomically. The "non-VIP" exclusion compares against the
configured VIP set built by `vipAddrSet`, which canonicalizes each VIP via
`net.ParseIP` before keying the set (`canonAddr`, #2516) so a
non-canonically-formatted IPv6 link-local VIP (`fe80::AB` vs `fe80::ab`)
still matches the canonical `net.IP.String()` form the interface reports —
otherwise the VIP would leak into the candidate set and the engine would
source adverts from its own VIP, self-filtering them as a peer's.
Because every add/del emits an event, the final
address state always wins a re-resolve. A transient empty result is
stored as `nil` so the next advert's lazy-resolve recovers it. The
watcher filters by ifindex so churn on an unrelated interface never
disturbs a VRRP source. The TX (`sendPacket`/`sendPacketIPv6`) and RX
(`handleMasterRx` self-filter) paths read the SAME re-resolved value via
`getLocalIP`/`getLocalIPv6`, so self-filtering stays consistent after a
re-resolve. The watcher is an optimization that closes the
stale-**non-nil** window; a subscribe failure degrades to pre-#2528
behavior (the lazy nil-path and the 2 s reconcile still recover the
nil-source case) rather than breaking correctness, so there is no poll
fallback (unlike the link-watcher). The `subscribeAddrs` seam defaults to
`netlink.AddrSubscribe` and is injectable for tests.

### AF_PACKET cBPF filter + IPv6 extension headers (#2155)

The AF_PACKET receiver attaches a cBPF prefilter
(`vrrpCBPFFilter`, attached in `openAfPacketReceiver`, `manager.go`) so
the kernel drops non-VRRP frames before they reach the per-instance RX
goroutine. It handles untagged and **single-tag** IPv4/IPv6, admitting
BOTH `0x8100` (802.1Q) and `0x88a8` (802.1ad / S-tag) as the outer VLAN
ethertype (#5088):

- **Kernel prefilter and userspace parser MUST admit the same
  encapsulation set (#5088).** A single S-tag has the identical layout as
  a C-tag (real ethertype at offset 16), and `parseAfPacket`
  (`instance_receive.go`) accepts both `0x8100` and `0x88a8`. Before #5088 the
  cBPF matched only `0x8100`, so on an S-tagged / provider-bridged segment
  the kernel dropped every advert before Go — both nodes went mutually
  deaf and could own the same VRID/VIPs (split-brain) despite the parser's
  advertised 802.1ad support. Adding the `0x88a8` instruction shifts the
  raw cBPF's relative jump offsets, which were recomputed; the exact
  program is exercised in a `bpf.VM` (`cbpf_8021ad_5088_test.go`) against
  untagged / 802.1Q / 802.1ad / non-VRRP frames. **Double-tag QinQ**
  (`0x88a8` then `0x8100`, real ethertype at offset 20) is deliberately
  NOT admitted — the Go parser does not decode it either, so the shared
  contract stays "untagged + single-tag {0x8100, 0x88a8}".
- IPv4 matches base protocol `== 112`; `parseAfPacketIPv4` then
  re-walks IHL + re-checks TTL 255 in Go (so IPv4 options are tolerated).
- IPv6 matches the base **Next-Header** against the set
  `{112 VRRP, 0 Hop-by-Hop, 43 Routing, 60 Dest-Opts}`
  (approach A2). A chained VRRP advert's base Next-Header is the FIRST
  ext-header's type, not 112, and a fixed-offset cBPF cannot walk an
  ext-header chain — so admitting these ext-header types lets any
  conformant advert through while ordinary IPv6 TCP/UDP/ICMPv6/ND stays
  kernel-dropped on a data-bearing RETH VLAN (e.g. `reth0.80`).
  Fragment (44) and AH (51) are deliberately **not** admitted: VRRP is
  never legitimately fragmented (no reassembly) and never IPsec-AH-wrapped
  (it authenticates itself), so such frames stay kernel-dropped instead of
  waking the RX goroutine only for the Go walker to drop them. The cBPF is
  only a volume reducer; authoritative validation is in Go.

`parseAfPacketIPv6` performs a **bounded** IPv6 ext-header walk
(`walkIPv6ExtHeaders`) to locate the real proto-112 payload offset
instead of assuming the old fixed 40-byte base header. Conventions and
explicit drop bounds (deliberate, documented):

- Hop-by-Hop (0) / Routing (43) / Dest-Opts (60) are the only chained
  headers a conformant advert can carry; each is `(HdrExtLen+1)*8` bytes
  (8-byte units) and is walked to the next header.
- Fragment (44) is a **hard drop** — VRRP adverts are never legitimately
  fragmented and the receiver does no reassembly. The cBPF prefilter
  already refuses base Next-Header 44, so the walker's drop is
  defense-in-depth for a Fragment header buried mid-chain.
- AH (51) and any other Next-Header is **dropped** — VRRP is not
  IPsec-AH-wrapped, so AH is not a VRRP carrier. The cBPF likewise
  refuses base Next-Header 51, so an AH-first advert is kernel-dropped
  before the walk runs.
- The walk is capped at 8 iterations and bounds-checks every step
  against the captured length, so a truncated or maliciously long chain
  can neither loop nor read out of bounds — it is simply dropped.

The raw `ip6:112` socket fallback (non-AF_PACKET path) is ext-header-safe
for the common extension headers because the kernel walks the chain and
hands `ReadFrom` the upper-layer payload directly. AH and fragmented
VRRP are out of scope on **both** paths — the cBPF, the Go walker, and the
fallback all agree that only `{112, 0, 43, 60}` carry a VRRP advert.

**Homogeneous-peer expectation:** xpf's own IPv6 sender emits a bare
base header (no ext-headers, hop-limit 255) per RFC 5798, which is the
normal way VRRPv3 IPv6 adverts are sent. The ext-header walk exists only
to interoperate with an unusual non-xpf VRRP speaker that inserts
extension headers; deploy homogeneous xpf peers and this path is never
exercised.

**Deliberately separate from the Rust dataplane walkers (#2150):** this
Go `walkIPv6ExtHeaders` is a parallel, intentionally non-shared
implementation. The Rust AF_XDP dataplane has its OWN canonical IPv6
ext-header walker (`userspace-dp/src/afxdp/frame/inspect.rs::packet_rel_l4_offset_and_protocol`,
#2148) and its own L2 parse contract (see
`userspace-dp/src/afxdp/frame/README.md`, #2150). Code cannot be shared
across the Go/Rust boundary, so any change to the ext-header walk
semantics must be mirrored by hand in both — do NOT assume the Rust
dataplane reuses this Go walker, and do NOT try to consolidate them.

## Gotchas

- Use the **non-VIP** primary IP as source on advertisements. Sourcing
  from the VIP would self-filter peer adverts.
- **`accept-data` is accepted for Junos config compatibility but is a
  no-op (#4080).** The leaf parses and compiles into `AcceptData`
  (`schema_interfaces.go`, `compiler_interfaces.go`), but no non-test
  code reads it to gate behavior. xpf uses a **VIP-as-real-address**
  model: on MASTER, `addVIPs()` installs each VIP as a genuine local
  kernel address via `netlink.AddrAdd` (`instance_vip.go`), so the Linux
  stack itself answers ARP/ND and replies to ICMP echo / accepts
  host-inbound traffic addressed to the VIP — regardless of the flag.
  That is exactly RFC 5798 §6.1 `Accept_Mode=on` (a pingable VIP, the
  common operator default), so `accept-data` on/off cannot change
  today's behavior. `accept-data=off` (the RFC default,
  don't-respond-unless-owner) is a **deferred non-default**: it would
  require NOT installing the VIP as a real kernel address — which
  directly conflicts with the `bpf_fib_lookup` dependency in
  `becomeMaster` and the VIP install/reconcile machinery
  (`ReconcileVIPs`, `KeepConfiguration=static`, GARP epoch/dampener) —
  plus the dataplane taking over ARP/ND and dropping VIP-addressed
  host-inbound traffic. That is a dataplane + control-plane redesign,
  not a wired gate; see #4080.
- RETH virtual MAC per node: `02:bf:72:CC:RR:NN`. Programmed via link
  DOWN → set MAC → link UP. This bounces all kernel addresses; VIPs are
  re-added by `ReconcileVIPs()` immediately afterwards, and the advert
  **source** (`localIP`/`localIPv6`) is re-resolved by the #2528
  address-watcher (`addrwatch.go`) as the flushed base/link-local
  addresses are re-added — so the instance never keeps advertising from a
  source that the MAC cycle removed (see "Source re-resolution on address
  change" above).
- Bind retry on simultaneous boot avoids losing the master election to
  whichever node booted first.
- Event channel is bounded at 256; backpressure increments an atomic
  counter and triggers a reconciliation callback. Don't switch to an
  unbounded channel — the counter is the early warning that something
  upstream stopped draining.
- Instance restart on VIP change is **build-before-teardown** (#2156):
  the new socket must open before the old instance is stopped, so the
  old `run()` goroutine and the new one never run concurrently for the
  same key (the proof step opens the socket but does NOT start `run()`;
  only the commit step stops the old, swaps, and starts the new). On a
  build failure no placeholder is added to `m.instances`, so
  `States` / `InstanceStates` / `Status` stay truthful. **`RGVRRPReady`
  needs more than that (#5641):** an RG usually has SEVERAL desired RETH
  keys under one VRID (a VLAN-tagged reth emits one instance per
  sub-interface — `reth0.50` + `reth0.80` — and reths can share the RG),
  so "one instance exists for the VRID" does NOT prove the RG is fully
  built. `UpdateInstances` records every desired key with no live instance
  in `m.unbuiltDesired` (the `desiredMap`-vs-`m.instances` diff, with the
  captured resolve/socket reason), and `RGVRRPReady` returns
  `(false, reasons)` naming any un-built key for the RG. This closes the
  false-ready hole where a sibling member/VLAN-sub/family key failed to
  build, its VIP was dark, yet the cluster state machine released the sync
  hold / preempted / claimed ownership. A build failure that leaves the
  OLD instance advertising (the case above) keeps its key in `m.instances`
  and is therefore NOT flagged — the RG is still in election, just on its
  previous VIP set. `RGVRRPReady` remains a pure readiness READ (no advert
  timing / socket / datapath change).
  Bounded self-recovery comes from the daemon's 2s
  `reconcileRGStateLoop`, which re-drives `reconcileVRRPInstances` →
  `UpdateInstances` every tick; a deferred restart retries (and succeeds)
  once the interface returns, with no operator re-commit. During the
  failure window the RG keeps advertising the OLD VIP set — strictly
  better than dropping out of election; the intended VIPs land on the
  next successful re-drive (~2s).
- The instance-lifecycle seams (`resolveIface`, `openInstanceSocket`,
  `runInstance`, `stopInstance`), link seams (`linkState`,
  `subscribeLinks`), the address seam (`subscribeAddrs`, #2528), and the
  per-instance `addrsFn` interface-address seam (#2528) exist so unit
  tests exercise the diff/lifecycle and source-resolution logic without
  real netlink, raw sockets, or live goroutines. Production defaults are
  wired in `NewManager` (`addrsFn` defaults to nil → live
  `iface.Addrs()`); do not change a seam's production default without
  updating the matching test fakes.

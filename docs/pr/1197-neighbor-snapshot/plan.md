---
status: REVISED v7 — Codex round-6 PLAN-NEEDS-MINOR; 3 final text fixes; PROCEEDING to implementation
issue: #1197
phase: Plan + fix design
prior:
  - v1 commit 2709752f — fixed second loop only; missed 5 things
  - v2 commit f6e7070a — addressed Codex round-1 5 findings (incremental defense)
  - v3 commit 867bd363 — kernel-as-authority redesign per user feedback
  - v4 commit 4bcb7947 — Codex round-3 4 substantive holes
  - v5 commit 0ae008de — Codex round-4 5 more holes
  - v6 (this) — Codex round-5 PLAN-NEEDS-MINOR; 6 nits applied
---

## 1. Issue framing (unchanged)

Issue #1197: xpfd preinstalls stale neighbor MAC into kernel ARP
every 15s. When peer MAC changes, kernel briefly learns fresh MAC
via normal ARP, then xpfd reverts. Self-heals only via xpfd
restart.

## 2. Design shift from v2 to v3

User feedback rejected the v2 incremental-defense approach in favor
of the principled redesign:

> "Shouldn't we be listening for neighbor advertisements and
> updating those when it changes to what we have cached? Also
> shouldn't we doing a neighbor solicit when our view of the
> world expires. We shouldn't be caching the mac forever if we
> haven't heard from it for a while. We should actually
> pre-emptively send our an NS before we expire the entry to
> make sure it's still there."

This is RFC 4861 NUD discipline applied to the snapshot:
- **Listen** on netlink for kernel ARP/NDP changes (RTM_NEWNEIGH/
  RTM_DELNEIGH).
- **Don't cache forever** — kernel NUD does the aging; xpfd
  follows. (Note: per-entry TTL inside xpfd is **deferred
  follow-up**, not shipped in this PR — kernel events plus the
  60s safety reconciliation tick are sufficient for the
  bug-class fix.)
- **Proactively probe** before an entry is too cold via NS/ARP,
  give the kernel a chance to confirm it's still valid.
- **Trust the kernel** as the source of truth on the current MAC.
  Stop pushing snapshot-MAC into kernel ARP.

The current design fights the kernel's NUD machinery. The right
design is to compose with it.

## 3. Inverted authority model

### Current (broken) data flow

```
xpfd snapshot (Go memory)  →  kernel ARP (push every 15s, NeighSet)
xpfd snapshot (Go memory)  →  userspace-dp state.neighbors (publish on regen)
```

Snapshot is treated as authoritative; pushed both ways.

### v3 data flow

```
Kernel ARP/NDP ← (kernel runs RFC 4861 NUD: REACHABLE→STALE→DELAY→PROBE)
Kernel ARP → xpfd snapshot ← listen on RTM_NEWNEIGH/DELNEIGH
xpfd snapshot → userspace-dp state.neighbors (publish on change)
xpfd → kernel: send proactive NS/ARP via resolveNeighbors
              for next-hops we actively care about
```

Kernel is authoritative; xpfd is a listener + proactive prober.

## 4. Existing infrastructure to leverage

### Netlink neighbor subscription
`pkg/daemon/daemon_ha_fabric.go:809` — `netlink.NeighSubscribe`
already exists, narrowly scoped to fabric peer IPs. We extend
or parallel this for all monitored neighbors.

### Proactive probing
`pkg/daemon/daemon_neighbor.go:117` — `resolveNeighbors` already
sends ARP / IPv6 NS for known next-hops, NAT destinations, address-
book hosts. Called from:
- `daemon_health.go:84` (health check)
- `daemon_ha_vip.go:174` (VRRP master transition)
- `daemon_apply.go:807` (after config apply)
- `daemon_neighbor.go:430,451` (config commit + DHCP refresh)

We add a periodic timer that calls `resolveNeighbors` (or its
inner equivalent) so kernel-side entries stay warm.

### Snapshot regeneration
`pkg/dataplane/userspace/manager.go:421` — `BumpFIBGeneration`
already rebuilds snapshot via `buildNeighborSnapshots(cfg)` and
publishes via `update_neighbors`. The new netlink listener
triggers this on neighbor change.

## 5. Concrete v3 design

### 5.1 Phase 1: stop the bug

Two minimum changes that stop the connectivity-breaking behavior:

**A) Remove the snapshot-driven NeighSet loop entirely.**
`pkg/daemon/daemon_neighbor.go:78-101` — delete this loop. It
unconditionally overwrites kernel ARP with stale snapshot MAC.
The replacement: nothing at the kernel-write level; we listen
instead.

**B) Make the kernel-list NeighSet loop state-preserving.**
`pkg/daemon/daemon_neighbor.go:33-74` — read kernel ARP, but
only re-NeighSet entries that are ALREADY REACHABLE. Don't
promote STALE/DELAY/PROBE → REACHABLE. (The whole loop is
arguably useless once we listen, but minimal-fix says preserve
the "keep REACHABLE timer warm" behavior.)

Actually — simpler: **delete the entire `preinstallSnapshotNeighbors`
function**. The kernel manages its own ARP. We don't touch it.
The function's stated purpose (keep standby warm for failover) is
already covered by:
- `resolveNeighbors` at activation (sends ARP/NS to populate kernel)
- The new netlink listener that keeps snapshot fresh
- The new periodic probe timer

The 15s preinstall tick disappears entirely.

### 5.2 Phase 2: listen for changes — **CORRECTED per Codex round-3**

Codex round-3 caught two issues with v3 listener:

1. **Filter scope wrong.** `buildNeighborSnapshots` publishes
   ALL kernel neighbors on configured forwarding/fabric
   interfaces (`snapshot.go:1758-1850`). Filter must align with
   that — not narrowed to next-hops only.

2. **Subscription is lossy.** Multicast can drop; not every NUD
   transition is notified. Need `NeighSubscribeWithOptions` with
   `ListExisting: true` (initial dump), error-callback resubscribe,
   debounce, periodic safety reconciliation.

3. **Event handling can't be MAC-only.** RTM_DELNEIGH must trigger
   immediate snapshot eviction. State changes to FAILED/INCOMPLETE
   may also matter. Avoid publish-churn on harmless REACHABLE↔STALE
   transitions via forwarding-effective diff.

Corrected design:

```go
// neighborListener runs the netlink RTM_NEWNEIGH/DELNEIGH event
// loop. Triggers snapshot regen when a monitored neighbor's
// forwarding-effective state changes.
func (d *Daemon) neighborListener(ctx context.Context) {
    var (
        regenDebounce = make(chan struct{}, 1)
        debounceMs    = 100 * time.Millisecond
    )
    // Debounce coalesces bursts (e.g., GARP storm during failover)
    go d.regenDebouncer(ctx, regenDebounce, debounceMs)

    // Periodic safety reconciliation: catches lost multicast events
    safetyTick := time.NewTicker(60 * time.Second)
    defer safetyTick.Stop()

    for {
        if !d.runOneSubscription(ctx, regenDebounce, safetyTick) {
            return // ctx done
        }
        // Subscription closed; resubscribe after backoff.
        select {
        case <-ctx.Done():
            return
        case <-time.After(2 * time.Second):
        }
    }
}

// runOneSubscription owns ONE NeighSubscribe lifetime. Returns
// true to keep retrying (resubscribe), false on ctx done.
//
// Codex round-4: the previous v4 sketch had a `break` inside a
// `select` that exited the select, not the inner loop, so a
// closed updates channel could spin and double-close `done`.
// This helper makes the lifetime explicit: subscription opened,
// loop runs to first error/close, then helper returns and outer
// loop reopens.
func (d *Daemon) runOneSubscription(
    ctx context.Context,
    regenDebounce chan struct{},
    safetyTick *time.Ticker) bool {

    updates := make(chan netlink.NeighUpdate, 1024)
    done := make(chan struct{})
    opts := netlink.NeighSubscribeOptions{
        ListExisting:      true,
        ErrorCallback:     func(err error) {
            slog.Warn("neighbor listener netlink err", "err", err)
        },
        ReceiveBufferSize: 1 << 20, // 1 MB; channel size != socket buf
    }
    if err := netlink.NeighSubscribeWithOptions(updates, done,
                                                opts); err != nil {
        slog.Warn("neighbor subscribe failed", "err", err)
        // Codex round-5 #5: NeighSubscribeWithOptions can start
        // its done goroutine before a ListExisting dump fails.
        // Close done explicitly here to avoid leaking the goroutine.
        close(done)
        return true // try again after backoff
    }
    defer close(done) // always close on successful subscribe path

    for {
        select {
        case <-ctx.Done():
            return false
        case <-safetyTick.C:
            d.triggerRegen(regenDebounce)
        case u, ok := <-updates:
            if !ok {
                return true // subscription closed; resubscribe
            }
            if !d.isMonitoredNeighbor(u.LinkIndex) {
                continue
            }
            if d.shouldTriggerRegen(u) {
                d.triggerRegen(regenDebounce)
            }
        }
    }
}

// isMonitoredNeighbor returns true if linkIndex belongs to an
// interface enumerated by buildNeighborSnapshots. Codex round-4
// caught: that snapshot iterates all configured base interfaces
// AND units (snapshot.go:1768-1787), not an informal "forwarding/
// fabric" subset. Export the enumeration as a public helper.
//
// Codex round-5 #3: pure config-derived filter has runtime
// ifindex drift hazard. If a link/VLAN disappears, recomputing
// via current LinkByName excludes the old ifindex, so an
// RTM_DELNEIGH for the disappeared ifindex gets dropped until
// the 60s safety regen. Mitigation: also include the union of
// CURRENT SNAPSHOT KEYS (entries we've already published to
// userspace-dp). A delete event for any published key MUST be
// processed even if the link is gone.
func (d *Daemon) isMonitoredNeighbor(linkIndex int) bool {
    cfg := d.store.ActiveConfig()
    if cfg == nil { return false }
    monitored := userspace.MonitoredInterfaceLinkIndexes(cfg)
    if _, ok := monitored[linkIndex]; ok {
        return true
    }
    // Snapshot-key fallback: we've already published entries for
    // this ifindex; we need delete events even if link is gone.
    if d.dp != nil && d.dp.SnapshotHasIfindex(linkIndex) {
        return true
    }
    return false
}

// shouldTriggerRegen filters out forwarding-irrelevant churn.
// Codex round-4: userspace forwarding (forwarding/mod.rs:45)
// treats every state EXCEPT failed/incomplete as usable. So
// new entries in DELAY/PROBE/NOARP with a valid MAC also need
// to trigger. Same-MAC state churn (REACHABLE↔STALE etc.) is
// the only ignored case.
//
// "Usable" set (must match userspace-dp's neighbor.rs treatment).
// Codex round-5 #2: explicitly EXCLUDE NUD_NONE (state==0). Rust
// treats "none" as usable because it's not failed/incomplete, but
// state-0 entries have no learned MAC and must not be published.
// This Go set must match neighborSnapshotPublishable's reject set.
//
// NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT | NUD_NOARP
const usableNUD = netlink.NUD_REACHABLE | netlink.NUD_STALE |
                  netlink.NUD_DELAY | netlink.NUD_PROBE |
                  netlink.NUD_PERMANENT | netlink.NUD_NOARP

func (d *Daemon) shouldTriggerRegen(u netlink.NeighUpdate) bool {
    switch u.Type {
    case syscall.RTM_DELNEIGH:
        // Kernel evicted entry; snapshot must drop it immediately.
        return true
    case syscall.RTM_NEWNEIGH:
        existing := d.dp.LookupSnapshotNeighbor(u.LinkIndex, u.IP)
        hasMAC := u.HardwareAddr != nil && len(u.HardwareAddr) > 0
        usable := u.State&usableNUD != 0
        unusable := u.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) != 0

        if existing == nil {
            // New usable entry with valid MAC → snapshot must learn it.
            return hasMAC && usable
        }
        // Existing snapshot has this entry.
        // 1. MAC change → always trigger (the bug-class case).
        if hasMAC && !bytes.Equal(existing.MAC, u.HardwareAddr) {
            return true
        }
        // 2. Transition to unusable → snapshot must drop entry.
        if unusable {
            return true
        }
        // 3. Same MAC, same usable category → harmless aging churn.
        return false
    }
    return false
}

// regenDebouncer coalesces regen requests so a burst of events
// (e.g., GARP storm during failover) results in one regen.
//
// Codex round-5 #5: previous version had a data race on `pending`
// because `time.AfterFunc` fires its callback in a separate
// goroutine. Replaced with a same-goroutine timer-channel pattern.
func (d *Daemon) regenDebouncer(ctx context.Context,
                                 ch chan struct{},
                                 delay time.Duration) {
    var timer *time.Timer
    var timerC <-chan time.Time

    for {
        select {
        case <-ctx.Done():
            if timer != nil {
                timer.Stop()
            }
            return
        case <-ch:
            // Request received: arm or reset timer.
            if timer == nil {
                timer = time.NewTimer(delay)
                timerC = timer.C
            } else {
                if !timer.Stop() {
                    // Drain stale fire if any.
                    select {
                    case <-timer.C:
                    default:
                    }
                }
                timer.Reset(delay)
                timerC = timer.C
            }
        case <-timerC:
            // Debounce window elapsed; regenerate.
            if d.dp != nil {
                d.dp.RegenerateNeighborSnapshot()
            }
            timerC = nil // disarm until next request
        }
    }
}

func (d *Daemon) triggerRegen(ch chan struct{}) {
    select { case ch <- struct{}{}: default: }
}
```

This requires a new `Manager.LookupSnapshotNeighbor(ifindex, ip)`
method (cheap O(1) read of in-memory snapshot map).

### 5.3 Phase 3: proactive expiry + reprobe — **CORRECTED per Codex round-3 + round-4**

Codex round-3 caught: `resolveNeighborsInner` at
`daemon_neighbor.go:323-334` skips entries already in
`NUD_REACHABLE|NUD_STALE|NUD_PERMANENT`. Idle STALE entries
**never get re-probed by this path**.

Codex round-4 added: `forceProbeNeighbors` is right shape but
**`collectMonitoredNeighbors` was undefined**, and the force
path **must also fire on RG takeover** (not only the 15s tick).
And **target prioritization** is needed: probe
STALE/PROBE/DELAY first, then on-link/next-hops, then rest —
to avoid a 256-target ARP storm at startup.

Defining `collectMonitoredNeighbors` precisely:

```go
// collectMonitoredNeighbors returns the deduped union of:
//   1. Current snapshot keys (every neighbor xpfd has published
//      to userspace-dp).
//   2. Configured next-hops, NAT destinations, address-book hosts.
//   3. Fabric peer IPs.
//
// Codex round-5 #4: tiering must be globally state-aware, not
// per-source. Build the full deduped target set FIRST, then for
// each target probe current kernel NUD state once via NeighList,
// then sort:
//
//   tier 1: state ∈ {STALE, PROBE, DELAY, FAILED, INCOMPLETE,
//                    NONE/missing} — at risk of stale forwarding
//   tier 2: state == REACHABLE AND target is critical
//           (next-hop or fabric peer)
//   tier 3: everything else (REACHABLE non-critical)
//
// Within a tier, sort by criticality (next-hops > fabric peers
// > snapshot keys > address-book).
//
// Truncate at the cap (default 256). Log skipped count.
func (d *Daemon) collectMonitoredNeighbors(
    cfg *config.Config) []probeTarget {
    // Implementation: iterate active snapshot first via
    // dp.SnapshotNeighbors() to learn (ifindex, IP, current
    // kernel state via NeighList lookup). Then add configured
    // targets via the existing addByIP/addByName helpers in
    // resolveNeighborsInner. Sort into tier order, truncate.
    // ...
}

// forceProbeNeighbors sends ARP/NS probes for monitored targets
// REGARDLESS of NUD state (no skip-STALE). Distinct from
// resolveNeighborsInner which only fills missing/INCOMPLETE/FAILED
// entries — that semantics is right for activation priming, but
// wrong for steady-state staleness reconciliation.
func (d *Daemon) forceProbeNeighbors(cfg *config.Config) {
    targets := d.collectMonitoredNeighbors(cfg)
    cap := d.neighborProbeMaxTargets // default 256
    if len(targets) > cap {
        slog.Warn("neighbor probe truncated",
                  "total", len(targets), "cap", cap)
        targets = targets[:cap]
    }
    for _, t := range targets {
        link, err := netlink.LinkByIndex(t.linkIndex)
        if err != nil { continue }
        ifName := link.Attrs().Name
        go func(ip net.IP, iface string) {
            if ip.To4() == nil {
                _ = cluster.SendNDSolicitationFromInterface(iface, ip)
            }
            sendICMPProbe(iface, ip)
        }(t.neighborIP, ifName)
    }
}
```

**RG takeover must call forceProbeNeighbors too.** Currently
`daemon_ha_vip.go:174` calls `resolveNeighbors` (skip-stale) on
VRRP MASTER. Change that call to `forceProbeNeighbors` so a
takeover with stale snapshot entries gets re-validated, not
left alone.

This is the periodic cadence (default 15s, tunable) that drives
proactive reprobing. Replies → kernel ARP update → RTM_NEWNEIGH
→ our listener → snapshot regen → userspace-dp update.

**Cardinality concern (Codex finding #4):** address-book hosts
can be much larger than the 5-10 next-hops estimate. Add a
configurable cap via env `BPFRX_NEIGHBOR_PROBE_MAX_TARGETS`
(default 256; log target count when truncated).

### 5.4 Phase 4: snapshot regeneration with forwarding-effective diff

Codex round-4 caught: v4 plan's `shouldTriggerRegen` filters
event-loop churn correctly, but **`RegenerateNeighborSnapshot`
itself uses `neighborsEqual` (snapshot.go:160) which compares
RAW state**. So the 60s safety tick + `BumpFIBGeneration` can
still publish on REACHABLE↔STALE churn — the buggy publish
happens at the manager level, not the listener level.

Add a manager-level **forwarding-effective equality**:

```go
// neighborsEqualForwarding compares snapshot entries on what
// matters for forwarding decisions, using ONLY publishable
// entries (those userspace-dp will accept and use).
//
// Codex round-5: empty-MAC INCOMPLETE rows from buildNeighborSnapshots
// would otherwise affect equality even though userspace-dp drops
// them at handlers.rs:165. Filter both sides to publishable-only
// before comparing. This also catches "old usable disappearing
// to INCOMPLETE" because the publishable key disappears.
//
// Publishable predicate (must mirror userspace-dp accept logic):
//   - Ifindex > 0
//   - IP parseable
//   - MAC non-empty
//   - State NOT in {FAILED, INCOMPLETE, NONE}
//
// Compared fields:
//   - (Ifindex, IP, Family) key
//   - MAC
// (Usable-bit is implicitly true; non-publishable rows excluded.)
func neighborsEqualForwarding(a, b []NeighborSnapshot) bool {
    // Build map<(ifindex,ip,family), mac> for publishable rows
    // in each side; compare.
}

// Publishable predicate: must match userspace-dp's accept rules
// at handlers.rs:165 / forwarding_build.rs:326. Drift here is a
// silent forwarding bug — keep this in sync if userspace changes.
//
// Codex round-6 #2: parse IP and MAC instead of string-emptiness;
// matches what Rust does on accept (parses both) and rejects
// malformed strings here rather than letting them through to
// userspace-dp where they'd be silently dropped.
func neighborSnapshotPublishable(n NeighborSnapshot) bool {
    if n.Ifindex <= 0 {
        return false
    }
    if net.ParseIP(n.IP) == nil {
        return false
    }
    if _, err := net.ParseMAC(n.MAC); err != nil {
        return false
    }
    // "none" is what neighborStateString emits for raw state 0;
    // Rust treats "none" as usable, but Go publishing should NOT
    // emit it because state 0 entries have no learned MAC info.
    // Codex round-5 finding #2: bridge mismatch.
    switch n.State {
    case "failed", "incomplete", "none":
        return false
    }
    return true
}
```

Use this in `RegenerateNeighborSnapshot` and the
`BumpFIBGeneration`-driven path so ONLY forwarding-relevant
changes publish.

`Manager.RegenerateNeighborSnapshot()` becomes:

```go
// RegenerateNeighborSnapshot rebuilds neighbors[] from kernel
// ARP/NDP via buildNeighborSnapshots, diffs forwarding-effectively,
// and publishes update_neighbors only on real changes.
//
// Codex round-6 #1: filter the publish payload to publishable-only
// entries. Rust accepts everything-not-failed-as-usable, so an
// empty-MAC INCOMPLETE row would otherwise reach state.neighbors
// as a usable-but-broken entry. We MUST drop those at publish time.
func (m *Manager) RegenerateNeighborSnapshot() {
    m.mu.Lock()
    defer m.mu.Unlock()
    if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
        return
    }
    newNeighbors := buildNeighborSnapshots(m.lastSnapshot.Config)
    if neighborsEqualForwarding(m.lastSnapshot.Neighbors,
                                 newNeighbors) {
        return // no forwarding-relevant change
    }
    m.lastSnapshot.Neighbors = newNeighbors
    m.lastSnapshot.Generation = m.generation

    // Filter to publishable-only before pushing to userspace-dp.
    publishable := make([]NeighborSnapshot, 0, len(newNeighbors))
    for _, n := range newNeighbors {
        if neighborSnapshotPublishable(n) {
            publishable = append(publishable, n)
        }
    }
    m.publishUpdateNeighbors(publishable)
}
```

Called from:
- `neighborListener` debouncer (event-driven primary path)
- `BumpFIBGeneration` (continues to call this on FIB regen;
  forwarding-effective diff prevents churn)
- `forceProbeNeighbors` completion (after probes have had time
  to land; bound by the 100ms debounce)

## 6. What gets deleted / changed

### Deleted
- `pkg/daemon/daemon_neighbor.go:24-105` — entire
  `preinstallSnapshotNeighbors` function
- The 15s timer at `daemon_neighbor.go:468` that calls it
  (replaced by the new force-probe tick added below; NOT
  repurposed to call skip-stale `resolveNeighborsInner`)

### Added
- `pkg/daemon/daemon_neighbor.go` — `neighborListener`,
  `handleNeighUpdate`, `isMonitoredNeighbor`, `probeNeighbor`,
  `snapshotDisagreesOrMissing` helpers
- `pkg/dataplane/userspace/manager.go` —
  `RegenerateNeighborSnapshot()` public method

### Changed
- `pkg/daemon/daemon.go` (or wherever the periodic loop is wired)
  — start `neighborListener` goroutine at daemon init; replace
  preinstall tick with probe tick

## 7. HA / failover considerations (revised v6)

**Failover path (RG transition: standby → active):**
- VRRP MASTER event fires `becomeMaster`. Per Codex round-5 #6
  fix-up: this PR **changes** the call from `resolveNeighbors`
  (skip-stale) to `forceProbeNeighbors` (no-skip-stale, with
  prioritized targets) so a takeover with stale snapshot entries
  re-validates them immediately rather than leaving them stale.
- `forceProbeNeighbors` sends ARP/NS for all monitored targets
  including stale ones, prioritized.
- Kernel updates ARP table on replies.
- RTM_NEWNEIGH fires for each MAC change → our listener updates
  snapshot via debounced regen.
- userspace-dp `state.neighbors` is fresh BEFORE first packet
  forwarded by new active.

**No regression risk** — the activation-time priming is
strengthened (force-probe replaces skip-stale-resolve); the
periodic preinstall is removed. Both changes converge on
"snapshot reflects kernel; kernel is authority."

**Standby cold-cache concern:** while standby, no traffic forces
kernel ARP entries. The kernel may evict over time. When standby
becomes active, `forceProbeNeighbors` re-sends probes for ALL
monitored targets (including stale + missing). First-packet
delay is bounded by ARP RTT (~ms) — same as today, plus
prioritization ensures critical next-hops resolve first.

If we want to keep standby warmer, the periodic force-probe
(5.3) runs on standby too — sends NS/ARP, kernel resolves,
entries stay warm. Net effect: standby's kernel ARP and snapshot
are fresher under v6 than under v1-v2 (where periodic preinstall
was reverting kernel to stale snapshot every 15s).

## 8. Risk assessment v3

| Class | Level | Why |
|---|---|---|
| Behavioral regression | LOW | Removes a buggy path; activation primer + listener cover the use cases |
| HA correctness | LOW | Activation-time `forceProbeNeighbors` (replaces skip-stale `resolveNeighbors` on VRRP MASTER) re-validates stale entries on takeover |
| Performance regression | NEGLIGIBLE | One netlink subscription; periodic probe sends ~5-10 ARP/NS every 15s; vs current 99-entry NeighSet every 15s |
| Architectural mismatch | LOW | Aligns with kernel NUD; stops fighting it |
| Test coverage | MEDIUM | Need unit tests for listener filter + snapshot regen path; existing `resolveNeighbors` tests cover probe |

## 9. Phased ship plan

**PR 1 (this):** v5 atomic ship — Codex round-4 explicit:
*"One PR is fine only if delete + listener + force-probe + regen
diff ship atomically. Do not ship deletion alone."* So PR1
contains the complete replacement of the broken mechanism:

- **Delete** `preinstallSnapshotNeighbors` (and its 15s tick at
  `daemon_neighbor.go:468`). Stop the bug source.
- **Add** `neighborListener` with:
  - `NeighSubscribeWithOptions{ListExisting:true,
    ErrorCallback:...}` for initial dump + resubscribe loop
  - **Broad filter** matching `buildNeighborSnapshots` keyspace
    (any configured forwarding/fabric interface), NOT narrowed to
    "static next-hops"
  - **Forwarding-effective diff** in `shouldTriggerRegen` —
    ignore REACHABLE↔STALE↔DELAY↔PROBE on same MAC; trigger on
    MAC change, RTM_DELNEIGH, FAILED/INCOMPLETE
  - 100ms debounce coalescer
  - 60s safety reconciliation tick
- **Add** `Manager.RegenerateNeighborSnapshot()` (event-driven
  regen API)
- **Add** `Manager.LookupSnapshotNeighbor(ifindex, ip)` (O(1)
  cheap read for diff)
- **Add** `forceProbeNeighbors(cfg)` — sibling of
  `resolveNeighborsInner` that does NOT skip STALE entries.
  Called periodically (15s, configurable) to drive proactive
  re-validation of all monitored neighbors.
- **Tunable cap** via env `BPFRX_NEIGHBOR_PROBE_MAX_TARGETS`
  (default 256) + log target count when truncated. (A Junos-
  config-style knob like `neighbor-probe-max-targets` is a
  follow-up; env var is sufficient for this PR's operational
  needs and avoids touching the config schema/parser.)
- **Replace** the 15s preinstall tick with the new force-probe
  tick (NOT the existing skip-stale `resolveNeighborsInner`,
  per Codex finding #1).

**PR 2 (follow-up if needed):** TTL-based expiry on snapshot
entries. If kernel entries age out (RTM_DELNEIGH), our snapshot
follows. If we don't hear about an entry for >T, drop it from
snapshot. Forces re-resolution on next packet via the userspace-
dp's existing dynamic_neighbors fallback path.

**PR 3 (follow-up if needed):** explicit takeover-context
preinstall. If failover diagnostics show measurable first-packet
delay despite the new design, add a `preinstallOnTakeover()` that
fires only on RG_active transition (not periodic).

## 10. Test plan

**Unit (pkg/daemon):**
- `TestNeighborListenerUpdatesSnapshotOnMACChange`: install handler,
  inject RTM_NEWNEIGH with new MAC, assert
  `RegenerateNeighborSnapshot` called.
- `TestNeighborListenerIgnoresUnmonitored`: inject for an IP not
  in monitored set; assert no regen.
- `TestNeighborListenerHandlesDelNeigh`: inject RTM_DELNEIGH;
  assert proactive probe fired.

**Unit (pkg/dataplane/userspace):**
- `TestRegenerateNeighborSnapshotPublishesOnChange`
- `TestRegenerateNeighborSnapshotIdempotent`

**Cargo build clean** + cargo tests pass.
**Go test full suite:** zero regressions.

**Manual repro on loss userspace cluster:**
1. Deploy v3 build.
2. `ip neigh replace 172.16.80.200 lladdr <fake_mac> dev
   ge-0-0-2.80 nud reachable` on fw0.
3. Wait 30s.
4. Verify: kernel ARP shows REAL MAC (kernel re-resolved); xpfd
   snapshot has REAL MAC; cluster-host → 172.16.80.200 ping works.
5. Verify journal: RTM_NEWNEIGH events seen, snapshot regen
   triggered.

**Smoke matrix on loss userspace cluster:**
- Full 30-cell smoke (v4+v6, push+reverse, CoS-off+CoS-on,
  per-class 5201-5206) — confirms throughput preserved.
- Failover test: trigger RG1 failover; verify TCP survives;
  verify standby's kernel ARP is fresh (not stale + reverted).

## 11. Open questions for adversarial review v4

1. Is `forceProbeNeighbors` (no skip-STALE) at 15s cadence safe
   in terms of ARP/NS traffic on the wire? Cap protects against
   pathological large address-books, but normal case may still
   be 50-100 probes/min on a busy WAN-side interface.

2. Is the `shouldTriggerRegen` filter sufficient, or are there
   forwarding-effective state transitions it misses?
   Specifically: does NUD_NOARP need any handling
   (loopback/dummy entries)?

3. Is the 60s safety reconciliation tick the right cadence, or
   should it be tighter (10s) to bound staleness if multicast
   loses many events in a row?

4. Does the dynamic-neighbor fallback in
   `userspace-dp/src/afxdp/forwarding/mod.rs:1464` actually
   contain the kernel-learned data, or is it independent of
   netlink? If independent, even a perfect Go-side fix won't
   reach the data plane — Phase 1 needs to verify the
   `update_neighbors` publish path is end-to-end correct.

5. Is "delete `preinstallSnapshotNeighbors` entirely" safe in
   one PR, or should it be progressive (first reduce blast
   radius, then add listener, then delete)? The argument for
   one PR: removing the buggy code is the actual fix; the new
   listener is the replacement. Argument for progressive: less
   blast radius if the listener has bugs.

## 12. Verdict request

PLAN-READY → implement v3 phase 1.
PLAN-NEEDS-MINOR → tweak rationale/code, then implement.
PLAN-NEEDS-MAJOR → still wrong; revise.
PLAN-KILL → premise wrong; redesign.

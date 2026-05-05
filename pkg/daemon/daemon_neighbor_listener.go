// Package daemon: neighbor listener + force-probe (issue #1197).
//
// This file implements the event-driven kernel-as-authority
// neighbor reconciliation that replaces the buggy periodic
// preinstall mechanism.
//
// Design (per docs/pr/1197-neighbor-snapshot/plan.md v7):
//
//   1. neighborListener subscribes to RTM_NEWNEIGH/DELNEIGH netlink
//      events; on relevant changes (MAC change, eviction, transition
//      to unusable) triggers Manager.RegenerateNeighborSnapshot()
//      via a 100ms debouncer.
//
//   2. forceProbeNeighbors periodically (15s tick) sends ARP/NS
//      probes for all monitored neighbors INCLUDING those in
//      NUD_STALE/PROBE/DELAY (unlike resolveNeighbors which skips
//      them). Probe replies update kernel ARP → RTM_NEWNEIGH fires
//      → listener regenerates snapshot.
//
//   3. On RG takeover (VRRP MASTER), forceProbeNeighbors is called
//      to re-validate stale entries on the new active.
//
// Trust model: kernel ARP/NDP is authoritative; xpfd listens and
// proactively probes. xpfd no longer pushes neighbor entries into
// the kernel table.
package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/vishvananda/netlink"
)

// usableNUD is the set of NUD states userspace-dp treats as
// usable for forwarding. MUST mirror the Rust accept rules at
// userspace-dp/src/server/handlers.rs:165 and
// userspace-dp/src/afxdp/forwarding/mod.rs:45.
//
// NUD_NONE (state==0) is INTENTIONALLY excluded — Rust treats
// "none" as usable but state-0 entries have no learned MAC info,
// so we filter them out at publish time
// (see neighborSnapshotPublishable in pkg/dataplane/userspace).
const usableNUD = netlink.NUD_REACHABLE | netlink.NUD_STALE |
	netlink.NUD_DELAY | netlink.NUD_PROBE |
	netlink.NUD_PERMANENT | netlink.NUD_NOARP

// neighborProbeMaxTargetsDefault caps the per-tick force-probe
// target count by default. Override via env
// BPFRX_NEIGHBOR_PROBE_MAX_TARGETS for sites with very large
// address-books. Read once via getNeighborProbeMaxTargets.
const neighborProbeMaxTargetsDefault = 256

// getNeighborProbeMaxTargets returns the per-tick probe-target
// cap, honoring BPFRX_NEIGHBOR_PROBE_MAX_TARGETS env override.
// Invalid / non-positive values fall back to the default.
func getNeighborProbeMaxTargets() int {
	if v := os.Getenv("BPFRX_NEIGHBOR_PROBE_MAX_TARGETS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return neighborProbeMaxTargetsDefault
}

// neighborSnapshotProvider is the dataplane Manager interface
// used by the listener to query/regenerate snapshot state.
type neighborSnapshotProvider interface {
	RegenerateNeighborSnapshot()
	LookupSnapshotNeighbor(ifindex int, ip net.IP) *userspace.NeighborSnapshot
	SnapshotHasIfindex(ifindex int) bool
	IsMonitoredIfindex(ifindex int) bool
}

// neighborListener runs the netlink RTM_NEWNEIGH/DELNEIGH event
// loop. Triggers Manager.RegenerateNeighborSnapshot() when a
// monitored neighbor's forwarding-effective state changes.
//
// Resubscribe loop: kernel multicast can lose events under load;
// runOneSubscription owns one subscription lifetime and returns
// when the subscription closes; the outer loop re-establishes.
//
// Safety net: a 60s ticker triggers full reconciliation
// regardless of events, in case multicast lost the relevant
// notification.
func (d *Daemon) neighborListener(ctx context.Context) {
	regenDebounce := make(chan struct{}, 1)
	debounceMs := 100 * time.Millisecond
	go d.regenDebouncer(ctx, regenDebounce, debounceMs)

	safetyTick := time.NewTicker(60 * time.Second)
	defer safetyTick.Stop()

	for {
		if !d.runOneSubscription(ctx, regenDebounce, safetyTick) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// runOneSubscription owns ONE NeighSubscribe lifetime. Returns
// true on subscription close (caller should retry); false on
// ctx cancellation (caller should exit).
//
// Lifetime guarantee: done is closed exactly once, regardless
// of whether subscribe succeeded, ctx was cancelled, or the
// updates channel was closed. No double-close.
func (d *Daemon) runOneSubscription(
	ctx context.Context,
	regenDebounce chan struct{},
	safetyTick *time.Ticker,
) bool {
	updates := make(chan netlink.NeighUpdate, 1024)
	done := make(chan struct{})
	opts := netlink.NeighSubscribeOptions{
		ListExisting:      true,
		ReceiveBufferSize: 1 << 20, // 1 MB
		ErrorCallback: func(err error) {
			slog.Warn("neighbor listener netlink error", "err", err)
		},
	}
	if err := netlink.NeighSubscribeWithOptions(updates, done, opts); err != nil {
		slog.Warn("neighbor listener subscribe failed", "err", err)
		// NeighSubscribeWithOptions can start its done goroutine
		// before a ListExisting dump request fails; close done
		// explicitly to avoid leaking the goroutine.
		close(done)
		return true
	}
	defer close(done)

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

// regenDebouncer coalesces regen requests so a burst of events
// (e.g., GARP storm during failover) produces one snapshot
// regeneration. Uses a same-goroutine timer-channel pattern to
// avoid races with time.AfterFunc callbacks.
func (d *Daemon) regenDebouncer(
	ctx context.Context,
	ch chan struct{},
	delay time.Duration,
) {
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
			if timer == nil {
				timer = time.NewTimer(delay)
				timerC = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(delay)
				timerC = timer.C
			}
		case <-timerC:
			provider := d.neighborProvider()
			if provider != nil {
				provider.RegenerateNeighborSnapshot()
			}
			timerC = nil
		}
	}
}

// triggerRegen sends a non-blocking signal to the debouncer. If
// a request is already pending, drops this one (the debounced
// regen will see the latest kernel state regardless).
func (d *Daemon) triggerRegen(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// isMonitoredNeighbor returns true if linkIndex belongs to an
// interface enumerated by buildNeighborSnapshots, OR if the
// current snapshot already contains entries for that ifindex
// (snapshot-key fallback for runtime ifindex drift — delete
// events on disappeared links must still be processed).
//
// Codex code-review #2: previously called
// userspace.MonitoredInterfaceLinkIndexes(cfg) on every event,
// which makes O(N) netlink LinkByName calls per N configured
// interfaces. Now reads the cached set from the manager;
// rebuilt only on snapshot publish.
func (d *Daemon) isMonitoredNeighbor(linkIndex int) bool {
	provider := d.neighborProvider()
	if provider == nil {
		return false
	}
	if provider.IsMonitoredIfindex(linkIndex) {
		return true
	}
	if provider.SnapshotHasIfindex(linkIndex) {
		return true
	}
	return false
}

// shouldTriggerRegen filters forwarding-irrelevant churn. Returns
// true when the snapshot should be regenerated; false on harmless
// aging transitions (REACHABLE↔STALE↔DELAY↔PROBE on same MAC).
func (d *Daemon) shouldTriggerRegen(u netlink.NeighUpdate) bool {
	return shouldTriggerRegenWithProvider(u, d.neighborProvider())
}

// shouldTriggerRegenWithProvider is the pure decision logic for
// the listener event filter. Extracted so tests can inject a
// stub provider without wiring a full Daemon/dataplane.
func shouldTriggerRegenWithProvider(u netlink.NeighUpdate, provider neighborSnapshotProvider) bool {
	switch u.Type {
	case syscall.RTM_DELNEIGH:
		// Kernel evicted the entry; snapshot must drop it
		// immediately so userspace-dp doesn't keep forwarding
		// to a removed neighbor.
		return true
	case syscall.RTM_NEWNEIGH:
		hasMAC := u.HardwareAddr != nil && len(u.HardwareAddr) > 0
		// Composite-state safety: a state with both REACHABLE and
		// FAILED bits set must NOT be classified as usable. Define
		// usable as: at least one usableNUD bit AND no failed/
		// incomplete bit.
		usable := u.State&usableNUD != 0 &&
			u.State&(netlink.NUD_FAILED|netlink.NUD_INCOMPLETE) == 0
		// "unusable" covers state==0/NONE/FAILED/INCOMPLETE OR
		// composite states that include FAILED/INCOMPLETE.
		unusable := !usable

		var existing *userspace.NeighborSnapshot
		if provider != nil {
			existing = provider.LookupSnapshotNeighbor(u.LinkIndex, u.IP)
		}
		if existing == nil {
			// New entry: trigger only if it's publishable.
			return hasMAC && usable
		}
		// MAC change → always trigger (the bug-class case).
		if hasMAC {
			existingMAC, err := net.ParseMAC(existing.MAC)
			if err != nil || !bytes.Equal(existingMAC, u.HardwareAddr) {
				return true
			}
		}
		// Transition to unusable → snapshot must drop entry.
		// Includes NUD_FAILED, NUD_INCOMPLETE, NUD_NONE (state==0).
		if unusable {
			return true
		}
		// Same MAC, still usable: harmless aging churn; skip.
		return false
	}
	return false
}

// neighborProvider returns the dataplane manager's neighbor
// snapshot interface, or nil if the dataplane doesn't expose
// the methods (defensive: tests / non-userspace dataplanes).
func (d *Daemon) neighborProvider() neighborSnapshotProvider {
	if d.dp == nil {
		return nil
	}
	if p, ok := d.dp.(neighborSnapshotProvider); ok {
		return p
	}
	return nil
}

// criticality levels for force-probe target prioritization.
// Higher value = probed earlier within a stale-tier bucket.
// Per Copilot review: a single boolean conflated address-book
// hosts with real next-hops, so under cap pressure a large
// address-book could crowd out gateways and fabric peers.
const (
	criticalityNormal    = 0 // snapshot-only entries (already-resolved peers)
	criticalityNextHop   = 1 // configured next-hops, NAT destinations
	criticalityFabric    = 2 // cluster fabric peers (highest)
)

// probeTarget is one entry in the force-probe target list.
type probeTarget struct {
	ip          net.IP
	linkIndex   int
	state       uint16 // current kernel NUD state (bitmask)
	criticality int    // see criticality* constants
}

// probeTier classifies a target's current state for tiered
// probing: tier1 (most likely to need re-validation) → tier3.
//
// Tier 1: states at risk of stale forwarding
//         (STALE, PROBE, DELAY, FAILED, INCOMPLETE, NONE/missing)
// Tier 2: REACHABLE on fabric/next-hop targets (criticality > Normal)
// Tier 3: everything else
func probeTier(state uint16, criticality int) int {
	stale := uint16(netlink.NUD_STALE | netlink.NUD_PROBE |
		netlink.NUD_DELAY | netlink.NUD_FAILED |
		netlink.NUD_INCOMPLETE)
	if state == 0 || state&stale != 0 {
		return 1
	}
	if state&netlink.NUD_REACHABLE != 0 && criticality > criticalityNormal {
		return 2
	}
	return 3
}

// forceProbeNeighbors sends ARP/IPv6 NS probes for all monitored
// neighbor targets, REGARDLESS of NUD state. Distinct from
// resolveNeighborsInner which skips REACHABLE/STALE/PERMANENT —
// that semantics is right for activation priming, but wrong for
// steady-state staleness reconciliation (#1197).
//
// Targets are tier-prioritized (stale-risk first, then critical
// next-hops, then rest) and capped at neighborProbeMaxTargets to
// avoid ARP/NS storms on large address-books.
func (d *Daemon) forceProbeNeighbors(cfg *config.Config) {
	if cfg == nil {
		return
	}
	targets := d.collectMonitoredNeighbors(cfg)
	if len(targets) == 0 {
		return
	}
	cap := getNeighborProbeMaxTargets()
	if len(targets) > cap {
		slog.Warn("neighbor probe truncated",
			"total", len(targets),
			"cap", cap)
		targets = targets[:cap]
	}
	slog.Info("force-probe neighbors", "count", len(targets))
	for _, t := range targets {
		link, err := netlink.LinkByIndex(t.linkIndex)
		if err != nil {
			continue
		}
		ifName := link.Attrs().Name
		go func(ip net.IP, iface string) {
			if ip.To4() == nil {
				if err := cluster.SendNDSolicitationFromInterface(iface, ip); err != nil {
					slog.Debug("force-probe: IPv6 NS failed",
						"iface", iface, "ip", ip, "err", err)
				}
			}
			sendICMPProbe(iface, ip)
		}(t.ip, ifName)
	}
}

// collectMonitoredNeighbors returns the deduped union of all
// targets we want to keep ARP/NDP-warm:
//   1. Snapshot keys (entries we've published to userspace-dp)
//   2. Configured next-hops, NAT destinations, address-book hosts
//      (the resolveNeighborsInner target set)
//   3. Fabric peer IPs
//
// Returned in PRIORITY ORDER (tier1 → tier2 → tier3) where
// tiering is annotated by current kernel NUD state per target.
func (d *Daemon) collectMonitoredNeighbors(cfg *config.Config) []probeTarget {
	type key struct {
		linkIndex int
		ip        string
	}
	seen := make(map[key]bool)
	var targets []probeTarget

	// Helper: NUD state lookup via NeighList per (ifindex, family).
	// Copilot review: previous arithmetic encoding `ifindex*2+family`
	// collides — netlink.FAMILY_V4=2, FAMILY_V6=10 → (if=1,v6) and
	// (if=5,v4) both produce 12. Use a struct key instead.
	type stateCacheKey struct {
		ifindex int
		family  int
	}
	stateCache := make(map[stateCacheKey]map[string]uint16)
	getState := func(ifindex int, ip net.IP) uint16 {
		family := netlink.FAMILY_V4
		if ip.To4() == nil {
			family = netlink.FAMILY_V6
		}
		k := stateCacheKey{ifindex, family}
		if m, ok := stateCache[k]; ok {
			return m[ip.String()]
		}
		neighs, err := netlink.NeighList(ifindex, family)
		m := make(map[string]uint16)
		if err == nil {
			for _, n := range neighs {
				if n.IP != nil {
					m[n.IP.String()] = uint16(n.State)
				}
			}
		}
		stateCache[k] = m
		return m[ip.String()]
	}

	addTarget := func(ip net.IP, linkIndex int, criticality int) {
		if ip == nil || linkIndex <= 0 {
			return
		}
		k := key{linkIndex, ip.String()}
		if seen[k] {
			return
		}
		seen[k] = true
		st := getState(linkIndex, ip)
		targets = append(targets, probeTarget{
			ip:          ip,
			linkIndex:   linkIndex,
			state:       st,
			criticality: criticality,
		})
	}

	// Source 1: snapshot keys (publishable-only).
	// Copilot review: SnapshotNeighbors walks raw lastSnapshot.Neighbors,
	// which can include filtered-out entries (FAILED/INCOMPLETE/none/
	// malformed MAC). Those entries are NOT in userspace-dp's neighbor
	// table — probing them is fine but they aren't load-bearing for
	// forwarding-correctness. The neighborIndex reflects publishable-
	// only entries (we built it that way after publish-success), so
	// use that as the source for snapshot keys.
	if provider := d.neighborProvider(); provider != nil {
		type indexEnumerator interface {
			ForEachSnapshotNeighbor(fn func(ifindex int, ip net.IP))
		}
		if e, ok := d.dp.(indexEnumerator); ok {
			e.ForEachSnapshotNeighbor(func(ifindex int, ip net.IP) {
				addTarget(ip, ifindex, criticalityNormal)
			})
		}
	}

	// (Source 2 removed per Copilot review.)
	// Configured next-hops + NAT + address-book targets are
	// covered by resolveNeighborsInner (which has skip-stale
	// semantics — appropriate for "fill in missing" rather than
	// "re-validate stale"). Including them here would duplicate
	// every probe at all 3 call sites (startup, 15s tick, VRRP
	// takeover) — exactly when minimizing ARP burst matters most.
	//
	// forceProbeNeighbors's job is to RE-VALIDATE entries we've
	// already seen (snapshot keys) and the cluster fabric peers
	// that must stay warm. Cold-start "fill missing" is
	// resolveNeighbors's responsibility.

	// Source 3: fabric peers (probed via fabric overlay link).
	d.fabricMu.RLock()
	fabricPeerIP := d.fabricPeerIP
	fabricPeerIP1 := d.fabricPeerIP1
	fabricOverlay := d.fabricOverlay
	fabricOverlay1 := d.fabricOverlay1
	d.fabricMu.RUnlock()
	if fabricPeerIP != nil && fabricOverlay != "" {
		if link, err := netlink.LinkByName(fabricOverlay); err == nil {
			addTarget(fabricPeerIP, link.Attrs().Index, criticalityFabric)
		}
	}
	if fabricPeerIP1 != nil && fabricOverlay1 != "" {
		if link, err := netlink.LinkByName(fabricOverlay1); err == nil {
			addTarget(fabricPeerIP1, link.Attrs().Index, criticalityFabric)
		}
	}

	// Sort into tier order. Within tier, higher criticality first.
	sort.SliceStable(targets, func(i, j int) bool {
		ti := probeTier(targets[i].state, targets[i].criticality)
		tj := probeTier(targets[j].state, targets[j].criticality)
		if ti != tj {
			return ti < tj
		}
		return targets[i].criticality > targets[j].criticality
	})
	return targets
}

// (collectResolveTargets was sketched here but removed: the
// existing resolveNeighborsInner already covers configured
// next-hops at activation, and snapshot keys cover the
// steady-state set. Re-derivation here would just drift.)

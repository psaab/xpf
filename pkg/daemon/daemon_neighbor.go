// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #1197: preinstallSnapshotNeighbors was deleted. It unconditionally
// pushed the userspace-dp's in-memory neighbor snapshot back into
// the kernel ARP table every 15s, which would revert kernel-learned
// fresher MACs to stale snapshot MACs and break forwarding until
// xpfd restart. The replacement is event-driven: see
// daemon_neighbor_listener.go for the RTM_NEWNEIGH/DELNEIGH listener
// (kernel-as-authority) and forceProbeNeighbors for the periodic
// proactive ARP/NS probe that keeps kernel entries fresh.

// resolveNeighbors proactively triggers ARP/NDP resolution for all known
// next-hops, gateways, NAT destinations, and address-book host entries.
// This ensures bpf_fib_lookup returns SUCCESS (with valid MAC addresses)
// instead of NO_NEIGH for the first packet.
//
// Runtime: the synchronous portion collects targets via netlink RouteGet +
// NeighList (~1-2ms each), then fires ICMP/NS probes as goroutines. For a
// typical config with 2-5 next-hops, the blocking phase completes in <10ms.
// The 500ms sleep at the end waits for ARP replies; callers that cannot
// afford the sleep should invoke this from a goroutine.
func (d *Daemon) resolveNeighbors(cfg *config.Config) {
	d.resolveNeighborsInner(cfg, true)
}

// neighborProbeTarget is the (IP, linkIndex) pair for a neighbor
// xpfd wants to probe via ARP/NDP. Used by both resolveNeighborsInner
// and forceProbeNeighbors (#1197).
type neighborProbeTarget struct {
	neighborIP net.IP
	linkIndex  int
}

// collectNeighborProbeTargets returns the deduped target list
// xpfd actively cares about: static-route next-hops, DHCP gateways,
// backup router, DNAT pool addresses, static NAT translated
// addresses, address-book host entries (/32 and /128 only).
//
// #1197: extracted from resolveNeighborsInner so both that
// function and forceProbeNeighbors share one source of truth for
// the configured-target set.
func (d *Daemon) collectNeighborProbeTargets(cfg *config.Config) []neighborProbeTarget {
	var targets []neighborProbeTarget
	seen := make(map[string]bool)
	if cfg == nil {
		return nil
	}

	addByLink := func(ip net.IP, linkIndex int) {
		key := fmt.Sprintf("%s@%d", ip, linkIndex)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, neighborProbeTarget{neighborIP: ip, linkIndex: linkIndex})
	}

	addByIP := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		routes, err := netlink.RouteGet(ip)
		if err != nil || len(routes) == 0 {
			return
		}
		neighborIP := ip
		if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
			neighborIP = gw
		}
		addByLink(neighborIP, routes[0].LinkIndex)
	}

	addByName := func(ipStr, ifName string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		resolved := resolveJunosIfName(cfg, ifName)
		link, err := netlink.LinkByName(resolved)
		if err != nil {
			return
		}
		addByLink(ip, link.Attrs().Index)
	}

	addByIPOrConfig := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		routes, err := netlink.RouteGet(ip)
		if err == nil && len(routes) > 0 {
			neighborIP := ip
			if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
				neighborIP = gw
			}
			addByLink(neighborIP, routes[0].LinkIndex)
			return
		}
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil {
				continue
			}
			for unitNum, unit := range ifc.Units {
				if unit == nil {
					continue
				}
				for _, addrStr := range unit.Addresses {
					_, ipNet, err := net.ParseCIDR(addrStr)
					if err != nil || !ipNet.Contains(ip) {
						continue
					}
					linuxName := resolveJunosIfName(cfg, name)
					if unit.VlanID > 0 {
						linuxName = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					} else if unitNum != 0 {
						linuxName = fmt.Sprintf("%s.%d", linuxName, unitNum)
					}
					link, err := netlink.LinkByName(linuxName)
					if err != nil {
						continue
					}
					addByLink(ip, link.Attrs().Index)
					return
				}
			}
		}
	}

	// 1. Static route next-hops.
	// Build the combined list in a fresh slice — appending Inet6StaticRoutes
	// onto cfg.RoutingOptions.StaticRoutes directly would write into that
	// slice's backing array when it has spare capacity (cap > len), mutating
	// the shared active-config object. resolveNeighbors runs concurrently with
	// VRRP-transition and config-apply callers (and, post-#1780, in a guarded
	// goroutine), so that in-place append is a data race on shared config
	// (AGY #1781 r1). A pre-sized copy avoids touching the config's arrays.
	allStaticRoutes := make([]*config.StaticRoute, 0,
		len(cfg.RoutingOptions.StaticRoutes)+len(cfg.RoutingOptions.Inet6StaticRoutes))
	allStaticRoutes = append(allStaticRoutes, cfg.RoutingOptions.StaticRoutes...)
	allStaticRoutes = append(allStaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
	for _, sr := range allStaticRoutes {
		if sr.Discard || sr.Reject {
			continue
		}
		for _, nh := range sr.NextHops {
			if nh.Address == "" {
				continue
			}
			if nh.Interface != "" {
				addByName(nh.Address, nh.Interface)
			} else {
				addByIPOrConfig(nh.Address)
			}
		}
	}
	for _, ri := range cfg.RoutingInstances {
		// Same copy-safety as above: never append onto the config's own
		// StaticRoutes backing array (AGY #1781 r1).
		riStaticRoutes := make([]*config.StaticRoute, 0,
			len(ri.StaticRoutes)+len(ri.Inet6StaticRoutes))
		riStaticRoutes = append(riStaticRoutes, ri.StaticRoutes...)
		riStaticRoutes = append(riStaticRoutes, ri.Inet6StaticRoutes...)
		for _, sr := range riStaticRoutes {
			if sr.Discard || sr.Reject {
				continue
			}
			for _, nh := range sr.NextHops {
				if nh.Address == "" {
					continue
				}
				if nh.Interface != "" {
					addByName(nh.Address, nh.Interface)
				} else {
					addByIPOrConfig(nh.Address)
				}
			}
		}
	}

	// 2. DHCP-learned gateways
	if d.dhcp != nil {
		for _, lease := range d.dhcp.Leases() {
			if lease.Gateway.IsValid() {
				addByName(lease.Gateway.String(), lease.Interface)
			}
		}
	}

	// 3. Backup router next-hop
	if cfg.System.BackupRouter != "" {
		addByIP(cfg.System.BackupRouter)
	}

	// 4. DNAT pool addresses
	if cfg.Security.NAT.Destination != nil {
		for _, pool := range cfg.Security.NAT.Destination.Pools {
			if pool.Address != "" {
				addByIP(stripCIDR(pool.Address))
			}
		}
	}

	// 5. Static NAT translated addresses
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.Then != "" {
				addByIP(stripCIDR(rule.Then))
			}
		}
	}

	// 6. Address-book host entries (/32 and /128 only)
	if cfg.Security.AddressBook != nil {
		for _, addr := range cfg.Security.AddressBook.Addresses {
			ip, ipNet, err := net.ParseCIDR(addr.Value)
			if err != nil {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if ones == bits {
				addByIP(ip.String())
			}
		}
	}

	return targets
}

func (d *Daemon) resolveNeighborsInner(cfg *config.Config, waitForReplies bool) {
	// #1197 v3 (Codex code-review #5): use the shared
	// collectNeighborProbeTargets helper instead of duplicating
	// the target-collection logic inline. This is the canonical
	// target source — drift between resolveNeighborsInner and
	// forceProbeNeighbors is impossible.
	targets := d.collectNeighborProbeTargets(cfg)

	// Resolve each target via ping (triggers kernel ARP/NDP resolution)
	resolved := 0
	for _, t := range targets {
		link, err := netlink.LinkByIndex(t.linkIndex)
		if err != nil {
			continue
		}
		ifName := link.Attrs().Name
		family := netlink.FAMILY_V4
		if t.neighborIP.To4() == nil {
			family = netlink.FAMILY_V6
		}
		// Skip if neighbor already exists and is usable
		neighs, _ := netlink.NeighList(t.linkIndex, family)
		skip := false
		for _, n := range neighs {
			if n.IP.Equal(t.neighborIP) && (n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT)) != 0 {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		resolved++
		// Trigger proactive neighbor discovery.
		// IPv4 continues to use ping so the kernel owns ARP resolution.
		// IPv6 additionally sends an explicit NS before pinging so the
		// failover path also nudges peer neighbor caches directly.
		go func(ip net.IP, iface string) {
			if ip.To4() == nil {
				if err := cluster.SendNDSolicitationFromInterface(iface, ip); err != nil {
					slog.Debug("neighbor warmup: IPv6 NS probe failed",
						"iface", iface, "ip", ip, "err", err)
				}
			}
			sendICMPProbe(iface, ip)
		}(t.neighborIP, ifName)
	}

	if resolved > 0 {
		slog.Info("proactive neighbor resolution", "resolving", resolved, "total_targets", len(targets))
		if waitForReplies {
			// Brief pause to allow ARP responses
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// cleanFailedNeighbors deletes NUD_FAILED neighbor entries on all interfaces
// and proactively pings the IP to pre-populate ARP/NDP for fast recovery.
//
// When a host goes down, the kernel marks its ARP/NDP entry as FAILED and
// retains it for ~60 seconds (gc_staletime). During that window, packets
// XDP_PASS'd for NO_NEIGH resolution are silently dropped by the kernel
// because it refuses to re-resolve a FAILED entry. Deleting the entry and
// pinging ensures ARP/NDP is resolved before the next forwarded packet.
func (d *Daemon) cleanFailedNeighbors() int {
	type probe struct {
		ip    net.IP
		iface string
	}
	var probes []probe
	cleaned := 0
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		neighs, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		for i := range neighs {
			if neighs[i].State&netlink.NUD_FAILED != 0 {
				// Capture interface name for probing before delete.
				link, linkErr := netlink.LinkByIndex(neighs[i].LinkIndex)
				if err := netlink.NeighDel(&neighs[i]); err == nil {
					cleaned++
					if linkErr == nil {
						probes = append(probes, probe{
							ip:    neighs[i].IP,
							iface: link.Attrs().Name,
						})
					}
				}
			}
		}
	}
	if cleaned > 0 {
		slog.Debug("cleaned failed neighbor entries", "count", cleaned)
	}
	// Reprobe cleaned neighbors so the kernel's table repopulates before
	// the next forwarded packet. IPv4 keeps the existing ARP probe path.
	// IPv6 now sends an explicit NS instead of waiting for passive later
	// traffic to trigger NDP.
	for _, p := range probes {
		if p.ip.To4() != nil {
			// Neighbor-table reprobe (not a VIP move): use the interface
			// primary as the ARP sender, preserving the self-resolved
			// sender SendARPProbe used before #2152.
			sender, perr := cluster.PrimaryIPv4(p.iface)
			if perr != nil {
				slog.Debug("failed-neighbor reprobe: no IPv4 sender",
					"iface", p.iface, "ip", p.ip, "err", perr)
				continue
			}
			if err := cluster.SendARPProbe(p.iface, sender, p.ip); err != nil {
				slog.Debug("failed-neighbor reprobe: IPv4 ARP probe failed",
					"iface", p.iface, "ip", p.ip, "err", err)
			}
		} else {
			if err := cluster.SendNDSolicitationFromInterface(p.iface, p.ip); err != nil {
				slog.Debug("failed-neighbor reprobe: IPv6 NS failed",
					"iface", p.iface, "ip", p.ip, "err", err)
			}
		}
	}
	return cleaned
}

// runPeriodicNeighborResolution manages periodic neighbor upkeep:
//   - Every 5 seconds: clean NUD_FAILED neighbor entries so the kernel
//     retries ARP/NDP on the next forwarded packet (fast recovery).
//   - Every 15 seconds: proactively resolve known forwarding targets
//     (gateways, DNAT pools, etc.) to keep ARP/NDP entries warm.
//   - In cluster mode: continuously refresh snapshot-learned neighbors and
//     session-derived neighbor cache entries so standby forwarding stays ready
//     without activation-time warmup.
//
// neighborPeriodicGuards groups the #1780 Path A per-phase supervision state
// for runPeriodicNeighborResolution. Each periodic phase runs in a guarded
// goroutine so a hung netlink/probe syscall in one phase can never freeze the
// for-select loop (the observed 17.5h stall). The in-flight bools skip a phase
// while a prior pass is still running (no overlap / netlink-socket leak — a
// stuck syscall can't be cancelled, so we leak at most one goroutine per phase,
// never a growing pile). The *LastSuccessNanos UnixNano feeds the
// neighbor_periodic_last_success_age_seconds{phase} gauge so a stalled phase is
// observable.
//
// This type was extracted from the flat Daemon fields as increment 2 of the
// #4407 Daemon god-struct decomposition — pure field grouping, no
// behavior/locking change. The fields keep their exact atomic types and are
// reached as d.neighborGuards.<field>; the runGuardedNeighborPhase helper still
// takes &-pointers to the addressable struct fields.
type neighborPeriodicGuards struct {
	// warmInFlight guards warmNeighborCache (the HA session-walk warmup) so a
	// pass that exceeds one tick interval does not overlap itself;
	// warmLastSuccessNanos records its last successful completion.
	warmInFlight atomic.Bool
	// resolveInFlight / forceProbeInFlight / cleanFailedInFlight are the
	// per-phase overlap guards for the resolve, force-probe, and clean phases.
	resolveInFlight     atomic.Bool
	forceProbeInFlight  atomic.Bool
	cleanFailedInFlight atomic.Bool
	// forceProbeCursor advances the start of each capped probe window so
	// equal-priority neighbors are all revisited within bounded ticks.
	forceProbeCursor atomic.Uint64
	// *LastSuccessNanos hold the wall-clock UnixNano of each phase's last
	// successful completion (0 = never), feeding the phase-age watchdog gauge.
	resolveLastSuccessNanos     atomic.Int64
	forceProbeLastSuccessNanos  atomic.Int64
	cleanFailedLastSuccessNanos atomic.Int64
	warmLastSuccessNanos        atomic.Int64
	// loopStarted gates the phase-age gauge: it is set once
	// runPeriodicNeighborResolution actually starts (the loop only runs when
	// the dataplane is enabled with active config). Without it, a daemon that
	// never starts the loop would report every phase as a forever-climbing
	// "wedged" age — a false positive (Codex #1781 r1).
	loopStarted atomic.Bool
}

// NeighborPeriodicPhaseAges returns, per periodic-neighbor-maintenance phase,
// the seconds since that phase last completed successfully — the #1780 Path A
// stall diagnostic. A phase frozen by a hung netlink/probe syscall shows a
// growing age while the healthy phases stay near 0; a phase that has never
// completed reports its age since the loop started so a never-running phase
// still flags. Surfaced as the
// xpf_daemon_neighbor_periodic_last_success_age_seconds{phase} gauge.
//
// To avoid false positives (Codex #1781 r1), it reports nothing until the
// periodic loop has actually started (the loop only runs when the dataplane
// is enabled with active config), and it omits the "warm" phase on a
// standalone firewall, since warmNeighborCache only runs under HA
// (maintainClusterNeighborReadiness no-ops when d.cluster == nil and so never
// updates warmLastSuccessNanos).
func (d *Daemon) NeighborPeriodicPhaseAges() map[string]float64 {
	if !d.neighborGuards.loopStarted.Load() {
		return nil
	}
	now := time.Now()
	// Clamp to >= 0: ages are wall-clock subtractions, so a backward clock
	// step (NTP/RTC adjustment) could otherwise emit a negative age, which is
	// nonsensical for a watchdog gauge (Copilot #1781 r2; mirrors the
	// clock-step floor in shouldScheduleStandbyNeighborRefresh).
	age := func(lastNanos int64) float64 {
		var sec float64
		if lastNanos == 0 {
			sec = now.Sub(d.startTime).Seconds()
		} else {
			sec = now.Sub(time.Unix(0, lastNanos)).Seconds()
		}
		if sec < 0 {
			sec = 0
		}
		return sec
	}
	ages := map[string]float64{
		"resolve":      age(d.neighborGuards.resolveLastSuccessNanos.Load()),
		"force_probe":  age(d.neighborGuards.forceProbeLastSuccessNanos.Load()),
		"clean_failed": age(d.neighborGuards.cleanFailedLastSuccessNanos.Load()),
	}
	// The warm phase only exists under HA; reporting it standalone would be a
	// forever-climbing false "wedge".
	if d.cluster != nil {
		ages["warm"] = age(d.neighborGuards.warmLastSuccessNanos.Load())
	}
	return ages
}

// runGuardedNeighborPhase runs one periodic neighbor-maintenance phase in a
// guarded goroutine so a hung netlink/probe syscall in that phase can NEVER
// freeze the runPeriodicNeighborResolution for-select loop (#1780 Path A: a
// blocking synchronous handler was observed wedging the whole loop ~17.5h,
// aging out data-path next-hops and causing cold-connect hangs). If a prior
// pass is still in flight, the tick is skipped rather than launching an
// overlapping pass — a stuck netlink syscall cannot be cancelled, so a second
// goroutine would only leak another socket; skipping caps the leak at one
// goroutine per phase, and the stalled phase becomes observable via its
// growing last-success-age gauge while every OTHER phase keeps running. On
// normal completion the phase records its success timestamp; a transient hang
// self-heals because the next tick relaunches once the prior pass returns.
func (d *Daemon) runGuardedNeighborPhase(inFlight *atomic.Bool, lastSuccess *atomic.Int64, fn func()) {
	if !inFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer func() {
			lastSuccess.Store(time.Now().UnixNano())
			inFlight.Store(false)
		}()
		fn()
	}()
}

func (d *Daemon) runPeriodicNeighborResolution(ctx context.Context) {
	// Mark the loop live so NeighborPeriodicPhaseAges reports phase ages only
	// once supervision is actually running (avoids the never-started false
	// positive — Codex #1781 r1).
	d.neighborGuards.loopStarted.Store(true)

	// #1780 Path A: each phase runs via runGuardedNeighborPhase (a guarded
	// goroutine) so one hung netlink/probe phase cannot freeze this loop.
	// WHAT each phase does is unchanged — only HOW it is supervised.
	resolvePass := func() {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.resolveNeighbors(cfg)
		}
	}
	// #1197: force-probe ALL monitored neighbors (including STALE/DELAY/PROBE)
	// so the kernel re-validates entries resolveNeighbors would skip. Replies
	// update kernel ARP → RTM_NEWNEIGH → listener regenerates snapshot.
	forceProbePass := func() {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.forceProbeNeighbors(cfg)
		}
	}
	// cleanFailedNeighbors returns a count; discard it for the void phase fn.
	cleanPass := func() { d.cleanFailedNeighbors() }
	// maintainClusterNeighborReadiness self-gates on d.cluster, but the prior
	// (pre-#1780) loop only invoked it when ActiveConfig() != nil; preserve
	// that gate exactly so this change stays HOW-only, not WHAT (Claude SMR
	// #1781 r1). It is called inline rather than via runGuardedNeighborPhase
	// because its only synchronous work is a nil check + a CAS — the heavy
	// session-walk warmNeighborCache already runs in its own goroutine guarded
	// by neighborWarmupInFlight, so maintain cannot freeze this loop.
	maintainPass := func() {
		if cfg := d.store.ActiveConfig(); cfg != nil {
			d.maintainClusterNeighborReadiness()
		}
	}

	// resolveTick is the 15s pass: resolve + force-probe (both guarded) +
	// maintain. cleanTick is the 5s pass: clean (guarded).
	resolveTick := func() {
		d.runGuardedNeighborPhase(&d.neighborGuards.resolveInFlight, &d.neighborGuards.resolveLastSuccessNanos, resolvePass)
		d.runGuardedNeighborPhase(&d.neighborGuards.forceProbeInFlight, &d.neighborGuards.forceProbeLastSuccessNanos, forceProbePass)
		maintainPass()
	}
	cleanTick := func() {
		d.runGuardedNeighborPhase(&d.neighborGuards.cleanFailedInFlight, &d.neighborGuards.cleanFailedLastSuccessNanos, cleanPass)
	}

	// Immediate first run — don't wait for first tick. force-probe is
	// intentionally skipped here (it needs a snapshot that doesn't exist yet
	// at startup; it joins on the first 15s tick with a non-overlapping set),
	// so the immediate pass is resolve + maintain + clean, matching the
	// pre-#1780 startup sequence exactly.
	d.runGuardedNeighborPhase(&d.neighborGuards.resolveInFlight, &d.neighborGuards.resolveLastSuccessNanos, resolvePass)
	maintainPass()
	cleanTick()

	const (
		cleanInterval   = 5 * time.Second
		resolveInterval = 15 * time.Second
	)
	d.neighborPeriodicLoop(ctx, cleanInterval, resolveInterval, cleanTick, resolveTick)
}

// neighborPeriodicLoop is the supervised for-select core of
// runPeriodicNeighborResolution, split out so a unit test can drive it with
// fast intervals and synthetic phase closures and prove the no-freeze
// invariant end-to-end: a wedged resolveTick phase must not stop cleanTick
// from firing (Codex #1781 r1). The loop itself never blocks — each tick
// callback is expected to dispatch its work via runGuardedNeighborPhase (a
// guarded goroutine) or be O(1) — so the select keeps servicing both tickers
// regardless of any single phase hanging.
func (d *Daemon) neighborPeriodicLoop(ctx context.Context, cleanInterval, resolveInterval time.Duration, cleanTick, resolveTick func()) {
	cleanTicker := time.NewTicker(cleanInterval)
	resolveTicker := time.NewTicker(resolveInterval)
	defer cleanTicker.Stop()
	defer resolveTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanTicker.C:
			cleanTick()
		case <-resolveTicker.C:
			resolveTick()
		}
	}
}

// maintainClusterNeighborReadiness runs every 15 seconds (via the resolve
// ticker in runPeriodicNeighborResolution) when HA is active. It refreshes
// kernel neighbor entries and spawns warmNeighborCache which iterates the
// full session table and sends one UDP probe per unique src/dst IP. The
// session walk can be large; an atomic guard prevents overlapping runs if
// a single pass exceeds one tick interval.
func (d *Daemon) maintainClusterNeighborReadiness() {
	if d.cluster == nil {
		return
	}
	// #1197: preinstall removed; the listener (daemon_neighbor_listener.go)
	// keeps the snapshot in sync with kernel via netlink events,
	// and the periodic forceProbeNeighbors tick keeps kernel entries
	// fresh via proactive ARP/NS.
	if !d.neighborGuards.warmInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer func() {
			d.neighborGuards.warmLastSuccessNanos.Store(time.Now().UnixNano())
			d.neighborGuards.warmInFlight.Store(false)
		}()
		d.warmNeighborCache()
	}()
}

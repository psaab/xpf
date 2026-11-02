package userspace

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/linuxsock"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func (m *Manager) bootstrapNAPIQueuesAsyncLocked(reason string) {
	now := time.Now()
	if !m.lastNAPIBootstrap.IsZero() && now.Sub(m.lastNAPIBootstrap) < 2*time.Second {
		return
	}
	m.lastNAPIBootstrap = now
	go func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.proc == nil || m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
			return
		}
		slog.Info("userspace: bootstrapping NAPI queues", "reason", reason)
		m.bootstrapNAPIQueuesLocked()
	}()
}

// bootstrapNAPIQueuesLocked sends UDP probe packets to each managed
// interface to trigger hardware RX events on all NIC queues. This is
// needed for mlx5 zero-copy: the driver only consumes XSK fill ring
// entries during NAPI poll, and NAPI only runs when there are HW RX
// events. Without at least one packet per queue, the fill ring stays
// unconsumed and XDP_REDIRECT silently drops packets.
//
// THE PROBES ARE LOAD-BEARING, and that was established by measurement rather
// than by reading (#8377). It is worth recording, because the code has three
// things that LOOK like they would make a cold queue self-heal and the tree's
// own history says they did not:
//
//   - `poll(POLLIN)` on the XSK fd from `maybe_wake_rx`
//     (userspace-dp/src/afxdp/tx/rings.rs), on every empty RX poll;
//   - the bind-time kick in `prime_fill_ring_offsets` / `drive_fill_prime_loop`
//     (userspace-dp/src/afxdp/bind.rs), which always runs at least one
//     iteration;
//   - `SO_BUSY_POLL`, which makes those calls run `napi_busy_loop()` inline.
//
// `ffe0b5520` recorded "mlx5 zero-copy fill ring consumer (frC) stays at 0
// after daemon restart despite correct XSKMAP registration. XDP_REDIRECT
// succeeds but packets are silently dropped" WITH the poll wake already in the
// tree, and `e0c01ac2b` then added SO_BUSY_POLL because "ndo_xsk_wakeup's ICOSQ
// NOP mechanism FAILS when NAPI is already scheduled from other sources" — the
// same early-outs the mlx5 driver's `mlx5e_xsk_wakeup` takes
// (`napi_if_scheduled_mark_missed`, `MLX5E_SQ_STATE_PENDING_XSK_TX`). That
// commit also observed the failure this file exists to prevent, on hardware:
// "The ARP/NDP reply for the egress next-hop may hash to an XSK queue that
// hasn't been bootstrapped yet."
//
// So do not delete or weaken these probes on the strength of a source reading
// that one of the wake paths "should" cover it. Three separate readings of that
// question have now inverted each other; the only measurement points the other
// way, and it is the one in the commit log.
//
// HOW MANY PROBES (#8377). Queue selection is by RSS hash, so this is a
// coupon-collector problem: covering n queues needs about n*(ln n + ln(1/eps))
// draws, not the "~2x the queue count" an earlier version of this comment
// claimed while the code sent a hard-coded 30. See napiProbeCount for the rule,
// the measured shortfall at 8+ queues, and why the count is now derived from
// the interface's own queue count instead of pinned.
//
// The probes are sent while ctrl is disabled, so only the local/control
// boundary reaches the kernel; transit remains fail-closed.
//
// WHICH INTERFACES ACTUALLY GET PROBED (#9019). The paragraphs above argue the
// probes are load-bearing; they said nothing about the interfaces that never
// received one. The target derivation queried IPv4 ONLY — `RouteList(link,
// FAMILY_V4)` and `NeighList(idx, FAMILY_V4)`, each additionally filtered
// through `.To4() != nil` — so an interface with no v4 gateway route and no v4
// neighbour was skipped unconditionally. That is a v6-only segment ALWAYS,
// and plausibly a cold-boot LAN segment where this firewall is itself the
// gateway (no gateway route on that link, empty neighbour table).
//
// The skip was also SILENT: a bare `continue`, no log, no counter, no status
// field, which made it indistinguishable from "this interface was probed
// successfully". That is what made it expensive rather than merely incomplete,
// because nothing else covers it either — the binding wedge recovery keys on
// `Registered && Armed && !Bound`, a bind FAILURE, and its own give-up message
// records that "binding readiness cannot see a queue that is bound-but-dead".
//
// The second half of that sentence used to read "and the XSK liveness gate is
// box-wide, so one live queue sets `xskLivenessProven` for the whole box and
// masks a cold one". #9331 REMOVED that masking: `xskLivenessProven` is gone
// from the wedge predicate, which now decides per binding. The point this
// paragraph is making SURVIVES it — wedge recovery keys on a bind FAILURE, and
// a queue with no NAPI probe target BINDS FINE and is simply never woken, so it
// is not a wedge in any sense the predicate can see. That is why this counter
// is still the only signal for its case.
//
// Both lookups now ask for FAMILY_ALL and `deriveNAPIProbeTarget` applies the
// priority (v4 gateway, v4 neighbour, v6 gateway, v6 neighbour), so an
// interface that derived a target before derives the SAME one now and the v6
// arms are reached only where the old code had already given up. A skip that
// remains is counted (`NAPIProbeTargetSkips`) and logged with the interface
// name.
//
// NOT done here: the issue also suggests a LAST-RESORT target for a segment
// with neither a gateway nor a neighbour — the link's own address, or a
// link-local all-nodes destination. Deliberately left out. The probe works by
// eliciting a hardware RX event, and a datagram to this box's own address is
// handled locally without one; a multicast probe might work but its efficacy is
// unmeasured in this tree, and this file's whole history is a warning against
// adding or weakening a probe path on a source reading rather than a
// measurement. Such a segment is now COUNTED as unprobed instead of silently
// skipped, which is the part that can be acted on.
func (m *Manager) bootstrapNAPIQueuesLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Send UDP probes and an ICMP echo on each managed interface to create
	// hardware RX events and neighbor resolution. This triggers mlx5 NAPI,
	// which processes the XSK fill ring and posts WQEs for zero-copy packet
	// reception. Without at least one HW RX event per queue, the fill ring
	// entries added after socket bind are never consumed by the driver's pool.
	for _, linuxName := range userspaceBootstrapProbeInterfaces(m.lastSnapshot.Config) {
		// Send many parallel pings to hit all RSS queues. Each ping
		// process gets a different ICMP echo ID from the kernel, causing
		// RSS to distribute replies across different NIC queues. This
		// triggers NAPI on each queue, which posts fill ring WQEs for
		// zero-copy XSK packet reception.
		link, err := netlink.LinkByName(linuxName)
		if err != nil || link == nil {
			// #9019: this `continue` was silent too. An interface named by the
			// config that the kernel does not have is a different fault from an
			// unprobeable one, but it has the same consequence here — no
			// synthetic HW RX event — so it is counted the same way.
			noteNAPIProbeTargetSkip(linuxName, "link lookup failed")
			continue
		}
		// Find a target: gateway or any neighbour, v4 first then v6.
		//
		// #9019: both lookups were FAMILY_V4, so an interface with no v4
		// gateway route and no v4 neighbour was skipped unconditionally — a
		// v6-only segment always. FAMILY_ALL asks the kernel once for both and
		// deriveNAPIProbeTarget applies the priority, which keeps the v4 answer
		// bit-identical while adding the v6 arms below it.
		routes, _ := netlink.RouteList(link, netlink.FAMILY_ALL)
		neighs, _ := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_ALL)
		target := deriveNAPIProbeTarget(routes, neighs)
		if target == "" {
			noteNAPIProbeTargetSkip(linuxName,
				"no gateway route and no resolved neighbour in either family")
			continue
		}
		targetIP := net.ParseIP(target)
		if targetIP != nil {
			// ICMP RSS hashes on (src, dst, proto) only — varying
			// ICMP ID doesn't change the target queue. Use UDP probes
			// with varying ports: mlx5 RSS hashes (src, dst, sport,
			// dport) for UDP, distributing across all queues.
			//
			// #8377: the count is DERIVED from the interface's RX queue
			// count, not pinned. See napiProbeCount for the rule and for
			// what these probes are and are not responsible for.
			probes := napiProbeCount(userspaceRXQueueCountFn(linuxName))
			for i := 0; i < probes; i++ {
				sendUDPProbeForNAPI(linuxName, targetIP, uint16(napiProbeBasePort+i))
				if i%6 == 5 {
					time.Sleep(time.Millisecond)
				}
			}
			// Also send one ICMP probe for neighbor resolution.
			sendICMPProbeFromManager(linuxName, targetIP)
		}
	}
}

// proactiveNeighborResolveLocked reads the kernel neighbor table and
// pings any STALE/FAILED entries to force re-resolution. Also pings
// the default gateway on each managed interface. This ensures the
// helper has fresh neighbor entries when ctrl is enabled.
func (m *Manager) proactiveNeighborResolveLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Collect all managed interface names
	seen := make(map[string]bool)
	var ifaces []string
	for ifName, ifc := range m.lastSnapshot.Config.Interfaces.Interfaces {
		base := config.LinuxIfName(ifName)
		if !seen[base] {
			seen[base] = true
			ifaces = append(ifaces, base)
		}
		for _, unit := range ifc.Units {
			if unit.VlanID > 0 {
				vlanName := fmt.Sprintf("%s.%d", base, unit.VlanID)
				if !seen[vlanName] {
					seen[vlanName] = true
					ifaces = append(ifaces, vlanName)
				}
			}
		}
	}
	// For each interface, read neighbors and ping any that need resolution
	var resolved int
	for _, ifName := range ifaces {
		link, err := netlink.LinkByName(ifName)
		if err != nil || link == nil {
			continue
		}
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			neighs, err := netlink.NeighList(link.Attrs().Index, family)
			if err != nil {
				continue
			}
			for _, n := range neighs {
				if n.IP == nil || n.IP.IsLinkLocalUnicast() {
					continue
				}
				// Trigger ARP/NDP resolution for STALE/FAILED/absent entries.
				if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
					n.State == netlink.NUD_STALE || n.State == netlink.NUD_DELAY ||
					n.State == netlink.NUD_PROBE || n.State == netlink.NUD_FAILED {
					sendICMPProbeFromManager(ifName, n.IP)
					resolved++
				}
			}
		}
	}
	// Also resolve route next-hops that aren't in the neighbor table yet.
	// After VRRP election, the kernel may not have ARP for destinations
	// like .200 that were previously known but got purged on restart.
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue // only managed interfaces
		}
		// Check if this gateway is already in neighbor table
		existing, _ := netlink.NeighList(r.LinkIndex, netlink.FAMILY_ALL)
		found := false
		for _, n := range existing {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if !found {
			sendICMPProbeFromManager(ifName, r.Gw)
			resolved++
		}
	}
	if resolved > 0 {
		slog.Info("userspace: proactive neighbor resolution",
			"resolved", resolved, "interfaces", len(ifaces))
	}
}

// sendICMPProbeFromManager sends a single raw ICMP/ICMPv6 echo request
// bound to the given interface. Triggers kernel ARP/NDP resolution
// without shelling out to ping. Non-blocking.
func sendICMPProbeFromManager(iface string, target net.IP) {
	sendICMPProbeWithID(iface, target, 0)
}

// sendICMPProbeWithID sends a single ICMP echo request with a specific echo
// ID. Varying the ID causes RSS to distribute replies across different NIC
// queues, triggering NAPI on each queue for zero-copy fill ring processing.
func sendICMPProbeWithID(iface string, target net.IP, id uint16) {
	if target.To4() != nil {
		fd, err := linuxsock.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP Echo: type=8, code=0, checksum(auto), id, seq=1
		icmp := [8]byte{8, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		// Compute checksum
		var sum uint32
		for i := 0; i < 8; i += 2 {
			sum += uint32(icmp[i])<<8 | uint32(icmp[i+1])
		}
		sum = (sum >> 16) + (sum & 0xffff)
		sum += sum >> 16
		cs := uint16(^sum)
		icmp[2] = byte(cs >> 8)
		icmp[3] = byte(cs)
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, icmp[:], unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := linuxsock.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 Echo: type=128, code=0, checksum(kernel), id, seq=1
		icmp6 := [8]byte{128, 0, 0, 0, byte(id >> 8), byte(id), 0, 1}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendUDPProbeForNAPI sends a single UDP packet to the target on the given
// port. The packet is sent via a raw UDP socket bound to the interface.
// The destination is unlikely to respond, but the important thing is that
// the REPLY (ICMP port unreachable) or even the outgoing packet's DMA
// completion triggers NAPI on the NIC queue determined by RSS hash of
// (src_ip, dst_ip, src_port, dst_port). Different ports → different queues.
func sendUDPProbeForNAPI(iface string, target net.IP, port uint16) {
	if target.To4() != nil {
		fd, err := linuxsock.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := linuxsock.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		sa6 := &unix.SockaddrInet6{Port: int(port)}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, []byte("napi"), unix.MSG_DONTWAIT, sa6)
	}
}

// neighborPrewarmDeadline bounds one async prewarm scan (#5104). It caps how
// long the singleflight guard can be held: the scan checks the context between
// netlink dumps and stops issuing more once the deadline passes, so a slow
// netlink layer or a large RIB cannot pin the guard indefinitely — the next
// tick spawns a fresh scan.
const neighborPrewarmDeadline = 15 * time.Second

// neighborPrewarmProbeWorkers caps the concurrent ICMP probe goroutines a
// single scan spawns (#5104). Before this, a scan launched ONE goroutine per
// resolve target, so a large neighbor/route set multiplied unbounded goroutines
// on every tick. A fixed pool keeps cold-path work bounded regardless of RIB
// size.
const neighborPrewarmProbeWorkers = 8

// proactiveNeighborResolveAsyncLocked is the non-blocking version that
// fires probes in background goroutines. Used by the status loop.
//
// #5104: at most ONE scan runs at a time. The status loop kicks this every 1s
// for the first 60s (then every 10s on HA standby); under slow netlink or a
// large RIB a scan can outlast its tick. Without a guard, overlapping ticks
// multiplied concurrent scans and probe goroutines — self-amplifying
// control-plane load that delayed apply/status/recovery. The singleflight CAS
// coalesces overlapping ticks onto the running scan; the guard is cleared when
// the scan goroutine returns (via defer, so a panic also clears it).
func (m *Manager) proactiveNeighborResolveAsyncLocked() {
	if m.lastSnapshot == nil || m.lastSnapshot.Config == nil {
		return
	}
	// Singleflight: skip this tick if a scan is already in flight. CAS is
	// lock-free so the background scan can clear it without taking m.mu.
	if !m.neighborPrewarmInFlight.CompareAndSwap(false, true) {
		return
	}
	cfg := m.lastSnapshot.Config
	scan := m.neighborPrewarmScan
	if scan == nil {
		scan = proactiveNeighborResolveAsync
	}
	go func() {
		defer m.neighborPrewarmInFlight.Store(false)
		// Deadline-bound the scan so a wedged/slow netlink dump can't hold the
		// singleflight guard forever; on deadline the scan stops issuing work,
		// returns, clears the guard, and the next tick retries.
		ctx, cancel := context.WithTimeout(context.Background(), neighborPrewarmDeadline)
		defer cancel()
		scan(ctx, cfg)
	}()
}

type neighborProbeTarget struct {
	iface string
	ip    string
}

// runBoundedNeighborProbes fires one ICMP/NDP probe per target through a
// fixed-size worker pool (#5104). It replaces the previous unbounded
// goroutine-per-target fan-out so N resolve targets spawn at most `workers`
// concurrent probes. It stops early once ctx is cancelled/expired, and waits
// for the in-flight probes to drain before returning.
func runBoundedNeighborProbes(ctx context.Context, targets []neighborProbeTarget, workers int, probe func(iface string, target net.IP)) {
	if workers < 1 {
		workers = 1
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		targetIP := net.ParseIP(t.ip)
		if targetIP == nil {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(iface string, ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			probe(iface, ip)
		}(t.iface, targetIP)
	}
	wg.Wait()
}

func proactiveNeighborResolveAsync(ctx context.Context, cfg *config.Config) {
	if ctx == nil {
		ctx = context.Background()
	}
	seen := make(map[string]bool)
	targetSet := make(map[string]struct{})
	var targets []neighborProbeTarget
	// #5104: cache ONE neighbor dump per link index per scan. The route loop
	// below previously re-dumped the neighbor table per route (often re-dumping
	// the same link many times on a large RIB). Caching collapses that to one
	// NeighList(FAMILY_ALL) per link per scan.
	linkNeighCache := make(map[int][]netlink.Neigh)
	neighborsForLink := func(linkIndex int) []netlink.Neigh {
		if cached, ok := linkNeighCache[linkIndex]; ok {
			return cached
		}
		neighs, _ := netlink.NeighList(linkIndex, netlink.FAMILY_ALL)
		linkNeighCache[linkIndex] = neighs
		return neighs
	}
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ctx.Err() != nil {
			return
		}
		base := config.LinuxIfName(ifName)
		seen[base] = true // include base interface for route-GW probing
		for _, unit := range ifc.Units {
			linuxName := base
			if unit.VlanID > 0 {
				linuxName = fmt.Sprintf("%s.%d", base, unit.VlanID)
			}
			seen[linuxName] = true
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, n := range neighborsForLink(link.Attrs().Index) {
				if n.IP == nil || n.IP.IsLinkLocalUnicast() {
					continue
				}
				if n.HardwareAddr == nil || len(n.HardwareAddr) == 0 ||
					n.State == netlink.NUD_STALE || n.State == netlink.NUD_FAILED {
					key := linuxName + "|" + n.IP.String()
					if _, ok := targetSet[key]; ok {
						continue
					}
					targetSet[key] = struct{}{}
					targets = append(targets, neighborProbeTarget{iface: linuxName, ip: n.IP.String()})
				}
			}
		}
	}
	if ctx.Err() != nil {
		return
	}
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_ALL)
	for _, r := range routes {
		if ctx.Err() != nil {
			return
		}
		if r.Gw == nil || r.Gw.IsLinkLocalUnicast() {
			continue
		}
		link, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link == nil {
			continue
		}
		ifName := link.Attrs().Name
		if !seen[ifName] {
			continue
		}
		found := false
		for _, n := range neighborsForLink(r.LinkIndex) {
			if n.IP.Equal(r.Gw) && n.HardwareAddr != nil && len(n.HardwareAddr) > 0 &&
				n.State != netlink.NUD_FAILED {
				found = true
				break
			}
		}
		if found {
			continue
		}
		key := ifName + "|" + r.Gw.String()
		if _, ok := targetSet[key]; ok {
			continue
		}
		targetSet[key] = struct{}{}
		targets = append(targets, neighborProbeTarget{iface: ifName, ip: r.Gw.String()})
	}
	runBoundedNeighborProbes(ctx, targets, neighborPrewarmProbeWorkers, sendICMPProbeFromManager)
}

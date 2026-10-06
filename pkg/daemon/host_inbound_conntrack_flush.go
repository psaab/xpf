package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #5566: stale kernel host-inbound authorization on a coarse tightening.
//
// The xpf_hostinbound kernel chain leads with `ct state established,related
// accept` (buildHostInboundFilterPayload), which precedes every per-zone coarse
// host-inbound catch-all DROP. Replacing the xpf_hostinbound table does NOT flush
// Linux netfilter conntrack, so a direct-kernel host connection admitted under a
// LOOSER prior config (e.g. an SSH/HTTPS/SNMP session) keeps riding that leading
// established-accept after the operator REMOVES the service — the new per-zone
// drop never sees the flow's original-direction packets. That is a host-inbound
// false-allow limited to the direct-kernel delivery path: the Rust userspace
// local-delivery path already re-checks the effective host-inbound set on every
// session hit and tears a now-denied session down
// (userspace-dp/src/afxdp/poll_descriptor/mod.rs), but the kernel path had no
// equivalent teardown.
//
// The fix reconciles kernel conntrack against the JUST-APPLIED host-inbound set
// after every successful real apply: any established/related kernel conntrack
// entry whose ORIGINAL-direction destination is a firewall-local host-inbound
// address under a default-deny AND whose (proto, dport) is NOT admitted by the
// CURRENT coarse host-inbound set is deleted, so the next original-direction
// packet is re-evaluated against the new rules (and dropped by the per-zone
// catch-all) instead of short-circuiting on the established-accept. This mirrors
// the Rust per-hit re-eval/teardown. Because the flush condition is "not admitted
// by the CURRENT config", a still-permitted service's connections are never
// flushed — a reconcile, not an edge-triggered delta, so it is regression-safe on
// loosening and no-op commits and needs no persisted prior-config snapshot.
//
// Only firewall-local addresses that carry a catch-all DROP are eligible (the
// covered set). Management / cluster-control lifeline INTERFACES (fxp0 / em0 /
// fab*) are excluded from the host-inbound views by BuildZoneHostInboundViews, so
// an address reachable ONLY through a lifeline is never in the covered set and its
// conntrack is never flushed. That exclusion is by INTERFACE, not by address
// VALUE. A management address ALSO configured on a non-lifeline interface IS in
// the covered set: shared onto a zone that ADMITS the service it keeps that
// service's admit tuple and its established sessions are preserved, but shared
// onto an UNZONED interface (#4420) or a zone with NO host-inbound-traffic stanza
// (#3405) it is recorded with an EMPTY admit set and every established entry to it
// — including a live operator SSH session — is flushed. So this reconcile CAN tear
// down management on those topologies, and the "already-established sessions
// survive" mitigation for the #6492 fence window does not hold there. See
// docs/host-inbound-service-matrix.md, "Lifeline exclusion is by INTERFACE, not by
// address value". Kernel netfilter conntrack on
// this appliance tracks only host-terminated / kernel-forwarded flows (transit
// forwarding runs through userspace-dp's own session table, not netfilter
// conntrack), so the table swept here is small.

// conntrackDeleteFilters is the netfilter-conntrack delete seam. It deletes every
// entry in the main conntrack table (both families are queried by the caller)
// that matches any supplied filter. A package var so the #5566 reconcile is
// unit-testable without a live kernel conntrack subsystem (mirrors the
// nftApplyPayload seam).
var conntrackDeleteFilters = func(family netlink.InetFamily, filters ...netlink.CustomConntrackFilter) (uint, error) {
	return netlink.ConntrackDeleteFilters(netlink.ConntrackTable, family, filters...)
}

// hostInboundAdmit records the CURRENT coarse host-inbound admit set for one
// firewall-local destination address, unioned across every zone view whose
// address set contains it (an address reachable from >1 zone is admitted if ANY
// of those zones admits — matching the nft chain, which emits a per-zone accept
// keyed on destination address only). An address present in the covered set with
// an otherwise-empty admit (e.g. an addressed-but-unzoned interface, #4420) is
// fully denied except for the global exemptions handled in MatchConntrackFlow.
type hostInboundAdmit struct {
	allowsAll bool               // `system-services all` / any-service → keep everything
	tcp       []config.PortRange // admitted TCP destination ports
	udp       []config.PortRange // admitted UDP destination ports
	protos    map[uint8]bool     // admitted bare IP protocols (e.g. gre=47)
}

// add folds one structured host-inbound admit tuple (the #3627 B1a SSOT
// config.L4Match) into the address's admit set. ICMP/ICMPv6 admits are NOT
// recorded here: ND/PMTUD/error subtypes are globally accepted and echo-request
// conntrack is short-lived, so ICMP is never flushed (MatchConntrackFlow returns
// early for it). The ident-reset marker (Reject) does not admit TCP/113 — it
// RESETS it — so it is skipped (a stale tcp/113 entry is therefore flushable).
func (a *hostInboundAdmit) add(m config.L4Match) {
	if m.Reject {
		return
	}
	switch m.Proto {
	case config.HostInboundProtoTCP:
		a.tcp = append(a.tcp, m.Ports...)
	case config.HostInboundProtoUDP:
		a.udp = append(a.udp, m.Ports...)
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		// globally accepted / short-lived — not tracked for flushing.
	default:
		if a.protos == nil {
			a.protos = map[uint8]bool{}
		}
		a.protos[m.Proto] = true
	}
}

// hostInboundConntrackFlushFilter is the netlink CustomConntrackFilter that
// selects now-denied host-inbound kernel conntrack entries for deletion (#5566).
// Ordinary peer-oriented flows are selected by their original destination and
// destination port. Box-oriented entries are selected only when the local
// original source address and source port match a guardable host-service tuple
// denied by BOTH the destination-owner union and every ingress view that
// judges it (#9637); this intersection avoids deleting a flow some ingress
// zone still permits, while the ingress-scoped nft guard enforces per-packet.
// The bounded catalog avoids flushing ephemeral egress and client-role ports.
type hostInboundConntrackFlushFilter struct {
	admit            map[netip.Addr]*hostInboundAdmit
	wgPorts          []uint16
	guardTCP         map[uint16]struct{}
	guardUDP         map[uint16]struct{}
	ingressTCP       []config.PortRange
	ingressUDP       []config.PortRange
	ingressAllowsAll bool
	ephemLo          uint16
	ephemHi          uint16
	// keptByAddr records covered flows the sweep deliberately kept, grouped
	// first by box address for aggregate journal counts and then by exact
	// conntrack tuple for transition-warning attribution. The custom class
	// looks like tightening-with-service-running staleness: TCP/UDP,
	// owner-denied, outside the catalog and client-role exempt sets, and either
	// outside the ephemeral range or (TCP only) backed by a local LISTEN
	// socket. The other class is exempt control-plane/client ports and bare
	// IP protocols (also owner-denied, never flushed, never guarded).
	// MatchConntrackFlow may run on the sweeper's goroutine(s), hence the mutex.
	keptMu       sync.Mutex
	keptByAddr   map[netip.Addr]*keptAddrEvidence
	tcpListeners map[uint16]bool
}

// readEphemeralPortRange returns the kernel's ephemeral source-port range for
// the kept-suspicious heuristic, defaulting to the Linux 32768-60999 default
// when the proc file is unreadable. A package var so tests pin boundaries
// deterministically.
var readEphemeralPortRange = func() (uint16, uint16) {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err == nil {
		fields := strings.Fields(string(raw))
		if len(fields) == 2 {
			lo, errLo := strconv.ParseUint(fields[0], 10, 16)
			hi, errHi := strconv.ParseUint(fields[1], 10, 16)
			if errLo == nil && errHi == nil && lo <= hi {
				return uint16(lo), uint16(hi)
			}
		}
	}
	return 32768, 60999
}

// readLocalTCPListenerPorts returns the set of local TCP ports with a LISTEN
// socket (state 0A in /proc/net/tcp{,6}), for distinguishing a bound TCP
// service sport inside the ephemeral range from ordinary egress (egress
// sockets never LISTEN). Unreadable proc files yield an empty set (fail-quiet
// for the WARN heuristic). A package var so tests pin deterministically.
var readLocalTCPListenerPorts = func() map[uint16]bool {
	out := map[uint16]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.ParseUint(parts[1], 16, 16)
			if err != nil {
				continue
			}
			out[uint16(port)] = true
		}
	}
	return out
}

func (f *hostInboundConntrackFlushFilter) boxOrientedDenied(addr netip.Addr, flow *netlink.ConntrackFlow) bool {
	a := f.admit[addr.Unmap()]
	if a == nil || a.allowsAll {
		return false
	}
	port := flow.Forward.SrcPort
	var guard map[uint16]struct{}
	switch flow.Forward.Protocol {
	case config.HostInboundProtoTCP:
		guard = f.guardTCP
	case config.HostInboundProtoUDP:
		guard = f.guardUDP
		if f.isWireGuardPort(port) {
			return false
		}
	default:
		// Bare IP protocols are never flushed (live-vs-stale
		// indistinguishable) but denied ones are evidence for the
		// transition-gated commit warning.
		f.noteKeptOther(addr, flow)
		return false
	}
	if _, ok := guard[port]; !ok {
		if xnft.HostInboundStaleReplyIsExempt(flow.Forward.Protocol, port) {
			f.noteKeptOther(addr, flow)
		} else {
			f.noteKeptSuspicious(addr, flow)
		}
		return false
	}
	if f.flowAdmitted(a, flow.Forward.Protocol, port) {
		return false
	}
	// Ingress intersection: some ingress zone may still permit this tuple to
	// this destination (ingress-permits/owner-denies). Flushing would break
	// that permitted use; the per-ingress nft guard already judges each
	// reply packet by its actual arrival zone, so keep the entry and let
	// the guard enforce.
	if f.ingressAllowsAll {
		return false
	}
	switch flow.Forward.Protocol {
	case config.HostInboundProtoTCP:
		if portInRanges(port, f.ingressTCP) {
			return false
		}
	case config.HostInboundProtoUDP:
		if portInRanges(port, f.ingressUDP) {
			return false
		}
	}
	return true
}

// noteKeptSuspicious records a box-oriented covered flow the sweep kept on a
// non-exempt catalog miss that is NOT convincingly legitimate egress: TCP/UDP,
// owner-denied, and either outside the ephemeral range or (TCP only) backed
// by a local LISTEN socket — a listener distinguishes a bound custom service
// sport inside the range from ordinary egress, which never LISTENs. UDP has
// no listen state (bound ephemeral clients are indistinguishable from bound
// services), so in-range UDP stays silent by design; see the matrix residual.
// Unlike the flush path, evidence deliberately ignores ingress permission:
// the flush intersection is safe only because a per-ingress nft guard judges
// each reply packet — and custom tuples have no guard anywhere, so an
// ingress-permitted custom still bypasses on every denying ingress.
func (f *hostInboundConntrackFlushFilter) noteKeptSuspicious(addr netip.Addr, flow *netlink.ConntrackFlow) {
	port := flow.Forward.SrcPort
	inEphem := port >= f.ephemLo && port <= f.ephemHi
	if inEphem && (flow.Forward.Protocol != config.HostInboundProtoTCP || !f.tcpListeners[port]) {
		return
	}
	a := f.admit[addr.Unmap()]
	if a == nil || f.flowAdmitted(a, flow.Forward.Protocol, port) {
		return
	}
	f.keptMu.Lock()
	defer f.keptMu.Unlock()
	ev := f.keptFor(addr.Unmap())
	sample := keptFlowSample10752(flow)
	ev.custom++
	if len(ev.customSamples) < 5 {
		ev.customSamples = append(ev.customSamples, sample)
	}
	recordKeptTupleEvidence10752(ev, flow, true)
}

// noteKeptOther records a box-oriented covered flow kept on an exempt
// control-plane/client tuple or a bare IP protocol that the owner denies.
// Like customs, evidence ignores ingress permission (no per-packet guard
// exists for these classes either). Unlike customs, this class surfaces ONLY
// through the transition-gated commit warning — per-apply journal WARNs
// would fire on legitimate steady-state control-plane traffic (DHCP
// renewals, NTP polls, OSPF hellos in zones that never admitted them).
func (f *hostInboundConntrackFlushFilter) noteKeptOther(addr netip.Addr, flow *netlink.ConntrackFlow) {
	a := f.admit[addr.Unmap()]
	if a == nil {
		return
	}
	switch flow.Forward.Protocol {
	case config.HostInboundProtoTCP, config.HostInboundProtoUDP:
		if f.flowAdmitted(a, flow.Forward.Protocol, flow.Forward.SrcPort) {
			return
		}
	default:
		if f.flowAdmitted(a, flow.Forward.Protocol, 0) {
			return
		}
	}
	f.keptMu.Lock()
	defer f.keptMu.Unlock()
	ev := f.keptFor(addr.Unmap())
	sample := keptFlowSample10752(flow)
	ev.other++
	if len(ev.otherSamples) < 3 {
		ev.otherSamples = append(ev.otherSamples, sample)
	}
	recordKeptTupleEvidence10752(ev, flow, false)
}

// keptFor returns the per-address evidence bucket, creating it (and the map)
// on first use. Callers must hold keptMu.
func (f *hostInboundConntrackFlushFilter) keptFor(addr netip.Addr) *keptAddrEvidence {
	if f.keptByAddr == nil {
		f.keptByAddr = map[netip.Addr]*keptAddrEvidence{}
	}
	ev, ok := f.keptByAddr[addr]
	if !ok {
		ev = &keptAddrEvidence{}
		f.keptByAddr[addr] = ev
	}
	return ev
}

func keptFlowSample10752(flow *netlink.ConntrackFlow) string {
	return fmt.Sprintf("%s %s:%d→%s:%d",
		protoName10752(flow.Forward.Protocol), ipString10752(flow.Forward.SrcIP), flow.Forward.SrcPort,
		ipString10752(flow.Forward.DstIP), flow.Forward.DstPort)
}

// recordKeptTupleEvidence10752 retains each observed conntrack tuple separately
// so commit projection can compare that exact L4 identity with old/new policy.
// Callers hold keptMu.
func recordKeptTupleEvidence10752(ev *keptAddrEvidence, flow *netlink.ConntrackFlow, custom bool) {
	if ev.byTuple == nil {
		ev.byTuple = make(map[keptFlowTuple10752]keptTupleEvidence10752)
	}
	tuple := keptFlowTupleIdentity10752(flow)
	tupleEv := ev.byTuple[tuple]
	if custom {
		tupleEv.custom++
	} else {
		tupleEv.other++
	}
	ev.byTuple[tuple] = tupleEv
}

func keptFlowTupleIdentity10752(flow *netlink.ConntrackFlow) keptFlowTuple10752 {
	src, _ := netip.AddrFromSlice(flow.Forward.SrcIP)
	dst, _ := netip.AddrFromSlice(flow.Forward.DstIP)
	return keptFlowTuple10752{
		src:      src.Unmap(),
		dst:      dst.Unmap(),
		protocol: flow.Forward.Protocol,
		srcPort:  flow.Forward.SrcPort,
		dstPort:  flow.Forward.DstPort,
	}
}

// keptSuspiciousReport returns the recorded custom-keep count and sample
// tuples (the journal WARN class): totals across addresses, samples in
// sorted-address order capped at five.
func (f *hostInboundConntrackFlushFilter) keptSuspiciousReport() (uint64, []string) {
	f.keptMu.Lock()
	defer f.keptMu.Unlock()
	var total uint64
	var samples []string
	for _, addr := range sortedKeptAddrs10752(f.keptByAddr) {
		ev := f.keptByAddr[addr]
		total += ev.custom
		for _, s := range ev.customSamples {
			if len(samples) >= 5 {
				break
			}
			samples = append(samples, s)
		}
	}
	return total, samples
}

// keptEvidenceReport returns the full evidence for commit projection: the
// per-address snapshot (a fresh map; callers may retain it).
func (f *hostInboundConntrackFlushFilter) keptEvidenceReport() map[netip.Addr]keptAddrEvidence {
	f.keptMu.Lock()
	defer f.keptMu.Unlock()
	if len(f.keptByAddr) == 0 {
		return nil
	}
	out := make(map[netip.Addr]keptAddrEvidence, len(f.keptByAddr))
	for addr, ev := range f.keptByAddr {
		out[addr] = cloneKeptAddrEvidence10752(*ev)
	}
	return out
}

func sortedKeptAddrs10752(byAddr map[netip.Addr]*keptAddrEvidence) []netip.Addr {
	addrs := make([]netip.Addr, 0, len(byAddr))
	for addr := range byAddr {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	return addrs
}

func protoName10752(proto uint8) string {
	switch proto {
	case config.HostInboundProtoTCP:
		return "tcp"
	case config.HostInboundProtoUDP:
		return "udp"
	default:
		return strconv.Itoa(int(proto))
	}
}

func ipString10752(ip net.IP) string {
	if ip == nil {
		return "?"
	}
	return ip.String()
}

func (f *hostInboundConntrackFlushFilter) flowAdmitted(a *hostInboundAdmit, proto uint8, port uint16) bool {
	switch proto {
	case 50, 51:
		return true
	case config.HostInboundProtoICMP, config.HostInboundProtoICMPv6:
		return true
	case config.HostInboundProtoTCP:
		return portInRanges(port, a.tcp)
	case config.HostInboundProtoUDP:
		return portInRanges(port, a.udp)
	default:
		return a.protos[proto]
	}
}

// MatchConntrackFlow reports whether the flow is a now-denied host-inbound entry
// to flush. It is deliberately conservative — it returns false (keep) for any
// flow it cannot prove is denied — so it can never delete a permitted or
// non-host-inbound flow.
func (f *hostInboundConntrackFlushFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if f == nil || flow == nil {
		return false
	}
	if dst, ok := netip.AddrFromSlice(flow.Forward.DstIP); ok {
		if a := f.admit[dst.Unmap()]; a != nil && !a.allowsAll {
			return !f.flowAdmitted(a, flow.Forward.Protocol, flow.Forward.DstPort) &&
				!(flow.Forward.Protocol == config.HostInboundProtoUDP && f.isWireGuardPort(flow.Forward.DstPort))
		}
	}
	// UDP can re-create an entry after the apply-time flush when the firewall
	// sends (for example) an IKE DPD packet. With ORIG box→peer, the incoming
	// peer packet is conntrack direction reply and the ordinary reply accept
	// precedes zone judgement. Match only catalogued local service source
	// ports; ephemeral egress and client-role ports are intentionally kept.
	if src, ok := netip.AddrFromSlice(flow.Forward.SrcIP); ok {
		return f.boxOrientedDenied(src.Unmap(), flow)
	}
	return false
}

// isWireGuardPort reports whether the destination UDP port is a configured
// WireGuard listen port, which the host-inbound chain admits globally (#5582) so
// the shim-steered outer transport reaches the kernel WG socket.
func (f *hostInboundConntrackFlushFilter) isWireGuardPort(port uint16) bool {
	for _, p := range f.wgPorts {
		if p == port {
			return true
		}
	}
	return false
}

// portInRanges reports whether port falls in any inclusive PortRange.
func portInRanges(port uint16, ranges []config.PortRange) bool {
	for _, r := range ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// buildHostInboundConntrackFlushFilter assembles the #5566 flush filter from the
// SAME structured host-inbound SSOT the nft chain renders from
// (config.HostInboundServiceMatch / HostInboundProtocolMatch), so the flush's
// admit decision cannot drift from the kernel chain's per-zone accepts. Returns
// nil when there is no covered firewall-local address (nothing to reconcile).
func buildHostInboundConntrackFlushFilter(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) *hostInboundConntrackFlushFilter {
	admit := map[netip.Addr]*hostInboundAdmit{}
	ensure := func(addr string) *hostInboundAdmit {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return nil
		}
		key := ip.Unmap()
		e := admit[key]
		if e == nil {
			e = &hostInboundAdmit{}
			admit[key] = e
		}
		return e
	}
	addFamily := func(v dpuserspace.ZoneHostInboundView, family string, addrs []string) {
		allowsAll := hostInboundAllowsAll(v)
		for _, addr := range addrs {
			e := ensure(addr)
			if e == nil {
				continue
			}
			if allowsAll {
				e.allowsAll = true
				continue
			}
			for _, svc := range v.SystemServices {
				for _, m := range config.HostInboundServiceMatch(svc, family) {
					e.add(m)
				}
			}
			for _, proto := range v.Protocols {
				for _, m := range config.HostInboundProtocolMatch(proto, family) {
					e.add(m)
				}
			}
		}
	}
	for _, v := range views {
		addFamily(v, "ip", v.V4Addrs)
		addFamily(v, "ip6", v.V6Addrs)
	}
	// #4420 HI-2: addressed-but-unzoned firewall-local addresses carry a catch-all
	// DROP with no service accepts — fully denied except the global exemptions, so
	// record them with an empty admit set.
	for _, addr := range unzonedV4 {
		ensure(addr)
	}
	for _, addr := range unzonedV6 {
		ensure(addr)
	}
	// An address reachable from an `all` / any-service zone gets a bare
	// `daddr <addr> accept` in the nft chain (no catch-all DROP), so every flow to
	// it is admitted — it is not "covered" by a default-deny and must never be
	// flushed even if a DIFFERENT zone view also names it (union: allows-all wins,
	// mirroring the chain's accept rule). Drop those entries so the covered set
	// equals the addresses that actually carry a default-deny.
	for addr, a := range admit {
		if a.allowsAll {
			delete(admit, addr)
		}
	}
	if len(admit) == 0 {
		return nil
	}
	guardTCP := map[uint16]struct{}{}
	guardUDP := map[uint16]struct{}{}
	for _, family := range []string{"ip", "ip6"} {
		catalog := xnft.HostInboundStaleReplyCatalog(family)
		for _, port := range catalog.TCP {
			guardTCP[port] = struct{}{}
		}
		for _, port := range catalog.UDP {
			guardUDP[port] = struct{}{}
		}
	}
	// Ingress admit union across every view that judges arrivals (#9637).
	// Only views with an ingress scope contribute; a view without netdevs
	// judges nothing via ingress. Trusted reinjection needs no separate
	// admit: it only fast-paths packets userspace already admitted under
	// this same ingress policy.
	var ingressTCP, ingressUDP []config.PortRange
	ingressAllowsAll := false
	for _, v := range views {
		if len(v.IngressNetdevs) == 0 && len(v.IngressVRFScopes) == 0 {
			continue
		}
		if hostInboundAllowsAll(v) {
			ingressAllowsAll = true
			continue
		}
		for _, family := range []string{"ip", "ip6"} {
			for _, svc := range v.SystemServices {
				for _, m := range config.HostInboundServiceMatch(svc, family) {
					if m.Reject {
						continue
					}
					switch m.Proto {
					case config.HostInboundProtoTCP:
						ingressTCP = append(ingressTCP, m.Ports...)
					case config.HostInboundProtoUDP:
						ingressUDP = append(ingressUDP, m.Ports...)
					}
				}
			}
			for _, proto := range v.Protocols {
				for _, m := range config.HostInboundProtocolMatch(proto, family) {
					switch m.Proto {
					case config.HostInboundProtoTCP:
						ingressTCP = append(ingressTCP, m.Ports...)
					case config.HostInboundProtoUDP:
						ingressUDP = append(ingressUDP, m.Ports...)
					}
				}
			}
		}
	}
	ephemLo, ephemHi := readEphemeralPortRange()
	return &hostInboundConntrackFlushFilter{
		admit: admit, wgPorts: wgListenPorts, guardTCP: guardTCP, guardUDP: guardUDP,
		ingressTCP: ingressTCP, ingressUDP: ingressUDP, ingressAllowsAll: ingressAllowsAll,
		ephemLo: ephemLo, ephemHi: ephemHi, tcpListeners: readLocalTCPListenerPorts(),
	}
}

// flushDeniedHostInboundConntrack reconciles Linux netfilter conntrack against
// the just-applied host-inbound set (#5566): it deletes every established/related
// kernel conntrack entry whose original-direction destination is a covered
// firewall-local host-inbound address that the CURRENT coarse rules no longer
// admit, so a service removed from a zone can no longer leave an existing
// direct-kernel connection authorized under the old config via the chain's
// leading `ct state established,related accept`.
//
// Best effort: the nft host-inbound table is already applied, so enforcement for
// NEW connections holds regardless. A conntrack flush failure only leaves
// PRE-EXISTING flows on their old authorization (the pre-fix behavior), so it is
// logged rather than surfaced as a commit failure — failing the commit would roll
// back correct enforcement over a transient conntrack-subsystem error.
// #6802: it returns whether every family's delete SUCCEEDED. A failure is still
// not a commit failure — the rationale above is sound and unchanged — but before
// #6802 it was not anything else either: no return value, no dirty flag, no
// counter, no metric, and no periodic reconcile re-ran it. Every ticker under
// pkg/daemon was enumerated and none re-drives applyConfig,
// applyHostInboundFilter or this flush, so the only re-attempt was the next
// externally-triggered apply — itself gated on InstallHostInbound succeeding.
//
// The failure direction is what makes that a defect rather than a tradeoff: the
// stale entry rides the chain's leading `ct state established,related accept`,
// so a now-DENIED host-inbound flow keeps working. It fails OPEN, and it stayed
// open until the flow closed or timed out.
//
// The caller records the outcome as retry DEBT and an always-on owner re-drives
// it (hostInboundConntrackReassertLoop), which is the same shape #6793 used for
// a dead RA sender: surface the failure, keep the state a retry needs, and let a
// cheap always-on gate re-drive it.
func (d *Daemon) flushDeniedHostInboundConntrack(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) bool {
	filter := buildHostInboundConntrackFlushFilter(views, unzonedV4, unzonedV6, wgListenPorts)
	if filter == nil {
		return true
	}
	var flushed uint
	ok := true
	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		n, err := conntrackDeleteFilters(family, filter)
		if err != nil {
			slog.Warn("host-inbound conntrack reconcile failed: existing direct-kernel connections to a now-denied host service may retain OLD authorization until they close or time out",
				"family", family, "err", err)
			// Keep going: the OTHER family's stale entries are independent and
			// still worth flushing. `continue` here is deliberate, not a
			// swallow — the failure is carried out in the return value.
			ok = false
			continue
		}
		flushed += n
	}
	if flushed > 0 {
		slog.Info("host-inbound conntrack reconcile: flushed now-denied kernel conntrack entries so stale direct-kernel host connections are re-evaluated against the current host-inbound set",
			"flushed", flushed)
	}
	// Evidence-based tightening visibility (#10752 HIGH residual): the sweep
	// deliberately keeps box-oriented non-catalog flows (custom ports such as
	// 2222 after an any-service→named tightening). Unlike the #6802 debt this
	// is not a failure — nothing failed — so it must not join the commit
	// error; but unlike a clean sweep it leaves authorization the new rules
	// no longer grant, so it must not pass silently either. The per-address
	// report (per-class counts with samples) is stashed for the commit
	// funnel's transition-aware warning; the journal WARN below covers
	// customs only, since exempt/bare steady-state traffic (DHCP renewals,
	// NTP polls, OSPF hellos in never-admitting zones) would make a
	// per-apply journal line pure noise.
	if d != nil {
		d.recordKeptSuspicious10752(filter.keptEvidenceReport())
	}
	if custom, samples := filter.keptSuspiciousReport(); custom > 0 {
		slog.Warn("host-inbound conntrack reconcile kept box-oriented non-catalog flows to covered addresses; with active traffic they ride the broad reply accept indefinitely — delete per the Removal procedures for unguarded tuples in docs/host-inbound-service-matrix.md, or verify with ss that each is a legitimate explicit-bind client",
			"kept", custom, "samples", samples)
	}
	return ok
}

// hostInboundConntrackFlushRequest is the exact desired set a flush was called
// with (#6802). The retry owner re-drives THIS, not a freshly-derived set: a
// retry that re-derived the set from the current config would silently attempt a
// different revocation than the one that failed, and the two differ exactly when
// a commit landed in between — which is when getting it wrong matters most.
type hostInboundConntrackFlushRequest struct {
	views         []dpuserspace.ZoneHostInboundView
	unzonedV4     []string
	unzonedV6     []string
	wgListenPorts []uint16
}

// noteHostInboundConntrackFlush records the outcome of a revocation attempt
// (#6802): on failure it retains the request as retry debt and counts it; on
// success it clears any debt, because a later successful flush over the CURRENT
// desired set has already revoked everything an older failed one would have.
//
// Clearing on success is safe for that reason and not merely convenient: the
// filter is built from the desired set, and a superset revocation subsumes an
// earlier one. Retaining stale debt after a good flush would make the owner
// re-drive a revocation whose target no longer exists.
func (d *Daemon) noteHostInboundConntrackFlush(req hostInboundConntrackFlushRequest, ok bool) {
	if ok {
		d.hostInboundConntrackDebt.Store(nil)
		return
	}
	d.hostInboundConntrackFlushFailures.Add(1)
	r := req
	d.hostInboundConntrackDebt.Store(&r)
	slog.Warn("host-inbound conntrack revocation failed; retaining retry debt " +
		"so an always-on owner re-drives it — until it succeeds, a now-denied " +
		"host-inbound flow may still be authorized by the chain's leading " +
		"established/related accept (#6802)")
}

// hostInboundConntrackReassertInterval is the cadence of the #6802 retry owner.
// A stale entry means a denied service is still reachable, so recovery wants to
// be prompt; but the retry is a conntrack dump+delete, so it must not run at the
// 2s cadence of the cluster reconcile. 30s matches proxyARPReassertInterval and
// raDeadSenderReassertInterval, the other always-on self-heal loops.
var hostInboundConntrackReassertInterval = 30 * time.Second

// hostInboundConntrackReassertLoop is the retry owner a failed revocation did
// not have (#6802).
//
// Every ticker under pkg/daemon was enumerated when this issue was measured —
// DDNS, RPM, HA fabric, HA, IPsec rebind, DHCP lease sync, neighbor, proxy-ARP,
// archive, kernel self-recover — and NONE re-runs applyConfig,
// applyHostInboundFilter or the flush. So the only re-attempt was the next
// externally-triggered apply, itself gated on InstallHostInbound succeeding.
//
// Always-on and mode-agnostic, mirroring proxyARPReassertLoop: free on the
// common path because the gate is a single atomic pointer load, so it costs
// nothing on a node whose revocations have all succeeded.
func (d *Daemon) hostInboundConntrackReassertLoop(ctx context.Context) {
	t := time.NewTicker(hostInboundConntrackReassertInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.retryHostInboundConntrackFlushOnce(ctx)
			d.retryHostInputFenceConntrackFlushOnce(ctx)
		}
	}
}

// retryHostInboundConntrackFlushOnce re-drives one owed revocation.
//
// It takes applySem before acting, for the #4001 reason the proxy-ARP loop
// gives: an apply may be mid-flight, and re-driving a revocation against a
// half-applied host-inbound set could revoke flows the in-flight apply is about
// to re-admit. The debt is re-read INSIDE the semaphore because the commit this
// tick queued behind may already have flushed successfully and cleared it —
// re-driving then would be a conntrack dump for nothing.
func (d *Daemon) retryHostInboundConntrackFlushOnce(ctx context.Context) {
	if d.hostInboundConntrackDebt.Load() == nil {
		return
	}
	if d.applySem == nil {
		return
	}
	if err := d.applySem.Acquire(ctx, 1); err != nil {
		return
	}
	defer d.applySem.Release(1)
	req := d.hostInboundConntrackDebt.Load()
	if req == nil {
		return
	}
	slog.Info("host-inbound conntrack revocation: re-driving a failed flush (#6802)")
	ok := d.flushDeniedHostInboundConntrack(req.views, req.unzonedV4, req.unzonedV6, req.wgListenPorts)
	d.noteHostInboundConntrackFlush(*req, ok)
}

// HostInboundConntrackFlushFailures reports the #6802 revocation failure count
// for the metrics collector.
func (d *Daemon) HostInboundConntrackFlushFailures() uint64 {
	return d.hostInboundConntrackFlushFailures.Load()
}

// HostInboundConntrackRevocationOwed reports whether a revocation is still owed
// (#6802) — the operator-facing form of "a now-denied host-inbound flow may
// still be authorized".
func (d *Daemon) HostInboundConntrackRevocationOwed() bool {
	return d.hostInboundConntrackDebt.Load() != nil
}

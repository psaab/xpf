package daemon

import (
	"net/netip"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// hostInboundWireGuardZonePorts maps a listener to the owner zone of its
// configured outer source address, not the logical WireGuard tunnel zone.
func hostInboundWireGuardZonePorts(cfg *config.Config, views []dpuserspace.ZoneHostInboundView) map[string][]uint16 {
	if cfg == nil {
		return nil
	}
	owners := make(map[netip.Addr]string)
	ambiguous := make(map[netip.Addr]bool)
	addrs := func(zone string, values []string) {
		for _, value := range values {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if owner, ok := owners[addr]; ok && owner != zone {
				ambiguous[addr] = true
				continue
			}
			owners[addr] = zone
		}
	}
	for _, view := range views {
		addrs(view.Zone, view.V4Addrs)
		addrs(view.Zone, view.V6Addrs)
	}

	byZone := make(map[string]map[uint16]bool)
	addPort := func(zone string, port uint16) {
		if byZone[zone] == nil {
			byZone[zone] = make(map[uint16]bool)
		}
		byZone[zone][port] = true
	}
	addTunnel := func(tc *config.TunnelConfig) {
		if tc == nil || tc.Mode != "wireguard" || tc.WgListenPort == 0 {
			return
		}
		source, err := netip.ParseAddr(tc.Source)
		if err != nil {
			addPort("", tc.WgListenPort)
			return
		}
		source = source.Unmap()
		zone, ok := owners[source]
		if !ok || ambiguous[source] || zone == "" {
			// Preserve the selected port in the global deny set without granting
			// an ingress-zone admit when its source owner is unknown.
			addPort("", tc.WgListenPort)
			return
		}
		addPort(zone, tc.WgListenPort)
	}
	for _, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		addTunnel(iface.Tunnel)
		for _, unit := range iface.Units {
			if unit != nil {
				addTunnel(unit.Tunnel)
			}
		}
	}
	if len(byZone) == 0 {
		return nil
	}
	out := make(map[string][]uint16, len(byZone))
	for zone, ports := range byZone {
		list := make([]uint16, 0, len(ports))
		for port := range ports {
			list = append(list, port)
		}
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
		out[zone] = list
	}
	return out
}

func hostInboundWireGuardZoneAddresses(views []dpuserspace.ZoneHostInboundView, family string) (zones []string, addresses map[string][]string, ambiguous []string) {
	owners := make(map[string]string)
	ambiguousSet := make(map[string]bool)
	for _, view := range views {
		addrs := view.V4Addrs
		if family == "ip6" {
			addrs = view.V6Addrs
		}
		for _, addr := range addrs {
			if owner, ok := owners[addr]; ok && owner != view.Zone {
				ambiguousSet[addr] = true
				continue
			}
			owners[addr] = view.Zone
		}
	}
	addresses = make(map[string][]string)
	seenZones := make(map[string]bool)
	seenAddrs := make(map[string]map[string]bool)
	for _, view := range views {
		addrs := view.V4Addrs
		if family == "ip6" {
			addrs = view.V6Addrs
		}
		for _, addr := range addrs {
			if ambiguousSet[addr] {
				if !seenZones["\x00"+addr] {
					ambiguous = append(ambiguous, addr)
					seenZones["\x00"+addr] = true
				}
				continue
			}
			if owners[addr] != view.Zone {
				continue
			}
			if !seenZones[view.Zone] {
				zones = append(zones, view.Zone)
				seenZones[view.Zone] = true
			}
			if seenAddrs[view.Zone] == nil {
				seenAddrs[view.Zone] = make(map[string]bool)
			}
			if !seenAddrs[view.Zone][addr] {
				addresses[view.Zone] = append(addresses[view.Zone], addr)
				seenAddrs[view.Zone][addr] = true
			}
		}
	}
	return zones, addresses, ambiguous
}

func hostInboundWireGuardZoneIngress(views []dpuserspace.ZoneHostInboundView) map[string][]string {
	ingress := make(map[string][]string)
	seenDevice := make(map[string]map[string]bool)
	for _, view := range views {
		if len(view.IngressNetdevs) == 0 {
			continue
		}
		if seenDevice[view.Zone] == nil {
			seenDevice[view.Zone] = make(map[string]bool)
		}
		for _, device := range view.IngressNetdevs {
			if !seenDevice[view.Zone][device] {
				ingress[view.Zone] = append(ingress[view.Zone], device)
				seenDevice[view.Zone][device] = true
			}
		}
	}
	return ingress
}

func hostInboundWGIntersectPorts(ports, listenPorts []uint16) []uint16 {
	allowed := make(map[uint16]bool, len(ports))
	for _, port := range ports {
		allowed[port] = true
	}
	var out []uint16
	for _, port := range listenPorts {
		if allowed[port] {
			out = append(out, port)
		}
	}
	return out
}

func hostInboundWGSubtractPorts(listenPorts, allowedPorts []uint16) []uint16 {
	allowed := make(map[uint16]bool, len(allowedPorts))
	for _, port := range allowedPorts {
		allowed[port] = true
	}
	var out []uint16
	for _, port := range listenPorts {
		if !allowed[port] {
			out = append(out, port)
		}
	}
	return out
}

func hostInboundWGAmbiguousAddresses(views []dpuserspace.ZoneHostInboundView, family string) []string {
	_, _, ambiguous := hostInboundWireGuardZoneAddresses(views, family)
	return ambiguous
}

// emitHostInboundWireGuardMismatchDrops runs before broad conntrack replies and
// service accepts. Only a selected port arriving on the outer-source owner
// zone's ingress and targeting that unique same-zone address escapes these
// counted guards.
func emitHostInboundWireGuardMismatchDrops(rules *[]string, views []dpuserspace.ZoneHostInboundView, unzoned []string, family string, listenPorts []uint16, zonePorts map[string][]uint16) {
	if len(listenPorts) == 0 {
		return
	}
	zones, addresses, ambiguous := hostInboundWireGuardZoneAddresses(views, family)
	ingress := hostInboundWireGuardZoneIngress(views)
	for _, zone := range zones {
		addrs := addresses[zone]
		if len(addrs) == 0 {
			continue
		}
		allowed := hostInboundWGIntersectPorts(zonePorts[zone], listenPorts)
		cn := xnft.HostInboundDenyCounterName(zone, family)
		if len(allowed) == 0 || len(ingress[zone]) == 0 {
			scope := family + " daddr " + nftAddrSet(addrs) + " udp dport " + renderWireGuardPortSpec(listenPorts)
			*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
			continue
		}
		if disallowed := hostInboundWGSubtractPorts(listenPorts, allowed); len(disallowed) > 0 {
			scope := family + " daddr " + nftAddrSet(addrs) + " udp dport " + renderWireGuardPortSpec(disallowed)
			*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
		}
		scope := "iifname != " + nftIifnameSet(ingress[zone]) + " " + family + " daddr " + nftAddrSet(addrs) +
			" udp dport " + renderWireGuardPortSpec(allowed)
		*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
	}
	if len(ambiguous) > 0 {
		cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
		scope := family + " daddr " + nftAddrSet(ambiguous) + " udp dport " + renderWireGuardPortSpec(listenPorts)
		*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
	}
	if len(unzoned) > 0 {
		cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
		scope := family + " daddr " + nftAddrSet(unzoned) + " udp dport " + renderWireGuardPortSpec(listenPorts)
		*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
	}
}

func emitHostInboundWireGuardIngressAccepts(rules *[]string, views []dpuserspace.ZoneHostInboundView, family string, listenPorts []uint16, zonePorts map[string][]uint16) {
	if len(listenPorts) == 0 {
		return
	}
	zones, addresses, _ := hostInboundWireGuardZoneAddresses(views, family)
	ingress := hostInboundWireGuardZoneIngress(views)
	for _, zone := range zones {
		allowed := hostInboundWGIntersectPorts(zonePorts[zone], listenPorts)
		if len(allowed) == 0 || len(ingress[zone]) == 0 || len(addresses[zone]) == 0 {
			continue
		}
		scope := "iifname " + nftIifnameSet(ingress[zone]) + " " + family + " daddr " + nftAddrSet(addresses[zone])
		*rules = append(*rules, "    "+scope+" udp dport "+renderWireGuardPortSpec(allowed)+" accept")
	}
}

// hostInboundIngressDestinations returns, per family, every firewall-local
// address the host-inbound chain must judge: each view's addresses, then the
// addressed-but-unzoned ones (#4420), first-seen order, no duplicates. It is
// used by unzoned and ambiguous ingress guards; ordinary zone-ingress rules
// intentionally use only zone-owned destinations.
func hostInboundIngressDestinations(views []dpuserspace.ZoneHostInboundView, unzonedV4, unzonedV6 []string) (v4, v6 []string) {
	seen4, seen6 := map[string]bool{}, map[string]bool{}
	add := func(out *[]string, seen map[string]bool, addrs []string) {
		for _, a := range addrs {
			if !seen[a] {
				seen[a] = true
				*out = append(*out, a)
			}
		}
	}
	for _, v := range views {
		add(&v4, seen4, v.V4Addrs)
		add(&v6, seen6, v.V6Addrs)
	}
	add(&v4, seen4, unzonedV4)
	add(&v6, seen6, unzonedV6)
	return v4, v6
}

func hostInboundZoneIngressDestinations(views []dpuserspace.ZoneHostInboundView) (v4, v6 []string) {
	return hostInboundIngressDestinations(views, nil, nil)
}

// hostInboundEmitsIngressDrop reports whether emitHostInboundZoneIngress emits a
// catch-all drop for the view in a family. The counter pre-pass consults it, so
// the chain never references a counter the table did not declare.
func hostInboundEmitsIngressDrop(v dpuserspace.ZoneHostInboundView, dests []string) bool {
	return len(v.IngressNetdevs) > 0 && hostInboundEmitsDrop(v, dests)
}

// hostInboundAmbiguousIngressNetdevs returns the builder's single, sorted list
// of effective netdevs claimed by multiple zone views. The builder attaches
// this list to one view only, rather than duplicating its global guard.
func hostInboundAmbiguousIngressNetdevs(views []dpuserspace.ZoneHostInboundView) []string {
	for _, v := range views {
		if len(v.IngressDenyNetdevs) > 0 {
			return v.IngressDenyNetdevs
		}
	}
	return nil
}

func hostInboundEmitsAmbiguousIngressDrop(views []dpuserspace.ZoneHostInboundView, dests []string) bool {
	return len(hostInboundAmbiguousIngressNetdevs(views)) > 0 && len(dests) > 0
}

func hostInboundEmitsUnzonedIngressDrop(netdevs, dests []string) bool {
	return len(netdevs) > 0 && len(dests) > 0
}

// emitHostInboundZoneIngress emits the #9637 ingress-zone rules for one view
// and family. Normal rules use the view's service and protocol matches, its
// per-zone deny counter, and every zone-owned local address. Unzoned
// destinations are denied later by their catch-all rather than admitted by an
// unrelated ingress zone. Ambiguous netdevs are handled separately after their
// address-owner service admits.
//
// Junos admits host-inbound traffic by the zone of the interface it arrives on.
// The destination-address rules alone judged a packet by the zone that owns the
// address it names. A client on a zone that denies ssh could therefore reach ssh
// on another zone's address, and a zone that admits ssh was refused on another
// zone's address. #9637 measured the refusal on the loss cluster.
func emitHostInboundZoneIngress(rules *[]string, v dpuserspace.ZoneHostInboundView, family string, dests []string) {
	if len(v.IngressNetdevs) == 0 || len(dests) == 0 {
		return
	}
	scope := "iifname " + nftIifnameSet(v.IngressNetdevs) + " " + family + " daddr " + nftAddrSet(dests)
	if hostInboundAllowsAll(v) {
		*rules = append(*rules, "    "+scope+" accept")
		return
	}
	for _, m := range hostInboundMatchSet(v, family) {
		*rules = append(*rules, "    "+scope+" "+m.match+" "+m.action)
	}
	cn := xnft.HostInboundDenyCounterName(v.Zone, family)
	*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
}

// emitHostInboundAmbiguousIngressAccepts applies each address owner's host
// services to an ambiguous effective netdev. WireGuard is deliberately absent:
// its exact ingress cannot be established on an ambiguous interface, and the
// earlier selected-port guard drops it before these broad accepts.
func emitHostInboundAmbiguousIngressAccepts(rules *[]string, views []dpuserspace.ZoneHostInboundView, family string) {
	netdevs := hostInboundAmbiguousIngressNetdevs(views)
	if len(netdevs) == 0 {
		return
	}
	for _, v := range views {
		addrs := v.V4Addrs
		if family == "ip6" {
			addrs = v.V6Addrs
		}
		if len(addrs) == 0 {
			continue
		}
		scope := "iifname " + nftIifnameSet(netdevs) + " " + family + " daddr " + nftAddrSet(addrs)
		if hostInboundAllowsAll(v) {
			*rules = append(*rules, "    "+scope+" accept")
			continue
		}
		for _, m := range hostInboundMatchSet(v, family) {
			*rules = append(*rules, "    "+scope+" "+m.match+" "+m.action)
		}
	}
}

// emitHostInboundAmbiguousIngressDrop fails closed for unmatched traffic on an
// ambiguous effective netdev. The junos-host counter is shared with unzoned
// drops because neither case has a uniquely attributable source zone.
func emitHostInboundAmbiguousIngressDrop(rules *[]string, views []dpuserspace.ZoneHostInboundView, family string, dests []string) {
	netdevs := hostInboundAmbiguousIngressNetdevs(views)
	if len(netdevs) == 0 || len(dests) == 0 {
		return
	}
	cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
	scope := "iifname " + nftIifnameSet(netdevs) + " " + family + " daddr " + nftAddrSet(dests)
	*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
}

// emitHostInboundUnzonedIngressDrop denies configured unzoned physical ingress
// before the residual established accept and destination-only zone fallback.
// Non-physical reinjection devices are intentionally absent from netdevs.
func emitHostInboundUnzonedIngressDrop(rules *[]string, netdevs []string, family string, dests []string) {
	if !hostInboundEmitsUnzonedIngressDrop(netdevs, dests) {
		return
	}
	cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
	scope := "iifname " + nftIifnameSet(netdevs) + " " + family + " daddr " + nftAddrSet(dests)
	*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
}

// emitHostInboundUnzonedVRFIngressDrop uses the slave name visible through
// meta sdifname before any zone rule scoped to the shared LOCAL_IN master.
func emitHostInboundUnzonedVRFIngressDrop(rules *[]string, slaves []string, family string, dests []string) {
	if !hostInboundEmitsUnzonedIngressDrop(slaves, dests) {
		return
	}
	cn := xnft.HostInboundDenyCounterName(dpuserspace.UnzonedHostInboundZoneLabel, family)
	scope := "meta sdifname " + nftIifnameSet(slaves) + " " + family + " daddr " + nftAddrSet(dests)
	*rules = append(*rules, "    "+scope+" counter name \""+cn+"\" drop")
}

package nftables

// stale_reply_guard.go is the shared SSOT for the #10752 (g1-input-F3, TCP)
// / #10764 (UDP twin) stale-reply guard: the set of box-side (proto, port)
// tuples a box-oriented conntrack entry may be revoked for.
//
// Background: the xpf_hostinbound chain leads with
// `ct state established,related ct direction reply accept` ahead of zone
// judgement. A conntrack entry created box-oriented (ORIG box→peer) — via
// TCP mid-stream pickup under nf_conntrack_tcp_loose=1 (#10752) or via a
// firewall-originated datagram such as IKE DPD (#10764) — has
// Forward.DstIP = the peer, so the #5566 flush predicate (which keys on the
// original-direction destination) keeps it forever, while the peer's packets
// ride the reply-direction accept. The guard closes this with a catalog drop
// ahead of the reply accept (emitted by both the daemon text oracle and this
// package's netlink renderer, parity-proven):
//
//   - `ct state established,related ct direction reply <fam> daddr
//     <covered-addrs> <proto> dport <catalog> drop`, where catalog ports
//     the current config does NOT admit are selected. Replies to still-
//     admitted services and non-catalog tuples continue to rule 2.
//
// The #5566 flush filter and the #9506 fence predicate use the same catalog
// to decide which box-oriented entries to delete: a box-oriented entry is
// flushable iff its box-side (proto, sport) is in the catalog and is not
// admitted by the current config for the box address. One catalog, three
// consumers (text guard, netlink guard, conntrack matchers) — it cannot
// drift.
//
// Catalog membership is derived from the #3627 B1a SSOT, never hand-listed:
//
//   - TCP: discrete system-service and routing-protocol ports, except
//     well-known client-role ports (BGP/LDP/MSDP and legacy rlogin/rsh/rexec).
//     The box can originate connections from those ports, so treating every
//     box-side service port as stale would break established control-plane or
//     client sessions when the interface's host-inbound set omits the service.
//   - UDP: discrete system-service ports except the client-role exemptions
//     below. UDP routing-protocol ports (RIP/RIPng/BFD/LDP) remain outside the
//     catalog because the box originates control-plane traffic from them.
//   - Excluded everywhere: port RANGES (traceroute's 33434-33523 overlaps the
//     default 32768-60999 ephemeral range), bare IP protocols, and ICMP.
//
// UDP client-role exemptions (kept out of the catalog, so the guard and
// matchers always let them ride rule 2):
//
//   - DHCPv4/6 ports: the DHCP client speaks FROM these ports. Guarding them
//     would break address acquisition on interfaces whose zone omits DHCP.
//   - NTP/123: chrony is the appliance time client; its source-port selection
//     is not pinned here, so keep it unguarded rather than risk breaking NTP.
//
// The residual hole is the exempt client-role set and services with no
// authoritative L4 tuple. The conntrack tuple alone cannot distinguish a
// service reply from an outbound client using that same source port; those
// tuples are kept rather than risking a false revocation of control-plane or
// client traffic. Bare-protocol and ranged flows are likewise unguarded.
// These limits preserve service-specific enforcement for the catalogued
// TCP/UDP tuples while keeping the normal ephemeral-source reply path intact.

import (
	"net/netip"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// staleReplyExemptUDPTokens are system-service tokens whose UDP tuples are
// client-role link-operation ports the box itself originates FROM. See the
// package comment above for why each is exempt.
var staleReplyExemptUDPTokens = map[string]bool{
	"dhcp":   true,
	"bootp":  true,
	"dhcpv6": true,
	"ntp":    true,
}

// StaleReplyGuardPorts is the per-family guardable port set: sorted-unique
// discrete ports. A box-side (proto, port) tuple is guardable iff it is in
// the corresponding set.
type StaleReplyGuardPorts struct {
	TCP []uint16
	UDP []uint16
}

// HostInboundStaleReplyCatalog returns the guardable port catalog for one
// nft family ("ip" / "ip6"). Pure function of the config SSOT — both nft
// renderers and both conntrack matchers derive from it, so they agree by
// construction. Output is sorted ascending and deduplicated (deterministic
// across map iteration orders, so parity byte-equality holds).
func HostInboundStaleReplyCatalog(family string) StaleReplyGuardPorts {
	tcpSet := map[uint16]bool{}
	udpSet := map[uint16]bool{}
	tokens := config.HostInboundAllExpansionServices()
	for _, tok := range tokens {
		for _, m := range config.HostInboundServiceMatch(tok, family) {
			switch m.Proto {
			case config.HostInboundProtoTCP:
				addDiscretePorts(tcpSet, m.Ports, staleReplyExemptTCPPorts)
			case config.HostInboundProtoUDP:
				if staleReplyExemptUDPTokens[tok] {
					continue
				}
				addDiscretePorts(udpSet, m.Ports, staleReplyExemptUDPPorts)
			}
		}
	}
	// Routing protocols contribute only TCP listeners the box does not
	// originate from. UDP protocols and the bidirectional TCP control-plane
	// ports remain outside the catalog; see staleReplyExemptTCPPorts above.
	for _, m := range config.HostInboundProtocolMatch("all", family) {
		if m.Proto == config.HostInboundProtoTCP {
			addDiscretePorts(tcpSet, m.Ports, staleReplyExemptTCPPorts)
		}
	}
	return StaleReplyGuardPorts{TCP: sortedPortKeys(tcpSet), UDP: sortedPortKeys(udpSet)}
}

// StaleReplyGuardRule drops reply-direction traffic to a covered local address
// when the reply's destination port is a currently denied catalog tuple.
// Addresses and ports are deterministic sorted slices for both renderers.
type StaleReplyGuardRule struct {
	Family    string
	Proto     uint8
	Ports     []uint16
	Addresses []string
}

type staleReplyAdmit struct {
	tcp []config.PortRange
	udp []config.PortRange
}

// HostInboundStaleReplyGuardRules derives the denied reply-tuple rules from
// the same desired views used to render the ordinary host-inbound chain.
// An address admitted by any-service is omitted, matching the chain's
// address-level union semantics. Unzoned addresses are covered with an empty
// admit set. WG listen ports remain globally admitted.
func HostInboundStaleReplyGuardRules(views []HostInboundZoneView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) []StaleReplyGuardRule {
	admit := map[netip.Addr]*staleReplyAdmit{}
	allowsAll := map[netip.Addr]bool{}
	ensure := func(raw string) (netip.Addr, *staleReplyAdmit) {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return netip.Addr{}, nil
		}
		ip = ip.Unmap()
		a := admit[ip]
		if a == nil {
			a = &staleReplyAdmit{}
			admit[ip] = a
		}
		return ip, a
	}
	addView := func(v HostInboundZoneView, family string, addrs []string) {
		full := hostInboundAllowsAll(v)
		for _, raw := range addrs {
			ip, a := ensure(raw)
			if !ip.IsValid() {
				continue
			}
			if full {
				allowsAll[ip] = true
				continue
			}
			for _, token := range v.SystemServices {
				for _, expanded := range config.HostInboundServiceTokenExpansion(token) {
					for _, m := range config.HostInboundServiceMatch(expanded, family) {
						if m.Reject {
							continue
						}
						switch m.Proto {
						case config.HostInboundProtoTCP:
							a.tcp = append(a.tcp, m.Ports...)
						case config.HostInboundProtoUDP:
							a.udp = append(a.udp, m.Ports...)
						}
					}
				}
			}
			for _, token := range v.Protocols {
				for _, m := range config.HostInboundProtocolMatch(token, family) {
					switch m.Proto {
					case config.HostInboundProtoTCP:
						a.tcp = append(a.tcp, m.Ports...)
					case config.HostInboundProtoUDP:
						a.udp = append(a.udp, m.Ports...)
					}
				}
			}
		}
	}
	for _, v := range views {
		addView(v, "ip", v.V4Addrs)
		addView(v, "ip6", v.V6Addrs)
	}
	for _, raw := range unzonedV4 {
		ensure(raw)
	}
	for _, raw := range unzonedV6 {
		ensure(raw)
	}
	for ip := range allowsAll {
		delete(admit, ip)
	}

	wg := make(map[uint16]bool, len(wgListenPorts))
	for _, port := range wgListenPorts {
		wg[port] = true
	}
	addrs := make([]netip.Addr, 0, len(admit))
	for ip := range admit {
		addrs = append(addrs, ip)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })

	var out []StaleReplyGuardRule
	for _, ip := range addrs {
		a := admit[ip]
		family := "ip"
		if ip.Is6() {
			family = "ip6"
		}
		catalog := HostInboundStaleReplyCatalog(family)
		for _, pair := range []struct {
			proto uint8
			ports []uint16
			allow []config.PortRange
		}{
			{config.HostInboundProtoTCP, catalog.TCP, a.tcp},
			{config.HostInboundProtoUDP, catalog.UDP, a.udp},
		} {
			var denied []uint16
			for _, port := range pair.ports {
				if pair.proto == config.HostInboundProtoUDP && wg[port] {
					continue
				}
				if !portInRanges(port, pair.allow) {
					denied = append(denied, port)
				}
			}
			if len(denied) > 0 {
				out = append(out, StaleReplyGuardRule{
					Family: family, Proto: pair.proto, Ports: denied, Addresses: []string{ip.String()},
				})
			}
		}
	}
	return out
}

var (
	staleReplyExemptTCPPorts = map[uint16]bool{
		20: true, 179: true, 512: true, 513: true, 514: true, 639: true, 646: true,
	}
	staleReplyExemptUDPPorts = map[uint16]bool{646: true}
)

// addDiscretePorts folds singleton ranges into the set, excluding known
// client-role ports whose box-originated replies must remain permitted.
func addDiscretePorts(set map[uint16]bool, prs []config.PortRange, exempt map[uint16]bool) {
	for _, p := range prs {
		if p.Lo != p.Hi || exempt[p.Lo] {
			continue
		}
		set[p.Lo] = true
	}
}

func portInRanges(port uint16, ranges []config.PortRange) bool {
	for _, r := range ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

func sortedPortKeys(set map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HostInboundStaleReplyFenceRules builds an all-services-denied guard catalog
// for the addresses carried by a cold-boot fence. Fences keep the global
// established-reply accept for ordinary client traffic, but must not let a
// box-originated service-port flow recreate the exact stale authorization the
// fence flushed.
func HostInboundStaleReplyFenceRules(views []HostInboundZoneView, unzonedV4, unzonedV6 []string, wgListenPorts []uint16) []StaleReplyGuardRule {
	v4 := append([]string(nil), unzonedV4...)
	v6 := append([]string(nil), unzonedV6...)
	for _, view := range views {
		v4 = append(v4, view.V4Addrs...)
		v6 = append(v6, view.V6Addrs...)
	}
	return HostInboundStaleReplyGuardRules(nil, v4, v6, wgListenPorts)
}

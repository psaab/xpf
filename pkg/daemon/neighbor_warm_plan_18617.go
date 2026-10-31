package daemon

import (
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// #18617: which session endpoints warmNeighborCache may probe, and out of
// which interface.
//
// The warm-up sends one datagram per unique session endpoint so the kernel
// resolves a neighbour. Before #18617 it sent to every endpoint through the
// default route. On a node that owned the WAN redundancy group but not the
// LAN one, a probe to a LAN host's global address therefore left through the
// WAN, came back from the upstream router to the cluster's own WAN address,
// and was default-denied as transit on this node's own dataplane (the
// test-failover RG1 Group 4 cell, every run). Probes to the source-NAT pool /
// proxy-ARP address looped the same way through whichever node answers ARP
// for it, and every routed endpoint (internet peers included) received a
// junk datagram that resolved nothing but the gateway.
//
// The plan is built once per pass from the ACTIVE CONFIG, not from the kernel
// routing table:
//
//   - owned: every address the cluster itself answers for. Interface unit
//     addresses (RETH units included, whether or not this node owns their RG
//     right now), VRRP virtual addresses, source-NAT pool addresses,
//     proxy-ARP addresses, and the addresses the kernel currently holds on a
//     configured interface (a DHCP lease). An owned address is never probed.
//   - on-link prefixes: each configured unit prefix (a DHCP unit contributes
//     the prefix of the address it currently holds). An endpoint is probed
//     only when it falls inside one that this node HOLDS: the unit is not a
//     RETH unit, or this node is primary for the RETH's redundancy group, AND
//     the kernel holds an address inside the prefix on that interface. The
//     probe is bound to that interface (SO_BINDTODEVICE), so it can never
//     follow a default route.
//
// Everything else is skipped and counted. A routed endpoint's gateway is
// warmed by the configured-target and force-probe passes, not here. A RETH
// prefix this node does not own is skipped on purpose: the node holds no
// address there, so the kernel cannot resolve a neighbour on it at all. The
// old probe for such an endpoint left through the default route and warmed
// nothing on the RETH member either, so skipping it loses no coverage. That
// standby pre-warm gap predates #18617 and is tracked in #18621.

// neighborWarmVerdict is the warm plan's decision for one endpoint.
type neighborWarmVerdict int

const (
	neighborWarmProbe   neighborWarmVerdict = iota // on-link on a held prefix
	neighborWarmOwned                              // a cluster-owned address
	neighborWarmNotHeld                            // configured prefix this node does not hold now
	neighborWarmRouted                             // in no configured prefix: reached via a gateway
)

// neighborWarmPrefix is one configured on-link prefix and the Linux interface
// that carries it on this node.
type neighborWarmPrefix struct {
	prefix netip.Prefix
	ifname string
	held   bool
}

// neighborWarmPlan is the per-pass classification state.
type neighborWarmPlan struct {
	ownedHosts    map[netip.Addr]struct{}
	ownedPrefixes []netip.Prefix
	prefixes      []neighborWarmPrefix // longest prefix first
	// primaryNotHeld names each configured RETH prefix whose RG this node is
	// primary for while the kernel holds no address inside it on the unit's
	// interface ("rg<N> <ifname> <prefix>"). Nothing on that prefix is
	// probed, which is the warm-up's silent no-op case (review of #18625).
	primaryNotHeld []string
}

// neighborWarmPlanInputs are the two runtime facts the plan needs besides the
// config. Both are seams so the plan is testable without netlink or a cluster.
type neighborWarmPlanInputs struct {
	// rgPrimary reports whether this node is primary for a redundancy group.
	rgPrimary func(rg int) bool
	// localAddrs returns the addresses the kernel holds on a Linux interface.
	localAddrs func(ifname string) []netip.Prefix
}

func netipPrefixFromCIDR(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func netipPrefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones), true
}

// unitLinuxName is the kernel name of a configured unit: the RETH resolved to
// its local member, then the VLAN id when the unit is tagged, else the unit
// number when it is not 0. resolveConfigSubnetLinuxName uses it too, so the
// warm-up and the DHCP relay cannot disagree about a unit's netdev.
func unitLinuxName(cfg *config.Config, ifcName string, unitNum int, unit *config.InterfaceUnit) string {
	name := resolveJunosIfName(cfg, ifcName)
	if unit.VlanID > 0 {
		return fmt.Sprintf("%s.%d", name, unit.VlanID)
	}
	if unitNum != 0 {
		return fmt.Sprintf("%s.%d", name, unitNum)
	}
	return name
}

// buildNeighborWarmPlan builds the per-pass plan. A nil cfg yields an empty
// plan: every endpoint is "routed" and nothing is probed.
func buildNeighborWarmPlan(cfg *config.Config, in neighborWarmPlanInputs) *neighborWarmPlan {
	p := &neighborWarmPlan{ownedHosts: make(map[netip.Addr]struct{})}
	if cfg == nil {
		return p
	}
	rgOwners := cfg.RethRGOwners()
	localCache := make(map[string][]netip.Prefix)
	local := func(ifname string) []netip.Prefix {
		if v, ok := localCache[ifname]; ok {
			return v
		}
		var v []netip.Prefix
		if in.localAddrs != nil {
			v = in.localAddrs(ifname)
		}
		localCache[ifname] = v
		return v
	}
	addOwned := func(pfx netip.Prefix) {
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits())
		if pfx.Bits() == pfx.Addr().BitLen() {
			p.ownedHosts[pfx.Addr()] = struct{}{}
			return
		}
		p.ownedPrefixes = append(p.ownedPrefixes, pfx.Masked())
	}
	for key, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		ifcName := ifc.Name
		if ifcName == "" {
			ifcName = key
		}
		rg, isReth := rgOwners[key]
		rgHeld := !isReth || (in.rgPrimary != nil && in.rgPrimary(rg))
		for unitNum, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			ifname := unitLinuxName(cfg, ifcName, unitNum, unit)
			held := local(ifname)
			for _, h := range held {
				p.ownedHosts[h.Addr().Unmap()] = struct{}{}
			}
			addPrefix := func(pfx netip.Prefix) {
				masked := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
				holds := false
				if rgHeld {
					for _, h := range held {
						if masked.Contains(h.Addr().Unmap()) {
							holds = true
							break
						}
					}
				}
				if isReth && rgHeld && !holds {
					p.primaryNotHeld = append(p.primaryNotHeld,
						fmt.Sprintf("rg%d %s %s", rg, ifname, masked))
				}
				p.prefixes = append(p.prefixes, neighborWarmPrefix{prefix: masked, ifname: ifname, held: holds})
			}
			for _, s := range unit.Addresses {
				pfx, ok := netipPrefixFromCIDR(s)
				if !ok {
					continue
				}
				// The unit's own address is cluster-owned whether or not
				// this node holds it now (a RETH VIP on the standby).
				p.ownedHosts[pfx.Addr().Unmap()] = struct{}{}
				if pfx.Bits() < pfx.Addr().BitLen() {
					addPrefix(pfx)
				}
			}
			// A DHCP unit has no configured prefix; it is on-link for the
			// prefix of the lease the kernel holds now.
			if unit.DHCP || unit.DHCPv6 {
				for _, h := range held {
					a := h.Addr()
					if a.IsLinkLocalUnicast() || h.Bits() >= a.BitLen() {
						continue
					}
					if (a.Is4() && unit.DHCP) || (!a.Is4() && unit.DHCPv6) {
						addPrefix(h)
					}
				}
			}
			for _, grp := range unit.VRRPGroups {
				if grp == nil {
					continue
				}
				for _, s := range grp.VirtualAddresses {
					if pfx, ok := netipPrefixFromCIDR(s); ok {
						p.ownedHosts[pfx.Addr().Unmap()] = struct{}{}
					}
				}
			}
		}
	}
	nat := &cfg.Security.NAT
	for name := range nat.SourcePools {
		nets, _ := config.SourceNATPoolNets(nat, name)
		for _, n := range nets {
			if pfx, ok := netipPrefixFromIPNet(n); ok {
				addOwned(pfx)
			}
		}
	}
	for _, e := range nat.ProxyARP {
		if e == nil {
			continue
		}
		for _, s := range e.Addresses {
			if pfx, ok := netipPrefixFromCIDR(s); ok {
				addOwned(pfx)
			}
		}
	}
	sort.Strings(p.primaryNotHeld)
	sort.SliceStable(p.prefixes, func(i, j int) bool {
		return p.prefixes[i].prefix.Bits() > p.prefixes[j].prefix.Bits()
	})
	return p
}

// owns reports whether ip is an address the cluster itself answers for.
func (p *neighborWarmPlan) owns(ip netip.Addr) bool {
	if p == nil {
		return false
	}
	ip = ip.Unmap()
	if _, ok := p.ownedHosts[ip]; ok {
		return true
	}
	for _, pfx := range p.ownedPrefixes {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// classify decides whether to probe ip and, if so, out of which interface.
// The longest configured prefix containing ip decides: if this node holds it,
// probe there; otherwise skip, even when a shorter held prefix also contains
// ip, because the kernel would route ip out the longer prefix's interface.
func (p *neighborWarmPlan) classify(ip netip.Addr) (string, neighborWarmVerdict) {
	if p == nil {
		return "", neighborWarmRouted
	}
	ip = ip.Unmap()
	if p.owns(ip) {
		return "", neighborWarmOwned
	}
	for _, pfx := range p.prefixes {
		if !pfx.prefix.Contains(ip) {
			continue
		}
		if pfx.held {
			return pfx.ifname, neighborWarmProbe
		}
		return "", neighborWarmNotHeld
	}
	return "", neighborWarmRouted
}

// kernelLocalAddrs is the production neighborWarmPlanInputs.localAddrs: the
// addresses the kernel holds on ifname, or none if the link is absent.
func kernelLocalAddrs(ifname string) []netip.Prefix {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		if pfx, ok := netipPrefixFromIPNet(a.IPNet); ok {
			out = append(out, pfx)
		}
	}
	return out
}

// neighborWarmPlan builds this pass's plan from the active config, the
// cluster's current RG ownership, and the kernel's per-interface addresses.
// Tests replace the two runtime inputs through d.neighborWarmPlanInputs.
func (d *Daemon) neighborWarmPlan(cfg *config.Config) *neighborWarmPlan {
	in := d.neighborWarmPlanInputs
	if in.rgPrimary == nil {
		in.rgPrimary = func(rg int) bool { return d.cluster != nil && d.cluster.IsLocalPrimary(rg) }
	}
	if in.localAddrs == nil {
		in.localAddrs = kernelLocalAddrs
	}
	return buildNeighborWarmPlan(cfg, in)
}

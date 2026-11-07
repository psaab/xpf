package daemon

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
)

// clusterControlLocalAddressCommitPreflight refuses a LIVE renumber of THIS
// node's cluster control-link address (#18606), the local-end half #8965
// does not see.
//
// THE DEFECT IT PREVENTS. #8965 gates the PEER address: the commit that moves
// what this node dials. Renumbering this node's OWN control address (same
// interface, same peer) passed every gate. Applying it moves the heartbeat and
// session sync to an address the peer does not target, and the coherent
// version of the change — the peer's `peer-address` updated to match — is
// refused by #8965 on whichever node it is local to, so the pair cannot be
// re-keyed live from one side. Before #18597 the per-commit heartbeat restart
// made this LOUD by accident (the restart could not bind the stale address and
// the commit failed through #9751, after it had already been applied); after
// it the commit succeeded and the cluster partitioned silently. This gate makes
// it loud on purpose, BEFORE promotion, with #8965's procedure.
//
// THE PREDICATE is "this commit moves the address the running heartbeat is
// bound to, or WOULD bind to on a fresh start": the bound address
// (Manager.HeartbeatLocalAddr) is a configured static address of the RUNNING
// config's control-link unit, and either the candidate's unit no longer
// carries it, or the candidate's primary/preferred selection changes what a
// fresh bind would SELECT while still carrying it (#18623). Both halves of
// the original predicate matter:
//   - the running-config half: if the heartbeat is bound to an address
//     config never named — a DHCP lease (networkd renders no static IPv4 for a
//     DHCPv4 row, so a unit with dhcp and a static address binds the lease), or
//     a foreign address listed ahead of the configured one — no commit is
//     removing it, and comparing against the candidate alone would refuse EVERY
//     commit on that node (review seats AG and AH).
//
// The selection half (#18623) mirrors the fresh-bind path exactly: networkd
// orders primary addresses first (per family/subnet for dual-stack) and
// preferred addresses first within their subnet (#15222/#15653), then
// selectClusterBindAddr picks the first address of the peer's family. Compare
// that pick for the running and candidate configs, and refuse only when a
// changed primary/preferred setting changes the pick away from the bound
// address while the bound address remains configured. This avoids refusing an
// unrelated commit when the kernel's enumeration order differs from
// networkd's configured order.
//
// A candidate that removes every static address (static -> DHCP) and so strands
// the bound one is refused like any renumber.
//
// It abstains (returns nil), so boot, the first cluster commit and node-id
// changes cannot trip it:
//   - no running heartbeat (HeartbeatLocalAddr == ""): boot applies run before
//     comms start, a first cluster commit has no heartbeat yet, and a
//     fabric-transport epoch never starts one; node-id / cluster-id changes are
//     refused live by #6192 and land through the boot path;
//   - the candidate has no control link (control-interface or peer-address
//     unset): #8965 / the topology gate own those;
//   - the running bind is not a configured static address of the running
//     config (above).
//
// PEER-SYNC. Wired on the synced path too, like #8965, and for its reason: in
// every shipped cluster config the control address sits inside
// `groups node0`/`node1` (docs/ha-cluster*.conf), so a synced text compiles to
// THIS node's own address and the gate no-ops in steady state. A synced text
// that DOES change this node's address (an operator edited node0's em0 on node1)
// is refused here: applying it would move this node to an address the peer
// does not target, while refusing keeps the pair connected on the old one. The
// synced call site runs this gate INSIDE Store.SyncApplyGated, on the compiled
// peer text and BEFORE anything is promoted (review seat AH): a refusal after
// promotion left the renumber active, so the re-push after the nack, any later
// push, a later local commit (whose running-config arm then abstains) and
// every background applier would have applied it. It passes the config
// captured before SyncApply as oldCfg.
func clusterControlLocalAddressCommitPreflight(running *cluster.Manager, oldCfg, newCfg *config.Config) error {
	if running == nil || !clusterTopologyConfigured(newCfg) {
		return nil
	}
	cc := newCfg.Chassis.Cluster
	if cc.ControlInterface == "" || cc.PeerAddress == "" {
		return nil
	}
	var running18606 controlLinkAddrs18606
	if oldCfg != nil && oldCfg.Chassis.Cluster != nil && oldCfg.Chassis.Cluster.ControlInterface != "" {
		running18606 = controlLinkState18606(oldCfg, oldCfg.Chassis.Cluster.ControlInterface)
	}
	return controlLocalAddressDecision18606(running.HeartbeatLocalAddr(), running18606,
		controlLinkState18606(newCfg, cc.ControlInterface), cc.PeerAddress)
}

// controlLinkAddrs18606 is the control-link unit's rendered static addresses
// plus the per-family primary/preferred selections that order them on a
// fresh bind (#18623). Empty primary/preferred means "no selection".
type controlLinkAddrs18606 struct {
	addrs       []string
	primary     string
	primaryV6   string
	preferred   string
	preferredV6 string
}

// controlLocalAddressDecision18606 is the DECISION, split from the accessors so
// every arm is unit testable without a running heartbeat. have is the running
// heartbeat's bound address; runningCfg and candidate are the running and the
// candidate configs' control-link unit state (rendered addresses + primary/
// preferred selections); peer is the candidate peer address used by fresh-bind
// selection for both configs so the comparison isolates selection changes.
func controlLocalAddressDecision18606(have string, runningCfg, candidate controlLinkAddrs18606, peer string) error {
	haveIP := net.ParseIP(have)
	if haveIP == nil || !cidrListHasIP18606(runningCfg.addrs, haveIP) {
		return nil
	}
	if cidrListHasIP18606(candidate.addrs, haveIP) {
		// Do not compare selected addresses by themselves: the kernel may
		// resolve configured addresses in either order. Only a changed
		// primary/preferred setting that changes the fresh bind selection
		// relative to the running config creates this deferred renumber.
		if !sameAddressSelection18606(runningCfg, candidate) {
			oldWant := freshBindSelection18606(runningCfg, peer)
			want := freshBindSelection18606(candidate, peer)
			if want != "" && want != have && want != oldWant {
				return controlLocalAddressMoveRefusal18606(have, want)
			}
		}
		return nil
	}
	want := freshBindSelection18606(candidate, peer)
	if want == "" {
		want = "no static address"
	}
	return controlLocalAddressMoveRefusal18606(have, want)
}

func sameAddressSelection18606(a, b controlLinkAddrs18606) bool {
	return a.primary == b.primary &&
		a.primaryV6 == b.primaryV6 &&
		a.preferred == b.preferred &&
		a.preferredV6 == b.preferredV6
}

// freshBindSelection18606 reproduces what a fresh comms start would bind:
// the candidate's rendered addresses reordered the way networkd renders
// them (each family's primary first, then preferred first within its
// subnet — pkg/networkd generateNetwork, #15222/#15653), fed through the
// same selectClusterBindAddr the live resolver uses. Returns "" when the
// candidate selects nothing (the caller then has no fresh pick to compare).
func freshBindSelection18606(candidate controlLinkAddrs18606, peer string) string {
	ordered := candidate.addrs
	// Mirror generateNetwork's ordering exactly: with any v6 selection,
	// primary is applied per-subnet for both families; otherwise the v4
	// primary goes first overall. Preferred then leads its own subnet.
	if candidate.primaryV6 != "" || candidate.preferredV6 != "" {
		ordered = orderPreferredFirstPerSubnet18606(ordered, candidate.primary)
		ordered = orderPreferredFirstPerSubnet18606(ordered, candidate.primaryV6)
	} else {
		ordered = orderAddresses18606(ordered, candidate.primary)
	}
	// Networkd filters the family whose DHCP client is on before address
	// ordering; controlLinkState18606 already applies that filter, so only
	// the preferred-address ordering remains to mirror here.
	ordered = orderPreferredFirstPerSubnet18606(ordered, candidate.preferred)
	if candidate.preferredV6 != "" {
		ordered = orderPreferredFirstPerSubnet18606(ordered, candidate.preferredV6)
	}
	var nets []net.Addr
	for _, c := range ordered {
		if ip, ipNet, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, &net.IPNet{IP: ip, Mask: ipNet.Mask})
		}
	}
	return selectClusterBindAddr(nets, peer, "")
}

// orderAddresses18606 mirrors pkg/networkd orderAddresses: primary first
// overall (if set and present). Kept in-package because the networkd
// helpers are unexported; the mirror is pinned by the same cases.
func orderAddresses18606(addrs []string, primaryAddr string) []string {
	if primaryAddr == "" || len(addrs) <= 1 {
		return addrs
	}
	ordered := make([]string, 0, len(addrs))
	found := false
	for _, a := range addrs {
		if a == primaryAddr {
			found = true
		} else {
			ordered = append(ordered, a)
		}
	}
	if found {
		ordered = append([]string{primaryAddr}, ordered...)
	}
	return ordered
}

// subnetKey18606 mirrors pkg/networkd subnetKey15222.
func subnetKey18606(addr string) string {
	_, ipNet, err := net.ParseCIDR(addr)
	if err != nil || ipNet == nil {
		return ""
	}
	return ipNet.String()
}

// orderPreferredFirstPerSubnet18606 mirrors pkg/networkd
// orderPreferredFirstPerSubnet (#15222): preferred leads its own subnet,
// every other address keeps its relative order.
func orderPreferredFirstPerSubnet18606(addrs []string, preferred string) []string {
	if preferred == "" || len(addrs) <= 1 {
		return addrs
	}
	key := subnetKey18606(preferred)
	if key == "" {
		return addrs
	}
	idx := -1
	firstInSubnet := -1
	for i, a := range addrs {
		if subnetKey18606(a) != key {
			continue
		}
		if firstInSubnet < 0 {
			firstInSubnet = i
		}
		if a == preferred {
			idx = i
		}
	}
	if idx < 0 || idx == firstInSubnet {
		return addrs
	}
	ordered := make([]string, 0, len(addrs))
	ordered = append(ordered, addrs[:firstInSubnet]...)
	ordered = append(ordered, preferred)
	for i, a := range addrs[firstInSubnet:] {
		if firstInSubnet+i == idx {
			continue
		}
		ordered = append(ordered, a)
	}
	return ordered
}

// cidrListHasIP18606 reports whether ip is the address of one of the CIDR
// strings (a bare address is accepted as well).
func cidrListHasIP18606(list []string, ip net.IP) bool {
	for _, c := range list {
		a, _, err := net.ParseCIDR(c)
		if err != nil {
			a = net.ParseIP(c)
		}
		if a != nil && a.Equal(ip) {
			return true
		}
	}
	return false
}

// controlLinkState18606 returns the control-link unit's rendered static
// addresses and the per-family primary/preferred selections networkd uses
// on a fresh bind. It resolves the control-interface ref the same way as
// the cluster monitor and #16425 gate: the last dot followed by a number
// names the unit, anything else is unit 0. It applies networkd's per-family
// DHCP rule (pkg/networkd generateNetwork, #2986), so a family whose DHCP
// client is on renders none of its static addresses. Selections are read
// through family-checked accessors so IPv6 values do not leak into IPv4
// slots (#15944).
func controlLinkState18606(cfg *config.Config, ref string) controlLinkAddrs18606 {
	if cfg == nil {
		return controlLinkAddrs18606{}
	}
	base, unit := ref, 0
	if i := strings.LastIndex(ref, "."); i >= 0 {
		if n, err := strconv.Atoi(ref[i+1:]); err == nil {
			base, unit = ref[:i], n
		}
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return controlLinkAddrs18606{}
	}
	u := ifc.Units[unit]
	if u == nil {
		return controlLinkAddrs18606{}
	}
	dhcpv6 := u.DHCPv6 || u.DHCPv6Client != nil
	out := controlLinkAddrs18606{
		primary:     u.PrimaryAddressForFamily(false),
		primaryV6:   u.PrimaryAddressForFamily(true),
		preferred:   u.PreferredAddressForFamily(false),
		preferredV6: u.PreferredAddressForFamily(true),
	}
	for _, a := range u.Addresses {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		if ip.To4() != nil && u.DHCP || ip.To4() == nil && dhcpv6 {
			continue
		}
		out.addrs = append(out.addrs, a)
	}
	return out
}

// controlLocalAddressMoveRefusal18606 is the operator-facing text. It names the
// procedure, in #8965's words, because a refusal that does not is a dead end.
func controlLocalAddressMoveRefusal18606(have, want string) error {
	return fmt.Errorf("commit rejected: changing this node's chassis cluster "+
		"control-link address from %s to %s cannot be done on a running cluster — "+
		"applying it moves this node's heartbeat and session sync to an address "+
		"the peer does not target, and the peer's matching peer-address change "+
		"cannot be applied live either, so the two nodes are durably partitioned.\n"+
		"To renumber the control link: set the new address on BOTH nodes and "+
		"restart xpfd on both, offline — stop xpfd on both nodes, put the new "+
		"address in each node's boot configuration, and start both; a boot apply "+
		"runs no preflight and the heartbeat starts fresh on the new address. Do NOT "+
		"commit the change on each node separately while both are running — that "+
		"produces the same partition by hand", have, want)
}

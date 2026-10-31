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
// THE PREDICATE is "this commit removes the address the running heartbeat is
// bound to": the bound address (Manager.HeartbeatLocalAddr) is a configured
// static address of the RUNNING config's control-link unit, and the
// candidate's unit no longer carries it. Both halves matter:
//   - membership in the candidate, not equality with one selected address: an
//     interface carrying two addresses can resolve them in a different order
//     from the kernel, so a gate that compared one selected address would
//     refuse an unrelated commit;
//   - membership in the RUNNING config: if the heartbeat is bound to an address
//     config never named — a DHCP lease (networkd renders no static IPv4 for a
//     DHCPv4 row, so a unit with dhcp and a static address binds the lease), or
//     a foreign address listed ahead of the configured one — no commit is
//     removing it, and comparing against the candidate alone would refuse EVERY
//     commit on that node (review seats AG and AH).
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
	var running18606 []string
	if oldCfg != nil && oldCfg.Chassis.Cluster != nil && oldCfg.Chassis.Cluster.ControlInterface != "" {
		running18606 = controlLinkStaticAddrs18606(oldCfg, oldCfg.Chassis.Cluster.ControlInterface)
	}
	return controlLocalAddressDecision18606(running.HeartbeatLocalAddr(), running18606,
		controlLinkStaticAddrs18606(newCfg, cc.ControlInterface), cc.PeerAddress)
}

// controlLocalAddressDecision18606 is the DECISION, split from the accessors so
// every arm is unit testable without a running heartbeat. have is the running
// heartbeat's bound address; runningCfg and candidate are the running and the
// candidate configs' static addresses on the control-link unit (CIDR strings);
// peer is the candidate's peer address (only used to name the new address in
// the refusal).
func controlLocalAddressDecision18606(have string, runningCfg, candidate []string, peer string) error {
	haveIP := net.ParseIP(have)
	if haveIP == nil || !cidrListHasIP18606(runningCfg, haveIP) {
		return nil
	}
	if cidrListHasIP18606(candidate, haveIP) {
		return nil
	}
	var nets []net.Addr
	for _, c := range candidate {
		if ip, ipNet, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, &net.IPNet{IP: ip, Mask: ipNet.Mask})
		}
	}
	want := selectClusterBindAddr(nets, peer, "")
	if want == "" {
		want = "no static address"
	}
	return controlLocalAddressMoveRefusal18606(have, want)
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

// controlLinkStaticAddrs18606 returns the static addresses networkd actually
// RENDERS for the unit a control-interface ref names: the last dot followed by
// a number names the unit, anything else is unit 0 (the split the cluster
// monitor and the #16425 gate use). It applies networkd's per-family rule
// (pkg/networkd generateNetwork, #2986): a family whose DHCP client is on
// renders none of its static addresses — IPv4 statics under `dhcp`, IPv6
// statics under `dhcpv6` (the compiler's unitHasDHCPv6) — so adding `dhcp` to a
// unit while keeping its static address H removes H from the kernel and is a
// renumber like any other (review seat AE). nil when the interface or unit is
// not declared.
func controlLinkStaticAddrs18606(cfg *config.Config, ref string) []string {
	if cfg == nil {
		return nil
	}
	base, unit := ref, 0
	if i := strings.LastIndex(ref, "."); i >= 0 {
		if n, err := strconv.Atoi(ref[i+1:]); err == nil {
			base, unit = ref[:i], n
		}
	}
	ifc := cfg.Interfaces.Interfaces[base]
	if ifc == nil {
		return nil
	}
	u := ifc.Units[unit]
	if u == nil {
		return nil
	}
	dhcpv6 := u.DHCPv6 || u.DHCPv6Client != nil
	var out []string
	for _, a := range u.Addresses {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		if ip.To4() != nil && u.DHCP || ip.To4() == nil && dhcpv6 {
			continue
		}
		out = append(out, a)
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

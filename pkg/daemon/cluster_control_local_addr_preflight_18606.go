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
// THE PREDICATE is "the address the RUNNING heartbeat is bound to is no longer
// a configured static address of the candidate's control-link unit". Keyed on
// membership, not on equality with one selected address: an interface carrying
// two addresses could resolve them in a different order from the kernel, and a
// gate that compared one selected address would refuse an unrelated commit.
//
// It abstains (returns nil), so boot, the first cluster commit and node-id
// changes cannot trip it:
//   - no running heartbeat (HeartbeatLocalAddr == ""): boot applies run before
//     comms start, a first cluster commit has no heartbeat yet, and a
//     fabric-transport epoch never starts one; node-id / cluster-id changes are
//     refused live by #6192 and land through the boot path;
//   - the candidate has no control link (control-interface or peer-address
//     unset): #8965 / the topology gate own those;
//   - the candidate's control unit carries NO static address (DHCP, or the
//     unit/interface not declared): there is nothing to compare, and refusing
//     would block every commit of a DHCP-addressed control link.
//
// PEER-SYNC. Wired on the synced path too, like #8965, and for its reason: in
// every shipped cluster config the control address sits inside
// `groups node0`/`node1` (docs/ha-cluster*.conf), so a synced text compiles to
// THIS node's own address and the gate no-ops in steady state. A synced text
// that DOES change this node's address (an operator edited node0's em0 on node1)
// is refused here: applying it would move this node to an address the peer
// does not target, while refusing keeps the pair connected on the old one. As
// on #8965's synced path, SyncApply has already promoted the text, so a restart
// applies it — which is the documented procedure.
func clusterControlLocalAddressCommitPreflight(running *cluster.Manager, newCfg *config.Config) error {
	if running == nil || !clusterTopologyConfigured(newCfg) {
		return nil
	}
	cc := newCfg.Chassis.Cluster
	if cc.ControlInterface == "" || cc.PeerAddress == "" {
		return nil
	}
	return controlLocalAddressDecision18606(running.HeartbeatLocalAddr(),
		controlLinkStaticAddrs18606(newCfg, cc.ControlInterface), cc.PeerAddress)
}

// controlLocalAddressDecision18606 is the DECISION, split from the accessors so
// every arm is unit testable without a running heartbeat. have is the running
// heartbeat's bound address, candidate the candidate's configured static
// addresses on the control-link unit (CIDR strings), peer the candidate's
// peer address (only used to name the new address in the refusal).
func controlLocalAddressDecision18606(have string, candidate []string, peer string) error {
	haveIP := net.ParseIP(have)
	if haveIP == nil || len(candidate) == 0 {
		return nil
	}
	var nets []net.Addr
	for _, c := range candidate {
		ip, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			if ip = net.ParseIP(c); ip == nil {
				continue
			}
			ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(len(ip)*8, len(ip)*8)}
		}
		if ip.Equal(haveIP) {
			return nil
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: ipNet.Mask})
	}
	if len(nets) == 0 {
		return nil
	}
	want := selectClusterBindAddr(nets, peer, "")
	if want == "" {
		want = strings.Join(candidate, ", ")
	}
	return controlLocalAddressMoveRefusal18606(have, want)
}

// controlLinkStaticAddrs18606 returns the configured static addresses of the
// unit a control-interface ref names: the last dot followed by a number names
// the unit, anything else is unit 0 — the split the cluster monitor and the
// #16425 gate use. nil when the interface or unit is not declared.
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
	return u.Addresses
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
		"restart xpfd on both, or take the cluster down before the move. Do NOT "+
		"commit the change on each node separately while both are running — that "+
		"produces the same partition by hand", have, want)
}

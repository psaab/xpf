package dataplane

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #15944 H4-01: a configured primary that is NOT YET INSTALLED cannot
// promote under the old rule (promote only an existing secondary): the
// AddrAdd appended it as IFA_F_SECONDARY behind the incumbent peer.
// planAddressReconcile must now cycle the subnet's existing desired
// peers (delete, re-add after the primary) so the fresh primary lands
// first.
//
// FAIL-ON-REVERT: removing the fresh-primary subnet marking in
// planAddressReconcile leaves the incumbent peer untouched and adds the
// primary behind it — the first cell's delete assertions fail.

func mkAddr15944(t *testing.T, cidr string, flags int) netlink.Addr {
	t.Helper()
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	ipnet.IP = ip
	return netlink.Addr{IPNet: ipnet, Flags: flags}
}

func addrKeys15944(addrs []*netlink.Addr) map[string]bool {
	out := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		out[a.IPNet.String()] = true
	}
	return out
}

func TestPlanAddressReconcileFreshPrimaryPromotes15944(t *testing.T) {
	// Existing peer 10.0.0.1/24 (flags=0), desired adds primary 10.0.0.2/24.
	existing := []netlink.Addr{mkAddr15944(t, "10.0.0.1/24", 0)}
	del, add, _ := planAddressReconcile(existing, []string{"10.0.0.1/24", "10.0.0.2/24"}, "ge-0-0-0", "10.0.0.2/24", "")
	delKeys := addrKeys15944(del)
	addKeys := addrKeys15944(add)
	if !delKeys["10.0.0.1/24"] {
		t.Fatalf("fresh primary: incumbent peer must be cycled (deleted), del=%v", delKeys)
	}
	if !addKeys["10.0.0.2/24"] || !addKeys["10.0.0.1/24"] {
		t.Fatalf("fresh primary: both addresses must be re-added, add=%v", addKeys)
	}
	// The primary must be added BEFORE the cycled peer so the kernel
	// marks it primary, not IFA_F_SECONDARY.
	primIdx, peerIdx := -1, -1
	for i, a := range add {
		switch a.IPNet.String() {
		case "10.0.0.2/24":
			primIdx = i
		case "10.0.0.1/24":
			peerIdx = i
		}
	}
	if primIdx < 0 || peerIdx < 0 || primIdx > peerIdx {
		t.Fatalf("add order must install primary first: add=%v", addKeys)
	}
}

func TestPlanAddressReconcileSecondaryPrimaryStillPromotes15944(t *testing.T) {
	// Control: an installed secondary primary still cycles (pre-existing
	// #15653 behaviour must not regress).
	existing := []netlink.Addr{
		mkAddr15944(t, "10.0.0.1/24", 0),
		mkAddr15944(t, "10.0.0.2/24", unix.IFA_F_SECONDARY),
	}
	del, add, _ := planAddressReconcile(existing, []string{"10.0.0.1/24", "10.0.0.2/24"}, "ge-0-0-0", "10.0.0.2/24", "")
	delKeys := addrKeys15944(del)
	addKeys := addrKeys15944(add)
	if !delKeys["10.0.0.2/24"] || !addKeys["10.0.0.2/24"] {
		t.Fatalf("secondary primary must be deleted and re-added: del=%v add=%v", delKeys, addKeys)
	}
}

func TestPlanAddressReconcileConvergedPrimaryNoChurn15944(t *testing.T) {
	// Control: a present non-secondary primary plans no churn.
	existing := []netlink.Addr{
		mkAddr15944(t, "10.0.0.2/24", 0),
		mkAddr15944(t, "10.0.0.1/24", unix.IFA_F_SECONDARY),
	}
	del, add, _ := planAddressReconcile(existing, []string{"10.0.0.1/24", "10.0.0.2/24"}, "ge-0-0-0", "10.0.0.2/24", "")
	if len(del) != 0 || len(add) != 0 {
		t.Fatalf("converged primary must plan no change, got del=%v add=%v", addrKeys15944(del), addrKeys15944(add))
	}
}

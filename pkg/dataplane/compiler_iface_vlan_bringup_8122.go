package dataplane

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/vishvananda/netlink"
)

// VLAN sub-interface bring-up: the sentinel, the accept_ra write, and the two
// netlink seams that make both testable (#8122).
//
// Split out of compiler_iface.go rather than appended to it. That file sits
// against the 2000 LOC modularity floor, and this is a cohesive unit — one
// failure classification, one side effect, and the seams that bind them — so
// carving it out is the split the discipline asks for rather than an exception
// recorded to avoid one.

// errVLANBringUpFailed marks the two failures that happen AFTER netlink.LinkAdd
// has already succeeded: the created link could not be found again, or it could
// not be brought up.
//
// It exists for the operator's record, not for control flow. Both of these fall
// through to the caller's soft skip, which labels its UnarmedSurface "create
// failed" for anything that is not errVLANAdoptRefused — so a link that WAS
// created and then failed to come up was filed as a creation failure. That is
// the same false-statement harm #6916 named one branch over: it is the sentence
// that sends an operator looking for a creation error that never happened,
// while the actual fault (a set-up refusal on a link that exists) goes unnamed.
//
// It deliberately does NOT change the disposition. Failing the apply here is
// what errVLANCreateFailed's own comment declines to do, and for the reason
// stated there: the link exists, the filter binding IS assigned, and the #6893
// harm does not arise.
var errVLANBringUpFailed = errors.New("VLAN sub-interface created but not brought up")

// disableAcceptRA turns off RA acceptance on a VLAN child — the firewall uses
// its own configured routes. Extracted (#8122) so the create and adopt paths
// call ONE thing: the split that let the adopt path skip it was structural, and
// a second inline copy would be the same shape waiting to drift again.
func disableAcceptRA(subName string) {
	raPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", subName)
	if err := acceptRAWriteSeam(raPath, []byte("0"), 0644); err != nil {
		slog.Warn("failed to disable accept_ra on VLAN sub-interface",
			"name", subName, "err", err)
	}
}

// acceptRAWriteSeam is disableAcceptRA's test seam. The real write targets
// /proc, which a unit test cannot create, so without a seam the create/adopt
// symmetry this change is about could only be asserted by reading the code —
// which is what let the paths diverge in the first place.
var acceptRAWriteSeam = os.WriteFile

// vlanLinkAddSeam / vlanLinkSetUpSeam are the create path's test seams.
//
// Added for a specific reason (#8122), and it is worth recording because the
// reason is a mutation that ESCAPED. The first version of the errVLANBringUpFailed
// test drove ensureVLANSubInterfaceFn — the CALLER's seam — and synthesized the
// wrapped error itself, so it bound the label switch and not the two production
// sites that must carry the sentinel. Deleting both `%w: %w` wraps from this file
// left that test green. Without these seams the wrapping is unbindable, and an
// unbindable claim is one that will be believed exactly as long as nobody tries
// it.
var (
	vlanLinkAddSeam     = netlink.LinkAdd
	vlanLinkSetUpSeam   = netlink.LinkSetUp
	vlanLinkSetDownSeam = netlink.LinkSetDown
)

// #8119/#8120: the netlink MUTATORS on the interface-reconcile path, behind
// seams so a test can drive the real compileZones over a simulated host and
// assert what TWO consecutive applies leave behind.
//
// A single apply is self-consistent, so a single-apply assertion passes on both
// of those defects whichever way the zone map happened to iterate. The second
// apply is the only witness that can contradict a reconcile, because it does
// not share the assumption that one pass converges.
//
// Reads are NOT seamed: CompileResult's ifCache / linkCache / linkIdxMap are
// package-visible maps a test seeds directly, which also reproduces the real
// cache lifetime — one CompileResult per apply, populated once from the host.
var (
	linkSetMTUSeam     = netlink.LinkSetMTU
	addrLinkByNameSeam = netlink.LinkByName
	addrListSeam       = netlink.AddrList
	addrAddSeam        = netlink.AddrAdd
	addrDelSeam        = netlink.AddrDel
)

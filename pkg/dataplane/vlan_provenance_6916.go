package dataplane

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

// This file is the ONE definition of "may this link's ParentIndex be read as an
// 802.1Q delegation, and may xpf adopt this device as its VLAN child".
//
// It exists because the two questions were answered in two places that could
// drift, and a divergence between them is ALWAYS a bug: the arm-coverage proof
// (#6864, armproof.go) decides whether a surface is covered, and
// ensureVLANSubInterface decides whether a device becomes that surface. If the
// proof trusts a device the compiler refuses — or worse, the compiler adopts a
// device the proof knows it cannot vouch for — the two disagree about the same
// physical link, which is precisely the state #5275 exists to make impossible.
//
// vishvananda/netlink folds IFLA_LINK into LinkAttrs.ParentIndex in the COMMON
// attribute loop, for EVERY link kind. What IFLA_LINK means is per-kind: a
// macvlan/ipvlan's lower device, a tunnel's bound device, and — the sharp one —
// a veth's PEER, which for a cross-namespace pair is an ifindex in the FOREIGN
// namespace and can numerically alias any local interface. So ParentIndex is
// meaningless until the kind is proven, and still meaningless for a genuine
// vlan whose real_dev lives in another namespace.

// vlanDelegationDefect reports why lnk's ParentIndex may NOT be read as an
// 802.1Q delegation, or "" when it may.
//
// The two rejections are the pair #6864 established, in the order that matters:
// kind first, because a non-vlan's ParentIndex is not a parent at all, then
// namespace, because a genuine vlan whose real_dev has moved keeps its kind and
// keeps a ParentIndex that now names an ifindex in the FOREIGN namespace.
//
// That second case is not inert. A hostile review of #6864 reproduced it across
// three namespaces: the orphan is un-`up`-able only while the foreign real_dev
// is down, and once that device is up in its own namespace the local child
// comes up (LinkSetUp rc=0, oper=up) and forwards.
func vlanDelegationDefect(lnk netlink.Link) string {
	if lnk == nil {
		return "no link"
	}
	if kind := lnk.Type(); kind != vlanLinkKind {
		return fmt.Sprintf("ifindex %d is a %q link, not an 802.1Q vlan — its "+
			"ParentIndex is not a vlan delegation", lnk.Attrs().Index, kind)
	}
	if nsid := lnk.Attrs().NetNsID; nsid != netnsIDLocal {
		return fmt.Sprintf("ifindex %d is an 802.1Q vlan whose real_dev is in "+
			"ANOTHER namespace (link-netnsid %d) — its ParentIndex names a "+
			"foreign ifindex", lnk.Attrs().Index, nsid)
	}
	return ""
}

// vlanAdoptionRefusal reports why the device already occupying "<phys>.<vid>"
// must NOT be adopted as xpf's VLAN child for wantParent/wantVID, or "" when it
// may be.
//
// #6916: the adoption used to be unconditional — LinkByName succeeded, so the
// ifindex was taken. That ifindex then becomes a delegated VLAN child
// (compiler_iface.go, the sole writer of genericXDPIfindexes), and the attach
// loop SKIPS delegated children because "the parent handles VLAN traffic". For
// a device that is not actually a child of that parent, nothing handles its
// traffic: it forwards with no shim on it, and the unmanaged sweep will not
// remove it either, because it deliberately skips any name whose prefix before
// '.' is a managed interface.
//
// So the checks are not tidiness. Each one is a way for a live foreign device
// to end up excluded from XDP attach:
//
//   - KIND and NAMESPACE, via vlanDelegationDefect above.
//   - VLAN ID, because a vlan at "p0.100" carrying VID 200 is a different
//     surface from the one the config asked for, and the vlan_iface_map entry
//     written from it would demux the wrong tag.
//   - PARENT, because a genuine local vlan of a DIFFERENT physical interface
//     answers every other check while delegating to a parent that is not the
//     one whose XDP program is supposed to cover it.
//   - PROTOCOL (#15215 A28-02), because an 802.1ad (0x88a8) vlan at
//     "p0.100" answers kind/VID/parent while classifying on the S-tag
//     ethertype. The create path builds netlink.Vlan{VlanId: vid} with no
//     protocol (kernel default 802.1Q) and the parent XDP classifies
//     802.1Q only, so adopting an 802.1ad child brings up a wrong-protocol
//     kernel child as the configured 802.1Q unit. VLAN_PROTOCOL_UNKNOWN
//     (zero) is accepted: netlink leaves it zero when IFLA_VLAN_PROTOCOL
//     is absent, and the kernel default for a vlan device is 802.1Q.
//
// The caller decides what to do with a refusal. It is deliberately a reason
// string rather than a sentinel error: the reason reaches the operator in an
// UnarmedSurface record, and "refused" without which check refused it would
// leave them nothing to act on.
func vlanAdoptionRefusal(existing netlink.Link, wantParent, wantVID int) string {
	if why := vlanDelegationDefect(existing); why != "" {
		return why
	}
	vlan, ok := existing.(*netlink.Vlan)
	if !ok {
		// Kind says "vlan" but the concrete type is not *netlink.Vlan. Nothing
		// in vishvananda/netlink produces that today; refusing rather than
		// falling through keeps the VlanId check below from being skipped by a
		// shape this function cannot read.
		return fmt.Sprintf("ifindex %d reports kind %q but did not decode as an "+
			"802.1Q link, so its VLAN ID cannot be verified",
			existing.Attrs().Index, vlanLinkKind)
	}
	if vlan.VlanId != wantVID {
		return fmt.Sprintf("ifindex %d is an 802.1Q vlan carrying VID %d, not the "+
			"configured VID %d", vlan.Attrs().Index, vlan.VlanId, wantVID)
	}
	if vlan.VlanProtocol != netlink.VLAN_PROTOCOL_UNKNOWN && vlan.VlanProtocol != netlink.VLAN_PROTOCOL_8021Q {
		return fmt.Sprintf("ifindex %d is a vlan with protocol %s (0x%04x), not "+
			"802.1Q — refusing to adopt it as the configured 802.1Q child",
			vlan.Attrs().Index, vlan.VlanProtocol.String(), uint16(vlan.VlanProtocol))
	}
	if got := vlan.Attrs().ParentIndex; got != wantParent {
		return fmt.Sprintf("ifindex %d is an 802.1Q vlan delegating to ifindex %d, "+
			"not the configured parent ifindex %d", vlan.Attrs().Index, got, wantParent)
	}
	return ""
}

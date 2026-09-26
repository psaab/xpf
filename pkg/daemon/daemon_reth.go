// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/netname"
	"github.com/psaab/xpf/pkg/rendersafe"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// fixRethLinkFile rewrites the .link file for a RETH member to use
// OriginalName= (the kernel name) instead of MACAddress= for matching.
// This ensures the .link works on reboot when the MAC reverts to physical.
func fixRethLinkFile(ifName, kernelName string) {
	if !rendersafe.SafeInterfaceName(kernelName) {
		slog.Warn("refusing unsafe RETH OriginalName", "iface", ifName, "kernelName", kernelName)
		return
	}
	if glob := rendersafe.FirstGlobMetacharacter(kernelName); glob != "" {
		slog.Warn("refusing glob RETH OriginalName", "iface", ifName, "kernelName", kernelName, "glob", glob)
		return
	}
	path := filepath.Join(linkDir, linkPrefix+ifName+".link")
	content := fmt.Sprintf("# Managed by xpfd — do not edit\n[Match]\nOriginalName=%s\n\n[Link]\nName=%s\n", kernelName, ifName)
	// AtomicGeneratedConfig: regenerated each apply/boot; a torn file is
	// unacceptable (would mis-name a RETH member) but a power-cut loss
	// self-heals next apply.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		slog.Warn("failed to fix RETH .link file", "path", path, "err", err)
	}
}

// ensureRethLinkOriginalName checks that a RETH member's .link file uses
// OriginalName= (PCI kernel name) instead of MACAddress=. If the file still
// uses MACAddress=, it derives the kernel name and rewrites the file. This
// handles bootstrap .link files that were created before the daemon ran.
func ensureRethLinkOriginalName(ifName string) {
	path := fmt.Sprintf("/etc/systemd/network/10-xpf-%s.link", ifName)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	if !strings.Contains(content, "MACAddress=") {
		return // already uses OriginalName= or other match
	}
	// Derive the kernel name. deriveKernelName consults the SAME altnames this
	// used to walk inline, in systemd's NamePolicy order, and falls back to the
	// sysfs PCI derivation — so the two paths cannot disagree about what a
	// NIC's pre-rename name is. A divergence between them would always be a
	// bug, which is why this is one implementation rather than two kept in
	// agreement.
	kernelName := deriveKernelName(ifName)
	if kernelName == "" {
		return
	}
	slog.Info("fixing RETH .link file to use OriginalName",
		"iface", ifName, "kernelName", kernelName)
	fixRethLinkFile(ifName, kernelName)
}

// altNameCandidatesFn returns an interface's kernel ALTERNATIVE names. It is a
// seam so tests can supply a device's real altname set without netlink.
var altNameCandidatesFn = func(ifName string) []string {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil
	}
	return link.Attrs().AltNames
}

// altNamePrefixOrder is systemd's default NamePolicy order, restricted to the
// prefixes a predictable name can carry: onboard (eno), hotplug slot (ens),
// then PCI path (enp). See 99-default.link's
// "NamePolicy=keep kernel database onboard slot path".
//
// The order matters: a device commonly carries SEVERAL candidate altnames
// (measured on a real host, ix0 carries eno5np0, enp183s0f0np0 and
// enx3cecef6aa8bc at once), and the one udev actually assigns is the first
// its policy resolves — onboard before path. Picking the first altname the
// kernel happens to list would be a coin flip between them.
//
// "eth" is kept as a LAST resort only. It is the pre-predictable-naming kernel
// default rather than a policy output, so it must never outrank a real
// predictable name — but ensureRethLinkOriginalName accepted it before this
// change, and dropping it would silently alter which name a RETH member
// records. Ordering it last preserves that behaviour without letting it win
// over eno/ens/enp.
//
// A MAC-based name (enx…) is deliberately NOT accepted: it is last in the
// default policy and is not a name udev assigns unless the others are
// unavailable.
// #7426: an ALIAS of the shared order, not a second copy. Keeping a
// separate literal here would leave derive_kernel_name_6677_test.go
// pinning a variable production no longer reads — a test that still
// passes while guarding nothing.
var altNamePrefixOrder = netname.NamePolicyPrefixOrder

// kernelNameFromAltNames returns the predictable name udev would assign, taken
// from the interface's kernel alternative names (#6677).
//
// This is the AUTHORITATIVE source and is preferred over re-deriving a name
// from the PCI address, because the kernel and udev have already computed
// every candidate and kept them as altnames. Re-deriving cannot match it:
// systemd's naming has at least three inputs a PCI address string does not
// carry, all of them measured on real hardware —
//
//   - ARI: with ari_enabled the slot and function fields are ONE 8-bit
//     function number (net_id does "func += slot * 8"), which a helper reading
//     the address alone cannot know;
//   - SR-IOV: a virtual function is named from its PHYSICAL function's address
//     plus the VF index, so the VF's own slot/function never appears — a VF at
//     0000:b7:02.0 is named enp183s0f0v0, from its physfn at 0000:b7:00.0;
//   - the port suffix: a multi-port NIC carries npN (enp183s0f0np0), which
//     comes from device properties the address does not contain.
//
// Altnames are stable across renames — they are the candidate set, not the
// current name — so this stays correct after xpf has renamed the interface to
// its logical name, which is exactly when the pre-rename name must be
// recovered. ensureRethLinkOriginalName has used the same mechanism in
// production since before this change.
func kernelNameFromAltNames(ifName string) string {
	// #7426: the NamePolicy ordering lives in pkg/netname, shared with the
	// dataplane compile path, which previously took whichever altname the
	// kernel listed first.
	return netname.FromAltNames(altNameCandidatesFn(ifName))
}

// deriveKernelName returns the predictable kernel name (e.g. enp8s0) for an
// interface.
//
// It asks the kernel first (kernelNameFromAltNames) and only falls back to
// deriving a name from the sysfs PCI address when no altname is available —
// early boot before udev has settled, or a container. The fallback is
// best-effort by construction: it reproduces the plain domain/bus/slot/function
// spelling and is blind to ARI, SR-IOV VF parentage and the port suffix (see
// kernelNameFromAltNames). #7415 records the one of those three that could not
// be reproduced on available hardware and names the device that would settle
// it; the other two are what motivated preferring the kernel's answer.
func deriveKernelName(ifName string) string {
	if name := kernelNameFromAltNames(ifName); name != "" {
		return name
	}
	devPath, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/class/net/%s/device", ifName))
	if err != nil {
		return ""
	}
	pciAddr := pciAddrFromPath(devPath)
	if pciAddr == "" {
		// Virtio: device is virtioN, parent directory is the PCI device
		parent := filepath.Dir(devPath)
		pciAddr = pciAddrFromPath(parent)
	}
	if pciAddr == "" {
		return ""
	}
	return pciAddrToEnp(pciAddr)
}

// pciAddrFromPath extracts a PCI address (domain:bus:slot.fn) from a sysfs
// path basename. Returns "" if the basename is not a PCI address.
func pciAddrFromPath(path string) string {
	base := filepath.Base(path)
	// PCI addresses look like "0000:08:00.0"
	parts := strings.SplitN(base, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	// Validate slot.fn exists
	if !strings.Contains(parts[2], ".") {
		return ""
	}
	return base
}

// pciAddrToEnp converts a PCI address like "0000:08:00.0" to a predictable
// network name like "enp8s0".
//
// The result must match the kernel's systemd-predictable interface name so it
// can be compared against the live NIC (deriveKernelName feeds it into the
// RETH-member OriginalName= lookup). systemd's ID_NET_NAME_PATH scheme
// (systemd.net-naming-scheme(7)) is en[P<domain>]p<bus>s<slot>[f<func>]: the
// "P<domain>" segment is prepended ONLY when the PCI domain is non-zero. For
// the common single-domain case (domain 0000) the domain is omitted, so the
// name is the bare enp<bus>s<slot>[f<func>]. On multi-PCI-domain hardware
// (domain != 0, e.g. 10000:01:00.0) the domain disambiguates two NICs that sit
// at the same bus/slot in different domains; dropping it here would collide
// them onto one name and resolve the wrong RETH member. systemd scans the
// sysfs address fields as hex and prints them decimal, so parse hex / render
// decimal for every component (domain, bus, slot, func) to match.
func pciAddrToEnp(pciAddr string) string {
	// #7426: single-sourced onto pkg/netname, shared with the dataplane
	// compile path. This copy had the domain segment and the hex function
	// parse but tested `fn > 0`, so it NEVER emitted the `f0` suffix — an
	// UNDER-emission bug, the mirror image of the OVER-emission #4795 fixed in
	// the dataplane copy. Measured on the ARI development host: 0000:b7:00.0
	// is multifunction (PCI_HEADER_TYPE 0x80) and its real ID_NET_NAME_PATH is
	// enp183s0f0np0, while this derivation produced enp183s0.
	//
	// `OriginalName=` is the only stable match for a RETH member — its MAC
	// alternates between physical at boot and virtual once the daemon programs
	// the RETH virtual MAC — so a wrong name here is not self-correcting at the
	// next boot.
	return netname.FromPCIAddr(pciAddr, netname.Multifunction(pciAddr))
}

// rethLinkOps groups the netlink primitives that renameRethMember and
// programRethMAC use. It exists as a seam so tests can inject a fake and
// assert the RETH member's final admin link state (#3920). The zero value is
// unusable; use rethLinkOpsFn, which is wired to the real netlink calls.
type rethLinkOps struct {
	interfaces      func() ([]net.Interface, error)
	byName          func(string) (netlink.Link, error)
	byIndex         func(int) (netlink.Link, error)
	setDown         func(netlink.Link) error
	setUp           func(netlink.Link) error
	setName         func(netlink.Link, string) error
	setHardwareAddr func(netlink.Link, net.HardwareAddr) error
}

// rethLinkOpsFn is the live wiring; tests save/restore and override it.
var rethLinkOpsFn = rethLinkOps{
	interfaces:      net.Interfaces,
	byName:          netlink.LinkByName,
	byIndex:         netlink.LinkByIndex,
	setDown:         netlink.LinkSetDown,
	setUp:           netlink.LinkSetUp,
	setName:         netlink.LinkSetName,
	setHardwareAddr: netlink.LinkSetHardwareAddr,
}

// renameRethMember finds an interface by its RETH virtual MAC and renames it
// to the expected config name. Returns the old kernel name if renamed, or "".
//
// The interface must be DOWN for the rename to succeed, so renameRethMember
// brings it down for the rename and then back UP — the function that downs a
// link owns bringing it back up. It does NOT rely on the caller's subsequent
// programRethMAC for the UP: programRethMAC early-returns (no UP) when the
// virtual MAC already matches, and that is exactly the case here — the
// interface was found by matching that same virtual MAC, so programRethMAC
// always no-ops on the just-renamed member. Without this UP the RETH data link
// would be left administratively DOWN → the interface track detects link-down
// → the redundancy group demotes → traffic blackhole (#3920).
func renameRethMember(targetName string, expectedMAC net.HardwareAddr, beforeCycle func() error) string {
	ops := rethLinkOpsFn
	ifaces, err := ops.interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if !bytes.Equal(iface.HardwareAddr, expectedMAC) || iface.Name == targetName {
			continue
		}
		link, err := ops.byIndex(iface.Index)
		if err != nil {
			return ""
		}
		// #6911: the worker join belongs HERE — after a rename candidate is
		// confirmed (so the hook cannot fire on a scan that cycles nothing) and
		// strictly BEFORE setDown, the first mutation of the link. This mirrors
		// programRethMAC's #5103 contract: worker threads live across the link
		// DOWN, touching UMEM pages the NIC unmaps as it tears down its queues.
		//
		// The hazard is LATENT today, not live: renameRethMember runs only when
		// LinkByName(targetName) already failed, it matches by the VIRTUAL MAC,
		// and the dataplane cannot have resolved a binding to a name that did
		// not exist — so there are no live bindings to tear down. That chain
		// rests on three properties of unrelated code, none of them asserted.
		// The hook makes the two cycle sites symmetric so a future change to
		// any of them fails loudly here instead of silently reopening #5103.
		if beforeCycle != nil {
			if err := beforeCycle(); err != nil {
				slog.Warn("skipping RETH member rename: worker join failed",
					"from", iface.Name, "to", targetName, "err", err)
				// Abort WITHOUT touching the link — the caller's workers are in
				// an unknown state and a cycle now is exactly the #5103 hazard.
				return ""
			}
		}
		// Ensure interface is DOWN for rename.
		ops.setDown(link)
		if err := ops.setName(link, targetName); err != nil {
			slog.Warn("failed to rename RETH member",
				"from", iface.Name, "to", targetName, "err", err)
			// We downed the link above; a failed rename must not strand
			// the member DOWN. Best-effort restore admin UP.
			ops.setUp(link)
			return ""
		}
		// Bring the member back UP after the rename. renameRethMember downed
		// it, so renameRethMember owns the UP — do not depend on
		// programRethMAC, which no-ops (no UP) when the MAC already matches
		// (#3920).
		if err := ops.setUp(link); err != nil {
			slog.Warn("failed to bring RETH member up after rename",
				"iface", targetName, "err", err)
		}
		return iface.Name
	}
	return ""
}

// programRethMAC sets a deterministic virtual MAC on a RETH member interface.
// Skips if the interface already has the correct MAC.
// The interface must be brought DOWN to change its MAC, then back UP.
//
// beforeCycle (#5103) is invoked at most once, on the ONLY path that cycles the
// link, and strictly BEFORE the first mutation of that link. It exists because
// whether a cycle is needed cannot be predicted: the live set is ATTEMPTED
// first, and the fallback runs on its failure.
//
// #6871: that failure does NOT prove the driver lacks IFF_LIVE_ADDR_CHANGE, and
// an earlier revision of this comment said it did. The branch below is taken on
// EVERY error from setHardwareAddr, and Linux's dev_set_mac_address path does
// not consult that flag at all — it fails for a missing ndo_set_mac_address, a
// wrong sa_family, an absent or busy device, or a driver/notifier rejection just
// the same. So the fallback is "a live set was refused, for whatever reason, and
// a cycle is the remaining option", which is why it is worth the cost only on the
// drivers that actually need it. The distinction matters here: a cycle entered
// for a transient reason still joins the workers and still drops forwarding.
//
// A rejected live set does not change link state — the kernel refuses the address
// change outright — so at the moment beforeCycle runs the link is still exactly
// as it was found, and returning an error from it aborts with nothing to undo.
//
// The caller uses this to join the AF_XDP workers. Previously the join happened
// AFTER programRethMAC returned linkCycled=true, so the workers were still
// running through the DOWN/UP and could touch UMEM while the NIC unmapped its
// pages. A nil beforeCycle means "no join needed" and is used by callers with
// no dataplane attached.
//
// On a beforeCycle error programRethMAC returns (false, err) WITHOUT touching
// the link: leaving the member on its old MAC is recoverable, cycling the link
// out from under live workers is not.
func programRethMAC(ifName string, mac net.HardwareAddr, beforeCycle func() error) (linkCycled bool, err error) {
	ops := rethLinkOpsFn
	link, err := ops.byName(ifName)
	if err != nil {
		return false, fmt.Errorf("interface %s: %w", ifName, err)
	}
	current := link.Attrs().HardwareAddr
	if bytes.Equal(current, mac) {
		return false, nil
	}
	slog.Info("setting RETH virtual MAC", "iface", ifName, "mac", mac)
	// Try setting MAC while link is UP (avoids link DOWN/UP cycle).
	// mlx5 zero-copy AF_XDP sockets break on link cycle — the driver
	// doesn't reinitialize XSK WQEs after link UP. When the kernel accepts
	// the change, no cycle happens.
	//
	// #6871: IFF_LIVE_ADDR_CHANGE is a necessary condition for this to succeed
	// on an UP link, not a sufficient one, and an earlier revision of this line
	// said "if the driver supports IFF_LIVE_ADDR_CHANGE, this succeeds". A busy
	// device is refused whether or not it carries the flag — which is why the
	// fallback below reports the actual error instead of naming a capability.
	liveSetErr := ops.setHardwareAddr(link, mac)
	if liveSetErr == nil {
		slog.Info("RETH MAC set without link cycle", "iface", ifName)
		return false, nil
	}
	// Fallback: bring link down, set MAC, bring back up.
	//
	// Say only what the failure proves. This branch is taken on EVERY error from
	// setHardwareAddr, and a refused live set does NOT establish that the driver
	// lacks IFF_LIVE_ADDR_CHANGE — dev_set_mac_address fails identically for a
	// missing ndo_set_mac_address, a wrong sa_family, an absent or busy device,
	// or a notifier rejection (see the beforeCycle contract above, which this
	// line used to contradict: it says exactly this, forty lines up, while the
	// log claimed the opposite). The remaining option is the same either way,
	// but the journal must not assert a driver capability it did not observe —
	// and it is the only place the actual reason survives, since the fallback
	// swallows it. So carry the error instead of guessing at its cause.
	slog.Info("RETH MAC live set refused; falling back to a link cycle",
		"iface", ifName, "err", liveSetErr)
	// #5103: the worker join belongs HERE — after the live-set attempt has
	// proven a cycle is unavoidable, and before setDown, the first mutation.
	// The barrier must precede the NIC queue/link teardown so no thread or DMA
	// path is using the UMEM/rings the driver is about to unmap.
	if beforeCycle != nil {
		if err := beforeCycle(); err != nil {
			return false, fmt.Errorf("prepare link cycle %s: %w", ifName, err)
		}
	}
	if err := ops.setDown(link); err != nil {
		return false, fmt.Errorf("link down %s: %w", ifName, err)
	}
	if err := ops.setHardwareAddr(link, mac); err != nil {
		ops.setUp(link) // best-effort restore
		// #6915: linkCycled reports whether the link WENT DOWN AND BACK UP, not
		// whether the MAC write succeeded. setDown returned nil on the line
		// above, so it did — and a DOWN flushes every kernel address on the
		// interface, including the VRRP VIPs and the stable RETH link-local.
		// Returning false here told step 2.6b (the VIP reconcile, gated on this
		// through needLinkCycleRecovery) that no cycle had happened, so the
		// addresses the cycle had just removed were never re-added: the member
		// came back UP holding the VRRP role and none of the addresses that role
		// answers for.
		//
		// The two post-setDown failures now agree. The link-up failure below has
		// always returned true for the same reason, so false here was the
		// outlier rather than a contract — the value differed on the two sides
		// of one `if` for outcomes that are identical in the only respect this
		// return describes.
		return true, fmt.Errorf("set mac %s: %w", ifName, err)
	}
	if err := ops.setUp(link); err != nil {
		return true, fmt.Errorf("link up %s: %w", ifName, err)
	}
	return true, nil
}

// clearDadFailed removes any dadfailed IPv6 addresses and re-adds them with
// IFA_F_NODAD so they become usable. It repairs global and link-local
// addresses on RETH members and VLAN children after a link cycle.
func clearDadFailed(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	repaired := 0
	for _, addr := range addrs {
		if addr.Flags&unix.IFA_F_DADFAILED == 0 {
			continue
		}
		if err := netlink.AddrDel(link, &addr); err != nil {
			slog.Warn("failed to remove dadfailed IPv6 address", "iface", ifName, "addr", addr.IP, "err", err)
			continue
		}
		addr.Flags = unix.IFA_F_NODAD
		if err := netlink.AddrAdd(link, &addr); err != nil {
			slog.Warn("failed to re-add dadfailed IPv6 address with NODAD", "iface", ifName, "addr", addr.IP, "err", err)
			continue
		}
		repaired++
	}
	if repaired > 0 {
		slog.Warn("repaired dadfailed IPv6 addresses", "iface", ifName, "dadfailed_count", repaired)
	}
}

// removeAutoLinkLocal removes the kernel auto-generated link-local IPv6 address
// from a RETH member interface. With addr_gen_mode=1 set, no new link-local will
// be created on link-up, but a stale one may remain from before the sysctl change.
func removeAutoLinkLocal(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			// Preserve stable router link-locals managed by addStableRethLinkLocal.
			if cluster.IsStableRethLinkLocal(addr.IP) {
				continue
			}
			if err := netlink.AddrDel(link, &addr); err == nil {
				slog.Info("removed auto link-local from RETH member", "iface", ifName, "addr", addr.IP)
			}
		}
	}
}

// ensureRethLinkLocal adds a link-local IPv6 address to a RETH member
// interface (or its VLAN sub-interface) if one is missing. RETH interfaces
// have addr_gen_mode=1 to suppress MLDv2 noise, but the kernel needs a
// link-local source address for NDP Neighbor Solicitations when forwarding
// IPv6 traffic to on-link destinations. Without this, bpf_fib_lookup returns
// NO_NEIGH and the kernel can never resolve the neighbor.
//
// Computes EUI-64 link-local from the interface MAC and adds it with NODAD.
func ensureRethLinkLocal(ifName string) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	mac := link.Attrs().HardwareAddr
	if len(mac) != 6 {
		return
	}
	// Check if link-local already exists.
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return
	}
	for _, a := range addrs {
		if a.IP.IsLinkLocalUnicast() {
			return // already have one
		}
	}

	// Compute EUI-64 link-local from MAC.
	ll := net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(64, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		slog.Warn("failed to add link-local to RETH interface",
			"iface", ifName, "addr", ll, "err", err)
	} else {
		slog.Info("added link-local for NDP on RETH interface",
			"iface", ifName, "addr", ll)
	}
}

// rethUnitHasConfiguredLinkLocal checks whether the RETH config has an
// explicitly configured link-local IPv6 address (fe80::/10) on the given unit.
func rethUnitHasConfiguredLinkLocal(rethCfg *config.InterfaceConfig, unitNum int) bool {
	unit, ok := rethCfg.Units[unitNum]
	if !ok {
		return false
	}
	for _, addr := range unit.Addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && ip.To4() == nil {
			return true
		}
	}
	return false
}

// rethUnitHasIPv6 checks whether the RETH config has IPv6 addresses on the
// given logical unit number. Unit 0 is the native/untagged interface. The
// argument is a UNIT number, not a vlan-id — callers that start from a kernel
// VLAN sub-interface suffix must translate the vlan-id to a unit with
// rethUnitForVlanID first (#5107).
func rethUnitHasIPv6(rethCfg *config.InterfaceConfig, unitNum int) bool {
	unit, ok := rethCfg.Units[unitNum]
	if !ok {
		return false
	}
	for _, addr := range unit.Addresses {
		if strings.Contains(addr, ":") {
			return true
		}
	}
	return unit.DHCPv6
}

// rethUnitForVlanID reverse-maps a kernel VLAN id to the logical unit number
// that carries it. RETH VLAN sub-interfaces are named after the unit's
// configured vlan-id (e.g. kernel "ge-7-0-1.180" for `reth1 unit 80 vlan-id
// 180`), but rethCfg.Units is keyed by the logical UNIT number (80), not the
// vlan-id (180). Callers that parse a vid out of a kernel netdev name MUST
// translate it back to the unit number before indexing Units — indexing
// Units[vid] directly silently misses whenever unit# != vlan-id (#5107).
//
// Returns (unit, true) for the unit whose VlanID == vid. Only units with a
// matching non-zero VlanID are considered: an untagged unit has no kernel
// VLAN sub-interface and is repaired on the parent netdev, not this path. If
// two units share a vlan-id (an invalid config Junos rejects), the lowest
// unit number wins deterministically and the collision is logged.
func rethUnitForVlanID(rethCfg *config.InterfaceConfig, vid int) (int, bool) {
	found := -1
	matches := 0
	for unitNum, unit := range rethCfg.Units {
		// Skip untagged units (VlanID 0): they have no VLAN sub-interface,
		// so a vlan-id parsed from a kernel netdev suffix never maps to them.
		if unit == nil || unit.VlanID <= 0 || unit.VlanID != vid {
			continue
		}
		matches++
		if found < 0 || unitNum < found {
			found = unitNum
		}
	}
	if found < 0 {
		return 0, false
	}
	if matches > 1 {
		slog.Warn("reth: multiple units share a vlan-id; using lowest unit for the netdev name (all matching units scanned for IPv6 link-local repair)",
			"iface", rethCfg.Name, "vlan-id", vid, "unit", found)
	}
	return found, true
}

// rethSubIfaceNeedsLinkLocal reports whether the RETH VLAN sub-interface whose
// kernel vlan-id is `vid` carries IPv6 in config and therefore needs its
// link-local re-added after a post-MAC-programming link cycle. The kernel netdev
// is keyed by vlan-id, but rethCfg.Units is keyed by logical unit number, so the
// vlan-id must be resolved back to a unit before checking for IPv6 (#5107).
//
// rethUnitForVlanID handles the existence check and logs a deterministic warning
// when several units share this vlan-id. We do NOT trust the single (lowest) unit
// it returns for the IPv6 decision: a duplicate vlan-id (an invalid config the
// compiler does not reject for uniqueness) can split addressing so a lower unit
// is IPv4-only while a higher unit carries IPv6. The one shared kernel netdev
// needs a link-local if ANY mapped unit has IPv6, so scan them all (#5107 fold).
func rethSubIfaceNeedsLinkLocal(rethCfg *config.InterfaceConfig, vid int) bool {
	if _, ok := rethUnitForVlanID(rethCfg, vid); !ok {
		return false
	}
	for unitNum, unit := range rethCfg.Units {
		if unit == nil || unit.VlanID != vid {
			continue
		}
		if rethUnitHasIPv6(rethCfg, unitNum) {
			return true
		}
	}
	return false
}

// rethSubIfaceNameNeedsLinkLocal parses the kernel vlan-id out of a RETH VLAN
// sub-interface name (e.g. "ge-7-0-1.180") and reports whether that
// sub-interface needs its IPv6 link-local re-added after a post-MAC link cycle.
// It is the smallest testable seam over the post-MAC repair decision in
// applyDataplaneAndHACore, so the production loop and its regression test share
// one code path (#5107). A name with no numeric vlan-id suffix returns false.
func rethSubIfaceNameNeedsLinkLocal(rethCfg *config.InterfaceConfig, subName string) bool {
	dotIdx := strings.LastIndex(subName, ".")
	if dotIdx < 0 {
		return false
	}
	vid, err := strconv.Atoi(subName[dotIdx+1:])
	if err != nil {
		return false
	}
	return rethSubIfaceNeedsLinkLocal(rethCfg, vid)
}

// removeAutoLinkLocalFn / ensureRethLinkLocalFn are the live wiring for the two
// netlink side-effects of rethSubIfaceLinkLocalRepair. They are package vars
// (mirroring the device_map.go seam idiom) so a test can drive the repair
// decision without real netlink and assert which sub-interface got a link-local.
var (
	removeAutoLinkLocalFn = removeAutoLinkLocal
	ensureRethLinkLocalFn = ensureRethLinkLocal
)

// rethSubIfaceLinkLocalRepair performs the per-VLAN-sub-interface link-local
// repair the post-MAC loop in applyDataplaneAndHACore runs for each child of a
// RETH member: always strip any stale kernel auto link-local, then re-add a
// stable one IF the sub-interface carries IPv6 in config (resolved vlan-id ->
// unit, #5107). Extracting the whole decision+action here keeps the netlink
// enumeration loop a trivial one-line delegation and lets a spy-driven test bind
// the parse/resolve/scan and the repair ordering without real netlink.
func rethSubIfaceLinkLocalRepair(rethCfg *config.InterfaceConfig, subName string) {
	removeAutoLinkLocalFn(subName)
	if rethSubIfaceNameNeedsLinkLocal(rethCfg, subName) {
		ensureRethLinkLocalFn(subName)
	}
}

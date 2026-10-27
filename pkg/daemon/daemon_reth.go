// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
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

// fixRethLinkFile ensures the .link file for a RETH member freshly renamed
// from kernelName uses OriginalName= (the kernel name) for matching,
// without downgrading a richer unit networkd already wrote (#17042,
// R4-Q43-01). The MAC alternates between physical and virtual, so a
// MACAddress= match breaks after virtual-MAC programming; an
// OriginalName= match is stable across reboots.
//
// It no longer renders its own stripped body or swallows the write
// error: an existing richer file is preserved field-for-field via
// preserveLinkFields, a missing file is created through writeLinkFile
// (networkd.RenderLink), and every refusal or write failure returns an
// error the apply caller joins into Phase.Networkd (the old Warn-only
// policy hid a failed write from the commit result — #2987 class). A
// refusal (unsafe/glob/negated kernelName, mismatched [Link] Name=)
// likewise returns an error and writes nothing.
func fixRethLinkFile(ifName, kernelName string) error {
	path := filepath.Join(linkDir, linkPrefix+ifName+".link")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			_, werr := writeLinkFile(ifName, kernelName)
			if werr != nil {
				return fmt.Errorf("write RETH .link for %s: %w", ifName, werr)
			}
			return nil
		}
		return fmt.Errorf("read RETH .link %s: %w", path, err)
	}
	if !strings.Contains(string(data), "MACAddress=") {
		return nil // already OriginalName= or other match; never downgrade
	}
	return rewriteLinkOriginalName(path, ifName, kernelName)
}

// rewriteLinkOriginalName rewrites a MAC-form .link at path to
// OriginalName=kernelName, preserving the richer fields networkd
// rendered (MTU/speed/duplex/description) so the rewrite never strips
// them (#17042).
func rewriteLinkOriginalName(path, ifName, kernelName string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read .link %s: %w", path, err)
	}
	content, err := preserveLinkFields(string(data), kernelName)
	if err != nil {
		return err
	}
	if content == string(data) {
		return nil
	}
	if err := validatePreservedLink(content, ifName, kernelName); err != nil {
		return err
	}
	// AtomicGeneratedConfig: regenerated each apply/boot; a torn file is
	// unacceptable (would mis-name a RETH member) but a power-cut loss
	// self-heals next apply.
	if err := fsatomic.WriteFileAtomic(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write RETH .link %s: %w", path, err)
	}
	return nil
}

// preserveLinkFields returns content with its [Match] MACAddress= line
// replaced by OriginalName=kernelName, preserving every other line
// byte-for-byte. A file with no MACAddress= line is returned unchanged.
func preserveLinkFields(content, kernelName string) (string, error) {
	if !rendersafe.SafeInterfaceName(kernelName) {
		return "", fmt.Errorf("refusing unsafe RETH OriginalName %q: it is not exactly one [Match] OriginalName= pattern (#9886/#10718)", kernelName)
	}
	if glob := rendersafe.FirstGlobMetacharacter(kernelName); glob != "" {
		return "", fmt.Errorf("refusing glob RETH OriginalName %q: glob metacharacter %q in [Match] OriginalName= (#10089)", kernelName, glob)
	}
	if rendersafe.IsNegatedMatchPattern(kernelName) {
		return "", fmt.Errorf("refusing negated RETH OriginalName %q: a leading '!' in [Match] OriginalName= inverts the match list (#15079)", kernelName)
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "MACAddress=") {
			lines[i] = "OriginalName=" + kernelName
			return strings.Join(lines, "\n"), nil
		}
	}
	return content, nil
}

// validatePreservedLink checks the rewritten content stays well-formed:
// the [Link] Name= (when present) still names ifName and the match now
// carries OriginalName=kernelName.
func validatePreservedLink(content, ifName, kernelName string) error {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name=") {
			if got := strings.TrimSpace(strings.TrimPrefix(line, "Name=")); got != ifName {
				return fmt.Errorf("refusing RETH .link rewrite for %q: existing [Link] Name=%q does not match", ifName, got)
			}
		}
	}
	if !strings.Contains(content, "OriginalName="+kernelName) {
		return fmt.Errorf("refusing RETH .link rewrite for %q: rewritten content lacks OriginalName=%s", ifName, kernelName)
	}
	return nil
}

// ensureRethLinkOriginalName checks that a RETH member's .link file uses
// OriginalName= (PCI kernel name) instead of MACAddress=. If the file
// still uses MACAddress=, it derives the kernel name and rewrites the
// file, preserving networkd's richer fields. This handles bootstrap
// .link files that were created before the daemon ran. It reads through
// the linkDir seam (the old copy hard-coded /etc/systemd/network) and
// returns any rewrite failure so it joins Phase.Networkd (#17042).
func ensureRethLinkOriginalName(ifName string) error {
	path := filepath.Join(linkDir, linkPrefix+ifName+".link")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // missing/unreadable: networkd owns the file; nothing to fix
	}
	if !strings.Contains(string(data), "MACAddress=") {
		return nil // already uses OriginalName= or other match
	}
	// Derive the kernel name. deriveKernelName consults the SAME altnames
	// this used to walk inline, in systemd's NamePolicy order, and falls
	// back to the sysfs PCI derivation — so the two paths cannot disagree
	// about what a NIC's pre-rename name is.
	kernelName := deriveKernelNameFn(ifName)
	if kernelName == "" {
		return nil
	}
	slog.Info("fixing RETH .link file to use OriginalName",
		"iface", ifName, "kernelName", kernelName)
	return rewriteLinkOriginalName(path, ifName, kernelName)
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

// formerRethMembers returns the sorted Linux names that were RETH members in
// prev but are not RETH members in the current set (#16860).
func formerRethMembers(prev, current map[string]struct{}) []string {
	var former []string
	for name := range prev {
		if _, ok := current[name]; !ok {
			former = append(former, name)
		}
	}
	sort.Strings(former)
	return former
}

// restoreFormerRethMemberMAC returns a former RETH member to its permanent
// hardware address, propagating to VLAN children, via programRethMAC so the
// worker-join/link-cycle discipline is identical to virtual-MAC programming
// (programRethMACWithWorkerJoin remains the sole wrapper call site, #5103).
// It returns (cycled, leaseKept, commitErr): leaseKept mirrors
// programRethMemberMAC's accumulator — an aborted restore's rollback rebound
// without releasing, so the caller must arm the end-of-apply release. A
// missing link or permanent MAC is an error, not a successful no-op: the
// previous-member record must remain pending until restoration can complete.
//
// The join hook mirrors programRethMACWithWorkerJoin's: it records that it
// ran, and on a post-join failure rebinds with NotifyLinkCycleKeepingLease
// and classifies the error as errRethPrepareLinkCycle, rather than leaving a
// half-applied prepare under a green commit.
func (d *Daemon) restoreFormerRethMemberMAC(linuxName string) (bool, bool, error) {
	link, err := rethLinkOpsFn.byName(linuxName)
	if err != nil {
		return false, false, fmt.Errorf("former RETH member %s: find link for permanent MAC restore: %w", linuxName, err)
	}
	perm := link.Attrs().PermHWAddr
	if len(perm) == 0 {
		return false, false, fmt.Errorf("former RETH member %s has no permanent MAC to restore", linuxName)
	}
	perm = append(net.HardwareAddr(nil), perm...)
	if bytes.Equal(link.Attrs().HardwareAddr, perm) {
		return false, false, nil
	}
	slog.Info("restoring permanent MAC on former RETH member",
		"iface", linuxName, "mac", perm)
	joinRan := false
	var notifyKeepingLease func() error
	beforeCycle := func() error {
		rt := d.dataplane()
		if rt == nil {
			return nil
		}
		notifyKeepingLease = func() error {
			return rt.Link().NotifyLinkCycleKeepingLease()
		}
		joinRan = true
		slog.Info("userspace: stopping workers before former RETH member MAC restore", "iface", linuxName)
		return rt.Link().PrepareLinkCycle()
	}
	cycled, _, macErr := programRethMAC(linuxName, perm, beforeCycle)
	// Propagate to VLAN children even on a partial cycle, mirroring
	// finishRethMemberLinkTail: children keep the stale virtual MAC otherwise.
	d.propagateMACToVLANChildren(linuxName, perm)
	d.renewLinkCycleLease()
	if macErr == nil {
		return cycled, false, nil
	}
	if !joinRan {
		return cycled, false, fmt.Errorf("restore permanent MAC on former RETH member %s: %w", linuxName, macErr)
	}
	if cycled {
		return cycled, false, fmt.Errorf("%w: %w", errRethPrepareLinkCycle, macErr)
	}
	if rebindErr := notifyKeepingLease(); rebindErr != nil {
		return cycled, true, fmt.Errorf("%w: %w", errRethPrepareLinkCycle, errors.Join(macErr, rebindErr))
	}
	return cycled, true, fmt.Errorf("%w: %w", errRethPrepareLinkCycle, macErr)
}

// propagateMACToVLANChildren sets mac on every VLAN child of parent. Shared by
// the former-member restore; the current-member tail keeps its inline loop
// (it also repairs link-locals per child).
func (d *Daemon) propagateMACToVLANChildren(parent string, mac net.HardwareAddr) {
	parentLink, err := rethParentLinkByName(parent)
	if err != nil {
		return
	}
	links, err := rethLinkLister()
	if err != nil {
		slog.Warn("failed to enumerate links for former RETH member VLAN MAC restore",
			"parent", parent, "err", err)
		return
	}
	for _, l := range links {
		if l.Attrs().ParentIndex != parentLink.Attrs().Index {
			continue
		}
		if bytes.Equal(l.Attrs().HardwareAddr, mac) {
			continue
		}
		if err := netlink.LinkSetHardwareAddr(l, mac); err != nil {
			slog.Warn("failed to restore MAC on VLAN sub-interface of former RETH member",
				"iface", l.Attrs().Name, "err", err)
		}
	}
}

// renameRethMember finds a RETH member by its indexed virtual MAC, with the
// original shared-MAC value as a migration fallback, then renames it to the
// expected config name. Interfaces already wearing any configured RETH member
// name are excluded so an old shared MAC cannot select a healthy sibling.
// Ambiguous matches are refused rather than depending on interface order.
//
// Returns the old kernel name, whether the link was cycled, and any operation
// error. The caller owns dataplane recovery after a successful/partial cycle.
func renameRethMember(targetName string, expectedMAC, legacyMAC net.HardwareAddr,
	configuredMemberNames map[string]struct{}, beforeCycle func() error) (string, bool, error) {
	ops := rethLinkOpsFn
	ifaces, err := ops.interfaces()
	if err != nil {
		return "", false, fmt.Errorf("list interfaces for RETH member recovery: %w", err)
	}

	candidateIndex := -1
	matches := 0
	for i := range ifaces {
		if ifaces[i].Name == targetName {
			continue
		}
		if _, configured := configuredMemberNames[ifaces[i].Name]; configured {
			continue
		}
		if bytes.Equal(ifaces[i].HardwareAddr, expectedMAC) {
			candidateIndex = i
			matches++
		}
	}
	if matches > 1 {
		slog.Warn("skipping ambiguous RETH member recovery",
			"to", targetName, "mac", expectedMAC, "matches", matches)
		return "", false, nil
	}
	if matches == 0 && !bytes.Equal(expectedMAC, legacyMAC) {
		for i := range ifaces {
			if ifaces[i].Name == targetName {
				continue
			}
			if _, configured := configuredMemberNames[ifaces[i].Name]; configured {
				continue
			}
			if bytes.Equal(ifaces[i].HardwareAddr, legacyMAC) {
				candidateIndex = i
				matches++
			}
		}
		if matches > 1 {
			slog.Warn("skipping ambiguous legacy-MAC RETH member recovery",
				"to", targetName, "mac", legacyMAC, "matches", matches)
			return "", false, nil
		}
	}
	if candidateIndex < 0 {
		return "", false, nil
	}
	iface := ifaces[candidateIndex]
	link, err := ops.byIndex(iface.Index)
	if err != nil {
		return "", false, fmt.Errorf("find RETH recovery candidate %s: %w", iface.Name, err)
	}
	// #6911: the worker join belongs HERE — after a rename candidate is
	// confirmed (so the hook cannot fire on a scan that cycles nothing) and
	// strictly BEFORE setDown, the first mutation of the link. This mirrors
	// programRethMAC's #5103 contract.
	if beforeCycle != nil {
		if err := beforeCycle(); err != nil {
			slog.Warn("skipping RETH member rename: worker join failed",
				"from", iface.Name, "to", targetName, "err", err)
			return "", false, fmt.Errorf("prepare RETH member rename %s: %w", iface.Name, err)
		}
	}
	if err := ops.setDown(link); err != nil {
		return "", false, fmt.Errorf("bring RETH recovery candidate %s down: %w", iface.Name, err)
	}
	if err := ops.setName(link, targetName); err != nil {
		slog.Warn("failed to rename RETH member",
			"from", iface.Name, "to", targetName, "err", err)
		// We downed the link above; a failed rename must not strand it DOWN.
		if upErr := ops.setUp(link); upErr != nil {
			err = errors.Join(err, fmt.Errorf("restore link up: %w", upErr))
		}
		return "", true, fmt.Errorf("rename RETH member %s to %s: %w", iface.Name, targetName, err)
	}
	// Bring the member back UP after the rename. renameRethMember downed
	// it, so renameRethMember owns the UP — do not depend on
	// programRethMAC, which no-ops (no UP) when the MAC already matches
	// (#3920).
	if err := ops.setUp(link); err != nil {
		slog.Warn("failed to bring RETH member up after rename",
			"iface", targetName, "err", err)
		return iface.Name, true, fmt.Errorf("bring renamed RETH member %s up: %w", targetName, err)
	}
	return iface.Name, true, nil
}

// programRethMAC sets a deterministic virtual MAC on a RETH member interface.
// Skips if the interface already has the correct MAC.
// The interface must be brought DOWN to change its MAC, then back UP.
//
// It reports two facts separately (#15276): linkCycled — the link went DOWN
// and back UP, flushing every kernel address on the member — and macChanged
// — the member's MAC actually changed, whether the live set succeeded or a
// cycle was needed. They differ on the live-set path: the MAC changed but no
// address was flushed, so no VIP/link-local reconcile or AF_XDP rebind is
// owed, yet neighbours still hold the old MAC and step 2.6b must announce.
// macChanged is true only where the target MAC was written (live set
// succeeded, or the cycled set succeeded — including when the following
// link-up failed). A failed MAC write leaves macChanged false.
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
// On a beforeCycle error programRethMAC returns (false, false, err) WITHOUT
// touching the link: leaving the member on its old MAC is recoverable, cycling
// the link out from under live workers is not.
func programRethMAC(ifName string, mac net.HardwareAddr, beforeCycle func() error) (linkCycled bool, macChanged bool, err error) {
	ops := rethLinkOpsFn
	link, err := ops.byName(ifName)
	if err != nil {
		return false, false, fmt.Errorf("interface %s: %w", ifName, err)
	}
	current := link.Attrs().HardwareAddr
	if bytes.Equal(current, mac) {
		return false, false, nil
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
		return false, true, nil
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
			return false, false, fmt.Errorf("prepare link cycle %s: %w", ifName, err)
		}
	}
	if err := ops.setDown(link); err != nil {
		return false, false, fmt.Errorf("link down %s: %w", ifName, err)
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
		return true, false, fmt.Errorf("set mac %s: %w", ifName, err)
	}
	if err := ops.setUp(link); err != nil {
		return true, true, fmt.Errorf("link up %s: %w", ifName, err)
	}
	return true, true, nil
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

// rethLinkAddrsFn / rethLinkAddrDelFn / rethLinkAddrAddFn are the netlink
// side-effect seams for the RETH link-local repair. They are package vars so
// a test can drive removeAutoLinkLocalExcluding / ensureRethLinkLocalExcluding
// decision logic without a privileged netdev.
var (
	rethLinkAddrsFn = func(ifName string) (netlink.Link, []netlink.Addr, error) {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return nil, nil, err
		}
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return nil, nil, err
		}
		return link, addrs, nil
	}
	rethLinkAddrDelFn = func(link netlink.Link, addr *netlink.Addr) error {
		return netlink.AddrDel(link, addr)
	}
	rethLinkAddrAddFn = func(link netlink.Link, addr *netlink.Addr) error {
		return netlink.AddrAdd(link, addr)
	}
)

// configuredRethLinkLocalIPs returns every configured IPv6 link-local
// unicast address on the given RETH unit, in config order and de-duplicated.
// A configured fe80::/64 is the operator's router link-local (installed as
// an RG VIP on the primary), not a kernel auto address.
func configuredRethLinkLocalIPs(rethCfg *config.InterfaceConfig, unitNum int) []net.IP {
	if rethCfg == nil {
		return nil
	}
	unit, ok := rethCfg.Units[unitNum]
	if !ok || unit == nil {
		return nil
	}
	var ips []net.IP
	seen := make(map[string]bool)
	for _, addr := range unit.Addresses {
		ip, _, err := net.ParseCIDR(addr)
		if err != nil {
			continue
		}
		if ip.IsLinkLocalUnicast() && ip.To4() == nil && !seen[ip.String()] {
			seen[ip.String()] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

func ipInList(ip net.IP, list []net.IP) bool {
	for _, candidate := range list {
		if ip.Equal(candidate) {
			return true
		}
	}
	return false
}

// linkLocalShouldKeep reports whether a live link-local must survive the
// auto-link-local strip: the auto stable pattern, or any address the
// operator configured on that RETH unit (#15148).
func linkLocalShouldKeep(ip net.IP, configured []net.IP) bool {
	if cluster.IsStableRethLinkLocal(ip) {
		return true
	}
	return ipInList(ip, configured)
}

// removeAutoLinkLocalExcluding removes kernel auto-generated link-local
// IPv6 addresses from a RETH member interface, preserving the stable
// pattern and any configured addresses passed in. With addr_gen_mode=1
// set, no new link-local will be created on link-up, but a stale one may
// remain from before the sysctl change.
// Without the configured exemption, a configured fe80::1/64 was deleted
// on every apply and only re-added by the 2s direct-mode VIP reconcile,
// while a per-node EUI-64 stayed on the owner (#15148).
func removeAutoLinkLocalExcluding(ifName string, configured []net.IP) {
	link, addrs, err := rethLinkAddrsFn(ifName)
	if err != nil {
		return
	}
	for _, addr := range addrs {
		if addr.IP.IsLinkLocalUnicast() {
			if linkLocalShouldKeep(addr.IP, configured) {
				continue
			}
			addrCopy := addr
			if err := rethLinkAddrDelFn(link, &addrCopy); err == nil {
				slog.Info("removed auto link-local from RETH member", "iface", ifName, "addr", addr.IP)
			}
		}
	}
}

// ensureRethLinkLocalExcluding adds a link-local IPv6 address to a RETH
// member interface (or its VLAN sub-interface) if one is missing and no
// configured link-local replaces it. RETH interfaces have addr_gen_mode=1
// to suppress MLDv2 noise, but the kernel needs a link-local source
// address for NDP Neighbor Solicitations when forwarding IPv6 traffic to
// on-link destinations. Without this, bpf_fib_lookup returns NO_NEIGH and
// the kernel can never resolve the neighbor.
//
// When a configured link-local exists it is the link-local for the unit,
// so no per-node EUI-64 may be added (#15148).
func ensureRethLinkLocalExcluding(ifName string, configured []net.IP) {
	if len(configured) > 0 {
		return
	}
	link, addrs, err := rethLinkAddrsFn(ifName)
	if err != nil {
		return
	}
	mac := link.Attrs().HardwareAddr
	if len(mac) != 6 {
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
	if err := rethLinkAddrAddFn(link, addr); err != nil {
		slog.Warn("failed to add link-local to RETH interface",
			"iface", ifName, "addr", ll, "err", err)
	} else {
		slog.Info("added link-local for NDP on RETH interface",
			"iface", ifName, "addr", ll)
	}
}

// rethParentLinkLocalRepair strips stale auto link-locals from a RETH parent
// member, preserving configured unit-0 link-locals, and re-adds an EUI-64
// only when unit 0 has IPv6 and no configured link-local (#15148).
func rethParentLinkLocalRepair(linuxName string, rethCfg *config.InterfaceConfig) {
	configured := configuredRethLinkLocalIPs(rethCfg, 0)
	removeAutoLinkLocalFn(linuxName, configured)
	if rethUnitHasIPv6(rethCfg, 0) {
		ensureRethLinkLocalFn(linuxName, configured)
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
// netlink side-effects of the RETH link-local repairs. They are package vars
// (mirroring the device_map.go seam idiom) so a test can drive the repair
// decision without real netlink and assert which sub-interface got a link-local.
// The configured argument carries the unit's configured link-locals that
// must survive the strip and suppress the EUI-64 (#15148).
var (
	removeAutoLinkLocalFn = removeAutoLinkLocalExcluding
	ensureRethLinkLocalFn = ensureRethLinkLocalExcluding
)

// configuredRethLinkLocalIPsForVlan resolves a kernel VLAN sub-interface name
// to every configured link-local on any unit mapped to its vlan-id
// (duplicate vlan-ids scan all mapped units, mirroring
// rethSubIfaceNeedsLinkLocal). A name with no numeric vlan-id, or a vlan-id
// no unit carries, yields nil.
func configuredRethLinkLocalIPsForVlan(rethCfg *config.InterfaceConfig, subName string) []net.IP {
	if rethCfg == nil {
		return nil
	}
	dotIdx := strings.LastIndex(subName, ".")
	if dotIdx < 0 {
		return nil
	}
	vid, err := strconv.Atoi(subName[dotIdx+1:])
	if err != nil {
		return nil
	}
	if _, ok := rethUnitForVlanID(rethCfg, vid); !ok {
		return nil
	}
	var ips []net.IP
	for unitNum, unit := range rethCfg.Units {
		if unit == nil || unit.VlanID != vid {
			continue
		}
		ips = append(ips, configuredRethLinkLocalIPs(rethCfg, unitNum)...)
	}
	// De-duplicate while preserving order.
	seen := make(map[string]bool)
	out := ips[:0]
	for _, ip := range ips {
		if !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, ip)
		}
	}
	return out
}

// rethSubIfaceLinkLocalRepair performs the per-VLAN-sub-interface link-local
// repair the post-MAC loop in applyDataplaneAndHACore runs for each child of a
// RETH member: strip any stale kernel auto link-local (preserving the auto
// stable pattern and any configured link-local of the resolved unit), then
// re-add an EUI-64 IF the sub-interface carries IPv6 in config (resolved
// vlan-id -> unit, #5107) and no configured link-local replaces it (#15148).
// Extracting the whole decision+action here keeps the netlink enumeration
// loop a trivial one-line delegation and lets a spy-driven test bind the
// parse/resolve/scan and the repair ordering without real netlink.
func rethSubIfaceLinkLocalRepair(rethCfg *config.InterfaceConfig, subName string) {
	configured := configuredRethLinkLocalIPsForVlan(rethCfg, subName)
	removeAutoLinkLocalFn(subName, configured)
	if rethSubIfaceNameNeedsLinkLocal(rethCfg, subName) {
		ensureRethLinkLocalFn(subName, configured)
	}
}

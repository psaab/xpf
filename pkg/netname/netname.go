// Package netname derives the predictable network-interface name udev would
// assign to a NIC. It is the SINGLE SOURCE for that derivation (#7426).
//
// # Why single-source rather than an agreement test
//
// Two re-implementations of this contract existed — `deriveKernelName`
// (pkg/daemon) and `getOriginalKernelName` (pkg/dataplane) — and they were
// wrong in OPPOSITE directions on the same field:
//
//   - altname selection: the daemon copy applied systemd's NamePolicy order;
//     the dataplane copy took the first match in whatever order the kernel
//     listed.
//   - the PCI `f0` suffix: the dataplane copy carried #4795's multifunction fix
//     ("getOriginalKernelName appends f0 for single-function PCI" — an
//     OVER-emission bug); the daemon copy tested `fn > 0` and so never emitted
//     `f0` at all, an UNDER-emission bug on a genuine multifunction device.
//
// An agreement test can only pin one copy's behaviour to the other's. On the
// `f0` field there is no direction to pin that is correct for both, because
// neither was right — so agreement would have frozen a bug rather than caught
// one. That is the general rule this package exists to illustrate: BIND an
// agreement when both copies can be right; SINGLE-SOURCE when they are wrong in
// opposite directions.
//
// # Package placement
//
// This is a deliberate leaf with ZERO xpf imports. `pkg/daemon` imports
// `pkg/dataplane` and not the reverse, so a resolver living in `pkg/daemon`
// compiles fine right up until `pkg/dataplane` needs it. `pkg/devicemap` was
// the other candidate, but `pkg/dataplane` does not import it today and adding
// that edge is a larger commitment than a zero-import leaf.
package netname

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NamePolicyPrefixOrder is systemd's default NamePolicy order, restricted to
// the prefixes a predictable name can carry: onboard (eno), hotplug slot
// (ens), then PCI path (enp). See 99-default.link's
// "NamePolicy=keep kernel database onboard slot path".
//
// The order is load-bearing, not cosmetic. A device commonly carries SEVERAL
// candidate altnames at once — measured on the ARI host this was developed on,
// `ix0` carries `eno5np0`, `enp183s0f0np0` and `enx3cecef6aa8bc`
// simultaneously, with udev reporting ID_NET_NAME_ONBOARD=eno5np0 and
// ID_NET_NAME_PATH=enp183s0f0np0. The name udev actually assigns is the first
// its policy resolves (onboard before slot before path), so taking whichever
// altname the kernel happened to list first is a coin flip between them.
//
// "eth" is a LAST resort only: it is the pre-predictable-naming kernel default
// rather than a policy output, so it must never outrank a real predictable
// name.
var NamePolicyPrefixOrder = []string{"eno", "ens", "enp", "eth"}

// FromAltNames returns the altname udev's NamePolicy would assign, or "" when
// none of the candidates carries a predictable prefix.
func FromAltNames(alts []string) string {
	for _, want := range NamePolicyPrefixOrder {
		for _, alt := range alts {
			if strings.HasPrefix(alt, want) {
				return alt
			}
		}
	}
	return ""
}

// UdevPropertyOrder is the ID_NET_NAME_* property order matching
// NamePolicyPrefixOrder: onboard, then hotplug slot, then PCI path.
var UdevPropertyOrder = []string{"ID_NET_NAME_ONBOARD", "ID_NET_NAME_SLOT", "ID_NET_NAME_PATH"}

// FromUdevProperties returns the predictable name udev recorded for the
// interface, picking the first property in NamePolicy order that is set.
//
// This source and FromAltNames are BOTH kept because they fail in different
// conditions and each is authoritative when present: udev properties need
// `udevadm` on PATH and a process spawn per NIC, while altnames need the
// altname policy to have run.
func FromUdevProperties(props map[string]string) string {
	for _, key := range UdevPropertyOrder {
		if v := strings.TrimSpace(props[key]); v != "" {
			return v
		}
	}
	return ""
}

// FromPCIAddr derives the predictable name from a PCI address of the form
// "domain:bus:slot.function" (e.g. "0000:b7:00.0").
//
// It is BEST-EFFORT BY CONSTRUCTION and is the last resort: it reproduces the
// plain domain/bus/slot/function spelling and is blind to the port suffix
// (`np0`) and to SR-IOV VF parentage, so it can differ from the kernel's answer
// even when it is working correctly. Prefer FromAltNames / FromUdevProperties;
// this exists for early boot before udev has settled, and for containers.
//
// multifunction must report the PCI_HEADER_TYPE multi-function bit for the same
// address (see Multifunction). systemd's names_pci_slot() appends the
// "f<function>" suffix when the device is multi-function OR the function is
// non-zero — so a multifunction device DOES carry `f0`, which is why testing
// `fn > 0` alone under-emits.
func FromPCIAddr(pciAddr string, multifunction bool) string {
	parts := strings.SplitN(pciAddr, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	domain, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return ""
	}
	bus, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return ""
	}
	sf := strings.SplitN(parts[2], ".", 2)
	if len(sf) != 2 {
		return ""
	}
	slot, err := strconv.ParseUint(sf[0], 16, 16)
	if err != nil {
		return ""
	}
	// Function is parsed base 16, and THE BASE IS UNOBSERVABLE — not a
	// correctness requirement in either direction (#9458).
	//
	// The comment that stood here claimed an ARI device "can carry functions
	// above 9 (up to 255), which a base-10 parse rejects outright". That is
	// false. Linux formats the address as
	// dev_set_name(..., "%04x:%02x:%02x.%d", ..., PCI_SLOT(devfn), PCI_FUNC(devfn))
	// and PCI_FUNC(devfn) is devfn & 0x07 — bits 7:3 are the slot. So the
	// FUNCTION FIELD IS ALWAYS 0-7, on ARI hardware included, and 0-7 parse
	// identically in base 10 and base 16. Measured on the ARI development
	// host: 175 PCI devices, every final field in {0..7}. This is a
	// structural bound, not a sampling result; TestPCIFunctionFieldIsThreeBits
	// (pci_function_domain_9458_test.go) re-measures it and goes RED if it
	// ever stops holding, which is the only condition under which the base
	// would start to matter.
	//
	// ARI does NOT widen this field; it reinterprets slot and function
	// TOGETHER as one 8-bit function, which systemd reconstructs as
	// `func += slot << 3` when ari_enabled is set. That divergence is real
	// (#6677) and is why the pre-rename kernel name is now read FROM THE
	// KERNEL rather than derived arithmetically (PR #7420, 3c49cabd7) — this
	// helper stays best-effort last-resort. #6204 and its two closed PRs
	// (#6320, #6671) both tried to reach that gap by changing this parse
	// base; a base change cannot reach it.
	//
	// Do not "fix" the base, and do not treat it as protection either.
	fn, err := strconv.ParseUint(sf[1], 16, 8)
	if err != nil {
		return ""
	}

	name := "en"
	if domain > 0 {
		name += fmt.Sprintf("P%d", domain)
	}
	name += fmt.Sprintf("p%ds%d", bus, slot)
	name += FunctionSuffix(multifunction, fn)
	return name
}

// FunctionSuffix returns the "f<function>" suffix systemd's names_pci_slot()
// appends, or "" when it appends none.
//
// The multifunction half is what #4795 added and what the daemon copy lacked:
// a multi-function device carries `f0` for function 0, while a single-function
// device carries no suffix at all. Testing only `fn != 0` under-emits on the
// first port of a multifunction NIC; appending unconditionally over-emits on a
// single-function one.
func FunctionSuffix(multifunction bool, fn uint64) string {
	if fn == 0 && !multifunction {
		return ""
	}
	return fmt.Sprintf("f%d", fn)
}

// Multifunction reports whether the PCI device at pciAddr is a multi-function
// device, per the kernel's PCI_HEADER_TYPE config-space byte (offset 0x0E), bit
// 0x80. This mirrors systemd's is_pci_multifunction(), the same signal
// names_pci_slot() uses to decide whether to append "f<function>".
//
// Any read failure (missing sysfs, short read, permission) conservatively
// reports false — the same fallback systemd uses on error, after which the
// caller falls back to the "fn != 0" half of the test.
func Multifunction(pciAddr string) bool {
	const (
		headerTypeOffset = 14 // PCI_HEADER_TYPE, config-space offset 0x0E
		multiFunctionBit = 0x80
	)
	data, err := os.ReadFile(fmt.Sprintf("/sys/bus/pci/devices/%s/config", pciAddr))
	if err != nil || len(data) <= headerTypeOffset {
		return false
	}
	return data[headerTypeOffset]&multiFunctionBit != 0
}

// Resolve is the full chain for a live interface: altnames in NamePolicy order
// first, then the best-effort PCI derivation.
//
// The caller supplies the altnames because each call site already owns a seam
// for obtaining them — the dataplane compile path reads them through its
// per-compile link CACHE, and collapsing that into this package would drop the
// cache. pciAddr may be "" when the interface has no PCI parent.
func Resolve(alts []string, pciAddr string) string {
	if name := FromAltNames(alts); name != "" {
		return name
	}
	if pciAddr == "" {
		return ""
	}
	return FromPCIAddr(pciAddr, Multifunction(pciAddr))
}

// PCIAddrFromDevicePath extracts the PCI address (DDDD:BB:DD.F) from a
// sysfs device path (#17119, single-sourcing the sysfs→BDF step #7426
// left in each caller). Every caller passes the resolved `device`
// symlink target. A PCI netdev's target ends in the device's own BDF
// (possibly below PCI bridges / a root port), so that BDF names this
// device; a virtio netdev's target ends in `virtioN` directly below its
// PCI function, which is a 1:1 channel to that function, so the parent
// BDF likewise names this device. Any other final component means the
// device sits on a NON-PCI bus below the last PCI ancestor, and that
// ancestor's BDF must NOT be reported as this device's address
// (#14595): on x86 a USB NIC hangs off an xHCI controller
// (…/0000:00:14.0/usb2/2-1/2-1:1.0), and reporting the controller's BDF
// gave every NIC behind one controller one shared "PCI address".
// Returns "" for a non-PCI device.
func PCIAddrFromDevicePath(realPath string) string {
	// The length guard must admit index 10 (the '.'), so require
	// >= 11 — a bare >= 10 lets a 10-char component with ':' at 4 and
	// 7 index p[10] out of bounds.
	parts := strings.Split(realPath, "/")
	last := parts[len(parts)-1]
	if len(last) >= 11 && last[4] == ':' && last[7] == ':' && last[10] == '.' {
		return last
	}
	if isVirtioComponent(last) {
		// virtioN directly below a PCI function: report that function.
		for i := len(parts) - 2; i >= 0; i-- {
			p := parts[i]
			if len(p) >= 11 && p[4] == ':' && p[7] == ':' && p[10] == '.' {
				return p
			}
		}
	}
	return ""
}

// isVirtioComponent reports whether a sysfs path component is a virtio
// device directory (`virtio0`, `virtio12`, …).
func isVirtioComponent(p string) bool {
	if !strings.HasPrefix(p, "virtio") || len(p) == len("virtio") {
		return false
	}
	for _, c := range p[len("virtio"):] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// PCIAddrForNetdev returns the PCI address of the NIC named name, by
// resolving /sys/class/net/<name>/device and applying
// PCIAddrFromDevicePath. Returns "" when the symlink cannot be
// resolved or the device has no PCI address (see PCIAddrFromDevicePath).
func PCIAddrForNetdev(name string) string {
	devReal, err := filepath.EvalSymlinks("/sys/class/net/" + name + "/device")
	if err != nil {
		return ""
	}
	return PCIAddrFromDevicePath(devReal)
}

package config

import (
	"fmt"
	"net"
	"strings"
)

// ValidatePCIAddr accepts a PCI bus address in the canonical
// DDDD:BB:DD.F form (e.g. 0000:09:00.0), the #1956 device-map primary
// identity key. The format mirrors what extractPCIAddr produces from
// sysfs (pkg/daemon/linksetup.go) so a committed key resolves against the
// live enumeration without normalization drift. The shorter BB:DD.F form
// (no domain) is rejected: sysfs always carries the 4-digit domain, and
// accepting an ambiguous short form would silently never match.
func ValidatePCIAddr(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a PCI bus address, e.g. 0000:09:00.0)")
	}
	if !pciAddrCanonical(trimmed) {
		return fmt.Errorf("not a canonical PCI bus address (got %q; expected DDDD:BB:DD.F, "+
			"e.g. 0000:09:00.0 — copy it from `show chassis device-map candidates`)", raw)
	}
	return nil
}

// pciAddrCanonical reports whether s is exactly DDDD:BB:DD.F where each
// field is lower-case hex of the right width (domain 4, bus 2, device 2,
// function 1). sysfs uses lower-case; we require it so two spellings of
// the same address can never both be present in one map.
func pciAddrCanonical(s string) bool {
	// 0000:00:00.0 = 12 chars.
	if len(s) != 12 || s[4] != ':' || s[7] != ':' || s[10] != '.' {
		return false
	}
	isHex := func(lo, hi int) bool {
		for i := lo; i < hi; i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	return isHex(0, 4) && isHex(5, 7) && isHex(8, 10) && isHex(11, 12)
}

// ValidateMAC accepts a 6-octet MAC address in colon-separated lower- or
// upper-case hex (xx:xx:xx:xx:xx:xx), the #1956 device-map permanent-MAC
// fallback key. It is compared against PermHWAddr at resolve time, never
// the running MAC. Reject the all-zero MAC (never a real factory MAC) and
// any multicast/group address (LSB of the first octet set) — neither can
// be a NIC's permanent unicast address, so accepting one guarantees a
// non-matching key.
func ValidateMAC(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("missing value (expected a MAC address, e.g. 00:11:22:33:44:55)")
	}
	hw, err := net.ParseMAC(trimmed)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("not a valid 6-octet MAC address (got %q; expected xx:xx:xx:xx:xx:xx)", raw)
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("all-zero MAC %q is never a valid device identity", raw)
	}
	if hw[0]&0x01 != 0 {
		return fmt.Errorf("multicast/group MAC %q is never a NIC permanent address", raw)
	}
	return nil
}

// ValidateDeviceMapLogicalName accepts an xpf/vSRX logical interface name
// usable as a #1956 device-map binding target. It permits the management
// names (fxp0, em0), the vSRX revenue form ge-N/0/N (and other media
// prefixes), and bare alphanumeric forms — but rejects whitespace, unit
// suffixes (.N — the map binds the physical NIC, not a unit), and obvious
// garbage so a typo fails loud at commit rather than producing an unbound
// entry that only shows up at next boot.
func ValidateDeviceMapLogicalName(raw string) error {
	name := strings.TrimSpace(raw)
	if name == "" {
		return fmt.Errorf("missing logical interface name (e.g. ge-0/0/3 or fxp0)")
	}
	if name != raw {
		return fmt.Errorf("logical interface name %q must not have leading/trailing whitespace", raw)
	}
	if strings.ContainsAny(name, " \t") {
		return fmt.Errorf("logical interface name %q must not contain whitespace", raw)
	}
	if strings.Contains(name, ".") {
		return fmt.Errorf("device-map binds the physical interface, not a unit — %q has a unit "+
			"suffix; map %q instead", raw, name[:strings.IndexByte(name, '.')])
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '/') {
			return fmt.Errorf("invalid character %q in logical interface name %q", r, raw)
		}
	}
	return nil
}

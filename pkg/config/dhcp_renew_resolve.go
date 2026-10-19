package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ResolveDHCPRenewTarget maps an operator-supplied `request dhcp renew`
// target to the lease key the DHCP manager runs its client under
// (DHCPLeaseIfName), accepting every spelling the operator can
// legitimately type (#15227 A43-04):
//
//   - the Junos config key with an optional unit: `ge-0/0/0`,
//     `ge-0/0/3.7` (unit 7, whose vlan-id may differ from the unit
//     number — the lease key carries the vlan-id, never the unit number);
//   - the Linux form of the same: `ge-0-0-0`, `ge-0-0-3.7`;
//   - the already-resolved lease key itself: `ge-0-0-3.50` — the
//     historically hidden workaround spelling must keep working.
//
// A bare interface (no unit) resolves to the DHCP unit it carries, or to
// the sole DHCP unit when there is one. A bare interface with several
// DHCP units is refused: renewing all of them would widen a scoped
// operator action silently, and refusing with the resumable unit list
// keeps the refusal truthful instead of the false "no DHCP client
// running" diagnosis. Unknown interfaces, unknown units, and units
// without a DHCP client stay refused — resolution never invents a lease
// key for a unit that runs no client.
//
// Nil-config safe: with no config there is nothing to resolve through,
// so only an already-lease-key-shaped target survives unchanged; the
// manager then reports its own "no DHCP client running" for it, which
// is the truthful diagnosis in that build.
func (c *Config) ResolveDHCPRenewTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("dhcp renew requires target interface")
	}
	if c == nil || len(c.Interfaces.Interfaces) == 0 {
		return target, nil
	}

	// Pass 1: the target is already a lease key (`ge-0-0-3.50`): match it
	// against the DHCP lease keys this config actually derives. This runs
	// FIRST because a lease key's ".<vlan-id>" suffix also parses as a
	// unit number on the Linux base (ge-0-0-3.50 = unit 50), which would
	// misrefuse the historically working hidden spelling. Only a key a
	// configured DHCP unit produces resolves.
	if key, ok := c.dhcpLeaseKeyByExact(target); ok {
		return key, nil
	}

	// Pass 2: exact interface key or its Linux alias, with an optional
	// ".<unit>" suffix. SplitInterfaceUnitRef applies the declared-name
	// precedence (#9821) on the slash form; the dash form needs the same
	// split against Linux aliases, which the splitter deliberately does
	// not do (#8829 stays local), so resolve the dash base explicitly.
	for _, form := range []string{target, dashToSlashAlias(target)} {
		if form == "" {
			continue
		}
		if leaseKey, handled, err := c.resolveRenewOnInterface(form); handled {
			return leaseKey, err
		}
	}

	return "", fmt.Errorf("no DHCP client running on interface %s", target)
}

// dashToSlashAlias returns the plausible Junos spelling of a Linux-form
// target (`ge-0-0-3.7` -> `ge-0/0/3.7`), or "" when target has no dash
// to fold. Interface names carry their first two dashes as the
// slot/port separators Junos writes with slashes; later dashes (reth
// member suffixes, tunnel names) are part of the name itself. Trying
// both fold points keeps `ge-0-0-3` and a dash-named interface both
// reachable; Pass 1 only accepts a form that names a declared
// interface, so a wrong fold is simply not handled.
func dashToSlashAlias(target string) string {
	base, suffix, hasUnit := strings.Cut(target, ".")
	parts := strings.Split(base, "-")
	if len(parts) < 3 {
		return ""
	}
	// ge-0-0-3 -> ge-0/0/3 (fold BOTH structural dashes: the FPC/pic
	// separator and the port separator). A 3-part dash name has no
	// second separator to fold (ge-0-0 -> ge-0/0 would name a different
	// interface), so it is returned unchanged and simply not handled.
	if len(parts) < 4 {
		return ""
	}
	candidate := parts[0] + "-" + parts[1] + "/" + parts[2] + "/" + strings.Join(parts[3:], "-")
	if hasUnit {
		candidate += "." + suffix
	}
	return candidate
}

// resolveRenewOnInterface resolves form (a Junos-spelled interface ref,
// optionally unit-qualified) against the declared interfaces. handled
// reports whether form named a declared interface at all; when it did,
// the returned error (if any) is final — the operator named a real
// interface, so a unit/DHCP refusal must not fall through to the lease-key
// pass and re-emerge as a confusing "no client" message.
func (c *Config) resolveRenewOnInterface(form string) (leaseKey string, handled bool, err error) {
	split := c.SplitInterfaceUnitRef(form)
	ifc := c.Interfaces.Interfaces[split.Base]
	if ifc == nil {
		return "", false, nil
	}
	if !split.HasUnit || split.UnitTok == "" {
		// Bare interface: renew the unit(s) it actually runs DHCP on.
		keys := c.dhcpLeaseKeysForInterface(split.Base)
		switch len(keys) {
		case 0:
			return "", true, fmt.Errorf("no DHCP client running on interface %s", form)
		case 1:
			return keys[0], true, nil
		default:
			return "", true, fmt.Errorf("interface %s has DHCP clients on multiple units (%s); renew a specific unit",
				split.Base, strings.Join(keys, ", "))
		}
	}
	unitNum, _, uerr := CanonicalLogicalUnit(split.UnitTok)
	if uerr != nil {
		return "", true, fmt.Errorf("no DHCP client running on interface %s", form)
	}
	unit := ifc.Units[unitNum]
	if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
		return "", true, fmt.Errorf("no DHCP client running on interface %s", form)
	}
	return DHCPLeaseIfName(split.Base, unit), true, nil
}

// dhcpLeaseKeysForInterface returns the sorted lease keys of every
// DHCP/DHCPv6 unit declared on ifName.
func (c *Config) dhcpLeaseKeysForInterface(ifName string) []string {
	ifc := c.Interfaces.Interfaces[ifName]
	if ifc == nil {
		return nil
	}
	var keys []string
	for _, unit := range ifc.Units {
		if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
			continue
		}
		keys = append(keys, DHCPLeaseIfName(ifName, unit))
	}
	sort.Strings(keys)
	return keys
}

// dhcpLeaseKeyByExact reports whether target is byte-identical to a
// lease key this config derives for a DHCP unit.
func (c *Config) dhcpLeaseKeyByExact(target string) (string, bool) {
	for ifName := range c.Interfaces.Interfaces {
		for _, key := range c.dhcpLeaseKeysForInterface(ifName) {
			if key == target {
				return key, true
			}
		}
	}
	return "", false
}

// DHCPRenewCompletionNames returns the interface spellings tab
// completion should offer for `request dhcp renew` (#15227 A43-04): the
// config-key spelling of every DHCP-carrying unit (`ge-0/0/0`,
// `ge-0/0/3.7`), never the hidden Linux lease key completion used to
// force operators to type. Sorted for deterministic help output.
func DHCPRenewCompletionNames(cfg *Config) []string {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	var names []string
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		nums := make([]int, 0, len(ifc.Units))
		for num, unit := range ifc.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6) {
				continue
			}
			nums = append(nums, num)
		}
		sort.Ints(nums)
		for _, num := range nums {
			names = append(names, ifName+"."+strconv.Itoa(num))
		}
	}
	sort.Strings(names)
	return names
}

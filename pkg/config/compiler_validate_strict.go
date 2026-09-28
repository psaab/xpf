package config

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
)

// validateDataplaneTypeStrict rejects retired dataplane backends at
// commit time. The parse path accepts `dataplane-type dpdk` as a
// legal known value (see compileSystemDataplaneType +
// validDataplaneType) so that `load merge` / `load override` of a
// pre-retirement config does not syntax-error; this strict validator
// is what tells the operator to migrate.
//
// Acceptance criterion in #1526 pins the verbatim message:
//
//	"the DPDK dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1525)"
//
// Tests substring-match the phrase so the same assertion holds
// whether the error is observed via `CompileConfig` directly,
// via `Store.CommitCheck()` (which returns the raw error), or via
// `Store.Commit()` (which wraps it as "commit check failed: ...").
func validateDataplaneTypeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.System.DataplaneType == dataplaneTypeDPDK {
		return ErrDPDKDataplaneRetired
	}
	if cfg.System.DataplaneType == dataplaneTypeEBPF {
		return ErrEBPFDataplaneRetired
	}
	return nil
}

// validateTrailingTokensStrict hard-rejects trailing tokens that rode past
// the legitimate value arity of a config leaf the generic schema-walk scalar
// gate cannot reach (#3332). Two shapes leak:
//
//   - address-book `address <name> <prefix>` / `address <name> description
//     <text>`: the `address` schema node is `multi:true` (it must absorb the
//     `description` sub-token onto its Keys to keep the #2419 dual-AST shape),
//     so the scalar-leaf arity gate skips it, and the compiler reads only the
//     prefix / description-text slot — `address h2 description web-server
//     bogus` silently drops `bogus`.
//   - IKE gateway compact-hierarchical `dynamic hostname <fqdn> <extra>`: the
//     flat-set form lands a `hostname` scalar CHILD the generic gate covers,
//     but the compact form collapses the tokens onto the parent `dynamic`
//     node's Keys and the compiler reads only Keys[2].
//
// Both record the leftover tokens on the typed struct during compile
// (mergeAddressNode / compileIPsec); this gate makes the silent drop
// operator-visible. Strict on commit / commit-check; the call site
// (compiler.go) downgrades to a warning on the tolerant load / peer-sync
// path so an already-persisted or peer-synced config still boots (#1960
// no-brick) — the dropped token never reached the dataplane, so a leniently
// loaded config runs exactly as it did before the gate. The walk is
// deterministic (entries sorted by name). Mirrors validateScreenUnknownStrict.
func validateTrailingTokensStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Address books: the global book plus every zone-local book. The
	// zone-local originals (sec.Zones[z].AddressBook) carry the recorded
	// TrailingTokens; resolveZoneLocalAddressBooks copies only Value /
	// Description into the qualified global entries, so both sources are
	// walked to catch the leak regardless of attachment point.
	checkBook := func(scope string, book *AddressBook) error {
		if book == nil {
			return nil
		}
		names := make([]string, 0, len(book.Addresses))
		for name := range book.Addresses {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			addr := book.Addresses[name]
			if addr == nil || len(addr.TrailingTokens) == 0 {
				continue
			}
			return fmt.Errorf(
				"security %saddress-book address %q: unexpected trailing token "+
					"%q (an address takes a single prefix or `description "+
					"<text>`; the extra token would be silently dropped — "+
					"quote a multi-word description as `\"...\"`)",
				scope, name, addr.TrailingTokens[0])
		}
		return nil
	}
	if err := checkBook("", cfg.Security.AddressBook); err != nil {
		return err
	}
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zn := range zoneNames {
		z := cfg.Security.Zones[zn]
		if z == nil {
			continue
		}
		if err := checkBook(fmt.Sprintf("zones security-zone %s ", zn), z.AddressBook); err != nil {
			return err
		}
	}

	// IKE gateways: compact-hierarchical `dynamic hostname <fqdn> <extra>`.
	gwNames := make([]string, 0, len(cfg.Security.IPsec.Gateways))
	for name := range cfg.Security.IPsec.Gateways {
		gwNames = append(gwNames, name)
	}
	sort.Strings(gwNames)
	for _, gn := range gwNames {
		gw := cfg.Security.IPsec.Gateways[gn]
		if gw == nil || len(gw.DynamicHostnameExtras) == 0 {
			continue
		}
		return fmt.Errorf(
			"security ike gateway %q dynamic hostname: unexpected trailing "+
				"token %q (the dynamic peer hostname is a single FQDN; the "+
				"extra token would be silently dropped)",
			gn, gw.DynamicHostnameExtras[0])
	}
	return nil
}

// validateFlowAgingStrict is the #3440 H2 commit-time gate for
// `security flow aging`. The aging subtree was an opaque untyped schema
// node, so its values were parsed with a bare strconv.Atoi and stored with
// no cross-field check. The typed schema leaves (schema_security.go) now
// bound each individual value (early-ageout >= 0, watermarks 0..100), but
// two failure modes are cross-field / structural and must be caught here:
//
//   - an unknown child leaf (`set security flow aging bogus 5`) — the schema
//     walker leaves unknown keywords to the compiler, and compileFlow used
//     to silently drop them; they are now recorded on
//     FlowConfig.AgingUnknownLeaves and rejected here (mirrors #3318
//     validateScreenUnknownStrict).
//   - low-watermark >= high-watermark when both are nonzero — aging
//     activates at high-watermark and deactivates below low-watermark, so a
//     low >= high config can never deactivate (it oscillates or latches on),
//     which is the H2 "high-watermark 90 low-watermark 95" example. Junos
//     requires low < high.
//
// Strict on commit / commit-check; the call site (compiler.go) downgrades
// to a warning on the tolerant load / peer-sync path so an already-persisted
// or peer-synced config still boots (#1960 no-brick) — the userspace
// dataplane does not enforce watermark aging at all (the #3440 H1 warning),
// so a leniently-loaded bad value is inert anyway.
func validateFlowAgingStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	flow := cfg.Security.Flow
	if len(flow.AgingUnknownLeaves) > 0 {
		return fmt.Errorf(
			"security flow aging: `%s` is not a supported aging option "+
				"(it would be silently dropped and have no effect); the "+
				"supported options are early-ageout, high-watermark, and "+
				"low-watermark",
			flow.AgingUnknownLeaves[0])
	}
	if flow.AgingHighWatermark > 0 && flow.AgingLowWatermark > 0 &&
		flow.AgingLowWatermark >= flow.AgingHighWatermark {
		return fmt.Errorf(
			"security flow aging: low-watermark %d must be less than "+
				"high-watermark %d (aging activates at high-watermark and "+
				"only deactivates below low-watermark; low >= high can never "+
				"deactivate)",
			flow.AgingLowWatermark, flow.AgingHighWatermark)
	}
	return nil
}

// #1830 (e): the #1733 MaxEqualFlowWorkers constant and
// validateEqualFlowWorkerCapStrict were retired together with the Rust
// MAX_WORKERS_SCRATCH cap they mirrored. The v8 lease rotation scratch
// is now heap-sized to the true worker count, so equal-flow-enforcement
// is supported at any configured worker count.

const (
	dataplaneTypeEBPF      = "ebpf"
	dataplaneTypeDPDK      = "dpdk"
	dataplaneTypeUserspace = "userspace"
)

func effectiveDataplaneType(dpType string) string {
	if dpType == "" {
		return dataplaneTypeUserspace
	}
	return dpType
}

func validDataplaneType(dpType string) bool {
	switch dpType {
	case dataplaneTypeEBPF, dataplaneTypeDPDK, dataplaneTypeUserspace:
		return true
	default:
		return false
	}
}

func userspaceSynCookieProtectionActive(cfg *Config) bool {
	if cfg == nil || effectiveDataplaneType(cfg.System.DataplaneType) != dataplaneTypeUserspace ||
		cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		return false
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile != nil && profile.TCP.SynFlood != nil &&
			profile.TCP.SynFlood.AttackThreshold > 0 {
			return true
		}
	}
	return false
}

// knownManagedProcessNames is the set of Junos process names that bpfrx
// actually honours when `system processes X disable` is configured.
// The runtime sites hard-code their process name (not a table lookup):
//   - pkg/daemon/daemon.go ~:715 — `isProcessDisabled(cfg, "snmpd")`
//   - pkg/daemon/daemon_system.go ~:383 — `isProcessDisabled(cfg, "ntp")`
//
// This table mirrors those hard-codes for the purpose of the #654
// validation warning. Any addition here MUST be paired with a matching
// runtime gating site, or the warning will go quiet while the knob
// remains a no-op.
var knownManagedProcessNames = map[string]struct{}{
	"snmpd": {},
	"ntp":   {},
}

func isKnownProcessName(name string) bool {
	_, ok := knownManagedProcessNames[name]
	return ok
}

// validateDHCPStaticBindingsStrict (#2243) hard-rejects, at commit /
// commit-check, a DHCP-server static (fixed/reserved) host binding that
// would render a broken or silently-mismatched Kea reservation:
//
//   - a binding missing its fixed-address (no reservation can be emitted);
//   - a fixed-address that is not a valid IP literal;
//   - a fixed-address whose family disagrees with the local-server family
//     (a v6 literal under dhcp-local-server, or a v4 literal under
//     dhcpv6-local-server) — Kea would reject the subnet;
//   - a fixed-address outside the enclosing pool's subnet (Kea silently
//     ignores such a reservation, so the client never gets the reserved
//     address — fail loud instead);
//   - a duplicate MAC identity or duplicate fixed-address within the same
//     pool (the reservation set would be ambiguous / Kea-rejected).
//
// The MAC shape itself is already gated by the schema (ValidateMAC); this
// validator re-parses it only to normalize the duplicate-identity key. A
// binding with no Subnet on its pool skips the in-subnet check (the pool is
// then incomplete in other ways the operator will hit first) but still gets
// the family/duplicate checks.
func validateDHCPStaticBindingsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(srv *DHCPLocalServerConfig, family string, wantV6 bool) error {
		if srv == nil {
			return nil
		}
		// Deterministic iteration so the first reported error is stable
		// across runs (map order is otherwise random).
		groupNames := make([]string, 0, len(srv.Groups))
		for name := range srv.Groups {
			groupNames = append(groupNames, name)
		}
		sort.Strings(groupNames)
		for _, gname := range groupNames {
			group := srv.Groups[gname]
			if group == nil {
				continue
			}
			for _, pool := range group.Pools {
				if pool == nil || len(pool.StaticBindings) == 0 {
					continue
				}
				var prefix netip.Prefix
				havePrefix := false
				if pool.Subnet != "" {
					if p, err := netip.ParsePrefix(pool.Subnet); err == nil {
						prefix = p.Masked()
						havePrefix = true
					}
				}
				seenMAC := make(map[string]string, len(pool.StaticBindings))
				seenAddr := make(map[string]string, len(pool.StaticBindings))
				for _, sb := range pool.StaticBindings {
					if sb == nil {
						continue
					}
					where := fmt.Sprintf("%s group %q pool %q static-binding %q",
						family, group.Name, pool.Name, sb.MACAddress)
					if sb.FixedAddress == "" {
						return fmt.Errorf("%s has no fixed-address — a reservation cannot be emitted", where)
					}
					addr, err := netip.ParseAddr(sb.FixedAddress)
					if err != nil {
						return fmt.Errorf("%s fixed-address %q is not a valid IP address", where, sb.FixedAddress)
					}
					if wantV6 && !addr.Is6() {
						return fmt.Errorf("%s fixed-address %q is not an IPv6 address (required under dhcpv6-local-server)", where, sb.FixedAddress)
					}
					if !wantV6 && !addr.Is4() {
						return fmt.Errorf("%s fixed-address %q is not an IPv4 address (required under dhcp-local-server)", where, sb.FixedAddress)
					}
					if havePrefix && !prefix.Contains(addr) {
						return fmt.Errorf("%s fixed-address %q is outside the pool subnet %s (Kea would silently drop the reservation)", where, sb.FixedAddress, pool.Subnet)
					}
					macKey := strings.ToLower(sb.MACAddress)
					if prev, dup := seenMAC[macKey]; dup {
						return fmt.Errorf("%s duplicates the hardware-address already bound to %s in the same pool", where, prev)
					}
					seenMAC[macKey] = sb.FixedAddress
					addrKey := addr.String()
					if prevMAC, dup := seenAddr[addrKey]; dup {
						return fmt.Errorf("%s fixed-address %q is already reserved for %s in the same pool", where, sb.FixedAddress, prevMAC)
					}
					seenAddr[addrKey] = sb.MACAddress
				}
			}
		}
		return nil
	}
	if err := check(cfg.System.DHCPServer.DHCPLocalServer, "dhcp-local-server", false); err != nil {
		return err
	}
	return check(cfg.System.DHCPServer.DHCPv6LocalServer, "dhcpv6-local-server", true)
}

// vrrpVIPHostIP returns the host IP of a VRRP virtual-address string. xpf
// requires a /prefix (schema_interfaces.go vrrpGroupSchemaNode), so the VIP is
// normally CIDR (e.g. 10.0.1.1/24); a bare IP is tolerated here so a leniently-
// loaded legacy config is still classified. An unparseable value returns nil
// and is left to the schema validator's concern.
func vrrpVIPHostIP(vip string) net.IP {
	if vip == "" {
		return nil
	}
	if ip, _, err := net.ParseCIDR(vip); err == nil {
		return ip
	}
	return net.ParseIP(vip)
}

// validateVRRPVirtualAddressSubnet (#3013) rejects a VRRP virtual-address that
// does not fall within any subnet configured on the same interface unit for the
// matching address family.
//
// Background: a `vrrp-group <id> virtual-address <vip>` block is authored under
// a `family inet|inet6 address <prefix>` on a unit. In Junos/vSRX a VIP outside
// every on-link subnet of the unit is a commit-time configuration error. xpf
// accepted it: at runtime the daemon installs the VIP as a host address, but
// with no connected route covering it return traffic sourced from the VIP has
// no on-link subnet association — a silent misconfiguration (operator-visible
// only as a blackhole). This check restores vSRX config-parity by catching the
// misconfig at commit instead of at runtime.
//
// For each VIP the validator asserts containment in the prefix of at least one
// address configured on the SAME unit of the MATCHING family. The owning /
// priority-255 case (VIP equals an interface address) is covered for free — an
// interface address is trivially contained in its own subnet. A cross-family
// VIP (e.g. a v4 literal authored under a v6-only address) has no matching-
// family subnet to contain it and is therefore rejected, which is the intent.
//
// A unit carrying a real VRRP group always has at least the parent address of
// the VIP's family in unit.Addresses (the group is nested under it), so the
// matching-family subnet set is non-empty in the valid case — the only empty
// case is the genuine cross-family/out-of-subnet misconfig.
//
// Strict (commit / commit-check): hard-reject, naming the interface, unit,
// group, VIP and family. Lenient (load / peer-sync): warn so an already-
// persisted or peer-synced config an older binary accepted still boots (#1960
// fail-closed-on-load class).
func validateVRRPVirtualAddressSubnet(cfg *Config, lenient bool) ([]string, error) {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil, nil
	}
	var warnings []string
	// Deterministic iteration so commit errors / warnings are stable.
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			// Pre-parse the unit's configured subnets by family. The
			// containment test is textual-CIDR based (net.ParseCIDR), so an
			// unparseable address is skipped — not this validator's concern.
			var v4nets, v6nets []*net.IPNet
			for _, a := range unit.Addresses {
				_, ipnet, err := net.ParseCIDR(a)
				if err != nil || ipnet == nil {
					continue
				}
				if ipnet.IP.To4() != nil {
					v4nets = append(v4nets, ipnet)
				} else {
					v6nets = append(v6nets, ipnet)
				}
			}
			gkeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				gkeys = append(gkeys, k)
			}
			sort.Strings(gkeys)
			for _, gk := range gkeys {
				vg := unit.VRRPGroups[gk]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					ip := vrrpVIPHostIP(vip)
					if ip == nil {
						// Bare/garbage VIP: the schema CIDR validator is
						// responsible for rejecting a non-address value.
						continue
					}
					nets := v6nets
					fam := "inet6"
					if ip.To4() != nil {
						nets = v4nets
						fam = "inet"
					}
					contained := false
					for _, n := range nets {
						if n.Contains(ip) {
							contained = true
							break
						}
					}
					if contained {
						continue
					}
					msg := fmt.Sprintf(
						"interfaces %s unit %d vrrp-group %d virtual-address %s: "+
							"not within any family %s subnet configured on the unit; "+
							"the VIP would install without a connected route and "+
							"blackhole return traffic (vSRX rejects this at commit)",
						ifName, un, vg.ID, vip, fam)
					if lenient {
						warnings = append(warnings, msg+
							" (ignored: VIP installed without a connected route until corrected)")
						continue
					}
					return nil, fmt.Errorf("%s", msg)
				}
			}
		}
	}
	return warnings, nil
}

// validateHelperStateFileStrict rejects helper state-file values the
// factory-reset sweep must never unlink (#10769 d05-F6): reserved
// reset-gate/identity paths (belt-and-braces behind the leaf validator,
// which tolerant load paths downgrade past), and equality with the
// configured control socket (the sweep would unlink the live socket).
// Strict on commit / commit-check; the call site downgrades to a warning
// on the tolerant load / peer-sync path so an already-persisted config
// still boots (#1960 no-brick) — the runtime sweep guard refuses
// reserved targets regardless.
func validateHelperStateFileStrict(cfg *Config) error {
	if cfg == nil || cfg.System.UserspaceDataplane == nil {
		return nil
	}
	stateFile := cfg.System.UserspaceDataplane.StateFile
	if stateFile == "" {
		return nil
	}
	if IsReservedHelperStatePath(stateFile) {
		return fmt.Errorf("system dataplane state-file %q aliases reserved reset-gate or system-identity state; "+
			"the factory-reset helper sweep unlinks this path and must never delete gates or identity files", stateFile)
	}
	if socket := cfg.System.UserspaceDataplane.ControlSocket; socket != "" &&
		filepath.Clean(stateFile) == filepath.Clean(socket) {
		return fmt.Errorf("system dataplane state-file %q must not equal the control-socket path: "+
			"the factory-reset helper sweep would unlink the live control socket", stateFile)
	}
	return nil
}

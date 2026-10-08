package config

import (
	"fmt"
	"sort"
	"strings"
)

// validateRethRedundancyGroupStrict rejects, at commit / commit-check, a
// `redundant-ether-options redundancy-group <N>` authored on an interface that
// is neither structurally nor nominally a redundant-ethernet interface:
// nothing names it as their `gigether-options redundant-parent`, AND it is not
// spelled `reth*` (#6781).
// It also bounds structurally owned active RETHs to MaxRethCount so the
// per-RETH virtual-MAC index remains unique and representable.
//
// Junos scopes `redundant-ether-options` to a reth; xpf's schema attaches it to
// any interface node (schema_interfaces.go), so `ge-0/0/5
// redundant-ether-options redundancy-group 1` committed cleanly and then meant
// three different things to three different consumers:
//
//   - networkd generation (pkg/dataplane compiler_iface.go) treated the
//     interface as a VRRP-backed reth member and REPLACED the operator's
//     configured address with a 169.254.<rg>.<node>/32 link-local.
//   - The VRRP-backed owner (CollectRethInstances) synthesized a VRRP instance
//     on it whose "VIPs" were that same configured address — so it existed only
//     while the node was MASTER, and was deleted on BACKUP.
//   - The direct owner (RethVIPsForRG, used under `no-reth-vrrp` /
//     `private-rg-election`) skipped it entirely.
//
// The two ownership modes therefore disagreed, and the disagreement was not
// symmetric: under `no-reth-vrrp` the address was stripped by networkd and
// installed by NOBODY, on both nodes, so a plain L3 interface silently lost its
// address by being given a redundancy group.
//
// Requiring member ports is the honest reading of what the operator asked for.
// A redundancy group is a failover relationship between two physical ports on
// two chassis; an interface with no members has nothing to fail over between
// and no netdev for VRRP to bind (RETH is bondless here — the reth name is not
// a kernel device). This gate does NOT require the interface to be NAMED
// `reth*`: interface names are validated by character class only
// (validate_interface_name.go), so the spelling is a convention, and rejecting
// a structurally valid pair for its name would turn a working config into a
// failed commit with no operator workaround.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRethRGOwnership) so an already-persisted or
// peer-synced config an older binary accepted still BOOTS (#1960 no-brick); the
// runtime consumers independently resolve ownership through the shared
// structural predicate (Config.RethRGOwners), so a leniently-loaded config
// keeps the interface as a plain L3 interface with its configured address
// rather than half-applying a redundancy group to it. Same doctrine as
// lenientRethMember (#6722).
func validateRethRedundancyGroupStrict(cfg *Config) error {
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	rethToPhys := cfg.RethToPhysical()
	if count := len(cfg.rethMACOwners()); count > MaxRethCount {
		return fmt.Errorf("configuration has %d RETH interfaces, exceeding the supported limit of %d",
			count, MaxRethCount)
	}

	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ifc, ok := LookupInterface(cfg, name)
		if !ok || ifc.RedundancyGroup <= 0 {
			continue
		}
		if _, hasMembers := rethToPhys[name]; hasMembers {
			continue
		}
		// A `reth*`-named interface with no members yet is DELIBERATELY not
		// rejected here. It is a declaration of intent to be a
		// redundant-ethernet interface — an incompletely-wired one — and
		// rejecting it would newly refuse a shape the repo's own fixtures and
		// an operator building a config incrementally both use. It is also not
		// what #6781 is about: the disagreement this gate closes is over
		// interfaces that are neither structurally NOR nominally a reth.
		//
		// It is safe to leave: the shared structural predicate
		// (Config.RethRGOwners) excludes it at runtime, so neither ownership
		// mode claims it and no address is taken from it. Before #6781 both
		// modes DID claim it and then failed in netlink against a `reth0`
		// netdev that does not exist (RETH is bondless), so this is strictly
		// quieter than what it replaces.
		if strings.HasPrefix(name, "reth") {
			continue
		}
		return fmt.Errorf(
			"interface %q sets `redundant-ether-options redundancy-group %d`, "+
				"but no interface names %q as its `gigether-options "+
				"redundant-parent`, so it is not a redundant-ethernet interface. "+
				"A redundancy group is a failover relationship between member "+
				"ports on the two chassis; with no members there is nothing to "+
				"fail over between and no kernel device to bind (a reth name is "+
				"not itself a netdev). The configured address on %q would be "+
				"replaced with a 169.254.%d.<node>/32 link-local in the generated "+
				"networkd config and handed to VRRP as a virtual address — and "+
				"under `no-reth-vrrp` nothing would install it back, so %q would "+
				"silently lose its address on both nodes. Add "+
				"`gigether-options redundant-parent %s` to the member ports, or "+
				"remove the redundancy-group from %q",
			name, ifc.RedundancyGroup, name, name, ifc.RedundancyGroup, name,
			name, name)
	}
	return nil
}

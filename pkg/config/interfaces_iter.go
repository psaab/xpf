package config

import "sort"

// Nil-safe interface/unit iterators for read-only presenters (#5813).
//
// REACHABILITY, corrected in #6780. The comments here and at ~12 call sites
// state that the lenient load / HA config-sync path ADMITS present-but-nil
// InterfaceConfig / InterfaceUnit map values (#3494/#5068). That premise was
// never demonstrated and is, as of #6780, believed to be FALSE: each container
// has exactly one compiler write site and each stores a freshly-allocated
// pointer, persistence decodes the AST (*ConfigTree) and recompiles, HA
// config-sync ships config TEXT, and nothing deserializes a *Config. The
// invariant is now enforced by TestCompilerNeverEmitsNilConfigSlots
// (nil_slot_invariant_6780_test.go) rather than assumed in either direction.
//
// These helpers are retained: they are correct, free, and make a consumer
// degrade rather than panic if a future config ingress ever breaks that
// invariant. What changed is the JUSTIFICATION — they are defence in depth
// behind an enforced invariant, not a fix for a reachable panic. Do not cite
// them as evidence that nil slots occur; that circularity (#5068 citing the
// #3494 test, whose own header says "The strict compiler never emits these
// nils") is what #6780 unwound.
//
// A peer-synced or tolerantly-loaded config would carry such a slot as a
// `cfg.Interfaces.Interfaces["ge-0/0/0"] = nil`, or an `ifc.Units[7] = nil`. Every
// read-only presenter that walks the interface tree — the CLI/gRPC/REST session
// egress-interface map builders, interface displays, completers — must SKIP
// those nil slots, not dereference them: a raw `for _, ifc := range … { for _,
// unit := range ifc.Units { unit.Number … } }` nil-derefs and panics the
// in-process daemon during a routine `show`. Routing every such walk through
// these two helpers keeps the guard in ONE place so this class stops recurring.
// LookupInterfaceByLinuxName ALSO serves the commit path (#9815): the
// kernel-name resolver and the default-instance scoping set resolve a
// possibly cross-spelled member base through it.

// RangeInterfaces calls fn for every (name, *InterfaceConfig) in cfg's interface
// map, SKIPPING any present-but-nil InterfaceConfig value. A nil cfg (or nil
// interface map) is a clean no-op. Map iteration order is unspecified (Go map
// order); callers that need determinism must sort the names themselves.
func RangeInterfaces(cfg *Config, fn func(name string, ifc *InterfaceConfig)) {
	if cfg == nil {
		return
	}
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		fn(name, ifc)
	}
}

// RangeUnits calls fn for every (unit-number, *InterfaceUnit) on ifc, SKIPPING
// any present-but-nil InterfaceUnit value. A nil ifc (or nil unit map) is a
// clean no-op.
func RangeUnits(ifc *InterfaceConfig, fn func(unitNum int, unit *InterfaceUnit)) {
	if ifc == nil {
		return
	}
	for unitNum, unit := range ifc.Units {
		if unit == nil {
			continue
		}
		fn(unitNum, unit)
	}
}

// LookupInterface returns cfg's InterfaceConfig for name and true ONLY when the
// name is present AND its value is non-nil (#5886). It treats a present-but-nil
// slot (tolerant load / HA config-sync, #3494/#5068) as ABSENT — a read-only
// presenter that key-checks `if ifc, ok := cfg.Interfaces.Interfaces[name]; ok`
// then dereferences `ifc` would panic on such a slot; routing the lookup through
// this helper makes `ok` imply a safe dereference. A nil cfg is (nil, false).
func LookupInterface(cfg *Config, name string) (*InterfaceConfig, bool) {
	if cfg == nil {
		return nil, false
	}
	ifc, ok := cfg.Interfaces.Interfaces[name]
	if !ok || ifc == nil {
		return nil, false
	}
	return ifc, true
}

// LookupInterfaceByLinuxName returns the declared stanza for a possibly
// cross-spelled interface base (#9815): the exact LookupInterface hit first,
// else the first-sorted stanza whose LinuxIfName equals LinuxIfName(base).
// The contract, each load-bearing:
//
//   - the return includes the matched DECLARED KEY (not just the stanza):
//     the tunnel-alias probes reconstruct the same-spelling twin's tunMap
//     key from it, and assuming ifc.Name equals the map key is unstated.
//   - exact-first: a same-spelling caller resolves byte-identically to the
//     direct map index, so #8994/#9821 pins and every same-spelling consumer
//     are unreachable by the fallback.
//   - first-sorted over a copied name list: a lenient config may declare
//     both spellings, and map order must not pick the winner (the
//     resolveMemberDeclaredBase level-2 twin in pkg/daemon pins the same
//     order).
//   - nil-safe (#5886 doctrine): nil cfg, nil map, and present-but-nil slots
//     (exact and scan paths alike) are a miss, never a panic.
//
// Placement rule: unit call sites stay strictly inside a HasUnit arm (for a
// bare ref base==member, a helper call WOULD be whole-member alias matching).
// TWO deliberate bare sites exist: the daemon bind fans a bare member down
// through its own first-sorted twin scan (resolveMemberDeclaredBase — that
// path never calls this helper), and the userspace FIB maps a bare member
// onto the declared stanza through this helper (#10174). Both own
// linux-name matching (#8829 precedent). The shared resolver's bare arm
// never consults this helper.
func LookupInterfaceByLinuxName(cfg *Config, base string) (string, *InterfaceConfig, bool) {
	if ifc, ok := LookupInterface(cfg, base); ok {
		return base, ifc, true
	}
	if cfg == nil {
		return "", nil, false
	}
	want := LinuxIfName(base)
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil {
			continue
		}
		if LinuxIfName(name) == want {
			return name, ifc, true
		}
	}
	return "", nil, false
}

// LookupUnit returns ifc's InterfaceUnit for num and true ONLY when the unit is
// present AND non-nil (#5886) — the unit-level companion to LookupInterface. A
// nil ifc (or nil unit map) is (nil, false).
func LookupUnit(ifc *InterfaceConfig, num int) (*InterfaceUnit, bool) {
	if ifc == nil {
		return nil, false
	}
	unit, ok := ifc.Units[num]
	if !ok || unit == nil {
		return nil, false
	}
	return unit, true
}

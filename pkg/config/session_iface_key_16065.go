package config

import (
	"fmt"
	"sort"
	"strings"
)

// session_iface_key_16065.go — #16065 (SI-6): the ONE derivation of the
// session {ifindex, VID} -> Junos unit-name table, shared by the CLI,
// gRPC and REST session surfaces, and of the ifindex -> display-name
// table the daemon installs for flow export / RT_FLOW (logging.EventReader).
//
// THE DEFECTS.
//
// (1) VLAN units keyed by the parent instead of the child. The pre-fix
// session surfaces resolved the unit's kernel device as the PARENT
// netdev (ResolveReth + SplitN(".",2)[0] / LinuxIfName(base)) and keyed
// every unit on {parentIfindex, VID}, with VID = vlan-id else the unit
// NUMBER. A VLAN unit's own device (<parent>.<vlan-id>) is a distinct
// kernel object with its own ifindex: an identity stamped with the
// CHILD ifindex (the logical unit the dataplane resolves, a route's
// egress device, an event's resolved unit) could never match a
// {parent, VID} key, and the VID was left to distinguish units that
// the device already distinguishes.
//
// (2) Sibling deletion on a shared/missing name. Two tunnel units
// sharing one device — wg0.0 and wg0.1 on the single wg0 TUN, both
// VID 0 — collided on {wg0Ifindex, 0}: the first writer won
// (nondeterministically, over Go map order, on the api/grpcapi
// surfaces; lowest-unit on the CLI) and BOTH units' sessions rendered
// and matched as that one name. `clear ... interface wg0.1` then
// deleted wg0.0's sessions (and vice versa) — selecting on a name the
// row never carried deletes sessions the operator did not name.
//
// (3) Flow-export first-wins unchanged. daemon.buildIfNames built a
// bare ifindex -> name map with sorted first-wins, so the same wg0.0/
// wg0.1 collision named every record on the shared TUN after whichever
// unit was visited first, and flow-export sampling judged both units'
// records by that surviving name.
//
// THE RULE. A unit's device is ResolveKernelIfName("<iface>.<unit>")
// — the canonical resolver that already knows per-unit tunnel devices
// (gr-0/0/0.1 -> gr-0-0-0u1), the shared WireGuard TUN (wg0.1 -> wg0),
// VLAN children (<parent>.<vlan-id>), the unit-0 collapse and RETH
// members. The ifindex is looked up on THAT device — the unit's OWN
// device, the VLAN child included — so units on distinct devices key
// distinctly, and SessionIfaceNames records the child ifindex with
// its wire VID, the pair a session row for that unit carries.
//
// Units that STILL share a device after that resolution (wg0.0/wg0.1
// on the one TUN; two untagged units of one interface) have NO
// per-packet identity separating them: the session row carries only
// {ifindex, VID} and decap rebinds inner packets to the tunnel's
// single logical ifindex (the same fact #16063's mirror refusal
// rests on). Naming one of them would be a coin flip, so the shared
// key is REFUSED — omitted from the name table — and every consumer
// falls back to its honest approximation: the zone list for filters,
// the zone/single-member rule for display columns, "" (nameless,
// zone semantics) for flow-export sampling. A per-unit filter name
// for a refused unit therefore matches only through the zone arm it
// already had, never through a sibling's name; clear-by-interface
// cannot select the wrong sibling's sessions through this table.
//
// Deterministic: interfaces and units are visited in sorted order
// (RETH spellings first, mirroring the operator preference for the
// redundant name over its member), so the table is stable across runs.

// SessionIfaceKey identifies a session row's interface identity: the
// kernel ifindex of the unit's OWN device plus the 802.1Q VID the row
// carries (0 = untagged). It is the key of SessionIfaceNames.
type SessionIfaceKey struct {
	Ifindex uint32
	VlanID  uint16
}

// SessionIfaceNames builds the {ifindex, VID} -> Junos unit-name table
// for session display, session interface filters (show AND clear) and
// flow-export interface attribution.
//
// lookupIfindex resolves a KERNEL device name (e.g. "wg0",
// "gr-0-0-0u1", "ge-0-0-3.50") to its ifindex; tests inject a fixed
// table, production passes net.InterfaceByName's index. A unit whose
// device does not resolve contributes no entry (the row degrades to
// the zone approximation, as before).
//
// A key claimed by two DIFFERENT unit names is ambiguous and is
// omitted entirely (shared-ifindex ambiguity refusal): see the file
// comment. The same name claiming a key twice (unit 0 collapsing onto
// its parent's device, a RETH and its member naming one device) is
// not ambiguity and keeps the name.
func SessionIfaceNames(cfg *Config, lookupIfindex func(string) (int, error)) map[SessionIfaceKey]string {
	names := make(map[SessionIfaceKey]string)
	if cfg == nil || lookupIfindex == nil {
		return names
	}
	ambiguous := make(map[SessionIfaceKey]struct{})
	// Deterministic visit order: RETH interfaces first (their spelling
	// is what operators write for the shared member device), then the
	// rest, each in sorted name order; units in numeric order.
	var rethNames, otherNames []string
	RangeInterfaces(cfg, func(name string, _ *InterfaceConfig) {
		if strings.HasPrefix(name, "reth") {
			rethNames = append(rethNames, name)
		} else {
			otherNames = append(otherNames, name)
		}
	})
	sort.Strings(rethNames)
	sort.Strings(otherNames)
	for _, group := range [][]string{rethNames, otherNames} {
		for _, ifName := range group {
			ifc, ok := LookupInterface(cfg, ifName)
			if !ok {
				continue
			}
			unitNums := make([]int, 0, len(ifc.Units))
			RangeUnits(ifc, func(num int, _ *InterfaceUnit) {
				unitNums = append(unitNums, num)
			})
			sort.Ints(unitNums)
			for _, num := range unitNums {
				unit, ok := LookupUnit(ifc, num)
				if !ok {
					continue
				}
				ref := fmt.Sprintf("%s.%d", ifName, num)
				device := cfg.ResolveKernelIfName(ref)
				if device == "" {
					continue
				}
				idx, err := lookupIfindex(device)
				if err != nil || idx <= 0 {
					continue
				}
				display := ref
				if num == 0 {
					// Unit 0 renders as the bare interface name (the
					// pre-#16065 surfaces' rule, which the zone
					// corroboration's parent/unit equivalence relies
					// on), whether it collapses onto the parent device
					// or owns a tunnel/xfrm device of its own.
					display = ifName
				}
				key := SessionIfaceKey{Ifindex: uint32(idx), VlanID: uint16(unit.VlanID)}
				if _, bad := ambiguous[key]; bad {
					continue
				}
				if held, exists := names[key]; exists {
					if held != display {
						// Two DIFFERENT units share this {device,
						// VID}: no per-packet identity separates
						// them, so naming either is a coin flip.
						// Refuse the key (shared-ifindex ambiguity
						// refusal); consumers fall back to the zone.
						delete(names, key)
						ambiguous[key] = struct{}{}
					}
					continue
				}
				names[key] = display
			}
		}
	}
	return names
}

// SharedSessionIfaceKey reports whether key is claimed by more than
// one distinct unit name in cfg under lookupIfindex — i.e. whether
// SessionIfaceNames refuses it. The claim comparison uses the DISPLAY
// name SessionIfaceNames would store (unit 0 as the bare interface
// name), so a unit 0 and its parent collapsing onto one device are
// one claim, not two. It exists for tests and diagnostics; production
// consumers just read the (absent) map entry.
func SharedSessionIfaceKey(cfg *Config, lookupIfindex func(string) (int, error), key SessionIfaceKey) bool {
	if cfg == nil || lookupIfindex == nil {
		return false
	}
	seen := make(map[string]struct{})
	found := false
	RangeInterfaces(cfg, func(ifName string, ifc *InterfaceConfig) {
		RangeUnits(ifc, func(num int, unit *InterfaceUnit) {
			device := cfg.ResolveKernelIfName(fmt.Sprintf("%s.%d", ifName, num))
			if device == "" {
				return
			}
			idx, err := lookupIfindex(device)
			if err != nil || idx <= 0 {
				return
			}
			k := SessionIfaceKey{Ifindex: uint32(idx), VlanID: uint16(unit.VlanID)}
			if k != key {
				return
			}
			found = true
			display := fmt.Sprintf("%s.%d", ifName, num)
			if num == 0 {
				display = ifName
			}
			seen[display] = struct{}{}
		})
	})
	return found && len(seen) > 1
}

// SessionIfNamesByIfindex projects SessionIfaceNames onto the bare
// ifindex -> name shape the daemon's EventReader consumes (RT_FLOW /
// flow-export attribution, #15094): the VID is dropped, so a key the
// {ifindex, VID} table REFUSES (two units sharing one device, wg0.0/
// wg0.1 on the one TUN) is refused here too — the ifindex resolves
// nameless downstream and the record keeps zone semantics instead of
// being named after a sibling by first-wins. A key claimed by the
// SAME display name at several VIDs keeps that name.
func SessionIfNamesByIfindex(cfg *Config, lookupIfindex func(string) (int, error)) map[uint32]string {
	out := make(map[uint32]string)
	for key, name := range SessionIfaceNames(cfg, lookupIfindex) {
		if _, exists := out[key.Ifindex]; !exists {
			out[key.Ifindex] = name
		}
	}
	return out
}

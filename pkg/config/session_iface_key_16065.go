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
// THE RULE — BOTH KEYS PER UNIT. A session row does not carry one
// canonical ifindex form. Ingress rows are stamped by AF_XDP with the
// PARENT/bind-port ifindex plus the frame's wire VID
// (UserspaceDpMeta.ingress_ifindex; the logical child is derived from
// that pair, never stamped instead of it), while child-stamped
// identities (FIB egress devices, kernel-path events) carry the
// unit's OWN device ifindex. So each unit registers TWO keys:
//
//   - {parentIfindex, VID} — the parent/bind device (see
//     sessionParentDevice) with the wire VID. This is the ingress
//     stamp, and the unit-number-as-VID fallback is gone: VID is
//     unit.VlanID only.
//   - {childIfindex, VID} — the unit's own device via
//     ResolveKernelIfName("<iface>.<unit>") (per-unit tunnel devices
//     gr-0/0/0.1 -> gr-0-0-0u1, the shared WireGuard TUN wg0.1 -> wg0,
//     VLAN children <parent>.<vlan-id>, unit-0 collapse, RETH members).
//
// When both devices coincide (unit 0 collapse, shared TUN) the two
// registrations are the same key and merge.
//
// Units that share a KEY after both registrations (wg0.0/wg0.1 on the
// one TUN at {wgIfindex, 0}; two VLAN units of one parent at
// {parent, VID} is NOT sharing — the VID separates them) have no
// identity separating them at that key: naming one would be a coin
// flip, so the key is REFUSED — omitted from the name table AND
// recorded in the ambiguous set returned alongside it (see
// SessionIfaceTable). Refusal is not the same as absence: a consumer
// matching an interface filter must NOT broaden a refused identity
// to the whole zone (that would let `clear interface wg0.1` delete
// wg0.0's sessions through the fallback), while a genuinely absent
// identity (0, unnameable, peer-synced) keeps the historical zone
// fallback for reachability.
//
// DISPLAY follows the same table: a refused key prints no name (the
// caller reports the zone), an agreed key prints its one name.
//
// Deterministic: interfaces and units are visited in sorted order
// (RETH spellings first, mirroring the operator preference for the
// redundant name over its member), so the table is stable across runs.
// The tunnel-name map is hoisted once (resolveKernelIfNameWith,
// #8862) so building the table is not quadratic in the unit count.

// SessionIfaceKey identifies a session row's interface identity: an
// ifindex (the unit's own device, or its parent/bind device) plus the
// 802.1Q VID the row carries (0 = untagged). It is the key of
// SessionIfaceNames / SessionIfaceTable.
type SessionIfaceKey struct {
	Ifindex uint32
	VlanID  uint16
}

// SessionIfaceTable is the result of building the session name table:
// Names maps each agreed key to its one Junos unit name; Ambiguous
// holds every key two DIFFERENT unit names claimed (shared-device
// refusal). A key in Ambiguous is absent from Names, and consumers
// must treat it as KNOWN-AMBIGUOUS — never broaden it to the zone
// when an interface filter is in force — which is distinct from a
// key that is simply absent (unknown device, identity-less row).
type SessionIfaceTable struct {
	Names     map[SessionIfaceKey]string
	Ambiguous map[SessionIfaceKey]struct{}
}

// IsAmbiguous reports whether key was refused for shared-device
// ambiguity. Nil-safe: a zero table has no ambiguous keys.
func (t SessionIfaceTable) IsAmbiguous(key SessionIfaceKey) bool {
	_, ok := t.Ambiguous[key]
	return ok
}

// sessionUnitDisplay is the Junos name stored for a unit: "<iface>.<n>",
// except an UNTAGGED unit 0, which renders as the bare interface name
// (the pre-#16065 surfaces' rule the zone corroboration's parent/unit
// equivalence relies on). A TAGGED unit 0 (VlanID > 0) owns a distinct
// VLAN child and keeps its ".0" identity: rendering it bare would make
// an explicit `interface ge-0/0/0.0` filter miss the unit it names,
// since matching accepts exact equality or a candidate starting with
// filter+"." — candidate "ge-0/0/0" never matches filter "ge-0/0/0.0".
func sessionUnitDisplay(ifName string, num int, unit *InterfaceUnit) string {
	if num == 0 && unit != nil && unit.VlanID == 0 {
		return ifName
	}
	return fmt.Sprintf("%s.%d", ifName, num)
}

// sessionParentDevice returns the kernel device the AF_XDP bind port
// for a unit's ingress frames is: the interface's bare device
// (ResolveKernelIfName of the bare iface ref — RETH resolves to its
// local member, a tunnel interface to its base device). Ingress rows
// stamp {parentIfindex, wire VID}, so the name table registers that
// pair alongside the unit's own-device pair.
func (c *Config) sessionParentDevice(ifName string, tunMap map[string]string) string {
	return c.resolveKernelIfNameWith(ifName, tunMap)
}

// SessionIfaceTableFor builds the {ifindex, VID} -> Junos unit-name
// table (and its ambiguity set) for session display, session interface
// filters (show AND clear) and flow-export interface attribution.
//
// lookupIfindex resolves a KERNEL device name (e.g. "wg0",
// "gr-0-0-0u1", "ge-0-0-3.50", "ge-0-0-3") to its ifindex; tests inject
// a fixed table, production passes net.InterfaceByName's index. A unit
// whose device does not resolve contributes no entry for that key
// form (the row degrades to the zone approximation, as before).
func SessionIfaceTableFor(cfg *Config, lookupIfindex func(string) (int, error)) SessionIfaceTable {
	table := SessionIfaceTable{
		Names:     make(map[SessionIfaceKey]string),
		Ambiguous: make(map[SessionIfaceKey]struct{}),
	}
	if cfg == nil || lookupIfindex == nil {
		return table
	}
	tunMap := tunnelNameMapFn(cfg)
	claim := func(key SessionIfaceKey, display string) {
		if _, bad := table.Ambiguous[key]; bad {
			return
		}
		if held, exists := table.Names[key]; exists {
			if held != display {
				delete(table.Names, key)
				table.Ambiguous[key] = struct{}{}
			}
			return
		}
		table.Names[key] = display
	}
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
			parentDevice := cfg.sessionParentDevice(ifName, tunMap)
			parentIdx := 0
			if parentDevice != "" {
				if idx, err := lookupIfindex(parentDevice); err == nil && idx > 0 {
					parentIdx = idx
				}
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
				display := sessionUnitDisplay(ifName, num, unit)
				vid := uint16(unit.VlanID)
				// Ingress form: {parent/bind ifindex, wire VID}.
				if parentIdx > 0 {
					claim(SessionIfaceKey{Ifindex: uint32(parentIdx), VlanID: vid}, display)
				}
				// Own-device form: {child/tunnel ifindex, wire VID}.
				ref := fmt.Sprintf("%s.%d", ifName, num)
				device := cfg.resolveKernelIfNameWith(ref, tunMap)
				if device == "" {
					continue
				}
				idx, err := lookupIfindex(device)
				if err != nil || idx <= 0 {
					continue
				}
				claim(SessionIfaceKey{Ifindex: uint32(idx), VlanID: vid}, display)
			}
		}
	}
	return table
}

// SessionIfaceNames returns just the agreed name map of
// SessionIfaceTableFor. Callers that match interface filters (show
// AND clear) should prefer SessionIfaceTableFor so a refused key is
// not broadened to the zone.
func SessionIfaceNames(cfg *Config, lookupIfindex func(string) (int, error)) map[SessionIfaceKey]string {
	return SessionIfaceTableFor(cfg, lookupIfindex).Names
}

// SharedSessionIfaceKey reports whether key is claimed by more than
// one distinct unit name in cfg under lookupIfindex — i.e. whether
// SessionIfaceTableFor refuses it. The claim comparison uses the
// DISPLAY name the table would store (untagged unit 0 as the bare
// interface name, tagged unit 0 as ".0"). It exists for tests and
// diagnostics; production consumers read the table's Ambiguous set.
func SharedSessionIfaceKey(cfg *Config, lookupIfindex func(string) (int, error), key SessionIfaceKey) bool {
	return SessionIfaceTableFor(cfg, lookupIfindex).IsAmbiguous(key)
}

// SessionIfNamesByIfindex projects the session table onto the bare
// ifindex -> name shape the daemon's EventReader consumes (RT_FLOW /
// flow-export attribution, #15094): the VID is dropped, so an ifindex
// is named ONLY when every surviving key for it agrees on one display
// name and no key for it was refused. A shared TUN (wg0.0/wg0.1 at
// {20,0}, refused) therefore resolves nameless, and two units sharing
// an ifindex at different VIDs with different names likewise resolve
// nameless rather than naming an arbitrary sibling. Deterministic:
// disagreement is detected over the whole table, not by map order.
func SessionIfNamesByIfindex(cfg *Config, lookupIfindex func(string) (int, error)) map[uint32]string {
	table := SessionIfaceTableFor(cfg, lookupIfindex)
	out := make(map[uint32]string)
	refused := make(map[uint32]struct{})
	for key := range table.Ambiguous {
		refused[key.Ifindex] = struct{}{}
	}
	for key, name := range table.Names {
		if _, bad := refused[key.Ifindex]; bad {
			continue
		}
		if held, exists := out[key.Ifindex]; exists {
			if held != name {
				delete(out, key.Ifindex)
				refused[key.Ifindex] = struct{}{}
			}
			continue
		}
		out[key.Ifindex] = name
	}
	for idx := range refused {
		delete(out, idx)
	}
	return out
}

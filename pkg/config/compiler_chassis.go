package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// compiler_chassis.go compiles and strictly validates the #1956 bare-metal
// device-map subtree. The device-map binds host NICs (by stable identity —
// PCI bus address with permanent-MAC fallback) to xpf logical names and
// governs everything not named via unmapped-interface-policy. The compile
// is independent of `chassis cluster` (R-7): a standalone box has a
// device-map but no cluster.

// compileDeviceMap converts the parsed `chassis device-map` subtree into a
// typed *DeviceMapConfig. Returns nil only when the subtree carries no
// usable content (so an empty/garbage block does not force device-map mode;
// the Active() predicate keys on len(Entries) > 0 anyway — R-7/V-7).
func compileDeviceMap(node *Node) *DeviceMapConfig {
	dm := &DeviceMapConfig{}

	if n := node.FindChild("unmapped-interface-policy"); n != nil {
		if v := nodeVal(n); v != "" {
			dm.UnmappedPolicy = v
		}
	}

	for _, inst := range bracketedGroupInstances8794(node.FindChildren("interface")) {
		entry := DeviceMapEntry{LogicalName: inst.name}
		props := map[string]string{}
		collectDeviceMapProps(inst.node, props)
		entry.PCIAddr = strings.ToLower(props["pci"])
		// Normalize the MAC to canonical colon-lowercase so it matches the
		// kernel's PermHWAddr formatting at resolve time regardless of the
		// committed spelling (net.ParseMAC also accepts aa-bb-.. and
		// aabb.ccdd.eeff) — AGY HIGH-1. A malformed MAC was already rejected
		// by ValidateMAC at commit; here we keep the raw value if parsing
		// fails (lenient path) so the resolver's miss is at worst UNBOUND.
		entry.MAC = normalizeMAC(props["mac"])
		entry.KeyOrder = props["key"]
		dm.Entries = append(dm.Entries, entry)
	}

	// Stable order so the map is deterministic across compiles (config
	// archive diffs, show output) regardless of AST iteration order.
	sort.Slice(dm.Entries, func(i, j int) bool {
		return dm.Entries[i].LogicalName < dm.Entries[j].LogicalName
	})

	if dm.UnmappedPolicy == "" && len(dm.Entries) == 0 {
		// Truly empty block — treat as absent (positional mode).
		return nil
	}
	return dm
}

// mergeDeviceMapConfigs13090 folds a later sibling `device-map` block's
// compiled content into dst (#13090): entries accumulate — the strict
// duplicate-logical-name gate (#6546) then sees cross-block duplicates and
// keeps them fatal — and a later block's unmapped-interface-policy
// supersedes an earlier one's, the leaf-level last-wins the #6543 fold uses.
// A block that compiles to nil (truly empty, R-7) contributes nothing. The
// merged entry list is re-sorted so archive diffs stay deterministic
// regardless of how the authoring split the blocks.
func mergeDeviceMapConfigs13090(dst, later *DeviceMapConfig) *DeviceMapConfig {
	if later == nil {
		return dst
	}
	if dst == nil {
		return later
	}
	dst.Entries = append(dst.Entries, later.Entries...)
	if later.UnmappedPolicy != "" {
		dst.UnmappedPolicy = later.UnmappedPolicy
	}
	sort.SliceStable(dst.Entries, func(i, j int) bool {
		return dst.Entries[i].LogicalName < dst.Entries[j].LogicalName
	})
	return dst
}

// collectDeviceMapProps walks a device-map `interface` instance subtree and
// records the pci/mac/key properties into props. It handles every AST shape
// the parser/SetPath produce:
//   - inline flat-set: a single line `interface ge-0/0/3 pci A mac B key C`
//     nests each prop under the previous (interface -> pci -> mac -> key),
//     each node Keys=[name, value];
//   - hierarchical: `interface ge-0/0/3 { pci A; mac B; }` — separate child
//     property nodes;
//   - inline-on-instance: extra tokens packed into the instance node's Keys.
//
// First value wins per property so a later malformed re-set cannot clobber a
// good one silently.
func collectDeviceMapProps(instNode *Node, props map[string]string) {
	// Scan inline Keys at EVERY node in the subtree: SetPath packs trailing
	// property tokens into the deepest leaf's Keys
	// (e.g. mac node Keys=[mac, <val>, key, mac-then-pci]), so a prop can
	// appear as Keys[i]==prop with its value at Keys[i+1] at any depth.
	var walk func(n *Node)
	walk = func(n *Node) {
		start := 0
		if n == instNode {
			start = 2 // skip "interface <name>"
		}
		for i := start; i+1 < len(n.Keys); i++ {
			if isDeviceMapProp(n.Keys[i]) {
				if _, ok := props[n.Keys[i]]; !ok {
					props[n.Keys[i]] = n.Keys[i+1]
				}
			}
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(instNode)
}

func isDeviceMapProp(s string) bool {
	return s == "pci" || s == "mac" || s == "key"
}

// normalizeMAC canonicalizes a MAC to colon-separated lower-case hex
// (the form the kernel reports for PermHWAddr), so the device-map resolver's
// string comparison matches regardless of the committed spelling. Returns the
// trimmed input unchanged if it does not parse as a 6-octet MAC (a malformed
// MAC is already rejected by ValidateMAC on the strict path; the lenient path
// leaves it as-is, yielding at worst an UNBOUND resolve, never a misbind).
func normalizeMAC(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return s
	}
	return hw.String() // net.HardwareAddr.String() is colon-lower-case
}

// validateDeviceMapStrict is the #1956 cross-entry commit-check validator.
// It runs ONLY on the strict compile path (commit / commit-check), so the
// lenient paths (Store.Load, peer SyncApply, display) DOWNGRADE these to
// warnings — load-bearing for HA, where node 0's strict commit cannot fail
// on node 1's section (different hardware) but node 1's SyncApply must not
// reject the whole sync (V-1). The node-local boot-time safety (mgmt
// lockout, live hardware presence) is enforced separately in the daemon's
// commit pre-flight (R-8) — this validator covers the purely structural
// invariants that hold without touching live sysfs.
func validateDeviceMapStrict(cfg *Config) error {
	dm := cfg.Chassis.DeviceMap
	if dm == nil || len(dm.Entries) == 0 {
		return nil
	}

	clusterMode := cfg.Chassis.Cluster != nil
	nodeID := 0
	if clusterMode {
		nodeID = cfg.Chassis.Cluster.NodeID
	}

	// Build the RETH-member set so a key-mac override on a RETH member can
	// be rejected (R-6): a RETH member's MAC alternates physical<->virtual.
	// #14194: keyed by the CANONICAL Linux name, like the duplicate-name
	// check below (#6546). Keying on the raw declared spelling let a slash
	// RETH member paired with a dash device-map entry (or vice versa) miss
	// this lookup entirely, admitting `key mac` strict.
	rethMembers := make(map[string]bool)
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			rethMembers[LinuxIfName(ifc.Name)] = true
		}
	}

	// #6546: keyed by the CANONICAL Linux name, not the raw spelling.
	// `LinuxIfName` folds the Junos slash form onto the kernel dash form, so
	// `ge-0/0/3` and `ge-0-0-3` are two spellings of ONE interface — and the
	// raw-string comparison accepted both, letting a duplicate logical name
	// through the STRICT commit gate (not merely the tolerant one). The value
	// carries the raw first spelling alongside its identity so the error names
	// what the operator actually typed.
	type firstUse struct{ spelling, identity string }
	seenName := make(map[string]firstUse) // canonical Linux name -> first use
	seenPCI := make(map[string]string)    // pci addr -> first logical name
	seenMAC := make(map[string]string)    // mac -> first logical name

	for _, e := range dm.Entries {
		if e.LogicalName == "" {
			return fmt.Errorf("chassis device-map: entry with empty logical interface name")
		}
		// Duplicate logical name → FATAL (two NICs cannot both be ge-0/0/3).
		canonName := LinuxIfName(e.LogicalName)
		if prev, ok := seenName[canonName]; ok {
			if prev.spelling == e.LogicalName {
				return fmt.Errorf("chassis device-map: logical name %q is mapped twice "+
					"(first to %s); each logical name binds exactly one NIC",
					e.LogicalName, prev.identity)
			}
			return fmt.Errorf("chassis device-map: logical names %q and %q are the same "+
				"interface %q and are mapped twice (%q first to %s); each logical name "+
				"binds exactly one NIC — use one spelling",
				prev.spelling, e.LogicalName, canonName, prev.spelling, prev.identity)
		}
		seenName[canonName] = firstUse{spelling: e.LogicalName, identity: entryIdentityDesc(e)}

		// An entry must carry at least one identity key.
		if e.PCIAddr == "" && e.MAC == "" {
			return fmt.Errorf("chassis device-map: interface %q has neither a pci nor a "+
				"mac identity key — add `pci <addr>` (preferred) or `mac <addr>`",
				e.LogicalName)
		}

		// Duplicate PCI / duplicate MAC → FATAL (one NIC, two names).
		if e.PCIAddr != "" {
			if prev, ok := seenPCI[e.PCIAddr]; ok {
				return fmt.Errorf("chassis device-map: PCI address %s is bound to both %q "+
					"and %q — one NIC cannot be two interfaces", e.PCIAddr, prev, e.LogicalName)
			}
			seenPCI[e.PCIAddr] = e.LogicalName
		}
		if e.MAC != "" {
			macKey := strings.ToLower(e.MAC)
			if prev, ok := seenMAC[macKey]; ok {
				return fmt.Errorf("chassis device-map: MAC %s is bound to both %q and %q — "+
					"one NIC cannot be two interfaces", e.MAC, prev, e.LogicalName)
			}
			seenMAC[macKey] = e.LogicalName
		}

		// Key-order sanity: a mac-only key order needs a mac; a pci-only
		// key order needs a pci.
		switch e.EffectiveKeyOrder() {
		case DeviceMapKeyMAC:
			if e.MAC == "" {
				return fmt.Errorf("chassis device-map: interface %q sets `key mac` but has no "+
					"`mac` identity", e.LogicalName)
			}
		case DeviceMapKeyPCI:
			if e.PCIAddr == "" {
				return fmt.Errorf("chassis device-map: interface %q sets `key pci` but has no "+
					"`pci` identity", e.LogicalName)
			}
		}

		// R-6: RETH member must stay PCI-keyed (OriginalName= match); a
		// mac-leading key order is rejected. #14194: look up by the
		// canonical Linux name so dash/slash aliases hit the same member.
		if rethMembers[LinuxIfName(e.LogicalName)] {
			switch e.EffectiveKeyOrder() {
			case DeviceMapKeyMAC, DeviceMapKeyMACThenPCI:
				return fmt.Errorf("chassis device-map: interface %q is a RETH member; its MAC "+
					"alternates physical<->virtual, so it must be PCI-keyed (drop `key mac`/"+
					"`key mac-then-pci`)", e.LogicalName)
			}
			if e.PCIAddr == "" {
				return fmt.Errorf("chassis device-map: RETH member %q must be bound by `pci` "+
					"(its MAC is unreliable)", e.LogicalName)
			}
		}

		// V-6: generalized FPC/node alignment — in cluster mode EVERY
		// logical name whose FPC slot is set must align with the local
		// node-id, not just RETH members. ge-7/0/3 on node 0 would
		// silently misattribute to the peer.
		if clusterMode {
			if slot := InterfaceSlot(e.LogicalName); slot >= 0 {
				if SlotToNodeID(slot) != nodeID {
					return fmt.Errorf("chassis device-map: interface %q has FPC slot %d which "+
						"maps to node %d, but this device-map section is for node %d — use the "+
						"per-node groups (node%d) section or the right FPC slot",
						e.LogicalName, slot, SlotToNodeID(slot), nodeID, nodeID)
				}
			}
		}
	}

	// Validate the unmapped policy value (defense in depth; the schema
	// enum already gates the set path, but a hand-imported config or a
	// future caller could bypass it).
	switch dm.UnmappedPolicy {
	case "", DeviceMapPolicyLeaveAlone, DeviceMapPolicyManageDown:
	default:
		return fmt.Errorf("chassis device-map: unknown unmapped-interface-policy %q "+
			"(expected leave-alone or manage-down)", dm.UnmappedPolicy)
	}
	return nil
}

// entryIdentityDesc renders an entry's identity for diagnostics.
func entryIdentityDesc(e DeviceMapEntry) string {
	switch {
	case e.PCIAddr != "" && e.MAC != "":
		return fmt.Sprintf("pci %s / mac %s", e.PCIAddr, e.MAC)
	case e.PCIAddr != "":
		return "pci " + e.PCIAddr
	case e.MAC != "":
		return "mac " + e.MAC
	default:
		return "(no identity)"
	}
}

package config

import (
	"fmt"
	"net"
	"sort"
	"strconv"
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
	//
	// #14685: consume each recognised pair (i += 2) instead of stepping
	// i++. The value of `key` is itself a prop keyword (`pci`/`mac`), so
	// stepping by one re-read that value as a property and captured the
	// following keyword as its address (`key pci pci 0000:01:00.0` ->
	// PCIAddr="pci", real address never recorded). Consuming the pair
	// keeps the scan aligned on keyword boundaries; an unrecognised token
	// still steps by one so a stray token cannot hide a later pair.
	var walk func(n *Node)
	walk = func(n *Node) {
		start := 0
		if n == instNode {
			start = 2 // skip "interface <name>"
		}
		for i := start; i+1 < len(n.Keys); {
			if isDeviceMapProp(n.Keys[i]) {
				if _, ok := props[n.Keys[i]]; !ok {
					props[n.Keys[i]] = n.Keys[i+1]
				}
				i += 2
				continue
			}
			i++
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

		// #14685: a present identity must be a well-formed address.
		// SchemaValidate gates operator commits, but direct CompileConfig
		// callers bypass it; without this a corrupted value such as
		// PCIAddr="pci" (the compact `key pci pci <addr>` mis-scan) is
		// non-empty and passed every check below, so the resolver
		// searched for a NIC literally named "pci". Reuse the schema
		// validators so strict compile and schema agree on the format.
		if e.PCIAddr != "" {
			if err := ValidatePCIAddr(e.PCIAddr); err != nil {
				return fmt.Errorf("chassis device-map: interface %q has an invalid pci identity: %w", e.LogicalName, err)
			}
		}
		if e.MAC != "" {
			if err := ValidateMAC(e.MAC); err != nil {
				return fmt.Errorf("chassis device-map: interface %q has an invalid mac identity: %w", e.LogicalName, err)
			}
		}

		// #14685: KeyOrder must be one of the schema enum values; an
		// unknown order silently fell through to the resolver default.
		switch e.KeyOrder {
		case "", DeviceMapKeyPCIThenMAC, DeviceMapKeyMACThenPCI, DeviceMapKeyPCI, DeviceMapKeyMAC:
		default:
			return fmt.Errorf("chassis device-map: interface %q has unknown key order %q "+
				"(expected pci-then-mac, mac-then-pci, pci, or mac)", e.LogicalName, e.KeyOrder)
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

// --- Chassis cluster compiler evicted from compiler_system.go (#16146):
// pure in-package code motion, unchanged call graph. ---

func compileChassis(node *Node, ch *ChassisConfig) error {
	// #1956 R-7/V-7: the device-map subtree compiles INDEPENDENTLY of
	// cluster — a sibling `device-map` must not be dropped on a standalone
	// (no-cluster) box. Compile it first, then fall through to cluster.
	//
	// #13090: the AST keeps sibling `device-map` blocks DISTINCT (brace
	// syntax, `load merge`), and the singular FindChild compiled only the
	// first — silently dropping every interface binding authored in a later
	// block, so a NIC fell back to the positional/unmapped policy. Fold
	// every block; cross-block duplicate logical names stay fatal through
	// the #6546 gate once both entries reach the compiled map.
	for _, dmNode := range node.FindChildren("device-map") {
		ch.DeviceMap = mergeDeviceMapConfigs13090(ch.DeviceMap, compileDeviceMap(dmNode))
	}

	// #6672: resolve the cluster body across all four spellings. A body packed
	// onto the `cluster` line — or onto the `chassis` line above it — carries
	// its statements on Keys with NO children, so the FindChild reads below saw
	// an empty stanza and compiled nothing while the commit succeeded. The
	// container spelling returns the same node, untouched.
	clusterNode := normalizedClusterNode(node)
	if clusterNode == nil {
		return nil
	}

	ch.Cluster = &ClusterConfig{}

	if n := clusterNode.FindChild("cluster-id"); n != nil {
		if v := nodeVal(n); v != "" {
			if id, err := strconv.Atoi(v); err == nil {
				ch.Cluster.ClusterID = id
			}
		}
	}
	if n := clusterNode.FindChild("node"); n != nil {
		if v := nodeVal(n); v != "" {
			if id, err := strconv.Atoi(v); err == nil {
				ch.Cluster.NodeID = id
				// Mark the leaf as explicitly present so the node-identity
				// cross-check (#4185) can tell "node 0" from an absent leaf.
				ch.Cluster.NodeIDSet = true
			}
		}
	}
	if rcNode := clusterNode.FindChild("reth-count"); rcNode != nil {
		if v := nodeVal(rcNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ch.Cluster.RethCount = n
			}
		}
	}
	if n := clusterNode.FindChild("heartbeat-interval"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.HeartbeatInterval = ms
			}
		}
	}
	if n := clusterNode.FindChild("heartbeat-threshold"); n != nil {
		if v := nodeVal(n); v != "" {
			if cnt, err := strconv.Atoi(v); err == nil {
				ch.Cluster.HeartbeatThreshold = cnt
			}
		}
	}
	if clusterNode.FindChild("control-link-recovery") != nil {
		ch.Cluster.ControlLinkRecovery = true
	}
	// #7441: node-local strict session-auth posture. A bare flag leaf, like
	// control-link-recovery above; its runtime meaning is in pkg/cluster.
	if clusterNode.FindChild("strict-session-auth") != nil {
		ch.Cluster.StrictSessionAuth = true
	}
	// #4107: compile the cluster control-channel PSK into a Secret so it is
	// redacted on every render/log path (mirrors the IKE/interface/routing
	// Secret compile sites). nodeVal reads the raw leaf value; it is never
	// logged here.
	if n := clusterNode.FindChild("authentication-key"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlLinkAuthKey = NewSecret(v)
		}
	}
	// #6630: the additional ACCEPTED key that makes a rotation rolling. Same
	// Secret treatment; never signed with, only verified against.
	if n := clusterNode.FindChild("additional-authentication-key"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlLinkAuthKeyAlt = NewSecret(v)
		}
	}
	if n := clusterNode.FindChild("control-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.ControlInterface = v
		}
	}
	if n := clusterNode.FindChild("peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.PeerAddress = v
		}
	}
	if n := clusterNode.FindChild("fabric-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.FabricInterface = v
		}
	}
	if n := clusterNode.FindChild("fabric-peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.FabricPeerAddress = v
		}
	}
	if n := clusterNode.FindChild("fabric1-interface"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.Fabric1Interface = v
		}
	}
	if n := clusterNode.FindChild("fabric1-peer-address"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.Fabric1PeerAddress = v
		}
	}
	if clusterNode.FindChild("configuration-synchronize") != nil {
		ch.Cluster.ConfigSync = true
	}
	if clusterNode.FindChild("nat-state-synchronization") != nil {
		ch.Cluster.NATStateSync = true
	}
	if clusterNode.FindChild("ipsec-session-synchronization") != nil {
		ch.Cluster.IPsecSASync = true
	}
	if clusterNode.FindChild("dhcp-lease-synchronization") != nil {
		ch.Cluster.DHCPLeaseSync = true
	}
	if n := clusterNode.FindChild("reth-advertise-interval"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.RethAdvertiseInterval = ms
			}
		}
	}
	if clusterNode.FindChild("hitless-restart") != nil {
		ch.Cluster.HitlessRestart = true
	}
	if clusterNode.FindChild("no-reth-vrrp") != nil {
		ch.Cluster.NoRethVRRP = true
	}
	// Private RG election is the default — suppress RETH VRRP, elect over
	// control link only.  "no-private-rg-election" opts out (legacy VRRP).
	ch.Cluster.PrivateRGElection = true
	if clusterNode.FindChild("no-private-rg-election") != nil {
		ch.Cluster.PrivateRGElection = false
	}
	if n := clusterNode.FindChild("peer-fencing"); n != nil {
		if v := nodeVal(n); v != "" {
			ch.Cluster.PeerFencing = v
		}
	}
	if n := clusterNode.FindChild("takeover-hold-time"); n != nil {
		if v := nodeVal(n); v != "" {
			if ms, err := strconv.Atoi(v); err == nil {
				ch.Cluster.TakeoverHoldTime = ms
			}
		}
	}

	// #6543: redundancy-group instances are folded by CANONICAL id, not by
	// the spelling the operator wrote. `strconv.Atoi` maps `1`, `01`, `001`
	// and `+1` to the same int, and the AST keeps them as DISTINCT instances
	// (namedInstances yields one entry per node, and a repeated hierarchical
	// `redundancy-group 1 { ... }` block is two nodes as well). Appending one
	// record per instance therefore committed TWO *RedundancyGroup with
	// ID=1 — one carrying the operator's `node <n> priority <p>` map and one
	// with an EMPTY map.
	//
	// Everything downstream keys redundancy groups by the int id, so the
	// split was silently lossy: cluster.Manager.UpdateConfig's id-keyed
	// last-wins loop overwrote LocalPriority with the map-miss zero from
	// whichever record came second, so a node configured to win the election
	// at priority 200 ran RG 1 at priority 0. The #4880 priority-range gate
	// could not catch it either — it iterated the empty-map record and passed
	// vacuously, having nothing to range-check.
	//
	// Folding by canonical id yields exactly one record per id and replays
	// every instance's body into it through the same statement table, so the
	// merge is leaf-level last-wins — Junos `set` semantics — rather than a
	// whole record silently displacing another. First-appearance order of the
	// ids is preserved so the compiled slice stays deterministic.
	byID := make(map[int]*RedundancyGroup)
	for _, rgInst := range namedInstances(clusterNode.FindChildren("redundancy-group")) {
		rgID, err := strconv.Atoi(rgInst.name)
		if err != nil {
			// The AST identity gate reports this malformed token. On the
			// tolerant path, drop the whole instance rather than let the
			// Atoi failure's old zero default alias redundancy-group 0.
			continue
		}

		rg, ok := byID[rgID]
		if !ok {
			rg = &RedundancyGroup{
				ID:             rgID,
				NodePriorities: make(map[int]int),
			}
			byID[rgID] = rg
			ch.Cluster.RedundancyGroups = append(ch.Cluster.RedundancyGroups, rg)
		}

		// #6588: redundancyGroupBody, not .Children — the whole body may be
		// packed onto the instance's own Keys.
		// Dispatch through redundancyGroupStatements — the same table
		// isRedundancyGroupStatement is derived from, so the set of statements
		// compiled here and the set redundancyGroupBody splits a packed line at
		// are one thing rather than two that must be kept in step.
		for _, child := range redundancyGroupBody(rgInst.node) {
			if compile, ok := redundancyGroupStatements[child.Name()]; ok {
				compile(rg, child)
			}
		}
	}

	return nil
}

// monitorEntryNodes returns one node per MONITORED ENTRY carried by cfgNode —
// a redundancy-group `interface-monitor` statement or an ip-monitoring
// `inet` address list — across every spelling (#6588). `skip` is the number of
// leading Keys that name the statement itself rather than an entry.
//
// Two independent collapses have to be undone, and they compose:
//
//  1. PACKED statement. `interface-monitor ge-0/0/0 weight 255;` yields
//     Keys=["interface-monitor","ge-0/0/0","weight","255"] and NO children,
//     while `interface-monitor { ge-0/0/0 weight 255; }` yields
//     Keys=["interface-monitor"] with one child per entry. A flat `set` command
//     produces the CONTAINER shape. Reading only Children dropped the packed
//     spelling entirely — the original #6588 fail-open.
//
//     Tail and children are EITHER/OR here, not accumulated — the rule
//     namedInstances already applies. A tail means the statement IS one entry,
//     so its children are that entry's ATTRIBUTES:
//     `interface-monitor ge-0/0/0 { weight 255; }` must compile ONE monitor for
//     ge-0/0/0, not a second one named after its first attribute. (Accumulating
//     there mints a monitor for an interface literally called "weight".)
//
//  2. BRACKETED list. The lexer strips `[`/`]` (#2419), so
//     `interface-monitor [ ge-0/0/0 ge-0/0/1 ]` collapses N names onto ONE
//     node's Keys in EVERY spelling — packed, hierarchical container child, and
//     flat-set child alike. Taking only Keys[skip] compiled the FIRST name and
//     silently discarded the rest, which is the same failover fail-open one
//     monitor at a time. Each candidate's Keys are therefore SPLIT at entry
//     boundaries: a token that is not the `weight` keyword (or the value slot
//     reserved immediately after it) starts a new entry.
//
// The value slot reservation matters for the same reason it does in the #6524
// application walk: `weight` consumes exactly one following token even when
// that token spells something else, so a malformed `weight weight` cannot
// silently split into two entries. A malformed or duplicated weight is
// reported by validateMonitorWeightTokensAST, which derives its entries from
// THIS function so the gate and the compiler can never disagree.
//
// A candidate's children are attributes of every entry it produces. That is
// exact for the N==1 case (the only shape Junos renders) and lossless for the
// invented `[ a b ] { weight 255; }` — over-applying a weight adds demotion
// debt, the fail-SAFE direction, whereas dropping it silently is the failure
// mode this whole change exists to remove.
func monitorEntryNodes(cfgNode *Node, skip int) []*Node {
	var candidates []*Node
	if len(cfgNode.Keys) > skip {
		candidates = []*Node{{
			Keys:     cfgNode.Keys[skip:],
			Children: cfgNode.Children,
			IsLeaf:   cfgNode.IsLeaf,
			Line:     cfgNode.Line,
			Column:   cfgNode.Column,
		}}
	} else {
		candidates = cfgNode.Children
	}

	var entries []*Node
	for _, cand := range candidates {
		// Separate the entry NAMES from the `weight <n>` attribute tokens, then
		// give every name the candidate's full attribute run. The attributes are
		// candidate-scoped, NOT positional: a bracketed list with a trailing
		// inline weight applies that weight to every member, matching the
		// children-block spelling `[ a b ] { weight 255; }` and the fail-safe
		// rule documented above. Attaching it to the preceding name only (the
		// obvious reading, and what this function did when it was first written)
		// left `[ ge-0/0/0 ge-0/0/1 ] weight 255` with ge-0/0/0 at weight ZERO —
		// monitored but deducting nothing, so its link going down did not demote
		// the group. That was WORSE than master, which compiled one monitor at
		// 255 and dropped the rest.
		var names, attrs []string
		for i := 0; i < len(cand.Keys); {
			tok := cand.Keys[i]
			if isMonitorAttrKeyword(tok) && len(names) > 0 {
				// Reserve the value slot: the keyword consumes exactly one
				// following token even when that token spells a name.
				attrs = append(attrs, tok)
				if i+1 < len(cand.Keys) {
					attrs = append(attrs, cand.Keys[i+1])
					i += 2
					continue
				}
				i++
				continue
			}
			names = append(names, tok)
			i++
		}
		for _, name := range names {
			keys := make([]string, 0, 1+len(attrs))
			keys = append(keys, name)
			keys = append(keys, attrs...)
			entries = append(entries, &Node{
				Keys:     keys,
				Children: cand.Children,
				IsLeaf:   cand.IsLeaf,
				Line:     cand.Line,
				Column:   cand.Column,
			})
		}
	}
	return entries
}

// monitorWeightKeyword is the weight attribute a monitored entry carries. It is
// named so monitorEntryNodes and validateMonitorWeightTokensAST cannot drift
// apart from the compiler's reader.
const monitorWeightKeyword = "weight"

// isMonitorAttrKeyword reports whether tok opens a per-entry attribute
// (keyword + one value token) rather than a new entry name. `weight` is the
// historical attribute; #15038 adds the ip-monitoring probe binding
// (`interface`, `secondary-ip-address`). Without reserving their value
// slots, a packed target shredded into one phantom entry per token.
func isMonitorAttrKeyword(tok string) bool {
	switch tok {
	case monitorWeightKeyword, "interface", "secondary-ip-address":
		return true
	}
	return false
}

// monitorWeightTokens returns every `weight` VALUE an entry carries, across
// both locations the value can occupy (#6588):
//
//   - inline on the entry's own Keys — `ge-0/0/0 weight 255`
//   - as a child leaf              — `ge-0/0/0 { weight 255; }`
//
// Callers take the FIRST token, so the compiled weight is the same regardless
// of spelling. Before #6588 the two locations disagreed on which duplicate
// won: the inline scan overwrote (last wins) while FindChild returned the
// first, so `weight 100 weight 200` compiled to 200 inline but 100 in a block.
// Returning every token also lets the AST gate REJECT a duplicate rather than
// silently pick one, which is what makes the answer spelling-independent.
//
// A `weight` keyword with no following token yields an empty-string entry, so
// the gate reports it as malformed rather than the caller treating it as absent.
func monitorWeightTokens(entry *Node) []string {
	var out []string
	for i := 1; i < len(entry.Keys); i++ {
		if entry.Keys[i] != monitorWeightKeyword {
			continue
		}
		if i+1 < len(entry.Keys) {
			out = append(out, entry.Keys[i+1])
			i++
			continue
		}
		out = append(out, "")
	}
	for _, c := range entry.Children {
		if len(c.Keys) > 0 && c.Keys[0] == monitorWeightKeyword {
			out = append(out, nodeVal(c))
		}
	}
	return out
}

// packedStatementProps returns one node per PROPERTY carried by a statement
// whose body is a set of named properties rather than a list of monitored
// entries — `ip-monitoring` (#6588). `skip` names the statement itself and
// isProp reports whether a token opens a new property.
//
//	ip-monitoring { global-weight 255; family inet 10.0.1.1 weight 100; }
//	  -> Keys=["ip-monitoring"], one child per property (returned as-is)
//	ip-monitoring global-weight 255;
//	  -> Keys=["ip-monitoring","global-weight","255"], no children
//	     -> one synthetic property node ["global-weight","255"]
//
// This is deliberately NOT monitorEntryNodes: there every non-attribute token
// opens an entry, which would shred `global-weight 255` into two. Here the tail
// is split only at recognized property keywords, so a property's value tokens
// stay with it. Both a packed tail and real children are returned when both
// exist — properties are siblings, so nothing is lost either way (unlike a
// monitored entry, where children are that entry's attributes).
func packedStatementProps(cfgNode *Node, skip int, isProp func(string) bool) []*Node {
	return packedStatementPropsArity(cfgNode, skip, isProp, nil)
}

// packedStatementPropsArity is packedStatementProps with a VALUE-SLOT contract
// (#6665).
//
// THE DEFECT. The plain splitter applies isProp to every token in the tail with
// no positional state at all, so a registered keyword opens a new statement
// WHEREVER it appears — including where a value is expected. An interface whose
// name spells a statement keyword is therefore consumed as that statement:
//
//	packed:    redundancy-group 1 interface-monitor ip-monitoring weight 255;
//	             -> InterfaceMonitors=[]  IPMonitoring=&{}
//	container: redundancy-group 1 { interface-monitor ip-monitoring weight 255; }
//	             -> InterfaceMonitors=[{ip-monitoring 255}]  IPMonitoring=nil
//
// The monitor is dropped AND an unrelated statement is fabricated, and the two
// spellings of one config compile differently. `pkg/cluster` then ranges an
// empty InterfaceMonitors, so the redundancy group accrues no link-down debt and
// never demotes — the failure `assertSingleMonitor` exists to name.
//
// It is sticky: configstore persists the TREE and re-emits a packed leaf as the
// same packed line, so it survives `show configuration`, reboot and HA peer
// sync. Authored once, wrong forever.
//
// THE FIX IS #6658'S OWN SHAPE, one level up. monitorEntryNodes already reserves
// a value slot — "`weight` consumes exactly one following token even when that
// token spells a name" — for exactly this class. `arity` lifts that contract to
// the statement splitter: a keyword that takes an argument consumes the next
// token unconditionally, so the token in its value slot cannot re-arm the
// splitter.
//
// A nil arity is the pre-#6665 behaviour, kept for the ip-monitoring caller
// whose sub-keywords have no name-shaped value slot.
//
// WHAT IT DOES NOT RESOLVE, stated rather than implied: `interface-monitor` is
// variadic, so only its FIRST token is protected. `interface-monitor ge-0/0/0
// preempt;` still reads `preempt` as a statement — which is also what the
// container form does, so the two spellings agree, which is the property under
// repair. There is no local information that distinguishes "a second monitor
// named preempt" from "no more monitors, then preempt", and inventing one would
// break the multi-statement packing #6588 pins.
func packedStatementPropsArity(
	cfgNode *Node,
	skip int,
	isProp func(string) bool,
	arity func(string) int,
) []*Node {
	var props []*Node
	if len(cfgNode.Keys) > skip {
		var cur *Node
		pending := 0 // value tokens the open statement must still absorb
		for _, tok := range cfgNode.Keys[skip:] {
			if pending > 0 {
				pending--
				cur.Keys = append(cur.Keys, tok)
				continue
			}
			if cur == nil || isProp(tok) {
				cur = &Node{Keys: []string{tok}, Line: cfgNode.Line, Column: cfgNode.Column}
				props = append(props, cur)
				if arity != nil {
					pending = arity(tok)
				}
				continue
			}
			cur.Keys = append(cur.Keys, tok)
		}
	}
	return append(props, cfgNode.Children...)
}

// redundancyGroupStatementArity is how many tokens a redundancy-group statement
// consumes as its VALUE before the splitter may open another statement (#6665).
//
// Derived from the grammar the compilers actually read, and deliberately only
// for the statements whose value slot can hold a free-form identifier or a
// number. `preempt`, `strict-vip-ownership`, and
// `allow-degraded-routing-takeover` take nothing, so the token after them
// genuinely does open a statement.
func redundancyGroupStatementArity(tok string) int {
	switch tok {
	case "interface-monitor":
		// `<ifname>` — the one free-form identifier slot in the whole stanza,
		// and therefore the only slot a keyword can be stolen out of.
		return 1
	case "node", "gratuitous-arp-count":
		// `<node-id>` / `<count>` — numeric, so a keyword here is already
		// rejected by the #5694 identity gate rather than silently stolen; the
		// reservation makes that a parse-time fact instead of a downstream one.
		return 1
	}
	return 0
}

// redundancyGroupBody returns the body statements of one `redundancy-group`
// instance across both spellings (#6588). It is the ONE-LEVEL-UP twin of the
// packing this file already undoes inside the body — and is itself one level
// BELOW the `chassis cluster` body, where the same shape dropped the entire
// cluster stanza (#6672, compiler_chassis_cluster_packed.go). The two splitters
// interact on exactly one token: `node` is both a cluster statement and a
// redundancy-group statement, so the cluster splitter must NOT re-arm on it
// inside a group's tail or this function never sees the priority it exists to
// preserve:
//
//	redundancy-group 1 { interface-monitor ge-0/0/0 weight 255; }
//	  -> Keys=["redundancy-group","1"], one child per statement
//	redundancy-group 1 interface-monitor ge-0/0/0 weight 255;
//	  -> Keys=["redundancy-group","1","interface-monitor","ge-0/0/0","weight","255"],
//	     NO children — the whole body is packed onto the instance's own Keys
//
// namedInstances resolves the instance NAME across both shapes (it reads
// Keys[1]), but hands back the node with the body still on Keys, so a caller
// that then walks `.Children` sees an EMPTY redundancy group. Every statement
// was silently dropped while `commit` succeeded: not just the monitors, but
// `node <id> priority <p>` — the election priority itself. The operator sets a
// priority, `show configuration` echoes it, and the cluster elects on defaults,
// so the WRONG NODE can hold the group. That is a superset of "the group never
// demotes".
//
// The split is at recognized redundancy-group statement keywords, so a tail
// carrying several statements (`node 0 priority 200 preempt;`) yields one node
// each rather than swallowing the trailing ones. Both a packed tail and real
// children are returned: RG statements are siblings, so nothing is lost if a
// config somehow carries both.
//
// Deliberately NOT fixed inside namedInstances itself. That helper has 130 call
// sites, and 24 of them already read the packed tail off `inst.node.Keys`
// themselves; synthesizing a child there double-feeds those readers. Measured,
// not assumed — making namedInstances synthesize breaks
// TestDHCPRelayOverrides_* (the override tokens get swallowed into Interfaces)
// and TestVRRPTrackInterface_KeysPackedDuplicateStrictReject (lenient
// first-wins yields an empty TrackInterface). See the #6588 PR body for the
// experiment. Other one-sided namedInstances callers are tracked separately.
func redundancyGroupBody(rgNode *Node) []*Node {
	// namedInstances returns TWO different node shapes, and the number of
	// leading identity Keys differs between them:
	//
	//   len(child.Keys) >= 2  -> the node ITSELF, Keys[0]=="redundancy-group",
	//                            Keys[1]==<id>                        -> skip 2
	//   otherwise             -> a `sub` CHILD of a bare `redundancy-group { }`
	//                            container, whose Keys[0] IS the <id>  -> skip 1
	//
	// Keys[0] is an exact discriminator: the first shape is always reached
	// through FindChildren("redundancy-group"), so its Keys[0] is that keyword;
	// the second is a child of that container, so its Keys[0] is the instance
	// name and never the keyword. Using a fixed skip of 2 swallowed the
	// STATEMENT keyword on the second shape and opened a node named after a
	// value, which no switch arm matches — the same silent-nothing outcome,
	// including the dropped election priority, that this function exists to fix.
	skip := 1
	if rgNode.Name() == "redundancy-group" {
		skip = 2
	}
	return packedStatementPropsArity(
		rgNode, skip, isRedundancyGroupStatement, redundancyGroupStatementArity)
}

// redundancyGroupStatements is the SINGLE SOURCE OF TRUTH for what a
// `redundancy-group` body may contain: it is both the compiler's dispatch
// table and the token set redundancyGroupBody splits a packed instance line
// at (#6588).
//
// The two MUST agree. A statement the compiler honours but the splitter does
// not know is not a loud failure — on a packed line carrying more than one
// statement its tokens are appended to whichever statement precedes it, so it
// silently does nothing, while the SAME statement alone on a line still works.
// A developer therefore sees it work, and ships the fold bug.
//
// This was previously a hand-written token list checked by a test that parsed
// compileChassis's source and extracted its `case "..."` literals. That guard
// passed while the statement was still dropped in three ways: a case on a
// named CONSTANT rather than a string literal (the idiom this very file uses
// for monitorWeightKeyword), a statement handled by a helper called outside
// the switch, and a nested switch inside a `default:` arm. Modelling another
// program's source text is the wrong tool; deriving both consumers from one
// table removes the divergence by construction instead.
//
// Adding a statement means adding an entry here, which registers it with the
// splitter in the same edit.
//
// Be precise about what that does and does not guarantee, because an overstated
// invariant is how the next person concludes they need not think about it. The
// invariant is "ALL dispatch goes through this table", and it is made natural
// rather than enforced. Two of the three routes above are now closed by
// construction: a named-constant KEY registers exactly like a literal one, and
// there is no switch left to nest another inside. The third is not. Compiling a
// statement from ad-hoc code beside the lookup — without an entry here — still
// re-opens the fold bug (verified, not assumed).
//
// What changed for that third route is which act is the natural one. With the
// switch, adding a `case` WAS the idiomatic way to add a statement, and it
// diverged silently. Now the idiomatic way is a table entry, which is correct by
// construction, and diverging means putting ad-hoc dispatch beside a five-line
// loop whose only other content is this lookup — obvious in review rather than
// invisible. Demoted, not eliminated; Go offers no construct that would
// eliminate it.
//
// FOURTH ROUTE, opposite direction — the splitter OVER-matches. All three routes
// above are the table under-covering what the compiler honours: a statement is
// compiled but not registered, so its tokens fold into the neighbour. There is
// one more of the other shape, and an earlier version of this comment enumerated
// "three" as if that were the whole space. The splitter matches a registered
// keyword wherever the token appears in the tail, including where the token is a
// VALUE rather than a statement keyword, so a value spelled like a statement is
// STOLEN and compiled as that statement:
//
//	packed:    redundancy-group 1 interface-monitor ip-monitoring weight 255;
//	             -> InterfaceMonitors=[]  IPMonitoring=&{GlobalWeight:0 GlobalThreshold:0 Targets:[]}
//	container: redundancy-group 1 { interface-monitor ip-monitoring weight 255; }
//	             -> InterfaceMonitors=[{ip-monitoring 255}]  IPMonitoring=nil
//
// The two spellings disagree — precisely what splitting the packed line exists
// to prevent. (Measured, not reasoned: both lines above were compiled at THIS
// head. The example deliberately uses ip-monitoring, which still reaches no
// gate. An earlier version of this comment used `preempt`, and that spelling is
// now REJECTED at commit by the arity gate added later in this same PR —
// "preempt: takes no argument but carries [weight 255]" — so quoting it here
// would show output the compiler no longer produces. `node` is likewise caught,
// by the #5694 identity gate. Re-measure this block if either gate moves;
// a stale "measured" claim is how the next reader concludes the analysis was
// already done and stops checking.)
//
// FIXED in #6665, by exactly the move the paragraph that used to sit here said
// would be needed: the splitter is now position-aware. A statement that takes an
// argument reserves its value slot (redundancyGroupStatementArity), so the token
// in that slot cannot re-arm the splitter — the same "reserve the value slot"
// contract monitorEntryNodes already applied one level down for `weight`.
//
// Two claims that used to live here were wrong and are corrected rather than
// deleted, because both were load-bearing for the decision to defer:
//
//   - "no legal Junos interface name collides with any keyword". The reachability
//     argument was "no operator would do this", not "the system prevents it" —
//     and the system does NOT prevent it. `chassis device-map interface
//     <logical-name>` is gated by ValidateDeviceMapLogicalName
//     (schema_validators_devicemap.go), which accepts any non-empty,
//     whitespace-free, dot-free [a-zA-Z0-9-/] string. All six registered
//     keywords pass it. The predicate the old comment said did not exist does.
//
//   - "there is deliberately NO test asserting the divergence: it would pin the
//     wrong answer as correct". True while the divergence stood; the test that
//     belongs here asserts the packed and container spellings AGREE, using the
//     container form as the oracle, which pins the RIGHT answer without
//     hand-writing an expectation. That is
//     TestPackedRGDoesNotStealAKeywordFromTheValueSlot_6665.
//
// The residual, stated rather than implied: `interface-monitor` is variadic, so
// only its FIRST token is protected. `interface-monitor ge-0/0/0 preempt;` still
// reads `preempt` as a statement — and so does the container form, so the two
// spellings agree, which is the property under repair. No local information
// distinguishes "a second monitor named preempt" from "no more monitors, then
// preempt", and inventing one would break the multi-statement packing
// TestRedundancyGroupStatementsSurvivePackedLine_6588 pins.
var redundancyGroupStatements = map[string]func(rg *RedundancyGroup, child *Node){
	"node":                            compileRGNodePriority,
	"gratuitous-arp-count":            compileRGGratuitousARPCount,
	"preempt":                         compileRGPreempt,
	"strict-vip-ownership":            compileRGStrictVIPOwnership,
	"allow-degraded-routing-takeover": compileRGAllowDegradedRoutingTakeover,
	"interface-monitor":               compileRGInterfaceMonitors,
	"ip-monitoring":                   compileRGIPMonitoring,
}

// isRedundancyGroupStatement reports whether tok opens a statement in a
// `redundancy-group` body. Derived from the dispatch table, so it can never
// fall behind what compileChassis actually compiles.
func isRedundancyGroupStatement(tok string) bool {
	_, ok := redundancyGroupStatements[tok]
	return ok
}

// compileRGNodePriority compiles a `node` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGNodePriority(rg *RedundancyGroup, child *Node) {
	// node <id> priority <value>
	nodeID := 0
	v := nodeVal(child)
	if v == "" && len(child.Keys) >= 2 {
		// A quoted-empty identity has an explicit empty second key. The
		// AST identity gate reports it; never let it default to node 0.
		return
	}
	if v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			// The AST identity gate reports this malformed token. Do not
			// let its old zero default overwrite node 0's real priority.
			return
		}
		nodeID = n
	}
	// Look for "priority" in inline keys or children
	for i := 2; i < len(child.Keys)-1; i++ {
		if child.Keys[i] == "priority" {
			if n, err := strconv.Atoi(child.Keys[i+1]); err == nil {
				rg.NodePriorities[nodeID] = n
			}
		}
	}
	if priNode := child.FindChild("priority"); priNode != nil {
		if v := nodeVal(priNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				rg.NodePriorities[nodeID] = n
			}
		}
	}
}

// compileRGGratuitousARPCount compiles a `gratuitous-arp-count` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGGratuitousARPCount(rg *RedundancyGroup, child *Node) {
	if v := nodeVal(child); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rg.GratuitousARPCount = n
		}
	}
}

// compileRGPreempt compiles a `preempt` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGPreempt(rg *RedundancyGroup, child *Node) {
	rg.Preempt = true
}

// compileRGStrictVIPOwnership compiles a `strict-vip-ownership` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGStrictVIPOwnership(rg *RedundancyGroup, child *Node) {
	rg.StrictVIPOwnership = true
}

// compileRGAllowDegradedRoutingTakeover compiles the explicit override for a
// planned transfer whose dynamic routing evidence is unavailable.
func compileRGAllowDegradedRoutingTakeover(rg *RedundancyGroup, child *Node) {
	rg.AllowDegradedRoutingTakeover = true
}

// compileRGInterfaceMonitors compiles a `interface-monitor` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
func compileRGInterfaceMonitors(rg *RedundancyGroup, child *Node) {
	// monitorEntryNodes (#6588): the packed one-liner
	// `interface-monitor ge-0/0/0 weight 255;` carries the monitor
	// on the statement's OWN Keys and has no children at all, and a
	// bracketed `[ ge-0/0/0 ge-0/0/1 ]` collapses N monitors onto
	// one node's Keys in EVERY spelling.
	//
	// #15036: entries fold BY INTERFACE, last-wins. A re-weighted
	// monitor (`... ge-0/0/1 weight 100;` then `... ge-0/0/1 weight
	// 255;`, in any spelling) used to append a SECOND monitor, and
	// the two runtime consumers disagreed about which was live:
	// pollInterfaceMonitors applied the FIRST entry's weight on the
	// shared dampening key while reconcileMonitorDebtsLocked's
	// desired map took the LAST, so the group stayed primary behind
	// a dead link until an unrelated commit flipped the weight.
	// One compiled monitor per interface makes both read one weight.
	// The strict commit path rejects the duplicate outright
	// (validateChassisClusterStrict); this fold is what the tolerant
	// load / peer-sync path keeps (#1960 no-brick).
	seen := make(map[string]int, len(rg.InterfaceMonitors))
	for i, m := range rg.InterfaceMonitors {
		if m != nil {
			seen[m.Interface] = i
		}
	}
	for _, ifChild := range monitorEntryNodes(child, 1) {
		im := &InterfaceMonitor{
			Interface: ifChild.Name(),
		}
		// monitorWeightTokens reads both value locations
		// (`ge-0/0/0 weight 255` and `ge-0/0/0 { weight 255; }`)
		// and is FIRST-WINS, so the compiled weight no longer
		// depends on the spelling. A malformed or duplicated
		// weight is rejected/warned by
		// validateMonitorWeightTokensAST; here it leaves the
		// pre-existing 0 default.
		if toks := monitorWeightTokens(ifChild); len(toks) > 0 {
			if n, err := strconv.Atoi(toks[0]); err == nil {
				im.Weight = n
			}
		}
		if idx, dup := seen[im.Interface]; dup {
			rg.InterfaceMonitors[idx] = im
			continue
		}
		seen[im.Interface] = len(rg.InterfaceMonitors)
		rg.InterfaceMonitors = append(rg.InterfaceMonitors, im)
	}
}

// compileRGIPMonitoring compiles a `ip-monitoring` statement of a redundancy-group body.
// Registered in redundancyGroupStatements; body moved VERBATIM from the
// switch arm it replaced (#6588).
//
// #13090: statements ACCUMULATE. #6543 folds every `redundancy-group <id>`
// instance into one record and replays each body through this table, and a
// single body may carry more than one `ip-monitoring` statement. A fresh
// struct here (stored unconditionally below) wiped GlobalWeight,
// GlobalThreshold and every earlier Target, so a second block whose lone
// statement was `family inet <addr>` left the election running with
// GlobalWeight 0 — failover fail-open. Reuse the record so globals replay
// last-wins and Targets append, exactly like NodePriorities and
// InterfaceMonitors already fold.
func compileRGIPMonitoring(rg *RedundancyGroup, child *Node) {
	ipm := rg.IPMonitoring
	if ipm == nil {
		ipm = &IPMonitoring{}
	}
	// #6588: ip-monitoring installs redundancy-group demotion debt
	// through the same election path as interface-monitor, and it
	// packs the same way — `ip-monitoring global-weight 255;` and
	// `ip-monitoring family inet 10.0.1.1 weight 100;` are leaves
	// with no children.
	ipmEntries := packedStatementProps(child, 1, isIPMonitoringProp)
	if gwNode := findNamedNode(ipmEntries, "global-weight"); gwNode != nil {
		if v := nodeVal(gwNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ipm.GlobalWeight = n
			}
		}
	}
	if gtNode := findNamedNode(ipmEntries, "global-threshold"); gtNode != nil {
		if v := nodeVal(gtNode); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				ipm.GlobalThreshold = n
			}
		}
	}
	for _, familyNode := range ipmEntries {
		if familyNode.Name() != "family" {
			continue
		}
		// Compound key "family inet" vs nested family { inet { } }.
		// inetSkip is how many of inetNode's leading Keys name the
		// node itself rather than a monitored address, so a packed
		// target (`family inet 10.0.1.1 weight 100;`) is unpacked
		// from the right offset. Shared with the #6588 weight gate.
		inetNode, inetSkip := ipMonitoringInetNode(familyNode)
		if inetNode == nil {
			continue
		}
		for _, addrChild := range monitorEntryNodes(inetNode, inetSkip) {
			target := &IPMonitorTarget{
				Address: addrChild.Name(),
			}
			// Same FIRST-WINS dual-location weight read as the
			// interface-monitor arm above.
			if toks := monitorWeightTokens(addrChild); len(toks) > 0 {
				if n, err := strconv.Atoi(toks[0]); err == nil {
					target.Weight = n
				}
			}
			// #15038: `interface <unit>` / `secondary-ip-address <addr>`
			// bind the probe to a unit and give the non-primary a source
			// it actually holds. Read from BOTH locations (inline Keys and
			// child leaves) like the weight, first-wins.
			if v := ipMonitorTargetProp(addrChild, "interface"); v != "" {
				target.Interface = v
			}
			if v := ipMonitorTargetProp(addrChild, "secondary-ip-address"); v != "" {
				target.SecondaryIPAddress = v
			}
			ipm.Targets = append(ipm.Targets, target)
		}
	}
	rg.IPMonitoring = ipm
}

// ipMonitorTargetProp returns the first value of the named per-target
// ip-monitoring property (`interface` / `secondary-ip-address`) across both
// spellings: inline on the entry's Keys (`10.0.0.1 interface reth0.0`) and as
// a child leaf (`10.0.0.1 { interface reth0.0; }`). First-wins, mirroring
// monitorWeightTokens. Empty when absent.
func ipMonitorTargetProp(entry *Node, name string) string {
	for i := 1; i < len(entry.Keys); i++ {
		if entry.Keys[i] != name {
			continue
		}
		if i+1 < len(entry.Keys) {
			return entry.Keys[i+1]
		}
		return ""
	}
	for _, c := range entry.Children {
		if len(c.Keys) > 0 && c.Keys[0] == name {
			return nodeVal(c)
		}
	}
	return ""
}

// isIPMonitoringProp reports whether tok opens an `ip-monitoring` property.
func isIPMonitoringProp(tok string) bool {
	switch tok {
	case "global-weight", "global-threshold", "family":
		return true
	}
	return false
}

// ipMonitoringGlobalTokens returns every VALUE carried by the named
// `ip-monitoring` global property (`global-weight` / `global-threshold`) in a
// packedStatementProps result, in source order.
//
// This is the globals' counterpart to monitorWeightTokens, and exists for the
// same reason (#6588): compileRGIPMonitoring reads a global with
// findNamedNode + nodeVal, which is FIRST-WINS and silently leaves the 0
// default when the value is missing or fails Atoi. A malformed or duplicated
// global is therefore indistinguishable from `global-weight 0` in the compiled
// struct, so it has to be caught on the AST — and the gate must read the same
// token the compiler does or the two can disagree about which value won.
//
// That correspondence is exact rather than parallel: over the same props slice
// this walks the same nodes with the same name predicate in the same order and
// reads them with the same nodeVal, so
//
//	nodeVal(findNamedNode(props, name)) == ipMonitoringGlobalTokens(props, name)[0]
//
// whenever the property is present at all. The gate rejects len > 1, so where
// the compiler's first-wins pick is observable there is exactly one token and
// the two readers cannot pick differently. Pinned by
// TestIPMonitoringGlobalTokensMatchesCompilerRead_6588.
func ipMonitoringGlobalTokens(props []*Node, name string) []string {
	var out []string
	for _, n := range props {
		if len(n.Keys) > 0 && n.Keys[0] == name {
			out = append(out, nodeVal(n))
		}
	}
	return out
}

// findNamedNode returns the first node in nodes whose first key is name — the
// slice equivalent of Node.FindChild, for callers that must search a
// packedStatementProps result rather than a node's raw Children.
func findNamedNode(nodes []*Node, name string) *Node {
	for _, n := range nodes {
		if len(n.Keys) > 0 && n.Keys[0] == name {
			return n
		}
	}
	return nil
}

// validateBackupRouterDst (#2911, extended by #4808, #9820, #15780) rejects a
// `system backup-router` whose next-hop is malformed, IPv4-mapped, or
// whose ANY EXPLICIT `destination` is malformed or of a different address
// family than the next-hop.
//
// Runtime: pkg/daemon reconciles the backup-router through netlink as a
// config.ManagementVRFMultipathStaticProtocol route in management table 999
// with metric 250 (#14972) — one route per destination (#15780). An empty
// destination list defaults to the next-hop family (v6 → ::/0, v4 → 0.0.0.0/0).
// The route must be excluded when either operand is malformed or their
// families disagree so an unusable fallback is never acknowledged.
//
// Checks, in order:
//  1. next-hop must parse as an IP address at all (#4808).
//  2. next-hop must not be an IPv4-mapped IPv6 literal (#9820: product
//     restriction — a single fallback default that never resolves is a
//     silent lockout risk).
//  3. EACH EXPLICIT destination must parse as a CIDR prefix at all (#4808) —
//     net.ParseCIDR validates the whole token (mask included).
//  4. EACH EXPLICIT destination of a different address family than the
//     next-hop is rejected (#2911), once both sides are known to parse.
//
// Only EXPLICIT destinations are format/family checked. An empty
// destination list is left to #2907's next-hop-family-aware default (v6
// next-hop → ::/0, v4 → 0.0.0.0/0) and is never malformed or a mismatch.
//
// Family classification uses FRRAddrFamily (netip; IPv4-mapped IPv6 literals
// classify as v6), shared with the netlink route programmer.
//
// Strict (commit / commit-check): hard-reject on the first failing check,
// naming the offending value. Lenient (load / peer-sync): warn (accumulating
// across all applicable checks) so an already-persisted or peer-synced
// config an older binary accepted still boots (#1960 fail-closed-on-load
// class).

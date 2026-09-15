package config

import "strings"

// resolveDerivedConfig runs the P5 "cross-section derivations" phase of config
// compilation — the contiguous block of post-dispatch derivations extracted
// from compileExpanded as step 5 of the #4406 god-orchestrator decomposition
// (ps-review-011 / codex-173 #4).
//
// Unlike the pre-walk (P1) and gate phases (P6b/P7), this phase runs NO
// validation and returns NO error: it is a pure sequence of mutations that fold
// cross-section state into the compiled *Config now that every top-level
// section compiler (P4) has populated its own sub-struct. Each sub-step reads
// fields written by an EARLIER section compiler or an earlier sub-step here and
// writes derived fields that the LATER validation phases (P6a early-strict,
// P6b uniform gates, P7 tail) read. The block therefore mutates cfg in place
// and threads no warnings.
//
// Internal order is LOAD-BEARING — the sub-steps run in exactly this sequence
// (do NOT reorder or split them):
//
//  1. #4329 NodeID stamp — stamp the compiled cluster node identity from the
//     runtime node-id when the config carries a chassis-cluster stanza but no
//     explicit `node` leaf. MUST precede every NodeID-dependent derivation:
//     the fabric fixup (step 6, `SlotToNodeID(member) == cc.NodeID`) AND
//     validateDeviceMapStrict (later, in the P6b uniform gates) both read
//     cc.NodeID.
//  2. resolveBGPAutonomousSystem — resolve the BGP local-AS from
//     `routing-options autonomous-system` when `protocols bgp local-as` was
//     omitted; runs after the child loop so routing-options and
//     protocols/routing-instances are both populated.
//  3. lo0 filter extract — hoist the lo0 unit-0 input filter names into
//     SystemConfig for the host-inbound-filter machinery.
//  4. applyCoSInterfaceLevelBindings — fold interface-level CoS bindings into
//     each interface's configured logical units.
//  5. resolveCoSTrafficControlProfiles — resolve output-traffic-control-profile
//     bindings into each unit's per-unit shaper. MUST run AFTER the
//     interface-level fold (step 4) so an interface-level profile binding is
//     already present on each unit.
//  6. fabric member/interface fixup — resolve vSRX-style fab0/fab1
//     member-interfaces to the local node's member and auto-populate
//     FabricInterface/Fabric1Interface/Fabric1PeerAddress. Reads the NodeID
//     stamped in step 1.
//
// Behavior-preserving invariants (do NOT reorder relative to master): this
// phase runs AFTER the P4 section dispatch and BEFORE the P6a early-strict
// folds (validateDataplaneTypeStrict onward), so the derived fields the strict
// and uniform gates read are populated in the same order as the inline block it
// replaces. It is covered by the reusable golden-output gate in
// compile_golden_4406_test.go.
func resolveDerivedConfig(cfg *Config, opts compileOpts) {
	// #4329: stamp the compiled cluster node identity from the runtime
	// node-id (/etc/xpf/node-id, or the `-node-id` flag on `xpfd
	// check-config`) when the config carries a chassis-cluster stanza but no
	// explicit `chassis cluster node` leaf. A canonical vSRX chassis-cluster
	// config encodes node ownership in the FPC slot (ge-0/0/N=node0,
	// ge-7/0/N=node1) and runs the SAME flat config on both nodes with no
	// `node` leaf. Without this stamp, Cluster.NodeID sits at its zero default
	// on BOTH nodes, so every NodeID-dependent derivation resolves to the
	// node-0 member on node 1 — reth breaks on the secondary (RethToPhysical
	// reads NodeID at runtime), AND the compile-time fabric-member /
	// FabricInterface auto-detect below (SlotToNodeID(member) == cc.NodeID)
	// binds fab0/fab1 to the node-0 member. Stamping makes the compiled
	// identity reflect the node the config is compiled FOR, so BOTH reth and
	// fabric resolve to the LOCAL member on each node and the flat vSRX form
	// is a drop-in.
	//
	// This MUST run after the child loop (Cluster + interfaces are populated)
	// and BEFORE every NodeID-dependent derivation that follows: the fabric
	// fixup below and validateDeviceMapStrict later in the compile both read
	// cc.NodeID.
	//
	// Guards (all load-bearing):
	//   - opts.nodeAware && stampNodeID >= 0: only the node-aware entry
	//     (compileConfigForNodeWithOpts) sets these. The standalone
	//     CompileConfig path leaves nodeAware false, so single-node compiles
	//     are unchanged; a negative node-id (defensive) never stamps.
	//   - Cluster != nil: never fabricate a cluster stanza. A config-less HA
	//     node (node-id present but empty/no-cluster config — the EMPTY-config
	//     takeover in pkg/daemon/daemon.go) must keep Cluster == nil so the
	//     daemon's `haMode` / `Cluster != nil` gates do not flip on a config
	//     that has no cluster. A real reth/fabric config always carries a
	//     `chassis cluster` stanza, so this never suppresses a genuine fix.
	//   - !NodeIDSet: an explicit `chassis cluster node <id>` leaf is the
	//     operator's SSOT and must win — never clobber it. crossCheckNodeID
	//     (pkg/configstore) already rejects a leaf that disagrees with the
	//     runtime node-id, and the GROUPS form (groups node0/node1 each carry
	//     an explicit `node` leaf) is left bit-identical.
	if opts.nodeAware && opts.stampNodeID >= 0 &&
		cfg.Chassis.Cluster != nil && !cfg.Chassis.Cluster.NodeIDSet {
		cfg.Chassis.Cluster.NodeID = opts.stampNodeID
	}

	// #3870: resolve the BGP local-AS from `routing-options
	// autonomous-system` when `protocols bgp local-as` was omitted. Runs
	// after the child loop so both routing-options and protocols/
	// routing-instances are populated regardless of their order under root.
	resolveBGPAutonomousSystem(cfg)

	// Extract lo0 filter input from parsed interfaces into SystemConfig.
	if lo0 := cfg.Interfaces.Interfaces["lo0"]; lo0 != nil {
		if u0 := lo0.Units[0]; u0 != nil {
			cfg.System.Lo0FilterInputV4 = u0.FilterInputV4
			cfg.System.Lo0FilterInputV6 = u0.FilterInputV6
		}
	}

	// #4021: fold interface-level CoS bindings (`class-of-service interfaces
	// geX { scheduler-map M; ... }` with no `unit`) into the interface's
	// configured logical units. Runs after the child loop so both the
	// interface stanza (cfg.Interfaces) and class-of-service are populated
	// regardless of their order under root; a unit-level binding overrides
	// the interface-level one per knob (Junos precedence).
	applyCoSInterfaceLevelBindings(cfg)

	// #4315 (fable-167 F-2): resolve output-traffic-control-profile bindings
	// into each unit's per-unit shaper (shaping-rate + scheduler-map). Runs
	// AFTER the interface-level fold so an interface-level profile binding is
	// already present on each unit. Before modeling, the hierarchical
	// traffic-control-profile binding was silently dropped — a clean commit
	// with ZERO shaping; now the shaper actually materializes.
	resolveCoSTrafficControlProfiles(cfg)

	// Post-compilation fixup: resolve vSRX-style fabric member-interfaces.
	// For fab0/fab1 with fabric-options member-interfaces, resolve which member
	// belongs to the local node using FPC slot → node-id mapping (slot 0 → node0,
	// slot 7 → node1). Also auto-populate FabricInterface/Fabric1Interface when
	// not explicitly set in chassis cluster config.
	if cc := cfg.Chassis.Cluster; cc != nil {
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if !strings.HasPrefix(ifName, "fab") || len(ifc.FabricMembers) == 0 {
				continue
			}
			for _, member := range ifc.FabricMembers {
				slot := InterfaceSlot(member)
				if slot >= 0 && SlotToNodeID(slot) == cc.NodeID {
					ifc.LocalFabricMember = member
					break
				}
			}
		}
		// Auto-detect fabric interfaces from fab0/fab1 member-interfaces
		// when not explicitly configured via fabric-interface/fabric1-interface.
		// Only set if the local node has a member (LocalFabricMember resolved above).
		// Dual-fabric: if both fab0 and fab1 have local members, set both
		// FabricInterface and Fabric1Interface (#130).
		// Single-fabric: only one fab is local → FabricInterface only.
		if cc.FabricInterface == "" {
			if f0, ok := cfg.Interfaces.Interfaces["fab0"]; ok && f0.LocalFabricMember != "" {
				cc.FabricInterface = "fab0"
			} else if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.FabricInterface = "fab1"
			}
		}
		// Auto-detect secondary fabric: fab1 when primary is fab0 and fab1
		// also has a local member (dual-fabric topology).
		if cc.Fabric1Interface == "" && cc.FabricInterface == "fab0" {
			if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.Fabric1Interface = "fab1"
			}
		}
		// Auto-derive Fabric1PeerAddress from the fab1 interface's /30 or /31
		// address when not explicitly configured.
		if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress == "" {
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				if u0 := f1.Units[0]; u0 != nil {
					for _, addr := range u0.Addresses {
						if peer := peerFromPointToPoint(addr); peer != "" {
							cc.Fabric1PeerAddress = peer
							break
						}
					}
				}
			}
		}
	}

	// 7. #7490 DHCP-scope withholding — stamp, per zone, the interface refs
	// from which the ZONE-LEVEL `dhcp` / `bootp` authorization is withheld
	// because the interface runs a DHCP server or relay and not the firewall's
	// own client.
	//
	// MUST run LAST of the sub-steps here, and the reason is the lifeline set:
	// HostInboundLifelineSet reads Chassis.Cluster's control/fabric interface
	// names, and the fabric fixup in step 6 is what AUTO-POPULATES
	// FabricInterface / Fabric1Interface on a vSRX-style config that names them
	// only through fab0/fab1 member-interfaces. Stamping before step 6 would
	// classify a fabric interface as non-lifeline on exactly the configs that
	// use the canonical Junos spelling.
	//
	// It runs in this phase rather than in a validator because the P6/P7
	// advisories READ the stamp — the #6519 advisory has to distinguish a
	// zone-level token that still authorizes from one that no longer does —
	// and because every consumer of the resolution holds only a *ZoneConfig.
	stampZoneDHCPScopeWithheld(cfg)
	// #9821: per-zone override closure for InterfaceHostInboundOverride,
	// adjacent to the scope-withhold stamp for the same reason (the method
	// cannot take a *Config). Independent of it — order between the two
	// does not matter.
	stampResolvedInterfaceOverrides(cfg)
}

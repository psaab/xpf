package config

import (
	"fmt"
	"sort"
)

// RethVRRPGroupIDBase is the fixed offset CollectRethInstances
// (pkg/vrrp/vrrp.go) adds to a RETH interface's chassis-cluster
// redundancy-group id to derive the synthesized VRRP GroupID:
// `GroupID = RethVRRPGroupIDBase + rgID`. Duplicated here rather than
// imported — pkg/vrrp imports pkg/config, so pkg/config validators must
// stay free of the reverse dependency. Keep this constant in lockstep with
// the `100 + rgID` literal in pkg/vrrp/vrrp.go if that offset ever changes.
const RethVRRPGroupIDBase = 100

// MaxRethRedundancyGroupID is the largest chassis-cluster redundancy-group
// id a RETH interface may carry without its derived VRRP GroupID
// (RethVRRPGroupIDBase + rgID) overflowing the RFC 5798 VRID range
// (MinVRRPGroupID..MaxVRRPGroupID, #4573) once pkg/vrrp/instance.go
// truncates it onto the single wire VRID byte.
const MaxRethRedundancyGroupID = MaxVRRPGroupID - RethVRRPGroupIDBase // 155

// validateRethVRRPGroupIDStrict hard-rejects, at commit / commit-check, a
// RETH interface (`redundant-ether-options redundancy-group <id>`) whose id
// would push the derived VRRP GroupID (RethVRRPGroupIDBase + id) past the
// RFC 5798 VRID range 1..255 (#4826).
//
// The chassis-cluster redundancy-group id gate (validateChassisClusterStrict,
// MaxHeartbeatRedundancyGroupID) caps a redundancy-group id at 255 — that
// bound is the heartbeat wire format and has nothing to do with VRRP.
// CollectRethInstances (pkg/vrrp/vrrp.go) synthesizes a VRRP GroupID of
// 100+rgID for every RETH interface with VIPs in its redundancy group, so an
// rgID in 156..255 is a legal, committable chassis config that derives a
// VRRP GroupID of 256..355 — out of range for the VRID byte, but the
// explicit `vrrp-group <id>` gate (validateVRRPGroupIDStrict, #4573) only
// inspects the explicit `vrrp-group` instance slot, never this reth-derived
// one. pkg/vrrp/manager.go UpdateInstances defends the WIRE (it inspects the
// pre-truncation int and skips with a WARN, so there is no wrong-VRID
// advert on air) — but the config still commits cleanly and then silently
// loses VRRP for that whole redundancy group. This closes that gap the same
// way #4573 closed it for the explicit vrrp-group path.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientRethVRRPGroupID) so an
// already-persisted or peer-synced config still boots (#1960 no-brick); the
// pkg/vrrp/manager.go runtime range check independently refuses to
// advertise the out-of-range VRID, so a leniently-loaded bad rgID is
// bounded (WARN + skip), not a wrong-VRID advert.
func validateRethVRRPGroupIDStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Mirror CollectRethInstances' own early return: when the cluster
	// directly manages VIPs (no-reth-vrrp) or elects over the control link
	// only (private-rg-election), no reth-derived VRRP instance is ever
	// synthesized, so an overflowing rgID has no runtime consequence.
	if cc := cfg.Chassis.Cluster; cc != nil && !cc.UsesRethVRRP() {
		return nil
	}

	// Deterministic walk so the first-error commit-check message is stable
	// across map-ordered runs, matching the sibling strict validators.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		if ifc == nil || ifc.RedundancyGroup <= 0 {
			continue
		}
		if ifc.RedundancyGroup > MaxRethRedundancyGroupID {
			return fmt.Errorf("interface %s redundant-ether-options "+
				"redundancy-group %d is out of range 1..%d (a RETH "+
				"interface's VRRP GroupID is derived as %d+redundancy-group, "+
				"and the VRRP VRID is one wire byte, RFC 5798 §5.2.3; a "+
				"redundancy-group above %d pushes the derived VRID past 255, "+
				"and that RETH's VRRP instance is silently skipped at "+
				"runtime with only a WARN log) — renumber the "+
				"redundancy-group", name, ifc.RedundancyGroup,
				MaxRethRedundancyGroupID, RethVRRPGroupIDBase,
				MaxRethRedundancyGroupID)
		}
	}
	return nil
}

package config

import (
	"fmt"
	"sort"
)

// MaxHeartbeatRedundancyGroups is the largest number of chassis-cluster
// redundancy groups the HA heartbeat wire format can advertise. The
// heartbeat group-count field is a single byte
// (pkg/cluster/heartbeat.go marshalHeartbeatBody writes
// buf[8] = uint8(len(pkt.Groups))), so a 256th group would overflow the
// count to 0 while 256 records are still written — the count byte and the
// body desync and the peer mis-parses the group section. (The marshaler
// also indexes a fixed maxHeartbeatSize buffer, so ~293 groups panic on
// write.) 255 is the binding uint8 count limit.
const MaxHeartbeatRedundancyGroups = 255

// MaxHeartbeatRedundancyGroupID is the largest redundancy-group id the HA
// heartbeat wire format can carry. The per-group GroupID field is a single
// byte (pkg/cluster/heartbeat.go HeartbeatGroup.GroupID is uint8, populated
// via uint8(rg.GroupID) in heartbeat_manager.go buildHeartbeat), so an id
// above 255 truncates on the wire and two distinct redundancy groups would
// then collide on the same GroupID byte and corrupt peer election.
const MaxHeartbeatRedundancyGroupID = 255

// MaxRedundancyGroups is the number of redundancy-group SLOTS the dataplane can
// index, so the highest usable RG id is MaxRedundancyGroups-1.
//
// #8317: it lives HERE, not in pkg/dataplane, and that direction is the fix
// rather than an accident of where it was easiest to put. `pkg/dataplane`
// already imports `pkg/config` and the reverse would be an import cycle, so
// this is the only package both the commit gate and the map sizing can share.
// `dataplane.MaxRedundancyGroups` is now an ALIAS of this — not a second
// literal — which makes "the commit bound equals the array length" a
// compile-time identity instead of a test that has to be remembered.
//
// WHY THAT MATTERS AND NOT JUST THE BOUND. The value 16 was already written
// down, as the max_entries of the `rg_active` and `ha_watchdog` BPF arrays. It
// was simply never connected to the id an operator can type, so ids 16..255
// committed against arrays whose valid indices are 0..15. Measured: a BPF array
// with max_entries 16 accepts an update at key 15 and returns E2BIG
// ("key too big for map") at 16, 17 and 255. `Manager.UpdateRGActive` returns
// that error to its caller BEFORE recording the group or syncing HA state to
// the helper, so such an RG never activates — the reconcile loop retries it
// forever (#757) and the RG's RETH interfaces never forward.
//
// A second literal in this package would have re-created exactly the drift that
// produced the gap, so there is deliberately only one.
const MaxRedundancyGroups = 16

// MinRedundancyGroupNodePriority / MaxRedundancyGroupNodePriority bound a
// redundancy-group node priority (Junos vSRX 1..254). 0 is treated as unset
// (VRRP maps pri==0 to the default 100) and 255 is the RFC 5798 IP-owner
// reserved value; both are excluded. The schema `priority` leaf
// (schema_chassis.go ValidateInteger(1,254)) enforces this on the flat-set /
// expanded shape, but the packed hierarchical one-liner
// `node 0 priority <v>;` carries the value inside the node instance's own key
// tail, which the schema walker consumes as identity and never validates —
// compileChassis still reads it into NodePriorities under no bound (#4880). The
// value feeds VRRP, which truncates it to uint8 on the wire
// (pkg/vrrp/instance.go), while the private control-link election uses the raw
// int (pkg/cluster/group_state.go), so an out-of-range priority both truncates
// on the wire and diverges the two election views.
const (
	MinRedundancyGroupNodePriority = 1
	MaxRedundancyGroupNodePriority = 254
)

// ClampRedundancyGroupNodePriority bounds a configured redundancy-group node
// priority to [MinRedundancyGroupNodePriority, MaxRedundancyGroupNodePriority].
// It returns the effective priority and whether clamping occurred.
//
// #8597 (muse-004 K17). The sibling of ClampInterfaceMonitorWeight below, for
// the field the #4880 gate above bounds at commit and nothing bounded at
// runtime. The gate's own error text names both consumers — "the priority feeds
// VRRP and truncates to a single wire byte, and the private control-link
// election reads the raw value" — and the weight case already carries the
// matching runtime belt. The priority case did not.
//
// Reachability is the tolerant ingress, verified by execution rather than
// argued: a `redundancy-group 1 node 0 priority 65700` is rejected by
// CompileConfig with that message and compiles clean through
// CompileConfigLenient with NodePriorities[0] == 65700 intact.
//
// The consequence of leaving it unbounded is DUAL PRIMARY, not a wrong display
// number. buildHeartbeat put `uint16(rg.LocalPriority)` on the wire while
// election.go compared the raw int, so 65700 advertised as 164: against a peer
// at 200, the local node saw 65700 > 200 and elected itself, and the peer saw
// 200 > 164 and elected ITSELF. Two primaries, duplicate VIPs and duplicate
// RETH virtual MAC on the LAN.
//
// Clamping rather than refusing is deliberate, and for the wireRGID reason:
// declining to advertise a group leaves the peer with `peerGroup == nil`, which
// election.go turns into "peer has no RG info -> elect local primary" — the fix
// would reproduce the bug.
func ClampRedundancyGroupNodePriority(p int) (int, bool) {
	switch {
	case p < MinRedundancyGroupNodePriority:
		return MinRedundancyGroupNodePriority, true
	case p > MaxRedundancyGroupNodePriority:
		return MaxRedundancyGroupNodePriority, true
	default:
		return p, false
	}
}

// MinInterfaceMonitorWeight / MaxInterfaceMonitorWeight bound a
// redundancy-group `interface-monitor <if> weight <w>` (Junos vSRX 0..255 —
// the same range the schema already types on the sibling ip-monitoring
// weights, schema_chassis.go `global-weight` / `global-threshold` / per-target
// `weight`).
//
// #6549: the interface-monitor leaf packs `<ifname> weight <n>` onto ONE node
// key, so it has NO typed schema leaf (schema_chassis.go documents the
// deferral: typing it would need a children/wildcard map, which flips
// SetPath's replace-vs-container grouping) and compileChassis reads the weight
// with strconv.Atoi under no bound. The weight is the DEBT subtracted from the
// redundancy group's weight, which starts at 255
// (pkg/cluster/election.go recalcWeight: `rg.Weight = 255 - totalLost`, with
// only a `< 0` floor and no ceiling), so a NEGATIVE weight on a down monitor
// raises rg.Weight ABOVE 255.
//
// That is the divergence: the LOCAL election reads the raw wide int
// (EffectivePriority = priority * weight / 255, election.go), while the
// heartbeat advertises the same weight through a SINGLE BYTE
// (HeartbeatGroup.Weight is uint8, populated via `uint8(rg.Weight)` in
// heartbeat_manager.go buildHeartbeat). With `weight -100` on a down monitor
// the local node holds 355 and the peer receives uint8(355) == 99, so at base
// priority 100 the local node computes its own effective priority as 139 while
// the peer computes 38 for it. The two nodes then elect from DIFFERENT views of
// identical state and can both take primary — duplicate VIP and duplicate RETH
// virtual MAC on the LAN. Same failure shape (wide local int vs single wire
// byte) as the #4880 node-priority gate above.
//
// The runtime carries the matching belts: ClampInterfaceMonitorWeight bounds
// the configured debt where pkg/cluster reads it, and rgWeightFromDebt bounds
// rg.Weight itself to the same [0,255] domain at every recompute site, so a
// config that reaches the tolerant load / peer-sync path (where this gate is
// downgraded to a warning per #1960) still cannot diverge.
const (
	MinInterfaceMonitorWeight = 0
	MaxInterfaceMonitorWeight = 255
)

// ClampInterfaceMonitorWeight bounds a configured interface-monitor weight to
// [MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight]. It returns the
// effective weight and whether clamping occurred.
//
// The strict commit / commit-check path never needs this — validateChassisCluster
// Strict rejects an out-of-range weight outright. It exists for the TOLERANT
// paths (Store.Load of a persisted config, Store.SyncApply of a peer-pushed
// one), which downgrade that gate to a warning so an already-persisted config
// still BOOTS (#1960 no-brick). Without the clamp those paths would install the
// out-of-range debt verbatim and reproduce exactly the local-vs-wire divergence
// the gate exists to prevent. Mirrors ClampGratuitousARPCount (#5695): the
// commit path signals, the runtime bounds.
func ClampInterfaceMonitorWeight(w int) (int, bool) {
	switch {
	case w < MinInterfaceMonitorWeight:
		return MinInterfaceMonitorWeight, true
	case w > MaxInterfaceMonitorWeight:
		return MaxInterfaceMonitorWeight, true
	default:
		return w, false
	}
}

// validateChassisClusterStrict hard-rejects, at commit / commit-check, a
// chassis-cluster config whose redundancy-group cardinality or ids exceed
// what the HA heartbeat wire format can encode (#4434, codex-172 C172-H02),
// whose per-RG node priority is out of the VRRP range (#4880), whose RG0 has
// unsupported `preempt` configured (#10754), or whose interface-monitor weight
// (#6549) or ip-monitoring global-weight / global-threshold / per-target weight
// (#6588) is out of the [0,255] heartbeat weight domain.
//
// The heartbeat count byte and per-group id byte are both uint8. There is
// no schema-level value validation on the `redundancy-group <id>` instance
// slot (schema_chassis.go documents it as an unvalidated identity token),
// and compileChassis parses the id with strconv.Atoi under no bound, so an
// operator could commit 256+ groups (count byte wraps to 0 — the peer sees
// "zero groups" while the body still carries them) or a group id > 255 (the
// id byte truncates and aliases another group). Both silently corrupt
// election on the wire.
//
// On the tolerant load / peer-sync paths the compileExpanded call site
// downgrades this to a warning (opts.lenientChassisRG) so an already-
// persisted or peer-synced config still boots (#1960 no-brick); the
// heartbeat marshaler independently caps the group section to the wire
// limit (pkg/cluster/heartbeat.go marshalHeartbeatBody, maxHeartbeatGroups),
// so a leniently-loaded over-size config is bounded on the wire, not a
// panic.
func validateChassisClusterStrict(cfg *Config) error {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	// #6772: the dead-peer timeout is `time.Duration(threshold) * interval`
	// (pkg/cluster/heartbeat.go), and failover.go doubles it for the transfer
	// grace. Each field is individually bounded — interval by MaxDurationMillis,
	// threshold at >= 1 — but nothing bounded their PRODUCT, and time.Duration
	// is int64 nanoseconds.
	//
	// An overflowed product does not merely become large: it wraps NEGATIVE,
	// and a negative timeout reads as already-expired. The peer is declared
	// lost on the first check, on both nodes, which is the exact inversion of
	// the liveness guard the threshold exists to provide — the same failure
	// MaxDurationSeconds' comment describes for ip-monitoring hold-down.
	//
	// Checked as a PRODUCT rather than by capping threshold alone: a cap safe
	// at a 1 ms interval overflows at a large one, so any single-field bound
	// would be either useless or arbitrary. This rejects exactly the
	// combinations that cannot be represented.
	if err := validateHeartbeatTimeoutProduct(cfg.Chassis.Cluster); err != nil {
		return err
	}

	rgs := cfg.Chassis.Cluster.RedundancyGroups

	if len(rgs) > MaxHeartbeatRedundancyGroups {
		return fmt.Errorf("chassis cluster: %d redundancy-groups exceeds the "+
			"heartbeat wire limit of %d (the heartbeat group-count field is one "+
			"byte, so %d groups would advertise as a count of 0 and desync the "+
			"peer's group parse) — reduce the number of redundancy-groups",
			len(rgs), MaxHeartbeatRedundancyGroups, len(rgs))
	}

	// RedundancyGroups is built from a map-ordered AST walk; sort the ids so
	// the first-error commit-check message is deterministic across runs.
	ids := make([]int, 0, len(rgs))
	for _, rg := range rgs {
		if rg == nil { // #3494: tolerant/HA-sync path may carry a nil entry.
			continue
		}
		ids = append(ids, rg.ID)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if id < 0 || id > MaxHeartbeatRedundancyGroupID {
			return fmt.Errorf("chassis cluster: redundancy-group id %d is out of "+
				"range 0..%d (the heartbeat per-group id field is one byte; an id "+
				"above %d truncates on the wire and collides with another "+
				"redundancy-group) — renumber the redundancy-group",
				id, MaxHeartbeatRedundancyGroupID, MaxHeartbeatRedundancyGroupID)
		}
		// #8317: the SECOND ceiling on the same value, and until now the
		// unenforced one. The id is used directly as the index into the
		// dataplane's `rg_active` / `ha_watchdog` arrays, which hold
		// MaxRedundancyGroups entries, so an id at or above that length cannot
		// be written at all: the BPF update returns E2BIG and UpdateRGActive
		// propagates it before the group is recorded or synced to the helper.
		// The RG then never activates and its RETH interfaces never forward,
		// while the reconcile loop retries forever.
		//
		// Checked SECOND so the wire-truncation message still wins for an id
		// that violates both — it names the more surprising consequence
		// (a silent collision with another group) and renumbering fixes both.
		if id >= MaxRedundancyGroups {
			return fmt.Errorf("chassis cluster: redundancy-group id %d is out of "+
				"range 0..%d (the dataplane indexes its rg_active and ha_watchdog "+
				"arrays by this id and they hold %d entries; an id at or above %d "+
				"cannot be written, so the group would never activate and its reth "+
				"interfaces would never forward) — renumber the redundancy-group",
				id, MaxRedundancyGroups-1, MaxRedundancyGroups, MaxRedundancyGroups)
		}
	}

	// #4880: node-priority range gate. The schema `priority` leaf validates the
	// flat-set / expanded shape, but the packed hierarchical one-liner
	// `node 0 priority <v>;` bypasses the walker (see
	// MinRedundancyGroupNodePriority doc). compileChassis stores whatever the
	// operator wrote into NodePriorities, and it flows to VRRP (uint8-truncated
	// on the wire) and the private election (raw int) — so re-assert the
	// [1,254] range on the compiled priorities here, closing BOTH shapes.
	// Iterate rgs sorted by id, then node ids, so the first-error message is
	// deterministic across the map-ordered AST walk.
	rgByID := make([]*RedundancyGroup, 0, len(rgs))
	for _, rg := range rgs {
		if rg != nil { // #3494: tolerant/HA-sync path may carry a nil entry.
			rgByID = append(rgByID, rg)
		}
	}
	sort.Slice(rgByID, func(i, j int) bool { return rgByID[i].ID < rgByID[j].ID })
	for _, rg := range rgByID {
		if rg.ID == 0 && rg.Preempt {
			return fmt.Errorf("chassis cluster: redundancy-group 0 preempt is unsupported; " +
				"it can bypass the cold-boot peer wait — remove `preempt` from redundancy-group 0")
		}
		nodeIDs := make([]int, 0, len(rg.NodePriorities))
		for nodeID := range rg.NodePriorities {
			nodeIDs = append(nodeIDs, nodeID)
		}
		sort.Ints(nodeIDs)
		for _, nodeID := range nodeIDs {
			pri := rg.NodePriorities[nodeID]
			if pri < MinRedundancyGroupNodePriority || pri > MaxRedundancyGroupNodePriority {
				return fmt.Errorf("chassis cluster: redundancy-group %d node %d priority "+
					"%d is out of range %d..%d (0 is treated as unset and 255 is the "+
					"RFC 5798 IP-owner reserved value; the priority feeds VRRP and "+
					"truncates to a single wire byte, and the private control-link "+
					"election reads the raw value) — set a priority in %d..%d",
					rg.ID, nodeID, pri,
					MinRedundancyGroupNodePriority, MaxRedundancyGroupNodePriority,
					MinRedundancyGroupNodePriority, MaxRedundancyGroupNodePriority)
			}
		}

		// #6549: interface-monitor weight range gate. The leaf packs
		// `<ifname> weight <n>` onto one node key and has no typed schema leaf
		// at all (unlike the ip-monitoring weight siblings), so the range is
		// asserted here on the compiled int — which covers BOTH parser shapes
		// (flat-set and hierarchical) at once. Out of range, the debt makes
		// rg.Weight leave the [0,255] domain the single-byte heartbeat field
		// can carry, and the local election and the peer's view of it diverge
		// (see MinInterfaceMonitorWeight). InterfaceMonitors is an
		// AST-order slice (not a map), so the first-error message is already
		// deterministic without sorting.
		for _, im := range rg.InterfaceMonitors {
			if im == nil { // tolerant/HA-sync path may carry a nil entry (#3494).
				continue
			}
			if im.Weight < MinInterfaceMonitorWeight || im.Weight > MaxInterfaceMonitorWeight {
				return fmt.Errorf("chassis cluster: redundancy-group %d interface-monitor %s "+
					"weight %d is out of range %d..%d (the weight is subtracted from the "+
					"redundancy-group weight, which the heartbeat advertises through a single "+
					"wire byte while the local election reads the raw value — an out-of-range "+
					"weight makes the two nodes compute different effective priorities from "+
					"identical state and both elect primary) — set a weight in %d..%d",
					rg.ID, im.Interface, im.Weight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight)
			}
		}

		// #6588: the SAME compiled-int gate for the ip-monitoring weights.
		// They carry a typed schema leaf (schema_chassis.go
		// ValidateInteger(0,255)), which is why #6549 left them to it — but
		// SchemaValidate walks the AST from setSchema and a PACKED statement
		// (`ip-monitoring family inet 10.0.1.1 weight -100;`) sits BELOW the
		// depth that walk reaches, so the typed leaf never fires on it. Before
		// #6588 that was harmless because the packed spelling compiled to
		// nothing at all; now that it compiles, an out-of-range packed weight
		// would reach the runtime with no commit-side gate on ANY path.
		// Asserting the range here — on the compiled int, exactly where the
		// interface-monitor gate above lives — makes all three spellings
		// (flat-set, container-hierarchical, packed) converge on one answer.
		//
		// The domain is the same one and for the same reason: an ip-monitoring
		// weight is demotion DEBT subtracted from the redundancy-group weight,
		// which the heartbeat advertises through a single wire byte while the
		// local election reads the raw int. A negative weight is worse here
		// than for interface-monitor: in global-threshold mode it SUBTRACTS
		// from the cumulative failure sum, so a second genuinely unreachable
		// target pushes the sum back BELOW the threshold and drops the debt the
		// first failure installed — more failures produce LESS demotion.
		if ipm := rg.IPMonitoring; ipm != nil {
			if ipm.GlobalWeight < MinInterfaceMonitorWeight || ipm.GlobalWeight > MaxInterfaceMonitorWeight {
				return fmt.Errorf("chassis cluster: redundancy-group %d ip-monitoring "+
					"global-weight %d is out of range %d..%d (the weight is subtracted from "+
					"the redundancy-group weight, which the heartbeat advertises through a "+
					"single wire byte while the local election reads the raw value) — set a "+
					"global-weight in %d..%d",
					rg.ID, ipm.GlobalWeight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight)
			}
			if ipm.GlobalThreshold < MinInterfaceMonitorWeight || ipm.GlobalThreshold > MaxInterfaceMonitorWeight {
				return fmt.Errorf("chassis cluster: redundancy-group %d ip-monitoring "+
					"global-threshold %d is out of range %d..%d (the threshold is compared "+
					"against the cumulative failure weight, which shares the single-byte "+
					"heartbeat weight domain) — set a global-threshold in %d..%d",
					rg.ID, ipm.GlobalThreshold,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight,
					MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight)
			}
			// Targets is an AST-order slice, so the first-error message is
			// already deterministic without sorting.
			for _, tgt := range ipm.Targets {
				if tgt == nil { // tolerant/HA-sync path may carry a nil entry (#3494).
					continue
				}
				if tgt.Weight < MinInterfaceMonitorWeight || tgt.Weight > MaxInterfaceMonitorWeight {
					return fmt.Errorf("chassis cluster: redundancy-group %d ip-monitoring "+
						"family inet %s weight %d is out of range %d..%d (the weight is "+
						"subtracted from the redundancy-group weight, and in global-threshold "+
						"mode a negative weight cancels a sibling target's real failure so more "+
						"failures produce LESS demotion) — set a weight in %d..%d",
						rg.ID, tgt.Address, tgt.Weight,
						MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight,
						MinInterfaceMonitorWeight, MaxInterfaceMonitorWeight)
				}
			}
		}
	}
	return nil
}

// validateHeartbeatTimeoutProduct rejects a heartbeat interval/threshold pair
// whose dead-peer timeout cannot be represented as a time.Duration (#6772).
//
// The runtime computes `time.Duration(threshold) * interval` and, for the
// transfer grace, `2 * time.Duration(threshold) * interval + slack`. The
// doubled form is checked because it overflows FIRST, so a pair that passes the
// plain timeout can still invert the grace.
//
// Zero means "use the default" for both fields at runtime, so a zero is left
// alone here rather than substituted — the defaults are small and cannot
// overflow, and substituting them would make this validator disagree with the
// runtime about what the config says.
// DefaultHeartbeatIntervalMillis and DefaultHeartbeatThreshold mirror the
// runtime's substitutions for an unset heartbeat field
// (cluster.DefaultHeartbeatInterval / cluster.DefaultHeartbeatThreshold).
//
// They are duplicated rather than imported because pkg/cluster imports
// pkg/config, so the dependency cannot run the other way. The duplication is
// bound by an agreement test in pkg/cluster, which CAN see both — a divergence
// here is always a bug, so it is asserted rather than trusted.
const (
	DefaultHeartbeatIntervalMillis = int64(100)
	DefaultHeartbeatThreshold      = int64(5)
)

func validateHeartbeatTimeoutProduct(cc *ClusterConfig) error {
	if cc == nil {
		return nil
	}
	interval, threshold := int64(cc.HeartbeatInterval), int64(cc.HeartbeatThreshold)
	// An unset field is not "no value" — the runtime substitutes its own
	// default (group_state.go only assigns when > 0), so an unset interval
	// paired with a huge threshold still overflows at run time. Model what the
	// runtime does rather than skipping: skipping accepted exactly that pair.
	if interval <= 0 {
		interval = DefaultHeartbeatIntervalMillis
	}
	if threshold <= 0 {
		threshold = DefaultHeartbeatThreshold
	}
	// Work in milliseconds and compare against the ms-denominated ceiling, so
	// the check itself cannot overflow while testing for overflow.
	if threshold > MaxDurationMillis/(2*interval) {
		return fmt.Errorf("chassis cluster: heartbeat-threshold %d with "+
			"heartbeat-interval %dms yields a dead-peer timeout that overflows "+
			"time.Duration (int64 nanoseconds) and wraps NEGATIVE — a negative "+
			"timeout reads as already-expired, so both nodes declare the peer "+
			"lost on the first check, inverting the liveness guard the threshold "+
			"exists to provide. Reduce heartbeat-threshold or heartbeat-interval "+
			"(the product, doubled for the failover transfer grace, must stay "+
			"under %dms)",
			threshold, interval, MaxDurationMillis)
	}
	return nil
}

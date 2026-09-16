package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// Keep logical-only synthetic ifindexes in a high private range so they do
// not collide with kernel-assigned ifindexes in practical deployments, while
// remaining positive int32 values for protocol compatibility.
//
// These bounds are package vars (not consts) ONLY so a test can temporarily
// shrink the window to drive the range-exhaustion path through the real
// buildInterfaceSnapshots caller (#5557); production never mutates them and the
// initial values are identical to the pre-#5557 constants.
var (
	syntheticInterfaceIfindexMin = 1 << 30
	syntheticInterfaceIfindexMax = (1 << 30) + (1 << 20) - 1
)

// syntheticIfindexExhausted is the sentinel syntheticLogicalIfindex returns
// when the whole synthetic range is already claimed. It is a negative value so
// it can never be mistaken for a real (positive) ifindex; the caller skips the
// affected unit and logs rather than crashing the daemon (#5557).
const syntheticIfindexExhausted = -1

// syntheticLogicalIfindex assigns a unique logical-only ifindex from the
// private synthetic range. It returns syntheticIfindexExhausted (a
// negative sentinel) when every slot in the range is already used — an
// exhaustion that is unreachable in practice (it needs >1<<20 logical-only
// VLAN units on one box) but must degrade gracefully instead of panicking
// and crash-looping the daemon (#5557).
func syntheticLogicalIfindex(name string, vlanID int, used map[int]struct{}) int {
	if used == nil {
		used = make(map[int]struct{})
	}
	const fnvOffset = uint32(2166136261)
	const fnvPrime = uint32(16777619)
	hash := fnvOffset
	for _, b := range []byte(fmt.Sprintf("%s/%d", name, vlanID)) {
		hash ^= uint32(b)
		hash *= fnvPrime
	}
	span := syntheticInterfaceIfindexMax - syntheticInterfaceIfindexMin + 1
	start := syntheticInterfaceIfindexMin + int(hash%uint32(span))
	for offset := 0; offset < span; offset++ {
		candidate := syntheticInterfaceIfindexMin + ((start - syntheticInterfaceIfindexMin + offset) % span)
		if _, exists := used[candidate]; exists {
			continue
		}
		used[candidate] = struct{}{}
		return candidate
	}
	slog.Error("userspace snapshot: exhausted synthetic ifindex range; skipping logical-only unit",
		"name", name,
		"vlan", vlanID,
		"hash", hash,
		"tried", span,
		"range_min", syntheticInterfaceIfindexMin,
		"range_max", syntheticInterfaceIfindexMax,
	)
	return syntheticIfindexExhausted
}

func shouldUseLogicalOnlyParentBoundRethVLAN(cfg *config.Config, ifName string, unit *config.InterfaceUnit, childIfindex int, parentIfindex int) bool {
	if cfg == nil || unit == nil || childIfindex > 0 || parentIfindex <= 0 || unit.VlanID <= 0 {
		return false
	}
	if !strings.HasPrefix(ifName, "reth") {
		return false
	}
	return config.LinuxIfName(cfg.ResolveReth(ifName)) != config.LinuxIfName(ifName)
}

// userspaceBindTargetNetdev returns the Linux netdev that the userspace
// dataplane's AF_XDP socket actually binds to for a snapshot interface.
// This is the SINGLE SOURCE OF TRUTH on the Go control plane for the
// VLAN-unit binding contract (#2917).
//
// A VLAN sub-interface (e.g. reth0.80 → Linux netdev `ge-0-0-2.80`) is a
// SOFTWARE netdev with no hardware RX queues of its own: its VLAN-tagged
// frames are delivered on the PHYSICAL PARENT's hardware queues
// (`ge-0-0-2`) and the kernel demuxes the tag. Zero-copy AF_XDP therefore
// MUST bind the parent physical netdev, never the `.80` unit netdev (which
// would fail or fall back to copy/generic and, in the queue planner,
// collapse the per-interface queue_count to its lone software queue — the
// #3091 single-worker regression).
//
// This rule mirrors the Rust planner's `vlan_child_parent_netdev`
// (`userspace-dp/src/server/helpers.rs`) EXACTLY: redirect to the parent
// only when the row is a distinct VLAN child (VLANID != 0, a non-empty
// ParentLinuxName, and a parent netdev that differs from the row's own
// netdev). For a physical interface or a non-VLAN unit the parent and own
// netdev are the same netdev, so the bind target is the row's own
// LinuxName — identical to what `replan_queues` pushes as a candidate. The
// two planes MUST stay in lock-step; the cross-plane parity test in
// snapshot_allowlist_test.go and the Rust SSOT test in main_tests.rs guard
// against re-divergence.
func userspaceBindTargetNetdev(iface InterfaceSnapshot) string {
	if iface.VLANID != 0 && iface.ParentLinuxName != "" && iface.ParentLinuxName != iface.LinuxName {
		return iface.ParentLinuxName
	}
	return iface.LinuxName
}

// UserspaceBoundLinuxInterfaces returns the deduplicated, sorted set of
// Linux interface names that the userspace dataplane will bind AF_XDP
// sockets to for the given compiled config. This is the authoritative
// allowlist used by the D3 RSS indirection path (#797) so that we only
// reshape RSS on interfaces we actually steer into AF_XDP workers —
// siblings like a spare mlx5 PF or a management netdev must not be
// touched.
//
// Scope mirrors buildUserspaceIngressIfindexes() and
// userspaceSkipsIngressInterface(): include zoned non-tunnel interfaces
// excluding fxp*, em*, fab*, lo0, mgmt/control zones, and RETH member
// children — and, since #6691 round 8, excluding a row whose AF_XDP bind
// TARGET is a netdev EVERY owning row was refused for (a VLAN child
// redirecting onto an excluded parent); plus every fabric's parent member (fab0/fab1 themselves are
// IPVLAN overlays and are excluded above, but their physical parent is
// where AF_XDP binds). For zoned VLAN units whose parent is the physical
// interface, we emit the parent Linux name — that is the netdev the
// AF_XDP socket actually binds to.
//
// Returns nil on nil config. Never returns an error: this is a
// best-effort derivation used to scope a best-effort optimization.
func UserspaceBoundLinuxInterfaces(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	ucfg := deriveUserspaceConfig(cfg)
	// Reuse the REAL builder so this stays in lock-step with binding logic.
	//
	// It does NOT skip ifindex resolution — an earlier revision said "build a
	// snapshot without depending on ifindex resolution", and that is false of
	// the code: buildSnapshot runs buildLinkSnapshot for every row and unit
	// exactly as the apply path does. What is true is weaker and is the only
	// thing the allowlist relies on: the RESULT is keyed by Linux NAME (what
	// `ethtool` consumes), so an unresolvable ifindex does not by itself drop
	// an entry here the way it would from the ingress map.
	// #2514: buildSnapshot can return an error (e.g. an unresolvable
	// address-book content-ID collision). This is a best-effort allowlist
	// derivation, so on error we degrade to nil rather than propagating —
	// the real apply path (ApplyConfig) surfaces the same error to the
	// operator and rejects the commit.
	snap, err := buildSnapshot(cfg, ucfg, 0, 0)
	if err != nil || snap == nil {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	// #6691 round 9: this builder takes its OWN sample of the kernel's xfrm
	// devices (buildSnapshot -> buildInterfaceSnapshots -> liveXfrmNetdevs), a
	// DIFFERENT instant from the applied snapshot's. Its daemon call sites
	// (daemon_apply_tail.go, daemon_run_naming.go) hold only a *config.Config,
	// so the sample cannot be inherited without changing the exported contract
	// — and the honest thing is to say so and make the disagreement safe rather
	// than claim it is impossible. Measured before this round: with an xfrm
	// device visible to the applied build and gone by this one, the allowlist
	// re-admitted the xfrmi that the ingress map had correctly excluded.
	//
	// Safe here means: an entry in this list is permission to RESHAPE a NIC's
	// RSS table and pin its coalescing, so the conservative answer to any doubt
	// is to name FEWER netdevs, never more. That is what the degrade-to-nil
	// above does for a build error, and it is why liveXfrmNetdevs no longer
	// discards a partial dump: the interrupted-dump case was the measured way
	// this sample came back EMPTY and re-admitted a device.
	refused := buildUserspaceRefusedNetdevs(snap)
	for _, iface := range snap.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		// #2917: resolve the AF_XDP bind target through the single
		// VLAN-unit binding contract (userspaceBindTargetNetdev), which
		// mirrors the Rust planner's vlan_child_parent_netdev rule
		// exactly. A VLAN sub-interface binds its physical PARENT netdev;
		// everything else binds its own netdev.
		//
		// #6691 round 8: that redirect is the second way an excluded netdev
		// re-enters an adjudicated set. This allowlist is NAME-keyed, so it is
		// asked by name — under `bind-interface st10` plus a zoned
		// `st10 unit 5 vlan-id 100`, the child's bind target is the string
		// "st10" and the allowlist measured at head contained it. The refusal
		// is only reachable through the redirect: for a non-VLAN row the bind
		// target is the row's OWN netdev, which its own row already passed the
		// predicate for.
		bindTarget := userspaceBindTargetNetdev(iface)
		if refused.refusesName(bindTarget) {
			continue
		}
		add(bindTarget)
	}
	for _, fab := range snap.Fabrics {
		// #6691 round 9: the fabric loop asks the refused index too. Round 8
		// left it unconditional and recorded "not reachable for a secure
		// tunnel", on the ground that compiler_derivations.go resolves
		// LocalFabricMember only for a member with an FPC slot, so an `st*`
		// member yields no fabric row. That reasoning asked the PRE-round-8
		// question — when the exclusion was keyed on the ref's NAME.
		//
		// Round 8's kernel-kind half classifies by DEVICE KIND, so it refuses
		// an xfrm device WHATEVER it is called, including a slot-shaped
		// `ge-0/0/0` created or renamed out of band. That name IS a legal
		// fabric member. Measured: with `fab0 fabric-options member-interfaces
		// ge-0/0/0` and `ge-0-0-0` reporting kernel kind `xfrm`, the refused
		// index held name{ge-0-0-0} and ifx{20} while this loop put ge-0-0-0
		// straight back into the allowlist and the sibling loop in
		// maps_sync.go put 20 back into the ingress set. The reachability was
		// created by this PR's own change, so it is this PR's to close.
		//
		// This does NOT filter the ORDINARY fabric: fab0/fab1 are IPVLAN
		// overlays excluded on their own row, and their physical parent is a
		// data NIC that no exclusion class names, so it is not in the index and
		// this guard is transparent. It fires only when the member netdev is
		// one the dataplane may never bind — where the honest outcome is that
		// the fabric gets no AF_XDP binding, not that it gets one onto an
		// unbindable device.
		// BOTH KEYS (#6691 round 16): this reader has the fabric row's ifindex
		// too, and refusesNetdev is the one predicate every two-identity caller
		// asks, so this list and the ingress map cannot land on opposite sides
		// of one netdev again. It was already name-keyed, so this only ever
		// refuses MORE — which is this list's standing bias (an entry here is
		// permission to reshape a NIC's RSS table).
		if refused.refusesNetdev(fab.ParentLinuxName, fab.ParentIfindex) {
			continue
		}
		add(fab.ParentLinuxName)
	}
	sort.Strings(out)
	return out
}

// sampleLiveXfrmNetdevs takes the ONE kernel xfrm-device sample a snapshot
// build is entitled to and applies the fail-open policy for a dump that failed.
//
// #6691 round 8 resolved this ONCE per snapshot rather than per row — it is a
// single RTM_GETLINK dump, against the two netlink lookups buildLinkSnapshot
// already issues for every row. Round 10 made it a NAMED function because the
// sample now has two consumers in one build (the interface rows AND the fabric
// parents, buildSnapshot), and re-sampling for the second would let the two
// disagree about the same device within one snapshot.
//
// The diagnostic is the whole error handling, so it is part of the contract and
// TestXfrmDumpFailureIsLoggedNotSwallowed binds it. Round 9 left it as a bare
// slog.Error inside a 200-line builder, where no test could reach it and a
// silent deletion would have looked like a cleanup.
func sampleLiveXfrmNetdevs() map[string]bool {
	liveXfrm, err := liveXfrmNetdevs()
	if err != nil {
		// The kernel half of snapshotSecureTunnel is unavailable for this
		// build. Log LOUDLY and continue on the config half, which stays
		// authoritative for every tunnel an IPsec stanza names — the gap this
		// leaves is exactly the stale-xfrmi case, which no config-keyed
		// predicate could have covered anyway. Failing the whole apply on a
		// transient RTM_GETLINK error would brick commits for a belt.
		slog.Error("userspace: could not classify xfrm netdevs; secure-tunnel "+
			"exclusion falls back to configuration ownership only",
			"err", err)
	}
	return liveXfrm
}

// buildInterfaceSnapshots builds the interface rows against a FRESH kernel xfrm
// sample. buildSnapshot does NOT use it: a build that also produces fabric
// parents must share one sample across both, via buildInterfaceSnapshotsFrom.
func buildInterfaceSnapshots(cfg *config.Config) []InterfaceSnapshot {
	if !snapshotHasInterfaceRows(cfg) {
		return nil
	}
	return buildInterfaceSnapshotsFrom(cfg, sampleLiveXfrmNetdevs())
}

func buildInterfaceSnapshotsFrom(cfg *config.Config, liveXfrm map[string]bool) []InterfaceSnapshot {
	if !snapshotHasInterfaceRows(cfg) {
		return nil
	}
	zoneByInterface := buildInterfaceZoneMap(cfg)
	ifaceRoutingInstance := buildInterfaceRoutingInstances(cfg)
	// #9956 F-032: keys ONLY a quarantined instance claims take the sentinel
	// session domain (never the default 0) via routingDomainForInterfaceKey.
	quarantinedKeys := quarantinedInterfaceKeys(cfg)
	usedSyntheticIfindexes := make(map[int]struct{})
	// Build RETH RG lookup: physical member → RETH's RedundancyGroup.
	// Physical members have RedundantParent set but RedundancyGroup=0;
	// the RG is on the RETH. Without this, flow cache HA checks on
	// RETH member egress interfaces return owner_rg=0 and bypass
	// HA active/inactive validation, causing stale forwarding after failover.
	rethRG := make(map[string]int)
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc != nil && ifc.RedundantParent != "" {
			if reth := cfg.Interfaces.Interfaces[ifc.RedundantParent]; reth != nil && reth.RedundancyGroup > 0 {
				rethRG[ifc.Name] = reth.RedundancyGroup
			}
		}
	}
	// #6722: the operator's LITERAL zone bindings — fanned DOWN onto a bare
	// reference's units, which is what that reference means, but never fanned UP
	// from a unit to its base, which is the derivation that manufactures a claim
	// about a sibling identity. stampEgressZones (run after this loop) needs the
	// provenance; see authoredZoneRefs in zones.go.
	//
	// Bindings to a zone the StableZoneID quarantine will DROP are removed here
	// rather than scrubbed afterwards. quarantineCollidingZones runs after this
	// builder and unzones the colliding zone's interfaces so they fail closed;
	// scrubbing the egress answer at that point would be wrong, because losing
	// one of two colliding bindings on an ifindex turns it from CONTESTED into
	// unanimous and the survivor's zone is then the right answer. The zone-name
	// set is the same one the quarantine uses — buildZoneSnapshots publishes
	// exactly cfg.Security.Zones — so the two cannot disagree.
	authored := authoredZoneRefs(cfg)
	if dropped := quarantinedZoneNames(cfg); len(dropped) > 0 {
		for ref, zone := range authored {
			if _, drop := dropped[zone]; drop {
				delete(authored, ref)
			}
		}
	}
	// Parallel to `out`: the egress-zone identity of each emitted row. Collected
	// here rather than re-derived afterwards because the loop is where the
	// aliasing is actually performed — `linuxUnit` vs `parentLinux` is the fact
	// that decides whether a unit collapses onto its base netdev.
	idents := make([]egressRowIdentity, 0, len(cfg.Interfaces.Interfaces))
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]InterfaceSnapshot, 0, len(names))
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxName := snapshotLinuxName(cfg, name, iface, nil)
		ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxName)
		// Use the interface's own RG, or inherit from RETH parent.
		rg := iface.RedundancyGroup
		if rg <= 0 {
			rg = rethRG[name]
		}
		out = append(out, InterfaceSnapshot{
			Name: name,
			// #9821 #22: structural row identity, stated explicitly — a
			// dotted base name (`ge-0/0/5.0`) must not parse as a unit.
			IsUnit:          false,
			Zone:            zoneByInterface[name],
			RoutingInstance: ifaceRoutingInstance[name],
			RoutingDomain:   routingDomainForInterfaceKey(name, ifaceRoutingInstance, quarantinedKeys),
			LinuxName:       linuxName,
			ParentLinuxName: "",
			Ifindex:         ifindex,
			ParentIfindex:   0,
			RXQueues:        userspaceRXQueueCount(linuxName),
			VLANID:          0,
			LocalFabric:     iface.LocalFabricMember,
			RedundancyGroup: rg,
			UnitCount:       len(iface.Units),
			Tunnel:          iface.Tunnel != nil,
			SecureTunnel:    snapshotSecureTunnel(cfg, name, linuxName, liveXfrm),
			MTU:             mtu,
			HardwareAddr:    hardwareAddr,
			Addresses:       addresses,
		})
		idents = append(idents, egressRowIdentity{owner: name, identity: name})
		if len(iface.Units) == 0 {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil {
				continue
			}
			var cosUnit *config.CoSInterfaceUnit
			if cfg.ClassOfService != nil {
				if cosIface := cfg.ClassOfService.Interfaces[name]; cosIface != nil {
					cosUnit = cosIface.Units[unitNum]
				}
			}
			unitName := fmt.Sprintf("%s.%d", name, unitNum)
			parentLinux := snapshotLinuxName(cfg, name, iface, nil)
			parentIfindex, parentMTU, parentHardwareAddr, _ := buildLinkSnapshot(parentLinux)
			parentRXQueues := userspaceRXQueueCount(parentLinux)
			linuxUnit := snapshotLinuxName(cfg, name, iface, unit)
			ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxUnit)
			rxQueues := userspaceRXQueueCount(linuxUnit)
			logicalOnly := false
			// Bondless RETH VLAN units can transmit through the parent
			// AF_XDP netdev without a Linux VLAN child. Keep a unique
			// logical ifindex for Rust FIB/filter/CoS state, while the
			// existing ParentIfindex path remains the socket bind target.
			if shouldUseLogicalOnlyParentBoundRethVLAN(cfg, name, unit, ifindex, parentIfindex) {
				ifindex = syntheticLogicalIfindex(unitName, unit.VlanID, usedSyntheticIfindexes)
				if ifindex == syntheticIfindexExhausted {
					// Range exhausted (unreachable in practice; already
					// logged in syntheticLogicalIfindex). Skip this unit
					// rather than emit a snapshot with a bogus/negative
					// ifindex — degrade gracefully instead of crashing the
					// daemon (#5557).
					continue
				}
				logicalOnly = true
				if mtu == 0 {
					mtu = parentMTU
				}
				if hardwareAddr == "" {
					hardwareAddr = parentHardwareAddr
				}
				if rxQueues == 0 {
					rxQueues = parentRXQueues
				}
			}
			addresses = mergeInterfaceAddressSnapshots(addresses, buildConfiguredAddressSnapshots(unit.Addresses))
			out = append(out, InterfaceSnapshot{
				Name:                      unitName,
				IsUnit:                    true,
				Zone:                      zoneByInterface[unitName],
				RoutingInstance:           ifaceRoutingInstance[unitName],
				RoutingDomain:             routingDomainForInterfaceKey(unitName, ifaceRoutingInstance, quarantinedKeys),
				LinuxName:                 linuxUnit,
				ParentLinuxName:           parentLinux,
				Ifindex:                   ifindex,
				ParentIfindex:             parentIfindex,
				LogicalOnly:               logicalOnly,
				RXQueues:                  rxQueues,
				VLANID:                    unit.VlanID,
				LocalFabric:               iface.LocalFabricMember,
				RedundancyGroup:           rg, // inherit resolved RG (RETH parent or own)
				UnitCount:                 0,
				Tunnel:                    iface.Tunnel != nil || unit.Tunnel != nil,
				SecureTunnel:              snapshotSecureTunnel(cfg, unitName, linuxUnit, liveXfrm),
				MTU:                       mtu,
				HardwareAddr:              hardwareAddr,
				Addresses:                 addresses,
				FilterInputV4:             unit.FilterInputV4,
				FilterOutputV4:            unit.FilterOutputV4,
				FilterInputV6:             unit.FilterInputV6,
				FilterOutputV6:            unit.FilterOutputV6,
				CoSShapingRateBytesPerSec: coSUnitShapingRate(cosUnit),
				CoSBurstSize:              coSUnitBurstSize(cosUnit),
				CoSSchedulerMap:           coSUnitSchedulerMap(cosUnit),
				CoSDSCPClassifier:         coSUnitDSCPClassifier(cosUnit),
				CoSIEEE8021Classifier:     coSUnitIEEE8021Classifier(cosUnit),
				// #6847: without this the unit-level inet-precedence binding
				// compiles and is never published, so the dataplane sees no
				// classifier and every packet falls through to the default
				// queue — a bound-but-inert knob.
				CoSINetPrecedenceClassifier: coSUnitINetPrecedenceClassifier(cosUnit),
				CoSDSCPRewriteRule:          coSUnitDSCPRewriteRule(cosUnit),
				// #1614 A1/A2: per-interface oversubscription policy
				// + priority-low min-share. All default-zero/empty
				// preserves current scheduler bit-for-bit.
				CoSOversubscriptionPolicy:            coSUnitOversubscriptionPolicy(cosUnit),
				CoSOversubscriptionGuaranteeFraction: coSUnitOversubscriptionFraction(cosUnit),
				CoSPriorityLowMinShareBytes:          coSUnitPriorityLowMinShare(cosUnit),
			})
			// UNIT 0 that lands on its base's netdev is not a separate egress
			// identity: it IS the interface. Junos treats unit 0 of an untagged
			// interface as the interface, and `snapshotLinuxName` collapses it
			// onto the base device to match.
			//
			// The two halves are NOT equally load-bearing, and the difference is
			// measured rather than asserted:
			//
			//	drop `unitNum == 0`         -> RED. TestContestedNetdevOwnership-
			//	  FailsClosed_6722/two-tunnel-units-on-one-device. `TunnelNameMap`
			//	  maps EVERY unit of an interface-level WireGuard tunnel onto the
			//	  tunnel netdev, so `wg0.0` and `wg0.1` are one device but two
			//	  logical interfaces; folding `wg0.1` onto `wg0` collapses the two
			//	  identities into one, the ifindex coheres, and the zone authored
			//	  on `wg0.1` decides for the deliberately unzoned `wg0.0`.
			//	drop `linuxUnit == parentLinux` -> SURVIVOR, and inert for a
			//	  reason that does not depend on enumerating shapes. The clause
			//	  can only CHANGE an identity string for a unit whose netdev is
			//	  not its base's; such a unit is on a different IFINDEX from the
			//	  base row, so it lands in a different bucket in stampEgressZones
			//	  and its identity never meets the base row's. And the only reader
			//	  of the identity strings, egressIdentitiesCohere, decides from
			//	  the OWNERS in a bucket, which this clause never alters. So the
			//	  fold can matter only by merging two identity KEYS inside ONE
			//	  bucket, and a differing netdev name is precisely what puts them
			//	  in two. More than one config produces such a unit — a VLAN
			//	  unit 0 on `<dev>.<vlan>`, and a RETH whose unit 0 carries a
			//	  per-unit tunnel — which is why the argument is stated as the
			//	  bucket property rather than as a list: a list is what #6722's
			//	  four earlier spellings were, and each was holed by the next
			//	  shape. Measured rather than argued: a differential dump of
			//	  per-ifindex EgressZone over 18 config shapes — every shape this
			//	  file's cells use, plus a VLAN unit 0 on its own netdev, which is
			//	  the only kind of unit the clause can reach — is byte-identical
			//	  with and without it, 36 ifindex rows unchanged, and the whole Go
			//	  suite stays green.
			//
			// It is kept as an explicit statement of the rule ("unit 0 that lands
			// on its base's netdev IS the interface"), not as a guard that
			// currently discriminates. If `snapshotLinuxName` ever puts a VLAN
			// unit back on the base ifindex, this is the clause that keeps the
			// fold correct; until then, removing it would be behaviour-preserving
			// and the comment must not claim otherwise.
			unitIdentity := unitName
			if unitNum == 0 && linuxUnit == parentLinux {
				unitIdentity = name
			}
			idents = append(idents, egressRowIdentity{owner: name, identity: unitIdentity, isUnit: true})
		}
	}
	// #7949: append a row for every secure tunnel the operator named ONLY
	// through `bind-interface` and then zoned. Placed BEFORE stampEgressZones
	// so the synthesized rows take part in the #6722 egress decision like any
	// other row — a row stamped with no EgressZone could not claim an egress
	// zone in the helper (forwarding_build/interfaces.rs:172 requires
	// corroboration) and would be adjudication-inert, which is the whole point
	// of adding it. It appends to `out` and `idents` TOGETHER: stampEgressZones
	// returns early unless the two slices are the same length, so growing one
	// alone would silently disable the egress decision for the entire snapshot.
	out, idents = appendBindInterfaceOnlySecureTunnelRows(
		cfg, out, idents, authored, zoneByInterface, ifaceRoutingInstance, quarantinedKeys, liveXfrm)
	// #6722: decide each ifindex's EGRESS zone here, from the operator's authored
	// bindings and this loop's own aliasing, and stamp the answer on every row.
	stampEgressZones(cfg, out, idents, authored)
	// #3362: stamp the per-interface host-inbound OVERRIDE onto each snapshot so
	// the Rust dataplane can key the host-inbound admission check by ingress
	// interface. Carried only for an interface that declared an interface-level
	// stanza and is NOT a management/cluster-control lifeline (matching the nft
	// primary path, which excludes lifeline addresses from host-inbound deny
	// scoping). The carried set is the EFFECTIVE set — the override, which
	// REPLACES the zone-level set (#6515) — so the Rust side enforces it as-is
	// without re-deriving it.
	// HostInboundConfigured marks a present override (even an empty one →
	// fail-closed) so an old Go binary that omits the field is distinguishable.
	//
	// #7490 added the SECOND reason to carry a per-interface set: an interface
	// the zone-level `dhcp` / `bootp` authorization is WITHHELD from. Without
	// it the flip would be silently half-done on this plane and only on this
	// plane. The Rust picker (host_inbound_admits_iface) consults the
	// per-interface table first and FALLS BACK to the zone-keyed table when the
	// interface has no entry — so an interface that is withheld but declares no
	// override would carry no entry, fall back, and be admitted by the very
	// zone-level token that was withheld from it. The nft plane has no such
	// hole, because it groups by resolved token signature rather than falling
	// back, which is exactly why this needed finding rather than assuming.
	{
		overrideByIface := buildInterfaceHostInboundMap(cfg)
		lifelines := hostInboundLifelineSet(cfg)
		for i := range out {
			zone := cfg.Security.Zones[out[i].Zone]
			if zone == nil || hostInboundLifelineInterface(out[i].Name, lifelines) {
				continue
			}
			ovr := overrideByIface[out[i].Name]
			if ovr == nil && !zone.WithholdsZoneLevelDHCPFor(out[i].Name) {
				continue
			}
			svc, proto := effectiveHostInboundTokens(zone, out[i].Name, ovr)
			out[i].HostInboundConfigured = true
			out[i].HostInboundSystemServices = svc
			out[i].HostInboundProtocols = proto
		}
	}
	return out
}

func coSUnitShapingRate(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return 0
	}
	return unit.ShapingRateBytes
}

func coSUnitBurstSize(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return 0
	}
	return unit.BurstSizeBytes
}

func coSUnitSchedulerMap(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.SchedulerMap
}

// #1614 A1: oversubscription-policy snapshot helpers. Empty string
// maps to Proportional (default) on the Rust side.
func coSUnitOversubscriptionPolicy(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.OversubscriptionPolicy
}

func coSUnitOversubscriptionFraction(unit *config.CoSInterfaceUnit) float64 {
	if unit == nil {
		return 0
	}
	return unit.OversubscriptionGuaranteeFraction
}

// #1614 A2: priority-low min-share snapshot helper.
func coSUnitPriorityLowMinShare(unit *config.CoSInterfaceUnit) uint64 {
	if unit == nil {
		return 0
	}
	return unit.PriorityLowMinShareBytes
}

func coSUnitDSCPClassifier(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.DSCPClassifier
}

func coSUnitIEEE8021Classifier(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.IEEE8021Classifier
}

func coSUnitINetPrecedenceClassifier(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.INetPrecedenceClassifier
}

func coSUnitDSCPRewriteRule(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.DSCPRewriteRule
}

// secureTunnelOwned reports whether an IPsec configuration BINDS ifName —
// i.e. some `security ipsec vpn <name> bind-interface` derives the same if_id.
//
// #6691 round 5: this replaces a NAME-SHAPE test as the input to the
// secure-tunnel exclusion. An `st` name is a secure tunnel because a VPN binds
// it, not because it is spelled that way, and nothing reserves the prefix —
// pkg/config/schema_interfaces.go accepts a wildcard interface name, so
// `set interfaces st5 unit 0 family inet address ...` with no VPN anywhere is
// a valid config naming an ordinary physical NIC. Classifying it by shape
// stripped it of ingress adjudication, of its AF_XDP binding and of its RSS
// entry — the traffic outage the excluding arm's own comment named.
//
// This is the CONFIG half of the row flag only; snapshotSecureTunnel unions it
// with the kernel half (liveXfrmNetdevs) and is what buildInterfaceSnapshots
// actually stamps on a row. Read that first if you are asking what
// InterfaceSnapshot.SecureTunnel means.
//
// The oracle is Config.SecureTunnelNetdevForRef. pkg/routing/xfrm.go — which
// actually creates the devices — does NOT call it; the two agree because both
// derive names and if_ids through config.XFRMIfNameAndID and both treat an
// if_id claimed by two distinct names as unresolvable. That is a shared
// derivation, not a shared function, so it is a drift risk to re-check when
// either side changes rather than a guarantee.
//
// Fails OPEN toward adjudication on an if_id collision, deliberately:
// SecureTunnelNetdevForRef returns false when two DISTINCT bind-interface
// strings derive one if_id, because routing then creates NEITHER device. The
// row keeps its dataplane role, which for a device that does not exist means
// its ifindex stays 0 and every ifindex-keyed set skips it anyway. That is the
// direction both planes' comments already rank safer: the gap costs a binding
// an xfrmi could not have used, over-matching costs a live interface its
// traffic.
//
// PASS THE REF THAT NAMES THE ROW, not the base name. The if_id is
// `stIndex<<16 | unit+1`, so the unit is part of it: `st10.5` and `st10` derive
// DIFFERENT if_ids and a VPN binding `st10.5` does not own `st10`. Only for
// unit 0 do the two coincide — a bare `st5` IS unit 0, which is the same
// property that makes `st0` and `st0.0` a collision rather than two tunnels.
//
// An earlier revision of this fix passed the base name for the unit row too,
// and TestSecureTunnelAddsNothingToTheAdjudicatedSets caught it on the
// multi-digit `st10.5` spelling: the tunnel resolved as unowned and re-entered
// the ingress-adjudication set.
//
// The BASE row is not an alias for its unit row, and passing the base name for
// the base row is not a lesser version of passing the unit ref (#6691 round
// 7). The two rows carry DIFFERENT netdevs — `st5` and, under
// `bind-interface st5.0`, `st5.0` — so they get different answers, and the
// resolver is directional for exactly that reason: `bind-interface st5.0`
// owns the `st5.0` row and not the `st5` row. Round 6 answered both the same
// and a live NIC named `st5` lost its ingress adjudication and its RSS entry
// to a VPN whose device is `st5.0`. Consequence to know: under the canonical
// `bind-interface st0.0` the BASE row `st0` now reports false, and being zoned
// it contributes its name to the name-keyed AF_XDP/RSS allowlist even though
// no `st0` netdev exists — which is what origin/master does for it, and what
// this allowlist already does for any zoned interface whose netdev is absent
// (a `ge-0/0/9` with no card behaves identically). Both measured.
func secureTunnelOwned(cfg *config.Config, ifName string) bool {
	if cfg == nil {
		return false
	}
	_, ok := cfg.SecureTunnelNetdevForRef(ifName)
	return ok
}

// liveXfrmNetdevs returns the LIVE kernel netdevs whose link KIND is `xfrm`.
//
// #6691 round 8. Every other predicate in this change is keyed on the CONFIG,
// and a live xfrmi the config no longer describes is invisible to all of them.
// Two routes reach that state, and neither needs an operator mistake:
//
//   - LinkDel FAILS. pkg/routing/xfrm.go deleteLocked deliberately RETAINS
//     tracking on a failed LinkDel (#4901) and returns the error; ApplyXfrmi
//     joins it, and applyInterfaceReconcile's result is a DEFERRED error
//     (daemon_apply.go — "All steps still run (no early return)"), so the apply
//     proceeds through applyDataplaneAndHACore with the xfrmi still in the
//     kernel. The new config has no bind-interface, so secureTunnelOwned says
//     false, and buildLinkSnapshot finds the retained device: the row ships
//     Ifindex > 0 with SecureTunnel false.
//   - DAEMON RESTART. xfrmManager.xfrmis starts EMPTY and both Apply's delete
//     pass and clearLocked iterate only TRACKED names, so an xfrmi left in the
//     kernel across a restart is never enumerated and never swept. Same end
//     state, and it persists.
//
// Measured at head on the second shape (`set interfaces st10 unit 0` + a zone,
// no VPN, `st10` live at ifindex 11): ingress [10 11], RSS [ge-0-0-0 st10] —
// the stale xfrmi in both adjudicated sets, and a candidate whose single RX
// queue becomes the planner's global minimum.
//
// The kernel is the only thing that knows, so the kernel is asked. This is a
// BELT, not a replacement for the ownership test: the xfrmi reconciler runs at
// apply time, so on the commit that CREATES a tunnel the device may not exist
// yet and only the config knows — the two halves cover different instants and
// snapshotSecureTunnel takes the union.
//
// It cannot over-match: `xfrm` is the kernel link kind (netlink IFLA_INFO_KIND,
// vishvananda/netlink *Xfrmi.Type()), so a wildcard-authored NIC named `st5` —
// the interface four earlier rounds of this PR fought to keep adjudicated — is
// not in this set, and no ordinary NIC ever can be.
//
// IT NO LONGER DISCARDS A PARTIAL DUMP (#6691 round 9). Round 8 wrote
// `if err != nil { return nil }` and called the result "fails OPEN … because
// the config half is the primary". That was not a considered trade: netlink
// v1.3.1's LinkList returns the links it DID deserialize together with
// ErrDumpInterrupted (link_linux.go — `if executeErr != nil &&
// !errors.Is(executeErr, ErrDumpInterrupted) { return nil, executeErr }` then
// `return res, executeErr`), so a dump interrupted by a concurrent link change
// threw away REAL evidence, including the xfrm device itself, while the
// per-row buildLinkSnapshot lookups that follow still resolved it — the stale
// xfrmi came back Ifindex > 0 with SecureTunnel false, which is exactly the
// state this belt exists to catch. The names are now taken from whatever the
// dump did return, and only a HARD error (one that is not ErrDumpInterrupted,
// i.e. one for which netlink itself returns no links) is reported to the
// caller.
//
// The error is REPORTED rather than swallowed because "no xfrm devices" and "I
// could not tell" are different answers with opposite safe handlings, and each
// consumer resolves it in its own conservative direction — see
// buildInterfaceSnapshots (logs and falls back to the config half, which is
// still authoritative for everything it covers) and UserspaceBoundLinuxInterfaces
// (degrades to touching no NIC at all).
//
// A package var so a test can present a kernel state without one; production
// never assigns it.
var liveXfrmNetdevs = func() (map[string]bool, error) {
	return xfrmDumpNames(netlink.LinkList())
}

// xfrmDumpNames is the ERROR POLICY half of liveXfrmNetdevs, split out for the
// same reason xfrmNetdevNames was (#6691 round 9): it is the half a test cannot
// otherwise reach, because every test presents a kernel by replacing the whole
// closure. Taking LinkList's (links, err) pair as arguments makes the policy a
// pure function of that pair.
//
// The policy: netlink v1.3.1 returns the links it DID deserialize together with
// ErrDumpInterrupted (link_linux.go returns early only for a non-interrupt
// error, then `return res, executeErr`). So an interrupted dump carries real
// evidence and is used; only a HARD error — one for which netlink returns no
// links at all — is reported to the caller, because "no xfrm devices" and "I
// could not tell" are different answers with opposite safe handlings.
//
// Round 8 wrote `if err != nil { return nil }` and called it "fails OPEN …
// because the config half is the primary". The interrupted case is the one that
// bit: a dump interrupted by concurrent link churn threw away the xfrm device
// while the per-row buildLinkSnapshot lookups still resolved it, so the stale
// xfrmi came back Ifindex > 0 with SecureTunnel false — exactly the state the
// belt exists to catch.
func xfrmDumpNames(links []netlink.Link, err error) (map[string]bool, error) {
	names := xfrmNetdevNames(links)
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return names, err
	}
	return names, nil
}

// xfrmNetdevNames is the CLASSIFIER half of liveXfrmNetdevs, split out so the
// `Type() == "xfrm"` discriminator can be driven directly (#6691 round 9).
//
// It could not be before: every test presented a kernel by replacing the whole
// liveXfrmNetdevs closure, so deleting the kind filter — a mutation that
// classifies EVERY enumerated link as an xfrm interface, and would strip an
// ordinary NIC of its AF_XDP binding — left the entire suite green. The
// discriminator is the single thing standing between "this netdev is a
// route-based IPsec tunnel" and "this netdev is a data NIC", so it is the one
// line in this file that most needs a test that does not itself supply the
// answer. TestXfrmNetdevNamesClassifiesByKernelKind feeds it a mixed link list
// and is the fail-on-revert guard.
func xfrmNetdevNames(links []netlink.Link) map[string]bool {
	var out map[string]bool
	for _, link := range links {
		if link == nil || link.Type() != "xfrm" {
			continue
		}
		name := link.Attrs().Name
		if name == "" {
			continue
		}
		if out == nil {
			out = make(map[string]bool)
		}
		out[name] = true
	}
	return out
}

// snapshotSecureTunnel is the value a row's SecureTunnel flag carries: the
// CONFIG-ownership fact (an IPsec bind-interface derives this ref's if_id) OR
// the KERNEL fact (the netdev this row resolves to is an xfrm interface).
//
// The flag's WIRE meaning is unchanged by the kernel half: it has always meant
// "the dataplane must not adjudicate or bind this row's netdev, because it is a
// route-based IPsec tunnel device", and both halves are that same claim reached
// by different evidence. (The version DID move to 6 in round 9 — for the
// refusal-rule change, not for this.) Rust reads the same `secure_tunnel` field,
// in more than one place since round 8; the first of them is
// include_userspace_binding_interface.
func snapshotSecureTunnel(cfg *config.Config, ref, netdev string, liveXfrm map[string]bool) bool {
	if secureTunnelOwned(cfg, ref) {
		return true
	}
	return netdev != "" && liveXfrm[netdev]
}

// NOTE: Keep in sync with (*Config).ResolveKernelIfName in
// pkg/config/types.go. The two implementations have intentional
// scope deltas (snapshotLinuxName does not implement IRB), but the
// shared cases must match. See drift-guard test in this package.
func snapshotLinuxName(cfg *config.Config, ifName string, iface *config.InterfaceConfig, unit *config.InterfaceUnit) string {
	if iface == nil {
		return config.LinuxIfName(ifName)
	}
	if unit != nil {
		// #5619: a secure-tunnel unit's kernel device is the one the xfrmi
		// reconciler creates for the AUTHORED bind-interface, which is NOT
		// derivable from the unit ref. The unit-0 collapse below yielded
		// `st0` for `bind-interface st0.0`, a name that exists on no box, so
		// buildLinkSnapshot missed and the unit reported ifindex 0 / MTU 0 /
		// no addresses.
		//
		// The rule itself lives in config.SecureTunnelUnitNetdev and is SHARED
		// with config.ResolveKernelIfName and config.junosHostLinuxName — not
		// re-derived here (#6691). Placed FIRST, matching ResolveKernelIfName's
		// ordering (the st rule precedes the tunnel-name map there too): an
		// explicit `bind-interface` outranks the tunnel-name map, which is
		// observable only on the config that names one ref as both, and is
		// pinned there by TestSecureTunnelOwnershipPrecedesTheTunnelNameMap.
		//
		// It declines (ok=false) for a ref NO VPN binds, and the arms below
		// then name the real device — the NIC, the VLAN device, the GRE
		// device. Round 5 returned the verbatim ref instead, which shadowed
		// every arm below for any `st`-spelled interface;
		// TestUnownedSecureTunnelUnitResolvesToItsRealDevice pins all three.
		//
		// Why it cannot be reconstructed: a bare `bind-interface st0` and an
		// explicit `bind-interface st0.0` derive ONE if_id under two DIFFERENT
		// device names ("st0" vs "st0.0", pkg/routing/xfrm.go), while the unit
		// ref is `st0.0` in both. Synthesizing "<ifName>.<unit>" here would be
		// right for the dotted spelling and WRONG for the bare one — the same
		// class of defect this function is being fixed for, one level down.
		//
		// Only the UNIT path resolves this way. A base `st0` row keeps
		// LinuxIfName(ifName): under `bind-interface st0` that IS the device,
		// and under `bind-interface st0.0` there is no `st0` device at all, so
		// resolving to nothing is the honest answer rather than aliasing the
		// base row onto the unit's device.
		//
		// THIS MOVES A FORWARDING DISPOSITION — read before "simplifying" it.
		// The unit row's ifindex is the gate on Rust `populate_interfaces`
		// (`if iface.ifindex <= 0 { continue }`), so resolving the name also
		// admits the tunnel's connected prefix to the FIB. Measured end to
		// end (real Go wire snapshot -> real Rust FIB) for a LAN->tunnel
		// transit flow, `next-hop <gw-in-tunnel-subnet>`:
		//
		//	bind-interface st0    : MissingNeighbor before AND after
		//	bind-interface st0.0  : NoRoute before -> MissingNeighbor after
		//
		// The two spellings describe ONE tunnel — same if_id, same unit ref
		// `st0.0` — and the divergence was purely this name bug. So the
		// change is a CONVERGENCE onto what the canonical bare spelling
		// already did, not a new state. It is still operator-visible: the
		// `NoRoute` arm reinjects unconditionally, whereas the
		// `MissingNeighbor` arm resolves zone ids and evaluates policy first
		// (poll_descriptor/mod.rs), so a LAN->tunnel flow is now adjudicated
		// where the dotted spelling used to be kernel-reinjected unread.
		//
		// WHAT THAT ADJUDICATION CURRENTLY DECIDES, stated exactly: an xfrmi
		// is ARPHRD_NONE, so `populate_egress` cannot build an EgressInterface
		// for it (its src_mac gate needs a MAC, a parent's MAC, or the tunnel
		// flag, and a secure-tunnel unit carries none of the three), the
		// to-zone therefore reads 0, and `evaluate_policy_result_l3_aware`
		// refuses to match ANY rule — exact, wildcard or junos-global — when
		// either zone id is 0. So today the flow lands on the default action
		// and a matching `permit` does NOT preserve delivery. That is a
		// PRE-EXISTING MAC-less-egress defect (#6713), not one this change
		// introduces, and it is fixed by #6722; the permit-preserves-delivery
		// behaviour this arm is meant to have DEPENDS ON #6722 landing.
		// TestSecureTunnelSpellingsAgreeOnForwardingInputs pins the
		// convergence; `secure_tunnel_unit_ifindex_decides_route_disposition`
		// (userspace-dp) pins the FIB consequence the claim rests on.
		if dev, ok := cfg.SecureTunnelUnitNetdev(
			fmt.Sprintf("%s.%d", ifName, unit.Number)); ok {
			return dev
		}
		if tunnelNames := cfg.TunnelNameMap(); len(tunnelNames) > 0 {
			ref := fmt.Sprintf("%s.%d", ifName, unit.Number)
			if linuxName, ok := tunnelNames[ref]; ok && linuxName != "" {
				return linuxName
			}
		}
		if unit.VlanID > 0 {
			return fmt.Sprintf("%s.%d", config.LinuxIfName(cfg.ResolveReth(ifName)), unit.VlanID)
		}
		if strings.HasPrefix(ifName, "reth") {
			if unit.Number == 0 {
				return config.LinuxIfName(cfg.ResolveReth(ifName))
			}
			return config.LinuxIfName(cfg.ResolveReth(fmt.Sprintf("%s.%d", ifName, unit.Number)))
		}
		if unit.Number == 0 {
			return config.LinuxIfName(ifName)
		}
		return config.LinuxIfName(fmt.Sprintf("%s.%d", ifName, unit.Number))
	}
	if strings.HasPrefix(ifName, "reth") {
		return config.LinuxIfName(cfg.ResolveReth(ifName))
	}
	return config.LinuxIfName(ifName)
}

// egressRowIdentity is the egress-zone identity of one emitted snapshot row,
// recorded by buildInterfaceSnapshots as it emits (#6722).
//
//   - owner    — the CONFIGURED interface this row belongs to. For a unit row
//     that is the base interface name, not a string split of the row name: an
//     interface may legally be NAMED with a dot (`ge-0/0/1.100`), and splitting
//     would silently reattribute it to a different owner.
//   - identity — the EGRESS identity this row speaks for. A unit whose netdev is
//     its base's netdev speaks for the base; one on its own netdev speaks for
//     itself. This is taken from the aliasing the builder just performed
//     (`linuxUnit == parentLinux`), never re-derived from names.
//   - isUnit   — whether the row is a logical unit row.
type egressRowIdentity struct {
	owner    string
	identity string
	isUnit   bool
}

// stampEgressZones decides the EGRESS security zone of every ifindex in the
// snapshot and writes it onto each row's EgressZone (#6722).
//
// WHY THIS IS DECIDED HERE. `ForwardingState::egress_zone_id`
// (userspace-dp/src/afxdp/types/forwarding.rs) must answer "which single zone
// does this ifindex identify" — a nonzero to-zone is what makes an operator
// `permit` match, so guessing one adjudicates transit under a policy that was
// never written for that device. Answering it from the snapshot ROWS is not
// possible, because a row's Zone is the OUTCOME of two derivations whose inputs
// the rows no longer carry:
//
//   - buildInterfaceZoneMap (zones.go) fans one authored reference UP to a base
//     as well as down onto units, so a row's Zone may be a restatement of a
//     sentence the operator wrote about a DIFFERENT identity. Measured: for
//     `ge-0/0/1` with unit 0 in `lan` and unit 1 in `dmz`, the BASE row carries
//     "dmz" — a zone nothing on that netdev was ever put in, chosen because
//     "dmz" sorts before "lan". (The fan-DOWN is not such a restatement, and
//     authoredZoneRefs keeps it: a bare interface reference is a sentence about
//     every unit of that interface.)
//   - snapshotLinuxName collapses several configured identities onto one netdev
//     (a non-VLAN unit 0 onto its base; a RETH and its member, via ResolveReth;
//     every unit of an interface-level tunnel onto the tunnel device).
//
// #6722 tried FOUR times to reconstruct that provenance downstream by
// classifying rows — from the raw `redundant-parent` string, from co-resident
// row names, from the set of netdevs a parent's rows occupy, and finally by
// asking snapshotLinuxName about the parent's BASE row. Each spelling was holed
// by a config shape it had not enumerated, because provenance is not recoverable
// from the outcome: by the time a row exists, "the operator zoned this device"
// and "something else was zoned and this row inherited the words" look identical.
// The enumeration was the defect, not any particular missing case. So the answer
// is computed once, here, where both inputs are in hand, and shipped.
//
// THE RULES, in order. For each ifindex > 0:
//
//  1. CONTESTED OWNERSHIP → no zone. An ifindex carrying two or more distinct
//     egress identities describes one kernel device that the config claims
//     twice. That is legitimate for exactly one relation — a redundant-ethernet
//     interface and the member port it resolves onto — and a fiction otherwise.
//     See egressIdentitiesCohere.
//  2. AUTHORED → that zone. Every `security-zone <z> interfaces <ref>` the
//     operator literally wrote, resolved to an ifindex by the row that ref
//     names. Exactly one distinct zone on the ifindex wins; two or more is a
//     real conflict about a real device and resolves to no zone.
//  3. TRUNK CARRIER → the units' unanimous zone. An ifindex with no authored
//     reference and NO logical unit row on it is a bare tagged-parent netdev:
//     its children all live on `<dev>.<vlan>` devices of their own. Attributing
//     the zone its units unanimously carry matches both origin/master and the
//     #921/#3618 ingress rule, and it is what keeps a `vlan-tagging` RETH's base
//     ifindex zoned (the reference cluster's `reth0`/ifindex 25). If ANY unit
//     row is on the ifindex, this rule does not fire: that unit is an identity
//     on the device in its own right and rule 2 already had its say.
//  4. Otherwise no zone. Rendered as "" and read by the helper as the 0
//     sentinel, against which evaluate_policy_result_l3_aware matches no rule
//     and the default policy decides.
//
// WHAT THIS MAKES UNREPRESENTABLE. There is no longer any per-row
// classification predicate on the dataplane side — no "is this row a
// projection", no exemption list, nothing for a new config shape to disagree
// with. A row's Zone is never consulted to adjudicate; it is used only as
// corroboration at the helper boundary (see populate_interfaces).
//
// WHAT IT DOES NOT. "A reth member is a bare L2 port" (egressMemberIsBarePort)
// is a MODEL rule imported from Junos, not something derivable from the config,
// and it stays a definition. It is now stated positively in one place and read
// by both the commit gate (validateRethMemberStrict) and this builder, rather
// than existing as a growing list of rejected shapes.
func stampEgressZones(cfg *config.Config, out []InterfaceSnapshot, idents []egressRowIdentity, authored map[string]string) {
	if cfg == nil || len(out) == 0 || len(out) != len(idents) {
		return
	}
	type ifxState struct {
		identities  map[string]string // identity -> owner
		authored    map[string]bool
		unitRefs    map[string]bool // authored zone of each UNIT row ("" = none)
		hasUnitRow  bool
		rowsByIndex []int
	}
	states := make(map[int]*ifxState)
	order := make([]int, 0, len(out))
	for i := range out {
		ifx := out[i].Ifindex
		if ifx <= 0 {
			continue
		}
		st := states[ifx]
		if st == nil {
			st = &ifxState{
				identities: map[string]string{},
				authored:   map[string]bool{},
				unitRefs:   map[string]bool{},
			}
			states[ifx] = st
			order = append(order, ifx)
		}
		st.identities[idents[i].identity] = idents[i].owner
		if idents[i].isUnit {
			st.hasUnitRow = true
			// Rule 1's escape hatch (see egressOneOwnerUnitsAgree): the
			// authored zone of THIS unit row, "" when the operator authored
			// none. "" is recorded on purpose — a unit left out of every zone
			// is a statement, and it must break unanimity.
			st.unitRefs[authored[out[i].Name]] = true
		}
		st.rowsByIndex = append(st.rowsByIndex, i)
		// Rule 2's input: an authored reference NAMING THIS ROW. Keyed by the
		// row's own name, so the ref lands on whatever ifindex the builder
		// resolved that name to — the same aliasing, not a second opinion.
		if z := authored[out[i].Name]; z != "" {
			st.authored[z] = true
		}
	}
	sort.Ints(order)
	for _, ifx := range order {
		st := states[ifx]
		zone := ""
		switch {
		case !egressIdentitiesCohere(cfg, st.identities) &&
			!egressOneOwnerUnitsAgree(st.identities, st.unitRefs):
			zone = ""
		case len(st.authored) == 1:
			for z := range st.authored {
				zone = z
			}
		case len(st.authored) > 1:
			zone = ""
		case !st.hasUnitRow:
			zone = unanimousUnitZone(cfg, st.identities, authored)
		}
		for _, i := range st.rowsByIndex {
			out[i].EgressZone = zone
		}
	}
}

// egressOneOwnerUnitsAgree is the one narrow case in which several egress
// identities on ONE ifindex still identify a single zone (#6722).
//
// egressIdentitiesCohere refuses every multi-identity ifindex whose identities
// belong to a single configured interface, on the ground that the operator
// described two logical interfaces and the kernel gave them one device. That is
// the right answer when the two disagree — a MEASURED fail-open otherwise, see
// TestContestedNetdevOwnershipFailsClosed_6722/two-tunnel-units-on-one-device,
// where `wg0.1` is zoned and `wg0.0` deliberately is not. It is the WRONG answer
// when they agree: an interface-level tunnel maps EVERY unit onto the tunnel
// netdev (`TunnelNameMap`), so `gr-0/0/0.0` and `gr-0/0/0.1` both in `sfmix` is
// one device on which every claimant names the same zone. origin/master
// resolved `sfmix` there; refusing it drops every transit flow out of the tunnel
// to the default policy for no safety gained.
//
// So the refusal is narrowed to what it is actually about — DISAGREEMENT — and
// only for a device no foreign interface claims:
//
//   - every identity on the ifindex must belong to the SAME configured
//     interface. One owner means there is no independent claimant to defer to
//     or to be misattributed; the reth/member relation and every cross-interface
//     collision keep going through egressIdentitiesCohere unchanged.
//   - every LOGICAL UNIT row on the ifindex must carry the SAME authored zone.
//     An unauthored unit contributes "" and breaks unanimity, which is what
//     preserves the fail-closed above.
//
// Base rows are not required to be authored: a bare `security-zone <z>
// interfaces <ifc>` reference does author them (authoredZoneRefs fans it down),
// but a per-unit reference legitimately leaves the base row unauthored, and rule
// 2 then reads the units' agreed zone off their own rows.
//
// MEASURED SURVIVOR: the `z != ""` test on the single agreed value. Removing it
// leaves the whole Go suite green, and the reason is structural rather than a
// missing fixture. It fires only when EVERY unit row on the ifindex is
// unauthored, i.e. `unitRefs == {""}`; the caller then reaches rule 2 with an
// `authored` set that can only have been filled by a BASE row, and a bare
// reference — the only spelling that authors a base row — is fanned down onto
// every configured unit, so it would have authored those unit rows too. The set
// is therefore empty, rule 2 does not fire, rule 3 is skipped because a unit row
// IS on the ifindex, and the answer is "" either way. It is kept because it
// states the rule the function is about ("the units agree on a ZONE", not "the
// units agree"), and because the fan-down is what makes it unreachable — a
// future change that narrows the fan-down would make this the difference between
// honouring a base-only zone on units the operator declined to zone and refusing
// it.
func egressOneOwnerUnitsAgree(identities map[string]string, unitRefs map[string]bool) bool {
	if len(identities) < 2 || len(unitRefs) != 1 {
		return false
	}
	owner := ""
	for _, o := range identities {
		if owner == "" {
			owner = o
			continue
		}
		if o != owner {
			return false
		}
	}
	for z := range unitRefs {
		return z != ""
	}
	return false
}

// egressIdentitiesCohere reports whether the egress identities sharing one
// ifindex describe a device the config claims coherently (#6722).
//
// One identity always coheres. Exactly two cohere only when one is a
// redundant-ethernet interface and the other is a bare member port that names it
// — the single relation under which two configured identities are DESIGNED to be
// one netdev (`ResolveReth`, pkg/config/types.go). Three or more never cohere:
// a reth resolves onto exactly one member, so a third claimant is always a
// second, unrelated claim on the same device.
//
// Everything the ledger used to enumerate falls out of this:
//
//   - The reference bondless cluster — `{ge-0/0/1, reth1}` on ifindex 24 —
//     coheres, which is the whole point of #6722: the member's rows must not
//     make the RETH's own zone ambiguous.
//   - An `interfaces ge-0-0-1` / `interfaces ge-0/0/1` canonicalization
//     collision (#5832) does NOT cohere — neither side is a reth, so the
//     deference premise ("the member is a port, the reth owns the L3") is
//     absent. It fails closed, retiring the fail-OPEN delta the previous
//     spelling admitted for that shape on the tolerant path.
//   - A reth that names a redundant parent of its own does NOT cohere: a reth is
//     never a member port. validateRethMemberStrict rejects it at commit; on the
//     tolerant load / peer-sync path, where that gate is a warning (#1960
//     no-brick), this is what holds the line.
//   - A WireGuard or other tunnel interface named as a member does NOT cohere.
//     A tunnel is an independently routed L3 endpoint, not a port, and the one
//     that reaches the builder anyway carries its own routes onto the shared
//     ifindex.
//   - A member carrying its OWN logical units does NOT cohere. Its units are
//     independently addressed L3 interfaces on the shared device, and their lack
//     of a zone is a real operator statement.
func egressIdentitiesCohere(cfg *config.Config, identities map[string]string) bool {
	if len(identities) <= 1 {
		return true
	}
	if len(identities) > 2 {
		return false
	}
	owners := make([]string, 0, 2)
	for _, owner := range identities {
		owners = append(owners, owner)
	}
	if owners[0] == owners[1] {
		// Two identities of ONE interface on one netdev — two units of an
		// interface-level tunnel, say. The operator described two logical
		// interfaces; the kernel gives them one device. Nothing designates
		// either as the other's port, so the device identifies no single zone.
		//
		// MEASURED SURVIVOR (#6722 round 11), and dead for a stronger reason
		// than that round recorded. A same-owner pair puts the SAME name in both
		// argument positions, and `egressRethMemberOf(X, X)` is a contradiction
		// on the name alone: the `reth` position demands
		// `strings.HasPrefix(X, "reth")` and the `member` position is handed to
		// `egressMemberIsBarePort`, which refuses exactly that prefix. No config
		// satisfies both, so the fall-through cannot admit a same-owner pair
		// whatever the `redundant-parent` says — the round-11 note read the
		// refusal as contingent on the parent match, and it is not.
		//
		// Kept because it states the rule at the level the rule is about
		// (identity vs. interface) rather than as a name-shape accident, and
		// because that accident is exactly the kind of thing a later change
		// unpicks: relaxing either prefix test would silently re-admit this
		// shape through a branch nobody was watching. Recorded as a survivor
		// rather than deleted or claimed to be load-bearing.
		return false
	}
	return egressRethMemberOf(cfg, owners[0], owners[1]) ||
		egressRethMemberOf(cfg, owners[1], owners[0])
}

// egressRethMemberOf reports whether `member` is a valid redundant-ethernet
// member port of `reth` (#6722): `reth` is a reth interface, `member` names it
// as its `gigether-options redundant-parent`, and `member` is a bare L2 port.
func egressRethMemberOf(cfg *config.Config, member, reth string) bool {
	if !strings.HasPrefix(reth, "reth") {
		return false
	}
	if cfg.Interfaces.Interfaces[reth] == nil {
		return false
	}
	ifc := cfg.Interfaces.Interfaces[member]
	if ifc == nil || ifc.RedundantParent != reth {
		return false
	}
	return egressMemberIsBarePort(member, ifc)
}

// egressMemberIsBarePort states POSITIVELY what a redundant-ethernet member is
// allowed to be: a port that contributes a netdev and nothing else (#6722).
//
// Junos models a reth as ONE interface described by several nodes — the `rethN`
// node owns the logical units, addresses, security zone and CoS, and each member
// node contributes only a physical port. That model is why a member's row may
// share the reth's ifindex without making it ambiguous, so the model's
// conditions are exactly the conditions of the deference. An interface that
// carries its own logical units, its own tunnel, or that is itself a reth has an
// L3 identity of its own and is not a port.
//
// validateRethMemberStrict (pkg/config/compiler_validate_strict_reth_member.go)
// rejects each of these at commit and quotes this rule; this is the runtime half
// that must hold on the tolerant load / peer-sync path, where those rejections
// are downgraded to warnings (#1960 no-brick).
func egressMemberIsBarePort(name string, ifc *config.InterfaceConfig) bool {
	if ifc == nil || strings.HasPrefix(name, "reth") {
		return false
	}
	if ifc.Tunnel != nil {
		return false
	}
	return !hasConfiguredUnit(ifc)
}

// hasConfiguredUnit reports whether ifc carries any configured (non-nil)
// logical unit. A present-but-nil unit slot (tolerant load / HA config-sync,
// #3494/#5068) is not a configured unit.
//
// This was firstConfiguredUnit, returning (int, bool). The int had no consumer
// -- the sole production call site and both test call sites read only the bool
// -- so the lowest-unit selection it performed was dead code, not merely
// unbound: reversing `num < lowest` to `num > lowest` left the whole Go suite
// green. The #6722 round-12 mutation table recorded that and deliberately left
// it alone, being a claims-only round; #7026 carried it forward. Collapsed here.
//
// The sibling firstUnitNumber (pkg/config/compiler_validate_strict_reth_member.go)
// keeps its int and its determinism requirement: it names the offending unit in
// the commit-check message, so its selection is load-bearing. Only this copy
// was dead.
func hasConfiguredUnit(ifc *config.InterfaceConfig) bool {
	for _, unit := range ifc.Units {
		if unit != nil {
			return true
		}
	}
	return false
}

// unanimousUnitZone implements rule 3 of stampEgressZones: the zone that every
// AUTHORED unit reference of the interfaces claiming this ifindex agrees on, or
// "" if they disagree or none exists (#6722).
//
// Only reached for an ifindex with no authored reference of its own AND no unit
// row on it — a bare tagged-parent netdev whose children all live on their own
// `<dev>.<vlan>` devices. Unzoned units are skipped rather than counted as
// dissent: they are not on this netdev and say nothing about it.
func unanimousUnitZone(cfg *config.Config, identities map[string]string, authored map[string]string) string {
	seen := ""
	for _, owner := range identities {
		ifc := cfg.Interfaces.Interfaces[owner]
		if ifc == nil {
			continue
		}
		for num, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			z := authored[fmt.Sprintf("%s.%d", owner, num)]
			if z == "" {
				continue
			}
			if seen != "" && seen != z {
				return ""
			}
			seen = z
		}
	}
	return seen
}

// buildLinkSnapshot resolves a kernel interface's live ifindex/MTU/MAC/addresses.
// It is a package var so the host-inbound view builder (which resolves the base
// netdev's LIVE addresses through it) is unit-testable without a real kernel
// interface — the #5699 base-vs-unit-0 double-emission only manifests when the
// base netdev actually carries the (unit-0-collapsed) live address.
var buildLinkSnapshot = func(linuxName string) (ifindex int, mtu int, hardwareAddr string, addresses []InterfaceAddressSnapshot) {
	if linuxName == "" {
		return 0, 0, "", nil
	}
	if link, err := net.InterfaceByName(linuxName); err == nil {
		ifindex = link.Index
	}
	if link, err := netlink.LinkByName(linuxName); err == nil && link != nil {
		mtu = link.Attrs().MTU
		if hw := link.Attrs().HardwareAddr; len(hw) > 0 {
			hardwareAddr = hw.String()
		}
		addresses = buildInterfaceAddressSnapshots(link)
	}
	return ifindex, mtu, hardwareAddr, addresses
}

func buildConfiguredAddressSnapshots(addrs []string) []InterfaceAddressSnapshot {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]InterfaceAddressSnapshot, 0, len(addrs))
	for _, cidr := range addrs {
		ip, netw, err := net.ParseCIDR(cidr)
		if err != nil || netw == nil {
			continue
		}
		netw.IP = ip
		family := "inet"
		if ip.To4() == nil {
			family = "inet6"
		}
		out = append(out, InterfaceAddressSnapshot{
			Family:  family,
			Address: netw.String(),
			Scope:   int(netlink.SCOPE_UNIVERSE),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func mergeInterfaceAddressSnapshots(live []InterfaceAddressSnapshot, configured []InterfaceAddressSnapshot) []InterfaceAddressSnapshot {
	if len(live) == 0 {
		return configured
	}
	if len(configured) == 0 {
		return live
	}
	seen := make(map[string]bool, len(live)+len(configured))
	out := make([]InterfaceAddressSnapshot, 0, len(live)+len(configured))
	for _, addr := range live {
		key := addr.Family + "/" + addr.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	for _, addr := range configured {
		key := addr.Family + "/" + addr.Address
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, addr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func buildInterfaceAddressSnapshots(link netlink.Link) []InterfaceAddressSnapshot {
	if link == nil {
		return nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	out := make([]InterfaceAddressSnapshot, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		family := "inet"
		if addr.IPNet.IP.To4() == nil {
			family = "inet6"
		}
		out = append(out, InterfaceAddressSnapshot{
			Family:  family,
			Address: addr.IPNet.String(),
			Scope:   addr.Scope,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Address < out[j].Address
	})
	return out
}

func userspaceRXQueueCount(linuxName string) int {
	if linuxName == "" {
		return 0
	}
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", linuxName, "queues"))
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if name := entry.Name(); len(name) > 3 && name[:3] == "rx-" {
			count++
		}
	}
	return count
}

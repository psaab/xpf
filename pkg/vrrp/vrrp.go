// Package vrrp manages native VRRPv3 instances for VRRP high availability.
package vrrp

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// MinVRID / MaxVRID bound the VRRP Virtual Router ID that may be advertised on
// the wire. RFC 5798 §5.2.3 defines the VRID as an 8-bit field with a valid
// range of 1..255; 0 is not a usable VRID. The state machine truncates the
// configured GroupID straight onto that byte (instance.go writes
// `uint8(vi.cfg.GroupID)` into the VRID field), so an out-of-range GroupID that
// slips past the config-layer commit gate (validateVRRPGroupIDStrict) on a
// lenient / HA-sync load would otherwise advertise VRID 0 (peer discards) or an
// aliased VRID. The manager range-checks GroupID against these bounds at
// instance creation (#4573) and refuses to build such an instance.
const (
	MinVRID = 1
	MaxVRID = 255
)

// rethVRID is the single checked constructor for the synthesized RETH VRID.
// Keep the range check alongside the 100+RG arithmetic: the config validator
// and the tolerant runtime both need the same boundary, while callers that
// only have an RG id must not duplicate an unchecked addition.
func rethVRID(rgID int) (int, bool) {
	const base = config.RethVRRPGroupIDBase
	if rgID <= 0 || rgID > MaxVRID-base {
		return 0, false
	}
	return base + rgID, true
}

// Instance describes a single VRRP instance.
type Instance struct {
	Interface string
	// Family is the address family this instance advertises: "inet" (IPv4) or
	// "inet6" (IPv6). It is part of the manager instance identity (#5083) so a
	// dual-stack VRRP group — an IPv4 and an IPv6 group sharing one unit AND one
	// VRID — yields TWO distinct instances instead of colliding on
	// (interface, VRID) and silently dropping a family (last-wins). The generic
	// collector (CollectInstances) sets it per Junos family address; the RETH
	// collector (CollectRethInstances) deliberately leaves it empty because a
	// RETH sub-interface carries mixed v4+v6 VIPs on ONE instance that
	// family-detects each VIP at advert time.
	Family            string
	GroupID           int
	Priority          int
	Preempt           bool
	PreemptHoldTime   int // seconds a higher-priority backup waits before preempting a live lower-priority master; 0 = immediate
	AcceptData        bool
	AdvertiseInterval int      // milliseconds (wire format is centiseconds)
	VirtualAddresses  []string // CIDR notation
	AuthType          string   // "" or "md5"
	AuthKey           string
	TrackInterface    string
	TrackPriorityCost int
	GARPCount         int // gratuitous ARP count per VIP on failover; 0 = default (3)
}

// CollectInstances extracts VRRP instances from the interface config.
func CollectInstances(cfg *config.Config) []*Instance {
	if cfg == nil {
		return nil
	}
	var instances []*Instance
	for _, ifName := range sortedIfNames(cfg) {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil {
				continue
			}
			// Resolve the CONFIGURED interface+unit to its KERNEL device name
			// via the SSOT resolver (#5083). Storing the raw Junos name
			// (ge-0/0/0) with no unit — as this collector did before — made the
			// manager's net.InterfaceByName("ge-0/0/0") fail so NO instance was
			// ever built for a slash-named interface, and two units sharing a
			// VRID both stored the bare base name and collided on the manager
			// key. ResolveKernelIfName translates the slash form, applies reth
			// resolution, and appends the unit's VLAN tag / unit-number suffix so
			// a VLAN sub-interface (ge-0/0/0.100 → ge-0-0-0.100) and a
			// non-zero unit map to the exact netdev InterfaceByName expects.
			kernelIf := cfg.ResolveKernelIfName(fmt.Sprintf("%s.%d", ifName, unitNum))
			groupKeys := make([]string, 0, len(unit.VRRPGroups))
			for vgKey := range unit.VRRPGroups {
				groupKeys = append(groupKeys, vgKey)
			}
			sort.Strings(groupKeys)
			for _, vgKey := range groupKeys {
				vg := unit.VRRPGroups[vgKey]
				if vg == nil {
					continue
				}
				inst := &Instance{
					Interface:         kernelIf,
					Family:            vrrpGroupFamily(vg.VirtualAddresses, vgKey),
					GroupID:           vg.ID,
					Priority:          vg.Priority,
					Preempt:           vg.Preempt,
					PreemptHoldTime:   vg.PreemptHoldTime,
					AcceptData:        vg.AcceptData,
					AdvertiseInterval: vg.AdvertiseInterval,
					VirtualAddresses:  vg.VirtualAddresses,
					AuthType:          vg.AuthType,
					AuthKey:           vg.AuthKey.Reveal(),
					// TrackInterface arrives as a Junos name
					// (ge-0/0/1); normalize to the Linux name
					// (ge-0-0-1) so netlink lookups and link-watcher
					// event matching work (#1814 — the RETH path
					// below normalizes the same way).
					TrackInterface:    config.LinuxIfName(vg.TrackInterface),
					TrackPriorityCost: vg.TrackPriorityDelta,
				}
				if inst.AdvertiseInterval == 0 {
					inst.AdvertiseInterval = 1000 // default 1s
				} else {
					inst.AdvertiseInterval *= 1000 // config seconds → ms
				}
				instances = append(instances, inst)
			}
		}
	}
	return instances
}

// CollectRethInstances generates VRRP instances for RETH interfaces that have
// a RedundancyGroup > 0. These provide VRRP-backed failover for HA cluster
// RETH interfaces. VRID = 100 + redundancyGroupID.
//
// The advertisement interval defaults to 30ms for sub-100ms failover detection.
// Override via chassis cluster reth-advertise-interval in config.
// GARP counts are read per-RG from chassis cluster redundancy-group gratuitous-arp-count.
func CollectRethInstances(cfg *config.Config, localPriority map[int]int) []*Instance {
	if cfg == nil {
		return nil
	}
	// When no-reth-vrrp is set, the cluster state machine directly manages
	// VIPs/GARPs — skip RETH VRRP instance creation.
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		return nil
	}
	rethToPhys := cfg.RethToPhysical()

	// Read cluster-level settings for RETH VRRP instances.
	advertInterval := 30 // 30ms default for sub-100ms failover
	garpCounts := map[int]int{}
	preemptMap := map[int]bool{}
	if cc := cfg.Chassis.Cluster; cc != nil {
		if cc.RethAdvertiseInterval > 0 {
			advertInterval = cc.RethAdvertiseInterval
		}
		for _, rg := range cc.RedundancyGroups {
			// #6780: skip a present-but-nil redundancy-group. Every sibling
			// walk of this slice already guards it (compiler_validate_warn.go,
			// compiler_validate_strict_chassis.go); this collector was the
			// outlier.
			if rg == nil {
				continue
			}
			if rg.GratuitousARPCount > 0 {
				garpCounts[rg.ID] = rg.GratuitousARPCount
			}
			preemptMap[rg.ID] = rg.Preempt
		}
	}

	// Sort interface names for deterministic output.
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)

	// #6781: RG ownership comes from the shared structural predicate, not from
	// a bare RedundancyGroup > 0. Built once for the whole walk.
	rgOwners := cfg.RethRGOwners()

	var instances []*Instance
	for _, name := range names {
		ifc := cfg.Interfaces.Interfaces[name]
		// #6780: skip a present-but-nil interface, matching CollectInstances
		// above and every RETH-ownership walk in pkg/daemon.
		if ifc == nil {
			continue
		}
		rgID, owns := rgOwners[name]
		// RG 0 is the control-plane group; no RETH VRRP instance is
		// synthesized for it, and an unset redundancy-group also reads as 0.
		// The `> 0` term lives here rather than in the shared predicate
		// because the direct collector below is legitimately queried for
		// group 0 (see Config.RethRGOwners).
		if !owns || rgID <= 0 {
			continue
		}
		vrid, validVRID := rethVRID(rgID)
		if !validVRID {
			slog.Warn("vrrp: skipping RETH instance with out-of-range VRID",
				"rg_id", rgID,
				"valid_range", fmt.Sprintf("%d..%d", MinVRID, MaxVRID))
			continue
		}

		pri := localPriority[rgID]
		if pri == 0 {
			pri = 100 // default to secondary priority
		}

		gc := garpCounts[rgID] // 0 = use default (3)

		// Resolve reth → physical member (no bond device)
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)

		// For VLAN-tagged interfaces, create one VRRP instance per
		// sub-interface (e.g. reth0.50) since the parent has no
		// IPv4 and VRRP requires one for advertisements.
		// For non-VLAN interfaces, use the base interface.
		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		if ifc.VlanTagging {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				// #6780: a present-but-nil unit reaches len(unit.Addresses) as
				// a nil deref, not as a zero length.
				if unit == nil || len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				instances = append(instances, &Instance{
					Interface:         subIface,
					GroupID:           vrid,
					Priority:          pri,
					Preempt:           preemptMap[rgID],
					AcceptData:        true,
					AdvertiseInterval: advertInterval,
					GARPCount:         gc,
					VirtualAddresses:  unit.Addresses,
				})
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if unit == nil { // #6780
					continue
				}
				vips = append(vips, unit.Addresses...)
			}
			if len(vips) == 0 {
				continue
			}
			instances = append(instances, &Instance{
				Interface:         linuxName,
				GroupID:           vrid,
				Priority:          pri,
				Preempt:           preemptMap[rgID],
				AcceptData:        true,
				AdvertiseInterval: advertInterval,
				GARPCount:         gc,
				VirtualAddresses:  vips,
			})
		}
	}
	return instances
}

// RethVIPsForRG returns the VIPs (CIDR strings) per Linux interface name for
// RETH interfaces belonging to the given redundancy group. Used by
// direct VIP mode (when no-reth-vrrp is set) where the daemon manages VIPs without VRRP.
func RethVIPsForRG(cfg *config.Config, rgID int) map[string][]string {
	if cfg == nil {
		return nil
	}
	rethToPhys := cfg.RethToPhysical()

	result := make(map[string][]string)
	// #6781: the same structural ownership predicate the VRRP-backed collector
	// uses. This replaces a `strings.HasPrefix(name, "reth")` filter whose
	// stated purpose — "skip fabric, control, and management interfaces that
	// default to RedundancyGroup 0" — is already served by the predicate (those
	// interfaces own no group), but which ALSO excluded a structurally valid
	// redundant pair whose owner is not spelled "reth*", leaving that group
	// with no VIPs installed at all.
	rgOwners := cfg.RethRGOwners()

	for _, name := range sortedIfNames(cfg) {
		ifc := cfg.Interfaces.Interfaces[name]
		// #6780: skip a present-but-nil interface — this is the direct
		// (no-reth-vrrp / private-rg-election) ownership mode's collector, and
		// it carried the same raw deref as the VRRP-mode one above.
		if ifc == nil {
			continue
		}
		if owns, ok := rgOwners[name]; !ok || owns != rgID {
			continue
		}

		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)

		unitNums := make([]int, 0, len(ifc.Units))
		for n := range ifc.Units {
			unitNums = append(unitNums, n)
		}
		sort.Ints(unitNums)

		if ifc.VlanTagging {
			for _, n := range unitNums {
				unit := ifc.Units[n]
				// #6780: nil unit derefs at len(unit.Addresses).
				if unit == nil || len(unit.Addresses) == 0 {
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				result[subIface] = append(result[subIface], unit.Addresses...)
			}
		} else {
			var vips []string
			for _, n := range unitNums {
				unit := ifc.Units[n]
				if unit == nil { // #6780
					continue
				}
				vips = append(vips, unit.Addresses...)
			}
			if len(vips) > 0 {
				result[linuxName] = append(result[linuxName], vips...)
			}
		}
	}
	return result
}

// StateKey builds the map key that Manager.States() / RXDropStats() index a
// running instance's state under, and that the display consumers (pkg/api,
// pkg/grpcapi, pkg/cli) reconstruct from a collected Instance to correlate it
// with that state. It is the single source of truth for the format so the two
// sides can never drift (#5083). A dual-stack generic VRRP group produces two
// instances that share (interface, VRID) and differ ONLY by family, so family
// is part of the key. RETH alone leaves Family empty and keeps the historical
// "VI_<iface>_<vrid>" form; every generic instance carries inet/inet6.
func StateKey(iface string, groupID int, family string) string {
	if family == "" {
		return fmt.Sprintf("VI_%s_%d", iface, groupID)
	}
	return fmt.Sprintf("VI_%s_%d_%s", iface, groupID, family)
}

// vrrpGroupFamily returns the address family ("inet" or "inet6") of a VRRP
// group. parseVRRPGroups keys each group "<address-CIDR>_grp<id>", so the
// address the group hangs off is the authoritative family even on a lenient
// load containing a malformed/cross-family VIP. Hand-built Config values may
// not carry that key shape, so the first parseable VIP is the compatibility
// fallback. Defaults to "inet" only when neither source is parseable.
func vrrpGroupFamily(vips []string, groupKey string) string {
	if i := strings.LastIndex(groupKey, "_grp"); i > 0 {
		if fam := familyOfAddrs([]string{groupKey[:i]}); fam != "" {
			return fam
		}
	}
	if fam := familyOfAddrs(vips); fam != "" {
		return fam
	}
	return "inet"
}

// familyOfAddrs reports the family of the first parseable address in addrs
// ("inet" for IPv4, "inet6" for IPv6), stripping any /prefix suffix. Returns ""
// when none parse.
func familyOfAddrs(addrs []string) string {
	for _, a := range addrs {
		s := a
		if idx := strings.Index(s, "/"); idx >= 0 {
			s = s[:idx]
		}
		if ip := net.ParseIP(s); ip != nil {
			if ip.To4() != nil {
				return "inet"
			}
			return "inet6"
		}
	}
	return ""
}

// sortedIfNames returns sorted interface names from config for deterministic iteration.
func sortedIfNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

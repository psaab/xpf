package userspace

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/vishvananda/netlink"
)

func buildSnapshot(cfg *config.Config, ucfg config.UserspaceConfig, generation uint64, fibGeneration uint32) *ConfigSnapshot {
	if cfg == nil {
		return &ConfigSnapshot{
			Version:       ProtocolVersion,
			Generation:    generation,
			FIBGeneration: 0,
			GeneratedAt:   time.Now().UTC(),
			Capabilities:  deriveUserspaceCapabilities(nil),
			MapPins:       userspaceMapPins(),
			Userspace:     ucfg,
		}
	}
	policyCount := len(cfg.Security.Policies)
	interfaces := buildInterfaceSnapshots(cfg)
	return &ConfigSnapshot{
		Version:         ProtocolVersion,
		Generation:      generation,
		FIBGeneration:   fibGeneration,
		GeneratedAt:     time.Now().UTC(),
		Capabilities:    deriveUserspaceCapabilities(cfg),
		MapPins:         userspaceMapPins(),
		Userspace:       ucfg,
		Zones:           buildZoneSnapshots(cfg),
		Interfaces:      interfaces,
		Fabrics:         buildFabricSnapshots(cfg),
		TunnelEndpoints: buildTunnelEndpointSnapshots(cfg, interfaces),
		Neighbors:       buildNeighborSnapshots(cfg),
		Routes:          buildRouteSnapshots(cfg, interfaces),
		Flow:            buildFlowSnapshot(cfg),
		DefaultPolicy:   policyActionString(cfg.Security.DefaultPolicy),
		Policies:        buildPolicySnapshots(cfg),
		SourceNAT:       buildSourceNATSnapshots(cfg),
		StaticNAT:       buildStaticNATSnapshots(cfg),
		DestinationNAT:  buildDestinationNATSnapshots(cfg),
		NAT64:           buildNAT64Snapshots(cfg),
		Nptv6:           buildNptv6Snapshots(cfg),
		Screens:         buildScreenSnapshots(cfg),
		Filters:         buildFirewallFilterSnapshots(cfg),
		Policers:        buildPolicerSnapshots(cfg),
		ClassOfService:  buildClassOfServiceSnapshot(cfg),
		FlowExport:      buildFlowExportSnapshot(cfg),
		Config:          cfg,
		Summary: SnapshotSummary{
			HostName:       cfg.System.HostName,
			DataplaneType:  cfg.System.DataplaneType,
			InterfaceCount: len(cfg.Interfaces.Interfaces),
			ZoneCount:      len(cfg.Security.Zones),
			PolicyCount:    policyCount,
			SchedulerCount: len(cfg.Schedulers),
			HAEnabled:      cfg.Chassis.Cluster != nil,
		},
	}
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
// children; plus every fabric's parent member (fab0/fab1 themselves are
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
	// Build a snapshot without depending on ifindex resolution — the
	// allowlist is by Linux name (what `ethtool` consumes), so ifindex
	// lookups are unnecessary here. We reuse the shared filter via the
	// real builder to stay in lock-step with binding logic.
	snap := buildSnapshot(cfg, ucfg, 0, 0)
	if snap == nil {
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
	for _, iface := range snap.Interfaces {
		if iface.Zone == "" || userspaceSkipsIngressInterface(iface) {
			continue
		}
		// Prefer the parent Linux name when present (VLAN units bind on
		// the parent physical netdev); otherwise the iface's own name.
		if iface.ParentLinuxName != "" {
			add(iface.ParentLinuxName)
		} else {
			add(iface.LinuxName)
		}
	}
	for _, fab := range snap.Fabrics {
		add(fab.ParentLinuxName)
	}
	sort.Strings(out)
	return out
}

// snapshotContentHash computes a SHA-256 hash over the stable content of a
// snapshot, excluding volatile fields (Generation, FIBGeneration, GeneratedAt)
// that change on every build even when the forwarding-relevant content is
// identical. Used to skip redundant control-socket publishes.
func snapshotContentHash(snap *ConfigSnapshot) ([32]byte, bool) {
	// Create a shallow copy with volatile fields zeroed, then JSON-encode.
	// This is cheaper than a custom hasher and reuses the existing JSON tags.
	tmp := *snap
	tmp.Generation = 0
	tmp.FIBGeneration = 0
	tmp.GeneratedAt = time.Time{}
	tmp.Config = nil // exclude raw config from content hash to avoid churn from non-forwarding metadata
	// #1197 (Copilot review): hash only PUBLISHABLE neighbors so
	// the dedup compares against what userspace-dp actually sees.
	// Filtered-out rows (state="none", malformed MAC) never reach
	// the dataplane, so churn in them must not shift the hash.
	tmp.Neighbors = filterPublishableNeighbors(snap.Neighbors)
	data, err := json.Marshal(&tmp)
	if err != nil {
		slog.Warn("snapshotContentHash: marshal failed, skipping dedup", "err", err)
		return [32]byte{}, false
	}
	return sha256.Sum256(data), true
}

// neighborsEqual returns true if two neighbor snapshot slices have identical content.
func neighborsEqual(a, b []NeighborSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// neighborsEqualForwarding returns true if two snapshots are
// equivalent for forwarding decisions: same publishable-key set,
// same MAC for each shared key. Raw NUD state (REACHABLE vs STALE)
// is NOT compared because both are usable for forwarding and aging
// churn shouldn't trigger republish.
//
// #1197: prevents the 60s safety reconciliation tick (and any
// other regeneration trigger) from publishing on harmless
// REACHABLE↔STALE transitions, while still detecting MAC change
// or transition to unusable state (which removes a key from the
// publishable set).
func neighborsEqualForwarding(a, b []NeighborSnapshot) bool {
	type keyMac struct{ ifindex int; ip, mac string }
	publishable := func(ns []NeighborSnapshot) map[keyMac]struct{} {
		out := make(map[keyMac]struct{}, len(ns))
		for _, n := range ns {
			if neighborSnapshotPublishable(n) {
				out[keyMac{n.Ifindex, n.IP, n.MAC}] = struct{}{}
			}
		}
		return out
	}
	am, bm := publishable(a), publishable(b)
	if len(am) != len(bm) {
		return false
	}
	for k := range am {
		if _, ok := bm[k]; !ok {
			return false
		}
	}
	return true
}

// neighborSnapshotPublishable returns true if a snapshot entry
// should be pushed to userspace-dp. Must mirror userspace-dp's
// accept rules at userspace-dp/src/afxdp/forwarding/mod.rs:45:
//
//   pub(super) fn neighbor_state_usable(state: &str) -> bool {
//       let normalized = state.to_ascii_lowercase();
//       !(normalized.contains("failed") || normalized.contains("incomplete"))
//   }
//
// Codex code-review #3: Rust uses SUBSTRING match after
// lowercasing; previous Go did EXACT match — drift. Fixed to
// match Rust's substring semantics.
//
// "none" is rejected here even though Rust treats it as usable,
// because state-0 entries have no learned MAC info — Rust would
// drop them at later parse-MAC anyway, but rejecting here
// prevents a useless publish round-trip.
//
// Drift here is a silent forwarding bug — keep in sync if
// userspace-dp changes its acceptance criteria.
func neighborSnapshotPublishable(n NeighborSnapshot) bool {
	if n.Ifindex <= 0 {
		return false
	}
	if net.ParseIP(n.IP) == nil {
		return false
	}
	if _, err := net.ParseMAC(n.MAC); err != nil {
		return false
	}
	lower := strings.ToLower(n.State)
	if strings.Contains(lower, "failed") || strings.Contains(lower, "incomplete") {
		return false
	}
	if lower == "none" {
		return false
	}
	return true
}

// MonitoredInterfaceLinkIndexes returns the set of kernel link
// indexes that buildNeighborSnapshots iterates over. Exported so
// the daemon's neighbor listener can filter incoming netlink
// events to exactly the same keyspace — guaranteeing no drift
// between snapshot publish and listener filter.
//
// #1197: previously the daemon's listener filter was inferred
// independently, which risks publishing snapshot entries the
// listener can't see updates for.
func MonitoredInterfaceLinkIndexes(cfg *config.Config) map[int]struct{} {
	out := make(map[int]struct{})
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return out
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxNames := []string{snapshotLinuxName(cfg, name, iface, nil)}
		if len(iface.Units) > 0 {
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
				linuxNames = append(linuxNames, snapshotLinuxName(cfg, name, iface, unit))
			}
		}
		for _, linuxName := range linuxNames {
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			out[link.Attrs().Index] = struct{}{}
		}
	}
	return out
}

func buildZoneSnapshots(cfg *config.Config) []ZoneSnapshot {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]ZoneSnapshot, 0, len(names))
	for i, name := range names {
		out = append(out, ZoneSnapshot{
			Name: name,
			ID:   uint16(i + 1),
		})
	}
	return out
}

func buildFabricSnapshots(cfg *config.Config) []FabricSnapshot {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cc := cfg.Chassis.Cluster
	type fabricInput struct {
		name string
		peer string
	}
	inputs := []fabricInput{
		{name: cc.FabricInterface, peer: cc.FabricPeerAddress},
		{name: cc.Fabric1Interface, peer: cc.Fabric1PeerAddress},
	}
	var out []FabricSnapshot
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		if in.name == "" {
			continue
		}
		if _, ok := seen[in.name]; ok {
			continue
		}
		seen[in.name] = struct{}{}
		ifCfg := cfg.Interfaces.Interfaces[in.name]
		if ifCfg == nil {
			continue
		}
		parentName := ifCfg.LocalFabricMember
		parentLinux := config.LinuxIfName(parentName)
		parentIfindex, _, parentMAC, _ := buildLinkSnapshot(parentLinux)
		overlayLinux := config.LinuxIfName(in.name)
		overlayIfindex, _, _, _ := buildLinkSnapshot(overlayLinux)
		rxQueues := 0
		if parentLinux != "" {
			rxQueues = userspaceRXQueueCount(parentLinux)
		}
		peerMAC := buildFabricPeerMAC(overlayIfindex, parentIfindex, in.peer)
		out = append(out, FabricSnapshot{
			Name:            in.name,
			ParentInterface: parentName,
			ParentLinuxName: parentLinux,
			ParentIfindex:   parentIfindex,
			OverlayLinux:    overlayLinux,
			OverlayIfindex:  overlayIfindex,
			RXQueues:        rxQueues,
			PeerAddress:     in.peer,
			LocalMAC:        parentMAC,
			PeerMAC:         peerMAC,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func buildFabricPeerMAC(overlayIfindex, parentIfindex int, peer string) string {
	ip := net.ParseIP(peer)
	if ip == nil {
		return ""
	}
	family := netlink.FAMILY_V4
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
	}
	for _, ifindex := range []int{overlayIfindex, parentIfindex} {
		if ifindex <= 0 {
			continue
		}
		neighs, err := netlink.NeighList(ifindex, family)
		if err != nil {
			continue
		}
		for _, neigh := range neighs {
			if neigh.IP == nil || !neigh.IP.Equal(ip) || neigh.HardwareAddr == nil {
				continue
			}
			return neigh.HardwareAddr.String()
		}
	}
	return ""
}

func userspaceMapPins() UserspaceMapPins {
	return UserspaceMapPins{
		Ctrl:        dataplane.UserspaceCtrlPinPath(),
		Bindings:    dataplane.UserspaceBindingsPinPath(),
		Heartbeat:   dataplane.UserspaceHeartbeatPinPath(),
		XSK:         dataplane.UserspaceXSKMapPinPath(),
		LocalV4:     dataplane.UserspaceLocalV4PinPath(),
		LocalV6:     dataplane.UserspaceLocalV6PinPath(),
		Sessions:    dataplane.UserspaceSessionsPinPath(),
		ConntrackV4: dataplane.ConntrackV4PinPath(),
		ConntrackV6: dataplane.ConntrackV6PinPath(),
		DnatTable:   dataplane.UserspaceDnatTablePinPath(),
		DnatTableV6: dataplane.UserspaceDnatTableV6PinPath(),
		Trace:       dataplane.UserspaceTracePinPath(),
	}
}

func buildInterfaceSnapshots(cfg *config.Config) []InterfaceSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	zoneByInterface := buildInterfaceZoneMap(cfg)
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
			Name:            name,
			Zone:            zoneByInterface[name],
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
			MTU:             mtu,
			HardwareAddr:    hardwareAddr,
			Addresses:       addresses,
		})
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
			parentIfindex, _, _, _ := buildLinkSnapshot(parentLinux)
			linuxUnit := snapshotLinuxName(cfg, name, iface, unit)
			ifindex, mtu, hardwareAddr, addresses := buildLinkSnapshot(linuxUnit)
			addresses = mergeInterfaceAddressSnapshots(addresses, buildConfiguredAddressSnapshots(unit.Addresses))
			out = append(out, InterfaceSnapshot{
				Name:                      unitName,
				Zone:                      zoneByInterface[unitName],
				LinuxName:                 linuxUnit,
				ParentLinuxName:           parentLinux,
				Ifindex:                   ifindex,
				ParentIfindex:             parentIfindex,
				RXQueues:                  userspaceRXQueueCount(linuxUnit),
				VLANID:                    unit.VlanID,
				LocalFabric:               iface.LocalFabricMember,
				RedundancyGroup:           rg, // inherit resolved RG (RETH parent or own)
				UnitCount:                 0,
				Tunnel:                    iface.Tunnel != nil || unit.Tunnel != nil,
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
				CoSDSCPRewriteRule:        coSUnitDSCPRewriteRule(cosUnit),
			})
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

func coSUnitDSCPRewriteRule(unit *config.CoSInterfaceUnit) string {
	if unit == nil {
		return ""
	}
	return unit.DSCPRewriteRule
}

func buildTunnelEndpointSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []TunnelEndpointSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	ifaceByName := make(map[string]InterfaceSnapshot, len(interfaces))
	rgByAddress := make(map[string]int)
	for _, iface := range interfaces {
		if iface.Name == "" || iface.Ifindex <= 0 {
			continue
		}
		ifaceByName[iface.Name] = iface
		if iface.RedundancyGroup <= 0 {
			continue
		}
		for _, addr := range iface.Addresses {
			ip, _, err := net.ParseCIDR(addr.Address)
			if err != nil || ip == nil {
				continue
			}
			rgByAddress[ip.String()] = iface.RedundancyGroup
		}
	}
	if len(ifaceByName) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]TunnelEndpointSnapshot, 0)
	var nextID uint16 = 1
	addEndpoint := func(ifName string, tunnel *config.TunnelConfig) {
		if tunnel == nil || tunnel.Source == "" || tunnel.Destination == "" || nextID == 0 {
			return
		}
		iface, ok := ifaceByName[ifName]
		if !ok {
			return
		}
		outerFamily := "inet"
		transportTable := "inet.0"
		if dst := net.ParseIP(tunnel.Destination); dst != nil && dst.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		} else if src := net.ParseIP(tunnel.Source); src != nil && src.To4() == nil {
			outerFamily = "inet6"
			transportTable = "inet6.0"
		}
		if tunnel.RoutingInstance != "" {
			if outerFamily == "inet6" {
				transportTable = tunnel.RoutingInstance + ".inet6.0"
			} else {
				transportTable = tunnel.RoutingInstance + ".inet.0"
			}
		}
		redundancyGroup := iface.RedundancyGroup
		if redundancyGroup <= 0 {
			if src := net.ParseIP(tunnel.Source); src != nil {
				redundancyGroup = rgByAddress[src.String()]
			}
		}
		out = append(out, TunnelEndpointSnapshot{
			ID:              nextID,
			Interface:       ifName,
			LinuxName:       iface.LinuxName,
			Ifindex:         iface.Ifindex,
			Zone:            iface.Zone,
			RedundancyGroup: redundancyGroup,
			MTU:             iface.MTU,
			Mode:            tunnel.Mode,
			OuterFamily:     outerFamily,
			Source:          tunnel.Source,
			Destination:     tunnel.Destination,
			Key:             tunnel.Key,
			TTL:             tunnel.TTL,
			TransportTable:  transportTable,
		})
		nextID++
	}
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		if iface.Tunnel != nil {
			if len(iface.Units) == 0 {
				addEndpoint(name, iface.Tunnel)
				continue
			}
			unitNums := make([]int, 0, len(iface.Units))
			for unitNum := range iface.Units {
				unitNums = append(unitNums, unitNum)
			}
			sort.Ints(unitNums)
			for _, unitNum := range unitNums {
				addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), iface.Tunnel)
			}
			continue
		}
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
			if unit == nil || unit.Tunnel == nil {
				continue
			}
			addEndpoint(fmt.Sprintf("%s.%d", name, unitNum), unit.Tunnel)
		}
	}
	return out
}

func buildInterfaceZoneMap(cfg *config.Config) map[string]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]string, len(cfg.Security.Zones))
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zoneName := range zoneNames {
		zone := cfg.Security.Zones[zoneName]
		if zone == nil {
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == "" {
				continue
			}
			if _, exists := out[iface]; !exists {
				out[iface] = zoneName
			}
			if base, unit, ok := strings.Cut(iface, "."); ok && base != "" {
				if _, exists := out[base]; !exists {
					out[base] = zoneName
				}
				if unit != "" {
					continue
				}
			}
			if ifCfg := cfg.Interfaces.Interfaces[iface]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					unitName := fmt.Sprintf("%s.%d", iface, unitNum)
					if _, exists := out[unitName]; !exists {
						out[unitName] = zoneName
					}
				}
			}
		}
	}
	return out
}

func snapshotLinuxName(cfg *config.Config, ifName string, iface *config.InterfaceConfig, unit *config.InterfaceUnit) string {
	if iface == nil {
		return config.LinuxIfName(ifName)
	}
	if unit != nil {
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

func buildLinkSnapshot(linuxName string) (ifindex int, mtu int, hardwareAddr string, addresses []InterfaceAddressSnapshot) {
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

func buildRouteSnapshots(cfg *config.Config, interfaces []InterfaceSnapshot) []RouteSnapshot {
	if cfg == nil {
		return nil
	}
	out := make([]RouteSnapshot, 0)
	seen := make(map[string]struct{})
	addSnapshot := func(snap RouteSnapshot) {
		key := snap.Table + "|" + snap.Family + "|" + snap.Destination + "|" + strings.Join(snap.NextHops, ",") + "|" + snap.NextTable
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, snap)
	}
	addRoutes := func(table, family string, routes []*config.StaticRoute) {
		for _, route := range routes {
			if route == nil {
				continue
			}
			tableName, familyName := normalizeRouteSnapshotFamily(table, family, route.Destination)
			snap := RouteSnapshot{
				Table:       tableName,
				Family:      familyName,
				Destination: route.Destination,
				Discard:     route.Discard,
				NextTable:   route.NextTable,
			}
			for _, nh := range route.NextHops {
				switch {
				case nh.Address != "" && nh.Interface != "":
					snap.NextHops = append(snap.NextHops, nh.Address+"@"+nh.Interface)
				case nh.Address != "":
					snap.NextHops = append(snap.NextHops, nh.Address)
				case nh.Interface != "":
					snap.NextHops = append(snap.NextHops, "@"+nh.Interface)
				}
			}
			addSnapshot(snap)
		}
	}
	interfaceTablesV4, interfaceTablesV6 := buildInterfaceRouteTables(cfg)
	addConnectedRoutes := func(family, table string, prefixes []string) {
		for _, prefix := range prefixes {
			snap := RouteSnapshot{
				Table:       table,
				Family:      family,
				Destination: prefix,
			}
			addSnapshot(snap)
		}
	}
	addRoutes("inet.0", "inet", cfg.RoutingOptions.StaticRoutes)
	addRoutes("inet6.0", "inet6", cfg.RoutingOptions.Inet6StaticRoutes)

	if len(cfg.RoutingInstances) > 0 {
		insts := make([]*config.RoutingInstanceConfig, 0, len(cfg.RoutingInstances))
		for _, ri := range cfg.RoutingInstances {
			if ri != nil {
				insts = append(insts, ri)
			}
		}
		sort.Slice(insts, func(i, j int) bool { return insts[i].Name < insts[j].Name })
		for _, ri := range insts {
			addRoutes(ri.Name+".inet.0", "inet", ri.StaticRoutes)
			addRoutes(ri.Name+".inet6.0", "inet6", ri.Inet6StaticRoutes)
		}
	}
	for _, iface := range interfaces {
		if iface.Name == "" {
			continue
		}
		v4Table := interfaceTablesV4[iface.Name]
		if v4Table == "" {
			v4Table = "inet.0"
		}
		v6Table := interfaceTablesV6[iface.Name]
		if v6Table == "" {
			v6Table = "inet6.0"
		}
		v4Prefixes, v6Prefixes := connectedPrefixesForInterface(iface)
		addConnectedRoutes("inet", v4Table, v4Prefixes)
		addConnectedRoutes("inet6", v6Table, v6Prefixes)
	}

	// Add synthetic routes for ip rule entries that implement inter-VRF
	// route leaking (rib-groups, next-table). These rules send traffic
	// matching a destination prefix to a different routing table.
	// Without these, the userspace FIB can't cross-reference VRF tables.
	tableIDToName := make(map[int]string)
	for _, inst := range cfg.RoutingInstances {
		if inst != nil && inst.TableID > 0 {
			tableIDToName[inst.TableID] = inst.Name + ".inet.0"
		}
	}
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if rule.Dst == nil || rule.Table <= 0 {
				continue
			}
			tableName, ok := tableIDToName[rule.Table]
			if !ok {
				continue
			}
			familyStr := "inet"
			mainTable := "inet.0"
			if family == syscall.AF_INET6 {
				familyStr = "inet6"
				mainTable = "inet6.0"
			}
			addSnapshot(RouteSnapshot{
				Table:       mainTable,
				Family:      familyStr,
				Destination: rule.Dst.String(),
				NextTable:   tableName,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Table != out[j].Table {
			return out[i].Table < out[j].Table
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].Destination < out[j].Destination
	})
	return out
}

func buildInterfaceRouteTables(cfg *config.Config) (map[string]string, map[string]string) {
	v4 := make(map[string]string)
	v6 := make(map[string]string)
	if cfg == nil {
		return v4, v6
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, ifname := range ri.Interfaces {
			if ifname == "" {
				continue
			}
			v4[ifname] = ri.Name + ".inet.0"
			v6[ifname] = ri.Name + ".inet6.0"
		}
	}
	return v4, v6
}

func connectedPrefixesForInterface(iface InterfaceSnapshot) ([]string, []string) {
	var v4 []string
	var v6 []string
	for _, addr := range iface.Addresses {
		if addr.Scope != 0 && addr.Scope != int(netlink.SCOPE_UNIVERSE) {
			continue
		}
		ip, network, err := net.ParseCIDR(addr.Address)
		if err != nil || network == nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones <= 0 || ones == bits {
			continue
		}
		network.IP = ip.Mask(network.Mask)
		prefix := network.String()
		switch addr.Family {
		case "inet":
			v4 = append(v4, prefix)
		case "inet6":
			if ip.IsLinkLocalUnicast() {
				continue
			}
			v6 = append(v6, prefix)
		}
	}
	slices.Sort(v4)
	slices.Sort(v6)
	return slices.Compact(v4), slices.Compact(v6)
}

func normalizeRouteSnapshotFamily(table, family, destination string) (string, string) {
	isIPv6 := strings.Contains(destination, ":")
	if isIPv6 {
		family = "inet6"
		switch {
		case table == "inet.0":
			table = "inet6.0"
		case strings.HasSuffix(table, ".inet.0"):
			table = strings.TrimSuffix(table, ".inet.0") + ".inet6.0"
		}
		return table, family
	}
	family = "inet"
	switch {
	case table == "inet6.0":
		table = "inet.0"
	case strings.HasSuffix(table, ".inet6.0"):
		table = strings.TrimSuffix(table, ".inet6.0") + ".inet.0"
	}
	return table, family
}

func buildSourceNATSnapshots(cfg *config.Config) []SourceNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		return nil
	}
	out := make([]SourceNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			sourceAddrs := append([]string(nil), rule.Match.SourceAddresses...)
			if len(sourceAddrs) == 0 && rule.Match.SourceAddress != "" {
				sourceAddrs = append(sourceAddrs, rule.Match.SourceAddress)
			}
			destAddrs := append([]string(nil), rule.Match.DestinationAddresses...)
			if len(destAddrs) == 0 && rule.Match.DestinationAddress != "" {
				destAddrs = append(destAddrs, rule.Match.DestinationAddress)
			}
			out = append(out, SourceNATRuleSnapshot{
				Name:                 rule.Name,
				FromZone:             rs.FromZone,
				ToZone:               rs.ToZone,
				SourceAddresses:      sourceAddrs,
				DestinationAddresses: destAddrs,
				InterfaceMode:        rule.Then.Interface,
				Off:                  rule.Then.Off,
				PoolName:             rule.Then.PoolName,
			})
		}
	}
	return out
}

func buildStaticNATSnapshots(cfg *config.Config) []StaticNATRuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	out := make([]StaticNATRuleSnapshot, 0)
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.IsNPTv6 {
				continue
			}
			out = append(out, StaticNATRuleSnapshot{
				Name:       rule.Name,
				FromZone:   rs.FromZone,
				ExternalIP: rule.Match,
				InternalIP: rule.Then,
			})
		}
	}
	return out
}

// appPortsFromSpec parses a port specification like "80", "1024-65535" into a
// list of port numbers. Mirrors the logic in pkg/dataplane/compiler.go.
func appPortsFromSpec(spec string) []int {
	if spec == "" {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil
		}
		hi, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil
		}
		if hi > lo {
			var ports []int
			for p := lo; p <= hi; p++ {
				ports = append(ports, int(p))
			}
			return ports
		}
		return []int{int(lo)}
	}
	p, err := strconv.ParseUint(spec, 10, 16)
	if err != nil {
		return nil
	}
	return []int{int(p)}
}

func buildDestinationNATSnapshots(cfg *config.Config) []DestinationNATRuleSnapshot {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		return nil
	}
	var out []DestinationNATRuleSnapshot
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]
			if !ok || pool == nil || pool.Address == "" {
				continue
			}
			if rule.Match.DestinationAddress == "" {
				continue
			}

			// Resolve application match to protocol+ports if specified.
			type appTerm struct {
				proto string
				ports []int
			}
			var appTerms []appTerm

			if rule.Match.Application != "" {
				userApps := cfg.Applications.Applications
				app, found := config.ResolveApplication(rule.Match.Application, userApps)
				if found {
					appTerms = append(appTerms, appTerm{proto: app.Protocol, ports: appPortsFromSpec(app.DestinationPort)})
				} else if _, isSet := cfg.Applications.ApplicationSets[rule.Match.Application]; isSet {
					expanded, err := config.ExpandApplicationSet(rule.Match.Application, &cfg.Applications)
					if err == nil {
						for _, termName := range expanded {
							tApp, ok := config.ResolveApplication(termName, userApps)
							if !ok {
								continue
							}
							appTerms = append(appTerms, appTerm{proto: tApp.Protocol, ports: appPortsFromSpec(tApp.DestinationPort)})
						}
					}
				}
			}

			// If no application terms resolved, use explicit match values
			if len(appTerms) == 0 {
				appTerms = []appTerm{{proto: rule.Match.Protocol, ports: rule.Match.DestinationPorts}}
			}

			for _, term := range appTerms {
				var dstPorts []uint16
				if len(term.ports) > 0 {
					for _, p := range term.ports {
						dstPorts = append(dstPorts, uint16(p))
					}
				} else if rule.Match.DestinationPort != 0 {
					dstPorts = []uint16{uint16(rule.Match.DestinationPort)}
				} else {
					dstPorts = []uint16{0}
				}

				for _, dstPort := range dstPorts {
					poolPort := dstPort
					if pool.Port != 0 {
						poolPort = uint16(pool.Port)
					}

					// Determine protocol string for the snapshot.
					proto := term.proto
					if proto == "" && dstPort != 0 {
						proto = "tcp" // default for port-based DNAT
					}

					// Strip the destination address CIDR suffix for the snapshot
					// (DNAT matches exact host IPs).
					dstAddr := rule.Match.DestinationAddress
					if idx := strings.IndexByte(dstAddr, '/'); idx != -1 {
						dstAddr = dstAddr[:idx]
					}
					poolAddr := pool.Address
					if idx := strings.IndexByte(poolAddr, '/'); idx != -1 {
						poolAddr = poolAddr[:idx]
					}

					out = append(out, DestinationNATRuleSnapshot{
						Name:               rule.Name,
						FromZone:           rs.FromZone,
						DestinationAddress: dstAddr,
						DestinationPort:    dstPort,
						Protocol:           proto,
						PoolAddress:        poolAddr,
						PoolPort:           poolPort,
					})
				}
			}
		}
	}
	return out
}

func buildNAT64Snapshots(cfg *config.Config) []NAT64RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.NAT64) == 0 {
		return nil
	}
	out := make([]NAT64RuleSnapshot, 0, len(cfg.Security.NAT.NAT64))
	for _, rs := range cfg.Security.NAT.NAT64 {
		if rs == nil || rs.Prefix == "" {
			continue
		}
		var poolAddresses []string
		if rs.SourcePool != "" {
			if pool, ok := cfg.Security.NAT.SourcePools[rs.SourcePool]; ok && pool != nil {
				if pool.Address != "" {
					poolAddresses = append(poolAddresses, pool.Address)
				}
				poolAddresses = append(poolAddresses, pool.Addresses...)
			}
		}
		out = append(out, NAT64RuleSnapshot{
			Name:          rs.Name,
			Prefix:        rs.Prefix,
			PoolAddresses: poolAddresses,
		})
	}
	return out
}

func buildNptv6Snapshots(cfg *config.Config) []Nptv6RuleSnapshot {
	if cfg == nil || len(cfg.Security.NAT.Static) == 0 {
		return nil
	}
	var out []Nptv6RuleSnapshot
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || !rule.IsNPTv6 {
				continue
			}
			out = append(out, Nptv6RuleSnapshot{
				Name:           rule.Name,
				FromZone:       rs.FromZone,
				ExternalPrefix: rule.Match,
				InternalPrefix: rule.Then,
			})
		}
	}
	return out
}

// hasNonNptv6StaticNAT returns true if the config has any static NAT rules
// that are NOT NPTv6. NPTv6 rules are supported by the userspace dataplane.
func hasNonNptv6StaticNAT(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule != nil && !rule.IsNPTv6 {
				return true
			}
		}
	}
	return false
}

func buildScreenSnapshots(cfg *config.Config) []ScreenProfileSnapshot {
	if cfg == nil || len(cfg.Security.Screen) == 0 || len(cfg.Security.Zones) == 0 {
		return nil
	}
	var out []ScreenProfileSnapshot
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		sp := cfg.Security.Screen[zone.ScreenProfile]
		if sp == nil {
			continue
		}
		snap := ScreenProfileSnapshot{
			Zone:        zone.Name,
			Land:        sp.TCP.Land,
			SynFin:      sp.TCP.SynFin,
			NoFlag:      sp.TCP.NoFlag,
			FinNoAck:    sp.TCP.FinNoAck,
			WinNuke:     sp.TCP.WinNuke,
			PingDeath:   sp.ICMP.PingDeath,
			Teardrop:    sp.IP.TearDrop,
			SynFrag:     sp.TCP.SynFrag, // #1137 — port from typed config
			SourceRoute: sp.IP.SourceRouteOption,
		}
		if sp.ICMP.FloodThreshold > 0 {
			snap.ICMPFloodThreshold = uint32(sp.ICMP.FloodThreshold)
		}
		if sp.UDP.FloodThreshold > 0 {
			snap.UDPFloodThreshold = uint32(sp.UDP.FloodThreshold)
		}
		if sp.TCP.SynFlood != nil && sp.TCP.SynFlood.AttackThreshold > 0 {
			snap.SYNFloodThreshold = uint32(sp.TCP.SynFlood.AttackThreshold)
		}
		if sp.LimitSession.SourceIPBased > 0 {
			snap.SessionLimitSrc = uint32(sp.LimitSession.SourceIPBased)
		}
		if sp.LimitSession.DestinationIPBased > 0 {
			snap.SessionLimitDst = uint32(sp.LimitSession.DestinationIPBased)
		}
		if sp.TCP.PortScanThreshold > 0 {
			snap.PortScanThreshold = uint32(sp.TCP.PortScanThreshold)
		}
		if sp.IP.IPSweepThreshold > 0 {
			snap.IPSweepThreshold = uint32(sp.IP.IPSweepThreshold)
		}
		// Only include profiles that have at least one check enabled
		if snap.Land || snap.SynFin || snap.NoFlag || snap.FinNoAck ||
			snap.WinNuke || snap.PingDeath || snap.Teardrop ||
			snap.SynFrag || snap.SourceRoute ||
			snap.ICMPFloodThreshold > 0 || snap.UDPFloodThreshold > 0 ||
			snap.SYNFloodThreshold > 0 ||
			snap.SessionLimitSrc > 0 || snap.SessionLimitDst > 0 ||
			snap.PortScanThreshold > 0 || snap.IPSweepThreshold > 0 {
			out = append(out, snap)
		}
	}
	return out
}

// userspaceSupportsScreenProfiles returns true if the configured screen
// profiles only use checks that the userspace dataplane implements.
// SYN cookies require eBPF-specific facilities and are not supported.
// Port scan detection, IP sweep detection, and per-IP session limiting
// are now implemented in the userspace dataplane.
func userspaceSupportsScreenProfiles(cfg *config.Config) bool {
	if cfg == nil || len(cfg.Security.Screen) == 0 {
		return true
	}
	if cfg.Security.Flow.SynFloodProtectionMode == "syn-cookie" {
		return false
	}
	return true
}

func buildFlowSnapshot(cfg *config.Config) FlowSnapshot {
	snap := FlowSnapshot{
		AllowDNSReply:      cfg.Security.Flow.AllowDNSReply,
		AllowEmbeddedICMP:  cfg.Security.Flow.AllowEmbeddedICMP,
		TCPMSSIPsecVPN:     cfg.Security.Flow.TCPMSSIPsecVPN,
		TCPMSSGreIn:        cfg.Security.Flow.TCPMSSGreIn,
		TCPMSSGreOut:       cfg.Security.Flow.TCPMSSGreOut,
		UDPSessionTimeout:  cfg.Security.Flow.UDPSessionTimeout,
		ICMPSessionTimeout: cfg.Security.Flow.ICMPSessionTimeout,
		GREAcceleration:    cfg.Security.Flow.GREPerformanceAcceleration,
		Lo0FilterInputV4:   cfg.System.Lo0FilterInputV4,
		Lo0FilterInputV6:   cfg.System.Lo0FilterInputV6,
	}
	if cfg.Security.Flow.TCPSession != nil {
		snap.TCPSessionTimeout = cfg.Security.Flow.TCPSession.EstablishedTimeout
	}
	return snap
}

func buildFlowExportSnapshot(cfg *config.Config) *FlowExportSnapshot {
	if cfg == nil || cfg.Services.FlowMonitoring == nil {
		return nil
	}
	fm := cfg.Services.FlowMonitoring
	if fm.Version9 == nil || len(fm.Version9.Templates) == 0 {
		return nil
	}
	// Find sampling config for flow server
	if cfg.ForwardingOptions.Sampling == nil {
		return nil
	}
	for _, inst := range cfg.ForwardingOptions.Sampling.Instances {
		if inst == nil {
			continue
		}
		rate := inst.InputRate
		if rate <= 0 {
			rate = 1
		}
		families := []*config.SamplingFamily{inst.FamilyInet, inst.FamilyInet6}
		for _, fam := range families {
			if fam == nil {
				continue
			}
			for _, server := range fam.FlowServers {
				if server == nil || server.Address == "" || server.Port == 0 {
					continue
				}
				snap := &FlowExportSnapshot{
					CollectorAddress: server.Address,
					CollectorPort:    server.Port,
					SamplingRate:     rate,
				}
				// Use template config if the server references one
				if server.Version9Template != "" && fm.Version9.Templates != nil {
					if tmpl, ok := fm.Version9.Templates[server.Version9Template]; ok {
						snap.ActiveTimeout = tmpl.FlowActiveTimeout
						snap.InactiveTimeout = tmpl.FlowInactiveTimeout
					}
				}
				return snap
			}
		}
	}
	return nil
}

func buildFirewallFilterSnapshots(cfg *config.Config) []FirewallFilterSnapshot {
	if cfg == nil {
		return nil
	}
	var out []FirewallFilterSnapshot
	// inet filters
	inetNames := make([]string, 0, len(cfg.Firewall.FiltersInet))
	for name := range cfg.Firewall.FiltersInet {
		inetNames = append(inetNames, name)
	}
	sort.Strings(inetNames)
	for _, name := range inetNames {
		filter := cfg.Firewall.FiltersInet[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet",
			Terms:  buildFilterTermSnapshots(filter, cfg),
		}
		out = append(out, snap)
	}
	// inet6 filters
	inet6Names := make([]string, 0, len(cfg.Firewall.FiltersInet6))
	for name := range cfg.Firewall.FiltersInet6 {
		inet6Names = append(inet6Names, name)
	}
	sort.Strings(inet6Names)
	for _, name := range inet6Names {
		filter := cfg.Firewall.FiltersInet6[name]
		if filter == nil {
			continue
		}
		snap := FirewallFilterSnapshot{
			Name:   name,
			Family: "inet6",
			Terms:  buildFilterTermSnapshots(filter, cfg),
		}
		out = append(out, snap)
	}
	return out
}

func buildFilterTermSnapshots(filter *config.FirewallFilter, cfg *config.Config) []FirewallTermSnapshot {
	if filter == nil || len(filter.Terms) == 0 {
		return nil
	}
	terms := make([]FirewallTermSnapshot, 0, len(filter.Terms))
	for _, term := range filter.Terms {
		if term == nil {
			continue
		}
		snap := FirewallTermSnapshot{
			Name:            term.Name,
			Action:          term.Action,
			Count:           term.Count,
			Log:             term.Log,
			PolicerName:     term.Policer,
			RoutingInstance: term.RoutingInstance,
			ForwardingClass: term.ForwardingClass,
		}
		// Source addresses (CIDRs)
		snap.SourceAddresses = append(snap.SourceAddresses, term.SourceAddresses...)
		// Destination addresses (CIDRs)
		snap.DestAddresses = append(snap.DestAddresses, term.DestAddresses...)
		// Protocols
		if term.Protocol != "" {
			snap.Protocols = []string{term.Protocol}
		}
		// Source ports
		snap.SourcePorts = append(snap.SourcePorts, term.SourcePorts...)
		// Destination ports
		snap.DestPorts = append(snap.DestPorts, term.DestinationPorts...)
		// DSCP
		if term.DSCP != "" {
			if val, ok := dataplane.DSCPValues[strings.ToLower(term.DSCP)]; ok {
				snap.DSCPValues = []uint8{val}
			} else if v, err := strconv.Atoi(term.DSCP); err == nil && v >= 0 && v <= 63 {
				snap.DSCPValues = []uint8{uint8(v)}
			}
		}
		// DSCP rewrite
		if term.DSCPRewrite != "" {
			if val, ok := dataplane.DSCPValues[strings.ToLower(term.DSCPRewrite)]; ok {
				rewrite := val
				snap.DSCPRewrite = &rewrite
			} else if v, err := strconv.Atoi(term.DSCPRewrite); err == nil && v >= 0 && v <= 63 {
				rewrite := uint8(v)
				snap.DSCPRewrite = &rewrite
			}
		}
		terms = append(terms, snap)
	}
	return terms
}

func buildPolicerSnapshots(cfg *config.Config) []PolicerSnapshot {
	if cfg == nil || len(cfg.Firewall.Policers) == 0 {
		return nil
	}
	names := make([]string, 0, len(cfg.Firewall.Policers))
	for name := range cfg.Firewall.Policers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]PolicerSnapshot, 0, len(names))
	for _, name := range names {
		pol := cfg.Firewall.Policers[name]
		if pol == nil {
			continue
		}
		snap := PolicerSnapshot{
			Name:         name,
			BandwidthBps: pol.BandwidthLimit,
			BurstBytes:   pol.BurstSizeLimit,
		}
		if pol.ThenAction == "discard" {
			snap.DiscardExcess = true
		}
		out = append(out, snap)
	}
	return out
}

func buildClassOfServiceSnapshot(cfg *config.Config) *ClassOfServiceSnapshot {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	cos := cfg.ClassOfService
	if len(cos.ForwardingClasses) == 0 && len(cos.DSCPClassifiers) == 0 && len(cos.IEEE8021Classifiers) == 0 && len(cos.DSCPRewriteRules) == 0 && len(cos.Schedulers) == 0 && len(cos.SchedulerMaps) == 0 && len(cos.Interfaces) == 0 {
		return nil
	}
	snap := &ClassOfServiceSnapshot{}

	if len(cos.ForwardingClasses) > 0 {
		names := make([]string, 0, len(cos.ForwardingClasses))
		for name := range cos.ForwardingClasses {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.ForwardingClasses = make([]CoSForwardingClassSnapshot, 0, len(names))
		for _, name := range names {
			class := cos.ForwardingClasses[name]
			if class == nil {
				continue
			}
			snap.ForwardingClasses = append(snap.ForwardingClasses, CoSForwardingClassSnapshot{
				Name:  class.Name,
				Queue: class.Queue,
			})
		}
	}

	if len(cos.DSCPClassifiers) > 0 {
		names := make([]string, 0, len(cos.DSCPClassifiers))
		for name := range cos.DSCPClassifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.DSCPClassifiers = make([]CoSDSCPClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.DSCPClassifiers[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSDSCPClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSDSCPClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					DSCPValues:      append([]uint8(nil), entry.DSCPValues...),
				})
			}
			snap.DSCPClassifiers = append(snap.DSCPClassifiers, classifierSnap)
		}
	}

	if len(cos.IEEE8021Classifiers) > 0 {
		names := make([]string, 0, len(cos.IEEE8021Classifiers))
		for name := range cos.IEEE8021Classifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.IEEE8021Classifiers = make([]CoSIEEE8021ClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.IEEE8021Classifiers[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSIEEE8021ClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSIEEE8021ClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					CodePoints:      append([]uint8(nil), entry.CodePoints...),
				})
			}
			snap.IEEE8021Classifiers = append(snap.IEEE8021Classifiers, classifierSnap)
		}
	}

	if len(cos.DSCPRewriteRules) > 0 {
		names := make([]string, 0, len(cos.DSCPRewriteRules))
		for name := range cos.DSCPRewriteRules {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.DSCPRewriteRules = make([]CoSDSCPRewriteRuleSnapshot, 0, len(names))
		for _, name := range names {
			rewriteRule := cos.DSCPRewriteRules[name]
			if rewriteRule == nil {
				continue
			}
			rewriteSnap := CoSDSCPRewriteRuleSnapshot{Name: rewriteRule.Name}
			for _, entry := range rewriteRule.Entries {
				if entry == nil {
					continue
				}
				rewriteSnap.Entries = append(rewriteSnap.Entries, CoSDSCPRewriteRuleEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					DSCPValue:       entry.DSCPValue,
				})
			}
			snap.DSCPRewriteRules = append(snap.DSCPRewriteRules, rewriteSnap)
		}
	}

	if len(cos.Schedulers) > 0 {
		names := make([]string, 0, len(cos.Schedulers))
		for name := range cos.Schedulers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.Schedulers = make([]CoSSchedulerSnapshot, 0, len(names))
		for _, name := range names {
			sched := cos.Schedulers[name]
			if sched == nil {
				continue
			}
			snap.Schedulers = append(snap.Schedulers, CoSSchedulerSnapshot{
				Name:              sched.Name,
				TransmitRateBytes: sched.TransmitRateBytes,
				TransmitRateExact: sched.TransmitRateExact,
				Priority:          sched.Priority,
				BufferSizeBytes:   sched.BufferSizeBytes,
				SurplusSharing:    sched.SurplusSharing,
			})
		}
	}

	if len(cos.SchedulerMaps) > 0 {
		names := make([]string, 0, len(cos.SchedulerMaps))
		for name := range cos.SchedulerMaps {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.SchedulerMaps = make([]CoSSchedulerMapSnapshot, 0, len(names))
		for _, name := range names {
			schedMap := cos.SchedulerMaps[name]
			if schedMap == nil {
				continue
			}
			entryNames := make([]string, 0, len(schedMap.Entries))
			for className := range schedMap.Entries {
				entryNames = append(entryNames, className)
			}
			sort.Strings(entryNames)
			mapSnap := CoSSchedulerMapSnapshot{Name: schedMap.Name}
			for _, className := range entryNames {
				entry := schedMap.Entries[className]
				if entry == nil {
					continue
				}
				mapSnap.Entries = append(mapSnap.Entries, CoSSchedulerMapEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					Scheduler:       entry.Scheduler,
				})
			}
			snap.SchedulerMaps = append(snap.SchedulerMaps, mapSnap)
		}
	}

	return snap
}

func buildPolicySnapshots(cfg *config.Config) []PolicyRuleSnapshot {
	if cfg == nil || (len(cfg.Security.Policies) == 0 && len(cfg.Security.GlobalPolicies) == 0) {
		return nil
	}
	out := make([]PolicyRuleSnapshot, 0)
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			sourceAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
			if !ok {
				sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
			}
			destinationAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
			if !ok {
				destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
			}
			applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
			if !ok {
				applicationTerms = nil
			}
			out = append(out, PolicyRuleSnapshot{
				Name:                 pol.Name,
				FromZone:             zpp.FromZone,
				ToZone:               zpp.ToZone,
				SourceAddresses:      sourceAddresses,
				DestinationAddresses: destinationAddresses,
				Applications:         append([]string(nil), pol.Match.Applications...),
				ApplicationTerms:     applicationTerms,
				Action:               policyActionString(pol.Action),
			})
		}
	}
	// Global policies match traffic regardless of zone pair.
	for _, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		sourceAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.SourceAddresses)
		if !ok {
			sourceAddresses = append([]string(nil), pol.Match.SourceAddresses...)
		}
		destinationAddresses, ok := expandUserspacePolicyAddresses(cfg, pol.Match.DestinationAddresses)
		if !ok {
			destinationAddresses = append([]string(nil), pol.Match.DestinationAddresses...)
		}
		applicationTerms, ok := expandUserspacePolicyApplications(cfg, pol.Match.Applications)
		if !ok {
			applicationTerms = nil
		}
		out = append(out, PolicyRuleSnapshot{
			Name:                 pol.Name,
			FromZone:             "junos-global",
			ToZone:               "junos-global",
			SourceAddresses:      sourceAddresses,
			DestinationAddresses: destinationAddresses,
			Applications:         append([]string(nil), pol.Match.Applications...),
			ApplicationTerms:     applicationTerms,
			Action:               policyActionString(pol.Action),
		})
	}
	return out
}

func policyActionString(action config.PolicyAction) string {
	switch action {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyReject:
		return "reject"
	default:
		return "deny"
	}
}

func buildNeighborSnapshots(cfg *config.Config) []NeighborSnapshot {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]NeighborSnapshot, 0)
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		iface := cfg.Interfaces.Interfaces[name]
		if iface == nil {
			continue
		}
		linuxNames := []string{snapshotLinuxName(cfg, name, iface, nil)}
		if len(iface.Units) > 0 {
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
				linuxNames = append(linuxNames, snapshotLinuxName(cfg, name, iface, unit))
			}
		}
		for _, linuxName := range linuxNames {
			link, err := netlink.LinkByName(linuxName)
			if err != nil || link == nil {
				continue
			}
			for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
				neighs, err := netlink.NeighList(link.Attrs().Index, family)
				if err != nil {
					continue
				}
				for _, neigh := range neighs {
					if neigh.IP == nil {
						continue
					}
					key := fmt.Sprintf("%d/%s", link.Attrs().Index, neigh.IP.String())
					if seen[key] {
						continue
					}
					seen[key] = true
					fam := "inet"
					if family == netlink.FAMILY_V6 {
						fam = "inet6"
					}
					mac := ""
					if neigh.HardwareAddr != nil {
						mac = neigh.HardwareAddr.String()
					}
					out = append(out, NeighborSnapshot{
						Interface: linuxName,
						Ifindex:   link.Attrs().Index,
						Family:    fam,
						IP:        neigh.IP.String(),
						MAC:       mac,
						State:     neighborStateString(neigh.State),
						Router:    neigh.Flags&netlink.NTF_ROUTER != 0,
						LinkLocal: neigh.IP.IsLinkLocalUnicast(),
					})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func neighborStateString(state int) string {
	parts := make([]string, 0, 4)
	if state&netlink.NUD_PERMANENT != 0 {
		parts = append(parts, "permanent")
	}
	if state&netlink.NUD_REACHABLE != 0 {
		parts = append(parts, "reachable")
	}
	if state&netlink.NUD_STALE != 0 {
		parts = append(parts, "stale")
	}
	if state&netlink.NUD_DELAY != 0 {
		parts = append(parts, "delay")
	}
	if state&netlink.NUD_PROBE != 0 {
		parts = append(parts, "probe")
	}
	if state&netlink.NUD_FAILED != 0 {
		parts = append(parts, "failed")
	}
	if state&netlink.NUD_NOARP != 0 {
		parts = append(parts, "noarp")
	}
	if state&netlink.NUD_INCOMPLETE != 0 {
		parts = append(parts, "incomplete")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

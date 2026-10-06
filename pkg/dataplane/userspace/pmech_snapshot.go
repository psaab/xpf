package userspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const pmechMainTable = uint32(unix.RT_TABLE_MAIN)

var pmechMainRouteListFn = func() ([]netlink.Route, error) {
	return netlink.RouteListFiltered(netlink.FAMILY_ALL,
		&netlink.Route{Table: int(pmechMainTable)}, netlink.RT_FILTER_TABLE)
}

type pmechVPNSelectorPolicy struct {
	Name           string                        `json:"name"`
	BindInterface  string                        `json:"bind_interface"`
	Selectors      []IpsecTrafficSelectorSnapshot `json:"selectors,omitempty"`
	Invalid        bool                          `json:"invalid,omitempty"`
}

type pmechPolicyProjection struct {
	Zones                  []ZoneSnapshot               `json:"zones,omitempty"`
	Interfaces             []InterfaceSnapshot          `json:"interfaces,omitempty"`
	DefaultPolicy          string                       `json:"default_policy"`
	DefaultLogSessionInit  bool                         `json:"default_log_session_init"`
	DefaultLogSessionClose bool                         `json:"default_log_session_close"`
	Policies               []PolicyRuleSnapshot         `json:"policies,omitempty"`
	PolicyRematchExtensive bool                         `json:"policy_rematch_extensive"`
	SourceNAT              []SourceNATRuleSnapshot      `json:"source_nat,omitempty"`
	StaticNAT              []StaticNATRuleSnapshot      `json:"static_nat,omitempty"`
	DestinationNAT         []DestinationNATRuleSnapshot `json:"destination_nat,omitempty"`
	NAT64                  []NAT64RuleSnapshot          `json:"nat64,omitempty"`
	Nptv6                  []Nptv6RuleSnapshot          `json:"nptv6,omitempty"`
	Screens                []ScreenProfileSnapshot      `json:"screens,omitempty"`
	ScreenMissingProfiles  []ScreenMissingProfileRef    `json:"screen_missing_profiles,omitempty"`
	ScreenInertProfiles    []ScreenMissingProfileRef    `json:"screen_inert_profiles,omitempty"`
	Filters                []FirewallFilterSnapshot     `json:"filters,omitempty"`
	Policers               []PolicerSnapshot            `json:"policers,omitempty"`
	ThreeColorPolicers     []ThreeColorPolicerSnapshot  `json:"three_color_policers,omitempty"`
	ClassOfService         *ClassOfServiceSnapshot      `json:"class_of_service,omitempty"`
	AddressBooks           []AddressBookSnapshot        `json:"address_books,omitempty"`
	AppCatalog             []AppCatalogEntrySnapshot    `json:"app_catalog,omitempty"`
	VPNSelectors            []pmechVPNSelectorPolicy     `json:"vpn_selectors,omitempty"`
	BindlessSelectorFenceEnabled bool                            `json:"bindless_selector_fence_enabled"`
	BindlessSelectorRows         []IpsecBindlessSelectorSnapshot `json:"bindless_selector_rows,omitempty"`
}

func stampPMechInventory(snap *ConfigSnapshot) {
	if snap == nil {
		return
	}
	routes, err := pmechMainRouteListFn()
	stampPMechInventoryFromRoutes(snap, routes, err)
}

func stampPMechInventoryFromRoutes(snap *ConfigSnapshot, routes []netlink.Route, routeErr error) {
	if snap == nil {
		return
	}
	inventory := &IpsecPMechInventorySnapshot{
		Generation:    snap.Generation,
		FIBGeneration: snap.FIBGeneration,
		Complete:      routeErr == nil,
	}
	snap.PMechInventory = inventory
	if routeErr != nil {
		routes = nil
	}

	parsedRoutes := make([]pmechParsedMainRoute, 0, len(routes))
	for _, route := range routes {
		row, prefix, nextHops, ok := snapshotPMechMainRoute(route)
		inventory.MainRoutes = append(inventory.MainRoutes, row)
		if !ok {
			inventory.Complete = false
			continue
		}
		parsedRoutes = append(parsedRoutes, pmechParsedMainRoute{
			snapshot: row,
			prefix:   prefix,
			nextHops: nextHops,
		})
	}
	sort.Slice(inventory.MainRoutes, func(i, j int) bool {
		return pmechRouteSnapshotKey(inventory.MainRoutes[i]) < pmechRouteSnapshotKey(inventory.MainRoutes[j])
	})

	selectorsBySTN, selectorErrors := pmechSelectorsBySTN(snap.Config)
	inventory.PolicyIdentity = pmechPolicyIdentity(snap)

	inventory.TunnelRows = make([]IpsecPMechTunnelRowSnapshot, len(snap.IpsecTunnelRows))
	ownersByIfindex := make(map[int][]int, len(snap.IpsecTunnelRows))
	for i, identity := range snap.IpsecTunnelRows {
		row := IpsecPMechTunnelRowSnapshot{
			STN:                 identity.STN,
			IfID:                identity.IfID,
			LogicalIfindex:      identity.LogicalIfindex,
			InventoryGeneration: inventory.Generation,
			FIBGeneration:       inventory.FIBGeneration,
			SourceKind:          "xfrmi",
			InventoryComplete:   inventory.Complete,
			InventoryValid:      inventory.Complete && inventory.PolicyIdentity != "",
			ExplicitSelectors:   append([]IpsecTrafficSelectorSnapshot(nil), selectorsBySTN[identity.STN]...),
		}
		if row.IfID == 0 || row.STN == "" || row.LogicalIfindex <= 0 {
			row.InventoryValid = false
			row.InventoryReason = "TUNNEL_IDENTITY_INVALID"
		}
		if inventory.PolicyIdentity == "" {
			row.InventoryValid = false
			row.InventoryReason = "POLICY_IDENTITY_UNAVAILABLE"
		}
		if !inventory.Complete {
			row.InventoryValid = false
			if routeErr != nil {
				row.InventoryReason = "MAIN_ROUTE_DUMP_FAILED"
			} else {
				row.InventoryReason = "MAIN_ROUTE_INVENTORY_INCOMPLETE"
			}
		}
		if selectorErrors[identity.STN] {
			row.InventoryValid = false
			row.InventoryReason = "SELECTOR_PROJECTION_INVALID"
		}
		row.SelectorProvenance = selectorProvenance(row.ExplicitSelectors)
		if len(row.ExplicitSelectors) == 0 && row.InventoryReason == "" {
			row.InventoryValid = false
			row.InventoryReason = "NO_EXPLICIT_SELECTORS"
		}
		inventory.TunnelRows[i] = row
		ownersByIfindex[int(row.LogicalIfindex)] = append(ownersByIfindex[int(row.LogicalIfindex)], i)
	}

	for _, route := range parsedRoutes {
		for _, nextHop := range route.nextHops {
			for _, owner := range ownersByIfindex[int(nextHop.Ifindex)] {
				row := &inventory.TunnelRows[owner]
				for _, selector := range row.ExplicitSelectors {
					if selector.RemoteTS == "" {
						continue
					}
					selectorPrefixes, ok := selectorPrefixes(selector.RemoteTS)
					if !ok {
						row.InventoryValid = false
						row.InventoryReason = "REMOTE_SELECTOR_UNRESOLVED"
						continue
					}
					for _, selectorPrefix := range selectorPrefixes {
						if selectorPrefix.Addr().Is4() != route.prefix.Addr().Is4() {
							continue
						}
						if effective, ok := intersectPrefixes(route.prefix, selectorPrefix); ok {
							row.EffectivePrefixes = append(row.EffectivePrefixes, effective.String())
						}
					}
				}
			}
		}
	}

	for i := range inventory.TunnelRows {
		row := &inventory.TunnelRows[i]
		row.EffectivePrefixes = canonicalPrefixSet(row.EffectivePrefixes)
		row.IngressPrefixes = append([]string(nil), row.EffectivePrefixes...)
		if !hasRemoteSelector(row.ExplicitSelectors) && row.InventoryReason == "" {
			row.InventoryValid = false
			row.InventoryReason = "NO_EXPLICIT_REMOTE_SELECTOR"
		}
		if len(row.EffectivePrefixes) == 0 && row.InventoryReason == "" {
			row.InventoryValid = false
			row.InventoryReason = "NO_OWNED_ROUTE_INTERSECTION"
		}
	}

	for i := 0; i < len(inventory.TunnelRows); i++ {
		for j := i + 1; j < len(inventory.TunnelRows); j++ {
			if tunnelPrefixSetsOverlap(inventory.TunnelRows[i].EffectivePrefixes,
				inventory.TunnelRows[j].EffectivePrefixes) {
				inventory.TunnelRows[i].InventoryValid = false
				inventory.TunnelRows[i].InventoryReason = "DOMAIN_OVERLAP"
				inventory.TunnelRows[j].InventoryValid = false
				inventory.TunnelRows[j].InventoryReason = "DOMAIN_OVERLAP"
			}
		}
	}
}

type pmechParsedMainRoute struct {
	snapshot IpsecMainRouteSnapshot
	prefix   netip.Prefix
	nextHops []IpsecMainRouteNextHopSnapshot
}

func snapshotPMechMainRoute(route netlink.Route) (IpsecMainRouteSnapshot, netip.Prefix,
	[]IpsecMainRouteNextHopSnapshot, bool) {
	row := IpsecMainRouteSnapshot{
		Table:       uint32(route.Table),
		Protocol:    uint8(route.Protocol),
		Disposition: uint8(route.Type),
	}
	valid := route.Table == int(pmechMainTable) && route.Type == unix.RTN_UNICAST &&
		route.Src == nil && route.Tos == 0 && route.Via == nil && route.Encap == nil &&
		route.NewDst == nil && route.MPLSDst == nil
	prefix, family, prefixOK := pmechRoutePrefix(route)
	row.Family = family
	if prefixOK {
		row.Destination = prefix.String()
	}
	valid = valid && prefixOK

	nextHops := make([]IpsecMainRouteNextHopSnapshot, 0, len(route.MultiPath))
	if len(route.MultiPath) > 0 {
		for _, hop := range route.MultiPath {
			if hop == nil || hop.LinkIndex <= 0 {
				valid = false
				continue
			}
			nextHops = append(nextHops, IpsecMainRouteNextHopSnapshot{
				Ifindex: uint32(hop.LinkIndex),
				Weight:  uint32(hop.Hops) + 1,
			})
		}
	} else if route.LinkIndex > 0 {
		nextHops = append(nextHops, IpsecMainRouteNextHopSnapshot{
			Ifindex: uint32(route.LinkIndex),
			Weight:  1,
		})
	} else {
		valid = false
	}
	sort.Slice(nextHops, func(i, j int) bool {
		if nextHops[i].Ifindex != nextHops[j].Ifindex {
			return nextHops[i].Ifindex < nextHops[j].Ifindex
		}
		return nextHops[i].Weight < nextHops[j].Weight
	})
	row.NextHops = nextHops
	return row, prefix, nextHops, valid
}

func pmechRoutePrefix(route netlink.Route) (netip.Prefix, string, bool) {
	family := ""
	switch route.Family {
	case unix.AF_INET:
		family = "inet"
	case unix.AF_INET6:
		family = "inet6"
	case 0:
		// The kernel route dump supplies a family. Allowing an omitted family
		// only for a concrete destination keeps direct pure-builder callers
		// convenient without guessing for a default route.
	default:
		return netip.Prefix{}, "", false
	}

	var prefix netip.Prefix
	if route.Dst == nil {
		if route.Family == unix.AF_INET {
			prefix = netip.MustParsePrefix("0.0.0.0/0")
		} else if route.Family == unix.AF_INET6 {
			prefix = netip.MustParsePrefix("::/0")
		} else {
			return netip.Prefix{}, "", false
		}
	} else {
		parsed, err := netip.ParsePrefix(route.Dst.String())
		if err != nil {
			return netip.Prefix{}, "", false
		}
		prefix = parsed.Masked()
		if family == "" {
			if prefix.Addr().Is4() {
				family = "inet"
			} else {
				family = "inet6"
			}
		}
	}
	if (route.Family == unix.AF_INET && !prefix.Addr().Is4()) ||
		(route.Family == unix.AF_INET6 && !prefix.Addr().Is6()) {
		return netip.Prefix{}, "", false
	}
	return prefix, family, true
}

func pmechRouteSnapshotKey(route IpsecMainRouteSnapshot) string {
	var b strings.Builder
	b.WriteString(route.Family)
	b.WriteByte('|')
	b.WriteString(route.Destination)
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(route.Protocol), 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(route.Disposition), 10))
	for _, hop := range route.NextHops {
		b.WriteByte('|')
		b.WriteString(strconv.FormatUint(uint64(hop.Ifindex), 10))
		b.WriteByte(':')
		b.WriteString(strconv.FormatUint(uint64(hop.Weight), 10))
	}
	return b.String()
}

func pmechSelectorsBySTN(cfg *config.Config) (map[string][]IpsecTrafficSelectorSnapshot, map[string]bool) {
	bySTN := make(map[string][]IpsecTrafficSelectorSnapshot)
	invalid := make(map[string]bool)
	if cfg == nil {
		return bySTN, invalid
	}
	vpns := cfg.Security.IPsec.VPNs
	names := make([]string, 0, len(vpns))
	for name := range vpns {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		vpn := vpns[name]
		if vpn == nil || vpn.BindInterface == "" {
			continue
		}
		selectors, ok := explicitSelectorsForVPN(name, vpn)
		if !ok {
			invalid[vpn.BindInterface] = true
			continue
		}
		bySTN[vpn.BindInterface] = append(bySTN[vpn.BindInterface], selectors...)
	}
	for stn := range bySTN {
		sort.Slice(bySTN[stn], func(i, j int) bool {
			a, b := bySTN[stn][i], bySTN[stn][j]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.LocalTS != b.LocalTS {
				return a.LocalTS < b.LocalTS
			}
			return a.RemoteTS < b.RemoteTS
		})
	}
	return bySTN, invalid
}

func explicitSelectorsForVPN(name string, vpn *config.IPsecVPN) ([]IpsecTrafficSelectorSnapshot, bool) {
	if vpn == nil {
		return nil, false
	}
	for _, selector := range vpn.TrafficSelectors {
		if selector == nil {
			return nil, false
		}
	}
	rendered := ipsec.EffectiveTrafficSelectors(name, vpn)
	if len(vpn.TrafficSelectors) == 0 {
		localExplicit := config.IsTrafficSelectorShape(vpn.LocalID)
		remoteExplicit := config.IsTrafficSelectorShape(vpn.RemoteID)
		if !localExplicit && !remoteExplicit {
			return nil, true
		}
		if len(rendered) != 1 {
			return nil, false
		}
		row := IpsecTrafficSelectorSnapshot{Source: "legacy-id"}
		if localExplicit {
			row.LocalTS = rendered[0].LocalTS
		}
		if remoteExplicit {
			row.RemoteTS = rendered[0].RemoteTS
		}
		return []IpsecTrafficSelectorSnapshot{row}, true
	}

	names := make([]string, 0, len(vpn.TrafficSelectors))
	for selectorName := range vpn.TrafficSelectors {
		names = append(names, selectorName)
	}
	sort.Strings(names)
	rows := make([]IpsecTrafficSelectorSnapshot, 0, len(rendered))
	childIndex := 0
	for _, selectorName := range names {
		selector := vpn.TrafficSelectors[selectorName]
		local, remote := vpn.LocalID, vpn.RemoteID
		if selector.LocalIP != "" {
			local = selector.LocalIP
		}
		if selector.RemoteIP != "" {
			remote = selector.RemoteIP
		}
		if (local != "" && !config.IsTrafficSelectorShape(local)) ||
			(remote != "" && !config.IsTrafficSelectorShape(remote)) {
			continue
		}
		if childIndex >= len(rendered) {
			return nil, false
		}
		child := rendered[childIndex]
		childIndex++
		row := IpsecTrafficSelectorSnapshot{Name: selectorName, Source: "named"}
		if config.IsTrafficSelectorShape(local) {
			row.LocalTS = child.LocalTS
		}
		if config.IsTrafficSelectorShape(remote) {
			row.RemoteTS = child.RemoteTS
		}
		if row.LocalTS != "" || row.RemoteTS != "" {
			rows = append(rows, row)
		}
	}
	if childIndex != len(rendered) {
		return nil, false
	}
	return rows, true
}

func selectorProvenance(selectors []IpsecTrafficSelectorSnapshot) string {
	set := make(map[string]bool)
	for _, selector := range selectors {
		if selector.Source != "" {
			set[selector.Source] = true
		}
	}
	sources := make([]string, 0, len(set))
	for source := range set {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return strings.Join(sources, "+")
}

func hasRemoteSelector(selectors []IpsecTrafficSelectorSnapshot) bool {
	for _, selector := range selectors {
		if selector.RemoteTS != "" {
			return true
		}
	}
	return false
}

func pmechPolicyIdentity(snap *ConfigSnapshot) string {
	if snap == nil {
		return ""
	}
	projection := pmechPolicyProjection{
		Zones:                  snap.Zones,
		Interfaces:             snap.Interfaces,
		DefaultPolicy:          snap.DefaultPolicy,
		DefaultLogSessionInit:  snap.DefaultLogSessionInit,
		DefaultLogSessionClose: snap.DefaultLogSessionClose,
		Policies:               snap.Policies,
		PolicyRematchExtensive: snap.PolicyRematchExtensive,
		SourceNAT:              snap.SourceNAT,
		StaticNAT:              snap.StaticNAT,
		DestinationNAT:         snap.DestinationNAT,
		NAT64:                  snap.NAT64,
		Nptv6:                  snap.Nptv6,
		Screens:                snap.Screens,
		ScreenMissingProfiles:  snap.ScreenMissingProfiles,
		ScreenInertProfiles:    snap.ScreenInertProfiles,
		Filters:                snap.Filters,
		Policers:               snap.Policers,
		ThreeColorPolicers:     snap.ThreeColorPolicers,
		ClassOfService:         snap.ClassOfService,
		AddressBooks:           snap.AddressBooks,
		AppCatalog:                   snap.AppCatalog,
		BindlessSelectorFenceEnabled: snap.BindlessSelectorFenceEnabled,
		BindlessSelectorRows:         snap.BindlessSelectorRows,
	}
	if snap.Config != nil {
		vpnNames := make([]string, 0, len(snap.Config.Security.IPsec.VPNs))
		for name := range snap.Config.Security.IPsec.VPNs {
			vpnNames = append(vpnNames, name)
		}
		sort.Strings(vpnNames)
		for _, name := range vpnNames {
			vpn := snap.Config.Security.IPsec.VPNs[name]
			if vpn == nil {
				continue
			}
			selectors, valid := explicitSelectorsForVPN(name, vpn)
			projection.VPNSelectors = append(projection.VPNSelectors, pmechVPNSelectorPolicy{
				Name:          name,
				BindInterface: vpn.BindInterface,
				Selectors:     selectors,
				Invalid:       !valid,
			})
		}
	}
	encoded, err := json.Marshal(projection)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func selectorPrefixes(selector string) ([]netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(selector); err == nil {
		return []netip.Prefix{prefix.Masked()}, true
	}
	if address, err := netip.ParseAddr(selector); err == nil {
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return []netip.Prefix{netip.PrefixFrom(address, bits)}, true
	}
	parts := strings.SplitN(selector, "-", 2)
	if len(parts) != 2 {
		return nil, false
	}
	start, errStart := netip.ParseAddr(parts[0])
	end, errEnd := netip.ParseAddr(parts[1])
	if errStart != nil || errEnd != nil || start.Is4() != end.Is4() || start.Compare(end) > 0 {
		return nil, false
	}
	startInt, bits := addrToBig(start)
	endInt, endBits := addrToBig(end)
	if bits != endBits {
		return nil, false
	}
	result := make([]netip.Prefix, 0, bits)
	for current := new(big.Int).Set(startInt); current.Cmp(endInt) <= 0; {
		alignment := current.TrailingZeroBits()
		if current.Sign() == 0 {
			alignment = uint(bits)
		}
		remaining := new(big.Int).Sub(endInt, current)
		remaining.Add(remaining, big.NewInt(1))
		fit := uint(remaining.BitLen() - 1)
		exponent := alignment
		if fit < exponent {
			exponent = fit
		}
		prefix := netip.PrefixFrom(bigToAddr(current, bits), bits-int(exponent)).Masked()
		result = append(result, prefix)
		current.Add(current, new(big.Int).Lsh(big.NewInt(1), exponent))
	}
	return result, true
}

func addrToBig(address netip.Addr) (*big.Int, int) {
	if address.Is4() {
		raw := address.As4()
		return new(big.Int).SetBytes(raw[:]), 32
	}
	raw := address.As16()
	return new(big.Int).SetBytes(raw[:]), 128
}

func bigToAddr(value *big.Int, bits int) netip.Addr {
	bytes := value.FillBytes(make([]byte, bits/8))
	if bits == 32 {
		var raw [4]byte
		copy(raw[:], bytes)
		return netip.AddrFrom4(raw)
	}
	var raw [16]byte
	copy(raw[:], bytes)
	return netip.AddrFrom16(raw)
}

func intersectPrefixes(left, right netip.Prefix) (netip.Prefix, bool) {
	if left.Addr().Is4() != right.Addr().Is4() || !left.Overlaps(right) {
		return netip.Prefix{}, false
	}
	if left.Bits() >= right.Bits() {
		return left.Masked(), true
	}
	return right.Masked(), true
}

func canonicalPrefixSet(values []string) []string {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err == nil {
			set[prefix.Masked().String()] = true
		}
	}
	result := make([]string, 0, len(set))
	for prefix := range set {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result
}

func tunnelPrefixSetsOverlap(left, right []string) bool {
	for _, leftValue := range left {
		leftPrefix, err := netip.ParsePrefix(leftValue)
		if err != nil {
			continue
		}
		for _, rightValue := range right {
			rightPrefix, err := netip.ParsePrefix(rightValue)
			if err == nil && leftPrefix.Addr().Is4() == rightPrefix.Addr().Is4() &&
				leftPrefix.Overlaps(rightPrefix) {
				return true
			}
		}
	}
	return false
}


package userspace

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/ipsec"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const pmechMainTable = uint32(unix.RT_TABLE_MAIN)

// RTM_F_LINKDOWN is not exported by the pinned x/sys version. It is transient
// link-liveness metadata, not a destination/output selector. P-MECH remains
// deny-only here; a forwarding slice must enforce link liveness independently.
const pmechRouteFlagLinkDown = 0x10

// pmechMainRouteIterFn streams the main table route by route. The collector
// below keeps only tunnel-relevant routes, so no full-table copy is built.
var pmechMainRouteIterFn = func(visit func(netlink.Route) bool) error {
	return netlink.RouteListFilteredIter(netlink.FAMILY_ALL,
		&netlink.Route{Table: int(pmechMainTable)}, netlink.RT_FILTER_TABLE, visit)
}

var pmechMainRouteSourceSelectorFn = pmechMainRouteHasSourceSelector

func pmechMainRouteSourceSelectorRequest() *nl.NetlinkRequest {
	request := nl.NewNetlinkRequest(unix.RTM_GETROUTE, unix.NLM_F_DUMP)
	message := nl.NewRtMsg()
	message.Family = uint8(netlink.FAMILY_ALL)
	message.Table = uint8(pmechMainTable)
	request.AddData(message)
	table := make([]byte, 4)
	binary.NativeEndian.PutUint32(table, pmechMainTable)
	request.AddData(nl.NewRtAttr(unix.RTA_TABLE, table))
	return request
}

var pmechMainRouteSourceRequestIterFn = func(request *nl.NetlinkRequest, visit func([]byte) bool) error {
	socket, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer socket.Close()
	if err := unix.SetsockoptInt(socket.GetFd(), unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1); err != nil {
		return err
	}
	request.Sockets = map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: socket},
	}
	return request.ExecuteIter(unix.NETLINK_ROUTE, unix.RTM_NEWROUTE, visit)
}

func pmechMainRouteHasSourceSelector() (bool, error) {
	request := pmechMainRouteSourceSelectorRequest()
	var (
		sourceSpecific bool
		parseErr       error
	)
	err := pmechMainRouteSourceRequestIterFn(request, func(raw []byte) bool {
		table, hasSelector, err := pmechRawRouteSourceSelector(raw)
		if err != nil {
			parseErr = err
			return false
		}
		if table == pmechMainTable && hasSelector {
			sourceSpecific = true
			return false
		}
		return true
	})
	if parseErr != nil {
		return false, parseErr
	}
	if err != nil {
		return false, err
	}
	return sourceSpecific, nil
}

func pmechRawRouteSourceSelector(raw []byte) (uint32, bool, error) {
	if len(raw) < unix.SizeofRtMsg {
		return 0, false, fmt.Errorf("short RTM_NEWROUTE payload: %d bytes", len(raw))
	}
	message := nl.DeserializeRtMsg(raw)
	attrs, err := nl.ParseRouteAttr(raw[message.Len():])
	if err != nil {
		return 0, false, err
	}
	table := uint32(message.Table)
	hasSelector := message.Src_len != 0
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case unix.RTA_TABLE:
			if len(attr.Value) != 4 {
				return 0, false, fmt.Errorf("invalid RTA_TABLE length %d", len(attr.Value))
			}
			table = binary.NativeEndian.Uint32(attr.Value)
		case unix.RTA_SRC:
			hasSelector = true
		}
	}
	if message.Flags&uint32(unix.RTM_F_CLONED) != 0 {
		return table, false, nil
	}
	return table, hasSelector, nil
}

type pmechVPNSelectorPolicy struct {
	Name          string                         `json:"name"`
	BindInterface string                         `json:"bind_interface"`
	Selectors     []IpsecTrafficSelectorSnapshot `json:"selectors,omitempty"`
	Invalid       bool                           `json:"invalid,omitempty"`
}

type pmechPolicyProjection struct {
	Zones                        []ZoneSnapshot                  `json:"zones,omitempty"`
	Interfaces                   []InterfaceSnapshot             `json:"interfaces,omitempty"`
	DefaultPolicy                string                          `json:"default_policy"`
	DefaultLogSessionInit        bool                            `json:"default_log_session_init"`
	DefaultLogSessionClose       bool                            `json:"default_log_session_close"`
	Policies                     []PolicyRuleSnapshot            `json:"policies,omitempty"`
	PolicyRematchExtensive       bool                            `json:"policy_rematch_extensive"`
	SourceNAT                    []SourceNATRuleSnapshot         `json:"source_nat,omitempty"`
	StaticNAT                    []StaticNATRuleSnapshot         `json:"static_nat,omitempty"`
	DestinationNAT               []DestinationNATRuleSnapshot    `json:"destination_nat,omitempty"`
	NAT64                        []NAT64RuleSnapshot             `json:"nat64,omitempty"`
	Nptv6                        []Nptv6RuleSnapshot             `json:"nptv6,omitempty"`
	Screens                      []ScreenProfileSnapshot         `json:"screens,omitempty"`
	ScreenMissingProfiles        []ScreenMissingProfileRef       `json:"screen_missing_profiles,omitempty"`
	ScreenInertProfiles          []ScreenMissingProfileRef       `json:"screen_inert_profiles,omitempty"`
	Filters                      []FirewallFilterSnapshot        `json:"filters,omitempty"`
	Policers                     []PolicerSnapshot               `json:"policers,omitempty"`
	ThreeColorPolicers           []ThreeColorPolicerSnapshot     `json:"three_color_policers,omitempty"`
	ClassOfService               *ClassOfServiceSnapshot         `json:"class_of_service,omitempty"`
	AddressBooks                 []AddressBookSnapshot           `json:"address_books,omitempty"`
	AppCatalog                   []AppCatalogEntrySnapshot       `json:"app_catalog,omitempty"`
	VPNSelectors                 []pmechVPNSelectorPolicy        `json:"vpn_selectors,omitempty"`
	BindlessSelectorFenceEnabled bool                            `json:"bindless_selector_fence_enabled"`
	BindlessSelectorRows         []IpsecBindlessSelectorSnapshot `json:"bindless_selector_rows,omitempty"`
}

func stampPMechInventory(snap *ConfigSnapshot) {
	stampPMechInventoryWithPrefetch(snap, nil)
}

// stampPMechInventoryWithPrefetch stamps snap from a matching prefetch, or
// obtains one when called outside a manager lock.
func stampPMechInventoryWithPrefetch(snap *ConfigSnapshot, prefetch *pmechRoutePrefetch) {
	if snap == nil {
		return
	}
	if len(snap.IpsecTunnelRows) == 0 {
		snap.PMechInventory = &IpsecPMechInventorySnapshot{
			Generation:    snap.Generation,
			FIBGeneration: snap.FIBGeneration,
		}
		markPMechInventorySource(snap)
		return
	}
	if !prefetch.matches(snap) {
		prefetch = dumpPMechMainRoutes(snap.Config, snap.IpsecTunnelRows)
	}
	selectorsBySTN, selectorErrors := pmechSelectorsBySTN(snap.Config)
	prefetch.collector.stamp(snap, selectorsBySTN, selectorErrors, prefetch.err, prefetch.sourceSpecific)
	markPMechInventorySource(snap)
}

func markPMechInventorySource(snap *ConfigSnapshot) {
	snap.pmechInventoryConfig = snap.Config
	snap.pmechInventoryRows = append([]IpsecTunnelRowSnapshot(nil), snap.IpsecTunnelRows...)
}

func pmechInventoryMatchesCurrentSource(snap *ConfigSnapshot) bool {
	if snap == nil || snap.PMechInventory == nil || snap.pmechInventoryConfig != snap.Config ||
		snap.PMechInventory.FIBGeneration != snap.FIBGeneration ||
		len(snap.pmechInventoryRows) != len(snap.IpsecTunnelRows) {
		return false
	}
	for i, row := range snap.IpsecTunnelRows {
		source := snap.pmechInventoryRows[i]
		if row.STN != source.STN || row.IfID != source.IfID || row.LogicalIfindex != source.LogicalIfindex {
			return false
		}
	}
	return true
}

// refreshPMechInventoryLocked reuses the already collected FIB snapshot when
// its config, tunnel identities, and FIB generation are unchanged. A locked
// refresh that cannot prove reuse fails closed instead of doing netlink I/O
// while Manager.mu is held.
func refreshPMechInventoryLocked(snap *ConfigSnapshot) {
	if snap == nil {
		return
	}
	if len(snap.IpsecTunnelRows) == 0 {
		stampPMechInventoryWithPrefetch(snap, nil)
		return
	}
	if !pmechInventoryMatchesCurrentSource(snap) {
		stampPMechInventoryWithoutRouteDump(snap,
			fmt.Errorf("P-MECH route inventory cannot be refreshed under manager lock"))
		return
	}
	inventoryCopy := *snap.PMechInventory
	inventoryCopy.TunnelRows = append([]IpsecPMechTunnelRowSnapshot(nil), inventoryCopy.TunnelRows...)
	snap.PMechInventory = &inventoryCopy
	inventory := snap.PMechInventory
	inventory.Generation = snap.Generation
	inventory.PolicyIdentity = pmechPolicyIdentity(snap)
	for i := range inventory.TunnelRows {
		inventory.TunnelRows[i].InventoryGeneration = snap.Generation
		inventory.TunnelRows[i].FIBGeneration = snap.FIBGeneration
		if inventory.PolicyIdentity == "" {
			inventory.TunnelRows[i].InventoryValid = false
			inventory.TunnelRows[i].InventoryReason = "POLICY_IDENTITY_UNAVAILABLE"
		}
	}
}

func stampPMechInventoryWithoutRouteDump(snap *ConfigSnapshot, routeErr error) {
	selectorsBySTN, selectorErrors := pmechSelectorsBySTN(snap.Config)
	collector := newPMechRouteCollector(snap.IpsecTunnelRows, selectorsBySTN)
	collector.stamp(snap, selectorsBySTN, selectorErrors, routeErr, false)
	for i := range snap.PMechInventory.TunnelRows {
		row := &snap.PMechInventory.TunnelRows[i]
		if row.InventoryReason == "MAIN_ROUTE_DUMP_FAILED" {
			row.InventoryReason = "MAIN_ROUTE_INVENTORY_STALE"
		}
	}
	markPMechInventorySource(snap)
}

// pmechRoutePrefetch is one streamed main-table dump, filtered for a config
// and a tunnel row set. FIB bumps take it before the manager lock so the dump
// never runs under m.mu; it is used only if the stamped snapshot still has
// the same config and tunnel identities.
type pmechRoutePrefetch struct {
	config         *config.Config
	rows           []IpsecTunnelRowSnapshot
	collector      *pmechRouteCollector
	err            error
	sourceSpecific bool
}

func dumpPMechMainRoutes(cfg *config.Config, rows []IpsecTunnelRowSnapshot) *pmechRoutePrefetch {
	selectorsBySTN, _ := pmechSelectorsBySTN(cfg)
	prefetch := &pmechRoutePrefetch{
		config:    cfg,
		rows:      append([]IpsecTunnelRowSnapshot(nil), rows...),
		collector: newPMechRouteCollector(rows, selectorsBySTN),
	}
	prefetch.err = pmechMainRouteIterFn(prefetch.collector.add)
	if prefetch.err == nil && prefetch.collector.hasIPv6 {
		prefetch.sourceSpecific, prefetch.err = pmechMainRouteSourceSelectorFn()
	}
	return prefetch
}

func (p *pmechRoutePrefetch) matches(snap *ConfigSnapshot) bool {
	if p == nil || snap == nil || p.config != snap.Config || len(p.rows) != len(snap.IpsecTunnelRows) {
		return false
	}
	for i, row := range snap.IpsecTunnelRows {
		if row.STN != p.rows[i].STN || row.LogicalIfindex != p.rows[i].LogicalIfindex {
			return false
		}
	}
	return true
}

// pmechRouteCollector validates every main-table route it is given but keeps
// only the routes that can change a tunnel row's projection: a route with a
// leg on a tunnel's logical ifindex (ownership and mixed-ECMP poisoning), or
// a route overlapping a remote traffic selector (a more-specific route only
// changes a row's effective prefixes where it intersects the row's
// selectors). The inventory, its sort, and its JSON therefore scale with the
// tunnel-relevant table, not with the whole main table.
type pmechRouteCollector struct {
	tunnelIfindexes map[uint32]struct{}
	remotePrefixes  []netip.Prefix
	total           int
	hasIPv6         bool
	invalid         bool
	rows            []IpsecMainRouteSnapshot
	parsed          []pmechParsedMainRoute
}

func newPMechRouteCollector(tunnelRows []IpsecTunnelRowSnapshot,
	selectorsBySTN map[string][]IpsecTrafficSelectorSnapshot) *pmechRouteCollector {
	collector := &pmechRouteCollector{tunnelIfindexes: make(map[uint32]struct{}, len(tunnelRows))}
	for _, row := range tunnelRows {
		if row.LogicalIfindex > 0 {
			collector.tunnelIfindexes[uint32(row.LogicalIfindex)] = struct{}{}
		}
		for _, selector := range selectorsBySTN[row.STN] {
			if prefixes, ok := selectorPrefixes(selector.RemoteTS); ok {
				collector.remotePrefixes = append(collector.remotePrefixes, prefixes...)
			}
		}
	}
	return collector
}

// add consumes one dumped route; it always continues the dump. An invalid
// route is kept for audit because it withholds authority from the inventory.
func (c *pmechRouteCollector) add(route netlink.Route) bool {
	c.total++
	if route.Family == unix.AF_INET6 {
		c.hasIPv6 = true
	}
	row, prefix, nextHops, ok := snapshotPMechMainRoute(route)
	if !ok {
		c.invalid = true
		c.rows = append(c.rows, row)
		return true
	}
	if !c.relevant(row, prefix) {
		return true
	}
	c.rows = append(c.rows, row)
	c.parsed = append(c.parsed, pmechParsedMainRoute{snapshot: row, prefix: prefix, nextHops: nextHops})
	return true
}

func (c *pmechRouteCollector) relevant(row IpsecMainRouteSnapshot, prefix netip.Prefix) bool {
	for _, hop := range row.NextHops {
		if _, owned := c.tunnelIfindexes[hop.Ifindex]; owned {
			return true
		}
	}
	for _, selector := range c.remotePrefixes {
		if selector.Addr().Is4() == prefix.Addr().Is4() && selector.Overlaps(prefix) {
			return true
		}
	}
	return false
}

func stampPMechInventoryFromRoutes(snap *ConfigSnapshot, routes []netlink.Route, routeErr error) {
	stampPMechInventoryFromRoutesAndSelectors(snap, routes, routeErr, false)
}

func stampPMechInventoryFromRoutesAndSelectors(snap *ConfigSnapshot, routes []netlink.Route,
	routeErr error, sourceSpecificRoutes bool) {

	if snap == nil {
		return
	}
	selectorsBySTN, selectorErrors := pmechSelectorsBySTN(snap.Config)
	collector := newPMechRouteCollector(snap.IpsecTunnelRows, selectorsBySTN)
	for _, route := range routes {
		collector.add(route)
	}
	collector.stamp(snap, selectorsBySTN, selectorErrors, routeErr, sourceSpecificRoutes)
	markPMechInventorySource(snap)
}

// pmechKeyedRoutes sorts retained rows by their precomputed canonical key.
type pmechKeyedRoutes struct {
	rows []IpsecMainRouteSnapshot
	keys []string
}

func (r pmechKeyedRoutes) Len() int           { return len(r.rows) }
func (r pmechKeyedRoutes) Less(i, j int) bool { return r.keys[i] < r.keys[j] }
func (r pmechKeyedRoutes) Swap(i, j int) {
	r.rows[i], r.rows[j] = r.rows[j], r.rows[i]
	r.keys[i], r.keys[j] = r.keys[j], r.keys[i]
}

// stamp freezes the collected routes, selectors, and policy identity into
// snap.PMechInventory.
func (c *pmechRouteCollector) stamp(snap *ConfigSnapshot,
	selectorsBySTN map[string][]IpsecTrafficSelectorSnapshot, selectorErrors map[string]bool,
	routeErr error, sourceSpecificRoutes bool) {

	inventory := &IpsecPMechInventorySnapshot{
		Generation:    snap.Generation,
		FIBGeneration: snap.FIBGeneration,
		Complete:      routeErr == nil && c.total != 0 && !c.invalid && !sourceSpecificRoutes,
	}
	snap.PMechInventory = inventory
	parsedRoutes := c.parsed
	if routeErr == nil {
		inventory.MainRoutes = append([]IpsecMainRouteSnapshot(nil), c.rows...)
	} else {
		parsedRoutes = nil
	}
	firstByPrefix := make(map[netip.Prefix]pmechParsedMainRoute, len(parsedRoutes))
	uniqueRoutes := make([]pmechParsedMainRoute, 0, len(parsedRoutes))
	for _, route := range parsedRoutes {
		if previous, found := firstByPrefix[route.prefix]; found {
			if !samePMechRouteDisposition(previous.snapshot, route.snapshot) {
				inventory.Complete = false
			}
			continue
		}
		firstByPrefix[route.prefix] = route
		uniqueRoutes = append(uniqueRoutes, route)
	}
	parsedRoutes = uniqueRoutes
	keys := make([]string, len(inventory.MainRoutes))
	for i, route := range inventory.MainRoutes {
		keys[i] = pmechRouteSnapshotKey(route)
	}
	sort.Sort(pmechKeyedRoutes{rows: inventory.MainRoutes, keys: keys})

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
			switch {
			case routeErr != nil:
				row.InventoryReason = "MAIN_ROUTE_DUMP_FAILED"
			case sourceSpecificRoutes:
				row.InventoryReason = "MAIN_ROUTE_SOURCE_SELECTOR_UNREPRESENTABLE"
			default:
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

	if !inventory.Complete || len(inventory.TunnelRows) == 0 {
		return
	}
	routeIndex := newPMechRoutePrefixIndex(parsedRoutes)
	mixedECMPPoisoned := false
	for _, route := range parsedRoutes {
		if route.snapshot.Disposition != uint8(unix.RTN_UNICAST) {
			continue
		}
		if pmechRouteHasMixedEgress(route) {
			hasTunnelOwner := false
			for _, nextHop := range route.nextHops {
				if len(ownersByIfindex[int(nextHop.Ifindex)]) > 0 {
					hasTunnelOwner = true
					break
				}
			}
			if hasTunnelOwner {
				mixedECMPPoisoned = true
				continue
			}
		}
		for _, nextHop := range route.nextHops {
			owners := ownersByIfindex[int(nextHop.Ifindex)]
			if len(owners) == 0 {
				continue
			}
			eligiblePrefixes := pmechRoutePrefixesForLegIndex(route, nextHop.Ifindex, routeIndex)
			for _, owner := range owners {
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
					for _, eligible := range eligiblePrefixes {
						for _, selectorPrefix := range selectorPrefixes {
							if selectorPrefix.Addr().Is4() != eligible.Addr().Is4() {
								continue
							}
							if effective, ok := intersectPrefixes(eligible, selectorPrefix); ok {
								row.EffectivePrefixes = append(row.EffectivePrefixes, effective.String())
							}
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
	if mixedECMPPoisoned {
		inventory.Complete = false
		for i := range inventory.TunnelRows {
			row := &inventory.TunnelRows[i]
			row.InventoryComplete = false
			row.InventoryValid = false
			row.InventoryReason = "MAIN_ROUTE_ECMP_AMBIGUOUS"
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
	row := IpsecMainRouteSnapshot{}
	protocolValid := route.Protocol >= 0 && uint64(route.Protocol) <= uint64(^uint8(0))
	if protocolValid {
		row.Protocol = uint8(route.Protocol)
	}
	dispositionValid := route.Type >= 0 && uint64(route.Type) <= uint64(^uint8(0))
	if dispositionValid {
		row.Disposition = uint8(route.Type)
	}
	if route.Table >= 0 && uint64(route.Table) <= uint64(^uint32(0)) {
		row.Table = uint32(route.Table)
	}
	tableValid := route.Table == int(pmechMainTable)
	if tableValid {
		row.Domain = 0
	}
	knownDisposition := route.Type == unix.RTN_UNICAST || route.Type == unix.RTN_LOCAL ||
		route.Type == unix.RTN_BLACKHOLE || route.Type == unix.RTN_UNREACHABLE ||
		route.Type == unix.RTN_PROHIBIT
	// netlink.Route.Src represents RTA_PREFSRC here; true RTA_SRC selectors
	// are detected from raw RTM messages before they can be lost.
	valid := tableValid && protocolValid && dispositionValid && knownDisposition &&
		route.Tos == 0 && route.Via == nil && route.Encap == nil &&
		route.NewDst == nil && route.MPLSDst == nil &&
		route.Flags&^pmechRouteFlagLinkDown == 0 && route.LinkIndex >= 0
	prefix, family, prefixOK := pmechRoutePrefix(route)
	row.Family = family
	if prefixOK {
		row.Destination = prefix.String()
	}
	valid = valid && prefixOK && pmechGatewayMatchesFamily(route.Gw, family)

	capturedHops := make([]IpsecMainRouteNextHopSnapshot, 0, len(route.MultiPath)+1)
	forwardingHops := make([]IpsecMainRouteNextHopSnapshot, 0, len(route.MultiPath)+1)
	if len(route.MultiPath) > 0 {
		if route.LinkIndex != 0 || route.Gw != nil {
			valid = false
		}
		for _, hop := range route.MultiPath {
			if hop == nil {
				capturedHops = append(capturedHops, IpsecMainRouteNextHopSnapshot{})
				valid = false
				continue
			}
			ifindex := uint32(0)
			if hop.LinkIndex > 0 && uint64(hop.LinkIndex) <= uint64(^uint32(0)) {
				ifindex = uint32(hop.LinkIndex)
			} else {
				valid = false
			}
			weight := uint32(0)
			if hop.Hops >= 0 && uint64(hop.Hops) < uint64(^uint32(0)) {
				weight = uint32(hop.Hops) + 1
			} else {
				valid = false
			}
			if hop.NewDst != nil || hop.Encap != nil || hop.Via != nil ||
				hop.Flags&^unix.RTNH_F_LINKDOWN != 0 ||
				!pmechGatewayMatchesFamily(hop.Gw, family) {
				valid = false
			}
			snapshotHop := IpsecMainRouteNextHopSnapshot{Ifindex: ifindex, Weight: weight}
			capturedHops = append(capturedHops, snapshotHop)
			if route.Type == unix.RTN_UNICAST {
				forwardingHops = append(forwardingHops, snapshotHop)
			}
		}
	} else if route.LinkIndex > 0 {
		snapshotHop := IpsecMainRouteNextHopSnapshot{Weight: 1}
		if uint64(route.LinkIndex) <= uint64(^uint32(0)) {
			snapshotHop.Ifindex = uint32(route.LinkIndex)
		} else {
			valid = false
		}
		capturedHops = append(capturedHops, snapshotHop)
		if route.Type == unix.RTN_UNICAST {
			forwardingHops = append(forwardingHops, snapshotHop)
		}
	} else if route.Type == unix.RTN_UNICAST {
		capturedHops = append(capturedHops, IpsecMainRouteNextHopSnapshot{Weight: 1})
		valid = false
	} else if route.LinkIndex < 0 {
		capturedHops = append(capturedHops, IpsecMainRouteNextHopSnapshot{})
		valid = false
	}
	sort.Slice(capturedHops, func(i, j int) bool {
		if capturedHops[i].Ifindex != capturedHops[j].Ifindex {
			return capturedHops[i].Ifindex < capturedHops[j].Ifindex
		}
		return capturedHops[i].Weight < capturedHops[j].Weight
	})
	sort.Slice(forwardingHops, func(i, j int) bool {
		if forwardingHops[i].Ifindex != forwardingHops[j].Ifindex {
			return forwardingHops[i].Ifindex < forwardingHops[j].Ifindex
		}
		return forwardingHops[i].Weight < forwardingHops[j].Weight
	})
	row.NextHops = capturedHops
	if route.Type == unix.RTN_UNICAST && len(forwardingHops) == 0 {
		valid = false
	}
	if route.Type != unix.RTN_UNICAST {
		forwardingHops = nil
	}
	return row, prefix, forwardingHops, valid
}

func pmechGatewayMatchesFamily(gateway []byte, family string) bool {
	if gateway == nil {
		return true
	}
	address, ok := netip.AddrFromSlice(gateway)
	if !ok {
		return false
	}
	address = address.Unmap()
	return (family == "inet" && address.Is4()) || (family == "inet6" && address.Is6())
}

func samePMechRouteDisposition(left, right IpsecMainRouteSnapshot) bool {
	if left.Domain != right.Domain || left.Table != right.Table || left.Family != right.Family ||
		left.Destination != right.Destination || left.Protocol != right.Protocol ||
		left.Disposition != right.Disposition || len(left.NextHops) != len(right.NextHops) {
		return false
	}
	for i := range left.NextHops {
		if left.NextHops[i] != right.NextHops[i] {
			return false
		}
	}
	return true
}

func pmechRouteHasMixedEgress(route pmechParsedMainRoute) bool {
	if len(route.nextHops) < 2 {
		return false
	}
	firstIfindex := route.nextHops[0].Ifindex
	for _, nextHop := range route.nextHops[1:] {
		if nextHop.Ifindex != firstIfindex {
			return true
		}
	}
	return false
}

type pmechRoutePrefixIndex struct {
	ipv4 []pmechParsedMainRoute
	ipv6 []pmechParsedMainRoute
}

func newPMechRoutePrefixIndex(routes []pmechParsedMainRoute) pmechRoutePrefixIndex {
	index := pmechRoutePrefixIndex{}
	for _, route := range routes {
		if route.prefix.Addr().Is4() {
			index.ipv4 = append(index.ipv4, route)
		} else {
			index.ipv6 = append(index.ipv6, route)
		}
	}
	sortByAddress := func(routes []pmechParsedMainRoute) {
		sort.Slice(routes, func(i, j int) bool {
			left, right := routes[i].prefix, routes[j].prefix
			if order := left.Addr().Compare(right.Addr()); order != 0 {
				return order < 0
			}
			return left.Bits() < right.Bits()
		})
	}
	sortByAddress(index.ipv4)
	sortByAddress(index.ipv6)
	return index
}

func pmechRoutePrefixesForLeg(route pmechParsedMainRoute, ifindex uint32,
	routes []pmechParsedMainRoute) []netip.Prefix {
	return pmechRoutePrefixesForLegIndex(route, ifindex, newPMechRoutePrefixIndex(routes))
}

func pmechRoutePrefixesForLegIndex(route pmechParsedMainRoute, ifindex uint32,
	index pmechRoutePrefixIndex) []netip.Prefix {
	routes := index.ipv6
	if route.prefix.Addr().Is4() {
		routes = index.ipv4
	}
	start := sort.Search(len(routes), func(i int) bool {
		return routes[i].prefix.Addr().Compare(route.prefix.Addr()) >= 0
	})
	excluded := make([]netip.Prefix, 0)
	for i := start; i < len(routes); i++ {
		moreSpecific := routes[i]
		if !route.prefix.Contains(moreSpecific.prefix.Addr()) {
			break
		}
		if moreSpecific.prefix.Bits() <= route.prefix.Bits() {
			continue
		}
		keepsLeg := false
		if moreSpecific.snapshot.Disposition == uint8(unix.RTN_UNICAST) {
			for _, nextHop := range moreSpecific.nextHops {
				if nextHop.Ifindex == ifindex {
					keepsLeg = true
					break
				}
			}
		}
		if !keepsLeg {
			excluded = append(excluded, moreSpecific.prefix)
		}
	}
	if len(excluded) == 0 {
		return []netip.Prefix{route.prefix}
	}
	result := make([]netip.Prefix, 0, len(excluded)*2)
	appendPMechPrefixComplement(route.prefix, excluded, 0, len(excluded), &result)
	return result
}

func appendPMechPrefixComplement(prefix netip.Prefix, excluded []netip.Prefix,
	start, end int, result *[]netip.Prefix) {
	if start == end {
		*result = append(*result, prefix)
		return
	}
	if excluded[start].Bits() <= prefix.Bits() && excluded[start].Contains(prefix.Addr()) {
		return
	}
	if prefix.Bits() == prefix.Addr().BitLen() {
		*result = append(*result, prefix)
		return
	}
	left := pmechPrefixChild(prefix, false)
	right := pmechPrefixChild(prefix, true)
	middle := start + sort.Search(end-start, func(i int) bool {
		return excluded[start+i].Addr().Compare(right.Addr()) >= 0
	})
	appendPMechPrefixComplement(left, excluded, start, middle, result)
	appendPMechPrefixComplement(right, excluded, middle, end, result)
}

func pmechPrefixChild(prefix netip.Prefix, right bool) netip.Prefix {
	bits := prefix.Bits()
	address := prefix.Masked().Addr()
	if address.Is4() {
		raw := address.As4()
		if right {
			raw[bits/8] |= 1 << uint(7-bits%8)
		}
		return netip.PrefixFrom(netip.AddrFrom4(raw), bits+1).Masked()
	}
	raw := address.As16()
	if right {
		raw[bits/8] |= 1 << uint(7-bits%8)
	}
	return netip.PrefixFrom(netip.AddrFrom16(raw), bits+1).Masked()
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
	b.WriteString(strconv.FormatUint(uint64(route.Domain), 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(route.Table), 10))
	b.WriteByte('|')
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
		Zones:                        snap.Zones,
		Interfaces:                   snap.Interfaces,
		DefaultPolicy:                snap.DefaultPolicy,
		DefaultLogSessionInit:        snap.DefaultLogSessionInit,
		DefaultLogSessionClose:       snap.DefaultLogSessionClose,
		Policies:                     snap.Policies,
		PolicyRematchExtensive:       snap.PolicyRematchExtensive,
		SourceNAT:                    snap.SourceNAT,
		StaticNAT:                    snap.StaticNAT,
		DestinationNAT:               snap.DestinationNAT,
		NAT64:                        snap.NAT64,
		Nptv6:                        snap.Nptv6,
		Screens:                      snap.Screens,
		ScreenMissingProfiles:        snap.ScreenMissingProfiles,
		ScreenInertProfiles:          snap.ScreenInertProfiles,
		Filters:                      snap.Filters,
		Policers:                     snap.Policers,
		ThreeColorPolicers:           snap.ThreeColorPolicers,
		ClassOfService:               snap.ClassOfService,
		AddressBooks:                 snap.AddressBooks,
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

package routing

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// familyName returns the Junos-style address-family label for a netlink
// address-family constant. It is used to tag a per-family route-dump
// failure so an operator can tell WHICH family's dump failed and thereby
// distinguish a transient partial failure from a genuinely empty table
// (#5125).
func familyName(family int) string {
	if family == netlink.FAMILY_V6 {
		return "inet6"
	}
	return "inet"
}

// RouteEntry represents a kernel routing table entry.
//
// NextHop/Interface carry the single (or, for a multipath route, the
// first) next-hop so existing single-field consumers keep working.
// NextHops is populated only for a kernel ECMP route (one whose
// next-hops live in the netlink RTA_MULTIPATH list rather than the
// single route.Gw); it lists every equal-cost path so `show route`
// can render all of them Junos-style. It is nil for a single-gateway,
// connected/direct, or discard route.
type RouteEntry struct {
	Destination string
	NextHop     string
	Interface   string
	Protocol    string
	Preference  int
	NextHops    []NextHop
}

// NextHop is one path of a (possibly multipath/ECMP) route.
type NextHop struct {
	Gateway   string // gateway IP; "" for a directly-connected leg
	Interface string // egress interface name (or numeric index on lookup miss)
	Weight    int    // ECMP weight (netlink Hops+1); 1 for equal-cost
}

// TableRoutes groups routes by their routing table name.
type TableRoutes struct {
	Name    string       // "inet.0", "VRF-name.inet.0", etc.
	Entries []RouteEntry // routes in this table
}

// routeLister is the minimal netlink read surface the route reader
// needs. Satisfied by *netlink.Handle in production.
type routeLister interface {
	RouteListFilteredIter(family int, filter *netlink.Route, filterMask uint64, fn func(netlink.Route) bool) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
	LinkByIndex(index int) (netlink.Link, error)
	LinkByName(name string) (netlink.Link, error)
}

// routeLinkLister supplies a link-name snapshot before a streaming route dump.
// The production netlink iterator holds its socket lock during callbacks, so
// route conversion must not call LinkByIndex from inside one.
type routeLinkLister interface {
	LinkList() ([]netlink.Link, error)
}

// routeReader reads kernel routing tables and converts them to
// RouteEntry values. It is stateless apart from the borrowed netlink
// read surface.
type routeReader struct {
	ops routeLister
}

// GetRoutesForTable reads routes from a specific kernel routing table.
//
// Each address family is dumped independently. A per-family netlink
// failure is joined into the returned error (tagged with the family name
// and table id) instead of being swallowed, while the family that DID
// succeed is still returned. A non-nil error alongside a non-empty slice
// therefore means "partial result" — callers must render the partial and
// surface the error, never drop the partial (#5125).
func (rr *routeReader) GetRoutesForTable(tableID int) ([]RouteEntry, error) {
	var entries []RouteEntry
	var errs error

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		filter := &netlink.Route{Table: tableID}
		routes, err := rr.ops.RouteListFiltered(family, filter, netlink.RT_FILTER_TABLE)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s route dump failed (table %d): %w", familyName(family), tableID, err))
			continue
		}
		for _, r := range routes {
			entries = append(entries, rr.routeToEntry(r, family))
		}
	}

	return entries, errs
}

// GetRoutes reads the main kernel routing table.
//
// Like GetRoutesForTable, each family is dumped independently and a
// per-family failure is joined into the returned error while the
// successful family's entries are still returned (#5125).
func (rr *routeReader) GetRoutes() ([]RouteEntry, error) {
	var entries []RouteEntry
	var errs error

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := rr.ops.RouteList(nil, family)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s route dump failed (main table): %w", familyName(family), err))
			continue
		}
		for _, r := range routes {
			entries = append(entries, rr.routeToEntry(r, family))
		}
	}

	return entries, errs
}

// StreamRoutes visits main-table routes without materializing either address
// family. Returning false from fn stops the dump; the netlink implementation
// drains the outstanding multipart reply without decoding more route records.
// Per-family errors retain GetRoutes' partial-result contract.
func (rr *routeReader) StreamRoutes(fn func(RouteEntry) bool) (stopped bool, err error) {
	var linkNames map[int]string
	hasLinkSnapshot := false
	if lister, ok := rr.ops.(routeLinkLister); ok {
		hasLinkSnapshot = true
		if links, err := lister.LinkList(); err == nil {
			linkNames = make(map[int]string, len(links))
			for _, link := range links {
				if link != nil && link.Attrs() != nil {
					linkNames[link.Attrs().Index] = link.Attrs().Name
				}
			}
		}
	}
	linkName := func(index int) string {
		if index <= 0 {
			return ""
		}
		if hasLinkSnapshot {
			if name := linkNames[index]; name != "" {
				return name
			}
			return strconv.Itoa(index)
		}
		return rr.linkNameByIndex(index)
	}

	var errs error
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		familyStopped := false
		familyErr := rr.ops.RouteListFilteredIter(family, &netlink.Route{}, 0, func(route netlink.Route) bool {
			entry := rr.routeToEntryWithLinkName(route, family, linkName)
			if !fn(entry) {
				familyStopped = true
				return false
			}
			return true
		})
		if familyStopped {
			return true, errs
		}
		if familyErr != nil {
			errs = errors.Join(errs, fmt.Errorf("%s route dump failed (main table): %w", familyName(family), familyErr))
		}
	}
	return false, errs
}

// GetVRFRoutes reads routes from a VRF's routing table by VRF device name.
func (rr *routeReader) GetVRFRoutes(vrfName string) ([]RouteEntry, error) {
	// VRF devices are created with "vrf-" prefix.
	devName := vrfName
	if !strings.HasPrefix(devName, "vrf-") {
		devName = "vrf-" + devName
	}
	link, err := rr.ops.LinkByName(devName)
	if err != nil {
		return nil, fmt.Errorf("VRF %q not found: %w", vrfName, err)
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok {
		return nil, fmt.Errorf("%q is not a VRF device", vrfName)
	}
	return rr.GetRoutesForTable(int(vrf.Table))
}

// GetTableRoutes returns routes for a Junos-style table name (e.g. "inet.0",
// "inet6.0", "dmz-vr.inet.0", "dmz-vr.inet6.0"). It resolves the VRF and
// filters by address family.
func (rr *routeReader) GetTableRoutes(tableName string) ([]RouteEntry, error) {
	// Determine VRF name and address family from Junos table name.
	vrfName := ""
	isV6 := false
	switch {
	case tableName == "inet.0":
		// main table, IPv4
	case tableName == "inet6.0":
		isV6 = true
	case strings.HasSuffix(tableName, ".inet6.0"):
		vrfName = strings.TrimSuffix(tableName, ".inet6.0")
		isV6 = true
	case strings.HasSuffix(tableName, ".inet.0"):
		vrfName = strings.TrimSuffix(tableName, ".inet.0")
	default:
		// Treat as VRF name directly (backwards compat).
		vrfName = tableName
	}

	var entries []RouteEntry
	var err error
	if vrfName == "" {
		entries, err = rr.GetRoutes()
	} else {
		entries, err = rr.GetVRFRoutes(vrfName)
	}
	if err != nil {
		return nil, err
	}

	// Filter by address family.
	var filtered []RouteEntry
	for _, e := range entries {
		entryIsV6 := strings.Contains(e.Destination, ":")
		if entryIsV6 == isV6 {
			filtered = append(filtered, e)
		}
	}
	return filtered, nil
}

// GetAllTableRoutes returns routes from the main table and all configured VRFs.
// IPv4 and IPv6 routes are split into separate inet.0/inet6.0 tables.
//
// A failure reading the main table or any per-instance table is joined
// into the returned error (tagged with the routing-instance name) rather
// than silently dropping that table, and whatever was successfully read —
// including a single-family partial from GetRoutes/GetRoutesForTable — is
// still returned. Callers render the partial and surface the error (#5125).
func (rr *routeReader) GetAllTableRoutes(instances []*config.RoutingInstanceConfig) ([]TableRoutes, error) {
	var tables []TableRoutes
	var errs error

	// Main table
	mainEntries, err := rr.GetRoutes()
	if err != nil {
		errs = errors.Join(errs, fmt.Errorf("main table: %w", err))
	}
	tables = appendSplitAF(tables, "", mainEntries)

	// Per-VRF tables
	for _, ri := range instances {
		if ri.TableID == 0 {
			continue
		}
		entries, err := rr.GetRoutesForTable(ri.TableID)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("routing-instance %q (table %d): %w", ri.Name, ri.TableID, err))
			// fall through: still render whatever entries were dumped
		}
		tables = appendSplitAF(tables, ri.Name, entries)
	}
	return tables, errs
}

// routeToEntry converts a netlink route to a RouteEntry.
func (rr *routeReader) routeToEntry(r netlink.Route, family int) RouteEntry {
	return rr.routeToEntryWithLinkName(r, family, rr.linkNameByIndex)
}

func (rr *routeReader) routeToEntryWithLinkName(r netlink.Route, family int, linkName func(int) string) RouteEntry {
	entry := RouteEntry{
		Preference: r.Priority,
		Protocol:   rtProtoName(r.Protocol),
	}

	if r.Dst != nil {
		entry.Destination = r.Dst.String()
	} else {
		if family == netlink.FAMILY_V6 {
			entry.Destination = "::/0"
		} else {
			entry.Destination = "0.0.0.0/0"
		}
	}

	if r.Gw != nil {
		entry.NextHop = r.Gw.String()
	} else if r.Type == unix.RTN_BLACKHOLE {
		entry.NextHop = "discard"
	} else if r.Type == unix.RTN_UNREACHABLE {
		// A `route <p> reject` installs as RTN_UNREACHABLE in the kernel
		// FIB (Junos reject → FRR `ip route <p> reject`, #5298). Label it
		// "reject" so the kernel-table view distinguishes it from a
		// silent discard (RTN_BLACKHOLE) and a directly-connected route,
		// matching the `show route` (CLI/gRPC) reject/discard conventions.
		entry.NextHop = "reject"
	} else {
		entry.NextHop = "direct"
	}

	if r.LinkIndex > 0 {
		entry.Interface = linkName(r.LinkIndex)
	}

	// ECMP / multipath: the kernel carries the per-path next-hops in the
	// RTA_MULTIPATH list, not in the single route.Gw (which is nil here).
	// Surface every leg so `show route` can render all of them, and back-
	// fill the single NextHop/Interface fields from the first leg so
	// single-field consumers show a real next-hop rather than "direct".
	if len(r.MultiPath) > 0 {
		entry.NextHops = rr.multiPathNextHops(r.MultiPath, linkName)
		if len(entry.NextHops) > 0 {
			first := entry.NextHops[0]
			if first.Gateway != "" {
				entry.NextHop = first.Gateway
			}
			if first.Interface != "" {
				entry.Interface = first.Interface
			}
		}
	}

	return entry
}

func (rr *routeReader) linkNameByIndex(index int) string {
	link, err := rr.ops.LinkByIndex(index)
	if err == nil && link != nil && link.Attrs() != nil {
		return link.Attrs().Name
	}
	return strconv.Itoa(index)
}

// multiPathNextHops converts a netlink RTA_MULTIPATH next-hop list into
// the display NextHop slice, resolving each leg's ifindex through linkName.
func (rr *routeReader) multiPathNextHops(mp []*netlink.NexthopInfo, linkName func(int) string) []NextHop {
	nhs := make([]NextHop, 0, len(mp))
	for _, nh := range mp {
		if nh == nil {
			continue
		}
		var gw string
		if nh.Gw != nil {
			gw = nh.Gw.String()
		}
		iface := ""
		if nh.LinkIndex > 0 {
			iface = linkName(nh.LinkIndex)
		}
		nhs = append(nhs, NextHop{
			Gateway:   gw,
			Interface: iface,
			Weight:    nh.Hops + 1,
		})
	}
	return nhs
}


// rtprotZStatic is FRR's private rtnetlink protocol value for staticd-
// installed routes (RTPROT_ZSTATIC). It is NOT a Linux UAPI constant, so
// it has no golang.org/x/sys/unix counterpart; FRR's zebra2proto() maps
// ZEBRA_ROUTE_STATIC -> RTPROT_ZSTATIC (zebra/rt_netlink.h, value 196)
// and proto2zebra() reads both RTPROT_STATIC and RTPROT_ZSTATIC back as
// ZEBRA_ROUTE_STATIC.
const rtprotZStatic = 196

// rtProtoName maps a netlink route protocol to its xpf protocol name.
//
// The argument is the kernel rtnetlink rtm_protocol byte. FRR's zebra
// stamps each FIB route with the originating daemon's RTPROT_* value via
// zebra2proto(): bgpd->RTPROT_BGP, ospfd/ospf6d->RTPROT_OSPF,
// isisd->RTPROT_ISIS, ripd->RTPROT_RIP, staticd->RTPROT_ZSTATIC(196),
// connected/local/kernel->RTPROT_KERNEL. RTPROT_ZEBRA(11) is reserved by
// FRR for ZEBRA_ROUTE_TABLE/NHG routes, which xpf does not surface as a
// named protocol, so it falls through to its numeric string like any
// other unrecognized value. The numeric comments record the constant
// values for the reader. The returned name feeds protoTag() and
// junosProtoName() in routeformat.go and the `show route protocol <x>`
// filter in pkg/cli/cli_show_routing.go.
func rtProtoName(p netlink.RouteProtocol) string {
	switch int(p) {
	case unix.RTPROT_REDIRECT: // 1
		return "redirect"
	case unix.RTPROT_KERNEL: // 2 — also FRR connected/local/kernel
		return "connected"
	case unix.RTPROT_BOOT: // 3
		return "dhcp"
	case unix.RTPROT_STATIC: // 4 — manual `ip route` static
		return "static"
	case unix.RTPROT_DHCP: // 16
		return "dhcp"
	case unix.RTPROT_BGP: // 186
		return "bgp"
	case unix.RTPROT_ISIS: // 187
		return "isis"
	case unix.RTPROT_OSPF: // 188
		return "ospf"
	case unix.RTPROT_RIP: // 189
		return "rip"
	case rtprotZStatic: // 196 — FRR staticd (RTPROT_ZSTATIC)
		return "static"
	default:
		return strconv.Itoa(int(p))
	}
}

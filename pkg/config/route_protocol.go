package config

import "golang.org/x/sys/unix"

// RouteProtocol is one row of the kernel route-protocol vocabulary (#17029).
// Every projection of this vocabulary — the rtnetlink byte to internal name
// mapping, the terse single-letter tag, the Junos display name, the
// operator-token normalization, and the `show route protocol` completion —
// derives from routeProtocols below, so adding a protocol touches one row
// instead of five hand-maintained switch tables.
//
// Tag is empty when the protocol has no assigned terse letter; the terse
// formatter renders that as "?". redirect is the one such row (parent
// decision on #17029, 2026-10-27): inventing a letter would be a display
// change with no precedent, so its tag stays explicitly unassigned.
//
// Aliases are accept-only operator spellings beyond Internal: Junos/display
// spellings and normalization tolerances. They are never completion tokens;
// completion offers Internal only.
type RouteProtocol struct {
	Internal string
	RTProtos []int
	Tag      string
	Junos    string
	Aliases  []string
}

// RouteProtocolZStatic is FRR's private rtnetlink protocol value for
// staticd-installed routes (RTPROT_ZSTATIC). It is not a Linux UAPI
// constant, so it has no golang.org/x/sys/unix counterpart; FRR's
// zebra2proto() maps ZEBRA_ROUTE_STATIC -> RTPROT_ZSTATIC
// (zebra/rt_netlink.h, value 196) and proto2zebra() reads both
// RTPROT_STATIC and RTPROT_ZSTATIC back as ZEBRA_ROUTE_STATIC.
const RouteProtocolZStatic = 196

var routeProtocols = []RouteProtocol{
	{Internal: "redirect", RTProtos: []int{unix.RTPROT_REDIRECT}, Junos: "Redirect"},
	{Internal: "connected", RTProtos: []int{unix.RTPROT_KERNEL}, Tag: "C", Junos: "Direct", Aliases: []string{"direct", "local", "kernel"}},
	{Internal: "dhcp", RTProtos: []int{unix.RTPROT_BOOT, unix.RTPROT_DHCP}, Tag: "D", Junos: "Access-internal", Aliases: []string{"access-internal", "access_internal", "access internal"}},
	{Internal: "static", RTProtos: []int{unix.RTPROT_STATIC, RouteProtocolZStatic, ManagementVRFMultipathStaticProtocol}, Tag: "S", Junos: "Static"},
	{Internal: "bgp", RTProtos: []int{unix.RTPROT_BGP}, Tag: "B", Junos: "BGP"},
	{Internal: "isis", RTProtos: []int{unix.RTPROT_ISIS}, Tag: "I", Junos: "IS-IS", Aliases: []string{"is-is"}},
	{Internal: "ospf", RTProtos: []int{unix.RTPROT_OSPF}, Tag: "O", Junos: "OSPF"},
	{Internal: "rip", RTProtos: []int{unix.RTPROT_RIP}, Tag: "R", Junos: "RIP"},
}

// RouteProtocols returns the route-protocol SSOT in table order. The slice
// and its rows' slices are copies, so callers cannot mutate the table.
func RouteProtocols() []RouteProtocol {
	out := make([]RouteProtocol, len(routeProtocols))
	for i, p := range routeProtocols {
		out[i] = p
		out[i].RTProtos = append([]int(nil), p.RTProtos...)
		out[i].Aliases = append([]string(nil), p.Aliases...)
	}
	return out
}

// RouteProtocolNames returns the canonical Internal tokens in table order —
// the `show route protocol` completion vocabulary. Junos spellings and
// other aliases are accept-only and never offered here (#17029).
func RouteProtocolNames() []string {
	out := make([]string, 0, len(routeProtocols))
	for _, p := range routeProtocols {
		out = append(out, p.Internal)
	}
	return out
}

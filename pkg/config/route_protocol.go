package config


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

// RTProtos are kernel UAPI rtm_protocol numbers (linux/rtnetlink.h):
// REDIRECT=1, KERNEL=2, BOOT=3, STATIC=4, BGP=186, ISIS=187,
// OSPF=188, RIP=189, DHCP=16. Literals, not golang.org/x/sys/unix
// constants: pkg/config is the portable leaf (the remote CLI builds
// for darwin/freebsd, where those constants do not exist — #17029
// fold). The values are ABI-fixed and never change.
var routeProtocols = []RouteProtocol{
	{Internal: "redirect", RTProtos: []int{1}, Junos: "Redirect"},
	{Internal: "connected", RTProtos: []int{2}, Tag: "C", Junos: "Direct", Aliases: []string{"direct", "local", "kernel"}},
	{Internal: "dhcp", RTProtos: []int{3, 16}, Tag: "D", Junos: "Access-internal", Aliases: []string{"access-internal", "access_internal", "access internal"}},
	{Internal: "static", RTProtos: []int{4, RouteProtocolZStatic, ManagementVRFMultipathStaticProtocol}, Tag: "S", Junos: "Static"},
	{Internal: "bgp", RTProtos: []int{186}, Tag: "B", Junos: "BGP"},
	{Internal: "isis", RTProtos: []int{187}, Tag: "I", Junos: "IS-IS", Aliases: []string{"is-is"}},
	{Internal: "ospf", RTProtos: []int{188}, Tag: "O", Junos: "OSPF"},
	{Internal: "rip", RTProtos: []int{189}, Tag: "R", Junos: "RIP"},
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

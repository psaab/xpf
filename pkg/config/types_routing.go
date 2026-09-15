package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Routing: routing-options, policy-options, dynamic protocols
// (OSPF/OSPFv3/BGP/RIP/IS-IS/LLDP), router advertisement, tunnels, and
// VRF routing instances.

// PolicyOptionsConfig holds prefix-lists, communities, as-paths, and policy-statements for routing control.
type PolicyOptionsConfig struct {
	PrefixLists      map[string]*PrefixList
	Communities      map[string]*CommunityDef
	ASPaths          map[string]*ASPathDef
	PolicyStatements map[string]*PolicyStatement
}

// ASPathDef defines a named AS-path regular expression for route matching.
type ASPathDef struct {
	Name  string
	Regex string // AS-path regex pattern (e.g. "65000", "65[0-9]+")
	// RegexUnquotedBracket reports that a token of the span Regex was joined
	// from was authored inside an UNQUOTED `[ ... ]` list (#9881). The lexer
	// strips brackets as list sugar, so such a Regex is the JOIN of the
	// surviving tokens (`[0-9]+` becomes `0-9 +`) — a different pattern than
	// the one written, and one no validity check can catch, because the
	// mangled form is itself valid POSIX. The strict commit gate rejects it
	// with a quote-the-regex diagnostic; the FRR renderer omits it on the
	// lenient path. False means "not known to be bracketed", never "known
	// bare": provenance-less trees (legacy persisted configs, synthesized
	// nodes) compile exactly as before.
	RegexUnquotedBracket bool
}

// CommunityDef defines a named BGP community with member values.
type CommunityDef struct {
	Name    string
	Members []string // e.g. "65000:100", "no-export", "no-advertise"
}

// PrefixList defines a named list of IP prefixes.
type PrefixList struct {
	Name     string
	Prefixes []string // CIDR entries ("10.0.0.0/8", "2001:db8::/32")
}

// PolicyStatement defines a routing policy with terms.
type PolicyStatement struct {
	Name          string
	Terms         []*PolicyTerm
	DefaultAction string // "accept", "reject", or "" (implicit reject)
}

// PolicyTerm is a single match+action clause within a policy-statement.
type PolicyTerm struct {
	Name          string
	FromProtocols []string // "direct", "static", "bgp", "ospf" — Junos
	// "from protocol [ bgp ospf static ]" matches ANY listed protocol.
	// PrefixList / FromCommunity / FromASPath hold the term's `from
	// prefix-list`, `from community`, and `from as-path` match statements.
	// Junos permits MULTIPLE sibling match statements of the same type in
	// one term (e.g. `from { community c1; community c2; }`), which match
	// with OR ("any") semantics. They are slices so every repeated match is
	// kept; a single-string field silently dropped all but the last (#2642).
	PrefixList      []string       // from prefix-list <name> (OR across entries)
	FromCommunity   []string       // from community <name> (match community-list; OR)
	FromASPath      []string       // from as-path <name> (match as-path access-list; OR)
	RouteFilters    []*RouteFilter // prefix matching
	Action          string         // "accept", "reject"
	NextHop         string         // then next-hop (e.g. "peer-address", "self", IP)
	LoadBalance     string         // then load-balance (e.g. "consistent-hash", "per-packet")
	LocalPreference int            // BGP local-preference value (valid when HasLocalPreference)
	// HasLocalPreference distinguishes an explicitly configured
	// local-preference (including the valid value 0, which maximally
	// deprioritizes a route within the AS) from "local-preference not
	// configured". A bare int could not tell local-preference-0 apart
	// from unset, so a `set local-preference 0` term silently rendered
	// no `set local-preference` clause (#2857). The renderer must gate
	// the FRR clause on HasLocalPreference, never on LocalPreference > 0.
	HasLocalPreference bool
	Metric             int // BGP MED/metric value (valid when HasMetric)
	// HasMetric distinguishes an explicitly configured metric (including the
	// valid traffic-engineering value 0, e.g. MED 0 = advertise a highly
	// preferred route) from "metric not configured". A bare int could not
	// tell metric-0 apart from unset, so a `set metric 0` term silently
	// rendered no `set metric` clause (#2847). The renderer must gate the
	// FRR clause on HasMetric, never on Metric > 0.
	HasMetric  bool
	MetricType int    // OSPF metric type (1 or 2, 0 = not set)
	Community  string // BGP community to REPLACE with (`then community set <v>` or the bare `then community <v>`; e.g. "65000:100")
	// CommunityOp distinguishes the Junos `then community (add|delete|set)`
	// operations from the legacy bare `then community <value>` (= replace).
	// Junos/vSRX supports append (additive), delete (by community-list), and
	// none (strip all) in addition to whole-attribute replace; emitting only
	// the replace clause (`set community <v>`) wiped any upstream-set
	// communities, a vSRX-parity gap (#2848). The compiler sets CommunityOp
	// to one of "", "set", "add", "delete", "none". Both "" and "set" mean
	// replace using term.Community (the empty string preserves back-compat
	// with the bare `then community <v>` form). For "add" the value lives in
	// CommunityAdd (rendered `set community <v> additive`), for "delete" the
	// referenced community-list NAMES live in CommunityDelete (one
	// `set comm-list <name> delete` line per name — FRR's set clause takes a
	// single community-list per line, so a multi-list
	// `then community delete [ listA listB ]` must accumulate every name, not
	// just the first; #2902), and "none" carries no argument (rendered
	// `set community none`).
	CommunityOp     string   // "", "set", "add", "delete", "none"
	CommunityAdd    string   // community value(s) to append (`then community add <v>`)
	CommunityDelete []string // community-list name(s) whose members to strip (`then community delete <name> ...`)
	Origin          string   // BGP origin: "igp", "egp", "incomplete"
	// ASPathPrepend holds the ordered list of ASNs to prepend to the BGP
	// AS_PATH attribute (`then as-path-prepend "<asn> <asn> ..."`), rendered
	// as the FRR route-map clause `set as-path prepend <asn> <asn> ...`
	// (#2892). AS-path prepending is a fundamental inbound traffic-engineering
	// knob — repeating the local ASN lengthens the advertised path so peers
	// prefer a shorter alternate path. Junos accepts the ASNs as a quoted
	// space-separated string ("65001 65001") or a bracketed list
	// ([ 65001 65001 ]); both flatten to this slice, preserving order and
	// repetition (the count of repeats is the whole point). Empty = no
	// prepend clause is rendered.
	ASPathPrepend []string
}

// RouteFilter matches a prefix with a match type.
type RouteFilter struct {
	Prefix    string // CIDR ("192.168.50.0/24")
	MatchType string // "exact", "longer", "orlonger", "upto", "prefix-length-range", "through"
	UptoLen   int    // for "upto" match type
	// RangeLow / RangeHigh hold the two prefix-length bounds for the
	// "prefix-length-range /low-/high" match type (#2525). Both are 0
	// (unset) for every other match type; parseRouteFilterRange leaves them
	// 0 when the "/low-/high" token is malformed so the renderer/validator
	// can treat 0 unambiguously as "no parseable range".
	RangeLow  int
	RangeHigh int
	// ThroughPrefix holds the second (more-specific) CIDR of a Junos
	// "through <prefix2>" match (#2525). FRR has no lossless equivalent for
	// the two-prefix containment-path semantics of "through", so the strict
	// commit gate rejects it; on the tolerant load/peer-sync path the
	// renderer skips the entry (match-nothing, fail-closed). Empty for every
	// other match type.
	ThroughPrefix string
}

// RoutingOptionsConfig holds static routing configuration.
type RoutingOptionsConfig struct {
	StaticRoutes      []*StaticRoute
	Inet6StaticRoutes []*StaticRoute // rib inet6.0 static routes
	// UnhandledRibs records every `routing-options rib <name>` whose static
	// routes this compiler does not implement, with how many routes were lost
	// (#7512). It exists so the drop can be REPORTED: before #7512 the rib loop
	// matched only the inet6 tables and every other name fell through with no
	// branch and no else, so `rib inet.0 { static { route ... } }` compiled to
	// nothing, committed clean, and emitted no warning.
	UnhandledRibs  []UnhandledRib
	GenerateRoutes []*GenerateRoute
	// ForwardingTableExport is the SELECTED `forwarding-table export` policy —
	// the value nodeVal takes from the first `export` leaf of the first
	// `forwarding-table` block, re-assigned per top-level `routing-options`
	// root so the LAST root wins. It is NOT ForwardingTableExports[0]; see
	// that field.
	ForwardingTableExport string
	// ForwardingTableExports is the FULL `forwarding-table export` list as
	// authored (#6659). The leaf is declared `multi: true`, but the compiler
	// read it with nodeVal and kept only the first policy — so a second policy
	// was neither rendered NOR reference-checked, and a DANGLING reference in
	// any slot but the first committed clean, defeating the very gate
	// (validatePolicyReferencesStrict) whose error text warns that "the
	// expected ECMP / consistent-hash load-balancing would be silently
	// disabled".
	//
	// ForwardingTableExport remains what the FRR renderer consumes (resolveECMP
	// derives ecmpMaxPaths from exactly one policy-statement).
	// validateForwardingTableExportSingleStrict rejects a multi-valued list
	// rather than letting it silently collapse.
	//
	// #6674 RATIFIED that rejection as the permanent contract rather than a
	// pending feature, and the reason is worth stating because "Junos takes a
	// chain here" is true and still does not make a chain implementable.
	// resolveECMP derives exactly TWO booleans from the ONE named policy: any
	// term with a load-balance action sets ecmpMaxPaths to 64, and any term
	// with `consistent-hash` sets fc.ConsistentHash. It evaluates no `from`
	// match, no term order, and no terminating action. Junos evaluates an
	// export chain PER ROUTE and stops at the first terminating action, so the
	// only cheap composition — OR the flags across the chain — is NOT Junos: a
	// route accepted by the first policy never reaches the second, yet the OR
	// would apply the second's load-balance to it. And the faithful reading
	// cannot be expressed at all, because the value being derived is FRR's
	// global `maximum-paths`, which has no per-route form. Supporting a chain
	// therefore needs a per-route forwarding-policy model xpf does not have —
	// a feature, tracked separately, not a bug in this read.
	//
	// #6673: the scalar is NOT element [0] of this list, and the list is read
	// with multiLeafAuthoredValues so empty values are KEPT. Two shapes make
	// the two differ, and both change which policy renders:
	//
	//   - an empty value in the first slot (`export [ "" p1 ];`, `export [ ];
	//     export p1;`, `export { ""; p1; }`, or the flat-set `export ""` +
	//     `export p1` pair). nodeVal selects "" — no export policy — which is
	//     what an operator blanking the export gets; an empty-FILTERED [0]
	//     promoted p1 into the selected slot instead.
	//   - two top-level `routing-options` roots. compiler_dispatch.go calls
	//     compileRoutingOptions once per root, so the scalar re-assigns (LAST
	//     wins) while this list appends — [0] names the FIRST root's policy.
	//
	// Keeping empty values guarantees the list always contains the selected
	// value, so the gates and diagnostics reading it describe the policy that
	// actually renders. An empty entry is a selection, not a second policy:
	// count with nonEmptyValues and skip empties when checking a reference.
	ForwardingTableExports    []string
	AutonomousSystem          uint32 // autonomous-system <number>
	RibGroups                 map[string]*RibGroup
	InterfaceRoutesRibGroup   string // global interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string // global interface-routes { rib-group inet6 <name>; }
}

// GenerateRoute defines a Junos generate (aggregate) route.
// In FRR, these become blackhole/reject static routes or BGP aggregate-address.
type GenerateRoute struct {
	Prefix  string // route prefix (e.g. "192.168.0.0/16")
	Policy  string // contributing route policy (optional)
	Discard bool   // discard traffic to this route (blackhole)
}

// RibGroup defines a RIB group for route sharing between routing instances.
type RibGroup struct {
	Name       string
	ImportRibs []string // import-rib [ rib1 rib2 ... ]
}

// ConnectedNetworkPrefix converts an interface address in CIDR form
// (e.g. "10.0.1.1/24" or "2001:db8::1/64") to its masked network prefix
// ("10.0.1.0/24"), applying the connected-route skip rules shared by the
// userspace FIB connected-route builder (pkg/dataplane/userspace,
// connectedPrefixesForInterface) and the rib-group per-prefix leak
// (pkg/routing, #3876). Both callers derive the SAME prefix set from an
// address so the ip rules the leak installs match the connected routes the
// FIB actually carries in the source table.
//
// A host address (/32 IPv4, /128 IPv6), a default route (/0), and an IPv6
// link-local address carry no leakable connected network and return
// ok=false. family is "inet" or "inet6". Unparseable input returns ok=false.
func ConnectedNetworkPrefix(cidr string) (prefix, family string, ok bool) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || network == nil {
		return "", "", false
	}
	ones, bits := network.Mask.Size()
	if ones <= 0 || ones == bits {
		// Default route (/0) or a host route (/32, /128) — no connected
		// network prefix to leak.
		return "", "", false
	}
	if ip.To4() == nil {
		family = "inet6"
		if ip.IsLinkLocalUnicast() {
			return "", "inet6", false
		}
	} else {
		family = "inet"
	}
	network.IP = ip.Mask(network.Mask)
	return network.String(), family, true
}

// NextHopEntry defines a single next-hop for a static route.
type NextHopEntry struct {
	Address   string // IP address (e.g. "10.0.1.1" or "fe80::1")
	Interface string // outgoing interface (for IPv6 link-local)
	// Preference is this next-hop's own administrative distance, carried from
	// a `qualified-next-hop <gw> { preference N; }` (#3871 — the Junos
	// FLOATING-static idiom: a primary next-hop plus a less-preferred backup).
	// Valid only when HasPreference. A plain `next-hop` leaves HasPreference
	// false and renders at the ROUTE-level distance (StaticRoute.Preference),
	// so plain `next-hop [ a b ]` stays equal-cost ECMP while a qualified
	// backup renders at its own higher distance and installs only when the
	// primary next-hop is down. Folding the qualified preference into the
	// single route-level Preference (the pre-#3871 behavior) rendered every
	// next-hop at equal cost, so the floating static load-balanced over the
	// backup instead of preferring the primary.
	Preference    int
	HasPreference bool
	// Metric is this next-hop's `qualified-next-hop <gw> { metric M; }` value
	// (#3871). Carried in the typed config for parity/display; FRR's static
	// route CLI (`ip route NET GW [DISTANCE]`) has no per-route metric field,
	// so the floating behavior is expressed entirely through the per-next-hop
	// admin distance (Preference), not Metric. Valid only when HasMetric.
	Metric    int
	HasMetric bool
}

// StaticRoute defines a single static route.
type StaticRoute struct {
	Destination string         // CIDR: "10.0.0.0/8" or "::/0"
	NextHops    []NextHopEntry // multiple next-hops = ECMP
	Discard     bool           // null route (blackhole): silently drop matching traffic
	// Reject installs an unreachable route: matching traffic is dropped AND an
	// ICMP unreachable is returned to the source (Junos `route <p> reject` →
	// FRR `ip route <p> reject`). Distinct from Discard (Junos `discard` → FRR
	// Null0/blackhole, a silent drop). Both suppress a next-hop; Reject and
	// Discard are mutually exclusive per route (Junos allows only one action).
	Reject     bool
	Preference int // route preference (admin distance), default 5
	// HasPreference distinguishes an explicitly configured preference --
	// INCLUDING one equal to the default 5 -- from an absent one (#9125).
	//
	// Without it the merge of two hierarchical `route <p> { }` blocks tested
	// `route.Preference != 5` to decide whether the later block said anything,
	// so an operator who wrote `preference 5` was indistinguishable from one
	// who wrote nothing and their statement was silently dropped:
	//
	//	route 10.0.0.0/8 { next-hop 192.0.2.1; preference 10; }
	//	route 10.0.0.0/8 { preference 5; }        -> compiled Preference = 10
	//
	// while `preference 7` in the same position compiled to 7. NextHopEntry
	// already carries HasPreference and HasMetric for exactly this reason; this
	// is the same bit at the route level, and the sibling's existence is why
	// the omission was invisible -- the pattern was in the file, one type over.
	//
	// `json:"-"` IS LOAD-BEARING. ConfigSnapshot embeds the whole typed Config,
	// so every exported field on a config struct is on the HELPER WIRE and moves
	// the #8892 shape digest. This bit is compiler-internal: it exists to let
	// the merge of two `route <p> { }` blocks tell an authored `preference 5`
	// from an absent one, and the helper reads Preference. Serializing it would
	// have forced a ProtocolVersion bump for a value no helper reads --
	// the same choice LifetimeSecondsInvalidSpec (#9008) made for the same
	// reason.
	//
	// Nothing is lost by not persisting it: the config DB stores the TREE, and
	// the bit is recomputed by the compiler on every load.
	HasPreference bool   `json:"-"`
	NextTable     string // routing instance name for inter-VRF route leaking (e.g. "Comcast.inet.0" → "Comcast")
	// NextTableRaw preserves the operator's original next-table token
	// (e.g. "Comcast.inet.0") before parseNextTableInstance strips the
	// family/index suffix. The commit-time definedness gate
	// (validateNextTableTargetReferencesStrict) reports this raw token so
	// the error names exactly what was typed, and the raw grammar is not
	// lost before validation runs (#5693). Empty when no next-table.
	NextTableRaw string
}

// ProtocolsConfig holds dynamic routing protocol configuration.
type ProtocolsConfig struct {
	OSPF                *OSPFConfig
	OSPFv3              *OSPFv3Config
	BGP                 *BGPConfig
	RIP                 *RIPConfig
	ISIS                *ISISConfig
	RouterAdvertisement []*RAInterfaceConfig
	LLDP                *LLDPConfig
}

// LLDPConfig holds LLDP (Link Layer Discovery Protocol) configuration.
type LLDPConfig struct {
	Interfaces     []LLDPInterface // interfaces to enable LLDP on
	Interval       int             // transmit interval in seconds (0 = default 30)
	HoldMultiplier int             // hold multiplier (0 = default 4)
	Disable        bool            // globally disable LLDP
}

// LLDPInterface holds per-interface LLDP configuration.
type LLDPInterface struct {
	Name    string
	Disable bool // per-interface disable
}

// OSPFv3Config holds OSPFv3 (IPv6 OSPF) routing configuration.
type OSPFv3Config struct {
	RouterID string
	Areas    []*OSPFv3Area
	Export   []string
}

// OSPFv3Area defines an OSPFv3 area.
type OSPFv3Area struct {
	ID         string // "0.0.0.0" (backbone) or area number
	Interfaces []*OSPFv3Interface
}

// OSPFv3Interface defines an interface participating in OSPFv3.
type OSPFv3Interface struct {
	Name          string
	Passive       bool
	Cost          int
	HelloInterval int  // hello-interval in seconds, 0 = ospf6d default (10)
	DeadInterval  int  // dead-interval in seconds, 0 = ospf6d default (40)
	RetransmitInt int  // retransmit-interval in seconds, 0 = ospf6d default (5)
	Priority      int  // DR-election priority (valid when HasPriority)
	HasPriority   bool // priority explicitly set; 0 is a valid value ("never DR")
	BFD           bool // enable BFD on this interface
	BFDInterval   int  // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int  // BFD detect-multiplier (0 = default)
}

// RIPConfig holds RIP routing configuration.
type RIPConfig struct {
	Interfaces   []string // interfaces participating in RIP
	Passive      []string // passive interfaces (receive only)
	Redistribute []string // "connected", "static", "ospf"
	AuthKey      Secret   // authentication key/password; redacted on marshal (#2053)
	AuthType     string   // "md5" or "simple"
}

// ISISConfig holds IS-IS routing configuration.
type ISISConfig struct {
	NET             string // ISO NET address (e.g. "49.0001.0100.0000.0001.00")
	Level           string // "level-1", "level-2", "level-1-2" (default "level-2")
	Interfaces      []*ISISInterface
	Export          []string // "connected", "static", etc.
	AuthKey         Secret   // area-level authentication key; redacted on marshal (#2053)
	AuthType        string   // "md5" or "simple" (plaintext)
	WideMetricsOnly bool     // use wide (32-bit) metrics
	Overload        bool     // set overload bit
}

// ISISInterface defines an interface participating in IS-IS.
type ISISInterface struct {
	Name          string
	Level         string // override per-interface
	Passive       bool
	Metric        int    // 0 = default
	AuthKey       Secret // per-interface authentication key; redacted on marshal (#2053)
	AuthType      string // "md5" or "simple"
	BFD           bool   // enable BFD on this interface
	BFDInterval   int    // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int    // BFD detect-multiplier (0 = default)
}

// RAInterfaceConfig configures Router Advertisement on an interface.
type RAInterfaceConfig struct {
	Interface     string
	ManagedConfig bool   // managed-configuration (M flag)
	OtherStateful bool   // other-stateful-configuration (O flag)
	Preference    string // "high", "medium", "low" (default: medium)
	// DefaultLifetime is the RA header Router Lifetime in seconds (RFC 4861
	// §4.2). It is meaningful ONLY when DefaultLifetimeSet is true; an
	// EXPLICIT 0 means "not a default router" (RFC 4861 §6.2.1) and MUST be
	// preserved through to the wire. When DefaultLifetimeSet is false the
	// field is unset and readers default it to defaultRouterLifetime (1800).
	// Do NOT treat 0 as "unset" — that conflation (#4119) made an explicit
	// 0 indistinguishable from absent and coerced it back to 1800.
	DefaultLifetime    int
	DefaultLifetimeSet bool // true when default-lifetime was explicitly configured
	MaxAdvInterval     int  // seconds, 0 = default (600)
	MinAdvInterval     int  // seconds, 0 = default (200)
	Prefixes           []*RAPrefix
	DNSServers         []string // recursive DNS server addresses
	NAT64Prefix        string   // PREF64 prefix (e.g. "64:ff9b::/96")
	NAT64PrefixLife    int      // PREF64 lifetime in seconds (0 = default)
	LinkMTU            int      // advertised link MTU, 0 = omit
	SourceLinkLocal    string   // explicit link-local to use as RA source (overrides auto-selected)
	// ReachableTime / RetransTimer are the RFC 4861 §4.2 RA header fields,
	// in milliseconds (#4307). 0 = "unspecified" (host uses its own
	// default), which is the pre-#4307 wire behavior.
	ReachableTime int // reachable-time (ms), 0 = unspecified
	RetransTimer  int // retransmit-timer (ms), 0 = unspecified
}

// RAPrefix defines a prefix advertised via RA.
type RAPrefix struct {
	Prefix        string // CIDR notation
	OnLink        bool   // on-link flag (default true)
	Autonomous    bool   // SLAAC autonomous flag (default true)
	ValidLifetime int    // seconds, 0 = default (2592000 = 30 days)
	PreferredLife int    // seconds, 0 = default (604800 = 7 days)
	// Delegated marks a prefix DERIVED from a DHCPv6 IA_PD delegation rather
	// than authored by the operator (#6587).
	//
	// It exists because pkg/ra cannot otherwise tell the two apart, and the
	// right answer differs: a delegated /0 is upstream garbage and must never
	// be advertised on-link + autonomous to the LAN, while an operator-authored
	// `::/0` is a legitimate configuration a blanket floor would silently
	// break. #6581 fixed the same class at the DHCPv6 DECODER for exactly this
	// reason — by the time a prefix reaches pkg/ra the provenance was gone.
	//
	// Set ONLY by buildRAConfigs (pkg/daemon) on the PD path. The compiler
	// leaves it at the zero value, so operator-authored prefixes stay false by
	// construction and no compiler change is needed.
	Delegated bool
}

// OSPFConfig holds OSPF routing configuration.
type OSPFConfig struct {
	RouterID string // e.g. "10.0.0.1"
	// #9408: MEGABITS PER SECOND — the unit FRR's `auto-cost
	// reference-bandwidth (1-4294967)` takes, NOT the bits/s the Junos leaf
	// is written in. The name carries the unit because the two differ by
	// 10^6 and the field is the boundary between them: the operator's token
	// is parsed and converted by ospfReferenceBandwidthMbps in
	// compileProtocols, and pkg/frr renders this field verbatim. 0 means
	// unset — no auto-cost line is emitted and FRR's own default (100 Mbps)
	// applies.
	ReferenceBandwidthMbps int
	PassiveDefault         bool // all interfaces passive by default
	Areas                  []*OSPFArea
	Export                 []string // export policy names (future)
}

// OSPFArea defines an OSPF area.
type OSPFArea struct {
	ID           string // "0.0.0.0" (backbone) or area number
	AreaType     string // "stub", "nssa", "" (normal)
	NoSummary    bool   // stub/nssa no-summary (totally stubby)
	Interfaces   []*OSPFInterface
	VirtualLinks []*OSPFVirtualLink
}

// OSPFVirtualLink defines a virtual link to the backbone through a transit area.
type OSPFVirtualLink struct {
	NeighborID  string // router-id of ABR at the other end
	TransitArea string // the area this virtual-link traverses (the area ID where it's configured)
}

// OSPFInterface defines an interface participating in OSPF.
type OSPFInterface struct {
	Name          string
	Passive       bool   // passive interface (no hello)
	NoPassive     bool   // override passive-default (explicitly active)
	Cost          int    // OSPF cost, 0 = default
	HelloInterval int    // hello-interval in seconds, 0 = FRR default (10)
	DeadInterval  int    // dead-interval (router-dead-interval) in seconds, 0 = FRR default (40)
	RetransmitInt int    // retransmit-interval in seconds, 0 = FRR default (5)
	Priority      int    // DR-election priority (valid when HasPriority)
	HasPriority   bool   // priority explicitly set; 0 is a valid value ("never DR"), so a bare int cannot distinguish it from unset
	NetworkType   string // "point-to-point", "broadcast", "" (default)
	AuthType      string // "md5", "simple", "" (none)
	AuthKey       Secret // authentication key/password; redacted on marshal (#2053)
	AuthKeyID     int    // key-id for MD5 (1-255)
	BFD           bool   // enable BFD on this interface
	BFDInterval   int    // BFD minimum-interval in ms (0 = default)
	BFDMultiplier int    // BFD detect-multiplier (0 = default)
}

// BGPConfig holds BGP routing configuration.
type BGPConfig struct {
	LocalAS              uint32
	RouterID             string
	ClusterID            string // route reflector cluster ID
	GracefulRestart      bool   // enable graceful restart
	Multipath            int    // maximum equal-cost paths (0 = disabled)
	MultipathMultipleAS  bool   // allow multipath across different ASes
	MultipathIBGP        bool   // also enable iBGP multipath (FRR `maximum-paths ibgp`)
	LogNeighborChanges   bool   // log neighbor state transitions
	Dampening            bool   // enable route flap dampening
	DampeningHalfLife    int    // half-life in minutes (default 15)
	DampeningReuse       int    // reuse threshold (default 750)
	DampeningSuppress    int    // suppress threshold (default 2000)
	DampeningMaxSuppress int    // max suppress time in minutes (default 60)
	Neighbors            []*BGPNeighbor
	Export               []string // "connected", "static", "ospf", etc.
	Import               []string // inbound filter policy-statements (route-map in); #2490
}

// BGPNeighbor defines a BGP peer.
type BGPNeighbor struct {
	Address              string // peer IP
	PeerAS               uint32
	LocalAS              uint32 // per-peering local-as (FRR `neighbor X local-as`); 0 = inherit router AS
	LocalAddress         string // BGP session source (FRR `neighbor X update-source`); "" = none
	HoldTime             int    // hold-time in seconds (FRR `neighbor X timers <keepalive> <hold>`); 0 = FRR default (180)
	Passive              bool   // do not initiate — wait for the peer (FRR `neighbor X passive`)
	Description          string
	MultihopTTL          int      // 0 = directly connected
	Export               []string // export policies (route-map out): group default + per-neighbor override; last wins (most-specific)
	Import               []string // import policies (route-map in): group default + per-neighbor override; last wins (most-specific); #2490
	FamilyInet           bool     // activate under address-family ipv4 unicast
	FamilyInet6          bool     // activate under address-family ipv6 unicast
	GroupName            string   // BGP group name (for display)
	AuthPassword         Secret   // TCP MD5 password for BGP session; redacted on marshal (#2053)
	BFD                  bool     // enable BFD for this neighbor
	BFDInterval          int      // BFD minimum interval in ms (0 = default 300)
	BFDMultiplier        int      // BFD detect-multiplier (0 = default 3)
	RouteReflectorClient bool     // mark as route-reflector client
	DefaultOriginate     bool     // advertise default route to this neighbor
	AllowASIn            int      // allow own AS in path N times (0 = disabled)
	RemovePrivateAS      bool     // strip private AS numbers from updates
	PrefixLimitInet      int      // max IPv4 prefixes (0 = unlimited)
	PrefixLimitInet6     int      // max IPv6 prefixes (0 = unlimited)
}

// TunnelConfig defines a GRE, IPIP, or other tunnel interface.
type TunnelConfig struct {
	Name            string   // Linux interface name (e.g. "gr-0-0-0", "ip-0-0-0")
	Mode            string   // "gre" or "ipip"
	Source          string   // local tunnel endpoint IP
	Destination     string   // remote tunnel endpoint IP
	Key             uint32   // GRE key, 0 = none
	TTL             int      // tunnel TTL, 0 = default 64
	Addresses       []string // IPs to assign to tunnel interface (CIDR)
	RoutingInstance string   // destination routing-instance (VRF)
	Keepalive       int      // keepalive interval in seconds (0 = disabled)
	KeepaliveRetry  int      // number of missed keepalives before declaring down (0 = default 3)
	AnchorOnly      bool     // create a dummy anchor instead of a kernel tunnel device

	// MTU is the config-desired link MTU for the tunnel device (#1884):
	// the owning interface's `mtu` statement (unit-level overrides
	// interface-level for unit tunnels, mirroring compiler_iface
	// precedence). 0 means unconfigured — the tunnel manager then never
	// writes MTU except the one-time TUN-default normalization when
	// ADOPTING an anchor it did not create (wireguard→gre same-name flip
	// repair). Populated by collectAppliedTunnels; the legacy
	// standalone-CLI apply path leaves it 0.
	MTU int

	// RIListMember is the routing-instance whose `interface` LIST names
	// this tunnel (after the daemon step-0a name normalization), or ""
	// (#1884). It is NOT a bind instruction — daemon_apply step 0a owns
	// list binds. The tunnel manager uses it as (a) an unbind VETO so a
	// stanza→list move never strips the 0a bind, and (b) the
	// observation-fallback claim target for later unbind-on-removal.
	// Populated by collectAppliedTunnels; the legacy CLI path leaves "".
	RIListMember string

	// WireGuard (#1432 S2a, multi-peer #1434). Populated only when
	// Mode == "wireguard". Minimal generic surface (the #1703 "generic
	// stanza") — not the full Junos wireguard grammar (S6).
	//
	// WgListenPort / WgLocalPrivkeyHex are TUNNEL-level (one kernel UDP
	// socket, one local identity per WG interface). WgPeers is the
	// ordered per-peer set (#1434): a WG interface may terminate N
	// peers, each with its own pubkey, AllowedIPs (cryptokey routing),
	// endpoint, keepalive, and optional preshared key. The compiler
	// sorts WgPeers by pubkey at the snapshot-builder boundary so both
	// HA nodes serialize byte-identical snapshots (compile determinism,
	// docs/research/1434-multitunnel-wg/plan.md §5.4).
	WgListenPort      uint16         // local UDP listen port for inbound WG
	WgLocalPrivkeyHex Secret         // local static X25519 private key (hex, 64 chars); redacted on marshal (#2053)
	WgPeers           []WgPeerConfig // ordered per-peer set (#1434)
}

// WgPeerConfig is one WireGuard peer on a WG tunnel (#1434). A tunnel
// holds an ordered slice of these (TunnelConfig.WgPeers). The pubkey is
// the peer identity (the named-instance key in the schema); the compiler
// hard-rejects duplicate pubkeys at commit so the slice never carries
// two peers with one identity (the engine's reconcile_peers contract,
// userspace-dp wg/engine.rs).
type WgPeerConfig struct {
	PublicKeyHex    string   // peer static X25519 public key (hex, 64 chars)
	AllowedIPs      []string // this peer's AllowedIPs (CIDR) — cryptokey routing / decap inner-src gate
	Endpoint        string   // optional peer endpoint IP:port (initiator role)
	KeepaliveSecs   uint16   // optional persistent-keepalive seconds (0 = off)
	PresharedKeyHex Secret   // optional per-peer PSK (hex, 64 chars); "" = zero PSK (#1434 B2); redacted on marshal
}

// MarshalJSON redacts a credential embedded in a WireGuard peer ENDPOINT
// (#6733).
//
// A peer endpoint is a host:port, which RedactURL returns unchanged (measured,
// including bare IPv4/IPv6 literals), so this is defence in depth rather than a
// live leak: it costs nothing for every real configuration and removes the need
// to assert, in a census row nobody re-checks, that this field can never hold a
// credential. The #6733 census fails on any URL-shaped field that renders a
// planted credential verbatim, and an empty census is a stronger end state than
// a justified one.
//
// The alias type sheds this method to avoid recursion while preserving every
// field, so a field added to WgPeerConfig later is still marshalled.
func (w WgPeerConfig) MarshalJSON() ([]byte, error) {
	type alias WgPeerConfig
	v := alias(w)
	v.Endpoint = RedactURL(v.Endpoint)
	return json.Marshal(v)
}

// String redacts WgLocalPrivkeyHex AND every per-peer PresharedKeyHex so
// a `%v`/`%s`/slog format of a TunnelConfig never leaks WireGuard secret
// key material (#1432 S2a privkey hygiene + #1434 B2 PSK hygiene). The
// Rust side already zeroizes + redacts its copy; this closes the Go-side
// cleartext-log exposure.
func (tc *TunnelConfig) String() string {
	if tc == nil {
		return "<nil>"
	}
	priv := "<unset>"
	if tc.WgLocalPrivkeyHex != "" {
		priv = "<redacted>"
	}
	peers := make([]string, 0, len(tc.WgPeers))
	for _, p := range tc.WgPeers {
		psk := "<unset>"
		if p.PresharedKeyHex != "" {
			psk = "<redacted>"
		}
		peers = append(peers, fmt.Sprintf(
			"{PublicKeyHex:%s AllowedIPs:%v Endpoint:%s KeepaliveSecs:%d PresharedKeyHex:%s}",
			p.PublicKeyHex, p.AllowedIPs, p.Endpoint, p.KeepaliveSecs, psk))
	}
	return fmt.Sprintf("TunnelConfig{Name:%s Mode:%s Source:%s Destination:%s "+
		"WgListenPort:%d WgLocalPrivkeyHex:%s WgPeers:[%s]}",
		tc.Name, tc.Mode, tc.Source, tc.Destination,
		tc.WgListenPort, priv, strings.Join(peers, " "))
}

// cloneForUnit returns a deep copy of tc for a per-unit tunnel netdev,
// with Name overridden to linuxName. Every reference-typed field is
// given an INDEPENDENT backing array so a per-unit override on one unit
// (e.g. appending its own Addresses or WgPeers) never mutates a slice
// that a sibling unit inherited from the same interface-level tunnel
// (#3898). A plain `*tc = *ifc.Tunnel` struct copy only copies the
// slice headers (ptr+len+cap), so siblings would alias the parent's
// backing array and cross-contaminate each other's IPs / peers.
//
// Deep-copied fields (audit of TunnelConfig for reference types):
//   - Addresses      []string
//   - WgPeers         []WgPeerConfig, and each peer's nested AllowedIPs []string
//
// All other fields are value types (strings, ints, uint32, uint16,
// bool, Secret which is a string alias) and are safe to copy by value.
func (tc *TunnelConfig) cloneForUnit(linuxName string) *TunnelConfig {
	cp := *tc
	cp.Name = linuxName
	if tc.Addresses != nil {
		cp.Addresses = append([]string(nil), tc.Addresses...)
	}
	if tc.WgPeers != nil {
		cp.WgPeers = make([]WgPeerConfig, len(tc.WgPeers))
		for i, p := range tc.WgPeers {
			cp.WgPeers[i] = p
			if p.AllowedIPs != nil {
				cp.WgPeers[i].AllowedIPs = append([]string(nil), p.AllowedIPs...)
			}
		}
	}
	return &cp
}

// WgOuterFamilyV6 reports whether the tunnel's outer transport family is
// IPv6 (#1434). A WG interface binds ONE kernel UDP socket, so it has a
// single outer family. The family is derived from the peer(s) that
// declare an endpoint; the commit-time validator
// (validateWireguardPeers) rejects a config where endpoint-bearing peers
// disagree on family, so reading the FIRST endpoint-bearing peer here is
// safe. Returns false (IPv4 default) when no peer declares an endpoint
// (responder-only / roaming — the Rust control thread may still LEARN a
// v6 endpoint, which the larger v6 MTU overhead and dual-stack socket
// accommodate; the conservative v4 default here is the outer-family
// SNIFF, distinct from the MTU overhead, which defaults to the larger v6
// value — see wgTunMTUForEndpoint).
func (tc *TunnelConfig) WgOuterFamilyV6() bool {
	for _, p := range tc.WgPeers {
		if p.Endpoint == "" {
			continue
		}
		// The strict commit gate (endpointFamily) requires a concrete
		// `host:port` (IPv6 as `[addr]:port`), and the lexer preserves the
		// bracketed literal whole (#5182), so SplitHostPort recovers the
		// host for classification. The bare-IP fallback is retained as
		// defense-in-depth for a leniently-loaded config that never went
		// through the strict gate.
		//
		// #7158: the host may now be a DNS HOSTNAME as well as a literal, so
		// a failed ParseIP below is no longer evidence of a malformed
		// endpoint.
		if host, _, err := net.SplitHostPort(p.Endpoint); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip.To4() == nil
			}
		}
		if ip := net.ParseIP(p.Endpoint); ip != nil {
			return ip.To4() == nil
		}
	}
	return false
}

// WgHasEndpoint reports whether any peer on the tunnel declares an
// endpoint (#1434). A tunnel with no endpoint-bearing peer is
// responder-only/roaming; callers (e.g. the MTU overhead pick) treat
// that as the conservative v6 case.
func (tc *TunnelConfig) WgHasEndpoint() bool {
	for _, p := range tc.WgPeers {
		if p.Endpoint != "" {
			return true
		}
	}
	return false
}

// RoutingInstanceConfig represents a VRF-based routing instance.
type RoutingInstanceConfig struct {
	Name              string
	Description       string
	InstanceType      string         // "virtual-router" or "vrf"
	Interfaces        []string       // interfaces belonging to this instance
	StaticRoutes      []*StaticRoute // per-instance static routes
	Inet6StaticRoutes []*StaticRoute // per-instance rib inet6.0 static routes
	// UnhandledRibs mirrors RoutingOptionsConfig.UnhandledRibs for this
	// instance (#7512). compileRoutingInstances copies the fields it wants off
	// the per-instance RoutingOptionsConfig one by one, so this must be carried
	// across explicitly or a VRF's dropped ribs go unreported.
	UnhandledRibs []UnhandledRib
	OSPF          *OSPFConfig   // per-instance OSPF (optional)
	OSPFv3        *OSPFv3Config // per-instance OSPFv3 (optional)
	BGP           *BGPConfig    // per-instance BGP (optional)
	RIP           *RIPConfig    // per-instance RIP (optional)
	ISIS          *ISISConfig   // per-instance IS-IS (optional)
	// AutonomousSystem is this instance's `routing-options autonomous-system`
	// (#3870). When the instance's BGP omits `local-as`, the BGP AS is
	// resolved from this instance-level AS if set, else the GLOBAL
	// routing-options autonomous-system (Junos inheritance). 0 = unset.
	AutonomousSystem          uint32
	TableID                   int    // Linux kernel routing table number (auto-assigned)
	InterfaceRoutesRibGroup   string // interface-routes { rib-group inet <name>; }
	InterfaceRoutesRibGroupV6 string // interface-routes { rib-group inet6 <name>; }
}

// UnhandledRib names a `routing-options rib <name>` whose static routes the
// compiler does not implement, and how many routes were discarded with it
// (#7512). Only ribs that actually CARRIED routes are recorded: an empty or
// route-less `rib` stanza loses nothing, and warning about it would be noise
// that trains operators to ignore the warning that matters.
type UnhandledRib struct {
	Name   string
	Routes int
}

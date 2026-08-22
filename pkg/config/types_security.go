package config

import (
	"slices"
	"sort"
	"strings"
)

// Security policy domain: zones, policies, NAT, screen/IDS, address book,
// applications, flow/session, ALG, logging, IPsec/IKE, dynamic-address
// feeds, and the [edit schedulers] policy time-range scheduler.

// SchedulerConfig defines a time-based policy scheduler.
//
// The time-of-day window (StartTime/StopTime) is the "daily" window: it
// applies to every weekday that does not have a specific override in Days.
// A weekday present in Days overrides the daily window for that day (Junos
// per-day scheduling). AllDay marks the daily window as active for the whole
// day (`daily all-day`). StartDate/StopDate bound the scheduler to a calendar
// range.
//
// Fail-closed invariant (#3849): a scheduler that resolves to NO window for a
// given instant (no daily window, no applicable per-day window, and no
// date-only range) is INACTIVE, not always-on. The runtime evaluator
// (pkg/scheduler.isWithinWindow) must never treat an absent window as
// always-permit — a policy `scheduler-name` scoped to a window that failed to
// compile must deny, not permit around the clock.
type SchedulerConfig struct {
	Name      string
	StartTime string // daily-window start "HH:MM:SS"
	StopTime  string // daily-window stop "HH:MM:SS"
	StartDate string // "YYYY-MM-DD" (optional)
	StopDate  string // "YYYY-MM-DD" (optional)
	Daily     bool   // `daily` recurrence keyword present
	AllDay    bool   // `daily all-day` — active the entire day

	// Days holds per-weekday overrides keyed by lowercase weekday name
	// ("monday".."sunday"). A present entry overrides the daily window for
	// that weekday. nil/empty when the scheduler has no per-day arms.
	Days map[string]*SchedulerDayWindow
}

// SchedulerDayWindow is a single day's time window inside a scheduler — the
// body of a `daily { ... }` or a `monday { ... }` (..`sunday`) container.
// A day is active when AllDay is set, or when the current time-of-day falls
// within [StartTime, StopTime); Exclude forces the day inactive. An empty
// window (no times, no all-day, no exclude) is treated as CLOSED by the
// runtime evaluator (#3849 fail-closed).
type SchedulerDayWindow struct {
	StartTime string // "HH:MM:SS"
	StopTime  string // "HH:MM:SS"
	AllDay    bool   // active the entire day
	Exclude   bool   // never active this day
}

// DynamicAddressConfig defines dynamic address feed servers and address-name bindings.
type DynamicAddressConfig struct {
	FeedServers     map[string]*FeedServer
	AddressBindings map[string]*AddressBinding // keyed by address-name
}

// FeedServer defines a remote address feed source with optional per-feed paths.
type FeedServer struct {
	Name           string
	URL            string      // explicit url (takes precedence)
	Hostname       string      // hostname for building URLs with per-feed paths
	UpdateInterval int         // seconds (0 = default 3600)
	HoldInterval   int         // seconds; 0/unset = retain last-good forever on failure, >0 = drop to empty after N seconds (#2050)
	FeedName       string      // single feed-name (backward compat, no path)
	FeedEntries    []FeedEntry // named feeds with per-feed paths
}

// FeedEntry is a named feed within a feed-server, with an optional path.
type FeedEntry struct {
	Name string
	Path string
}

// AddressBinding binds an address-name to one or more feed-names via a profile.
type AddressBinding struct {
	Name      string
	FeedNames []string // feed-names referenced in the profile
}

// SecurityConfig holds all security-related configuration.
type SecurityConfig struct {
	Zones              map[string]*ZoneConfig // keyed by zone name
	Policies           []*ZonePairPolicies    // ordered list of zone-pair policy sets
	GlobalPolicies     []*Policy              // global policies (apply to all zone pairs)
	DefaultPolicy      PolicyAction           // global fallback policy (permit-all or deny-all)
	NAT                NATConfig
	Screen             map[string]*ScreenProfile // keyed by profile name
	AddressBook        *AddressBook
	Log                LogConfig
	Flow               FlowConfig
	ALG                ALGConfig
	IPsec              IPsecConfig
	DynamicAddress     DynamicAddressConfig
	SSHKnownHosts      map[string][]SSHKnownHostKey // host -> keys
	PolicyStatsEnabled bool                         // policy-stats system-wide enable
	PreIDDefaultPolicy *PreIDDefaultPolicy          // pre-id-default-policy
	// DefaultPolicyLogSessionInit / DefaultPolicyLogSessionClose carry
	// `security policies default-policy-log session-init|session-close`
	// (#3534, split from #3363 Part 2). They request RT_FLOW session logging
	// for flows that hit the IMPLICIT default-policy verdict (no matching
	// zone-pair/global/wildcard rule), mirroring a named policy's `then log`
	// selection. Wired to the dataplane via ConfigSnapshot.DefaultLogSessionInit
	// /Close → the Rust default-verdict result. The session-init/session-close
	// records only fire for a default-PERMIT verdict (which installs a session);
	// a default-DENY/REJECT verdict installs no session and is already logged
	// unconditionally via the policy-deny RT_FLOW record, so the flags are inert
	// there (commit emits a WARNING — validateDefaultPolicyLogWarnings).
	DefaultPolicyLogSessionInit  bool
	DefaultPolicyLogSessionClose bool
	// PolicyRematch / PolicyRematchExtensive carry `security policies
	// policy-rematch [extensive]` (#4233). In Junos this re-evaluates
	// in-progress sessions against the changed policy set on commit; xpf
	// does not yet perform any session invalidation on commit (tracked as
	// the enforcement feature #4234). The knob is accepted and recorded so
	// it no longer commits-clean-and-is-silently-dropped, and commit emits
	// an accepted-only advisory (validateConfig, mirroring the #2078 /
	// #2008 H13 doctrine). Extensive is the Junos sub-mode that additionally
	// re-evaluates sessions matched by an unchanged policy when referenced
	// address-book/application objects change; it is recorded for the same
	// advisory and future enforcement.
	PolicyRematch          bool
	PolicyRematchExtensive bool
}

// FlowConfig holds flow/session timeout configuration.
type FlowConfig struct {
	TCPSession                 *TCPSessionConfig
	UDPSessionTimeout          int // seconds, 0 = default (60s)
	ICMPSessionTimeout         int // seconds, 0 = default (60s — DEFAULT_ICMP_SESSION_TIMEOUT_NS, userspace-dp/src/session/mod.rs)
	TCPMSSAllTCP               int // TCP MSS clamp for all forwarded TCP (0 = disabled) (#2486)
	TCPMSSIPsecVPN             int // TCP MSS clamp for IPsec VPN traffic (0 = disabled) — rejected at commit (#2486: no IPsec context in the userspace forward path)
	TCPMSSGreIn                int // TCP MSS clamp for GRE ingress traffic (0 = disabled)
	TCPMSSGreOut               int // TCP MSS clamp for GRE egress traffic (0 = disabled)
	AllowDNSReply              bool
	AllowEmbeddedICMP          bool
	GREPerformanceAcceleration bool
	PowerModeDisable           bool
	SynFloodProtectionMode     string // "syn-cookie" or "" (default = drop)
	Traceoptions               *FlowTraceoptions
	AgingEarlyAgeout           int // seconds (0 = disabled)
	AgingHighWatermark         int // percent of max sessions (0 = disabled)
	AgingLowWatermark          int // percent of max sessions (0 = disabled)
	// AgingUnknownLeaves records `security flow aging` child keywords the
	// compiler does not recognize (#3440 H2). The aging subtree previously
	// silently dropped any unknown leaf; compileFlow now records them so
	// validateFlowAgingStrict can reject them at commit (mirrors
	// ScreenProfile.UnknownLeaves / #3318).
	AgingUnknownLeaves []string
	// #4231 (fable-167 P-3): five `security flow` knobs that commit but are
	// NOT enforced by the userspace AF_XDP dataplane. Typed here (with schema
	// leaves + compileFlow parsing) so the operator gets completion + value
	// validation and an accepted-only commit advisory
	// (compiler_validate_warn.go, the #2078 doctrine) instead of the previous
	// silent drop. The two duration knobs are seconds (0 = unset / absent); the
	// three toggles are presence booleans. None reach the dataplane wire.
	RouteChangeTimeout           int  // seconds (0 = unset)
	SyncICMPSession              bool // no-op: xpf syncs ICMP sessions to the HA peer unconditionally
	ForceIPReassembly            bool // accepted-only
	MulticastSessionLifetime     int  // seconds (0 = unset)
	PreserveIncomingFragmentSize bool // accepted-only
}

// FlowTraceoptions holds flow trace debugging configuration.
type FlowTraceoptions struct {
	File          string   // log file name
	FileSize      int      // max file size in bytes
	FileCount     int      // number of rotated files
	Flags         []string // trace flags (e.g. "basic-datapath", "session")
	PacketFilters []*TracePacketFilter
}

// TracePacketFilter defines a packet filter for flow tracing.
type TracePacketFilter struct {
	Name              string
	SourcePrefix      string
	DestinationPrefix string
	Protocol          string // protocol name (tcp|udp|icmp|...) or number
	// InvalidPrefix marks a filter whose source-prefix or destination-prefix
	// node was PRESENT in the config but carried an empty value (e.g.
	// `source-prefix ""`). An empty prefix string is indistinguishable from an
	// absent one once it reaches the runtime (PacketFilter carries only
	// strings), but the two have opposite intent: an absent prefix is a
	// legitimate protocol-only filter, while a present-but-empty prefix is
	// malformed and — if treated as "no constraint" — collapses the filter to
	// match EVERY event (the #3422 M01 fail-open in a smaller costume). The
	// compiler, which alone sees the AST and can tell present-empty from
	// absent, sets this so the runtime (NewTraceWriter) can fail the filter
	// closed (match-none) without over-rejecting a protocol-only filter. The
	// strict commit gate rejects present-but-empty loudly; this carries the
	// conclusion through the lenient load / peer-sync path.
	InvalidPrefix bool
}

// ALGConfig holds ALG (Application Layer Gateway) disable flags.
type ALGConfig struct {
	DNSDisable  bool
	FTPDisable  bool
	SIPDisable  bool
	TFTPDisable bool
	// UnsupportedProtos records `security alg <proto>` stanzas whose proto is
	// NOT one of the four the compiler wires (dns/ftp/sip/tftp) — e.g. h323,
	// msrpc, rsh, sql, talk, pptp (#4232, fable-167 P-4a). Junos configures ALG
	// behavior for these; xpf silently dropped the whole stanza. compileALG now
	// records the unrecognized proto names so validateSecurityAcceptedOnly
	// (compiler_validate_warn.go) can emit an accepted-but-inert advisory. The
	// names are recorded in config order so the warning is deterministic.
	UnsupportedProtos []string
}

// TCPSessionConfig holds TCP session timeout configuration.
type TCPSessionConfig struct {
	EstablishedTimeout   int  // default 1800
	InitialTimeout       int  // default 30
	ClosingTimeout       int  // default 30
	TimeWaitTimeout      int  // default 120
	NoSynCheck           bool // allow mid-stream TCP session creation
	NoSynCheckInTunnel   bool // allow mid-stream TCP for tunnel traffic only
	RstInvalidateSession bool // immediately expire session on RST
	// NoSequenceCheck disables TCP sequence-number validation for flow
	// sessions (`set security flow tcp-session no-sequence-check`, #2008 M9).
	// Typed-config only today, exactly like NoSynCheck / RstInvalidateSession:
	// the userspace AF_XDP dataplane does not currently perform TCP
	// sequence-number window validation, so there is nothing to skip yet. The
	// field captures operator intent at commit (with schema validation +
	// completion) and is the single seam a future sequence-checking dataplane
	// would read.
	NoSequenceCheck bool
}

// LogConfig holds logging/syslog configuration.
type LogConfig struct {
	Mode            string // "stream" or "event"
	Format          string // "sd-syslog", "syslog", "binary", "structured"
	SourceInterface string // interface for source address
	Streams         map[string]*SyslogStream
	Report          bool // enable session aggregation reporting (security log report)
	// Profiles holds Junos `security log profile <name>` objects (#2008
	// H7). Before this was added the whole `profile` stanza parsed but was
	// silently discarded (no schema child, no compiler case) — a config
	// such as `vsrx-ha.conf`'s `profile default-syslog { stream-name ...;
	// default-profile; }` committed with no effect and no validation. It
	// is now compiled and cross-referenced against Streams at commit.
	Profiles map[string]*LogProfile
}

// LogProfile is a Junos `security log profile <name>` object: a named log
// routing profile that targets a configured stream and may be marked the
// default profile (#2008 H7). xpf's per-stream routing is a Junos superset
// — every stream whose category/severity filter matches receives the
// event — so a profile's StreamName names the stream that carries its
// events and DefaultProfile records the operator's default designation.
// No dispatch change is required: the runtime already routes by stream.
// The compiler cross-references StreamName against LogConfig.Streams so a
// profile naming a non-existent stream is rejected at commit rather than
// silently dropped (see validateLogProfileStreamReferencesStrict).
type LogProfile struct {
	Name           string
	StreamName     string // references LogConfig.Streams[StreamName] when set
	DefaultProfile bool   // `default-profile;` — operator's default designation
}

// SyslogTransport defines the transport protocol for a syslog stream.
type SyslogTransport struct {
	Protocol   string // "udp" (default), "tcp", "tls"
	TLSProfile string // TLS profile name (for protocol=tls)
}

// SyslogStream defines a syslog forwarding destination.
type SyslogStream struct {
	Name          string
	Host          string
	Port          int    // default 514
	Severity      string // any|emergency|alert|critical|error|warning|notice|info|debug|none, or "" (no filter) — full logging.ParseSeverity domain (#5523 C179-046)
	Facility      string // "local0".."local7", "user", "daemon", or "" (default: local0)
	Format        string // per-stream format override
	Category      string // "all", or specific category
	SourceAddress string // source IP for this stream
	Transport     SyslogTransport
}

// SSHKnownHostKey represents a known SSH host key.
type SSHKnownHostKey struct {
	Type string // "ecdsa-sha2-nistp256-key", "ssh-rsa-key", etc.
	Key  string
}

// PreIDDefaultPolicy defines a pre-identification default policy.
type PreIDDefaultPolicy struct {
	LogSessionInit  bool
	LogSessionClose bool
}

// ZoneConfig represents a security zone.
type ZoneConfig struct {
	Name               string
	Description        string
	Interfaces         []string
	ScreenProfile      string // reference to screen profile name
	HostInboundTraffic *HostInboundTraffic
	// InterfaceHostInbound holds per-interface host-inbound-traffic overrides
	// (#3362), keyed by the interface ref exactly as it appears under
	// `security zones security-zone <z> interfaces <ref>` (e.g. "ge-0/0/0.0").
	// Junos models host-inbound-traffic at BOTH the zone level (HostInboundTraffic
	// above, applies to every interface in the zone) and the interface level
	// (here, applies only to that interface); the EFFECTIVE admission set for an
	// interface is the UNION of the two (Junos additive semantics). A zone is
	// host-inbound-ENFORCING if it declares a zone-level stanza OR carries any
	// interface-level override here — so an operator can expose a service
	// (e.g. ssh) on one interface of a zone while denying it on the others by
	// setting the override only on the exposed interface and leaving the
	// zone-level set empty. nil/empty = no per-interface override (pre-#3362
	// zone-wide-only behaviour).
	InterfaceHostInbound map[string]*HostInboundTraffic
	TCPRst               bool // send TCP RST for non-SYN packets to closed ports
	// AddressBook is the zone-local address book (#3061). A policy whose
	// from-zone (source-address) or to-zone (destination-address) is this
	// zone resolves a name against this book FIRST, then falls back to the
	// global SecurityConfig.AddressBook. Resolved into the global book under
	// zone-qualified internal names by resolveZoneLocalAddressBooks during
	// compile, so the dataplane resolution path stays global-only.
	AddressBook *AddressBook
}

// HostInboundTraffic defines what services are permitted to the firewall itself.
type HostInboundTraffic struct {
	SystemServices []string // ssh, ping, dns, etc.
	Protocols      []string // ospf, bgp, etc.
}

// SortedInterfaceHostInboundRefs returns the interface refs that declare a
// per-interface host-inbound-traffic override (#3362), sorted for a stable
// presentation order. It is the SSOT for the REST/gRPC zone-inventory
// projection (#3328) so both surfaces iterate the overrides identically.
// Returns nil for a zone with no per-interface overrides.
func (z *ZoneConfig) SortedInterfaceHostInboundRefs() []string {
	if z == nil || len(z.InterfaceHostInbound) == 0 {
		return nil
	}
	refs := make([]string, 0, len(z.InterfaceHostInbound))
	for ref := range z.InterfaceHostInbound {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

// ZonePairPolicies contains ordered policies for a from-zone/to-zone pair.
type ZonePairPolicies struct {
	FromZone string
	ToZone   string
	Policies []*Policy
}

// Policy is a single security policy rule.
type Policy struct {
	Name          string
	Description   string
	Match         PolicyMatch
	Action        PolicyAction
	Log           *PolicyLog
	Count         bool
	SchedulerName string // reference to SchedulerConfig name
	// terminalActions records, in config order, the terminal action tokens
	// (permit/deny/reject) parsed under this policy's `then` stanza. It
	// exists only to drive the commit-time validator
	// (validatePolicyTerminalActionStrict, #3043): a policy MUST resolve to
	// exactly one terminal action. Zero tokens (a log-only/count-only or
	// typo'd `then`) historically fell through to Action's zero value
	// (PolicyPermit) — a silent fail-OPEN; more than one token resolved
	// last-wins (the conflicting actions were silently collapsed by child
	// visitation order). The typed Config is never serialized, so this
	// unexported field carries no persistence / back-compat obligation.
	terminalActions []PolicyAction
	// UnknownChildren records DIRECT children of a `policy <name>` node whose
	// keyword is not one the compiler reads (match / then / description /
	// scheduler-name) — e.g. a typo'd `descripton` or `scheduler-nam`, which
	// Junos rejects at commit but xpf silently dropped (#4232, fable-167 P-4b).
	// The exhaustive #3113/#3114/#3115 gates cover the `match`/`then` subtrees
	// but not the policy level itself. compilePolicy records the unrecognized
	// keywords so validateSecurityAcceptedOnly (compiler_validate_warn.go) can
	// emit an accepted-but-inert / probable-typo advisory. Recorded in config
	// order so the warning is deterministic.
	UnknownChildren []string
	// LenientContentDropped marks a policy the TOLERANT compile path
	// (CompileConfigLenient / CompileConfigForNodeLenient) accepted only by
	// DOWNGRADING a hard reject to a warning for a match / then-permit
	// constraint the compiler then SILENTLY DROPPED — a MISSING required match
	// dimension (#3044), an UNSUPPORTED `match` leaf (#3113, incl. the #3142
	// collapsed-tail and #3673 swallowed-keyword escapes), or an UNSUPPORTED
	// `then permit` modifier (#3114). In each case the dropped constraint
	// leaves the corresponding dimension EMPTY / the permit UNCONDITIONAL, and
	// the userspace matcher reads an empty dimension as match-ANY — a permit
	// BROADER than the operator configured (a security fail-OPEN on the
	// persisted-load / peer-sync path, #5575). The strict commit path
	// hard-rejects all three before compilePolicy runs, so this flag is only
	// ever set on the tolerant load / peer-sync path; a clean strict-committed
	// policy always leaves it false (byte-identical snapshots).
	//
	// compilePolicy derives it (never the raw AST / wire), so it is recomputed
	// identically on both HA peers and needs no serialization. The userspace
	// snapshot builder (buildOneRuleSnapshot) poisons such a policy with the
	// __unsupported__ application sentinel so the Rust integrity preflight
	// rejects the WHOLE snapshot (previous-good retained; fresh-boot
	// default-deny) — an action-agnostic fail-CLOSED that turns the widened
	// permit (and a symmetric over-broad deny) into never-match instead of
	// match-any.
	LenientContentDropped bool
}

// PolicyMatch defines what traffic a policy matches.
type PolicyMatch struct {
	SourceAddresses      []string // address-book names or "any"
	DestinationAddresses []string
	Applications         []string // application names or "any"
	// SourceAddressExcluded inverts the source-address match sense:
	// when true the policy matches every source EXCEPT those named in
	// SourceAddresses (Junos `match source-address-excluded`).
	SourceAddressExcluded bool
	// DestinationAddressExcluded inverts the destination-address match
	// sense (Junos `match destination-address-excluded`).
	DestinationAddressExcluded bool
	// FromZones and ToZones carry the optional from-zone/to-zone match
	// context of a Junos GLOBAL policy (#3148, #4626). A Junos global policy
	// may narrow which zone pairs it applies to with
	// `match { from-zone [ <z> ... ]; to-zone [ <z> ... ]; }`; an empty
	// slice means "all zones" (the historical global behaviour). Each side
	// is a zone SET: a packet's from-zone must be in FromZones AND its
	// to-zone must be in ToZones for the global to apply (#4626 M03). A
	// single-zone scope is a one-element slice — bit-identical to the
	// pre-#4626 single-string model. These fields are only meaningful for
	// global policies — zone-pair policies derive their zones from the
	// surrounding from-zone/to-zone stanza, so the compiler never populates
	// these for them. The global policy is still evaluated in the GLOBAL
	// tier ordering (after exact zone-pair and the #3090
	// from-any/to-any/both-any wildcard tiers); the zone context is an
	// extra match predicate, not a tier promotion. The compiler sorts and
	// de-duplicates each slice so display is stable and HA expansion is
	// order-symmetric.
	FromZones []string
	ToZones   []string
}

// IsWildcardZone reports whether a Junos GLOBAL-policy zone-scope token names
// every zone (the all-zones wildcard). Two spellings are equivalent: the empty
// string (an omitted `match from-zone`/`to-zone`, the historical unscoped
// global) AND the explicit reserved token "any" (the idiomatic Junos wildcard).
//
// This is the single source of truth for the wildcard-scope test. It mirrors
// the runtime build_global_zone_scope (userspace-dp/src/policy.rs), which maps
// BOTH "" and "any" to GlobalZoneScope::Any, and it is shared by
// GlobalPolicyAppliesToZone here and by the policymatch helpers
// (globalScopeSetMatches, GlobalPolicyAppliesToZonePair) so the display/audit
// surfaces cannot drift from the runtime — the exact drift that hid
// explicit-"any" globals from zone-detail (#3680, was: only "" treated as
// wildcard here while policymatch + the runtime also honoured "any").
//
// Note: this is the GLOBAL-policy scope wildcard. The zone-PAIR wildcard tiers
// (#3090, policymatch from/to-any) deliberately treat ONLY the explicit "any"
// as a wildcard — an empty zone-pair zone is not meaningful there — so those
// sites do not use this helper.
func IsWildcardZone(s string) bool {
	return s == "" || s == "any"
}

// IsWildcardZoneSet reports whether a GLOBAL-policy zone SCOPE SET (#4626 M03)
// names every zone. The empty slice (an omitted `match from-zone`/`to-zone`,
// the historical unscoped global) is the all-zones wildcard, and so is any set
// that contains the reserved token "any". The strict commit gate rejects a set
// that mixes "any" with concrete zones (redundant + ambiguous), so a clean
// commit only ever produces the empty set, exactly ["any"], or an all-concrete
// list; the contains-"any" collapse here is the tolerant/corrupt-snapshot
// backstop (a mixed set from a bad HA peer or hand-built snapshot still degrades
// safely to all-zones on both planes). This is the set-level SSOT for the
// wildcard test, mirroring the runtime build_global_zone_scope
// (userspace-dp/src/policy.rs), which maps an empty list or any "any" element to
// GlobalZoneScope::Any.
func IsWildcardZoneSet(zs []string) bool {
	return len(zs) == 0 || slices.Contains(zs, "any")
}

// sortDedupZones returns a sorted, de-duplicated copy of zs with blank tokens
// dropped. It is the canonical form the compiler stamps onto a scoped-global
// zone set (#4626 M03) so display is stable and HA expansion is order-symmetric;
// a nil/empty input returns nil (the all-zones wildcard).
func sortDedupZones(zs []string) []string {
	if len(zs) == 0 {
		return nil
	}
	out := make([]string, 0, len(zs))
	for _, z := range zs {
		if z != "" {
			out = append(out, z)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// ZoneScopeSetLabel renders a scoped-global zone SET (#4626 M03) for display: a
// wildcard set (empty or containing "any") prints as the idiomatic Junos "any";
// a concrete set prints its sorted-unique members space-joined ("dmz trust").
// It is the display SSOT so no surface open-codes its own join/wildcard rule.
func ZoneScopeSetLabel(zs []string) string {
	if IsWildcardZoneSet(zs) {
		return "any"
	}
	return strings.Join(sortDedupZones(zs), " ")
}

// ScopeLabelOr renders a scoped-global zone SET for a display surface that uses
// a placeholder for the UNSCOPED (all-zones) case — e.g. the "*" hit-count
// columns or the "junos-global" detail zones. An empty set (unscoped global)
// yields the caller's placeholder; a non-empty set yields its canonical
// ZoneScopeSetLabel (an explicit `["any"]` still renders "any", concrete zones
// render their sorted join). This preserves the pre-#4626 per-site behaviour
// where `FromZone != ""` swapped the placeholder for the scope value (#4626 M03).
func ScopeLabelOr(zs []string, placeholder string) string {
	if len(zs) == 0 {
		return placeholder
	}
	return ZoneScopeSetLabel(zs)
}

// ScopeSingular returns the first element of a scoped-global zone SET, or ""
// for an unscoped (empty) set. It is the value stamped onto the SINGULAR wire /
// proto / REST fields (#4626 A8) for rolling-upgrade safety: an old helper /
// client that only reads the singular field sees the first zone (a safe
// single-zone degradation), while a new reader prefers the plural field with the
// complete set. For a one-element set this is the zone itself, keeping the
// pre-#4626 singular value bit-identical.
func ScopeSingular(zs []string) string {
	if len(zs) == 0 {
		return ""
	}
	return zs[0]
}

// IsHostToZoneScope reports whether a global policy's TO-zone scope set (#4626
// M03) is the reserved host-inbound scope — exactly the single token
// "junos-host". The strict commit gate rejects a to-zone list that mixes
// junos-host with any other token, so a host-inbound global has ToZones ==
// ["junos-host"] exactly and a transit global never contains junos-host. This
// predicate replaces the pre-#4626 `ToZone == "junos-host"` string test.
func IsHostToZoneScope(zs []string) bool {
	return len(zs) == 1 && zs[0] == "junos-host"
}

// GlobalPolicyAppliesToZone reports whether a global policy with the given
// match context can affect security zone `zone` — i.e. the global's from- or
// to-zone scope can place `zone` on either side of an evaluated zone pair. An
// empty or explicit-"any" FromZone/ToZone is the "any zone" wildcard (#3148
// unscoped global, or #3680 idiomatic-Junos explicit any).
//
// It mirrors the runtime AND-combined GlobalZoneScope match in the userspace
// dataplane (userspace-dp/src/policy.rs: a global matches a packet iff its
// from-scope matches the packet's from-zone AND its to-scope matches the
// packet's to-zone): `zone` is a possible SOURCE when the from-scope is
// any-or-`zone`, and a possible DESTINATION when the to-scope is any-or-`zone`.
// Either possibility means the global can permit/deny some traffic that
// involves `zone`, so it belongs in that zone's audit.
//
// Used by the zone-detail policy summary (#3658) to list the global tier the
// runtime evaluates after zone-pair rules. Callers filter nil policies first.
func GlobalPolicyAppliesToZone(m PolicyMatch, zone string) bool {
	asSource := IsWildcardZoneSet(m.FromZones) || slices.Contains(m.FromZones, zone)
	asDest := IsWildcardZoneSet(m.ToZones) || slices.Contains(m.ToZones, zone)
	return asSource || asDest
}

// PolicyAction is the action to take when a policy matches.
type PolicyAction int

const (
	PolicyPermit PolicyAction = iota
	PolicyDeny
	PolicyReject
)

// PolicyLog configures session logging for a policy.
type PolicyLog struct {
	SessionInit  bool
	SessionClose bool
}

// SessionLogModes returns the enabled session-log trigger tokens in Junos
// display order: "at-create" when SessionInit is set (log at session start)
// and "at-close" when SessionClose is set (log at session teardown). A nil
// receiver, or a log block with neither trigger enabled, returns nil so a
// caller can gate the "Session log:" line on len()>0.
//
// This is the single source of truth for the session-log display token set
// shared by the local CLI detail renderer and the gRPC text detail renderer
// (#3667), so the two surfaces cannot drift on the at-create/at-close labels.
func (l *PolicyLog) SessionLogModes() []string {
	if l == nil {
		return nil
	}
	var modes []string
	if l.SessionInit {
		modes = append(modes, "at-create")
	}
	if l.SessionClose {
		modes = append(modes, "at-close")
	}
	return modes
}

// NATConfig holds NAT configuration.
type NATConfig struct {
	Source               []*NATRuleSet
	SourcePools          map[string]*NATPool // named source NAT pools
	AddressPersistent    bool                // source { address-persistent; }
	Destination          *DestinationNATConfig
	Static               []*StaticNATRuleSet
	NAT64                []*NAT64RuleSet
	NATv6v4              *NATv6v4Config // natv6v4 options
	PoolUtilizationAlarm *PoolUtilizationAlarmConfig
	ProxyARP             []*ProxyARPEntry
	// SourceInterfacePortOverloadingOff records `security nat source interface
	// port-overloading off` (#4291). Junos `off` disables source-port reuse
	// across destinations (a src-port-uniqueness hardening posture). xpf accepts
	// and records it but does NOT enforce it — source-port overloading is always
	// on in the SNAT allocator — so `off` hardens nothing. An accept-with-
	// advisory (ValidateConfig) surfaces the false-hardening. Enforcement is a
	// userspace-dp SNAT-allocator follow-up.
	SourceInterfacePortOverloadingOff bool
}

// ProxyARPEntry configures proxy ARP responses for NAT addresses.
type ProxyARPEntry struct {
	Interface string
	Addresses []string // /32 CIDRs (expanded from ranges)
	// MalformedRangeSpecs records every proxy-arp `address` STATEMENT on this
	// interface whose token stream still carried the `to` range keyword after
	// neither well-formed range shape consumed it (#6714). Two things reach it:
	// a genuinely broken range (`address [ to 192.0.2.1 ]`, `address 192.0.2.1
	// to`), and a LIST that MIXES discrete addresses with a range
	// (`address [ 192.0.2.1 192.0.2.2 to 192.0.2.9 ]`), which is not authorable
	// Junos — the leaf takes one address/prefix, one `<low> to <high>` range, or
	// a bracketed list of plain addresses, never a mixture.
	//
	// Both compile to what MASTER installed: proxyARPAddressValues falls back to
	// the single-value read for such a statement (#6673 pinned that against
	// origin/master through the installer's own netip.ParsePrefix gate), so the
	// dataplane answers ARP for exactly the addresses it did before. What was
	// missing was any signal that the rest of the statement had been discarded:
	// `show configuration` rendered the whole list back and the compiler
	// installed one address of it. This field is that signal —
	// validateProxyARPAddressesStrict hard-rejects at commit and the call site
	// downgrades to a warning on the tolerant load / peer-sync path (#1960
	// no-brick), so an already-persisted config still boots with the identical
	// installed set.
	//
	// `json:"-"`: a compile-time diagnostic artifact recomputed on every
	// compile. It does not cross the wire to the Rust helper and must not leak
	// into configstore.ExportJSON's dump of the compiled *config.Config —
	// mirrors NATPool.PortRangeInvalidSpec.
	MalformedRangeSpecs []string `json:"-"`
}

// PoolUtilizationAlarmConfig configures NAT pool utilization alarms.
type PoolUtilizationAlarmConfig struct {
	RaiseThreshold int
	ClearThreshold int
}

// NATv6v4Config holds NAT64 v6-to-v4 translation options.
type NATv6v4Config struct {
	NoV6FragHeader bool // no-v6-frag-header: omit IPv6 fragment header in translated packets
}

// NAT64RuleSet defines NAT64 translation rules.
type NAT64RuleSet struct {
	Name       string
	Prefix     string // well-known prefix, e.g. "64:ff9b::/96"
	SourcePool string // IPv4 source pool name for translated packets
}

// StaticNATRuleSet is a set of static 1:1 NAT rules bound to a from scope.
// Junos static NAT has only a `from` clause (no `to`). The scope is one of
// zone | interface | routing-instance (#3096); exactly one of FromZone /
// FromInterface / FromRoutingInstance is non-empty for a scoped rule-set, and
// all three empty means match-any (global). The compiler Cartesian-expands a
// bracket list of scope values into one StaticNATRuleSet per value.
type StaticNATRuleSet struct {
	Name     string
	FromZone string
	// FromInterface scopes the rule-set to traffic ingressing this logical
	// interface (config name, e.g. "ge-0/0/1.0"). "" = unscoped. #3096.
	FromInterface string
	// FromRoutingInstance scopes the rule-set to traffic in this routing
	// instance / VRF. "" = the default instance / unscoped. #3096.
	FromRoutingInstance string
	Rules               []*StaticNATRule
}

// DestinationNATConfig holds destination NAT pools and rule sets.
type DestinationNATConfig struct {
	Pools    map[string]*NATPool
	RuleSets []*NATRuleSet
}

// NATRuleSet is a set of NAT rules bound to a from/to scope pair. Each scope
// side is one of zone | interface | routing-instance (Junos #3096); within a
// side exactly one of the *Zone / *Interface / *RoutingInstance fields is
// non-empty for a scoped rule-set, and all-empty means match-any (global) on
// that side. The compiler Cartesian-expands a bracket list of scope values
// into one NATRuleSet per (from-scope, to-scope) pair, mirroring the existing
// from-zone × to-zone expansion.
type NATRuleSet struct {
	Name     string
	FromZone string
	ToZone   string
	// FromInterface / ToInterface scope the rule-set to traffic
	// ingressing / egressing this logical interface (config name, e.g.
	// "ge-0/0/1.0"). "" = unscoped on that side. #3096.
	FromInterface string
	ToInterface   string
	// FromRoutingInstance / ToRoutingInstance scope the rule-set to traffic
	// in this routing instance / VRF on ingress / egress. "" = the default
	// instance / unscoped. #3096.
	FromRoutingInstance string
	ToRoutingInstance   string
	Rules               []*NATRule
}

// NATRule is a single NAT rule.
type NATRule struct {
	Name  string
	Match NATMatch
	Then  NATThen
}

// NATMatch defines what traffic a NAT rule matches.
type NATMatch struct {
	SourceAddress          string   // CIDR (first address, for backward compat)
	SourceAddresses        []string // all matched source CIDRs (bracket list support)
	SourceAddressName      string   // first address-book name (backward compat)
	SourceAddressNames     []string // all matched source address-book names (#3431 bracket list / repeated)
	DestinationAddress     string   // CIDR (first address, for backward compat)
	DestinationAddresses   []string // all matched destination CIDRs (bracket list support)
	DestinationAddressName string   // first address-book name (backward compat, #3229)
	// DestinationAddressNames is every `match destination-address-name`
	// value (#3431). The scalar above keeps the first for back-compat.
	DestinationAddressNames []string
	DestinationPort         int   // primary port (first port for BPF rule)
	DestinationPorts        []int // all matched ports (for multi-port DNAT rules)
	// InvalidDestinationPorts holds raw `match destination-port` tokens that
	// did NOT parse as an integer (e.g. "http", "httpp"). The parser used to
	// silently drop them, which let an all-nonnumeric port list collapse to an
	// empty DestinationPorts and then widen to the wildcard port (#3446 H14).
	// They are preserved so validateNATMatchDestinationPortStrict can reject
	// them at commit and the snapshot builders can fail CLOSED (match nothing)
	// on the lenient load / peer-sync path.
	InvalidDestinationPorts []string
	// ReversedDestinationPortRanges holds raw `match destination-port <low> to
	// <high>` tokens where high < low (a reversed range, e.g. `4000 to 3000`).
	// The parser used to silently split such a range into its two discrete
	// endpoints ({4000, 3000}), miscompiling the operator's intended
	// contiguous range with no feedback. They are preserved so
	// validateNATMatchDestinationPortStrict can reject them at commit (#4422)
	// and downgrade to a warning on the lenient load / peer-sync path.
	ReversedDestinationPortRanges []string
	Protocol                      string   // first protocol (backward compat): "tcp", "udp", "icmp6", "gre", or "" (auto)
	Protocols                     []string // all matched protocols (#3431 bracket list / repeated, DNAT only)
	Application                   string   // first application name (backward compat), e.g. "junos-http"
	Applications                  []string // all matched application names (#3431 bracket list / repeated)
}

// natMatchValues returns the full multi-value list for a NAT match axis,
// falling back to the scalar when the plural slice is empty. The fallback
// keeps consumers correct when a NATMatch arrives without the #3431 plural
// fields populated (e.g. a config JSON-synced from an older peer that only
// carried the scalar). An empty result means "criterion absent".
func natMatchValues(list []string, scalar string) []string {
	if len(list) > 0 {
		return list
	}
	if scalar != "" {
		return []string{scalar}
	}
	return nil
}

// ApplicationList returns every `match application` value (#3431).
func (m NATMatch) ApplicationList() []string {
	return natMatchValues(m.Applications, m.Application)
}

// ProtocolList returns every `match protocol` value (#3431, DNAT only).
func (m NATMatch) ProtocolList() []string {
	return natMatchValues(m.Protocols, m.Protocol)
}

// SourceAddressNameList returns every `match source-address-name` value (#3431).
func (m NATMatch) SourceAddressNameList() []string {
	return natMatchValues(m.SourceAddressNames, m.SourceAddressName)
}

// DestinationAddressNameList returns every `match destination-address-name`
// value (#3431).
func (m NATMatch) DestinationAddressNameList() []string {
	return natMatchValues(m.DestinationAddressNames, m.DestinationAddressName)
}

// NATThen defines the NAT translation action.
type NATThen struct {
	Type      NATType
	Interface bool   // source-nat interface mode
	PoolName  string // pool reference
	Off       bool   // source-nat / destination-nat off (no-NAT exemption, #3844)
}

// NATType is the type of NAT.
type NATType int

const (
	NATSource NATType = iota
	NATDestination
	NATStatic
)

// NATPool is a pool of addresses for NAT.
type NATPool struct {
	Name      string
	Address   string   // single address (DNAT compat)
	Addresses []string // multiple addresses (source NAT pools)
	Port      int      // optional port mapping (DNAT)
	// PortRaw is the raw DNAT pool `port` token exactly as configured
	// (empty when no `port` leaf was set). It lets the strict commit gate
	// (validateDNATPoolStrict) and the snapshot builder distinguish a
	// configured-but-invalid port (e.g. "0", "70000", "httpp" — which must
	// fail closed) from no port leaf at all (Port stays 0 = "preserve the
	// destination port", a legitimate DNAT mode). Without it a `port 0` or
	// `port httpp` collapsed to Port==0 and was indistinguishable from the
	// preserve-port default, silently no-op'ing the requested rewrite (#3450
	// M04).
	//
	// `json:"-"`: PortRaw is a compile-time parse artifact recomputed from the
	// ConfigTree on every compile. It is read only Go-side — by the commit gate
	// and the dataplane snapshot builder, both of which run against the
	// in-memory config (the builder resolves the validated port into the
	// existing DestinationNATRuleSnapshot.PoolPort wire slot). It must NEVER be
	// serialized: it does not cross the wire to the Rust helper (the helper
	// decodes the Snapshot, not config.NATPool — protocol_wire_v1.json is
	// unaffected), and it would otherwise leak into configstore.ExportJSON's
	// debug dump of the compiled *config.Config as a redundant duplicate of
	// Port. The tag keeps it out of any json.Marshal of NATPool.
	PortRaw  string `json:"-"`
	PortLow  int    // source pool port range low (default 1024)
	PortHigh int    // source pool port range high (default 65535)
	// PortRangeInvalidSpec records that an explicit source-pool `port [range]`
	// leaf was configured but its value violated the port invariant — a
	// non-canonical token, an endpoint outside 1..65535 (0 included), or a
	// reversed low>high range (#5457). parseSourcePoolPortRange fails closed
	// (ok=false) on such input, so the bad value is NEVER stamped into
	// PortLow/PortHigh (they keep the 1024/65535 default); this field preserves
	// the raw offending spec so validateSourceNATPoolStrict hard-rejects at
	// commit (operator-visible) and the snapshot builder (sourceNATPoolPortRange)
	// marks the pool unusable on the tolerant load / peer-sync path — never
	// silently installing the defaulted range the operator did not ask for.
	// Before #5457 the endpoints were parsed with strconv.Atoi and stamped
	// verbatim: a non-zero out-of-range/reversed range was caught downstream, but
	// a 0-valued endpoint slipped through as the "unconfigured" sentinel and
	// silently widened to the default PAT range. "" means no port leaf, or a
	// valid range. `json:"-"`: a compile-time parse artifact recomputed on every
	// compile, never serialized to the helper (like PortRaw above).
	PortRangeInvalidSpec string `json:"-"`
	// PortNoTranslation records the source-pool `port no-translation` modifier
	// (#3906). When true the pool translates the source ADDRESS but PRESERVES
	// the original source port (Junos 1:1 source-port behaviour) — the
	// dataplane takes the address-only path and leaves rewrite_src_port unset,
	// so the packet keeps its L4 source port. PortLow/PortHigh are irrelevant
	// in this mode. Before #3906 the token was silently dropped and the pool
	// PAT-translated the port anyway.
	PortNoTranslation bool
	// PortOverloadingFactor records the source-pool `port-overloading-factor
	// <n>` knob (#4291). Junos scales the number of concurrent translations a
	// single pool address may serve. xpf accepts and records it but does NOT
	// enforce it — the SNAT allocator has no factor-scaled port budget — so an
	// accept-with-advisory (ValidateConfig) surfaces the accepted-but-inert
	// state. 0 = not configured. Enforcement is a userspace-dp SNAT-allocator
	// follow-up.
	PortOverloadingFactor int
	// RoutingInstance records the source / destination NAT pool `routing-
	// instance <ri>` translation-TARGET routing instance (#4292). Accepted +
	// recorded for the advisory; not enforced (the dataplane does not route the
	// post-translation packet against a non-ingress table). "" = unset.
	RoutingInstance string
	PersistentNAT   *PersistentNATConfig
	Deterministic   *DeterministicNATConfig
}

// PersistentNATPermit selects the remote-endpoint scope of a persistent
// NAT binding (Junos `persistent-nat permit`, #2823). It replaces the
// pre-#2823 binary PermitAnyRemoteHost bool with the full three-way enum.
type PersistentNATPermit string

const (
	// PersistentNATPermitAnyRemoteHost: any external host reuses the
	// binding. The lease is keyed by the local source tuple only (no
	// remote endpoint in the key). Junos `permit any-remote-host`.
	PersistentNATPermitAnyRemoteHost PersistentNATPermit = "any-remote-host"
	// PersistentNATPermitTargetHost: scoped to the original remote HOST.
	// The lease is keyed by the source tuple + remote destination IP only
	// (the remote PORT is dropped), so a new flow to a NEW remote port on
	// the SAME host reuses the binding. Junos `permit target-host`.
	PersistentNATPermitTargetHost PersistentNATPermit = "target-host"
	// PersistentNATPermitTargetHostPort: scoped to the original remote
	// host:PORT. The lease is keyed by the source tuple + remote
	// destination IP + destination port, so a new remote port keys to a
	// distinct lease. Junos `permit target-host-port`. This is the
	// pre-#2823 false-flag behavior and the default when `persistent-nat`
	// is configured without an explicit `permit` (preserves #2819).
	PersistentNATPermitTargetHostPort PersistentNATPermit = "target-host-port"
)

// PersistentNATConfig configures persistent NAT bindings for a pool.
type PersistentNATConfig struct {
	// Permit is the remote-host reuse scope. The default (when
	// `persistent-nat` is configured with no `permit`) is
	// PersistentNATPermitTargetHostPort, matching the pre-#2823 binary
	// model's false-flag (dst_ip, dst_port) keying so existing configs are
	// byte-identical. #2823.
	Permit            PersistentNATPermit
	InactivityTimeout int // seconds (default 300)
}

// DeterministicNATConfig configures CGNAT deterministic port allocation.
type DeterministicNATConfig struct {
	BlockSize   int    // port block size per subscriber (e.g. 2016)
	HostAddress string // subscriber CIDR (e.g. "100.64.0.0/22")
}

// StaticNATRule is a 1:1 bidirectional NAT rule.
type StaticNATRule struct {
	Name  string
	Match string // destination-address (external/public IP)
	// MatchAddresses is the FULL `match destination-address` list as authored
	// (#6659). The compiler previously read this leaf with nodeVal, so a
	// bracket / block list silently kept only the first prefix — and, worse,
	// the dropped values never reached ValidateIPPrefix, so a MALFORMED prefix
	// in any slot but the first committed clean (a validation fail-open).
	//
	// Match still carries the value the LAST authored statement selected — the
	// nodeVal assignment runs once per child, so the last `match
	// destination-address` node wins, and within a bracketed list that node's
	// FIRST value. It is therefore not in general MatchAddresses[0] nor
	// MatchAddresses[len-1]: for `sibling then bracket` the three differ.
	// Match is what the dataplane snapshot
	// lowers to (ExternalIP is a single address in the Rust static_nat table),
	// so a rule with more than one prefix has no representable meaning today.
	// validateStaticNATMatchAddressesStrict therefore REJECTS a multi-valued
	// list at commit rather than letting it silently collapse to the first.
	// Widening static NAT to fan one rule into N external prefixes is a
	// separate semantic change (see #6674), not this fix.
	//
	// #6673: read with multiLeafAuthoredValues, which KEEPS empty values, so this
	// list always contains what Match selected; an empty entry is a selection, not
	// a second prefix. Rationale: compileNATStatic and docs/config-schema.md.
	MatchAddresses []string
	// SourceAddress is the FIRST configured `match source-address` value,
	// retained for back-compat (e.g. "::/0" for NAT64). Prefer
	// SourceAddresses for the full bracket/repeated list — SourceAddress
	// drops every entry after the first (#3435 M02).
	SourceAddress string
	// SourceAddresses is the full `match source-address` list (#3435). Junos
	// static NAT `match source-address <prefix>` restricts which client
	// source IPs the 1:1/DNAT translation applies to. Before #3435 the value
	// was stored as a single scalar (dropping list tail, M02) AND never
	// carried into the dataplane snapshot (the rule installed as an
	// all-source mapping, a fail-open exposure, H01). The first element is
	// mirrored into SourceAddress for back-compat. Empty = match any source.
	SourceAddresses []string
	// Then is the static-nat prefix (internal/private IP). The Junos NAT64
	// keyword `then static-nat inet` records the sentinel "inet" here, but it
	// is REJECTED at strict commit (validateStaticNATInetTargetStrict, #5859):
	// no dataplane lowering exists and emitting the literal "inet" into the
	// static_nat address slot left the rule silently inert. Lenient load /
	// peer-sync downgrades to a warning and the snapshot builder drops the rule
	// (fail-closed). The supported IPv6->IPv4 path is `security nat nat64`.
	Then string
	// ThenPrefixName is the raw `then static-nat prefix-name <name>` reference
	// (#4290). Junos static NAT `prefix-name` names a global address-book entry
	// whose literal prefix is the 1:1 translation target — the named twin of
	// `then static-nat prefix <ip>`. The compiler records the raw name here and
	// resolveStaticNATThenPrefixNames (run post-address-book-fold) resolves it
	// into Then. Before #4290 the target keyword fell through the then switch,
	// leaving Then=="" — the rule committed with an EMPTY translation target
	// (silent broken static NAT). An unresolvable reference is rejected at
	// strict commit (validateStaticNATThenTargetStrict); lenient load / peer-
	// sync downgrades to a warning (#1960) and the dataplane fails closed (the
	// empty prefix does not parse as an IP → no translation installed).
	ThenPrefixName string
	// ThenRoutingInstance is the raw `then static-nat {inet|prefix <ip>}
	// routing-instance <ri>` translation-TARGET routing instance (#4292). It is
	// distinct from the rule-set `from` SCOPE routing-instance (#3096): the
	// scope selects which ingress traffic the rule matches, the target RI would
	// place the TRANSLATED packet in a different routing table (cross-VRF NAT).
	// Recorded so the accepted-but-unenforced advisory (ValidateConfig) can
	// surface it; the dataplane does not yet route the post-translation packet
	// against a non-ingress table, so the token is otherwise silently dropped.
	ThenRoutingInstance string
	IsNPTv6             bool // true if this is an nptv6-prefix rule (RFC 6296)
	// MatchDestinationPort is the external (pre-translation) destination
	// port the inbound packet must carry for this rule to apply (Junos
	// `match destination-port`). 0 = match any port (whole-address 1:1,
	// the legacy behaviour). #2491.
	MatchDestinationPort int
	// MappedPort is the internal (post-translation) destination port the
	// 1:1 host receives (Junos `then static-nat prefix <ip> mapped-port
	// <port>`). 0 = no port translation (whole-address 1:1). When set, the
	// inbound DNAT rewrites the destination port to this value and the
	// outbound return SNAT un-translates it back to MatchDestinationPort.
	// #2491.
	MappedPort int
	// MappedPortRaw records the raw `then static-nat prefix <ip> mapped-port
	// <token>` value as authored ("" when the keyword is absent OR present
	// with no operand). The token rides inside the children:nil static-nat
	// leaf and bypasses the schema value validator; MappedPortRaw lets the
	// strict gate name the offending token when the parsed MappedPort is not
	// a valid 1-65535 port. Compile-only (`json:"-"`): it is a Go-internal
	// diagnostic artifact and must NOT cross the control-socket / REST /
	// ConfigSnapshot wire — the Rust dataplane reads only MappedPort.
	MappedPortRaw string `json:"-"`
	// MappedPortPresent is true whenever a `then static-nat mapped-port`
	// keyword appears, EVEN with no operand or an empty/zero/garbage operand.
	// It is the explicit presence signal that breaks the sentinel collision
	// the string/int fields alone could not: MappedPort==0 means BOTH "absent"
	// and "present-but-malformed" (non-numeric, empty, bare, or the literal
	// "0"), and MappedPortRaw=="" means BOTH "absent" and "present-but-empty".
	// The strict gate (validateNATHostMaskStrict, C179-038) rejects a PRESENT
	// mapped-port whose parsed value is not a valid 1-65535 port; an ABSENT
	// mapped-port (Present==false) is never rejected. Compile-only (`json:"-"`)
	// — it is never serialized, so the dataplane never sees it and the lenient
	// load / peer-sync path (#1960 no-brick) keeps MappedPort==0 (plain 1:1,
	// no bogus port).
	MappedPortPresent bool `json:"-"`
	// ThenTargetCount is how many mutually-exclusive translation TARGETS the
	// winning `then {}` block declares (prefix / prefix-name / nptv6-prefix /
	// inet), counted from the AST during compile by staticNATThenTargetCount
	// (#6483). A well-formed rule declares EXACTLY ONE. Because prefix / inet /
	// nptv6-prefix all land in the shared Then field (a later target overwrites an
	// earlier one), the final field state cannot reveal a multi-target rule; this
	// count, taken before the fields collapse, can. validateStaticNATSingleTarget-
	// Strict rejects a rule with >1 (both a prefix AND a prefix-name, an inet
	// sibling plus a prefix sibling, two prefixes, …) — invalid Junos the compiler
	// otherwise silently accepted by honoring one target and dropping the rest,
	// which also let a malformed mapped-port on a dropped target slip through (the
	// #6479/C179-038 residual). A zero-target rule is the empty-target gate's
	// domain (#4290); this gates only the >1 case. Compile-only (`json:"-"`):
	// derived state recomputed on every compile (last `then` block wins, #3850),
	// never serialized to the dataplane / peer-sync wire.
	ThenTargetCount int `json:"-"`
}

// LimitSessionScreen configures per-IP session limiting.
type LimitSessionScreen struct {
	SourceIPBased      int // max sessions per source IP, 0 = disabled
	DestinationIPBased int // max sessions per destination IP, 0 = disabled
}

// ScreenProfile defines IDS screening options.
type ScreenProfile struct {
	Name         string
	ICMP         ICMPScreen
	IP           IPScreen
	TCP          TCPScreen
	UDP          UDPScreen
	LimitSession LimitSessionScreen

	// AlarmWithoutDrop is the Junos `alarm-without-drop` ids-option: a
	// profile-wide audit/log-only mode. When set, every check in this
	// screen profile that would otherwise DROP a packet instead raises a
	// log-only ALARM event (the same reason string a drop would emit) and
	// FORWARDS the packet. It is the standard vSRX threshold-tuning posture
	// (observe the attack under live traffic without impacting forwarding).
	// It applies to ALL ids-options in the profile, including the
	// rate-based flood / SYN-cookie checks. Default false = today's
	// drop-on-trip behavior.
	AlarmWithoutDrop bool

	// BadNumeric records screen numeric leaves whose explicitly-provided value
	// failed to parse as a positive integer (#3317). compileScreen previously
	// swallowed the strconv.Atoi error and fell back to a Junos default or to
	// zero/disabled — a typo'd threshold silently disabled or weakened the
	// protection (fail-open). validateScreenNumericStrict reads this to reject
	// the commit fail-closed instead of silently defaulting. Each entry names
	// the screen leaf path and the offending value.
	BadNumeric []ScreenBadNumeric
	// UnknownLeaves records screen leaves the dataplane does NOT support
	// (#3318). The screen schema subtrees are open and compileScreen switched
	// only on known child names with no default case, so a misspelled or
	// unsupported leaf committed cleanly and was silently dropped — the operator
	// believed a control was enabled when it was absent. validateScreenUnknownStrict
	// reads this to reject the commit fail-closed. Each entry is the full
	// `<family> <leaf>` path under the ids-option.
	UnknownLeaves []string
}

// ScreenBadNumeric records a screen numeric leaf whose explicitly-provided value
// did not parse as a positive integer (#3317): the full leaf path (e.g.
// "tcp syn-flood attack-threshold") and the raw offending value.
type ScreenBadNumeric struct {
	Path  string
	Value string
}

// ICMPScreen configures ICMP screening.
type ICMPScreen struct {
	PingDeath      bool
	Fragment       bool
	FloodThreshold int
}

// IPScreen configures IP screening.
type IPScreen struct {
	SourceRouteOption bool
	TearDrop          bool
	IPSweepThreshold  int // #4114 Junos detection WINDOW in microseconds (fixed count 10); 0 = disabled
}

// TCPScreen configures TCP screening.
type TCPScreen struct {
	SynFlood          *SynFloodConfig
	Land              bool
	WinNuke           bool
	SynFrag           bool
	SynFin            bool
	NoFlag            bool
	FinNoAck          bool
	PortScanThreshold int // #4114 Junos detection WINDOW in microseconds (fixed count 10); 0 = disabled
}

// UDPScreen configures UDP screening.
type UDPScreen struct {
	FloodThreshold int
}

// SynFloodConfig configures SYN flood protection thresholds.
type SynFloodConfig struct {
	AlarmThreshold       int
	AttackThreshold      int
	SourceThreshold      int
	DestinationThreshold int
	Timeout              int
}

// AddressBook holds named addresses and address sets.
type AddressBook struct {
	Addresses   map[string]*Address
	AddressSets map[string]*AddressSet
}

// Address is a named address entry (IP prefix).
type Address struct {
	Name        string
	Value       string // CIDR notation
	Description string // optional Junos `description` sub-stanza
	// TrailingTokens holds tokens that rode past the legitimate arity of a
	// flat-set `address <name> <prefix>` / `address <name> description
	// <text>` line (#3332). The address node is a `multi:true` leaf (so the
	// generic scalar-leaf arity gate cannot reach it) and the compiler reads
	// only the prefix / description-text slot, silently dropping anything
	// after it. validateAddressBookTrailingStrict rejects these at commit
	// (lenient downgrade on the tolerant load / peer-sync path).
	TrailingTokens []string
}

// AddressSet is a named group of addresses and/or nested address-sets.
type AddressSet struct {
	Name        string
	Addresses   []string // references to Address names
	AddressSets []string // references to other AddressSet names (nested)
}

// ApplicationsConfig holds application definitions.
type ApplicationsConfig struct {
	Applications    map[string]*Application
	ApplicationSets map[string]*ApplicationSet
	// MixedDirectTermApps records the names of user-defined applications that
	// carried BOTH a direct match body (protocol / destination-port /
	// source-port / inactivity-timeout / timeout / icmp-type / icmp-code / alg)
	// AND one or more `term` sub-blocks. Junos requires a custom application to
	// be EITHER scalar/direct OR term-based, never both. compileApplications
	// stores only the synthesized term applications for a term-bearing app, so
	// the direct body was SILENTLY DROPPED (a fail-open under-match for a deny
	// application). The offending parent names are recorded here and the deferred
	// gate (validateApplicationStructureStrict) hard-rejects them on the strict
	// commit path / warns on the tolerant load / peer-sync path (#3366).
	MixedDirectTermApps []string
}

// ApplicationSet groups multiple applications or nested application-sets.
type ApplicationSet struct {
	Name         string
	Applications []string // references to Application or ApplicationSet names
	// UnknownMembers records the raw member keywords inside an application-set
	// body that are NOT a recognized member statement (`application` or
	// `application-set`). The schema declares `application-set` as an opaque
	// args:1 leaf (children:nil), so the SchemaValidate walk never reaches its
	// members; before #3890 compileApplications had no default arm on the
	// member switch, so a typo'd member keyword (e.g. `applicaton foo` for
	// `application foo`, or a mistyped `application-set`) was SILENTLY DROPPED —
	// the set was under-populated, and if it was referenced by a DENY policy the
	// deny matched FEWER applications than the operator intended (a fail-open
	// under-match; traffic meant to be blocked is permitted). Mirroring
	// UnknownTermLeaves, the offending keyword is recorded here and the deferred
	// gate (validateApplicationSyntaxStrict) hard-rejects the first one on the
	// strict commit path / warns on the tolerant load / peer-sync path (#3890).
	UnknownMembers []string
}

// Application defines a network application by protocol and port.
type Application struct {
	Name              string
	Protocol          string // tcp, udp, icmp, or numeric ("47")
	DestinationPort   string // "80", "8080-8090"
	SourcePort        string // "1024-65535" (optional)
	InactivityTimeout int    // seconds (0 = default)
	ALG               string // "ssh", "ftp", etc. (informational)
	Description       string
	// ICMPType / ICMPCode constrain an ICMP/ICMPv6 application to a single
	// message type (and optionally code), e.g. junos-ping = ICMP type 8
	// (echo-request) and junos-pingv6 = ICMPv6 type 128. nil means "no
	// constraint" — the application matches every type/code of its protocol
	// (the historical behavior and what the all-ICMP aliases keep). #3020.
	ICMPType *uint8
	ICMPCode *uint8
	// UnknownTimeouts records the raw `inactivity-timeout` / `timeout` tokens
	// (top-level or inline-term) that did NOT parse to a valid integer in the
	// accepted 1..86400-second range. compileApplications cannot return an
	// error from the per-leaf parse without breaking the tolerant load path, so
	// — mirroring UnknownActions / UnknownFlexMatch — it records the offending
	// raw token here and the deferred gate (validateApplicationSpecsStrict)
	// hard-rejects it on the strict commit path / warns on the lenient
	// load / peer-sync path. A malformed value left InactivityTimeout at its
	// zero default, silently falling the application back to the global
	// per-protocol timeout instead of the configured one (#3320).
	UnknownTimeouts []string
	// UnknownICMP records the raw `icmp-type` / `icmp-code` tokens (top-level or
	// inline-term) that did NOT parse to a valid integer in 0..255. The schema
	// range-validates the TOP-LEVEL leaves at commit-check, but the inline
	// `term` is opaque to the schema walk (children:nil), so a malformed inline
	// `icmp-type` would otherwise be silently dropped by parseICMPTypeCode —
	// leaving the term UNCONSTRAINED, i.e. matching every ICMP type (a fail-open
	// widening, the inverse of the #3348 fix). Mirroring UnknownTimeouts, the
	// offending raw token is recorded here and the deferred gate
	// (validateApplicationSpecsStrict) hard-rejects it on the strict commit path
	// / warns on the lenient load / peer-sync path (#3348).
	UnknownICMP []string
	// UnknownTermLeaves records the raw tokens inside an inline
	// `application <a> term <t> { ... }` that are NOT a recognized term leaf
	// (protocol / source-port / destination-port / inactivity-timeout / timeout
	// / icmp-type / icmp-code / alg). The inline `term` is declared as an opaque
	// `args:1` schema leaf (children:nil), so the SchemaValidate walk cannot
	// reach inside it; before #3352 parseApplicationTerms had no default arm, so
	// an unknown leaf (a typo like `destination-poort 22`) was silently dropped
	// along with its value — the term kept only its remaining constraints and a
	// narrow permit/deny term widened to all-protocol (e.g. all-TCP). Mirroring
	// UnknownTimeouts / UnknownICMP, the offending token is recorded here and the
	// deferred gate (validateApplicationSpecsStrict) hard-rejects the first one
	// on the strict commit path / warns on the tolerant load / peer-sync path
	// (#3352).
	UnknownTermLeaves []string
	// DuplicateTermLeaves records the names of single-valued (scalar) leaves
	// (destination-port / source-port / inactivity-timeout / timeout / alg /
	// icmp-type / icmp-code) that
	// appeared MORE THAN ONCE with a CONFLICTING (different) value inside one
	// inline `application <a> term <t>`. The inline term is opaque to the
	// SchemaValidate walk, so a repeated scalar leaf — via apply-groups, flat-set
	// ordering, or hand authoring — was last-writer-wins: parseApplicationTerms
	// overwrote the earlier value with no validation, silently narrowing (or
	// widening) the term to the final token by parse order. An idempotent repeat
	// (the same value again, e.g. the `timeout` / `inactivity-timeout` aliases
	// both set to the same number) is harmless and is NOT recorded. `protocol` is
	// NOT tracked here — a repeated `protocol` is the documented
	// multi-protocol-term syntax. Mirroring UnknownTermLeaves, the offending leaf
	// name is recorded and the deferred gate (validateApplicationStructureStrict)
	// hard-rejects the first one on the strict commit path / warns on the tolerant
	// load / peer-sync path (#3366; icmp-type / icmp-code added in #6766 — their
	// omission let a conflicting repeat silently narrow a referenced deny to the
	// LAST type/code).
	DuplicateTermLeaves []string
	// DuplicateDirectLeaves records the names of single-valued (scalar) DIRECT
	// match leaves (protocol / destination-port / source-port / inactivity-timeout
	// / timeout / icmp-type / icmp-code / alg) that appeared MORE THAN ONCE with a
	// CONFLICTING (different) value directly on one `applications application
	// <name>` body — the direct-body analogue of DuplicateTermLeaves. The direct
	// scalar loop in compileApplications assigns each leaf straight into a SINGLE
	// typed field, so a repeated conflicting leaf (protocol tcp; protocol udp;
	// destination-port 22; destination-port 53) was last-writer-wins: only the
	// FINAL value was enforced with no commit error, so a deny referencing the
	// application covered FEWER protocol/port combinations than authored and could
	// fall through to a permit / default-permit (a fail-open under-match). This is
	// reachable whenever the AST carries duplicate sibling leaves — a hierarchical
	// config load / paste, an apply-groups merge, or a peer-synced serialized
	// config; flat-set `SetPath` collapses a single-value leaf to the last value
	// before the compiler runs, so it cannot reproduce the drop. An idempotent
	// same-value repeat is NOT recorded. Unlike DuplicateTermLeaves, `protocol` IS
	// tracked here — the direct body has no multi-protocol syntax (Application.Protocol
	// is a single field), so a second protocol silently overwrites rather than
	// adding a term. Mirroring DuplicateTermLeaves, the offending leaf name is
	// recorded and the deferred gate (validateApplicationStructureStrict)
	// hard-rejects the first one on the strict commit path / warns on the tolerant
	// load / peer-sync path (#5574).
	DuplicateDirectLeaves []string
	// UnknownDirectLeaves records the raw tokens directly under an
	// `applications application <name>` body that are NOT a recognized direct
	// match leaf (protocol / destination-port / source-port /
	// inactivity-timeout / timeout / icmp-type / icmp-code / alg / description /
	// term) — the DIRECT-body analogue of UnknownTermLeaves.
	//
	// #6524: the flat-set grammar builds `set a b c d` as a CHAIN of single-key
	// nodes, so `set applications application myapp protocol tcp
	// destination-port 8080` nests `destination-port` UNDER the value node
	// `tcp` rather than beside `protocol`. applicationDirectLeaves now follows
	// that chain, so a token it cannot map to a known leaf keyword is real
	// operator garbage rather than a shape the walk failed to reach. Two forms
	// land here:
	//
	//   - a bracketed list on a single-valued leaf — `protocol [ tcp udp ]`,
	//     `destination-port [ 22 23 ]`. Junos gives a direct application body
	//     ONE protocol and ONE port (multi-valued matching is what `term`
	//     sub-blocks are for), and Application.Protocol / .DestinationPort are
	//     single fields that cannot represent the set, so every value past the
	//     first was silently dropped;
	//   - a typo'd leaf keyword (`destination-poort 8080`), silently dropped
	//     along with its value.
	//
	// Either way the dropped token changes what the application matches, in
	// whichever DIRECTION the dropped constraint pointed: losing a port or
	// icmp-type WIDENS it (pkg/policymatch treats an empty DestinationPort as
	// match-any, so a permit over-permits), while losing an alternative from a
	// bracketed protocol list NARROWS it to the first value (so a deny
	// under-matches). Both are wrong; neither is uniformly "widening".
	//
	// `description` never contributes to this list from its own token run. It is
	// a TAIL leaf (Junos takes its text to the end of the statement), so
	// applicationDirectLeaves joins the run into the description text rather
	// than recording the second and later words here. That covers
	// `description destination-port` (text that happens to spell a keyword —
	// the leaf's value slot is reserved before the keyword scan resumes) and a
	// multi-word description PACKED onto one node's Keys. Rejecting a METADATA
	// leaf that cannot affect what the application matches would be pure
	// friction, and that spelling committed on master.
	//
	// The join is deliberately NOT a claim that every multi-word description
	// now commits. A description that HEADS a flat-set chain
	// (`set ... description my web app ...`) parks its tail in a CHILD node, so
	// "web" opens a fresh run and IS recorded here — and SchemaValidate rejects
	// the same line independently ("unexpected trailing token"). Master
	// rejected it by that same schema gate, so this is parity, not a new
	// refusal; see TestDescriptionIsATailLeaf, which pins both positions.
	//
	// The `scalar: true` arity the schema enforces for `description`
	// (validateScalarValueLeaf / #3332) is untouched. It governs the SIBLING
	// spelling and the head-of-chain spelling; the only position it does not
	// reach is a description packed into a chain TAIL, below the depth the
	// schema walk descends to — which is exactly the position the join above
	// exists to cover. So no config that was committable on master is newly
	// refused.
	//
	// Mirroring UnknownTermLeaves, the offending token is recorded here and the
	// deferred gate (validateApplicationSyntaxStrict) hard-rejects the first one
	// on the strict commit path / warns on the tolerant load / peer-sync path
	// (#1960 no-brick).
	UnknownDirectLeaves []string
}

// IPsecConfig holds IPsec VPN configuration.
type IPsecConfig struct {
	// Phase 1 (IKE)
	IKEProposals map[string]*IKEProposal
	IKEPolicies  map[string]*IKEPolicy
	Gateways     map[string]*IPsecGateway

	// Phase 2 (IPsec)
	Proposals map[string]*IPsecProposal
	Policies  map[string]*IPsecPolicyDef
	VPNs      map[string]*IPsecVPN
}

// IKEProposal defines Phase 1 (IKE) negotiation parameters.
type IKEProposal struct {
	Name            string
	AuthMethod      string // "pre-shared-keys"
	EncryptionAlg   string // "aes-256-cbc"
	AuthAlg         string // "sha-256"
	DHGroup         int    // DH group number
	LifetimeSeconds int
}

// IKEPolicy defines Phase 1 policy (mode, proposal reference, PSK).
type IKEPolicy struct {
	Name string
	Mode string // "main" or "aggressive"
	// ProposalSet is a Junos predefined IKE proposal-set keyword
	// (standard, basic, compatible, suiteb-gcm-128, suiteb-gcm-256).
	// When set and no explicit Proposals are given, the compiler expands
	// it into concrete synthetic IKE proposals (expandIKEProposalSets,
	// #4297) so the common vSRX shorthand commits a working tunnel instead
	// of being silently dropped.
	ProposalSet string
	// Proposals is the ordered list of IKE proposal references. Junos
	// `proposals [ p1 p2 ]` offers every listed proposal for phase-1
	// negotiation; reading only the first (the pre-#3904 scalar) narrowed
	// crypto negotiation so a peer requiring the second proposal could not
	// establish. Rendered comma-joined into the swanctl `proposals =` line.
	Proposals []string
	PSK       Secret // pre-shared key; redacted on JSON/YAML marshal (#2053)
}

// IPsecProposal defines Phase 2 (ESP) encryption and authentication parameters.
type IPsecProposal struct {
	Name            string
	Protocol        string // "esp"
	EncryptionAlg   string // "aes-256-cbc", "aes-128-gcm"
	AuthAlg         string // "hmac-sha-256" (ignored for GCM)
	DHGroup         int    // DH group number
	LifetimeSeconds int
	// LifetimeKilobytes is the Junos ESP volume-based rekey threshold
	// (`lifetime-kilobytes`). It is CAPTURED so the #4313 closed-world flip
	// on `security ipsec proposal` is leaf-complete (a valid proposal
	// carrying it is not false-rejected) and so ValidateConfig can emit the
	// accepted-only advisory — the userspace dataplane / strongSwan renderer
	// does not yet program a volume-based rekey, so the value is accepted but
	// not enforced (config-only parity, #2078/#4231 doctrine).
	LifetimeKilobytes int
}

// IPsecPolicyDef defines Phase 2 policy (PFS + proposal reference).
type IPsecPolicyDef struct {
	Name     string
	PFSGroup int // PFS DH group number (0 = disabled)
	// ProposalSet is a Junos predefined IPsec proposal-set keyword
	// (standard, basic, compatible, suiteb-gcm-128, suiteb-gcm-256).
	// When set and no explicit Proposals are given, the compiler expands
	// it into concrete synthetic ESP proposals (expandIPsecProposalSets,
	// #4297). Mirror of IKEPolicy.ProposalSet.
	ProposalSet string
	// Proposals is the ordered list of IPsec (ESP) proposal references.
	// Junos `proposals [ p1 p2 ]` offers every listed proposal; the
	// pre-#3904 scalar truncated to the first, narrowing negotiation.
	// Rendered comma-joined into the swanctl `esp_proposals =` line.
	Proposals []string
}

// IPsecGateway defines a remote IKE gateway.
type IPsecGateway struct {
	Name             string
	Address          string // remote gateway IP
	DynamicHostname  string // dynamic peer hostname (DNS-resolved)
	ResponderOnly    bool   // dynamic peer with no fixed address/hostname: responder-only (remote_addrs = %any)
	LocalAddress     string // local IP
	IKEPolicy        string // IKE policy reference
	ExternalIface    string // external-facing interface
	LocalCertificate string // local certificate name for pubkey auth
	Version          string // "v1-only", "v2-only" (empty = both)
	NoNATTraversal   bool   // disable NAT-T (legacy, use NATTraversal)
	NATTraversal     string // "enable" (default), "disable", "force"
	// DPDEnable records that a `dead-peer-detection` stanza is present, so a
	// bare `dead-peer-detection;` (Junos: enable DPD with defaults) or an
	// interval-only / threshold-only form enables DPD even though no explicit
	// mode keyword was given. It is the single source of truth for "is DPD
	// on"; DeadPeerDetect only carries the explicit mode keyword (#3994).
	DPDEnable      bool
	DeadPeerDetect string // explicit mode: "always-send", "optimized", "probe-idle-tunnel" (empty = Junos default / bare stanza)
	DPDInterval    int    // seconds
	DPDThreshold   int    // retry count before peer is considered dead
	LocalIDType    string // "hostname", "inet", "fqdn"
	LocalIDValue   string // identity value
	RemoteIDType   string // "hostname", "inet", "fqdn"
	RemoteIDValue  string // identity value
	// DynamicHostnameExtras holds tokens that rode past the FQDN on a
	// compact-hierarchical `dynamic hostname <fqdn> <extra>` line (#3332).
	// The flat-set form lands `hostname <fqdn>` as a scalar child the generic
	// arity gate covers, but the compact-hierarchical form collapses
	// `hostname <fqdn> <extra>` onto the parent `dynamic` node's Keys and the
	// compiler reads only Keys[2], silently dropping the rest.
	// validateTrailingTokensStrict rejects these at commit (lenient downgrade
	// on the tolerant load / peer-sync path).
	DynamicHostnameExtras []string
}

type IPsecTrafficSelector struct {
	Name     string
	LocalIP  string
	RemoteIP string
}

// IPsecVPN defines an IPsec VPN tunnel.
type IPsecVPN struct {
	Name             string
	Gateway          string // gateway reference
	IPsecPolicy      string // IPsec policy reference
	LocalID          string // local traffic selector (CIDR)
	RemoteID         string // remote traffic selector (CIDR)
	PSK              Secret // pre-shared key (legacy, prefer IKE policy); redacted on marshal (#2053)
	LocalAddr        string // local address
	BindInterface    string // tunnel interface (e.g. "st0.0") — creates xfrmi with if_id
	DFBit            string // "copy", "set", "clear"
	EstablishTunnels string // "immediately", "on-traffic", "responder-only"
	TrafficSelectors map[string]*IPsecTrafficSelector
	// Manual records a `manual { ... }` manual-key SA block (#4300, V-4).
	// xpf does not support manual-key SAs; the block used to be silently
	// dropped, leaving a dead tunnel that committed OK. It is now captured
	// so validateIPsecManualKeyStrict can hard-reject it at commit with a
	// clear "use an IKE-negotiated VPN" message (lenient warn on load).
	Manual bool
	// VPNMonitor records a `vpn-monitor { ... }` block (#4299, V-3). xpf
	// does not implement vpn-monitor's ICMP-probe liveness / st0
	// interface-state coupling; the stanza is accepted and captured so
	// ValidateConfig can emit an accepted-but-not-enforced advisory
	// (mirroring the #2078/#4231 doctrine) rather than silently dropping it.
	VPNMonitor                bool
	VPNMonitorSourceInterface string
	VPNMonitorDestinationIP   string
	VPNMonitorOptimized       bool
}

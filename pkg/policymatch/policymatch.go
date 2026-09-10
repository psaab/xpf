// Package policymatch is the single operator-side security-policy simulator
// shared by the REST `match-policies` handler, the gRPC `MatchPolicies` RPC,
// and the CLI `show security match-policies` command.
//
// Before #3042 each of those three surfaces carried its own hand-written
// shadow matcher, and all three diverged from the runtime policy evaluator in
// userspace-dp/src/policy.rs in ways that made the diagnostic return the
// OPPOSITE of what the dataplane actually does:
//
//   - they looped only cfg.Security.Policies (the zone-pair sets) and never
//     consulted cfg.Security.GlobalPolicies, so a flow admitted/denied by a
//     `policy global` rule was reported as the default action;
//   - they hard-coded "deny (default)" on a miss even when
//     `default-policy permit-all` was active;
//   - their address matcher handled only `any` plus address-book names/sets —
//     no literal CIDRs, no `any-ipv4`/`any-ipv6`, no source/destination
//     `*-address-excluded` exclusion flags, and no dynamic-address feed
//     overlay;
//   - their application matcher read only cfg.Applications.Applications, so a
//     predefined Junos application (junos-http, ...) never matched, only one
//     application-set level was expanded, and source-port terms were ignored.
//
// This package replicates the runtime precedence and semantics exactly. The
// ground truth is userspace-dp/src/policy.rs (evaluate_policy_result_with_len
// + try_match_rule + parse_v3_literal_set + CompiledApplications) fed by the
// Go snapshot builder (pkg/dataplane/userspace/policies.go). Where the runtime
// and the old per-surface matchers disagreed, the runtime wins.
//
// Note on scheduler state (#3104): the runtime honors a policy's
// scheduler-driven `inactive` flag — policy.rs try_match_rule returns None for
// an inactive rule BEFORE app/address matching, and the snapshot builder
// (pkg/dataplane/userspace/policies.go) stamps that Inactive flag and fails
// closed on missing scheduler state. This simulator is schedule-aware when the
// caller threads live per-scheduler active-state into Query.PolicyInactiveFn:
// it then SKIPS a scheduler-inactive policy exactly like the runtime, falling
// through to the next active rule / configured default-policy. The live
// daemon-local surfaces (REST/gRPC/CLI match-policies) ALWAYS thread a non-nil
// PolicyInactiveFn — even before scheduler state is published — because
// dataplane/userspace.PolicyInactiveFn fails closed on a nil state map (#3414),
// so the simulator treats a scheduled policy as inactive exactly as the
// dataplane does rather than certifying it as-if-active. When PolicyInactiveFn
// is nil the simulator falls back to evaluating the configured policy set
// as-if-active; that is reserved for a purely offline, dataplane-less config
// simulator that has no runtime verdict to agree with. A
// NON-scheduled policy is unaffected in either case: PolicyInactiveFn is only
// ever consulted with a policy's scheduler name, and the SSOT predicate
// (dataplane/userspace.PolicyInactive) reports an empty scheduler name as
// always active.
package policymatch

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// MaxPort is the largest valid TCP/UDP port number.
const MaxPort = 65535

// icmpProtoNum / icmpv6ProtoNum are the IANA protocol numbers for ICMP and
// ICMPv6. They gate an ICMP-type-constrained application term (#3284) so it can
// only match an ICMP-family flow, mirroring the dataplane keying its
// icmp_constraints under the ICMP protocol (policy.rs CompiledApplications).
const (
	icmpProtoNum   uint8 = 1
	icmpv6ProtoNum uint8 = 58
)

// JunosHostZone is the reserved self-traffic zone name. A query whose ToZone is
// this name is host-bound (LocalDelivery) traffic; it is evaluated by the
// dataplane's separate host gate (evaluate_junos_host_policy), not the transit
// precedence chain. See matchJunosHost / Result.HostInboundUnmatched (#3285).
const JunosHostZone = "junos-host"

// ValidatePort checks an already-parsed simulator port value (the gRPC int32
// field and the REST query int, which arrive numeric). A zero value means
// "unspecified" — the port dimension is not constrained, the established
// wildcard behavior — and is accepted. Any other value outside [1, MaxPort]
// (negative, or above the 16-bit port space) cannot describe a real packet, so
// it is REJECTED with an error rather than silently coerced to the 0 wildcard
// (#3116). The shared matcher gates the port term on dstPort/srcPort > 0, so a
// malformed/negative/out-of-range value that slips through silently becomes
// "no port constraint" and yields a verdict for a packet that cannot exist.
func ValidatePort(port int) error {
	if port < 0 || port > MaxPort {
		return fmt.Errorf("port %d out of range (0-%d, 0 = unspecified)", port, MaxPort)
	}
	return nil
}

// ParsePort parses a simulator port token supplied as an operator string (the
// CLI surface). An empty/whitespace token means "unspecified" and returns
// (0, nil) — the wildcard behavior, unchanged. A non-empty token must be a
// canonical unsigned decimal that ValidatePort accepts ([0, MaxPort]); a
// malformed ("abc"), signed ("+80"/"-80", #3679), or >MaxPort token is REJECTED
// with an error so it can never silently degrade to the 0 wildcard (#3116). An
// explicit "0" is accepted as "unspecified" for parity with the gRPC int field,
// where proto3 cannot distinguish an unset scalar from 0.
//
// #3679: this diagnostic parser routes through config.ParseCanonicalUint — the
// same canonical-form primitive the #3606 commit-time and dataplane port
// parsers use — so a signed spelling the config grammar and dataplane now reject
// can no longer be accepted here (a commit-vs-diagnostic split that made
// automated policy verification green for a token the platform rejects).
func ParsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	n, err := config.ParseCanonicalUint(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if err := ValidatePort(n); err != nil {
		return 0, err
	}
	return n, nil
}

// ParseICMPValue parses an operator-supplied ICMP type or code token (#3284)
// into a *uint8 the simulator threads into Query.ICMPType / Query.ICMPCode. An
// empty/whitespace token means "unspecified" and returns (nil, nil) — the
// dimension is not constrained, the established wildcard behavior. A non-empty
// token must be a canonical unsigned decimal in [0, 255] (the 8-bit ICMP
// type/code space); a malformed, signed ("+8"/"-8", #3679), or >255 token is
// REJECTED with an error so it can never silently degrade to the nil wildcard.
// The pointer return distinguishes "unspecified" from a valid 0 (ICMP type 0 =
// echo-reply, code 0 is common).
//
// #3679: like ParsePort, this diagnostic parser routes through
// config.ParseCanonicalUint so a signed spelling (Atoi accepted "+8" as
// echo-request) is rejected, matching the canonical rule the commit-time and
// dataplane parsers enforce.
func ParseICMPValue(s string) (*uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	n, err := config.ParseCanonicalUint(s)
	if err != nil {
		return nil, fmt.Errorf("invalid icmp type/code %q", s)
	}
	if n < 0 || n > 255 {
		return nil, fmt.Errorf("icmp type/code %d out of range (0-255)", n)
	}
	v := uint8(n)
	return &v, nil
}

// ValidateProtocol checks an explicitly-supplied simulator protocol token. An
// empty/whitespace token means "unspecified" — the protocol dimension is not
// constrained (the established match-any wildcard) — and is accepted. A
// non-empty token must resolve to an IANA protocol number via
// appid.ProtocolNumber: a known name/alias ("tcp", "udp", "icmp", "ospf", ...)
// or a numeric value in 0-255. An unknown name ("notaproto") or an
// out-of-range / non-numeric value ("999", "tcpp") is REJECTED with an error
// rather than silently treated as "any protocol" (#3108).
//
// This is the protocol analogue of ValidatePort/ParsePort (#3116). The shared
// matcher (matchApp) short-circuits to match-any when the query protocol is the
// empty string, so an invalid token that slips through unvalidated silently
// becomes "no protocol constraint" and yields a permit/deny verdict for traffic
// that cannot exist — masking an operator typo. There is no "any" protocol
// keyword: omit the token (empty) for the protocol wildcard, matching the
// runtime evaluator which constrains the protocol dimension only when a
// resolvable protocol is supplied.
//
// A single string validator covers every simulator surface (REST query, gRPC
// field, CLI/remote-cli token, gRPC test-policy), since each accepts the
// protocol as a string that matchApp resolves identically by name or number.
func ValidateProtocol(proto string) error {
	if strings.TrimSpace(proto) == "" {
		return nil
	}
	if _, ok := appid.ProtocolNumber(proto); !ok {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	return nil
}

// matchPoliciesUsageTail is the SINGLE source of truth for the selector list
// advertised by the match-policies / test-policy simulators (#3628). It is the
// text printed after the command-specific "usage: ..." prefix and is shared by
// all four surfaces: the local CLI (pkg/cli) `show security match-policies` +
// `test policy`, and the remote CLI (cmd/cli) equivalents.
//
// Before #3628 each surface printed its own hard-coded copy. Those copies had
// already drifted (the local `show security match-policies` advertised only
// `source-ip destination-ip destination-port protocol <tcp|udp>` while the
// remote surface also listed `source-port`) and, more importantly, ALL FOUR
// hid the icmp-type/icmp-code and non-TCP/UDP protocol selectors that every
// surface actually parses (ParsePort, ParseICMPValue, ValidateProtocol). An
// operator debugging an ICMP, source-port-constrained, or gre/esp/ospf policy
// would omit the required selector and read a false no-match / wrong verdict
// from a firewall debug tool that hid valid inputs.
//
// The block lists every selector the parsers accept, with concrete TCP / UDP /
// ICMP / ICMPv6 examples, and notes that protocol takes a name or a 0-255
// number. from-zone and to-zone are the only required selectors.
const matchPoliciesUsageTail = ` from-zone <zone> to-zone <zone>
       [source-ip <ip>] [destination-ip <ip>]
       [source-port <0-65535>] [destination-port <0-65535>]
       [protocol <name|number>]   tcp, udp, icmp, icmp6, gre, esp, ospf, ... or 0-255
       [icmp-type <0-255>] [icmp-code <0-255>]
       [ingress-interface <if>]   scope host-inbound (to-zone junos-host) to one
                                  interface's effective host-inbound view
       [non-first-fragment]       simulate a non-first IP fragment (no L4 header)
       from-zone and to-zone are required; an omitted selector matches any.
       an unknown selector, or a selector given without a value, is an error
       (the query is not silently widened to match traffic you did not type).
       non-first-fragment is the only valueless selector; it makes the simulator
       reproduce the dataplane's fragment-associated deny (a port-bearing deny the
       first fragment would hit denies the fragment too).
       examples:
         ... protocol tcp destination-port 443
         ... protocol udp source-port 53 destination-port 53
         ... protocol icmp icmp-type 8 icmp-code 0    (IPv4 echo request)
         ... protocol icmp6 icmp-type 128             (IPv6 echo request)
         ... protocol tcp non-first-fragment          (non-first TCP fragment)`

// MatchPoliciesUsage is the full usage/help block printed by `show security
// match-policies` when the required from-zone/to-zone selectors are missing
// (#3628).
const MatchPoliciesUsage = "usage: show security match-policies" + matchPoliciesUsageTail

// TestPolicyUsage is the full usage/help block printed by `test policy` when
// the required from-zone/to-zone selectors are missing (#3628).
const TestPolicyUsage = "usage: test policy" + matchPoliciesUsageTail

// Query is a 5-tuple policy-simulation request. A nil SrcIP/DstIP or an empty
// Protocol means "unspecified" — the corresponding match dimension is not
// constrained (the established diagnostic behavior). A zero SrcPort/DstPort
// means "unspecified port" and likewise does not constrain a port-bearing
// application term.
type Query struct {
	FromZone string
	ToZone   string
	SrcIP    net.IP
	DstIP    net.IP
	Protocol string // "tcp", "udp", "89", "ospf", ... ("" = unspecified)
	SrcPort  int
	DstPort  int

	// IngressInterface scopes a `to-zone junos-host` query's host-inbound
	// admission to ONE ingress interface's effective host-inbound view (#5579).
	// A zone can carry multiple per-interface host-inbound effective views
	// (#3362); without this selector the classifier reports HostInboundAmbiguous
	// when they disagree. With it, the classifier evaluates ONLY this interface's
	// effective view (its per-interface override where declared, which REPLACES
	// the zone-level set — #6515 — else the zone-level set), so an operator can
	// certify one interface's TRUE host-inbound posture (admit vs deny) instead of
	// a zone-wide fold. The ref must name an interface assigned to FromZone; a
	// caller validates it via dataplane/userspace.ResolveHostInboundIngressInterface
	// before building the Query, so an invalid ref never reaches here. "" =
	// unspecified (zone-scoped classification, unchanged for every existing
	// caller). It affects ONLY the host-inbound classifier annotation, never the
	// transit/host policy match verdict.
	IngressInterface string

	// ICMPType / ICMPCode carry the query packet's ICMP/ICMPv6 type and code
	// (#3284). They mirror the dataplane's per-packet `packet_icmp` tuple
	// (policy.rs evaluate_policy_result_with_icmp): a type-constrained
	// application term (junos-ping = ICMP type 8, junos-pingv6 = ICMPv6
	// type 128) matches ONLY when the query's type is known and equal (and the
	// code too, when the term constrains a code). A nil ICMPType means the
	// query did not specify a type: a type-constrained term then fails closed
	// (does NOT match), exactly like the runtime passing `packet_icmp = None`.
	// An UNCONSTRAINED ICMP application (junos-icmp-all) is unaffected by these
	// fields — it matches every ICMP packet on protocol alone. Pointers
	// distinguish "unspecified" from a valid type/code 0 (ICMP type 0 is
	// echo-reply, code 0 is common), which a plain int could not.
	ICMPType *uint8
	ICMPCode *uint8

	// NonFirstFragment marks the query as a NON-FIRST IP fragment (#5572), the
	// flowless / no-L4 packet shape the dataplane calls `l4_present == false`
	// (policy.rs evaluate_policy_result_l3_aware, #3291/#4569). A non-first
	// TCP/UDP fragment carries the datagram's post-IP bytes as PAYLOAD, not an L4
	// header, so it has no readable ports (SrcPort/DstPort are meaningless — they
	// are ignored) and no readable ICMP type/code. The default false is a normal
	// L4-present packet, so every existing caller is byte-identical.
	//
	// When true the simulator reproduces the dataplane's #4569
	// fragment-associated deny EXACTLY:
	//
	//   - a PORT-BEARING or ICMP-type-constrained application term fails closed
	//     (matchApp with l4Present == false), regardless of any port value the
	//     caller left in SrcPort/DstPort — a fragment cannot be classified into an
	//     exact port, a port range (including a `0-1023` range that a naive port-0
	//     query would spuriously match), or an ICMP type;
	//   - a PROTOCOL-ONLY / `application any` term STILL matches on the L3 identity
	//     + known IP protocol the fragment does carry;
	//   - while walking rules in first-match precedence order, the FIRST
	//     port-bearing DENY/REJECT whose L3 (zone fixed by the tier + src/dst
	//     address) OVERLAPS the fragment but was SKIPPED only because its
	//     L4-constrained term is inapplicable is remembered; if the walk then lands
	//     on a PERMIT (a matched permit OR a default-permit) it is OVERRIDDEN to
	//     that DENY (Result.FragmentAssociatedDeny), so the simulator reports the
	//     same DROP + enforcing policy the dataplane applies rather than a
	//     fabricated port-0 permit.
	//
	// BOTH walks apply the override. The transit walk (Match) has since #5572;
	// the host walk (matchJunosHost) since #6576, mirroring #6465 in policy.rs.
	// They share one fragDenyTracker so the two cannot drift again — this
	// comment previously asserted the host gate had NO override, which stopped
	// being true the moment #6505 shipped and made the simulator report PERMIT
	// for a host-bound fragment the dataplane DROPS.
	//
	// On the host path the fall-through itself is permit-like (an unmatched
	// host-bound flow is DELIVERED — the management lifeline), so a skipped
	// overlapping port-bearing DENY fails the fragment closed there too.
	NonFirstFragment bool

	// FeedOverlay is the dynamic-address feed-prefix overlay (#2049): an
	// address-name -> union-of-live-feed-CIDR-strings map, the same shape the
	// snapshot builder consumes (feeds.Manager.SnapshotForBindings). When a
	// policy address token names a feed-backed address-name, its feed CIDRs are
	// merged with any static address-book content for that name. nil is valid
	// (no feed enforcement / surface without live feed access); a feed-backed
	// name then resolves to its static content only, matching the runtime
	// fail-closed-before-first-fetch behavior.
	FeedOverlay map[string][]string

	// PolicyInactiveFn, when non-nil, reports whether a policy bound to the
	// given scheduler name is currently runtime-inactive (#3104). It mirrors
	// the runtime's per-rule scheduler gate (policy.rs try_match_rule, which
	// drops an inactive rule before app/address matching). A policy for which
	// this returns true is SKIPPED, so the simulator falls through to the next
	// active rule / configured default-policy — agreeing with the dataplane.
	//
	// Callers build this from the live daemon-local per-scheduler active-state
	// map via dataplane/userspace.PolicyInactiveFn, which wraps the SSOT
	// PolicyInactive predicate shared with the snapshot builder and the #3062
	// display surfaces. An empty scheduler name reports active, so a
	// NON-scheduled policy is never skipped.
	//
	// nil is valid and means "scheduler-unaware": the simulator evaluates
	// scheduled policies as-if-active. This is reserved for a purely offline,
	// dataplane-less config simulator that has no runtime verdict to agree with.
	// The live daemon-local surfaces (REST/gRPC/CLI match-policies) ALWAYS
	// supply a non-nil predicate via dataplane/userspace.PolicyInactiveFn — even
	// when scheduler state is not yet published — because that predicate fails
	// closed on a nil state map (#3414), so a scheduled policy is treated as
	// inactive exactly as the dataplane treats it rather than certified active.
	PolicyInactiveFn func(schedulerName string) bool

	// SrcFamily / DstFamily carry the COLON-STRICT address family ("v4"/"v6"/"")
	// of the source/destination, derived by the caller from the RAW operator
	// text before net.ParseIP folded it (#6377). net.ParseIP renders `192.0.2.1`
	// and the IPv4-mapped literal `::ffff:192.0.2.1` as byte-identical 16-byte
	// values whose .To4() is non-nil, so by the time Match sees q.SrcIP/q.DstIP
	// the ':' that distinguishes a real IPv4 from a mapped IPv6 is gone. A caller
	// populates these from config.NATAddrFamily on the original string (the SSOT
	// colon-strict classifier that reproduces the Rust parsers,
	// pkg/config/compiler_nat_helpers.go), so a source authored as
	// `::ffff:192.0.2.1` yields "v6".
	//
	// The hint is consumed EVERYWHERE the family matters, so the simulator agrees
	// with the colon-strict runtime (userspace-dp/src/policy.rs):
	//
	//   - the (V4 src, V6 dst) unsupported-tuple gate in Match (queryTupleFamily);
	//   - the per-side address matcher matchAddr (its isV4 branch) — without the
	//     hint a mapped-v6 source would fold to v4 and match the V4 address rules,
	//     fabricating a permit the runtime never produces;
	//   - the host-inbound classifier hostInboundAdmission (ipFamilyStrict), so a
	//     mapped-v6 host-bound destination is classified ip6, not ip.
	//
	// Empty ("") means the caller supplied no hint — the net.IP-only callers,
	// e.g. tests. Every consumer then falls back to the folding To4() heuristic
	// for that side, preserving the pre-#6377 behavior. The hint never overrides
	// the actual address bytes: address CONTAINMENT still uses q.SrcIP/q.DstIP;
	// the family only selects which family's rules/tokens the side is tested
	// against.
	SrcFamily string
	DstFamily string
}

// SelectorArgs is the parsed, VALIDATED result of a policy-simulator selector
// token vector — the space-separated `from-zone <z> to-zone <z> [source-ip
// <ip>] [destination-ip <ip>] [source-port <p>] [destination-port <p>]
// [protocol <name|number>] [icmp-type <n>] [icmp-code <n>]` grammar that all
// four operator surfaces accept: the local CLI `show security match-policies`
// and `test policy` (pkg/cli), and the remote CLI equivalents (cmd/cli).
//
// A "" SrcIP/DstIP/Protocol or a 0 SrcPort/DstPort means the operator OMITTED
// that selector, the established wildcard — the corresponding match dimension
// is unconstrained. A nil ICMPType/ICMPCode is likewise unspecified. These are
// the ONLY wildcard signals: a selector that is PRESENT always carries a
// validated value (ParseSelectorArgs rejects a present-but-valueless selector),
// so a field left at its zero value here unambiguously means "omitted", never
// "present but silently dropped".
type SelectorArgs struct {
	FromZone string
	ToZone   string
	SrcIP    string // "" = unspecified; non-empty is a net.ParseIP-validated literal
	DstIP    string // "" = unspecified; non-empty is a net.ParseIP-validated literal
	Protocol string // "" = unspecified; non-empty resolves via appid.ProtocolNumber
	SrcPort  int    // 0 = unspecified
	DstPort  int    // 0 = unspecified
	ICMPType *uint8 // nil = unspecified
	ICMPCode *uint8 // nil = unspecified

	// IngressInterface scopes a `to-zone junos-host` host-inbound query to one
	// ingress interface's effective host-inbound view (#5579). "" = unspecified
	// (zone-scoped classification). The parser accepts any non-empty token; the
	// ref is validated against the live config (zone membership, lifeline reject)
	// at the surface that has cfg, not here.
	IngressInterface string

	// NonFirstFragment is the #5572 non-first-fragment / no-L4 discriminator.
	// false (default) = a normal L4-present packet, unchanged for every existing
	// query. true = the operator supplied the valueless `non-first-fragment`
	// selector, so the simulator evaluates the flowless fragment path
	// (l4_present == false) and reproduces the dataplane's #4569
	// fragment-associated deny. It is the ONLY non-value-taking selector; it is
	// still duplicate-checked like every other selector.
	NonFirstFragment bool
}

// ParseSelectorArgs is the SINGLE strict grammar for the policy-simulator
// selector token vector (#3696). Before it, each of the four CLI surfaces
// hand-maintained its own `for i := range args { switch args[i] {...} }` loop,
// and all four shared the SAME two fail-OPEN defects the session-filter parser
// hit and #3439 (H5) fixed strictly:
//
//   - a value-taking selector present WITHOUT a following value was guarded by
//     `if i+1 < len(args)` with no else, so a trailing selector left the field
//     at its zero/empty wildcard — `... destination-port` (no value) evaluated
//     ALL destination ports and printed a verdict for a port the operator never
//     typed;
//   - the switch had no `default:` arm, so an UNKNOWN/misspelled selector token
//     (and its value) were both silently skipped — `... protcol tcp` dropped
//     both tokens and yielded an any-protocol verdict.
//
// Because the shared matcher treats a zero port / empty protocol / nil
// icmp-type as "no constraint", either defect silently WIDENED the query: the
// operator got a permit/deny verdict for a broader set of traffic than they
// asked about, from a firewall diagnostic whose entire job is to answer
// precisely which traffic a policy matches.
//
// ParseSelectorArgs fails CLOSED, mirroring cmd/cli parseFlowSessionArgs
// (#3439): a value-taking selector without a value is an error; an empty value
// (e.g. an explicit `""` token) is an error (a present selector must carry a
// concrete value — M01); an unknown token is an error; and every value routes
// through the existing ParsePort / ParseICMPValue / ValidateProtocol / net.IP
// validators, so a malformed port / icmp / protocol / IP errors instead of
// degrading to the wildcard. A field left at its zero value in the returned
// SelectorArgs therefore means the operator OMITTED it (legit wildcard), never
// "present but dropped". from-zone and to-zone are the only REQUIRED selectors;
// they may be absent (the caller prints usage), but if present must carry a
// value like any other selector.
func ParseSelectorArgs(args []string) (SelectorArgs, error) {
	var s SelectorArgs
	// seen tracks which selector keywords have already been consumed so a
	// DUPLICATE selector is rejected (#3709). Every simulator selector is
	// value-taking and routes through takeValue exactly once per occurrence,
	// so a keyword already in seen is an unambiguous duplicate.
	seen := make(map[string]bool)
	// takeValue consumes the token following a value-taking selector, erroring
	// when the selector is REPEATED (#3709), when its value is missing (trailing
	// selector), or when its value is empty (present-but-valueless). Mirrors
	// cmd/cli/show.go parseFlowSessionArgs (#3439 H5).
	takeValue := func(i *int, kw string) (string, error) {
		// #3709: fail CLOSED on a duplicate selector (e.g. `source-port 80
		// source-port 443` or `from-zone trust from-zone dmz`). Before this the
		// switch below re-assigned the field on the second occurrence, silently
		// LAST-WINning: the simulator returned an allow/deny verdict for a
		// DIFFERENT packet than the operator typed. The gRPC text topic also
		// last-won while REST first-won, so the three surfaces even disagreed on
		// WHICH value survived. There is no correct silent pick for a duplicate,
		// so the ambiguity is an error — the fail-closed posture #3696 set for
		// the rest of this grammar.
		if seen[kw] {
			return "", fmt.Errorf("selector %q specified more than once", kw)
		}
		seen[kw] = true
		if *i+1 >= len(args) {
			return "", fmt.Errorf("selector %q requires a value", kw)
		}
		*i++
		v := strings.TrimSpace(args[*i])
		if v == "" {
			return "", fmt.Errorf("selector %q requires a value", kw)
		}
		return v, nil
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone":
			v, err := takeValue(&i, "from-zone")
			if err != nil {
				return SelectorArgs{}, err
			}
			s.FromZone = v
		case "to-zone":
			v, err := takeValue(&i, "to-zone")
			if err != nil {
				return SelectorArgs{}, err
			}
			s.ToZone = v
		case "source-ip":
			v, err := takeValue(&i, "source-ip")
			if err != nil {
				return SelectorArgs{}, err
			}
			// A non-empty but malformed IP would parse to nil and be treated as
			// a wildcard by the matcher, yielding a false-positive verdict
			// (#1711). Reject it here so every surface fails closed identically.
			if net.ParseIP(v) == nil {
				return SelectorArgs{}, fmt.Errorf("invalid source-ip %q", v)
			}
			s.SrcIP = v
		case "destination-ip":
			v, err := takeValue(&i, "destination-ip")
			if err != nil {
				return SelectorArgs{}, err
			}
			if net.ParseIP(v) == nil {
				return SelectorArgs{}, fmt.Errorf("invalid destination-ip %q", v)
			}
			s.DstIP = v
		case "source-port":
			v, err := takeValue(&i, "source-port")
			if err != nil {
				return SelectorArgs{}, err
			}
			p, err := ParsePort(v)
			if err != nil {
				return SelectorArgs{}, fmt.Errorf("invalid source-port: %w", err)
			}
			s.SrcPort = p
		case "destination-port":
			v, err := takeValue(&i, "destination-port")
			if err != nil {
				return SelectorArgs{}, err
			}
			p, err := ParsePort(v)
			if err != nil {
				return SelectorArgs{}, fmt.Errorf("invalid destination-port: %w", err)
			}
			s.DstPort = p
		case "protocol":
			v, err := takeValue(&i, "protocol")
			if err != nil {
				return SelectorArgs{}, err
			}
			if err := ValidateProtocol(v); err != nil {
				return SelectorArgs{}, err
			}
			s.Protocol = v
		case "ingress-interface":
			// #5579: the ingress interface whose EFFECTIVE host-inbound view a
			// `to-zone junos-host` query is classified against. Value-taking and
			// duplicate-checked like every other selector; the token is a free-form
			// interface ref (e.g. `ge-0/0/0.0`) validated against the live config at
			// the surface that has cfg (zone membership + lifeline reject), so no
			// per-value validation happens here beyond the shared present-but-empty
			// / duplicate guards in takeValue.
			v, err := takeValue(&i, "ingress-interface")
			if err != nil {
				return SelectorArgs{}, err
			}
			s.IngressInterface = v
		case "icmp-type":
			v, err := takeValue(&i, "icmp-type")
			if err != nil {
				return SelectorArgs{}, err
			}
			t, err := ParseICMPValue(v)
			if err != nil {
				return SelectorArgs{}, fmt.Errorf("invalid icmp-type: %w", err)
			}
			s.ICMPType = t
		case "icmp-code":
			v, err := takeValue(&i, "icmp-code")
			if err != nil {
				return SelectorArgs{}, err
			}
			cc, err := ParseICMPValue(v)
			if err != nil {
				return SelectorArgs{}, fmt.Errorf("invalid icmp-code: %w", err)
			}
			s.ICMPCode = cc
		case "non-first-fragment":
			// #5572: the ONLY valueless selector — a non-first IP fragment
			// (l4_present == false) is a packet SHAPE, not a value dimension, so
			// it takes no following token. It is still duplicate-checked (a
			// repeated `non-first-fragment non-first-fragment` is an error, the
			// same fail-closed posture as every value-taking selector, #3709). It
			// does NOT consume a value, so it must NOT route through takeValue.
			if seen["non-first-fragment"] {
				return SelectorArgs{}, fmt.Errorf("selector %q specified more than once", "non-first-fragment")
			}
			seen["non-first-fragment"] = true
			s.NonFirstFragment = true
		default:
			return SelectorArgs{}, fmt.Errorf("unknown selector %q", args[i])
		}
	}
	return s, nil
}

// Query builds a policymatch.Query from parsed selectors. The caller-supplied
// FeedOverlay and PolicyInactiveFn are left nil for the caller to populate.
// An empty SrcIP/DstIP maps to a nil net.IP (the match-any wildcard); a
// non-empty value is already net.ParseIP-validated by ParseSelectorArgs.
//
// #6377: the colon-strict family hint is derived from the RAW selector text
// (s.SrcIP/s.DstIP), before net.ParseIP folds an IPv4-mapped IPv6 literal, so a
// Query built here classifies the tuple family the same way the four operator
// surfaces do. (No production surface currently routes through this helper — it
// is a test/convenience builder — but keeping it colon-strict avoids seeding the
// fold into any future caller.)
func (s SelectorArgs) Query() Query {
	return Query{
		FromZone:         s.FromZone,
		ToZone:           s.ToZone,
		SrcIP:            net.ParseIP(s.SrcIP),
		DstIP:            net.ParseIP(s.DstIP),
		SrcFamily:        config.NATAddrFamily(s.SrcIP),
		DstFamily:        config.NATAddrFamily(s.DstIP),
		Protocol:         s.Protocol,
		SrcPort:          s.SrcPort,
		DstPort:          s.DstPort,
		ICMPType:         s.ICMPType,
		ICMPCode:         s.ICMPCode,
		NonFirstFragment: s.NonFirstFragment,
		IngressInterface: s.IngressInterface,
	}
}

// Result is the simulator verdict.
type Result struct {
	// Matched is true when a concrete zone-pair or global policy matched. When
	// false the verdict is the configured default-policy (see DefaultUsed).
	Matched bool
	// Global is true when the match came from a `policy global` rule rather
	// than a zone-pair rule.
	Global bool
	// DefaultUsed is true when no policy matched and Action is the configured
	// default-policy.
	DefaultUsed bool

	// UnzonedIngress is true when the query's FROM zone is not a known zone, so
	// the runtime denies it unconditionally (#6682) rather than falling through
	// to default-policy (#8318).
	//
	// It exists because the verdict is otherwise indistinguishable from a
	// default-deny, and on a `permit-all` box that misattribution is actively
	// false: `DisplayAction` would render "deny (default)" and the show surfaces
	// "Default deny (no matching policy ...)" for a deny the default did not
	// produce. Modelled on HostInboundUnmatched, which carries a different
	// terminal condition out of the matcher for the same reason.
	//
	// The EGRESS side has no such flag on purpose — an unknown ToZone really
	// does fall through to default-policy in the runtime.
	UnzonedIngress bool

	// ContentRejected is true when the simulated config references policy
	// content the userspace snapshot builder fails the WHOLE snapshot closed on
	// (#3727) — today, an application-set a policy names that cannot be expanded
	// (ExpandApplicationSet error, or an application-set that resolves to zero
	// members). The runtime treats it the way pkg/dataplane/userspace
	// expandUserspacePolicyApplications -> resolveUserspaceApplicationNames do:
	// the rule is poisoned with the reserved __unsupported__ sentinel term, the
	// helper integrity preflight raises SnapshotIntegrityError, and the dataplane
	// retains its previous-good snapshot (or fresh-boots default-deny) — it
	// enforces NONE of this config's verdicts. matchApp used to SILENTLY SKIP the
	// malformed set (its old `continue`) and fall through to a later rule /
	// default-policy, so the simulator reported a permit/deny/default verdict the
	// dataplane never certifies; under a default-permit it under-reported a
	// fail-closed config as PERMIT (the exact operator lie #3727 removes). When
	// ContentRejected is set the verdict reports that fail-closed retention
	// instead of a fabricated answer: Matched, DefaultUsed and
	// HostInboundUnmatched are all false, Action carries no enforced meaning
	// (set to the conservative PolicyDeny for a raw reader, but DisplayAction
	// renders the dedicated ContentRejectedActionString), and
	// ContentRejectionReasons names the offending policy + application-set so the
	// operator sees WHY. This is a config-level property (the runtime rejects the
	// ENTIRE snapshot on the first unrepresentable rule), so it is reported for
	// EVERY query against the config, not only a query that would hit the bad
	// rule.
	ContentRejected         bool
	ContentRejectionReasons []string

	// UnsupportedTupleFamily is true when the query carries an
	// IPv4-source / IPv6-destination tuple (codex-182 A10-b02-C1). The
	// forwarding path never produces that tuple — NAT46 is not supported, so
	// no inbound translation yields a v4 source with a v6 destination — and the
	// runtime matcher fails it closed (userspace-dp/src/policy.rs try_match_rule
	// rejects the (V4 src, V6 dst) arm). The reverse V6-source / V4-destination
	// tuple IS valid (it is the NAT64 arm) and is evaluated normally. Before
	// this gate the simulator evaluated the two address sides independently and
	// could return a concrete permit/deny/default verdict for a packet shape
	// the runtime can never see. When set, Matched / DefaultUsed /
	// HostInboundUnmatched / ContentRejected are all false and Action is the
	// conservative PolicyDeny for a raw reader; DisplayAction renders the
	// dedicated UnsupportedTupleFamilyActionString.
	UnsupportedTupleFamily bool

	// HostInboundUnmatched is true ONLY for a `to-zone junos-host` query that
	// matched no host-bound policy (#3285). The dataplane host gate
	// (evaluate_junos_host_policy) returns None here — no security *policy*
	// governs the flow: there is no implicit host default-deny at the policy
	// layer and NO transit global/default fallback. Local delivery is instead
	// gated by host-inbound-traffic service admission, which post-#3405
	// DEFAULT-DENIES a zone that has no host-inbound-traffic stanza — so
	// "unmatched" does NOT mean the packet is delivered (#3627).
	//
	// #6576 NARROWED this flag: an unmatched host walk that recorded a SKIPPED
	// overlapping port-bearing frag-deny candidate returns that deny
	// (FragmentAssociatedDeny) instead of setting this — the host fall-through
	// is permit-like, so the fragment fails closed against the rule it skipped,
	// mirroring the post-walk arm in evaluate_junos_host_policy. The flag now
	// means "unmatched AND no frag candidate", which for every ordinary L4
	// query (which never records a candidate) is the unchanged pre-#6576
	// contract — the management lifeline is untouched.
	//
	// Matched is false and DefaultUsed is false; callers must render this as
	// "host-inbound, subject to host-inbound-traffic service admission (no
	// stanza => default deny), not governed by transit/global/default
	// policy", NOT as the
	// default-policy verdict. Action is unset (PolicyPermit zero value) and
	// carries no meaning in this case.
	HostInboundUnmatched bool

	// FromZone and ToZone identify the SCOPE of the matched policy (#3331), so
	// a caller can disambiguate a verdict when the same policy name repeats
	// across zone pairs / global scope (legal in Junos). For a zone-pair policy
	// these are the surrounding `from-zone`/`to-zone` stanza. For a GLOBAL
	// policy they are the optional `match from-zone`/`match to-zone` scope
	// (#3148/#3288); an empty value means the global policy is unconstrained and
	// applies to every zone (callers render "" as "any" when Global is true).
	// Both are empty when no policy matched (DefaultUsed / HostInboundUnmatched).
	FromZone string
	ToZone   string

	// PolicyID is the stable runtime/RT_FLOW/session-table policy ID of the
	// matched policy (#3331), computed by the SSOT
	// dataplane/userspace.RuntimePolicyIDs (the same span-accumulated namespace
	// the dataplane write side and the `show policies` Index column use, #3063).
	// It lets a match-policies verdict be cross-referenced against the session
	// table and the policy-deny/permit audit log even when policy names collide
	// across scopes. Meaningful only when Matched is true; 0 for the
	// default-policy / host-inbound verdicts (and for a config that overflows
	// MaxRulesPerPolicy, which cannot be applied anyway — see RuntimePolicyIDs).
	PolicyID uint32

	PolicyName  string
	Description string
	Action      config.PolicyAction

	// SchedulerName is the `scheduler-name` binding of the matched policy
	// (#3685 M06), the same value the inventory (REST/gRPC GetPolicies,
	// #3624) carries. A matched policy is by construction currently ACTIVE —
	// the live simulator surfaces always thread a non-nil
	// Query.PolicyInactiveFn (dataplane/userspace.PolicyInactiveFn) that
	// SKIPS a scheduler-inactive rule before it can match (#3104/#3414) — so a
	// non-empty SchedulerName on a matched verdict names the time-gate that is
	// controlling the rule right now, not a rule that is currently gated off.
	// Empty for a non-scheduled (always-on) policy and for the
	// default-policy / host-inbound verdicts. Populated from pol.SchedulerName
	// in matchedResult; the offline (nil PolicyInactiveFn) simulator may report
	// a scheduler name for a rule that is not runtime-active, but no live
	// transport uses that mode.
	SchedulerName string

	// RuleID is the stable "<from>-><to>/<name>" rule identity the inventory
	// (REST/gRPC GetPolicies) and the snapshot/event path carry, computed by the
	// shared dpuserspace.StablePolicyRuleID (#3668). PolicyID above is the
	// runtime/reorder-fragile numeric id; RuleID lets a match-policies verdict be
	// joined to the stable identifier used by inventory, logs, and tests even
	// after a policy reorder. For a matched GLOBAL policy it uses the
	// "junos-global->junos-global/<name>" form exactly like the inventory global
	// rows. Meaningful only when Matched is true; empty for the default-policy /
	// host-inbound verdicts.
	RuleID string

	SrcAddresses []string
	DstAddresses []string
	// SourceAddressExcluded / DestinationAddressExcluded report whether the
	// matched policy carries Junos `source-address-excluded` /
	// `destination-address-excluded` (#3668): the rule matches every address
	// EXCEPT those in SrcAddresses/DstAddresses. The shared matcher (ruleMatches
	// -> matchAddr) already INVERTS the address test correctly for an excluded
	// side; these flags exist so a positive verdict does not read backwards —
	// without them a match against a source OUTSIDE an excluded set prints the
	// excluded list as if it were the reason for the match. DISPLAY-ONLY, like
	// SrcAddresses/DstAddresses; every re-match path reads pol.Match directly.
	// Meaningful only when Matched is true; false for the default-policy /
	// host-inbound verdicts.
	SourceAddressExcluded      bool
	DestinationAddressExcluded bool
	Applications               []string

	// HostInbound reports how the ingress zone's host-inbound-traffic admission
	// gate treats a host-bound (to-zone junos-host) query tuple (#3627 B1a): the
	// admitting system-service / protocol token, a global accept (ICMP error/ND,
	// ESP/AH), a default-deny, or indeterminate. It is set ONLY on the host path
	// (ToZone == junos-host); nil for every transit / default / content-rejected
	// verdict. It is ADDITIONAL context, not a verdict tier — the host gate has
	// no transit fallback (#3285), and this does not change Matched /
	// HostInboundUnmatched. The classifier reads the SAME structured host-inbound
	// SSOT the kernel-nft builder renders from (config.HostInboundServiceMatch /
	// HostInboundProtocolMatch), so the reported token cannot drift from the port
	// the kernel actually opens.
	HostInbound *dpuserspace.HostInboundAdmission

	// RouteDropBeforePolicy is true when the query's DESTINATION address is a
	// class the transit forwarding path drops at ROUTE LOOKUP, before the
	// security-policy engine ever runs (#4373 E4/H2/H7): IPv4/IPv6 multicast,
	// the IPv4 limited broadcast 255.255.255.255, the unspecified address, or a
	// loopback address. For such a destination the dataplane has no forwarding
	// route to reach policy evaluation, so the permit/deny verdict this Result
	// carries does NOT describe what happens to real traffic — the packet is
	// dropped at route regardless of any policy that "matches". A firewall
	// filter `then accept; then log` for the same tuple likewise logs an ACCEPT
	// the packet never survives (the E4 "filter-accept log but the flow is
	// dropped at route" confusion). This is ADVISORY context, exactly like
	// HostInbound: it does NOT change Matched / Action / DefaultUsed. Every
	// operator surface (CLI show, `test policy`, REST) must surface RouteDropNote
	// so a simulator verdict cannot over-promise forwarding for a
	// non-transit-routable destination. Only a TRANSIT query is annotated; a
	// `to-zone junos-host` query takes the local-delivery gate, not the transit
	// route lookup, so it is never stamped. The route-drop itself is enforced in
	// userspace-dp; a dataplane NoRoute/martian drop COUNTER (so a live filter-
	// accept log has a matching visible drop) is the deferred Rust half of the
	// same remedy.
	RouteDropBeforePolicy bool
	// RouteDropClass names the destination address class ("multicast",
	// "broadcast", "unspecified", or "loopback") when RouteDropBeforePolicy is
	// set; empty otherwise. It feeds RouteDropNote so the operator sees WHICH
	// class triggered the route-drop advisory.
	RouteDropClass string

	// FragmentAssociatedDeny is true when this verdict is a #5572 non-first
	// fragment whose PERMIT (matched or default) was OVERRIDDEN to the DENY it
	// skipped, reproducing the dataplane's #4569 fragment-associated deny. When
	// set, the Result is attributed to the enforcing policy's IDENTITY (PolicyName
	// / PolicyID / RuleID name the shadowing rule) and Matched is true, but Action
	// is ALWAYS config.PolicyDeny — never reject, even when the skipped rule is a
	// `reject`. A non-first fragment has no L4 header, so the dataplane cannot send
	// a RST/ICMP: it can only silently DROP, and the Rust
	// frag_associated_deny_result hardcodes PolicyAction::Deny to match (see
	// fragDenyResult). It is set ONLY for a Query with NonFirstFragment == true
	// whose walk would otherwise have permitted — the TRANSIT walk, or (since
	// #6576, mirroring #6465/#6505) the junos-host walk, whose permit-like
	// unmatched fall-through counts as a permit here; a fragment that a real
	// (protocol-only / `any`) deny matched directly, or that permits with no
	// overlapping skipped deny, does not carry it. Callers surface FragmentDenyNote
	// so an operator reads WHY the fragment is denied (the security-over-
	// availability over-drop) rather than mistaking it for a first-fragment deny.
	FragmentAssociatedDeny bool
}

// FragmentDenyNotePrefix is the stable leading token of the fragment-associated
// deny advisory (#5572), an SSOT so every match-policies surface shares one
// wording and cannot drift. A caller renders FragmentDenyNote(), never a
// hand-built string. Mirrors the RouteDropNotePrefix pattern.
const FragmentDenyNotePrefix = "fragment-associated deny advisory:"

// FragmentDenyNote returns the operator-facing advisory for a Result whose
// PERMIT was overridden to a #4569 fragment-associated deny (#5572), or "" when
// the Result carries no such override. It states plainly that the verdict is a
// non-first fragment inheriting an overlapping port-bearing deny — the Junos
// security-over-availability default — so an operator does not read the deny as a
// first-fragment / exact-port match, and understands a plain L4 packet on the
// same tuple may instead permit. Like RouteDropNote it is ADVISORY (it does not
// alter the verdict) and mirrors that SSOT pattern so the surfaces stay in
// lock-step.
func (r Result) FragmentDenyNote() string {
	if !r.FragmentAssociatedDeny {
		return ""
	}
	return fmt.Sprintf("%s this is a NON-FIRST IP fragment (no L4 header, no ports); "+
		"it is denied because it overlaps port-bearing deny policy %q, which the first "+
		"fragment's real ports WOULD hit — Junos associates a non-first fragment with the "+
		"first fragment's deny (a security-over-availability over-drop). A plain L4 packet "+
		"on the same addresses/protocol may instead be permitted by a later rule.",
		FragmentDenyNotePrefix, r.PolicyName)
}

// RouteDropNotePrefix is the stable leading token of the route-drop advisory
// (#4373), kept as an SSOT so every match-policies surface (CLI show, `test
// policy`, REST) and its tests share one wording and cannot drift. A caller
// renders RouteDropNote(), never a hand-built string.
const RouteDropNotePrefix = "route-drop advisory:"

// RouteDropNote returns the operator-facing advisory line for a Result whose
// destination address is dropped at route lookup before policy evaluation
// (#4373 E4/H2/H7), or "" when the Result carries no route-drop condition. The
// line states plainly that the verdict does not describe real forwarding, so an
// operator does not read a permit/deny for a multicast/broadcast/unspecified/
// loopback destination as if the flow is actually forwarded. It is ADVISORY —
// it does not alter the verdict — and mirrors the HostInboundShowLine /
// ContentRejectedShowLine SSOT pattern so the surfaces stay in lock-step.
func (r Result) RouteDropNote() string {
	if !r.RouteDropBeforePolicy {
		return ""
	}
	class := r.RouteDropClass
	if class == "" {
		class = "non-routable"
	}
	return fmt.Sprintf("%s destination is %s — transit traffic to this address is "+
		"dropped at route lookup BEFORE security-policy evaluation, so this verdict "+
		"does not describe real forwarding (the packet is dropped at route regardless "+
		"of the matching policy / filter-accept log)", RouteDropNotePrefix, class)
}

// routeDropClass classifies a query DESTINATION address into the transit
// forwarding class that is dropped at route lookup before policy evaluation
// (#4373 E4/H2/H7), or "" for an ordinary unicast destination that reaches the
// policy engine. Multicast (IPv4 224.0.0.0/4, IPv6 ff00::/8), the IPv4 limited
// broadcast 255.255.255.255, the unspecified address (0.0.0.0 / ::), and
// loopback (127.0.0.0/8 / ::1) are all destinations the transit forwarding path
// has no route to hand to policy. A nil dst (the "unspecified destination"
// simulator wildcard) is NOT classified: it means the operator did not pin a
// destination, not that the destination is 0.0.0.0.
func routeDropClass(dst net.IP) string {
	if dst == nil {
		return ""
	}
	switch {
	case dst.IsMulticast():
		return "multicast"
	case dst.Equal(net.IPv4bcast):
		return "broadcast"
	case dst.IsUnspecified():
		return "unspecified"
	case dst.IsLoopback():
		return "loopback"
	default:
		return ""
	}
}

// HostInboundActionString is the operator-facing verdict rendered for a
// HostInboundUnmatched result (#3285/#3375/#3627). The dataplane host gate
// returns None for an unmatched `to-zone junos-host` flow — no security policy
// governs it. Local delivery is instead gated by host-inbound-traffic
// system-services/protocols, which post-#3405 DEFAULT-DENIES a zone with no
// host-inbound-traffic stanza; the verdict must therefore NOT claim that
// delivery unconditionally proceeds (the pre-#3627 "local delivery proceeds"
// wording read as an admit even for a no-stanza default-deny zone). Both the
// REST and gRPC match-policies surfaces render this exact string (via
// DisplayAction) so a remote client never sees a blank verdict for the host
// path and the two transports never diverge.
const HostInboundActionString = "host-inbound (local delivery subject to host-inbound-traffic service admission — a zone with no host-inbound-traffic stanza denies by default; transit/global/default policy NOT applied)"

// HostInboundShowLine is the human-readable one-line explanation the CLI /
// `show` / `request` match-policies surfaces print (after a "No matching
// to-zone junos-host policy ..." header) for a HostInboundUnmatched result.
// Kept here as the SSOT so the three CLI/gRPC-show call sites cannot drift from
// each other or from HostInboundActionString (#3627). Like the action string it
// states that local delivery is gated by host-inbound-traffic admission
// (default-deny for a no-stanza zone), not that it unconditionally proceeds.
// UnzonedIngressActionString is the operator-facing verdict rendered for a
// query whose FROM zone is not a known zone (#8318). The runtime denies such a
// flow unconditionally (#6682) instead of consulting default-policy, so this
// must NOT render as "deny (default)" — on a permit-all box that would name the
// operator's default as the cause of a deny it did not produce.
const UnzonedIngressActionString = "deny (ingress zone unknown — transit on an interface in no zone is denied unconditionally; default-policy NOT applied)"

// UnzonedIngressShowLine is the human-readable one-line explanation the CLI /
// `show` / `request` match-policies surfaces print after an "Ingress zone
// unknown ..." header, kept here as the SSOT for the same reason
// HostInboundShowLine is.
const UnzonedIngressShowLine = "unzoned ingress: an interface in no zone resolves to the reserved zone id 0, which is ineligible for zone-pair, wildcard and junos-global policies; the dataplane denies rather than falling through to default-policy (#6682)"

const HostInboundShowLine = "host-inbound: local delivery subject to host-inbound-traffic service admission (a zone with no host-inbound-traffic stanza denies by default; transit global/default-policy NOT applied)"

// ContentRejectedActionString is the operator-facing verdict rendered for a
// ContentRejected result (#3727) — the simulated config names application
// content (an unexpandable application-set) the userspace snapshot builder fails
// the WHOLE snapshot closed on. The runtime raises SnapshotIntegrityError and
// retains its previous-good snapshot (or fresh-boots default-deny), so no
// permit/deny/default verdict this config's policies would produce is actually
// enforced. The string must report that fail-closed retention rather than a
// fabricated answer. Rendered by DisplayAction so the REST and gRPC transports
// (which route the verdict through DisplayAction) cannot diverge or emit a
// misleading permit/deny for a config the dataplane never applies.
const ContentRejectedActionString = "policy content rejected by dataplane (fail-closed): the userspace helper cannot represent this config (see reasons), so it retains its previous-good snapshot or fresh-boots default-deny — no simulated permit/deny/default verdict is enforced"

// ContentRejectedShowLine is the human-readable one-line explanation the CLI /
// `show` / `request` match-policies surfaces print for a ContentRejected result
// (#3727), kept here as the SSOT so the CLI/gRPC-show call sites cannot drift
// from each other or from ContentRejectedActionString (mirrors HostInboundShowLine).
const ContentRejectedShowLine = "policy content rejected: the dataplane fails this config closed (retains previous-good snapshot / fresh-boots default-deny) and enforces none of its policies — the offending application content is listed below"

// DisplayAction renders the single operator-facing verdict string for a Result,
// shared by every match-policies surface (#3375) so the REST and gRPC
// transports cannot diverge. Before #3375 gRPC returned a BLANK action for the
// host-inbound and default-deny verdicts while REST returned explicit strings;
// routing both surfaces through this method keeps them in lockstep.
//
//   - ContentRejected -> ContentRejectedActionString (#3727)
//   - HostInboundUnmatched -> HostInboundActionString
//   - no match (default-policy verdict) -> "<action> (default)"
//   - concrete policy match -> "<action>"
func (r Result) DisplayAction() string {
	switch {
	case r.UnsupportedTupleFamily:
		return UnsupportedTupleFamilyActionString
	case r.ContentRejected:
		return ContentRejectedActionString
	case r.HostInboundUnmatched:
		return HostInboundActionString
	case r.UnzonedIngress:
		return UnzonedIngressActionString
	case !r.Matched:
		return ActionString(r.Action) + " (default)"
	default:
		return ActionString(r.Action)
	}
}

// UnsupportedTupleFamilyActionString is the operator-facing verdict rendered
// for a query whose source is IPv4 and destination is IPv6 (codex-182
// A10-b02-C1). NAT46 is not supported, so no forwarding path ever produces this
// tuple and the runtime matcher fails it closed; the simulator reports that
// rather than a fabricated per-side verdict.
const UnsupportedTupleFamilyActionString = "unsupported tuple: an IPv4 source with an IPv6 destination has no supported translation (NAT46 is not implemented), so the forwarding path never produces it and the runtime matcher fails closed — no simulated permit/deny/default verdict applies"

// queryTupleFamily resolves the address family ("v4"/"v6"/"") of one side of a
// query for the unsupported-tuple gate. It prefers the colon-strict text hint
// (fam), which the caller derived from the RAW operator string via
// config.NATAddrFamily before net.ParseIP folded an IPv4-mapped IPv6 literal
// (#6377). When no hint is supplied (fam == "" — the net.IP-only callers, e.g.
// tests), it falls back to the To4() heuristic, which FOLDS a mapped literal to
// v4 (the pre-#6377 behavior). A nil ip with no hint is "" (unspecified). The
// gate only fires on a resolved ("v4","v6"), so a "" from either source is
// simply never the (v4,v6) shape.
func queryTupleFamily(ip net.IP, fam string) string {
	switch fam {
	case "v4", "v6":
		return fam
	}
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return "v4"
	}
	return "v6"
}

// Match runs the simulator against the active config and returns the verdict
// with the SAME precedence the runtime enforces (userspace-dp/src/policy.rs
// evaluate_policy_result_with_icmp / try_match_rule), first-match terminating:
//
//  1. exact zone-pair (both zones concrete)
//  2. single-wildcard tier — `from-zone any to-zone <X>` and
//     `from-zone <X> to-zone any`, MERGED in config order (#3090)
//  3. both-any — `from-zone any to-zone any` (#3090)
//  4. global (`junos-global`), gated by the optional `match from-zone` /
//     `match to-zone` scope (#3148); an empty/`any` scope applies to every
//     zone, an undefined-zone scope fails closed (matches nothing)
//  5. configured default-policy
//
// A `to-zone junos-host` query is host-bound and takes the separate host-gate
// path (matchJunosHost, #3285): exact ingress->junos-host then
// `from-zone any`->junos-host, with NO global/default transit fallback.
func Match(cfg *config.Config, q Query) (res Result) {
	// codex-182 A10-b02-C1: an IPv4 source with an IPv6 destination is a tuple
	// the forwarding path never produces — NAT46 is unsupported, so no inbound
	// translation yields a v4 source with a v6 destination — and the runtime
	// matcher fails it closed (userspace-dp/src/policy.rs try_match_rule rejects
	// the (V4 src, V6 dst) arm). matchAddr evaluates the two address sides
	// INDEPENDENTLY below, so without this gate the simulator could return a
	// concrete permit/deny/default verdict for a packet shape the runtime can
	// never see. Reject it up front — this single shared entry point serves
	// every transport (CLI, REST, gRPC MatchPolicies), so the fix covers all
	// three. Both sides must be specified; the reverse (V6 src, V4 dst) NAT64
	// arm and every same-family tuple fall through unchanged.
	//
	// Family is COLON-STRICT (#6377): each side is resolved by queryTupleFamily,
	// which prefers the caller's q.SrcFamily/q.DstFamily text hint (derived from
	// the RAW operator string via config.NATAddrFamily before net.ParseIP folded
	// it) and falls back to To4() only when no hint is supplied. This closes the
	// #5720 fold: net.ParseIP("::ffff:192.0.2.1").To4() is NON-nil, so before
	// #6377 a source authored as the IPv4-mapped literal `::ffff:192.0.2.1` was
	// classified V4 here and `::ffff:192.0.2.1 -> 2001:db8::1` was FALSELY flagged
	// an unsupported (V4 src, V6 dst) tuple, diverging from the colon-strict
	// runtime matcher (userspace-dp/src/policy.rs) that sees a same-family V6/V6
	// tuple. All FIVE Query builders (cli_request_testcmd.go, cli_show_
	// security.go, server_show_firewall.go, server_cluster.go, api/security.go)
	// now thread the text family, so the mapped source yields "v6" and falls
	// through to normal evaluation. This is the same Go/Rust family-parity
	// convention the NAT compile gate uses (config.NATAddrFamily / natAddrFamily
	// in pkg/config/compiler_nat_helpers.go: family keyed on the presence of a
	// ':' in the ORIGINAL text). A net.IP-only caller that supplies no hint keeps
	// the pre-#6377 To4() behavior for that side.
	if q.SrcIP != nil && q.DstIP != nil &&
		queryTupleFamily(q.SrcIP, q.SrcFamily) == "v4" &&
		queryTupleFamily(q.DstIP, q.DstFamily) == "v6" {
		return Result{UnsupportedTupleFamily: true, Action: config.PolicyDeny}
	}
	// #4373 (E4/H2/H7): a TRANSIT destination that is multicast / broadcast /
	// unspecified / loopback is dropped by the forwarding path at ROUTE LOOKUP,
	// before the policy engine runs, so any permit/deny verdict below (and a
	// firewall `then accept; then log` for the same tuple) over-promises
	// forwarding the dataplane never performs. Classify the destination up front
	// and stamp the advisory onto whatever Result the tier chain returns via a
	// defer, so EVERY return path (default, matched, content-rejected) carries it
	// without threading the flag through each construction. Host-bound
	// (junos-host) queries take the local-delivery gate, not transit route
	// lookup, so they are exempt — matchJunosHost never sees this stamp.
	if q.ToZone != JunosHostZone {
		if class := routeDropClass(q.DstIP); class != "" {
			defer func() {
				res.RouteDropBeforePolicy = true
				res.RouteDropClass = class
			}()
		}
	}
	if cfg == nil {
		return Result{DefaultUsed: true, Action: config.PolicyDeny}
	}

	// #3727/#4394: the runtime snapshot builder fails the WHOLE snapshot closed
	// when any policy references content the userspace matcher cannot represent —
	// an unexpandable application-set (#3727), a protocol-less application, an
	// unrepresentable protocol/port, an undefined application reference, or an
	// unresolvable address (#4394). In every such case the builder poisons the
	// rule with the reserved __unsupported__ / __unsupported_address__ sentinel
	// (or the app-catalog build errors), which the helper integrity preflight
	// rejects (SnapshotIntegrityError), so the dataplane retains its
	// previous-good snapshot or fresh-boots default-deny and enforces NONE of
	// this config. matchApp/matchAddr used to SILENTLY SKIP the unrepresentable
	// term (a per-term no-match) and fall through to a later rule / default-policy,
	// so the simulator reported a permit/deny/default verdict the dataplane never
	// certifies — under a default-permit it under-reported a fail-closed config as
	// PERMIT. Detect the same fail-closed set up front, config-wide (the shared
	// dpuserspace.PolicyContentRejectionReasons SSOT, feed-aware via q.FeedOverlay),
	// BEFORE any per-tier / host-gate evaluation, so every query for the config
	// reports the runtime's retention rather than a fabricated answer.
	if reasons := policyContentRejectionReasons(cfg, q.FeedOverlay); len(reasons) > 0 {
		return Result{ContentRejected: true, ContentRejectionReasons: reasons, Action: config.PolicyDeny}
	}

	// #3331: resolve the stable runtime policy-ID namespace once, up front, so a
	// match can stamp Result.PolicyID. This is the SAME SSOT the dataplane write
	// side and the `show policies` Index column use (RuntimePolicyIDs ->
	// walkPolicyRuleSlots), keyed by [policySetID, sliceIndex] — the exact
	// (set index, slice index) coordinates the tier loops below already iterate.
	ids := dpuserspace.RuntimePolicyIDs(cfg)

	// #3285: host-bound (LocalDelivery) traffic is governed by the dataplane's
	// host gate, which does NOT apply transit global/default fallback. Branch
	// before the transit tiers so that invariant cannot regress.
	if q.ToZone == JunosHostZone {
		return matchJunosHost(cfg, q, ids)
	}

	// #3355: the runtime gates the ENTIRE transit block — exact zone-pair, the
	// #3090 from-any/to-any/both-any wildcard tiers, AND the #3148 global tier —
	// on `from_id != 0 && to_id != 0` (policy.rs evaluate_policy_result_with_icmp).
	// Zone id 0 is the reserved "unknown / no zone" sentinel an unconfigured
	// zone name resolves to; a flow whose ingress OR egress zone is unknown
	// belongs to no DEFINED zone pair and is ineligible for zone-pair, wildcard,
	// or junos-global policies. A query naming an UNDEFINED zone is the simulator
	// analogue of id 0, so it must fall straight through to the configured
	// default-policy rather than wrongly matching a `from-zone any` / `to-zone
	// any` / global rule.
	// #8318: the two sides are NOT symmetric at the terminal action, and this
	// branch used to collapse them. Eligibility IS symmetric — that is what the
	// paragraph above describes, and it is unchanged: an unknown zone on either
	// side is excluded from the zone-pair, wildcard and global tiers, exactly as
	// the runtime's `from_id != 0 && to_id != 0` gate does. What differs is what
	// happens AFTER that exclusion.
	//
	// The runtime denies an unzoned INGRESS unconditionally (#6682,
	// policy.rs `if from_id == 0`), without consulting default-policy: Junos does
	// not pass transit on an interface that is in no zone, and screens were
	// already skipped for it. It deliberately does NOT do the same for the
	// EGRESS side — its comment says denying on `to_id` "would risk
	// black-holing a correctly-configured path to fix a case that has not been
	// shown to occur. It still falls through to the default below" (#6713 is the
	// cited precedent: a MAC-less xfrmi egress resolving to 0 for an unrelated
	// reason).
	//
	// Collapsing both into `DefaultUsed: true` agreed with the runtime only
	// because `deny-all` is the default default-policy, so both sides denied and
	// the divergence was invisible. Under `permit-all` the simulator said PERMIT
	// where the dataplane drops — on the surface an operator uses to VERIFY
	// policy before trusting it, which is the worst place for it: they conclude
	// the policy is right and look elsewhere.
	if !zoneKnown(cfg, q.FromZone) {
		// DefaultUsed is deliberately FALSE: its own contract is "Action is the
		// configured default-policy", and this Deny is not — it overrides the
		// default. Reporting true here would tell an operator on a permit-all
		// box that their default produced a deny.
		return Result{UnzonedIngress: true, Action: config.PolicyDeny}
	}
	if !zoneKnown(cfg, q.ToZone) {
		return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
	}

	// #5572: while walking the transit tiers in first-match precedence order,
	// remember the FIRST port-bearing DENY/REJECT a non-first fragment SKIPPED
	// (overlapping L3, L4-constrained term inapplicable), mirroring the
	// dataplane's #4569 note_skipped_frag_deny. `matchOr` then reproduces
	// apply_frag_deny_override: a matched PERMIT with an earlier skipped
	// overlapping deny is OVERRIDDEN to that deny. For a normal (L4-present)
	// query q.NonFirstFragment is false, so both are inert and the walk is
	// byte-identical to before.
	//
	// #6576: the machinery now lives on the shared fragDenyTracker so the host
	// walk (matchJunosHost) uses the SAME implementation instead of silently
	// lacking one.
	frag := newFragDenyTracker(cfg, q, ids)
	noteFrag := frag.note
	matchOr := frag.override

	// Tier 1: exact zone-pair policies, in config order (first match wins).
	// q.FromZone/q.ToZone are concrete zone names; a wildcard set
	// (FromZone/ToZone == "any") never compares equal, so it is excluded here.
	for setIdx, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != q.FromZone || zpp.ToZone != q.ToZone {
			continue
		}
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if ruleMatches(cfg, q, pol) {
				return matchOr(matchedResult(ids, pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx))
			}
			noteFrag(pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)
		}
	}

	// Tier 2: single-wildcard tier (#3090) — `from-zone any to-zone <q.ToZone>`
	// OR `from-zone <q.FromZone> to-zone any`, MERGED in config order. The
	// dataplane two-pointer-merges its from_any/to_any index buckets by global
	// rule index; the snapshot builder (walkPolicyRuleSlots) emits rules in
	// cfg.Security.Policies slice order with each set's policies contiguous, so
	// a single in-order pass over the sets reproduces that merge exactly.
	for setIdx, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		fromAny := zpp.FromZone == "any"
		toAny := zpp.ToZone == "any"
		if fromAny == toAny {
			continue // both-any (Tier 3) or neither (Tier 1) — not single-wildcard
		}
		applies := (fromAny && zpp.ToZone == q.ToZone) || (toAny && zpp.FromZone == q.FromZone)
		if !applies {
			continue
		}
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if ruleMatches(cfg, q, pol) {
				return matchOr(matchedResult(ids, pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx))
			}
			noteFrag(pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)
		}
	}

	// Tier 3: both-any (`from-zone any to-zone any`), in config order.
	for setIdx, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.FromZone != "any" || zpp.ToZone != "any" {
			continue
		}
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if ruleMatches(cfg, q, pol) {
				return matchOr(matchedResult(ids, pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx))
			}
			noteFrag(pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)
		}
	}

	// Tier 4: global policies (junos-global), in config order, gated by the
	// optional #3148 from-zone/to-zone match scope. The runtime policy-ID
	// namespace places global policies in the policy set that immediately
	// follows the last zone-pair set (walkPolicyRuleSlots), i.e. policySetID ==
	// len(cfg.Security.Policies); use that as the RuntimePolicyIDs lookup key.
	globalSetIdx := len(cfg.Security.Policies)
	for sliceIdx, pol := range cfg.Security.GlobalPolicies {
		if pol == nil {
			continue
		}
		if !globalScopeSetMatches(cfg, pol.Match.FromZones, q.FromZone) ||
			!globalScopeSetMatches(cfg, pol.Match.ToZones, q.ToZone) {
			continue
		}
		// A global policy's scope is its `match from-zone`/`match to-zone` SET
		// (empty = all zones), NOT the surrounding stanza. Report the CONCRETE
		// flow zone the packet traversed (or "" for a wildcard side, rendered
		// "any") so a multi-zone scope keeps a single concrete zone per column —
		// never a joined label (#3331/#3148/#4626 A10).
		gFrom := reportedScopeZone(pol.Match.FromZones, q.FromZone)
		gTo := reportedScopeZone(pol.Match.ToZones, q.ToZone)
		if ruleMatches(cfg, q, pol) {
			return matchOr(matchedResult(ids, pol, true, gFrom, gTo, globalSetIdx, sliceIdx))
		}
		noteFrag(pol, true, gFrom, gTo, globalSetIdx, sliceIdx)
	}

	// Tier 5: configured default-policy (NOT a hard-coded deny).
	//
	// #5572: a flowless fragment that reaches the implicit default still fails
	// closed against an overlapping port-bearing DENY it skipped when the default
	// is PERMIT — mirroring the dataplane's post-walk #4569 override. A
	// default-DENY/REJECT already drops, so the override only matters for
	// default-permit; when no deny was skipped this is inert.
	if cfg.Security.DefaultPolicy == config.PolicyPermit {
		return frag.overridePermissiveTerminal(Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy})
	}
	return Result{DefaultUsed: true, Action: cfg.Security.DefaultPolicy}
}

// matchJunosHost mirrors the dataplane host gate evaluate_junos_host_policy
// (policy.rs) for a `to-zone junos-host` query (#3285). It consults, in Junos
// most-specific-first order: exact `from-zone <ingress> to-zone junos-host`
// rules, then the `from-zone any to-zone junos-host` wildcard, then a GLOBAL
// policy `match to-zone junos-host` (#3639 / #3611 Piece B). There is NO
// implicit host default-deny and NO transit-default fallback: an unmatched
// host-bound flow falls through to local delivery (the management lifeline
// guarantee), so the simulator returns HostInboundUnmatched rather than
// inheriting the transit default verdict. `to-zone any` and `from-zone any
// to-zone any` transit wildcards are deliberately NOT pulled onto the host
// path, matching the runtime gate — only a global explicitly scoped to
// `to-zone junos-host` is consulted.
func matchJunosHost(cfg *config.Config, q Query, ids map[[2]uint32]uint32) Result {
	// #3627 B1a: classify the ingress zone's host-inbound-traffic admission for
	// this tuple ONCE and attach it to every Result this host path returns, so a
	// host-inbound verdict names the admitting service/protocol token (or reports
	// deny / global-accept / indeterminate) rather than the fixed
	// "subject to host-inbound-traffic" string. This is additional context, not a
	// verdict tier — it never changes the match outcome (#3285 host gate has no
	// transit fallback).
	hi := hostInboundAdmission(cfg, q)
	withHI := func(r Result) Result {
		r.HostInbound = hi
		return r
	}

	// #3355: evaluate_junos_host_policy returns None for from_id == 0 (the
	// unknown/undefined ingress zone), mirroring the #3110 unzoned guard. An
	// undefined query from-zone therefore matches no host-bound rule; local
	// delivery proceeds (the management lifeline), so surface
	// HostInboundUnmatched rather than running the host tiers against an
	// unresolved ingress zone.
	if !zoneKnown(cfg, q.FromZone) {
		return withHI(Result{HostInboundUnmatched: true})
	}

	// #6576: track a port-bearing DENY/REJECT this walk SKIPS because a
	// non-first fragment carries no L4 header, exactly as the transit walk
	// does — the host gate learned this in #6465 (policy.rs) and the Go mirror
	// did not follow.
	frag := newFragDenyTracker(cfg, q, ids)

	// Exact ingress -> junos-host.
	for setIdx, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != JunosHostZone || zpp.FromZone != q.FromZone {
			continue
		}
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if ruleMatches(cfg, q, pol) {
				return withHI(frag.override(matchedResult(ids, pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)))
			}
			frag.note(pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)
		}
	}
	// from-zone any -> junos-host.
	for setIdx, zpp := range cfg.Security.Policies {
		if zpp == nil || zpp.ToZone != JunosHostZone || zpp.FromZone != "any" {
			continue
		}
		for sliceIdx, pol := range zpp.Policies {
			if pol == nil {
				continue
			}
			if ruleMatches(cfg, q, pol) {
				return withHI(frag.override(matchedResult(ids, pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)))
			}
			frag.note(pol, false, zpp.FromZone, zpp.ToZone, setIdx, sliceIdx)
		}
	}
	// #3639 / #3611 Piece B: a GLOBAL policy `match to-zone junos-host`
	// (host-INBOUND) governs host-bound traffic in the GLOBAL tier — consulted
	// LAST, after the exact `from-zone <ingress> to-zone junos-host` pair and
	// the `from-zone any to-zone junos-host` wildcard, mirroring the dataplane
	// (evaluate_junos_host_policy_l3_aware) and transit-policy precedence (a
	// global policy is least-specific and never jumps ahead of a zone-pair
	// rule). The optional `match from-zone` scope still restricts by ingress
	// zone (empty / "any" = every zone). We select on IsHostToZoneScope
	// (ToZones == ["junos-host"]) directly rather than globalScopeSetMatches
	// because junos-host is not a defined zone in cfg.Security.Zones
	// (globalScopeSetMatches would fail it closed). A `match
	// from-zone junos-host` global (host-ORIGINATED) is rejected at commit and
	// never reaches this host-inbound path (#3611 Piece A).
	globalSetIdx := len(cfg.Security.Policies)
	for sliceIdx, pol := range cfg.Security.GlobalPolicies {
		if pol == nil || !config.IsHostToZoneScope(pol.Match.ToZones) {
			continue
		}
		if !globalScopeSetMatches(cfg, pol.Match.FromZones, q.FromZone) {
			continue
		}
		gFrom := reportedScopeZone(pol.Match.FromZones, q.FromZone)
		gTo := reportedScopeZone(pol.Match.ToZones, q.ToZone)
		if ruleMatches(cfg, q, pol) {
			return withHI(frag.override(matchedResult(ids, pol, true, gFrom, gTo, globalSetIdx, sliceIdx)))
		}
		frag.note(pol, true, gFrom, gTo, globalSetIdx, sliceIdx)
	}
	// No host-bound rule matched: local delivery proceeds. Do NOT fall through
	// to the transit default — the dataplane host gate returns None here.
	//
	// #6576: that delivery is PERMIT-LIKE, so a non-first fragment that skipped
	// an overlapping port-bearing DENY fails closed against it instead —
	// mirroring the #6465 post-walk arm in evaluate_junos_host_policy. Inert
	// for an ordinary L4 query, which never records a candidate, so the
	// management lifeline is unchanged.
	return withHI(frag.overridePermissiveTerminal(Result{HostInboundUnmatched: true}))
}

// hostInboundAdmission classifies the ingress zone's host-inbound-traffic
// admission for a host-bound query tuple (#3627 B1a). It resolves the query's
// protocol via appid.ProtocolNumber (empty = unspecified) and the address family
// from the destination (then source) IP, and delegates to the SSOT-backed
// dataplane/userspace classifier. Returns nil for a nil config.
//
// #6377: the family is COLON-STRICT — ipFamilyStrict prefers the caller's
// DstFamily/SrcFamily hint, so a mapped-v6 host-inbound destination (e.g. a
// DHCPv6 flow to the firewall authored as ::ffff:...) is classified ip6, not
// folded to ip by To4(). A family-scoped token (dhcpv6=ip6, dhcp=ip; ping's
// ICMP vs ICMPv6 type) would otherwise be mis-admitted in the simulator.
func hostInboundAdmission(cfg *config.Config, q Query) *dpuserspace.HostInboundAdmission {
	if cfg == nil {
		return nil
	}
	proto, hasProto := appid.ProtocolNumber(q.Protocol)
	family := ""
	switch {
	case q.DstIP != nil:
		family = ipFamilyStrict(q.DstIP, q.DstFamily)
	case q.SrcIP != nil:
		family = ipFamilyStrict(q.SrcIP, q.SrcFamily)
	}
	// #5579: when the query names an ingress interface, scope the host-inbound
	// classification to THAT interface's effective view (admit vs deny for the
	// interface, not a zone-wide first-admit fold). The ref is validated against
	// the config at the operator surface before the Query is built. Without the
	// selector, the zone-scoped classifier reports HostInboundAmbiguous if the
	// zone's per-interface views disagree.
	if q.IngressInterface != "" {
		adm := dpuserspace.ClassifyHostInboundForInterface(cfg, q.FromZone, q.IngressInterface, proto, hasProto, q.DstPort, q.ICMPType, family)
		return &adm
	}
	adm := dpuserspace.ClassifyHostInbound(cfg, q.FromZone, proto, hasProto, q.DstPort, q.ICMPType, family)
	return &adm
}

// ipFamily returns the nft-style family token ("ip" / "ip6") for an IP, matching
// the family spelling the host-inbound SSOT and views use.
func ipFamily(ip net.IP) string {
	if ip.To4() != nil {
		return "ip"
	}
	return "ip6"
}

// ipFamilyStrict returns the nft-style family token ("ip" / "ip6") but keys on
// the colon-strict family hint (fam, "v4"/"v6"/"") when present, so an
// IPv4-mapped IPv6 literal is classified ip6 rather than folded to ip by To4()
// (#6377). With no hint (fam == "" — net.IP-only callers) it is byte-identical
// to ipFamily. The caller invokes this only for a non-nil ip, so
// queryTupleFamily always resolves to "v4"/"v6" here.
func ipFamilyStrict(ip net.IP, fam string) string {
	if queryTupleFamily(ip, fam) == "v4" {
		return "ip"
	}
	return "ip6"
}

// GlobalPolicyAppliesToZonePair reports whether a global policy (#3148) with the
// given match-scope zones is selected by a `from-zone X to-zone Y` display
// filter (#3357). It governs which scoped/unscoped globals a FILTERED policy
// view shows. An empty filter axis selects every global on that axis. A global
// whose match-scope zone is empty or "any" spans every zone, so it always
// applies (it IS enforced for the filtered pair). A scoped global is selected
// only when its scope equals the filter on each constrained axis. The semantics
// mirror globalScopeSetMatches (an "any"/empty scope is all-zones) so the filtered
// view shows exactly the globals the runtime enforces for that zone pair.
func GlobalPolicyAppliesToZonePair(matchFrom, matchTo []string, filterFrom, filterTo string) bool {
	axisApplies := func(scope []string, filter string) bool {
		if filter == "" || config.IsWildcardZoneSet(scope) {
			return true
		}
		return slices.Contains(scope, filter)
	}
	return axisApplies(matchFrom, filterFrom) && axisApplies(matchTo, filterTo)
}

// globalScopeSetMatches replicates GlobalZoneScope::matches + build_global_zone_scope
// (policy.rs, #3148/#4626) for a zone SET scope. An empty scope or one that
// contains "any" (config.IsWildcardZoneSet) applies to every zone. Otherwise the
// flow's zone must equal some DEFINED element of the set; an undefined element
// (typo'd, or reserved like junos-host) contributes nothing — it never silently
// widens the scope to all-zones, matching the runtime fail-closed backstop.
func globalScopeSetMatches(cfg *config.Config, scope []string, flowZone string) bool {
	if config.IsWildcardZoneSet(scope) {
		return true
	}
	for _, z := range scope {
		if _, ok := cfg.Security.Zones[z]; !ok {
			continue // Unresolved element → contributes nothing
		}
		if z == flowZone {
			return true
		}
	}
	return false
}

// reportedScopeZone returns the single zone token for a scoped-global match's
// Result From/To column (#4626 A10). To stay bit-identical with the pre-#4626
// single-string model it reports the scope token VERBATIM for the 0-or-1-token
// cases — "" for an unscoped side (rendered "any"), the literal token for a
// single-element scope (a concrete zone, or explicit "any" preserved as "any").
// Only a genuinely MULTI-zone scope (which the single-string model could never
// express) reports the CONCRETE flow zone the packet traversed, so the column
// stays a single concrete zone rather than a joined scope label.
func reportedScopeZone(scope []string, flowZone string) string {
	switch len(scope) {
	case 0:
		return ""
	case 1:
		return scope[0]
	default:
		return flowZone
	}
}

// zoneKnown reports whether a query zone is DEFINED for the runtime's `id != 0`
// eligibility guard (#3355). The runtime resolves an unconfigured zone name to
// the reserved unknown id 0, which is ineligible for zone-pair / wildcard /
// global / junos-host policies (policy.rs evaluate_policy_result_with_icmp gates
// the whole transit block on from_id != 0 && to_id != 0; evaluate_junos_host_policy
// returns None for from_id == 0). A zone is "known" iff it is present in
// cfg.Security.Zones AND is not QUARANTINED (#5649, C181-C14/C20).
//
// This mirrors the runtime UNCONDITIONALLY — there is deliberately NO
// empty-Zones leniency. policy.rs applies the from_id/to_id != 0 gate for every
// evaluation; a config with no defined zones resolves every zone name to id 0,
// so the runtime matches NOTHING in the transit tiers. An earlier "offline
// tolerance" short-circuit (return true when Zones is empty) was simulator-vs-
// runtime DRIFT: a no-zones config matched transit tiers in the simulator that
// the runtime would never evaluate. A committed production config always
// populates Zones; a synthetic config without zones now faithfully matches
// nothing in transit.
//
// #5649 (C181-C14/C20): a lenient/HA-loaded config with a StableZoneID
// collision keeps compiling — the LATER-sorting zone name is QUARANTINED at
// snapshot build (config.QuarantinedZoneNames / zoneid.go) and dropped from
// the dataplane: its interfaces are unzoned (fail to id 0) and its policies
// are scrubbed. Before this fix, zoneKnown consulted only the raw typed
// cfg.Security.Zones map, which STILL contains the quarantined name (typed
// config carries the collision; only the built snapshot resolves it), so the
// simulator reported a quarantined zone as policy-matchable — telling an
// operator that a policy referencing the DROPPED zone permits or denies a
// flow, when the runtime never installed that zone at all. Projecting the
// same collision-quarantine result used by the wire builder keeps the
// simulator's "known" predicate honest about what the dataplane actually
// admitted.
func zoneKnown(cfg *config.Config, zone string) bool {
	if _, ok := cfg.Security.Zones[zone]; !ok {
		return false
	}
	if _, quarantined := quarantinedZoneNames(cfg)[zone]; quarantined {
		return false
	}
	return true
}

// quarantinedZoneNames computes the #3719 StableZoneID collision-quarantine
// set for cfg's configured zone names — the exact projection zoneKnown needs
// to treat a runtime-dropped zone as unknown (#5649, C181-C14/C20). This is a
// cold config-tool path (CLI/REST/gRPC `match-policies`, not per-packet), so
// recomputing the O(n log n) sort per zoneKnown call is not hot-path work; n
// is the configured zone count, typically tens of entries.
func quarantinedZoneNames(cfg *config.Config) map[string]struct{} {
	if len(cfg.Security.Zones) < 2 {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	return config.QuarantinedZoneNames(names)
}

// matchedResult builds the verdict for a concrete policy hit, stamping its zone
// scope (#3331) and the stable runtime policy ID resolved from the shared
// RuntimePolicyIDs namespace. setIdx/sliceIdx are the [policySetID, sliceIndex]
// coordinates of the policy in the typed config — the exact key RuntimePolicyIDs
// uses (a global policy's setIdx is len(cfg.Security.Policies)). A missing key
// (a config that overflows MaxRulesPerPolicy and so cannot be applied) yields
// PolicyID 0; the zone scope + name still disambiguate the verdict.
func matchedResult(ids map[[2]uint32]uint32, pol *config.Policy, global bool, fromZone, toZone string, setIdx, sliceIdx int) Result {
	// #3668: stamp the stable rule identity, mirroring the inventory EXACTLY. The
	// inventory keys a zone-pair rule under its surrounding stanza zones and a
	// GLOBAL rule under the reserved "junos-global"/"junos-global" pair
	// (pkg/api/security.go, pkg/grpcapi/server_show_zones.go). fromZone/toZone
	// here carry a global policy's optional match-SCOPE (empty = all zones), NOT
	// that reserved pair, so a global rule must use the junos-global identity to
	// join to the same inventory row.
	ridFrom, ridTo := fromZone, toZone
	if global {
		ridFrom, ridTo = "junos-global", "junos-global"
	}
	return Result{
		Matched:     true,
		Global:      global,
		FromZone:    fromZone,
		ToZone:      toZone,
		PolicyID:    ids[[2]uint32{uint32(setIdx), uint32(sliceIdx)}],
		RuleID:      dpuserspace.StablePolicyRuleID(ridFrom, ridTo, pol.Name),
		PolicyName:  pol.Name,
		Description: pol.Description,
		Action:      pol.Action,
		// #3685 M06: carry the scheduler binding so a match-policies verdict
		// names the time-gate controlling the rule, mirroring the inventory.
		SchedulerName:              pol.SchedulerName,
		SourceAddressExcluded:      pol.Match.SourceAddressExcluded,
		DestinationAddressExcluded: pol.Match.DestinationAddressExcluded,
		// #3358: a zone-local address book (#3061) is folded into the global
		// book under the synthetic key zone-local/<zone>/<name>, and
		// resolveZoneLocalAddressBooks already rewrote pol.Match.* to those
		// qualified tokens. Result.Src/DstAddresses are DISPLAY-ONLY — every
		// re-match path (ruleMatches/matchAddr/classifyPolicyAddresses/nameToID)
		// reads pol.Match directly, never the Result — so unqualifying the
		// authored name here (the SSOT for all three match-policies transports:
		// CLI, gRPC MatchPolicies, REST MatchPoliciesResult) cannot affect
		// matching. The from/to-zone in the verdict keeps the bare name
		// unambiguous. DisplayAddressNames returns a NEW slice (never mutates
		// the compiled config) and preserves nil.
		SrcAddresses: config.DisplayAddressNames(pol.Match.SourceAddresses),
		DstAddresses: config.DisplayAddressNames(pol.Match.DestinationAddresses),
		Applications: pol.Match.Applications,
	}
}

func ruleMatches(cfg *config.Config, q Query, pol *config.Policy) bool {
	// #3104: scheduler gate, FIRST — mirror policy.rs try_match_rule, which
	// returns None for a scheduler-inactive rule before any app/address
	// matching. Skipping here lets Match fall through to the next active rule
	// or the default-policy, exactly as the runtime does. PolicyInactiveFn is
	// nil when the caller has no live scheduler state (simulate as-if-active),
	// and reports an empty scheduler name as active, so a non-scheduled policy
	// is never skipped.
	if q.PolicyInactiveFn != nil && q.PolicyInactiveFn(pol.SchedulerName) {
		return false
	}
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded, q.SrcIP, q.SrcFamily) {
		return false
	}
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded, q.DstIP, q.DstFamily) {
		return false
	}
	// #5572: a non-first fragment is flowless (l4_present == false) — port-bearing
	// and ICMP-type-constrained application terms then fail closed, while
	// protocol-only / `any` terms still match on the L3 identity + known protocol
	// the fragment carries. The default (NonFirstFragment == false) passes
	// l4Present == true, so the existing L4 path is byte-identical.
	return matchApp(cfg, pol.Match.Applications, q.Protocol, q.SrcPort, q.DstPort, q.ICMPType, q.ICMPCode, !q.NonFirstFragment)
}

// matchAddr replicates policy.rs try_match_rule's per-side address logic
// EXACTLY (#3356). A nil ip (unspecified) does not constrain the match.
//
// The runtime computes, per side:
//
//	excluded:     !(v4_empty && v6_empty) && !(ip is in the set)
//	not excluded:  match_any || (ip is in the set)
//
// Two faithfulness fixes over the pre-#3356 simulator:
//
//   - The empty-address-list "match any" short-circuit must NOT run before the
//     exclusion check. An empty-but-EXCLUDED set ([] with excluded=true) is the
//     genuine typo/parse-drop signal #2008 fails CLOSED on: the runtime sees
//     v4_empty && v6_empty and yields false. Returning match-any first made the
//     simulator fail OPEN — it reported a match no dataplane packet would get.
//     The "no constraint = match any" convenience now applies only to the
//     NON-excluded empty list.
//
//   - The excluded fail-closed gate keys on BOTH families being empty, not on
//     the packet's own family. The runtime fails closed only when
//     v4_empty && v6_empty (policy.rs ~2095-2106). A v6-only exclusion set on a
//     v4 packet (#3023 cross-family) leaves v4_empty true but v6_empty false:
//     the v4 address is then trivially NOT in the (v6-only) excluded set, so the
//     side MATCHES. The old per-packet-family `contributesFamily` gate failed
//     closed there and over-blocked legitimate cross-family traffic.
//
// The packet's family is COLON-STRICT (#6377): it is resolved by
// queryTupleFamily from the caller's family hint ("v4"/"v6"/"", derived from the
// RAW operator text via config.NATAddrFamily), falling back to ip.To4() only
// when no hint is supplied (net.IP-only callers, e.g. tests). This matters
// because net.ParseIP("::ffff:192.0.2.1").To4() FOLDS an IPv4-mapped IPv6 source
// to a v4-looking value: without the hint the mapped source would be matched
// against the V4 address rules and could fabricate a PERMIT the runtime never
// produces (the colon-strict Rust matcher, userspace-dp/src/policy.rs, sees a V6
// address and evaluates it against the V6 rules). With the hint a mapped source
// is classified v6 and takes the v6 branch, in parity with the dataplane.
//
// Only the isV4 branch selection (which family's nets the PACKET is tested
// against) uses the family. The v4Empty/v6Empty gates below key on the ADDRESS
// SETS, not the packet family, so the #3023 cross-family + #2008 excluded
// fail-closed semantics above are unchanged.
func matchAddr(cfg *config.Config, overlay map[string][]string, addrs []string, excluded bool, ip net.IP, family string) bool {
	if ip == nil {
		return true
	}

	isV4 := queryTupleFamily(ip, family) == "v4"

	rawMatched := false
	v4Empty := true
	v6Empty := true
	for _, tok := range addrs {
		v4nets, v6nets, anyV4, anyV6 := resolveToken(cfg, overlay, tok)
		if anyV4 || len(v4nets) > 0 {
			v4Empty = false
		}
		if anyV6 || len(v6nets) > 0 {
			v6Empty = false
		}
		if isV4 {
			if anyV4 || containsAny(v4nets, ip) {
				rawMatched = true
			}
		} else {
			if anyV6 || containsAnyV6(v6nets, ip) {
				rawMatched = true
			}
		}
	}

	if !excluded {
		if len(addrs) == 0 {
			// No address constraint configured: the runtime treats this as
			// match-any for both families (parse_legacy_address_set of an empty
			// list). Only the NON-excluded empty list is match-any.
			return true
		}
		return rawMatched
	}
	// Excluded: fail CLOSED only when the set is empty across BOTH families —
	// the #2008 typo/parse-drop signal (matches policy.rs's
	// `!(v4_empty && v6_empty)`). A populated other-family set means the
	// operator listed only one family; the packet's family is then trivially
	// NOT in the excluded set, so the side matches (#3023 cross-family).
	if v4Empty && v6Empty {
		return false
	}
	return !rawMatched
}

// containsAny reports whether ip falls inside any of the V4 nets. It keeps
// net.IPNet.Contains, whose leading `if x := ip.To4(); x != nil { ip = x }`
// narrowing is CORRECT here: net.ParseIP hands back a 16-byte 4-in-6 slice for
// a plain dotted quad, and addCIDRValue stores v4 prefixes 4-byte, so the fold
// is what makes the two widths meet.
//
// The fold is only safe because addCIDRValue routes a value into a v4 set on
// the COLON-STRICT text family (addrValueFamily), so every net here came from a
// colonless literal and is a genuine 4-byte IPv4 prefix. Before #6577 the
// routing used ipnet.IP.To4(), which filed a mapped `::ffff:0:0/96` here — and
// Contains then sliced its 16-byte mask to the trailing four ZERO bytes,
// degrading it to an IPv4 /0 that matched every IPv4 address.
func containsAny(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// containsAnyV6 is the v6 counterpart and deliberately does NOT use
// net.IPNet.Contains.
//
// #6577: Contains opens with the same `ip.To4()` narrowing, so an IPv4-MAPPED
// IPv6 address (`::ffff:a.b.c.d`) is folded to 4 bytes and then fails the
// `len(ip) != len(nn)` length guard against EVERY 16-byte v6 prefix — `::/0`
// included. The dataplane compares UNFOLDED 128-bit values
// (`userspace-dp/src/prefix.rs`: `(u128::from(ip) & self.mask) == self.network`),
// so a mapped destination matched a v6 DENY there while falling through to a
// later PERMIT here — the simulator reported PERMIT where the box DENIES, in
// the package whose contract is dataplane parity.
//
// This is the untested half of #6377: that issue fixed WHICH family's rules a
// mapped address is tested against (the unsupported-tuple gate); this is HOW
// containment is performed once the address lands in the v6 branch.
//
// Every net reaching a v6 set carries a 16-byte IP AND a 16-byte mask —
// addCIDRValue routes a value here on the COLON-STRICT text family
// (addrValueFamily), and net.ParseCIDR of a colon-bearing literal yields a
// 16-byte network plus a CIDRMask(n, 128), while the bare-IP branch stores
// To16() plus CIDRMask(128, 128). That holds for an IPv4-MAPPED prefix too
// (`::ffff:0:0/96` -> 16-byte `::ffff:0.0.0.0` + a 16-byte /96 mask), which is
// what lets the straight 16-byte masked compare below mirror the Rust
// `PrefixV6` mask exactly for the mapped forms #6577 is about. Written
// explicitly rather than through netip (the #6327 preference) because
// netip.Prefix.Contains keys family off Addr.BitLen(), and the 4-in-6 slice
// net.ParseIP returns for a dotted quad would make an implicit-family form
// silently stop matching v4.
//
// The caller supplies the PACKET family colon-strictly too (queryTupleFamily
// off config.NATAddrFamily on the raw operator text). That hint is the SOLE
// guard against a plain dotted quad reaching this branch: net.ParseIP("10.0.1.5")
// and net.ParseIP("::ffff:10.0.1.5") are BYTE-IDENTICAL, so containsAnyV6
// cannot itself tell them apart and would happily match a v4 address against
// `::/0`. Every production call site derives the family from the same raw
// string it parses the IP from, so the case is unreachable there.
func containsAnyV6(nets []*net.IPNet, ip net.IP) bool {
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	for _, n := range nets {
		nip := n.IP.To16()
		if nip == nil || len(n.Mask) != net.IPv6len {
			continue
		}
		matched := true
		for i := 0; i < net.IPv6len; i++ {
			if ip16[i]&n.Mask[i] != nip[i]&n.Mask[i] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// resolveToken resolves a single policy address token to its v4/v6 CIDR sets
// plus per-family "match any" flags, mirroring the snapshot builder's
// classifyPolicyAddresses (book-name precedence) and policy.rs's
// parse_v3_literal_set / expandBookNameToCIDRs.
func resolveToken(cfg *config.Config, overlay map[string][]string, tok string) (v4nets, v6nets []*net.IPNet, anyV4, anyV6 bool) {
	if tok == "" {
		return nil, nil, false, false
	}

	// #9523: a match-all keyword is never a name, so it is tested BEFORE the
	// book lookup, exactly as classifyPolicyAddresses does. Before #9523 the
	// switch below ran after isBookName, and an address named `any` turned every
	// `match ... any` into a match on its prefixes here as in the dataplane.
	switch tok {
	case "any":
		return nil, nil, true, true
	case "any-ipv4", "any4":
		return nil, nil, true, false
	case "any-ipv6", "any6":
		return nil, nil, false, true
	}

	// Book-name precedence (classifyPolicyAddresses): a token that names a
	// static address/address-set OR a feed-overlay address-name is resolved as
	// a book reference, never as a literal.
	if isBookName(cfg, overlay, tok) {
		// #3294: expandBookName is feed-aware — it merges the live feed
		// prefixes for the token AND for any feed-bound MEMBER nested inside an
		// address-set, mirroring the dataplane's expandBookNameRecursive. This
		// keeps the in-process simulator in parity with what the AF_XDP helper
		// enforces (a `deny <set-containing-a-feed>` denies the feed portion).
		values := expandBookName(cfg, overlay, tok, make(map[string]bool))
		for _, val := range values {
			addCIDRValue(val, &v4nets, &v6nets, &anyV4, &anyV6)
		}
		return v4nets, v6nets, anyV4, anyV6
	}

	addCIDRValue(tok, &v4nets, &v6nets, &anyV4, &anyV6)
	return v4nets, v6nets, anyV4, anyV6
}

// addCIDRValue parses one address value (CIDR, bare IP, "any", or a family
// wildcard) and appends it to the appropriate family set / wildcard flag.
//
// The family is classified COLON-STRICTLY from the value's TEXT
// (config.NATAddrFamily on config.NATCIDRIPPart), never from the parsed
// net.IP's To4() — see addrValueFamily.
func addCIDRValue(val string, v4nets, v6nets *[]*net.IPNet, anyV4, anyV6 *bool) {
	switch val {
	case "":
		// #3261: an address-book entry with no compiled prefix (a Junos
		// dns-name / wildcard-address / range-address that compiled to
		// Value=="") contributes NOTHING — it must NOT widen to match-any.
		// Mirrors the dataplane's expandBookNameToCIDRs, which now skips an
		// empty value instead of emitting 0.0.0.0/0 (the pre-#3261 fail-open).
		return
	case "any":
		*anyV4 = true
		*anyV6 = true
		return
	case "any-ipv4", "any4":
		*anyV4 = true
		return
	case "any-ipv6", "any6":
		*anyV6 = true
		return
	}
	if _, ipnet, err := net.ParseCIDR(val); err == nil {
		if addrValueFamily(val) == "v4" {
			*v4nets = append(*v4nets, ipnet)
		} else {
			*v6nets = append(*v6nets, ipnet)
		}
		return
	}
	if ip := net.ParseIP(val); ip != nil {
		if addrValueFamily(val) == "v4" {
			*v4nets = append(*v4nets, &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)})
		} else {
			*v6nets = append(*v6nets, &net.IPNet{IP: ip.To16(), Mask: net.CIDRMask(128, 128)})
		}
	}
}

// addrValueFamily classifies one address-book / policy address literal into
// "v4" or "v6" from its TEXT, mirroring the Rust `parse_address` /
// `parse_book_prefix_into` dispatch in userspace-dp/src/policy.rs
// (`prefix.parse::<IpNet>()` tries `Ipv4Net` first, and Rust's
// `Ipv4Addr::from_str` REJECTS anything containing a colon, so a colon-bearing
// literal is always `IpNet::V6`). config.NATAddrFamily is the colon-strict
// SSOT for exactly this Go/Rust divergence and config.NATCIDRIPPart strips the
// mask so the classification runs on the ORIGINAL text.
//
// #6577 (prefix half): the previous `ipnet.IP.To4() != nil` / `ip.To4() != nil`
// test FOLDS an IPv4-mapped literal, so `::ffff:0:0/96` and every mapped
// `/97`-`/128` prefix landed in the V4 set. That is not a cosmetic
// misfiling — once a mapped prefix is in the v4 set, net.IPNet.Contains folds
// the 16-byte network through To4() and slices the 16-byte mask down to its
// TRAILING four bytes (net.networkNumberAndMask), so `::ffff:0:0/96` degrades
// to an IPv4 /0 that matches EVERY IPv4 address, and a mapped `/120` aliases
// to the embedded IPv4 `/24`. On a DENY rule the simulator therefore reported
// the rule covering all of IPv4 while the dataplane holds it as a `PrefixV6`
// that no plain IPv4 packet is ever tested against — the opposite verdict, in
// the package whose contract is dataplane parity. The bare-IP branch had the
// identical defect: `::ffff:10.0.0.1` became a v4 /32 while Rust's `Err(_)`
// arm parses it as an `Ipv6Addr` and stores a v6 /128.
//
// This is the address-SET half of the same defect the containsAnyV6 fix closes
// on the query side. Ordinary literals are unaffected: a dotted quad / v4 CIDR
// has no colon ("v4") and a genuine v6 literal has one ("v6"), so both classify
// exactly as the To4() test did — only the mapped forms move, which is the fix.
// See README "Colon-strict family — containment and prefix classification
// (#6577)" for the address-BOOK path, which fails closed separately.
func addrValueFamily(val string) string {
	return config.NATAddrFamily(config.NATCIDRIPPart(val))
}

func isBookName(cfg *config.Config, overlay map[string][]string, tok string) bool {
	if _, ok := overlay[tok]; ok {
		return true
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return false
	}
	if _, ok := ab.Addresses[tok]; ok {
		return true
	}
	if _, ok := ab.AddressSets[tok]; ok {
		return true
	}
	return false
}

// expandBookName resolves an address-book name to its raw address VALUE
// strings (CIDRs / bare IPs / "any"), recursing through address-sets with
// path-based cycle detection — a direct port of the snapshot builder's
// expandBookNameRecursive.
//
// #3294: feed-aware. A dynamic-address feed binding name contributes its live
// overlay prefixes at the top level AND when nested as an address-set member,
// matching expandBookNameRecursive so the simulator and the dataplane agree
// (closing the feed-portion under-deny in the simulator too). overlay may be
// nil; ab may be nil while overlay carries the name (a pure feed binding).
func expandBookName(cfg *config.Config, overlay map[string][]string, name string, visited map[string]bool) []string {
	if visited[name] {
		return nil
	}
	visited[name] = true
	defer delete(visited, name)

	var out []string
	if feeds := overlay[name]; len(feeds) > 0 {
		out = append(out, feeds...)
	}
	ab := cfg.Security.AddressBook
	if ab == nil {
		return out
	}
	if addr, ok := ab.Addresses[name]; ok {
		out = append(out, addr.Value)
		return out
	}
	if as, ok := ab.AddressSets[name]; ok {
		for _, member := range as.Addresses {
			out = append(out, expandBookName(cfg, overlay, member, visited)...)
		}
		for _, nested := range as.AddressSets {
			out = append(out, expandBookName(cfg, overlay, nested, visited)...)
		}
		return out
	}
	return out
}

// matchApp replicates policy.rs CompiledApplications.matches fed by the
// snapshot builder's application expansion: predefined + user applications via
// ResolveApplication, recursive application-set expansion via
// ExpandApplicationSet, BOTH source-port and destination-port terms, and the
// ICMP/ICMPv6 type/code constraints enforced in matchSingleApp (#3284).
//
// An empty application list is the runtime match-any case.
//
// #3323: an OMITTED (or unresolvable) query protocol must NOT short-circuit to
// match-any for an application-constrained term — it must fail closed, mirroring
// the runtime. The runtime always carries a concrete protocol and keys its
// per-application terms under that protocol (policy.rs CompiledApplications.matches
// does `by_protocol.get(&protocol)?`, yielding None when no term exists for the
// packet's protocol). An omitted query protocol resolves to queryProtoOK=false
// (appid.ProtocolNumber("") is (0,false)), so every protocol-bearing app term —
// the predefined Junos apps and any custom app with a `protocol` — fails the
// matchSingleApp protocol gate and does NOT match. The old
// `if proto == "" { return true }` convenience reported a permit/deny by an
// app-constrained policy that no concrete ICMP/UDP/GRE/random-TCP packet would
// ever hit (the sibling of #3330's destination-port omission). Falling through
// here lets Match reach the configured default-policy, exactly as the dataplane
// would for a protocol that matches no term.
//
// An application that is genuinely UNCONSTRAINED on protocol (app.Protocol == ""
// with no port / ICMP-type constraint either) still matches regardless of the
// query protocol — it is a true match-any term, unchanged. Once a non-empty
// protocol IS supplied, matchSingleApp constrains by protocol (and ICMP
// type/code for a type-constrained term) exactly as before; a non-empty but
// UNRESOLVABLE protocol fails closed for every protocol-constrained app term.
// policyContentRejectionReasons detects the config-level conditions under which
// the userspace snapshot builder fails the WHOLE snapshot closed and enforces
// NONE of the config, so the simulator must report that fail-closed retention
// rather than a fabricated permit/deny/default verdict. It delegates to the
// shared dpuserspace.PolicyContentRejectionReasons SSOT (the exact detection
// buildSnapshot uses), covering every fail-closed policy-content axis:
//
//   - an unexpandable application-SET (#3727) — the app catalog build errors
//     (order-insensitive, so `[ any bad-set ]` is caught too) OR the per-rule
//     application expansion poisons the rule with the __unsupported__ sentinel;
//   - a protocol-less application (#3323) — proto == "" is unrepresentable;
//   - an unrepresentable protocol/port (#2124/#4345) — appid.ProtocolNumber /
//     userspacePortSpecRepresentable rejects it;
//   - an undefined application reference — resolveUserspaceApplicationNames fails;
//   - an unresolvable address (#3261) — an undefined address-book / prefix-list
//     name, or a defined book/set whose value is a non-literal dns-name /
//     wildcard / range (or resolves to no concrete prefix), poisons the rule
//     with the __unsupported_address__ sentinel.
//
// A single unrepresentable rule anywhere fails the ENTIRE snapshot closed, so
// every query for the config reports the fail-closed verdict, not just one that
// would hit the offending rule. The detection is feed-aware (feedOverlay): a
// healthy dynamic-address feed policy resolves through the overlay and is not
// falsely flagged — callers pass q.FeedOverlay, the same overlay the production
// builder uses, so the simulator agrees with the helper on feed-backed names.
func policyContentRejectionReasons(cfg *config.Config, feedOverlay map[string][]string) []string {
	return dpuserspace.PolicyContentRejectionReasons(cfg, feedOverlay)
}

// #5572: l4Present is false for a NON-FIRST fragment (the dataplane's
// evaluate_policy_result_l3_aware l4_present == false, #3291). It fails closed a
// PORT-BEARING or ICMP-type-constrained term (which a fragment cannot be
// classified into) while a protocol-only / `any` term still matches on the known
// IP protocol — a direct mirror of CompiledApplications::matches. Every ordinary
// (L4-present) caller passes true, so the L4 path is byte-identical.
func matchApp(cfg *config.Config, apps []string, proto string, srcPort, dstPort int, icmpType, icmpCode *uint8, l4Present bool) bool {
	if len(apps) == 0 {
		return true
	}
	queryProto, queryProtoOK := appid.ProtocolNumber(proto)

	for _, a := range apps {
		if a == "any" {
			return true
		}
		// Application-set: expand recursively (multi-level) and test each
		// member application.
		// #5666: recognize a PREDEFINED application-set bundle (junos-ms-rpc,
		// junos-sun-rpc, junos-cifs, junos-routing-inbound), not just
		// user-defined sets — mirror the #5629 dataplane fix so this operator
		// simulator matches the fixed dataplane. Resolve an application FIRST so
		// a user application shadowing a predefined-set name keeps application
		// semantics (matches resolveUserspaceApplicationNames + #5629's
		// app-first precedence). config.ResolveApplicationSet consults user sets
		// then the #4102 predefined table.
		_, isApp := config.ResolveApplication(a, cfg.Applications.Applications)
		if _, isSet := config.ResolveApplicationSet(a, cfg.Applications.ApplicationSets); !isApp && isSet {
			members, err := config.ExpandApplicationSet(a, &cfg.Applications)
			if err != nil {
				// #3727: an unexpandable application-set is a whole-snapshot
				// fail-close in the runtime, not a silent skip. Match already
				// gates on policyContentRejectionReasons BEFORE any rule is
				// evaluated and returns a ContentRejected verdict, so this branch
				// is unreachable for a config that entered through Match; keep it
				// defensive (do not silently fall through to a later app / rule as
				// the pre-#3727 `continue` did — that fabricated the permit/deny
				// verdict the dataplane never certifies).
				continue
			}
			for _, m := range members {
				if matchSingleApp(cfg, m, queryProto, queryProtoOK, srcPort, dstPort, icmpType, icmpCode, l4Present) {
					return true
				}
			}
			continue
		}
		if matchSingleApp(cfg, a, queryProto, queryProtoOK, srcPort, dstPort, icmpType, icmpCode, l4Present) {
			return true
		}
	}
	return false
}

func matchSingleApp(cfg *config.Config, appName string, queryProto uint8, queryProtoOK bool, srcPort, dstPort int, icmpType, icmpCode *uint8, l4Present bool) bool {
	app, ok := config.ResolveApplication(appName, cfg.Applications.Applications)
	if !ok {
		return false
	}
	// Protocol: a NAMED application MUST carry a resolvable protocol, and it must
	// equal the query protocol. Compare by IANA number so a named app protocol
	// ("89"/"ospf") and a named/numeric query protocol agree (the old EqualFold
	// string compare failed "89" vs "ospf").
	//
	// #3323/#4394: a protocol-less named app is NOT match-any — it fails closed.
	// The dataplane cannot represent such an app and never enforces it: the
	// snapshot builder fails closed (deriveUserspaceCapabilities,
	// pkg/dataplane/userspace/capabilities.go returns ok=false for proto=="" →
	// the reserved __unsupported__ sentinel → whole-snapshot reject, #3261) and
	// strict commit hard-rejects it (pkg/config/compiler_validate_strict.go:
	// "cannot represent a protocol-less application"). A protocol-less named app
	// can therefore only exist via a lenient/HA-loaded config, where the runtime
	// STILL never enforces it. #4394: Match now gates a protocol-less CONFIG app
	// as a config-wide ContentRejected (the whole-snapshot fail-close) BEFORE any
	// rule is evaluated, so this per-term guard is unreachable for a config with a
	// protocol-less app — it is kept defensive so that even if the config-wide
	// gate were bypassed, reporting the app as a concrete match-any (which the
	// dataplane never produces) can never happen. appid.ProtocolNumber("") is
	// (0,false), so an empty app.Protocol makes appOK false and the term fails
	// closed. The literal `application any` token never reaches matchSingleApp
	// (matchApp short-circuits a == "any"), so this does not affect the genuine
	// match-any case.
	appProto, appOK := appid.ProtocolNumber(app.Protocol)
	if !appOK || !queryProtoOK || appProto != queryProto {
		return false
	}
	// #3284: ICMP/ICMPv6 type[,code] constraint (junos-ping = type 8). Mirror
	// policy.rs CompiledApplications.matches: a type-constrained term matches
	// ONLY when the query's ICMP type is known and equal — and the code too,
	// when the term constrains a code. A nil query type fails closed for the
	// term (the runtime's `packet_icmp == None` path). An application with NO
	// ICMP type constraint (junos-icmp-all, or any non-ICMP app) is unaffected:
	// it matches on protocol/ports alone, exactly as before.
	if app.ICMPType != nil {
		// #5572: a non-first fragment (l4Present == false) carries no readable
		// ICMP type/code — the dataplane's packet_icmp is None there — so an
		// ICMP-type-constrained term fails closed regardless of any type the
		// caller left in the query. Mirrors CompiledApplications::matches, which
		// only consults icmp_constraints when packet_icmp is Some.
		if !l4Present {
			return false
		}
		// The dataplane keys icmp_constraints under the app's ICMP protocol, so
		// the type constraint is only ever consulted for an ICMP-family packet.
		// A predefined ICMP app pins app.Protocol (handled by the check above),
		// but a custom app could carry an icmp-type without a pinned protocol;
		// require the query to be ICMP (1) / ICMPv6 (58) so a type-constrained
		// term can never match a TCP/UDP flow.
		if !queryProtoOK || (queryProto != icmpProtoNum && queryProto != icmpv6ProtoNum) {
			return false
		}
		if icmpType == nil || *icmpType != *app.ICMPType {
			return false
		}
		if app.ICMPCode != nil && (icmpCode == nil || *icmpCode != *app.ICMPCode) {
			return false
		}
	}
	// #3330: when the application term CONSTRAINS a destination port, an OMITTED
	// query dst port must NOT match-any — it must fail closed, mirroring the
	// runtime. The dataplane keys a single dst-port term in exact_dst_ports and
	// range terms in range_terms (policy.rs CompiledApplications.matches): an
	// omitted query port arrives as 0, which a real app port (e.g. 80) never
	// equals and no app range admits, so the constrained term does NOT match.
	// The old `&& dstPort > 0` gate skipped the check entirely for an omitted
	// port, reporting a permit for a port-constrained app no concrete packet
	// would hit (sibling of #3323's protocol omission). An UNCONSTRAINED dst
	// port term (app.DestinationPort == "") still matches any port, unchanged.
	if app.DestinationPort != "" {
		// #5572: a non-first fragment (l4Present == false) has no L4 header, so a
		// destination-port term fails closed unconditionally — even a term like
		// `destination-port 0-1023` that a naive port-0 query would spuriously
		// match. This is the exact port-gate the dataplane's matches() applies
		// (exact_dst_ports / range_terms are consulted only when l4_present).
		if !l4Present {
			return false
		}
		if dstPort <= 0 || !portMatches(app.DestinationPort, dstPort) {
			return false
		}
	}
	// #3415: when the application term CONSTRAINS a source port, an OMITTED query
	// source port must NOT match-any — it must fail closed, mirroring the runtime
	// and the now fail-closed protocol (#3323) and destination-port (#3330)
	// siblings above. The runtime always carries a concrete source port and the
	// dataplane gates a source-port-constrained app on it (appid.matchTuple ->
	// portInSpec(srcPort, appSrcPort); policy.rs CompiledApplications.matches): a
	// packet whose source port differs from the app's `source-port` never
	// matches. An omitted query source port arrives as 0, which a real app source
	// port (e.g. 5000) never equals and no app range admits, so the constrained
	// term does NOT match. The old `&& srcPort > 0` gate skipped the check for an
	// omitted port — #3107's deliberate diagnostic stance — and over-certified a
	// permit for a source-port-bearing app no concrete packet would hit. This
	// supersedes that #3107 absent-source-port contract: source port is ephemeral
	// and rarely known, but a SOURCE-PORT-CONSTRAINED app is rare, and certifying
	// a permit/deny for a broader class of packets than the runtime enforces is
	// the exact over-match #3323/#3330 closed. An UNCONSTRAINED source-port term
	// (app.SourcePort == "") still matches any port, unchanged — the common case
	// (no source-port constraint) is unaffected, so a query omitting source port
	// against an ordinary destination-port app behaves exactly as before.
	if app.SourcePort != "" {
		// #5572: a non-first fragment has no L4 header — a source-port term fails
		// closed unconditionally, the source-side sibling of the destination-port
		// gate above.
		if !l4Present {
			return false
		}
		if srcPort <= 0 || !portMatches(app.SourcePort, srcPort) {
			return false
		}
	}
	return true
}

// hasL4ConstrainedTerm reports whether the policy's application list carries at
// least one term FOR the query protocol whose match is GATED by L4 presence —
// an exact destination-port, a port RANGE, a source-port constraint, or an
// ICMP/ICMPv6 type constraint (#5572). It is the exact mirror of the dataplane's
// CompiledApplications::has_l4_constrained_term (policy.rs #4569): the
// discriminator that tells a DENY skipped for a flowless fragment ONLY because
// its L4-constrained term is inapplicable (→ fail the fragment closed) from a
// DENY that genuinely does not apply to this protocol at all (→ let the fragment
// proceed). An `application any` (match-any) or a protocol-only term is NOT
// gated, so those return false.
func hasL4ConstrainedTerm(cfg *config.Config, apps []string, proto string) bool {
	queryProto, ok := appid.ProtocolNumber(proto)
	if !ok {
		return false
	}
	for _, a := range apps {
		if a == "any" {
			// match-any covers this protocol with an ungated term.
			return false
		}
		// #5666: recognize a PREDEFINED application-set bundle (junos-ms-rpc,
		// junos-sun-rpc, junos-cifs, junos-routing-inbound), not just
		// user-defined sets — mirror the #5629 dataplane fix so this operator
		// simulator matches the fixed dataplane. Resolve an application FIRST so
		// a user application shadowing a predefined-set name keeps application
		// semantics (matches resolveUserspaceApplicationNames + #5629's
		// app-first precedence). config.ResolveApplicationSet consults user sets
		// then the #4102 predefined table.
		_, isApp := config.ResolveApplication(a, cfg.Applications.Applications)
		if _, isSet := config.ResolveApplicationSet(a, cfg.Applications.ApplicationSets); !isApp && isSet {
			members, err := config.ExpandApplicationSet(a, &cfg.Applications)
			if err != nil {
				continue
			}
			for _, m := range members {
				if appTermL4Constrained(cfg, m, queryProto) {
					return true
				}
			}
			continue
		}
		if appTermL4Constrained(cfg, a, queryProto) {
			return true
		}
	}
	return false
}

// appTermL4Constrained reports whether a single application resolves to a term
// FOR queryProto that is port- or ICMP-type-constrained (#5572). A term for a
// different protocol does not count (the dataplane keys terms by protocol, so a
// tcp-only deny is not "L4-constrained" for a udp fragment).
func appTermL4Constrained(cfg *config.Config, appName string, queryProto uint8) bool {
	app, ok := config.ResolveApplication(appName, cfg.Applications.Applications)
	if !ok {
		return false
	}
	appProto, appOK := appid.ProtocolNumber(app.Protocol)
	if !appOK || appProto != queryProto {
		return false
	}
	return app.DestinationPort != "" || app.SourcePort != "" || app.ICMPType != nil
}

// fragDenyCandidate remembers the FIRST port-bearing DENY/REJECT a non-first
// fragment skipped while walking the transit tiers (#5572), enough to rebuild the
// full matchedResult so the fragment-associated deny verdict names the ENFORCING
// policy (PolicyName / PolicyID / RuleID / scope), not just a bare drop. The
// dataplane's SkippedFragDeny carries only policy_id + counter (it attributes a
// wire PolicyDeny event); the simulator's operator-facing verdict must carry the
// full identity, so it stores the tier coordinates matchedResult keys on.
type fragDenyCandidate struct {
	pol      *config.Policy
	global   bool
	fromZone string
	toZone   string
	setIdx   int
	sliceIdx int
}

// fragDenyResult builds the #5572 fragment-associated deny verdict from a skipped
// candidate: the DENY policy's full matchedResult (identity — PolicyName /
// PolicyID / RuleID / scope), flagged FragmentAssociatedDeny so callers render
// FragmentDenyNote.
//
// Action is FORCED to config.PolicyDeny — never the reject the skipped rule may
// carry. A non-first fragment has no L4 header, so the dataplane cannot emit a
// RST/ICMP: it can only SILENTLY DROP the fragment. The Rust
// frag_associated_deny_result hardcodes PolicyAction::Deny for exactly this
// reason, so a skipped REJECT (isSkippedFragDeny accepts PolicyReject, since a
// reject shadows the fragment identically to a deny) still yields a Deny label
// here. Reporting reject would tell the operator a RST/ICMP is sent when the
// firewall silently drops — a simulator/dataplane label divergence. Both verdicts
// are DROPs, so the #5572 false-permit is not re-introduced; this only corrects
// the deny-vs-reject label.
func fragDenyResult(ids map[[2]uint32]uint32, c fragDenyCandidate) Result {
	r := matchedResult(ids, c.pol, c.global, c.fromZone, c.toZone, c.setIdx, c.sliceIdx)
	r.Action = config.PolicyDeny
	r.FragmentAssociatedDeny = true
	return r
}

// fragDenyTracker reproduces the dataplane's #4569 note_skipped_frag_deny /
// apply_frag_deny_override pair for ONE policy walk, and is shared by BOTH the
// transit walk (Match) and the host walk (matchJunosHost).
//
// #6576: sharing it is the point. #6505 taught policy.rs's junos-host gate to
// fail closed on a skipped fragment deny, but the Go host walk kept its
// pre-#6465 permissive terminal because the transit walk owned the machinery
// as local closures that matchJunosHost — which returns before they are even
// declared — could not reach. The simulator then reported PERMIT / "local
// delivery" for a fragment the box DROPS, in the package whose whole contract
// is dataplane parity. One tracker, two callers: a future host-gate change
// cannot silently diverge again.
//
// For an ordinary L4 query q.NonFirstFragment is false, so every method is
// inert and both walks are byte-identical to before.
type fragDenyTracker struct {
	cfg  *config.Config
	q    Query
	ids  map[[2]uint32]uint32
	cand *fragDenyCandidate
}

func newFragDenyTracker(cfg *config.Config, q Query, ids map[[2]uint32]uint32) *fragDenyTracker {
	return &fragDenyTracker{cfg: cfg, q: q, ids: ids}
}

// note remembers the FIRST port-bearing DENY/REJECT this walk SKIPPED because
// the fragment carries no L4 header (overlapping L3, L4-constrained term
// inapplicable) — the mirror of note_skipped_frag_deny.
func (f *fragDenyTracker) note(pol *config.Policy, global bool, fromZone, toZone string, setIdx, sliceIdx int) {
	if !f.q.NonFirstFragment || f.cand != nil || pol == nil {
		return
	}
	if isSkippedFragDeny(f.cfg, f.q, pol) {
		f.cand = &fragDenyCandidate{
			pol: pol, global: global, fromZone: fromZone, toZone: toZone,
			setIdx: setIdx, sliceIdx: sliceIdx,
		}
	}
}

// override converts a matched PERMIT into the remembered deny —
// apply_frag_deny_override.
func (f *fragDenyTracker) override(res Result) Result {
	if f.q.NonFirstFragment && f.cand != nil && res.Action == config.PolicyPermit {
		return fragDenyResult(f.ids, *f.cand)
	}
	return res
}

// overridePermissiveTerminal converts a PERMIT-LIKE fall-through into the
// remembered deny. The junos-host fall-through is "no implicit default-deny" —
// an unmatched host-bound flow is DELIVERED (the management lifeline), which is
// a permit-like posture, so a fragment that skipped an overlapping port-bearing
// DENY must fail closed exactly as it does against a transit default-PERMIT.
// This is the Go mirror of the #6465 post-walk arm in
// evaluate_junos_host_policy (`if let Some(deny) = skipped_frag_deny { return
// Some(frag_associated_deny_result(deny)) }`). Inert when no deny was skipped,
// and the L4 path never records one — so the lifeline is unchanged there.
func (f *fragDenyTracker) overridePermissiveTerminal(res Result) Result {
	if f.q.NonFirstFragment && f.cand != nil {
		return fragDenyResult(f.ids, *f.cand)
	}
	return res
}

// isSkippedFragDeny mirrors the dataplane's rule_is_skipped_frag_ambiguous_deny
// (policy.rs #4569): is pol a port-bearing (L4-constrained) DENY/REJECT that a
// flowless non-first fragment SKIPPED only because l4_present == false, and whose
// L3 (source + destination address — the zone side is already fixed by the tier
// the caller is walking) OVERLAPS the fragment? Only such a deny is remembered so
// a later PERMIT can be failed closed. Returns true iff ALL hold:
//   - the policy is scheduler-active (mirrors rule.inactive);
//   - its action is deny or reject (a permit is not a fail-open risk);
//   - it carries an L4-constrained term for the fragment's protocol
//     (hasL4ConstrainedTerm) — a term the fragment cannot be classified into,
//     not a rule for a different protocol;
//   - it does NOT already match this flowless fragment (a protocol-only / `any`
//     deny term matches directly and is a real deny, never "skipped");
//   - its source+destination address set overlaps the fragment.
//
// A non-overlapping deny, a different-protocol deny, or a permit therefore leaves
// the fragment on its normal (forward) path.
func isSkippedFragDeny(cfg *config.Config, q Query, pol *config.Policy) bool {
	if q.PolicyInactiveFn != nil && q.PolicyInactiveFn(pol.SchedulerName) {
		return false
	}
	if pol.Action != config.PolicyDeny && pol.Action != config.PolicyReject {
		return false
	}
	if !hasL4ConstrainedTerm(cfg, pol.Match.Applications, q.Protocol) {
		return false
	}
	// A protocol-only / `any` term would match flowlessly → the rule is a real
	// deny handled directly by the tier walk, not a skip. Fail-closed ports pass
	// 0 and l4Present == false so port/icmp terms cannot match.
	if matchApp(cfg, pol.Match.Applications, q.Protocol, 0, 0, nil, nil, false) {
		return false
	}
	// L3 overlap: the zone is fixed by the tier bucket, so only source +
	// destination address overlap is checked (the same matchAddr the runtime uses
	// via rule_l3_matches).
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded, q.SrcIP, q.SrcFamily) {
		return false
	}
	if !matchAddr(cfg, q.FeedOverlay, pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded, q.DstIP, q.DstFamily) {
		return false
	}
	return true
}

// portMatches reports whether port falls in the application port spec, which
// may be a named alias ("http"), a single port ("80"), or a range
// ("80-90") — mirroring policy.rs parse_port_spec.
func portMatches(spec string, port int) bool {
	spec = normalizePortAlias(spec)
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, errL := strconv.Atoi(strings.TrimSpace(lo))
		h, errH := strconv.Atoi(strings.TrimSpace(hi))
		if errL != nil || errH != nil {
			return false
		}
		return port >= l && port <= h
	}
	p, err := strconv.Atoi(strings.TrimSpace(spec))
	if err != nil {
		return false
	}
	return p == port
}

func normalizePortAlias(spec string) string {
	switch spec {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	case "telnet":
		return "23"
	case "ftp":
		return "21"
	case "ftp-data":
		return "20"
	case "smtp":
		return "25"
	case "dns":
		return "53"
	case "pop3":
		return "110"
	case "imap":
		return "143"
	case "snmp":
		return "161"
	case "ntp":
		return "123"
	case "bgp":
		return "179"
	case "ldap":
		return "389"
	case "syslog":
		return "514"
	default:
		return spec
	}
}

// ExceptSuffix returns " (except)" when a matched policy's address side carries
// Junos source-address-excluded / destination-address-excluded, and "" otherwise
// (#3668). It is the SSOT for the negated-address annotation shared by the local
// CLI (pkg/cli) and remote CLI (cmd/cli) match-policies renderers, so the label
// cannot drift between the two surfaces. The shared matcher already inverts the
// address test correctly; this suffix keeps the DISPLAY from reading backwards.
func ExceptSuffix(excluded bool) string {
	if excluded {
		return " (except)"
	}
	return ""
}

// ActionString renders a policy action token (permit/deny/reject).
func ActionString(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

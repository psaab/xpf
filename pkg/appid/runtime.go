package appid

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

const Unknown = "UNKNOWN"

type builtinApp struct {
	proto uint8
	port  uint16
}

// Keep fallback heuristics intentionally narrow. Real AppID names should come
// from dataplane-assigned app_id values, not broad protocol-only guesses.
var builtinFallbacks = map[string]builtinApp{
	"junos-http":        {proto: 6, port: 80},
	"junos-https":       {proto: 6, port: 443},
	"junos-ssh":         {proto: 6, port: 22},
	"junos-telnet":      {proto: 6, port: 23},
	"junos-ftp":         {proto: 6, port: 21},
	"junos-smtp":        {proto: 6, port: 25},
	"junos-dns-tcp":     {proto: 6, port: 53},
	"junos-dns-udp":     {proto: 17, port: 53},
	"junos-bgp":         {proto: 6, port: 179},
	"junos-ntp":         {proto: 17, port: 123},
	"junos-snmp":        {proto: 17, port: 161},
	"junos-syslog":      {proto: 17, port: 514},
	"junos-dhcp-client": {proto: 17, port: 68},
	"junos-ike":         {proto: 17, port: 500},
	"junos-ipsec-nat-t": {proto: 17, port: 4500},
}

// CatalogNames returns the set of application names that should be compiled.
// When includeAll is true, it includes all predefined and user-defined apps so
// session tracking can identify flows even when policies do not reference them.
func CatalogNames(cfg *config.Config, includeAll bool) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}

	names := make(map[string]struct{})
	if includeAll {
		for name := range config.PredefinedApplications {
			names[name] = struct{}{}
		}
		for name := range cfg.Applications.Applications {
			names[name] = struct{}{}
		}
		return sortedNames(names), nil
	}

	// addAppRef records one `match application` reference (from a security
	// policy OR a NAT rule) into the catalog. An application-set is expanded to
	// its members; a bare application name is recorded directly. "" / "any" is
	// not a reference. This is the single per-reference resolver shared by the
	// policy and NAT walks so the two paths cannot diverge (#3626 L04).
	addAppRef := func(appName string) error {
		if appName == "" || appName == "any" {
			return nil
		}
		// Resolve a reference the SAME way the userspace policy path does
		// (resolveUserspaceApplicationNames, #4102): an application FIRST (user
		// then predefined), then an application-SET (user then predefined). The
		// set test MUST go through config.ResolveApplicationSet, which is
		// predefined-set-aware — a bare cfg.Applications.ApplicationSets map
		// membership check only sees USER-defined sets, so a strict predefined
		// bundle (junos-ms-rpc, junos-sun-rpc, junos-cifs,
		// junos-routing-inbound) referenced by a policy OR a NAT rule was
		// recorded as if the bundle NAME were itself an application (#5629). The
		// dataplane catalog then carried a set name with no resolvable
		// port/proto, diverging from the resolver's member expansion. Resolving
		// the application first keeps a user application that shadows a
		// predefined-set name winning (user definitions win, matching the policy
		// path); an unknown token still falls through to a bare record so the
		// catalog and the dataplane agree on the reference.
		if _, isApp := config.ResolveApplication(appName, cfg.Applications.Applications); isApp {
			names[appName] = struct{}{}
			return nil
		}
		// A present-but-nil USER set slot (#5179: the tolerant-load / peer-sync
		// path admits a null value) must still be treated as a set reference so
		// it fails CLOSED with a deterministic ExpandApplicationSet error rather
		// than being silently recorded as a bare app name. config.Resolve
		// ApplicationSet SKIPS a nil slot (returns false), so the raw user-map
		// membership test is kept for that case; ResolveApplicationSet ADDS the
		// predefined bundle awareness (#5629) a bare membership test misses.
		_, inUserSetMap := cfg.Applications.ApplicationSets[appName]
		_, isSet := config.ResolveApplicationSet(appName, cfg.Applications.ApplicationSets)
		if inUserSetMap || isSet {
			expanded, err := config.ExpandApplicationSet(appName, &cfg.Applications)
			if err != nil {
				return fmt.Errorf("expand application-set %q: %w", appName, err)
			}
			for _, expandedName := range expanded {
				names[expandedName] = struct{}{}
			}
			return nil
		}
		names[appName] = struct{}{}
		return nil
	}

	addPolicyApps := func(policies []*config.Policy) error {
		for _, pol := range policies {
			// #3622: a nil policy entry is admitted by the tolerant-load
			// path (#1960) and must fail closed, not panic. Match the strict
			// walker (compiler_validate_strict.go), which skips nil rules.
			if pol == nil {
				continue
			}
			for _, appName := range pol.Match.Applications {
				if err := addAppRef(appName); err != nil {
					return err
				}
			}
		}
		return nil
	}

	for _, zpp := range cfg.Security.Policies {
		// #3622: a nil zone-pair entry is admitted by the tolerant-load
		// path (#1960); skip it rather than deref zpp.Policies and panic.
		// Matches the strict walker (compiler_validate_strict.go).
		if zpp == nil {
			continue
		}
		if err := addPolicyApps(zpp.Policies); err != nil {
			return nil, err
		}
	}
	if err := addPolicyApps(cfg.Security.GlobalPolicies); err != nil {
		return nil, err
	}

	// #3626: a source/destination-NAT rule's `match application <name>` also
	// consumes the referenced app's port/proto (pkg/dataplane/userspace/nat.go
	// appPortsFromSpec). An app referenced ONLY by a NAT rule — with no
	// security policy referencing it — must still land in the compiled catalog,
	// or the dataplane cannot resolve it and session naming for that flow falls
	// back to tuple/numeric. Walk NAT rule references exactly as the strict
	// validator does (compiler_validate_strict.go applicationsToValidateStrict:
	// Source + Destination.RuleSets, skipping nil rule-sets/rules, the scalar
	// rule.Match.Application) so the runtime catalog and the commit-time strict
	// gate agree on the referenced-app set — TestStrictValidationSetMatches-
	// CatalogNames pins the two walks together. Static NAT carries no
	// application match, so only source and destination NAT are walked.
	addNATRuleSet := func(rs *config.NATRuleSet) error {
		if rs == nil {
			return nil
		}
		for _, rule := range rs.Rules {
			if rule == nil {
				continue
			}
			if err := addAppRef(rule.Match.Application); err != nil {
				return err
			}
		}
		return nil
	}
	for _, rs := range cfg.Security.NAT.Source {
		if err := addNATRuleSet(rs); err != nil {
			return nil, err
		}
	}
	if cfg.Security.NAT.Destination != nil {
		for _, rs := range cfg.Security.NAT.Destination.RuleSets {
			if err := addNATRuleSet(rs); err != nil {
				return nil, err
			}
		}
	}

	return sortedNames(names), nil
}

// ResolveSessionName returns the session application name using the actual
// dataplane-assigned app_id when available. When AppID is enabled, unknown
// sessions are reported as UNKNOWN instead of guessed from port heuristics.
//
// srcPort is the session source port; it is required so the tuple fallback can
// honor a configured `source-port` constraint (#3428). Both the source and the
// destination port are threaded through to the fallback matcher.
func ResolveSessionName(appNames map[uint16]string, cfg *config.Config, proto uint8, srcPort, dstPort uint16, appID uint16) string {
	if appID != 0 {
		if name := appNames[appID]; name != "" {
			return name
		}
	}

	// #3438 L1: when AppID is enabled the contract
	// (docs/services-application-identification.md) is honest UNKNOWN, never a
	// port-heuristic guess. A session whose app_id is 0 (unstamped/legacy) OR
	// nonzero-but-absent from AppNames (a control/dataplane catalog skew,
	// including the #3438 H4 id wrap) must render UNKNOWN rather than masking the
	// skew with a tuple guess. Tuple fallback is kept ONLY for the disabled-knob
	// path below.
	if cfg != nil && cfg.Services.ApplicationIdentification {
		return Unknown
	}

	return resolveTupleFallback(proto, srcPort, dstPort, cfg, appNames)
}

// SessionMatches reports whether a session's resolved application name equals
// the operator's `show`/`clear ... application <name>` filter.
//
// The comparison is CASE-SENSITIVE exact equality (#5820). Application names
// are case-sensitive identifiers everywhere else in the stack — the parser,
// typed store, resolver, catalog, and AppID stamping all preserve and key on
// exact case, so `Payroll` and `payroll` are two distinct applications with
// distinct AppIDs and distinct session labels. A case-folded filter compare
// here (the pre-#5820 strings.EqualFold) was the sole inconsistency: it let a
// single-case filter collapse two distinct applications on the display path and
// — because the same predicate drives the destructive ClearSessions walk —
// broaden a filtered clear to delete sessions the operator did not name. Junos
// application filters are case-exact, so exact `==` here is the parity contract.
func SessionMatches(filter string, appNames map[uint16]string, cfg *config.Config, proto uint8, srcPort, dstPort uint16, appID uint16) bool {
	if filter == "" {
		return true
	}
	return ResolveSessionName(appNames, cfg, proto, srcPort, dstPort, appID) == filter
}

func sortedNames(names map[string]struct{}) []string {
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// assignedIDForName resolves a catalog name's actual app_id without allocating
// a second map for each session-name lookup. Most names retain their natural
// hash, so the common case is one map lookup. Only a name whose natural slot is
// occupied needs a scan to find its collision-displaced assigned id.
func assignedIDForName(appNames map[uint16]string, name string) uint16 {
	naturalID := config.StableAppID(name)
	if owner := appNames[naturalID]; owner == "" || owner == name {
		return naturalID
	}
	for assignedID, assignedName := range appNames {
		if assignedName == name {
			return assignedID
		}
	}
	return naturalID
}

func resolveTupleFallback(proto uint8, srcPort, dstPort uint16, cfg *config.Config, appNames map[uint16]string) string {
	if cfg != nil {
		// #2578: cfg.Applications.Applications is a Go map; iterating it and
		// returning the first match is non-deterministic. When BOTH a
		// port-constrained app (e.g. tcp/8443) and a protocol-only app (tcp)
		// match the same session, the more-specific port-based app must win,
		// deterministically. Scan all matches, prefer a port-constrained app
		// (a source-port and/or destination-port constraint) over a
		// protocol-only one, and break same-tier ties by LOWEST assigned app_id.
		//
		// #10722: use the assigned app_id carried by the catalog, not the natural
		// StableAppID hash. AssignStableAppIDs displaces a user app that collides
		// with an already-placed id, so its assigned id can differ from its hash.
		// Rust resolves same-tier overlaps by the lowest assigned app_id; using
		// this map keeps the AppID-disabled Go label path in parity, including
		// collision-displaced apps (#5296/#5988/#3612).
		//
		// Names absent from this catalog map (for example, a tolerated config
		// entry not referenced by policy) retain the natural hash fallback so
		// the disabled label path keeps its existing configured-app coverage.
		best := ""
		bestPortBased := false
		var bestID uint16
		for name, app := range cfg.Applications.Applications {
			// #4865: skip a tolerated nil user-application value (a JSON null
			// decoding to a nil pointer on a lenient/HA-synced load, #3494).
			// icmpTypeConstrained is nil-safe, but matchTuple below dereferences
			// app.Protocol/SourcePort/DestinationPort and would panic the
			// AppID-disabled show/session-name path on a nil entry.
			if app == nil {
				continue
			}
			// #3781 interim (log-integrity): a type/code-constrained ICMP app
			// (icmp-type/icmp-code set) match-alls every ICMP type here because
			// matchTuple is protocol + port only (blind to the ICMP type/code).
			// Skip it so a non-echo ICMP resolves to an honest UNKNOWN (or a
			// protocol-only ICMP app when one is referenced) on the AppID-disabled
			// show/session-name path rather than a false type-constrained label.
			// The type/code-aware match is DEFERRED with the catalog wire per the
			// #3781 /research plan. A protocol-only ICMP app is unaffected.
			if icmpTypeConstrained(app) {
				continue
			}
			if !matchTuple(proto, srcPort, dstPort, app.Protocol, app.SourcePort, app.DestinationPort) {
				continue
			}
			portBased := app.DestinationPort != "" || app.SourcePort != ""
			id := assignedIDForName(appNames, name)
			if best == "" || (portBased && !bestPortBased) ||
				(portBased == bestPortBased && id < bestID) {
				best = name
				bestPortBased = portBased
				bestID = id
			}
		}
		if best != "" {
			return best
		}
	}
	for name, ba := range builtinFallbacks {
		if ba.proto == proto && ba.port == dstPort {
			return name
		}
	}
	return ""
}

// matchTuple reports whether a session (proto, srcPort, dstPort) satisfies a
// configured application's protocol + source-port + destination-port
// constraints. An empty appProto never match-alls. An empty appSrcPort /
// appDstPort is "no constraint" for that port. A source-port AND a
// destination-port constraint are both required to hold when present (#3428).
func matchTuple(proto uint8, srcPort, dstPort uint16, appProto, appSrcPort, appDstPort string) bool {
	if appProto == "" {
		return false
	}
	if pn, ok := protocolNumber(appProto); !ok || pn != proto {
		return false
	}
	// #3428: a configured `source-port` constraint must be honored. Previously
	// only protocol + destination-port were compared, so a source-port-scoped
	// app (e.g. `protocol tcp source-port 12345 destination-port 8443`) was
	// matched on dst-port alone — ANY session to dst/8443 was mislabeled as that
	// app regardless of its source port. An empty source-port is unconstrained.
	if !portInSpec(srcPort, appSrcPort) {
		return false
	}
	// #2548: a custom application configured with a protocol but no
	// destination-port is PROTOCOL-ONLY (e.g. user-defined GRE/ESP/AH). The
	// protocol (and any source-port) match above is the whole constraint, so an
	// empty destination-port matches here instead of being rejected. A
	// port-only/port-ranged app (appDstPort != "") still requires the
	// destination port to match.
	return portInSpec(dstPort, appDstPort)
}

// portInSpec reports whether port satisfies an application port spec. An empty
// spec means "no constraint" and always matches. A "lo-hi" spec is an inclusive
// range; a bare value is an exact match. A malformed spec never matches.
//
// #3725 (H02/M05): the tuple fallback MUST parse a port token the same way the
// strict commit gate does (config.validatePortSpec via config.ParseCanonicalUint)
// and reject anything the strict path rejects, rather than mislabeling a real
// session as a malformed app. The old strconv.Atoi parse had two mislabel bugs
// on the tolerant-load / stale-persisted / peer-sync path (strict commit rejects
// these specs, but a leniently-loaded typed config still flows into this
// fallback):
//   - uint16 narrowing: strconv.Atoi("70000")==70000 and uint16(70000)==4464, so
//     portInSpec(4464,"70000") was true — a real session to port 4464 got labeled
//     as the malformed "70000" app.
//   - signed acceptance: strconv.Atoi("+80")==80, so a "+80" spec matched port 80
//     even though the canonical config parser rejects the signed spelling.
//
// canonicalPort (below) parses bare unsigned digits only and range-checks
// 1..65535, so a malformed spec is DROPPED (never matches / never mislabels)
// consistent with the strict path, the catalog parser, and the NAT parser.
func portInSpec(port uint16, spec string) bool {
	if spec == "" {
		return true
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, ok1 := canonicalPort(parts[0])
		hi, ok2 := canonicalPort(parts[1])
		// A reversed range (lo>hi) can never match any port; reject it here so
		// the fallback fails CLOSED rather than treating garbage bounds as a
		// live constraint (mirrors validatePortSpec's start>end rejection).
		if !ok1 || !ok2 || lo > hi {
			return false
		}
		return port >= lo && port <= hi
	}
	v, ok := canonicalPort(spec)
	return ok && v == port
}

// canonicalPort parses one canonical port token — a bare run of unsigned decimal
// digits, no sign and no surrounding whitespace — and requires it in the valid
// 1..65535 range. It returns ok=false for a signed ("+80"), non-numeric, or
// out-of-range ("70000") token so a malformed spec is dropped rather than
// sign-stripped or uint16-narrowed into a wrong-but-plausible port. This mirrors
// the strict commit gate config.validatePortSpec, which parses through
// config.ParseCanonicalUint and range-checks 1..65535.
func canonicalPort(s string) (uint16, bool) {
	n, err := config.ParseCanonicalUint(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return uint16(n), true
}

// protocolNumber resolves a protocol token for app-id runtime tuple matching.
// #2124: delegates to the centralized ProtocolNumber so this path agrees with
// the policy capability gate and the catalog table on the full named set
// (previously this copy recognized only tcp/udp/icmp/icmpv6/gre by name, so a
// user-defined esp/ah/sctp application could never name-match here). The
// (uint8, bool) contract is preserved.
func protocolNumber(proto string) (uint8, bool) {
	return ProtocolNumber(proto)
}

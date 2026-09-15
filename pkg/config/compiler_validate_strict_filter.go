package config

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// validateFirewallPolicerReferencesStrict hard-rejects a firewall-filter
// term whose `then policer <name>` (Finding A, #2217) references neither a
// defined single-rate policer (`firewall policer <name>`) nor a defined
// three-color-policer (`firewall three-color-policer <name>`).
//
// The schema declares `then policer` with no validator and ValidateConfig
// never checked the reference, so a typo'd / dangling policer name compiled
// cleanly: the term keeps Policer="no-such-policer" and the rate-limit
// silently never applies (fail-OPEN — traffic the operator meant to police
// passes unpoliced). This gate turns that silent fail-open into an operator-
// visible commit error, mirroring the SNAT/DNAT-pool reference family.
//
// Both filter families (inet + inet6) are walked, sorted by filter name then
// by the term's position, so the first-reported error is deterministic across
// runs (Go map order is randomized).
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFirewallRefs) so an already-persisted or peer-synced
// config carrying the typo still BOOTS (#1960 fail-closed-on-load class); the
// dataplane simply does not police the term, exactly as before. Commit /
// commit-check stay strict. Mirrors validateRoutingExportReferencesStrict.
func validateFirewallPolicerReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.Firewall.Policers != nil {
			if _, ok := cfg.Firewall.Policers[name]; ok {
				return true
			}
		}
		if cfg.Firewall.ThreeColorPolicers != nil {
			if _, ok := cfg.Firewall.ThreeColorPolicers[name]; ok {
				return true
			}
		}
		return false
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.Policer == "" || defined(term.Policer) {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q references undefined "+
						"policer %q (define `firewall policer %s` or `firewall "+
						"three-color-policer %s`, or fix the policer name — the "+
						"rate-limit would otherwise silently never apply)",
					family, name, term.Name, term.Policer, term.Policer, term.Policer)
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFirewallTCPFlagsStrict hard-rejects a firewall-filter term whose
// `from tcp-flags <expr>` the conjunctive dataplane matcher cannot enforce —
// a disjunction (`ack | rst`), a negated parenthesized group (a disjunction by
// De Morgan), an unknown flag token, a dangling negation, a
// self-contradictory required/forbidden pair (#3076 / #4714), or an
// operator-only / empty-operand / dangling-`&` expression that sets no flag
// bits (`&`, `()`, `syn &`, `syn && ack`, #5455). Without a reject such an
// expression committed cleanly and the constraint was silently dropped on the
// wire — the term matched regardless of flags (fail-OPEN, a dropped security
// constraint). The gate keys off `ParseTCPFlagsExpression` returning err!=nil;
// the `len(term.TCPFlags) == 0` guard below skips a legitimately-ABSENT value
// (no tcp-flags configured), which is NOT the same as a present-but-malformed
// value that parses to no flag bits.
//
// #4953: this gate is the strict/tolerant home of the #3076 reject that used
// to live inline in compileFirewall (where it could not be mode-gated — the
// section compiler receives no compileOpts). The commit / commit-check path
// hard-rejects; the tolerant load / peer-sync path downgrades to a warning
// (opts.lenientFirewallTCPFlags) so a config an older binary persisted — or a
// peer authored — before this reject existed still BOOTS (#1960 no-brick).
// The leniently-loaded term keeps its raw (unparseable) TCPFlags, which the
// userspace snapshot builder detects (ParseTCPFlagsExpression errors) and marks
// TCPFlagsUnparseable so the Rust filter compiler fails the term CLOSED
// (#3367) — a fail-closed deny sentinel, NEVER a fail-open widening.
//
// Both families (inet + inet6) are walked, sorted by filter name then by term
// position, so the first-reported error is deterministic (Go map order is
// randomized). Mirrors validateFirewallPolicerReferencesStrict.
func validateFirewallTCPFlagsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || len(term.TCPFlags) == 0 {
					continue
				}
				if _, _, _, err := ParseTCPFlagsExpression(term.TCPFlags); err != nil {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: %w",
						family, name, term.Name, err)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFirewallPrefixListReferencesStrict hard-rejects a firewall-filter
// term whose `from source-prefix-list <name>` / `destination-prefix-list
// <name>` (with or without `except`) names a prefix-list not defined under
// `policy-options prefix-list <name>` (#2506).
//
// A dangling prefix-list reference compiled cleanly and the userspace snapshot
// builder contributed NO prefixes for it, so the term reached the dataplane
// with no address scope from that reference — a silent fail-open (accept/PBR
// permits unintended traffic) or fail-closed (discard/reject drops everything),
// action-dependent. This gate makes the typo operator-visible at commit,
// consistent with the policer and routing-instance reference gates.
//
// Both filter families are walked, sorted by filter name then by term position
// for a deterministic first error. On the tolerant load / peer-sync paths the
// call site downgrades to a warning (opts.lenientFirewallRefs) so an already-
// persisted or peer-synced config still BOOTS (#1960); the resolver then
// contributes no prefixes for the unresolved reference. Mirrors
// validateFirewallPolicerReferencesStrict.
func validateFirewallPrefixListReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.PrefixLists == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.PrefixLists[name]
		return ok
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				for _, ref := range term.SourcePrefixLists {
					if defined(ref.Name) {
						continue
					}
					return fmt.Errorf(
						"firewall family %s filter %q term %q references undefined "+
							"source-prefix-list %q (define `policy-options prefix-list "+
							"%s` or fix the name — the address scope would otherwise be "+
							"silently lost)",
						family, name, term.Name, ref.Name, ref.Name)
				}
				for _, ref := range term.DestPrefixLists {
					if defined(ref.Name) {
						continue
					}
					return fmt.Errorf(
						"firewall family %s filter %q term %q references undefined "+
							"destination-prefix-list %q (define `policy-options "+
							"prefix-list %s` or fix the name — the address scope would "+
							"otherwise be silently lost)",
						family, name, term.Name, ref.Name, ref.Name)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFirewallRoutingInstanceReferencesStrict hard-rejects a
// firewall-filter term whose `then routing-instance <name>` (FBF /
// filter-based-forwarding, Finding C, #2217) does not name a routing-instance
// defined under `routing-instances <name>`.
//
// ValidateConfig validated routing-instance INTERFACE membership but never the
// FBF steering reference. A dangling reference compiled with no warning; the
// FBF snapshot carries the unknown instance name and the dataplane steers
// matched packets toward a routing table that does not exist — a silent
// blackhole / fall-through to the default table. This gate makes the typo
// operator-visible at commit, consistent with the other cross-reference gates.
//
// Any defined routing-instance is a valid steer target (Junos FBF accepts
// virtual-router / vrf / forwarding instances alike); the gap closed here is
// strictly the dangling-name case, so instance-type is intentionally not
// constrained.
//
// Both filter families are walked, sorted by filter name then by term position
// for a deterministic first-error. On the tolerant load / peer-sync paths the
// call site downgrades to a warning (opts.lenientFirewallRefs) so an already-
// persisted or peer-synced config still BOOTS (#1960). Mirrors
// validateFirewallPolicerReferencesStrict.
func validateFirewallRoutingInstanceReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			defined[ri.Name] = true
		}
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.RoutingInstance == "" || defined[term.RoutingInstance] {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q references undefined "+
						"routing-instance %q (define `routing-instances %s` or "+
						"fix the name — filter-based-forwarding would otherwise "+
						"steer matched traffic into a routing table that does not "+
						"exist, silently blackholing it or falling through to the "+
						"default table)",
					family, name, term.Name, term.RoutingInstance, term.RoutingInstance)
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFirewallFilterReferencesStrict hard-rejects an interface/unit (and
// lo0) `family inet|inet6 filter input|output <name>` reference that names a
// filter not defined under `firewall family inet|inet6 filter <name>` (#3296).
//
// A dangling filter reference compiled cleanly: ValidateConfig only WARNED
// (`compiler_validate_warn.go`, "filter input %q not defined"), and at runtime
// the userspace filter compiler left the per-interface fast-path map with NO
// entry for the missing key, so the hot path returned the default
// FilterResult — Accept. The security hook was silently disarmed,
// indistinguishable from "no filter configured": a fail-OPEN on a typo'd
// firewall hook (e.g. `filter input WAN-BLOCK` where the defined filter is
// `WAN_BLOCK`). This gate makes the typo an operator-visible commit error,
// consistent with the policer / prefix-list / routing-instance reference
// gates above.
//
// lo0 input/output references are covered for free: lo0 is stored as an
// ordinary interface under `cfg.Interfaces.Interfaces["lo0"]`
// (compiler.go:1819), so the interface walk validates the lo0 host-bound
// filter hooks too.
//
// Interfaces are walked in sorted name order, then by ascending unit number,
// then in a fixed direction order (input-v4, input-v6, output-v4, output-v6),
// so the first-reported error is deterministic across runs (Go map order is
// randomized).
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFirewallRefs) so an already-persisted or peer-synced
// config carrying the typo still BOOTS (#1960 fail-closed-on-load class); the
// userspace helper's own snapshot-integrity backstop then refuses to publish a
// snapshot whose interface references an undefined filter (preserving the
// prior good state rather than degrading the hook to Accept). Commit /
// commit-check stay strict. Mirrors validateFirewallPolicerReferencesStrict.
func validateFirewallFilterReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	inetDefined := func(name string) bool {
		if cfg.Firewall.FiltersInet == nil {
			return false
		}
		_, ok := cfg.Firewall.FiltersInet[name]
		return ok
	}
	inet6Defined := func(name string) bool {
		if cfg.Firewall.FiltersInet6 == nil {
			return false
		}
		_, ok := cfg.Firewall.FiltersInet6[name]
		return ok
	}

	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil { // tolerant/HA-sync path may carry a nil interface (#3494)
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil { // tolerant/HA-sync path may carry a nil unit (#3494)
				continue
			}
			// Fixed direction order for a deterministic first error.
			type ref struct {
				name      string
				family    string
				direction string
				defined   func(string) bool
			}
			for _, r := range []ref{
				{unit.FilterInputV4, "inet", "input", inetDefined},
				{unit.FilterInputV6, "inet6", "input", inet6Defined},
				{unit.FilterOutputV4, "inet", "output", inetDefined},
				{unit.FilterOutputV6, "inet6", "output", inet6Defined},
			} {
				if r.name == "" || r.defined(r.name) {
					continue
				}
				return fmt.Errorf(
					"interface %s unit %d family %s filter %s references "+
						"undefined filter %q (define `firewall family %s "+
						"filter %s` or fix the name — the security hook would "+
						"otherwise be silently disarmed and the interface would "+
						"forward unfiltered, a fail-open on a firewall filter)",
					ifName, unitNum, r.family, r.direction, r.name,
					r.family, r.name)
			}
		}
	}
	return nil
}

// validateFilterRoutingInstanceDirectionStrict hard-rejects an OUTPUT-attached
// firewall filter (`family inet|inet6 filter output <name>`) whose referenced
// filter carries a `then routing-instance <x>` (FBF / filter-based-forwarding)
// term — #3432.
//
// FBF route override is an INGRESS-only operation in the userspace dataplane.
// The forwarding route-override path (ingress_route_table_override /
// interface_filter_affects_route_lookup, userspace-dp/src/afxdp/forwarding/
// mod.rs) resolves the INGRESS logical ifindex and only consults the INPUT
// filter's affects_route_lookup flag; the Rust filter compiler
// (userspace-dp/src/filter/compiler.rs) sets affects_route_lookup ONLY on the
// input attach branch — the output attach branch never sets it. So a
// `then routing-instance` term reached only via an output attach is compiled
// for output evaluation but NEVER influences the route lookup: the configured
// steering action is silently a no-op. Commit accepted it (the reference and
// the discard/reject-conflict gates above check the target name and the
// terminal-action conflict, never the input/output DIRECTION of the
// attachment).
//
// This gate makes the unsupported direction an operator-visible commit error
// rather than a silent no-op, consistent with the other firewall-filter strict
// gates. A filter that carries a routing-instance term is rejected on an
// output attach regardless of which term matches: the operator's intent
// (policy-based forwarding) cannot be honored on egress, and an output filter
// that ALSO does legitimate output work (e.g. count / DSCP rewrite) should not
// silently carry a dead steering action. The same filter remains valid on an
// INPUT attach.
//
// Interfaces are walked in sorted name order, then by ascending unit number,
// then inet before inet6, for a deterministic first error. lo0 is covered for
// free (stored as an ordinary interface under cfg.Interfaces.Interfaces["lo0"]),
// though an output FBF on lo0 is doubly meaningless. On the tolerant load /
// peer-sync path the caller downgrades the error to a warning (#1960 no-brick);
// the runtime already treats the output steering term as inert independently,
// so the config still boots. Mirrors validateFirewallFilterReferencesStrict.
func validateFilterRoutingInstanceDirectionStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// A filter is an FBF filter if any of its terms names a routing-instance.
	hasRoutingInstance := func(filters map[string]*FirewallFilter, name string) bool {
		filter := filters[name]
		if filter == nil {
			return false
		}
		for _, term := range filter.Terms {
			if term != nil && term.RoutingInstance != "" {
				return true
			}
		}
		return false
	}

	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)

	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil { // tolerant/HA-sync path may carry a nil interface (#3494)
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if unit == nil { // tolerant/HA-sync path may carry a nil unit (#3494)
				continue
			}
			type ref struct {
				name    string
				family  string
				filters map[string]*FirewallFilter
			}
			for _, r := range []ref{
				{unit.FilterOutputV4, "inet", cfg.Firewall.FiltersInet},
				{unit.FilterOutputV6, "inet6", cfg.Firewall.FiltersInet6},
			} {
				if r.name == "" || !hasRoutingInstance(r.filters, r.name) {
					continue
				}
				return fmt.Errorf(
					"interface %s unit %d family %s filter output %q has a term "+
						"with `then routing-instance` (filter-based-forwarding), "+
						"which is only supported on an INPUT-attached filter — FBF "+
						"route override is evaluated on ingress, so an output attach "+
						"would silently never steer the traffic; attach this filter "+
						"with `filter input %s` or remove the routing-instance action",
					ifName, unitNum, r.family, r.name, r.name)
			}
		}
	}
	return nil
}

// validateFilterProtocolsStrict hard-rejects any firewall-filter term whose
// `from protocol <token>` is not resolvable by the centralized protocol SSOT
// (#2175) — neither a known protocol name, a junos-* alias, nor a 0..255
// number. It walks every inet and inet6 filter and reports the first offending
// family / filter / term / token (sorted by filter name, then by the term's
// position, so the first-reported error is deterministic across runs).
//
// Resolution goes through filterProtocolResolvable, which INLINE-mirrors the
// acceptance set of appid.ProtocolNumber. The compiler cannot call
// appid.ProtocolNumber directly because pkg/appid imports pkg/config (an import
// cycle) — the same constraint that forces validateApplicationSpecsStrict to
// duplicate appid.CatalogNames's policy-reference walk (#2142). A pkg/appid
// drift-guard test (TestFilterProtocolResolvableMatchesProtocolNumber) asserts
// the two acceptance sets agree via the exported FilterProtocolResolvable
// accessor, so a future change to appid.ProtocolNumber cannot let this copy
// drift silently.
//
// The dataplane compiler (compileFirewallFilters → validateFilterProtocols)
// keeps an identical check as defense-in-depth, but its error is swallowed by
// the daemon (compileErrorMustAbortApply == false): this commit-check gate is
// what makes the refusal operator-visible. On the tolerant load / peer-sync
// path the caller downgrades the returned error to a warning (#1960 no-brick).
func validateFilterProtocolsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				// #2545: protocol is multi-value — every token must resolve.
				for _, proto := range term.Protocols {
					if proto == "" {
						continue
					}
					if !filterProtocolResolvable(proto) {
						return fmt.Errorf(
							"firewall family %s filter %q term %q: unknown protocol %q "+
								"(use a protocol name such as tcp/udp/icmp/icmpv6/gre/esp/ah/"+
								"sctp/ospf or a numeric value 0-255)",
							family, name, term.Name, proto)
					}
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// firstIncompatibleProtocol returns the first NON-EMPTY protocol token in a
// firewall-filter term's protocol list for which pred returns false, plus true;
// or ("", false) when every present token satisfies pred (or none is present).
// Empty / whitespace-only tokens are skipped — they are placeholders, not a real
// protocol constraint (mirroring validateFilterProtocolsStrict). Because it
// reports the FIRST failing token, a mixed bracket list such as
// `from protocol [ tcp gre ]` is rejected on `gre` (the #3723 M01 partial-
// enforce case: one configured deny that only enforces on the compatible
// protocol and silently never-matches the rest).
func firstIncompatibleProtocol(protocols []string, pred func(string) bool) (string, bool) {
	for _, p := range protocols {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if !pred(p) {
			return p, true
		}
	}
	return "", false
}

// validateFilterCrossFieldStrict hard-rejects any firewall-filter term whose
// `from` block combines a protocol-specific L4 predicate with a `protocol`
// (or the inet6 `next-header`) that cannot carry it — the stateless-filter
// mirror of the application cross-field gate #3373/#3348 in
// validateApplicationSpecsStrict. #3723 (codex-review-154 H01/H02/H03/M01/M02/M03).
//
// The firewall-filter matcher (userspace-dp engine/matching.rs) keys each L4
// predicate on the packet's actual L4 shape:
//
//   - port_match tests the constrained port set against the extracted L4 port,
//     which is 0 for every protocol the dataplane does not extract ports for
//     (only TCP/UDP — ip_proto.rs has_l4_ports); so `from protocol gre;
//     destination-port 80` can NEVER match (H01);
//   - per_packet_l4_matches returns false for a tcp-flags term whenever the
//     packet protocol is not TCP, so `from protocol udp; tcp-flags syn` can
//     never match (H02);
//   - the icmp-type / icmp-code arms return false for a non-ICMP(v6) packet, so
//     `from protocol tcp; icmp-type echo-request` can never match (H03).
//
// A never-match term is a SILENT FAIL-OPEN for a `then discard` / `then reject`:
// an xpf filter falls through to an implicit ACCEPT on no-match (the #3427
// no-catchall class), so the drop the operator wrote is dead and the traffic is
// admitted by a later permit or the implicit accept. Junos rejects these
// cross-field combinations at commit, so accepting them is also a config-language
// parity gap — xpf can express a term the dataplane cannot faithfully enforce.
//
// The gate reuses the same protocolIsPortBearing / protocolIsICMPFamily SSOT the
// application gate uses (plus protocolIsTCP for the tcp-flags arm), so the two
// compatibility gates stay aligned (the TestApplicationAndFilterCrossFieldGates-
// UseSharedSSOT canary pins that). It fires only when a protocol is PRESENT: a
// port / tcp-flags / icmp match with NO protocol is legitimate and enforceable
// for a FILTER (unlike an application, whose matcher keys on protocol+port, a
// filter matches the port on whatever L4-port-bearing packet arrives and the
// tcp-flags/icmp arms self-gate on the packet protocol). next-header (the inet6
// spelling) is covered because compileFilterFrom routes BOTH protocol and
// next-header into term.Protocols (M02).
//
// The one exception that fires WITHOUT a protocol is icmp-code without
// icmp-type (M03): the matcher constrains the code independently of the type, so
// a code-only term matches a broader ICMP set than a Junos config implies
// (icmp-code 0 is common across many types). Junos couples code to type, and the
// application gate rejects the same shape (#3506), so mirror it here.
//
// The walk is deterministic (filters sorted by name, terms in config order) so
// the first-reported error is stable across runs, matching the other filter
// strict gates. On the tolerant load / peer-sync path the caller downgrades the
// returned error to a warning (#1960 no-brick); the Rust snapshot builder's
// UnsatisfiableFilterCrossField backstop then fails the whole snapshot closed so
// a leniently-loaded never-match term never silently forwards.
func validateFilterCrossFieldStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				// H01 / M01 / M02: a source-port / destination-port match (or the
				// negated *-except lists) requires a port-bearing transport
				// (TCP/UDP). If ANY protocol token is non-port-bearing the term is a
				// never-match on that protocol.
				hasPorts := len(term.SourcePorts) > 0 || len(term.DestinationPorts) > 0 ||
					len(term.SourcePortsExcept) > 0 || len(term.DestPortsExcept) > 0
				if hasPorts {
					if proto, bad := firstIncompatibleProtocol(term.Protocols, protocolIsPortBearing); bad {
						return fmt.Errorf(
							"firewall family %s filter %q term %q: a source-port/destination-port "+
								"match is set with protocol %q, which does not carry L4 ports — "+
								"source-port/destination-port are valid only on tcp/udp (the "+
								"dataplane keys port terms on the packet's ports, which are always 0 "+
								"for a non-port protocol, so the term would never match; a "+
								"`then discard`/`reject` then fails OPEN. Remove the port or change "+
								"the protocol)",
							family, name, term.Name, proto)
					}
				}
				// H02: a tcp-flags match requires TCP. If ANY protocol token is not
				// TCP the term is a never-match on that protocol.
				if len(term.TCPFlags) > 0 {
					if proto, bad := firstIncompatibleProtocol(term.Protocols, protocolIsTCP); bad {
						return fmt.Errorf(
							"firewall family %s filter %q term %q: a tcp-flags match is set with "+
								"protocol %q, which is not TCP — tcp-flags is valid only on tcp (the "+
								"dataplane matches tcp-flags only when the packet protocol is TCP, so "+
								"the term would never match; a `then discard`/`reject` then fails "+
								"OPEN. Remove tcp-flags or set protocol tcp)",
							family, name, term.Name, proto)
					}
				}
				// H03: an icmp-type / icmp-code match requires ICMP/ICMPv6. If ANY
				// protocol token is not an ICMP protocol the term is a never-match on
				// that protocol.
				if len(term.ICMPTypes) > 0 || len(term.ICMPCodes) > 0 {
					if proto, bad := firstIncompatibleProtocol(term.Protocols, protocolIsICMPFamily); bad {
						return fmt.Errorf(
							"firewall family %s filter %q term %q: an icmp-type/icmp-code match is "+
								"set with protocol %q, which is not an ICMP protocol — icmp-type/"+
								"icmp-code are valid only on icmp/icmpv6 (the dataplane matches them "+
								"only when the packet is ICMP/ICMPv6, so the term would never match; a "+
								"`then discard`/`reject` then fails OPEN. Remove the constraint or set "+
								"protocol icmp/icmpv6)",
							family, name, term.Name, proto)
					}
				}
				// M03: an icmp-code with no icmp-type constrains the code while the
				// type stays unconstrained — a code-only term matches a broader ICMP
				// set than a Junos config implies (icmp-code 0 is common across many
				// types). Junos couples code to type; the application gate rejects the
				// same shape (#3506). Mirror it here.
				if len(term.ICMPCodes) > 0 && len(term.ICMPTypes) == 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: icmp-code is set without "+
							"icmp-type; an ICMP code is meaningful only together with a type "+
							"(icmp-code 0 is common across many types, so a code-only match is "+
							"broader than a Junos config implies). Set icmp-type as well, or "+
							"remove icmp-code",
						family, name, term.Name)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterActionsStrict hard-rejects any firewall-filter term whose
// `then` block carries a token that is neither a recognized terminating action
// (accept/reject/discard) nor a recognized modifier (count/log/syslog/
// forwarding-class/loss-priority/dscp/traffic-class/policer/routing-instance)
// — #2399 finding 032-16.
//
// Before this gate, compileFilterThen silently DROPPED an unrecognized or
// misspelled `then` token. The term's Action stayed "", which the dataplane
// compiler (pkg/dataplane/compiler_filter.go) and the Rust filter
// (userspace-dp/src/filter/compiler.rs parse_term) BOTH map to
// FilterAction::Accept — a fail-open permit. An operator who typed `then
// frobnicate` (or a future action a peer node understands) got an ACCEPT for a
// filter term they intended to deny. In Junos an unknown filter action is a
// commit error, so the safe behavior is fail-CLOSED: refuse the commit and
// name the offending token rather than silently permit.
//
// The walk is deterministic (filters sorted by name, terms in config order)
// so the first-reported error is stable across runs, matching
// validateFilterProtocolsStrict. On the tolerant load / peer-sync path the
// caller downgrades the returned error to a warning (#1960 no-brick); the
// dataplane still has no representation for the unknown token, so the
// leniently-loaded term defaults to accept independently — but the operator
// never reaches that state through a commit.
func validateFilterActionsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || len(term.UnknownActions) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q: unknown `then` action %q "+
						"(use accept/reject/discard/next-term or a modifier such as "+
						"count/log/syslog/forwarding-class/loss-priority/dscp/"+
						"traffic-class/policer/routing-instance)",
					family, name, term.Name, term.UnknownActions[0])
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// warnFilterTermExpansionOverBound appends an ADVISORY warning (never a hard
// reject) for each firewall-filter term whose rule cross-product — (literal
// source addresses + every source-prefix-list prefix) × (literal destination
// addresses + every destination-prefix-list prefix) × destination-ports ×
// source-ports — exceeds MaxFilterTermExpansion (#5456).
//
// This is deliberately NOT a strict commit gate. The cross-product and its
// uint32 counter-slot stride are RETIRED-eBPF-path artifacts: the LIVE userspace
// dataplane enforces the term natively (prefix-set membership, name-keyed
// per-term counters — FirewallFilterTermCounterKey), never materializes the
// cross-product, and is immune to stride drift. A term referencing, say, two
// 1500-entry prefix-lists (2.25M cross-product) is handled trivially by the live
// runtime, so REJECTING it at commit would false-reject a legitimate,
// enforceable config. The real defect #5456 fixes is the silent uint32
// truncation, already closed by FilterTermExpansionCount computing the product
// in checked uint64 and CLAMPING the stride (and expandFilterTerm's materialized
// slice) to MaxFilterTermExpansion — the wrap can no longer occur.
//
// The warning exists only to tell the operator that, ON THE RETIRED-eBPF
// per-rule counter path (unused on this build), such a term's per-rule
// `show firewall filter` counts would be clamped and therefore inexact. Both
// families are walked, sorted by filter name then by the term's position, so the
// warnings are emitted deterministically (Go map order is randomized).
func warnFilterTermExpansionOverBound(cfg *Config) {
	if cfg == nil {
		return
	}
	prefixLists := cfg.PolicyOptions.PrefixLists
	emit := func(family string, filters map[string]*FirewallFilter) {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				count := FilterTermExpansionCount64(term, prefixLists)
				if count > MaxFilterTermExpansion {
					cfg.Warnings = append(cfg.Warnings, fmt.Sprintf(
						"firewall family %s filter %q term %q expands to %d match "+
							"combinations (source-addresses+prefixes × destination-"+
							"addresses+prefixes × destination-ports × source-ports), "+
							"above the %d per-term counter-stride bound; the userspace "+
							"dataplane enforces this term natively (prefix-set membership, "+
							"name-keyed counter) so it is COMMITTED, but per-rule "+
							"`show firewall filter` counts on the retired-eBPF counter "+
							"path would be clamped/inexact — split the term if you rely "+
							"on per-rule firewall counters",
						family, name, term.Name, count, MaxFilterTermExpansion))
				}
			}
		}
	}
	emit("inet", cfg.Firewall.FiltersInet)
	emit("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterMatchValuesStrict hard-rejects any firewall-filter term that
// carries a SYMBOLIC match value (icmp-type / icmp-code name or a named port)
// the compiler could not resolve to a number — #3205 (agy-070 #07/#08).
//
// Before this gate the compiler silently dropped an unresolved symbolic value:
//
//   - an unresolved icmp-type left ICMPTypes empty, which means "match ANY
//     ICMP" — a term meant to narrow to one type (e.g. `then accept` of
//     echo-request only) silently permitted every ICMP type (policy bypass);
//   - an unresolved named port left the port set constrained-but-empty, and a
//     `*-port-except` term then matched ALL ports — it accepted the very port
//     it was meant to exclude (fail open).
//
// compileFilterFrom records each unresolved token on the term (UnknownICMPTypes
// / UnknownICMPCodes / UnknownPorts, mirroring UnknownActions); this gate is
// what makes the refusal operator-visible at commit. The walk is deterministic
// (filters sorted by name, terms in config order). On the tolerant load /
// peer-sync path the caller downgrades the returned error to a warning (#1960
// no-brick); the unresolved token is kept verbatim on the wire so the dataplane
// fails CLOSED (constrained-but-unparseable) independently.
func validateFilterMatchValuesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				if len(term.UnknownICMPTypes) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown icmp-type %q "+
							"(use a numeric value 0-255 or a Junos icmp-type name such as "+
							"echo-request/echo-reply/destination-unreachable/time-exceeded)",
						family, name, term.Name, term.UnknownICMPTypes[0])
				}
				if len(term.UnknownICMPCodes) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown icmp-code %q "+
							"(use a numeric value 0-255)",
						family, name, term.Name, term.UnknownICMPCodes[0])
				}
				if len(term.UnknownPorts) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown port %q "+
							"(use a numeric port 1-65535, a `low-high` range, or a Junos "+
							"service name such as ssh/http/https/domain)",
						family, name, term.Name, term.UnknownPorts[0])
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterFlexMatchStrict hard-rejects any firewall-filter term whose
// `from flexible-match-range` carries a numeric token (byte-offset / bit-length
// / match-value / match-mask) the compiler could not parse or that fell outside
// the representable range — #3203 (agy-070 #02/#03/#04).
//
// Before this gate compileFilterFrom IGNORED the strconv error on each of these
// fields, leaving the offending value at its zero default. A malformed or
// >32-bit match-value silently became 0x0 and the rule then matched value 0
// instead of the intended pattern; an out-of-range bit-length truncated through
// an unchecked uint8() cast (999 -> 231). The commit succeeded cleanly, so the
// operator never saw the misclassification — a security-policy correctness gap.
//
// compileFilterFrom now records each unparseable/out-of-range token on the term
// (UnknownFlexMatch, mirroring UnknownActions); this gate makes the refusal
// operator-visible at commit. The walk is deterministic (filters sorted by name,
// terms in config order). On the tolerant load / peer-sync path the caller
// downgrades the returned error to a warning (#1960 no-brick).
func validateFilterFlexMatchStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				// #5823: a term may name at most ONE flexible-match-range range
				// (the wire matcher supports one). More than one is a cardinality
				// violation the pre-fix compiler silently collapsed to the first
				// range — an accept term then over-permitted, a discard/reject
				// over-dropped. Reject deterministically, naming every range so
				// the operator knows exactly what to split into separate terms.
				if len(term.FlexMatchRangeNames) > 1 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: flexible-match-range "+
							"specifies %d ranges (%s) but at most one range per term "+
							"is supported; split the extra ranges into separate terms",
						family, name, term.Name,
						len(term.FlexMatchRangeNames),
						strings.Join(term.FlexMatchRangeNames, ", "))
				}
				if len(term.UnknownFlexMatch) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q: invalid "+
						"flexible-match-range %q (byte-offset 0-255, bit-length "+
						"1-32, match-value/match-mask a hex value up to "+
						"0xFFFFFFFF, match-start layer-3 or layer-4)",
					family, name, term.Name, term.UnknownFlexMatch[0])
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterPortExceptStrict hard-rejects any firewall-filter term that
// carries BOTH a positive port match and the negated `*-port-except` list in
// the SAME direction — #3297.
//
// Junos treats `source-port` / `destination-port` and their
// `source-port-except` / `destination-port-except` counterparts as mutually
// exclusive match families and rejects a term carrying both at commit. xpf's
// parser, however, lands the positive list on term.SourcePorts /
// term.DestinationPorts and the negated list on term.SourcePortsExcept /
// term.DestPortsExcept (compileFilterFrom), so both can coexist on one term.
//
// The Rust matcher (userspace-dp filter/compiler.rs) resolves the ambiguity
// deterministically as positive-wins (the positive list builds the matcher and
// the except list is ignored). That is fail-safe at runtime — the configured
// positive scope is honored, no traffic leaks — but it silently accepts a
// Junos-invalid term and discards one side of the operator's intent. This gate
// makes the conflict an operator-visible commit error instead.
//
// The walk is deterministic (filters sorted by name, terms in config order).
// On the tolerant load / peer-sync path the caller downgrades the returned
// error to a warning (#1960 no-brick); the dataplane's positive-wins fallback
// keeps that direction fail-safe independently.
func validateFilterPortExceptStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				if len(term.SourcePorts) > 0 && len(term.SourcePortsExcept) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: `from source-port` and "+
							"`from source-port-except` are mutually exclusive in the same "+
							"term (Junos rejects this; remove one)",
						family, name, term.Name)
				}
				if len(term.DestinationPorts) > 0 && len(term.DestPortsExcept) > 0 {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: `from destination-port` and "+
							"`from destination-port-except` are mutually exclusive in the same "+
							"term (Junos rejects this; remove one)",
						family, name, term.Name)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterAddressExceptStrict hard-rejects any firewall-filter term that
// mixes a SPECIFIC positive address match (a non-match-any literal
// `source-address`/`destination-address` OR a non-except
// `source-prefix-list`/`destination-prefix-list`) with an `except` prefix-list
// in the SAME direction — #3359, relaxed for the match-any case in #4338.
//
// The mixed SPECIFIC-positive + except shape has no faithful single-term
// representation in xpf's boolean-inversion matcher (one direction would need
// both a positive set AND a negated set), so it is rejected. xpf's parser lands
// literal addresses on term.SourceAddresses / term.DestAddresses and prefix-list
// references (positive AND except) on term.SourcePrefixLists /
// term.DestPrefixLists (compileFilterFrom), so a positive set and an except set
// can coexist on one direction of one term.
//
// #4338 (match-any composes): the canonical Junos lockdown idiom `from {
// source-address 0.0.0.0/0; source-prefix-list mgmt except; }` (match any source
// EXCEPT the management prefixes, then reject) is ACCEPTED by Junos and is NOT
// rejected here. A match-any positive (`0.0.0.0/0` / `::/0` / `any`) does not
// constrain the positive set, so `any AND NOT X` reduces exactly to the
// sole-`except` representation ("any address not in X"). The runtime lowering
// (ResolveFilterPrefixListAddrs) drops the redundant match-any universe and
// emits the term as `except=true` over X, so the compiled semantics match the
// operator's intent. Pre-#4338 this idiom was rejected with an error that
// wrongly claimed "Junos rejects this" (false for the 0/0+except shape).
//
// The userspace lowering (pkg/dataplane/userspace/filters.go
// resolvePrefixListAddrs) has no single boolean-inversion representation for the
// mixed shape — one direction would need both a positive set and a negated set.
// Before this gate it FOLDED the except prefixes into the positive match set
// (dropping the `except` modifier) and only emitted a runtime slog.Warn. That
// fold is a silent fail-OPEN on a stateless drop path: for a `discard`/`reject`
// term the operator's `(positive) AND NOT (except)` (or `NOT(except)`) intent
// collapses to a plain positive match, and traffic the operator meant to drop
// via the except carve-out is no longer dropped. For an `accept` term the fold
// is also fail-open in the other direction — it ADMITS the except prefixes the
// operator wrote to exclude. The runtime fold is now changed to positive-wins
// (the except side is ignored, never folded in) so a leniently-loaded term is
// fail-safe; this gate makes the conflict an operator-visible commit error so
// the term is split into faithful per-direction terms instead.
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to
// a warning (#1960 no-brick); the dataplane's positive-wins fallback keeps that
// direction fail-safe independently. Mirrors validateFilterPortExceptStrict
// (#3297, the port-match sibling of this address-match case).
func validateFilterAddressExceptStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// hasExcept reports whether any prefix-list ref in the direction carries the
	// `except` modifier; hasPositiveRef whether any ref is a plain (non-except)
	// reference.
	hasExcept := func(refs []PrefixListRef) bool {
		for _, ref := range refs {
			if ref.Except {
				return true
			}
		}
		return false
	}
	hasPositiveRef := func(refs []PrefixListRef) bool {
		for _, ref := range refs {
			if !ref.Except {
				return true
			}
		}
		return false
	}
	// hasSpecificAddr reports whether the literal address list carries a
	// CONSTRAINING positive match — i.e. any literal that is NOT the match-any
	// universe. A match-any literal (`0.0.0.0/0`, `::/0`, or the `any` / empty
	// placeholder) does NOT constrain the positive set, so it COMPOSES with an
	// `except` prefix-list rather than conflicting with it (#4338): the term
	// `source-address 0.0.0.0/0; source-prefix-list X except;` is the canonical
	// Junos "match any EXCEPT the listed prefixes" lockdown idiom, which lowers
	// cleanly to the sole-`except` representation (the universe AND-NOT X = "any
	// address not in X"). Only a SPECIFIC positive literal (e.g. 10.0.0.0/8)
	// alongside an except list is a genuine conflict — it would require both a
	// positive set and a negated set in one direction, which the boolean-
	// inversion matcher cannot represent, so that shape stays rejected.
	hasSpecificAddr := func(addrs []string) bool {
		for _, a := range addrs {
			if a == "" || a == "any" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(a)
			if err != nil {
				// Not a parseable CIDR — a malformed literal is caught by
				// validateFilterAddressLiteralsStrict; treat it as specific
				// (constraining) here so this gate never masks it.
				return true
			}
			if ones, _ := ipnet.Mask.Size(); ones != 0 {
				return true
			}
		}
		return false
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				srcPositive := hasSpecificAddr(term.SourceAddresses) || hasPositiveRef(term.SourcePrefixLists)
				if srcPositive && hasExcept(term.SourcePrefixLists) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: a SPECIFIC positive "+
							"source address match (a non-match-any `from source-address` "+
							"or a non-except `from source-prefix-list`) and an `except` "+
							"source-prefix-list have no faithful single-term "+
							"representation in xpf (the direction would need both a "+
							"positive and a negated set) and would fail open for "+
							"discard/reject; split into separate terms. A match-any "+
							"`from source-address 0.0.0.0/0`/`::/0` combined with an "+
							"`except` source-prefix-list IS accepted — it composes to "+
							"\"any source except the listed prefixes\"",
						family, name, term.Name)
				}
				dstPositive := hasSpecificAddr(term.DestAddresses) || hasPositiveRef(term.DestPrefixLists)
				if dstPositive && hasExcept(term.DestPrefixLists) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: a SPECIFIC positive "+
							"destination address match (a non-match-any `from "+
							"destination-address` or a non-except `from "+
							"destination-prefix-list`) and an `except` "+
							"destination-prefix-list have no faithful single-term "+
							"representation in xpf (the direction would need both a "+
							"positive and a negated set) and would fail open for "+
							"discard/reject; split into separate terms. A match-any "+
							"`from destination-address 0.0.0.0/0`/`::/0` combined with "+
							"an `except` destination-prefix-list IS accepted — it "+
							"composes to \"any destination except the listed prefixes\"",
						family, name, term.Name)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterAddressLiteralsStrict hard-rejects any firewall-filter term
// whose literal `from source-address` / `destination-address` carries a MALFORMED
// token or an address of the WRONG family for the filter — #3433 (codex audit 094
// H02/H09).
//
// The firewall-filter address leaves were untyped at commit:
// validateFilterMatchValuesStrict checks only icmp-type/icmp-code/named-ports and
// validateFilterFromMatchStrict only rejects unimplemented `from` leaves, so a
// malformed CIDR (`10.0.0.0/99`) or a wrong-family literal (a v4 CIDR under
// `family inet6`) reached the lowering verbatim. In the kernel lo0 mirror it then
// emitted invalid nft (`ip6 saddr 10.0.0.0/24`, `ip saddr 10.0.0.0/99`) that
// failed the atomic `nft -f -` load — breaking a legitimate commit, or on the
// lenient/peer-sync path leaving the kernel mirror ABSENT while userspace stayed
// armed (a host-protection divergence). The userspace matcher dropped the bad
// token at parse time and, because the direction was still constrained, fell
// CLOSED (match nothing); the kernel mirror could not. This gate makes the bad
// token an operator-visible commit error so the two enforcement paths converge on
// a clean config.
//
// `any` and the empty string are NO-CONSTRAINT placeholders (the userspace
// matcher's addr_is_real / parse_address drop them); they are NOT malformed and
// are accepted here. Prefix-list references are NOT validated for family — a
// prefix-list may legitimately carry both families and the matcher only consults
// the chain's family vector, so a cross-family prefix in a list is harmless (the
// empty-resolution / unresolved cases are covered by #2506 + the existing
// validateFirewallPrefixListReferencesStrict gate).
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to a
// warning (#1960 no-brick); the lowering's defensive family-filter (#3433,
// nftFamilyAddrs) and the userspace matcher both fail closed for the bad token
// independently, so a leniently-loaded config still enforces fail-safe. Mirrors
// validateFilterFromMatchStrict.
func validateFilterAddressLiteralsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		wantV6 := family == "inet6"
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				for _, side := range []struct {
					leaf  string
					addrs []string
				}{
					{"source-address", term.SourceAddresses},
					{"destination-address", term.DestAddresses},
				} {
					for _, a := range side.addrs {
						// `any` / empty are no-constraint placeholders, not literals.
						if a == "" || a == "any" {
							continue
						}
						isV6, ok := classifyFilterAddrFamily(a)
						if !ok {
							return fmt.Errorf(
								"firewall family %s filter %q term %q: malformed `from %s` "+
									"value %q (use a valid IPv%s address or CIDR prefix)",
								family, name, term.Name, side.leaf, a,
								map[bool]string{false: "4", true: "6"}[wantV6])
						}
						if isV6 != wantV6 {
							return fmt.Errorf(
								"firewall family %s filter %q term %q: `from %s` value %q is "+
									"the wrong address family (an inet filter takes IPv4, an "+
									"inet6 filter takes IPv6); it would emit unloadable nft and "+
									"match nothing in the dataplane",
								family, name, term.Name, side.leaf, a)
						}
					}
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// classifyFilterAddrFamily reports whether a literal firewall-filter address is
// IPv6 (isV6) and whether it parsed at all (ok), accepting both a CIDR prefix
// (10.0.0.0/24) and a bare host IP (10.0.0.1 -> /32, ::1 -> /128) — exactly the
// forms the userspace matcher's parse_address accepts.
func classifyFilterAddrFamily(a string) (isV6 bool, ok bool) {
	if pfx, err := netip.ParsePrefix(a); err == nil {
		return pfx.Addr().Is6(), true
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		return ip.Is6(), true
	}
	return false, false
}

// validateFilterFromMatchStrict hard-rejects any firewall-filter term whose
// `from` block carries a match leaf the dataplane does NOT enforce — #3307.
//
// The schema gate is opt-in (schema_walk.go: an unknown keyword resolves to a
// nil schema child and returns no error), and compileFilterFrom's switch had no
// default arm, so a `from` leaf the matcher does not implement (ttl,
// source-mac-address, ip-options, fragment-offset, hop-limit, ...) committed
// cleanly and was silently DROPPED from the compiled term. The resulting term
// then enforced a BROADER match than the operator authored: a less-constrained
// `accept` term permits MORE than intended (fail open) and a less-constrained
// `discard`/`reject` term drops MORE than intended (over-drop). The operator
// saw neither a commit error nor an apply error — a vSRX/SRX-imported filter
// could carry a supported-looking but unimplemented match condition and enforce
// silently-wrong.
//
// The enforced set is EXACTLY the compileFilterFrom switch cases: every one
// maps to a wire field the snapshot builder emits (pkg/dataplane/userspace/
// filters.go) and the Rust matcher evaluates (userspace-dp/src/filter/engine).
// `next-header` is IN that enforced set — it is the IPv6 alias for `protocol`
// (compileFilterFrom routes it to term.Protocols), so it is NOT one of the
// rejected unenforced leaves despite not having its own typed field.
// compileFilterFrom's default arm records every other leaf on the term
// (UnknownFrom, mirroring UnknownActions / UnknownFlexMatch); this gate makes
// the refusal operator-visible at commit. No NEW matching is implemented — the
// unsupported leaf is rejected, which is the fail-closed-correct outcome (a
// constraint is never silently dropped). The walk is deterministic (filters
// sorted by name, terms in config order). On the tolerant load / peer-sync path
// the caller downgrades the returned error to a warning (#1960 no-brick); the
// dataplane never represented the leaf, so a leniently-loaded term keeps
// matching without that constraint independently — but the operator never
// reaches that state through a commit. Mirrors validateFilterActionsStrict.
func validateFilterFromMatchStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || len(term.UnknownFrom) == 0 {
					continue
				}
				return fmt.Errorf(
					"firewall family %s filter %q term %q: `from %s` is not enforced "+
						"by the dataplane (the constraint would be silently dropped, "+
						"so the term would match more broadly than authored — an "+
						"accept over-permits, a discard/reject over-drops); remove it "+
						"or use a supported match such as source-address/"+
						"destination-address/protocol/next-header/source-port/"+
						"destination-port/dscp/traffic-class/icmp-type/icmp-code/"+
						"tcp-flags/is-fragment/flexible-match-range",
					family, name, term.Name, term.UnknownFrom[0])
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterRoutingInstanceConflictStrict hard-rejects a firewall-filter
// term that co-locates `then routing-instance <x>` with a terminating
// `then discard` / `then reject` — #3308.
//
// Such a term is contradictory: it asks the dataplane to BOTH route the packet
// via the named instance AND drop/reject it. Historically there was no
// commit-time mutual-exclusion gate AND both forwarding paths honored the steer
// while only logging the deny — a fail-open PBR whose audit trail lied. Both
// paths now resolve the contradiction to the DENY: the userspace PBR runtime
// (ingress_route_table_override, userspace-dp/src/afxdp/forwarding/mod.rs)
// returns RouteOverride::Drop for a reject/discard term (#4392), and the kernel
// `ip rule` mirror (buildPBRFromFilter, pkg/routing/rules.go) skips the steering
// rule (#4534). This gate keeps the operator from authoring the contradiction at
// commit; on the tolerant load / peer-sync path it warns and both runtimes drop
// the term independently.
//
// The conflict is on the typed fields term.RoutingInstance (the
// `then routing-instance` value) and term.Action ("discard" / "reject", set by
// compileFilterThen). A routing-instance term with `then accept` (or no terminal
// action) is the legitimate filter-based-forwarding case and is NOT rejected.
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to
// a warning (#1960 no-brick); the runtime already routes-and-mislogs such a term
// independently, but the operator never reaches that state through a commit.
// Mirrors validateFilterPortExceptStrict.
func validateFilterRoutingInstanceConflictStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil || term.RoutingInstance == "" {
					continue
				}
				if term.Action == "discard" || term.Action == "reject" {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: `then routing-instance "+
							"%s` and `then %s` are mutually exclusive in the same term — "+
							"the dataplane would still route the packet via the named "+
							"instance while logging it as denied (the audit trail would "+
							"lie); keep only the routing-instance or only the discard/"+
							"reject",
						family, name, term.Name, term.RoutingInstance, term.Action)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterTerminalConflictStrict hard-rejects a firewall-filter term that
// specifies more than one DISTINCT terminating action (accept / reject /
// discard) — #4375 (avo-review-007 H3).
//
// Junos treats accept/reject/discard as mutually exclusive: a term has exactly
// ONE terminating action. xpf stores the action on the single-valued field
// term.Action, which compileFilterThen overwrites last-write-wins, so a term
// with `then accept` AND `then reject` (whether in one `then {}` block or across
// two — #3850 applies every block) silently compiled to whichever keyword came
// last. The operator's intent was ambiguous and the compiled behavior did not
// necessarily match what they wrote — a silent misconfiguration.
//
// compileFilterThen now records every terminating keyword it sees on
// term.TerminalActions (in order, with duplicates). This gate reports the
// conflict when the term carries more than one DISTINCT terminal. Repeating the
// SAME terminal (e.g. two `then discard` blocks) is a redundancy, not a
// conflict, and is allowed. The non-terminating modifiers (count/log/
// forwarding-class/loss-priority/dscp/traffic-class/policer) are not terminals
// and coexist with a terminal — a term with `then count X accept` is valid.
//
// `then routing-instance <x>` is NOT one of them. It is a TERMINATING
// (filter-based-forwarding) action: the term takes its own forwarding decision
// and both runtimes terminate on it — the Rust evaluator sets
// `continue_term: snap.action.is_empty() && snap.routing_instance.is_empty()`
// (userspace-dp/src/filter/compiler.rs) and resolves the empty action to
// Accept, and the kernel lo0 nft mirror emits a terminating `accept`
// (nftRulesFromTerm, pkg/daemon/daemon_nft_term_lower.go;
// nftLo0RulesFromTerm, pkg/nftables/netlink_lo0.go). It is simply not recorded
// on term.TerminalActions, because that slice carries only the accept/reject/
// discard KEYWORDS. #9140 corrects this comment, which previously listed
// routing-instance among the non-terminating modifiers — the misreading that
// let the next-term contradiction below through. (`then routing-instance`
// co-located with an explicit terminating discard/reject is a separate
// contradiction handled by validateFilterRoutingInstanceConflictStrict, #3308;
// co-located with `then accept` it is the legitimate FBF case and stays legal.)
//
// The walk is deterministic (filters sorted by name, terms in config order) so
// the first-reported error is stable across runs. On the tolerant load /
// peer-sync path the caller downgrades the returned error to a warning (#1960
// no-brick); the last-wins term.Action still drives the dataplane, so a
// leniently-loaded contradictory term forwards deterministically — but the
// operator never reaches that state through a commit. Mirrors
// validateFilterRoutingInstanceConflictStrict.
func validateFilterTerminalConflictStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				// #4375: reject MORE THAN ONE distinct terminating action.
				if len(term.TerminalActions) >= 2 {
					// Collect distinct terminals in first-seen order so the
					// error is stable and reads in the order the operator
					// wrote them.
					seen := make(map[string]bool, len(term.TerminalActions))
					distinct := make([]string, 0, len(term.TerminalActions))
					for _, a := range term.TerminalActions {
						if !seen[a] {
							seen[a] = true
							distinct = append(distinct, a)
						}
					}
					if len(distinct) > 1 {
						return fmt.Errorf(
							"firewall family %s filter %q term %q: conflicting "+
								"terminating actions %s — a term may have at most one "+
								"terminating action (accept/reject/discard are mutually "+
								"exclusive)",
							family, name, term.Name, strings.Join(distinct, " and "))
					}
				}
				// #5142 (security, fail-CLOSED): a SINGLE terminating action
				// (discard/reject/accept) co-located with `then next term` is a
				// contradiction — the terminal must apply its action, but
				// next-term asks to fall through. A fall-through bit must NEVER
				// suppress a parsed terminal (vSRX filter semantics). Before
				// #5142 the loop skipped every term with fewer than two
				// terminals, so `then discard; then next term;` committed and
				// (on the runtime) fell through, leaving the implicit Accept in
				// place — the deny was silently dropped (fail-OPEN). Reject the
				// contradiction here, naming the filter+term. A modifier-only
				// next-term term (no terminating action) is a VALID fall-through
				// (#2544/#3427) and is left untouched.
				//
				// #9140 extends the same invariant to `then routing-instance
				// <x>`, which is a TERMINATING filter-based-forwarding action
				// that compileFilterThen records on term.RoutingInstance rather
				// than on term.TerminalActions. Because the gate read only
				// TerminalActions, `then { routing-instance mgmt-vrf; next
				// term; }` committed cleanly and then rendered a TERMINATING
				// accept in BOTH runtimes (continue_term is false when the
				// routing-instance is set, and the empty action resolves to
				// Accept), so every later term — including an SSH deny — went
				// dead for the term's whole match set. That is the #5142
				// fail-open shape reached through a different field. The
				// runtimes are NOT the bug here and must not be changed: they
				// agree with each other, and diverging the nft mirror from the
				// Rust evaluator would break the mirror contract stated at
				// daemon_nft_term_lower.go. The bug is that the operator was
				// allowed to author the contradiction at all.
				terminal := ""
				switch {
				case len(term.TerminalActions) > 0:
					terminal = term.TerminalActions[0]
				case term.RoutingInstance != "":
					terminal = "routing-instance " + term.RoutingInstance
				}
				if term.NextTerm && terminal != "" {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: terminating "+
							"action %q cannot be combined with `then next term` — "+
							"a terminating action (accept/reject/discard, and "+
							"`routing-instance`, which takes its own forwarding "+
							"decision) always terminates and must not fall through "+
							"to the next term (remove one)",
						family, name, term.Name, terminal)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// validateFilterDSCPStrict hard-rejects a firewall-filter term whose
// `from dscp` / `from traffic-class` MATCH token or `then dscp` /
// `then traffic-class` REWRITE token is neither a known DSCP code-point name nor
// an integer in 0..63 — #3309.
//
// Before this gate the compiler appended the raw token to term.DSCPs /
// term.DSCPRewrite with no validation, and the snapshot builder
// (pkg/dataplane/userspace/filters.go) emitted only a known name or a numeric
// 0..63 and SILENTLY DROPPED everything else. A dropped `from dscp` value left
// the term with NO DSCP constraint — it then matched ALL DSCPs (a policy
// widening: `from dscp not-a-code then accept` becomes an unconstrained accept;
// `from dscp 64 then discard` drops broader traffic than intended). A dropped
// `then dscp` rewrite silently did nothing. There was no commit-time DSCP /
// traffic-class token validation — the same silent fail-open class as #3205's
// icmp/port unresolved-token gate, but DSCP was uncovered.
//
// The valid name set is filterDSCPResolvable, which INLINE-mirrors
// dataplane.DSCPValues (the snapshot builder's table) plus the numeric 0..63
// range it accepts. pkg/config cannot import pkg/dataplane (import cycle:
// pkg/dataplane imports pkg/config), so the name set is duplicated and pinned by
// a drift-guard test (TestFilterDSCPResolvableMatchesDSCPValues) via the
// exported FilterDSCPResolvable accessor — the same arrangement as
// filterProtocolResolvable / appid.ProtocolNumber. Since #7422 the builder side
// of that comparison is a single exported function,
// dataplane.ResolveFilterDSCP, and the guard asserts AGREEMENT with it
// (TestFilterDSCPResolvableAgreesWithTheBuildersResolver7422) rather than
// pinning both sides to a literal range. Both `dscp` and
// `traffic-class` (the IPv6 spelling) compile to the same fields and share the
// same 0..63 / code-point-name range, so one check covers both.
//
// The walk is deterministic (filters sorted by name, terms in config order). On
// the tolerant load / peer-sync path the caller downgrades the returned error to
// a warning (#1960 no-brick); the snapshot builder then handles the bad token
// independently, and the two DSCP halves behave DIFFERENTLY there (L10, #3715):
//
//   - MATCH: an unresolvable `from dscp` NAME is dropped and the term is marked
//     dscp_match_unrepresentable, which the Rust filter compiler FAILS CLOSED on
//     (SnapshotIntegrityError::UnrepresentableFilterDSCP, #3406) — it does NOT
//     silently widen. A raw numeric value >= 64 is likewise failed closed
//     (FilterDSCPOutOfRange, #3715) rather than silently dropped from the bitmap.
//   - REWRITE: an unresolvable `then dscp` NAME warn/no-ops (CoS-only, no match
//     widening), and a raw numeric value >= 64 is failed closed by the Rust
//     compiler (FilterDSCPOutOfRange, #3715) rather than masked into a different
//     valid code point. #7422: `show firewall` no longer renders that dropped
//     rewrite as applied — it annotates it NOT INSTALLED, using the builder's
//     own resolver (dataplane.ResolveFilterDSCP).
//
// The operator never reaches any of those states through a commit — this gate is
// the primary defense. Mirrors validateFilterMatchValuesStrict.
func validateFilterDSCPStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(family string, filters map[string]*FirewallFilter) error {
		names := make([]string, 0, len(filters))
		for name := range filters {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			filter := filters[name]
			if filter == nil {
				continue
			}
			for _, term := range filter.Terms {
				if term == nil {
					continue
				}
				for _, d := range term.DSCPs {
					if d == "" || filterDSCPResolvable(d) {
						continue
					}
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown `from` dscp/"+
							"traffic-class value %q (use a code-point name such as "+
							"be/ef/af11-af43/cs0-cs7 or a number 0-63) — an unresolved "+
							"value is silently dropped, leaving the term matching ALL "+
							"DSCPs",
						family, name, term.Name, d)
				}
				if r := term.DSCPRewrite; r != "" && !filterDSCPResolvable(r) {
					return fmt.Errorf(
						"firewall family %s filter %q term %q: unknown `then` dscp/"+
							"traffic-class rewrite value %q (use a code-point name such "+
							"as be/ef/af11-af43/cs0-cs7 or a number 0-63) — an unresolved "+
							"value is silently dropped, so the rewrite never happens",
						family, name, term.Name, r)
				}
			}
		}
		return nil
	}
	if err := check("inet", cfg.Firewall.FiltersInet); err != nil {
		return err
	}
	return check("inet6", cfg.Firewall.FiltersInet6)
}

// filterDSCPNames INLINE-mirrors the KEY set of dataplane.DSCPValues
// (pkg/dataplane/types.go) — the code-point names dataplane.ResolveFilterDSCP,
// the resolver the snapshot builder (pkg/dataplane/userspace/filters.go) and
// `show firewall` both call, accepts for a firewall-filter dscp /
// traffic-class match or rewrite. pkg/config cannot import pkg/dataplane (import
// cycle), so the names are duplicated here and pinned to the SSOT by the
// drift-guard test TestFilterDSCPResolvableMatchesDSCPValues via the exported
// FilterDSCPResolvable accessor. Keep in sync with dataplane.DSCPValues.
var filterDSCPNames = map[string]bool{
	"ef":   true,
	"af11": true, "af12": true, "af13": true,
	"af21": true, "af22": true, "af23": true,
	"af31": true, "af32": true, "af33": true,
	"af41": true, "af42": true, "af43": true,
	"cs0": true, "cs1": true, "cs2": true, "cs3": true,
	"cs4": true, "cs5": true, "cs6": true, "cs7": true,
	"be": true,
}

// filterDSCPResolvable reports whether a firewall-filter dscp / traffic-class
// token (match or rewrite) is representable: a known code-point name
// (case-insensitive, mirroring the resolver's strings.ToLower lookup) or an
// integer in 0..63 (the 6-bit DSCP field). It mirrors the snapshot builder's
// emit condition branch-for-branch so commit and emission agree on what
// resolves. Keep in sync with dataplane.ResolveFilterDSCP (#7422), which is now
// the single spelling of that condition.
func filterDSCPResolvable(token string) bool {
	if filterDSCPNames[strings.ToLower(token)] {
		return true
	}
	if v, err := strconv.Atoi(token); err == nil && v >= 0 && v <= 63 {
		return true
	}
	return false
}

// FilterDSCPResolvable exposes filterDSCPResolvable for the drift-guard test
// TestFilterDSCPResolvableMatchesDSCPValues, which asserts this acceptance set
// agrees with dataplane.DSCPValues + the snapshot builder's 0..63 numeric range
// so the INLINE-duplicated table cannot drift from the SSOT silently. It is a
// TEST seam, not a runtime coupling — production code uses the unexported
// filterDSCPResolvable directly.
func FilterDSCPResolvable(token string) bool {
	return filterDSCPResolvable(token)
}

// FilterDSCPNames exposes the config-side code-point NAME set (the keys of
// filterDSCPNames) for the BIDIRECTIONAL drift-guard test
// TestFilterDSCPResolvableMatchesDSCPValues. The forward direction (every
// dataplane.DSCPValues key is accepted here) catches the config mirror missing a
// name; this accessor lets the test assert the inverse — every name the config
// mirror accepts is STILL present in dataplane.DSCPValues — so a name DROPPED
// from the dataplane SSOT (which the snapshot builder would then silently fail to
// emit) cannot leave a stale accept here. TEST seam only.
func FilterDSCPNames() []string {
	names := make([]string, 0, len(filterDSCPNames))
	for name := range filterDSCPNames {
		names = append(names, name)
	}
	return names
}

// filterProtocolResolvable reports whether a `from protocol <token>` is
// representable: it INLINE-mirrors the acceptance set of
// appid.ProtocolNumber's ok==true result (the #2124/#2175 SSOT). pkg/config
// cannot import pkg/appid (import cycle: pkg/appid imports pkg/config), so the
// known-name set is duplicated here and pinned by the pkg/appid drift-guard
// test TestFilterProtocolResolvableMatchesProtocolNumber via the exported
// FilterProtocolResolvable accessor.
//
// The acceptance set is intentionally TIGHTER than validateProtocol (the
// lenient validator used by ValidateConfig's warning surface): validateProtocol
// blanket-accepts ANY "junos-" prefix, but appid.ProtocolNumber only resolves
// the specific junos-* aliases below, so an unknown "junos-foobar" must be
// rejected here to stay consistent with the dataplane SSOT — otherwise commit
// would pass while the swallowed dataplane gate dropped the constraint. Since
// #3150, validateApplicationSpecsStrict also resolves an application's own
// `protocol` leaf through THIS helper (not validateProtocol) for the same
// reason — the broad junos-* accept there caused a commit/apply split.
func filterProtocolResolvable(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "tcp", "junos-tcp-any",
		"udp", "junos-udp-any",
		"icmp", "junos-icmp-all", "junos-ping",
		"icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6",
		"gre", "junos-gre",
		"ospf", "junos-ospf",
		"junos-ip-in-ip", "junos-ipip", "ipip",
		"ipv6",
		"egp",
		"igmp",
		"pim",
		"ah",
		"esp",
		"sctp",
		"vrrp":
		return true
	default:
		// Numeric protocol number, including the deliberate "0" (HOPOPT).
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil && n >= 0 && n < 256 {
			return true
		}
		return false
	}
}

// protocolIsPortBearing reports whether a protocol token names a transport for
// which THIS dataplane actually extracts L4 ports — i.e. a protocol for which a
// source-port/destination-port constraint is enforceable. The authoritative set
// is the dataplane's own port-extraction predicate, NOT a name→number resolver:
//
//   - userspace-dp/src/ip_proto.rs `has_l4_ports(protocol)` == TCP | UDP, and
//   - userspace-dp/src/afxdp/frame/inspect.rs `parse_flow_ports` reads port
//     bytes only for TCP | UDP (SCTP and everything else fall through to None).
//
// So ONLY TCP (6) and UDP (17) carry ports the dataplane reads. ICMP/ICMPv6,
// GRE, OSPF, ESP, AH, VRRP, IGMP, PIM, IP-in-IP — and crucially SCTP (132) —
// do not: SCTP HAS ports on the wire, but this dataplane deliberately never
// extracts or rewrites them (CRC32c checksum, see the ip_proto.rs has_l4_ports
// comment), so an SCTP packet still presents dst_port/src_port = 0 to the
// matcher. policy.rs (`PortMatcher::lookup` / `matches`) indexes every
// application term by protocol number and keys port terms on those extracted
// ports; for any protocol outside the extraction set a port-constrained term
// becomes a NEVER-MATCH — fail-open for a deny rule, fail-closed for a permit
// rule (the #3373 hole). Rejecting a port on such a protocol at commit is the
// fail-closed-correct outcome: the dataplane cannot enforce the constraint, so
// refuse it rather than silently compile a term that never matches.
//
// This subset is replicated inline because appid cannot be imported here
// (pkg/appid imports pkg/config — the same import-cycle constraint that forces
// filterProtocolResolvable to be duplicated). The
// TestProtocolIsPortBearingMatchesDataplaneExtraction drift-guard pins it to the
// ip_proto.rs has_l4_ports SSOT (TCP/UDP).
func protocolIsPortBearing(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "tcp", "junos-tcp-any",
		"udp", "junos-udp-any":
		return true
	default:
		// Numeric protocol number form: only 6 (TCP) and 17 (UDP). Note 132
		// (SCTP) is intentionally absent — this dataplane does not extract SCTP
		// ports (ip_proto.rs has_l4_ports).
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil {
			return n == 6 || n == 17
		}
		return false
	}
}

// protocolIsTCP reports whether a protocol token names TCP — the only protocol
// on which a firewall-filter `from tcp-flags` match is enforceable (#3723). The
// dataplane matcher (userspace-dp engine/matching.rs per_packet_l4_matches)
// returns false for a tcp-flags term whenever the packet protocol is not
// PROTO_TCP, so tcp-flags on any other protocol — including UDP, which IS
// port-bearing — can never match. It is a stricter predicate than
// protocolIsPortBearing (which also accepts UDP): tcp-flags implies the TCP
// family specifically. Recognizes the tcp name, the junos-tcp-any alias, and
// the numeric protocol number 6.
func protocolIsTCP(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "tcp", "junos-tcp-any":
		return true
	default:
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil {
			return n == 6
		}
		return false
	}
}

// protocolIsICMPFamily reports whether a protocol token names ICMP or ICMPv6 —
// the only protocols on which an application `icmp-type`/`icmp-code` constraint
// is enforceable (#3348). It recognizes the canonical names, the junos-*
// aliases that resolve to ICMP/ICMPv6 (including junos-ping/junos-pingv6, which
// carry an implicit echo type), and the numeric protocol numbers 1 (ICMP) and
// 58 (ICMPv6). The set mirrors the ICMP arm of filterProtocolResolvable.
func protocolIsICMPFamily(token string) bool {
	switch strings.ToLower(strings.TrimSpace(token)) {
	case "icmp", "junos-icmp-all", "junos-ping",
		"icmpv6", "icmp6", "junos-icmp6-all", "junos-pingv6":
		return true
	default:
		if n, err := strconv.Atoi(strings.TrimSpace(token)); err == nil {
			return n == 1 || n == 58
		}
		return false
	}
}

// ProtocolIsPortBearing exposes protocolIsPortBearing for the pkg/appid
// drift-guard test so the inline port-bearing subset cannot silently drift from
// the dataplane's port-extraction set (ip_proto.rs has_l4_ports). Test seam only
// — production code uses the unexported form directly.
func ProtocolIsPortBearing(token string) bool {
	return protocolIsPortBearing(token)
}

// FilterProtocolResolvable exposes filterProtocolResolvable for the pkg/appid
// drift-guard test (TestFilterProtocolResolvableMatchesProtocolNumber), which
// asserts this acceptance set agrees with appid.ProtocolNumber's ok==true
// result so the INLINE-duplicated table cannot drift from the SSOT silently. It
// is a TEST seam, not a runtime coupling — production code uses the unexported
// filterProtocolResolvable directly.
func FilterProtocolResolvable(token string) bool {
	return filterProtocolResolvable(token)
}

// validateFirewallPolicerUnknownActionsStrict hard-rejects a policer or
// three-color-policer whose `then` block carries a token that is none of the
// recognized policer actions (`discard` / `loss-priority` / `forwarding-class`)
// — #9882.
//
// # Why reject rather than keep the default
//
// PolicerConfig.ThenAction defaults to "discard", so an unrecognized token was
// silently dropped while the policer kept the most destructive action: a typo
// like `then discrad` committed clean on every path including strict and
// dropped excess traffic with zero diagnostic — an availability over-drop
// versus intent. Junos rejects an unknown policer action at commit, so the
// fail-closed-correct behavior is to refuse the commit and name the offending
// token. This is the policer path's #2399 (filter terms got their
// UnknownActions channel there; this path never did).
//
// # What this gate reads
//
// The DEFERRED channel (`UnknownActions`), populated by compileFirewall's
// `then` loops — not the AST. Reading the recorded set keeps gate and compiler
// agreeing by construction on which tokens are unknown, on both AST shapes
// (hierarchical and flat-set), exactly like validateFilterActionsStrict.
//
// Strict on commit / commit-check; lenient on load / peer-sync (warn — #1960
// no-brick: an already-persisted or peer-synced config still boots, and the
// "discard" default drives the dataplane exactly as it did before, so a
// leniently-loaded config is no worse off than before the gate).
// Deterministic: policers then three-color-policers, each sorted by name.
// Runs BEFORE the #8445 terminal-vs-marking gate (same order as the filter
// side, where #2399 unknown-actions runs before #4375 terminal-conflict): an
// unknown token means the intent cannot be fully characterized, so it is
// reported first.
func validateFirewallPolicerUnknownActionsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(kind string, unknownByName map[string][]string) error {
		names := make([]string, 0, len(unknownByName))
		for name := range unknownByName {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if len(unknownByName[name]) == 0 {
				continue
			}
			return fmt.Errorf(
				"firewall %s %q: unknown `then` action %q "+
					"(supported: `then discard`, `then loss-priority <level>`, "+
					"`then forwarding-class <class>`)",
				kind, name, unknownByName[name][0])
		}
		return nil
	}

	policers := make(map[string][]string, len(cfg.Firewall.Policers))
	for name, pol := range cfg.Firewall.Policers {
		if pol != nil {
			policers[name] = pol.UnknownActions
		}
	}
	if err := check("policer", policers); err != nil {
		return err
	}
	tcps := make(map[string][]string, len(cfg.Firewall.ThreeColorPolicers))
	for name, tcp := range cfg.Firewall.ThreeColorPolicers {
		if tcp != nil {
			tcps[name] = tcp.UnknownActions
		}
	}
	return check("three-color-policer", tcps)
}

// validateFirewallPolicerThenConflictStrict hard-rejects a policer or
// three-color-policer whose `then` block carries BOTH the terminal action
// `discard` and a marking action (`loss-priority` / `forwarding-class`) —
// #8445.
//
// # Why reject rather than compose
//
// Composing them is not available, and not merely inconvenient. The dataplane
// enforces exactly one policer action: `then discard`, which maps the excess
// colours to a drop treatment. A marking action is METERED BUT NOT ACTED UPON —
// `build_single_rate_policer_state` selects `ThreeColorTreatments::default()`
// for any non-discard policer and its own doc says "the marking action is not
// wired here". So "drop the excess AND mark it" has no representation to
// compile to; a composing fix would have to invent the half that does not
// exist.
//
// It is also contradictory on its own terms: a discarded packet is not marked.
// Junos treats a policer `then` as one action on the out-of-profile traffic.
//
// # Why silently keeping one is worse than it looks
//
// PolicerConfig.ThenAction is single-valued and last-write-wins, so SOURCE
// ORDER decides which statement survives, and the two orders do not merely
// differ — they differ in whether the rate limit exists at all:
//
//	then { discard; loss-priority high; }  -> ThenAction "loss-priority high"
//	                                       -> DiscardExcess false
//	                                       -> policer METERS AND DOES NOTHING
//	then { loss-priority high; discard; }  -> ThenAction "discard"
//	                                       -> DiscardExcess true, rate enforced
//
// The first is the dangerous one: the operator authored a rate limit, the
// commit succeeded, and the limit is entirely unenforced. It does not degrade
// to mark-and-forward — it becomes a complete no-op.
//
// # What this gate reads, and why it cannot read ThenAction
//
// The AUTHORED set (`ThenActions`), not the survivor. A check on ThenAction
// cannot see the conflict: the compiled value IS what was authored, for one of
// the two statements. That is the trap this gate exists to avoid, and it is why
// recording the set was part of the fix rather than an implementation detail.
//
// Repeating the SAME action is a redundancy, not a conflict, and is allowed —
// mirroring validateFilterTerminalConflictStrict (#4375), whose shape this
// follows. `forwarding-class` is recorded and rejected alongside `discard` even
// though the compiler never acted on it: it is an action the operator wrote and
// the config silently dropped.
//
// Strict on commit / commit-check; lenient on load / peer-sync (warn — #1960
// no-brick: an already-persisted or peer-synced config still boots, and the
// last-wins ThenAction drives the dataplane exactly as it did before, so a
// leniently-loaded config is no worse off than before the gate). Deterministic:
// policers then three-color-policers, each sorted by name.
func validateFirewallPolicerThenConflictStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// A policer `then` action is either TERMINAL (acts on the packet and ends
	// the decision) or a MARKING action (rewrites a field and forwards). One of
	// each is the contradiction.
	isMarking := func(a string) bool {
		return a == "loss-priority" || a == "forwarding-class"
	}
	check := func(kind string, actionsByName map[string][]string) error {
		names := make([]string, 0, len(actionsByName))
		for name := range actionsByName {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			var terminal, marking []string
			seen := map[string]bool{}
			for _, a := range actionsByName[name] {
				if seen[a] {
					continue
				}
				seen[a] = true
				if a == "discard" {
					terminal = append(terminal, a)
				} else if isMarking(a) {
					marking = append(marking, a)
				}
			}
			if len(terminal) > 0 && len(marking) > 0 {
				return fmt.Errorf(
					"firewall %s %q: `then` carries both the terminal action %s and "+
						"the marking action %s — a policer applies ONE action to "+
						"out-of-profile traffic, and keeping whichever was written last "+
						"silently changed the rate limit (with `discard` first the "+
						"policer meters and drops nothing at all). Supported: `then "+
						"discard` alone, which enforces the limit by dropping the "+
						"excess; or `then loss-priority <level>` / `then "+
						"forwarding-class <class>` alone, which METERS ONLY — this "+
						"dataplane does not yet act on a policer marking action",
					kind, name,
					strings.Join(terminal, " and "), strings.Join(marking, " and "))
			}
		}
		return nil
	}

	policers := make(map[string][]string, len(cfg.Firewall.Policers))
	for name, pol := range cfg.Firewall.Policers {
		if pol != nil {
			policers[name] = pol.ThenActions
		}
	}
	if err := check("policer", policers); err != nil {
		return err
	}
	tcps := make(map[string][]string, len(cfg.Firewall.ThreeColorPolicers))
	for name, tcp := range cfg.Firewall.ThreeColorPolicers {
		if tcp != nil {
			tcps[name] = tcp.ThenActions
		}
	}
	return check("three-color-policer", tcps)
}

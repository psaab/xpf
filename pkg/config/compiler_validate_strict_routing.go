package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// A bare protocol keyword an OSPF/OSPFv3/BGP/IS-IS `export` (or a RIP
// `redistribute`) accepts in lieu of a named policy-statement is exactly what
// FRRRoutingProtocolKeyword admits, the same domain pkg/frr renders, spelled in
// lower case (the renderer writes the token through). This used to be a
// separate, shorter list that lacked ospf6 and ripng, so `protocols ospf3
// export ripng` was refused as an unknown protocol (#9667).
func bareRedistKeyword(token string) (string, bool) {
	kw, ok := FRRRoutingProtocolKeyword(token)
	if !ok || (token != kw && !(token == "direct" && kw == "connected")) {
		return "", false
	}
	return kw, true
}

// validateRoutingExportReferencesStrict hard-rejects a dynamic-protocol
// `export` (OSPF / OSPFv3 / BGP / IS-IS), a RIP `redistribute`, a BGP
// group/neighbor `export`, or a `routing-options forwarding-table export`
// whose token resolves to neither a known redistribution protocol nor a
// defined policy-statement (#2144).
//
// Without this gate a typo passes commit and reaches FRR render-time, where
// it fails OPEN in three distinct ways:
//
//   - resolveRedistribute's fallback (policy_render.go) emits
//     `redistribute <typo>` for any unknown token. FRR either rejects the
//     line — failing the whole frr-reload (a single vtysh -f add-batch
//     exits non-zero on any CMD_WARNING_CONFIG_FAILED) — or silently
//     no-ops, so the intended redistribution never happens.
//   - a BGP group/neighbor `export` renders `neighbor <addr> route-map
//     <typo> out`. FRR resolves a route-map name with no definition to
//     NULL, which it treats as permit-all — the outbound filter the
//     operator wrote silently advertises EVERYTHING.
//   - `forwarding-table export <typo>` is read by resolveECMP
//     (config_render.go), which returns 0 max-paths when the policy is
//     missing — silently DISABLING the expected ECMP / consistent-hash
//     load balancing instead of rejecting the config.
//
// Protocol-token acceptance differs by site. A redistribute-backed export
// (OSPF/OSPFv3/BGP/IS-IS export, RIP redistribute) legitimately names a
// bare protocol (`export static`) OR a policy-statement, matching
// resolveRedistribute. A BGP group/neighbor export and a forwarding-table
// export render directly as a route-map / ECMP policy name, so only a
// defined policy-statement is valid there — a protocol token would be a
// dangling route-map / missing-policy reference, not a redistribute verb.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRoutingExportRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960
// fail-closed-on-load class); the render-path fallbacks above keep it inert
// or fail-open-on-an-already-committed-config exactly as before. Commit /
// commit-check stay strict. Mirrors validateLogProfileStreamReferencesStrict.
func validateRoutingExportReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.PolicyStatements == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.PolicyStatements[name]
		return ok
	}

	// checkRedist validates a redistribute-backed export list: each token
	// must be a known protocol OR a defined policy-statement.
	checkRedist := func(scope, proto string, exports []string) error {
		for _, e := range exports {
			if e == "" || defined(e) {
				continue
			}
			kw, ok := bareRedistKeyword(e)
			if !ok {
				return fmt.Errorf("%s%s export %q references neither a known "+
					"redistribution protocol (connected/direct/static/kernel/"+
					"ospf/ospf6/bgp/rip/ripng/isis) nor a defined policy-statement — the "+
					"FRR redistribute line would be rejected or silently no-op; "+
					"define the policy-statement or fix the export name",
					scope, proto, e)
			}
			// #9667: a bare token is bound to its use site, so a family the use
			// site cannot carry can be refused here. (A policy-statement's
			// `from protocol` cannot: the same policy is valid under another
			// router, so pkg/frr filters those per term at render, #9510.)
			src, sok := RedistributionSourceFamilies(kw)
			use, uok := exportUseSiteFamilies[proto]
			if sok && uok && src&use == 0 {
				return fmt.Errorf("%s%s export %q redistributes %s routes, which %s "+
					"cannot carry (it redistributes %s only), so the line would never "+
					"render; export it under a protocol that carries %s routes (#9667)",
					scope, proto, e, src, proto, use, src)
			}
		}
		return nil
	}

	// checkPolicyRef validates a reference that renders directly as a
	// route-map / ECMP policy name: only a defined policy-statement is valid.
	// hint is the trailing remediation text — direction-aware so an import
	// failure does not say "fix the export name" (Copilot review, #2490).
	checkPolicyRef := func(detail, name, hint string) error {
		if name == "" || defined(name) {
			return nil
		}
		return fmt.Errorf("%s references undefined policy-statement %q; %s",
			detail, name, hint)
	}
	const (
		hintExport = "define the policy-statement or fix the export name"
		hintImport = "define the policy-statement or fix the import name"
	)

	checkProtocols := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			if err := checkRedist(scope, "protocols ospf", ospf.Export); err != nil {
				return err
			}
		}
		if ospfv3 != nil {
			if err := checkRedist(scope, "protocols ospf3", ospfv3.Export); err != nil {
				return err
			}
		}
		if rip != nil {
			if err := checkRedist(scope, "protocols rip", rip.Redistribute); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := checkRedist(scope, "protocols isis", isis.Export); err != nil {
				return err
			}
		}
		if bgp != nil {
			if err := checkRedist(scope, "protocols bgp", bgp.Export); err != nil {
				return err
			}
			// A global `protocols bgp import` renders `route-map <name> in`.
			// Unlike export, import has NO redistribute equivalent — inbound
			// filtering is route-map-only — so it must name a DEFINED
			// policy-statement (no protocol-token fallback). An undefined ref
			// would render a dangling `route-map in` that FRR resolves to
			// PERMIT-ALL, accepting every inbound advertisement and defeating
			// the operator's filter (#2490, the #2473 lesson on the inbound
			// direction). #2490.
			for _, e := range bgp.Import {
				detail := fmt.Sprintf("%sprotocols bgp import", scope)
				if err := checkPolicyRef(detail, e, hintImport); err != nil {
					return err
				}
			}
			// A BGP group/neighbor export renders `route-map <name> out`,
			// and a group/neighbor import renders `route-map <name> in`, so
			// both must be defined policy-statements (no protocol-token
			// fallback). Sort neighbor addresses for a deterministic
			// first-error message.
			neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
			sort.SliceStable(neighbors, func(i, j int) bool {
				return neighbors[i].Address < neighbors[j].Address
			})
			for _, n := range neighbors {
				if n == nil {
					continue
				}
				for _, e := range n.Export {
					detail := fmt.Sprintf("%sprotocols bgp neighbor %s export", scope, n.Address)
					if n.GroupName != "" {
						detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s export", scope, n.GroupName, n.Address)
					}
					if err := checkPolicyRef(detail, e, hintExport); err != nil {
						return err
					}
				}
				for _, e := range n.Import {
					detail := fmt.Sprintf("%sprotocols bgp neighbor %s import", scope, n.Address)
					if n.GroupName != "" {
						detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s import", scope, n.GroupName, n.Address)
					}
					if err := checkPolicyRef(detail, e, hintImport); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	// Top-level protocols.
	if err := checkProtocols("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return err
	}

	// Per routing-instance protocols.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkProtocols(scope, ri.OSPF, ri.OSPFv3, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return err
		}
	}

	// forwarding-table export → resolveECMP (config_render.go). Renders
	// directly as an ECMP policy lookup, so it must be a defined
	// policy-statement; a missing one silently disables ECMP/consistent-hash.
	//
	// #6659: check EVERY authored policy, not just the first. This gate used to
	// read the scalar ForwardingTableExport, which the compiler filled with
	// nodeVal — so `export [ p1 p2 ]` validated only p1 and a DANGLING p2
	// committed clean, defeating the gate on exactly the silent-ECMP-loss
	// scenario its own error text describes. Fall back to the scalar when the
	// list is empty so a typed config produced by an older binary (peer sync /
	// a restored DB) is still checked.
	refs := cfg.RoutingOptions.ForwardingTableExports
	if len(refs) == 0 && cfg.RoutingOptions.ForwardingTableExport != "" {
		refs = []string{cfg.RoutingOptions.ForwardingTableExport}
	}
	// #6715: the consequence is per VALUE, exactly as on the static-NAT side
	// (emitMatchAddr, compiler_validate_strict_nat.go). Widening this gate to
	// every authored value let a NON-rendering token reach a message that only
	// the RENDERING one earns: resolveECMP looks up
	// cfg.RoutingOptions.ForwardingTableExport, so with `export [ p1 nosuch ]`
	// the dangling `nosuch` is inert while `p1` renders and ECMP resolves —
	// "load-balancing would be silently disabled" is simply false there. Master
	// could not hit this because it only ever passed the scalar. Decide which
	// value the reference is before naming the consequence.
	selected := cfg.RoutingOptions.ForwardingTableExport
	for _, ref := range refs {
		err := checkPolicyRef(
			"routing-options forwarding-table export",
			ref,
			hintExport,
		)
		if err == nil {
			continue
		}
		switch {
		case ref == selected:
			return fmt.Errorf("%s (the expected ECMP / consistent-hash "+
				"load-balancing would be silently disabled)", err)
		case selected == "":
			// The selected slot is an authored blank (`export [ "" nosuch ]`),
			// so nothing renders and there is no surviving policy to name —
			// the same empty-selection case emitMatchAddr handles.
			return fmt.Errorf("%s (this value is not the one the forwarding "+
				"table renders — the selected forwarding-table export is EMPTY, "+
				"so no ECMP policy is configured at all; correct or remove the "+
				"undefined policy)", err)
		case checkPolicyRef("routing-options forwarding-table export",
			selected, hintExport) != nil:
			// #6673: "%q is, and it still resolves" ASSUMED the selected policy
			// resolves without ever checking it. The loop reaches a
			// non-selected undefined policy FIRST and reassured the operator
			// that the selected one "still resolves" when it is undefined too
			// and ECMP is disabled. The verdict was right (strict rejects,
			// tolerant warns) and the stated consequence was backwards, which
			// on the tolerant path is the only thing the operator gets.
			//
			// Reaching this branch needs the SELECTED value to be a LATER
			// authored one, which takes two top-level `routing-options` roots:
			//
			//   routing-options { forwarding-table { export missing-old; } }
			//   routing-options { forwarding-table { export missing-selected; } }
			//
			// → list [missing-old missing-selected], scalar "missing-selected".
			// Both single-block spellings — two `export` leaves in one
			// forwarding-table, and `export [ missing-old missing-selected ]` —
			// select the FIRST value instead (FindChild takes the first leaf;
			// measured scalar "missing-old"), so the loop hits `ref == selected`
			// on iteration 1 and returns there. Do not use them as a repro for
			// this branch; they exercise the case above it.
			return fmt.Errorf("%s (this value is not the one the forwarding "+
				"table renders — %q is, but that policy is UNDEFINED as well, "+
				"so the expected ECMP / consistent-hash load-balancing is "+
				"silently disabled; define or correct it)", err, selected)
		default:
			return fmt.Errorf("%s (this value is not the one the forwarding "+
				"table renders — %q is, and it still resolves; correct or "+
				"remove the undefined policy)", err, selected)
		}
	}

	return nil
}

// validateForwardingTableExportSingleStrict (#6659) hard-rejects a
// `routing-options forwarding-table export` list carrying MORE THAN ONE policy.
//
// Junos accepts an export policy CHAIN here and the schema declares the leaf
// `multi: true`, but the FRR renderer honours exactly ONE: resolveECMP
// (frr/config_render.go) looks up a single policy-statement to derive
// ecmpMaxPaths. Before #6659 the compiler read the leaf with nodeVal, so a
// multi-policy chain silently collapsed to the first — the operator's remaining
// policies had no effect on load-balancing and nothing said so.
//
// Rejecting makes that collapse loud and fails CLOSED, and #6674 RATIFIED it as
// the permanent contract rather than a pending renderer change.
//
// The reason, stated because "Junos takes a chain here" is true and still does
// not make a chain implementable: resolveECMP (pkg/frr/config_render.go) derives
// exactly TWO booleans from the ONE named policy — any term with a load-balance
// action sets ecmpMaxPaths to 64, any term with `consistent-hash` sets
// fc.ConsistentHash — and evaluates no `from` match, no term order, and no
// terminating action. Junos evaluates an export chain PER ROUTE and stops at the
// first terminating action, so the only cheap composition (OR the flags across
// the chain) is NOT Junos: a route accepted by the first policy never reaches
// the second, yet the OR would apply the second's load-balance to it. Measured,
// not assumed — the two readings differ whenever the first policy carries no
// load-balance term and a later one does, which is pinned by
// TestForwardingTableExportIsAGlobalToggleNotAChain_6674. The faithful reading
// cannot be expressed at all: the value being derived is FRR's GLOBAL
// `maximum-paths`, which has no per-route form. A chain therefore needs a
// per-route forwarding-policy model xpf does not have — a feature, tracked
// separately, not a defect in this gate.
//
// Strict on commit / commit-check (hard reject); the call site downgrades to a
// warning on the tolerant load / peer-sync path (#1960 no-brick), where
// ForwardingTableExport still carries the SELECTED policy so rendering is
// exactly pre-#6659. "Selected", not "first": across two top-level
// `routing-options` roots the last root wins (#6673), which is why the error
// below quotes cfg.RoutingOptions.ForwardingTableExport rather than exports[0].
func validateForwardingTableExportSingleStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// #6673: count only NON-EMPTY values, and name the policy that actually
	// renders. ForwardingTableExports records every authored value slot
	// including empty ones so the list always contains what the scalar selected
	// (see multiLeafAuthoredValues); an empty slot blanks the export rather than
	// adding a policy, and `export [ "" p1 ];` must stay acceptable exactly as
	// it was before #6659. The selected policy is the scalar, NOT element [0]:
	// with two top-level `routing-options` roots the last root wins, so [0]
	// named a policy that does not render.
	//
	// #6673 fold: count only DISTINCT ones too, for the same reason. `export
	// [ p1 p1 ];` (or `export p1;` twice) names ONE policy; master accepted it
	// and rendered the identical ECMP lookup, and the raw count rejected it at
	// commit while claiming "the rest would be silently ignored" about the very
	// policy that renders. Exact-text identity is the right one here — an export
	// value is an opaque POLICY NAME with no canonical form, so two spellings
	// are two different references and only an exact repeat may be collapsed
	// (dedupeValues). The #6659 rejection for a genuine multi-policy chain,
	// where the tail really does not render, is untouched.
	exports := dedupeValues(nonEmptyValues(cfg.RoutingOptions.ForwardingTableExports))
	if n := len(exports); n > 1 {
		// #6673: the selected slot can itself be an authored BLANK —
		// `export [ "" p1 p2 ];` counts two policies but nodeVal selects the
		// empty slot, so resolveECMP looks nothing up and NO policy renders.
		// "only %q would take effect" then printed `only "" would take effect`,
		// naming a policy that does not exist and implying one of the two is
		// still honoured.
		if cfg.RoutingOptions.ForwardingTableExport == "" {
			return fmt.Errorf(
				"routing-options forwarding-table export declares %d policies (%v); "+
					"the forwarding-table export renders as a SINGLE ECMP policy "+
					"lookup and the selected value is EMPTY, so NONE of them takes "+
					"effect and no ECMP policy is configured at all — configure one "+
					"export policy (#6659)",
				n, exports)
		}
		return fmt.Errorf(
			"routing-options forwarding-table export declares %d policies (%v); "+
				"the forwarding-table export renders as a SINGLE ECMP policy "+
				"lookup, so only %q would take effect and the rest would be "+
				"silently ignored — configure one export policy (#6659)",
			n, exports, cfg.RoutingOptions.ForwardingTableExport)
	}
	return nil
}

// validatePolicyCommunityReferencesStrict hard-rejects a policy-statement term
// whose `from community <name>` or `then community delete <name>` references a
// community the config never defines under `policy-options community <name>`
// (#2881).
//
// xpf renders `from community <name>` as the FRR route-map clause
// `match community <name>` and `then community delete <name>` (added in #2848)
// as `set comm-list <name> delete`. Both clauses reference an FRR
// `bgp community-list <name>`, which xpf emits ONLY for a defined
// `policy-options community <name>` (policy_render.go). With no validation an
// undefined name passes commit and breaks at FRR render time: a dangling
// `match community` / `set comm-list ... delete` line is rejected by
// frr-reload, and because a single vtysh -f add-batch exits non-zero on any
// CMD_WARNING_CONFIG_FAILED, the WHOLE reload fails — leaving dynamic routing
// stale, a commit-accepted config the routing daemon cannot load.
//
// Only NAME references are checked. `then community (set|add) <value>` and the
// bare `then community <value>` carry a community VALUE (e.g. 65000:100 /
// no-export), not a community-list reference, so they are not validated here;
// `then community none` carries no argument. Multiple `from community` siblings
// (FromCommunity slice) and a multi-list `then community delete [ a b ]`
// (CommunityDelete slice) are each fully walked.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientPolicyCommunityRef) so an already-persisted or
// peer-synced config carrying the typo still boots (#1960 fail-closed-on-load
// class). Commit / commit-check stay strict. Runs on the fully-compiled
// *Config so the community map is populated regardless of authoring order.
// Mirrors validateRoutingExportReferencesStrict.
func validatePolicyCommunityReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	defined := func(name string) bool {
		if cfg.PolicyOptions.Communities == nil {
			return false
		}
		_, ok := cfg.PolicyOptions.Communities[name]
		return ok
	}

	// Sort policy-statement names for a deterministic first-error message
	// (the typed-config map iteration order is otherwise random).
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, psName := range names {
		ps := cfg.PolicyOptions.PolicyStatements[psName]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, c := range term.FromCommunity {
				if c == "" || defined(c) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `from community %s` "+
					"references undefined community %q — xpf renders no "+
					"`bgp community-list %s`, so the `match community` line would "+
					"fail frr-reload (failing the entire FRR config load); define "+
					"`policy-options community %s` or fix the name",
					psName, term.Name, c, c, c, c)
			}
			for _, c := range term.CommunityDelete {
				if c == "" || defined(c) {
					continue
				}
				return fmt.Errorf("policy-statement %s term %s `then community delete %s` "+
					"references undefined community %q — xpf renders no "+
					"`bgp community-list %s`, so the `set comm-list %s delete` line "+
					"would fail frr-reload (failing the entire FRR config load); "+
					"define `policy-options community %s` or fix the name",
					psName, term.Name, c, c, c, c, c)
			}
		}
	}
	return nil
}

// frrTokenUnsafeIndex returns the byte index of the first character in s
// that FRR's command lexer cannot carry inside a single config token, or
// -1 if every character is safe.
//
// FRR's CLI lexer (lib/command_lex.l) tokenizes a vtysh / frr.conf line on
// ASCII whitespace and has NO quoted-string rule and NO rest-of-line
// ("LINE") token — a double-quoted value is NOT grouped, the quotes are
// taken literally. So any whitespace inside a rendered value splits it into
// multiple arguments: a password / auth key is truncated at the first space,
// or trailing words become spurious vtysh arguments. We therefore reject
// only the characters that actually break tokenization: ASCII space, tab,
// and the C0 / DEL control set (which sanitizeFRRValue would otherwise turn
// into spaces at render time, re-introducing the same split). Other
// punctuation (`.`, `@`, `!`, `#`, …) is matched by the lexer's single-char
// catch-all rule and stays adjacent with no whitespace, so it is safe.
func frrTokenUnsafeIndex(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c < 0x20 || c == 0x7f {
			return i
		}
	}
	return -1
}

// validateFRRAuthValuesStrict hard-rejects a dynamic-routing authentication
// secret that cannot be rendered as a single FRR/vtysh token (#2889):
//
//   - a BGP neighbor TCP-MD5 password (`neighbor <addr> password ...`)
//   - an OSPF interface authentication key (`ip ospf message-digest-key`
//     md5 / `ip ospf authentication-key`)
//   - a RIP authentication key (`ip rip authentication string`)
//   - an IS-IS area/domain or per-interface authentication key
//     (`area-password` / `domain-password` / `isis password`)
//
// All of these render the secret directly into a frr.conf line. FRR's
// command lexer (lib/command_lex.l) splits on whitespace and supports
// neither a quoted string nor a rest-of-line token, so a secret containing
// a space or tab is parsed as multiple arguments at config load: the secret
// is truncated at the first space, or — worse — the trailing words are
// interpreted as additional vtysh arguments (a malformed-line / injection
// risk). The render-side belt (sanitizeFRRValue, #1798) already collapses
// embedded control characters to spaces, so it cannot rescue this; it would
// only widen the split. Quoting is not an option here, so the safe contract
// is to reject the value at commit, naming the field.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientFRRAuthValues) so an already-persisted or peer-synced
// config carrying such a value still BOOTS (#1960 fail-closed-on-load
// class); the render path strips control chars and the offending line stays
// inert / single-line. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateFRRAuthValuesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	const why = "FRR's vtysh config lexer splits on whitespace and supports " +
		"no quoting, so the secret would be truncated at the first space or " +
		"inject trailing words as extra arguments at frr.conf load — remove " +
		"the whitespace/control characters from the value"

	checkKey := func(scope, field string, s Secret) error {
		if s == "" {
			return nil
		}
		if i := frrTokenUnsafeIndex(s.Reveal()); i >= 0 {
			return fmt.Errorf("%s%s contains whitespace or a control "+
				"character (at byte offset %d) that cannot be represented "+
				"in FRR config — %s", scope, field, i, why)
		}
		return nil
	}

	checkProtocols := func(scope string, ospf *OSPFConfig, bgp *BGPConfig, rip *RIPConfig, isis *ISISConfig) error {
		if ospf != nil {
			for _, area := range ospf.Areas {
				if area == nil {
					continue
				}
				for _, iface := range area.Interfaces {
					if iface == nil {
						continue
					}
					fld := fmt.Sprintf("protocols ospf area %s interface %s authentication-key", area.ID, iface.Name)
					if err := checkKey(scope, fld, iface.AuthKey); err != nil {
						return err
					}
				}
			}
		}
		if rip != nil {
			if err := checkKey(scope, "protocols rip authentication-key", rip.AuthKey); err != nil {
				return err
			}
		}
		if isis != nil {
			if err := checkKey(scope, "protocols isis authentication-key", isis.AuthKey); err != nil {
				return err
			}
			for _, iface := range isis.Interfaces {
				if iface == nil {
					continue
				}
				fld := fmt.Sprintf("protocols isis interface %s authentication-key", iface.Name)
				if err := checkKey(scope, fld, iface.AuthKey); err != nil {
					return err
				}
			}
		}
		if bgp != nil {
			// Sort neighbor addresses for a deterministic first-error
			// message (Go map / slice authoring order is not stable across
			// the parse paths).
			neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
			sort.SliceStable(neighbors, func(i, j int) bool {
				return neighbors[i].Address < neighbors[j].Address
			})
			for _, n := range neighbors {
				if n == nil {
					continue
				}
				fld := fmt.Sprintf("protocols bgp neighbor %s authentication-key", n.Address)
				if n.GroupName != "" {
					fld = fmt.Sprintf("protocols bgp group %s neighbor %s authentication-key", n.GroupName, n.Address)
				}
				if err := checkKey(scope, fld, n.AuthPassword); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// Top-level protocols.
	if err := checkProtocols("", cfg.Protocols.OSPF, cfg.Protocols.BGP, cfg.Protocols.RIP, cfg.Protocols.ISIS); err != nil {
		return err
	}

	// Per routing-instance protocols.
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkProtocols(scope, ri.OSPF, ri.BGP, ri.RIP, ri.ISIS); err != nil {
			return err
		}
	}

	return nil
}

// validateBGPNeighborAddressStrict hard-rejects a BGP neighbor identity that
// does not occupy exactly ONE FRR token (#6796).
//
// The address is rendered RAW into frr.conf at 24 sites — unlike every operand
// around it (update-source, description, password are all sanitized) — so a
// value carrying whitespace SPANS MULTIPLE FRR TOKENS. FRR's command lexer has
// no quoted-string and no rest-of-line token: it splits on whitespace. An
// address of `1.1.1.1 remote-as 65000\n neighbor 2.2.2.2` therefore renders a
// valid first statement followed by an attacker-chosen second one — arbitrary
// FRR configuration injected through a config value, including peerings and
// route-maps the operator never wrote.
//
// Strict on commit / commit-check (hard reject naming the neighbor, and the
// group when there is one); lenient on load / peer-sync so an already-persisted
// or peer-synced config still BOOTS (#1960) — the render path skips a neighbor
// whose address is not a bare IP, so an invalid one never reaches frr.conf and
// a leniently-loaded bad address is inert. Same doctrine as
// validateBGPNeighborPeerASStrict, whose exclusion set the renderer shares.
//
// The test is token COUNT, deliberately not address form. FRR's grammar is
// `neighbor <A.B.C.D|X:X::X:X|WORD>` and this tree already commits configs
// whose neighbor is a hostname, so requiring an IP literal would reject configs
// that work today — over-rejection in routing config is an outage. Empty is not
// accepted: an unnamed neighbor cannot be rendered at all, and letting it
// through would emit `neighbor  remote-as N` with a doubled space.

// isSingleFRRToken reports whether s is one unbroken FRR token: non-empty, and
// free of every byte FRR's lexer treats as a separator (space, tab, CR, LF,
// form feed, vertical tab) as well as the remaining control bytes and DEL,
// which would corrupt the rendered line. It is the commit-side twin of
// frr.validBGPNeighborAddress; the two must agree, and
// TestNeighborTokenGateAgreesWithTheRenderBelt6796 asserts that rather than
// pinning either to a literal.
func isSingleFRRToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}
func validateBGPNeighborAddressStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
		sort.SliceStable(neighbors, func(i, j int) bool {
			return neighbors[i].Address < neighbors[j].Address
		})
		for _, n := range neighbors {
			if n == nil {
				continue
			}
			if isSingleFRRToken(n.Address) {
				continue
			}
			detail := fmt.Sprintf("%sprotocols bgp neighbor %q", scope, n.Address)
			if n.GroupName != "" {
				detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %q", scope, n.GroupName, n.Address)
			}
			return fmt.Errorf("%s: not a single token — FRR's command lexer "+
				"splits on whitespace and has no quoted-string token, so a "+
				"neighbor identity carrying spaces or newlines renders as "+
				"MULTIPLE frr.conf statements and injects configuration the "+
				"operator did not write; use one unbroken address or peer name",
				detail)
		}
		return nil
	}

	if err := checkBGP("", cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkBGP(scope, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

// validateBGPNeighborPeerASStrict hard-rejects a BGP neighbor whose effective
// peer-as (remote-as) is missing/0 or out of the valid AS range (#2963).
//
// peer-as is optional in the parser/compiler (compiler_protocols.go assigns
// BGPNeighbor.PeerAS only when a per-neighbor `peer-as` token or an inherited
// group `peer-as` is present; otherwise it stays the zero value). The FRR
// renderer (pkg/frr/policy_render.go) emits `neighbor <addr> remote-as <PeerAS>`
// unconditionally, so a neighbor authored without a peer-as renders
// `neighbor <addr> remote-as 0`. AS 0 is reserved (RFC 7607) and FRR/vtysh
// rejects it: the whole frr-reload fails (a single vtysh -f add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED), leaving dynamic routing in a
// broken/stale state. That is a commit-accepted config the routing daemon
// cannot load — exactly the fail-class this gate closes.
//
// The valid 4-byte AS space is 1..4294967295 (uint32 max); 0 is reserved
// (RFC 7607) and 23456 (AS_TRANS) is reserved for 4-byte transition but is a
// legal configured remote-as, so only 0 is rejected here. (PeerAS is a uint32
// so the upper bound cannot be exceeded by the typed value — the range check
// documents intent and is robust to a future wider type.)
//
// Both the global `protocols bgp` and per-routing-instance scopes are checked.
// Neighbor addresses are sorted for a deterministic first-error message.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientBGPNeighborPeerAS) so an already-persisted or
// peer-synced config carrying such a neighbor still BOOTS (#1960
// fail-closed-on-load class); the render path now skips a remote-as-0 neighbor
// (defense-in-depth) so AS 0 never reaches frr.conf and a leniently-loaded bad
// neighbor is inert. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateBGPNeighborPeerASStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		neighbors := append([]*BGPNeighbor(nil), bgp.Neighbors...)
		sort.SliceStable(neighbors, func(i, j int) bool {
			return neighbors[i].Address < neighbors[j].Address
		})
		for _, n := range neighbors {
			if n == nil {
				continue
			}
			if n.PeerAS == 0 {
				detail := fmt.Sprintf("%sprotocols bgp neighbor %s", scope, n.Address)
				if n.GroupName != "" {
					detail = fmt.Sprintf("%sprotocols bgp group %s neighbor %s", scope, n.GroupName, n.Address)
				}
				return fmt.Errorf("%s: missing/invalid peer-as — a BGP neighbor "+
					"requires a peer-as (remote-as) in 1..4294967295; AS 0 is "+
					"reserved (RFC 7607) and FRR/vtysh rejects `remote-as 0`, "+
					"failing the frr-reload — set the neighbor (or its group) "+
					"peer-as", detail)
			}
		}
		return nil
	}

	if err := checkBGP("", cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkBGP(scope, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

// validateRouterIDStrict hard-rejects an OSPF / OSPFv3 / BGP router-id that is
// not a valid 32-bit IPv4 dotted-quad (#2980).
//
// router-id is parsed as a raw string and stored verbatim
// (compiler_protocols.go assigns OSPF/OSPFv3/BGP RouterID = child.Keys[1] with
// no validation). The FRR renderer (pkg/frr/policy_render.go) emits
// `ospf router-id <v>` / `ospf6 router-id <v>` / `bgp router-id <v>` whenever
// the field is non-empty. FRR/vtysh requires a 32-bit dotted-quad router-id
// for ALL of these protocols — including the IPv6 protocols OSPFv3 (ospf6) and
// BGP — and rejects anything else (e.g. `foo`, `300.1.2.3`, or an IPv6
// address): the whole frr-reload fails (a single vtysh -f add-batch exits
// non-zero on any CMD_WARNING_CONFIG_FAILED), leaving dynamic routing in a
// broken/stale state. That is a commit-accepted config the routing daemon
// cannot load — exactly the fail-class this gate closes.
//
// A router-id is the 32-bit dotted-quad form even for IPv6 protocols, so the
// check is net.ParseIP + To4()!=nil (net/netip ParseAddr+Is4 is equivalent;
// To4 keeps the validator on the same net.* surface the file already uses for
// other address checks). Empty is allowed at every scope — an unset router-id
// is omitted by the renderer and FRR auto-derives one, which is the documented
// Junos/FRR default.
//
// Both the global `protocols {}` and per-routing-instance scopes are checked,
// covering OSPF, OSPFv3, and BGP. Routing instances are walked in declaration
// order for a deterministic first-error message.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientRouterID) so an already-persisted or peer-synced config
// carrying a bad router-id still BOOTS (#1960 fail-closed-on-load class); the
// render path now skips an invalid router-id (defense-in-depth) so a malformed
// value never reaches frr.conf and a leniently-loaded bad router-id is inert.
// Commit / commit-check stay strict. Mirrors validateBGPNeighborPeerASStrict.
func validateRouterIDStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	check := func(scope, proto, routerID string) error {
		if routerID == "" {
			return nil
		}
		if ip := net.ParseIP(routerID); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%s%s router-id %q is not a valid IPv4 "+
				"dotted-quad address — FRR/vtysh requires a 32-bit IPv4 "+
				"router-id for all routing protocols (including OSPFv3 and "+
				"BGP) and rejects anything else, failing the frr-reload",
				scope, proto, routerID)
		}
		return nil
	}

	checkScope := func(scope string, ospf *OSPFConfig, ospfv3 *OSPFv3Config, bgp *BGPConfig) error {
		if ospf != nil {
			if err := check(scope, "protocols ospf", ospf.RouterID); err != nil {
				return err
			}
		}
		if ospfv3 != nil {
			if err := check(scope, "protocols ospf3", ospfv3.RouterID); err != nil {
				return err
			}
		}
		if bgp != nil {
			if err := check(scope, "protocols bgp", bgp.RouterID); err != nil {
				return err
			}
		}
		return nil
	}

	if err := checkScope("", cfg.Protocols.OSPF, cfg.Protocols.OSPFv3, cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instance %s ", ri.Name)
		if err := checkScope(scope, ri.OSPF, ri.OSPFv3, ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

// validateRibGroupImportRibReferencesStrict hard-rejects a
// `routing-options rib-groups <group> import-rib <rib>` entry whose rib
// name resolves to no real routing table (#2226).
//
// A valid import-rib names one of:
//   - inet.0 / inet6.0 (the main table), OR
//   - "<instance>.inet.0" / "<instance>.inet6.0" where <instance> is a
//     defined routing-instance.
//
// Any other name — a typo, a non-existent instance, or unparseable
// garbage — is undefined. ValidateConfig only ever emitted an over-limit
// WARNING for rib-groups; it never validated that an import-rib names a
// real rib. The applier's resolveRibTable previously mapped any
// unresolvable name to a bare table 0 (see pkg/routing/rules.go). Because
// a routing-instance's source table is always >= 100, an unresolvable
// import-rib yielded targetTable(0) != sourceTable, which set needsLeak
// and installed an `ip rule from all lookup <sourceTable> pref 33000` for
// a rib that does not exist — a silent mis-leak of the source table into
// the main lookup, with no diagnostic. This gate makes the dangling
// reference an operator-visible commit error; resolveRibTable's ok=false
// path is the defense-in-depth backstop for any reference that still
// reaches apply via the tolerant load / peer-sync path.
//
// Rib-group names are iterated in sorted order, and each group's
// import-rib list is walked in declaration order, so the first-reported
// error is deterministic (Go map order is randomized). Every defined
// rib-group is validated (not only ones referenced by an instance's
// interface-routes rib-group), mirroring Junos, which rejects an
// undefined rib regardless of whether the group is in use.
//
// On the tolerant load / peer-sync paths the call site downgrades this to
// a warning (opts.lenientRibGroupRefs) so an already-persisted or peer-
// synced config carrying a dangling import-rib still BOOTS (#1960
// fail-closed-on-load class); the applier's ok=false guard keeps it inert
// (the phantom rib is skipped, no rule is installed), exactly matching the
// post-fix runtime behaviour. Commit / commit-check stay strict. Mirrors
// validateRoutingExportReferencesStrict.
func validateRibGroupImportRibReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	ribGroups := cfg.RoutingOptions.RibGroups
	if len(ribGroups) == 0 {
		return nil
	}
	definedInstance := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			definedInstance[ri.Name] = true
		}
	}
	// resolvable mirrors pkg/routing.resolveRibTable's definedness view:
	// inet.0 / inet6.0, or "<defined-instance>.inet[6].0". The instance form
	// requires an EXACT family suffix (see ribInstanceFromName) — a loose
	// ".inet" substring match would accept malformed names like
	// "<instance>.inetX.0" and "<instance>.inet.0.garbage" (#2253). The
	// commit-time gate and pkg/routing's runtime applier MUST agree on what
	// resolves, so both call the same exact-suffix matcher (#2226).
	resolvable := func(ribName string) bool {
		if ribName == "inet.0" || ribName == "inet6.0" {
			return true
		}
		if instance, ok := ribInstanceFromName(ribName); ok {
			return definedInstance[instance]
		}
		return false
	}
	names := make([]string, 0, len(ribGroups))
	for name := range ribGroups {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rg := ribGroups[name]
		if rg == nil {
			continue
		}
		for _, ribName := range rg.ImportRibs {
			if ribName == "" || resolvable(ribName) {
				continue
			}
			return fmt.Errorf(
				"routing-options rib-groups %q import-rib %q references an "+
					"undefined rib (name a defined routing-instance as "+
					"\"<instance>.inet.0\" / \"<instance>.inet6.0\", or use "+
					"inet.0 / inet6.0 for the main table — an undefined rib "+
					"would otherwise silently leak this table's routes into "+
					"the main lookup)",
				name, ribName)
		}
	}
	return nil
}

// ribInstanceFromName extracts the routing-instance prefix from a non-default
// rib name of the EXACT form "<instance>.inet.0" or "<instance>.inet6.0",
// returning ok=false for any other shape. The instance prefix must be
// non-empty. Bare "inet.0" / "inet6.0" (the main table) are NOT instance ribs
// and are handled by callers directly. Malformed family tokens
// (".inetX.0", ".inetfoo.0", ".inet60.0") and trailing garbage (".inet.0.x")
// return ok=false (#2253). This mirrors pkg/routing.ribInstanceFromName — the
// two MUST stay in lockstep so the commit-time gate and the runtime applier
// agree on what resolves (#2226).
func ribInstanceFromName(ribName string) (string, bool) {
	for _, suffix := range []string{".inet.0", ".inet6.0"} {
		if instance, ok := strings.CutSuffix(ribName, suffix); ok && instance != "" {
			return instance, true
		}
	}
	return "", false
}

// validateNextTableTargetReferencesStrict hard-rejects a static route whose
// `next-table <target>` names a routing-instance that is NOT defined in the
// config (a typo, a deleted instance, or an unparseable target). next-table
// implements inter-VRF route leaking: the applier (pkg/routing.nextTableManager
// Apply) resolves the target to a kernel table id via a map keyed by
// routing-instance NAME. An unresolvable target had `tableIDs[...] == !ok`,
// so the applier logged a `slog.Warn("next-table references unknown routing
// instance")` and SKIPPED the rule — the leak silently never happened, with no
// commit-time diagnostic. Traffic that the operator intended to leak into
// another VRF instead followed the ingress table's own default (often the WAN
// default route), a silent mis-forward.
//
// The gate resolves the target with the SAME parseNextTableInstance the
// compiler and applier use (strip the trailing .inet[6].N suffix → instance
// name), then requires that name to be a defined routing-instance. This keeps
// the commit-time gate and the runtime applier in lockstep on what resolves
// (the #2226 rib-group doctrine). The error names the RAW next-table token the
// operator typed (route.NextTableRaw, preserved before the suffix strip, #5693)
// so a "Comcst.inet.0" typo is quoted verbatim rather than as the stripped
// "Comcst".
//
// The GLOBAL inet.0 + inet6.0 static routes are validated for target
// DEFINEDNESS — those are exactly the routes daemon_apply feeds to
// ApplyNextTableRules (daemon_apply.go). A next-table authored UNDER a
// routing-instance is a different case (#5830): it is not programmed on the
// kernel/FRR plane AT ALL (daemon_apply passes only the global statics; the
// FRR renderer emits nothing for a NextTable route) yet the userspace FIB used
// to publish it as a live route — a split-brain that leaked traffic in the
// userspace dataplane with no kernel/FRR equivalent and, for an undefined
// target, bypassed the definedness gate above. So the second loop rejects ANY
// per-instance next-table as an unsupported forwarding disposition (defined or
// undefined target); the userspace snapshot no longer publishes it
// (pkg/dataplane/userspace/routes.go). Supporting per-instance next-table for
// real needs source-table-scoped (iif/fwmark) ip rules — a feature deferred
// alongside the rib-group VRF->VRF Phase-2 work, not a bug fix. Routes are
// walked inet.0 then inet6.0 in declaration order so the first-reported error
// is deterministic.
//
// Strict on commit / commit-check (hard reject so the typo is operator-
// visible); the call site downgrades this to a warning on the tolerant load /
// peer-sync paths (opts.lenientNextTableRefs) so an already-persisted or peer-
// synced config carrying a dangling next-table still BOOTS (#1960
// fail-closed-on-load class) — the applier's tableIDs !ok guard keeps it inert.
// Mirrors validateRibGroupImportRibReferencesStrict.
func validateNextTableTargetReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	definedInstance := make(map[string]bool, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri != nil && ri.Name != "" {
			definedInstance[ri.Name] = true
		}
	}
	routeSets := [][]*StaticRoute{
		cfg.RoutingOptions.StaticRoutes,
		cfg.RoutingOptions.Inet6StaticRoutes,
	}
	for _, routes := range routeSets {
		for _, sr := range routes {
			if sr == nil || sr.NextTable == "" {
				continue
			}
			if definedInstance[sr.NextTable] {
				continue
			}
			raw := sr.NextTableRaw
			if raw == "" {
				raw = sr.NextTable
			}
			return fmt.Errorf(
				"routing-options static route %q next-table %q references an "+
					"undefined routing-instance %q; define `set routing-instances "+
					"%s instance-type ...` in the same commit or the next-table "+
					"leak is silently dropped at apply time and matching traffic "+
					"follows the ingress table's own routes",
				sr.Destination, raw, sr.NextTable, sr.NextTable)
		}
	}

	// #5830: reject ANY next-table authored under a routing-instance. Unlike
	// the global routes above, a per-instance next-table is not programmed on
	// the kernel/FRR forwarding plane (see this function's doc comment), so a
	// defined OR undefined target is unsupported — accepting it published a
	// userspace-only NextTable leak with no kernel/FRR equivalent (a split-
	// brain) and let an undefined per-instance target sidestep the definedness
	// gate above. Walk each instance's inet.0 then inet6.0 route set in
	// declaration order so the first-reported error is deterministic. Strict on
	// commit / commit-check; downgraded to a warning on the tolerant load /
	// peer-sync paths (opts.lenientNextTableRefs — same wiring as the global
	// gate) so an already-persisted or peer-synced legacy config carrying a
	// per-instance next-table still BOOTS (the userspace snapshot drops it and
	// the kernel/FRR plane never programmed it, so it stays inert).
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name == "" {
			continue
		}
		for _, routes := range [][]*StaticRoute{ri.StaticRoutes, ri.Inet6StaticRoutes} {
			for _, sr := range routes {
				if sr == nil || sr.NextTable == "" {
					continue
				}
				raw := sr.NextTableRaw
				if raw == "" {
					raw = sr.NextTable
				}
				undefinedNote := ""
				if !definedInstance[sr.NextTable] {
					undefinedNote = fmt.Sprintf(
						" (its target routing-instance %q is also undefined)", sr.NextTable)
				}
				return fmt.Errorf(
					"routing-instances %s static route %q next-table %q is not "+
						"supported: a next-table under a routing-instance is not "+
						"programmed on the kernel/FRR forwarding plane and would "+
						"leak only in the userspace dataplane (a split-brain); move "+
						"the leak to the global `routing-options static route %s "+
						"next-table %s` or remove it%s",
					ri.Name, sr.Destination, raw, sr.Destination, raw, undefinedNote)
			}
		}
	}
	return nil
}

// staticRouteDispositionConflict names the mutually-exclusive dispositions a
// single compiled StaticRoute carries. A well-formed static route has exactly
// ONE of: forwarding next-hop(s), a next-table VRF leak, discard, or reject.
// Multiple next-hops for one destination are legitimate ECMP / qualified-
// next-hop (all the single "next-hop" disposition) and are NOT a conflict. The
// helper returns "" when at most one disposition is present, otherwise a
// human-readable `a + b`-style list of the ≥2 distinct dispositions found.
func staticRouteDispositionConflict(sr *StaticRoute) string {
	if sr == nil {
		return ""
	}
	var found []string
	if len(sr.NextHops) > 0 {
		found = append(found, "next-hop")
	}
	if sr.NextTable != "" {
		found = append(found, "next-table")
	}
	if sr.Discard {
		found = append(found, "discard")
	}
	if sr.Reject {
		found = append(found, "reject")
	}
	if len(found) < 2 {
		return ""
	}
	return strings.Join(found, " + ")
}

// validateStaticRouteDispositionConflictStrict hard-rejects a static route that
// carries MORE THAN ONE mutually-exclusive disposition for a single destination
// prefix — e.g. `discard` together with a reachable `next-hop`, a `next-table`
// VRF leak together with a `next-hop`, or `discard` together with `reject`.
//
// The compiler merges repeated same-destination static-route blocks (flat "set"
// syntax emits one block per line) into a single StaticRoute
// (compileStaticRoutes): next-hops are APPENDED and the terminal / next-table
// fields are STICKY (discard/reject latch true, next-table/preference are
// last-writer-wins). A config that declares the SAME prefix once as `discard`
// (or `next-table X`) and once with a `next-hop` therefore compiled into ONE
// route holding BOTH a blackhole/leak AND a forwarding next-hop — a
// contradiction that passed the strict gate. The live snapshot copies every
// field (pkg/dataplane/userspace/routes.go) and the Rust forwarder resolves
// discard before next-table before next-hops
// (userspace-dp/src/afxdp/forwarding/mod.rs), so the stale terminal / leak wins
// and a later next-hop meant to RESTORE ordinary forwarding is silently ignored
// — a blackhole or a cross-VRF leak the operator did not author (#5633).
//
// Junos permits exactly one action per static route. Rejecting the mix at commit
// keeps the compiled route unambiguous and the operator informed rather than
// letting the dataplane pick a precedence the config never expressed. Multiple
// next-hops for one destination stay legitimate ECMP and do NOT trip this gate.
//
// Strict on commit / commit-check (hard reject so the contradiction is
// operator-visible); the call site downgrades this to a warning on the tolerant
// load / peer-sync path (opts.lenientRouteDispositionConflict, #1960) so an
// already-persisted or peer-synced config still BOOTS — the dataplane then
// resolves the deterministic disposition precedence. Global inet.0/inet6.0 are
// walked first, then each routing-instance's routes in RoutingInstances order,
// so the first-reported error is deterministic. Mirrors
// validateNextTableTargetReferencesStrict.
func validateStaticRouteDispositionConflictStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, routes []*StaticRoute) error {
		for _, sr := range routes {
			conflict := staticRouteDispositionConflict(sr)
			if conflict == "" {
				continue
			}
			return fmt.Errorf(
				"%s %q defines contradictory dispositions (%s) for one "+
					"destination prefix; a static route may carry only ONE of "+
					"next-hop, next-table, discard, or reject (repeated "+
					"same-prefix `set` lines merge into a single route). Split "+
					"the destinations or keep one disposition — otherwise the "+
					"dataplane silently resolves the terminal/leak action and "+
					"ignores the forwarding next-hop",
				scope, sr.Destination, conflict)
		}
		return nil
	}
	if err := check("routing-options static route", cfg.RoutingOptions.StaticRoutes); err != nil {
		return err
	}
	if err := check("routing-options static route", cfg.RoutingOptions.Inet6StaticRoutes); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		scope := fmt.Sprintf("routing-instances %s static route", ri.Name)
		if err := check(scope, ri.StaticRoutes); err != nil {
			return err
		}
		if err := check(scope, ri.Inet6StaticRoutes); err != nil {
			return err
		}
	}
	return nil
}

// validateRouteFilterMatchTypesStrict gates the two route-filter match-types
// that the FRR prefix-list backend cannot render losslessly (#2525):
//
//   - "through <prefix2>" has NO FRR equivalent. Junos "through" matches the
//     base prefix, prefix2, and only the prefixes on the direct radix-tree
//     path between them — not every prefix of intermediate length. FRR
//     prefix-lists express only length ranges (ge/le), so any rendering would
//     change the match set. Reject it loudly rather than silently degrade.
//
//   - "prefix-length-range /low-/high" maps to FRR "ge low le high", but only
//     when the bounds are well-formed. Reject a malformed, inverted, out-of-
//     family-range, or below-base range so the operator fixes it instead of
//     getting the pre-#2525 silent open-ended "le maxLen" fall-through.
//
// Strict on commit / commit-check (hard reject so the unsupported / malformed
// match-type is operator-visible); the compiler downgrades this to a warning on
// the tolerant load / peer-sync path (#1960) so an already-persisted or
// peer-synced config still boots — the renderer then skips the offending entry
// (match-nothing, fail-closed). Runs on the fully-compiled *Config.
func validateRouteFilterMatchTypesStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statements by sorted name.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ps := cfg.PolicyOptions.PolicyStatements[name]
		if ps == nil {
			continue
		}
		for _, term := range ps.Terms {
			if term == nil {
				continue
			}
			for _, rf := range term.RouteFilters {
				if rf == nil {
					continue
				}
				switch rf.MatchType {
				case "through":
					return fmt.Errorf(
						"policy-statement %q term %q route-filter %q through %q: the "+
							"`through` match-type is not supported by the FRR routing "+
							"backend — it matches a two-prefix containment path that has "+
							"no lossless prefix-list (ge/le) equivalent. Use "+
							"`prefix-length-range /<low>-/<high>`, `upto /<n>`, or "+
							"`orlonger` instead",
						name, term.Name, rf.Prefix, rf.ThroughPrefix)
				case "prefix-length-range":
					if err := validatePrefixLengthRange(rf); err != nil {
						return fmt.Errorf(
							"policy-statement %q term %q route-filter %q prefix-length-range: %v",
							name, term.Name, rf.Prefix, err)
					}
				}
			}
		}
	}
	return nil
}

// validatePrefixLengthRange enforces the semantic constraints on a
// prefix-length-range route-filter (#2525): both bounds parsed (non-zero), the
// per-family max not exceeded, low<=high, and low at least the base prefix
// length (Junos requires the range to be no less specific than the base).
func validatePrefixLengthRange(rf *RouteFilter) error {
	maxLen := 32
	if strings.Contains(rf.Prefix, ":") {
		maxLen = 128
	}
	if rf.RangeLow == 0 || rf.RangeHigh == 0 {
		return fmt.Errorf(
			"malformed range (expected /<low>-/<high> with both lengths in 1..%d, e.g. /16-/24)",
			maxLen)
	}
	if rf.RangeLow > maxLen || rf.RangeHigh > maxLen {
		return fmt.Errorf(
			"range /%d-/%d exceeds the address-family maximum /%d",
			rf.RangeLow, rf.RangeHigh, maxLen)
	}
	if rf.RangeLow > rf.RangeHigh {
		return fmt.Errorf(
			"inverted range /%d-/%d (low must be <= high)",
			rf.RangeLow, rf.RangeHigh)
	}
	// The base prefix length floors the range: the range low bound must be
	// STRICTLY more specific than the base prefix. Junos requires this, and FRR
	// rejects a prefix-list whose `ge` value is not strictly greater than the
	// prefix length ("len < ge-value"). Accepting RangeLow == baseLen would emit
	// `ge baseLen le high` → FRR rejects the line → frr-reload exits non-zero on
	// the whole managed batch → FRR brick (#1880-class). The renderer carries
	// the same guard for the lenient (downgraded-to-warning) path.
	if _, ipnet, err := net.ParseCIDR(rf.Prefix); err == nil {
		baseLen, _ := ipnet.Mask.Size()
		if rf.RangeLow <= baseLen {
			return fmt.Errorf(
				"range low /%d must be more specific than the base prefix /%d "+
					"(low > base; FRR rejects a ge value not strictly greater "+
					"than the prefix length)",
				rf.RangeLow, baseLen)
		}
	}
	return nil
}

// ReservedRedistSuffix is the route-map name suffix xpf RESERVES for the
// per-use-site fail-closed redistribute aliases the FRR renderer derives
// (redistFailClosedRouteMap in pkg/frr/policy_render.go emits `name + suffix`).
// FRR keys route-maps by NAME in a single GLOBAL namespace, so an operator
// policy-statement whose name ends in this suffix would collide with a
// generated alias in that shared object and could silently undo the #4481
// fail-closed BGP/IGP separation — reintroducing route redistribution leakage
// under a config that otherwise passes validation (#5116). The alias derivation
// (pkg/frr) and the strict validator below MUST agree on this exact string;
// pkg/frr references this constant so the two never drift.
const ReservedRedistSuffix = "-xpf-redist"

// validatePolicyReservedRedistNameStrict hard-rejects an operator
// policy-statement whose name ends in the reserved ReservedRedistSuffix. That
// suffix is owned by the FRR renderer's generated fail-closed redistribute
// aliases (#4481); an operator name in that namespace can collide with a
// generated alias in FRR's global name-keyed route-map object and silently
// reintroduce BGP/IGP redistribution leakage (#5116). Reserving the suffix at
// commit makes the generated-alias namespace injective BY CONSTRUCTION — no
// legal config can name a policy-statement into the generated slot.
//
// Strict on commit / commit-check (hard reject so the reserved name is
// operator-visible); lenient on load / peer-sync (warn so an already-persisted
// or peer-synced config an older binary accepted still boots — #1960
// fail-closed-on-load class). The render-side defense-in-depth (redistAliasCollision
// in pkg/frr) fails the whole managed-section apply CLOSED on the tolerant path,
// so a leniently-loaded collision cannot leak. Runs on the fully-compiled
// *Config so the policy-statement map is populated regardless of authoring
// order. Mirrors validateRoutingExportReferencesStrict.
func validatePolicyReservedRedistNameStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statement names in sorted order.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, ReservedRedistSuffix) {
			return fmt.Errorf(
				"policy-statement %q ends in the reserved %q suffix; xpf owns "+
					"that suffix for generated fail-closed redistribute route-map "+
					"aliases (#4481/#5116) and an operator name in that namespace "+
					"can collide with a generated alias in FRR's global route-map "+
					"object, silently reintroducing BGP/IGP redistribution leakage "+
					"— rename the policy-statement off the reserved suffix",
				name, ReservedRedistSuffix)
		}
	}
	return nil
}

// ReservedChainSuffix is the route-map name suffix xpf RESERVES for the composed
// BGP policy-chain route-maps the FRR renderer derives for an ordered
// import/export policy list of length >= 2 (composedChainName in pkg/frr joins
// the member policy names and appends this suffix). FRR keys route-maps by NAME
// in a single GLOBAL namespace, so an operator policy-statement whose name ends
// in this suffix would collide with a generated composed route-map in that
// shared object and FRR would MERGE the two same-named definitions, silently
// altering the operator's BGP filtering (#5277/#5442). The composed-name
// derivation (pkg/frr) and the strict validator below MUST agree on this exact
// string; pkg/frr re-exports this constant (frr.ReservedChainSuffix =
// config.ReservedChainSuffix) so the two never drift.
const ReservedChainSuffix = "-xpf-chain"

// validatePolicyReservedChainNameStrict hard-rejects an operator
// policy-statement whose name ends in the reserved ReservedChainSuffix. That
// suffix is owned by the FRR renderer's generated composed BGP policy-chain
// route-maps (#5277): an ordered import/export chain of length >= 2 is joined
// and suffixed with ReservedChainSuffix (composedChainName in pkg/frr). An
// operator name in that suffix namespace can collide with a generated composed
// route-map in FRR's global name-keyed route-map object; FRR MERGES two
// same-named route-map definitions, silently altering the operator's BGP
// filtering (#5442). Reserving the suffix at commit makes the composed-name
// namespace injective against operator policy-statements BY CONSTRUCTION — no
// legal config can name a policy-statement into the generated slot.
//
// Strict on commit / commit-check (hard reject so the reserved name is
// operator-visible); lenient on load / peer-sync (warn so an already-persisted
// or peer-synced config an older binary accepted still boots — #1960
// fail-closed-on-load class). The render-side defense-in-depth
// (bgpComposedChainCollision in pkg/frr) fails the whole managed-section apply
// CLOSED on the tolerant path, so a leniently-loaded collision cannot leak. Runs
// on the fully-compiled *Config so the policy-statement map is populated
// regardless of authoring order. Mirrors validatePolicyReservedRedistNameStrict.
func validatePolicyReservedChainNameStrict(cfg *Config) error {
	if cfg == nil || cfg.PolicyOptions.PolicyStatements == nil {
		return nil
	}
	// Deterministic first-error: iterate policy-statement names in sorted order.
	names := make([]string, 0, len(cfg.PolicyOptions.PolicyStatements))
	for name := range cfg.PolicyOptions.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, ReservedChainSuffix) {
			return fmt.Errorf(
				"policy-statement %q ends in the reserved %q suffix; xpf owns "+
					"that suffix for generated composed BGP policy-chain "+
					"route-maps (#5277/#5442) and an operator name in that "+
					"namespace can collide with a generated composed route-map "+
					"in FRR's global route-map object, which FRR would merge — "+
					"silently altering BGP route filtering — rename the "+
					"policy-statement off the reserved suffix",
				name, ReservedChainSuffix)
		}
	}
	return nil
}

// validatePolicyASPathRegexStrict hard-rejects a `policy-options as-path
// <name>` whose regular expression cannot be rendered into frr.conf at
// all — an EMPTY regex, or one that is not a valid POSIX extended regular
// expression (#6686).
//
// xpf renders one `bgp as-path access-list <name> permit <regex>` line per
// definition (pkg/frr/policy_render.go). FRR's DEFUN for that command ends
// in a variadic `LINE...` parameter which argv_concat joins back with
// single spaces, which is what makes a multi-AS regex like `.* 65000 .*`
// expressible at all — but it also means an ABSENT regex is an incomplete
// command, and a malformed one fails FRR's regcomp. Either is a
// CMD_WARNING_CONFIG_FAILED, and a single such failure exits the whole
// vtysh add-batch non-zero: it does not merely drop this one access-list,
// it fails the ENTIRE frr-reload and leaves every dynamic routing change
// stale.
//
// An empty regex was reachable with no diagnostic at all: `set
// policy-options as-path AP1` with no value compiled to an ASPathDef with
// Regex "" and committed clean.
//
// On the tolerant load / peer-sync paths the call site downgrades this to
// a warning (opts.lenientPolicyASPathRegex) so an already-persisted or
// peer-synced config still boots (#1960 fail-closed-on-load class);
// pkg/frr's ValidASPathRegex belt then keeps the unrenderable definition
// out of frr.conf on that path, so the reload survives. Commit /
// commit-check stay strict. Runs on the fully-compiled *Config so the
// as-path map is populated regardless of authoring order. Mirrors
// validatePolicyCommunityReferencesStrict.
// validatePolicyCommunityRegexStrict hard-rejects a `policy-options community`
// member that xpf cannot render into a loadable frr.conf line — the sibling of
// validatePolicyASPathRegexStrict that #6686 never got (#8449).
//
// A member carrying a regex metacharacter renders into an FRR `expanded`
// community-list, where FRR runs it through regcomp. One that does not compile
// is a CMD_WARNING_CONFIG_FAILED, and a single such failure exits the whole
// vtysh add-batch non-zero — failing the ENTIRE frr-reload, not just this list,
// and leaving every dynamic routing change stale.
//
// Note which malformed members reached this gate before it existed and which
// did not: `65000:(`, `65000:a{3,1}` and `65000:\` are rejected by the LEXER as
// `unexpected character`, an accident of tokenization rather than a gate, while
// `65000:[` and `*65000` committed clean and were rendered verbatim. That
// partial coverage is why the hole was easy to miss — a spot check of malformed
// members mostly returns "rejected".
//
// Pairs with the render-side belt in pkg/frr (generatePolicyOptions), which
// shares ValidCommunityMember so the two cannot drift.
func validatePolicyCommunityRegexStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Sort for a deterministic first-error message (map order is random).
	names := make([]string, 0, len(cfg.PolicyOptions.Communities))
	for name := range cfg.PolicyOptions.Communities {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		cd := cfg.PolicyOptions.Communities[name]
		if cd == nil {
			continue
		}
		for _, member := range cd.Members {
			if err := ValidCommunityMember(member); err != nil {
				return fmt.Errorf("policy-options community %s members %q: %v — xpf "+
					"renders `bgp community-list <standard|expanded> %s permit %s`, which "+
					"frr-reload rejects, failing the entire FRR config load; "+
					"write the member as a QUOTED value if it is meant as a "+
					"literal, e.g. `set policy-options community %s members "+
					"\"65000:100\"`",
					name, member, err, name, member, name)
			}
		}
	}
	return nil
}

func validatePolicyASPathRegexStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Sort for a deterministic first-error message (the typed-config map
	// iteration order is otherwise random).
	names := make([]string, 0, len(cfg.PolicyOptions.ASPaths))
	for name := range cfg.PolicyOptions.ASPaths {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		ap := cfg.PolicyOptions.ASPaths[name]
		if ap == nil {
			continue
		}
		if err := ValidASPathRegex(ap.Regex); err != nil {
			return fmt.Errorf("policy-options as-path %s: %v — xpf renders "+
				"`bgp as-path access-list %s permit %s`, which frr-reload "+
				"rejects (failing the entire FRR config load); write the "+
				"regular expression as a QUOTED value, e.g. "+
				"`set policy-options as-path %s \".* 65000 .*\"`",
				name, err, name, ap.Regex, name)
		}
	}
	return nil
}

// validateBGPDuplicateNeighborStrict hard-rejects one BGP neighbor address
// appearing in TWO DIFFERENT `protocols bgp group` blocks within a single BGP
// instance (#9007).
//
// Junos rejects this at commit; xpf accepted it with zero warnings. The typed
// config keeps a *BGPNeighbor per authored (group, neighbor) pair, and
// pkg/frr/protocols_render.go builds its `validNeighbors` set by filtering
// only on PeerAS and address shape -- there is no dedup on Address. Every
// downstream loop (the neighbor declaration, the address-family activation,
// and the BFD peer accumulator) then iterates that slice PER ENTRY, so the
// address renders once per group: two `remote-as`, two `timers`, two
// `password` lines and two `bfd` peer blocks for one peer.
//
// The password line is the sharp edge. The other divergences are
// misconfigurations an operator can eventually observe; the authentication
// key is not. One of two secrets is selected by render order, silently, while
// `show` keeps reporting both groups exactly as authored -- so the operator's
// view and FRR's behaviour disagree with nothing in the product signalling
// that they do.
//
// DIFFERENT groups is the whole condition, and the narrowness is load-bearing.
// The compiler emits one *BGPNeighbor PER AST NODE, and a single authored
// neighbor can occupy several nodes: `set protocols bgp group G neighbor X`
// followed by `set protocols bgp group G neighbor X import PS` -- ordinary
// flat-set authoring, and the shape the slot-escape fixtures use -- yields TWO
// entries for one peer, both in group G, one carrying the import policy. Those
// are not an operator error and must not be rejected: they render redundantly
// (a repeated `remote-as` line, which FRR accepts) but CORRECTLY, because the
// second entry is what carries `activate` and the route-map. A gate keyed on
// the address alone would blame the operator for a compiler artifact, and a
// render-side first-wins dedup would silently DROP the policy-bearing entry.
// Tracked separately; this gate deliberately says nothing about it.
//
// Scope: the check partitions by BGP INSTANCE. The same neighbor address in
// two different routing instances is legitimate (separate VRFs peering with
// one address is ordinary), so duplicates are sought only WITHIN one
// BGPConfig, never across them.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientBGPDuplicateNeighbor) so an already-persisted or
// peer-synced config still BOOTS (#1960 fail-closed-on-load class). Commit /
// commit-check stay strict. Mirrors validateBGPNeighborPeerASStrict.
func validateBGPDuplicateNeighborStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	checkBGP := func(scope string, bgp *BGPConfig) error {
		if bgp == nil {
			return nil
		}
		// first[addr] is the group that claimed the address earliest in
		// authoring order. A later entry for that address matters only when
		// it names a DIFFERENT group; repeats within one group are the
		// per-AST-node artifact described above.
		first := make(map[string]string, len(bgp.Neighbors))
		var dups []string
		for _, n := range bgp.Neighbors {
			if n == nil {
				continue
			}
			prev, seen := first[n.Address]
			if !seen {
				first[n.Address] = n.GroupName
				continue
			}
			if prev == n.GroupName {
				continue
			}
			dups = append(dups, fmt.Sprintf("%sprotocols bgp neighbor %q is configured in "+
				"more than one group (%s and %s)", scope, n.Address, prev, n.GroupName))
		}
		if len(dups) == 0 {
			return nil
		}
		sort.Strings(dups)
		return fmt.Errorf("%s: one neighbor address renders once per group that "+
			"names it, so FRR receives two divergent definitions (including two "+
			"`password` lines) for one peer and resolves them by render order; "+
			"give the peer a single group", dups[0])
	}

	if err := checkBGP("", cfg.Protocols.BGP); err != nil {
		return err
	}
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		if err := checkBGP(fmt.Sprintf("routing-instance %s ", ri.Name), ri.BGP); err != nil {
			return err
		}
	}
	return nil
}

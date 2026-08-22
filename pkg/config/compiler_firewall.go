package config

import (
	"fmt"
	"strconv"
	"strings"
)

func compileFirewall(node *Node, fw *FirewallConfig) error {
	if fw.FiltersInet == nil {
		fw.FiltersInet = make(map[string]*FirewallFilter)
	}
	if fw.FiltersInet6 == nil {
		fw.FiltersInet6 = make(map[string]*FirewallFilter)
	}
	if fw.Policers == nil {
		fw.Policers = make(map[string]*PolicerConfig)
	}

	// Compile policer definitions
	for _, polInst := range namedInstances(node.FindChildren("policer")) {
		pol := &PolicerConfig{
			Name:       polInst.name,
			ThenAction: "discard", // default action
		}

		ifExceeding := polInst.node.FindChild("if-exceeding")
		if ifExceeding != nil {
			for _, child := range ifExceeding.Children {
				switch child.Name() {
				case "bandwidth-limit":
					if v := nodeVal(child); v != "" {
						pol.BandwidthLimit = parseBandwidthLimit(v)
					}
				case "burst-size-limit":
					if v := nodeVal(child); v != "" {
						pol.BurstSizeLimit = parseBurstSizeLimit(v)
					}
				}
			}
		}

		thenNode := polInst.node.FindChild("then")
		if thenNode != nil {
			for _, child := range thenNode.Children {
				switch child.Name() {
				case "discard":
					pol.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						pol.ThenAction = "loss-priority " + v
					}
				}
			}
		}

		// Check for logical-interface-policer flag
		if polInst.node.FindChild("logical-interface-policer") != nil {
			pol.LogicalInterfacePolicer = true
		}

		fw.Policers[pol.Name] = pol
	}

	// Compile three-color policer definitions
	if fw.ThreeColorPolicers == nil {
		fw.ThreeColorPolicers = make(map[string]*ThreeColorPolicerConfig)
	}
	for _, tcpInst := range namedInstances(node.FindChildren("three-color-policer")) {
		tcp := fw.ThreeColorPolicers[tcpInst.name]
		if tcp == nil {
			tcp = &ThreeColorPolicerConfig{
				Name:       tcpInst.name,
				ThenAction: "discard",
			}
			fw.ThreeColorPolicers[tcpInst.name] = tcp
		}

		singleRates := tcpInst.node.FindChildren("single-rate")
		if len(singleRates) > 0 {
			tcp.SingleRateConfigured = true
			tcp.TwoRate = false
		}
		for _, sr := range singleRates {
			if sr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if sr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range sr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "excess-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		twoRates := tcpInst.node.FindChildren("two-rate")
		if len(twoRates) > 0 {
			tcp.TwoRateConfigured = true
			tcp.TwoRate = true
		}
		for _, tr := range twoRates {
			if tr.FindChild("color-blind") != nil {
				tcp.ColorBlind = true
				tcp.ColorBlindConfigured = true
			}
			if tr.FindChild("color-aware") != nil {
				tcp.ColorAwareConfigured = true
			}
			for _, child := range tr.Children {
				switch child.Name() {
				case "committed-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.CIR = parseBandwidthLimit(v)
					}
				case "committed-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.CBS = parseBurstSizeLimit(v)
					}
				case "peak-information-rate":
					if v := nodeVal(child); v != "" {
						tcp.PIR = parseBandwidthLimit(v)
					}
				case "peak-burst-size":
					if v := nodeVal(child); v != "" {
						tcp.PBS = parseBurstSizeLimit(v)
					}
				}
			}
		}

		if thenNode := tcpInst.node.FindChild("then"); thenNode != nil {
			for _, child := range thenNode.Children {
				switch child.Name() {
				case "discard":
					tcp.ThenAction = "discard"
				case "loss-priority":
					if v := nodeVal(child); v != "" {
						tcp.ThenAction = "loss-priority " + v
					}
				}
			}
		}
	}

	// #4535: a three-color policer with NEITHER `color-blind` nor
	// `color-aware` configured defaults to COLOR-BLIND mode, matching
	// Junos (which accepts and enforces such a policer). Without this
	// default the snapshot carries color_blind=false, which the userspace
	// capability gate (userspaceSupportsThreeColorPolicers) treats as
	// unsupported color-aware mode and disarms the WHOLE dataplane
	// (ForwardingSupported=false) — refusing a valid Junos config outright.
	// Applied after all instances merge so a color statement split across
	// set-lines / firewall blocks is fully observed first. Only the
	// UNSPECIFIED case changes: explicit `color-aware` keeps ColorBlind
	// false (its documented unsupported-mode disarm is unchanged),
	// explicit `color-blind` keeps it true.
	for _, tcp := range fw.ThreeColorPolicers {
		if tcp == nil {
			continue
		}
		if !tcp.ColorBlindConfigured && !tcp.ColorAwareConfigured {
			tcp.ColorBlind = true
		}
	}

	for _, familyNode := range node.FindChildren("family") {
		var afNodes []*Node
		var afName string

		if len(familyNode.Keys) >= 2 {
			// Hierarchical: family inet { ... }
			afName = familyNode.Keys[1]
			afNodes = []*Node{familyNode}
		} else {
			// Set-command shape: family { inet { ... } inet6 { ... } }
			for _, child := range familyNode.Children {
				afNodes = append(afNodes, child)
			}
		}

		for _, afNode := range afNodes {
			af := afName
			if af == "" {
				// #4827: Name() safely returns "" for an empty Keys slice —
				// afNode.Keys[0] would panic (index out of range) on a
				// malformed persisted Node reaching this compile path (a
				// corrupted on-disk config-store JSON blob;
				// pkg/configstore/db.go's plain json.Unmarshal has no Node
				// validator). The live parser/SetPath paths structurally
				// guarantee len(Keys) >= 1, so this only ever bites a
				// corrupted store, but a bad persisted state must error on
				// load, never panic (#1960 fail-closed-on-load doctrine).
				af = afNode.Name()
				if len(afNode.Keys) >= 2 {
					af = afNode.Keys[1]
				}
			}

			// #4287: a Junos `family any` filter is protocol-independent —
			// it matches BOTH IPv4 and IPv6. Folding it into FiltersInet
			// only (the pre-#4287 behavior for every non-inet6 family) lost
			// its IPv6 arm: a `family any` discard/deny filter enforced on
			// v4 only silently let v6 through (a security fail-open). Compile
			// it into BOTH pools so the deny applies to both families. The
			// #3884 cross-family same-name collision gate
			// (validateFirewallFilterFamilyCollisionsAST) now also treats an
			// `any`+`inet6` same-name reuse as a collision, since `any` folds
			// into FiltersInet6 too — a name shared with a distinct inet6
			// filter would otherwise silently overwrite in FiltersInet6.
			dests := []map[string]*FirewallFilter{fw.FiltersInet}
			switch af {
			case "inet6":
				dests = []map[string]*FirewallFilter{fw.FiltersInet6}
			case "any":
				dests = []map[string]*FirewallFilter{fw.FiltersInet, fw.FiltersInet6}
			}

			for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
				filter := &FirewallFilter{Name: filterInst.name}

				// #4316 (fable-167 F-3a): record interface-specific so the
				// commit advisory can flag the single-shared-counter divergence.
				if filterInst.node.FindChild("interface-specific") != nil {
					filter.InterfaceSpecific = true
				}

				for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
					term := &FirewallFilterTerm{
						Name: termInst.name,
					}

					// #3850: apply EVERY `from {}` block, not just the first via
					// FindChild — a duplicate block (a `load merge`/`load
					// override` that splits its conditions, or a hierarchical
					// config authored twice) must AND-combine every condition,
					// never be dropped (a fail-open widening of the term match).
					// compileFilterFrom accumulates into term. Flat-set is
					// unaffected: SetPath merges duplicate containers into one
					// node (ast_edit.go), so this only changes the hierarchical
					// (parser / load merge) shape.
					for _, fromNode := range termInst.node.FindChildren("from") {
						compileFilterFrom(fromNode, term, af)
					}

					// #3850: apply EVERY `then {}` block. compileFilterThen
					// accumulates modifiers (count/log/forwarding-class/...); a
					// terminal action (accept/discard/reject) resolves last-wins
					// across blocks (Junos merges duplicate stanzas), so the
					// second block's action is applied, never silently dropped.
					for _, thenNode := range termInst.node.FindChildren("then") {
						compileFilterThen(thenNode, term)
					}

					// #3076: a tcp-flags expression the dataplane cannot enforce
					// (disjunction, a negated group, an unknown flag, or a
					// self-contradictory required/forbidden pair) is rejected —
					// without a reject such an expression committed cleanly and
					// the constraint was silently dropped on the wire (fail-open).
					// #4953: the reject moved OUT of the section compiler and into
					// the strict/tolerant gate validateFirewallTCPFlagsStrict
					// (runUniformGates) so the commit / commit-check path still
					// hard-rejects but the load / peer-sync path downgrades to a
					// warning — an already-persisted or peer-synced config an
					// older binary accepted still BOOTS (#1960 no-brick). The term
					// keeps its raw (unparseable) TCPFlags, which the userspace
					// snapshot builder detects and marks TCPFlagsUnparseable so the
					// Rust filter compiler fails the term CLOSED (#3367) — the raw
					// value IS the deny sentinel, never widening to match-all.

					filter.Terms = append(filter.Terms, term)
				}

				for _, dest := range dests {
					dest[filter.Name] = filter
				}
			}
		}
	}
	return nil
}

// validateFirewallFilterFamilyCollisionsAST walks every top-level `firewall`
// node and rejects a firewall-filter NAME reused across two DIFFERENT non-inet6
// families (#3884, fable-review-161 F-030).
//
// compileFirewall selects the destination map with `dest := fw.FiltersInet`
// (compiler_firewall.go) and only switches to fw.FiltersInet6 when the family
// is literally "inet6" — so EVERY other family (inet, any, mpls, ccc, vpls,
// bridge, and any not-yet-modelled token, since SchemaValidate does not reject
// an unknown family keyword) folds into the single fw.FiltersInet pool, then
// writes `dest[filter.Name] = filter` unconditionally. A same-name filter
// authored under a second such family therefore silently OVERWRITES the first
// (last-write-wins). If `family inet filter blockX { ... then discard; }` is
// followed by `family any filter blockX { ... then accept; }`, the effective
// IPv4 filter becomes accept-all — a deny silently downgraded to an accept
// (a security fail-open).
//
// Downstream consumers reference filters by NAME within the inet (V4) / inet6
// (V6) buckets only — an interface unit's FilterInputV4 resolves against
// fw.FiltersInet, FilterInputV6 against fw.FiltersInet6 (compiler_validate_warn.go,
// routing/rules.go, dataplane/userspace/filters.go). There is no family
// dimension in the reference, so once two non-inet6 families share a name the
// map cannot disambiguate them — the reuse is genuinely ambiguous. Junos
// namespaces firewall filters per family; xpf folds them, so it rejects the
// reuse fail-closed instead of resolving it by arbitrary map-write order.
//
// inet6 has its own destination map (fw.FiltersInet6) and is the ONLY family
// that folds there, so a name shared between family inet and family inet6 lands
// in two DIFFERENT maps and does NOT collide — that legitimate dual-stack case
// (the same filter name for the V4 and V6 path) is preserved. Only a name that
// appears under >= 2 distinct non-inet6 families is flagged.
//
// Strict path (commit / commit-check, lenient=false): the first collision is a
// hard compile error naming the offending filter and its families. Lenient path
// (load / peer-sync, lenient=true): every collision is returned as a warning and
// compilation continues with the existing last-write-wins behavior, so an
// already-persisted or peer-synced config that an older binary silently accepted
// still BOOTS (#1960 / #3261 fail-closed-on-load doctrine).
//
// The traversal mirrors compileFirewall's family/filter walk exactly (BOTH AST
// shapes: hierarchical `family inet { filter ... }` and the set-command
// `family { inet { filter ... } }`), and aggregates across every top-level
// `firewall {}` block because compileFirewall compiles each into the same
// fw.FiltersInet map — a collision split across two blocks is just as real.
func validateFirewallFilterFamilyCollisionsAST(nodes []*Node, lenient bool) ([]string, error) {
	// filterFamilies[name] = the ordered set of DISTINCT non-inet6 families that
	// define a filter of this name (all folding into the shared FiltersInet pool).
	filterFamilies := map[string][]string{}
	// order preserves first-seen filter-name order for a deterministic error.
	order := []string{}
	// inet6Names records filter names defined under `family inet6` (their own
	// FiltersInet6 pool). #4287 compiles a `family any` filter into BOTH pools,
	// so an `any` name that ALSO names a distinct inet6 filter now collides in
	// FiltersInet6 — tracked here and flagged below.
	inet6Names := map[string]bool{}

	record := func(name, fam string) {
		for _, f := range filterFamilies[name] {
			if f == fam {
				return // same family already recorded — not a cross-family reuse
			}
		}
		if len(filterFamilies[name]) == 0 {
			order = append(order, name)
		}
		filterFamilies[name] = append(filterFamilies[name], fam)
	}

	for _, fwNode := range nodes {
		if fwNode.Name() != "firewall" {
			continue
		}
		for _, familyNode := range fwNode.FindChildren("family") {
			var afNodes []*Node
			var afName string
			if len(familyNode.Keys) >= 2 {
				// Hierarchical: family inet { ... }
				afName = familyNode.Keys[1]
				afNodes = []*Node{familyNode}
			} else {
				// Set-command shape: family { inet { ... } inet6 { ... } }
				afNodes = append(afNodes, familyNode.Children...)
			}
			for _, afNode := range afNodes {
				af := afName
				if af == "" {
					// #4827: Name() safely returns "" for an empty Keys
					// slice — afNode.Keys[0] would panic (index out of
					// range) on a malformed persisted Node (e.g. a
					// corrupted on-disk config-store JSON blob;
					// pkg/configstore/db.go's plain json.Unmarshal has no
					// Node validator). The live parser/SetPath paths
					// structurally guarantee len(Keys) >= 1, so this only
					// ever bites a corrupted store, but a bad persisted
					// state must error on load, never panic (#1960
					// fail-closed-on-load doctrine).
					af = afNode.Name()
					if len(afNode.Keys) >= 2 {
						af = afNode.Keys[1]
					}
				}
				if af == "inet6" {
					// Its own dest map (FiltersInet6). It cannot collide with
					// the FiltersInet pool, but #4287 dual-applies `family any`
					// into FiltersInet6 too, so record inet6 names for the
					// any+inet6 cross-check below.
					for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
						if filterInst.name != "" {
							inet6Names[filterInst.name] = true
						}
					}
					continue
				}
				for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
					if filterInst.name == "" {
						continue
					}
					record(filterInst.name, af)
				}
			}
		}
	}

	var warnings []string
	for _, name := range order {
		fams := filterFamilies[name]
		if len(fams) < 2 {
			continue
		}
		msg := fmt.Sprintf(
			"firewall filter %q is defined under multiple non-inet6 families "+
				"(%s) — xpf folds every family except inet6 into one name-keyed "+
				"filter map, so the later definition silently overwrites the "+
				"earlier (a discard filter can become accept-all — fail-open); "+
				"Junos namespaces filters per family, so rename one of them (#3884)",
			name, strings.Join(fams, ", "))
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	// #4287 any+inet6 cross-check: a `family any` filter now folds into the
	// FiltersInet6 pool as well, so a name shared with a distinct `family inet6`
	// filter silently overwrites in FiltersInet6 (the same fail-open the pool
	// gate above defends against, but on the v6 side). `any` names are recorded
	// in filterFamilies (and thus `order`), so iterating order catches them.
	for _, name := range order {
		if !inet6Names[name] {
			continue
		}
		hasAny := false
		for _, f := range filterFamilies[name] {
			if f == "any" {
				hasAny = true
				break
			}
		}
		if !hasAny {
			continue
		}
		msg := fmt.Sprintf(
			"firewall filter %q is defined under both family any and family "+
				"inet6 — xpf compiles a family any filter into BOTH the inet and "+
				"inet6 pools (#4287), so the any definition and the inet6 "+
				"definition collide in the inet6 pool and one silently overwrites "+
				"the other (fail-open); rename one of them",
			name)
		if !lenient {
			return nil, fmt.Errorf("%s", msg)
		}
		warnings = append(warnings, msg)
	}
	return warnings, nil
}

// familyAnySpecificMatches is the set of firewall-filter `from` match leaves
// that only make sense for ONE address family and must not appear under a
// `family any` filter (#4296):
//
//   - source-address / destination-address: a firewall-filter address match is
//     always an IP prefix LITERAL (v4 or v6), which binds to exactly one family.
//   - icmp-type / icmp-code: ICMPv4 and ICMPv6 use DIFFERENT numeric type/code
//     tables (echo-request is 8 for v4, 128 for v6); compileFilterFrom resolves
//     the symbolic name via the ICMPv4 table for af=="any" (filter_match_resolve.go),
//     so the resulting numeric is correct for at most one family.
//
// (next-header is the inet6 spelling of `protocol` and matches family-agnostic
// L4 protocol NUMBERS, so it is NOT family-specific and is deliberately absent.
// source-prefix-list / destination-prefix-list reference NAMED prefix-lists that
// may legitimately mix v4 and v6 prefixes, so they are NOT in this static set —
// their family content is not knowable from the leaf keyword alone. A prefix-list
// whose RESOLVED prefixes cover only ONE family is caught separately by the
// content-aware check in validateFirewallFilterFamilyAnyMatchesAST — see #4426.)
var familyAnySpecificMatches = map[string]bool{
	"source-address":      true,
	"destination-address": true,
	"icmp-type":           true,
	"icmp-code":           true,
}

// plFamily records which address families a prefix-list's resolved prefixes
// cover. Both false means empty or all-unclassifiable; both true means a
// legitimately mixed v4+v6 list; exactly one true is a single-family list.
type plFamily struct {
	hasV4 bool
	hasV6 bool
}

// prefixFamily classifies a single prefix-list entry as IPv4 or IPv6 by the
// only discriminator that cannot collide: a v6 literal always contains a colon
// and a v4 dotted-quad always contains a dot but never a colon. The optional
// `/len` mask is stripped first. A token that is neither (garbage — caught
// elsewhere by the prefix-list validators) sets neither flag so it never drives
// a false single-family verdict.
func prefixFamily(p string) (v4, v6 bool) {
	host := p
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, ":") {
		return false, true
	}
	if strings.Contains(host, ".") {
		return true, false
	}
	return false, false
}

// firewallPrefixListFamilies collects, for every `policy-options prefix-list
// NAME`, the address families its resolved prefixes cover. It mirrors
// compilePolicyOptions' prefix reading exactly (namedInstances +
// inst.node.Children, each child's full Keys slice — the #3996 dual-shape
// read), so the family verdict matches what the compiler actually loads. The
// tree passed here is already apply-groups-expanded, so applied group
// prefix-lists are inlined at top level; an un-applied group's prefix-list is
// absent, matching the compiler (which ignores both it and any reference to
// it). Used by the #4426 family-any single-family prefix-list gate.
func firewallPrefixListFamilies(nodes []*Node) map[string]plFamily {
	out := map[string]plFamily{}
	for _, top := range nodes {
		if top == nil || top.Name() != "policy-options" {
			continue
		}
		for _, inst := range namedInstances(top.FindChildren("prefix-list")) {
			if inst.name == "" {
				continue
			}
			fam := out[inst.name]
			for _, entry := range inst.node.Children {
				for _, p := range entry.Keys {
					if p == "" {
						continue
					}
					if v4, v6 := prefixFamily(p); v4 {
						fam.hasV4 = true
					} else if v6 {
						fam.hasV6 = true
					}
				}
			}
			out[inst.name] = fam
		}
	}
	return out
}

// validateFirewallFilterFamilyAnyMatchesAST walks every top-level `firewall`
// node and rejects a `family any` filter term whose `from` block carries a
// FAMILY-SPECIFIC match leaf (#4296, fable-review-167 F-1 residual).
//
// #4287 fixed the original fail-open (a `family any` deny compiled into the
// IPv4 pool only, silently letting IPv6 through) by dual-compiling a `family
// any` filter into BOTH FiltersInet and FiltersInet6. But a family-specific
// match under `family any` is dual-compiled VERBATIM: a v4 `source-address` (or
// a symbolic icmp-type that resolves via the ICMPv4 table for af=="any") lands
// in the FiltersInet6 pool as a predicate that can NEVER match a v6 packet, so
// the v6 term falls through to the implicit ACCEPT — an imperfect v6 UNDER-block
// (it degrades to the pre-#4287 state for that term; never an over-block, so no
// legitimate v6 traffic is broken). These configs are also non-Junos (Junos
// disallows family-specific matches under `family any`) and only reachable via a
// hierarchical config-file / peer-synced AST, since the flat `set` schema does
// not model `family any`.
//
// Rather than silently dual-compile a match that cannot work for one family,
// this gate REJECTS it at commit with a message pointing the operator at
// `family inet` / `family inet6`. Strict path (commit / commit-check,
// lenient=false): the first offending match is a hard compile error. Lenient
// path (load / peer-sync, lenient=true): every offending match is returned as a
// warning and compilation continues with the existing dual-compile behavior, so
// an already-persisted or peer-synced config that an older binary silently
// accepted still BOOTS (#1960 / #3261 fail-closed-on-load doctrine).
//
// #4426 residual: a `source-prefix-list` / `destination-prefix-list` reference
// is not a static family-specific keyword (a named prefix-list MAY mix families),
// so it is deliberately NOT in familyAnySpecificMatches. But a reference whose
// RESOLVED prefixes cover only ONE family reproduces the SAME v6 (or v4)
// under-block: `from source-prefix-list v4-only then discard` under `family any`
// dual-compiles the v4-only list into the inet6 pool, where the v6 arm has zero
// v6 prefixes, matches nothing, and falls through to the implicit ACCEPT. This
// gate therefore also resolves each prefix-list reference against the candidate
// tree's `policy-options prefix-list` definitions and rejects (strict) / warns
// (lenient) when a DIRECTION's referenced prefix-lists collectively cover a
// single family only. A mixed-family list, or two lists that together cover both
// families in one direction, is accepted — that is the legitimate `family any`
// shape #4287 enables. An empty or undefined reference is left to the empty-set
// semantics and validateFirewallPrefixListReferencesStrict respectively.
//
// The traversal mirrors compileFirewall's family/filter/term/from walk exactly
// (BOTH AST shapes) and aggregates across every top-level `firewall {}` block.
func validateFirewallFilterFamilyAnyMatchesAST(nodes []*Node, lenient bool) ([]string, error) {
	var warnings []string
	plFamilies := firewallPrefixListFamilies(nodes)
	for _, fwNode := range nodes {
		if fwNode.Name() != "firewall" {
			continue
		}
		for _, familyNode := range fwNode.FindChildren("family") {
			var afNodes []*Node
			var afName string
			if len(familyNode.Keys) >= 2 {
				// Hierarchical: family any { ... }
				afName = familyNode.Keys[1]
				afNodes = []*Node{familyNode}
			} else {
				// Set-command shape: family { any { ... } }
				afNodes = append(afNodes, familyNode.Children...)
			}
			for _, afNode := range afNodes {
				af := afName
				if af == "" {
					// #4827: Name() safely returns "" for an empty Keys
					// slice — afNode.Keys[0] would panic (index out of
					// range) on a malformed persisted Node (e.g. a
					// corrupted on-disk config-store JSON blob;
					// pkg/configstore/db.go's plain json.Unmarshal has no
					// Node validator). The live parser/SetPath paths
					// structurally guarantee len(Keys) >= 1, so this only
					// ever bites a corrupted store, but a bad persisted
					// state must error on load, never panic (#1960
					// fail-closed-on-load doctrine).
					af = afNode.Name()
					if len(afNode.Keys) >= 2 {
						af = afNode.Keys[1]
					}
				}
				if af != "any" {
					continue
				}
				for _, filterInst := range namedInstances(afNode.FindChildren("filter")) {
					if filterInst.name == "" {
						continue
					}
					for _, termInst := range namedInstances(filterInst.node.FindChildren("term")) {
						// Per-direction prefix-list coverage, accumulated across
						// every `from` block of the term (#4426). Index 0 = source,
						// 1 = destination. POSITIVE (`source-prefix-list X`) and
						// EXCEPT (`source-prefix-list X except`) refs are tracked
						// SEPARATELY because they fail differently under `family
						// any`: a single-family POSITIVE list under-blocks the
						// missing family (its arm matches nothing), while a
						// single-family EXCEPT list OVER-matches the missing family
						// (that arm is `except` over an empty set = match ALL — the
						// clean-except branch of resolvePrefixListAddrs, #4338).
						var posFam, excFam [2]plFamily
						var hasPos, hasExc [2]bool
						var dirNames [2][]string
						for _, fromNode := range termInst.node.FindChildren("from") {
							for _, child := range fromNode.Children {
								mname := child.Name()
								// #4426: accumulate the resolved family coverage of
								// every source/destination-prefix-list reference so a
								// single-family list under `family any` is caught below.
								dir := -1
								switch mname {
								case "source-prefix-list":
									dir = 0
								case "destination-prefix-list":
									dir = 1
								}
								if dir >= 0 {
									for _, ref := range firewallPrefixListRefs(child) {
										fam, ok := plFamilies[ref.Name]
										if !ok {
											// Undefined reference — left to
											// validateFirewallPrefixListReferencesStrict.
											continue
										}
										dirNames[dir] = append(dirNames[dir], ref.Name)
										if ref.Except {
											hasExc[dir] = true
											if fam.hasV4 {
												excFam[dir].hasV4 = true
											}
											if fam.hasV6 {
												excFam[dir].hasV6 = true
											}
										} else {
											hasPos[dir] = true
											if fam.hasV4 {
												posFam[dir].hasV4 = true
											}
											if fam.hasV6 {
												posFam[dir].hasV6 = true
											}
										}
									}
									continue
								}
								if !familyAnySpecificMatches[mname] {
									continue
								}
								detail := mname
								if vals := firewallMatchValues(child); len(vals) > 0 {
									detail = mname + " " + vals[0]
								}
								msg := fmt.Sprintf(
									"firewall filter %q term %q: `from %s` is a family-specific match not allowed under `family any` — a family any filter compiles into BOTH the inet (v4) and inet6 (v6) pools (#4287), and a single-family match (a v4/v6 address literal or a per-family icmp type/code) can never match the other family, silently under-blocking it; use `family inet` or `family inet6` (#4296)",
									filterInst.name, termInst.name, detail)
								if !lenient {
									return nil, fmt.Errorf("%s", msg)
								}
								warnings = append(warnings, msg)
							}
						}
						// #4426: a direction whose referenced prefix-lists cover
						// exactly ONE family under `family any` is a commit-time
						// surprise — but the failure mode (and so the message) differs
						// by whether the coverage is POSITIVE or EXCEPT. Reject strict /
						// warn lenient in both cases, mirroring the #4296 remedy.
						// Both-families and empty coverage are fine.
						for dir, keyword := range [2]string{"source-prefix-list", "destination-prefix-list"} {
							// Effective match semantics for this direction, mirroring
							// resolvePrefixListAddrs (#4338): a DEFINED positive ref
							// makes the direction positive-wins (any `except` ref is
							// dropped, warned separately); only a SOLE `except` (no
							// positive ref) uses the clean-except match-ALL semantics.
							var fam plFamily
							except := false
							switch {
							case hasPos[dir]:
								fam = posFam[dir] // positive-wins; except refs ignored
							case hasExc[dir]:
								fam = excFam[dir]
								except = true
							default:
								continue // no defined refs in this direction
							}
							if fam.hasV4 == fam.hasV6 {
								// both (legit mixed / dual-list) or neither (empty).
								continue
							}
							names := strings.Join(dirNames[dir], " ")
							var msg string
							if except {
								// Single-family `except` list: the arm for the family
								// the list does NOT cover evaluates `except` over an
								// empty set = MATCH ALL — an over-block on `then
								// discard`, a fail-OPEN over-accept on `then accept`.
								// This is the OPPOSITE of an under-block, so it needs
								// its own message (#4426, coordinator review).
								haveFam, overFam := "inet (v4)", "inet6 (v6)"
								if fam.hasV6 {
									haveFam, overFam = "inet6 (v6)", "inet (v4)"
								}
								msg = fmt.Sprintf(
									"firewall filter %q term %q: `from %s %s except` references only %s prefixes under `family any` — a family any filter compiles into BOTH the inet (v4) and inet6 (v6) pools (#4287), and an `except` over a prefix set with no %s entries matches EVERY %s packet (an over-block on `then discard`, a fail-open over-accept on `then accept`); use `family inet` / `family inet6`, or an except prefix-list covering both families (#4426)",
									filterInst.name, termInst.name, keyword, names, haveFam, overFam, overFam)
							} else {
								// Single-family POSITIVE list: the arm for the missing
								// family has no matching prefixes → matches nothing →
								// falls through to the implicit ACCEPT (silent
								// under-block).
								haveFam, missFam := "inet (v4)", "inet6 (v6)"
								if fam.hasV6 {
									haveFam, missFam = "inet6 (v6)", "inet (v4)"
								}
								msg = fmt.Sprintf(
									"firewall filter %q term %q: `from %s %s` references only %s prefixes under `family any` — a family any filter compiles into BOTH the inet (v4) and inet6 (v6) pools (#4287), so the %s arm has no matching prefixes and silently under-blocks that family; use `family inet` / `family inet6`, or a prefix-list covering both families (#4426)",
									filterInst.name, termInst.name, keyword, names, haveFam, missFam)
							}
							if !lenient {
								return nil, fmt.Errorf("%s", msg)
							}
							warnings = append(warnings, msg)
						}
					}
				}
			}
		}
	}
	return warnings, nil
}

// firewallMatchValues extracts every value carried by a `from` match-criterion
// node, across BOTH parser AST shapes (#2545):
//
//   - hierarchical leaf  `protocol tcp;`            → Keys=["protocol","tcp"]
//   - bracket list       `protocol [ tcp udp ];`    → Keys=["protocol","tcp","udp"]
//   - flat set command   `... protocol tcp` (one    → Keys=["protocol"] with a
//     line per value, merged under one node)          child node per value
//
// Returning the full slice lets the caller ACCUMULATE repeated occurrences into
// a match-ANY set instead of overwriting (the prior scalar last-write-wins bug).
// Empty / blank tokens are skipped so an empty result means "criterion absent".
//
// #6714: EVERY key of each child, not Keys[0]. The node's own tail was already
// read in full (Keys[1:]), so taking one key per child made the identical token
// sequence read differently depending on which side of the AST the parser put
// it on — `flag basic-datapath session;` kept both and
// `flag { basic-datapath session; }` kept one. That shape comes from a
// hand-authored or `load merge`d file (a value tail packed onto a statement
// inside a value block, or a bracket list nested in one); the canonical Junos
// spellings put one token per child, which is why it survived every
// brace-authored fixture in this package.
//
// Two things it is deliberately NOT:
//
//   - It does NOT descend. A child with a sub-block (`neighbor 10.0.0.1
//     { metric 2; }`) contributes its NAME only; descending would promote
//     `metric` and `2` into the value list. That is the line between this and
//     plainListValues (ast.go), which descends and must only ever be pointed at
//     a leaf whose subtree is entirely values.
//   - It does NOT become safe for a leaf with per-value option KEYWORDS. It
//     already promoted every token of the node's own tail, so a leaf like
//     `ntp server <ip> prefer` was never eligible and still keeps its own
//     reader (ntpServerValues). This change did not widen that exposure; it
//     made the two sides of one node agree.
func firewallMatchValues(child *Node) []string {
	var vals []string
	for _, k := range child.Keys[1:] {
		if k != "" {
			vals = append(vals, k)
		}
	}
	for _, vn := range child.Children {
		for _, k := range vn.Keys {
			if k != "" {
				vals = append(vals, k)
			}
		}
	}
	return vals
}

// firewallPrefixListRefs extracts every prefix-list reference carried by a
// firewall-filter `from source-prefix-list` / `destination-prefix-list` match
// node, across BOTH parser AST shapes (#3843 — the prefix-list-ref instance of
// the #2419 dual-shape class):
//
//   - hierarchical single-name leaf  `source-prefix-list plX;`
//     → Keys=["source-prefix-list","plX"], no children
//     hierarchical single-name+except `source-prefix-list plX except;`
//     → Keys=["source-prefix-list","plX","except"], no children
//   - hierarchical block             `source-prefix-list { pl1; pl2 except; }`
//     → one child node per name (child.Keys=["pl1"] / ["pl2","except"])
//   - flat set command               `set ... source-prefix-list plX except`
//     → one child node (child.Keys=["plX"] / ["plX","except"])
//
// The single-name leaf shape was SILENTLY DROPPED before #3843: the caller only
// iterated child.Children and never read child.Keys[1], so a `load merge`/config-
// file term compiled with NO prefix-list scope (implicit match-all) yet passed
// strict commit cleanly — a fail-open. Reading BOTH child.Keys[1:] AND
// child.Children guarantees the scope survives every shape; an unresolvable name
// is still hard-rejected by validateFirewallPrefixListReferencesStrict, so a
// dropped scope is impossible (fail-closed).
func firewallPrefixListRefs(child *Node) []PrefixListRef {
	var refs []PrefixListRef
	// A token slice is a sequence of `<name> [except]` groups: an `except`
	// modifier attaches to the prefix-list name immediately preceding it.
	appendTokens := func(tokens []string) {
		for i := 0; i < len(tokens); {
			name := tokens[i]
			i++
			if name == "" {
				continue
			}
			ref := PrefixListRef{Name: name}
			if i < len(tokens) && tokens[i] == "except" {
				ref.Except = true
				i++
			}
			refs = append(refs, ref)
		}
	}
	// Single-name / flat leaf shape: the name(s) ride on this node's own Keys.
	appendTokens(child.Keys[1:])
	// Block / flat-set shape: one child node per referenced prefix-list.
	for _, plNode := range child.Children {
		appendTokens(plNode.Keys)
	}
	return refs
}

// compileFilterFrom compiles a firewall-filter term's `from` match block. The
// family ("inet" / "inet6") selects the ICMPv4 vs ICMPv6 icmp-type name table
// when resolving symbolic icmp-type values (#3205).
func compileFilterFrom(node *Node, term *FirewallFilterTerm, family string) {
	for _, child := range node.Children {
		switch child.Name() {
		case "dscp", "traffic-class":
			// Multi-value (#2545): ACCUMULATE every value rather than
			// overwrite. Handle BOTH AST shapes — a bracket/flat-set list
			// carries values as child.Keys[1:] and/or child nodes, while a
			// hierarchical leaf carries a single value via nodeVal.
			term.DSCPs = append(term.DSCPs, firewallMatchValues(child)...)
		case "protocol", "next-header":
			// `next-header` is the IPv6 spelling of `protocol` (Junos family
			// inet6). It matches the IPv6 Next Header / L4 protocol number, which
			// the dataplane already enforces via term.Protocols — so it is an
			// ALIAS for the existing protocol matcher, not new matching. Before
			// #3307 it had no switch case and was silently dropped (the term lost
			// its protocol constraint); routing it to Protocols enforces it.
			term.Protocols = append(term.Protocols, firewallMatchValues(child)...)
		case "source-address":
			// Multi-value (#2419/#2545): a bracket/flat-set list collapses
			// onto child.Keys[1:] (firewallMatchValues), a hierarchical
			// block carries each address as a child node — handle both.
			// #6463: record every literal classifyFilterAddrFamily rejects on
			// term.UnknownAddresses (kept VERBATIM in SourceAddresses) so the
			// snapshot builder can set the AddressUnrepresentable wire marker
			// on the tolerant path — the Rust parse_address drops such a token
			// per-token, and a partially-malformed list would otherwise
			// silently narrow a discard/reject term (fail-open).
			srcValues := firewallMatchValues(child)
			recordFilterAddrTokens(term, srcValues)
			term.SourceAddresses = append(term.SourceAddresses, srcValues...)
		case "destination-address":
			dstValues := firewallMatchValues(child)
			recordFilterAddrTokens(term, dstValues)
			term.DestAddresses = append(term.DestAddresses, dstValues...)
		case "destination-port":
			// #3205: resolve named/service ports to numerics and record any
			// unresolved token for the strict commit gate (fail closed).
			term.DestinationPorts = append(term.DestinationPorts, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "source-prefix-list":
			// #3843: read BOTH the single-name leaf shape
			// (`source-prefix-list plX;` → child.Keys[1:]) AND the block /
			// flat-set shape (`source-prefix-list { plX except; }` /
			// `set ... source-prefix-list plX` → child.Children). Iterating
			// only child.Children silently dropped the leaf-shape scope.
			term.SourcePrefixLists = append(term.SourcePrefixLists, firewallPrefixListRefs(child)...)
		case "destination-prefix-list":
			term.DestPrefixLists = append(term.DestPrefixLists, firewallPrefixListRefs(child)...)
		case "source-port":
			term.SourcePorts = append(term.SourcePorts, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "destination-port-except":
			// #2622 negated port match: match all destination ports EXCEPT
			// these. Multi-value/bracket-list, same accumulation as the
			// positive destination-port case. #3205: resolve named ports and
			// record unresolved tokens. An unresolved except port is
			// hard-rejected at commit by validateFilterMatchValuesStrict, so an
			// operator never reaches the dataplane with one. If a leniently
			// loaded / peer-synced snapshot still carries an unresolved token,
			// the Rust dataplane now fails CLOSED: port_match returns false for
			// a constrained term with an empty PortMatcher::Any in BOTH
			// directions, so the except term matches NOTHING (not all ports).
			// Pre-#3205 this except case failed OPEN — an unresolved except port
			// matched every port, including the one it was meant to exclude.
			term.DestPortsExcept = append(term.DestPortsExcept, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "source-port-except":
			term.SourcePortsExcept = append(term.SourcePortsExcept, resolveFilterPortTokens(firewallMatchValues(child), term)...)
		case "icmp-type":
			// #3205: resolve symbolic icmp-type names (echo-request, ...) to
			// their numeric value using the family-appropriate Junos table.
			// strconv.Atoi alone silently dropped every name, leaving the type
			// set empty (matches ALL ICMP — a policy bypass). An unresolved
			// token is recorded for the strict commit gate (fail closed).
			for _, v := range firewallMatchValues(child) {
				if n, ok := resolveICMPTypeToken(v, family); ok {
					term.ICMPTypes = append(term.ICMPTypes, n)
				} else {
					term.UnknownICMPTypes = append(term.UnknownICMPTypes, v)
				}
			}
		case "icmp-code":
			for _, v := range firewallMatchValues(child) {
				if n, ok := resolveICMPCodeToken(v); ok {
					term.ICMPCodes = append(term.ICMPCodes, n)
				} else {
					term.UnknownICMPCodes = append(term.UnknownICMPCodes, v)
				}
			}
		case "tcp-flags":
			// Can be bracket list or single value: tcp-flags "syn ack" or [ syn ack ]
			term.TCPFlags = append(term.TCPFlags, firewallMatchValues(child)...)
		case "is-fragment":
			term.IsFragment = true
		case "flexible-match-range":
			for _, rangeInst := range namedInstances(child.FindChildren("range")) {
				// #5823: aggregate EVERY named range across every repeated
				// flexible-match-range block (this switch arm fires once per
				// block; namedInstances yields every range within a block).
				// len(FlexMatchRangeNames) > 1 is the cardinality violation the
				// strict gate rejects and the lenient path fails closed on. The
				// pre-#5823 code `break`ed after the first range, silently
				// dropping the rest (an accept term over-permitted, a
				// discard/reject over-dropped). Compile the FIRST range into
				// FlexMatch exactly as before (a single-range term is
				// byte-identical); later ranges are only COUNTED — the wire is
				// poisoned to match nothing when the count exceeds one, so
				// compiling their fields would be dead work.
				term.FlexMatchRangeNames = append(term.FlexMatchRangeNames, rangeInst.name)
				if term.FlexMatch != nil {
					continue
				}
				fm := &FlexMatchConfig{MatchStart: "layer-3"}
				for _, rc := range rangeInst.node.Children {
					switch rc.Name() {
					case "match-start":
						if v := nodeVal(rc); v != "" {
							// #3232: only layer-3 (the default) and layer-4 are
							// implemented in the userspace matcher. `payload` (and
							// any other token) would previously be stored but
							// silently evaluated at the L3 base by the wire builder
							// and Rust matcher — a wrong-offset match (security
							// evasion). layer-3/layer-4 carry through to the wire;
							// everything else is recorded so
							// validateFilterFlexMatchStrict fails the commit closed.
							switch v {
							case "layer-3", "layer-4":
								fm.MatchStart = v
							default:
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-start "+v)
							}
						}
					case "byte-offset":
						if v := nodeVal(rc); v != "" {
							// #3203: a parse error (or a value outside 0..255,
							// the wire field width) must FAIL CLOSED at commit,
							// not silently coerce the offset to 0. Record the
							// token for validateFilterFlexMatchStrict.
							if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 255 {
								fm.ByteOffset = uint8(n)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "byte-offset "+v)
							}
						}
					case "bit-length":
						if v := nodeVal(rc); v != "" {
							// #3203: bit-length must be 1..32 (the wire value is a
							// u32 read of ceil(bits/8) bytes). strconv.Atoi
							// followed by an unchecked uint8() cast previously
							// truncated an out-of-range value (e.g. 999 -> 231)
							// silently; a non-numeric token was ignored, leaving
							// bit-length 0 (later defaulted to 32). Fail closed on
							// either by recording the token.
							if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 32 {
								fm.BitLength = uint8(n)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "bit-length "+v)
							}
						}
					case "range", "match-value":
						if v := nodeVal(rc); v != "" {
							// Format: "0xVALUE/0xMASK" or just "0xVALUE".
							// #3203: a ParseUint error (malformed hex or a value
							// wider than 32 bits) previously left fm.Value/fm.Mask
							// at the zero default — the rule then matched value 0
							// instead of the intended pattern, with a clean
							// commit. Fail closed: record the unparseable token.
							parts := strings.SplitN(v, "/", 2)
							if val, err := strconv.ParseUint(strings.TrimPrefix(parts[0], "0x"), 16, 32); err == nil {
								fm.Value = uint32(val)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-value "+parts[0])
							}
							if len(parts) == 2 {
								if mask, err := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 32); err == nil {
									fm.Mask = uint32(mask)
								} else {
									term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-mask "+parts[1])
								}
							}
						}
					case "match-mask":
						if v := nodeVal(rc); v != "" {
							if mask, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32); err == nil {
								fm.Mask = uint32(mask)
							} else {
								term.UnknownFlexMatch = append(term.UnknownFlexMatch, "match-mask "+v)
							}
						}
					}
				}
				if fm.BitLength == 0 {
					fm.BitLength = 32 // default to 32-bit match
				}
				if fm.Mask == 0 {
					// #3203: default mask = the low BitLength bits set, for ANY
					// 1..32-bit length (not just 8/16). The Rust matcher
					// (userspace-dp/src/filter/engine/matching.rs) reads
					// ceil(bits/8) bytes big-endian into a u32 (right-aligned in
					// the low bits) and compares (read & mask) == value, so a
					// 24-bit field needs 0x00FFFFFF. The old code defaulted every
					// non-8/16 length to 0xFFFFFFFF, which that read could never
					// satisfy for a value with a non-zero high byte.
					if fm.BitLength >= 32 {
						fm.Mask = 0xFFFFFFFF
					} else {
						fm.Mask = uint32(1)<<fm.BitLength - 1
					}
				}
				term.FlexMatch = fm
				// #5823: do NOT break — the loop continues so every remaining
				// range is COUNTED in FlexMatchRangeNames (the guard above skips
				// re-compiling them). The strict gate then rejects a term with
				// more than one range, and the lenient path fails it closed.
			}
		default:
			// #3307: a `from` match leaf the dataplane does NOT enforce. The
			// schema gate is opt-in, so an unknown leaf (ttl, source-mac-address,
			// ip-options, fragment-offset, hop-limit, ...) passes commit and was
			// previously dropped silently here — the term then enforced a BROADER
			// match than authored (an accept over-permits, a discard/reject
			// over-drops). Record it so validateFilterFromMatchStrict can reject
			// the commit fail-closed instead of silently dropping the constraint.
			// The enforced set is exactly the cases above; every one maps to a
			// wire field the snapshot builder emits and the Rust matcher reads.
			term.UnknownFrom = append(term.UnknownFrom, child.Name())
		}
	}
}

// rejectMessageTypes is the set of message-types Junos accepts after
// `then reject <type>` (RFC 792 ICMP-unreachable codes plus tcp-reset). A term
// with one of these still acts as a plain reject — the dataplane does not act
// on the message-type today (#2399 fold) — but the type is recognized so a real
// Juniper config import (`then reject tcp-reset`) commits cleanly instead of
// being flagged as an unknown action. A token NOT in this set after `reject` is
// a typo and is still flagged.
var rejectMessageTypes = map[string]bool{
	"administratively-prohibited": true,
	"bad-host-tos":                true,
	"bad-network-tos":             true,
	"host-prohibited":             true,
	"host-unreachable":            true,
	"network-prohibited":          true,
	"network-unreachable":         true,
	"port-unreachable":            true,
	"precedence-cutoff":           true,
	"precedence-violation":        true,
	"protocol-unreachable":        true,
	"source-host-isolated":        true,
	"source-route-failed":         true,
	"tcp-reset":                   true,
}

func compileFilterThen(node *Node, term *FirewallFilterTerm) {
	// Handle leaf form: "then discard;" or "then accept;" produces
	// Keys=["then", "discard"] with IsLeaf=true and no children. A leaf can
	// also carry an argument-bearing modifier, e.g. "then forwarding-class be"
	// → Keys=["then","forwarding-class","be"], so the keyword consumes its
	// following token rather than treating it as a separate action.
	if node.IsLeaf && len(node.Keys) >= 2 {
		keys := node.Keys[1:]
		for i := 0; i < len(keys); i++ {
			k := keys[i]
			arg := func() string {
				// Consume the modifier's argument if present.
				if i+1 < len(keys) {
					i++
					return keys[i]
				}
				return ""
			}
			switch k {
			case "accept":
				term.Action = "accept"
				term.TerminalActions = append(term.TerminalActions, "accept")
			case "reject":
				term.Action = "reject"
				term.TerminalActions = append(term.TerminalActions, "reject")
				// Junos `then reject <message-type>`: the term is a plain
				// reject; capture a KNOWN message-type for fidelity. Only
				// consume the following token if it is a recognized type — a
				// typo (e.g. `reject blorp`) must fall through to the default
				// arm and be flagged, not silently swallowed as the reject arg.
				if i+1 < len(keys) && rejectMessageTypes[keys[i+1]] {
					i++
					term.RejectMessageType = keys[i]
				}
			case "discard":
				term.Action = "discard"
				term.TerminalActions = append(term.TerminalActions, "discard")
			case "next":
				// `then next term` / bare `then next` — explicit fall-through
				// to the next term (a no-op terminating-wise). Consume an
				// optional "term" token.
				term.NextTerm = true
				if i+1 < len(keys) && keys[i+1] == "term" {
					i++
				}
			case "log":
				term.Log = true
			case "syslog":
				term.Log = true
			case "routing-instance":
				if v := arg(); v != "" {
					term.RoutingInstance = v
				}
			case "count":
				if v := arg(); v != "" {
					term.Count = v
				}
			case "forwarding-class":
				if v := arg(); v != "" {
					term.ForwardingClass = v
				}
			case "loss-priority":
				if v := arg(); v != "" {
					term.LossPriority = v
				}
			case "dscp", "traffic-class":
				if v := arg(); v != "" {
					term.DSCPRewrite = v
				}
			case "policer":
				if v := arg(); v != "" {
					term.Policer = v
				}
			default:
				// #2399 (032-16): an unrecognized `then` token must NOT be
				// silently dropped — it would default to ACCEPT in the
				// dataplane (fail-open). Record it so the strict commit gate
				// (validateFilterActionsStrict) can reject the operator's typo.
				term.UnknownActions = append(term.UnknownActions, k)
			}
		}
		return
	}

	for _, child := range node.Children {
		switch child.Name() {
		case "accept":
			term.Action = "accept"
			term.TerminalActions = append(term.TerminalActions, "accept")
		case "reject":
			term.Action = "reject"
			term.TerminalActions = append(term.TerminalActions, "reject")
			// `then reject <message-type>` — capture a KNOWN type for fidelity;
			// a typo after reject is flagged (see leaf-form note above). The
			// message-type is the second key (block form) or a single child.
			if len(child.Keys) >= 2 && rejectMessageTypes[child.Keys[1]] {
				term.RejectMessageType = child.Keys[1]
			} else if len(child.Keys) >= 2 {
				// Unknown token after reject — a typo. Flag it.
				term.UnknownActions = append(term.UnknownActions, "reject "+child.Keys[1])
			} else {
				for _, mt := range child.Children {
					if len(mt.Keys) >= 1 {
						if rejectMessageTypes[mt.Keys[0]] {
							term.RejectMessageType = mt.Keys[0]
						} else {
							term.UnknownActions = append(term.UnknownActions, "reject "+mt.Keys[0])
						}
					}
				}
			}
		case "discard":
			term.Action = "discard"
			term.TerminalActions = append(term.TerminalActions, "discard")
		case "next":
			// `then next term` / bare `then next` — explicit fall-through.
			term.NextTerm = true
		case "log":
			term.Log = true
		case "syslog":
			term.Log = true
		case "routing-instance":
			if len(child.Keys) >= 2 {
				term.RoutingInstance = child.Keys[1]
			}
		case "count":
			if len(child.Keys) >= 2 {
				term.Count = child.Keys[1]
			}
		case "forwarding-class":
			if len(child.Keys) >= 2 {
				term.ForwardingClass = child.Keys[1]
			}
		case "loss-priority":
			if len(child.Keys) >= 2 {
				term.LossPriority = child.Keys[1]
			}
		case "dscp", "traffic-class":
			term.DSCPRewrite = nodeVal(child)
		case "policer":
			if len(child.Keys) >= 2 {
				term.Policer = child.Keys[1]
			}
		default:
			// #2399 (032-16): see leaf-form note above — record the unknown
			// `then` token for the strict commit gate instead of dropping it.
			term.UnknownActions = append(term.UnknownActions, child.Name())
		}
	}
}

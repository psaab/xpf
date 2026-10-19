// redistribute.go converts a Junos routing export value into FRR
// `redistribute` commands, skipping-and-warning on anything that cannot
// resolve to a source protocol so one bad line never poisons the whole
// managed frr-reload (#1880/#2223).
//
// Split out of policy_render.go (#6424); #12065 derives filtered route-maps per
// source protocol and avoids daemon-unsupported `match source-protocol` clauses.
//
// Symbols:
//   - knownRedistProtocols
//   - resolveRedistribute
//   - bgpExportPolicies14586, bgpPolicyRedistEntries14586
package frr

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// knownRedistProtocols are the FRR redistribute protocol keywords.
// ospf6 / ripng are the FRR keywords for OSPFv3 / RIPng redistribution;
// without them a bare `export ospf6` / `export ripng` falls through to the
// skip-and-warn path and IPv6 IGP redistribution cannot be expressed (#2943).
// #7121: the domain moved to config.FRRRoutingProtocolKeyword so the COMMIT
// gate can consult it. It lived here, where a commit-time validator could not
// reach it (pkg/frr imports pkg/config, not the reverse), which is why an
// unknown `from protocol` token committed clean and degraded the reload.
func knownRedistProtocol(name string) bool {
	return config.RoutingProtocolResolvable(name)
}

// resolveRedistribute converts a Junos export value into FRR redistribute commands.
// A known protocol emits a bare `redistribute <proto>` line.
// If it matches a policy-statement, it emits one `redistribute <proto>
// route-map <policy>-<proto>-xpf-redist` line per source protocol. Each
// referenced map contains only terms applicable to that source.
//
// Invariant: this never emits a syntactically-invalid `redistribute
// <name>` line. FRR's `redistribute` requires a source protocol token
// (connected/static/ospf/bgp/rip/isis/kernel); a bare policy-statement or
// typo name is rejected by FRR's parser. Because the line lands in the
// xpf-managed section, ONE rejected line fails the WHOLE reload, not just
// this stanza. frr-reload.py exits non-zero, and the additive `vtysh -f`
// fallback in reloadLocked applies every other line but also exits non-zero
// on that one: FRR stable/10.6 vtysh_config_from_file keeps going past a
// rejected line and returns its error. So the reload fails, and every retry
// re-reads the same file and fails the same way. What is lost is REMOVAL, not
// addition: a later commit that deletes a route, neighbour or policy leaves it
// live in FRR for as long as the bad line is rendered (#1880/#2223, #9510). So
// when an export cannot be resolved to a source protocol we SKIP it and warn
// rather than poison the managed reload.
//
// Cases after the no-from expansion (#14380) and the reject-only
// gate (#14698):
//
//   - A policy-statement whose explicit `from protocol` sources are
//     all self or off-family at this node, or a policy-statement
//     with no terms at all, still skips and warns: there is no
//     per-source route-map to attach at this node.
//     A term with NO `from protocol` that can accept is NOT in this
//     class — it applies to every source (redistPolicyForProtocol)
//     and enumerates the whole node-fitting keyword domain.
//     Per-source maps are defined union-wide only for the node an
//     export actually references.
//   - #14698: a source named ONLY by reject terms (explicit or
//     no-from) enrols nothing. `from protocol` in a reject term is a
//     Junos filter condition, never a redistribution request; the
//     reject term still rides in any enrolled source's filtered map.
//   - The export is neither a known protocol token nor a defined
//     policy-statement (a name that slipped past validation on a tolerant
//     load / peer-sync path, opts.lenientRoutingExportRef in pkg/config).
//     The strict validator REJECTS this case at commit; only the lenient
//     load/peer-sync path can reach the renderer with such a name.
//
// A source protocol can also be valid in general and still be rejected where
// the line lands. FRR's redistribute grammar is per address family, so
// `redistribute ospf6` under `router ospf` is rejected exactly like a typo
// (#9510). redistSourceFitsNode filters that on BOTH paths, at the use site,
// rather than rejecting the policy at commit: a policy-statement is reusable,
// and `from protocol ospf6` is valid under `router ospf6`.
// redistEntry is one source a `redistribute` export resolves to under an
// enclosing router: the FRR source protocol, and the route-map to attach
// ("" for a bare protocol token).
type redistEntry struct {
	proto    string
	routeMap string
}

func normalizedRedistProtocol(proto string) string {
	return config.CanonicalSourceProtocol(proto)
}

func redistProtocolRouteMapName(policy, proto string) string {
	return policy + "-" + normalizedRedistProtocol(proto) + config.ReservedRedistSuffix
}

// #15156 (B07-01): composed per-source redistribute maps.
//
// FRR keeps ONE route-map per (router, AF, source): successive
// `redistribute <proto> route-map X` lines replace, they do not chain.
// An IGP `export [ P1 P2 ]` chain — and the #14586 BGP origination union
// across neighbours — therefore must emit exactly one line per source,
// naming a composed map that evaluates the chain's per-source terms in
// chain order. Name: join(policies,"-") + ReservedChainSuffix +
// "-<proto>" + ReservedRedistSuffix, e.g.
// `NO-RFC1918-STATICS-xpf-chain-static-xpf-redist`.
// Collision with an operator policy or another generated map is refused
// fail-closed (redistChainMapCollision15156), mirroring #5277/#12065.
func redistChainRouteMapName15156(chain []string, proto string) string {
	return composedChainName(chain) + "-" + normalizedRedistProtocol(proto) + config.ReservedRedistSuffix
}

// redistChainForSource15156 resolves a proto across an ordered policy
// chain. It returns the distinct defined policies (in chain order) whose
// per-source enrollment includes proto, and whether the source appears
// only via bare protocol tokens (then it has no composed map).
func (m *Manager) redistChainForSource15156(chain []string, po *config.PolicyOptionsConfig, self, node, proto string) (policies []string, bare bool, ok bool) {
	seen := make(map[string]bool)
	for _, name := range chain {
		if name == "" {
			continue
		}
		if !isDefinedPolicyStatement(name, po) {
			if kw, isProto := config.FRRRoutingProtocolKeyword(name); isProto && normalizedRedistProtocol(kw) == proto {
				bare = true
			}
			continue
		}
		for _, e := range m.redistributeEntriesAt(name, po, self, node) {
			if e.proto == proto && !seen[name] {
				seen[name] = true
				policies = append(policies, name)
			}
		}
	}
	return policies, bare, len(policies) > 0 || bare
}

// redistChainEntries15156 composes one entry per source across a chain:
// bare-token sources stay bare, a single-policy source keeps its
// per-source map, and a multi-policy source names the composed map.
func (m *Manager) redistChainEntries15156(chain []string, po *config.PolicyOptionsConfig, self, node string) []redistEntry {
	protoSet := make(map[string]bool)
	var protos []string
	add := func(p string) {
		if !protoSet[p] {
			protoSet[p] = true
			protos = append(protos, p)
		}
	}
	for _, name := range chain {
		if name == "" {
			continue
		}
		if !isDefinedPolicyStatement(name, po) {
			for _, e := range m.redistributeEntriesAt(name, po, self, node) {
				add(e.proto)
			}
			continue
		}
		for _, e := range m.redistributeEntriesAt(name, po, self, node) {
			add(e.proto)
		}
	}
	sort.Strings(protos)
	var out []redistEntry
	for _, proto := range protos {
		policies, bare, _ := m.redistChainForSource15156(chain, po, self, node, proto)
		switch {
		case len(policies) >= 2:
			out = append(out, redistEntry{proto: proto, routeMap: redistChainRouteMapName15156(policies, proto)})
		case len(policies) == 1:
			out = append(out, redistEntry{proto: proto, routeMap: redistProtocolRouteMapName(policies[0], proto)})
		case bare:
			out = append(out, redistEntry{proto: proto})
		}
	}
	return out
}

// redistChainNameKey15156 identifies a distinct (chain, source) composed
// map; chains are stored sorted by rendered name at call sites.
func redistChainKey15156(chain []string, proto string) string {
	return strings.Join(chain, "\x00") + "\x01" + proto
}

// redistComposedChains15156 collects every composed per-source map the
// section needs: IGP export chains of >=2 policies sharing a source, and
// the BGP origination union (sorted distinct defined policies per source).
// Keys are the composed route-map names.
func redistComposedChains15156(fc *FullConfig) map[string]redistComposedReq15156 {
	out := make(map[string]redistComposedReq15156)
	if fc == nil || fc.PolicyOptions == nil {
		return out
	}
	po := fc.PolicyOptions
	m := New()
	addChain := func(chain []string, self, node string) {
		// Distinct defined policies in chain order.
		var defined []string
		seen := make(map[string]bool)
		for _, n := range chain {
			if isDefinedPolicyStatement(n, po) && !seen[n] {
				seen[n] = true
				defined = append(defined, n)
			}
		}
		if len(defined) < 2 {
			return
		}
		for _, e := range m.redistChainEntries15156(defined, po, self, node) {
			if !strings.Contains(e.routeMap, ReservedChainSuffix) {
				continue
			}
			policies, _, _ := m.redistChainForSource15156(defined, po, self, node, e.proto)
			if len(policies) < 2 {
				continue
			}
			name := redistChainRouteMapName15156(policies, e.proto)
			if _, ok := out[name]; !ok {
				out[name] = redistComposedReq15156{chain: append([]string(nil), policies...), proto: e.proto}
			}
		}
	}
	addBGP := func(bgp *config.BGPConfig) {
		if bgp == nil {
			return
		}
		policies := bgpExportPolicies14586(bgp, po)
		if len(policies) < 2 {
			return
		}
		for _, node := range []string{"bgp", "bgp-ipv6"} {
			// Per node, enrollment differs by family; compose per source
			// with the policies enrolling there, sorted (bgpExportPolicies
			// is sorted) for a deterministic OR composition.
			protoPolicies := make(map[string][]string)
			var protos []string
			for _, name := range policies {
				for _, e := range m.redistributeEntriesAt(name, po, "bgp", node) {
					if !containsString15156(protoPolicies[e.proto], name) {
						if len(protoPolicies[e.proto]) == 0 {
							protos = append(protos, e.proto)
						}
						protoPolicies[e.proto] = append(protoPolicies[e.proto], name)
					}
				}
			}
			for _, proto := range protos {
				ps := protoPolicies[proto]
				if len(ps) < 2 {
					continue
				}
				name := redistChainRouteMapName15156(ps, proto)
				if _, ok := out[name]; !ok {
					out[name] = redistComposedReq15156{chain: append([]string(nil), ps...), proto: proto}
				}
			}
		}
	}
	walk := func(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig) {
		if ospf != nil {
			addChain(ospf.Export, "ospf", "ospf")
		}
		if ospfv3 != nil {
			addChain(ospfv3.Export, "ospf6", "ospf6")
		}
		if rip != nil {
			addChain(rip.Redistribute, "rip", "rip")
		}
		if isis != nil {
			addChain(isis.Export, "isis", "isis")
		}
		addBGP(bgp)
	}
	walk(fc.OSPF, fc.OSPFv3, fc.BGP, fc.RIP, fc.ISIS)
	for _, inst := range fc.Instances {
		walk(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS)
	}
	return out
}

func containsString15156(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

type redistComposedReq15156 struct {
	chain []string
	proto string
}

// renderRedistComposedMaps15156 emits the composed per-source route-map
// definitions (sorted by name, deterministic).
func (m *Manager) renderRedistComposedMaps15156(fc *FullConfig) string {
	reqs := redistComposedChains15156(fc)
	if len(reqs) == 0 {
		return ""
	}
	names := make([]string, 0, len(reqs))
	for n := range reqs {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, name := range names {
		req := reqs[name]
		b.WriteString(m.renderRedistComposedMap15156(fc.PolicyOptions, name, req.chain, req.proto))
		b.WriteString("!\n")
	}
	return b.String()
}

// renderRedistComposedMap15156 renders one composed per-source map: each
// chain member's per-source filtered terms in order, continuous sequences,
// explicit defaults terminate (next-policy jumps to the next member), and
// fall-off-the-end resolves to deny — the protocol default for IGP
// redistribution and the fail-closed origination default for BGP.
func (m *Manager) renderRedistComposedMap15156(po *config.PolicyOptionsConfig, name string, chain []string, proto string) string {
	var filtered []*config.PolicyStatement
	var names []string
	var total uint64
	for _, pn := range chain {
		ps := po.PolicyStatements[pn]
		if ps == nil {
			continue
		}
		f := redistPolicyForProtocol(ps, proto)
		filtered = append(filtered, f)
		names = append(names, pn)
		total += config.RouteMapSequenceCount(po, f)
	}
	if total > config.MaxRouteMapSequences {
		slog.Warn("oversized composed redistribute route-map; rendering an explicit deny instead (#15156)",
			"route_map", name, "sequences", total, "max", config.MaxRouteMapSequences)
		m.noteQuarantined(name)
		return renderQuarantineDenyRouteMap(name) + "!\n"
	}
	type part struct {
		definitions string
		body        string
		nextPolicy  bool
		startSeq    int
		defaultSeq  int
		defaultVerb string
	}
	var parts []part
	seq := 10
	terminated := false
	for i, f := range filtered {
		definitions, body, next := m.renderPolicyTermSequencesWithDefinitions(po, name, name+"-"+names[i], f, seq)
		p := part{definitions: definitions, body: body, nextPolicy: policyHasNextPolicyTerm(f), startSeq: seq}
		seq = next
		switch f.DefaultAction {
		case "accept":
			p.defaultVerb = "permit"
			p.defaultSeq = seq
			seq += 10
			terminated = !p.nextPolicy
		case "reject":
			p.defaultVerb = "deny"
			p.defaultSeq = seq
			seq += 10
			terminated = !p.nextPolicy
		}
		parts = append(parts, p)
		if terminated {
			break
		}
	}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.definitions)
	}
	fallbackSeq := seq
	for i, p := range parts {
		target := fallbackSeq
		if i+1 < len(parts) {
			target = parts[i+1].startSeq
		}
		if p.nextPolicy {
			p.body = renderNextPolicyTarget(p.body, target)
		}
		b.WriteString(p.body)
		if p.defaultVerb != "" {
			fmt.Fprintf(&b, "route-map %s %s %d\n", frrName(name), p.defaultVerb, p.defaultSeq)
			b.WriteString("exit\n")
		}
	}
	if !terminated {
		fmt.Fprintf(&b, "route-map %s deny %d\n", frrName(name), fallbackSeq)
		b.WriteString("exit\n")
	}
	return b.String()
}

// redistChainMapCollision15156 refuses (fail-closed) a composed
// redistribute map name that collides with an operator policy-statement,
// a per-source map, a #5277 composed BGP chain map, or a distinct
// (chain, source) deriving the same name — FRR merges same-named maps.
func redistChainMapCollision15156(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	po := fc.PolicyOptions
	reqs := redistComposedChains15156(fc)
	if len(reqs) == 0 {
		return nil
	}
	operator := make(map[string]string)
	for name := range po.PolicyStatements {
		operator[frrName(name)] = name
	}
	// Generated names that must stay distinct.
	generated := make(map[string]string)
	for _, name := range mapKeysReq15156(reqs) {
		req := reqs[name]
		final := frrName(name)
		if op, ok := operator[final]; ok {
			return fmt.Errorf("composed redistribute route-map %q (chain %v, source %s) collides with operator policy-statement %q; FRR merges same-named route-maps — refusing to render (#15156)", name, req.chain, req.proto, op)
		}
		key := redistChainKey15156(req.chain, req.proto)
		if prev, ok := generated[final]; ok && prev != key {
			return fmt.Errorf("redistribute chains derive the same composed route-map %q; FRR would merge them — refusing to render (#15156)", name)
		}
		generated[final] = key
		// Per-source maps.
		for _, pn := range req.chain {
			_ = pn
		}
	}
	// Cross-check against per-source and QNH names via final names.
	for _, psName := range sortedKeysPS15156(po) {
		ps := po.PolicyStatements[psName]
		for _, proto := range redistReferencedProtocols14380(ps, redistReferencedNodes14380(fc)[psName]) {
			final := frrName(redistProtocolRouteMapName(psName, proto))
			if _, ok := reqs[final]; ok {
				// reqs keyed by raw name; compare final forms.
				for raw := range reqs {
					if frrName(raw) == final {
						return fmt.Errorf("composed redistribute route-map %q collides with per-source route-map %q; FRR merges same-named route-maps — refusing to render (#15156)", raw, redistProtocolRouteMapName(psName, proto))
					}
				}
			}
		}
	}
	return nil
}

func mapKeysReq15156(m map[string]redistComposedReq15156) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysPS15156(po *config.PolicyOptionsConfig) []string {
	out := make([]string, 0, len(po.PolicyStatements))
	for k := range po.PolicyStatements {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// termCanAcceptForRedist14698 reports whether term can ever cause a
// route to be accepted for redistribution. It mirrors the route-map
// action mapping in renderPolicyTermSequences: a cost-set rejecting
// term (`then reject`, incl. the contradictory NextPolicy+action form
// that renders deny) only filters; every other term — terminating
// accept, non-terminating fall-through (its set clauses run and the
// route reaches a later term or the policy default, which may
// accept), or bare `then next policy` (resume at the next policy,
// which may accept) — can accept. In Junos, `from protocol` in a
// reject term is a match condition, never a redistribution request
// (#14698).
func termCanAcceptForRedist14698(term *config.PolicyTerm) bool {
	if term == nil {
		return false
	}
	if term.NextPolicy && term.Action != "" {
		return false // renders deny (contradictory actions)
	}
	return !(term.Action == "reject" && !term.NextPolicy)
}

// redistFilterPermitDominated14698 reports whether enrolling proto
// for ps would attach a source the policy can never permit through
// that source's filtered map, in the #14698 reject-only sense: proto
// is NAMED by at least one cost-set rejecting term, no accept-capable
// term can match proto (explicitly or no-from), and the policy
// default is not accept. A reject term's `from protocol` is a Junos
// filter condition, never a redistribution request, so such a source
// must not be activated by the guard. Sources never named by a
// reject term, sources an accept term can match, and sources under
// an authored default-accept are NOT dominated — the #14369/#14586
// contracts (keyword-named reject policies, no-from reject guards
// under default-accept) keep their attachments and deny sequences.
func redistFilterPermitDominated14698(ps *config.PolicyStatement, proto string) bool {
	if ps.DefaultAction == "accept" {
		return false
	}
	proto = normalizedRedistProtocol(proto)
	namedByReject := false
	for _, term := range ps.Terms {
		if term == nil || termCanAcceptForRedist14698(term) {
			continue
		}
		for _, p := range term.FromProtocols {
			if normalizedRedistProtocol(p) == proto {
				namedByReject = true
			}
		}
	}
	if !namedByReject {
		return false
	}
	for _, term := range ps.Terms {
		if !termCanAcceptForRedist14698(term) {
			continue
		}
		if len(term.FromProtocols) == 0 {
			return false
		}
		for _, p := range term.FromProtocols {
			if normalizedRedistProtocol(p) == proto {
				return false
			}
		}
	}
	return true
}

// redistProtocols is the explicit-only set: the per-source maps
// generatePolicyOptions defines for every policy it renders and the
// names redistProtocolMapCollision guards, where no export node is
// in hand. A no-from term adds nothing here (see
// redistProtocolsForNode). Only terms that can accept enrol a source
// (#14698), and only known routing-protocol keywords enrol — an
// unknown lenient-path token must never become a `redistribute
// <unknown>` source.
func redistProtocols(ps *config.PolicyStatement) []string {
	return redistProtocolsFiltered(ps, "", "", false)
}

// redistProtocolsForNode is redistProtocols at one render node
// (#14380): a term with no `from protocol` that can accept applies to
// every source (redistPolicyForProtocol), so it adds the whole keyword
// domain, filtered exactly like an explicit term — self excluded,
// redistSourceFitsNode(proto, node) required. Explicit tokens are
// filtered the same way (#15011): a mixed policy must not re-add a
// self or off-family explicit source via this union. With no enclosing
// router (self/node both "") the whole domain renders. A no-from
// reject term adds nothing (#14698): it can only deny.
func redistProtocolsForNode(ps *config.PolicyStatement, self, node string) []string {
	return redistProtocolsFiltered(ps, self, node, true)
}

func redistProtocolsFiltered(ps *config.PolicyStatement, self, node string, expandNoFrom bool) []string {
	if ps == nil {
		return nil
	}
	seen := make(map[string]bool)
	hasNoFromTerm := false
	for _, term := range ps.Terms {
		if term == nil {
			continue
		}
		if len(term.FromProtocols) == 0 {
			// #14698: only a term that can accept expands the domain;
			// a no-from reject term is a pure filter and enrols no
			// source (it still rides in any enrolled source's map
			// via redistPolicyForProtocol, preserving deny order).
			if termCanAcceptForRedist14698(term) {
				hasNoFromTerm = true
			}
			continue
		}
		if !termCanAcceptForRedist14698(term) {
			continue
		}
		for _, proto := range term.FromProtocols {
			// #14698: gate explicit tokens through the same
			// knownRedistProtocol allowlist the bare-export branch
			// uses; unknown lenient-path tokens enrol nothing
			// (normalizedRedistProtocol alone would pass them raw).
			if !knownRedistProtocol(proto) {
				continue
			}
			proto = normalizedRedistProtocol(proto)
			// #15011: explicit tokens are filtered exactly like the
			// no-from expansion below — self excluded and
			// redistSourceFitsNode required — whenever a render
			// node is in hand. redistProtocols passes self/node
			// both "" so the explicit-only set (map definitions
			// and the collision guard, where no node exists) is
			// unchanged. Without this, a mixed policy (an explicit
			// `from protocol bgp` term plus a no-from term) merged
			// its unfiltered explicit set back in via
			// redistProtocolsForNode, rendering FRR-invalid
			// `redistribute bgp` under router bgp / `ospf6`
			// under IPv4 and failing the whole managed reload.
			if self != "" && proto == self {
				continue
			}
			if !redistSourceFitsNode(proto, node) {
				continue
			}
			seen[proto] = true
		}
	}
	// Only the enumeration site (redistributeEntriesAt, via
	// redistProtocolsForNode) expands: with no enclosing router
	// (self/node both "") the whole domain renders, exactly like an
	// explicit term that no node filters.
	if expandNoFrom && hasNoFromTerm {
		for _, proto := range config.RedistributionSourceKeywords() {
			proto = normalizedRedistProtocol(proto)
			if self != "" && proto == self {
				continue
			}
			if !redistSourceFitsNode(proto, node) {
				continue
			}
			seen[proto] = true
		}
	}
	// #14698: drop permit-dominated sources — e.g. bgp named only by a
	// reject guard while a no-from accept expands the domain. The
	// guard still rides in other sources' maps; bgp itself originates
	// nothing, so no `redistribute bgp` and no EXP-bgp map.
	for proto := range seen {
		if redistFilterPermitDominated14698(ps, proto) {
			delete(seen, proto)
		}
	}
	protocols := make([]string, 0, len(seen))
	for proto := range seen {
		protocols = append(protocols, proto)
	}
	sort.Strings(protocols)
	return protocols
}

func redistPolicyForProtocol(ps *config.PolicyStatement, proto string) *config.PolicyStatement {
	if ps == nil {
		return nil
	}
	proto = normalizedRedistProtocol(proto)
	filtered := *ps
	filtered.Terms = nil
	for _, term := range ps.Terms {
		if term == nil {
			continue
		}
		applies := len(term.FromProtocols) == 0
		for _, source := range term.FromProtocols {
			if normalizedRedistProtocol(source) == proto {
				applies = true
				break
			}
		}
		if applies {
			copy := *term
			copy.FromProtocols = nil
			filtered.Terms = append(filtered.Terms, &copy)
		}
	}
	return &filtered
}

func redistProtocolMapCollision(po *config.PolicyOptionsConfig) error {
	return redistProtocolMapCollisionFiltered(po, func(ps *config.PolicyStatement) []string {
		return redistProtocols(ps)
	})
}

// redistProtocolMapCollisionForNodes is redistProtocolMapCollision
// over the #14380 expanded sets: for a policy-statement actually
// referenced by an export at (self, node), a no-from term also
// generates the node-fitting whole domain, and an operator policy
// colliding with one of those generated names must refuse the apply
// (FRR merges same-named route-maps). Unreferenced policies keep the
// explicit-only set above.
func redistProtocolMapCollisionForNodes(po *config.PolicyOptionsConfig, self, node string) error {
	return redistProtocolMapCollisionFiltered(po, func(ps *config.PolicyStatement) []string {
		return redistProtocolsForNode(ps, self, node)
	})
}

func redistProtocolMapCollisionFiltered(po *config.PolicyOptionsConfig, protocolsFor func(*config.PolicyStatement) []string) error {
	if po == nil || po.PolicyStatements == nil {
		return nil
	}
	names := make([]string, 0, len(po.PolicyStatements))
	for name := range po.PolicyStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	operatorNames := make(map[string]string, len(names))
	for _, name := range names {
		normalized := frrName(name)
		if _, exists := operatorNames[normalized]; !exists {
			operatorNames[normalized] = name
		}
	}
	generated := make(map[string]string)
	for _, policy := range names {
		for _, proto := range protocolsFor(po.PolicyStatements[policy]) {
			routeMap := redistProtocolRouteMapName(policy, proto)
			final := frrName(routeMap)
			if operator, ok := operatorNames[final]; ok {
				return fmt.Errorf(
					"policy-statement %q generates redistribute route-map %q, which collides with operator policy-statement %q; FRR merges same-named route-maps — refusing to render",
					policy, routeMap, operator)
			}
			if previous, ok := generated[final]; ok && previous != policy+"\x00"+proto {
				return fmt.Errorf(
					"policy-statements generate the same redistribute route-map %q (%q vs %q); FRR merges same-named route-maps — refusing to render",
					final, previous, policy+" / "+proto)
			}
			generated[final] = policy + "\x00" + proto
		}
	}
	return nil
}

func renderRedistributePolicyMap(m *Manager, po *config.PolicyOptionsConfig, policy string, ps *config.PolicyStatement, proto string) string {
	routeMap := redistProtocolRouteMapName(policy, proto)
	filtered := redistPolicyForProtocol(ps, proto)
	if n := config.RouteMapSequenceCount(po, filtered); n > config.MaxRouteMapSequences {
		slog.Warn("oversized redistribute route-map policy: expansion would overflow FRR sequence numbers; rendering an explicit deny instead",
			"policy", policy, "protocol", proto, "sequences", n, "max", config.MaxRouteMapSequences)
		m.noteQuarantined(routeMap)
		return renderQuarantineDenyRouteMap(routeMap) + "!\n"
	}
	body := m.renderRouteMapForPolicyWithFallback(
		po, routeMap, filtered, policyTrailingAction(policy, filtered, nil), "deny")
	return body + "!\n"
}

// resolveRedistribute renders an export as OSPF/RIP/BGP-shaped
// `redistribute <proto> [route-map X]` lines. IS-IS has a different grammar
// and uses resolveISISRedistribute instead (#9666).
// The optional qualified-next-hop metric scope is passed by IGP call sites
// only; BGP MED is distinct and must not consume the IGP export cost.
func (m *Manager) resolveRedistribute(export string, po *config.PolicyOptionsConfig, self string, _ map[string]bool, metrics ...*qnhMetricScope11447) string {
	return formatRedistEntries(m.redistributeEntries(export, po, self, metrics...))
}

// bgpExportPolicies14586 returns the sorted, de-duplicated set of DEFINED
// policy-statements referenced by the effective BGP export chain of any
// neighbor in this BGP instance (global default or per-neighbor override,
// Junos most-specific-wins via bgpNeighborExportChain), plus the global
// chain when the instance has no neighbors. Import chains never
// contribute: inbound filtering originates nothing.
//
// #14586: a defined policy in an effective export chain must ORIGINATE
// the routes its `from protocol` terms select. Junos has no separate
// redistribution step — the BGP export policy is what originates
// static/direct (and other) routes — so the renderer emits, per policy
// and source, `redistribute <proto> route-map <policy>-<proto>-xpf-redist`
// (the filtered per-source map #12065 already renders) alongside the
// per-peer `route-map out`. This is not the #2473 leak: redistribution
// is gated by that filtered map (fail-closed deny), never unfiltered.
func bgpExportPolicies14586(bgp *config.BGPConfig, po *config.PolicyOptionsConfig) []string {
	if bgp == nil || po == nil {
		return nil
	}
	global := bgpGlobalExportChain(bgp, po)
	seen := make(map[string]bool)
	add := func(chain []string) {
		for _, name := range chain {
			seen[name] = true
		}
	}
	if len(bgp.Neighbors) == 0 {
		add(global)
	}
	for _, n := range bgp.Neighbors {
		if n == nil {
			continue
		}
		add(bgpNeighborExportChain(n, global, po))
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// bgpPolicyRedistEntries14586 returns the filtered redistribution entries
// for the defined policies in policies at the router-level BGP node,
// de-duplicated by (proto, routeMap) so a policy named by several chains
// originates each source once. Self (bgp) and off-family sources are
// dropped by redistributeEntriesAt, exactly as for IGP exports; a
// no-`from protocol` term expands over the whole node-fitting domain
// (#14380 semantics). The IPv6 sibling is bgpPolicyIPv6RedistEntries14586.
func (m *Manager) bgpPolicyRedistEntries14586(policies []string, po *config.PolicyOptionsConfig) []redistEntry {
	return m.bgpPolicyRedistEntriesAt14586(policies, po, "bgp", "bgp")
}

// bgpPolicyIPv6RedistEntries14586 is bgpPolicyRedistEntries14586 at the
// `address-family ipv6 unicast` node ("bgp-ipv6" grammar).
func (m *Manager) bgpPolicyIPv6RedistEntries14586(policies []string, po *config.PolicyOptionsConfig) []redistEntry {
	return m.bgpPolicyRedistEntriesAt14586(policies, po, "bgp", "bgp-ipv6")
}

func (m *Manager) bgpPolicyRedistEntriesAt14586(policies []string, po *config.PolicyOptionsConfig, self, node string) []redistEntry {
	// #15156: compose per source across the whole policy set — one entry
	// per source (bare/single/composed), never one map per policy.
	return m.redistChainEntries15156(policies, po, self, node)
}

// redistReferencedNodes14380 collects the (self, node) pairs at which
// a policy-statement is actually referenced by a redistribute-backed
// export, so the per-source maps generatePolicyOptions defines and the
// collision belt guards cover exactly the nodes whose attachments name
// them. IGP exports (OSPF/OSPFv3/RIP/IS-IS, global and per-instance)
// contribute their (self, node) pair; #14586 BGP exports contribute
// ("bgp", "bgp") AND ("bgp", "bgp-ipv6") — a defined policy in an
// effective BGP export chain now also renders as a filtered
// `redistribute … route-map <policy>-<proto>-xpf-redist` per family,
// so its per-source maps (incl. a no-from policy's expanded set) must
// be defined at both BGP nodes.
func redistReferencedNodes14380(fc *FullConfig) map[string][][2]string {
	out := make(map[string][][2]string)
	if fc == nil {
		return out
	}
	po := fc.PolicyOptions
	add := func(name, self, node string) {
		if name == "" || !isDefinedPolicyStatement(name, po) {
			return
		}
		for _, p := range out[name] {
			if p[0] == self && p[1] == node {
				return
			}
		}
		out[name] = append(out[name], [2]string{self, node})
	}
	walk := func(ospf *config.OSPFConfig, ospfv3 *config.OSPFv3Config, bgp *config.BGPConfig, rip *config.RIPConfig, isis *config.ISISConfig) {
		if ospf != nil {
			for _, e := range ospf.Export {
				add(e, "ospf", "ospf")
			}
		}
		if ospfv3 != nil {
			for _, e := range ospfv3.Export {
				add(e, "ospf6", "ospf6")
			}
		}
		if bgp != nil {
			// #14586: the union of effective export chains (global +
			// per-neighbor) at both BGP family nodes.
			for _, name := range bgpExportPolicies14586(bgp, po) {
				add(name, "bgp", "bgp")
				add(name, "bgp", "bgp-ipv6")
			}
		}
		if rip != nil {
			for _, e := range rip.Redistribute {
				add(e, "rip", "rip")
			}
		}
		if isis != nil {
			for _, e := range isis.Export {
				add(e, "isis", "isis")
			}
		}
	}
	walk(fc.OSPF, fc.OSPFv3, fc.BGP, fc.RIP, fc.ISIS)
	for _, inst := range fc.Instances {
		walk(inst.OSPF, inst.OSPFv3, inst.BGP, inst.RIP, inst.ISIS)
	}
	return out
}

// redistReferencedProtocols14380 returns, per policy-statement, the
// union of per-source protocols over the nodes that actually
// reference it: the explicit set (for unreferenced-node map
// definitions) plus, at each referencing node, the node-filtered
// set — explicit tokens filtered by self/family (#15011) and, for
// a no-from term, the whole node-fitting domain.
func redistReferencedProtocols14380(ps *config.PolicyStatement, nodes [][2]string) []string {
	seen := make(map[string]bool)
	for _, proto := range redistProtocols(ps) {
		seen[proto] = true
	}
	for _, nd := range nodes {
		for _, proto := range redistProtocolsForNode(ps, nd[0], nd[1]) {
			seen[proto] = true
		}
	}
	out := make([]string, 0, len(seen))
	for proto := range seen {
		out = append(out, proto)
	}
	sort.Strings(out)
	return out
}

func applyQNHMetricRouteMap11447(export string, metrics *qnhMetricScope11447, entries []redistEntry, resolvedAsPolicy ...bool) {
	if metrics == nil {
		return
	}
	routeMap := ""
	// #14369: a defined policy-statement named `static` resolves through
	// the policy branch, so its static entries take the policy QNH map;
	// the bare-protocol staticMap applies only to the bare-token reading.
	if export == "static" && knownRedistProtocol(export) && !(len(resolvedAsPolicy) > 0 && resolvedAsPolicy[0]) {
		routeMap = metrics.staticMap
	} else {
		routeMap = metrics.policyMaps[export]
	}
	if routeMap == "" {
		return
	}
	for i := range entries {
		if entries[i].proto == "static" {
			entries[i].routeMap = routeMap
		}
	}
}

func formatRedistEntries(entries []redistEntry) string {
	var sb strings.Builder
	for _, e := range entries {
		if e.routeMap == "" {
			fmt.Fprintf(&sb, " redistribute %s\n", sanitizeFRRValue(e.proto))
			continue
		}
		fmt.Fprintf(&sb, " redistribute %s route-map %s\n", sanitizeFRRValue(e.proto), frrName(e.routeMap))
	}
	return sb.String()
}

// resolveRedistributeChain renders a whole IGP export chain as one
// redistribute line per source (#15156). With <2 defined policies it is
// byte-identical to resolving each export singly.
func (m *Manager) resolveRedistributeChain(chain []string, po *config.PolicyOptionsConfig, self string, metrics ...*qnhMetricScope11447) string {
	if countDefined15156(chain, po) < 2 {
		var b strings.Builder
		for _, e := range chain {
			b.WriteString(m.resolveRedistribute(e, po, self, nil, metrics...))
		}
		return b.String()
	}
	entries := m.redistChainEntries15156(chain, po, self, self)
	if len(metrics) > 0 && metrics[0] != nil {
		m.applyQNHChain15156(chain, metrics[0], entries)
	}
	return formatRedistEntries(entries)
}

func (m *Manager) resolveISISRedistributeChain(chain []string, po *config.PolicyOptionsConfig, isisLevel string, metrics ...*qnhMetricScope11447) string {
	if countDefined15156(chain, po) < 2 {
		var b strings.Builder
		for _, e := range chain {
			b.WriteString(m.resolveISISRedistribute(e, po, isisLevel, nil, metrics...))
		}
		return b.String()
	}
	entries := m.redistChainEntries15156(chain, po, "isis", "isis")
	if len(metrics) > 0 && metrics[0] != nil {
		m.applyQNHChain15156(chain, metrics[0], entries)
	}
	return isisRedistributeLines(entries, isisLevel)
}

func countDefined15156(chain []string, po *config.PolicyOptionsConfig) int {
	n := 0
	for _, e := range chain {
		if isDefinedPolicyStatement(e, po) {
			n++
		}
	}
	return n
}

// applyQNHChain15156 rewrites only single-policy (or bare) static entries
// to their QNH metric map, preserving per-policy scoping; a composed
// multi-policy static entry keeps its composed map (metric overlay for
// composed chains is deferred — see docs/log/15156.md).
func (m *Manager) applyQNHChain15156(chain []string, metrics *qnhMetricScope11447, entries []redistEntry) {
	for i := range entries {
		if entries[i].proto != "static" {
			continue
		}
		if strings.Contains(entries[i].routeMap, ReservedChainSuffix) {
			continue
		}
		if entries[i].routeMap == "" {
			if metrics.staticMap != "" {
				entries[i].routeMap = metrics.staticMap
			}
			continue
		}
		for _, name := range chain {
			if entries[i].routeMap == redistProtocolRouteMapName(name, "static") {
				if rm := metrics.policyMaps[name]; rm != "" {
					entries[i].routeMap = rm
				}
			}
		}
	}
}

// resolveISISRedistribute renders an export in isisd's grammar (#9666):
//
//	redistribute <ipv4|ipv6> <proto> <level-1|level-2> [route-map X]
//
// isisd installs only that form (isis_cli.c isis_redistribute_cmd). The
// address-family keyword and the level are mandatory, so the OSPF-shaped
// `redistribute <proto>` resolveRedistribute renders was rejected for EVERY
// IS-IS export, and one rejected line fails the whole managed reload (#9510).
//
// The families come from the source's lib/route_types.txt columns
// (frrRedistSourceAFI): ospf/rip are IPv4 only, ospf6/ripng IPv6 only, the
// rest both. xpf enables both `ip router isis` and `ipv6 router isis` on its
// circuits (#8450), so a dual-family source is redistributed into both.
//
// The levels come from the router's is-type, through the same canonicalizer
// the is-type line uses (#8446): level-1 -> level-1; level-1-2 -> one line per
// level, since a router in both levels redistributes into both and each FRR
// line names one; everything else -> the narrow level-2 default.
func (m *Manager) resolveISISRedistribute(export string, po *config.PolicyOptionsConfig, isisLevel string, _ map[string]bool, metrics ...*qnhMetricScope11447) string {
	return isisRedistributeLines(m.redistributeEntries(export, po, "isis", metrics...), isisLevel)
}

func isisRedistributeLines(entries []redistEntry, isisLevel string) string {
	level, ok := config.CanonicalISISLevel(isisLevel)
	if !ok {
		level = config.DefaultISISLevel
	}
	var levels []string
	switch level {
	case "level-1":
		levels = []string{"level-1"}
	case "level-1-2":
		levels = []string{"level-1", "level-2"}
	default:
		levels = []string{"level-2"}
	}
	var sb strings.Builder
	for _, e := range entries {
		afi, known := frrRedistSourceAFI[e.proto]
		if !known {
			afi = afiBoth
		}
		for _, fam := range []struct {
			bit  redistAFI
			name string
		}{{afiV4, "ipv4"}, {afiV6, "ipv6"}} {
			if afi&fam.bit == 0 {
				continue
			}
			for _, lv := range levels {
				if e.routeMap == "" {
					fmt.Fprintf(&sb, " redistribute %s %s %s\n", fam.name, sanitizeFRRValue(e.proto), lv)
				} else {
					fmt.Fprintf(&sb, " redistribute %s %s %s route-map %s\n", fam.name, sanitizeFRRValue(e.proto), lv, frrName(e.routeMap))
				}
			}
		}
	}
	return sb.String()
}

func (m *Manager) redistributeEntries(export string, po *config.PolicyOptionsConfig, self string, metrics ...*qnhMetricScope11447) []redistEntry {
	entries := m.redistributeEntriesAt(export, po, self, self)
	if len(metrics) > 0 {
		applyQNHMetricRouteMap11447(export, metrics[0], entries, isDefinedPolicyStatement(export, po))
	}
	return entries
}

// resolveBGPIPv6Redistribute renders a BGP bare-token export into
// `address-family ipv6 unicast` (#9667). It applies the same self and policy
// rules as resolveRedistribute under router bgp, but filters sources by the
// grammar installed in that address family ("bgp-ipv6"), and indents the lines
// one level deeper to sit inside the block.
func (m *Manager) resolveBGPIPv6Redistribute(export string, po *config.PolicyOptionsConfig, _ map[string]bool) string {
	entries := m.redistributeEntriesAt(export, po, "bgp", "bgp-ipv6")
	return indentFRRLines(formatRedistEntries(entries), " ")
}

func indentFRRLines(s, prefix string) string {
	if s == "" {
		return s
	}
	lines := strings.SplitAfter(s, "\n")
	var sb strings.Builder
	for _, l := range lines {
		if l == "" {
			continue
		}
		sb.WriteString(prefix)
		sb.WriteString(l)
	}
	return sb.String()
}

// redistributeEntriesAt is redistributeEntries with the render node separate
// from the router identity: self decides the self-redistribute drop, node
// selects the redistribute grammar a source must fit (#9667, #9510).
func (m *Manager) redistributeEntriesAt(export string, po *config.PolicyOptionsConfig, self, node string) []redistEntry {
	// #14369: a DEFINED policy-statement wins over the bare-protocol
	// reading (the Junos reading, and the BGP renderer's reading in
	// protocols_render.go). Look up the RAW export name, before the
	// bare-token canonicalization below, so a policy literally
	// named `direct` (or any protocol keyword) is honored as a policy;
	// the bare-token reading applies only when no such policy exists.
	// #14376 canonicalization therefore happens AFTER this lookup and
	// only on the bare-token path: a defined policy name is never
	// rewritten, and an unknown lenient-path name still misses both
	// branches by its exact name and reaches skip-and-warn below.
	if po != nil && po.PolicyStatements != nil {
		if ps, ok := po.PolicyStatements[export]; ok {
			protocols := make(map[string]bool)
			skipped := false
			hasNoFromTerm := false
			for _, term := range ps.Terms {
				if term == nil {
					continue
				}
				// A term with no `from protocol` matches routes from
				// every source (redistPolicyForProtocol), so a term
				// that can accept contributes the whole keyword
				// domain below, filtered exactly like an explicit
				// term: self excluded, redistSourceFitsNode(proto,
				// node) required. #14698: a no-from REJECT term is a
				// pure filter — it enrols no source, though it still
				// rides in any enrolled source's map via
				// redistPolicyForProtocol.
				if len(term.FromProtocols) == 0 {
					if termCanAcceptForRedist14698(term) {
						hasNoFromTerm = true
					}
					continue
				}
				// #14698: a reject term's `from protocol` is a match
				// condition, never a redistribution request; only
				// terms that can accept enrol their sources. The
				// reject term itself is preserved in the per-source
				// map by redistPolicyForProtocol, so its filtering
				// is unchanged for enrolled sources.
				if !termCanAcceptForRedist14698(term) {
					continue
				}
				for _, rawProto := range term.FromProtocols {
					// #14698: unknown lenient-path tokens enrol
					// nothing — only the knownRedistProtocol
					// allowlist may become a redistribute source.
					if !knownRedistProtocol(rawProto) {
						continue
					}
					proto := normalizedRedistProtocol(rawProto)
					// Skip a policy term that matches the enclosing
					// protocol's own routes — `redistribute ospf
					// route-map X` under `router ospf` is self-
					// redistribution and FRR rejects it (#2943).
					if self != "" && proto == self {
						skipped = true
						continue
					}
					// #9510: a term whose source is outside the enclosing
					// router's address family is dropped here, at the use
					// site. The same policy stays valid under a router
					// whose grammar lists that source.
					if !redistSourceFitsNode(proto, node) {
						slog.Warn("FRR redistribute policy term skipped: source protocol is not in this router's address family",
							"policy", export, "protocol", self, "source", proto)
						skipped = true
						continue
					}
					protocols[proto] = true
				}
			}
			if hasNoFromTerm {
				// #14380: a no-from term expands over every source
				// that fits this node (redistProtocolsForNode), so a
				// protocol-less or mixed policy yields the union.
				for _, proto := range redistProtocolsForNode(ps, self, node) {
					protocols[proto] = true
				}
			}
			// #14698: prune permit-dominated sources (redistProtocols-
			// Filtered already drops them on the expansion path; this
			// covers explicit-only enrollment, e.g. a bgp source whose
			// every applying term rejects).
			for proto := range protocols {
				if redistFilterPermitDominated14698(ps, proto) {
					delete(protocols, proto)
				}
			}
			if len(protocols) > 0 {
				sorted := make([]string, 0, len(protocols))
				for p := range protocols {
					sorted = append(sorted, p)
				}
				sort.Strings(sorted)
				entries := make([]redistEntry, 0, len(sorted))
				for _, proto := range sorted {
					// #8597: the protocol and route-map are both belted at
					// their output sites below. The map name is derived from
					// the selected source protocol so each daemon receives
					// only the terms it can evaluate.
					entries = append(entries, redistEntry{
						proto: proto, routeMap: redistProtocolRouteMapName(export, proto),
					})
				}
				return entries
			}
			if skipped {
				// Every `from protocol` was filtered above, as self or as
				// another address family. "has no `from protocol`" would send
				// the operator looking for a term that already exists.
				slog.Warn("FRR redistribute export skipped: no `from protocol` in the policy-statement applies under this router",
					"policy", export, "protocol", self)
				return nil
			}
			// Defined policy-statement with no source at this node
			// (no terms at all). Nothing valid to redistribute here.
			// Skip + warn rather than emit the FRR-invalid
			// `redistribute <policy>` line that would degrade the
			// managed-section reload (#2223).
			slog.Warn("FRR redistribute export skipped: policy-statement has no applicable source protocol under this router",
				"policy", export,
				"hint", "redistribute requires a source protocol; add `from protocol <proto>` to the policy or use a bare protocol token")
			return nil
		}
	}

	// #14376: canonicalize a bare protocol token ONCE, before the
	// self/AFI gates and emission. knownRedistProtocol
	// (config.RoutingProtocolResolvable) resolves case-variant and
	// padded spellings — `BGP`, `OSPF6`, ` bgp` — by trimming and
	// lower-casing, so it ADMITS them; but the self check
	// (`export == self`), the AFI check (redistSourceFitsNode, keyed
	// by canonical keywords), and the emitted token below previously
	// compared and rendered the RAW export string, so `export BGP`
	// under `router bgp` bypassed the self-redistribute drop,
	// `export OSPF6` under `router ospf` bypassed the family filter,
	// and the renderer wrote `redistribute BGP` — a token FRR
	// rejects, failing the whole managed reload. FRRRoutingProtocolKeyword
	// also maps Junos `direct` to FRR `connected` (#2144), subsuming
	// the former direct-only special case. This runs only after the
	// #14369 defined-policy lookup above, so a policy named e.g.
	// `direct` or `static` is never rewritten here.
	if kw, ok := config.FRRRoutingProtocolKeyword(export); ok {
		export = kw
	}
	if knownRedistProtocol(export) {
		// A protocol can never redistribute itself: FRR rejects
		// `redistribute ospf` under `router ospf` (etc.), and ONE
		// rejected line degrades the WHOLE managed reload (#1880/#2223).
		// Drop the self-redistribute rather than poison the section
		// (#2943). self is "" for callers with no enclosing protocol.
		if self != "" && export == self {
			slog.Warn("FRR redistribute export skipped: protocol cannot redistribute itself",
				"protocol", self)
			return nil
		}
		// #9510: the source must also be in a family the enclosing router's
		// redistribute grammar lists (redistribute_afi_9510.go).
		if !redistSourceFitsNode(export, node) {
			slog.Warn("FRR redistribute export skipped: source protocol is not in this router's address family",
				"protocol", self, "source", export)
			return nil
		}
		// #8597 (muse-004 K87): sanitized for PARITY, not because this site is
		// reachable with a dirty operand.
		//
		// This branch is gated by knownRedistProtocol above — an ALLOWLIST,
		// which is the stronger belt — so a control byte can never arrive here.
		// Measured: knownRedistProtocol("static\n x") is false. The belt is
		// here so the file has no unbelted `redistribute %s` interpolation for
		// a future audit to have to reason about, and so a future change that
		// widens the allowlist does not silently open the hole.
		//
		// The two-operand site below is the one that WAS reachable.
		return []redistEntry{{proto: export}}
	}

	// Unknown token: neither a known protocol nor a defined policy-statement
	// (a name that slipped past the strict validator on a tolerant load /
	// peer-sync path). Never emit a bare `redistribute <name>` — it has no
	// valid source protocol and would be rejected by frr-reload, degrading
	// the entire managed reload (#2223).
	slog.Warn("FRR redistribute export skipped: not a known protocol or defined policy-statement",
		"export", export,
		"hint", "use a known protocol (connected/static/ospf/bgp/rip/isis/kernel) or a defined policy-statement with a `from protocol`")
	return nil
}

// isDefinedPolicyStatement reports whether name resolves to a defined
// policy-statement in policyOptions. This is the SAME predicate the
// commit-time validator uses (checkRedist/checkPolicyRef in
// pkg/config/compiler_validate_strict.go) to distinguish a route-map-out
// reference from a bare redistribute protocol token. A defined
// policy-statement renders as `route-map <name> out`; anything else (a
// bare protocol token, or a typo that slipped past the strict validator on
// a lenient load/HA-sync path) goes to resolveRedistribute.
func isDefinedPolicyStatement(name string, po *config.PolicyOptionsConfig) bool {
	if po == nil || po.PolicyStatements == nil {
		return false
	}
	_, ok := po.PolicyStatements[name]
	return ok
}

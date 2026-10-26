package frr

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// emittedRouteMapFinalCollision16867 fails the apply CLOSED when two
// DISTINCT route-map identities — from ANY population that emits into
// FRR's single global route-map namespace — render to the same final
// frrName (#16867, Gate5 Astra F1).
//
// frrName's alias (readable fragment truncated to 112 bytes + 4-byte
// hash) ERASES the reserved suffixes that used to separate generated
// families: a composed BGP chain name (`<chain>-xpf-chain`) and a
// per-source redist map name (`<policy>-<proto>-xpf-redist`) whose raw
// forms share the 112-byte fragment and 32-bit hash render as ONE
// identifier, and FRR merges the two filters. The per-family guards
// (bgpComposedChainCollision, redistProtocolMapCollisionFiltered,
// redistVariantMapCollision16864, redistChainMapCollision15156,
// narrowedAliasCollision10129, qualifiedNextHopMetricCollision11447,
// the #16871 reserved registry, the operator-alias guard) each compare
// within one population; none compares ACROSS populations. This belt is
// that missing union (beltRouteMapIdentities16867): every final
// route-map identity the managed section can emit — operator
// policy-statements, composed BGP chains (every BGP in fc +
// instances), composed redist maps, per-source and variant redist
// maps for EXACTLY the emitter's set (redistReferencedProtocols14380:
// explicit tokens plus node-filtered per-referencing-node expansion —
// what generatePolicyOptions defines; Gate6 F1: an unfiltered
// whole-domain enumeration would invent phantom maps the emitter never
// renders and could refuse a non-fusing config), narrowed-chain
// aliases, QNH metric maps, and the fixed generated maps (derived from
// the #16871 registry, each included only when its emitter actually
// emits it; cluster Null0 guard when ClusterMode) — is
// normalized through frrName, and two distinct identities sharing a
// final name are refused. Same identity reached twice (an identity
// enumerated by two passes) is one map and stays clean. Deterministic
// order: families in enumeration order, identities sorted, so refusal
// text is stable.
//
// It does NOT replace or weaken any per-family guard: those keep their
// precise diagnostics and the #16871 registry; this belt only adds the
// cross-family comparison none of them performs. Wired into ApplyFull
// after all per-family belts, before buildManagedSection — so a
// refusal precedes any write or reload and FRR keeps its last-good
// config.
func emittedRouteMapFinalCollision16867(fc *FullConfig) error {
	seen := make(map[string]string) // final name -> "family\x00identity"
	for _, id := range beltRouteMapIdentities16867(fc) {
		final := frrName(id.identity)
		key := id.family + "\x00" + id.identity
		if prev, ok := seen[final]; ok && prev != key {
			pf, pi, _ := strings.Cut(prev, "\x00")
			return fmt.Errorf(
				"route-maps %s %q and %s %q render as the same FRR route-map %q; "+
					"FRR merges same-named route-maps and would fuse two distinct filters (#16867) — refusing to render",
				pf, pi, id.family, id.identity, final)
		}
		if _, ok := seen[final]; !ok {
			seen[final] = key
		}
	}
	return nil
}

// beltRouteMapIdentity16867 is one (family, raw identity) pair the
// cross-family belt compares in final frrName space.
type beltRouteMapIdentity16867 struct {
	family   string
	identity string
}

// beltRouteMapIdentities16867 enumerates every route-map identity the
// managed section can emit, per family, in deterministic order. It is
// the belt's single derivation — shared with the Gate6
// phantom-enumeration pin so no second derivation can drift.
func beltRouteMapIdentities16867(fc *FullConfig) []beltRouteMapIdentity16867 {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	po := fc.PolicyOptions
	var out []beltRouteMapIdentity16867
	add := func(family, identity string) {
		out = append(out, beltRouteMapIdentity16867{family: family, identity: identity})
	}

	// Operator policy-statements (rendered as route-maps by name).
	for _, name := range sortedKeys16867(po.PolicyStatements) {
		add("policy-statement", name)
	}

	// Composed BGP chain maps (fc.BGP + every instance).
	composed := make(map[string][]string)
	collect := func(bgp *config.BGPConfig) {
		if bgp != nil {
			collectBGPComposedChains(bgp, po, composed)
		}
	}
	collect(fc.BGP)
	for i := range fc.Instances {
		collect(fc.Instances[i].BGP)
	}
	composedNames := make([]string, 0, len(composed))
	for name := range composed {
		composedNames = append(composedNames, name)
	}
	sort.Strings(composedNames)
	for _, name := range composedNames {
		add("composed BGP chain", name)
	}

	// Composed redist maps (keys are the exact attached names).
	for _, name := range mapKeysReq15156(redistComposedChains15156(fc)) {
		add("composed redistribute", name)
	}

	// Per-source + variant redist maps for exactly the emitter's set
	// (see header; Gate6 F1 — no unfiltered whole-domain pass).
	nodesByPolicy := redistReferencedNodes14380(fc)
	addPerSource := func(policy string, protos []string, ctxs []redistVariantContext16864) {
		for _, proto := range protos {
			add("redistribute", redistProtocolRouteMapName(policy, proto))
			for _, ctx := range ctxs {
				if !redistProtoFitsVariant16864(proto, ctx) {
					continue
				}
				add("redistribute variant", redistVariantRouteMapName16864(policy, proto, ctx))
			}
		}
	}
	for _, policy := range sortedKeysPS15156(po) {
		ps := po.PolicyStatements[policy]
		nodes := nodesByPolicy[policy]
		addPerSource(policy, redistReferencedProtocols14380(ps, nodes), redistVariantsForNodes16864(nodes))
	}

	// Narrowed-chain aliases (only sites that actually alias).
	var sites []narrowedChainSite
	addSites := func(bgp *config.BGPConfig) { sites = append(sites, narrowedChainSites(bgp, po)...) }
	addSites(fc.BGP)
	for i := range fc.Instances {
		addSites(fc.Instances[i].BGP)
	}
	for _, site := range sites {
		if !narrowedAliasEligible10821(site, po) {
			continue
		}
		add("narrowed chain alias", narrowedAliasName10129(site.Kept))
	}

	// QNH metric maps (static + per-policy variants), when a metric set exists.
	if set := buildQNHMetricSet11447(fc, po); set != nil {
		referencedNodes := redistReferencedNodes14380(fc)
		var qnhNames []string
		for _, scope := range set.scopes() {
			qnhNames = append(qnhNames, scope.staticMap)
			for policy, base := range scope.policyMaps {
				for _, ctx := range qnhMetricPolicyVariants11447(referencedNodes[policy]) {
					qnhNames = append(qnhNames, qnhMetricPolicyVariantRouteMap11447(base, ctx))
				}
			}
		}
		sort.Strings(qnhNames)
		for _, name := range qnhNames {
			if name == "" {
				continue
			}
			add("QNH metric", name)
		}
	}

	// Fixed generated maps, derived from the config-owned #16871
	// registry (reservedGeneratedRouteMaps16871) so a future generated
	// name registered there joins this union structurally instead of
	// drifting. Their names are short (alias-stable). The registry
	// itself is untouched. Cluster Null0 is not in that registry (it
	// ends in the redist suffix and is guarded separately), so it stays
	// an explicit addition under ClusterMode.
	// Fixed generated maps fire ONLY when their emitter would
	// actually emit them (Gate7 Astra F1): the emptied-chain deny and
	// default-export definitions are conditional (unused chain ⇒ no
	// definition rendered), so adding them unconditionally made the
	// belt refuse a tolerant-path operator policy that merely SHARES
	// the reserved name while the generated map does not exist — a
	// phantom refusal of a non-fusing config. The predicates are the
	// emitters' own (bgpUsesEmptiedChainDeny /
	// bgpUsesDefaultExport15157, the same ones their dedicated
	// collision guards use), evaluated over fc.BGP + every instance,
	// exactly as renderEmptiedChainDeny / renderBGPDefaultExport15157
	// do. Cluster Null0's emitter is the cluster-mode render itself,
	// so ClusterMode remains its emission condition.
	usedFixed := func(uses func(*config.BGPConfig, *config.PolicyOptionsConfig) bool) bool {
		if uses(fc.BGP, po) {
			return true
		}
		for i := range fc.Instances {
			if uses(fc.Instances[i].BGP, po) {
				return true
			}
		}
		return false
	}
	for _, reserved := range reservedGeneratedRouteMaps16871 {
		switch reserved.name {
		case emptiedChainDenyName:
			if usedFixed(bgpUsesEmptiedChainDeny) {
				add("generated "+reserved.kind, reserved.name)
			}
		case bgpDefaultExportName15157:
			if usedFixed(bgpUsesDefaultExport15157) {
				add("generated "+reserved.kind, reserved.name)
			}
		default:
			// A future registry member whose emitter is unconditional
			// (or not yet classified here): included — failing closed
			// on a registered generated name is the registry's contract.
			add("generated "+reserved.kind, reserved.name)
		}
	}
	if fc.ClusterMode {
		add("generated cluster Null0 guard", clusterNull0DenyRouteMap15158)
	}
	return out
}

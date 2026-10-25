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
// that missing union: it collects every final route-map identity the
// managed section can emit — operator policy-statements, composed BGP
// chains (every BGP in fc + instances), composed redist maps,
// per-source and variant redist maps for every referenced node, plus
// every protocol in the unreferenced-node fallback (the same superset
// redistProtocolMapCollision uses), narrowed-chain aliases, QNH metric
// maps, and the fixed generated maps (default-export, emptied-chain
// deny, cluster Null0 guard when ClusterMode) — normalizes each through
// frrName, and refuses when two distinct identities share a final name.
// Same identity reached twice (e.g. an unreferenced policy enumerated
// under both the referenced-node and fallback passes) is one map and
// stays clean. Deterministic order: families in the order above,
// identities sorted, so refusal text is stable.
//
// It does NOT replace or weaken any per-family guard: those keep their
// precise diagnostics and the #16871 registry; this belt only adds the
// cross-family comparison none of them performs. Wired into ApplyFull
// after all per-family belts, before buildManagedSection — so a refusal
// precedes any write or reload and FRR keeps its last-good config.
func emittedRouteMapFinalCollision16867(fc *FullConfig) error {
	if fc == nil || fc.PolicyOptions == nil {
		return nil
	}
	po := fc.PolicyOptions
	seen := make(map[string]string) // final name -> identity
	add := func(family, identity string) error {
		final := frrName(identity)
		key := family + "\x00" + identity
		if prev, ok := seen[final]; ok && prev != key {
			pf, pi, _ := strings.Cut(prev, "\x00")
			return fmt.Errorf(
				"route-map %q (%s %q) and %q (%s %q) render as the same FRR route-map %q; "+
					"FRR merges same-named route-maps and would fuse two distinct filters (#16867) — refusing to render",
				pi, pf, pi, identity, family, identity, final)
		}
		if _, ok := seen[final]; !ok {
			seen[final] = key
		}
		return nil
	}

	// Operator policy-statements (rendered as route-maps by name).
	for _, name := range sortedKeys16867(po.PolicyStatements) {
		if err := add("policy-statement", name); err != nil {
			return err
		}
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
		if err := add("composed BGP chain", name); err != nil {
			return err
		}
	}

	// Composed redist maps (keys are the exact attached names).
	for _, name := range mapKeysReq15156(redistComposedChains15156(fc)) {
		if err := add("composed redistribute", name); err != nil {
			return err
		}
	}

	// Per-source + variant redist maps: referenced-node pass (the
	// candidates the node-aware guards use), then the unreferenced-node
	// fallback over the whole protocol domain (the superset
	// redistProtocolMapCollision enumerates for unreferenced policies).
	nodesByPolicy := redistReferencedNodes14380(fc)
	addPerSource := func(policy string, protos []string, ctxs []redistVariantContext16864) error {
		for _, proto := range protos {
			if err := add("redistribute", redistProtocolRouteMapName(policy, proto)); err != nil {
				return err
			}
			for _, ctx := range ctxs {
				if !redistProtoFitsVariant16864(proto, ctx) {
					continue
				}
				if err := add("redistribute variant", redistVariantRouteMapName16864(policy, proto, ctx)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, policy := range sortedKeysPS15156(po) {
		ps := po.PolicyStatements[policy]
		nodes := nodesByPolicy[policy]
		if err := addPerSource(policy, redistReferencedProtocols14380(ps, nodes), redistVariantsForNodes16864(nodes)); err != nil {
			return err
		}
		if err := addPerSource(policy, redistProtocolsForNode(ps, "", ""), nil); err != nil {
			return err
		}
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
		if err := add("narrowed chain alias", narrowedAliasName10129(site.Kept)); err != nil {
			return err
		}
	}

	// QNH metric maps (static + per-policy), when a metric set exists.
	if set := buildQNHMetricSet11447(fc, po); set != nil {
		var qnhNames []string
		for _, scope := range set.scopes() {
			qnhNames = append(qnhNames, scope.staticMap)
			qnhNames = append(qnhNames, mapValues11447(scope.policyMaps)...)
		}
		sort.Strings(qnhNames)
		for _, name := range qnhNames {
			if name == "" {
				continue
			}
			if err := add("QNH metric", name); err != nil {
				return err
			}
		}
	}

	// Fixed generated maps. Their names are short (alias-stable), so
	// these only fuse with an operator/generated name of the exact —
	// or aliased-to-exact — spelling; included so the union is complete
	// over every route-map definition the section can emit. The #16871
	// registry itself is untouched (bgpComposedChainCollision above).
	for _, fixed := range []struct{ family, name string }{
		{"generated default-export", bgpDefaultExportName15157},
		{"generated emptied-chain deny", emptiedChainDenyName},
	} {
		if err := add(fixed.family, fixed.name); err != nil {
			return err
		}
	}
	if fc.ClusterMode {
		if err := add("generated cluster Null0 guard", clusterNull0DenyRouteMap15158); err != nil {
			return err
		}
	}
	return nil
}

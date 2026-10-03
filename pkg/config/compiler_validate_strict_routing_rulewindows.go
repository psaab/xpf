package config

import (
	"fmt"
	"strings"
)

// maxNextTableRules and maxRibGroupLeakRules mirror the admission caps in
// pkg/routing/rules.go. Both rule kinds use the same destination-leak priority
// range, whose priorities are assigned by descending prefix length; these
// limits instead bound how many rules each manager installs:
//
//   - next-table: NextTableRuleWindow entries. Each leak costs one rule per
//     default-instance ingress interface (#9420), so the eligible route count
//     is floor(window/N), with N from the shared resolver (#9810).
//   - rib-group:  maxRibGroupLeakRules connected-prefix rules per family.
//
// The shared [NextTableRulePriorityBase, +RouteLeakRulePriorityWindow) range
// is wide enough for IPv6 prefixes and is independent of either admission cap.
//
// pkg/config CANNOT import pkg/routing — pkg/routing already imports pkg/config,
// so the reverse edge would be an import cycle. maxRibGroupLeakRules is
// therefore duplicated here and MUST stay in lockstep with pkg/routing/rules.go:
// if that cap changes there, change it here too or the commit-time gate and
// runtime applier disagree on what fits.
const (
	maxNextTableRules    = NextTableRuleWindow
	maxRibGroupLeakRules = 1000
)

// nextTableRouteCount counts the static routes (global inet + inet6) that carry
// a next-table VRF-leak target. Since #9420 the applier
// (pkg/routing.nextTableManager) feeds each of these into its admission cap
// once per default-instance ingress interface — one RULE per (leak, interface),
// drawn down leak-atomically — so the cap cost of a config is this count
// times len(DefaultInstanceIngressIfaces(cfg)) (#9810 SYN-WIN-01).

// The count stays CONSERVATIVE: it includes leaks the applier would skip
// (unknown target, unparseable CIDR). That is safe on the strict path because
// #5693 rejects undefined targets ahead of this gate and ValidateRouteDestination
// (#2448, via the #1319 schema gate, strict-before-compile on the store commit
// and peer-pipeline paths for every static block) rejects unparseable
// destinations ahead of it — so every counted leak is eligible; on the lenient
// path an over-count only over-warns, the fail-safe direction.
// Routes explicitly marked `no-install` are not counted because the applier
// skips them.
func nextTableRouteCount(cfg *Config) int {
	if cfg == nil {
		return 0
	}
	n := 0
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr != nil && !sr.NoInstall && sr.NextTable != "" {
			n++
		}
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		if sr != nil && !sr.NoInstall && sr.NextTable != "" {
			n++
		}
	}
	return n
}

// ribGroupImportsMain mirrors pkg/routing.ribGroupLeaksIntoMain and
// resolveRibTable: only an import that resolves to the selected main RIB
// family installs a Phase-1 leak. mainRIBName is "inet.0" for the IPv4 slot
// or "inet6.0" for the IPv6 slot. This resolver is duplicated to avoid an
// import cycle, so keep its table-ID and exact-suffix matching in sync. A
// sibling-family main RIB must not enable this slot; named-instance ribs still
// resolve to their shared Linux table ID as in the applier.
func ribGroupImportsMain(groupName string, groups map[string]*RibGroup, tableIDs map[string]int, mainRIBName string) bool {
	if groupName == "" {
		return false
	}
	group, ok := groups[groupName]
	if !ok || group == nil {
		return false
	}
	for _, ribName := range group.ImportRibs {
		if ribName == mainRIBName {
			return true
		}
		instance, ok := ribInstanceFromName(ribName)
		if !ok {
			continue
		}
		if tableID, ok := tableIDs[instance]; ok && tableID == mainRIBTableID {
			return true
		}
	}
	return false
}

// ribGroupLeakPrefixCount mirrors the forward leak set in
// ribGroupManager.Apply. RibGroupConnectedPrefixes returns a sorted, unique
// prefix set per leaking instance; counts are family-scoped to the
// corresponding import-rib and once per source table (the runtime's
// leakedTables guard).
func ribGroupLeakPrefixCount(cfg *Config) (inet, inet6 int) {
	if cfg == nil {
		return 0, 0
	}
	ribGroups := cfg.RoutingOptions.RibGroups
	tableIDs := make(map[string]int, len(cfg.RoutingInstances))
	for _, instance := range cfg.RoutingInstances {
		if instance != nil {
			tableIDs[instance.Name] = instance.TableID
		}
	}
	connected := RibGroupConnectedPrefixes(cfg)
	leakedTables := make(map[int]bool)
	for _, instance := range cfg.RoutingInstances {
		if instance == nil {
			continue
		}
		leakV4 := ribGroupImportsMain(instance.InterfaceRoutesRibGroup, ribGroups, tableIDs, "inet.0")
		leakV6 := ribGroupImportsMain(instance.InterfaceRoutesRibGroupV6, ribGroups, tableIDs, "inet6.0")
		if !leakV4 && !leakV6 {
			continue
		}
		if leakedTables[instance.TableID] {
			continue
		}
		leakedTables[instance.TableID] = true
		for _, prefix := range connected[instance.Name] {
			if strings.Contains(prefix, ":") {
				if leakV6 {
					inet6++
				}
			} else if leakV4 {
				inet++
			}
		}
	}
	return inet, inet6
}

// validateRoutingRuleWindowsStrict hard-rejects a config that would exceed the
// next-table or interface-routes rib-group admission caps (#5854).
//
// The applier admits up to 100 next-table rules, one per default-instance
// ingress interface per leak (#9810), and 1000 rib-group connected-prefix
// rules per address family (pkg/routing/rules.go). Priorities for both kinds
// are assigned independently from the shared prefix-derived range. A route
// beyond an admission cap is never installed. A config exceeding a cap used
// to commit green while the reconciler silently stopped at its cap and
// returned success: the committed generation CLAIMED routes the kernel never
// programs.
// The result is a blackhole / asymmetric routing / silent inter-VRF leak loss
// with no operator-visible signal, because truncation was previously only a
// WARNING (ValidateConfig, the pre-#5854 warn-only path).
//
// This gate makes over-subscription an operator-visible COMMIT ERROR on the
// strict path (CompileConfig — interactive / gRPC commit + commit-check). The
// call site (runUniformGates) downgrades it to a WARNING on tolerant load /
// peer-sync paths (opts.lenientRoutingRuleWindows) so an ALREADY-committed or
// peer-synced generation that predates this rejection still boots (#1960
// fail-closed-on-load class); the applier's admission caps keep excess rules
// inert. Next-table is reported before rib-group; an overflowing IPv4 family
// is reported before IPv6 so the first-reported cap error is deterministic.
//
// The cap sizes come from maxNextTableRules / maxRibGroupLeakRules, which are
// kept in lockstep with pkg/routing/rules.go (pkg/config cannot import
// pkg/routing — see the const block above).
func validateRoutingRuleWindowsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if n := nextTableRouteCount(cfg); n > 0 {
		// #9810 SYN-WIN-01: each leak costs one ip-rule entry per default-instance
		// ingress interface (per-ingress rules since #9420), drawn down
		// leak-atomically: what fits is floor(cap/N) LEAKS, with N from the
		// shared resolver the applier consumes.
		ingress := len(DefaultInstanceIngressIfaces(cfg))
		if ingress == 0 {
			// The applier installs nothing without an ingress interface (#9420
			// fail-closed), so no leak fits; fail fast here instead of committing
			// green and erroring at apply time. This arm also fires before the
			// #5633 disposition gate for interface-less configs (accepted: the
			// operator fixes ingress first, then the disposition — two commit
			// cycles; do NOT reorder the gates to "fix" the attribution).
			return fmt.Errorf(
				"routing-options: %d static routes use next-table, but only 0 can be "+
					"programmed as kernel ip rules with 0 default-instance ingress "+
					"interfaces (each leak costs one rule per ingress interface and no "+
					"interface resolves to scope to — the applier installs nothing "+
					"without ingress scope).",
				n)
		}
		if capacity := maxNextTableRules / ingress; n > capacity {
			return fmt.Errorf(
				"routing-options: %d static routes use next-table, but only %d can be "+
					"programmed as kernel ip rules with %d default-instance ingress "+
					"interfaces (each leak costs one rule per ingress interface: %d "+
					"entries of the %d-rule admission cap); routes beyond the limit "+
					"would be dropped at apply time (the committed routes are not "+
					"programmed — blackhole / asymmetric routing). Reduce the number of "+
					"next-table routes to at most %d.",
				n, capacity, ingress, n*ingress, maxNextTableRules, capacity)
		}
	}
	inetCount, inet6Count := ribGroupLeakPrefixCount(cfg)
	for _, family := range []struct {
		name  string
		count int
	}{
		{name: "inet", count: inetCount},
		{name: "inet6", count: inet6Count},
	} {
		if family.count > maxRibGroupLeakRules {
			return fmt.Errorf(
				"routing-options: interface-routes rib-group would leak %d connected prefixes "+
					"in family %s as kernel ip rules, but only %d per family can be programmed; "+
					"prefixes beyond the limit would be dropped at apply time. Reduce the %s "+
					"rib-group-leaked interface prefixes to at most %d.",
				family.count, family.name, maxRibGroupLeakRules, family.name, maxRibGroupLeakRules)
		}
	}
	return nil
}

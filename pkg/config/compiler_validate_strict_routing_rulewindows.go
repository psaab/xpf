package config

import "fmt"

// maxNextTableRules and maxRibGroupLeakRules mirror the FIXED ip-rule priority
// windows the runtime applier (pkg/routing/rules.go) programs next-table and
// interface-routes rib-group leaks into. The applier HARD-CAPS at each window
// boundary and skips any rule past it, so a config that exceeds a window has
// the excess routes silently dropped at apply time (#5854):
//
//   - next-table: [NextTableRulePriorityBase, +NextTableRuleWindow) — a
//     100-rule window that clear() scans (pkg/routing/rules.go, the
//     `prio >= nextTableRulePriority+maxNextTableRules` cap). maxNextTableRules
//     derives from the exported NextTableRuleWindow SSOT (types_system.go) so
//     the commit gate here, the runtime applier, AND the userspace FIB mirror
//     (pkg/dataplane/userspace/routes.go) share one window value (#6467) —
//     no lockstep drift possible. Since #9420 each leak costs one slot per
//     default-instance ingress interface (#9810), so the LEAK capacity is
//     floor(window/N), not window leaks.
//   - rib-group:  [ribGroupLeakRulePriority, +maxRibGroupLeakRules) — a
//     1000-rule window (pkg/routing/rules.go const maxRibGroupLeakRules = 1000,
//     the `prio >= ribGroupLeakRulePriority+maxRibGroupLeakRules` cap). This
//     window is NOT shared with the userspace FIB, so it stays duplicated here
//     and MUST stay in lockstep with pkg/routing/rules.go.
//
// pkg/config CANNOT import pkg/routing — pkg/routing already imports pkg/config,
// so the reverse edge would be an import cycle. maxRibGroupLeakRules is
// therefore duplicated here and MUST stay in lockstep with pkg/routing/rules.go:
// if that window size changes there, change it here too or the commit-time gate
// and the runtime applier disagree on what fits.
const (
	maxNextTableRules    = NextTableRuleWindow
	maxRibGroupLeakRules = 1000
)

// nextTableRouteCount counts the static routes (global inet + inet6) that carry
// a next-table VRF-leak target. Since #9420 the applier
// (pkg/routing.nextTableManager) feeds each of these into its ip-rule window
// once per default-instance ingress interface — one RULE per (leak, interface),
// drawn down leak-atomically — so the window cost of a config is this count
// times len(DefaultInstanceIngressIfaces(cfg)) (#9810 SYN-WIN-01).

// The count stays CONSERVATIVE: it includes leaks the applier would skip
// (unknown target, unparseable CIDR). That is safe on the strict path because
// #5693 rejects undefined targets and unparseable destinations cannot commit
// there, so every counted leak is eligible; on the lenient path an over-count
// only over-warns, the fail-safe direction.
func nextTableRouteCount(cfg *Config) int {
	if cfg == nil {
		return 0
	}
	n := 0
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			n++
		}
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			n++
		}
	}
	return n
}

// ribGroupLeakPrefixCount counts the connected prefixes an interface-routes
// rib-group would leak as ip rules (#3876 per-prefix leak), one rule per
// prefix. It is a CONSERVATIVE upper bound computed from the same inputs the
// applier consumes (RibGroupConnectedPrefixes) — it does not replicate the
// applier's exact skip/dedup logic, so it may count slightly high but never
// misses a real over-subscription.
func ribGroupLeakPrefixCount(cfg *Config) int {
	n := 0
	for _, prefixes := range RibGroupConnectedPrefixes(cfg) {
		n += len(prefixes)
	}
	return n
}

// validateRoutingRuleWindowsStrict hard-rejects a config that would program
// more next-table or interface-routes rib-group ip rules than the runtime's
// FIXED priority windows can hold (#5854).
//
// The applier programs next-table leaks into a 100-rule window at one slot per
// default-instance ingress interface per leak (#9810), and rib-group
// connected-prefix leaks into a 1000-rule window (pkg/routing/rules.go), and
// HARD-CAPS at each boundary — a route beyond the window is never installed. So
// a config that exceeds a window commits green but the reconciler silently
// stops at the limit and returns success: the committed generation CLAIMS
// routes the kernel never programs. The result is a blackhole / asymmetric
// routing / silent inter-VRF leak loss with no operator-visible signal, because
// the truncation was previously only a WARNING (ValidateConfig, the pre-#5854
// warn-only path).
//
// This gate makes the over-subscription an operator-visible COMMIT ERROR on the
// strict path (CompileConfig — interactive / gRPC commit + commit-check). The
// call site (runUniformGates) downgrades it to a WARNING on the tolerant
// load / peer-sync paths (opts.lenientRoutingRuleWindows) so an ALREADY-
// committed or peer-synced generation that predates this rejection still boots
// (#1960 fail-closed-on-load class) — the applier's window hard-cap keeps the
// excess inert, exactly matching the post-fix runtime behaviour. Next-table is
// reported before rib-group so the first-reported error is deterministic.
//
// The window sizes come from maxNextTableRules / maxRibGroupLeakRules, which are
// kept in lockstep with pkg/routing/rules.go (pkg/config cannot import
// pkg/routing — see the const block above).
func validateRoutingRuleWindowsStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if n := nextTableRouteCount(cfg); n > 0 {
		// #9810 SYN-WIN-01: each leak costs one ip-rule slot per default-instance
		// ingress interface (per-ingress rules since #9420), drawn down
		// leak-atomically: what fits is floor(window/N) LEAKS, with N from the
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
					"slots of the %d-rule window); routes beyond the limit would be "+
					"dropped at apply time (the committed routes are not "+
					"programmed — blackhole / asymmetric routing). Reduce the number of "+
					"next-table routes to at most %d.",
				n, capacity, ingress, n*ingress, maxNextTableRules, capacity)
		}
	}
	if n := ribGroupLeakPrefixCount(cfg); n > maxRibGroupLeakRules {
		return fmt.Errorf(
			"routing-options: interface-routes rib-group would leak %d connected "+
				"prefixes as kernel ip rules, but only %d can be programmed; prefixes "+
				"beyond the limit would be silently dropped at apply time (the leak "+
				"rules are claimed but not programmed). Reduce the number of "+
				"rib-group-leaked interface prefixes to at most %d.",
			n, maxRibGroupLeakRules, maxRibGroupLeakRules)
	}
	return nil
}

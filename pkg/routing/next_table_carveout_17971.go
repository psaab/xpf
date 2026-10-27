package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// #17971: dynamic main-table carve-outs for next-table leaks.
//
// The static carve-out mechanism from #17684 only mints slot-0 main lookups
// for CONFIGURED static routes the FRR render admits. Every other main-table
// route the kernel actually holds — BGP/OSPF/RIP/ISIS learned routes, DHCP
// and zebra staticd installs, operator `ip route` entries, and kernel
// blackhole/unreachable negatives — had no exception, so the kernel's
// lookup-first RPDB sent the destination to the leak target while the Rust
// FIB's merged-walk LPM (junos_next_table_winner's SourceTable arm) selected
// the more-specific main route. The kernel and the helper dataplane then
// disagreed about the SAME destination — the divergence #17971 exists to
// close, reproduced v4+v6.
//
// The mechanism is the issue's candidate 1: enumerate the exception rules
// from the live main-table dump. The dump reuses ImportLearnedRoutes over
// the main table — the same classifier the helper FIB's learned-route
// import applies to main — so both planes derive from one adoption
// predicate (protocol allowlist, gateway requirement, dead-leg rejection,
// terminal-type admission) instead of two that could drift. The sets are
// not identical by construction: the FIB additionally suppresses a learned
// row a config route already covers, while a carve-out can only help when
// the row would otherwise win. Connected (gateway-less) main routes are
// excluded: the importer rejects them, and their parity needs the
// RG-ownership-aware connected set from the snapshot layer (#15742
// peer-owned filtering) rather than the raw kernel table — tracked
// separately.
//
// Maintenance on churn: Apply reconciles the carve-out band on every commit,
// and the daemon route listener (#7437) re-runs RefreshCarveouts on its
// coalesced actuation, so a learned route appearing or withdrawing between
// commits converges the band without reinstalling the leak rules themselves.
// Between the kernel route change and that coalesced refresh, a withdrawn
// dynamic route keeps a transient exception whose suppression boundary
// fails exactly like the #17684 static-withdrawal window: broader ordinary
// main answers suppress the rule (the leak resumes) and terminal main
// answers abort RPDB evaluation (fail-closed drop, never a leak rescue).

// importMainLearnedRoutes is the production live main-table dump backing the
// dynamic carve-out leg. It deliberately reuses ImportLearnedRoutes so the
// kernel rule derivation and the helper FIB snapshot consume one classifier;
// a second adoption predicate here could disagree with the FIB and re-create
// the divergence this mechanism exists to remove.
func importMainLearnedRoutes() ([]LearnedRoute, error) {
	return ImportLearnedRoutes([]int{mainTableID})
}

// nextTableDynamicCarveoutRules derives slot-0 main lookups for live
// learned main-table routes strictly more specific than an admitted
// next-table leak prefix. Rows come from ImportLearnedRoutes, so every row
// is already an ordinary main row in the helper FIB: gateway-bearing unicast
// under an adopted protocol, or a blackhole/unreachable terminal.
func nextTableDynamicCarveoutRules(
	learned []LearnedRoute,
	admittedLeakRoutes []*config.StaticRoute,
	ingressIfaces []string,
) []*netlink.Rule {
	leakPrefixes := nextTableAdmittedLeakPrefixes(admittedLeakRoutes)
	var rules []*netlink.Rule
	seen := make(map[nextTableCarveoutKey]struct{})
	for i := range learned {
		route := &learned[i]
		if route.TableID != mainTableID {
			continue
		}
		// The importer normalises a nil-Dst default to 0.0.0.0/0 or ::/0;
		// a default is never strictly more specific than a leak, but keep
		// the parse failure skip local so a malformed row cannot mint a
		// bogus destination selector.
		_, dst, err := net.ParseCIDR(route.Destination)
		if err != nil {
			continue
		}
		family := unix.AF_INET
		if dst.IP.To4() == nil {
			family = unix.AF_INET6
		}
		if family != route.Family {
			continue
		}
		// Terminal negatives carry no next-hops by construction; a unicast
		// row the importer adopted always has at least one live gateway
		// leg. Requiring one here keeps a future classifier change from
		// silently minting an exception for a next-hop-less row.
		if !route.Discard && !route.Reject && len(route.NextHops) == 0 {
			continue
		}
		if !nextTableCarveoutMatchesLeak(dst, family, leakPrefixes) {
			continue
		}
		rules = mintNextTableCarveout(rules, seen, dst, family, ingressIfaces)
	}
	return rules
}

// desiredMainCarveoutRules computes the complete desired slot-0 exception
// set: configured statics (as in #17684) plus the live learned rows. The
// dump runs FIRST — before any kernel mutation — so a failed dump leaves the
// installed band untouched instead of replacing it with a statics-only
// subset (a silent partial state would re-create the #17971 divergence).
func (n *nextTableManager) desiredMainCarveoutRules(
	routes, admittedLeakRoutes []*config.StaticRoute,
	definedInstances map[string]struct{},
	ingressIfaces []string,
) ([]*netlink.Rule, error) {
	desired := nextTableMainCarveoutRules(routes, admittedLeakRoutes, definedInstances, ingressIfaces)
	seen := make(map[nextTableCarveoutKey]struct{}, len(desired))
	for _, rule := range desired {
		seen[nextTableCarveoutKey{family: rule.Family, prefix: rule.Dst.String(), ifname: rule.IifName}] = struct{}{}
	}
	if n.mainRoutes == nil {
		return desired, nil
	}
	learned, err := n.mainRoutes()
	if err != nil {
		return nil, fmt.Errorf(
			"next-table dynamic main-table carve-out: live main-table dump failed: %w", err)
	}
	// Deterministic add order (priority, then prefix, then iif) so the
	// installed band and the audit log are stable across churn refreshes.
	dynamic := nextTableDynamicCarveoutRules(learned, admittedLeakRoutes, ingressIfaces)
	sort.SliceStable(dynamic, func(i, j int) bool {
		if dynamic[i].Priority != dynamic[j].Priority {
			return dynamic[i].Priority < dynamic[j].Priority
		}
		if dynamic[i].Dst.String() != dynamic[j].Dst.String() {
			return dynamic[i].Dst.String() < dynamic[j].Dst.String()
		}
		return dynamic[i].IifName < dynamic[j].IifName
	})
	for _, rule := range dynamic {
		key := nextTableCarveoutKey{family: rule.Family, prefix: rule.Dst.String(), ifname: rule.IifName}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		desired = append(desired, rule)
	}
	return desired, nil
}

// reconcileMainCarveouts converges the kernel's slot-0 main-table exception
// band to the desired set: every carve-out-shaped rule in the shared
// next-table window is removed and the desired rules are re-added, without
// touching the target lookups or unreachable shadows. It is the single
// installation path shared by Apply (commit) and RefreshCarveouts (route
// churn), so the static and dynamic legs can never diverge into two owners.
func (n *nextTableManager) reconcileMainCarveouts(
	routes, admittedLeakRoutes []*config.StaticRoute,
	definedInstances map[string]struct{},
	ingressIfaces []string,
) error {
	desired, err := n.desiredMainCarveoutRules(routes, admittedLeakRoutes, definedInstances, ingressIfaces)
	if err != nil {
		return err
	}
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := n.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"list next-table main-table carve-out rules family %d: %w", family, err))
			continue
		}
		for _, r := range rules {
			if !isNextTableMainCarveoutShape(r) {
				continue
			}
			// RuleList does not decode the fib-rule action; carve-outs are
			// installed under RTN_UNICAST, so delete under that action
			// first and accept ENOENT as already-converged.
			candidate := r
			candidate.Type = unix.RTN_UNICAST
			if delErr := n.ops.RuleDel(&candidate); delErr != nil && !isRuleAlreadyGone(delErr) {
				slog.Warn("failed to delete stale next-table main-table carve-out",
					"priority", r.Priority, "destination", r.Dst, "err", delErr)
				errs = append(errs, fmt.Errorf(
					"delete stale next-table main-table carve-out destination %s iif %s: %w",
					r.Dst, r.IifName, delErr))
			}
		}
	}
	var added []*netlink.Rule
	for _, rule := range desired {
		if err := n.ops.RuleAdd(rule); err != nil {
			if !isRuleAlreadyPresent(err) {
				errs = append(errs, fmt.Errorf(
					"add next-table main-table carve-out destination %s iif %s: %w",
					rule.Dst, rule.IifName, err))
			}
		} else {
			added = append(added, rule)
		}
	}
	if len(errs) != 0 {
		for _, rule := range added {
			if err := n.ops.RuleDel(rule); err != nil && !isRuleAlreadyGone(err) {
				errs = append(errs, fmt.Errorf(
					"roll back next-table main-table carve-out destination %s iif %s: %w",
					rule.Dst, rule.IifName, err))
			}
		}
	}
	return errors.Join(errs...)
}

// RefreshCarveouts re-derives and reconciles only the main-table exception
// band from the current config plus the live main-table dump. The leak
// lookups and shadows are left installed; admission is recomputed with
// nextTableAdmittedRoutes, the same deterministic mirror of Apply's window
// the static derivation uses, so a churn refresh and a commit derive the
// same exception set.
func (n *nextTableManager) RefreshCarveouts(
	routes []*config.StaticRoute,
	instances []*config.RoutingInstanceConfig,
	ingressIfaces []string,
) error {
	tableIDs := make(map[string]int, len(instances))
	for _, inst := range instances {
		if inst == nil {
			continue
		}
		tableIDs[inst.Name] = inst.TableID
	}
	definedInstances := make(map[string]struct{}, len(tableIDs))
	for name := range tableIDs {
		definedInstances[name] = struct{}{}
	}
	admitted := nextTableAdmittedRoutes(
		nextTableFamilyOrdered(routes), tableIDs, len(ingressIfaces))
	return n.reconcileMainCarveouts(routes, admitted, definedInstances, ingressIfaces)
}

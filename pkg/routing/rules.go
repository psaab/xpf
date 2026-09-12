package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ruleOps is the narrow netlink policy-routing surface the three rule
// reconcilers (next-table, rib-group, PBR) use. Satisfied by
// *netlink.Handle in production; tests substitute a fake. This is the
// interface that makes the rule domains unit-testable without netlink.
type ruleOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RuleList(family int) ([]netlink.Rule, error)
	// RuleAddDSCP installs a rule carrying a DSCP selector. It is separate from
	// RuleAdd because netlink's Rule cannot represent one: it has only the
	// legacy `Tos` byte, which the kernel masks to IPTOS_TOS_MASK and which
	// therefore rejects every DSCP >= 8 (#7796). See rule_dscp_linux.go.
	RuleAddDSCP(rule *netlink.Rule, dscp uint8) error
}

// nextTableRulePriority is the base priority for next-table ip rules.
// Lower values = higher priority. We use the 100-199 range for next-table
// rules. The base + window are the SSOT in pkg/config (NextTableRulePriorityBase
// / NextTableRuleWindow) so the install cap here, the commit-time gate
// (pkg/config maxNextTableRules), and the userspace FIB mirror
// (pkg/dataplane/userspace/routes.go) all cap at the same boundary (#6467).
const nextTableRulePriority = config.NextTableRulePriorityBase

// maxNextTableRules bounds the number of next-table inter-VRF leak ip rules the
// applier installs, matching the nextTableRulePriority window clear() scans
// ([nextTableRulePriority, nextTableRulePriority+maxNextTableRules)). A larger
// next-table set is truncated and reported as a degraded apply (mirroring
// maxPBRRules / maxRibGroupLeakRules) rather than silently dropping later leaks
// with a bare Warn (#6467). The userspace FIB config-static mirror caps at the
// SAME value (config.NextTableRuleWindow) so the kernel ip-rule table and the
// userspace dataplane FIB agree on which leaks survive truncation.
const maxNextTableRules = config.NextTableRuleWindow

// ribGroupRulePriority is the LEGACY base priority for the pre-#3876
// rib-group `from all lookup <sourceTable>` blanket rules. It sat AFTER the
// main table (32766), so any main-table default route was matched first and
// the rule was never consulted — the rib-group import leak was a silent
// no-op in every deployment carrying a default route (#3876). It is retained
// ONLY so clear() removes any stale rule an in-place upgrade left behind; no
// new rule is programmed in this window.
const ribGroupRulePriority = 33000

// ribGroupLeakRulePriority is the base priority for the #3876 rib-group
// per-prefix import leak rules: `ip rule to <connected-prefix> lookup
// <sourceTable>`. It sits BEFORE the main table (32766) and before PBR
// (31000-31999) so a specific imported connected prefix wins over a
// main-table default route — the fix for the #3876 shadow-by-default no-op.
// We use the 30000-30999 range (maxRibGroupLeakRules priorities).
const ribGroupLeakRulePriority = 30000

// maxRibGroupLeakRules bounds the number of per-prefix rib-group leak ip
// rules the applier installs, matching the ribGroupLeakRulePriority window
// clear() scans ([ribGroupLeakRulePriority, ribGroupLeakRulePriority+1000)).
// A larger connected-prefix set is truncated and reported as a degraded
// apply (mirroring maxPBRRules) rather than programming a rule the clear()
// pass could not later remove. ValidateConfig emits a commit-time warning
// before this cap is reached.
const maxRibGroupLeakRules = 1000

// mainTableID is the Linux main routing table (RT_TABLE_MAIN). The #3876
// Phase-1 leak targets ONLY main: an interface-routes rib-group whose
// import-rib list resolves to this table has its source instance's
// connected prefixes leaked into main. Non-main (VRF→VRF) import targets are
// deferred to Phase 2 and warned at commit.
const mainTableID = 254

// pbrRulePriority is the base priority for policy-based routing ip rules.
// BEFORE the main table (32766) so the kernel also honors PBR for XDP_PASS'd
// packets (e.g. SNAT'd traffic destined for a VRF/GRE tunnel).
// We use 31000-31999 range. The band constant is the SSOT in pkg/config so
// the userspace FIB snapshot ingest (pkg/dataplane/userspace/routes.go) can
// skip this same band without drifting from the install side (#4479).
const pbrRulePriority = config.PBRRulePriorityBase

// nextTableManager reconciles next-table inter-VRF route-leak ip rules.
// Stateless apart from the borrowed ruleOps; it reconciles against live
// kernel ip-rule state.
type nextTableManager struct {
	ops ruleOps
}

// Apply creates Linux policy routing rules (ip rule) for static routes
// with next-table directives. This implements inter-VRF route leaking:
// "route X/Y next-table Instance.inet.0" means traffic to X/Y should be
// looked up in Instance's routing table.
//
// #9420: every emitted rule is SCOPED to an ingress interface of the routing
// instance that authored the leak, exactly as #5117 scoped the PBR/FBF mirror
// in this same file. next-table statics are read from the DEFAULT instance's
// routing-options (daemon_apply_routing.go passes
// cfg.RoutingOptions.StaticRoutes + Inet6StaticRoutes), so `ingressIfaces` is
// the resolved kernel ifname set of the interfaces that are NOT assigned to
// any routing instance — see DefaultInstanceIngressIfaces.
//
// Before #9420 the rule carried Dst + Table + Priority + Family and nothing
// else, at priority 100-199 — AHEAD of the kernel's l3mdev rule at 1000. A
// packet ingressing ANY other VRF whose destination fell in the leaked prefix
// was therefore steered out of the TARGET instance's table, on the target
// instance's device, overriding the ingress VRF's own routing. Measured on a
// live kernel, with a control and with the sharper case where the ingress VRF
// has its OWN route for the same prefix and still loses; the measurements are
// reproduced in docs/log/9420.md and pinned by TestNextTableRulesIngressScope_9420.
//
// Fail-closed, matching BuildPBRRules: with no resolvable default-instance
// ingress interface, NOTHING is installed and a degraded error is returned,
// rather than installing a global iif-less rule. The fail-safe direction is an
// under-steer (the leak is not followed) — never a cross-VRF over-steer.
func (n *nextTableManager) Apply(routes []*config.StaticRoute, instances []*config.RoutingInstanceConfig, ingressIfaces []string) error {
	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Clean up old next-table rules (priority range 100-199). A failed
	// per-family list does NOT abort the apply — we still re-add every
	// desired rule below so forward progress is preserved on the common
	// path. The clear error is captured and returned at the end so the
	// caller can observe (and a future caller retry) instead of leaving
	// orphaned rules in an unobservable window (#2273).
	clearErr := n.clear()
	if clearErr != nil {
		slog.Warn("failed to clear old next-table rules", "err", clearErr)
	}

	// Aggregate every failure (clear + per-rule add) and return it so the
	// commit/apply outcome reflects a half-installed leak instead of
	// reporting success after the up-front clear already removed the
	// previously-working next-table rules (#3731). A per-rule RuleAdd error
	// used to be logged and swallowed (Apply returned clearErr only), so a
	// transient netlink failure after clear() left inter-VRF leaking DOWN
	// with no signal to the daemon apply loop. This mirrors the #3430 PBR
	// pattern (aggregate + errors.Join) already used below. The clear error,
	// if any, is the first aggregated entry.
	var errs []error
	if clearErr != nil {
		errs = append(errs, clearErr)
	}

	// #6583: draw the priority window down IPv4-FIRST, independent of the
	// caller's slice order.
	//
	// This loop advances ONE family-blind `prio` in slice order, so which
	// leaks survive the maxNextTableRules cap was decided entirely by the two
	// `append` lines in pkg/daemon/daemon_apply_routing.go — v4 statics before
	// v6 statics. The userspace FIB mirrors the same cap but draws it down in
	// its OWN order (routes.go: addRoutes("inet.0", ...) then
	// addRoutes("inet6.0", ...)), so the two sides agreed only by convention
	// across a package boundary, with nothing on either side binding it.
	// Swapping those two appends would have installed 60 v6 + 40 v4 rules in
	// the kernel against 60 v4 + 40 v6 in the FIB: 40 leaks in the kernel and
	// not the FIB, 40 in the FIB and not the kernel — the #6467 kernel/FIB
	// verdict split in a new shape, where a leak present only in the FIB
	// resolves into the target VRF on the AF_XDP fast path while a slow-path
	// packet for the same flow resolves in the main table.
	//
	// Ordering HERE rather than asserting on the caller makes the agreement
	// structural: no caller can get it wrong, and the guard cannot rot into a
	// check of one caller while a second caller is added elsewhere. The
	// partition is STABLE, so within a family the caller's relative order —
	// which is what the FIB's per-family pass also preserves — is untouched.
	routes = nextTableFamilyOrdered(routes)

	// #9420 fail-closed gate. An empty ingress set means we cannot scope the
	// rules to the instance that authored the leak; installing them unscoped is
	// the defect this issue is about, so install nothing and report degraded.
	// This runs AFTER clear() so a stale unscoped rule from a previous apply is
	// still removed — leaving it installed would preserve the cross-VRF steer
	// the gate exists to prevent.
	if hasEligibleNextTableRoute(routes, tableIDs) && len(ingressIfaces) == 0 {
		errs = append(errs, errors.New(
			"next-table leak: cannot resolve any ingress interface for the routing "+
				"instance that authored the leak; the leak is not installed "+
				"(fail-safe under-steer) rather than installing a global iif-less "+
				"rule that would steer traffic from every other routing instance "+
				"into the target table (#9420)"))
		return errors.Join(errs...)
	}

	prio := nextTableRulePriority
	for i, sr := range routes {
		if sr == nil || sr.NextTable == "" {
			continue
		}
		tableID, ok := tableIDs[sr.NextTable]
		if !ok {
			slog.Warn("next-table references unknown routing instance",
				"destination", sr.Destination, "instance", sr.NextTable)
			continue
		}

		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil {
			slog.Warn("invalid next-table destination", "destination", sr.Destination, "err", err)
			continue
		}

		family := unix.AF_INET
		if dst.IP.To4() == nil {
			family = unix.AF_INET6
		}

		// Hard-cap the priority inside the window that clear() scans
		// ([nextTableRulePriority, nextTableRulePriority+maxNextTableRules)).
		// A rule programmed at or beyond the upper bound would never be
		// removed on a later apply and would leak permanently. Stop
		// programming further next-table routes once the window is exhausted,
		// matching the pbrManager cap pattern below.
		//
		// #6467: aggregate a degraded error (mirroring the rib-group and PBR
		// caps below) instead of a bare Warn+break. A silent truncation let
		// Apply report success while dropping a security-relevant inter-VRF
		// routing control AND diverging the kernel from the userspace FIB
		// (which mirrors the same cap). Name how many next-table routes past
		// the cap are not leaked so the operator sees the degraded result.
		// The strict commit gate (validateRoutingRuleWindowsStrict, #5854)
		// rejects an over-subscribed config up front; this belt catches the
		// tolerant-load / peer-sync path where that gate is downgraded to a
		// warning.
		// #9420: the window is drawn down LEAK-ATOMICALLY. One leak now costs
		// len(ingressIfaces) priorities, so a leak whose full ingress expansion
		// does not fit is dropped WHOLE rather than installed on a subset of its
		// interfaces — a partially-scoped leak would work on some ingress
		// interfaces and silently not on others, which is harder to diagnose
		// than a leak that is reported as not installed.
		if prio+len(ingressIfaces) > nextTableRulePriority+maxNextTableRules {
			// Count only ELIGIBLE routes past the cap — those the applier WOULD
			// have installed (known instance + parseable CIDR). An
			// unknown-instance or unparseable route is skipped above (no prio++),
			// so it never consumes a window slot and is not a "dropped leak"; the
			// tableIDs + net.ParseCIDR gates here mirror the per-route eligibility
			// checks at the top of this loop so the "N not leaked" count is
			// accurate rather than inflated by routes that would never install
			// (#6467).
			dropped := 0
			for _, rem := range routes[i:] {
				if rem == nil || rem.NextTable == "" {
					continue
				}
				if _, ok := tableIDs[rem.NextTable]; !ok {
					continue
				}
				if _, _, err := net.ParseCIDR(rem.Destination); err != nil {
					continue
				}
				dropped++
			}
			errs = append(errs, fmt.Errorf(
				"next-table rule limit (%d) reached; %d next-table route(s) beyond "+
					"the limit are not leaked — each leak costs one rule per "+
					"default-instance ingress interface (%d here), so reduce the "+
					"number of next-table routes",
				maxNextTableRules, dropped, len(ingressIfaces)))
			break
		}

		// One rule per ingress interface of the authoring instance (#9420).
		// ingressIfaces is pre-sorted and de-duplicated by
		// DefaultInstanceIngressIfaces so the priorities are stable across
		// applies despite Go map-iteration order.
		added := 0
		for _, iif := range ingressIfaces {
			rule := netlink.NewRule()
			rule.Dst = dst
			rule.Table = tableID
			rule.Priority = prio + added
			rule.Family = family
			rule.IifName = iif

			if err := n.ops.RuleAdd(rule); err != nil {
				errs = append(errs, fmt.Errorf(
					"add next-table rule destination %s instance %s table %d iif %s: %w",
					sr.Destination, sr.NextTable, tableID, iif, err))
			}
			added++
		}
		slog.Info("next-table rule added",
			"destination", sr.Destination, "instance", sr.NextTable, "table", tableID,
			"ingress_interfaces", len(ingressIfaces))
		prio += added
	}
	// Desired rules are re-added; surface any clear/add failure so a dropped
	// leak rule (or the orphaned-rule window) is observable rather than
	// silently nil (#3731 / #2273).
	return errors.Join(errs...)
}

// hasEligibleNextTableRoute reports whether any route would actually install a
// next-table ip rule — the same eligibility the Apply loop applies (non-nil,
// a NextTable set, and a known target instance). It exists so the #9420
// fail-closed gate stays SILENT for a config with no next-table leaks at all:
// without it, every commit on a box with zero leaks and zero resolvable
// interfaces would report a degraded next-table apply for a leak that does not
// exist.
//
// The CIDR parse is deliberately not re-checked here: an unparseable
// destination is skipped by the loop with a Warn and consumes no window slot,
// so treating it as eligible only risks arming the gate one config earlier —
// the fail-safe direction — and keeps this predicate cheap.
func hasEligibleNextTableRoute(routes []*config.StaticRoute, tableIDs map[string]int) bool {
	for _, sr := range routes {
		if sr == nil || sr.NextTable == "" {
			continue
		}
		if _, ok := tableIDs[sr.NextTable]; ok {
			return true
		}
	}
	return false
}

// DefaultInstanceIngressIfaces returns the sorted, de-duplicated kernel ifnames
// of every configured interface unit that is NOT assigned to a routing
// instance — i.e. the ingress interfaces of the DEFAULT routing instance.
//
// This is the #9420 scoping set for next-table leak rules. next-table statics
// are authored in the default instance's routing-options
// (daemon_apply_routing.go reads cfg.RoutingOptions.StaticRoutes and
// Inet6StaticRoutes; a per-instance static's next-table is not passed to the
// applier), so the default instance IS the authoring instance and its ingress
// interfaces are the only ones whose traffic the leak may steer.
//
// The kernel ifname is resolved via cfg.ResolveKernelIfName — the same
// Junos-ref → Linux-name mapping #5117 already paid the cost of for unit-0
// collapse (ge-0/0/0 → ge-0-0-0), 802.1Q sub-units (ge-0/0/0.50) and RETH
// members. An unresolvable unit contributes nothing rather than an empty
// ifname, so a rule is never emitted with an empty FRA_IIFNAME.
//
// Loopback is deliberately EXCLUDED. An `iif lo` rule matches locally
// generated traffic — measured, including traffic from a socket bound to
// ANOTHER VRF, which is the first exposed path #9420 names. Including lo to
// keep host-originated default-instance traffic following the leak would
// therefore reintroduce the cross-VRF hijack for every VRF-bound daemon (FRR
// peering, DHCP relay, syslog, RPM probes, IPsec). The narrowing is recorded
// in docs/rib-group-route-leaking.md and pkg/routing/README.md.
func DefaultInstanceIngressIfaces(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	claimed := make(map[string]struct{})
	for _, inst := range cfg.RoutingInstances {
		if inst == nil {
			continue
		}
		for _, ref := range inst.Interfaces {
			claimed[ref] = struct{}{}
			// An instance may claim the base interface ("ge-0/0/0") or a unit
			// ref ("ge-0/0/0.0"). Record the resolved kernel name too so a
			// claim written in either spelling excludes the same device.
			if k := cfg.ResolveKernelIfName(ref); k != "" {
				claimed[k] = struct{}{}
			}
		}
	}

	seen := make(map[string]struct{})
	var out []string
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		if _, taken := claimed[ifc.Name]; taken {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			ref := fmt.Sprintf("%s.%d", ifc.Name, unit.Number)
			if _, taken := claimed[ref]; taken {
				continue
			}
			iif := cfg.ResolveKernelIfName(ref)
			if iif == "" {
				continue
			}
			if _, taken := claimed[iif]; taken {
				continue
			}
			if _, dup := seen[iif]; dup {
				continue
			}
			seen[iif] = struct{}{}
			out = append(out, iif)
		}
	}
	sort.Strings(out)
	return out
}

// nextTableFamilyOrdered returns routes stably partitioned IPv4-first, so the
// next-table priority window is drawn down in the same family order the
// userspace FIB uses (#6583).
//
// A nil entry or an unparseable destination keeps its position in the FIRST
// group: both are skipped by Apply's own eligibility checks, so grouping them
// with v4 costs nothing and avoids inventing a third bucket whose ordering
// would itself be unspecified. It also preserves the pre-#6583 property that
// such an entry never consumes a window slot.
func nextTableFamilyOrdered(routes []*config.StaticRoute) []*config.StaticRoute {
	out := make([]*config.StaticRoute, 0, len(routes))
	var v6 []*config.StaticRoute
	for _, sr := range routes {
		if sr == nil {
			out = append(out, sr)
			continue
		}
		_, dst, err := net.ParseCIDR(sr.Destination)
		if err != nil || dst.IP.To4() != nil {
			out = append(out, sr)
			continue
		}
		v6 = append(v6, sr)
	}
	return append(out, v6...)
}

// clear removes all ip rules in the next-table priority range.
//
// A per-family RuleList dump that fails transiently must NOT be silently
// swallowed: continuing past it means the rules in that family's window
// are left in place (orphaned) for this pass while the other family is
// cleaned, and the caller never learns it happened. We still best-effort
// delete every family whose dump DID succeed, but we aggregate the dump
// failures and return them so Apply (and ultimately the daemon apply
// loop) can observe — and a future caller could retry — instead of the
// brief, unobservable self-healing-orphan window described in #2273.
func (n *nextTableManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := n.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list next-table rules family %d: %w", family, err))
			continue
		}
		for _, r := range rules {
			if r.Priority >= nextTableRulePriority && r.Priority < nextTableRulePriority+maxNextTableRules {
				if err := n.ops.RuleDel(&r); err != nil {
					if isRuleAlreadyGone(err) {
						// The rule is already absent (ENOENT / no such
						// rule) — a delete of a rule that is not there IS
						// the desired end-state, not a failure. Log for
						// diagnostics but do NOT aggregate so an idempotent
						// re-clear does not spuriously fail the apply.
						slog.Debug("stale next-table rule already absent",
							"priority", r.Priority, "err", err)
						continue
					}
					// #5118: a real RuleDel failure leaves a STALE next-table
					// route-leak rule in the kernel. That rule is an active
					// cross-VRF forwarding instruction sitting BEFORE the main
					// table, so a silent success here would preserve an
					// inter-VRF leak after a "successful" commit. Aggregate the
					// error (mirroring pbrManager.clear) so Apply — and the
					// daemon apply loop — observe the divergence instead of nil.
					slog.Warn("failed to delete stale next-table rule",
						"priority", r.Priority, "err", err)
					errs = append(errs, fmt.Errorf(
						"delete stale next-table rule prio %d: %w", r.Priority, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// isRuleAlreadyGone reports whether a RuleDel error means the rule was
// already absent (ENOENT / "no such rule"). The next-table and rib-group
// clear() passes list-then-delete, so the kernel returning ENOENT means the
// rule vanished between the dump and the delete (e.g. a concurrent flush or
// an idempotent re-clear). Deleting an already-gone rule reaches the desired
// end-state, so this MUST NOT be aggregated as an apply failure; only a rule
// that exists but cannot be removed is a genuine stale-rule failure (#5118).
func isRuleAlreadyGone(err error) bool {
	return errors.Is(err, unix.ENOENT) || os.IsNotExist(err)
}

// ribGroupManager reconciles rib-group route-leak ip rules. Stateless
// apart from the borrowed ruleOps.
type ribGroupManager struct {
	ops ruleOps
}

// Apply creates Linux policy routing rules (ip rule) for rib-group route
// leaking. When a routing instance has interface-routes with a rib-group
// that imports the main table, the instance's CONNECTED (interface) routes
// are leaked into main so main-table lookups reach them.
//
// #3876: this is done PER CONNECTED PREFIX with a rule that sits BEFORE the
// main table (priority < 32766), so a specific imported prefix wins over a
// main-table default route:
//
//	ip rule to <connected-prefix> lookup <sourceTable> pref 30000
//
// This replaces the pre-#3876 `from all lookup <sourceTable> pref 33000`
// blanket rule, which (a) sat AFTER main so any default route shadowed it —
// making the leak a silent no-op — and (b) leaked the WHOLE source table as
// a catch-all fall-through rather than just the interface routes Junos
// leaks. The per-prefix rules also carry a Dst, so the userspace FIB
// snapshot builder auto-captures them as NextTable leaks into main (see
// pkg/dataplane/userspace/routes.go) — the pre-#3876 Dst-less rule was
// skipped there too, so the leak was absent from BOTH FIBs.
//
// connectedPrefixes is keyed by routing-instance name and holds that
// instance's connected network prefixes (v4 and v6 mixed), derived from the
// config addresses on its member interface units via
// config.ConnectedNetworkPrefix — the SAME derivation the userspace FIB uses
// for connected routes, so the leaked prefix set matches the connected
// routes in the source table.
//
// Both IPv4 (InterfaceRoutesRibGroup) and IPv6 (InterfaceRoutesRibGroupV6)
// rib-groups are handled. Non-main (VRF→VRF) import targets are deferred to
// Phase 2 and warned at commit (pkg/config); this applier installs nothing
// for them.
//
// #9819: for each source whose leak installs, Apply also adds return rules
// (`iif`/`oif vrf-<instance> lookup main`), so the VRF miss terminator does
// not cut the leak's return path. See ribGroupReturnRulePriority.
func (rg *ribGroupManager) Apply(ribGroups map[string]*config.RibGroup, instances []*config.RoutingInstanceConfig, connectedPrefixes map[string][]string) error {
	// Clean up old rib-group rules. As with next-table, a failed per-family
	// list does not abort the apply; the clear error is captured and
	// returned at the end (or at the early-return below) so the caller can
	// observe it (#2273).
	clearErr := rg.clear()
	if clearErr != nil {
		slog.Warn("failed to clear old rib-group rules", "err", clearErr)
	}

	// Aggregate every failure (clear + per-rule add) and return it so a
	// dropped leak rule is surfaced instead of reporting success after the
	// up-front clear already removed the previously-working rules (#3731).
	// A per-rule RuleAdd error used to be logged and swallowed (Apply
	// returned clearErr only), so a transient netlink failure after clear()
	// left inter-VRF leaking DOWN with no signal. This mirrors the #3430 PBR
	// pattern (aggregate + errors.Join) already used below. The clear error,
	// if any, is the first aggregated entry.
	var errs []error
	if clearErr != nil {
		errs = append(errs, clearErr)
	}

	if len(ribGroups) == 0 || len(instances) == 0 {
		return errors.Join(errs...)
	}

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range instances {
		tableIDs[inst.Name] = inst.TableID
	}

	// Track which source tables we've already added rules for (avoid
	// duplicate rules if two instances share a table ID).
	leakedTables := make(map[int]bool)

	prio := ribGroupLeakRulePriority
	capped := false
	for _, inst := range instances {
		if capped {
			break
		}
		sourceTable := inst.TableID

		// Phase 1 leaks ONLY into main. A rib-group whose import-ribs resolve
		// only to non-main tables (VRF→VRF) installs nothing here and is
		// warned at commit (Phase 2 deferral). Family gating: the v4
		// rib-group leaks v4 connected prefixes, the v6 rib-group leaks v6.
		leakV4 := ribGroupLeaksIntoMain(inst.InterfaceRoutesRibGroup, ribGroups, tableIDs, inst.Name)
		leakV6 := ribGroupLeaksIntoMain(inst.InterfaceRoutesRibGroupV6, ribGroups, tableIDs, inst.Name)
		if !leakV4 && !leakV6 {
			continue
		}
		if leakedTables[sourceTable] {
			continue
		}
		leakedTables[sourceTable] = true

		v4, v6 := splitConnectedPrefixesByFamily(connectedPrefixes[inst.Name])
		var toInstall []struct {
			prefix string
			family int
		}
		if leakV4 {
			for _, p := range v4 {
				toInstall = append(toInstall, struct {
					prefix string
					family int
				}{p, unix.AF_INET})
			}
		}
		if leakV6 {
			for _, p := range v6 {
				toInstall = append(toInstall, struct {
					prefix string
					family int
				}{p, unix.AF_INET6})
			}
		}

		installed := map[int]bool{}
		for _, lr := range toInstall {
			// Hard-cap at the priority window clear() scans. A rule at or
			// beyond the upper bound would never be removed on a later apply
			// and would leak permanently. ValidateConfig warns before this
			// point is reached; mirror the maxPBRRules/next-table caps.
			if prio >= ribGroupLeakRulePriority+maxRibGroupLeakRules {
				errs = append(errs, fmt.Errorf(
					"rib-group leak rule limit (%d) reached; connected prefixes beyond "+
						"the limit are not leaked — reduce the number of interface-routes "+
						"rib-group prefixes", maxRibGroupLeakRules))
				capped = true
				break
			}
			_, dst, err := net.ParseCIDR(lr.prefix)
			if err != nil || dst == nil {
				errs = append(errs, fmt.Errorf(
					"rib-group leak: parse connected prefix %q instance %s: %w",
					lr.prefix, inst.Name, err))
				continue
			}
			rule := netlink.NewRule()
			rule.Dst = dst
			rule.Table = sourceTable
			rule.Priority = prio
			rule.Family = lr.family

			familyStr := "inet"
			if lr.family == unix.AF_INET6 {
				familyStr = "inet6"
			}
			if err := rg.ops.RuleAdd(rule); err != nil {
				errs = append(errs, fmt.Errorf(
					"add rib-group leak rule prefix %s instance %s table %d family %s: %w",
					lr.prefix, inst.Name, sourceTable, familyStr, err))
				prio++
				continue
			}
			installed[lr.family] = true
			slog.Info("rib-group leak rule added",
				"instance", inst.Name, "prefix", lr.prefix,
				"table", sourceTable, "family", familyStr, "pref", prio)
			prio++
		}
		// #9819: the source's return path, in each family whose leak
		// installed. See ribGroupReturnRulePriority for why it is main, and
		// only main.
		errs = append(errs, rg.addRibGroupReturnRules(inst, installed)...)
	}
	// Desired rules are re-added; surface any clear/add failure so a dropped
	// leak rule (or the orphaned-rule window) is observable rather than
	// silently nil (#3731 / #2273).
	return errors.Join(errs...)
}

// ribGroupLeaksIntoMain reports whether the named interface-routes rib-group
// imports the main table — the #3876 Phase-1 target for per-prefix connected-
// route leaking. It returns false for an empty name, an undefined group, or a
// group whose import-ribs resolve only to non-main tables (a VRF→VRF import,
// deferred to Phase 2 and warned at commit). Unresolvable import-ribs are
// skipped (never treated as a main-table hit) — the #2226 fail-closed guard.
func ribGroupLeaksIntoMain(rgName string, ribGroups map[string]*config.RibGroup, tableIDs map[string]int, instName string) bool {
	if rgName == "" {
		return false
	}
	rgDef, ok := ribGroups[rgName]
	if !ok {
		slog.Warn("interface-routes references unknown rib-group",
			"instance", instName, "rib-group", rgName)
		return false
	}
	for _, ribName := range rgDef.ImportRibs {
		targetTable, ok := resolveRibTable(ribName, tableIDs)
		if !ok {
			slog.Warn("rib-group import-rib references unknown rib; skipping (not leaking)",
				"instance", instName, "rib-group", rgName, "import-rib", ribName)
			continue
		}
		if targetTable == mainTableID {
			return true
		}
	}
	return false
}

// splitConnectedPrefixesByFamily partitions a mixed connected-prefix list
// (as carried in ApplyRibGroupRules' connectedPrefixes map) into v4 and v6
// by literal ':' presence — the same family test the userspace route
// snapshot uses.
func splitConnectedPrefixesByFamily(prefixes []string) (v4, v6 []string) {
	for _, p := range prefixes {
		if strings.Contains(p, ":") {
			v6 = append(v6, p)
		} else {
			v4 = append(v4, p)
		}
	}
	return v4, v6
}

// clear removes all ip rules in the rib-group priority ranges. It scans
// THREE windows so an in-place binary upgrade removes stale rules from every
// generation of this reconciler:
//   - [ribGroupLeakRulePriority, +maxRibGroupLeakRules): the current #3876
//     per-prefix leak window (30000-30999).
//   - [ribGroupRulePriority, +100): the pre-#3876 `from all lookup <table>`
//     blanket window (33000-33099). Removing these on reconcile is what
//     prevents an upgrade from leaving a shadowed-by-default blanket rule
//     behind alongside the new per-prefix rules.
//   - [200, 300): the original legacy window.
//
// It also removes the #9819 return rules at ribGroupReturnRulePriority, which
// Apply re-adds for every source whose leak installs.
//
// Per-family RuleList dump failures are aggregated and returned rather
// than swallowed; see the rationale on nextTableManager.clear (#2273).
func (rg *ribGroupManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := rg.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list rib-group rules family %d: %w", family, err))
			continue
		}
		for _, r := range rules {
			inCurrent := r.Priority >= ribGroupLeakRulePriority && r.Priority < ribGroupLeakRulePriority+maxRibGroupLeakRules
			inOldBlanket := r.Priority >= ribGroupRulePriority && r.Priority < ribGroupRulePriority+100
			inLegacy := r.Priority >= 200 && r.Priority < 300
			inReturn := r.Priority == ribGroupReturnRulePriority // #9819
			if inCurrent || inOldBlanket || inLegacy || inReturn {
				if err := rg.ops.RuleDel(&r); err != nil {
					if isRuleAlreadyGone(err) {
						// Already absent — the desired end-state, not a
						// failure. Log only; do not fail an idempotent
						// re-clear (see isRuleAlreadyGone / #5118).
						slog.Debug("stale rib-group rule already absent",
							"priority", r.Priority, "err", err)
						continue
					}
					// #5118: a real RuleDel failure leaves a STALE rib-group
					// route-leak rule (a per-prefix connected-route leak that
					// precedes the main table) in the kernel. Aggregate it so
					// Apply surfaces the inter-VRF leak instead of reporting a
					// silent success, mirroring pbrManager.clear.
					slog.Warn("failed to delete stale rib-group rule",
						"priority", r.Priority, "err", err)
					errs = append(errs, fmt.Errorf(
						"delete stale rib-group rule prio %d: %w", r.Priority, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// PBRRule describes a single policy-based routing rule derived from a
// firewall filter term with a routing-instance action.
type PBRRule struct {
	Family int   // unix.AF_INET or unix.AF_INET6
	DSCP   uint8 // raw 6-bit DiffServ code point (0-63); meaningful when DSCPSet
	// DSCPSet distinguishes "match DSCP 0" (be / cs0 / numeric 0) from
	// "no DSCP match" (#3430 H2). DSCP==0 is a perfectly valid code point
	// (best-effort / class-selector 0); without an explicit presence flag
	// the applier either skipped the rule (no address predicate) or widened
	// it to ALL DSCP values (address predicate present). The rule emits a
	// `dscp` selector iff DSCPSet is true.
	//
	// #7796: this used to be a TOS BYTE holding DSCP << 2, emitted as the
	// netlink rule's legacy `Tos`. The kernel masks that byte to
	// IPTOS_TOS_MASK (0x1E) and rejected every DSCP >= 8 with EINVAL, which
	// failed the whole commit. The field is the 6-bit DSCP now because the
	// selector it feeds (FRA_DSCP) is a DSCP, not a TOS — the shift was the
	// bug, so the type no longer carries a shifted value at all.
	DSCPSet bool
	Src     string // source CIDR, "" = any (no `from` selector)
	Dst     string // destination CIDR, "" = any (no `to` selector)
	// IPProto, Sport and Dport mirror the L4 predicates a kernel `ip rule` CAN
	// express (#3730): FRA_IP_PROTO, FRA_SPORT_RANGE and FRA_DPORT_RANGE. Before
	// #3730 the FBF mirror emitted only the address/DSCP selectors and silently
	// dropped every L4 predicate, so a port/protocol-constrained
	// `then routing-instance` term either over-steered ALL address-matching
	// traffic to the target VRF or no-opped — with no degraded signal. The
	// builder now honors these; predicates an ip rule cannot represent
	// (port-except, tcp-flags, icmp-type/code, is-fragment, flexible-match-range)
	// fail closed (the whole term is dropped and the build is marked degraded)
	// rather than widening the match.
	IPProto  int           // IP protocol number, 0 = no protocol selector
	Sport    *PBRPortRange // source-port range, nil = no source-port selector
	Dport    *PBRPortRange // destination-port range, nil = no dest-port selector
	TableID  int           // target routing table
	Instance string        // routing instance name (for logging)
	// IifName scopes the kernel FBF ip rule to the Linux ingress interface the
	// firewall filter is attached to (#5117). Junos filter-based-forwarding is
	// bound to a specific interface-unit input filter, so a `then
	// routing-instance` term only steers traffic INGRESSING that interface. The
	// pre-#5117 mirror set no iif selector, so a slow-path (XDP_PASS) packet
	// arriving on a DIFFERENT interface could match the rule and be steered into
	// the wrong VRF (cross-WAN / tenant route-leak). This carries the resolved
	// kernel ifname (e.g. "ge-0-0-0", "ge-0-0-0.50", a RETH member) so Apply
	// emits FRA_IIFNAME and the rule matches ONLY that interface. It is never
	// empty for a built rule: BuildPBRRules fails closed (drops the term +
	// degrades) rather than installing a global iif-less rule.
	IifName string
}

// PBRPortRange is a numeric [Lo,Hi] port range for the kernel FBF ip-rule
// mirror. A single port has Lo==Hi. It maps 1:1 onto netlink's RulePortRange
// (FRA_SPORT_RANGE / FRA_DPORT_RANGE) but stays netlink-free so the builder is
// unit-testable without the kernel.
type PBRPortRange struct {
	Lo uint16
	Hi uint16
}

// String renders the range as a single port ("443") or a low-high span
// ("1024-2048"). A nil receiver renders as "" so it is safe to log an unset
// selector directly.
func (r *PBRPortRange) String() string {
	if r == nil {
		return ""
	}
	if r.Lo == r.Hi {
		return strconv.Itoa(int(r.Lo))
	}
	return fmt.Sprintf("%d-%d", r.Lo, r.Hi)
}

// maxPBRRules bounds the number of ip rules the PBR builder/applier will
// install, matching the pbrRulePriority window (clear() scans
// [pbrRulePriority, pbrRulePriority+1000)). A larger DSCP×src×dst expansion
// is truncated and reported as a degraded build (#3430 M3) rather than
// silently dropping later terms' steering. Window size is the SSOT in
// pkg/config (PBRRuleWindow) so the install cap and the userspace snapshot
// skip band cannot drift (#4479).
const maxPBRRules = config.PBRRuleWindow

// pbrManager reconciles policy-based routing ip rules. Stateless apart
// from the borrowed ruleOps.
type pbrManager struct {
	ops ruleOps
}

// Apply creates Linux policy routing rules (ip rule) for firewall filter
// terms that use a routing-instance action. This implements
// policy-based routing: traffic matching DSCP/source/destination
// criteria is routed via the specified VRF's routing table.
func (p *pbrManager) Apply(rules []PBRRule) error {
	// Clean up old PBR rules first. As with next-table, a failed per-family
	// list does not abort the apply; the clear error is captured and
	// returned at the end (or at the early-return below) so the caller can
	// observe it (#2273).
	clearErr := p.clear()
	if clearErr != nil {
		slog.Warn("failed to clear old PBR rules", "err", clearErr)
	}

	// Aggregate every failure (clear, parse, add, overflow) and return it so
	// the commit/apply outcome reflects a half-installed policy instead of
	// reporting success after the up-front clear already removed the
	// previously-working steering (#3430 H3). The clear error, if any, is the
	// first aggregated entry.
	var errs []error
	if clearErr != nil {
		errs = append(errs, clearErr)
	}

	if len(rules) == 0 {
		return errors.Join(errs...)
	}

	prio := pbrRulePriority
	for _, pbr := range rules {
		// Cap at the priority window (defense-in-depth; BuildPBRRules already
		// truncates). Checked at the top so exactly maxPBRRules rules install
		// without a spurious overflow error (#3430 M3 apply leg).
		if prio >= pbrRulePriority+maxPBRRules {
			errs = append(errs, fmt.Errorf("PBR rule limit (%d) reached; remaining rules dropped", maxPBRRules))
			break
		}
		rule := netlink.NewRule()
		rule.Table = pbr.TableID
		rule.Priority = prio
		rule.Family = pbr.Family

		// Scope the rule to the ingress interface the filter is attached to
		// (#5117) so a slow-path packet on a different interface cannot match a
		// global rule and be steered into the wrong VRF. BuildPBRRules guarantees
		// IifName is non-empty (it fails closed otherwise), but guard anyway so a
		// malformed rule never installs an unscoped (global) FRA-less rule.
		if pbr.IifName == "" {
			errs = append(errs, fmt.Errorf(
				"PBR rule instance %s table %d has no ingress interface; refusing to "+
					"install a global iif-less FBF rule (#5117)", pbr.Instance, pbr.TableID))
			continue
		}
		rule.IifName = pbr.IifName

		// The DSCP selector is NOT set on the netlink.Rule: it cannot represent
		// one (#7796). It is carried to RuleAddDSCP below instead. rule.Tos is
		// deliberately left zero — the encoder rejects a rule that sets both.
		if pbr.Src != "" {
			_, src, err := net.ParseCIDR(pbr.Src)
			if err != nil {
				errs = append(errs, fmt.Errorf("PBR source %q (instance %s): %w", pbr.Src, pbr.Instance, err))
				continue
			}
			rule.Src = src
		}
		if pbr.Dst != "" {
			_, dst, err := net.ParseCIDR(pbr.Dst)
			if err != nil {
				errs = append(errs, fmt.Errorf("PBR destination %q (instance %s): %w", pbr.Dst, pbr.Instance, err))
				continue
			}
			rule.Dst = dst
		}

		// Emit the L4 selectors the kernel ip rule supports (#3730). IPProto is
		// written only when > 0 (the netlink FRA_IP_PROTO emit condition; 0 =
		// "match any"). Sport/Dport map onto FRA_SPORT_RANGE / FRA_DPORT_RANGE.
		if pbr.IPProto > 0 {
			rule.IPProto = pbr.IPProto
		}
		if pbr.Sport != nil {
			rule.Sport = netlink.NewRulePortRange(pbr.Sport.Lo, pbr.Sport.Hi)
		}
		if pbr.Dport != nil {
			rule.Dport = netlink.NewRulePortRange(pbr.Dport.Lo, pbr.Dport.Hi)
		}

		// Emit a dscp selector iff the term actually matched a DSCP (#3430 H2).
		addErr := error(nil)
		if pbr.DSCPSet {
			addErr = p.ops.RuleAddDSCP(rule, pbr.DSCP)
		} else {
			addErr = p.ops.RuleAdd(rule)
		}
		if addErr != nil {
			errs = append(errs, fmt.Errorf("add PBR rule instance %s table %d: %w", pbr.Instance, pbr.TableID, addErr))
			continue
		}
		slog.Info("PBR rule added",
			"instance", pbr.Instance, "iif", pbr.IifName,
			"dscp", pbr.DSCP, "dscp_set", pbr.DSCPSet,
			"src", pbr.Src, "dst", pbr.Dst, "ipproto", pbr.IPProto,
			"sport", pbr.Sport.String(), "dport", pbr.Dport.String(),
			"table", pbr.TableID)
		prio++
	}
	// Desired rules are re-added; surface any clear/parse/add/overflow failure.
	return errors.Join(errs...)
}

// clear removes all ip rules in the PBR priority range.
//
// Per-family RuleList dump failures are aggregated and returned rather
// than swallowed; see the rationale on nextTableManager.clear (#2273).
func (p *pbrManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := p.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("list PBR rules family %d: %w", family, err))
			continue
		}
		for _, r := range rules {
			if r.Priority >= pbrRulePriority && r.Priority < pbrRulePriority+1000 {
				if err := p.ops.RuleDel(&r); err != nil {
					// #3430 H3: a RuleDel failure leaves a STALE PBR rule in the
					// kernel. Join it into the returned error so Apply does not
					// report success after the up-front clear could not remove a
					// stale (now-divergent) rule — the operator must see that the
					// installed steering may still carry leftover rules.
					errs = append(errs, fmt.Errorf("delete stale PBR rule prio %d: %w", r.Priority, err))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// BuildPBRRules extracts policy-based routing (filter-based-forwarding) ip
// rules from the firewall configuration, matching Junos FBF semantics.
//
// Junos FBF is realized by an INPUT firewall filter attached to an interface;
// a `then routing-instance <vr>` term steers matching ingress traffic to that
// instance's routing table. The builder therefore derives rules ONLY from
// filters actually attached as an interface-unit input filter (#3430 H1) — a
// defined-but-unattached filter has no dataplane effect in Junos and must not
// program a global ip rule. Output-attached filters are not FBF and are
// ignored.
//
// Each rule is scoped to the Linux ingress interface the filter is attached to
// (#5117): a filter bound to several interfaces is expanded once PER
// (filter, interface) attachment, and every emitted rule carries an IifName
// (FRA_IIFNAME) resolved via cfg.ResolveKernelIfName so it matches ONLY packets
// ingressing that interface. This mirrors per-interface Junos FBF, where a
// `then routing-instance` term only steers traffic ingressing the interface the
// filter is attached to. The pre-#5117 mirror emitted one iif-less rule per
// filter, so a slow-path (XDP_PASS) packet arriving on a DIFFERENT interface
// could match the global rule and be steered into the wrong VRF. An attachment
// whose ingress interface cannot be resolved fails CLOSED (the term is dropped
// and the build degraded) rather than installing a global iif-less rule.
//
// Kernel-mirror support matrix (#3730). An `ip rule` can only express a subset
// of a firewall-filter term's `from` predicates, so the mirror is exact for the
// representable ones and FAILS CLOSED for the rest:
//
//   - REPRESENTABLE (honored): source/destination address + prefix-list (FRA_SRC/
//     FRA_DST), DSCP — ANY value 0-63, carried in FRA_DSCP (#7796) — `protocol`
//     (FRA_IP_PROTO), `source-port` (FRA_SPORT_RANGE) and `destination-port`
//     (FRA_DPORT_RANGE). Multi-value protocol/port sets expand to one ip rule per
//     value; a port range maps to a single [lo,hi] rule range.
//   - UNREPRESENTABLE (fail-closed, whole term dropped + degraded): a non-empty
//     address `except` set, an unknown DSCP name, `source-port-except` /
//     `destination-port-except` (no negated port selector), `tcp-flags`,
//     `icmp-type` / `icmp-code`, `is-fragment`, `flexible-match-range`, and any
//     unresolved / unenforceable `from` leaf. Emitting the address/protocol/port
//     half while silently dropping these would WIDEN the match and steer traffic
//     the operator constrained away (the #3730 over-steer); dropping the term is
//     the fail-safe under-steer (steered traffic falls back to the main table),
//     and the userspace filter path still enforces the term exactly.
//
// The returned error is non-nil when the build is DEGRADED: a term carries an
// ip-rule-unrepresentable predicate (per the matrix above) or the expansion
// exceeds maxPBRRules. The successfully-built rules are still returned so the
// caller can install them and surface the degradation.
func BuildPBRRules(cfg *config.Config) ([]PBRRule, error) {
	if cfg == nil {
		return nil, nil
	}
	fw := &cfg.Firewall

	// Build instance name → table ID map
	tableIDs := make(map[string]int)
	for _, inst := range cfg.RoutingInstances {
		tableIDs[inst.Name] = inst.TableID
	}

	inetAttached, inet6Attached := collectAttachedInputFilters(cfg)
	pls := cfg.PolicyOptions.PrefixLists

	var rules []PBRRule
	var errs []error
	// #5683: once the running rule count reaches maxPBRRules no further term can
	// be materialized (the installer's priority window addresses only that many
	// rules), so stop feeding attachments to the expander. This is the outer half
	// of the bounded-materialization guard — buildPBRFromFilter enforces the same
	// budget per term so the six-dimensional Cartesian product is NEVER allocated
	// beyond the cap.
	overflowed := false
	build := func(atts []pbrAttachment, filters map[string]*config.FirewallFilter, family int) {
		for _, att := range atts {
			if overflowed {
				return
			}
			filter := filters[att.Filter]
			if filter == nil {
				// Dangling attachment (filter named on an interface but not
				// defined). The strict commit gate rejects this
				// (validateFilterAttachmentReferences / warn path); skip here.
				continue
			}
			if att.Iif == "" {
				// #5117: the ingress interface could not be resolved to a kernel
				// ifname. Fail closed — installing a global iif-less rule would
				// over-steer traffic on every interface into the target VRF. The
				// userspace filter path still enforces the term exactly.
				errs = append(errs, fmt.Errorf(
					"PBR filter %s: cannot resolve the ingress interface for FBF "+
						"scoping; steering for this attachment is dropped (fail-safe "+
						"under-steer) rather than installing a global iif-less rule",
					att.Filter))
				continue
			}
			// Budget the remaining priority window for this attachment so a term
			// whose Cartesian product would overrun the cap is dropped BEFORE it
			// is expanded (#5683), not materialized-then-truncated.
			r, e, of := buildPBRFromFilter(filter, family, tableIDs, pls, maxPBRRules-len(rules))
			// Scope every rule this attachment produced to its ingress interface.
			for i := range r {
				r[i].IifName = att.Iif
			}
			rules = append(rules, r...)
			errs = append(errs, e...)
			if of {
				overflowed = true
				return
			}
		}
	}
	build(inetAttached, fw.FiltersInet, unix.AF_INET)
	build(inet6Attached, fw.FiltersInet6, unix.AF_INET6)

	// #5683 defense-in-depth: buildPBRFromFilter's per-term budget guard already
	// guarantees len(rules) <= maxPBRRules, so this truncation is a no-op belt
	// (it can never allocate the pre-cap blow-up the guard prevents). The
	// per-offender overflow error is emitted by buildPBRFromFilter, naming the
	// filter and term whose product crossed the cap.
	if len(rules) > maxPBRRules {
		rules = rules[:maxPBRRules]
	}
	return rules, errors.Join(errs...)
}

// PBRBuildStats returns observability counts derived from BuildPBRRules for the
// active config (#4422). It is a pure function of cfg (no netlink), safe to call
// on the Prometheus scrape path — the same posture as the config-derived
// host-inbound addressless collectors.
//
//   - installed: the number of kernel `ip rule` FBF entries the
//     routing-instance filter terms yield (post-truncation to the maxPBRRules
//     priority window). This is the desired-install count; ApplyPBRRules
//     installs exactly this set (a later netlink failure there is a separate,
//     logged concern).
//   - degraded: the number of routing-instance filter terms DROPPED from the
//     kernel FBF mirror (fail-closed under-steer to the main table) — an
//     unrepresentable `except` set, an unknown DSCP name, a contradictory
//     `routing-instance` + `discard`/`reject` term (#4534), an
//     ip-rule-unrepresentable L4/per-packet predicate (#3730), or the
//     maxPBRRules overflow (#3430 M3, counted as one condition). A non-zero
//     value means the kernel slow path under-steers vs the userspace fast path
//     (which still enforces every term exactly).
//
// There is deliberately no "widened" count: BuildPBRRules REFUSES to widen an
// unrepresentable match to an address-only over-steer (fail-closed drop), so an
// over-steer is never mirrored — the "widened" audit state does not exist by
// design.
func PBRBuildStats(cfg *config.Config) (installed, degraded int) {
	rules, err := BuildPBRRules(cfg)
	installed = len(rules)
	if err != nil {
		// BuildPBRRules returns errors.Join(errs...); its joinError exposes the
		// per-term error slice via Unwrap() []error, so the count of degraded
		// terms is exact. The single-error fallback is defensive only.
		if u, ok := err.(interface{ Unwrap() []error }); ok {
			degraded = len(u.Unwrap())
		} else {
			degraded = 1
		}
	}
	return installed, degraded
}

// pbrAttachment binds a firewall filter to the Linux ingress interface it is
// attached to as an interface-unit input filter. Carrying the interface
// identity (not just the filter name, #5117) lets BuildPBRRules scope each
// kernel FBF ip rule to the interface the filter is bound to — matching
// per-interface Junos FBF instead of steering matching traffic globally.
type pbrAttachment struct {
	Filter string // firewall filter name
	Iif    string // Linux ingress ifname (e.g. "ge-0-0-0", "ge-0-0-0.50")
}

// collectAttachedInputFilters returns the ordered, de-duplicated set of
// (filter, ingress-interface) attachments for interface-unit INPUT filters,
// split by family. These are the only filters whose `then routing-instance`
// terms take effect as Junos FBF (#3430 H1).
//
// Unlike the pre-#5117 collector (which returned filter NAMES only and so
// deduplicated a filter attached to several interfaces into a single global
// rule), this preserves the ingress interface each attachment binds to. The
// kernel ifname is resolved canonically via cfg.ResolveKernelIfName — the same
// Junos-ref → Linux-name mapping the rest of routing uses, so a unit-0 collapse
// (ge-0/0/0 → ge-0-0-0), an 802.1Q VLAN unit (ge-0/0/0.50), and a RETH member
// (reth0 → local physical member) all resolve consistently. Entries are
// de-duplicated by (filter, iif) so the same filter on the same interface is
// not double-counted, and the result is sorted (filter, then iif) so emitted
// ip-rule priorities are stable across applies despite Go map-iteration order.
func collectAttachedInputFilters(cfg *config.Config) (inet, inet6 []pbrAttachment) {
	if cfg == nil {
		return nil, nil
	}
	seenV4 := make(map[pbrAttachment]struct{})
	seenV6 := make(map[pbrAttachment]struct{})
	add := func(seen map[pbrAttachment]struct{}, list *[]pbrAttachment, a pbrAttachment) {
		if _, dup := seen[a]; dup {
			return
		}
		seen[a] = struct{}{}
		*list = append(*list, a)
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		for _, unit := range ifc.Units {
			if unit == nil {
				continue
			}
			if unit.FilterInputV4 == "" && unit.FilterInputV6 == "" {
				continue
			}
			// Resolve the kernel ingress ifname for this interface-unit, matching
			// how the filter binds (base / VLAN sub-interface / RETH member).
			iif := cfg.ResolveKernelIfName(fmt.Sprintf("%s.%d", ifc.Name, unit.Number))
			if unit.FilterInputV4 != "" {
				add(seenV4, &inet, pbrAttachment{Filter: unit.FilterInputV4, Iif: iif})
			}
			if unit.FilterInputV6 != "" {
				add(seenV6, &inet6, pbrAttachment{Filter: unit.FilterInputV6, Iif: iif})
			}
		}
	}
	sortAttachments(inet)
	sortAttachments(inet6)
	return inet, inet6
}

// sortAttachments orders attachments deterministically (filter name, then
// ingress ifname) so the emitted ip-rule priorities are stable across applies
// regardless of Go map-iteration order.
func sortAttachments(atts []pbrAttachment) {
	sort.Slice(atts, func(i, j int) bool {
		if atts[i].Filter != atts[j].Filter {
			return atts[i].Filter < atts[j].Filter
		}
		return atts[i].Iif < atts[j].Iif
	})
}

// buildPBRFromFilter extracts PBR rules from a single firewall filter.
// The returned error slice carries per-term DEGRADED conditions (an
// unrepresentable except set, an unknown DSCP name, or an ip-rule-unrepresentable
// L4/per-packet predicate — #3730); the buildable rules are still returned.
//
// budget is the number of ip rules the caller can still install before the
// maxPBRRules priority window is full. Before expanding a term's six-dimensional
// Cartesian product (DSCP × protocol × source-port × destination-port × source ×
// destination), the term's product SIZE is computed from the resolved dimension
// lengths — O(dimensions), not O(product) — and a term that would push the
// running total past the remaining budget is DROPPED WHOLE (fail-safe
// under-steer to the main table) with a degraded error rather than materialized
// and then truncated (#5683). This makes the pre-cap memory/CPU blow-up
// impossible: the full product is never allocated. The returned bool is true
// when such an overflow drop occurred, signalling the caller to stop feeding
// further attachments (the window is full).
func buildPBRFromFilter(filter *config.FirewallFilter, family int, tableIDs map[string]int, pls map[string]*config.PrefixList, budget int) ([]PBRRule, []error, bool) {
	var rules []PBRRule
	var errs []error
	for _, term := range filter.Terms {
		if term.RoutingInstance == "" {
			continue
		}

		// #4534: a term that co-locates `then routing-instance <x>` with a
		// terminating `then discard` / `then reject` is CONTRADICTORY — it asks
		// the dataplane to BOTH steer the packet into <x> AND drop/reject it. The
		// deny wins: the userspace forwarding path (ingress_route_table_override,
		// userspace-dp/src/afxdp/forwarding/mod.rs) returns RouteOverride::Drop for
		// such a term (#4392). The kernel `ip rule` mirror must match that
		// disposition — building a steering rule here would fail OPEN, steering
		// slow-path / XDP_PASS traffic ingressing the attached interface (even
		// with the #5117 iif selector) into the target VRF that userspace drops.
		// The strict commit gate (validateFilterRoutingInstanceConflictStrict)
		// rejects this term, but is LENIENT on load / peer-sync (#1960 no-brick),
		// so a contradictory term can still reach here — skip it (do NOT steer).
		if term.Action == "discard" || term.Action == "reject" {
			errs = append(errs, fmt.Errorf(
				"PBR filter %s term %s co-locates routing-instance %q with a terminating "+
					"%q action; the deny wins (mirroring the userspace drop, #4392) — no "+
					"steering ip rule is built for this contradictory term",
				filter.Name, term.Name, term.RoutingInstance, term.Action))
			continue
		}

		tableID, ok := tableIDs[term.RoutingInstance]
		if !ok {
			slog.Warn("PBR: routing-instance not found",
				"filter", filter.Name, "term", term.Name,
				"instance", term.RoutingInstance)
			continue
		}

		// Classify the term's L4/per-packet predicates against what a kernel ip
		// rule can express (#3730). A predicate an ip rule cannot represent
		// (port-except / tcp-flags / icmp / is-fragment / flex / unresolved from
		// leaf, or an unknown protocol / unparseable port) fails CLOSED: the whole
		// term is dropped so the mirror never widens a constrained steer to
		// address-only. The representable predicates (protocol, source/destination
		// port) are honored below via the cross-product.
		protos, sports, dports, unrep := pbrTermL4(term)
		if len(unrep) > 0 {
			errs = append(errs, fmt.Errorf(
				"PBR filter %s term %s carries filter predicate(s) [%s] that a kernel "+
					"ip rule cannot represent (the FBF mirror steers on address / DSCP / "+
					"protocol / port only); steering for this term is dropped (fail-safe "+
					"under-steer to the main table) rather than widening the match — enforce "+
					"it on the userspace filter path",
				filter.Name, term.Name, strings.Join(unrep, ", ")))
			continue
		}

		// DSCP presence-tracked values (#2545 multi-value, #3430 H2).
		// An ip rule carries a SINGLE dscp, so a term with several `from dscp`
		// values expands to one rule per DSCP (× the src/dst cross-product).
		//
		// #7796: DSCP 0 (be / cs0 / numeric 0) IS representable and is no longer
		// dropped. The old drop was correct only for the legacy tos selector,
		// where a zero byte is indistinguishable from "no selector" and therefore
		// matches ANY DSCP. The rule now carries FRA_DSCP, where the ATTRIBUTE'S
		// PRESENCE is the selector and its value is free to be 0 — the kernel
		// renders such a rule as "dscp default" and matches only DSCP 0. Keeping
		// the drop would have left `from dscp be` / `cs0` silently non-functional
		// after the crash for every OTHER value was fixed.
		//
		// An UNPARSEABLE dscp is a different failure from DSCP 0 and now says so.
		// dscpToTOS returned 0 both for `cs0`/`be` and for an unrecognised name, so
		// a typo was reported as "matches DSCP 0" — a misleading message about a
		// value the operator never wrote.
		type dscpEntry struct {
			dscp uint8
			set  bool
		}
		var dscps []dscpEntry
		hadDSCP := false
		for _, d := range term.DSCPs {
			if d == "" {
				continue
			}
			hadDSCP = true
			v, ok := dscpValue(d)
			if !ok {
				errs = append(errs, fmt.Errorf(
					"PBR filter %s term %s matches unknown DSCP %q (expected a DiffServ "+
						"name such as ef/af31/cs3/be, or a number 0-63); steering for this "+
						"match is dropped",
					filter.Name, term.Name, d))
				continue
			}
			dscps = append(dscps, dscpEntry{dscp: v, set: true})
		}
		if hadDSCP {
			if len(dscps) == 0 {
				// Every DSCP this term matched was unparseable (all dropped above).
				// Emitting an address-only sentinel rule here would over-match
				// ALL DSCP, so skip the term entirely — the degraded error is
				// already recorded.
				continue
			}
		} else {
			// No DSCP constraint: a single unset entry so the address-only case
			// still emits one rule (no dscp selector).
			dscps = []dscpEntry{{dscp: 0, set: false}}
		}

		// Resolve source / destination scope, expanding prefix-lists and
		// normalizing any/bare-host tokens (#3430 M1, M2). A direction that
		// matches NOTHING (constrained-but-empty positive set) skips the whole
		// term; an unrepresentable except set degrades the build.
		srcs, srcSkip, srcErr := resolvePBRDirection(
			term.SourceAddresses, term.SourcePrefixLists, pls, filter.Name, term.Name, "source")
		dsts, dstSkip, dstErr := resolvePBRDirection(
			term.DestAddresses, term.DestPrefixLists, pls, filter.Name, term.Name, "destination")
		if srcErr != nil {
			errs = append(errs, srcErr)
		}
		if dstErr != nil {
			errs = append(errs, dstErr)
		}
		if srcErr != nil || dstErr != nil || srcSkip || dstSkip {
			// Either unrepresentable (already recorded) or matches nothing —
			// emit no rule for this term in both cases (fail-safe: never widen).
			continue
		}

		hasDSCP := false
		for _, t := range dscps {
			if t.set {
				hasDSCP = true
				break
			}
		}
		srcConstrained := !(len(srcs) == 1 && srcs[0] == "")
		dstConstrained := !(len(dsts) == 1 && dsts[0] == "")
		// A protocol / source-port / destination-port constraint is now an
		// ip-rule-compatible criterion (#3730), so a term carrying only an L4
		// predicate is no longer a no-op under-steer — it emits an ip rule with
		// the L4 selector.
		hasL4 := len(protos) > 0 || len(sports) > 0 || len(dports) > 0
		if !hasDSCP && !srcConstrained && !dstConstrained && !hasL4 {
			// A truly unconstrained `then routing-instance` term (no dscp, no
			// address, no L4) would program `from all to all iif <if> lookup <vr>`.
			// Even with the #5117 iif selector scoping it to the attached
			// interface, xpf conservatively declines to emit an interface-wide
			// catch-all steer here (fail-safe under-steer), matching the pre-#3730
			// behavior; the userspace filter path still enforces the term exactly.
			slog.Warn("PBR: filter term has routing-instance but no ip-rule-compatible criteria (dscp, address, protocol, port)",
				"filter", filter.Name, "term", term.Name)
			continue
		}

		// Normalize each L4 dimension to a single "unset" entry when the term did
		// not constrain it, so the cross-product still emits one rule per
		// dscp × src × dst combination (IPProto 0 / nil port = no selector).
		if len(protos) == 0 {
			protos = []int{0}
		}
		if len(sports) == 0 {
			sports = []*PBRPortRange{nil}
		}
		if len(dports) == 0 {
			dports = []*PBRPortRange{nil}
		}

		// #5683: cap the expansion BEFORE materializing it. The term expands to
		// exactly len(toses)×len(protos)×len(sports)×len(dports)×len(srcs)×len(dsts)
		// ip rules; computing that product from the dimension lengths is O(1) and
		// cannot overflow (pbrTermProduct saturates). A term whose product would
		// exhaust the remaining priority-window budget is dropped WHOLE (fail-safe
		// under-steer, matching the unrepresentable/unknown-DSCP drops above) rather than
		// allocating millions of PBRRule structs and truncating — the pre-cap
		// memory/CPU exhaustion the 1000-rule cap was meant to bound but did not.
		remaining := budget - len(rules)
		product := pbrTermProduct(len(dscps), len(protos), len(sports), len(dports), len(srcs), len(dsts))
		if remaining < 0 || product > remaining {
			errs = append(errs, fmt.Errorf(
				"PBR filter %s term %s expands to %s policy-based-routing ip rules "+
					"(DSCP×protocol×source-port×destination-port×source×destination "+
					"cross-product), which exceeds the remaining %d-rule budget of the "+
					"%d-rule limit; steering for this term is dropped (fail-safe "+
					"under-steer to the main table) — tighten the match (fewer source/"+
					"destination addresses, DSCP values, protocols, or ports) so the "+
					"total stays within %d rules",
				filter.Name, term.Name, pbrProductString(product), max(remaining, 0),
				maxPBRRules, maxPBRRules))
			return rules, errs, true
		}

		for _, t := range dscps {
			for _, proto := range protos {
				for _, sp := range sports {
					for _, dp := range dports {
						for _, src := range srcs {
							for _, dst := range dsts {
								rules = append(rules, PBRRule{
									Family:   family,
									DSCP:     t.dscp,
									DSCPSet:  t.set,
									IPProto:  proto,
									Sport:    sp,
									Dport:    dp,
									Src:      src,
									Dst:      dst,
									TableID:  tableID,
									Instance: term.RoutingInstance,
								})
							}
						}
					}
				}
			}
		}
	}
	return rules, errs, false
}

// pbrTermProduct returns the size of a routing-instance term's Cartesian
// expansion (the product of its per-dimension counts) SATURATED at
// maxPBRRules+1, so a pathological config whose dimensions multiply past the
// int range cannot overflow — the exact magnitude past the cap is irrelevant,
// only that it EXCEEDS the bound. Each dimension is normalized to at least 1 by
// the caller (an unconstrained dimension still contributes one rule), but a
// defensive floor of 1 is applied here too. O(dimensions), never O(product):
// it multiplies the slice lengths, it never visits a tuple.
func pbrTermProduct(dims ...int) int {
	const ceil = maxPBRRules + 1
	product := 1
	for _, d := range dims {
		if d < 1 {
			d = 1
		}
		if d > ceil {
			return ceil
		}
		product *= d
		if product > maxPBRRules {
			return ceil
		}
	}
	return product
}

// pbrProductString renders a saturated pbrTermProduct count for an operator
// error: an exact count under the cap, or ">N" once the product saturated at
// the ceiling (the true magnitude was deliberately never computed).
func pbrProductString(product int) string {
	if product > maxPBRRules {
		return fmt.Sprintf(">%d", maxPBRRules)
	}
	return strconv.Itoa(product)
}

// pbrTermL4 classifies a routing-instance term's L4 / per-packet `from`
// predicates against what a kernel `ip rule` can express (#3730).
//
// It returns the REPRESENTABLE dimensions the caller folds into the ip-rule
// cross-product — protos (FRA_IP_PROTO values), sports and dports
// (FRA_SPORT_RANGE / FRA_DPORT_RANGE) — plus unrep, the list of predicates the
// term carries that an ip rule CANNOT represent. A non-empty unrep means the
// caller must FAIL CLOSED (drop the whole term + degrade); honoring the
// representable half while dropping the rest would widen the steer beyond what
// the operator authored (the #3730 over-steer). Unknown protocol names,
// protocol 0 (HOPOPT, which the netlink FRA_IP_PROTO>0 emit condition cannot
// express), and unparseable ports are also reported as unrep so they fail
// closed rather than silently narrowing/widening the match.
func pbrTermL4(term *config.FirewallFilterTerm) (protos []int, sports, dports []*PBRPortRange, unrep []string) {
	// Predicates an ip rule has no selector for at all.
	if hasRealString(term.SourcePortsExcept) {
		unrep = append(unrep, "source-port-except")
	}
	if hasRealString(term.DestPortsExcept) {
		unrep = append(unrep, "destination-port-except")
	}
	if len(term.TCPFlags) > 0 {
		unrep = append(unrep, "tcp-flags")
	}
	if term.IsFragment {
		unrep = append(unrep, "is-fragment")
	}
	if len(term.ICMPTypes) > 0 || len(term.UnknownICMPTypes) > 0 {
		unrep = append(unrep, "icmp-type")
	}
	if len(term.ICMPCodes) > 0 || len(term.UnknownICMPCodes) > 0 {
		unrep = append(unrep, "icmp-code")
	}
	if term.FlexMatch != nil || len(term.UnknownFlexMatch) > 0 {
		unrep = append(unrep, "flexible-match-range")
	}
	for _, f := range term.UnknownFrom {
		unrep = append(unrep, "unsupported from-match "+f)
	}

	// Representable: `from protocol` → one FRA_IP_PROTO value per protocol.
	for _, p := range term.Protocols {
		if strings.TrimSpace(p) == "" {
			continue
		}
		n, ok := appid.ProtocolNumber(p)
		if !ok || n == 0 {
			unrep = append(unrep, fmt.Sprintf("protocol %q", p))
			continue
		}
		protos = append(protos, int(n))
	}

	// Representable: `from source-port` / `from destination-port` → one
	// FRA_SPORT_RANGE / FRA_DPORT_RANGE per port spec (a range maps to [lo,hi]).
	for _, spec := range term.SourcePorts {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		lo, hi, ok := config.ResolveFilterPortRange(spec)
		if !ok {
			unrep = append(unrep, fmt.Sprintf("source-port %q", spec))
			continue
		}
		sports = append(sports, &PBRPortRange{Lo: lo, Hi: hi})
	}
	for _, spec := range term.DestinationPorts {
		if strings.TrimSpace(spec) == "" {
			continue
		}
		lo, hi, ok := config.ResolveFilterPortRange(spec)
		if !ok {
			unrep = append(unrep, fmt.Sprintf("destination-port %q", spec))
			continue
		}
		dports = append(dports, &PBRPortRange{Lo: lo, Hi: hi})
	}
	return protos, sports, dports, unrep
}

// hasRealString reports whether the slice carries at least one non-empty
// (trimmed) entry — the "constrained" test for a firewall-filter match list.
func hasRealString(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// resolvePBRDirection resolves one direction (source or destination) of a
// firewall-filter term into the CIDR match strings for ip-rule generation,
// applying the same prefix-list + empty-set + except semantics as the
// userspace snapshot builder (resolvePrefixListAddrs) and then mapping them
// onto what an `ip rule from/to` selector can express (#3430 M1, M2).
//
// Returns:
//   - matches: the CIDRs to emit, one rule each. The single element "" means
//     "no selector" (match any).
//   - skip: the direction matches NOTHING (a constrained-but-empty positive
//     set, e.g. an empty / unresolved positive prefix-list). The caller emits
//     no rule for the term — omitting the rule is the correct realization of
//     "steer nothing" for FBF (an omitted rule cannot steer).
//   - err: the direction cannot be represented as an ip rule (a non-empty
//     address `except` set; ip rule has no negated from/to). The caller skips
//     the term (fail-safe: never steer the wrong traffic) and reports degraded.
func resolvePBRDirection(
	literal []string,
	refs []config.PrefixListRef,
	pls map[string]*config.PrefixList,
	filterName, termName, direction string,
) (matches []string, skip bool, err error) {
	constrained := len(literal) > 0 || len(refs) > 0
	if !constrained {
		return []string{""}, false, nil
	}

	var positive []string
	hasPositiveRef := false
	hasExcept := false
	exceptCount := 0
	unconstrainedSeen := false

	addNorm := func(tok string) error {
		cidr, unc, e := normalizePBRAddr(tok)
		if e != nil {
			return e
		}
		if unc {
			unconstrainedSeen = true
			return nil
		}
		positive = append(positive, cidr)
		return nil
	}

	for _, tok := range literal {
		if e := addNorm(tok); e != nil {
			return nil, false, fmt.Errorf("PBR %s address %q (filter %s term %s): %w",
				direction, tok, filterName, termName, e)
		}
	}
	for _, ref := range refs {
		pl := pls[ref.Name]
		if pl == nil {
			// Unresolved reference. The strict gate rejects this at commit; on
			// the tolerant/peer-sync path it contributes no prefixes, but the
			// direction stays constrained so we fail closed (positive) /
			// match-all (except) per the empty-set semantics below.
			slog.Warn("PBR: filter prefix-list reference unresolved",
				"filter", filterName, "term", termName, "direction", direction,
				"prefix-list", ref.Name)
			if ref.Except {
				hasExcept = true
			} else {
				hasPositiveRef = true
			}
			continue
		}
		if ref.Except {
			hasExcept = true
			exceptCount += len(pl.Prefixes)
		} else {
			hasPositiveRef = true
			for _, p := range pl.Prefixes {
				if e := addNorm(p); e != nil {
					slog.Warn("PBR: skipping unparseable prefix-list entry",
						"filter", filterName, "term", termName, "direction", direction,
						"prefix-list", ref.Name, "prefix", p, "err", e)
				}
			}
		}
	}

	// Pure-except: an `except` set is the SOLE scope for this direction.
	if hasExcept && len(positive) == 0 && !hasPositiveRef && !unconstrainedSeen {
		if exceptCount == 0 {
			// "match every source NOT in {}" = match ALL.
			return []string{""}, false, nil
		}
		// "match every source NOT in <set>" — ip rule has no negated selector.
		return nil, false, fmt.Errorf(
			"PBR %s scope of filter %s term %s uses a non-empty `except` prefix-list, "+
				"which an ip rule cannot represent (no negated from/to); steering for "+
				"this term is dropped — express the complement explicitly or use the "+
				"userspace filter path", direction, filterName, termName)
	}

	if hasExcept {
		// Mixed positive + except in one direction: commit-rejected
		// (validateFilterAddressExceptStrict, #3359); reaches here only on the
		// tolerant/peer-sync path. POSITIVE-WINS — ignore the except prefixes
		// (mirrors resolvePrefixListAddrs); fail-safe (never widen the steer).
		slog.Warn("PBR: filter term mixes positive addresses with an except "+
			"prefix-list in one direction; the except modifier is ignored "+
			"(positive-wins)",
			"filter", filterName, "term", termName, "direction", direction)
	}

	if unconstrainedSeen {
		// An `any` / 0.0.0.0/0 / ::/0 token widens the direction to match all.
		return []string{""}, false, nil
	}
	if len(positive) == 0 {
		// Constrained but resolved to no prefixes — matches nothing. For FBF
		// "steer nothing" is realized by emitting no rule (skip the term).
		return nil, true, nil
	}
	return positive, false, nil
}

// normalizePBRAddr maps a firewall-filter address token onto an ip-rule CIDR,
// mirroring the userspace filter compiler (#3430 M1):
//   - "any" (and 0.0.0.0/0 / ::/0) → unconstrained (no from/to selector).
//   - a bare host IP → /32 (IPv4) or /128 (IPv6).
//   - a literal CIDR → passed through unchanged.
//   - anything else → error (the caller fails closed instead of widening).
func normalizePBRAddr(tok string) (cidr string, unconstrained bool, err error) {
	t := strings.TrimSpace(tok)
	if t == "" || strings.EqualFold(t, "any") {
		return "", true, nil
	}
	if ip := net.ParseIP(t); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", false, nil
		}
		return ip.String() + "/128", false, nil
	}
	if _, n, e := net.ParseCIDR(t); e == nil {
		if ones, _ := n.Mask.Size(); ones == 0 {
			return "", true, nil // 0.0.0.0/0 or ::/0 — match all
		}
		return t, false, nil
	}
	return "", false, fmt.Errorf("unparseable address %q", tok)
}

// dscpToTOS converts a DSCP name or numeric value to a TOS byte.
// TOS byte = DSCP value << 2 (DSCP occupies the upper 6 bits of the TOS byte).
func dscpValue(dscp string) (uint8, bool) {
	// DSCP name → 6-bit code point (same values as dataplane.DSCPValues).
	//
	// #7796: this returns the RAW code point, not DSCP << 2. The shift existed
	// to build a legacy TOS byte, and that shift was the defect — the kernel
	// masks the tos byte to IPTOS_TOS_MASK and rejects everything from cs1 up.
	//
	// It also returns an explicit ok flag. The previous dscpToTOS returned 0
	// both for the legitimate zero code points (cs0 / be / "0") and for an
	// unrecognised name, so the caller could not tell "match best-effort" from
	// "the operator typed a DSCP that does not exist" and reported both as
	// "matches DSCP 0".
	dscpValues := map[string]uint8{
		"ef":   46,
		"af11": 10, "af12": 12, "af13": 14,
		"af21": 18, "af22": 20, "af23": 22,
		"af31": 26, "af32": 28, "af33": 30,
		"af41": 34, "af42": 36, "af43": 38,
		"cs0": 0, "cs1": 8, "cs2": 16, "cs3": 24,
		"cs4": 32, "cs5": 40, "cs6": 48, "cs7": 56,
		"be": 0,
	}

	name := strings.ToLower(dscp)
	if val, ok := dscpValues[name]; ok {
		return val, true
	}
	if v, err := strconv.Atoi(dscp); err == nil && v >= 0 && v <= maxDSCP {
		return uint8(v), true
	}
	return 0, false
}

// resolveRibTable maps a Junos rib name to its kernel routing table ID.
// "<instance>.inet.0" or "<instance>.inet6.0" maps to the instance's table.
//
// The boolean return distinguishes "resolved to a real table" (ok=true)
// from "unresolvable rib name" (ok=false) — a name that is neither
// inet.0/inet6.0 nor "<known-instance>.inet[6].0". Callers MUST treat
// ok=false as "unknown rib": never fall back to table 0 (#2226). Before
// this split the unresolvable case returned a bare 0, which the Apply
// needsLeak loop read as a real (non-source) table and spuriously
// installed an `ip rule from all lookup <sourceTable>` for a typo'd /
// non-existent import-rib — a silent mis-leak of the source table into
// the main lookup. Commit-time validation
// (validateRibGroupImportRibReferencesStrict) now also rejects the
// dangling reference; this guard is defense in depth for any reference
// that reaches apply via the tolerant load / peer-sync path.
func resolveRibTable(ribName string, tableIDs map[string]int) (int, bool) {
	if ribName == "inet.0" || ribName == "inet6.0" {
		return mainTableID, true // main table
	}
	// Parse "<instance>.inet.0" or "<instance>.inet6.0" with an EXACT family
	// suffix — a loose ".inet" substring match would accept malformed names
	// like "<instance>.inetX.0" or "<instance>.inet.0.garbage" and resolve
	// them to the instance table (#2253). ribInstanceFromName returns the
	// instance only for the two valid unicast families.
	if instanceName, ok := ribInstanceFromName(ribName); ok {
		if tableID, ok := tableIDs[instanceName]; ok {
			return tableID, true
		}
	}
	return 0, false
}

// ribInstanceFromName extracts the routing-instance prefix from a non-default
// rib name of the EXACT form "<instance>.inet.0" or "<instance>.inet6.0",
// returning ok=false for any other shape. The instance prefix must be
// non-empty. Junos rib names are exactly "<table>.inet.0" (IPv4 unicast) or
// "<table>.inet6.0" (IPv6 unicast); bare "inet.0" / "inet6.0" (the main
// table) are handled by the caller and are NOT treated as instance ribs here.
// Malformed family tokens (".inetX.0", ".inetfoo.0", ".inet60.0") and trailing
// garbage (".inet.0.x") return ok=false so the caller rejects them rather than
// silently mapping a typo'd rib onto the instance table (#2253). This mirrors
// pkg/config.ribInstanceFromName — the two MUST stay in lockstep so the
// commit-time gate and the runtime applier agree on what resolves (#2226).
func ribInstanceFromName(ribName string) (string, bool) {
	for _, suffix := range []string{".inet.0", ".inet6.0"} {
		if instance, ok := strings.CutSuffix(ribName, suffix); ok && instance != "" {
			return instance, true
		}
	}
	return "", false
}

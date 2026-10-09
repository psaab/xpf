// probe_pin.go implements the RPM probe next-hop pin reconciler
// (#1827 PR-1a §4.2.4).
//
// Each RPM test with a `next-hop` gets a deterministic per-test fwmark +
// per-test kernel routing table (mark config.ProbeFwmarkBase+idx, table
// config.ProbeTableBase+idx, idx assigned in sorted probe/test order),
// one `ip rule fwmark <mark> lookup <table>` in the reserved priority
// band 50-99, and the pinned /32 (/128) host route installed with an
// explicit `dev` + `onlink` in the per-test table. Probe sockets set
// SO_MARK with the same mark (pkg/rpm), so ONLY probe traffic follows
// the pin: the rules and tables are invisible to transit traffic (fast
// path AND kernel slow path), are NOT rendered into FRR, and are NOT
// part of the dataplane snapshot.
//
// Per-test tables make "same target via two uplinks" (the normal
// dual-WAN probe pattern) first-class. Startup sweeps the band only on
// hosts xpf owns, so a crashed daemon never leaks stale pins there while
// uncommitted foreign-host boots preserve rules and routes in the shared
// bands (AGY r2-3). Pin state follows the prober lifecycle, not config
// lifecycle.
package routing

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ProbePin describes one RPM test's next-hop pin: the fwmark rule plus
// the pinned host route in the per-test probe table.
type ProbePin struct {
	TestKey   string // "probe/test" — matches the pkg/rpm results key
	Index     int    // deterministic index in sorted probe/test order
	Mark      uint32 // fwmark (config.ProbeFwmarkBase + Index)
	Table     int    // kernel routing table (config.ProbeTableBase + Index)
	Priority  int    // ip-rule priority (config.ProbeRulePriorityBase + Index)
	Target    string // probe target IP literal
	NextHop   string // pinned next-hop IP
	Interface string // Linux egress interface name (resolved)
}

// BuildProbePins computes the deterministic pin assignment for every
// RPM test that configures a next-hop. The assignment is in sorted
// probe-name then test-name order so both the rule programmer (this
// package) and the SO_MARK socket option (pkg/rpm) derive identical
// marks from the same config. rethMap translates Junos RETH interface
// names to physical member names (e.g. "reth0.50" → "ge-0-0-2.50").
func BuildProbePins(rpmCfg *config.RPMConfig, rethMap map[string]string) []ProbePin {
	if rpmCfg == nil || len(rpmCfg.Probes) == 0 {
		return nil
	}
	probeNames := make([]string, 0, len(rpmCfg.Probes))
	for name := range rpmCfg.Probes {
		probeNames = append(probeNames, name)
	}
	sort.Strings(probeNames)

	var pins []ProbePin
	idx := 0
	for _, pn := range probeNames {
		probe := rpmCfg.Probes[pn]
		if probe == nil {
			continue
		}
		testNames := make([]string, 0, len(probe.Tests))
		for name := range probe.Tests {
			testNames = append(testNames, name)
		}
		sort.Strings(testNames)
		for _, tn := range testNames {
			test := probe.Tests[tn]
			if test == nil || test.NextHop == "" {
				continue
			}
			if idx >= config.ProbeTableCount {
				// Commit validation caps this; defensive guard so a
				// non-strict-path config can never program outside the
				// reserved band.
				slog.Warn("probe pin band exhausted; ignoring further next-hop pins",
					"probe", pn, "test", tn, "limit", config.ProbeTableCount)
				return pins
			}
			pins = append(pins, ProbePin{
				TestKey:   pn + "/" + tn,
				Index:     idx,
				Mark:      uint32(config.ProbeFwmarkBase + idx),
				Table:     config.ProbeTableBase + idx,
				Priority:  config.ProbeRulePriorityBase + idx,
				Target:    test.Target,
				NextHop:   test.NextHop,
				Interface: ResolveProbeInterface(test.DestinationInterface, rethMap),
			})
			idx++
		}
	}
	return pins
}

// ResolveProbeInterface translates a Junos interface/unit name into the
// Linux kernel interface name used for SO_BINDTODEVICE and the pinned
// route's `dev`: RETH base names resolve through rethMap to the local
// physical member, slashes become dashes, and the default ".0" unit
// suffix is stripped (VLAN units like ".50" are real kernel names and
// are preserved). Mirrors the FRR static-route name translation.
//
// #7173: on a rethMap MISS the RETH base falls through to
// config.LinuxIfName(base) — the raw translated Junos name — rather than
// failing here. The resulting name will not resolve. The routing manager
// reports a missing pin, but daemon admin-up filtering does not retain that
// hold for a missing egress; RPM's SO_BINDTODEVICE setup then fails with
// ENODEV, and ErrProbeSetup holds the probe without treating it as path loss.
// A probe silently sent on the wrong interface, or with no interface at all,
// would report reachability it never measured and could drive ip-monitoring
// route injection off it.
//
// So do not "fix" the miss by substituting a default interface or dropping
// the pin — either turns a held probe into a false-passing one.
func ResolveProbeInterface(name string, rethMap map[string]string) string {
	if name == "" {
		return ""
	}
	parts := strings.SplitN(name, ".", 2)
	base := parts[0]
	if phys, ok := rethMap[base]; ok && phys != "" {
		base = phys
	}
	base = config.LinuxIfName(base)
	if len(parts) == 2 && parts[1] != "0" {
		return base + "." + parts[1]
	}
	return base
}

// probePinOps is the narrow netlink surface the probe-pin reconciler
// uses. Satisfied by *netlink.Handle; tests substitute a fake.
type probePinOps interface {
	RuleAdd(*netlink.Rule) error
	RuleDel(*netlink.Rule) error
	RuleList(family int) ([]netlink.Rule, error)
	RouteAdd(*netlink.Route) error
	RouteDel(*netlink.Route) error
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	LinkByName(name string) (netlink.Link, error)
}

// probePinManager reconciles probe pin rules + routes. Stateless apart
// from the borrowed probePinOps; it reconciles against live kernel
// state (clear-then-program, like the rules.go reconcilers).
type probePinManager struct {
	ops probePinOps
}

// Apply clears the probe-pin band and programs one fwmark rule + one
// pinned host route per pin. It returns a map keyed by ProbePin.TestKey
// containing ONLY the pins whose kernel install failed (invalid
// target/next-hop, missing egress link, RuleAdd/RouteAdd error), with
// the wrapped cause; an empty/nil map means every pin installed. When
// RouteAdd fails after a successful RuleAdd, the fwmark rule is rolled
// back so a partial install does not persist (best-effort: if the
// rollback RuleDel itself fails, the stale rule is logged and left for
// the next apply's band clear() to sweep — the pin is reported failed
// either way, so the probe holds rather than probing unpinned, #1895).
//
// Before #1895 every failure mode here was log-and-continue with an
// unconditional nil return — the probe then ran with an unbacked
// SO_MARK, fell through to the main table, and reported the *pinned
// uplink* healthy (false PASS, failover suppression). Callers now
// thread the failed-pin map into pkg/rpm so affected tests hold state
// (ErrProbeSetup) instead of probing the wrong path.
func (p *probePinManager) Apply(pins []ProbePin) map[string]error {
	if err := p.clear(); err != nil {
		slog.Warn("failed to clear probe pin band", "err", err)
	}
	var failed map[string]error
	fail := func(pin ProbePin, err error) {
		if failed == nil {
			failed = make(map[string]error)
		}
		failed[pin.TestKey] = err
	}
	for _, pin := range pins {
		target := net.ParseIP(pin.Target)
		nextHop := net.ParseIP(pin.NextHop)
		if target == nil || nextHop == nil {
			slog.Warn("probe pin: invalid target/next-hop",
				"test", pin.TestKey, "target", pin.Target, "next_hop", pin.NextHop)
			fail(pin, fmt.Errorf("invalid target %q / next-hop %q", pin.Target, pin.NextHop))
			continue
		}
		family := unix.AF_INET
		hostBits := 32
		if target.To4() == nil {
			family = unix.AF_INET6
			hostBits = 128
		}

		link, err := p.ops.LinkByName(pin.Interface)
		if err != nil {
			slog.Warn("probe pin: egress interface not found",
				"test", pin.TestKey, "interface", pin.Interface, "err", err)
			fail(pin, fmt.Errorf("egress interface %q: %w", pin.Interface, err))
			continue
		}

		rule := netlink.NewRule()
		rule.Family = family
		rule.Mark = pin.Mark
		rule.Table = pin.Table
		rule.Priority = pin.Priority
		if err := p.ops.RuleAdd(rule); err != nil {
			slog.Warn("probe pin: failed to add fwmark rule",
				"test", pin.TestKey, "mark", pin.Mark, "table", pin.Table, "err", err)
			fail(pin, fmt.Errorf("fwmark rule add (mark %#x, table %d): %w",
				pin.Mark, pin.Table, err))
			continue
		}

		route := &netlink.Route{
			Dst:       &net.IPNet{IP: target, Mask: net.CIDRMask(hostBits, hostBits)},
			Gw:        nextHop,
			LinkIndex: link.Attrs().Index,
			Table:     pin.Table,
			Flags:     int(netlink.FLAG_ONLINK),
		}
		if err := p.ops.RouteAdd(route); err != nil {
			slog.Warn("probe pin: failed to add pinned route",
				"test", pin.TestKey, "target", pin.Target,
				"next_hop", pin.NextHop, "table", pin.Table, "err", err)
			// Roll back the fwmark rule so a partial install never
			// persists: a rule over an empty band table is stale state
			// (empty-table lookups fall through, but a later stale or
			// leftover route would silently re-route the probe). The
			// band clear() on the next apply remains the backstop if
			// the rollback itself fails.
			if delErr := p.ops.RuleDel(rule); delErr != nil {
				slog.Warn("probe pin: failed to roll back fwmark rule after route failure",
					"test", pin.TestKey, "mark", pin.Mark, "table", pin.Table, "err", delErr)
			}
			fail(pin, fmt.Errorf("pinned route add (table %d): %w", pin.Table, err))
			continue
		}
		slog.Info("probe pin programmed",
			"test", pin.TestKey, "target", pin.Target, "next_hop", pin.NextHop,
			"interface", pin.Interface, "mark", fmt.Sprintf("%#x", pin.Mark),
			"table", pin.Table)
	}
	return failed
}

// clear removes all ip rules in the probe-pin priority band and flushes
// every route in the reserved probe tables (both families). The daemon's
// startup caller runs this only when xpf owns host routing posture; Apply
// also uses it before reprogramming configured pins.
//
// A RuleList/RouteListFiltered dump failure is aggregated and returned
// (errors.Join, mirroring the pattern in rules.go) rather than silently
// skipped (#4822): a swallowed dump failure meant clear()'s wired-up
// error return could never fire, so Apply()'s caller had no way to detect
// an incomplete band clear (stale rules/routes from a removed pin can
// survive and mis-route a later probe cycle). Per-item RuleDel/RouteDel
// failures on an item we DID enumerate stay Debug-only best-effort — the
// band clear() on the NEXT apply remains the backstop for those, same as
// before.
func (p *probePinManager) clear() error {
	var errs []error
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := p.ops.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule list (family %d): %w", family, err))
			continue
		}
		for _, r := range rules {
			if r.Priority >= config.ProbeRulePriorityBase &&
				r.Priority < config.ProbeRulePriorityBase+config.ProbeTableCount {
				if err := p.ops.RuleDel(&r); err != nil {
					slog.Debug("failed to delete stale probe pin rule",
						"priority", r.Priority, "err", err)
				}
			}
		}
		for table := config.ProbeTableBase; table < config.ProbeTableBase+config.ProbeTableCount; table++ {
			routes, err := p.ops.RouteListFiltered(family,
				&netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil {
				errs = append(errs, fmt.Errorf("route list (family %d, table %d): %w", family, table, err))
				continue
			}
			for i := range routes {
				if err := p.ops.RouteDel(&routes[i]); err != nil {
					slog.Debug("failed to delete stale probe pin route",
						"table", table, "err", err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

// wantPin is a validated pin plus its resolved readback expectations.
type wantPin struct {
	pin      ProbePin
	family   int // unix.AF_INET / unix.AF_INET6, from the target literal
	hostBits int // 32 / 128
	target   net.IP
	nextHop  net.IP
	linkIdx  int
}

func resolveProbePin(ops probePinOps, pin ProbePin) (wantPin, error) {
	if pin.Index < 0 || pin.Index >= config.ProbeTableCount ||
		pin.Table != config.ProbeTableBase+pin.Index ||
		pin.Priority != config.ProbeRulePriorityBase+pin.Index ||
		pin.Mark != uint32(config.ProbeFwmarkBase+pin.Index) {
		return wantPin{}, fmt.Errorf("invalid probe pin assignment (index %d, mark %#x, table %d, priority %d)",
			pin.Index, pin.Mark, pin.Table, pin.Priority)
	}
	target := net.ParseIP(pin.Target)
	nextHop := net.ParseIP(pin.NextHop)
	if target == nil || nextHop == nil {
		return wantPin{}, fmt.Errorf("invalid target %q / next-hop %q", pin.Target, pin.NextHop)
	}
	targetV4, nextHopV4 := target.To4(), nextHop.To4()
	family := unix.AF_INET
	hostBits := 32
	if targetV4 != nil {
		if nextHopV4 == nil {
			return wantPin{}, fmt.Errorf("target %q and next-hop %q use different address families", pin.Target, pin.NextHop)
		}
		target, nextHop = targetV4, nextHopV4
	} else {
		if nextHopV4 != nil {
			return wantPin{}, fmt.Errorf("target %q and next-hop %q use different address families", pin.Target, pin.NextHop)
		}
		target, nextHop = target.To16(), nextHop.To16()
		if target == nil || nextHop == nil {
			return wantPin{}, fmt.Errorf("invalid target %q / next-hop %q", pin.Target, pin.NextHop)
		}
		family = unix.AF_INET6
		hostBits = 128
	}
	link, err := ops.LinkByName(pin.Interface)
	if err != nil {
		return wantPin{}, fmt.Errorf("egress interface %q: %w", pin.Interface, err)
	}
	var linkIndex int
	if link != nil {
		if attrs := link.Attrs(); attrs != nil {
			linkIndex = attrs.Index
		}
	}
	if linkIndex <= 0 {
		return wantPin{}, fmt.Errorf("egress interface %q: link has no valid ifindex", pin.Interface)
	}
	return wantPin{
		pin: pin, family: family, hostBits: hostBits,
		target: target, nextHop: nextHop, linkIdx: linkIndex,
	}, nil
}

// Verify reads back the kernel's probe-pin rules and routes and reports the
// pins whose install is missing or no longer matches, keyed by
// ProbePin.TestKey; a nil map means every pin is healthy. Read-only: it
// issues RuleList/RouteListFiltered/LinkByName only and never adds, deletes,
// or otherwise mutates kernel state.
//
// Verify exists because the kernel can delete a pin's table-7000+ routes
// behind the daemon's back — administratively downing/upping the egress
// interface, or removing its last IPv4 address, flushes the per-test table
// while the fwmark rule survives. A rule-only pin then looks installed but
// steers the probe nowhere (#12088): Verify requires BOTH the exact fwmark
// rule Apply installs (family, mark, full mask, priority, table, no
// narrowing selectors) AND the exact pinned host route (host destination,
// next-hop, egress ifindex, ONLINK, unicast, single-path) before it
// accepts a pin. Genuinely missing or mismatched pins hold ErrProbeSetup and
// are reinstalled via Apply on reconcile, preventing a false-passing probe;
// ambiguous pin shape fails closed:
//
//   - an inconsistent probe-band assignment, malformed or mixed-family
//     target/next-hop, missing egress link, or rule/route dump error is
//     reported for the affected pin(s) rather than skipped;
//   - a rule with a partial fwmark mask, or any Src/Dst/interface/Tos/
//     port/proto/UID/invert/goto/flow/suppression selector Apply never emits,
//     does not satisfy the pin even when mark/table/priority match;
//   - a route with the wrong gateway, egress, host prefix, table, family-default
//     metric, required ONLINK flag, type, or scope fails; DEAD without LINKDOWN,
//     unresolved nexthops, and equal-or-better-metric competing routes to the
//     same host also fail.
//
// RTNH_F_LINKDOWN is deliberately NOT in the fail set: it is a carrier-loss
// flag, not proof that the installed pin is unusable. The kernel may skip
// DEAD|LINKDOWN nexthops for lookups when ignore_routes_with_linkdown=1;
// SO_BINDTODEVICE confines RPM to the configured egress, so carrier loss must
// flow through the loss threshold instead of holding the test. Holding the
// pin on LINKDOWN would freeze LastStatus and suppress ip-monitoring failover
// for the outage (blackhole).
//
// Dumps are bounded: one RuleList per address family that has at least one
// valid pin, and one RouteListFiltered per (family, configured table); a
// zero-pin call performs no kernel reads at all.
func (p *probePinManager) Verify(pins []ProbePin) map[string]error {
	if len(pins) == 0 {
		return nil
	}
	var failed map[string]error
	fail := func(pin ProbePin, err error) {
		if failed == nil {
			failed = make(map[string]error)
		}
		failed[pin.TestKey] = err
	}
	var want []wantPin
	families := make(map[int]bool, 2)
	for _, pin := range pins {
		w, err := resolveProbePin(p.ops, pin)
		if err != nil {
			fail(pin, err)
			continue
		}
		want = append(want, w)
		families[w.family] = true
	}
	if len(want) == 0 {
		return failed
	}
	rulesByFamily := make(map[int][]netlink.Rule, 2)
	ruleErrByFamily := make(map[int]error, 2)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		if !families[family] {
			continue
		}
		rules, err := p.ops.RuleList(family)
		if err != nil {
			ruleErrByFamily[family] = err
			continue
		}
		rulesByFamily[family] = rules
	}
	type tableKey struct {
		family int
		table  int
	}
	routesByTable := make(map[tableKey][]netlink.Route)
	routeErrByTable := make(map[tableKey]error)
	dumped := make(map[tableKey]bool)
	for _, w := range want {
		if _, hasRuleErr := ruleErrByFamily[w.family]; hasRuleErr {
			continue
		}
		k := tableKey{family: w.family, table: w.pin.Table}
		if dumped[k] {
			continue
		}
		dumped[k] = true
		routes, err := p.ops.RouteListFiltered(w.family,
			&netlink.Route{Table: w.pin.Table}, netlink.RT_FILTER_TABLE)
		if err != nil {
			routeErrByTable[k] = err
			continue
		}
		routesByTable[k] = routes
	}
	for _, w := range want {
		if err, ok := ruleErrByFamily[w.family]; ok {
			fail(w.pin, fmt.Errorf("probe pin rule list (family %d): %w", w.family, err))
			continue
		}
		if !probePinRuleInstalled(rulesByFamily[w.family], w.pin, w.family) {
			fail(w.pin, fmt.Errorf("probe pin rule missing or mismatched (mark %#x, table %d, priority %d)",
				w.pin.Mark, w.pin.Table, w.pin.Priority))
			continue
		}
		k := tableKey{family: w.family, table: w.pin.Table}
		if err, ok := routeErrByTable[k]; ok {
			fail(w.pin, fmt.Errorf("probe pin route list (family %d, table %d): %w",
				w.family, w.pin.Table, err))
			continue
		}
		if !probePinRouteInstalled(routesByTable[k], w) {
			fail(w.pin, fmt.Errorf("probe pin route missing or mismatched (target %s via %s dev %s, table %d)",
				w.pin.Target, w.pin.NextHop, w.pin.Interface, w.pin.Table))
			continue
		}
	}
	return failed
}

// probePinRuleInstalled reports whether the dumped rules contain the exact
// fwmark lookup rule Apply installs for the pin: same family, mark, table,
// and priority, a full fwmark mask, and no other selector that could exclude
// marked probe packets. An omitted mask (nil, as Apply sends it) and an
// explicit 0xffffffff (as the kernel echoes it back) both mean a full match;
// any other mask value narrows the match and fails the pin.
//
// hasNoAdditionalRuleSelectors (rules.go) is deliberately NOT reused: it
// asserts Mark == 0 for leak/return rules, while a probe-pin rule carries a
// nonzero fwmark by design.
func probePinRuleInstalled(rules []netlink.Rule, pin ProbePin, family int) bool {
	for _, r := range rules {
		if r.Family != family || r.Priority != pin.Priority ||
			r.Table != pin.Table || r.Mark != pin.Mark {
			continue
		}
		if r.Mask != nil && *r.Mask != 0xffffffff {
			continue
		}
		if r.Src != nil || r.Dst != nil || r.IifName != "" || r.OifName != "" {
			continue
		}
		if r.Tos != 0 || r.TunID != 0 || r.Goto != -1 || r.Flow != -1 ||
			r.SuppressIfgroup != -1 || r.SuppressPrefixlen != -1 || r.Invert ||
			r.Dport != nil || r.Sport != nil || r.IPProto != 0 ||
			r.UIDRange != nil || r.Protocol != 0 || r.Type != 0 {
			continue
		}
		return true
	}
	return false
}

// probePinDefaultMetric returns the family default for the pin's family.
func probePinDefaultMetric(family int) int {
	if family == unix.AF_INET6 {
		return 1024 // IP6_RT_PRIO_USER: kernel default for user-added v6 routes
	}
	return 0
}

// probePinRouteInstalled reports whether the pin's host route has the exact
// shape Apply installs. It checks route shape, not whether the kernel selects
// it for lookup: with ignore_routes_with_linkdown=1 the kernel may skip
// DEAD|LINKDOWN nexthops. SO_BINDTODEVICE confines RPM to the configured
// egress, so carrier loss must advance the loss threshold instead of holding
// the test. DEAD without LINKDOWN and UNRESOLVED remain unusable pin shapes.
// Apply leaves the route metric unset, so the kernel stores the family default
// (0 for IPv4, 1024 for IPv6). Higher-metric routes cannot override the pin;
// equal-or-better competitors with another shape fail closed.
func probePinRouteInstalled(routes []netlink.Route, w wantPin) bool {
	wantMetric := probePinDefaultMetric(w.family)
	matched := false
	for _, r := range routes {
		if r.Table != w.pin.Table || r.Family != w.family || r.Dst == nil {
			continue
		}
		ones, bits := r.Dst.Mask.Size()
		if ones != bits || bits != w.hostBits || !r.Dst.IP.Equal(w.target) {
			continue
		}
		if r.Priority > wantMetric {
			continue
		}
		if r.Priority != wantMetric || matched {
			return false
		}
		if r.Gw == nil || !r.Gw.Equal(w.nextHop) || r.LinkIndex != w.linkIdx {
			return false
		}
		// LINKDOWN marks carrier-only loss on the installed path. With
		// ignore_routes_with_linkdown=1 the kernel may skip a DEAD|LINKDOWN
		// nexthop for lookup; SO_BINDTODEVICE still confines RPM to this
		// egress, so genuine carrier loss must flow through RPM instead of
		// holding the test. DEAD without LINKDOWN or UNRESOLVED is unusable.
		const unusableFlags = unix.RTNH_F_DEAD | unix.RTNH_F_UNRESOLVED
		flags := r.Flags
		if flags&int(unix.RTNH_F_LINKDOWN) != 0 {
			flags &^= int(unix.RTNH_F_DEAD)
		}
		if r.Flags&int(netlink.FLAG_ONLINK) == 0 ||
			flags&int(unusableFlags) != 0 ||
			r.Type != unix.RTN_UNICAST || r.Scope != unix.RT_SCOPE_UNIVERSE ||
			len(r.MultiPath) != 0 {
			return false
		}
		if r.Tos != 0 || r.Src != nil || r.Via != nil || r.ILinkIndex != 0 ||
			r.MPLSDst != nil || r.NewDst != nil || r.Encap != nil {
			return false
		}
		matched = true
	}
	return matched
}

package routing

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestNextTableApplyCapAggregatesDegradedError is the #6467 fail-on-revert
// guard. When the next-table leak set exceeds the hard cap
// (config.NextTableRuleWindow), nextTableManager.Apply MUST aggregate a
// degraded error naming how many leaks were dropped — NOT a bare slog.Warn.
//
// Before #6467 the cap did `slog.Warn(...); break` with no `errs = append(...)`,
// so Apply returned nil and reported SUCCESS while silently truncating the leak
// set. That diverged the kernel (which drops leak #101+) from the userspace FIB
// (which mirrored ALL config next-table leaks uncapped), so a slow-path packet
// matching leak #101+ resolved in the target VRF in userspace but the main
// table in the kernel — a security-relevant kernel/dataplane verdict split with
// no operator signal. This mirrors the rib-group (TestRibGroupRulesPriorityCap)
// and PBR (TestPBRApplyCapBoundary) over-limit guards.
//
// RED-on-revert: reverting the cap block to the pre-#6467 `slog.Warn(...); break`
// (dropping the `errs = append(...)`) makes Apply return nil, so the first
// assertion fails with a clean t.Fatal (not a compile error — keep the loop
// index and drop-count feeding the Warn if neutralizing to reproduce master).
func TestNextTableApplyCapAggregatesDegradedError(t *testing.T) {
	mkRoutes := func(n int) []*config.StaticRoute {
		routes := make([]*config.StaticRoute, n)
		for i := 0; i < n; i++ {
			routes[i] = &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			}
		}
		return routes
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	const over = 50 // 50 next-table routes past the cap must be reported.
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(mkRoutes(config.NextTableRuleWindow+over), instances, testNextTableIifs)
	if err == nil {
		t.Fatal("over-cap Apply must return a degraded error naming the dropped " +
			"next-table leaks, not a bare Warn (#6467)")
	}
	// The error must name the cap so the degraded result is self-describing.
	if !strings.Contains(err.Error(), "next-table rule limit") {
		t.Errorf("degraded error must name the next-table cap, got %v", err)
	}
	// The error must name HOW MANY leaks were dropped (the routes past the cap).
	// Match the full unique fragment ("; N next-table route(s) beyond ") so a
	// count bug that emitted e.g. 150 could not satisfy a bare "50" substring
	// ("150 next-table route" contains "50 next-table route").
	if !strings.Contains(err.Error(), fmt.Sprintf("; %d next-table route(s) beyond ", over)) {
		t.Errorf("degraded error must name the %d dropped leaks, got %v", over, err)
	}
	// The cap still holds: exactly NextTableRuleWindow rules install. Their
	// prefix-derived priorities remain in the shared destination-leak range.
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Errorf("expected the cap to hold at %d installed rules, got %d",
			config.NextTableRuleWindow, total)
	}
	assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+config.RouteLeakRulePriorityWindow)
}

// TestNextTableApplyUnderCapNoError is the companion no-false-positive guard:
// exactly at the cap (and below) Apply returns nil and installs every leak, so
// the #6467 degraded error only fires on genuine over-subscription.
func TestNextTableApplyUnderCapNoError(t *testing.T) {
	mkRoutes := func(n int) []*config.StaticRoute {
		routes := make([]*config.StaticRoute, n)
		for i := 0; i < n; i++ {
			routes[i] = &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			}
		}
		return routes
	}
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	if err := nt.Apply(mkRoutes(config.NextTableRuleWindow), instances, testNextTableIifs); err != nil {
		t.Fatalf("exactly %d next-table routes must apply without a degraded error, got %v",
			config.NextTableRuleWindow, err)
	}
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Fatalf("expected all %d routes programmed at the limit, got %d",
			config.NextTableRuleWindow, total)
	}
}

// TestNextTableApplyDroppedCountCountsOnlyEligible is the #6467-fold guard for
// the degraded-error drop count. The applier skips a next-table route with an
// unknown target instance (no prio++), so such a route never consumes a window
// slot and is NOT a "dropped leak". The "N not leaked" figure must therefore
// count only ELIGIBLE routes past the cap (known instance + parseable CIDR), not
// every next-table route in the tail.
//
// Layout: the window's worth of valid routes fill the window, then the tail
// carries 50 valid + 30 dangling routes. The cap fires with 50 eligible +
// 30 ineligible past it, so the accurate drop count is 50, not 80.
//
// RED-on-revert: reverting the dropped-count scan to `if rem.NextTable != ""`
// (counting all next-table routes in the tail) makes the error say "80", so the
// "50" assertion fails and the "not 80" assertion fails.
func TestNextTableApplyDroppedCountCountsOnlyEligible(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	var routes []*config.StaticRoute
	// Fill the window with valid routes.
	for i := 0; i < config.NextTableRuleWindow; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			NextTable:   "dmz-vr",
		})
	}
	// Tail: 50 eligible (valid) next-table routes past the cap...
	for i := 0; i < 50; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("172.16.%d.0/24", i),
			NextTable:   "dmz-vr",
		})
	}
	// ...plus 30 dangling (unknown-instance) routes that would never install.
	for i := 0; i < 30; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("192.168.%d.0/24", i),
			NextTable:   "ghost-vr", // not a defined instance
		})
	}

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(routes, instances, testNextTableIifs)
	if err == nil {
		t.Fatal("over-cap Apply must return a degraded error (#6467)")
	}
	// Match the full unique fragment ("; N next-table route(s) beyond ") so a
	// bare "50" substring cannot be satisfied by an inflated count like 150/180.
	if !strings.Contains(err.Error(), "; 50 next-table route(s) beyond ") {
		t.Errorf("drop count must name only the 50 ELIGIBLE routes past the cap, got %v", err)
	}
	if strings.Contains(err.Error(), "; 80 next-table route(s) beyond ") {
		t.Errorf("drop count must NOT include the 30 dangling routes that never install, got %v", err)
	}
	// Only the window's worth of valid rules installed.
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Errorf("expected the cap to hold at %d installed rules, got %d", config.NextTableRuleWindow, total)
	}
}

// TestNextTableApplyDroppedCountExcludesMalformedCIDR binds the net.ParseCIDR
// half of the dropped-count eligibility scan (its sibling above only exercises
// the unknown-instance half). A DEFINED-instance next-table route with an
// UNPARSEABLE destination past the cap installs no ip rule (the applier's
// top-of-loop net.ParseCIDR gate skips it) and must NOT be counted as a
// "dropped leak".
//
// Layout: the window's worth of valid routes fill the window, then the tail
// carries 50 valid + 1 malformed-CIDR (defined-instance) route. The accurate
// eligible drop count is 50, not 51.
//
// RED-on-revert: removing ONLY the net.ParseCIDR check in the dropped-count scan
// makes the count 51, so the "; 50 next-table route(s) beyond " assertion fails.
func TestNextTableApplyDroppedCountExcludesMalformedCIDR(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	var routes []*config.StaticRoute
	// Fill the window with valid routes.
	for i := 0; i < config.NextTableRuleWindow; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			NextTable:   "dmz-vr",
		})
	}
	// Tail: 50 eligible (valid) routes past the cap...
	for i := 0; i < 50; i++ {
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("172.16.%d.0/24", i),
			NextTable:   "dmz-vr",
		})
	}
	// ...plus one DEFINED-instance route with an unparseable destination, which
	// the applier skips (no ip rule) and must not count as a dropped leak.
	routes = append(routes, &config.StaticRoute{
		Destination: "10.2.0.0/99", // invalid mask — net.ParseCIDR fails
		NextTable:   "dmz-vr",
	})

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(routes, instances, testNextTableIifs)
	if err == nil {
		t.Fatal("over-cap Apply must return a degraded error (#6467)")
	}
	if !strings.Contains(err.Error(), "; 50 next-table route(s) beyond ") {
		t.Errorf("drop count must exclude the malformed-CIDR route (want 50, not 51), got %v", err)
	}
	if strings.Contains(err.Error(), "; 51 next-table route(s) beyond ") {
		t.Errorf("drop count must NOT count the malformed-CIDR route that never installs, got %v", err)
	}
	// The malformed route must not be installed, and the cap holds at the window.
	if total := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); total != config.NextTableRuleWindow {
		t.Errorf("expected the cap to hold at %d installed rules, got %d", config.NextTableRuleWindow, total)
	}
}

// #6583: the next-table priority window must be drawn down IPv4-FIRST
// regardless of the order the caller hands routes in.
//
// nextTableManager.Apply advances ONE family-blind `prio` in slice order, so
// before this the draw-down order was set entirely by two `append` lines in
// pkg/daemon/daemon_apply_routing.go (v4 statics, then v6 statics) — a
// cross-package convention bound by nothing on either side. The userspace FIB
// mirrors the same cap but draws it down in its OWN order
// (pkg/dataplane/userspace/routes.go: addRoutes("inet.0", ...) then
// addRoutes("inet6.0", ...)), so the two agreed only by coincidence of those
// appends.
//
// Swapping them would have installed 60 v6 + 40 v4 in the kernel against
// 60 v4 + 40 v6 in the FIB: 40 leaks present in the kernel and absent from the
// FIB, 40 the reverse. A leak in the FIB but not the kernel resolves into the
// target VRF on the AF_XDP fast path while a slow-path packet for the same flow
// resolves in the main table — the #6467 verdict split in a new shape.
//
// Nothing was red. The FIB-side test asserts the FIB only, and THIS file's
// kernel-side guard used a `10.%d.%d.0/24` generator, so its
// `count(AF_INET) + count(AF_INET6)` total always carried a zero v6 term and
// could not see a family reordering at all.
//
// The fix is structural rather than an assertion on the caller: Apply orders
// the slice itself, so no caller can get it wrong and the guard cannot rot into
// a check of one caller while a second is added elsewhere. This test therefore
// binds the PROPERTY (v4 draws down first) against a deliberately v6-FIRST
// input — the order the old code would have honoured.
//
// RED-on-revert: delete the `routes = nextTableFamilyOrdered(routes)` line in
// Apply and the v6-first input is honoured verbatim: v6 takes the low
// priorities and the surviving-family counts interchange.
func TestNextTableDrawsDownV4FirstRegardlessOfCallerOrder6583(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	// Two thirds of a window per family, so the cap bites and exactly one
	// family can be fully installed — which is what makes the draw-down order
	// observable rather than cosmetic.
	perFamily := (config.NextTableRuleWindow * 2) / 3
	v4 := make([]*config.StaticRoute, 0, perFamily)
	v6 := make([]*config.StaticRoute, 0, perFamily)
	for i := 0; i < perFamily; i++ {
		v4 = append(v4, &config.StaticRoute{
			Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			NextTable:   "dmz-vr",
		})
		v6 = append(v6, &config.StaticRoute{
			Destination: fmt.Sprintf("2001:db8:%x::/64", i),
			NextTable:   "dmz-vr",
		})
	}

	// The caller hands them v6 FIRST — the shape a swapped append pair, or any
	// future second caller, would produce.
	routes := append(append([]*config.StaticRoute{}, v6...), v4...)

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	// Over-cap, so Apply returns the #6467 degraded error; that is expected
	// here and not what this test is about.
	_ = nt.Apply(routes, instances, testNextTableIifs)

	gotV4, gotV6 := ops.count(unix.AF_INET), ops.count(unix.AF_INET6)
	if total := gotV4 + gotV6; total != config.NextTableRuleWindow {
		t.Fatalf("installed %d rules (v4=%d v6=%d), want the cap %d — fixture is not "+
			"over-subscribing the window, so the draw-down order is not observable",
			total, gotV4, gotV6, config.NextTableRuleWindow)
	}
	if gotV4 != perFamily {
		t.Errorf("v4 installed %d of %d offered. IPv4 must draw the window down FIRST "+
			"so the kernel agrees with the userspace FIB, which programs inet.0 before "+
			"inet6.0. The caller offered v6 first and the window followed it (#6583).",
			gotV4, perFamily)
	}
	if want := config.NextTableRuleWindow - perFamily; gotV6 != want {
		t.Errorf("v6 installed %d, want %d (the remainder after v4 draws down first)", gotV6, want)
	}

	// The families must not interleave in the window either: every v4 rule
	// takes a lower priority than every v6 rule. A count-only assertion would
	// pass on an alternating layout that still splits differently from the FIB.
	maxV4, minV6 := -1, 1<<30
	for _, r := range ops.rules[unix.AF_INET] {
		if r.Priority > maxV4 {
			maxV4 = r.Priority
		}
	}
	for _, r := range ops.rules[unix.AF_INET6] {
		if r.Priority < minV6 {
			minV6 = r.Priority
		}
	}
	if gotV6 > 0 && maxV4 >= minV6 {
		t.Errorf("families interleave in the priority window: highest v4 prio %d >= lowest "+
			"v6 prio %d. The FIB draws inet.0 down entirely before inet6.0, so an "+
			"interleaved kernel window splits from it even when the per-family COUNTS match",
			maxV4, minV6)
	}
	// STABILITY within the family. The partition must not reorder v4 among
	// itself: which v4 leaks survive the cap is decided by their relative
	// order, and the FIB's per-family pass walks the config slice in order. A
	// partition that grouped correctly but shuffled inside the group would
	// match on COUNTS and still install a different SET than the FIB.
	byPrio := append([]netlink.Rule(nil), ops.rules[unix.AF_INET]...)
	sort.Slice(byPrio, func(i, j int) bool { return byPrio[i].Priority < byPrio[j].Priority })
	for i, r := range byPrio {
		want := v4[i].Destination
		if got := r.Dst.String(); got != want {
			t.Fatalf("v4 rule at cap position %d is %s, want %s — the family partition is "+
				"not STABLE, so the surviving set differs from the FIB's even though the "+
				"per-family counts agree (#6583)", i, got, want)
		}
	}

	assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+config.RouteLeakRulePriorityWindow)
}

// TestNextTableCapHoldsOnMixedFamilyFixture6583 closes the fixture gap this
// file had: every pre-#6583 case here generated `10.%d.%d.0/24` only, so the
// `count(AF_INET) + count(AF_INET6)` totals always summed a real v4 term with a
// zero v6 term. The cap arithmetic was therefore never exercised across
// families at all.
func TestNextTableCapHoldsOnMixedFamilyFixture6583(t *testing.T) {
	instances := []*config.RoutingInstanceConfig{{Name: "dmz-vr", TableID: 101}}

	const over = 20
	n := config.NextTableRuleWindow + over
	routes := make([]*config.StaticRoute, 0, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			routes = append(routes, &config.StaticRoute{
				Destination: fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
				NextTable:   "dmz-vr",
			})
			continue
		}
		routes = append(routes, &config.StaticRoute{
			Destination: fmt.Sprintf("2001:db8:%x::/64", i),
			NextTable:   "dmz-vr",
		})
	}

	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	err := nt.Apply(routes, instances, testNextTableIifs)
	if err == nil {
		t.Fatal("over-cap mixed-family Apply must still return the #6467 degraded error")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("; %d next-table route(s) beyond ", over)) {
		t.Errorf("degraded error must name the %d dropped leaks on a mixed-family set, got %v", over, err)
	}
	gotV4, gotV6 := ops.count(unix.AF_INET), ops.count(unix.AF_INET6)
	if gotV4+gotV6 != config.NextTableRuleWindow {
		t.Errorf("mixed-family cap: installed v4=%d v6=%d (total %d), want %d",
			gotV4, gotV6, gotV4+gotV6, config.NextTableRuleWindow)
	}
	if gotV6 == 0 {
		t.Error("the mixed-family fixture installed ZERO v6 rules — the v6 term is still " +
			"absent, so this guard cannot see a family-ordering change (#6583)")
	}
	assertAllRulesInRange(t, ops, nextTableRulePriority, nextTableRulePriority+config.RouteLeakRulePriorityWindow)
}

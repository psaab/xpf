package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
)

func ruleListAtPriorities18005(family int, priorities ...int) []netlink.Rule {
	rules := make([]netlink.Rule, 0, len(priorities))
	for _, priority := range priorities {
		rules = append(rules, netlink.Rule{Family: family, Priority: priority})
	}
	return rules
}

// #16804: systemd-networkd's default ManageForeignRoutingPolicyRules=yes
// deletes every xpf ip rule on `networkctl reconfigure` and on networkd
// restart. These cells pin the Go-side owners: the mgmt-DNS steering
// reconcile re-runs after the networkd activation (and after FRR), and
// 30 s #9693 routing owner samples the pref-2000 canary before attempting
// terminator restoration, then restores the policy bands, route-leak
// snapshot and mgmt-DNS pairs without a commit when a flush is detected.

// TestMgmtDNSReconcileRunsAfterNetworkdActivation16804 is the source-order
// pin for the acceptance "MGMT-DNS-RULES-INSTALL after
// NETWORKD-RECONFIGURE": the post-FRR applyMgmtDNSRules call (the one
// that lands after applyDataplaneAndHACore's networkd.Apply) must remain
// after the FRR call and after the dataplane core. FAIL-ON-REVERT:
// moving the post-FRR reconcile back before applyDataplaneAndHACore
// (or deleting it) leaves the 2500-2503 pairs flushed by the activation
// and this pin goes red.
func TestMgmtDNSReconcileRunsAfterNetworkdActivation16804(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_apply.go"))
	core := strings.Index(src, "core := d.applyDataplaneAndHACore(ctx, cfg)")
	frr := strings.Index(src, "frrErr := d.applyFRRFull(cfg, commitOverlay)")
	if core < 0 || frr < 0 || frr < core {
		t.Fatal("applyDataplaneAndHACore / applyFRRFull order not found")
	}
	// The reconcile after FRR is necessarily after the networkd
	// activation inside the dataplane core.
	second := strings.Index(src[frr:], "d.applyMgmtDNSRules()")
	if second < 0 {
		t.Fatal("no applyMgmtDNSRules after networkd activation + FRR (#16804)")
	}
	// And the routing-rule reconcile (next-table/rib-group/PBR) must
	// also land after the activation, as it already did pre-#16804.
	if strings.Index(src[frr:], "routingRuleErr := d.applyRoutingRules") < 0 {
		t.Fatal("no applyRoutingRules after networkd activation (#16804)")
	}
}

// TestApplyOrderMgmtDNSAfterNetworkdFlushDynamic16804 drives the real
// applyConfigLocked with the #10421 activation seam extended to the DNS
// bands: afterNetworkdApplyForTest records NETWORKD-RECONFIGURE, and the
// mgmt-DNS reconcile seam records MGMT-DNS-RULES-INSTALL on every
// applyMgmtDNSRules run. The acceptance order is dynamic, not source
// text: a post-activation install must be recorded after the
// reconfigure marker. FAIL-ON-REVERT: deleting the post-FRR reconcile
// leaves only the pre-activation install and this cell goes red.
func TestApplyOrderMgmtDNSAfterNetworkdFlushDynamic16804(t *testing.T) {
	d, term, cfg := startupApplyDaemon10421(t)

	var events []string
	prevDNS := mgmtDNSRulesApplyFn
	t.Cleanup(func() { mgmtDNSRulesApplyFn = prevDNS })
	mgmtDNSRulesApplyFn = func(*Daemon, []*dhcp.Lease, *config.Config) error {
		events = append(events, "MGMT-DNS-RULES-INSTALL")
		return nil
	}
	d.afterNetworkdApplyForTest = func() {
		term.networkdActivations++
		events = append(events, "NETWORKD-RECONFIGURE")
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET, Priority: 2000})
		_ = term.RuleDel(&netlink.Rule{Family: unix.AF_INET6, Priority: 2000})
	}

	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}
	reconf := slices.Index(events, "NETWORKD-RECONFIGURE")
	if reconf < 0 {
		t.Fatalf("no NETWORKD-RECONFIGURE recorded; events = %v", events)
	}
	post := slices.Index(events[reconf+1:], "MGMT-DNS-RULES-INSTALL")
	if post < 0 {
		t.Fatalf("no MGMT-DNS-RULES-INSTALL after NETWORKD-RECONFIGURE; events = %v", events)
	}
}

// TestRoutingTickRestoresAllRuleBandsAfterFlush16804 drives the real
// reassertRoutingReconcileOnce tick against a stateful terminator shared by
// the real routing.Manager repair and the RuleList readback. A flush must be
// sampled before the terminator write restores its evidence.
// FAIL-ON-REVERT: with the old write-before-read ordering, the manager adds
// both canaries before the RuleList fake reads them, so the full band
// reconciles do not run.
func TestRoutingTickRestoresAllRuleBandsAfterFlush16804(t *testing.T) {
	for _, tc := range []struct {
		name             string
		alreadyInstalled map[int]bool
	}{
		{name: "both families flushed", alreadyInstalled: map[int]bool{}},
		{name: "IPv4 missing", alreadyInstalled: map[int]bool{unix.AF_INET6: true}},
		{name: "IPv6 missing", alreadyInstalled: map[int]bool{unix.AF_INET: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := &day2StatefulTerm10458{}
			d := day2Daemon10458(t, term, day2SfmixConfig10458)
			spec := []routing.VRFSpec{{Name: "sfmix", TableID: 488570}}
			if err := d.routing.ReconcileVRFs(spec); err != nil {
				t.Fatalf("initial VRF reconcile: %v", err)
			}
			term.mu.Lock()
			term.installed = make(map[int]bool, len(tc.alreadyInstalled))
			for family := range tc.alreadyInstalled {
				term.installed[family] = true
			}
			term.mu.Unlock()

			var calls []string
			prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
			prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
			t.Cleanup(func() {
				routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
				mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
			})
			routingPolicyReconcileFn = func(*Daemon, *config.Config) error {
				calls = append(calls, "policy")
				return nil
			}
			routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
				calls = append(calls, "leak")
				return nil
			}
			dnsSawCanaries := false
			mgmtDNSRulesReconcileFn = func(*Daemon) error {
				calls = append(calls, "mgmtdns")
				installed, _, _, _ := term.snapshot()
				dnsSawCanaries = installed[unix.AF_INET] && installed[unix.AF_INET6]
				return nil
			}
			terminatorFlushRuleListFn = day2RuleList10458(term)
			_, addsBefore, _, _ := term.snapshot()

			d.reassertRoutingReconcileOnce(context.Background())

			want := []string{"policy", "leak", "mgmtdns"}
			if !slices.Equal(calls, want) {
				t.Fatalf("flush tick calls = %v, want %v", calls, want)
			}
			if !dnsSawCanaries {
				t.Fatal("management-DNS reconcile ran before both pref-2000 canaries were restored")
			}
			installed, addCalls, _, invalid := term.snapshot()
			if invalid != 0 || !installed[unix.AF_INET] || !installed[unix.AF_INET6] {
				t.Fatalf("terminator state after flush recovery = %v (invalid=%d), want both families", installed, invalid)
			}
			if addCalls != addsBefore+2 {
				t.Fatalf("terminator add attempts on one tick = %d, want exactly 2", addCalls-addsBefore)
			}
			if owed, _, last := d.RoutingReconcileDebt(); owed {
				t.Fatalf("successful flush restore must not latch debt: owed=%v last=%q", owed, last)
			}
		})
	}
}

// TestRoutingTickNoFlushIsQuiet16804 is the negative control: with the
// terminator present on readback and no debt owed, the tick must NOT
// re-run the policy/mgmt-DNS reconciles (a healthy steady-state box
// would otherwise rewrite its rule bands every 30 s).
func TestRoutingTickNoFlushIsQuiet16804(t *testing.T) {
	d, _, cfg := startupApplyDaemon10421(t)
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	calls := 0
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { calls++; return nil }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		calls++
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { calls++; return nil }
	terminatorFlushRuleListFn = func(family int) ([]netlink.Rule, error) {
		return ruleListAtPriorities18005(family, 0, 1000, vrfMissTerminatorPriority16804, 32766), nil
	}

	d.reassertRoutingReconcileOnce(context.Background())
	if calls != 0 {
		t.Fatalf("healthy tick ran %d band reconciles, want 0", calls)
	}
	if owed, _, _ := d.RoutingReconcileDebt(); owed {
		t.Fatal("healthy tick latched routing debt")
	}
}

// TestRoutingTickProbeFailureConservativelyRecovers16804 pins the fail-safe
// probe-error policy: a failed read is not evidence that the bands survived.
func TestRoutingTickProbeFailureConservativelyRecovers16804(t *testing.T) {
	term := &day2StatefulTerm10458{}
	d := day2Daemon10458(t, term, day2SfmixConfig10458)
	if err := d.routing.ReconcileVRFs([]routing.VRFSpec{{Name: "sfmix", TableID: 488570}}); err != nil {
		t.Fatalf("initial VRF reconcile: %v", err)
	}
	term.flush(unix.AF_INET, unix.AF_INET6)

	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	var calls []string
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error {
		calls = append(calls, "policy")
		return nil
	}
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		calls = append(calls, "leak")
		return nil
	}
	dnsSawCanaries := true
	mgmtDNSRulesReconcileFn = func(*Daemon) error {
		calls = append(calls, "mgmtdns")
		installed, _, _, _ := term.snapshot()
		dnsSawCanaries = dnsSawCanaries && installed[unix.AF_INET] && installed[unix.AF_INET6]
		return nil
	}
	probeErr := errors.New("injected RuleList failure")
	probes := 0
	terminatorFlushRuleListFn = func(int) ([]netlink.Rule, error) {
		probes++
		return nil, probeErr
	}

	for range 2 {
		d.reassertRoutingReconcileOnce(context.Background())
		if owed, _, last := d.RoutingReconcileDebt(); owed {
			t.Fatalf("successful recovery retained probe-only debt: %q", last)
		}
	}
	want := []string{"policy", "leak", "mgmtdns", "policy", "leak", "mgmtdns"}
	if !slices.Equal(calls, want) {
		t.Fatalf("probe-error recovery calls = %v, want %v", calls, want)
	}
	if !dnsSawCanaries {
		t.Fatal("management-DNS reconcile ran before the terminator repair")
	}
	if probes != 2 {
		t.Fatalf("probe calls = %d, want 2 (one per tick)", probes)
	}
	installed, addCalls, installs, invalid := term.snapshot()
	if invalid != 0 || !installed[unix.AF_INET] || !installed[unix.AF_INET6] {
		t.Fatalf("terminator state after probe-error recovery = %v (invalid=%d), want both families", installed, invalid)
	}
	if addCalls != 6 || installs != 4 {
		t.Fatalf("terminator adds/installs = %d/%d, want 6/4 (initial 2, then one repair per tick)",
			addCalls, installs)
	}
}

// TestRoutingTickFlushRestoreFailureLatchesDebt16804: when the flush
// restore itself fails, the tick must latch ordinary routing debt so
// the next tick retries — the restart arm must not heal once and give up.
func TestRoutingTickFlushRestoreFailureLatchesDebt16804(t *testing.T) {
	d, _, cfg := startupApplyDaemon10421(t)
	if err := d.applyConfigLocked(context.Background(), cfg); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	injected := errors.New("injected flush-restore failure")
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	routingPolicyReconcileFn = func(*Daemon, *config.Config) error { return injected }
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		return nil
	}
	mgmtDNSRulesReconcileFn = func(*Daemon) error { return nil }
	terminatorFlushRuleListFn = func(family int) ([]netlink.Rule, error) {
		if family == unix.AF_INET {
			return ruleListAtPriorities18005(family, 0, 1000), nil // v4 terminator flushed
		}
		return ruleListAtPriorities18005(family, 0, 1000, vrfMissTerminatorPriority16804), nil
	}

	d.reassertRoutingReconcileOnce(context.Background())
	owed, _, last := d.RoutingReconcileDebt()
	if !owed || !strings.Contains(last, "injected flush-restore failure") {
		t.Fatalf("failed flush restore must latch debt: owed=%v last=%q", owed, last)
	}
}

// TestTerminatorFlushedProbe16804 unit-pins the canary: desired-but-
// missing in either family reports a flush; present in both does not.
func TestTerminatorFlushedProbe16804(t *testing.T) {
	d, _, _ := startupApplyDaemon10421(t)
	prev := terminatorFlushRuleListFn
	t.Cleanup(func() { terminatorFlushRuleListFn = prev })

	live := map[int][]netlink.Rule{
		unix.AF_INET:  ruleListAtPriorities18005(unix.AF_INET, 0, 1000, vrfMissTerminatorPriority16804, 32766),
		unix.AF_INET6: ruleListAtPriorities18005(unix.AF_INET6, 0, 1000, vrfMissTerminatorPriority16804, 32766),
	}
	terminatorFlushRuleListFn = func(family int) ([]netlink.Rule, error) { return live[family], nil }
	flushed, err := routingRuleBandsFlushed18005(d)
	if err != nil || flushed {
		t.Fatalf("present terminator: flushed=%v err=%v, want false,nil", flushed, err)
	}

	live[unix.AF_INET6] = ruleListAtPriorities18005(unix.AF_INET6, 0, 1000)
	flushed, err = routingRuleBandsFlushed18005(d)
	if err != nil || !flushed {
		t.Fatalf("v6 terminator missing: flushed=%v err=%v, want true,nil", flushed, err)
	}
}

// statefulRuleOps18005 shares one in-memory rule table between tick readback,
// policy recovery, DNS recovery, and the VRF terminator.
type statefulRuleOps18005 struct {
	rules     []netlink.Rule
	addCalls  int
	delCalls  int
	termAdds  int
	listCalls int
}

func (f *statefulRuleOps18005) RuleAdd(rule *netlink.Rule) error {
	for _, current := range f.rules {
		if reflect.DeepEqual(current, *rule) {
			return unix.EEXIST
		}
	}
	f.rules = append(f.rules, *rule)
	f.addCalls++
	return nil
}

func (f *statefulRuleOps18005) RuleAddDSCP(rule *netlink.Rule, _ uint8) error {
	return f.RuleAdd(rule)
}

func (f *statefulRuleOps18005) RuleDel(rule *netlink.Rule) error {
	for i, current := range f.rules {
		if reflect.DeepEqual(current, *rule) {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			f.delCalls++
			return nil
		}
	}
	return unix.ENOENT
}

func (f *statefulRuleOps18005) RuleList(family int) ([]netlink.Rule, error) {
	f.listCalls++
	var out []netlink.Rule
	for _, rule := range f.rules {
		if rule.Family == family {
			out = append(out, rule)
		}
	}
	return out, nil
}

func (f *statefulRuleOps18005) RuleAddL3mdevUnreachable(family, priority int) error {
	f.termAdds++
	return f.RuleAdd(&netlink.Rule{Family: family, Priority: priority})
}

func (f *statefulRuleOps18005) flushPBR() int {
	kept := f.rules[:0]
	removed := 0
	for _, rule := range f.rules {
		if rule.Priority >= config.PBRRulePriorityBase &&
			rule.Priority < config.PBRRulePriorityBase+config.PBRRuleWindow {
			removed++
			continue
		}
		kept = append(kept, rule)
	}
	f.rules = kept
	return removed
}
func (f *statefulRuleOps18005) removeRuleFamilyPriority(family, priority int) bool {
	for i, rule := range f.rules {
		if rule.Family == family && rule.Priority == priority {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return true
		}
	}
	return false
}

func ruleRecoveryConfig18005(withVRF, withPBR bool) string {
	var text strings.Builder
	if withVRF || withPBR {
		text.WriteString("routing-instances {\n")
		if withVRF {
			text.WriteString("    sfmix { instance-type virtual-router; table-id 488570; }\n")
		}
		if withPBR {
			text.WriteString("    steer-ri { instance-type forwarding; }\n")
		}
		text.WriteString("}\n")
	}
	if withPBR {
		text.WriteString(`firewall {
    family inet {
        filter steer {
            term route {
                from { source-address 192.0.2.0/24; }
                then { routing-instance steer-ri; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { filter { input steer; } }
        }
    }
}
`)
	}
	if !withVRF && !withPBR {
		text.WriteString("system { host-name no-policy; }\n")
	}
	return text.String()
}

func policyRecoveryDaemon18005(t *testing.T, withVRF, withPBR bool) (*Daemon, *statefulRuleOps18005, *config.Config) {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	if _, err := store.SyncApply(ruleRecoveryConfig18005(withVRF, withPBR), nil); err != nil {
		t.Fatalf("SyncApply: %v", err)
	}
	ops := newReconcileFakeLinkOps()
	if withVRF {
		ops.links["vrf-sfmix"] = &netlink.Vrf{
			LinkAttrs: netlink.LinkAttrs{Name: "vrf-sfmix"},
			Table:     488570,
		}
	}
	rules := &statefulRuleOps18005{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
		routing:  routing.NewManagerWithLinkTermAndRuleOpsForTest(ops, rules, rules),
	}
	if withVRF {
		if err := d.routing.ReconcileVRFs([]routing.VRFSpec{{Name: "sfmix", TableID: 488570}}); err != nil {
			t.Fatalf("ReconcileVRFs: %v", err)
		}
	}
	cfg := store.ActiveConfig()
	if err := d.applyPolicyRoutingRules(cfg); err != nil {
		t.Fatalf("initial applyPolicyRoutingRules: %v", err)
	}
	return d, rules, cfg
}

func installRoutingRecoverySeams18005(t *testing.T, rules *statefulRuleOps18005, policyCalls *int) {
	t.Helper()
	prevPolicy, prevLeak := routingPolicyReconcileFn, routeLeakReconcileFn
	prevDNS, prevList := mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn
	t.Cleanup(func() {
		routingPolicyReconcileFn, routeLeakReconcileFn = prevPolicy, prevLeak
		mgmtDNSRulesReconcileFn, terminatorFlushRuleListFn = prevDNS, prevList
	})
	routingPolicyReconcileFn = func(d *Daemon, cfg *config.Config) error {
		if policyCalls != nil {
			(*policyCalls)++
		}
		return d.applyPolicyRoutingRules(cfg)
	}
	routeLeakReconcileFn = func(*Daemon, *config.Config, []config.RouteOverlayEntry) error {
		return nil
	}
	mgmtDNSRulesReconcileFn = func(d *Daemon) error {
		return reconcileMgmtDNSRulesFiltered(rules, nil, d.mgmtVRFIfaceSet(), nil, d.store.ActiveConfig())
	}
	terminatorFlushRuleListFn = rules.RuleList
}

func TestPBRPolicyBandRecovery18005(t *testing.T) {
	t.Run("PBR-only flush restores without a canary", func(t *testing.T) {
		d, rules, cfg := policyRecoveryDaemon18005(t, false, true)
		if d.shouldReassertVRFMissTerminator(cfg) {
			t.Fatal("PBR-only config must not own a VRF miss terminator")
		}
		if counts := routing.DesiredPolicyRulePriorityCounts(cfg); len(counts) == 0 {
			t.Fatal("fixture must produce desired PBR policy rules")
		}
		wantRules := append([]netlink.Rule(nil), rules.rules...)
		if rules.flushPBR() == 0 {
			t.Fatal("fixture had no PBR rules to flush")
		}
		if owed, _, _ := d.RoutingReconcileDebt(); owed {
			t.Fatal("precondition: no routing debt before the post-flush tick")
		}
		installRoutingRecoverySeams18005(t, rules, nil)

		d.reassertRoutingReconcileOnce(context.Background())

		assertRuleSetEqual18005(t, rules.rules, wantRules)
		if rules.termAdds != 0 || hasRulePriority18005(rules, vrfMissTerminatorPriority16804) {
			t.Fatal("PBR-only recovery must not install the global pref-2000 canary")
		}
		if owed, _, last := d.RoutingReconcileDebt(); owed {
			t.Fatalf("successful no-debt recovery latched debt: %q", last)
		}
		addsBefore, delsBefore := rules.addCalls, rules.delCalls
		d.reassertRoutingReconcileOnce(context.Background())
		if rules.addCalls != addsBefore || rules.delCalls != delsBefore {
			t.Fatalf("idempotent recovery rewrote healthy bands: adds %d→%d, deletes %d→%d",
				addsBefore, rules.addCalls, delsBefore, rules.delCalls)
		}
	})

	t.Run("one PBR rule is recovered with both canaries retained", func(t *testing.T) {
		d, rules, _ := policyRecoveryDaemon18005(t, true, true)
		wantRules := append([]netlink.Rule(nil), rules.rules...)
		if !hasRuleFamilyPriority18005(rules, unix.AF_INET, vrfMissTerminatorPriority16804) ||
			!hasRuleFamilyPriority18005(rules, unix.AF_INET6, vrfMissTerminatorPriority16804) {
			t.Fatal("fixture must start with both family canaries")
		}
		if !rules.removeRuleFamilyPriority(unix.AF_INET, config.PBRRulePriorityBase) {
			t.Fatal("fixture lacks the first IPv4 PBR lookup rule")
		}
		if !hasRuleFamilyPriority18005(rules, unix.AF_INET, vrfMissTerminatorPriority16804) ||
			!hasRuleFamilyPriority18005(rules, unix.AF_INET6, vrfMissTerminatorPriority16804) {
			t.Fatal("selective policy deletion must retain both family canaries")
		}
		installRoutingRecoverySeams18005(t, rules, nil)

		d.reassertRoutingReconcileOnce(context.Background())

		assertRuleSetEqual18005(t, rules.rules, wantRules)
		if !hasRuleFamilyPriority18005(rules, unix.AF_INET, vrfMissTerminatorPriority16804) ||
			!hasRuleFamilyPriority18005(rules, unix.AF_INET6, vrfMissTerminatorPriority16804) {
			t.Fatal("policy recovery must preserve both family canaries")
		}
		if owed, _, last := d.RoutingReconcileDebt(); owed {
			t.Fatalf("successful selective recovery latched debt: %q", last)
		}
	})

	t.Run("healthy PBR does not rewrite", func(t *testing.T) {
		d, rules, cfg := policyRecoveryDaemon18005(t, false, true)
		policyCalls := 0
		installRoutingRecoverySeams18005(t, rules, &policyCalls)
		addsBefore, delsBefore := rules.addCalls, rules.delCalls

		d.reassertRoutingReconcileOnce(context.Background())

		if policyCalls != 0 {
			t.Fatalf("healthy policy recovery calls = %d, want 0", policyCalls)
		}
		if rules.addCalls != addsBefore || rules.delCalls != delsBefore {
			t.Fatalf("healthy rule state was rewritten: adds %d→%d, deletes %d→%d",
				addsBefore, rules.addCalls, delsBefore, rules.delCalls)
		}
		assertDesiredRulePriorities18005(t, rules, routing.DesiredPolicyRulePriorityCounts(cfg))
	})

	t.Run("no policy rules does not probe or install canary", func(t *testing.T) {
		d, rules, _ := policyRecoveryDaemon18005(t, false, false)
		policyCalls := 0
		installRoutingRecoverySeams18005(t, rules, &policyCalls)
		rules.listCalls = 0

		d.reassertRoutingReconcileOnce(context.Background())

		if rules.listCalls != 0 {
			t.Fatalf("no-policy tick made %d RuleList calls, want 0", rules.listCalls)
		}
		if policyCalls != 0 {
			t.Fatalf("no-policy tick ran %d policy recoveries, want 0", policyCalls)
		}
		if rules.termAdds != 0 || hasRulePriority18005(rules, vrfMissTerminatorPriority16804) {
			t.Fatal("no-policy config must not install a VRF miss canary")
		}
	})
}

func hasRulePriority18005(rules *statefulRuleOps18005, priority int) bool {
	for _, rule := range rules.rules {
		if rule.Priority == priority {
			return true
		}
	}
	return false
}

func hasRuleFamilyPriority18005(rules *statefulRuleOps18005, family, priority int) bool {
	for _, rule := range rules.rules {
		if rule.Family == family && rule.Priority == priority {
			return true
		}
	}
	return false
}

func assertRuleSetEqual18005(t *testing.T, actual, want []netlink.Rule) {
	t.Helper()
	if len(actual) != len(want) {
		t.Fatalf("recovered rule set has %d entries, want snapshot with %d: got=%+v want=%+v",
			len(actual), len(want), actual, want)
	}
	matched := make([]bool, len(want))
	for _, got := range actual {
		found := false
		for i, expected := range want {
			if !matched[i] && reflect.DeepEqual(got, expected) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("unexpected recovered rule %+v; initial rule snapshot was %+v", got, want)
		}
	}
}

func assertDesiredRulePriorities18005(t *testing.T, rules *statefulRuleOps18005, desired []routing.PolicyRulePriorityCount) {
	t.Helper()
	live := make(map[routingRulePriorityKey18005]int)
	for _, rule := range rules.rules {
		live[routingRulePriorityKey18005{family: rule.Family, priority: rule.Priority}]++
	}
	for _, want := range desired {
		key := routingRulePriorityKey18005{family: want.Family, priority: want.Priority}
		if live[key] < want.Count {
			t.Fatalf("desired policy rule count at family %d priority %d = %d, want at least %d",
				want.Family, want.Priority, live[key], want.Count)
		}
	}
}

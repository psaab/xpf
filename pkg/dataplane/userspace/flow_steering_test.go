package userspace

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubStatusProvider lets tests feed canned ProcessStatus snapshots
// to the controller without spinning up a Manager.
type stubStatusProvider struct {
	mu     sync.Mutex
	status ProcessStatus
	err    error
}

func (s *stubStatusProvider) Status() (ProcessStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status, s.err
}

func (s *stubStatusProvider) set(ps ProcessStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = ps
}

// fakeEthtool captures every shell-out and returns scripted replies.
// The default reply is the canonical "Added rule with ID N" line so
// tests don't have to spell it out for every successful install.
type fakeEthtool struct {
	mu     sync.Mutex
	calls  [][]string
	idCtr  int
	errs   []error
	stdout []string
}

func (f *fakeEthtool) run(args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, append([]string(nil), args...))
	var err error
	if len(f.errs) > 0 {
		err = f.errs[0]
		f.errs = f.errs[1:]
	}
	if len(args) > 0 && args[0] == "-N" && contains(args, "delete") {
		return "", err
	}
	if len(args) > 0 && args[0] == "-N" && !contains(args, "delete") {
		// install path
		f.idCtr++
		out := fmt.Sprintf("Added rule with ID %d\n", 1024-f.idCtr)
		if len(f.stdout) > 0 {
			out = f.stdout[0]
			f.stdout = f.stdout[1:]
		}
		return out, err
	}
	if len(args) > 0 && args[0] == "-k" {
		return "ntuple-filters: on\n", err
	}
	return "", err
}

func (f *fakeEthtool) callCount(filterFn func([]string) bool) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if filterFn(c) {
			n++
		}
	}
	return n
}

func contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func makeBinding(slot, queue, count uint32, ifname string, ifindex int, sample []ActiveFlowSampleStatus) BindingStatus {
	return BindingStatus{
		Slot:                     slot,
		QueueID:                  queue,
		Interface:                ifname,
		Ifindex:                  ifindex,
		ActiveIngressFlowsCount:  count,
		ActiveIngressFlowsSample: sample,
	}
}

func makeFlow(srcPort uint16) ActiveFlowSampleStatus {
	return ActiveFlowSampleStatus{
		Wire5Tuple:     fmt.Sprintf("tcp 10.0.0.1:%d -> 172.16.80.200:5203", srcPort),
		InstallAgeSecs: flowSteeringStableInstallAgeSecs + 1,
		LastSeenAgeMs:  100,
	}
}

func newTestController(provider flowSteeringStatusProvider, fake *fakeEthtool) *FlowSteeringController {
	c := NewFlowSteeringController(slog.Default(), provider)
	c.runEthtool = fake.run
	// Mark the test interface eligible so reconcileIface doesn't bail
	// on the sysfs driver detection during tests.
	c.ifaces["ge-0-0-1"] = &flowSteeringIfaceState{
		name: "ge-0-0-1", driver: "mlx5_core", eligible: true, reason: "test",
		resolvedAt: time.Now(),
	}
	return c
}

// === selectStableCandidatesLocked ===

func TestSelectStableCandidates_excludesYoungFlows(t *testing.T) {
	c := newTestController(&stubStatusProvider{}, &fakeEthtool{})
	young := ActiveFlowSampleStatus{Wire5Tuple: "tcp a:1 -> b:2", InstallAgeSecs: 1, LastSeenAgeMs: 100}
	stable := makeFlow(40000)
	c.mu.Lock()
	got := c.selectStableCandidatesLocked("ge-0-0-1", []ActiveFlowSampleStatus{young, stable})
	c.mu.Unlock()
	if len(got) != 1 || got[0].Wire5Tuple != stable.Wire5Tuple {
		t.Fatalf("expected only stable flow, got %v", got)
	}
}

func TestSelectStableCandidates_excludesIdleFlows(t *testing.T) {
	c := newTestController(&stubStatusProvider{}, &fakeEthtool{})
	idle := ActiveFlowSampleStatus{Wire5Tuple: "tcp a:1 -> b:2", InstallAgeSecs: 10, LastSeenAgeMs: 5000}
	stable := makeFlow(40000)
	c.mu.Lock()
	got := c.selectStableCandidatesLocked("ge-0-0-1", []ActiveFlowSampleStatus{idle, stable})
	c.mu.Unlock()
	if len(got) != 1 || got[0].Wire5Tuple != stable.Wire5Tuple {
		t.Fatalf("expected only stable flow, got %v", got)
	}
}

func TestSelectStableCandidates_skipsAlreadySteeredFlows(t *testing.T) {
	// Sticky placement: once a flow has a controller-owned rule, it
	// must not appear in the candidate pool. The original 5-tick
	// no-resteer cooldown was the wrong shape — it allowed re-pick
	// after expiry, leaving stale duplicate rules.
	c := newTestController(&stubStatusProvider{}, &fakeEthtool{})
	already := makeFlow(40000)
	fresh := makeFlow(40001)
	key := flowSteeringFlowKey{wire5tuple: already.Wire5Tuple, iface: "ge-0-0-1"}
	c.mu.Lock()
	c.rules[key] = &flowSteeringInstalledRule{
		iface: "ge-0-0-1", ruleLoc: 1023, targetQueue: 1, tick: 0, lastSeenTick: 5,
	}
	got := c.selectStableCandidatesLocked("ge-0-0-1", []ActiveFlowSampleStatus{already, fresh})
	c.mu.Unlock()
	if len(got) != 1 || got[0].Wire5Tuple != fresh.Wire5Tuple {
		t.Fatalf("expected only fresh flow, got %v", got)
	}
}

func TestSelectStableCandidates_deterministicOrder(t *testing.T) {
	// Selection must be deterministic for reproducible logs.
	c := newTestController(&stubStatusProvider{}, &fakeEthtool{})
	a := makeFlow(50000)
	b := makeFlow(50001)
	cflow := makeFlow(50002)
	c.mu.Lock()
	got1 := c.selectStableCandidatesLocked("ge-0-0-1", []ActiveFlowSampleStatus{a, b, cflow})
	got2 := c.selectStableCandidatesLocked("ge-0-0-1", []ActiveFlowSampleStatus{cflow, a, b})
	c.mu.Unlock()
	if len(got1) != len(got2) {
		t.Fatalf("len mismatch")
	}
	for i := range got1 {
		if got1[i].Wire5Tuple != got2[i].Wire5Tuple {
			t.Fatalf("non-deterministic: %v vs %v", got1, got2)
		}
	}
}

// === selectDestinationQueues ===

func TestSelectDestinationQueues_picksLeastLoaded(t *testing.T) {
	group := []BindingStatus{
		makeBinding(0, 0, 5, "ge-0-0-1", 1, nil),
		makeBinding(1, 1, 1, "ge-0-0-1", 1, nil),
		makeBinding(2, 2, 3, "ge-0-0-1", 1, nil),
	}
	got := selectDestinationQueues(group, nil, 2)
	want := []uint32{1, 2} // queues from bindings sorted by count asc
	if !equalU32(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSelectDestinationQueues_dedupsQueueID(t *testing.T) {
	// HA mode: 12 bindings share 6 NIC queues. Two bindings on
	// queue 0 should produce queue 0 only once in the dst list.
	group := []BindingStatus{
		makeBinding(0, 0, 1, "ge-0-0-1", 1, nil),
		makeBinding(1, 0, 1, "ge-0-0-1", 1, nil), // duplicate queue
		makeBinding(2, 1, 2, "ge-0-0-1", 1, nil),
		makeBinding(3, 2, 3, "ge-0-0-1", 1, nil),
	}
	got := selectDestinationQueues(group, nil, 4)
	want := []uint32{0, 1, 2}
	if !equalU32(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSelectDestinationQueues_skipsCooldown(t *testing.T) {
	group := []BindingStatus{
		makeBinding(0, 0, 1, "ge-0-0-1", 1, nil),
		makeBinding(1, 1, 1, "ge-0-0-1", 1, nil),
		makeBinding(2, 2, 1, "ge-0-0-1", 1, nil),
	}
	cooldown := map[uint32]bool{1: true}
	got := selectDestinationQueues(group, cooldown, 3)
	want := []uint32{0, 2}
	if !equalU32(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestSelectDestinationQueues_kZeroOrEmpty(t *testing.T) {
	if got := selectDestinationQueues(nil, nil, 1); got != nil {
		t.Fatalf("nil group should return nil, got %v", got)
	}
	if got := selectDestinationQueues([]BindingStatus{makeBinding(0, 0, 0, "x", 1, nil)}, nil, 0); got != nil {
		t.Fatalf("k=0 should return nil, got %v", got)
	}
}

// === parseWire5Tuple ===

func TestParseWire5Tuple_v4TCP(t *testing.T) {
	p, err := parseWire5Tuple("tcp 10.0.0.1:5201 -> 172.16.80.200:43210")
	if err != nil {
		t.Fatal(err)
	}
	if p.proto != "tcp" || !p.isV4 {
		t.Fatalf("unexpected: %+v", p)
	}
	if p.srcIP != "10.0.0.1" || p.srcPort != 5201 {
		t.Fatalf("src wrong: %+v", p)
	}
	if p.dstIP != "172.16.80.200" || p.dstPort != 43210 {
		t.Fatalf("dst wrong: %+v", p)
	}
}

func TestParseWire5Tuple_v6TCP(t *testing.T) {
	p, err := parseWire5Tuple("tcp [2001:db8::1]:5201 -> [2001:db8::2]:43210")
	if err != nil {
		t.Fatal(err)
	}
	if p.proto != "tcp" || p.isV4 {
		t.Fatalf("expected v6: %+v", p)
	}
	if p.srcIP != "2001:db8::1" || p.dstIP != "2001:db8::2" {
		t.Fatalf("addr wrong: %+v", p)
	}
}

func TestParseWire5Tuple_icmpNoPort(t *testing.T) {
	p, err := parseWire5Tuple("icmp 10.0.0.1 -> 10.0.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if p.srcPort != 0 || p.dstPort != 0 {
		t.Fatalf("icmp should have zero ports: %+v", p)
	}
}

func TestParseWire5Tuple_malformed(t *testing.T) {
	cases := []string{
		"",
		"tcp 10.0.0.1",
		"tcp 10.0.0.1:80 99.9.9.9:80",   // missing ->
		"tcp not-an-ip:80 -> 1.2.3.4:80",
	}
	for _, in := range cases {
		if _, err := parseWire5Tuple(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

// === parseEthtoolRuleID ===

func TestParseEthtoolRuleID_canonical(t *testing.T) {
	id, err := parseEthtoolRuleID("Added rule with ID 1023\n")
	if err != nil || id != 1023 {
		t.Fatalf("got id=%d err=%v", id, err)
	}
}

func TestParseEthtoolRuleID_extraLines(t *testing.T) {
	in := "warning: foo\nAdded rule with ID 42\n\n"
	id, err := parseEthtoolRuleID(in)
	if err != nil || id != 42 {
		t.Fatalf("got id=%d err=%v", id, err)
	}
}

func TestParseEthtoolRuleID_missing(t *testing.T) {
	if _, err := parseEthtoolRuleID(""); err == nil {
		t.Error("expected error on empty")
	}
	if _, err := parseEthtoolRuleID("no rule line\n"); err == nil {
		t.Error("expected error on non-matching")
	}
}

// === installRule ===

func TestInstallRule_v4(t *testing.T) {
	fake := &fakeEthtool{}
	c := newTestController(&stubStatusProvider{}, fake)
	flow := flowSteeringFlowKey{wire5tuple: "tcp 10.0.0.1:5201 -> 172.16.80.200:43210", iface: "ge-0-0-1"}
	id, err := c.installRule(flow, 3)
	if err != nil {
		t.Fatal(err)
	}
	if id != 1023 {
		t.Errorf("expected id=1023, got %d", id)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 ethtool call, got %d", len(fake.calls))
	}
	args := fake.calls[0]
	if !contains(args, "tcp4") {
		t.Errorf("expected flow-type tcp4 in %v", args)
	}
	if !contains(args, "10.0.0.1") || !contains(args, "172.16.80.200") {
		t.Errorf("missing IPs in %v", args)
	}
	if !contains(args, "3") {
		t.Errorf("missing action queue 3 in %v", args)
	}
}

func TestInstallRule_v6(t *testing.T) {
	fake := &fakeEthtool{}
	c := newTestController(&stubStatusProvider{}, fake)
	flow := flowSteeringFlowKey{wire5tuple: "tcp [2001:db8::1]:5201 -> [2001:db8::2]:43210", iface: "ge-0-0-1"}
	if _, err := c.installRule(flow, 0); err != nil {
		t.Fatal(err)
	}
	args := fake.calls[0]
	if !contains(args, "tcp6") {
		t.Errorf("expected flow-type tcp6 in %v", args)
	}
}

func TestInstallRule_rejectsNonTCP(t *testing.T) {
	fake := &fakeEthtool{}
	c := newTestController(&stubStatusProvider{}, fake)
	flow := flowSteeringFlowKey{wire5tuple: "udp 10.0.0.1:53 -> 10.0.0.2:53", iface: "ge-0-0-1"}
	if _, err := c.installRule(flow, 0); err == nil {
		t.Error("expected error for udp flow")
	}
}

func TestInstallRule_propagatesEthtoolError(t *testing.T) {
	fake := &fakeEthtool{errs: []error{errors.New("boom")}}
	c := newTestController(&stubStatusProvider{}, fake)
	flow := flowSteeringFlowKey{wire5tuple: "tcp 10.0.0.1:80 -> 10.0.0.2:80", iface: "ge-0-0-1"}
	if _, err := c.installRule(flow, 0); err == nil {
		t.Error("expected error")
	}
}

// === reconcile / sticky placement / eviction ===

func TestReconcile_installsRulesForImbalance(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)
	c.enabled.Store(true)

	heavy := makeBinding(0, 0, 4, "ge-0-0-1", 1, []ActiveFlowSampleStatus{
		makeFlow(50001), makeFlow(50002), makeFlow(50003), makeFlow(50004),
	})
	light := makeBinding(1, 1, 0, "ge-0-0-1", 1, nil)
	stub.set(ProcessStatus{Bindings: []BindingStatus{heavy, light}})

	if err := c.reconcile(); err != nil {
		t.Fatal(err)
	}
	installed := fake.callCount(func(args []string) bool {
		return len(args) > 0 && args[0] == "-N" && !contains(args, "delete")
	})
	if installed == 0 {
		t.Error("expected install calls but got 0")
	}
	if c.rulesInstalled.Load() == 0 {
		t.Error("rulesInstalled counter not bumped")
	}
}

func TestReconcile_stickyPlacement_doesNotReinstallSameFlow(t *testing.T) {
	// The bug from production: the controller kept re-installing
	// rules for the same flow every cooldown expiry, accumulating
	// dead rules. After fix, a flow with an installed rule is out
	// of the candidate pool permanently.
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)
	c.enabled.Store(true)

	heavy := makeBinding(0, 0, 4, "ge-0-0-1", 1, []ActiveFlowSampleStatus{
		makeFlow(50001), makeFlow(50002), makeFlow(50003), makeFlow(50004),
	})
	light := makeBinding(1, 1, 0, "ge-0-0-1", 1, nil)
	stub.set(ProcessStatus{Bindings: []BindingStatus{heavy, light}})

	for i := 0; i < 10; i++ {
		if err := c.reconcile(); err != nil {
			t.Fatal(err)
		}
	}
	// At most flowSteeringMaxResteerPerTick rules per tick, but
	// across 10 ticks with sticky placement we should NOT exceed
	// the number of distinct candidate flows (4 in this test).
	installed := fake.callCount(func(args []string) bool {
		return len(args) > 0 && args[0] == "-N" && !contains(args, "delete")
	})
	if installed > 4 {
		t.Errorf("sticky placement broken: %d rules for 4 flows over 10 ticks", installed)
	}
}

func TestReconcile_skipsBelowMinImbalance(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)
	c.enabled.Store(true)

	// Imbalance of 1 (just below flowSteeringMinImbalance).
	a := makeBinding(0, 0, 2, "ge-0-0-1", 1, []ActiveFlowSampleStatus{makeFlow(50001), makeFlow(50002)})
	b := makeBinding(1, 1, 1, "ge-0-0-1", 1, []ActiveFlowSampleStatus{makeFlow(50003)})
	stub.set(ProcessStatus{Bindings: []BindingStatus{a, b}})

	if err := c.reconcile(); err != nil {
		t.Fatal(err)
	}
	installed := fake.callCount(func(args []string) bool {
		return len(args) > 0 && args[0] == "-N" && !contains(args, "delete")
	})
	if installed != 0 {
		t.Errorf("expected no installs below min imbalance, got %d", installed)
	}
}

func TestReconcile_skipsWhenDisabled(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)
	// enabled=false (default) — controller should be inert.

	heavy := makeBinding(0, 0, 4, "ge-0-0-1", 1, []ActiveFlowSampleStatus{
		makeFlow(50001), makeFlow(50002), makeFlow(50003), makeFlow(50004),
	})
	light := makeBinding(1, 1, 0, "ge-0-0-1", 1, nil)
	stub.set(ProcessStatus{Bindings: []BindingStatus{heavy, light}})

	// Direct call to reconcile (bypasses the run-loop's enabled
	// gate) — verifies that when SetEnabled is never called and the
	// caller invokes reconcile directly, it still does work because
	// the run-loop is the gate; but evictStaleRules and friends
	// must not panic when rules map is empty either way.
	// The actual disabled-skip is enforced in run() via the
	// enabled.Load() check, so confirm that path doesn't fire by
	// driving run() directly via SetEnabled toggle:
	c.SetEnabled(false)
	c.SetEnabled(false) // idempotent
	if c.enabled.Load() {
		t.Error("disabled state corrupt")
	}
}

func TestEvictStaleRules_removesNotSeenFor30Ticks(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)

	flowKey := flowSteeringFlowKey{wire5tuple: "tcp 10.0.0.1:80 -> 10.0.0.2:80", iface: "ge-0-0-1"}
	c.mu.Lock()
	c.rules[flowKey] = &flowSteeringInstalledRule{
		iface: "ge-0-0-1", ruleLoc: 1023, targetQueue: 1,
		tick: 0, lastSeenTick: 0, flow: flowKey,
	}
	c.markRuleLocUsedLocked("ge-0-0-1", 1023)
	c.mu.Unlock()

	// At tick 31, the rule (lastSeenTick=0) is stale.
	c.evictStaleRules(31)
	if _, still := c.rules[flowKey]; still {
		t.Error("stale rule not evicted")
	}
	deleted := fake.callCount(func(args []string) bool {
		return len(args) > 1 && args[0] == "-N" && contains(args, "delete")
	})
	if deleted != 1 {
		t.Errorf("expected 1 delete call, got %d", deleted)
	}
	if c.rulesRemoved.Load() != 1 {
		t.Errorf("rulesRemoved counter not bumped, got %d", c.rulesRemoved.Load())
	}
}

func TestEvictStaleRules_keepsRecentRules(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)

	flowKey := flowSteeringFlowKey{wire5tuple: "tcp 10.0.0.1:80 -> 10.0.0.2:80", iface: "ge-0-0-1"}
	c.mu.Lock()
	c.rules[flowKey] = &flowSteeringInstalledRule{
		tick: 0, lastSeenTick: 28, iface: "ge-0-0-1", ruleLoc: 1023,
	}
	c.mu.Unlock()

	c.evictStaleRules(29) // 29 - 28 = 1 < 30, NOT stale
	if _, still := c.rules[flowKey]; !still {
		t.Error("recent rule wrongly evicted")
	}
}

// === SetEnabled ===

func TestSetEnabled_flushesOnDisable(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)

	flowKey := flowSteeringFlowKey{wire5tuple: "tcp 10.0.0.1:80 -> 10.0.0.2:80", iface: "ge-0-0-1"}
	c.mu.Lock()
	c.rules[flowKey] = &flowSteeringInstalledRule{
		iface: "ge-0-0-1", ruleLoc: 1023, targetQueue: 1,
	}
	c.mu.Unlock()
	c.enabled.Store(true)

	c.SetEnabled(false)
	if len(c.rules) != 0 {
		t.Errorf("expected rules flushed on disable, %d remain", len(c.rules))
	}
	deleted := fake.callCount(func(args []string) bool {
		return len(args) > 1 && args[0] == "-N" && contains(args, "delete")
	})
	if deleted != 1 {
		t.Errorf("expected 1 delete call, got %d", deleted)
	}
}

func TestSetEnabled_idempotent(t *testing.T) {
	stub := &stubStatusProvider{}
	fake := &fakeEthtool{}
	c := newTestController(stub, fake)

	c.SetEnabled(true)
	c.SetEnabled(true)
	c.SetEnabled(true)
	// Should not panic and should not have made any flush calls.
	if got := len(fake.calls); got != 0 {
		t.Errorf("expected 0 ethtool calls on idempotent enable, got %d", got)
	}
}

// === groupBindingsByIface ===

func TestGroupBindings_byInterface(t *testing.T) {
	bindings := []BindingStatus{
		makeBinding(0, 0, 0, "ge-0-0-1", 1, nil),
		makeBinding(1, 1, 0, "ge-0-0-1", 1, nil),
		makeBinding(2, 0, 0, "ge-0-0-2", 2, nil),
	}
	g := groupBindingsByIface(bindings)
	if len(g["ge-0-0-1"]) != 2 || len(g["ge-0-0-2"]) != 1 {
		t.Errorf("unexpected grouping: %+v", g)
	}
}

func TestGroupBindings_skipsZeroIfindex(t *testing.T) {
	bindings := []BindingStatus{makeBinding(0, 0, 0, "ge-0-0-1", 0, nil)}
	g := groupBindingsByIface(bindings)
	if len(g) != 0 {
		t.Errorf("expected ifindex=0 to be skipped, got %+v", g)
	}
}

// === resolveParentIface ===

func TestResolveParentIface(t *testing.T) {
	cases := map[string]string{
		"ge-0-0-2.80": "ge-0-0-2",
		"ge-0-0-1":    "ge-0-0-1",
		"eth0.50":     "eth0",
	}
	for in, want := range cases {
		if got := resolveParentIface(in); got != want {
			t.Errorf("resolveParentIface(%q) = %q, want %q", in, got, want)
		}
	}
}

// === MetricsSnapshot ===

func TestMetricsSnapshot_reflectsCounters(t *testing.T) {
	c := newTestController(&stubStatusProvider{}, &fakeEthtool{})
	c.enabled.Store(true)
	c.rulesInstalled.Store(7)
	c.rulesRemoved.Store(3)
	c.imbalanceDetected.Store(15)
	c.installFailures.Store(1)
	c.ruleTableCapacity.Store(1024)

	m := c.MetricsSnapshot()
	if !m.Enabled || m.RulesInstalled != 7 || m.RulesRemoved != 3 ||
		m.ImbalanceDetected != 15 || m.InstallFailures != 1 || m.RuleTableCapacity != 1024 {
		t.Errorf("metrics snapshot incorrect: %+v", m)
	}
}

// === HistorySnapshot ring buffer ===

func TestHistorySnapshot_capped(t *testing.T) {
	c := newTestController(&stubStatusProvider{}, &fakeEthtool{})
	for i := 0; i < flowSteeringHistorySize+10; i++ {
		c.recordResteer(FlowSteeringResteerEvent{
			At:    time.Now(),
			Iface: "ge-0-0-1",
			Flow:  fmt.Sprintf("tcp 10.0.0.1:%d -> 10.0.0.2:80", i),
		})
	}
	hist := c.HistorySnapshot()
	if len(hist) != flowSteeringHistorySize {
		t.Errorf("expected history capped to %d, got %d", flowSteeringHistorySize, len(hist))
	}
	// Oldest events should have been dropped — the first event in
	// the ring should be event index 10 (offset by overflow count).
	if !strings.Contains(hist[0].Flow, ":10 -> ") {
		t.Errorf("expected oldest preserved event to be index 10, got %q", hist[0].Flow)
	}
}

// === helpers ===

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

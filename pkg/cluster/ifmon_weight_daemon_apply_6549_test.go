package cluster

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// #6549, second producer: the daemon config-apply tail installs interface-monitor
// debt DIRECTLY, bypassing both the poll path and reconcileMonitorDebtsLocked.
//
// pkg/daemon/daemon_apply_tail.go runs three steps in order on EVERY config apply:
//
//	18.  d.routing.ApplyInterfaceMonitors(...)  (display sample only, #17132)
//	19.  d.cluster.UpdateConfig(cfg.Chassis.Cluster) -> reconcile + PollNow
//	(pre-#17132 19b fed SetMonitorWeight from the routing sample; deleted.)
//
// pkg/routing's monitorManager.Apply USED to copy `mon.Weight` verbatim off
// the compiled *config.InterfaceMonitor, so the (pre-#17132) step 19b fed the
// RAW configured weight into the debt map — overwriting the value step 19a
// had just clamped. #17132 deleted step 19b entirely; these cells now pin
// that UpdateConfig alone (reconcile + PollNow) cannot install raw debt.
//
// That is now closed at TWO independent layers, deliberately: pkg/routing
// bounds the weight where it builds the status so the DISPLAY renders
// the effective (clamped) value, not the raw configured one — display
// only since #17132, never election input — and Manager.SetMonitorWeight
// bounds every debt on the way in so a FUTURE producer that forgets its
// own clamp is still safe.
//
// WHAT THESE TESTS BIND. Because both layers are live, the two
// TestDaemonApplyTail_* cases below fail only when BOTH are removed — either
// clamp alone keeps the end-to-end path safe, which is the whole point of
// layering it. They are the END-TO-END guard, not a single-clamp guard. Each
// individual clamp has its own dedicated binder:
//
//   - Manager.SetMonitorWeight        -> TestSetMonitorWeight_ClosesTheDebtDomain_6549 (this file)
//   - pkg/routing monitorManager.Apply -> TestInterfaceMonitorStatus_WeightIsBounded_6549 (pkg/routing)
//
// Verified by mutation: a compile-clean removal of the SetMonitorWeight clamp
// alone (go vet clean) leaves both TestDaemonApplyTail_* cases GREEN and fails
// TestSetMonitorWeight_ClosesTheDebtDomain_6549; removing both together fails
// the TestDaemonApplyTail_* cases with the fail-open assertions below.
//
// These tests drive the REAL producer (routing.Manager against a fake netlink
// surface) and the REAL consumer in the daemon's exact call order, rather than
// a hand-rolled equivalent.

// applyTailFakeLink is a netlink.Link carrying caller-chosen attrs.
type applyTailFakeLink struct {
	attrs netlink.LinkAttrs
}

func (l *applyTailFakeLink) Attrs() *netlink.LinkAttrs { return &l.attrs }
func (l *applyTailFakeLink) Type() string              { return "apply-tail-fake" }

// applyTailFakeOps satisfies pkg/routing's (unexported) linkOps structurally.
// Only LinkByName is meaningful — the interface-monitor path touches nothing
// else — but the whole surface must be present to be accepted by
// routing.NewManagerWithLinkOpsForTest.
type applyTailFakeOps struct {
	links map[string]netlink.Link
}

func (o *applyTailFakeOps) LinkByName(name string) (netlink.Link, error) {
	if l, ok := o.links[name]; ok {
		return l, nil
	}
	return nil, net.UnknownNetworkError("not found: " + name)
}

func (o *applyTailFakeOps) LinkAdd(netlink.Link) error                     { return nil }
func (o *applyTailFakeOps) LinkDel(netlink.Link) error                     { return nil }
func (o *applyTailFakeOps) LinkSetUp(netlink.Link) error                   { return nil }
func (o *applyTailFakeOps) LinkSetDown(netlink.Link) error                 { return nil }
func (o *applyTailFakeOps) LinkSetMaster(netlink.Link, netlink.Link) error { return nil }
func (o *applyTailFakeOps) LinkSetNoMaster(netlink.Link) error             { return nil }
func (o *applyTailFakeOps) LinkSetMTU(netlink.Link, int) error             { return nil }
func (o *applyTailFakeOps) LinkList() ([]netlink.Link, error)              { return nil, nil }
func (o *applyTailFakeOps) AddrAdd(netlink.Link, *netlink.Addr) error      { return nil }
func (o *applyTailFakeOps) AddrDel(netlink.Link, *netlink.Addr) error      { return nil }
func (o *applyTailFakeOps) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return nil, nil
}

// applyTailLinks builds the fake netlink surface for the monitored interfaces,
// keyed by their LINUX names (monitorManager.Apply translates ge-0/0/0 ->
// ge-0-0-0 before the lookup). Admin-up with carrier down is the realistic
// "cable pulled" shape and is what linkAttrsUp reads as down.
func applyTailLinks(up bool, junosNames ...string) *applyTailFakeOps {
	var oper netlink.LinkOperState = netlink.OperDown
	if up {
		oper = netlink.OperUp
	}
	ops := &applyTailFakeOps{links: make(map[string]netlink.Link, len(junosNames))}
	for _, n := range junosNames {
		linux := config.LinuxIfName(n)
		ops.links[linux] = &applyTailFakeLink{attrs: netlink.LinkAttrs{
			Name:      linux,
			OperState: oper,
			Flags:     net.FlagUp,
		}}
	}
	return ops
}

// runDaemonApplyTail replays pkg/daemon/daemon_apply_tail.go steps 18/19 in the
// daemon's exact order against a real routing.Manager and the cluster Manager.
// #17132: step 19 no longer feeds routing statuses into SetMonitorWeight —
// pkg/cluster.Monitor is the only producer; UpdateConfig's PollNow is the
// commit-time poll. The routing Manager is still exercised (display sample).
func runDaemonApplyTail(m *Manager, rm *routing.Manager, cfg *config.ClusterConfig) {
	rm.ApplyInterfaceMonitors(cfg.RedundancyGroups)
	m.UpdateConfig(cfg)
	drainEvents(m, 8)
}

// TestDaemonApplyTail_OutOfRangeWeightCannotCancelARealFailure_6549 is the
// daemon-path twin of the poll-path and reconcile-path tests: a NEGATIVE
// interface-monitor weight arriving on the tolerant load / peer-sync path is
// negative DEBT, so it credits weight back and cancels the demotion a
// genuinely dead sibling link just applied. Both monitored links are down and
// the node still holds weight 100 and PRIMARY — a fail-open.
//
// This is PERSISTENT, not a transient window: pollInterfaceMonitors re-fires
// SetMonitorWeight only on a dampened state TRANSITION, and there is no
// transition when the link was already down before the config apply. The raw
// debt sits in m.monitorWeights indefinitely.
//
// Fail-on-revert (END-TO-END guard — see the file preamble): drop the
// config.ClampInterfaceMonitorWeight call in BOTH pkg/routing's
// monitorManager.Apply and Manager.SetMonitorWeight, and the debt becomes
// 255 + (-100) = 155, leaving weight 100 and the node primary. Either clamp
// alone keeps this green; that is the layering working, and each clamp has its
// own dedicated binder.
func TestDaemonApplyTail_OutOfRangeWeightCannotCancelARealFailure_6549(t *testing.T) {
	const ifA, ifB = "trust0", "trust1"

	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: ifA, Weight: 255},
		&config.InterfaceMonitor{Interface: ifB, Weight: -100},
	))

	m := NewManager(0, 1)
	// #17132: install the real dampened Monitor (backed by the same fake
	// links, both down) BEFORE the apply, so UpdateConfig's PollNow drives
	// it — the daemon's monitor exists from Start, before any apply.
	downMon := NewMonitor(m, cfg.RedundancyGroups)
	downNlh := newMockNlHandle()
	downNlh.setLink(ifA, false)
	downNlh.setLink(ifB, false)
	downMon.nlHandle = downNlh
	setNoDampening(downMon)
	m.mu.Lock()
	m.monitor = downMon
	m.mu.Unlock()
	rm := routing.NewManagerWithLinkOpsForTest(applyTailLinks(false, ifA, ifB))

	runDaemonApplyTail(m, rm, cfg)

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after the daemon apply tail with both monitored links "+
			"down = %d, want 0 — the raw negative weight the daemon feeds "+
			"SetMonitorWeight credited debt back and cancelled %s's real link "+
			"failure (fail-open)", w, ifA)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node must not hold primary after the daemon apply tail with " +
			"both monitored links down")
	}
	local, advertised := localVsAdvertisedWeight(t, m, 0)
	if local != advertised {
		t.Fatalf("local weight %d but advertised %d", local, advertised)
	}
}

// TestDaemonApplyTail_CannotRegressAClampedDebt_6549 pins the sharper half: the
// daemon tail does not merely miss the clamp, it UNDOES one already installed.
// UpdateConfig clamps the debt (reconcileMonitorDebtsLocked, the layer the
// config-apply path already had), and the SetMonitorWeight loop six lines later
// overwrites it with the raw value — promoting a correctly-demoted group back
// to primary.
//
// Fail-on-revert (END-TO-END guard — see the file preamble): drop the
// config.ClampInterfaceMonitorWeight call in BOTH pkg/routing's
// monitorManager.Apply and Manager.SetMonitorWeight, and the group goes
// 0 -> 100 across the apply tail. Either clamp alone keeps this green.
func TestDaemonApplyTail_CannotRegressAClampedDebt_6549(t *testing.T) {
	const ifA, ifB = "trust0", "trust1"

	cfg := makeConfig(makeRG(0, false, map[int]int{0: 200},
		&config.InterfaceMonitor{Interface: ifA, Weight: 255},
		&config.InterfaceMonitor{Interface: ifB, Weight: -100},
	))

	m := NewManager(0, 1)

	// The clamped poll path runs first and correctly resigns the group.
	nlh := newMockNlHandle()
	nlh.setLink(ifA, true)
	nlh.setLink(ifB, true)
	m.UpdateConfig(cfg)
	drainEvents(m, 8)
	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)
	mon.poll()
	nlh.setLink(ifA, false)
	nlh.setLink(ifB, false)
	mon.poll()
	drainEvents(m, 8)

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("precondition: weight after the clamped poll path = %d, want 0", w)
	}

	// Now the operator commits anything at all. The apply tail re-derives the
	// monitor statuses and re-installs the debt.
	rm := routing.NewManagerWithLinkOpsForTest(applyTailLinks(false, ifA, ifB))
	runDaemonApplyTail(m, rm, cfg)

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after the daemon apply tail = %d, want 0 — the apply "+
			"tail REGRESSED a correctly-demoted redundancy group by overwriting "+
			"the clamped debt with the raw configured weight", w)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("the daemon apply tail promoted a resigned redundancy group " +
			"back to primary with both monitored links down")
	}
}

// TestIPMonitor_OutOfRangeWeightCannotCancelARealFailure_6549 covers the OTHER
// debt class the chokepoint now bounds.
//
// validateChassisClusterStrict carries no compiled-int gate for ip-monitoring
// weights, so their ONLY commit-side defense is the schema's
// ValidateInteger(0,255), which compileTreeLenient downgrades to a warning on
// Store.Load / Store.SyncApply. A negative ip-monitoring weight is therefore
// reachable at runtime and is negative debt exactly like a negative
// interface-monitor weight: it cancels a sibling target's real unreachability.
//
// Fail-on-revert (END-TO-END guard, same shape as the daemon cases above):
// drop the config.ClampInterfaceMonitorWeight call in BOTH
// Monitor.ipTargetWeight and Manager.SetMonitorWeight, and the debt becomes
// 255 + (-100) = 155, leaving weight 100 and the node primary with BOTH
// monitored targets unreachable. Either clamp alone keeps this green — the
// chokepoint bounds what is installed, ipTargetWeight bounds what is computed
// and reported. Their dedicated binders are
// TestSetMonitorWeight_ClosesTheDebtDomain_6549 and
// TestIPMonitor_NegativeWeightCannotMaskTheGlobalThreshold_6549 (the
// global-threshold case the chokepoint provably cannot reach).
func TestIPMonitor_OutOfRangeWeightCannotCancelARealFailure_6549(t *testing.T) {
	const addrA, addrB = "10.0.0.1", "10.0.0.2"

	// Independent mode (no global-threshold): each unreachable target owes its
	// own effective weight.
	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			Targets: []*config.IPMonitorTarget{
				{Address: addrA, Weight: 255},
				{Address: addrB, Weight: -100},
			},
		},
	}
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}

	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 8)

	reach := map[string]bool{addrA: true, addrB: true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight with both targets reachable = %d, want 255", w)
	}

	// Both targets go unreachable. The full-weight one alone resigns the group;
	// the out-of-range one must not credit any weight back.
	reach[addrA] = false
	reach[addrB] = false
	mon.poll()
	drainEvents(m, 8)

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight with both monitored targets unreachable = %d, want 0 — "+
			"a negative ip-monitoring weight credited debt back and cancelled "+
			"%s's real unreachability (fail-open)", w, addrA)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node must not stay primary with both monitored targets unreachable")
	}
}

// TestIPMonitor_NegativeWeightCannotMaskTheGlobalThreshold_6549 is the sharper
// half of the ip-monitoring residual, and the one the SetMonitorWeight
// chokepoint CANNOT close.
//
// In global-threshold (vSRX aggregate) mode each unreachable target's weight
// accumulates into a cumulative sum, and a single global-weight debt is owed
// only while that sum is >= global-threshold. A NEGATIVE target weight
// SUBTRACTS from the sum — so a SECOND genuinely unreachable target pushes the
// cumulative back below the threshold and drops the aggregate debt the FIRST
// failure correctly installed. More failures produce LESS demotion: the group
// returns from weight 0 / SECONDARY to full weight / PRIMARY with every
// monitored target dead.
//
// The chokepoint cannot see this: when the threshold is masked, no debt is
// desired, so SetMonitorWeight is never called at all. Only bounding the value
// where the cumulative sum reads it (Monitor.ipTargetWeight) closes it.
//
// Fail-on-revert: drop the config.ClampInterfaceMonitorWeight call in
// ipTargetWeight and the cumulative becomes 255 + (-100) = 155 < 200, so the
// final assertion sees weight 255 and the node primary.
func TestIPMonitor_NegativeWeightCannotMaskTheGlobalThreshold_6549(t *testing.T) {
	const addrA, addrB = "10.0.0.1", "10.0.0.2"

	rg := &config.RedundancyGroup{
		ID:             0,
		NodePriorities: map[int]int{0: 200},
		IPMonitoring: &config.IPMonitoring{
			GlobalWeight:    255,
			GlobalThreshold: 200,
			Targets: []*config.IPMonitorTarget{
				{Address: addrA, Weight: 255},
				{Address: addrB, Weight: -100},
			},
		},
	}
	cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}

	m := NewManager(0, 1)
	m.UpdateConfig(cfg)
	drainEvents(m, 8)

	reach := map[string]bool{addrA: true, addrB: true}
	mon := NewMonitor(m, cfg.RedundancyGroups)
	injectFakeNl(mon)
	setNoDampening(mon)
	mon.probeFn = reachProbeFn(reach)

	mon.poll()
	if w := m.GroupStates()[0].Weight; w != 255 {
		t.Fatalf("weight with both targets reachable = %d, want 255", w)
	}

	// The weight-255 target alone meets the threshold and resigns the group.
	reach[addrA] = false
	mon.poll()
	drainEvents(m, 8)
	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight with the weight-255 target unreachable = %d, want 0 "+
			"(cumulative 255 >= threshold 200)", w)
	}

	// A SECOND target dies. Demotion must not weaken.
	reach[addrB] = false
	mon.poll()
	drainEvents(m, 8)

	if w := m.GroupStates()[0].Weight; w != 0 {
		t.Fatalf("weight after a SECOND target went unreachable = %d, want 0 — "+
			"the negative ip-monitoring weight subtracted from the cumulative "+
			"failure sum, pushed it back below global-threshold and dropped the "+
			"aggregate debt: more failures produced LESS demotion (fail-open)", w)
	}
	if m.IsLocalPrimary(0) {
		t.Fatal("node must not regain primary when a second monitored target dies")
	}
}

// TestIPMonitor_AggregateGlobalWeightIsBounded_6549 covers the aggregate branch
// of desiredRGIPDebts, where the debt owed once the cumulative failure sum
// reaches global-threshold is the raw configured global-weight.
//
// The SetMonitorWeight chokepoint already bounds what the ELECTION applies, so
// this binds the other half of the contract: the weight recorded in the
// Monitor's own ipDebts ledger — which is what the operator-facing RecordEvent
// ("deducting global-weight N") reports — must equal the weight applied, not
// the raw configured one.
//
// Fail-on-revert: drop the config.ClampInterfaceMonitorWeight call in
// desiredRGIPDebts' aggregate branch and the ledger records 100000 / -100 while
// the election applies 255 / 0.
func TestIPMonitor_AggregateGlobalWeightIsBounded_6549(t *testing.T) {
	tests := []struct {
		name         string
		globalWeight int
		wantDebt     int
		wantRGWeight int
	}{
		{"legal-max", 255, 255, 0},
		{"legal-mid", 100, 100, 155},
		{"over-max", 100000, 255, 0},
		{"negative", -100, 0, 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const addr = "10.0.0.1"

			rg := &config.RedundancyGroup{
				ID:             0,
				NodePriorities: map[int]int{0: 200},
				IPMonitoring: &config.IPMonitoring{
					GlobalWeight:    tt.globalWeight,
					GlobalThreshold: 200,
					Targets:         []*config.IPMonitorTarget{{Address: addr, Weight: 255}},
				},
			}
			cfg := &config.ClusterConfig{RedundancyGroups: []*config.RedundancyGroup{rg}}

			m := NewManager(0, 1)
			m.UpdateConfig(cfg)
			drainEvents(m, 8)

			reach := map[string]bool{addr: true}
			mon := NewMonitor(m, cfg.RedundancyGroups)
			injectFakeNl(mon)
			setNoDampening(mon)
			mon.probeFn = reachProbeFn(reach)
			mon.poll()

			// The weight-255 target alone meets the threshold.
			reach[addr] = false
			mon.poll()
			drainEvents(m, 8)

			mon.mu.Lock()
			debt, installed := mon.ipDebts[0][ipAggregateMonitorName]
			mon.mu.Unlock()
			if !installed {
				t.Fatalf("global-weight %d: no aggregate debt installed "+
					"(cumulative 255 >= threshold 200)", tt.globalWeight)
			}
			if debt != tt.wantDebt {
				t.Errorf("global-weight %d: ipDebts ledger recorded %d, want the "+
					"effective %d — the RecordEvent would report a weight the "+
					"election does not apply", tt.globalWeight, debt, tt.wantDebt)
			}
			if w := m.GroupStates()[0].Weight; w != tt.wantRGWeight {
				t.Errorf("global-weight %d: rg.Weight = %d, want %d",
					tt.globalWeight, w, tt.wantRGWeight)
			}
		})
	}
}

// TestBuildHeartbeat_WireWeightSaturatesAtTheCallSites_6549 binds the layer-4
// belt's CALL SITES, not just the function. clampWireWeight has its own unit
// test, but reverting buildHeartbeat's two uses back to `uint8(...)` produced
// no failure anywhere — the belt could be silently dropped by a refactor.
//
// The upstream clamps make out-of-domain values unreachable through the public
// API, so this reaches inside the package to inject one directly under m.mu,
// mirroring how TestMonitorPoll_LocalAndAdvertisedMonitorWeightAgree_6549
// already installs a Monitor.
//
// Fail-on-revert: restore `Weight: uint8(rg.Weight)` / `Weight: uint8(ls.Weight)`
// in buildHeartbeat and both rows fail — 355 aliases to 99 and -100 to 156.
func TestBuildHeartbeat_WireWeightSaturatesAtTheCallSites_6549(t *testing.T) {
	tests := []struct {
		name     string
		injected int
		want     int
	}{
		{"over-domain-truncates-to-99", 355, 255},
		{"negative-wraps-to-156", -100, 0},
		{"legal-max-unchanged", 255, 255},
		{"legal-mid-unchanged", 128, 128},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const iface = "trust0"

			m := NewManager(0, 1)
			cfg := makeConfig(makeRG(0, false, map[int]int{0: 100},
				&config.InterfaceMonitor{Interface: iface, Weight: 0}))
			m.UpdateConfig(cfg)
			drainEvents(m, 8)

			// A Monitor supplies buildHeartbeat's Monitors section.
			nlh := newMockNlHandle()
			nlh.setLink(iface, true)
			mon := NewMonitor(m, cfg.RedundancyGroups)
			mon.nlHandle = nlh
			setNoDampening(mon)
			mon.poll()

			// Inject an out-of-domain weight on BOTH marshal paths, bypassing
			// every upstream clamp — this is the state a future producer that
			// skips them would create.
			m.mu.Lock()
			m.monitor = mon
			m.groups[0].Weight = tt.injected
			m.mu.Unlock()
			mon.mu.Lock()
			for i := range mon.localStatuses {
				mon.localStatuses[i].Weight = tt.injected
			}
			mon.mu.Unlock()

			pkt, err := UnmarshalHeartbeat(MarshalHeartbeat(m.buildHeartbeat()))
			if err != nil {
				t.Fatalf("UnmarshalHeartbeat: %v", err)
			}
			if len(pkt.Groups) != 1 {
				t.Fatalf("expected 1 advertised group, got %d", len(pkt.Groups))
			}
			if got := int(pkt.Groups[0].Weight); got != tt.want {
				t.Errorf("injected rg.Weight %d advertised as %d, want %d — the "+
					"marshal truncated instead of saturating", tt.injected, got, tt.want)
			}
			if len(pkt.Monitors) != 1 {
				t.Fatalf("expected 1 advertised monitor, got %d", len(pkt.Monitors))
			}
			if got := int(pkt.Monitors[0].Weight); got != tt.want {
				t.Errorf("injected monitor weight %d advertised as %d, want %d",
					tt.injected, got, tt.want)
			}
		})
	}
}

// TestSetMonitorWeight_ClosesTheDebtDomain_6549 states the chokepoint rule
// directly: whatever a caller hands SetMonitorWeight, the installed debt stays
// inside the [0,255] heartbeat weight domain, and the local weight never
// diverges from the advertised one.
//
// This is the DEDICATED binder for the chokepoint clamp, and the only test in
// the #6549 set that fails when that clamp alone is removed. Every current
// producer (the daemon apply tail via pkg/routing, the interface-monitor poll,
// ip-monitoring via ipTargetWeight) bounds its own value first, so the
// end-to-end tests above stay green on a chokepoint-only revert — by design.
// Binding the chokepoint directly here is what keeps it from being silently
// dropped, and what makes a FUTURE producer that forgets its own clamp safe by
// construction.
//
// Fail-on-revert: drop the config.ClampInterfaceMonitorWeight call in
// Manager.SetMonitorWeight and every out-of-range row escapes the domain
// (verified: compile-clean removal, go vet clean, this test the sole red).
func TestSetMonitorWeight_ClosesTheDebtDomain_6549(t *testing.T) {
	tests := []struct {
		name     string
		weight   int
		wantDebt int
	}{
		// Over-reach guard: legal weights must be installed verbatim.
		{"legal-zero", 0, 0},
		{"legal-one", 1, 1},
		{"legal-half", 128, 128},
		{"legal-max", 255, 255},
		// Out-of-range: clamped into the domain.
		{"negative-small", -1, 0},
		{"negative-large", -100, 0},
		{"over-max", 256, 255},
		{"over-max-large", 100000, 255},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const iface = "trust0"

			m := NewManager(0, 1)
			m.UpdateConfig(makeConfig(makeRG(0, false, map[int]int{0: 100},
				&config.InterfaceMonitor{Interface: iface, Weight: 0})))
			drainEvents(m, 8)

			m.SetMonitorWeight(0, iface, true, tt.weight)
			drainEvents(m, 8)

			m.mu.Lock()
			debt := m.monitorWeights[monitorKey{rgID: 0, iface: iface}]
			m.mu.Unlock()
			if debt != tt.wantDebt {
				t.Errorf("SetMonitorWeight(%d) installed debt %d, want %d",
					tt.weight, debt, tt.wantDebt)
			}

			local, advertised := localVsAdvertisedWeight(t, m, 0)
			if local != advertised {
				t.Errorf("weight %d: local %d but advertised %d",
					tt.weight, local, advertised)
			}
			if want := 255 - tt.wantDebt; local != want {
				t.Errorf("weight %d: rg.Weight = %d, want %d", tt.weight, local, want)
			}
		})
	}
}

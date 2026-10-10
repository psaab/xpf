package daemon

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/ipmon"
	"github.com/psaab/xpf/pkg/rpm"
	"github.com/psaab/xpf/pkg/scheduler"
	"golang.org/x/sync/semaphore"
)

// fakeOverlayDP records the actuator's call order against the
// routes-only publish surface.
type fakeOverlayDP struct {
	dataplane.RuntimeDataPlane // nil embed: only the overlay surface is used
	calls                      []string
	publishErr                 error
	publishSkipped             bool // simulate the duplicate-skip (published=false)
	bumpErr                    error
	lastOverlay                []config.RouteOverlayEntry
	lastSchedulerState         map[string]bool
	lastFailClosed             bool
}

func (f *fakeOverlayDP) PublishRouteOverlaySnapshot(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool) (bool, error) {
	return f.PublishRouteOverlaySnapshotWithLatch(cfg, overlay, schedulerState, false)
}

func (f *fakeOverlayDP) PublishRouteOverlaySnapshotWithLatch(cfg *config.Config, overlay []config.RouteOverlayEntry, schedulerState map[string]bool, failClosed bool) (bool, error) {
	f.calls = append(f.calls, "publish")
	f.lastOverlay = overlay
	f.lastSchedulerState = make(map[string]bool, len(schedulerState))
	for name, active := range schedulerState {
		f.lastSchedulerState[name] = active
	}
	f.lastFailClosed = failClosed
	if f.publishErr != nil {
		return false, f.publishErr
	}
	return !f.publishSkipped, nil
}

func (f *fakeOverlayDP) BumpFIBGeneration() (uint32, error) {
	f.calls = append(f.calls, "bump")
	return 1, f.bumpErr
}

func failedIPMonEngine(t *testing.T) *ipmon.Engine {
	t.Helper()
	e := ipmon.New(nil)
	e.Apply(&config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}, nil)
	e.HandleTransition(rpm.Transition{
		ProbeName: "WAN", TestName: "t", Status: "fail",
		Results: []*rpm.ProbeResult{{ProbeName: "WAN", TestName: "t", LastStatus: "fail"}},
	})
	if len(e.ActiveOverlay()) == 0 {
		t.Fatal("engine setup: no overlay after failure")
	}
	return e
}

// TestActuatorPublishesBeforeFIBBump enforces the load-bearing
// ordering (AGY r2-1): BumpFIBGeneration runs ONLY after a successful
// snapshot publish — bumping first would re-resolve established flows
// against the OLD routes and the later snapshot would not
// re-invalidate them.
func TestActuatorPublishesBeforeFIBBump(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell
	d.actuateRouteOverlayLocked(&config.Config{})

	if len(dp.calls) != 2 || dp.calls[0] != "publish" || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump]", dp.calls)
	}
	if len(dp.lastOverlay) != 1 || dp.lastOverlay[0].NextHop != "172.16.80.1" {
		t.Fatalf("published overlay = %+v", dp.lastOverlay)
	}
}

func TestActuatorCarriesSchedulerFailClosedLatch12273(t *testing.T) {
	now := time.Date(2026, time.October, 6, 12, 0, 0, 0, time.UTC)
	sched, _ := scheduler.NewPrimed(
		map[string]*config.SchedulerConfig{"workhours": {Name: "workhours", AllDay: true}},
		func(context.Context, map[string]bool) error { return nil },
		now,
	)
	if !sched.ActiveState()["workhours"] {
		t.Fatal("test precondition: open schedule was not active before stale republish")
	}
	failErr := errors.New("stale scheduler republish")
	sched.RecordRepublishResult(failErr, now.Add(-6*time.Minute))
	sched.RecordRepublishResult(failErr, now)
	if !sched.RepublishFailClosed() {
		t.Fatal("test precondition: scheduler latch was not set")
	}
	if sched.ActiveState()["workhours"] {
		t.Fatal("latched scheduler state must report inactive before route-overlay publish")
	}

	dp := &fakeOverlayDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		ipmon:    failedIPMonEngine(t),
	}
	d.scheduler.Store(sched)
	d.setDataplane(dp)
	if !d.actuateRouteOverlayLocked(&config.Config{}) {
		t.Fatal("latched route-overlay actuation did not converge")
	}
	if !dp.lastFailClosed || dp.lastSchedulerState["workhours"] {
		t.Fatalf("route-overlay publish lost latch disposition: failClosed=%v activeState=%v",
			dp.lastFailClosed, dp.lastSchedulerState)
	}
}

// TestActuatorSkipsBumpOnPublishFailure: a failed publish must NOT
// bump — the helper does not have the new routes yet.
func TestActuatorSkipsBumpOnPublishFailure(t *testing.T) {
	dp := &fakeOverlayDP{publishErr: errors.New("socket down")}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell
	d.actuateRouteOverlayLocked(&config.Config{})

	for _, c := range dp.calls {
		if c == "bump" {
			t.Fatalf("calls = %v: FIB generation bumped after failed publish", dp.calls)
		}
	}
}

// TestAssembleFRRConfigCarriesOverlay: the shared constructor injects
// the active overlay as PreferredRoutes, so BOTH the full apply path
// and the actuator render the failover route — the AGY r2-2
// commit-while-failover-active scenario at the FRR consumer.
func TestAssembleFRRConfigCarriesOverlay(t *testing.T) {
	d := &Daemon{ipmon: failedIPMonEngine(t)}
	cfg := &config.Config{}
	cfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{
		{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
	}

	fc := d.assembleFRRConfig(cfg, d.ipmonActiveOverlay())
	if len(fc.PreferredRoutes) != 1 || fc.PreferredRoutes[0].NextHop != "172.16.80.1" {
		t.Fatalf("PreferredRoutes = %+v, want active overlay", fc.PreferredRoutes)
	}
	// The config baseline stays present (the overlay shadows it at
	// distance 1; it does not REPLACE config statics in FRR).
	if len(fc.StaticRoutes) != 1 {
		t.Fatalf("StaticRoutes = %+v", fc.StaticRoutes)
	}

	// Standby gating: a gated engine yields a baseline render.
	d.ipmon.SetPublishEnabled(false)
	fc = d.assembleFRRConfig(cfg, d.ipmonActiveOverlay())
	if len(fc.PreferredRoutes) != 0 {
		t.Fatalf("PreferredRoutes = %+v on standby, want none", fc.PreferredRoutes)
	}
}

// TestAssembleFRRConfigResolvesOverlayLinkLocal is the #3759 wiring
// check at the assembler: assembleFRRConfig must feed the overlay it is
// handed into inferIPv6StaticNextHopInterfaces so a link-local
// preferred-route next-hop carries an interface scope into the FRR
// render. On revert (the overlay is not passed to the inference) the
// map entry is absent and the assertion fails.
func TestAssembleFRRConfigResolvesOverlayLinkLocal(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Units: map[int]*config.InterfaceUnit{
						50: {Addresses: []string{"2001:559:8585:50::8/64"}},
					},
				},
			},
		},
	}
	overlay := []config.RouteOverlayEntry{
		{Destination: "::/0", NextHop: "fe80::1", Policy: "wan-failover"},
	}

	fc := d.assembleFRRConfig(cfg, overlay)
	if got := fc.IPv6NextHopInterfaces[""]["fe80::1"]; got != "ge-0-0-3.50" {
		t.Fatalf("IPv6NextHopInterfaces[\"\"][fe80::1] = %q, want ge-0-0-3.50 (overlay not fed into inference, #3759)", got)
	}
}

// TestAssembleFRRConfigForwardingInstanceTable (#1827 PR-2): forwarding
// instances map to InstanceConfig{VRFName: "", TableID: <kernel table>}
// so FRR renders their statics with `table <id>` instead of polluting
// the default table; virtual-router instances keep the VRF rendering.
func TestAssembleFRRConfigForwardingInstanceTable(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{Name: "ISP-B", InstanceType: "forwarding", TableID: 100,
			StaticRoutes: []*config.StaticRoute{
				{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.80.1"}}},
			}},
		{Name: "BLUE", InstanceType: "virtual-router", TableID: 101},
	}

	fc := d.assembleFRRConfig(cfg, nil)
	if len(fc.Instances) != 2 {
		t.Fatalf("Instances = %+v, want 2", fc.Instances)
	}
	fwd := fc.Instances[0]
	if fwd.Name != "ISP-B" || fwd.VRFName != "" || fwd.TableID != 100 {
		t.Fatalf("forwarding instance = %+v, want Name=ISP-B VRFName=\"\" TableID=100", fwd)
	}
	vr := fc.Instances[1]
	if vr.Name != "BLUE" || vr.VRFName != "vrf-BLUE" || vr.TableID != 0 {
		t.Fatalf("virtual-router instance = %+v, want Name=BLUE VRFName=vrf-BLUE TableID=0", vr)
	}
}

// TestRPMHAGatingFilter exercises the §4.4 gating scope: only
// policy-referenced or RETH-bound probes are gated, and only while the
// node is secondary for the relevant RG.
func TestRPMHAGatingFilter(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN": {Name: "WAN", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "1.1.1.1", DestinationInterface: "reth0.50"},
		}},
		"plain": {Name: "plain", Tests: map[string]*config.RPMTest{
			"t": {Name: "t", Target: "8.8.8.8"},
		}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"p": {Name: "p", MatchRPMProbe: "WAN"},
	}}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", RedundancyGroup: 1},
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		RedundancyGroups: []*config.RedundancyGroup{{ID: 0}, {ID: 1}},
	}

	gated := rpmProbeGatingRGs(cfg)
	if len(gated) != 1 {
		t.Fatalf("gated = %+v, want only WAN (policy-referenced + RETH-bound)", gated)
	}
	if rg, ok := gated["WAN"]; !ok || rg != 1 {
		t.Fatalf("gated[WAN] = %d/%v, want RG 1 from the bound RETH", rg, ok)
	}
	if _, ok := gated["plain"]; ok {
		t.Fatal("plain probe must keep run-everywhere behavior")
	}
	if got := lowestDataRG(cfg); got != 1 {
		t.Fatalf("lowestDataRG = %d, want 1", got)
	}
}

// TestTakeoverBurstOnlyIncludesNewlyEnabledIPMonProbes11414 keeps the
// takeover acceleration scoped to ip-monitoring probes that were gated off
// before the RG transition; unrelated probes retain normal cadence.
func TestTakeoverBurstOnlyIncludesNewlyEnabledIPMonProbes11414(t *testing.T) {
	cfg := &config.Config{}
	cfg.Services.RPM = &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"WAN":       {Name: "WAN", Tests: map[string]*config.RPMTest{"t": {Name: "t"}}},
		"unrelated": {Name: "unrelated", Tests: map[string]*config.RPMTest{"t": {Name: "t"}}},
	}}
	cfg.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {Name: "wan-failover", MatchRPMProbe: "WAN"},
	}}

	previous := &config.RPMConfig{Probes: map[string]*config.RPMProbe{
		"unrelated": cfg.Services.RPM.Probes["unrelated"],
	}}
	effective := &config.RPMConfig{Probes: cfg.Services.RPM.Probes}
	got := newlyEnabledIPMonProbeNames(cfg, previous, effective)
	if len(got) != 1 {
		t.Fatalf("takeover burst probes = %v, want only newly-enabled WAN", got)
	}
	if _, ok := got["WAN"]; !ok {
		t.Fatalf("takeover burst probes = %v, missing WAN", got)
	}

	previous.Probes["WAN"] = cfg.Services.RPM.Probes["WAN"]
	if got := newlyEnabledIPMonProbeNames(cfg, previous, effective); len(got) != 0 {
		t.Fatalf("already-active probe was burst again: %v", got)
	}

	delete(previous.Probes, "WAN")
	withoutWAN := &config.RPMConfig{Probes: map[string]*config.RPMProbe{"unrelated": cfg.Services.RPM.Probes["unrelated"]}}
	if got := newlyEnabledIPMonProbeNames(cfg, previous, withoutWAN); len(got) != 0 {
		t.Fatalf("inactive probe was burst: %v", got)
	}
}

// TestCommitOverlayForConfigFiltersStaleEntries (Codex PR #1843
// HIGH-1): the overlay riding an operator commit's own publish is
// filtered against the INCOMING config — removed policies and edited
// preferred-route specs drop out; unrelated commits preserve it.
func TestCommitOverlayForConfigFiltersStaleEntries(t *testing.T) {
	d := &Daemon{ipmon: failedIPMonEngine(t)}

	// Unrelated commit: same policy spec in the incoming config.
	same := &config.Config{}
	same.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.1"},
			},
		},
	}}
	if got := d.commitOverlayForConfig(same); len(got) != 1 || got[0].NextHop != "172.16.80.1" {
		t.Fatalf("unrelated commit lost the active overlay: %+v", got)
	}

	// Commit removes the policy → nothing rides the commit.
	if got := d.commitOverlayForConfig(&config.Config{}); got != nil {
		t.Fatalf("removed policy still riding the commit publish: %+v", got)
	}

	// Commit edits the next-hop → the old hop must not ride.
	edited := &config.Config{}
	edited.Services.IPMonitoring = &config.IPMonitoringConfig{Policies: map[string]*config.IPMonitoringPolicy{
		"wan-failover": {
			Name:          "wan-failover",
			MatchRPMProbe: "WAN",
			PreferredRoutes: []*config.PreferredRoute{
				{Destination: "0.0.0.0/0", NextHop: "172.16.80.2"},
			},
		},
	}}
	if got := d.commitOverlayForConfig(edited); got != nil {
		t.Fatalf("stale next-hop riding the commit publish: %+v", got)
	}
}

// TestActuatorSkipsBumpOnDuplicatePublish (Codex PR #1843 MED): when
// the snapshot publish is a duplicate-skip (content unchanged,
// published=false), the actuator must NOT bump the FIB generation —
// the dataplane routes did not move, so invalidating established-flow
// route caches would be pure churn.
func TestActuatorSkipsBumpOnDuplicatePublish(t *testing.T) {
	dp := &fakeOverlayDP{publishSkipped: true}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell
	d.actuateRouteOverlayLocked(&config.Config{})

	if len(dp.calls) != 1 || dp.calls[0] != "publish" {
		t.Fatalf("calls = %v, want [publish] only (no bump on duplicate-skip)", dp.calls)
	}
}

// TestActuatorRetriesUnconfirmedBump (#1844 plan §4.3, Codex r2-1):
// publish succeeds (content hash advances) but the bump_fib_generation
// control message fails. A later duplicate actuation is hash-skipped
// (published=false) — without the pendingFIBBump retry the bump would
// never happen and cached flow routes would stay pinned to the
// pre-failover paths. The retry must fire exactly until confirmed.
func TestActuatorRetriesUnconfirmedBump(t *testing.T) {
	dp := &fakeOverlayDP{bumpErr: errors.New("control socket timeout")}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell

	// Actuation 1: publish OK, bump fails → pending.
	d.actuateRouteOverlayLocked(&config.Config{})
	if len(dp.calls) != 2 || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump]", dp.calls)
	}
	if !d.pendingFIBBump {
		t.Fatal("pendingFIBBump not set after bump failure")
	}

	// Actuation 2: duplicate publish (hash-skip) + bump still failing →
	// the bump IS retried and stays pending.
	dp.publishSkipped = true
	d.actuateRouteOverlayLocked(&config.Config{})
	if len(dp.calls) != 4 || dp.calls[3] != "bump" {
		t.Fatalf("calls = %v, want retried bump on duplicate publish", dp.calls)
	}
	if !d.pendingFIBBump {
		t.Fatal("pendingFIBBump cleared while bump still failing")
	}

	// Actuation 3: bump recovers → retried once more, then confirmed.
	dp.bumpErr = nil
	d.actuateRouteOverlayLocked(&config.Config{})
	if len(dp.calls) != 6 || dp.calls[5] != "bump" {
		t.Fatalf("calls = %v, want final retry bump", dp.calls)
	}
	if d.pendingFIBBump {
		t.Fatal("pendingFIBBump not cleared after confirmed bump")
	}

	// Actuation 4: duplicate publish with NO pending bump → no bump
	// (the plan's named no-churn test).
	d.actuateRouteOverlayLocked(&config.Config{})
	if len(dp.calls) != 7 || dp.calls[6] != "publish" {
		t.Fatalf("calls = %v, want trailing [publish] only", dp.calls)
	}
}

// TestActuatorPublishFailureKeepsPendingBump: a failed publish must
// neither bump nor clear a pending retry — the helper's route state is
// unknown, and the earlier unconfirmed invalidation still owes a bump.
func TestActuatorPublishFailureKeepsPendingBump(t *testing.T) {
	dp := &fakeOverlayDP{publishErr: errors.New("socket down")}
	d := &Daemon{
		applySem:       semaphore.NewWeighted(1),
		ipmon:          failedIPMonEngine(t),
		pendingFIBBump: true,
	}
	d.setDataplane(dp) // #2114: publish through the cell
	d.actuateRouteOverlayLocked(&config.Config{})

	if len(dp.calls) != 1 || dp.calls[0] != "publish" {
		t.Fatalf("calls = %v, want [publish] only", dp.calls)
	}
	if !d.pendingFIBBump {
		t.Fatal("pendingFIBBump lost across a failed publish")
	}
}

// hardFailFRRExec makes BOTH the frr-reload.py primary AND the vtysh -f
// additive fallback fail, so frr.Manager.ApplyFull returns a HARD
// (non-degraded) error — the manager contract's "nothing converged"
// case, where the kernel FIB still holds the previous routes.
type hardFailFRRExec struct{}

func (hardFailFRRExec) Vtysh(context.Context, string) (string, error) { return "", nil }
func (hardFailFRRExec) FrrReloadPy(context.Context, string) error {
	return errors.New("frr-reload.py boom")
}
func (hardFailFRRExec) VtyshLoad(context.Context, string) ([]byte, error) {
	return nil, errors.New("vtysh -f boom")
}

func (hardFailFRRExec) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("vtysh -d -f boom")
}

func (hardFailFRRExec) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("vtysh -d -c boom")
}
func (hardFailFRRExec) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

// TestActuatorAbortsPublishOnHardFRRError is the #3757 H1 regression: a
// HARD FRR reload failure leaves the kernel FIB on the PREVIOUS routes
// (frr manager contract: nothing converged). The actuator must NOT
// publish the userspace snapshot on top — that would split the FIB
// (kernel on the old route, dataplane on the failover route). It must
// abort before the dataplane consumer, report failure so the ipmon
// engine keeps the state dirty and retries, and leave pendingFIBBump
// untouched. On revert (publish regardless of the FRR outcome) dp.calls
// contains "publish" and this goes RED.
func TestActuatorAbortsPublishOnHardFRRError(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		frr:      frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), hardFailFRRExec{}),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell

	if ok := d.actuateRouteOverlayLocked(&config.Config{}); ok {
		t.Fatal("actuator reported success on a hard FRR reload failure")
	}
	if len(dp.calls) != 0 {
		t.Fatalf("calls = %v, want none: a divergent snapshot was published after a hard FRR failure (split FIB)", dp.calls)
	}
	if d.pendingFIBBump {
		t.Fatal("pendingFIBBump set by an aborted actuation")
	}
}

// TestActuatorPublishesOnDegradedFRR: a DEGRADED reload (#1880, the
// additive vtysh -f fallback applied) leaves the new routes LIVE in the
// kernel FIB, so — unlike a hard error — the actuator SHOULD publish the
// matching userspace snapshot (both FIBs agree) and report success. This
// pins the degraded/hard-error distinction so the H1 fix does not
// over-abort on the deliberate warn-and-continue path.
func TestActuatorPublishesOnDegradedFRR(t *testing.T) {
	dp := &fakeOverlayDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		frr:      frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), &frr.RecordingExecutor{ReloadErr: errors.New("frr-reload down")}),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell

	if ok := d.actuateRouteOverlayLocked(&config.Config{}); !ok {
		t.Fatal("actuator reported failure on a DEGRADED (additive-applied) reload")
	}
	if len(dp.calls) != 2 || dp.calls[0] != "publish" || dp.calls[1] != "bump" {
		t.Fatalf("calls = %v, want [publish bump] on a degraded reload", dp.calls)
	}
}

// TestActuateRouteOverlaySkipsWhenResetting pins the #5281 review fold: once a
// factory reset (zeroize) has entered the terminal reset generation, the
// ip-monitoring route-overlay actuator must be a NO-OP. It re-renders
// /etc/frr/frr.conf (the world-readable file carrying the xpf-managed BGP-MD5 /
// OSPF / IS-IS routing-auth keys) from the still-resident in-memory
// ActiveConfig; in the wipe→stop window a probe-flap sweep would otherwise
// re-materialize the just-erased routing-auth keys into a file that survives the
// post-zeroize reboot — defeating the wipe. The actuator must NOT reload FRR and
// NOT publish/bump, and must return false (stay dirty; the daemon is being
// wiped/stopped, so the retry never fires).
//
// RED on revert: removing the isResetting gate lets the actuator render frr.conf
// (RecordingExecutor.ReloadCalls == 1) and publish (dp.calls != nil) — this test
// then fails.
func TestActuateRouteOverlaySkipsWhenResetting(t *testing.T) {
	exec := &frr.RecordingExecutor{} // clean reload — the ungated path WOULD render+publish
	dp := &fakeOverlayDP{}
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		frr:      frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), exec),
		ipmon:    failedIPMonEngine(t),
	}
	d.setDataplane(dp) // #2114: publish through the cell
	d.enterResetGeneration()

	if ok := d.actuateRouteOverlayLocked(&config.Config{}); ok {
		t.Fatal("actuator reported success during a factory reset; must be a no-op (false)")
	}
	if exec.ReloadCalls != 0 {
		t.Fatalf("frr.conf was re-rendered during a factory reset (ReloadCalls=%d): erased routing-auth keys re-materialized", exec.ReloadCalls)
	}
	if len(dp.calls) != 0 {
		t.Fatalf("dataplane actuated during a factory reset: calls = %v (must be none)", dp.calls)
	}
}

// TestActuateRouteOverlayAbortsOnContextCancel is the #3758 regression
// at the exact bug line: actuateRouteOverlay acquires the apply
// semaphore with the ENGINE's actuation context (cancelled on ipmon
// shutdown), not context.Background(). When an unrelated apply holds
// applySem, the actuator blocks in Acquire — and a shutdown, which
// cancels that context, must abort the wait promptly rather than hang
// the ipmon run loop (and, through it, daemon shutdown) behind the
// wedged apply. This test holds applySem, launches the actuator so it
// blocks in Acquire, and asserts a context cancel unblocks it with a
// clean (false, no half-actuation) return. On revert (Acquire uses
// context.Background()) the cancel has no effect, the goroutine stays
// blocked, and the watchdog timeout fires — RED.
func TestActuateRouteOverlayAbortsOnContextCancel(t *testing.T) {
	d := &Daemon{applySem: semaphore.NewWeighted(1)}

	// An unrelated apply holds the semaphore for the whole test.
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("seed Acquire: %v", err)
	}
	defer d.applySem.Release(1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() { done <- d.actuateRouteOverlay(ctx) }()

	// It must be blocked in Acquire (semaphore held) — not returned yet.
	select {
	case <-done:
		t.Fatal("actuateRouteOverlay returned while applySem was held (did not block on Acquire)")
	case <-time.After(50 * time.Millisecond):
	}

	// A shutdown cancels the actuation context — Acquire must abort.
	cancel()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("actuateRouteOverlay returned true after ctx cancel; must abort (false) without actuating")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("actuateRouteOverlay did not abort on ctx cancel (#3758 shutdown-hang regression)")
	}
}

// ipmonCluster builds a single-node (no-peer) cluster.Manager for node 0
// in cluster mode (ControlInterface set) with the given redundancy
// groups. Single-node election promotes a Preempt=true RG to PRIMARY and
// holds a Preempt=false RG at SECONDARY (no peer heartbeat), which lets a
// test express split primaryship deterministically.
func ipmonCluster(rgs ...*config.RedundancyGroup) *cluster.Manager {
	m := cluster.NewManager(0, 1)
	m.UpdateConfig(&config.ClusterConfig{
		RethCount:        len(rgs),
		ControlInterface: "control0",
		RedundancyGroups: rgs,
	})
	// #7161: this fixture is cluster-mode (ControlInterface set) and has never
	// seen a peer, which is a COLD BOOT. Since #7161 the takeover readiness gate
	// applies on cold boot, so an RG that never reports readiness stays
	// SECONDARY — it would forward nothing anyway. Report readiness so the
	// preempt RGs reach PRIMARY and this test can go on being about the ipmon
	// publish gate rather than about election policy.
	for _, rg := range rgs {
		m.SetRGReady(rg.ID, true, nil)
	}
	return m
}

// ipmonClusterCfg builds a minimal *config.Config whose chassis cluster
// declares data RGs with the given IDs — enough for lowestDataRG(cfg)
// and the ipmonPublishAllowed gate.
func ipmonClusterCfg(ids ...int) *config.Config {
	cfg := &config.Config{}
	rgs := make([]*config.RedundancyGroup, len(ids))
	for i, id := range ids {
		rgs[i] = &config.RedundancyGroup{ID: id}
	}
	cfg.Chassis.Cluster = &config.ClusterConfig{RedundancyGroups: rgs}
	return cfg
}

// TestIPMonPublishAllowedAnyPrimary pins the #3764 fix: overlay
// publication is gated on IsLocalPrimaryAny(), not primaryship of the
// lowest data RG. Probe HA gating is already per-RG, so a node only
// genuinely FAILs the policies whose RG it owns — publishing whenever
// primary for ANY RG is precise (node B injects its RG2 route) and has
// zero regression for the single-data-RG common case.
func TestIPMonPublishAllowedAnyPrimary(t *testing.T) {
	// Split-primary two-data-RG cluster: node 0 SECONDARY for RG1 (the
	// lowest data RG) and PRIMARY for RG2. The publish gate must be
	// ENABLED so node 0 injects the RG2 failover route it genuinely owns
	// and detects as failed. Pre-#3764 keyed on IsLocalPrimary(lowestRG)
	// = IsLocalPrimary(1) = false, suppressing the WHOLE overlay here —
	// this assertion goes RED on revert.
	t.Run("split-primary publishes for the owned RG", func(t *testing.T) {
		d := &Daemon{cluster: ipmonCluster(
			&config.RedundancyGroup{ID: 1, NodePriorities: map[int]int{0: 100}, Preempt: false},
			&config.RedundancyGroup{ID: 2, NodePriorities: map[int]int{0: 200}, Preempt: true},
		)}
		if d.cluster.IsLocalPrimary(1) {
			t.Fatal("setup: node must be SECONDARY for RG1 (lowest data RG)")
		}
		if !d.cluster.IsLocalPrimary(2) {
			t.Fatal("setup: node must be PRIMARY for RG2")
		}
		cfg := ipmonClusterCfg(1, 2)
		if got := lowestDataRG(cfg); got != 1 {
			t.Fatalf("setup: lowestDataRG = %d, want 1", got)
		}
		if !d.ipmonPublishAllowed(cfg) {
			t.Fatal("split-primary: publish gate must be ENABLED for the RG2-primary node (RED on revert to the lowest-RG gate)")
		}
	})

	// Single-data-RG cluster (the common case): the new gate must be
	// IDENTICAL to the old IsLocalPrimary(lowestDataRG) gate — asserted as
	// an explicit equivalence for both primary and secondary, so any
	// regression that diverges the two surfaces here.
	t.Run("single-data-RG has zero regression", func(t *testing.T) {
		cfg := ipmonClusterCfg(1)

		dp := &Daemon{cluster: ipmonCluster(
			&config.RedundancyGroup{ID: 1, NodePriorities: map[int]int{0: 200}, Preempt: true},
		)}
		if got, want := dp.ipmonPublishAllowed(cfg), dp.cluster.IsLocalPrimary(lowestDataRG(cfg)); got != want {
			t.Fatalf("single-RG primary: publish=%v, IsLocalPrimary(lowest)=%v — must be equivalent", got, want)
		}
		if !dp.ipmonPublishAllowed(cfg) {
			t.Fatal("single-RG primary: publish must be enabled")
		}

		ds := &Daemon{cluster: ipmonCluster(
			&config.RedundancyGroup{ID: 1, NodePriorities: map[int]int{0: 100}, Preempt: false},
		)}
		if got, want := ds.ipmonPublishAllowed(cfg), ds.cluster.IsLocalPrimary(lowestDataRG(cfg)); got != want {
			t.Fatalf("single-RG secondary: publish=%v, IsLocalPrimary(lowest)=%v — must be equivalent", got, want)
		}
		if ds.ipmonPublishAllowed(cfg) {
			t.Fatal("single-RG secondary: publish must be suppressed")
		}
	})

	// True standby (primary for NO data RG): publication stays suppressed
	// under both the old and new gate.
	t.Run("standby primary-for-none stays suppressed", func(t *testing.T) {
		d := &Daemon{cluster: ipmonCluster(
			&config.RedundancyGroup{ID: 1, NodePriorities: map[int]int{0: 100}, Preempt: false},
			&config.RedundancyGroup{ID: 2, NodePriorities: map[int]int{0: 100}, Preempt: false},
		)}
		if d.cluster.IsLocalPrimaryAny() {
			t.Fatal("setup: node must be primary for NO RG")
		}
		if d.ipmonPublishAllowed(ipmonClusterCfg(1, 2)) {
			t.Fatal("standby (primary for no RG): publish must be suppressed")
		}
	})

	// Standalone (no cluster manager): always publish.
	t.Run("standalone always publishes", func(t *testing.T) {
		d := &Daemon{}
		if !d.ipmonPublishAllowed(&config.Config{}) {
			t.Fatal("standalone: publish must always be allowed")
		}
	})
}

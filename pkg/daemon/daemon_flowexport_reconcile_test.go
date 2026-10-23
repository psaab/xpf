package daemon

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/vrrp"
)

// flowSamplingConfig returns a config that enables NetFlow v9 flow
// export to a single (loopback, unreachable-but-resolvable) collector.
// UDP connect does not require a live listener, so NewExporter succeeds
// with no external dependency.
//
// #2129: it now carries a `services flow-monitoring version9` stanza.
// BuildExportConfig gates the v9 exporter on Version9 != nil (mirroring
// the IPFIX VersionIPFIX guard), so without this stanza no v9 exporter
// would start and the whole reconcile suite below — which asserts the v9
// exporter DOES start — would fail.
func flowSamplingConfig(collector string, rate int) *config.Config {
	cfg := &config.Config{}
	cfg.ForwardingOptions.Sampling = &config.SamplingConfig{
		Instances: map[string]*config.SamplingInstance{
			"s": {
				Name:      "s",
				InputRate: rate,
				FamilyInet: &config.SamplingFamily{
					FlowServers: []*config.FlowServer{
						{Address: collector, Port: 2055},
					},
				},
			},
		},
	}
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		Version9: &config.NetFlowV9Config{
			Templates: map[string]*config.NetFlowV9Template{
				"t": {Name: "t"},
			},
		},
	}
	return cfg
}

// ipfixSamplingConfig augments a v9 sampling config with a
// services flow-monitoring version-ipfix stanza so the IPFIX exporter
// also becomes configured. The base config already sets Version9 (#2129),
// so this config drives BOTH exporters — used by the no-callback-leak and
// independence tests.
//
// #2136: each flow-server now binds to exactly one export version, so to
// drive BOTH exporters this fixture pins the base v9 server explicitly to
// version9 and adds a SECOND, IPFIX-bound flow-server. (An UNBOUND server
// under both global versions resolves to IPFIX only — the documented
// precedence — so leaving the single server unbound would start only the
// IPFIX exporter. That behaviour is asserted directly by
// TestReconcileBothVersionsUnboundServerNoDoubleExport.)
func ipfixSamplingConfig(collector string, rate int) *config.Config {
	cfg := flowSamplingConfig(collector, rate)
	cfg.Services.FlowMonitoring.VersionIPFIX = &config.NetFlowIPFIXConfig{
		Templates: map[string]*config.NetFlowIPFIXTemplate{
			"t": {Name: "t"},
		},
	}
	fam := cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet
	// Pin the existing server to v9 so the v9 exporter keeps its collector.
	fam.FlowServers[0].Version = config.FlowServerVersion9
	// Add a distinct IPFIX-bound collector so the IPFIX exporter also runs.
	fam.FlowServers = append(fam.FlowServers, &config.FlowServer{
		Address: collector, Port: 4739, Version: config.FlowServerVersionIPFIX,
	})
	return cfg
}

// newFlowTestDaemon builds a daemon with the minimum wiring
// reconcileFlowExporters needs: a non-nil EventReader and a daemon
// context.
func newFlowTestDaemon() *Daemon {
	d := &Daemon{
		daemonCtx:   context.Background(),
		eventReader: logging.NewEventReader(nil, nil),
	}
	return d
}

// TestReconcileFlowExporterAddAfterBoot is the headline #2075 fix:
// flow export NOT configured at boot but ADDED in a later commit must
// start the exporter (previously it never started).
func TestReconcileFlowExporterAddAfterBoot(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	// No sampling configured: reconcile is a no-op start.
	if d.reconcileFlowExporters(&config.Config{}) {
		t.Fatal("empty config should not start an exporter")
	}
	if b := d.flowBundle.Load(); b != nil && b.firstExp() != nil {
		t.Fatal("no exporter should exist for empty config")
	}

	// Add sampling in a later commit.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("adding flow export must start the exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("exporter must be live after add-after-boot")
	}
	if len(d.flowExporters) == 0 {
		t.Fatal("d.flowExporter must be set after add-after-boot")
	}
}

// TestReconcileFlowExporterRemoveAfterBoot proves a commit that removes
// flow export stops the exporter (impossible before #2075).
func TestReconcileFlowExporterRemoveAfterBoot(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("exporter must be live")
	}

	// Remove sampling.
	if !d.reconcileFlowExporters(&config.Config{}) {
		t.Fatal("removing flow export must reconcile (stop exporter)")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() != nil {
		t.Fatal("exporter must be stopped after removal")
	}
	if len(d.flowExporters) > 0 {
		t.Fatal("d.flowExporter must be nil after removal")
	}
}

// TestReconcileFlowExporterHashGate proves an unrelated / identical
// commit does NOT bounce a healthy exporter — the SAME exporter
// instance survives, preserving its template-refresh + 1-in-N counter
// state.
func TestReconcileFlowExporterHashGate(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start exporter")
	}
	first := d.flowBundle.Load().firstExp()
	if first == nil {
		t.Fatal("exporter must be live")
	}

	// Identical config: gated (no restart).
	if d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("identical config must be hash-gated (no restart)")
	}
	if got := d.flowBundle.Load().firstExp(); got != first {
		t.Fatal("hash-gated reconcile must keep the SAME exporter instance")
	}

	// A real change re-applies and swaps to a new instance.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.2", 100)) {
		t.Fatal("changed collector must re-apply")
	}
	if got := d.flowBundle.Load().firstExp(); got == first {
		t.Fatal("a real config change must swap to a new exporter instance")
	}
	// A sampling-rate change also re-applies.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.2", 50)) {
		t.Fatal("changed sampling rate must re-apply")
	}
}

// TestReconcileFlowExporterNoCallbackLeak proves the indirection
// callback is registered exactly once across many reconciles — the
// append-only EventReader callback list never grows.
func TestReconcileFlowExporterNoCallbackLeak(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	for i := 0; i < 5; i++ {
		// Alternate collectors so each reconcile actually swaps.
		coll := "127.0.0.1"
		if i%2 == 1 {
			coll = "127.0.0.2"
		}
		d.reconcileFlowExporters(ipfixSamplingConfig(coll, 100))
	}
	// Exactly one open fanout callback + one v9 callback + one IPFIX callback.
	if n := d.eventReader.CallbackCount(); n != 3 {
		t.Fatalf("expected exactly 3 callbacks (open + v9 + ipfix), got %d — callback leak", n)
	}
}

// TestReconcileV9IPFIXIndependence proves the two families gate
// independently: adding IPFIX in a later commit must not bounce the
// running v9 exporter.
func TestReconcileV9IPFIXIndependence(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	// v9 only at first.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("v9 config must start")
	}
	v9 := d.flowBundle.Load().firstExp()
	if v9 == nil {
		t.Fatal("v9 exporter must be live")
	}
	if b := d.ipfixBundlePtr.Load(); b != nil && b.firstExp() != nil {
		t.Fatal("IPFIX must not be configured yet")
	}

	// Add IPFIX in a later commit.
	if !d.reconcileFlowExporters(ipfixSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("adding IPFIX must reconcile")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("IPFIX exporter must be live after add")
	}
	// v9 untouched (same instance).
	if got := d.flowBundle.Load().firstExp(); got != v9 {
		t.Fatal("adding IPFIX must NOT bounce the running v9 exporter")
	}
}

// flowSamplingConfigSrc returns a sampling config that pins a collector
// source-address. An unassignable source IP makes dialCollectors fail,
// exercising the NewExporter create-failure path.
func flowSamplingConfigSrc(collector, source string, rate int) *config.Config {
	cfg := flowSamplingConfig(collector, rate)
	cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet.SourceAddress = source
	return cfg
}

// TestReconcileFlowExporterRetriesAfterCreateFailure proves a transient
// NewExporter failure (here: an unassignable pinned source-address) does
// NOT hash-gate the exporter into a permanently-dead state — a later
// commit (even of a working config) retries and starts it.
func TestReconcileFlowExporterRetriesAfterCreateFailure(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	// 192.0.2.250 (TEST-NET-1) is not assigned to this host, so binding
	// it as a UDP source fails with "cannot assign requested address".
	if !d.reconcileFlowExporters(flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100)) {
		t.Fatal("a create-failing reconcile should still report a change")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() != nil {
		t.Fatal("no exporter should be live after a create failure")
	}
	if d.flowHashSet {
		t.Fatal("the hash must NOT be recorded on a create failure " +
			"(else an identical retry would be gated into a dead exporter)")
	}

	// A later commit with a working config must retry and start.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("a working config after a create failure must start the exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("exporter must recover on the next working commit")
	}
}

// TestApplyConfigLockedReconcilesFlowExporters is the NON-tautological
// apply-wiring guard: it drives the REAL applyConfigLocked body (not the
// applyBodyForTest seam) and asserts the flow exporter started. It FAILS
// if the reconcileFlowExporters call is removed from applyConfigLocked.
//
// Mutation check: delete the `d.reconcileFlowExporters(cfg)` line from
// applyConfigLocked and this test fails — d.flowExporter stays nil after
// committing a config that enables flow-monitoring sampling.
func TestApplyConfigLockedReconcilesFlowExporters(t *testing.T) {
	installFakeNetworkctl(t)
	d := &Daemon{
		applySem:    semaphore.NewWeighted(1),
		vrrpMgr:     vrrp.NewManager(),
		store:       newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		eventReader: logging.NewEventReader(nil, nil),
		daemonCtx:   context.Background(),
		opts:        Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{}) // #2114: publish through the cell
	t.Cleanup(d.stopFlowExporter)

	if err := d.applyConfigLocked(context.Background(), flowSamplingConfig("127.0.0.1", 100)); err != nil {
		t.Fatalf("applyConfigLocked: %v", err)
	}

	if len(d.flowExporters) == 0 {
		t.Fatal("applyConfigLocked did not reconcile the flow exporter: " +
			"a committed forwarding-options sampling stanza left the NetFlow " +
			"exporter unstarted (missing reconcileFlowExporters wiring)")
	}
}

// ipfixOnlySamplingConfig returns a config with sampling + flow-server +
// `services flow-monitoring version-ipfix` but NO `version9` stanza. It is
// the #2129 regression fixture: an IPFIX-only operator must NOT get a v9
// exporter.
func ipfixOnlySamplingConfig(collector string, rate int) *config.Config {
	cfg := flowSamplingConfig(collector, rate)
	// Drop the v9 stanza the base helper installs; keep only IPFIX.
	cfg.Services.FlowMonitoring = &config.FlowMonitoringConfig{
		VersionIPFIX: &config.NetFlowIPFIXConfig{
			Templates: map[string]*config.NetFlowIPFIXTemplate{
				"t": {Name: "t"},
			},
		},
	}
	return cfg
}

// TestReconcileIPFIXOnlyDoesNotStartV9 is the #2129 regression guard:
// a config with sampling + flow-server + version-ipfix but NO version9
// must start the IPFIX exporter and must NOT start the v9 exporter.
// Before the BuildExportConfig Version9 gate, this config started a v9
// exporter too, emitting an unrequested NetFlow v9 stream to the
// collector. If the gate is removed this test fails (v9 exporter live).
func TestReconcileIPFIXOnlyDoesNotStartV9(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(ipfixOnlySamplingConfig("127.0.0.1", 100)) {
		t.Fatal("an IPFIX-only config must reconcile (the IPFIX exporter starts)")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("IPFIX exporter must be live for an IPFIX-only config")
	}
	if b := d.flowBundle.Load(); b != nil && b.firstExp() != nil {
		t.Fatal("#2129: no v9 exporter may start without a `version9` stanza " +
			"— an IPFIX-only operator must not get an unrequested v9 stream")
	}
	if n := d.eventReader.CallbackCount(); n != 1 {
		t.Fatalf("#2129: IPFIX-only config must register exactly 1 callback "+
			"(IPFIX), got %d", n)
	}
}

// bothVersionsUnboundConfig returns sampling with a SINGLE flow-server
// that carries NO per-server version selector, under BOTH global version
// stanzas. Per #2136 the unbound server resolves to IPFIX (documented
// precedence), so this drives ONLY the IPFIX exporter — not both.
func bothVersionsUnboundConfig(collector string, rate int) *config.Config {
	cfg := flowSamplingConfig(collector, rate) // sets Version9
	cfg.Services.FlowMonitoring.VersionIPFIX = &config.NetFlowIPFIXConfig{
		Templates: map[string]*config.NetFlowIPFIXTemplate{"t": {Name: "t"}},
	}
	// The single flow-server stays UNBOUND (no .Version).
	return cfg
}

// TestReconcileBothVersionsUnboundServerNoDoubleExport is the #2136
// regression at the live exporter-wiring layer: a single, unbound
// flow-server configured under BOTH version9 and version-ipfix must
// register exactly ONE session-close callback (IPFIX), not two. Before
// #2136 both exporters started against the same collector and each
// registered its own callback, so every flow was exported twice (one v9
// + one IPFIX datagram). With per-server binding the unbound server
// resolves to IPFIX only, so the v9 exporter never starts.
func TestReconcileBothVersionsUnboundServerNoDoubleExport(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(bothVersionsUnboundConfig("127.0.0.1", 100)) {
		t.Fatal("both-versions config must reconcile (the IPFIX exporter starts)")
	}
	if b := d.ipfixBundlePtr.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("#2136: unbound server under both versions must run the IPFIX exporter")
	}
	if b := d.flowBundle.Load(); b != nil && b.firstExp() != nil {
		t.Fatal("#2136: an UNBOUND collector under both versions must NOT also " +
			"start the v9 exporter — that is the double-export bug")
	}
	// Exactly one callback (IPFIX), not two — the wire-level proof of no
	// double-export to the single collector socket.
	if n := d.eventReader.CallbackCount(); n != 1 {
		t.Fatalf("#2136: both-versions unbound server must register exactly 1 "+
			"callback (IPFIX), got %d — double-export", n)
	}
}

// TestReconcileV9RequiresVersion9Stanza is the positive/negative pair for
// the #2129 gate at the daemon reconcile layer: sampling + flow-server
// alone (no flow-monitoring stanza at all) starts no v9 exporter, and
// adding `version9` in a later commit starts it.
func TestReconcileV9RequiresVersion9Stanza(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	// sampling + flow-server but NO services flow-monitoring stanza.
	cfg := flowSamplingConfig("127.0.0.1", 100)
	cfg.Services.FlowMonitoring = nil
	if d.reconcileFlowExporters(cfg) {
		t.Fatal("#2129: sampling without any flow-monitoring stanza must " +
			"NOT start a v9 exporter (no change to reconcile)")
	}
	if b := d.flowBundle.Load(); b != nil && b.firstExp() != nil {
		t.Fatal("#2129: no v9 exporter may start without a `version9` stanza")
	}

	// Add version9 — now the exporter must start.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("adding version9 must start the v9 exporter")
	}
	if b := d.flowBundle.Load(); b == nil || b.firstExp() == nil {
		t.Fatal("v9 exporter must be live once version9 is configured")
	}
}

// ipfixSamplingConfigSrc pins an unassignable source-address on the
// sampling instance so BOTH the v9 and IPFIX NewExporter builds fail
// (dialCollectors cannot bind the source), exercising the #3742
// build-before-swap failure path for the IPFIX family.
func ipfixSamplingConfigSrc(collector, source string, rate int) *config.Config {
	cfg := ipfixSamplingConfig(collector, rate)
	cfg.ForwardingOptions.Sampling.Instances["s"].FamilyInet.SourceAddress = source
	return cfg
}

// TestReconcileFlowExporterBuildFailureKeepsOldRunning is the #3742
// availability fix: a reconcile whose NEW-exporter build fails must KEEP
// the OLD exporters running (flow export stays UP) rather than tearing the
// healthy set down and disabling export until the next commit.
//
// RED on revert: the pre-#3742 reconcile stopped+closed the old exporters
// BEFORE building the new set, so a NewExporter failure left flowBundle
// empty (firstExp() == nil) and flowExporters nil — export disabled — and
// the assertions below fail.
func TestReconcileFlowExporterBuildFailureKeepsOldRunning(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	// A healthy exporter is running.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start exporter")
	}
	first := d.flowBundle.Load().firstExp()
	if first == nil {
		t.Fatal("exporter must be live before the failing reconcile")
	}

	// A day-2 commit that changes the config hash (so it is NOT gated) but
	// whose NewExporter build fails: 192.0.2.250 (TEST-NET-1) is not
	// assigned to this host, so binding it as a UDP source fails.
	if !d.reconcileFlowExporters(flowSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100)) {
		t.Fatal("a build-failing reconcile should still report a change")
	}

	// #3742: the OLD exporter must still be published and live — export is
	// NOT disabled by the transient build failure.
	if got := d.flowBundle.Load().firstExp(); got != first {
		t.Fatal("#3742: a NewExporter build failure must KEEP the old exporter " +
			"running (export stays up), not tear it down and disable export")
	}
	if len(d.flowExporters) == 0 {
		t.Fatal("#3742: the old exporter set must be retained after a build failure")
	}
	// The hash is NOT recorded, so the next commit retries.
	if d.flowHashSet {
		t.Fatal("#3742: the hash must NOT be recorded on a build failure " +
			"(else an identical retry would gate into the failed state)")
	}
	// The error is surfaced for observability.
	if d.FlowExportError() == nil {
		t.Fatal("#3742: a build failure must surface an error via FlowExportError()")
	}

	// A session-close callback firing now still resolves to the LIVE old
	// exporter (not a dead/empty bundle), so the record is queued into a
	// still-flushing exporter rather than dropped.
	d.flowExportCallback(logging.EventRecord{
		Type:     "SESSION_CLOSE",
		SrcAddr:  "10.0.0.1:1234",
		DstAddr:  "10.0.0.2:80",
		Protocol: "tcp",
	}, nil)

	// A later working commit recovers cleanly and swaps to a NEW exporter.
	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.2", 100)) {
		t.Fatal("a working config after a build failure must reconcile")
	}
	if got := d.flowBundle.Load().firstExp(); got == nil || got == first {
		t.Fatal("a working reconcile after a failure must swap to a NEW live exporter")
	}
	if d.FlowExportError() != nil {
		t.Fatal("a successful reconcile must clear the export error")
	}
}

// TestReconcileIPFIXExporterBuildFailureKeepsOldRunning is the IPFIX
// equivalent of the #3742 availability fix (the IPFIX reconcile path is
// structurally identical).
func TestReconcileIPFIXExporterBuildFailureKeepsOldRunning(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)
	t.Cleanup(d.stopIPFIXExporter)

	if !d.reconcileFlowExporters(ipfixSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start the IPFIX exporter")
	}
	first := d.ipfixBundlePtr.Load().firstExp()
	if first == nil {
		t.Fatal("IPFIX exporter must be live before the failing reconcile")
	}

	if !d.reconcileFlowExporters(ipfixSamplingConfigSrc("127.0.0.1", "192.0.2.250", 100)) {
		t.Fatal("a build-failing reconcile should still report a change")
	}

	if got := d.ipfixBundlePtr.Load().firstExp(); got != first {
		t.Fatal("#3742: an IPFIX NewExporter build failure must KEEP the old " +
			"exporter running, not disable export")
	}
	if len(d.ipfixExporters) == 0 {
		t.Fatal("#3742: the old IPFIX exporter set must be retained after a build failure")
	}
	if d.ipfixHashSet {
		t.Fatal("#3742: the IPFIX hash must NOT be recorded on a build failure")
	}
	if d.IPFIXExportError() == nil {
		t.Fatal("#3742: an IPFIX build failure must surface an error via IPFIXExportError()")
	}
}

// TestReconcileFlowExporterSwapNoCallbackLoss stresses the #3742
// build-before-swap ordering: while session-close callbacks fire
// continuously, repeated reconciles must never publish an empty bundle
// mid-swap — d.flowBundle must always resolve to a LIVE exporter across
// every healthy swap (old -> new, never a gap). Run with -race to catch a
// torn handoff of the per-generation cancel / WaitGroup / bundle triple.
func TestReconcileFlowExporterSwapNoCallbackLoss(t *testing.T) {
	d := newFlowTestDaemon()
	t.Cleanup(d.stopFlowExporter)

	if !d.reconcileFlowExporters(flowSamplingConfig("127.0.0.1", 100)) {
		t.Fatal("initial config must start exporter")
	}

	stop := make(chan struct{})
	var sawEmpty atomic.Bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rec := logging.EventRecord{
			Type:     "SESSION_CLOSE",
			SrcAddr:  "10.0.0.1:1",
			DstAddr:  "10.0.0.2:2",
			Protocol: "tcp",
		}
		for {
			select {
			case <-stop:
				return
			default:
			}
			// The published bundle must always be live during a healthy
			// swap sequence (#3742): it goes old -> new, never empty.
			if b := d.flowBundle.Load(); b == nil || b.firstExp() == nil {
				sawEmpty.Store(true)
			}
			d.flowExportCallback(rec, nil)
		}
	}()

	// Hammer the reconcile with alternating collectors so each call swaps.
	for i := 0; i < 200; i++ {
		coll := "127.0.0.1"
		if i%2 == 1 {
			coll = "127.0.0.2"
		}
		d.reconcileFlowExporters(flowSamplingConfig(coll, 100))
	}
	close(stop)
	wg.Wait()

	if sawEmpty.Load() {
		t.Fatal("#3742: the published bundle was empty mid-swap — a session-" +
			"close callback firing then would be lost")
	}
}

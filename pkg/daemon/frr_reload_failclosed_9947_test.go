package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #9947 F-007: a degraded or hard FRR reload used to report commit success —
// degraded mapped to nil in applyFRRConfig, hard logged-and-continued in
// applyRoutingRules — while stale config (a permit the operator removed)
// stayed installed, up to INDEFINITELY when frr-pythontools is missing
// (the fallback cannot remove and the retry re-invokes the missing
// program forever). The full path now fails the commit closed via its own
// frrErr deferred slot (never via routingRuleErr, which the #9693 owner
// would falsely discharge), with the persistent cause named distinctly.

// TestApplyFRRFullFailsClosedOnHardFailure9947: both reload legs fail, so
// NOTHING converged and live FRR keeps its previous config — the commit
// must fail, not report success.
func TestApplyFRRFullFailsClosedOnHardFailure9947(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{frr: frr.NewForTest(conf, hardFailFRRExec{})}
	err := d.applyFRRFull(&config.Config{}, nil)
	if err == nil {
		t.Fatal("applyFRRFull must fail closed on a hard FRR reload failure; got nil")
	}
	if errors.Is(err, frr.ErrFRRReloadDegraded) {
		t.Fatalf("hard double-failure must not be reported as degraded: %v", err)
	}
	if !strings.Contains(err.Error(), "not yet fully in effect") {
		t.Fatalf("frrErr must tell the operator the change is not in effect, got %v", err)
	}
}

// TestApplyFRRFullFailsClosedOnDegradedTransient9947: the primary fails
// transiently and the additive fallback applies the new lines but defers
// stale removal — the removal the operator asked for did not happen, so
// the commit must fail even though the retry will converge it.
func TestApplyFRRFullFailsClosedOnDegradedTransient9947(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rec := &frr.RecordingExecutor{ReloadErr: errors.New("frr-reload.py: vtysh socket refused")}
	d := &Daemon{frr: frr.NewForTest(conf, rec)}
	err := d.applyFRRFull(&config.Config{}, nil)
	if err == nil {
		t.Fatal("applyFRRFull must fail closed on a transient degraded reload; got nil")
	}
	if !errors.Is(err, frr.ErrFRRReloadDegraded) {
		t.Fatalf("transient degraded frrErr must wrap the degraded sentinel, got %v", err)
	}
	if !d.frr.ReloadDegraded() {
		t.Fatal("CONTROL FAILED: expected the degraded gauge set after a degraded reload")
	}
}

// TestApplyFRRFullFailsClosedOnPytoolsMissing9947: without frr-pythontools
// the fallback cannot remove anything and the retry re-invokes the missing
// program forever, so the unenforced removal is INDEFINITE — returning nil
// would stamp MarkActiveApplied certifying full convergence of a commit
// whose permit removal never took effect. The commit must fail, with the
// persistent cause named (install frr-pythontools).
func TestApplyFRRFullFailsClosedOnPytoolsMissing9947(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rec := &frr.RecordingExecutor{ReloadErr: os.ErrNotExist}
	d := &Daemon{frr: frr.NewForTest(conf, rec)}
	err := d.applyFRRFull(&config.Config{}, nil)
	if err == nil {
		t.Fatal("pytools-missing degraded must fail the commit closed (indefinite unenforced removal); got nil")
	}
	if !errors.Is(err, frr.ErrFRRReloadDegraded) {
		t.Fatalf("pytools-missing frrErr must wrap the degraded sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "frr-pythontools") {
		t.Fatalf("pytools-missing frrErr must name the persistent cause, got %v", err)
	}
	if !d.frr.ReloadDegraded() {
		t.Fatal("pytools-missing must set the degraded gauge")
	}
}

// TestApplyFRRFullFailsClosedOnRemovalUnderPytoolsMissing9947 is the
// removal-bearing shape F-007 exists for: the operator's commit REMOVES a
// static route (a permit-bearing stanza), the reload degrades with the
// script missing, and live FRR keeps the stale route indefinitely. The
// commit must fail rather than certify a removal that never took effect.
func TestApplyFRRFullFailsClosedOnRemovalUnderPytoolsMissing9947(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rec := &frr.RecordingExecutor{ReloadErr: os.ErrNotExist}
	d := &Daemon{frr: frr.NewForTest(conf, rec)}
	oldCfg := &config.Config{}
	oldCfg.RoutingOptions.StaticRoutes = []*config.StaticRoute{{
		Destination: "10.9.9.0/24",
		NextHops:    []config.NextHopEntry{{Address: "192.0.2.1"}},
	}}
	newCfg := &config.Config{}
	// Removal-bearing control: the new assembly carries one fewer route.
	if got := len(d.assembleFRRConfig(oldCfg, nil).StaticRoutes); got != 1 {
		t.Fatalf("CONTROL FAILED: old assembly carries %d static routes, want 1", got)
	}
	if got := len(d.assembleFRRConfig(newCfg, nil).StaticRoutes); got != 0 {
		t.Fatalf("CONTROL FAILED: new assembly carries %d static routes, want 0 (the removal)", got)
	}
	err := d.applyFRRFull(newCfg, nil)
	if err == nil {
		t.Fatal("a removal commit under pytools-missing must fail closed; got nil — " +
			"the stale route stays live while the commit would be certified")
	}
	if !errors.Is(err, frr.ErrFRRReloadDegraded) {
		t.Fatalf("removal frrErr must wrap the degraded sentinel, got %v", err)
	}
}

// TestApplyFRRFullCleanSucceeds9947: positive control — a clean full-diff
// reload reports success and leaves the gauge clear.
func TestApplyFRRFullCleanSucceeds9947(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{frr: frr.NewForTest(conf, &frr.RecordingExecutor{})}
	if err := d.applyFRRFull(&config.Config{}, nil); err != nil {
		t.Fatalf("a clean FRR reload must not fail the commit, got %v", err)
	}
	if d.frr.ReloadDegraded() {
		t.Fatal("a clean reload must leave the degraded gauge clear")
	}
}

// TestApplyTailReconcilesSurfacesFRRError9947 pins the tail errors.Join
// wiring for the new frrErr operand.
func TestApplyTailReconcilesSurfacesFRRError9947(t *testing.T) {
	installFakeNetworkctl(t)

	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	defer func() { nftApplyPayload, nftDeleteTable = origApply, origDelete }()

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"reth0.0"}},
	}

	injected := errors.New("injected: FRR reload did not converge")
	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, injected)
	if err == nil {
		t.Fatal("applyTailReconciles must surface the FRR failure (fail-closed); got nil")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("returned commit error must include the FRR failure, got %v", err)
	}
}

// TestApplyConfigLockedCapturesAndPassesFRRErr9947 is the call-site half
// of the wiring binding (mirrors #6791): the join cell above passes
// frrErr directly, so it stays green if applyConfigLocked stops
// capturing or threading it. It also pins that frrErr is NEVER latched
// into noteRoutingReconcileResult — the #9693 owner re-runs only
// ip-rules + snapshot and would falsely discharge FRR debt.
func TestApplyConfigLockedCapturesAndPassesFRRErr9947(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_apply.go"))

	if !strings.Contains(src, "frrErr := d.applyFRRFull(cfg, commitOverlay)") {
		t.Errorf("applyConfigLocked does not CAPTURE applyFRRFull's error; " +
			"a discarded return value means an FRR non-convergence is still " +
			"reported as commit success (#9947 F-007)")
	}
	call := "d.applyTailReconciles("
	i := strings.Index(src, call)
	if i < 0 {
		t.Fatal("could not find the applyTailReconciles call in daemon_apply.go")
	}
	end := strings.Index(src[i:], ")")
	if end < 0 {
		t.Fatal("malformed applyTailReconciles call")
	}
	if !strings.Contains(src[i:i+end], "frrErr") {
		t.Errorf("applyConfigLocked does not PASS frrErr to "+
			"applyTailReconciles; captured-but-unthreaded is the same false "+
			"success. Call: %s", src[i:i+end+1])
	}
	latch := "d.noteRoutingReconcileResult("
	j := strings.Index(src, latch)
	if j < 0 {
		t.Fatal("could not find the noteRoutingReconcileResult call in daemon_apply.go")
	}
	lend := strings.Index(src[j:], ")")
	if lend < 0 {
		t.Fatal("malformed noteRoutingReconcileResult call")
	}
	if strings.Contains(src[j:j+lend], "frrErr") {
		t.Errorf("frrErr is latched into the routing reconcile debt; the #9693 "+
			"owner re-runs only ip-rules and would falsely discharge it while "+
			"FRR is still broken. Call: %s", src[j:j+lend+1])
	}
}

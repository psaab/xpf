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
// stayed installed. The full path now fails the commit closed via its own
// frrErr deferred slot (never via routingRuleErr, which the #9693 owner
// would falsely discharge), tolerating only the persistent
// pytools-missing degraded state.

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

// TestApplyFRRFullToleratesPytoolsMissing9947: without frr-pythontools
// EVERY reload degrades until the package is installed — failing the
// commit there would red every commit with no operator action short of
// installing the package, so it stays warn-and-continue with gauge +
// slow retry (the #1880 tolerated persistent state).
func TestApplyFRRFullToleratesPytoolsMissing9947(t *testing.T) {
	conf := filepath.Join(t.TempDir(), "frr.conf")
	if err := os.WriteFile(conf, []byte("log syslog informational\n"), 0644); err != nil {
		t.Fatal(err)
	}
	rec := &frr.RecordingExecutor{ReloadErr: os.ErrNotExist}
	d := &Daemon{frr: frr.NewForTest(conf, rec)}
	if err := d.applyFRRFull(&config.Config{}, nil); err != nil {
		t.Fatalf("pytools-missing degraded must stay tolerated (nil), got %v", err)
	}
	if !d.frr.ReloadDegraded() {
		t.Fatal("tolerated pytools-missing must still set the degraded gauge")
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

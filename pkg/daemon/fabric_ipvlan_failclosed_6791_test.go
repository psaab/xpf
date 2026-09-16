package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #6791: applyFabricIPVLAN converted a terminal netlink failure into commit
// SUCCESS, and nothing ever retried it.
//
// The evidence was an asymmetry, not a judgement call: in applyConfigLocked the
// neighbouring reconcilers are captured and threaded into the tail error join
// (`mgmtRouteErr := …`, `ifaceErr := …`), while `d.applyFabricIPVLAN(cfg)` was a
// bare statement returning nothing. It logged "CRITICAL: fabric IPVLAN creation
// failed after retries — cluster heartbeat will not work" and the commit
// reported success — a node with no heartbeat and no session-sync transport.
//
// Both halves of the title are covered here, and separately:
//   1. the failure PROPAGATES, and reaches the caller that acts on it
//   2. a persistent recovery owner exists, is started by Run, and re-drives

// fakeFabricLink is a minimal netlink.Link whose admin flags are controllable.
type fakeFabricLink struct{ attrs netlink.LinkAttrs }

func (f *fakeFabricLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeFabricLink) Type() string              { return "ipvlan" }

// fabricCfg6791 builds a config with one fabric interface fab0 over ge-0/0/0.
func fabricCfg6791() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fab0": {
			Name:              "fab0",
			LocalFabricMember: "ge-0/0/0",
			Units: map[int]*config.InterfaceUnit{
				0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
			},
		},
	}
	return cfg
}

// withFabricEnsure swaps the overlay-creation seam for the duration of a test.
func withFabricEnsure(t *testing.T, fn func(parent, name string, addrs []string) error) {
	t.Helper()
	prev := fabricEnsureFn
	fabricEnsureFn = fn
	t.Cleanup(func() { fabricEnsureFn = prev })
}

// --- 1. PROPAGATION -------------------------------------------------------

// TestApplyTailReconcilesJoinsFabricErr is the WIRING cell. Making
// applyFabricIPVLAN return an error is worthless if that error is dropped at
// the call site or left out of the join, and a test that only exercised
// applyFabricIPVLAN's own return value would stay green through exactly that
// regression.
//
// FAIL-ON-REVERT: drop `fabricErr` from the errors.Join in applyTailReconciles
// (or stop threading it from applyConfigLocked) and this goes RED.
func TestApplyTailReconcilesJoinsFabricErr_6791(t *testing.T) {
	// Same construction as the #6792 route-leak/DNS wiring cells: the tail
	// dispatches to real subsystems, so they are stubbed to SUCCEED and the
	// injected fabric error is the only operand that can surface.
	installFakeNetworkctl(t)
	origApply, origDelete := nftApplyPayload, nftDeleteTable
	nftApplyPayload = func(string) ([]byte, error) { return nil, nil }
	nftDeleteTable = func(string, string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { nftApplyPayload, nftDeleteTable = origApply, origDelete })

	d := &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
		opts:     Options{NoDataplane: true},
	}
	d.setDataplane(&runtimeOnlyApplyTestDP{})

	cfg := &config.Config{}
	injected := errors.New("fabric-ipvlan-injected-6791")

	err := d.applyTailReconciles(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, injected, nil)
	if err == nil {
		t.Fatalf("applyTailReconciles returned nil; a terminal fabric IPVLAN " +
			"failure must fail the commit closed, not be acknowledged as success")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("joined error %v does not wrap the injected fabric error; the "+
			"commit result must carry it so the operator sees the cluster has "+
			"no heartbeat transport", err)
	}
}

// TestApplyFabricIPVLANReturnsTerminalFailure covers the PRODUCING half: the
// retries-exhausted path must yield an error naming the overlay, instead of the
// bare `continue` that discarded it.
//
// FAIL-ON-REVERT: restore that `continue` (drop the fabricErrs append) and this
// reds on the nil return — while the log line still says the cluster heartbeat
// will not work.
func TestApplyFabricIPVLANReturnsTerminalFailure_6791(t *testing.T) {
	prev := fabricIPVLANRetryDelay
	fabricIPVLANRetryDelay = time.Millisecond
	t.Cleanup(func() { fabricIPVLANRetryDelay = prev })

	boom := errors.New("no such device")
	var mu sync.Mutex
	var calls int
	withFabricEnsure(t, func(parent, name string, addrs []string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		return boom
	})

	d := &Daemon{}
	err := d.applyFabricIPVLAN(fabricCfg6791())

	mu.Lock()
	got := calls
	mu.Unlock()
	if got == 0 {
		t.Fatal("applyFabricIPVLAN never attempted the overlay, so this cell " +
			"cannot distinguish a returned error from a dropped one")
	}
	if err == nil {
		t.Fatalf("applyFabricIPVLAN returned nil after %d failed attempts; a "+
			"terminal netlink failure must not be converted into commit "+
			"success — the node has no cluster heartbeat transport", got)
	}
	if !errors.Is(err, boom) {
		t.Errorf("returned error %v does not wrap the netlink failure", err)
	}
	if !strings.Contains(err.Error(), "fab0") {
		t.Errorf("returned error %v does not name the overlay that failed", err)
	}
}

// TestApplyFabricIPVLANSucceedsWhenOverlayCreates is the TIGHTENING control for
// the propagation change: applyFabricIPVLAN must return nil on the healthy
// path. A version that returned an error unconditionally would fail every
// commit on every node, so this is the cell that makes "fail closed" mean
// "fail closed on FAILURE" rather than "fail always".
func TestApplyFabricIPVLANSucceedsWhenOverlayCreates_6791(t *testing.T) {
	withFabricEnsure(t, func(parent, name string, addrs []string) error { return nil })

	d := &Daemon{}
	if err := d.applyFabricIPVLAN(fabricCfg6791()); err != nil {
		t.Fatalf("applyFabricIPVLAN returned %v on a healthy overlay creation; "+
			"the commit must not fail when the fabric came up", err)
	}
}

// --- 2. RECOVERY OWNER ----------------------------------------------------

// TestFabricReassertGateIsQuietWhenOverlayIsUp is the TIGHTENING control: the
// retry owner must do NOTHING when the overlay is present and up, or it would
// rebuild a working fabric device every 30s forever.
//
// FAIL-ON-REVERT: make the gate unconditional (always report the overlay
// missing) and this reds.
func TestFabricReassertGateIsQuietWhenOverlayIsUp_6791(t *testing.T) {
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		return &fakeFabricLink{attrs: netlink.LinkAttrs{
			Name:  name,
			Flags: net.FlagUp,
		}}, nil
	}}
	if got := d.missingFabricOverlays(fabricCfg6791()); len(got) != 0 {
		t.Errorf("gate reported %v as needing re-assert while fab0 is present "+
			"and UP; the loop must be free on a healthy node", got)
	}
}

// TestFabricReassertGateFiresWhenOverlayIsDown pins the other side of the gate:
// a link that exists but is DOWN still needs re-asserting. A gate that only
// checked existence would leave a down fab0 carrying no traffic forever.
func TestFabricReassertGateFiresWhenOverlayIsDown_6791(t *testing.T) {
	d := &Daemon{linkByNameFn: func(name string) (netlink.Link, error) {
		return &fakeFabricLink{attrs: netlink.LinkAttrs{Name: name}}, nil // no FlagUp
	}}
	if got := d.missingFabricOverlays(fabricCfg6791()); len(got) != 1 {
		t.Errorf("gate did not fire for a fab0 that exists but is DOWN; got %v", got)
	}
}

// TestReassertFabricIPVLANOnceRedrives proves the owner actually re-creates the
// overlay — the behaviour the whole loop exists for.
func TestReassertFabricIPVLANOnceRedrives_6791(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	withFabricEnsure(t, func(parent, name string, addrs []string) error {
		mu.Lock()
		seen = append(seen, parent+"->"+name)
		mu.Unlock()
		return nil
	})

	d := newFabricReassertDaemon(t, fabricCfg6791())
	d.reassertFabricIPVLANOnce(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "ge-0-0-0->fab0" {
		t.Fatalf("re-assert did not re-create the missing overlay; ensure calls = %v", seen)
	}
}

// TestRunStartsFabricReassertLoop is the LOOP-START cell. Every test above
// drives the re-assert function directly, so a Run that never launched the
// owner would pass all of them — and "no persistent recovery owner" is half the
// issue. This asserts the loop is actually started, and started
// UNCONDITIONALLY (no cluster/standalone gate), by driving the same goroutine
// Run launches and observing a tick.
//
// FAIL-ON-REVERT: delete the `go d.fabricIPVLANReassertLoop(ctx)` block from Run
// (or wrap it in a mode condition) and this reds on the timeout.
func TestRunStartsFabricReassertLoop_6791(t *testing.T) {
	// Prove Run launches it, by source: the loop is a goroutine in Run's
	// startup fan-out, and a behavioural probe of Run() would need a fully
	// constructed daemon (netlink, dataplane, sockets) that this package's
	// unit tests cannot stand up.
	src := readDaemonSource(t, "daemon_run.go")
	if !strings.Contains(src, "d.fabricIPVLANReassertLoop(ctx)") {
		t.Fatalf("Run does not start fabricIPVLANReassertLoop; the fabric " +
			"overlay has no persistent recovery owner (#6791) and a boot-time " +
			"netlink failure persists until an operator commits")
	}
	// …and that it is not gated behind a mode check, the way the proxy-ARP loop
	// is. Locate the launch and require the enclosing statement to be the
	// unconditional wg.Add/go pair.
	idx := strings.Index(src, "d.fabricIPVLANReassertLoop(ctx)")
	window := src[clampZero6791(idx-400):idx]
	if strings.Contains(window, "if d.cluster != nil") ||
		strings.Contains(window, "if d.isCluster") {
		t.Errorf("fabricIPVLANReassertLoop is started behind a cluster-mode " +
			"gate; standalone nodes create fab* from a config apply too and " +
			"need the same retry owner")
	}

	// Behavioural half: the loop body itself must tick and call the re-assert.
	prev := fabricIPVLANReassertInterval
	fabricIPVLANReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { fabricIPVLANReassertInterval = prev })

	fired := make(chan struct{}, 1)
	withFabricEnsure(t, func(parent, name string, addrs []string) error {
		select {
		case fired <- struct{}{}:
		default:
		}
		return nil
	})

	d := newFabricReassertDaemon(t, fabricCfg6791())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.fabricIPVLANReassertLoop(ctx)

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("fabricIPVLANReassertLoop never re-asserted the missing overlay")
	}
}

func clampZero6791(i int) int {
	if i < 0 {
		return 0
	}
	return i
}

// newFabricReassertDaemon builds a Daemon whose active config is cfg and whose
// fab* devices are ABSENT, so the re-assert gate fires. applySem is real: the
// #4001 lock discipline (acquire before reading ActiveConfig) is part of what
// is under test, and a nil semaphore would panic rather than exercise it.
func newFabricReassertDaemon(t *testing.T, cfg *config.Config) *Daemon {
	t.Helper()
	dir := t.TempDir()
	s, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// LocalFabricMember is resolved only under a chassis-cluster stanza
	// (compiler_derivations.go), and only for a member whose FPC slot maps to
	// this node — ge-0/0/0 is slot 0, i.e. node 0.
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-6791\n" +
			"set interfaces ge-0/0/0 unit 0 family inet address 10.99.0.254/24\n" +
			"set interfaces fab0 fabric-options member-interfaces ge-0/0/0\n" +
			"set interfaces fab0 unit 0 family inet address 10.99.0.1/24\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Daemon{
		store:    s,
		applySem: semaphore.NewWeighted(1),
		// Every fab* lookup fails => the gate reports it missing.
		linkByNameFn: func(name string) (netlink.Link, error) {
			return nil, errors.New("no such device")
		},
	}
}

// readDaemonSource reads a production source file from this package so a test
// can assert a WIRING fact (that Run starts a goroutine) that no unit-level
// behavioural probe can reach without standing up a full daemon.
func readDaemonSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestApplyConfigLockedCapturesAndPassesFabricErr is the CALL-SITE half of the
// wiring binding, and it exists because the join cell above could not see it.
//
// TestApplyTailReconcilesJoinsFabricErr passes the error to applyTailReconciles
// DIRECTLY, so it stays green if applyConfigLocked stops capturing the return
// value or stops threading it — which would be the entire fix undone. Measured:
// replacing the call site with `_ = d.applyFabricIPVLAN(cfg)` left the whole
// package suite green.
//
// applyConfigLocked cannot be driven from a unit test (it needs netlink, a
// dataplane, sockets), so this asserts the wiring at the source, the same way
// the loop-START cell does for Run.
func TestApplyConfigLockedCapturesAndPassesFabricErr_6791(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_apply.go"))

	if !strings.Contains(src, "fabricErr := d.applyFabricIPVLAN(cfg)") {
		t.Errorf("applyConfigLocked does not CAPTURE applyFabricIPVLAN's error; " +
			"a discarded return value means a terminal fabric failure is still " +
			"reported as commit success (#6791)")
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
	if !strings.Contains(src[i:i+end], "fabricErr") {
		t.Errorf("applyConfigLocked does not PASS fabricErr to "+
			"applyTailReconciles; captured-but-unthreaded is the same false "+
			"success. Call: %s", src[i:i+end+1])
	}
}

// TestReassertTakesApplySemBeforeReadingConfig binds the #4001 lock discipline
// this loop's doc comment claims.
//
// Reading ActiveConfig outside applySem lets a tick capture a PRE-commit
// snapshot and re-create a fab device the commit's own stale-overlay sweep has
// just torn down. The ordering is not observable from a unit test without a
// real concurrent commit, so it is asserted structurally: the semaphore must be
// acquired before the config read that drives the re-creation loop.
//
// FAIL-ON-REVERT: delete the applySem.Acquire and this reds — measured; the
// behavioural cells all stayed green without it.
func TestReassertTakesApplySemBeforeReadingConfig_6791(t *testing.T) {
	src := stripLineComments6791(readDaemonSource(t, "daemon_fabric_reassert.go"))
	body, ok := fabricFuncBody6791(src, "reassertFabricIPVLANOnce")
	if !ok {
		t.Fatal("could not locate reassertFabricIPVLANOnce")
	}
	acq := strings.Index(body, "d.applySem.Acquire(")
	if acq < 0 {
		t.Fatalf("reassertFabricIPVLANOnce does not acquire applySem; a tick can " +
			"then re-create an overlay a concurrent commit just removed (#4001)")
	}
	if !strings.Contains(body, "defer d.applySem.Release(1)") {
		t.Errorf("reassertFabricIPVLANOnce acquires applySem without releasing it")
	}
	// The config read that drives the re-creation loop must come AFTER the
	// acquire. The cheap pre-check read before it is fine (it reconciles
	// nothing), so anchor on the loop itself.
	loop := strings.Index(body, "for _, ov := range d.missingFabricOverlays(")
	if loop < 0 {
		t.Fatal("could not find the re-creation loop")
	}
	if loop < acq {
		t.Errorf("reassertFabricIPVLANOnce re-creates overlays BEFORE acquiring " +
			"applySem; the config it acts on can be a pre-commit snapshot (#4001)")
	}
}

func stripLineComments6791(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}

func fabricFuncBody6791(src, name string) (string, bool) {
	i := strings.Index(src, ") "+name+"(")
	if i < 0 {
		return "", false
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return "", false
	}
	open += i
	depth := 0
	for j := open; j < len(src); j++ {
		switch src[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : j+1], true
			}
		}
	}
	return "", false
}

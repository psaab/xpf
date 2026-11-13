package daemon

// shutdown_frr_statics_19083_test.go — #19083: a graceful HA stop must not
// leave this node's RG-owned FRR statics behind.
//
// The defect (confirmed on loss, #19083 issuecomment-6767898063): shutdown
// cancels the apply context first, so the demotion's coalesced FRR reconcile
// cannot render, and frr.Stop() clears nothing. FRR outlives xpfd, so the
// stopped node keeps every owned static. After the VIPs go, a non-default
// static resolves through the cluster Null0 default and stays ACTIVE as a
// kernel blackhole that redistribution can export. The design
// (issuecomment-6858271088, coordinator answers Q1-Q3) REMOVES them: before
// frr.Stop() and after cluster.Stop(), every graceful HA stop (lone node,
// peered, hitless) applies a non-owner render, so the owned RETH statics leave
// the managed section and a full frr-reload.py removes them from FRR. A
// standalone stop is untouched.
//
// These cells drive the real runShutdownSequence and read frr.conf and the FRR
// executor afterwards, so they pin the wiring, not a helper.

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/frr"
)

const shutdownClusterSet19083 = "" +
	"set chassis cluster cluster-id 1\n" +
	"set chassis cluster node 0\n" +
	"set chassis cluster reth-count 1\n" +
	"set chassis cluster redundancy-group 0 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 0 node 1 priority 100\n" +
	"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
	"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
	"set chassis cluster authentication-key test-cluster-psk-6611\n" +
	"set chassis cluster control-interface em0\n" +
	"set chassis cluster peer-address 10.99.0.2\n" +
	"set interfaces em0 unit 0 family inet address 10.99.0.1/24\n" +
	"set interfaces ge-0/0/2 gigether-options redundant-parent reth0\n" +
	"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
	"set interfaces reth0 unit 0 family inet address 172.16.50.8/24\n" +
	"set interfaces ge-0/0/3 unit 0 family inet address 192.0.2.1/24\n" +
	"set routing-options static route 0.0.0.0/0 next-hop 172.16.50.1\n" +
	"set routing-options static route 198.51.100.0/24 next-hop 172.16.50.1\n" +
	"set routing-options static route 203.0.113.0/24 next-hop 192.0.2.254\n"

const (
	ownedDefault19083 = "ip route 0.0.0.0/0 172.16.50.1"
	ownedStatic19083  = "ip route 198.51.100.0/24 172.16.50.1"
	localStatic19083  = "ip route 203.0.113.0/24 192.0.2.254" // node-local egress: never RG-owned
)

// reloadRecorder19083 records every FrrReloadPy: whether the manager's
// lifetime context was already cancelled (frr.Stop ran) and the frr.conf the
// reload was asked to converge to.
type reloadRecorder19083 struct {
	*frr.RecordingExecutor
	confPath string
	mu       sync.Mutex
	reloads  []reload19083
}

type reload19083 struct {
	stopped bool
	conf    string
}

func (r *reloadRecorder19083) FrrReloadPy(ctx context.Context, conf string) error {
	b, _ := os.ReadFile(conf)
	r.mu.Lock()
	r.reloads = append(r.reloads, reload19083{stopped: ctx.Err() != nil, conf: string(b)})
	r.mu.Unlock()
	return r.RecordingExecutor.FrrReloadPy(ctx, conf)
}

func (r *reloadRecorder19083) snapshot() []reload19083 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]reload19083(nil), r.reloads...)
}

type shutdownArm19083 int

const (
	armLone19083 shutdownArm19083 = iota
	armPeered19083
	armHitless19083
	armStandalone19083
)

// shutdownDaemon19083 is an RG1 owner whose managed section holds the owned
// statics, written by a real FRR apply, ready to be stopped gracefully.
func shutdownDaemon19083(t *testing.T, arm shutdownArm19083) (*Daemon, *reloadRecorder19083) {
	t.Helper()
	set := shutdownClusterSet19083
	switch arm {
	case armHitless19083:
		set += "set chassis cluster hitless-restart\n"
	case armStandalone19083:
		var keep []string
		for _, l := range strings.Split(set, "\n") {
			if !strings.HasPrefix(l, "set chassis cluster") && !strings.Contains(l, "reth") {
				keep = append(keep, l)
			}
		}
		set = strings.Join(keep, "\n") +
			"set interfaces ge-0/0/2 unit 0 family inet address 172.16.50.8/24\n"
	}
	if arm != armHitless19083 {
		seamTransitClose9686(t) // a fail-closed or standalone stop closes transit
	}
	store := fenceTestStore(t, set)
	cfg := store.ActiveConfig()
	daemonCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rec := &reloadRecorder19083{RecordingExecutor: &frr.RecordingExecutor{}, confPath: filepath.Join(t.TempDir(), "frr.conf")}
	d := &Daemon{
		store:              store,
		applySem:           semaphore.NewWeighted(1),
		daemonCtx:          daemonCtx,
		frr:                frr.NewForTest(rec.confPath, rec),
		directRemoveVIPsFn: func(int) int { return 0 },
	}
	applyCtx, applyCancel := context.WithCancel(context.Background())
	d.applyCancelContext, d.applyCancel = applyCtx, applyCancel
	if arm != armStandalone19083 {
		if cfg.Chassis.Cluster == nil {
			t.Fatal("premise: the HA arms need a cluster config")
		}
		cm := cluster.NewManager(0, 1)
		cm.UpdateConfig(cfg.Chassis.Cluster)
		for drained := true; drained; {
			select {
			case <-cm.Events():
			default:
				drained = false
			}
		}
		cm.SetGroupStateForTesting(0, cluster.StatePrimary)
		cm.SetGroupStateForTesting(1, cluster.StatePrimary)
		if arm == armPeered19083 {
			cm.SetPeerGroupStateForTesting(0, cluster.StateSecondary)
			cm.SetPeerGroupStateForTesting(1, cluster.StateSecondary)
		}
		d.cluster = cm
	} else if cfg.Chassis.Cluster != nil {
		t.Fatal("premise: the standalone arm must have no cluster config")
	}
	if err := d.frr.ApplyFullIfCurrent(d.assembleFRRConfig(cfg, nil), func() bool { return true }); err != nil {
		t.Fatalf("owner apply: %v", err)
	}
	section := managedSection19083(t, rec)
	for _, l := range []string{ownedDefault19083, ownedStatic19083, localStatic19083} {
		if !strings.Contains(section, l) {
			t.Fatalf("premise: the owner's managed section must hold %q:\n%s", l, section)
		}
	}
	return d, rec
}

func managedSection19083(t *testing.T, rec *reloadRecorder19083) string {
	t.Helper()
	b, err := os.ReadFile(rec.confPath)
	if err != nil {
		t.Fatal(err)
	}
	begin, end := frr.ManagedSectionMarkersForTest()
	s := string(b)
	i := strings.Index(s, begin)
	if i < 0 {
		return ""
	}
	s = s[i:]
	if j := strings.Index(s, end); j >= 0 {
		s = s[:j]
	}
	return s
}

func runShutdown19083(t *testing.T, d *Daemon) {
	t.Helper()
	var wg sync.WaitGroup
	_, stopRun := context.WithCancel(context.Background())
	sentinel := errors.New("run-error-passthrough")
	done := make(chan error, 1)
	go func() { done <- d.runShutdownSequence(context.Background(), &wg, stopRun, sentinel) }()
	select {
	case got := <-done:
		if !errors.Is(got, sentinel) {
			t.Fatalf("runShutdownSequence returned %v, want the run error passed through", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runShutdownSequence did not return within 30s")
	}
}

// TestGracefulHAStopRemovesOwnedStatics19083: in every graceful HA stop shape
// the owned RETH statics leave the managed section, and a full FRR reload of
// that section runs BEFORE frr.Stop (its lifetime context still live), so FRR
// removes them too. The node-local static stays.
func TestGracefulHAStopRemovesOwnedStatics19083(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  shutdownArm19083
	}{
		{"lone-node", armLone19083},  // no live peer: the resign is a no-op (Q1: remove anyway)
		{"peered", armPeered19083},   // the resign demotes every RG
		{"hitless", armHitless19083}, // #19101: hitless preserves no forwarding on userspace
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, rec := shutdownDaemon19083(t, tc.arm)
			if hr := d.store.ActiveConfig().Chassis.Cluster.HitlessRestart; hr != (tc.arm == armHitless19083) {
				t.Fatalf("premise: hitless-restart = %v in the %s arm", hr, tc.name)
			}
			before := len(rec.snapshot())
			runShutdown19083(t, d)
			// The arms differ in ownership at the stop, or they would be one
			// cell: a peered stop resigns (RG1 demoted), a lone node keeps
			// ownership through the stop (#12171) and must still remove (Q1).
			if owner := d.cluster.IsLocalPrimary(1); owner != (tc.arm != armPeered19083) {
				t.Fatalf("premise: after the stop RG1 local-primary = %v in the %s arm", owner, tc.name)
			}
			section := managedSection19083(t, rec)
			for _, l := range []string{ownedDefault19083, ownedStatic19083} {
				if strings.Contains(section, l) {
					t.Errorf("after a graceful HA stop the managed section still holds the owned static %q", l)
				}
			}
			if !strings.Contains(section, localStatic19083) {
				t.Errorf("the node-local static %q was removed too:\n%s", localStatic19083, section)
			}
			removed := false
			for _, r := range rec.snapshot()[before:] {
				if !r.stopped && !strings.Contains(r.conf, ownedStatic19083) && !strings.Contains(r.conf, ownedDefault19083) {
					removed = true
				}
			}
			if !removed {
				t.Errorf("no FRR reload of a section without the owned statics ran before frr.Stop (%d reloads during shutdown); FRR keeps them", len(rec.snapshot())-before)
			}
		})
	}
}

// TestStandaloneStopLeavesFRRAlone19083: statics are not ownership-gated
// without a cluster, and a standalone restart keeps FRR as it is.
func TestStandaloneStopLeavesFRRAlone19083(t *testing.T) {
	d, rec := shutdownDaemon19083(t, armStandalone19083)
	before, sectionBefore := len(rec.snapshot()), managedSection19083(t, rec)
	runShutdown19083(t, d)
	if n := len(rec.snapshot()) - before; n != 0 {
		t.Errorf("a standalone stop ran %d FRR reloads", n)
	}
	if got := managedSection19083(t, rec); got != sectionBefore {
		t.Errorf("a standalone stop rewrote the managed section:\n%s\nwas:\n%s", got, sectionBefore)
	}
}

// TestShutdownFRRDemoteOrder19083 pins the placement the design settled (Q3):
// runShutdownSequence calls shutdownFRRDemote19083 after d.cluster.Stop()
// (ownership frozen, VIPs gone) and before d.frr.Stop() (the manager is still
// live to apply it).
func TestShutdownFRRDemoteOrder19083(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon_run_shutdown.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]token.Pos{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runShutdownSequence" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			key := sel.Sel.Name
			if inner, ok := sel.X.(*ast.SelectorExpr); ok {
				key = inner.Sel.Name + "." + key
			}
			if _, seen := pos[key]; !seen {
				pos[key] = call.Pos()
			}
			return true
		})
	}
	demote, ok := pos["shutdownFRRDemote19083"]
	if !ok {
		t.Fatal("runShutdownSequence never calls shutdownFRRDemote19083: a graceful HA stop leaves the owned FRR statics (#19083)")
	}
	if c, ok := pos["cluster.Stop"]; !ok || demote < c {
		t.Errorf("shutdownFRRDemote19083 at %s must come after d.cluster.Stop() (%v)", fset.Position(demote), ok)
	}
	if f, ok := pos["frr.Stop"]; !ok || demote > f {
		t.Errorf("shutdownFRRDemote19083 at %s must come before d.frr.Stop() (%v)", fset.Position(demote), ok)
	}
}

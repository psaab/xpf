package daemon

// shutdown_dhcp_stop_6787_test.go — #6787 WIRING + ORDERING regression.
//
// The mechanics live in pkg/dhcpserver (Manager.Shutdown + the latch, bound by
// shutdown_latch_6787_test.go there). Those cells stay GREEN if runShutdownSequence
// never calls Shutdown at all — which is exactly the bug: an orderly HA shutdown
// withdrew VRRP ownership, cleared rg_active and stopped the heartbeat while
// leaving the Kea units running, so the promoted peer and this node both served
// DHCP on one segment.
//
// These cells drive the real teardown path and assert what only the wiring
// produces.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcpserver"
)

// keaRecorder6787 records systemctl invocations and the resulting unit state.
type keaRecorder6787 struct {
	mu     sync.Mutex
	calls  []string
	active map[string]bool
}

func newKeaRecorder6787() *keaRecorder6787 {
	return &keaRecorder6787{active: map[string]bool{}}
}

func (r *keaRecorder6787) run(args ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(args, " "))
	if len(args) >= 2 {
		switch args[0] {
		case "restart", "start":
			r.active[args[1]] = true
		case "stop":
			r.active[args[1]] = false
		}
	}
	return nil
}

func (r *keaRecorder6787) isActive(unit string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active[unit]
}

func (r *keaRecorder6787) anyActive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, on := range r.active {
		if on {
			return true
		}
	}
	return false
}

func (r *keaRecorder6787) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.calls))
	copy(out, r.calls)
	return out
}

func servingDHCPConfig6787() *config.DHCPServerConfig {
	return &config.DHCPServerConfig{
		DHCPLocalServer: &config.DHCPLocalServerConfig{
			Groups: map[string]*config.DHCPServerGroup{"g4": {
				Name:       "g4",
				Interfaces: []string{"reth1.0"},
				Pools: []*config.DHCPPool{{
					Name:      "p4",
					Subnet:    "10.0.61.0/24",
					RangeLow:  "10.0.61.100",
					RangeHigh: "10.0.61.200",
				}},
			}},
		},
	}
}

// clusterDaemon6787 builds a Daemon whose ACTIVE config is a chassis cluster,
// with a serving Kea manager wired in, ready to be driven through
// runShutdownSequence.
func clusterDaemon6787(t *testing.T, cluster bool) (*Daemon, *keaRecorder6787) {
	t.Helper()
	dir := t.TempDir()
	store, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if cluster {
		// #9686: a cluster shutdown can reach the transit close.
		seamTransitClose9686(t)
		// A cluster stanza with NO redundancy groups: enough to make haMode
		// true without entering the rg_active loop, which would need a live HA
		// controller. hitless-restart is set so the teardown takes the hitless
		// arm with a nil dataplane — the DHCP stop is gated on haMode, NOT on
		// hitless, and a fixture that only covered the fail-closed arm would
		// miss exactly the case this distinction exists for. The
		// authentication-key is not optional (commit rejects a cluster without
		// one), so it is fixture scaffolding.
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(`
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "cyaLE6jUXcHqZBB6xSJP7CVc5S9dHRBAtF5vTBqFEss=";
        hitless-restart;
    }
}
`); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		store.ExitConfigure()
		cfg := store.ActiveConfig()
		if cfg == nil || cfg.Chassis.Cluster == nil {
			t.Fatalf("fixture must commit a cluster config; got %+v", cfg)
		}
	}

	r := newKeaRecorder6787()
	mgr := dhcpserver.NewManagerForTesting(
		filepath.Join(dir, "kea-dhcp4.conf"),
		filepath.Join(dir, "kea-dhcp6.conf"),
		r.run,
		r.isActive,
	)
	if err := mgr.Apply(servingDHCPConfig6787()); err != nil {
		t.Fatalf("precondition Apply: %v", err)
	}
	if !r.anyActive() {
		t.Fatalf("precondition: no Kea unit started, so a later 'nothing "+
			"active' assertion would prove nothing; calls=%v", r.snapshot())
	}

	daemonCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	d := &Daemon{
		store:      store,
		applySem:   semaphore.NewWeighted(1),
		daemonCtx:  daemonCtx,
		dhcpServer: mgr,
	}
	return d, r
}

// runShutdownFor6787 drives the real teardown path and joins it. The empty
// WaitGroup is deliberate: this harness starts no run goroutines, so the
// sequence has nothing to wait on and the assertion below observes only what
// the sequence itself did.
func runShutdownFor6787(t *testing.T, d *Daemon) {
	t.Helper()
	var wg sync.WaitGroup
	_, stopRun := context.WithCancel(context.Background())
	sentinel := errors.New("run-error-passthrough")
	done := make(chan error, 1)
	go func() { done <- d.runShutdownSequence(&wg, stopRun, sentinel) }()
	select {
	case got := <-done:
		if !errors.Is(got, sentinel) {
			t.Fatalf("runShutdownSequence returned %v, want the run error passed through", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("runShutdownSequence did not return within 30s")
	}
}

// TestRunShutdownSequenceStopsKeaInClusterMode6787 is the wiring cell.
//
// RED-on-revert: delete the d.dhcpServer.Shutdown() call from
// runShutdownSequence and the units stay active after the sequence returns,
// while every pkg/dhcpserver cell stays green.
func TestRunShutdownSequenceStopsKeaInClusterMode6787(t *testing.T) {
	d, r := clusterDaemon6787(t, true)

	runShutdownFor6787(t, d)

	if r.anyActive() {
		t.Fatalf("a Kea unit is still active after an orderly HA shutdown — "+
			"the peer promotes and starts ITS Kea while this node keeps "+
			"answering on the same segment (#6787); calls=%v", r.snapshot())
	}
}

// TestRunShutdownSequenceLeavesKeaAloneStandalone6787 is the PAIRED half, and
// it is what keeps the fix from being a regression.
//
// In standalone there is no peer to hand the segment to, and the Kea units are
// separate systemd services that deliberately survive an xpfd restart today.
// Stopping them here would turn every daemon restart into a DHCP outage. The
// discriminator is cluster mode, NOT the hitless flag — VRRP sends its
// priority-0 burst even on a hitless HA restart, so the peer takes over and an
// HA node must stop serving either way.
//
// Without this cell, "cluster mode stops Kea" would be satisfied by an
// unconditional stop, which is a strictly worse behaviour than the bug.
func TestRunShutdownSequenceLeavesKeaAloneStandalone6787(t *testing.T) {
	d, r := clusterDaemon6787(t, false)

	runShutdownFor6787(t, d)

	if !r.anyActive() {
		t.Fatalf("Kea was stopped on a STANDALONE shutdown — there is no peer "+
			"to hand the segment to, and the units survive an xpfd restart "+
			"today, so this makes every daemon restart a DHCP outage; calls=%v",
			r.snapshot())
	}
}

// TestKeaStopPrecedesVRRPWithdrawal6787 pins the ORDERING, which is the whole
// point of the fix rather than an implementation detail: stopping Kea AFTER the
// priority-0 burst still leaves a window in which the peer is already serving
// and this node has not stopped.
//
// It is a source check, deliberately. The behavioural observation would need
// the VRRP manager and the Kea manager instrumented together inside one
// runShutdownSequence, and pkg/daemon has no seam that orders them — a cell
// built on a sleep or on goroutine scheduling would be the kind of green that
// is indistinguishable from healthy.
//
// Comments are stripped before matching: the comment introducing the stop names
// the VRRP stop, and a gate satisfiable by its own documentation proves nothing.
func TestKeaStopPrecedesVRRPWithdrawal6787(t *testing.T) {
	src, err := os.ReadFile("daemon_run_shutdown.go")
	if err != nil {
		t.Fatalf("read daemon_run_shutdown.go: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			code.WriteString("\n")
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	const keaStop = "d.dhcpServer.Shutdown()"
	const vrrpStop = "d.vrrpMgr.Stop()"
	const clusterStop = "d.cluster.Stop()"

	keaAt := strings.Index(body, keaStop)
	if keaAt < 0 {
		t.Fatalf("%s is not called in runShutdownSequence — an orderly HA "+
			"shutdown relinquishes ownership with the Kea units still serving "+
			"(#6787)", keaStop)
	}
	for _, later := range []struct{ name, needle string }{
		{"the VRRP priority-0 withdrawal", vrrpStop},
		{"the cluster heartbeat stop", clusterStop},
	} {
		at := strings.Index(body, later.needle)
		if at < 0 {
			t.Fatalf("%s not found; this cell can no longer order against %s",
				later.needle, later.name)
		}
		if keaAt > at {
			t.Fatalf("the Kea stop runs AFTER %s — the peer is already promoted "+
				"and serving while this node has not stopped, which is the "+
				"overlap window the fix exists to close (#6787)", later.name)
		}
	}
}

package daemon

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

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #9686: the fail-closed HA stop closes kernel transit BEFORE it detaches the
// dataplane, and the hitless stops leave forwarding alone.
//
// transitWitnessDP records, at the moment Close or Teardown is called, what the
// two forwarding sysctls held and which barrier calls had already happened.
// Reading them at that instant is the ordering proof. A close that ran after
// the detach would leave the same end state and pass an end-state check.
type transitWitnessDP struct {
	dataplane.RuntimeDataPlane

	v4, v6 string
	nft    *fakeNftInstaller

	called         string
	sysctlsAtCall  [2]string
	barrierAtCall  []string
	lifecycleCalls int
}

func (d *transitWitnessDP) snapshot(what string) {
	d.called = what
	d.lifecycleCalls++
	for i, p := range []string{d.v4, d.v6} {
		b, _ := os.ReadFile(p)
		d.sysctlsAtCall[i] = strings.TrimSpace(string(b))
	}
	d.barrierAtCall = append([]string(nil), d.nft.barrierCalls...)
}

func (d *transitWitnessDP) Start(context.Context) error { return nil }
func (d *transitWitnessDP) Close() error                { d.snapshot("Close"); return nil }
func (d *transitWitnessDP) Teardown() error             { d.snapshot("Teardown"); return nil }

// seamTransitClose9686 points the forwarding sysctls at temp files seeded "1"
// and swaps in a fake nftables installer, restoring both afterwards. Every test
// that drives the real non-hitless HA shutdown needs it since #9686: that path
// now closes kernel transit, and without the seams it would write the host's
// /proc sysctls and program a real nftables barrier (under root, disabling the
// test machine's forwarding).
func seamTransitClose9686(t *testing.T) (v4, v6 string, fake *fakeNftInstaller) {
	t.Helper()
	v4, v6 = withTempTransitForwardSysctls(t, "1")
	fake = &fakeNftInstaller{}
	orig := nftInstaller
	nftInstaller = fake
	t.Cleanup(func() { nftInstaller = orig })
	return v4, v6, fake
}

func commitShutdownFixture9686(t *testing.T, body string) *configstore.Store {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	return store
}

func TestFailClosedHAStopClosesTransitBeforeTheDetach9686(t *testing.T) {
	const clusterFmt = `
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "cyaLE6jUXcHqZBB6xSJP7CVc5S9dHRBAtF5vTBqFEss=";
        %s
    }
}
`
	for _, tc := range []struct {
		name        string
		config      string
		wantCall    string
		wantSysctl  string
		wantBarrier []string
	}{
		{
			name:        "HA fail-closed stop",
			config:      strings.Replace(clusterFmt, "%s", "", 1),
			wantCall:    "Teardown",
			wantSysctl:  "0",
			wantBarrier: []string{"install"},
		},
		{
			name:        "HA stop with hitless-restart",
			config:      strings.Replace(clusterFmt, "%s", "hitless-restart;", 1),
			wantCall:    "Close",
			wantSysctl:  "1",
			wantBarrier: nil,
		},
		{
			name:        "standalone stop",
			config:      "system {\n    host-name fw9686;\n}\n",
			wantCall:    "Close",
			wantSysctl:  "1",
			wantBarrier: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6, fake := seamTransitClose9686(t)

			store := commitShutdownFixture9686(t, tc.config)
			cfg := store.ActiveConfig()
			if cfg == nil {
				t.Fatal("fixture: no active config")
			}
			if wantHA := tc.name != "standalone stop"; (cfg.Chassis.Cluster != nil) != wantHA {
				t.Fatalf("fixture: cluster configured = %v, want %v", cfg.Chassis.Cluster != nil, wantHA)
			}
			if cfg.Chassis.Cluster != nil && len(cfg.Chassis.Cluster.RedundancyGroups) != 0 {
				t.Fatalf("fixture must bind no redundancy groups")
			}

			daemonCtx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			dp := &transitWitnessDP{v4: v4, v6: v6, nft: fake}
			d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), daemonCtx: daemonCtx}
			d.setDataplane(dp)
			d.dataplaneArmed.Store(true)

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

			if dp.called != tc.wantCall || dp.lifecycleCalls != 1 {
				t.Fatalf("dataplane lifecycle: called %q %d time(s), want %q once", dp.called, dp.lifecycleCalls, tc.wantCall)
			}
			for i, fam := range []string{"IPv4 ip_forward", "IPv6 conf.all.forwarding"} {
				if dp.sysctlsAtCall[i] != tc.wantSysctl {
					t.Errorf("%s read %q when %s ran, want %q. A fail-closed stop must close "+
						"kernel transit BEFORE detaching the dataplane, and a hitless stop must "+
						"leave it open (#9686)", fam, dp.sysctlsAtCall[i], dp.called, tc.wantSysctl)
				}
			}
			if strings.Join(dp.barrierAtCall, ",") != strings.Join(tc.wantBarrier, ",") {
				t.Errorf("transit barrier calls before %s = %v, want %v (#7191 barrier, #9686)",
					dp.called, dp.barrierAtCall, tc.wantBarrier)
			}
			if tc.wantSysctl == "0" && d.DataplaneArmed() {
				t.Error("a fail-closed stop must record the dataplane as not armed")
			}
			// Nothing on the way out may re-open what the stop closed.
			assertTransitForwarding(t, v4, v6, tc.wantSysctl, "after the stop returned")
		})
	}
}

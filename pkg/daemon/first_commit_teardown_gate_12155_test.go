package daemon

// N1/N2 permanent cells (folded from the PlasticMoose integration probes):
// mismatched-generation gate + unreadable-record DEGRADED.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/networkd"
	"golang.org/x/sync/semaphore"
)

var pmLifeline12155 = []byte(bootstrapLifelineNetworkMarker +
	" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")

// TestFirstCommitTeardownMismatchedGenerationStaysDegraded12155 pins N1: a
// valid durable record bound to a STALE generation must not restore onto the
// live candidate. DEGRADED + candidate untouched + debt retained. Deleting
// the generation compare (M5) restores the stale bytes and clears debt —
// this test FAILS then.
func TestFirstCommitTeardownMismatchedGenerationStaysDegraded12155(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	store, _ := firstCommit12155ExpiredStore(t)
	candidate := []byte("# Managed by xpfd — do not edit\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n")
	netPath := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.WriteFile(netPath, candidate, 0o644); err != nil {
		t.Fatal(err)
	}
	stale := []byte(bootstrapLifelineNetworkMarker + " (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=203.0.113.7/24\n")
	data, _ := json.Marshal(bootstrapLifelineSnapshotRecord{Generation: "stale-generation-from-an-earlier-window", Network: stale})
	if err := os.WriteFile(filepath.Join(dir, bootstrapLifelineSnapshotBase), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{NoDataplane: true}}
	done := d.teardownRecoveredFirstCommitBeforeDataplane()
	d.completeRecoveredFirstCommitTeardown(done)
	got, _ := os.ReadFile(netPath)
	t.Logf("RESULT: filesystemDone=%v debtStillOwed=%v fxp0==candidate:%v fxp0==STALE:%v",
		done, store.FirstCommitTeardownOwed(), bytes.Equal(got, candidate), bytes.Equal(got, stale))
	if bytes.Equal(got, stale) {
		t.Fatal("stale-generation snapshot restored onto fxp0 (generation gate absent)")
	}
	if !bytes.Equal(got, candidate) {
		t.Fatalf("candidate fxp0.network was modified: %q", got)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("teardown debt cleared despite the generation mismatch")
	}
	if done {
		t.Fatal("teardown reported convergence despite the generation mismatch")
	}
}

// TestFirstCommitTeardownUnreadableRecordStaysDegraded12155 pins N2: a
// present-but-unreadable durable record (oversized, FIFO, corrupt JSON) is
// evidence a lifeline existed — DEGRADED + debt retained + warning, never
// the absent-absent no-op. A matched-generation control converges (the
// no-op path is covered by the debt-owed suites with genuinely absent
// records).
func TestFirstCommitTeardownUnreadableRecordStaysDegraded12155(t *testing.T) {
	for _, tc := range []string{"oversized", "fifo", "corrupt-json", "valid-matched-generation"} {
		t.Run(tc, func(t *testing.T) {
			dir := firstCommit12155FilesAndCommands(t)
			store, _ := firstCommit12155ExpiredStore(t)
			rec := filepath.Join(dir, bootstrapLifelineSnapshotBase)
			switch tc {
			case "oversized":
				if err := os.WriteFile(rec, bytes.Repeat([]byte("x"), maxBootstrapLifelineSnapshotSize+16), 0o600); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(rec, 0o600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-json":
				if err := os.WriteFile(rec, []byte("{\"generation\":"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "valid-matched-generation":
				data, _ := json.Marshal(bootstrapLifelineSnapshotRecord{Generation: store.FirstCommitTeardownGeneration(), Network: pmLifeline12155})
				if err := os.WriteFile(rec, append(data, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{NoDataplane: true}}
			buf, restore := captureSlog(t)
			done := d.teardownRecoveredFirstCommitBeforeDataplane()
			d.completeRecoveredFirstCommitTeardown(done)
			restore()
			if tc == "valid-matched-generation" {
				if !done || store.FirstCommitTeardownOwed() {
					t.Fatalf("matched control: done=%v owed=%v; want converged teardown", done, store.FirstCommitTeardownOwed())
				}
				return
			}
			if done {
				t.Fatalf("[%s] unreadable record reported converged teardown", tc)
			}
			if !store.FirstCommitTeardownOwed() {
				t.Fatalf("[%s] unreadable record cleared teardown debt", tc)
			}
			if logs := buf.String(); !strings.Contains(logs, "unreadable") {
				t.Fatalf("[%s] no unreadable-record warning logged:\n%s", tc, logs)
			}
		})
	}
}

// TestFirstCommitTeardownDoubleWindowRepersistConverges12155 pins P1: two FIRST
// windows in one process; window 1 rolls back live, window 2 expires across a
// restart. Bootstrap exit re-persists the same marked bytes under window 2's
// generation, so the boot debt gates authentic bytes — teardown CONVERGES
// (lifeline restored, debt cleared). Without the re-persist the gate rejects
// authentic bytes and the box sticks DEGRADED every boot.
func TestFirstCommitTeardownDoubleWindowRepersistConverges12155(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	installFakeNetworkctl(t)
	netPath := filepath.Join(dir, linkPrefix+"fxp0.network")
	if err := os.WriteFile(netPath, pmLifeline12155, 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "xpf.conf")
	storeA := newConfigStore(t, cfgPath)
	if err := storeA.Load(); err != nil {
		t.Fatal(err)
	}
	managed := []networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}}
	dA := lifelineDaemon12154(t, storeA, dir, managed)
	dA.bootstrapMode.Store(true)

	commitConfirmedText12154(t, storeA, "interfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }\n")
	g1 := storeA.ActiveConfigGeneration()
	if err := dA.applyConfigLocked(context.Background(), storeA.ActiveConfig()); err != nil {
		t.Fatal(err)
	}
	storeA.InvokeRollbackTimerForTesting(storeA.ConfirmGenForTesting())
	if got, _ := os.ReadFile(netPath); !bytes.Equal(got, pmLifeline12155) || !dA.inBootstrap() {
		t.Fatalf("premise: window-1 live rollback did not restore lifeline: %q", got)
	}

	commitConfirmedText12154(t, storeA, "system { host-name second; }\ninterfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }\n")
	g2 := storeA.ActiveConfigGeneration()
	if err := dA.applyConfigLocked(context.Background(), storeA.ActiveConfig()); err != nil {
		t.Fatal(err)
	}
	storeA.CancelConfirmTimerForTesting()
	recGen, ok := pmReadRecord12155(t, dir)
	t.Logf("g1=%.12s g2=%.12s durableRecordGen=%.12s ok=%v (record==g1:%v)", g1, g2, recGen, ok, recGen == g1)
	if err := expireConfirmWindow12155(t, cfgPath); err != nil {
		t.Fatal(err)
	}

	storeB := newConfigStore(t, cfgPath)
	dB := &Daemon{applySem: semaphore.NewWeighted(1), store: storeB, opts: Options{ConfigFile: cfgPath}}
	closed, err := dB.loadAndBootstrapConfig()
	if err != nil || !closed {
		t.Fatalf("restart load closed=%v err=%v", closed, err)
	}
	t.Logf("boot debt owed=%v debtGen=%.12s (==g2:%v)", storeB.FirstCommitTeardownOwed(),
		storeB.FirstCommitTeardownGeneration(), storeB.FirstCommitTeardownGeneration() == g2)
	if err := dB.setupInterfaceNaming(); err != nil {
		t.Fatal(err)
	}
	done := dB.teardownRecoveredFirstCommitBeforeDataplane()
	dB.setDataplane(&firstCommitTeardownRuntime12155{})
	dB.completeRecoveredFirstCommitTeardown(done)
	got, _ := os.ReadFile(netPath)
	if !done || storeB.FirstCommitTeardownOwed() {
		t.Fatalf("double-window boot teardown did not converge (done=%v owed=%v)", done, storeB.FirstCommitTeardownOwed())
	}
	if !bytes.Equal(got, pmLifeline12155) {
		t.Fatalf("fxp0 not restored to the authentic lifeline: %q", firstLine12155(got, 3))
	}
}

func pmReadRecord12155(t *testing.T, dir string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, bootstrapLifelineSnapshotBase))
	if err != nil {
		return "", false
	}
	var rec bootstrapLifelineSnapshotRecord
	if json.Unmarshal(data, &rec) != nil {
		return "", false
	}
	return rec.Generation, true
}

func firstLine12155(b []byte, n int) string {
	lines := strings.SplitN(string(b), "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "|")
}

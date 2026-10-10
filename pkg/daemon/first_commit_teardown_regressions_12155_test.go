package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/frr"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
	"golang.org/x/sync/semaphore"
)

func firstCommit12155FilesAndCommands(t *testing.T) string {
	t.Helper()
	seamTransitClose9686(t)
	dir := t.TempDir()
	oldDir, oldRun := linkDir, runCommandTimeout
	linkDir = dir
	runCommandTimeout = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { linkDir, runCommandTimeout = oldDir, oldRun })
	return dir
}

func firstCommit12155ExpiredStore(t *testing.T) (*configstore.Store, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "xpf.conf")
	store := newConfigStore(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name Abandoned"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()
	store.CancelConfirmTimerForTesting()
	confirmPath := filepath.Join(root, ".configdb", "confirm.json")
	data, err := os.ReadFile(confirmPath)
	if err != nil {
		t.Fatal(err)
	}
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		t.Fatal("missing confirm envelope")
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data[newline+1:], &record); err != nil {
		t.Fatal(err)
	}
	record["deadline"], _ = json.Marshal(time.Now().Add(-time.Hour))
	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(confirmPath, append(append([]byte(nil), data[:newline+1]...), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered := newConfigStore(t, path)
	if err := recovered.Load(); err != nil {
		t.Fatal(err)
	}
	if !recovered.FirstCommitTeardownOwed() {
		t.Fatal("fixture did not acquire FIRST teardown debt")
	}
	return recovered, path
}

func TestFirstCommitConfirmedReplacementSurvivesOldDebt12155(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	store, path := firstCommit12155ExpiredStore(t)
	blocked := filepath.Join(dir, "10-xpf-blocked.network")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "busy"), []byte("busy"), 0o600); err != nil {
		t.Fatal(err)
	}
	daemon := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: path, NoDataplane: true}}
	if daemon.teardownRecoveredFirstCommitBeforeDataplane() {
		t.Fatal("blocked cleanup unexpectedly converged")
	}
	daemon.completeRecoveredFirstCommitTeardown(false)
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("failed cleanup cleared durable debt")
	}
	if err := os.Remove(filepath.Join(blocked, "busy")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	daemon.applyBodyForTest = func(*config.Config) {}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name Corrected"); err != nil {
		t.Fatal(err)
	}
	if _, err := daemon.commitConfirmedAndApply(context.Background(), configstore.InternalCommitter(), 10, peerSyncNever); err != nil {
		t.Fatal(err)
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()

	livePath := filepath.Join(dir, "10-xpf-ge-0-0-1.network")
	liveBytes := []byte("[Match]\nName=ge-0-0-1\n[Network]\nAddress=198.51.100.77/24\n")
	if err := os.WriteFile(livePath, liveBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	frrPath, sentinel := seededFRRConf(t)
	recorder := &frr.RecordingExecutor{}
	restarted := &Daemon{
		store: newConfigStore(t, path), applySem: semaphore.NewWeighted(1),
		opts: Options{ConfigFile: path, NoDataplane: true}, frr: frr.NewForTest(frrPath, recorder),
	}
	closed, err := restarted.loadAndBootstrapConfig()
	if err != nil {
		t.Fatal(err)
	}
	if closed || restarted.store.ActiveConfig() == nil || restarted.store.ActiveConfig().System.HostName != "Corrected" {
		t.Fatalf("replacement boot classification closed=%v config=%+v", closed, restarted.store.ActiveConfig())
	}
	if restarted.teardownRecoveredFirstCommitBeforeDataplane() {
		t.Fatal("superseded generation still requested destructive teardown")
	}
	got, err := os.ReadFile(livePath)
	if err != nil || !bytes.Equal(got, liveBytes) {
		t.Fatalf("replacement networkd output = %q, err=%v", got, err)
	}
	if !strings.Contains(readConf(t, frrPath), sentinel) {
		t.Fatal("replacement FRR output was removed by old FIRST-generation debt")
	}
}
func TestFirstCommitReloadDebtRetriesUntilNetworkdAck12155(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	store, path := firstCommit12155ExpiredStore(t)
	daemon := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: path, NoDataplane: true}}
	networkFile := filepath.Join(dir, "10-xpf-ge-0-0-1.network")
	if err := os.WriteFile(networkFile, []byte("[Match]\nName=ge-0-0-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	runCommandTimeout = func(name string, args ...string) ([]byte, error) {
		if name == "networkctl" && len(args) > 0 && args[0] == "reload" {
			reloads++
			if reloads == 1 {
				return nil, errors.New("injected networkd reload refusal")
			}
		}
		return nil, nil
	}
	filesystemDone := daemon.teardownRecoveredFirstCommitBeforeDataplane()
	if filesystemDone || reloads != 1 {
		t.Fatalf("first teardown = done %v, reloads %d; want failed reload", filesystemDone, reloads)
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("durable teardown marker cleared before networkd reload was acknowledged")
	}
	if _, err := os.Stat(networkFile); !os.IsNotExist(err) {
		t.Fatalf("filesystem removal premise failed: %v", err)
	}
	daemon.setDataplane(&firstCommitTeardownRuntime12155{})
	daemon.completeRecoveredFirstCommitTeardown(filesystemDone)
	if reloads != 2 {
		t.Fatalf("networkd reload attempts = %d, want retry after file scan became clean", reloads)
	}
	if store.FirstCommitTeardownOwed() {
		t.Fatal("durable teardown debt cleared before networkd acknowledged reload")
	}
}

func TestFirstCommitLifelineSnapshotSurvivesFullRestart12155(t *testing.T) {
	firstCommit12155FilesAndCommands(t)
	state := staticLifelineSeams(t)
	installFakeNetworkctl(t)
	original := []byte(bootstrapLifelineNetworkMarker + " (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
	networkPath := filepath.Join(state.linkDir, "10-xpf-fxp0.network")
	if err := os.WriteFile(networkPath, original, 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newConfigStore(t, path)
	daemon := &Daemon{
		applySem: semaphore.NewWeighted(1), store: store, networkd: networkd.NewInDir(state.linkDir),
		vrrpMgr: vrrp.NewManager(), opts: Options{NoDataplane: true},
	}
	daemon.networkd.SetProtectedResolver(func() map[string]bool { return map[string]bool{"fxp0": true} })
	daemon.bootstrapMode.Store(true)
	daemon.setDataplane(&runtimeOnlyApplyTestDP{applyResult: &dataplane.ApplyResult{
		ManagedInterfaces: []networkd.InterfaceConfig{{Name: "fxp0", Addresses: []string{"192.0.2.99/24"}}},
	}})
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride("interfaces { fxp0 { unit 0 { family inet { address 192.0.2.99/24; } } } }"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	store.ExitConfigure()
	if err := daemon.applyConfigLocked(context.Background(), store.ActiveConfig()); err != nil {
		t.Fatal(err)
	}
	store.CancelConfirmTimerForTesting()
	if !bytes.Equal(daemon.bootstrapLifelineNetwork, original) {
		t.Fatal("first apply did not capture the authentic bootstrap lifeline")
	}
	candidate, err := os.ReadFile(networkPath)
	if err != nil || !strings.Contains(string(candidate), "192.0.2.99/24") || isBootstrapLifelineNetwork(candidate) {
		t.Fatalf("candidate networkd output = %q, err=%v", candidate, err)
	}
	if daemon.bootstrapLifelineGeneration != store.ActiveConfigGeneration() {
		t.Fatal("persisted lifeline provenance is not bound to the active generation")
	}
	if err := expireConfirmWindow12155(t, path); err != nil {
		t.Fatal(err)
	}

	restartedStore := newConfigStore(t, path)
	restarted := &Daemon{applySem: semaphore.NewWeighted(1), store: restartedStore, opts: Options{ConfigFile: path}}
	closed, err := restarted.loadAndBootstrapConfig()
	if err != nil || !closed {
		t.Fatalf("restart load closed=%v err=%v", closed, err)
	}
	if err := restarted.setupInterfaceNaming(); err != nil {
		t.Fatal(err)
	}
	filesystemDone := restarted.teardownRecoveredFirstCommitBeforeDataplane()
	restarted.setDataplane(&firstCommitTeardownRuntime12155{})
	restarted.completeRecoveredFirstCommitTeardown(filesystemDone)
	got, err := os.ReadFile(networkPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("restart restored %q, want authentic snapshot %q (debt=%v)", got, original, restartedStore.FirstCommitTeardownOwed())
	}
	if restartedStore.FirstCommitTeardownOwed() {
		t.Fatal("teardown remained owed after restoring the authentic snapshot")
	}
	if _, err := os.Stat(filepath.Join(state.linkDir, bootstrapLifelineSnapshotBase)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolved snapshot file remains: %v", err)
	}
}

func TestFirstCommitLifelineSnapshotRestoresMissingNetworkFile12155(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	store, _ := firstCommit12155ExpiredStore(t)
	original := []byte(bootstrapLifelineNetworkMarker +
		" (static snapshot)\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.1/24\n")
	snapshot, err := json.Marshal(bootstrapLifelineSnapshotRecord{
		Generation: store.FirstCommitTeardownGeneration(),
		Network:    original,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot = append(snapshot, '\n')
	if err := os.WriteFile(filepath.Join(dir, bootstrapLifelineSnapshotBase), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	daemon := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{NoDataplane: true}}
	filesystemDone := daemon.teardownRecoveredFirstCommitBeforeDataplane()
	if !filesystemDone {
		t.Fatal("durable snapshot did not restore an absent bootstrap lifeline file")
	}
	daemon.completeRecoveredFirstCommitTeardown(filesystemDone)
	got, err := os.ReadFile(filepath.Join(dir, linkPrefix+"fxp0.network"))
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("restored lifeline = %q, err=%v, want %q", got, err, original)
	}
	if store.FirstCommitTeardownOwed() {
		t.Fatal("durable teardown debt remained after restoring the missing lifeline")
	}
}

func TestFirstCommitMissingLifelineSnapshotStaysDegraded12155(t *testing.T) {
	dir := firstCommit12155FilesAndCommands(t)
	_, path := firstCommit12155ExpiredStore(t)
	candidate := []byte("# Managed by xpfd — do not edit\n[Match]\nName=fxp0\n\n[Network]\nAddress=192.0.2.99/24\n")
	networkPath := filepath.Join(dir, "10-xpf-fxp0.network")
	if err := os.WriteFile(networkPath, candidate, 0o644); err != nil {
		t.Fatal(err)
	}
	abandonedPath := filepath.Join(dir, "10-xpf-ge-0-0-1.network")
	if err := os.WriteFile(abandonedPath, []byte("[Match]\nName=ge-0-0-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	preserved := map[string][]byte{
		"10-xpf-ge-0-0-1.link": []byte("[Match]\nOriginalName=enp3s0\n[Link]\nName=ge-0-0-1\n"),
		"80-operator.network":  []byte("[Match]\nName=operator0\n"),
	}
	for name, content := range preserved {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	store := newConfigStore(t, path)
	daemon := &Daemon{store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: path}}
	closed, err := daemon.loadAndBootstrapConfig()
	if err != nil || !closed {
		t.Fatalf("load classification closed=%v err=%v", closed, err)
	}
	if err := daemon.setupInterfaceNaming(); err != nil {
		t.Fatal(err)
	}
	filesystemDone := daemon.teardownRecoveredFirstCommitBeforeDataplane()
	daemon.completeRecoveredFirstCommitTeardown(filesystemDone)
	if filesystemDone {
		t.Fatal("missing authentic snapshot reported converged teardown")
	}
	got, err := os.ReadFile(networkPath)
	if err != nil || !bytes.Equal(got, candidate) {
		t.Fatalf("candidate lifeline was rewritten without provenance: %q err=%v", got, err)
	}
	if isBootstrapLifelineNetwork(got) {
		t.Fatal("abandoned runtime candidate was relabeled as a trusted bootstrap lifeline")
	}
	if _, err := os.Stat(abandonedPath); !os.IsNotExist(err) {
		t.Fatalf("abandoned networkd file was not removed: %v", err)
	}
	for name, want := range preserved {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("foreign or managed-link file %s mutated: got=%q err=%v", name, got, err)
		}
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("missing authentic snapshot did not retain teardown debt")
	}
}

func expireConfirmWindow12155(t *testing.T, path string) error {
	t.Helper()
	confirmPath := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	data, err := os.ReadFile(confirmPath)
	if err != nil {
		return err
	}
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		return errors.New("missing confirm envelope")
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data[newline+1:], &record); err != nil {
		return err
	}
	record["deadline"], _ = json.Marshal(time.Now().Add(-time.Hour))
	body, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(confirmPath, append(append([]byte(nil), data[:newline+1]...), body...), 0o600)
}

type firstCommitTransitDetachWitness12155 struct {
	runtimeOnlyApplyTestDP
	v4, v6         string
	seenV4, seenV6 string
	teardowns      int
}

func (w *firstCommitTransitDetachWitness12155) Teardown() error {
	v4, err := os.ReadFile(w.v4)
	if err != nil {
		return err
	}
	v6, err := os.ReadFile(w.v6)
	if err != nil {
		return err
	}
	w.seenV4, w.seenV6 = strings.TrimSpace(string(v4)), strings.TrimSpace(string(v6))
	w.teardowns++
	return nil
}

func TestFirstCommitForeignRollbackClosesTransitBeforeDetach12155(t *testing.T) {
	firstCommit12155FilesAndCommands(t)
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withApplianceMarker10733(t, false)
	fence := withBarrierRecorder(t)
	path := filepath.Join(t.TempDir(), "xpf.conf")
	previousStore := newConfigStore(t, path)
	if err := previousStore.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := previousStore.LoadOverride("interfaces { ge-0/0/0 { unit 0 { family inet { address 198.51.100.1/24; } } } }"); err != nil {
		t.Fatal(err)
	}
	if _, err := previousStore.CommitConfirmed(10); err != nil {
		t.Fatal(err)
	}
	previousStore.ExitConfigure()
	priorDaemon := &Daemon{store: previousStore}
	priorDaemon.setDataplane(&armedRecorderDP{})
	priorDaemon.armBootDataplane(priorDaemon.dataplane())
	if !priorDaemon.DataplaneArmed() || !priorDaemon.shouldManageTransitGate() {
		t.Fatal("prior FIRST generation did not arm and acquire transit ownership")
	}
	assertTransitForwarding(t, v4, v6, "1", "after prior FIRST generation armed")
	previousStore.CancelConfirmTimerForTesting()
	if err := expireConfirmWindow12155(t, path); err != nil {
		t.Fatal(err)
	}
	fence.barrierCalls = nil

	store := newConfigStore(t, path)
	witness := &firstCommitTransitDetachWitness12155{v4: v4, v6: v6}
	daemon := &Daemon{
		store: store, applySem: semaphore.NewWeighted(1), opts: Options{ConfigFile: path},
		buildRuntimeDataPlaneForTest: func(string) (dataplane.RuntimeDataPlane, error) { return witness, nil },
	}
	closed, err := daemon.loadAndBootstrapConfig()
	if err != nil || !closed {
		t.Fatalf("load classification closed=%v err=%v", closed, err)
	}
	daemon.applyBootTransitPolicy()
	filesystemDone := daemon.teardownRecoveredFirstCommitBeforeDataplane()
	if !filesystemDone {
		t.Fatal("filesystem teardown did not converge")
	}
	if err := daemon.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatal(err)
	}
	daemon.completeRecoveredFirstCommitTeardown(filesystemDone)
	daemon.reassertTransitGate("first-rollback post-boot tick")
	if witness.teardowns != 1 {
		t.Fatalf("detach calls = %d, want one", witness.teardowns)
	}
	if witness.seenV4 != "0" || witness.seenV6 != "0" {
		t.Fatalf("forwarding at detach = (%s,%s), want closed (0,0)", witness.seenV4, witness.seenV6)
	}
	assertTransitForwarding(t, v4, v6, "0", "after foreign-host FIRST rollback")
	if len(fence.barrierCalls) == 0 {
		t.Fatal("prior transit ownership was not reasserted around dataplane detach")
	}
}

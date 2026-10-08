package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/frr"
	"golang.org/x/sync/semaphore"
)

type firstCommitTeardownRuntime12155 struct {
	runtimeOnlyApplyTestDP
	teardownCalls int
}

func (d *firstCommitTeardownRuntime12155) Teardown() error {
	d.teardownCalls++
	return nil
}

// TestExpiredFirstCommitBootTearsDownTakeover12155 covers the complete fake-root
// recovery path: an expired FIRST window is reverted during Store.Load, day-0
// config remains suppressed, then the same bootstrap teardown used by a live
// timer removes the abandoned networkd/FRR state before its debt is cleared.
func TestExpiredFirstCommitBootTearsDownTakeover12155(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "xpf.conf")
	store, err := configstore.New(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.SetFromInput("system host-name FirstEver"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	store.ExitConfigure()

	// A valid day-0 config makes the suppression assertion observable: without
	// the durable-debt guard, loadAndBootstrapConfig would promote this file.
	if err := os.WriteFile(storePath, []byte("system { host-name Day0; }\n"), 0o600); err != nil {
		t.Fatalf("write day-0 config: %v", err)
	}
	confirmPath := filepath.Join(root, ".configdb", "confirm.json")
	data, err := os.ReadFile(confirmPath)
	if err != nil {
		t.Fatal(err)
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		t.Fatalf("confirm envelope has no header: %q", data)
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data[nl+1:], &record); err != nil {
		t.Fatalf("decode confirm body: %v", err)
	}
	deadline, _ := json.Marshal(time.Now().Add(-time.Minute))
	record["deadline"] = deadline
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	backdated := append(append([]byte(nil), data[:nl+1]...), body...)
	if err := os.WriteFile(confirmPath, backdated, 0o600); err != nil {
		t.Fatal(err)
	}

	fakeLink := filepath.Join(root, "network")
	if err := os.MkdirAll(fakeLink, 0o755); err != nil {
		t.Fatal(err)
	}
	abandoned := filepath.Join(fakeLink, "10-xpf-ge-0-0-1.network")
	if err := os.WriteFile(abandoned, []byte("[Match]\nName=ge-0-0-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldLinkDir := linkDir
	linkDir = fakeLink
	t.Cleanup(func() { linkDir = oldLinkDir })
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "networkctl"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldPath := os.Getenv("PATH")
	if err := os.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Setenv("PATH", oldPath) })

	confPath, sentinel := seededFRRConf(t)
	recorder := &frr.RecordingExecutor{}
	store, err = configstore.New(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var runtime *firstCommitTeardownRuntime12155
	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    store,
		frr:      frr.NewForTest(confPath, recorder),
		opts:     Options{ConfigFile: storePath},
		buildRuntimeDataPlaneForTest: func(string) (dataplane.RuntimeDataPlane, error) {
			runtime = &firstCommitTeardownRuntime12155{}
			return runtime, nil
		},
	}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || !failClosed {
		t.Fatalf("loadAndBootstrapConfig = (%v, %v), want (true, nil)", failClosed, err)
	}
	if store.EverCommitted() || store.ActiveConfig() != nil {
		t.Fatalf("rollback boot imported day-0 config: everCommitted=%v active=%v",
			store.EverCommitted(), store.ActiveConfig())
	}
	if store.IsConfirmPending() {
		t.Fatal("expired FIRST window remains pending after recovery")
	}
	if !store.FirstCommitTeardownOwed() {
		t.Fatal("Store.Load did not retain the durable teardown debt")
	}

	filesystemTeardownDone := d.teardownRecoveredFirstCommitBeforeDataplane()
	if !filesystemTeardownDone {
		t.Fatal("filesystem/FRR rollback teardown did not converge")
	}
	if _, err := os.Stat(abandoned); !os.IsNotExist(err) {
		t.Fatalf("bootstrap teardown left abandoned network file: %v", err)
	}
	if got := readConf(t, confPath); strings.Contains(got, sentinel) {
		t.Fatalf("bootstrap teardown left FRR managed sentinel %q", sentinel)
	}
	if recorder.ReloadCalls != 1 {
		t.Fatalf("bootstrap teardown FRR reloads=%d, want exactly one", recorder.ReloadCalls)
	}
	if err := d.setupDataplaneAndInitialConfig(); err != nil {
		t.Fatalf("setupDataplaneAndInitialConfig: %v", err)
	}
	if runtime == nil {
		t.Fatal("bootstrap dataplane backend was not constructed")
	}

	// The runtime was constructed by dataplane-setup but remains unarmed in
	// bootstrap mode; its Teardown call is the second stage of rollback cleanup.
	d.completeRecoveredFirstCommitTeardown(filesystemTeardownDone)
	if runtime.teardownCalls != 1 {
		t.Fatalf("constructed dataplane teardown calls=%d, want exactly one", runtime.teardownCalls)
	}
	if store.FirstCommitTeardownOwed() {
		t.Fatal("teardown debt remained after all cleanup steps converged")
	}
	markerPath := filepath.Join(root, ".configdb", "first-commit-teardown.json")
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("durable teardown marker remains after convergence: %v", err)
	}
}

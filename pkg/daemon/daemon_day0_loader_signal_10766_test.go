package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoaderCommitCheckRejectNotRecordedAsNoConfig_10766(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "xpf.conf")
	marker := filepath.Join(filepath.Dir(configFile), day0RejectMarkerName)
	if err := os.WriteFile(marker, []byte(day0RejectMarkerContent+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		store: newConfigStore(t, configFile),
		opts:  Options{ConfigFile: configFile},
	}
	if failClosed, err := d.loadAndBootstrapConfig(); err != nil || failClosed {
		t.Fatalf("loadAndBootstrapConfig() = (%v, %v); want (false, nil)", failClosed, err)
	}

	got := d.BootstrapImportSnapshot()
	if got.Status != bootstrapImportFailed || !got.Failed {
		t.Fatalf("bootstrap import = %+v; want import-failed", got)
	}
	if !strings.Contains(got.Error, "day-0 config REJECTED by commit-check") {
		t.Fatalf("bootstrap import error = %q; want the loader REJECT reason", got.Error)
	}
}

func TestDay0ImportRetriesAfterFirstCommitRollback_10766(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "xpf.conf")
	first := newConfigStore(t, configFile)
	if err := first.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := first.LoadOverride("system { host-name unconfirmed; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := first.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	first.ExitConfigure()
	if _, ok := first.PromoteRollback(first.ConfirmGenForTesting()); !ok {
		t.Fatal("first-commit rollback did not promote its never-committed target")
	}

	// Reopen the actual committed=0 active.json written by rollback. It must
	// load a non-nil compiled empty config while remaining never-committed.
	reloaded := newConfigStore(t, configFile)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load never-committed active.json: %v", err)
	}
	if reloaded.ActiveConfig() == nil || reloaded.EverCommitted() {
		t.Fatalf("reloaded rollback state: active=%v everCommitted=%v; want non-nil/false",
			reloaded.ActiveConfig() != nil, reloaded.EverCommitted())
	}
	if err := os.WriteFile(configFile,
		[]byte("system { host-name day0-retry; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{store: reloaded, opts: Options{ConfigFile: configFile}}
	if failClosed, err := d.loadAndBootstrapConfig(); err != nil || failClosed {
		t.Fatalf("loadAndBootstrapConfig() = (%v, %v); want (false, nil)", failClosed, err)
	}
	if !reloaded.EverCommitted() || !strings.Contains(reloaded.ShowActiveSet(), "day0-retry") {
		t.Fatalf("day-0 config was not imported after committed=0 rollback: committed=%v active=%s",
			reloaded.EverCommitted(), reloaded.ShowActiveSet())
	}
	if got := d.BootstrapImportSnapshot(); got.Status != bootstrapImportPending || got.Failed {
		t.Fatalf("after the successful import but before credential reconciliation = %+v; want credential-apply-pending", got)
	}
}

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadAndBootstrapAbsentActiveHistoryFailsClosed_10297 exercises the real
// startup path, not just its pure predicates. Reverting the Store marker check,
// the load-error switch, the bootstrap import gate, or the combined return
// wiring would re-import day-0 xpf.conf and recreate active.json.
func TestLoadAndBootstrapAbsentActiveHistoryFailsClosed_10297(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	seed := newConfigStore(t, path)
	for _, host := range []string{"history-a", "history-b"} {
		if err := seed.EnterConfigure(); err != nil {
			t.Fatal(err)
		}
		if err := seed.LoadOverride("system { host-name " + host + "; }"); err != nil {
			t.Fatal(err)
		}
		if _, err := seed.Commit(); err != nil {
			t.Fatal(err)
		}
		seed.ExitConfigure()
	}
	if err := os.WriteFile(path, []byte("system { host-name day-0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}

	reloaded := newConfigStore(t, path)
	d := &Daemon{store: reloaded, opts: Options{ConfigFile: path}}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil {
		t.Fatalf("loadAndBootstrapConfig: %v", err)
	}
	if !failClosed {
		t.Fatal("absent active DB with history returned failClosed=false")
	}
	if !d.inBootstrap() {
		t.Fatal("absent active DB with history did not enter bootstrap mode")
	}
	if reloaded.ActiveConfig() != nil {
		t.Fatal("absent active DB with history unexpectedly produced an active config")
	}
	if !reloaded.EverCommitted() {
		t.Fatal("absent active DB with history lost the committed state")
	}
	found := false
	for _, entry := range reloaded.ListHistory() {
		if entry.Config != nil && strings.Contains(entry.Config.Format(), "history-a") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("startup path lost surviving rollback history")
	}
	if _, statErr := os.Stat(activePath); !os.IsNotExist(statErr) {
		t.Fatalf("stale day-0 bootstrap recreated active.json; stat error = %v", statErr)
	}
	bootFile, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(bootFile), "day-0") {
		t.Fatal("test fixture day-0 config changed unexpectedly")
	}
}

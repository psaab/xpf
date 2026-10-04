package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func TestCLIHandleLoadRescueChangesOnlyCandidate11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store, err := configstore.New(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride("system { host-name candidate-before-rescue; }"); err != nil {
		t.Fatal(err)
	}
	rescuePath := filepath.Join(filepath.Dir(path), configstore.RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte("system { host-name rescue-from-cli; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli := New(store, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	activeBefore := store.ShowActiveSet()

	if err := cli.handleLoad([]string{"rescue"}); err != nil {
		t.Fatalf("handleLoad(rescue): %v", err)
	}
	candidate := store.ShowCandidateSet()
	if !strings.Contains(candidate, "host-name rescue-from-cli") || strings.Contains(candidate, "candidate-before-rescue") {
		t.Fatalf("CLI rescue load did not replace candidate: %s", candidate)
	}
	if got := store.ShowActiveSet(); got != activeBefore {
		t.Fatalf("CLI rescue load changed active config: before=%q after=%q", activeBefore, got)
	}
}

func TestCLIHandleLoadRescueHonorsRestrictedClassAndSyntax11802(t *testing.T) {
	cli, store := cliWithRestrictedClass9892(t, "limited")
	if err := os.WriteFile(filepath.Join(filepath.Dir(store.ConfigPath()), configstore.RescueConfigBase),
		[]byte("system { host-name rescue-restricted; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := store.ShowCandidateSet()
	if err := cli.handleLoad([]string{"rescue"}); err == nil || !strings.Contains(err.Error(), "rescue") {
		t.Fatalf("restricted load rescue error = %v, want refusal naming rescue", err)
	}
	if got := store.ShowCandidateSet(); got != before {
		t.Fatalf("restricted rescue load changed candidate: before=%q after=%q", before, got)
	}
	if err := cli.handleLoad([]string{"rescue", "extra"}); err == nil {
		t.Fatal("load rescue accepted extra arguments")
	}
}

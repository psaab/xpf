package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const validRescue11802 = "system { host-name rescue-11802; }\n"

func writeRescue11802(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write rescue config: %v", err)
	}
}

func TestLoadRescueFallbackOnFreshStore11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
	writeRescue11802(t, rescuePath, validRescue11802)

	store := newTestStoreAt(t, path)
	if err := store.Load(); !errors.Is(err, ErrConfigRescueFallback) {
		t.Fatalf("Load() = %v, want ErrConfigRescueFallback", err)
	}
	if !store.EverCommitted() {
		t.Fatal("selected rescue config did not mark the store previously committed")
	}
	if store.ActiveConfig() != nil {
		t.Fatal("rescue fallback must not install a compiled active config before explicit commit")
	}
	if got := store.ShowActiveSet(); !strings.Contains(got, "host-name rescue-11802") {
		t.Fatalf("selected rescue tree is not visible as the active candidate source: %s", got)
	}
	if len(store.ListHistory()) != 0 {
		t.Fatalf("rescue fallback wrote rollback history: %v", store.ListHistory())
	}
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if _, err := os.Stat(activePath); !os.IsNotExist(err) {
		t.Fatalf("rescue fallback persisted active.json: stat error = %v", err)
	}
	if got, err := os.ReadFile(rescuePath); err != nil || string(got) != validRescue11802 {
		t.Fatalf("rescue file changed during fallback: data=%q err=%v", got, err)
	}
}

func TestInvalidRescueDoesNotChangeFreshBoot11802(t *testing.T) {
	cases := []struct {
		name string
		text *string
	}{
		{name: "missing"},
		{name: "empty", text: ptrString11802("")},
		{name: "malformed", text: ptrString11802("system { host-name broken\n")},
		{name: "uncompilable", text: ptrString11802("apply-groups badgroup;\nsystem { host-name box; }\n")},
		{name: "oversized", text: ptrString11802(strings.Repeat(" ", MaxConfigSize+1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "xpf.conf")
			rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
			if tc.text != nil {
				writeRescue11802(t, rescuePath, *tc.text)
			}
			store := newTestStoreAt(t, path)
			if err := store.Load(); err != nil {
				t.Fatalf("fresh Load() = %v, want ordinary fresh boot", err)
			}
			if store.EverCommitted() || store.ActiveConfig() != nil || strings.TrimSpace(store.ShowActiveSet()) != "" {
				t.Fatalf("invalid rescue changed fresh boot state: committed=%v active=%v tree=%q",
					store.EverCommitted(), store.ActiveConfig(), store.ShowActiveSet())
			}
		})
	}
}

func ptrString11802(s string) *string { return &s }

func TestRescueFallbackDoesNotOverrideRecoveryMarkers11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	seed := newTestStoreAt(t, path)
	if err := seed.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := seed.LoadOverride("system { host-name committed-before-loss; }"); err != nil {
		t.Fatal(err)
	}
	if _, err := seed.Commit(); err != nil {
		t.Fatal(err)
	}
	seed.ExitConfigure()
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if err := os.Remove(activePath); err != nil {
		t.Fatal(err)
	}

	store := newTestStoreAt(t, path)
	if err := store.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load() = %v, want ErrConfigAbsentWithHistory", err)
	}
	if strings.Contains(store.ShowActiveSet(), "rescue-11802") {
		t.Fatal("saved rescue overrode surviving rollback history")
	}
	if !store.EverCommitted() {
		t.Fatal("recovery-marker path lost committed state")
	}
}

func TestRescueFallbackDoesNotOverrideConfirmMarker11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newTestStoreAt(t, path)
	if err := store.db.WriteConfirm(&confirmRecord{Deadline: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)

	reloaded := newTestStoreAt(t, path)
	if err := reloaded.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load() = %v, want ErrConfigAbsentWithHistory", err)
	}
	if strings.Contains(reloaded.ShowActiveSet(), "rescue-11802") {
		t.Fatal("saved rescue overrode the surviving confirm marker")
	}
}

func TestRescueFallbackDoesNotOverridePresentUnreadableActive11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if err := os.MkdirAll(filepath.Dir(activePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(activePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)

	store := newTestStoreAt(t, path)
	if err := store.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load() = %v, want ErrConfigDBUnreadable", err)
	}
	if strings.Contains(store.ShowActiveSet(), "rescue-11802") {
		t.Fatal("saved rescue overrode a present unreadable active DB")
	}
}

func TestRescueFallbackDoesNotOverridePresentCompileFailedActive11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	broken := "apply-groups badgroup;\nsystem { host-name committed-broken; }\n"
	tree, parseErrs := config.NewParser(broken).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse compile-failure fixture: %v", parseErrs[0])
	}
	db, err := NewDB(filepath.Join(filepath.Dir(path), ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetWriterVersion("test-11802")
	if err := db.WriteActive(tree); err != nil {
		t.Fatal(err)
	}
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)

	store := newTestStoreAt(t, path)
	if err := store.Load(); !errors.Is(err, ErrConfigCompile) {
		t.Fatalf("Load() = %v, want ErrConfigCompile", err)
	}
	got := store.ShowActiveSet()
	if !strings.Contains(got, "badgroup") || strings.Contains(got, "rescue-11802") {
		t.Fatalf("present compile-failed active DB was replaced by rescue: %s", got)
	}
}

func TestFactoryResetMarkerPrecedesRescueFallback11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	marker := filepath.Join(filepath.Dir(path), FactoryResetPendingBase)
	if err := os.WriteFile(marker, []byte(FactoryResetPendingPrefix), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)

	store := newTestStoreAt(t, path)
	if err := store.Load(); !errors.Is(err, ErrFactoryResetPending) {
		t.Fatalf("Load() = %v, want ErrFactoryResetPending", err)
	}
	if strings.Contains(store.ShowActiveSet(), "rescue-11802") {
		t.Fatal("rescue fallback bypassed factory-reset marker")
	}
}

func TestExplicitLoadRescueReplacesOnlyCandidate11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newTestStoreAt(t, path)
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride("system { host-name candidate-before-rescue; }"); err != nil {
		t.Fatal(err)
	}
	activeBefore := store.ShowActiveSet()
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)

	if err := store.LoadRescueAsPlantClass("", "operator"); err != nil {
		t.Fatalf("LoadRescueAsPlantClass: %v", err)
	}
	candidate := store.ShowCandidateSet()
	if !strings.Contains(candidate, "host-name rescue-11802") || strings.Contains(candidate, "candidate-before-rescue") {
		t.Fatalf("saved rescue did not replace the candidate atomically: %s", candidate)
	}
	if got := store.ShowActiveSet(); got != activeBefore {
		t.Fatalf("explicit rescue load changed active config: before=%q after=%q", activeBefore, got)
	}
	if !store.IsDirty() || store.EverCommitted() {
		t.Fatalf("candidate load changed commit state: dirty=%v everCommitted=%v", store.IsDirty(), store.EverCommitted())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), ".configdb", "active.json")); !os.IsNotExist(err) {
		t.Fatalf("candidate load persisted active.json: stat error = %v", err)
	}
}

func TestExplicitLoadRescueErrorsAreAtomic11802(t *testing.T) {
	for _, tc := range []struct {
		name       string
		text       *string
		wantAbsent bool
	}{
		{name: "missing", wantAbsent: true},
		{name: "empty", text: ptrString11802(""), wantAbsent: true},
		{name: "malformed", text: ptrString11802("system { host-name broken\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "xpf.conf")
			store := newTestStoreAt(t, path)
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.LoadOverride("system { host-name candidate-preserved; }"); err != nil {
				t.Fatal(err)
			}
			before := store.ShowCandidateSet()
			if tc.text != nil {
				writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), *tc.text)
			}
			err := store.LoadRescueAsPlantClass("", "")
			if err == nil {
				t.Fatal("LoadRescueAsPlantClass unexpectedly succeeded")
			}
			if tc.wantAbsent && !errors.Is(err, ErrRescueNotFound) {
				t.Fatalf("error = %v, want ErrRescueNotFound", err)
			}
			if !tc.wantAbsent && errors.Is(err, ErrRescueNotFound) {
				t.Fatalf("malformed rescue was classified as absent: %v", err)
			}
			if got := store.ShowCandidateSet(); got != before {
				t.Fatalf("failed rescue load changed candidate:\nbefore: %s\nafter:  %s", before, got)
			}
		})
	}
}

func TestFlatRescueFallbackCanCommitConfirmed11802(t *testing.T) {
	previousFactoryResetPath := FactoryResetPendingPath
	FactoryResetPendingPath = filepath.Join(t.TempDir(), FactoryResetPendingBase)
	t.Cleanup(func() { FactoryResetPendingPath = previousFactoryResetPath })

	path := filepath.Join(t.TempDir(), "xpf.conf")
	rescue := "set system host-name flat-rescue-11802\n"
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), rescue)

	store := newTestStoreAt(t, path)
	if err := store.Load(); !errors.Is(err, ErrConfigRescueFallback) {
		t.Fatalf("Load() = %v, want ErrConfigRescueFallback", err)
	}
	if got := store.ShowActiveSet(); !strings.Contains(got, "host-name flat-rescue-11802") {
		t.Fatalf("flat rescue was not selected: %s", got)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.CommitCheck(); err != nil {
		t.Fatalf("strict commit-check rejected the selected flat rescue: %v", err)
	}
	if _, err := store.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	t.Cleanup(func() {
		if store.IsConfirmPending() {
			_ = store.ConfirmCommit()
		}
	})
	if !store.IsConfirmPending() || store.ActiveConfig() == nil {
		t.Fatal("commit-confirmed did not promote the validated rescue candidate")
	}
	if err := store.ConfirmCommit(); err != nil {
		t.Fatalf("ConfirmCommit: %v", err)
	}
	if store.IsConfirmPending() {
		t.Fatal("confirmed rescue commit retained its rollback window")
	}
	activePath := filepath.Join(filepath.Dir(path), ".configdb", "active.json")
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("confirmed rescue commit did not persist active.json: %v", err)
	}
}

func TestExplicitLoadRescueHonorsReadOnlyAndHolderGates11802(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xpf.conf")
	store := newTestStoreAt(t, path)
	if err := store.EnterConfigureSession("holder"); err != nil {
		t.Fatal(err)
	}
	writeRescue11802(t, filepath.Join(filepath.Dir(path), RescueConfigBase), validRescue11802)
	before := store.ShowCandidateSet()
	if err := store.LoadRescueAsPlantClass("other", ""); !errors.Is(err, ErrConfigLockedByOther) {
		t.Fatalf("non-holder rescue load error = %v, want ErrConfigLockedByOther", err)
	}
	store.SetClusterReadOnly(true)
	if err := store.LoadRescueAsPlantClass("holder", ""); !errors.Is(err, ErrClusterReadOnly) {
		t.Fatalf("read-only rescue load error = %v, want ErrClusterReadOnly", err)
	}
	if got := store.ShowCandidateSet(); got != before {
		t.Fatalf("rejected rescue load changed candidate: before=%q after=%q", before, got)
	}
}

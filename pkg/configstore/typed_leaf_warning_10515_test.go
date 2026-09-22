package configstore

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const toleratedTypedLeaf10515 = `class-of-service {
    schedulers be transmit-rate asd;
}`

const nonTypedMidKeyword10515 = `security {
    policies {
        from-zone trust to-zon untrust {
            policy p1 {
                then permit;
            }
        }
    }
}`

func assertTypedLeafWarning10515(t *testing.T, cfg *config.Config) string {
	t.Helper()
	if cfg == nil {
		t.Fatal("tolerant ingress returned a nil compiled config")
	}
	warnings := config.ToleratedTypedLeafWarnings(cfg)
	if len(warnings) != 1 {
		t.Fatalf("typed-leaf warning count = %d, want 1; cfg.Warnings=%v", len(warnings), cfg.Warnings)
	}
	warning := warnings[0]
	for _, want := range []string{
		config.ToleratedTypedLeafWarningPrefix,
		"class-of-service schedulers be transmit-rate",
		"asd",
		"#10515",
	} {
		if !strings.Contains(warning, want) {
			t.Fatalf("typed-leaf warning %q does not contain %q", warning, want)
		}
	}
	return warning
}

func TestTypedLeafStrictRejectsAndLenientWarningPersists10515(t *testing.T) {
	if _, err := CheckText(toleratedTypedLeaf10515, -1); err == nil {
		t.Fatal("strict configstore.CheckText accepted transmit-rate asd")
	} else if !strings.Contains(err.Error(), "asd") {
		t.Fatalf("strict rejection does not name asd: %v", err)
	}

	tree, errs := config.NewParser(toleratedTypedLeaf10515).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse failed: %v", errs[0])
	}
	compiled, err := newTestStore(t).compileTreeLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile returned an error: %v", err)
	}
	assertTypedLeafWarning10515(t, compiled)
}

func TestLoadPersistsTypedLeafWarning10515(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(toleratedTypedLeaf10515).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse failed: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("persisting fixture: %v", err)
	}

	store := newTestStoreAt(t, path)
	if err := store.Load(); err != nil {
		t.Fatalf("Store.Load rejected tolerated typed leaf: %v", err)
	}
	assertTypedLeafWarning10515(t, store.ActiveConfig())
}

func TestSyncApplyPersistsTypedLeafWarning10515(t *testing.T) {
	store := newTestStore(t)
	compiled, err := store.SyncApply(toleratedTypedLeaf10515, nil)
	if err != nil {
		t.Fatalf("Store.SyncApply rejected tolerated typed leaf: %v", err)
	}
	assertTypedLeafWarning10515(t, compiled)
	assertTypedLeafWarning10515(t, store.ActiveConfig())
}

func TestTypedLeafWarningFilterLeavesOrdinaryWarningsOut10515(t *testing.T) {
	cfg := &config.Config{Warnings: []string{
		"ordinary compiler advisory",
		config.ToleratedTypedLeafWarningPrefix + " schema detail (#10515)",
	}}
	got := config.ToleratedTypedLeafWarnings(cfg)
	if len(got) != 1 || got[0] != cfg.Warnings[1] {
		t.Fatalf("filtered warnings = %v, want only typed-leaf marker", got)
	}
}

// TestToleratedNonTypedSchemaErrorsStayOutOfTypedLeafWarnings10515 prevents
// the producer from classifying closed-world/top-level keyword failures as
// typed-leaf values. Both fixtures are already accepted by tolerant Load.
func TestToleratedNonTypedSchemaErrorsStayOutOfTypedLeafWarnings10515(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "unknown top-level stanza", body: unknownTopLevelStanza8882},
		{name: "security policy typo", body: typoPersistedConfig9878},
		{name: "security policy middle keyword typo", body: nonTypedMidKeyword10515},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := newTestStore(t).SyncApply(tc.body, nil)
			if err != nil {
				t.Fatalf("tolerant SyncApply: %v", err)
			}
			if got := config.ToleratedTypedLeafWarnings(compiled); len(got) != 0 {
				t.Fatalf("non-typed schema error received typed-leaf warning: %v", got)
			}
		})
	}
}

func typedLeafTree10515(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(toleratedTypedLeaf10515).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse failed: %v", errs[0])
	}
	return tree
}

func TestTypedLeafWarningClearsOnCleanSyncReplacement10515(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.SyncApply(toleratedTypedLeaf10515, nil); err != nil {
		t.Fatalf("typed SyncApply: %v", err)
	}
	assertTypedLeafWarning10515(t, store.ActiveConfig())

	if _, err := store.SyncApply("system { host-name clean-replacement; }", nil); err != nil {
		t.Fatalf("clean SyncApply: %v", err)
	}
	if got := config.ToleratedTypedLeafWarnings(store.ActiveConfig()); len(got) != 0 {
		t.Fatalf("typed-leaf warning survived clean replacement: %v", got)
	}
}

func TestTypedLeafWarningSurvivesLiveConfirmRecovery10515(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if _, err := store.SyncApply("system { host-name live-active; }", nil); err != nil {
		t.Fatalf("clean SyncApply: %v", err)
	}
	if got := config.ToleratedTypedLeafWarnings(store.ActiveConfig()); len(got) != 0 {
		t.Fatalf("clean active fixture unexpectedly has typed-leaf warnings: %v", got)
	}
	target := typedLeafTree10515(t)
	if err := store.db.WriteConfirm(&confirmRecord{
		Deadline: time.Now().Add(time.Hour),
		PrevTree: target,
	}); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("live confirm recovery Load: %v", err)
	}
	beforeRollback := restarted.ActiveConfig()
	if config.ToleratedTypedLeafWarnings(beforeRollback) != nil {
		t.Fatalf("live recovery changed the clean active config before rollback: %v",
			config.ToleratedTypedLeafWarnings(beforeRollback))
	}
	if !restarted.IsConfirmPending() {
		t.Fatal("live confirm record did not re-arm during Load")
	}
	restarted.InvokeRollbackTimerForTesting(restarted.ConfirmGenForTesting())
	afterRollback := restarted.ActiveConfig()
	if afterRollback == beforeRollback {
		t.Fatal("live confirm rollback did not promote the persisted typed rollback target")
	}
	if got, want := journalConfigHash(restarted.ActiveTree()), journalConfigHash(target); got != want {
		t.Fatalf("live confirm rollback active tree hash = %q, want persisted typed target %q", got, want)
	}
	assertTypedLeafWarning10515(t, afterRollback)
}

func TestTypedLeafWarningSurvivesExpiredConfirmRecovery10515(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if _, err := store.SyncApply("system { host-name expired-active; }", nil); err != nil {
		t.Fatalf("clean SyncApply: %v", err)
	}
	if got := config.ToleratedTypedLeafWarnings(store.ActiveConfig()); len(got) != 0 {
		t.Fatalf("clean active fixture unexpectedly has typed-leaf warnings: %v", got)
	}
	target := typedLeafTree10515(t)
	if err := store.db.WriteConfirm(&confirmRecord{
		Deadline: time.Now().Add(-time.Minute),
		PrevTree: target,
	}); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("expired confirm recovery Load: %v", err)
	}
	assertTypedLeafWarning10515(t, restarted.ActiveConfig())
	if got, want := journalConfigHash(restarted.ActiveTree()), journalConfigHash(target); got != want {
		t.Fatalf("expired confirm recovery active tree hash = %q, want persisted typed target %q", got, want)
	}
	if restarted.IsConfirmPending() {
		t.Fatal("expired confirm record remained pending after rollback")
	}
}

func TestTypedLeafWarningSurvivesRetainedGenerationActiveAndHistory10515(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if _, err := store.SyncApply(toleratedTypedLeaf10515, nil); err != nil {
		t.Fatalf("typed SyncApply: %v", err)
	}
	digest := store.ActiveDigest()
	active, ok := store.RetainedGeneration(digest)
	if !ok || active != store.ActiveConfig() {
		t.Fatalf("active retained generation = (%v, %v), want active config", active, ok)
	}
	assertTypedLeafWarning10515(t, active)

	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet("delete class-of-service\n"); err != nil {
		t.Fatalf("delete tolerated class-of-service subtree: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("clean replacement Commit: %v", err)
	}
	history, ok := store.RetainedGeneration(digest)
	if !ok || history == nil {
		t.Fatalf("typed history generation did not resolve: cfg=%v ok=%v", history, ok)
	}
	assertTypedLeafWarning10515(t, history)
}

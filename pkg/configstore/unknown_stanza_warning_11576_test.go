package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Issue 11576: an unknown top-level stanza is discarded on lenient load
// (correct no-brick behavior per #8882/#1960) but left no trace in
// cfg.Warnings — Store.SyncApply with a typo'd root returned nil and Warnings
// empty while only slog named the stanza. Operators reading active-config
// warnings cannot see which root was ignored.
//
// The tolerant ingress must persist the unknown-stanza schema error on the
// compiled object while still loading (no brick); the strict commit path
// still rejects (pinned by TestUnknownTopLevelStanzaIsRejectedAtCommit_8882).
// RED-on-revert: remove tolerant warning persistence/compiler fallback and the
// tolerant compile/load legs report no warning naming the stanza.
func TestCompileConfigLenientWarnsUnknownTopLevelStanza11576(t *testing.T) {
	tree, errs := config.NewParser(unknownTopLevelStanza8882).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	compiled, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must not reject an unknown top-level stanza: %v", err)
	}
	assertUnknownStanzaWarning11576(t, compiled.Warnings)
	if got := config.ToleratedUnknownTopLevelStanzaWarnings(compiled); len(got) != 1 {
		t.Fatalf("active-config unknown-stanza warnings = %v, want one warning", got)
	}
	if err := config.SchemaValidate(tree, nil); err == nil || !config.IsUnknownTopLevelStanzaSchemaError(err) {
		t.Fatalf("strict schema validation = %v, want unknown-stanza rejection", err)
	}
	if _, err := CheckText(unknownTopLevelStanza8882, -1); err == nil {
		t.Fatal("strict commit check accepted an unknown top-level stanza")
	}
}

func TestSyncApplyWarnsUnknownTopLevelStanza11576(t *testing.T) {
	store := newTestStore(t)
	compiled, err := store.SyncApply(unknownTopLevelStanza8882, nil)
	if err != nil {
		t.Fatalf("tolerant SyncApply must not brick on an unknown top-level stanza: %v", err)
	}
	if compiled == nil {
		t.Fatal("tolerant SyncApply returned no error but no compiled config")
	}
	assertUnknownStanzaWarning11576(t, compiled.Warnings)
}

func TestLoadWarnsUnknownTopLevelStanza11576(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	tree, errs := config.NewParser(unknownTopLevelStanza8882).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: the fixture must parse: %v", errs[0])
	}
	if err := newTestStoreAt(t, path).db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("precondition: persisting the stanza must succeed: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("Store.Load must not brick on an unknown top-level stanza: %v", err)
	}
	if booted.ActiveConfig() == nil {
		t.Fatal("Store.Load returned no error but left ActiveConfig() nil")
	}
	assertUnknownStanzaWarning11576(t, booted.ActiveConfig().Warnings)
}

func assertUnknownStanzaWarning11576(t *testing.T, warnings []string) {
	t.Helper()
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "securty") {
		t.Fatalf("tolerant warnings must name the discarded stanza; got %q", warnings)
	}
	if count := strings.Count(joined, config.ToleratedUnknownTopLevelStanzaWarningPrefix); count != 1 {
		t.Fatalf("unknown-stanza warning marker count = %d, want one; warnings=%q", count, warnings)
	}
	if !strings.Contains(joined, "[unknown-stanza-tolerated]") {
		t.Fatalf("tolerant warnings must carry the stable unknown-stanza marker; got %q", warnings)
	}
}

package configstore

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9641 Codex implementation review, finding 4. A rollback slot is read from disk with a
// bare parse, without Load's preprocessing. A slot an older xpf wrote can carry syntax
// this xpf retired, and charon can still run that generation after an upgrade restart.
// RetainedGeneration must resolve it the way Load would have compiled it. Unguarded, the
// lenient compile rejects the retired syntax and the generation does not resolve.
func TestRetainedGenerationResolvesASlotWithRetiredSyntax9641(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	s := configuredStore9641(t, path)
	commitHostName9641(t, s, "gen0")
	commitHostName9641(t, s, "gen1")

	const old = "system {\n    host-name oldgen;\n    dataplane-type ebpf;\n}\n"
	tree, errs := config.NewParser(old).Parse()
	if len(errs) > 0 {
		t.Fatalf("FIXTURE: parse the old slot: %v", errs)
	}
	digest := configTextDigest(tree.Format())
	if err := os.WriteFile(s.rollbackPath(1), []byte(old), 0o600); err != nil {
		t.Fatalf("FIXTURE: write the old slot: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := restarted.compileTreeLenient(tree.Clone()); err == nil {
		t.Fatal("FIXTURE: without Load's rewrite the retired syntax must fail the lenient compile")
	}
	cfg, ok := restarted.RetainedGeneration(digest)
	if !ok || cfg == nil || cfg.System.HostName != "oldgen" {
		t.Errorf("a retained slot carrying retired syntax did not resolve (ok=%v)", ok)
	}
}

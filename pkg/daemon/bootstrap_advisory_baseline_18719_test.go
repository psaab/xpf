package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)
const fabricStampBootstrapConfig18719 = `set chassis cluster cluster-id 1
set chassis cluster node 0
set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
set chassis cluster fabric-interface fab0
`

func TestBootstrapDoesNotHideFabricReminder18719(t *testing.T) {
	d, _ := bootstrapDaemon(t, fabricStampBootstrapConfig18719, 0)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile: %v", err)
	}
	if active := d.store.ActiveConfig(); active == nil || !hasWarningText18719(active.Warnings) {
		t.Fatalf("premise: bootstrap compiled the fabric reminder; active=%v", active)
	}
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := d.store.LoadSet("set system host-name after-bootstrap"); err != nil {
		t.Fatalf("stage unrelated operator change: %v", err)
	}
	compiled, err := d.store.Commit()
	if err != nil {
		t.Fatalf("first operator commit after bootstrap: %v", err)
	}
	if !hasWarningText18719(compiled.Warnings) {
		t.Fatalf("first operator commit hid the bootstrap reminder: %v", compiled.Warnings)
	}
}

func TestEventEnginePromotionDoesNotHideFabricReminder18719(t *testing.T) {
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, command := range []string{
		"chassis cluster cluster-id 1",
		"chassis cluster node 0",
		"chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"chassis cluster fabric-interface fab0",
	} {
		if err := s.SetFromInput(command); err != nil {
			t.Fatalf("stage %q: %v", command, err)
		}
	}
	seed, err := s.Commit()
	if err != nil {
		t.Fatalf("commit fabric baseline: %v", err)
	}
	if !hasWarningText18719(seed.Warnings) {
		t.Fatalf("premise: initial commit must contain #10105 reminder; warnings=%v", seed.Warnings)
	}
	if err := s.SetFromInput("system host-name event-engine"); err != nil {
		t.Fatalf("stage event-engine change: %v", err)
	}

	d := &Daemon{
		applySem: semaphore.NewWeighted(1),
		store:    s,
		cluster:  cluster.NewManager(0, 1),
	}
	d.applyBodyForTest = func(*config.Config) {}
	if compiled, err := d.commitAndApply(
		context.Background(),
		configstore.InternalCommitterAs("system:event-engine"),
		"automated advisory baseline test",
		peerSyncNever,
	); err != nil || compiled == nil {
		t.Fatalf("event-engine commit = (%v, %v), want promoted config", compiled, err)
	}

	if err := s.SetFromInput("system domain-name after-event-engine"); err != nil {
		t.Fatalf("stage operator change: %v", err)
	}
	operatorCommit, err := s.Commit()
	if err != nil {
		t.Fatalf("operator commit after event-engine promotion: %v", err)
	}
	if !hasWarningText18719(operatorCommit.Warnings) {
		t.Fatalf("event-engine promotion hid the next operator reminder: %v", operatorCommit.Warnings)
	}
}

func hasWarningText18719(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "fabric zone stamp (#10105)") {
			return true
		}
	}
	return false
}

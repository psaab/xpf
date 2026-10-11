package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #1798 regression gates:
//  (a) a PERSISTED config containing a newline description must Load()
//      and boot — the lenient path sanitizes with a warning;
//  (b) re-introducing the value must be REJECTED at strict commit;
//  (c) after a sanitized Load, the operator's next unrelated commit
//      must succeed (the stored tree was scrubbed, not just the
//      compiled view).

const injectedSetCmd = `set interfaces ge-0-0-0 description "lan\nDHCP=ipv4"`

func newlinePersistedTree(t *testing.T) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	path, err := config.ParseSetCommand(injectedSetCmd)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	return tree
}

func TestLoadBootsAndSanitizesPersistedNewlineDescription(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")

	// Persist a bad tree directly (bypassing commit, as a pre-gate
	// daemon would have): the DB stores the tree as JSON, so the real
	// newline round-trips exactly.
	s1 := newTestStoreAt(t, path)
	if err := s1.db.WriteActive(newlinePersistedTree(t)); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	// Gate (a): the box must boot.
	s2 := newTestStoreAt(t, path)
	if err := s2.Load(); err != nil {
		t.Fatalf("Load must boot on a persisted control-char config: %v", err)
	}
	cfg := s2.ActiveConfig()
	if cfg == nil {
		t.Fatal("loaded config is nil")
	}
	ifc := cfg.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil {
		t.Fatal("interface ge-0-0-0 missing from loaded config")
	}
	if strings.ContainsAny(ifc.Description, "\n\r") {
		t.Fatalf("loaded description still carries control chars: %q", ifc.Description)
	}
	if ifc.Description != "lan DHCP=ipv4" {
		t.Errorf("loaded description not sanitized as expected: %q", ifc.Description)
	}

	// Gate (c): the stored ACTIVE TREE was scrubbed too, so the next
	// unrelated commit cannot mysteriously fail on the old value.
	if err := s2.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// The zone reference needs a real unit 0 since #11433 (absent-unit
	// zone refs fail strict commit); the #1798 property is the scrubbed
	// description, not the zone target.
	if err := s2.SetFromInput("interfaces ge-0-0-0 unit 0 family inet"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s2.SetFromInput("security zones security-zone trust interfaces ge-0-0-0.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s2.Commit(); err != nil {
		t.Fatalf("next unrelated commit after sanitized Load must succeed: %v", err)
	}
}

func TestCommitRejectsNewlineDescription(t *testing.T) {
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.SetFromInput(`interfaces ge-0-0-0 description "lan\nDHCP=ipv4"`); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	// Gate (b): strict commit-check and commit both reject.
	if _, err := s.CommitCheck(); err == nil {
		t.Fatal("CommitCheck must reject a newline description")
	} else if !strings.Contains(err.Error(), "control characters") {
		t.Fatalf("CommitCheck error should mention control characters: %v", err)
	}
	if _, err := s.Commit(); err == nil {
		t.Fatal("Commit must reject a newline description")
	}
}

func TestSyncApplySanitizesNewlineDescription(t *testing.T) {
	s := newTestStore(t)
	// Hierarchical text as pushed by a (possibly un-upgraded) cluster
	// primary; the quoted "\n" escape becomes a real newline in the
	// parsed tree.
	content := "interfaces {\n" +
		"    ge-0-0-0 {\n" +
		"        description \"lan\\nDHCP=ipv4\";\n" +
		"    }\n" +
		"}\n"
	compiled, err := s.SyncApply(content, nil)
	if err != nil {
		t.Fatalf("SyncApply must tolerate a peer-synced control-char config: %v", err)
	}
	ifc := compiled.Interfaces.Interfaces["ge-0-0-0"]
	if ifc == nil {
		t.Fatal("interface ge-0-0-0 missing from synced config")
	}
	if strings.ContainsAny(ifc.Description, "\n\r") {
		t.Fatalf("synced description still carries control chars: %q", ifc.Description)
	}
	// The stored active tree must be clean for any later strict commit.
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	// Real unit 0 for the zone reference since #11433 (see above).
	if err := s.SetFromInput("interfaces ge-0-0-0 unit 0 family inet"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if err := s.SetFromInput("security zones security-zone trust interfaces ge-0-0-0.0"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("commit after sanitized SyncApply must succeed: %v", err)
	}
}

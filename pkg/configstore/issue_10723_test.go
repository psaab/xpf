package configstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

func tree10723(t *testing.T, host string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser("system { host-name " + host + "; }\n").Parse()
	if len(errs) != 0 {
		t.Fatalf("parse tree for %q: %v", host, errs[0])
	}
	return tree
}

// TestRollbackLoadRejectsMixedSlotGeneration10723 injects a failed replacement
// of slot 2. The written metadata must tombstone that stale slot while allowing
// later slots whose content, file identity, and generation are all current.
func TestRollbackLoadRejectsMixedSlotGeneration10723(t *testing.T) {
	// RED-on-revert: admitting old slot 2 would expose the previous rollback
	// target at the new slot 2 position.
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	max := s.history.MaxSize()
	s.history = NewHistory(max)
	for _, host := range []string{"old-slot-3", "old-slot-2", "old-slot-1"} {
		s.history.Push(&HistoryEntry{Config: tree10723(t, host), Timestamp: time.Now()})
	}
	s.saveRollbackFiles()

	s.history = NewHistory(max)
	for _, host := range []string{"new-slot-3", "new-slot-2", "new-slot-1"} {
		s.history.Push(&HistoryEntry{Config: tree10723(t, host), Timestamp: time.Now()})
	}
	oldWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = oldWrite })
	injected := errors.New("injected rollback slot 2 failure")
	rbWriteFileDurable = func(p string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Clean(p) == filepath.Clean(s.rollbackPath(2)) {
			return injected
		}
		return oldWrite(p, data, perm, opts...)
	}
	s.saveRollbackFiles()

	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) != 3 {
		t.Fatalf("loaded %d history entries, want all three positions preserved", len(entries))
	}
	if entries[0].Config == nil || !strings.Contains(entries[0].Config.Format(), "new-slot-1") {
		t.Fatalf("slot 1 should be the new generation, got %#v", entries[0])
	}
	if entries[1].Config != nil {
		t.Fatalf("slot 2 admitted a stale rollback target: %s", entries[1].Config.Format())
	}
	if entries[2].Config == nil || !strings.Contains(entries[2].Config.Format(), "new-slot-3") {
		t.Fatalf("slot 3 should remain independently verifiable in its position, got %#v", entries[2])
	}
}

// TestRollbackLoadRejectsHistoryFromPriorActiveGeneration10723 covers a crash
// between an atomic active.json replacement and the first rollback-slot rewrite.
// The active bytes are identical, but the new inode identifies a different save.
func TestRollbackLoadRejectsHistoryFromPriorActiveGeneration10723(t *testing.T) {
	// RED-on-revert: without active-file identity binding, restart accepts the
	// unchanged slot set after active.json was replaced.
	path := filepath.Join(t.TempDir(), "xpf.conf")
	s := newTestStoreAt(t, path)
	s.active = tree10723(t, "active-old")
	if err := s.db.WriteActive(s.active); err != nil {
		t.Fatalf("write old active tree: %v", err)
	}
	for _, host := range []string{"old-slot-3", "old-slot-2", "old-slot-1"} {
		s.history.Push(&HistoryEntry{Config: tree10723(t, host), Timestamp: time.Now()})
	}
	s.saveRollbackFiles()

	if err := s.db.WriteActive(tree10723(t, "active-old")); err != nil {
		t.Fatalf("rewrite identical active tree: %v", err)
	}
	restarted := newTestStoreAt(t, path)
	restarted.loadRollbackHistory()
	entries := restarted.history.List()
	if len(entries) != 3 {
		t.Fatalf("loaded %d history entries, want all three positions preserved", len(entries))
	}
	for i, entry := range entries {
		if entry.Config != nil {
			t.Fatalf("rollback slot %d admitted history bound to the prior active config: %s",
				i+1, entry.Config.Format())
		}
	}
}

func TestConfirmEnvelopeVersionGateAndUnknownFields10723(t *testing.T) {
	// RED-on-revert: omitting the outer marker or strict decoder makes these
	// compatibility and unknown-field assertions fail.
	db, err := NewDB(filepath.Join(t.TempDir(), ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	rec := &confirmRecord{Deadline: time.Now().Add(time.Hour), PrevTree: &config.ConfigTree{}}
	if err := db.WriteConfirm(rec); err != nil {
		t.Fatalf("WriteConfirm: %v", err)
	}
	raw, err := os.ReadFile(db.confirmPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(raw, []byte(confirmEnvelopeMagic+" v=1\n")) {
		t.Fatalf("confirm record lacks its version gate: %q", raw[:min(len(raw), 80)])
	}
	var oldReader confirmRecord
	if err := json.Unmarshal(raw, &oldReader); err == nil {
		t.Fatal("a pre-envelope JSON reader accepted the safety record instead of failing closed")
	}
	if got, err := db.ReadConfirm(); err != nil || got == nil || !got.Deadline.Equal(rec.Deadline) {
		t.Fatalf("ReadConfirm round trip = (%+v, %v), want a valid pending record", got, err)
	}

	body, err := json.Marshal(map[string]any{
		"deadline":            time.Now().Add(time.Hour),
		"prev_tree":           &config.ConfigTree{},
		"future_safety_marker": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := append([]byte(confirmEnvelopeMagic+" v=1\n"), body...)
	if err := os.WriteFile(db.confirmPath(), unknown, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadConfirm(); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ReadConfirm unknown field error = %v, want strict unknown-field refusal", err)
	}

	future := append([]byte(confirmEnvelopeMagic+" v=2\n"), body...)
	if err := os.WriteFile(db.confirmPath(), future, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ReadConfirm(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("ReadConfirm future envelope error = %v, want version-gate refusal", err)
	}

	// Existing unenveloped records stay readable during a rolling upgrade.
	legacy, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db.confirmPath(), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := db.ReadConfirm(); err != nil || got == nil {
		t.Fatalf("legacy confirm record = (%+v, %v), want it to remain readable", got, err)
	}
}

func TestParseFailureTextIsPositionOnly10723(t *testing.T) {
	// RED-on-revert: exposing ParseError.Message from Error() leaks the sentinel
	// through every affected ingress.
	const secret = "PRESHAREDLEAKSENTINEL"
	parseErr := config.ParseError{Line: 7, Column: 11, Message: secret}
	if got := parseErr.Error(); strings.Contains(got, secret) ||
		!strings.Contains(got, "line 7") || !strings.Contains(got, "column 11") {
		t.Fatalf("ParseError text = %q, want only line/column and no token message", got)
	}

	bad := "system {\n host-name \"" + secret
	checkPositionOnly10723(t, "CheckText", func() error {
		_, err := CheckText(bad, -1)
		return err
	})

	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	checkPositionOnly10723(t, "LoadOverride", func() error { return s.LoadOverride(bad) })
	checkPositionOnly10723(t, "LoadMerge", func() error { return s.LoadMerge(bad) })
	checkPositionOnly10723(t, "SyncApply", func() error {
		_, err := s.SyncApply(bad, nil)
		return err
	})
}

func checkPositionOnly10723(t *testing.T, path string, run func() error) {
	t.Helper()
	const secret = "PRESHAREDLEAKSENTINEL"
	err := run()
	if err == nil {
		t.Fatalf("%s accepted malformed config", path)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("%s echoed config token in parse error: %v", path, err)
	}
	if !strings.Contains(err.Error(), "line ") || !strings.Contains(err.Error(), "column ") {
		t.Fatalf("%s error lacks parser position: %v", path, err)
	}
}

func TestReadBoundedFileRefusesSymlink10723(t *testing.T) {
	// RED-on-revert: opening without O_NOFOLLOW reads through the planted symlink.
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "config")
	if err := os.WriteFile(target, []byte("authoritative config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadBoundedFile(link, 1024); err == nil {
		t.Fatalf("ReadBoundedFile followed symlink and returned %q", data)
	}
	data, err := ReadBoundedFile(target, 1024)
	if err != nil || string(data) != "authoritative config" {
		t.Fatalf("regular-file read = (%q, %v), want original payload", data, err)
	}
}

func TestPlaintextV2EnvelopeIsUnreadableByPreV2Reader10723(t *testing.T) {
	// RED-on-revert: a pre-v2 bare JSON decoder must reject the plaintext v2 header.
	db, err := NewDB(filepath.Join(t.TempDir(), ".configdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WriteActive(&config.ConfigTree{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(db.activePath())
	if err != nil {
		t.Fatal(err)
	}
	_, hdr, err := stripEnvelope(raw)
	if err != nil {
		t.Fatalf("stripEnvelope: %v", err)
	}
	if hdr.FormatVersion != 2 || hdr.MinReader != EnvelopeMinReaderVersion {
		t.Fatalf("plaintext envelope header = %+v, want v2 with baseline min-reader", hdr)
	}
	var oldReader config.ConfigTree
	if err := json.Unmarshal(raw, &oldReader); err == nil {
		t.Fatal("a pre-v2 JSON reader accepted the plaintext v2 envelope")
	}
}

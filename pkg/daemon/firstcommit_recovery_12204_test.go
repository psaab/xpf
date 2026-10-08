package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestExpiredFirstCommitRecoveryBootClass12204 connects the configstore
// first-commit recovery oracle to the actual daemon boot-class predicate. The
// configstore test pins EverCommitted and the disk marker; this consumer test
// makes sure that the post-recovery values really resolve to BOOTSTRAP rather
// than NORMAL (operator-committed-empty).
func TestExpiredFirstCommitRecoveryBootClass12204(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	armed, err := configstore.New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := armed.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := armed.SetFromInput("system host-name First"); err != nil {
		t.Fatalf("SetFromInput: %v", err)
	}
	if _, err := armed.CommitConfirmed(10); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	armed.CancelConfirmTimerForTesting()

	// A first commit has an empty rollback target, so confirm.json is plaintext
	// (no master-password key is needed). Preserve its versioned envelope and
	// all fields, changing only the deadline as downtime would.
	confirmPath := filepath.Join(filepath.Dir(path), ".configdb", "confirm.json")
	data, err := os.ReadFile(confirmPath)
	if err != nil {
		t.Fatalf("read confirm.json: %v", err)
	}
	newline := bytes.IndexByte(data, '\n')
	if newline < 0 {
		t.Fatal("confirm.json has no envelope header")
	}
	var record map[string]json.RawMessage
	if err := json.Unmarshal(data[newline+1:], &record); err != nil {
		t.Fatalf("decode confirm.json: %v", err)
	}
	var firstCommit bool
	if err := json.Unmarshal(record["first_commit"], &firstCommit); err != nil || !firstCommit {
		t.Fatalf("premise broken: first_commit=%v err=%v", firstCommit, err)
	}
	deadline, err := json.Marshal(time.Now().Add(-2 * time.Minute))
	if err != nil {
		t.Fatalf("marshal expired deadline: %v", err)
	}
	record["deadline"] = deadline
	body, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatalf("marshal confirm.json: %v", err)
	}
	if err := os.WriteFile(confirmPath, append(data[:newline+1], body...), 0o600); err != nil {
		t.Fatalf("write expired confirm.json: %v", err)
	}

	recovered, err := configstore.New(path)
	if err != nil {
		t.Fatalf("New recovered store: %v", err)
	}
	if err := recovered.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if recovered.EverCommitted() {
		t.Fatal("EverCommitted=true after expired first-commit recovery; daemon must not resolve the empty rollback target as operator-committed")
	}
	if recovered.ActiveConfig() != nil {
		t.Fatal("ActiveConfig non-nil after first-commit recovery; rollback target is the empty bootstrap tree")
	}

	got := computeBootClass(recovered.ActiveConfig() != nil, recovered.EverCommitted(), false, false)
	if got != bootClassBootstrap {
		t.Fatalf("computeBootClass after expired first-commit recovery = %v; want bootClassBootstrap", got)
	}
}

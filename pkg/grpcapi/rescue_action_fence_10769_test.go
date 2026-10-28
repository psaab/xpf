package grpcapi

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestRescueActionReportsResetFence_10769 proves the remote explicit save
// reports the factory-reset fence as a failed precondition rather than claiming
// rescue.conf was saved or returning an unrelated internal error.
func TestRescueActionReportsResetFence_10769(t *testing.T) {
	dir := t.TempDir()
	store, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	store.QuiesceRescueWrites()

	server := NewServer("", Config{Store: store})
	if _, err := server.rescueAction("rescue-save"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rescueAction(rescue-save) code = %s, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	if _, err := os.Stat(filepath.Join(dir, configstore.RescueConfigBase)); !os.IsNotExist(err) {
		t.Fatalf("fenced rescue action created rescue.conf: stat err=%v", err)
	}
}

// TestRescueActionRejectsUncommittedRescueSave_11803 reports an empty-store
// rescue save as an operator precondition failure and preserves the old file.
func TestRescueActionRejectsUncommittedRescueSave_11803(t *testing.T) {
	dir := t.TempDir()
	store, err := configstore.New(filepath.Join(dir, "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	const knownGood = "system { host-name tenant-good; }\n"
	path := filepath.Join(dir, configstore.RescueConfigBase)
	if err := os.WriteFile(path, []byte(knownGood), 0o600); err != nil {
		t.Fatalf("seed existing rescue config: %v", err)
	}

	server := NewServer("", Config{Store: store})
	if _, err := server.rescueAction("rescue-save"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rescueAction(rescue-save) code = %s, want FailedPrecondition (err=%v)", status.Code(err), err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read existing rescue config: %v", err)
	}
	if string(got) != knownGood {
		t.Fatalf("rescue-save changed existing rescue config: got %q, want %q", got, knownGood)
	}
}

// TestRescueDeleteSupersededIsFailedPrecondition_17825 keeps the expected
// latest-operation-wins race out of the gRPC internal-error class.
func TestRescueDeleteSupersededIsFailedPrecondition_17825(t *testing.T) {
	err := fmt.Errorf("delete rescue config: %w", configstore.ErrRescueDeleteSuperseded)
	if got := status.Code(rescueDeleteRPCError(err)); got != codes.FailedPrecondition {
		t.Fatalf("superseded rescue delete code = %s, want FailedPrecondition", got)
	}
	if got := status.Code(rescueDeleteRPCError(fmt.Errorf("unlink failed"))); got != codes.Internal {
		t.Fatalf("ordinary rescue delete code = %s, want Internal", got)
	}
}

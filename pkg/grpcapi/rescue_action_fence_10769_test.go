package grpcapi

import (
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

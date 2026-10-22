package grpcapi

import (
	"context"
	"github.com/psaab/xpf/pkg/factoryreset"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestZeroizeRefusesSharedConfigRoot pins the gRPC half of #5684: a `zeroize`
// SystemAction whose configured config root resolves to a shared/parent/system
// directory must FAIL CLOSED — surface an error and NEVER invoke the wipe — so a
// custom/adversarial -config can't turn a factory reset into a broad deletion of
// the enclosing directory. configDir is filepath.Dir(store.ConfigPath()); the
// guard lives in (*Server).zeroizeConfigRoot, before runZeroize enters the
// terminal reset generation or performZeroizeWipe touches any leg.
//
// The wipe primitive is stubbed to a capture (never touches real system paths),
// and a throwaway directory is registered as a shared root via the
// configstore.FactoryResetForbiddenRoots seam, so the test is hermetic and safe
// on revert.
//
// RED on revert: drop the ValidateFactoryResetRoot guard in zeroizeConfigRoot
// and the handler proceeds to call the (stubbed) wipe — `wiped` flips true and
// the fail-closed error disappears, tripping both assertions.
func TestZeroizeRefusesSharedConfigRoot(t *testing.T) {
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		scheduleStopDaemon = origStop
	})

	var wiped bool
	t.Cleanup(factoryreset.StubWipeWithLogInventoryForTest(func(_, _, _ string, _ factoryreset.LogInventory, _ factoryreset.Completion) error {
		wiped = true
		return nil
	}))
	scheduleStopDaemon = func() {}

	// A config file placed directly in a shared directory: filepath.Dir resolves
	// the config root to that shared directory (the #5684 footgun).
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(shared, 0o700); err != nil {
		t.Fatalf("mkdir shared: %v", err)
	}
	configPath := filepath.Join(shared, "xpf.conf")
	store := newConfigStore(t, configPath)
	s := &Server{store: store}

	// Register the throwaway dir as a shared/system root for this test, in
	// RESOLVED form (#9897 review): the gate compares resolved candidates,
	// which differ under a symlinked TMPDIR (identity on Linux).
	wantShared, werr := filepath.EvalSymlinks(shared)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", shared, werr)
	}
	old := configstore.FactoryResetForbiddenRoots
	configstore.FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(wantShared))
	t.Cleanup(func() { configstore.FactoryResetForbiddenRoots = old })

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err == nil {
		t.Fatalf("SystemAction(zeroize) with a shared config root must fail closed; got resp=%+v", resp)
	}
	if wiped {
		t.Error("zeroize must NOT invoke the wipe when the config root is a shared/parent directory (fail-closed)")
	}
}

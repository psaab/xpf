package grpcapi

import (
	"context"
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
	origWipe := performZeroizeWipeWithLogInventory
	origStop := scheduleStopDaemon
	t.Cleanup(func() {
		performZeroizeWipeWithLogInventory = origWipe
		scheduleStopDaemon = origStop
	})

	var wiped bool
	performZeroizeWipeWithLogInventory = func(_, _, _ string, _ ZeroizeLogInventory) error {
		wiped = true
		return nil
	}
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

// TestZeroizeConfigDirRefusesSharedRoot pins the #5684 defense-in-depth guard on
// the gRPC config-state wipe PRIMITIVE (zeroizeConfigDir) — the more destructive
// one, since it RemoveAll's <root>/.configdb and <root>/tls. In production
// runZeroize validates the root before performZeroizeWipe reaches this
// primitive, but the primitive re-validates itself so it never trusts a caller
// to have handed it an xpf-owned root (mirroring the CLI's FactoryResetConfigDir
// guard). Fully hermetic: zeroizeConfigDir only ever touches configDir, so a
// throwaway shared dir + the FactoryResetForbiddenRoots seam keeps even the RED
// path from reaching a real system directory.
//
// RED on revert: remove the ValidateFactoryResetRoot guard at the top of
// zeroizeConfigDir and every seeded artifact is deleted (*.conf glob,
// isTextRollbackFile, RemoveAll .configdb + tls) — the "survives" assertions
// fail and the "returns an error" check fails (the removals succeed → nil).
func TestZeroizeConfigDirRefusesSharedRoot(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(filepath.Join(shared, ".configdb"), 0o700); err != nil {
		t.Fatalf("mkdir shared/.configdb: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(shared, "tls"), 0o700); err != nil {
		t.Fatalf("mkdir shared/tls: %v", err)
	}
	// Files a pre-fix broad wipe would have destroyed inside the shared dir.
	seeded := map[string]string{
		filepath.Join(shared, "neighbor.conf"):             "not xpf's config",
		filepath.Join(shared, ".configdb", "foreign.json"): "someone else's DB",
		filepath.Join(shared, "tls", "key.pem"):            "someone else's key",
		filepath.Join(shared, "xpf.conf.1"):                "rollback-shaped bystander",
		filepath.Join(shared, ".config.journal"):           "foreign journal",
	}
	for p, body := range seeded {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	// Register the throwaway dir as a shared/system root for this test, in
	// RESOLVED form (#9897 review — see above).
	wantShared, werr := filepath.EvalSymlinks(shared)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", shared, werr)
	}
	old := configstore.FactoryResetForbiddenRoots
	configstore.FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(wantShared))
	t.Cleanup(func() { configstore.FactoryResetForbiddenRoots = old })

	if err := zeroizeConfigDir(shared, "xpf.conf"); err == nil {
		t.Fatalf("zeroizeConfigDir(%q) = nil; want an error refusing to wipe a shared/parent directory", shared)
	}

	// Every seeded artifact must SURVIVE — the primitive touched nothing.
	for p := range seeded {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("zeroizeConfigDir removed %s from a shared directory it must not touch: %v", p, statErr)
		}
	}
	for _, d := range []string{filepath.Join(shared, ".configdb"), filepath.Join(shared, "tls")} {
		if _, statErr := os.Stat(d); statErr != nil {
			t.Errorf("zeroizeConfigDir removed shared subdir %s: %v", d, statErr)
		}
	}
}

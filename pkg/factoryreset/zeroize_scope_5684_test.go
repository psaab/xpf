package factoryreset

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestZeroizeConfigDirRefusesSharedRoot pins the #5684 defense-in-depth guard on
// the gRPC config-state wipe PRIMITIVE (wipeConfigDir) — the more destructive
// one, since it RemoveAll's <root>/.configdb and <root>/tls. In production
// runZeroize validates the root before performWipe reaches this
// primitive, but the primitive re-validates itself so it never trusts a caller
// to have handed it an xpf-owned root (mirroring the CLI's FactoryResetConfigDir
// guard). Fully hermetic: wipeConfigDir only ever touches configDir, so a
// throwaway shared dir + the FactoryResetForbiddenRoots seam keeps even the RED
// path from reaching a real system directory.
//
// RED on revert: remove the ValidateFactoryResetRoot guard at the top of
// wipeConfigDir and every seeded artifact is deleted (*.conf glob,
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

	if err := wipeConfigDir(shared, "xpf.conf"); err == nil {
		t.Fatalf("wipeConfigDir(%q) = nil; want an error refusing to wipe a shared/parent directory", shared)
	}

	// Every seeded artifact must SURVIVE — the primitive touched nothing.
	for p := range seeded {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("wipeConfigDir removed %s from a shared directory it must not touch: %v", p, statErr)
		}
	}
	for _, d := range []string{filepath.Join(shared, ".configdb"), filepath.Join(shared, "tls")} {
		if _, statErr := os.Stat(d); statErr != nil {
			t.Errorf("wipeConfigDir removed shared subdir %s: %v", d, statErr)
		}
	}
}

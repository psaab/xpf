package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFactoryResetConfigDirScopedToOwnedArtifacts5768 pins #5768 for the CLI /
// shared config-state wipe primitive (FactoryResetConfigDir): it must delete
// ONLY the artifacts xpf itself created/tracks and must NEVER delete unowned
// siblings that merely share the config directory.
//
// The pre-#5768 code matched a broad `*.conf` suffix and `rollback*` prefix, so
// a custom -config whose directory PASSED ValidateFactoryResetRoot (an unlisted
// shared dir, or a subdir of a listed root) turned the factory reset into a
// broad deletion of a neighbor's foo.conf or an unrelated rollback-notes file.
//
// The config root is a throwaway TempDir subdir (absolute, not an exact
// FactoryResetForbiddenRoots entry, so it PASSES validation), seeded with both
// xpf-owned artifacts and unowned siblings. After the wipe every owned artifact
// is gone (including the day-0 stamp, so the loader's
// ConditionPathExists=!stamp gate permits a fresh medium) and every unowned
// sibling survives. Note FactoryResetConfigDir does NOT remove <root>/tls (that
// is the gRPC primitive's leg), so no tls artifact is seeded here.
//
// RED on revert: restore the `strings.HasSuffix(name, ".conf")` /
// `strings.HasPrefix(name, "rollback")` globs and the unowned other.conf /
// frr.conf / rollback / rollback.bak siblings are deleted — the "survives"
// assertions fail. Omitting the #10740 stamp match likewise fails the owned-
// artifact absence assertion.
func TestFactoryResetConfigDirScopedToOwnedArtifacts5768(t *testing.T) {
	dir := t.TempDir()
	configBase := "xpf.conf"
	secret := []byte("OWNED-SECRET-5768")
	foreign := []byte("NOT-XPFS-5768")

	if err := os.MkdirAll(filepath.Join(dir, ".configdb"), 0o700); err != nil {
		t.Fatalf("mkdir .configdb: %v", err)
	}
	// xpf-owned config-state artifacts (must be erased — no secret retention).
	owned := []string{
		filepath.Join(dir, configBase),                 // the live config file
		filepath.Join(dir, RescueConfigBase),           // rescue.conf
		filepath.Join(dir, Day0ConfigAppliedBase),      // day-0 loader stamp (#10740)
		filepath.Join(dir, configBase+".1"),            // <base>.<N> text rollback slot
		filepath.Join(dir, ".config.journal"),          // audit journal
		filepath.Join(dir, ".config.journal.1"),        // rotated journal segment
		filepath.Join(dir, ".xpf.conf.tmp-abc123"),     // fsatomic crash temp
		filepath.Join(dir, ".configdb", "master.key"),  // AES-GCM key
		filepath.Join(dir, ".configdb", "active.json"), // SSOT
	}
	for _, p := range owned {
		if err := os.WriteFile(p, secret, 0o600); err != nil {
			t.Fatalf("seed owned %s: %v", p, err)
		}
	}

	// Unowned siblings sharing the directory (must SURVIVE) — exactly what the
	// pre-#5768 broad globs would have deleted.
	neighborDir := filepath.Join(dir, "neighbor")
	if err := os.MkdirAll(neighborDir, 0o700); err != nil {
		t.Fatalf("mkdir neighbor: %v", err)
	}
	unowned := []string{
		filepath.Join(dir, "other.conf"),   // foreign .conf (was: *.conf suffix glob)
		filepath.Join(dir, "frr.conf"),     // a neighbor's frr.conf (was: *.conf glob)
		filepath.Join(dir, "rollback"),     // was: rollback* prefix glob
		filepath.Join(dir, "rollback.bak"), // was: rollback* prefix glob
		filepath.Join(dir, "notes.txt"),    // unrelated bystander
		filepath.Join(neighborDir, "data"), // file inside an unrelated subdir
	}
	for _, p := range unowned {
		if err := os.WriteFile(p, foreign, 0o600); err != nil {
			t.Fatalf("seed unowned %s: %v", p, err)
		}
	}

	if err := FactoryResetConfigDir(dir, configBase); err != nil {
		t.Fatalf("FactoryResetConfigDir(%q): %v", dir, err)
	}

	// Every owned artifact must be gone — the wipe still erases xpf's secrets.
	for _, p := range owned {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("owned artifact survived the wipe (secret-retention regression): %s (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ".configdb")); !os.IsNotExist(err) {
		t.Errorf("owned subdir .configdb survived the wipe (err=%v)", err)
	}

	// Every unowned sibling must SURVIVE — the #5768 ownership scoping.
	for _, p := range unowned {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("#5768: factory reset deleted an UNOWNED sibling it must not touch: %s (%v)", p, err)
		}
	}
	if _, err := os.Stat(neighborDir); err != nil {
		t.Errorf("#5768: factory reset deleted an unrelated subdir: %s (%v)", neighborDir, err)
	}
}

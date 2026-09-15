package configstore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateFactoryResetRoot pins the #5684 shared/parent-directory guard: a
// factory-reset config-state wipe must REFUSE a config root that resolves to a
// shared/system directory or is non-absolute, and ACCEPT the default appliance
// root plus any dedicated subdirectory. configDir is filepath.Dir(ConfigPath()),
// so a custom -config placed directly in a shared directory (or a directory-
// shaped -config, where filepath.Dir climbs to the parent) would otherwise turn
// the reset into a broad deletion of unowned siblings.
//
// RED on revert: neutering ValidateFactoryResetRoot (return nil) makes every
// wantErr row fail — /etc, /, /srv, /home, an empty and a relative path would
// all be accepted as erasable config roots.
func TestValidateFactoryResetRoot(t *testing.T) {
	cases := []struct {
		dir     string
		wantErr bool
	}{
		// Shared/system roots and the filesystem root: REFUSED.
		{"/", true},
		{"/etc", true},
		{"/srv", true},
		{"/home", true},
		{"/root", true},
		{"/var", true},
		{"/var/lib", true},
		{"/usr", true},
		{"/usr/local", true},
		{"/tmp", true},
		{"/etc/", true},       // trailing slash cleans to /etc
		{"/etc/xpf/..", true}, // .. traversal cleans to /etc
		// Non-absolute (empty/relative) -config: filepath.Dir → "." / relative.
		{"", true},
		{".", true},
		{"relative/dir", true},
		{"xpf.conf", true},
		// The default appliance root and dedicated subdirectories: ACCEPTED.
		{"/etc/xpf", false},
		{"/etc/xpf/", false},
		{"/srv/xpf", false},
		{"/opt/xpf/data", false},
		{"/var/lib/xpf", false},
	}
	for _, tc := range cases {
		err := ValidateFactoryResetRoot(tc.dir)
		if tc.wantErr && err == nil {
			t.Errorf("ValidateFactoryResetRoot(%q) = nil, want an error (shared/parent/non-absolute root must be refused)", tc.dir)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("ValidateFactoryResetRoot(%q) = %v, want nil (a dedicated xpf config root must be accepted)", tc.dir, err)
		}
	}
}

// forbidFactoryResetRoot registers dir as a #5684 forbidden root for the test's
// lifetime so a THROWAWAY directory can stand in for a shared/system root like
// /etc or /srv, keeping the test hermetic (mirrors the DefaultArchiveDir seam).
// Production code never mutates FactoryResetForbiddenRoots. The RESOLVED form
// is registered (#9897 review): the wipe compares resolved candidates, so an
// unresolved registration would miss under a symlinked TMPDIR.
func forbidFactoryResetRoot(t *testing.T, dir string) {
	t.Helper()
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}
	old := FactoryResetForbiddenRoots
	FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(dir))
	t.Cleanup(func() { FactoryResetForbiddenRoots = old })
}

// TestFactoryResetConfigDirRefusesSharedParent is the #5684 fail-on-revert: when
// the resolved config root is a shared/parent directory, FactoryResetConfigDir
// must erase NOTHING and return an error — a custom/adversarial -config path can
// never turn a factory reset into a broad deletion of the enclosing directory.
//
// The scenario reproduces the defect: an operator points -config at a file in a
// shared directory (or at a directory-shaped path, where filepath.Dir climbs to
// the parent), so configDir resolves to a directory xpf does not own that holds
// unrelated files — a sibling *.conf, a foreign .configdb, a foreign tls/,
// a rollback-shaped file, a foreign journal. A pre-fix wipe globbed *.conf and
// RemoveAll'd .configdb + tls INSIDE that shared directory.
//
// RED on revert: remove the ValidateFactoryResetRoot guard at the top of
// FactoryResetConfigDir and every seeded artifact below is deleted — the
// "survives" assertions fail, and the "returns an error" check fails.
func TestFactoryResetConfigDirRefusesSharedParent(t *testing.T) {
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

	// Treat the throwaway dir as a shared/system root (stands in for /etc, /srv).
	forbidFactoryResetRoot(t, shared)

	err := FactoryResetConfigDir(shared, "xpf.conf")
	if err == nil {
		t.Fatalf("FactoryResetConfigDir(%q) = nil; want an error refusing to wipe a shared/parent directory", shared)
	}

	// Every seeded artifact must SURVIVE — the reset touched nothing.
	for p := range seeded {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("factory reset removed %s from a shared directory it must not touch: %v", p, statErr)
		}
	}
	// The subdirectories themselves must survive too.
	for _, d := range []string{filepath.Join(shared, ".configdb"), filepath.Join(shared, "tls")} {
		if _, statErr := os.Stat(d); statErr != nil {
			t.Errorf("factory reset removed shared subdir %s: %v", d, statErr)
		}
	}
}

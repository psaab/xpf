package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// forbidRoot9897 registers dir as a shared/system root for one test (the
// configstore.FactoryResetForbiddenRoots seam), restoring it afterwards. The
// RESOLVED form is registered: the wipe compares resolved candidates, so an
// unresolved registration would miss under a symlinked TMPDIR (macOS /var ->
// /private/var). Best-effort — falls back to Clean when the path does not
// exist yet (callers create-then-register, and the canonical-identity check
// covers the rest).
func forbidRoot9897(t *testing.T, dir string) {
	t.Helper()
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}
	old := configstore.FactoryResetForbiddenRoots
	configstore.FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(dir))
	t.Cleanup(func() { configstore.FactoryResetForbiddenRoots = old })
}

// #9897 F-040, production copy: zeroizeConfigDir is the wipe production runs
// (FactoryResetConfigDir has no non-test caller), and it carries the identical
// lexical-Validate + ReadDir-through-link mechanism — a symlinked root into a
// forbidden directory passes the guard and xpf-named files under the unowned
// tree are deleted with success reported.
func TestZeroizeConfigDirRefusesSymlinkToForbidden9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	victim := filepath.Join(real, "xpf.conf")
	mustWrite(t, victim, []byte("live config text\n"))
	// Create-then-register, and assert the RESOLVED target: the wipe names
	// resolved paths, which differ from these under a symlinked TMPDIR.
	forbidRoot9897(t, real)
	wantTarget, werr := filepath.EvalSymlinks(real)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", real, werr)
	}

	link := filepath.Join(root, "link")
	mustSymlink(t, real, link)

	err := zeroizeConfigDir(link, "xpf.conf")
	if err == nil {
		t.Fatalf("zeroizeConfigDir wiped through a SYMLINKED root into a FORBIDDEN " +
			"directory and reported success -- the #9897 F-040 defect (production copy)")
	}
	if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), wantTarget) {
		t.Fatalf("error must name the link AND the resolved target, got: %v", err)
	}
	if _, serr := os.Stat(victim); serr != nil {
		t.Fatalf("file under the forbidden target was deleted: %v", serr)
	}
}

func TestZeroizeConfigDirRefusesIntermediateLink9897(t *testing.T) {
	root := t.TempDir()
	resolved := filepath.Join(root, "real", "sub")
	victim := filepath.Join(resolved, "xpf.conf")
	mustWrite(t, victim, []byte("live config text\n"))
	// Create-then-register, and assert the RESOLVED target (see above).
	forbidRoot9897(t, resolved)
	wantTarget, werr := filepath.EvalSymlinks(resolved)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", resolved, werr)
	}

	mustSymlink(t, filepath.Join(root, "real"), filepath.Join(root, "l"))
	configDir := filepath.Join(root, "l", "sub")

	err := zeroizeConfigDir(configDir, "xpf.conf")
	if err == nil {
		t.Fatalf("zeroizeConfigDir wiped through an INTERMEDIATE link into a " +
			"forbidden directory and reported success")
	}
	if !strings.Contains(err.Error(), configDir) || !strings.Contains(err.Error(), wantTarget) {
		t.Fatalf("error must name the link AND the resolved target, got: %v", err)
	}
	if _, serr := os.Stat(victim); serr != nil {
		t.Fatalf("file under the forbidden target was deleted: %v", serr)
	}
}

// Mirror parity: the two factory-reset copies must reach the SAME verdict on
// the SAME fixture shape. #9013's lesson is that a guard landing on one copy
// silently misses the reachable one; this cell fails if the pair ever drifts
// again. Each copy gets an independent tree (a wipe is destructive), seeded
// identically within the COMMON artifact scope.
func TestZeroizeMirrorParitySymlinkedRoot9897(t *testing.T) {
	seed := func(t *testing.T, dir string) []string {
		t.Helper()
		seeds := []string{
			filepath.Join(dir, "xpf.conf"),
			filepath.Join(dir, configstore.RescueConfigBase),
			filepath.Join(dir, ".config.journal"),
			filepath.Join(dir, ".configdb", "active.json"),
		}
		for _, s := range seeds {
			mustWrite(t, s, []byte("secret\n"))
		}
		return seeds
	}
	survived := func(seeds []string) int {
		n := 0
		for _, s := range seeds {
			if _, err := os.Lstat(s); err == nil {
				n++
			}
		}
		return n
	}

	cases := []struct {
		name string
		// forbidden registers the RESOLVED target as a shared root.
		forbidden bool
		// intermediate puts the link in a parent component (root/l/sub with
		// l -> root/real) instead of the final one (root/link -> root/real).
		intermediate bool
		// forbidAlias registers an ALIAS of the target (root/falias ->
		// resolved) instead of the target itself: the canonical-identity
		// completion must still refuse, since an alias of a forbidden
		// directory is the same directory (GPT-2; same shape as a symlinked
		// TMPDIR providing the alias on macOS).
		forbidAlias bool
		wantErr     bool
	}{
		{name: "link-to-forbidden", forbidden: true, wantErr: true},
		{name: "link-to-dedicated", forbidden: false, wantErr: false},
		{name: "intermediate-to-forbidden", forbidden: true, intermediate: true, wantErr: true},
		{name: "intermediate-to-dedicated", forbidden: false, intermediate: true, wantErr: false},
		{name: "alias-of-forbidden", forbidAlias: true, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotErr [2]bool
			var gotSurvived [2]int
			for i, wipe := range []struct {
				name string
				fn   func(configDir, configBase string) error
			}{
				{"configstore.FactoryResetConfigDir", configstore.FactoryResetConfigDir},
				{"grpcapi.zeroizeConfigDir", zeroizeConfigDir},
			} {
				root := t.TempDir()
				var resolved, pass string
				if tc.intermediate {
					resolved = filepath.Join(root, "real", "sub")
					mustSymlink(t, filepath.Join(root, "real"), filepath.Join(root, "l"))
					pass = filepath.Join(root, "l", "sub")
				} else {
					resolved = filepath.Join(root, "real")
					pass = filepath.Join(root, "link")
					mustSymlink(t, resolved, pass)
				}
				// Seed first (create-then-register): the denylist holds the
				// RESOLVED form, which requires the tree to exist.
				seeds := seed(t, resolved)
				if tc.forbidden {
					forbidRoot9897(t, resolved)
				}
				if tc.forbidAlias {
					alias := filepath.Join(root, "falias")
					mustSymlink(t, resolved, alias)
					// Register the RAW alias spelling, not the resolved
					// form: production denylist entries are fixed spellings
					// (e.g. "/tmp"), never pre-resolved, so only the raw
					// registration exercises the canonical-identity path.
					old := configstore.FactoryResetForbiddenRoots
					configstore.FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(alias))
					t.Cleanup(func() { configstore.FactoryResetForbiddenRoots = old })
				}

				err := wipe.fn(pass, "xpf.conf")
				gotErr[i] = err != nil
				gotSurvived[i] = survived(seeds)
				if gotErr[i] != tc.wantErr {
					t.Errorf("%s: err-present = %v, want %v (err=%v)",
						wipe.name, gotErr[i], tc.wantErr, err)
				}
				// Absolute outcome per copy, not just mirror agreement: a
				// refusal must leave EVERYTHING (fail closed, erase nothing)
				// and a success must leave NOTHING in the common scope.
				wantSurvived := 0
				if tc.wantErr {
					wantSurvived = len(seeds)
				}
				if gotSurvived[i] != wantSurvived {
					t.Errorf("%s: survived = %d, want %d (refusal must erase "+
						"nothing; success must erase the whole common scope)",
						wipe.name, gotSurvived[i], wantSurvived)
				}
			}
			if gotErr[0] != gotErr[1] || gotSurvived[0] != gotSurvived[1] {
				t.Fatalf("mirror DIVERGED: configstore(err=%v,survived=%d) vs "+
					"grpcapi(err=%v,survived=%d)",
					gotErr[0], gotSurvived[0], gotErr[1], gotSurvived[1])
			}
		})
	}
}

// The early gate must see the resolved root too: zeroizeConfigRoot validates
// BEFORE runZeroize enters the terminal reset generation, so a symlinked root
// into a forbidden directory must be refused HERE, not only inside the wipe
// primitive.
func TestZeroizeConfigRootResolvesSymlink9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	forbidRoot9897(t, real)
	// The gate names resolved paths; resolve the want side for a symlinked
	// TMPDIR (identity on Linux).
	wantTarget, werr := filepath.EvalSymlinks(real)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", real, werr)
	}
	link := filepath.Join(root, "link")
	mustSymlink(t, real, link)

	store := newConfigStore(t, filepath.Join(link, "xpf.conf"))
	s := &Server{store: store}
	_, _, err := s.zeroizeConfigRoot()
	if err == nil {
		t.Fatal("zeroizeConfigRoot accepted a symlinked root into a FORBIDDEN " +
			"directory; the early gate is bypassed")
	}
	if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), wantTarget) {
		t.Fatalf("error must name the link AND the resolved target, got: %v", err)
	}
}

// CONTROL: a link to a DEDICATED root still resolves, and the resolver returns
// the ORIGINAL path (the wipe primitive re-resolves idempotently) so ordinary
// callers observe byte-identical roots.
func TestZeroizeConfigRootDedicatedLinkUnaffected9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	mustSymlink(t, real, link)

	store := newConfigStore(t, filepath.Join(link, "xpf.conf"))
	s := &Server{store: store}
	gotDir, gotBase, err := s.zeroizeConfigRoot()
	if err != nil {
		t.Fatalf("zeroizeConfigRoot on a link to a DEDICATED root: %v", err)
	}
	if gotDir != link {
		t.Fatalf("resolver returned %q, want the ORIGINAL path %q", gotDir, link)
	}
	if gotBase != "xpf.conf" {
		t.Fatalf("resolver returned base %q, want xpf.conf", gotBase)
	}
}

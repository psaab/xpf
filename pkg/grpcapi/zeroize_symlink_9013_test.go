package grpcapi

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #9013: os.Remove and os.RemoveAll act on the LINK when a path's FINAL
// component is a symlink — they unlink it and return nil, leaving the real
// bytes on the target volume while the operator is told "System zeroized.
// Configuration erased."
//
// These cells drive PerformZeroizeWipe, the primitive BOTH the gRPC zeroize and
// the console (via the zeroizeFullWipe seam) actually run. The sibling
// configstore.FactoryResetConfigDir has no non-test caller, so a guard written
// only against it would be inert against production — that duplication is why
// the predicate is shared rather than re-spelled.
const symlinkPSK9013 = "PSK-SUPERSECRET-DO-NOT-SURVIVE"

func TestZeroizeRefusesSymlinkedTargets9013(t *testing.T) {
	secret := []byte("pre-shared-key ascii-text \"" + symlinkPSK9013 + "\";")

	cases := []struct {
		name string
		// setup builds the tree; returns the basenames that MUST still exist on
		// the target afterwards (we refuse, so they survive BY DESIGN — the
		// contract is that the operator is TOLD, not that we delete them).
		setup    func(t *testing.T, configDir, real string)
		wantSkip bool
	}{
		{name: "configdb-dir-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			mustSymlink(t, real, filepath.Join(cd, ".configdb"))
			mustWrite(t, filepath.Join(real, "master.key"), []byte("keymaterial"))
			mustWrite(t, filepath.Join(real, "active.json"), secret)
		}},
		{name: "master-key-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			db := filepath.Join(cd, ".configdb")
			if err := os.MkdirAll(db, 0o700); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(real, "master.key"), []byte("keymaterial"))
			mustSymlink(t, filepath.Join(real, "master.key"), filepath.Join(db, "master.key"))
		}},
		{name: "tls-dir-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			mustSymlink(t, real, filepath.Join(cd, "tls"))
			mustWrite(t, filepath.Join(real, "key.pem"), []byte("PRIVATE KEY"))
		}},
		{name: "live-config-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			mustWrite(t, filepath.Join(real, "xpf.conf"), secret)
			mustSymlink(t, filepath.Join(real, "xpf.conf"), filepath.Join(cd, "xpf.conf"))
		}},
		{name: "rescue-config-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			mustWrite(t, filepath.Join(real, configstore.RescueConfigBase), secret)
			mustSymlink(t, filepath.Join(real, configstore.RescueConfigBase),
				filepath.Join(cd, configstore.RescueConfigBase))
		}},
		{name: "journal-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			mustWrite(t, filepath.Join(real, ".config.journal"), secret)
			mustSymlink(t, filepath.Join(real, ".config.journal"), filepath.Join(cd, ".config.journal"))
		}},
		{name: "rollback-slot-symlink", wantSkip: true, setup: func(t *testing.T, cd, real string) {
			mustWrite(t, filepath.Join(real, "xpf.conf.1"), secret)
			mustSymlink(t, filepath.Join(real, "xpf.conf.1"), filepath.Join(cd, "xpf.conf.1"))
		}},
		// CONTROL: no symlink anywhere. A guard that refused everything would
		// pass every row above while breaking the ordinary zeroize, so this row
		// is what makes the others mean something.
		{name: "CONTROL-no-symlink", wantSkip: false, setup: func(t *testing.T, cd, real string) {
			db := filepath.Join(cd, ".configdb")
			if err := os.MkdirAll(db, 0o700); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(db, "master.key"), []byte("keymaterial"))
			mustWrite(t, filepath.Join(db, "active.json"), secret)
			mustWrite(t, filepath.Join(cd, "xpf.conf"), secret)
			mustWrite(t, filepath.Join(cd, "tls", "key.pem"), []byte("PRIVATE KEY"))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			configDir := filepath.Join(root, "etc", "xpf")
			real := filepath.Join(root, "elsewhere")
			for _, d := range []string{configDir, real} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			tc.setup(t, configDir, real)

			err := PerformZeroizeWipe(configDir, "xpf.conf", "")

			var symErr *configstore.FactoryResetSymlinkError
			gotSkip := errors.As(err, &symErr)

			if !tc.wantSkip {
				if err != nil {
					t.Fatalf("ordinary zeroize (no symlink) must succeed, got: %v", err)
				}
				// And it must actually have erased: a guard that refuses
				// everything would otherwise pass every row above.
				if leftovers := walkForSecrets(t, configDir, secret); len(leftovers) > 0 {
					t.Fatalf("ordinary zeroize left %v behind", leftovers)
				}
				return
			}

			if !gotSkip {
				t.Fatalf("zeroize reported %v for a SYMLINKED erase target; the real bytes "+
					"survive on the target volume and the operator is told the box is "+
					"clean -- this is the #9013 defect", err)
			}
			if len(symErr.Skipped) == 0 {
				t.Fatal("FactoryResetSymlinkError carries no paths; the operator cannot " +
					"find the surviving secrets")
			}
			// The message must name the real location, not just the link: the
			// link is what gets reported, the TARGET is where the secrets are.
			for _, sk := range symErr.Skipped {
				if sk.Target == "" {
					t.Fatalf("skipped entry %q has no target; the operator is told a path "+
						"was skipped but not where the data actually is", sk.Path)
				}
				if !bytes.Contains([]byte(symErr.Error()), []byte(sk.Target)) {
					t.Fatalf("error text omits the target %q: %v", sk.Target, symErr)
				}
			}
		})
	}
}

func walkForSecrets(t *testing.T, dir string, secret []byte) []string {
	t.Helper()
	var found []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, e error) error {
		if e != nil || fi.IsDir() {
			return nil
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, secret) || filepath.Base(p) == "master.key" {
			found = append(found, filepath.Base(p))
		}
		return nil
	})
	return found
}

func mustWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

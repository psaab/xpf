package grpcapi

import (
	"github.com/psaab/xpf/pkg/configstore"
	"os"
	"path/filepath"
	"testing"
)

// Shared zeroize RPC-boundary test helpers (#16138: the wipe primitive
// moved to pkg/factoryreset; these helpers stay with the grpcapi cells
// that drive SystemAction/runZeroize).

func mustWriteFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s to be absent after zeroize, stat err = %v", path, err)
	}
}

// forbidRoot9897 registers dir as a shared/system root for one test (the
// configstore.FactoryResetForbiddenRoots seam), restoring it afterwards.
// The RESOLVED form is registered: the wipe compares resolved candidates,
// so an unresolved registration would miss under a symlinked TMPDIR.
// (#16138: the primitive-side copy moved to pkg/factoryreset with the
// wipe; this copy stays for the grpcapi zeroizeConfigRoot gate cells.)
func forbidRoot9897(t *testing.T, dir string) {
	t.Helper()
	if resolved, rerr := filepath.EvalSymlinks(dir); rerr == nil {
		dir = resolved
	}
	old := configstore.FactoryResetForbiddenRoots
	configstore.FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(dir))
	t.Cleanup(func() { configstore.FactoryResetForbiddenRoots = old })
}

func mustWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(link), err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

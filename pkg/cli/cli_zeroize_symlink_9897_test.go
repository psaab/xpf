package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #9897 F-040, console twin: cli.zeroizeConfigRoot is the local-CLI twin of
// grpcapi's resolver (#5554/#5684) and carries the same lexical-only check, so
// a symlinked root into a forbidden directory must be refused here as well.
func TestCLIZeroizeConfigRootResolvesSymlink9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	// Register and assert the RESOLVED form: the gate compares and names
	// resolved paths, which differ under a symlinked TMPDIR (identity on
	// Linux).
	wantTarget, werr := filepath.EvalSymlinks(real)
	if werr != nil {
		t.Fatalf("EvalSymlinks(%q): %v", real, werr)
	}
	old := configstore.FactoryResetForbiddenRoots
	configstore.FactoryResetForbiddenRoots = append(append([]string(nil), old...), filepath.Clean(wantTarget))
	t.Cleanup(func() { configstore.FactoryResetForbiddenRoots = old })

	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	c := &CLI{store: newConfigStore(t, filepath.Join(link, "xpf.conf"))}
	_, _, err := c.zeroizeConfigRoot()
	if err == nil {
		t.Fatal("cli.zeroizeConfigRoot accepted a symlinked root into a FORBIDDEN " +
			"directory; the console early gate is bypassed")
	}
	if !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), wantTarget) {
		t.Fatalf("error must name the link AND the resolved target, got: %v", err)
	}
}

// CONTROL: a link to a DEDICATED root still resolves, returning the ORIGINAL
// path (the shared wipe primitive re-resolves idempotently).
func TestCLIZeroizeConfigRootDedicatedLinkUnaffected9897(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	c := &CLI{store: newConfigStore(t, filepath.Join(link, "xpf.conf"))}
	gotDir, gotBase, err := c.zeroizeConfigRoot()
	if err != nil {
		t.Fatalf("cli.zeroizeConfigRoot on a link to a DEDICATED root: %v", err)
	}
	if gotDir != link {
		t.Fatalf("resolver returned %q, want the ORIGINAL path %q", gotDir, link)
	}
	if gotBase != "xpf.conf" {
		t.Fatalf("resolver returned base %q, want xpf.conf", gotBase)
	}
}

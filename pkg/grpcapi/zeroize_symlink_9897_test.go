package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbidRoot9897 registers dir as a shared/system root for one test (the
// configstore.FactoryResetForbiddenRoots seam), restoring it afterwards. The
// RESOLVED form is registered: the wipe compares resolved candidates, so an
// unresolved registration would miss under a symlinked TMPDIR (macOS /var ->
// /private/var). Best-effort — falls back to Clean when the path does not
// exist yet (callers create-then-register, and the canonical-identity check
// covers the rest).

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

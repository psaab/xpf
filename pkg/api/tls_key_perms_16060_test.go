package api

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Decisive regression for #16060 K3: a pre-existing loose GENERATED key
// must not be loaded and served as-is. Mint guarantees 0600/0700; the
// load path previously asserted nothing. These tests drive the real
// production loader (generateSelfSignedCertAt) against a seeded temp dir.
// RED on revert: drop the assertGeneratedTLSKeyPerms call in
// generateSelfSignedCertAtWithStatusMulti and the loose-key/dir cells
// fail (mode stays loose); drop the chmod-failure return and the
// failure cell serves silently.

func permOf16060(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// mintLoose16060 mints a real durable pair, then loosens it as the issue
// describes (restored backup / operator chmod) and returns its paths.
func mintLoose16060(t *testing.T, dirPerm, keyPerm os.FileMode) (dir, certPath, keyPath string) {
	t.Helper()
	resetTLSSeams(t)
	dir, certPath, keyPath = tlsPaths(t)
	if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, ""); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := os.Chmod(keyPath, keyPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		t.Fatal(err)
	}
	return dir, certPath, keyPath
}

func TestGeneratedTLSLooseKeyTightenedOnLoad16060(t *testing.T) {
	dir, certPath, keyPath := mintLoose16060(t, 0o700, 0o644)
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("load of loose generated pair must tighten and serve, got: %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("returned cert is not usable")
	}
	if got := permOf16060(t, keyPath); got != 0o600 {
		t.Fatalf("key mode after load = %04o, want 0600 (loose generated key must be tightened on use)", got)
	}
	// Pair must not churn: same cert bytes served, not a re-mint.
	after, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("cert churned on perm repair — tighten must not re-mint the durable pair")
	}
}

func TestGeneratedTLSLooseDirTightenedOnLoad16060(t *testing.T) {
	dir, certPath, keyPath := mintLoose16060(t, 0o755, 0o600)
	if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, ""); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := permOf16060(t, dir); got != 0o700 {
		t.Fatalf("dir mode after load = %04o, want 0700", got)
	}
	if got := permOf16060(t, keyPath); got != 0o600 {
		t.Fatalf("key mode after load = %04o, want 0600 (already-tight key must stay)", got)
	}
}

func TestGeneratedTLSStrictPermsUntouchedOnLoad16060(t *testing.T) {
	// Tighten-only: a deliberately stricter key must never be loosened.
	dir, certPath, keyPath := mintLoose16060(t, 0o700, 0o400)
	if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, ""); err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := permOf16060(t, keyPath); got != 0o400 {
		t.Fatalf("key mode after load = %04o, want 0400 (repair must only tighten)", got)
	}
}

// Fold witness (#16103): an execute-only generated directory (0111) is
// stricter than 0700 for key confidentiality — it grants no group/other
// read/write — yet it cannot be opened O_RDONLY (EACCES) or O_RDWR
// (EISDIR) on Linux. The pair must load fine and the mode stay 0111.
// RED on the pre-fold code: the O_RDWR fallback returns EISDIR and the
// load fails closed. Cleanup restores traversal so TempDir removal works.
func TestGeneratedTLSExecuteOnlyDirLoads16060(t *testing.T) {
	dir, certPath, keyPath := mintLoose16060(t, 0o111, 0o600)
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	before, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("execute-only dir must load the valid pair, got: %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("returned cert is not usable")
	}
	if got := permOf16060(t, dir); got != 0o111 {
		t.Fatalf("dir mode after load = %04o, want 0111 (strict dir must be left untouched)", got)
	}
	if got := permOf16060(t, keyPath); got != 0o600 {
		t.Fatalf("key mode after load = %04o, want 0600", got)
	}
	after, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("cert churned under execute-only dir — pair must load as-is")
	}
}

func TestGeneratedTLSChmodFailureRefusesOnLoad16060(t *testing.T) {
	dir, certPath, keyPath := mintLoose16060(t, 0o700, 0o644)
	injected := errors.New("injected chmod failure 16060")
	tlsChmod = func(f *os.File, mode os.FileMode) error { return injected }
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err == nil {
		t.Fatal("load with unrepairable loose key must loudly refuse, got nil error (silent serve)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("load error = %v, want wrapped injected chmod failure", err)
	}
	if usableCert(cert) {
		t.Fatal("refused load must not return a usable cert")
	}
	if got := permOf16060(t, keyPath); got != 0o644 {
		t.Fatalf("key mode after refused load = %04o, want still 0644", got)
	}
}

func TestGeneratedTLSSymlinkedKeyRefusedOnLoad16060(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)
	if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, ""); err != nil {
		t.Fatalf("mint: %v", err)
	}
	target := filepath.Join(dir, "elsewhere.key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, keyPath); err != nil {
		t.Fatal(err)
	}
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked generated key must be refused, got cert usable=%v err=%v", usableCert(cert), err)
	}
	// The link target must never be chmodded through the link.
	if got := permOf16060(t, target); got != 0o644 {
		t.Fatalf("symlink target mode = %04o, want 0644 (chmod must not follow the link)", got)
	}
}

func TestGeneratedTLSAbsentPairStillMints16060(t *testing.T) {
	// Control: absence is not a refusal — first boot mints as before.
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("first-boot mint: %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("minted cert is not usable")
	}
	if got := permOf16060(t, keyPath); got != 0o600 {
		t.Fatalf("minted key mode = %04o, want 0600", got)
	}
}

// Custom (operator-supplied) keys must NOT be chmodded: the load path for
// files.custom() never asserts generated perms. A loose custom key loads
// exactly as the operator left it.
func TestCustomTLSKeyNeverChmoddedOnLoad16060(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	certPath, keyPath, _ := writeManagementTLSFixture(t, dir, "custom16060", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{
		HTTPSAddr:      "127.0.0.1:0",
		TLS:            true,
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
	})
	state, err := s.loadManagementTLSCertificate("127.0.0.1:8443")
	if err != nil {
		t.Fatalf("custom load: %v", err)
	}
	if state == nil || state.invalid {
		t.Fatalf("custom load state = %+v, want valid", state)
	}
	if got := permOf16060(t, keyPath); got != 0o644 {
		t.Fatalf("custom key mode after load = %04o, want 0644 (operator keys must not be chmodded)", got)
	}
}

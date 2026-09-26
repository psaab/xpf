package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// resetTLSSeams restores the TLS persistence seams after a test mutates one.
func resetTLSSeams(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		tlsMkdirAllDurable = fsatomic.MkdirAllDurable
		tlsRemove = os.Remove
		tlsSyncDir = fsatomic.SyncDir
		tlsWriteFileDurable = fsatomic.WriteFileDurable
		tlsHostname = os.Hostname
	})
}

func tlsPaths(t *testing.T) (dir, certPath, keyPath string) {
	t.Helper()
	dir = t.TempDir()
	return dir, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
}

// genPair returns an independent self-signed cert+key PEM pair (used to seed
// a deliberately MISMATCHED on-disk state).
func genPair(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "seed", Organization: []string{"xpf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	return certPEM, keyPEM
}

// usableCert reports whether c carries a parsed leaf/private key (a usable,
// non-zero tls.Certificate).
func usableCert(c tls.Certificate) bool {
	return len(c.Certificate) > 0 && c.PrivateKey != nil
}

func TestGenerateSelfSignedCertHappyPath(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("returned cert is not usable")
	}
	// Both files persisted with the expected modes.
	if fi, serr := os.Stat(keyPath); serr != nil {
		t.Fatalf("key not written: %v", serr)
	} else if fi.Mode().Perm() != 0600 {
		t.Fatalf("key mode = %v, want 0600", fi.Mode().Perm())
	}
	if fi, serr := os.Stat(certPath); serr != nil {
		t.Fatalf("cert not written: %v", serr)
	} else if fi.Mode().Perm() != 0644 {
		t.Fatalf("cert mode = %v, want 0644", fi.Mode().Perm())
	}
	// On-disk pair loads and matches.
	onDisk, lerr := tls.LoadX509KeyPair(certPath, keyPath)
	if lerr != nil {
		t.Fatalf("on-disk pair does not load: %v", lerr)
	}
	if string(onDisk.Certificate[0]) != string(cert.Certificate[0]) {
		t.Fatal("on-disk cert differs from returned cert")
	}
	// A second call loads the persisted pair (stable cert — no churn).
	cert2, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(cert2.Certificate[0]) != string(cert.Certificate[0]) {
		t.Fatal("cert churned on reload — DurableState pair must be stable")
	}
}

func TestGenerateSelfSignedCertFailedCertWrite(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	injected := errors.New("injected cert write failure")
	tlsWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if path == certPath {
			return injected
		}
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}

	// Persistence failure → usable cert returned with NIL error (HTTPS
	// still installs); only the disk write failed.
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("persistence failure must return nil error, got %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("cert unusable on persistence failure")
	}
}

func TestGenerateSelfSignedCertFailedKeyWrite(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	injected := errors.New("injected key write failure")
	tlsWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if path == keyPath {
			return injected
		}
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("persistence failure must return nil error, got %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("cert unusable on key-write persistence failure")
	}
	// Key write was aborted; cert must NOT have been written after it (the
	// {neither}/{key-only} crash-visible invariant: never cert-without-key).
	if _, serr := os.Stat(certPath); serr == nil {
		t.Fatal("cert written despite key write failure — must not leave cert-only")
	}
}

func TestGenerateSelfSignedCertMismatchedStartRegens(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	// Seed a deliberately MISMATCHED pair: cert from pair A, key from pair B.
	certA, _ := genPair(t)
	_, keyB := genPair(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certA, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyB, 0600); err != nil {
		t.Fatal(err)
	}

	// LoadX509KeyPair rejects the mismatch → regen runs → strict-remove of
	// the stale pair → a fresh MATCHING pair lands on disk.
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("returned cert unusable")
	}
	if _, lerr := tls.LoadX509KeyPair(certPath, keyPath); lerr != nil {
		t.Fatalf("on-disk pair still mismatched after regen: %v", lerr)
	}
}

func TestGenerateSelfSignedCertStaleCertOnlyRegens(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	// Crash-after-key-loss state: a cert exists with no key.
	certA, _ := genPair(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certA, 0644); err != nil {
		t.Fatal(err)
	}

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("returned cert unusable")
	}
	// A matching pair now persists (the stale cert was strict-removed).
	if _, lerr := tls.LoadX509KeyPair(certPath, keyPath); lerr != nil {
		t.Fatalf("on-disk pair does not load after stale-cert regen: %v", lerr)
	}
}

func TestGenerateSelfSignedCertStrictRemoveFailureAborts(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	// Seed a stale cert so the strict-remove path runs.
	certA, _ := genPair(t)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certA, 0644); err != nil {
		t.Fatal(err)
	}

	// A non-ENOENT remove error must ABORT: no new key/cert written, so the
	// {neither} start is proven, not assumed.
	injected := errors.New("injected non-ENOENT remove failure")
	tlsRemove = func(string) error { return injected }
	var wrote bool
	tlsWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		wrote = true
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("persistence abort must still return usable in-memory cert with nil error, got %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("cert unusable after strict-remove abort")
	}
	if wrote {
		t.Fatal("a key/cert write proceeded despite a strict-remove failure")
	}
	// The seeded key path was never created (no write happened).
	if _, serr := os.Stat(keyPath); serr == nil {
		t.Fatal("key written despite strict-remove abort")
	}
}

func TestGenerateSelfSignedCertDirSyncFailureAborts(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	injected := errors.New("injected dir-sync failure")
	tlsSyncDir = func(string) error { return injected }
	var wrote bool
	tlsWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		wrote = true
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("dir-sync abort must return usable in-memory cert with nil error, got %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("cert unusable after dir-sync abort")
	}
	if wrote {
		t.Fatal("a key/cert write proceeded despite a SyncDir failure")
	}
}

func TestGenerateSelfSignedCertMkdirFailureAborts(t *testing.T) {
	resetTLSSeams(t)
	dir, certPath, keyPath := tlsPaths(t)

	injected := errors.New("injected mkdir failure")
	tlsMkdirAllDurable = func(string, os.FileMode) error { return injected }
	var wrote bool
	tlsWriteFileDurable = func(path string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		wrote = true
		return fsatomic.WriteFileDurable(path, data, perm, opts...)
	}

	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("mkdir abort must return usable in-memory cert with nil error, got %v", err)
	}
	if !usableCert(cert) {
		t.Fatal("cert unusable after mkdir abort")
	}
	if wrote {
		t.Fatal("a key/cert write proceeded despite a MkdirAllDurable failure")
	}
}

// TestHTTPSInstalledOnPersistFailure verifies that HTTPS retains a usable
// in-memory certificate even when durable storage is unavailable.
func TestHTTPSInstalledOnPersistFailure(t *testing.T) {
	resetTLSSeams(t)

	// Force every durable write to fail — a full persistence failure.
	tlsMkdirAllDurable = func(string, os.FileMode) error {
		return errors.New("injected persistence failure")
	}

	s := NewServer(Config{
		Addr:      "127.0.0.1:0",
		HTTPSAddr: "127.0.0.1:0",
		TLS:       true,
	})
	if s.httpsServer == nil {
		t.Fatal("httpsServer not installed on persistence failure — HTTPS wrongly disabled by a disk error")
	}
	cert := s.HTTPSCertForTest()
	if cert == nil || !usableCert(*cert) {
		t.Fatal("HTTPS selector has no usable in-memory certificate")
	}
}

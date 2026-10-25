package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func contextWithCancel(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithCancel(context.Background())
}

func execLookPath(name string) (string, error) { return exec.LookPath(name) }

func runOpenssl(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

// under its own key. corruptSig flips a signature byte after signing
// so the name match holds but the cryptographic self-signature does
// not verify.
func buildSelfSigned16832(t *testing.T, caLeaf, corruptSig bool) tls.Certificate {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(16832),
		Subject:               pkix.Name{CommonName: "fw"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  caLeaf,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"fw", "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	if caLeaf {
		// OpenSSL 3 req -x509 emits KeyUsage certSign+crlSign too.
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if corruptSig {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		// Re-encode is not available for a mutated signature; instead
		// tamper at the parsed level by rebuilding the chain entry the
		// preflight sees: flip a byte in a copy of the DER and re-parse.
		// The TBS is untouched so parsing still succeeds.
		mut := append([]byte(nil), der...)
		mut[len(mut)-1] ^= 0xff
		if _, err := x509.ParseCertificate(mut); err == nil {
			der = mut
		} else {
			// Fallback: present the parsed cert with a mutated
			// Signature field directly via the chain helper path.
			parsed.Signature = append([]byte(nil), parsed.Signature...)
			parsed.Signature[len(parsed.Signature)-1] ^= 0xff
			return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
		}
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func writeCertPair16832(t *testing.T, dir string, cert tls.Certificate) (string, string) {
	t.Helper()
	// Reuse the 15667 helper shape: single PEM cert + EC key.
	return writeChainPair(t, dir, cert)
}

// TestPreflightSelfSignedCALeaf16832 is the defect cell: a single-entry
// self-signed CA:TRUE leaf (stock OpenSSL 3 req -x509 shape) must pass
// preflight. Pre-fix it returned "leaf certificate is a CA certificate".
func TestPreflightSelfSignedCALeaf16832(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cert := buildSelfSigned16832(t, true, false)
	_, leaf, chain, err := managementTLSCertificateChain(cert)
	if err != nil {
		t.Fatalf("chain parse: %v", err)
	}
	if !leaf.IsCA {
		t.Fatal("fixture leaf must be CA:TRUE (OpenSSL req -x509 default)")
	}
	if !managementTLSCertificateIsSelfSignedCALeaf(chain) {
		t.Fatal("fixture must classify as self-signed CA leaf")
	}
	if err := managementTLSCertificatePreflightError(chain, now); err != nil {
		t.Fatalf("self-signed CA:TRUE leaf must pass preflight (#16832): %v", err)
	}
	// Positive control: CA:FALSE single self-signed leaf still passes
	// and is not classified as a CA leaf.
	plain := buildSelfSigned16832(t, false, false)
	_, _, plainChain, err := managementTLSCertificateChain(plain)
	if err != nil {
		t.Fatalf("chain parse: %v", err)
	}
	if managementTLSCertificateIsSelfSignedCALeaf(plainChain) {
		t.Fatal("CA:FALSE leaf must not classify as self-signed CA leaf")
	}
	if err := managementTLSCertificatePreflightError(plainChain, now); err != nil {
		t.Fatalf("CA:FALSE self-signed leaf must pass preflight: %v", err)
	}
}

// TestPreflightNonSelfSignedCALeafRejected16832 keeps the #15667
// control: a CA:TRUE leaf that is not a single-entry verified
// self-signed chain is still rejected.
func TestPreflightNonSelfSignedCALeafRejected16832(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	// (a) CA leaf issued by an intermediate (existing 15667 fixture).
	cert, _ := buildChain(t, chainSpec{leafIsCA: true})
	_, _, chain, err := managementTLSCertificateChain(cert)
	if err != nil {
		t.Fatalf("chain parse: %v", err)
	}
	if managementTLSCertificateIsSelfSignedCALeaf(chain) {
		t.Fatal("intermediate-issued CA leaf must not classify as self-signed")
	}
	if err := managementTLSCertificatePreflightError(chain, now); err == nil || !strings.Contains(err.Error(), "leaf certificate is a CA") {
		t.Fatalf("intermediate-issued CA leaf preflight = %v, want CA rejection", err)
	}
	// (b) Single-entry CA leaf whose self-signature does not verify.
	bad := buildSelfSigned16832(t, true, true)
	_, _, badChain, err := managementTLSCertificateChain(bad)
	if err != nil {
		t.Fatalf("chain parse: %v", err)
	}
	if managementTLSCertificateIsSelfSignedCALeaf(badChain) {
		t.Fatal("corrupt self-signature must not classify as self-signed")
	}
	if err := managementTLSCertificatePreflightError(badChain, now); err == nil || !strings.Contains(err.Error(), "leaf certificate is a CA") {
		t.Fatalf("corrupt self-signed CA leaf preflight = %v, want CA rejection", err)
	}
}

// TestCustomSelfSignedCALeafLoads16832 exercises the production load
// path (NewServer with custom files) plus the handshake selector and a
// real TLS handshake against the installed leg.
func TestCustomSelfSignedCALeafLoads16832(t *testing.T) {
	cert := buildSelfSigned16832(t, true, false)
	dir := t.TempDir()
	certPath, keyPath := writeCertPair16832(t, dir, cert)
	var s *Server
	out := captureTLSLog(t, func() {
		s = NewServer(Config{HTTPSAddr: "127.0.0.1:0", TLS: true, TLSCertificate: certPath, TLSPrivateKey: keyPath})
	})
	if s.httpsServer() == nil {
		t.Fatal("self-signed CA:TRUE custom cert did not install HTTPS server (#16832)")
	}
	if !strings.Contains(out, "self-signed CA") {
		t.Fatalf("load must log the CA:TRUE diagnostic, got: %q", out)
	}
	if _, err := s.managementTLSGetCertificate(nil); err != nil {
		t.Fatalf("selector must serve self-signed CA:TRUE leaf: %v", err)
	}
	// Real handshake: start and dial the leg with the leaf pinned.
	ctx, cancel := contextWithCancel(t)
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()
	addr := s.EffectiveHTTPSAddr()
	if addr == "" {
		t.Fatal("no effective HTTPS address")
	}
	leaf := chainLeaf(t, cert)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{RootCAs: pool, ServerName: "fw"})
	if err != nil {
		t.Fatalf("pinned handshake to CA:TRUE self-signed leg: %v", err)
	}
	conn.Close()
}

// TestCustomOpensslCALeafLoads16832 loads a certificate actually
// produced by `openssl req -x509` (the exact command in #16832) when
// the openssl binary is available.
func TestCustomOpensslCALeafLoads16832(t *testing.T) {
	bin, err := execLookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fw.crt")
	keyPath := filepath.Join(dir, "fw.key")
	out, err := runOpenssl(t, bin, "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-subj", "/CN=fw", "-addext", "subjectAltName=DNS:fw", "-keyout", keyPath, "-out", certPath, "-days", "2")
	if err != nil {
		t.Fatalf("openssl req -x509: %v\n%s", err, out)
	}
	// Sanity: the generated cert really is CA:TRUE.
	der, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = der
	loaded, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf := chainLeaf(t, loaded)
	if !leaf.IsCA {
		t.Skip("this openssl build does not emit CA:TRUE for req -x509; fixture premise absent")
	}
	var s *Server
	logOut := captureTLSLog(t, func() {
		s = NewServer(Config{HTTPSAddr: "127.0.0.1:0", TLS: true, TLSCertificate: certPath, TLSPrivateKey: keyPath})
	})
	if s.httpsServer() == nil {
		t.Fatal("openssl CA:TRUE self-signed cert did not install HTTPS server (#16832)")
	}
	if !strings.Contains(logOut, "self-signed CA") {
		t.Fatalf("load must log the CA:TRUE diagnostic, got: %q", logOut)
	}
	if _, err := s.managementTLSGetCertificate(nil); err != nil {
		t.Fatalf("selector must serve openssl CA:TRUE leaf: %v", err)
	}
}

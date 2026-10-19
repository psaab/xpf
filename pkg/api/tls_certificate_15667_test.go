package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func captureTLSLog(t *testing.T, fn func()) string {
	t.Helper()
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	fn()
	slog.SetDefault(restore)
	return buf.String()
}

// chainFixture builds a leaf + intermediate + root chain with
// configurable validity, CA flags, EKU and signature linkage. The
// returned tls.Certificate carries the leaf key; Certificate order is
// [leaf, intermediate, root] as a server would present it.
type chainSpec struct {
	leafNotBefore, leafNotAfter   time.Time
	interNotBefore, interNotAfter time.Time
	leafIsCA                      bool
	leafEKU                       []x509.ExtKeyUsage
	leafSANs                      []string
	interNotCA                    bool
	wrongInterKey                 bool // leaf signed by unrelated key -> bad link
}

func buildChain(t *testing.T, spec chainSpec) (tls.Certificate, []*x509.Certificate) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	def := func(t time.Time, d time.Duration) time.Time {
		if t.IsZero() {
			return now.Add(d)
		}
		return t
	}
	mkKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey := mkKey()
	interKey := mkKey()
	leafKey := mkKey()
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "root15667"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	interIsCA := true
	if spec.interNotCA {
		interIsCA = false
	}
	interTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "inter15667"},
		NotBefore: def(spec.interNotBefore, -time.Hour), NotAfter: def(spec.interNotAfter, 24*time.Hour),
		IsCA: interIsCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootTmpl, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interCert, _ := x509.ParseCertificate(interDER)
	signerKey := interKey
	if spec.wrongInterKey {
		signerKey = mkKey()
	}
	eku := spec.leafEKU
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "leaf15667"},
		NotBefore: def(spec.leafNotBefore, -time.Hour), NotAfter: def(spec.leafNotAfter, 24*time.Hour),
		IsCA: spec.leafIsCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
		DNSNames: spec.leafSANs,
	}
	if len(spec.leafSANs) == 0 {
		leafTmpl.DNSNames = []string{"localhost"}
		leafTmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1)}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interTmpl, &leafKey.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)
	// For the CA-leaf cell the served leaf IS the intermediate-shaped CA:
	// rebuild as a single self-signed CA cert when leafIsCA is set is not
	// needed; the chain leaf already carries IsCA=true.
	cert := tls.Certificate{
		Certificate: [][]byte{leafDER, interDER, rootDER},
		PrivateKey:  leafKey,
		Leaf:        leafCert,
	}
	return cert, []*x509.Certificate{leafCert, interCert, rootCert}
}

func writeChainPair(t *testing.T, dir string, cert tls.Certificate) (string, string) {
	t.Helper()
	var pemBytes []byte
	for _, der := range cert.Certificate {
		pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "chain.crt")
	keyPath := filepath.Join(dir, "chain.key")
	if err := os.WriteFile(certPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestPreflight15667(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid, _ := buildChain(t, chainSpec{})
	if _, _, chain, err := managementTLSCertificateChain(valid); err != nil {
		t.Fatalf("chain parse: %v", err)
	} else if err := managementTLSCertificatePreflightError(chain, now); err != nil {
		t.Fatalf("valid chain must pass preflight: %v", err)
	}
	if got := managementTLSSANDiagnostic(chainLeaf(t, valid)); !strings.Contains(got, "localhost") {
		t.Fatalf("valid chain SAN diagnostic = %q, want localhost", got)
	}

	cases := []struct {
		name string
		spec chainSpec
		want string
	}{
		{"expired intermediate", chainSpec{interNotAfter: now.Add(-time.Hour)}, "intermediate 1 has expired"},
		{"not-yet intermediate", chainSpec{interNotBefore: now.Add(time.Hour)}, "intermediate 1 is not valid yet"},
		{"CA leaf", chainSpec{leafIsCA: true}, "leaf certificate is a CA"},
		{"client-auth leaf", chainSpec{leafEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, "does not allow ServerAuth"},
		{"non-CA intermediate", chainSpec{interNotCA: true}, "intermediate 1 is not a CA"},
		{"bad signature link", chainSpec{wrongInterKey: true}, "signature link 0->1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, _ := buildChain(t, tc.spec)
			_, _, chain, err := managementTLSCertificateChain(cert)
			if err != nil {
				t.Fatalf("chain parse: %v", err)
			}
			err = managementTLSCertificatePreflightError(chain, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("preflight = %v, want substring %q", err, tc.want)
			}
		})
	}

	// Legacy exact strings for the leaf window (existing tests/metrics rely on them).
	expiredLeaf, _ := buildChain(t, chainSpec{leafNotAfter: now.Add(-time.Hour)})
	if err := managementTLSCertificateValidityError(chainLeaf(t, expiredLeaf), now); err == nil || !strings.HasPrefix(err.Error(), "certificate has expired:") {
		t.Fatalf("leaf expiry wording = %v", err)
	}
}

func chainLeaf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	_, leaf, _, err := managementTLSCertificateChain(cert)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// TestCustomChainRejectedAtLoad15667: an expired-intermediate custom
// chain is rejected at preflight load (no HTTPS server, selector
// refuses, invalid counter increments) — not served until handshake.
func TestCustomChainRejectedAtLoad15667(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cert, _ := buildChain(t, chainSpec{interNotAfter: now.Add(-time.Hour)})
	dir := t.TempDir()
	certPath, keyPath := writeChainPair(t, dir, cert)
	before := managementTLSCertificateInvalidEvents.Load()
	s := NewServer(Config{HTTPSAddr: "127.0.0.1:0", TLS: true, TLSCertificate: certPath, TLSPrivateKey: keyPath})
	if s.httpsServer() != nil {
		t.Fatal("expired-intermediate chain installed an HTTPS server")
	}
	if _, err := s.managementTLSGetCertificate(nil); err == nil {
		t.Fatal("expired-intermediate chain remained available to selector")
	}
	if got := managementTLSCertificateInvalidEvents.Load(); got != before+1 {
		t.Fatalf("invalid counter = %d want %d", got, before+1)
	}
	if s.tlsDesired.Load() {
		t.Fatal("tlsDesired latched true on initial load failure (#15667)")
	}
	if !s.tlsDesiredConfigured.Load() {
		t.Fatal("tlsDesiredConfigured must remain true for monitor retry")
	}
}

// TestCustomValidChainSANLog15667: a valid custom chain is accepted and
// the load log carries its SAN diagnostic.
func TestCustomValidChainSANLog15667(t *testing.T) {
	cert, _ := buildChain(t, chainSpec{leafSANs: []string{"mgmt.example.test"}})
	dir := t.TempDir()
	certPath, keyPath := writeChainPair(t, dir, cert)
	var s *Server
	out := captureTLSLog(t, func() {
		s = NewServer(Config{HTTPSAddr: "127.0.0.1:0", TLS: true, TLSCertificate: certPath, TLSPrivateKey: keyPath})
	})
	if s.httpsServer() == nil {
		t.Fatal("valid chain did not install HTTPS server")
	}
	if !s.tlsDesired.Load() {
		t.Fatal("tlsDesired must arm after successful load")
	}
	if !strings.Contains(out, "mgmt.example.test") {
		t.Fatalf("custom load log lacks SAN diagnostic: %q", out)
	}
	if got := managementTLSSANDiagnostic(chainLeaf(t, cert)); !strings.Contains(got, "mgmt.example.test") {
		t.Fatalf("SAN diagnostic = %q", got)
	}
	// No-SAN diagnostic marker.
	noSAN, _ := buildChain(t, chainSpec{})
	// buildChain always adds SANs; craft SAN-less leaf via helper check on nil leaf names:
	leaf := chainLeaf(t, noSAN)
	leaf2 := *leaf
	leaf2.DNSNames, leaf2.IPAddresses = nil, nil
	if got := managementTLSSANDiagnostic(&leaf2); !strings.Contains(got, "no subjectAltName") {
		t.Fatalf("no-SAN diagnostic = %q", got)
	}
}

// TestMonitorRecoversAfterFix15667: boot with a bad custom chain leaves
// no HTTPS leg; after the operator fixes the files, a monitor refresh
// installs the cert AND creates the serving leg without a restart or a
// ReconcileHTTPS call.
func TestMonitorRecoversAfterFix15667(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	bad, _ := buildChain(t, chainSpec{interNotAfter: now.Add(-time.Hour)})
	certPath, keyPath := writeChainPair(t, dir, bad)
	s := NewServer(Config{HTTPSAddr: "127.0.0.1:0", TLS: true, TLSCertificate: certPath, TLSPrivateKey: keyPath})
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()
	if s.HTTPSServing() {
		t.Fatal("precondition: bad chain must not be serving")
	}
	good, _ := buildChain(t, chainSpec{})
	writeChainPair(t, dir, good) // same paths, fixed content

	// Direct refresh (monitor tick equivalent, deterministic).
	s.refreshManagementTLSCertificate()
	if !s.HTTPSServing() {
		t.Fatal("monitor refresh did not recover HTTPS leg after cert fix (#15667)")
	}
	addr := s.EffectiveHTTPSAddr()
	if addr == "" {
		t.Fatal("recovered leg has no effective address")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("handshake to recovered leg: %v", err)
	}
	conn.Close()
	if !s.tlsDesired.Load() {
		t.Fatal("tlsDesired must arm after recovery install")
	}
}

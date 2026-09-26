package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func writeManagementTLSFixture(t *testing.T, dir, name string, notBefore, notAfter time.Time) (string, string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pair, leaf, err := managementTLSCertificateLeaf(pair)
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf = leaf
	return certPath, keyPath, pair
}

func TestManagementTLSRejectsOutOfWindowCustomCertificates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{name: "expired", notBefore: now.Add(-2 * time.Hour), notAfter: now.Add(-time.Hour)},
		{name: "not-yet-valid", notBefore: now.Add(time.Hour), notAfter: now.Add(24 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath, _ := writeManagementTLSFixture(t, dir, tc.name, tc.notBefore, tc.notAfter)
			before := managementTLSCertificateInvalidEvents.Load()
			s := NewServer(Config{
				HTTPSAddr:      "127.0.0.1:0",
				TLS:            true,
				TLSCertificate: certPath,
				TLSPrivateKey:  keyPath,
			})
			if s.httpsServer != nil {
				t.Fatal("an out-of-window custom pair installed an HTTPS server")
			}
			if _, err := s.managementTLSGetCertificate(nil); err == nil {
				t.Fatal("an out-of-window custom pair remained available to the TLS selector")
			}
			if got := managementTLSCertificateInvalidEvents.Load(); got != before+1 {
				t.Fatalf("invalid-certificate counter = %d, want %d", got, before+1)
			}

			// The operator-facing scrape exposes the same event counter even
			// when the dataplane is not loaded.
			w := httptest.NewRecorder()
			s.sharedBase.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
			wantSample := "xpf_management_tls_certificate_invalid_total " +
				strconv.FormatUint(managementTLSCertificateInvalidEvents.Load(), 10) + "\n"
			if w.Code != 200 || !strings.Contains(w.Body.String(), wantSample) {
				t.Fatalf("/metrics omitted the TLS invalid-certificate counter sample %q (status %d): %s",
					wantSample, w.Code, w.Body.String())
			}
		})
	}
}

func TestManagementTLSMonitorRefusesExpiredCertificateWithoutSNI(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	certPath, keyPath, _ := writeManagementTLSFixture(t, dir, "valid", now.Add(-time.Hour), now.Add(24*time.Hour))
	s := NewServer(Config{
		HTTPSAddr:      "127.0.0.1:0",
		TLS:            true,
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
	})
	if len(s.httpsServer.TLSConfig.Certificates) != 0 {
		t.Fatal("TLSConfig contains a snapshot certificate that can bypass GetCertificate without SNI")
	}
	s.tlsNow = func() time.Time { return now.Add(48 * time.Hour) }
	s.tlsCheckInterval = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start HTTPS server: %v", err)
	}
	defer func() {
		cancel()
		s.Wait()
	}()

	deadline := time.Now().Add(time.Second)
	for !s.tlsCertificateInvalid.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !s.tlsCertificateInvalid.Load() {
		t.Fatal("periodic certificate monitor did not reject the expired leaf")
	}
	addr := s.EffectiveHTTPSAddr()
	if addr == "" {
		t.Fatal("HTTPS listener stopped instead of refusing certificate selection")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) // No ServerName: the client sends no SNI for this IP address.
	if err == nil {
		conn.Close()
		t.Fatal("a client without SNI completed a TLS handshake using the expired certificate")
	}
}

func TestManagementTLSReconcilesCustomCertificateRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	certA, keyA, pairA := writeManagementTLSFixture(t, dir, "first", now.Add(-time.Hour), now.Add(24*time.Hour))
	certB, keyB, pairB := writeManagementTLSFixture(t, dir, "second", now.Add(-time.Hour), now.Add(48*time.Hour))
	s := NewServer(Config{
		HTTPSAddr:      "127.0.0.1:0",
		TLS:            true,
		TLSCertificate: certA,
		TLSPrivateKey:  keyA,
	})
	current := s.HTTPSCertForTest()
	if current == nil || current.Leaf == nil || string(current.Leaf.Raw) != string(pairA.Leaf.Raw) {
		t.Fatal("initial custom certificate was not selected")
	}
	if err := s.ReconcileTLSCertificate(certB, keyB); err != nil {
		t.Fatalf("reconcile rotated custom certificate: %v", err)
	}
	current, err := s.managementTLSGetCertificate(nil)
	if err != nil {
		t.Fatalf("select rotated custom certificate: %v", err)
	}
	if current.Leaf == nil || string(current.Leaf.Raw) != string(pairB.Leaf.Raw) {
		t.Fatal("TLS selector continued serving the old certificate after rotation")
	}
}

func TestManagementTLSRemintsExpiredSystemGeneratedCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	dir := t.TempDir()
	_, _, expired := writeManagementTLSFixture(t, dir, "expired", now.Add(-48*time.Hour), now.Add(-time.Hour))
	if err := os.Rename(filepath.Join(dir, "expired.crt"), filepath.Join(dir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "expired.key"), filepath.Join(dir, "key.pem")); err != nil {
		t.Fatal(err)
	}
	s := NewServer(Config{})
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		cancel()
		s.Wait()
	}()
	s.SetTLSCertDirForTest(dir)
	before := managementTLSCertificateInvalidEvents.Load()
	if err := s.ReconcileHTTPS(true, "127.0.0.1:0"); err != nil {
		t.Fatalf("reconcile HTTPS with expired durable pair: %v", err)
	}
	served := s.HTTPSCertForTest()
	if served == nil || served.Leaf == nil {
		t.Fatal("system-generated replacement certificate was not installed")
	}
	if string(served.Leaf.Raw) == string(expired.Leaf.Raw) {
		t.Fatal("expired durable certificate was served instead of re-minted")
	}
	if err := managementTLSCertificateValidityError(served.Leaf, now); err != nil {
		t.Fatalf("replacement certificate is outside its validity window: %v", err)
	}
	if got := managementTLSCertificateInvalidEvents.Load(); got != before+1 {
		t.Fatalf("invalid-certificate counter = %d, want %d", got, before+1)
	}
}

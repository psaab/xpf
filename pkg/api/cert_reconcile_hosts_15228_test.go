package api

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
)

// #15228 A44-04: construction-time httpsBindHosts captured only the
// NewServer Config set. A server constructed single-stack and later
// reconciled (ReconcileHTTPSAddrs) to dual-stack minted, on a fresh
// durable dir, a cert covering only the construction host — the v6 leg
// served a cert strict clients reject for its own address, and removing
// /etc/xpf/tls reproduced the same shape because the mint input was stale.
//
// FAIL-ON-REVERT: reverting the reconcile-time httpsBindHosts update (or
// the bindHostsForCertGen union) leaves the new host out and this fails.
func TestCertGenHostsAfterReconcile15228(t *testing.T) {
	dir := t.TempDir()
	s := NewServer(Config{TLS: true, HTTPSAddr: "10.0.0.1:8443"})
	s.SetTLSCertDirForTest(dir)

	// Reconcile toward a second host. The bind itself fails (10.0.0.1 is
	// not local) and the leg is retained/not installed — that is fine:
	// the cert host set must already reflect the DESIRED set so the
	// first successful mint covers both. Ignore the bind error.
	_ = s.ReconcileHTTPSAddrs(true, []string{"10.0.0.1:8443", "[2001:db8::99]:8443"})

	hosts := bindHostsForCertGen(s, "2001:db8::99")
	foundV4, foundV6 := false, false
	for _, h := range hosts {
		if h == "10.0.0.1" {
			foundV4 = true
		}
		if h == "2001:db8::99" {
			foundV6 = true
		}
	}
	if !foundV4 || !foundV6 {
		t.Fatalf("bindHostsForCertGen after reconcile = %v, want both 10.0.0.1 and 2001:db8::99", hosts)
	}

	// Fresh mint with that host set covers both SANs. Use a FRESH
	// durable dir (the server's dir already holds the construction
	// cert, which is loaded as-is by design #1916 — not re-minted).
	freshDir := t.TempDir()
	gen := func(hosts []string) (tls.Certificate, *x509.Certificate, error) {
		return generateSelfSignedCertAtWithStatusHosts(freshDir, filepath.Join(freshDir, "cert.pem"), filepath.Join(freshDir, "key.pem"), hosts)
	}
	cert, _, err := gen(hosts)
	if err != nil {
		t.Fatalf("certGen: %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("leaf nil")
	}
	if !hasIPSAN(cert.Leaf, net.ParseIP("10.0.0.1")) || !hasIPSAN(cert.Leaf, net.ParseIP("2001:db8::99")) {
		t.Fatalf("fresh dual mint SANs %v want both 10.0.0.1 and 2001:db8::99", cert.Leaf.IPAddresses)
	}

	// Control: single-stack construction still covers its one host.
	single := NewServer(Config{TLS: true, HTTPSAddr: "10.0.0.1:8443"})
	single.SetTLSCertDirForTest(t.TempDir())
	c2, _, err := single.certGen(bindHostsForCertGen(single, "10.0.0.1"))
	if err != nil {
		t.Fatalf("single certGen: %v", err)
	}
	if c2.Leaf == nil || !hasIPSAN(c2.Leaf, net.ParseIP("10.0.0.1")) {
		t.Fatalf("single-stack control SANs %v lack 10.0.0.1", c2.Leaf.IPAddresses)
	}
}

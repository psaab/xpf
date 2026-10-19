package api

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
)

// TestDualStackPerLegTLSCert14984 is the #14984 D36-04 regression.
//
// Pre-fix, NewServer built both HTTPS legs against ONE shared atomic
// (s.tlsCertificate) and every leg's TLSConfig pointed at the same
// managementTLSGetCertificate selector. The v6 build ran second and
// overwrote the v4 build's state, so the IPv4 listener presented a leaf
// whose IP SANs named the IPv6 bind host but not its own.
//
// FAIL-ON-REVERT: reverting to the shared selector makes
// httpsServers[0].TLSConfig.GetCertificate return the LAST-built (v6)
// leaf, whose IP SANs lack 10.0.0.1; the per-leg VerifyHostname fails.
// Control: a single-stack IPv4-only server still serves its own bind host
// (shared state accidentally passed single-stack before), and a real
// HTTPS /health dial on each bound loopback address stays green.
func TestDualStackPerLegTLSCert14984(t *testing.T) {
	if ln, err := net.Listen("tcp", "[::1]:0"); err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	} else {
		ln.Close()
	}

	// --- Per-leg SAN invariant -------------------------------------
	s := NewServer(Config{
		TLS:        true,
		HTTPSAddrs: []string{"10.0.0.1:8443", "[2001:db8::1]:8443"},
	})
	if len(s.httpsServers) != 2 {
		t.Fatalf("httpsServers = %d, want 2 (one per family)", len(s.httpsServers))
	}
	s.SetTLSCertDirForTest(t.TempDir())

	wants := []struct {
		ip   string
		addr string
	}{
		{"10.0.0.1", "10.0.0.1:8443"},
		{"2001:db8::1", "[2001:db8::1]:8443"},
	}
	for i, w := range wants {
		srv := s.httpsServers[i]
		if srv == nil || srv.TLSConfig == nil || srv.TLSConfig.GetCertificate == nil {
			t.Fatalf("httpsServers[%d] has no GetCertificate closure", i)
		}
		if srv.Addr != w.addr {
			t.Fatalf("httpsServers[%d].Addr = %q, want %q", i, srv.Addr, w.addr)
		}
		cert, err := srv.TLSConfig.GetCertificate(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatalf("httpsServers[%d] GetCertificate: %v", i, err)
		}
		if cert == nil || cert.Leaf == nil {
			t.Fatalf("httpsServers[%d] returned no leaf", i)
		}
		if err := cert.Leaf.VerifyHostname(w.ip); err != nil {
			t.Fatalf("httpsServers[%d] (%s) leaf does not verify for its own bind host %s: %v; DNS=%v IPs=%v",
				i, srv.Addr, w.ip, err, cert.Leaf.DNSNames, cert.Leaf.IPAddresses)
		}
		if !hasIPSAN(cert.Leaf, net.ParseIP(w.ip)) {
			t.Fatalf("httpsServers[%d] leaf IP SANs %v lack %s", i, cert.Leaf.IPAddresses, w.ip)
		}
	}

	// HTTPSCertForTest must read the FIRST leg's selector, not the shared
	// fallback's last write (which is the v6 state here).
	if c := s.HTTPSCertForTest(); c == nil || c.Leaf == nil || !hasIPSAN(c.Leaf, net.ParseIP("10.0.0.1")) {
		var dns []string
		var ips []net.IP
		if c != nil && c.Leaf != nil {
			dns, ips = c.Leaf.DNSNames, c.Leaf.IPAddresses
		}
		t.Fatalf("HTTPSCertForTest did not read the first leg's cert; DNS=%v IPs=%v", dns, ips)
	}

	// --- Serving control: both loopback families answer -------------
	ctx, cancel := context.WithCancel(context.Background())
	dual := NewServer(Config{
		Addrs:      []string{"127.0.0.1:0", "[::1]:0"},
		TLS:        true,
		HTTPSAddrs: []string{"127.0.0.1:0", "[::1]:0"},
	})
	dual.SetTLSCertDirForTest(t.TempDir())
	if err := dual.Start(ctx); err != nil {
		cancel()
		t.Fatalf("dual-stack Start: %v", err)
	}
	defer func() { cancel(); dual.Wait() }()
	if !dual.HTTPSServing() {
		t.Fatal("dual-stack HTTPS is not fully serving after fix")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // test dial to self-signed mgmt cert
	defer tr.CloseIdleConnections()
	for _, addr := range dual.EffectiveHTTPSAddrs() {
		assertHTTPS200(t, tr, "https://"+addr+"/health")
	}

	// Single-stack control: an IPv4-only server's one leg covers its bind.
	single := NewServer(Config{TLS: true, HTTPSAddr: "10.0.0.1:8443"})
	if got := single.HTTPSCertForTest(); got == nil || got.Leaf == nil || !hasIPSAN(got.Leaf, net.ParseIP("10.0.0.1")) {
		var ips []net.IP
		if got != nil && got.Leaf != nil {
			ips = got.Leaf.IPAddresses
		}
		t.Fatalf("single-stack control: leaf IP SANs %v lack 10.0.0.1", ips)
	}
	_ = http.MethodGet
}

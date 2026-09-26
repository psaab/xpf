package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// certLeaf generates a fresh self-signed cert with tlsHostname pinned to
// hostname and returns the parsed leaf. It fails the test if cert generation
// returns an error — the point of most #5719 cases is that a weird hostname
// must NOT abort generation.
func certLeaf(t *testing.T, hostname string) *x509.Certificate {
	t.Helper()
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return hostname, nil }
	dir, certPath, keyPath := tlsPaths(t)
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, "")
	if err != nil {
		t.Fatalf("hostname=%q: cert generation aborted: %v", hostname, err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatalf("hostname=%q: no certificate produced", hostname)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("hostname=%q: parse leaf: %v", hostname, err)
	}
	return leaf
}

func hasIPSAN(leaf *x509.Certificate, ip net.IP) bool {
	for _, s := range leaf.IPAddresses {
		if s.Equal(ip) {
			return true
		}
	}
	return false
}

func hasDNSSAN(leaf *x509.Certificate, name string) bool {
	for _, s := range leaf.DNSNames {
		if s == name {
			return true
		}
	}
	return false
}

// assertLoopbackSANs is the invariant that must hold for EVERY generated cert
// regardless of hostname: localhost DNS + 127.0.0.1 / ::1 IP SANs are always
// present, so a loopback-bound HTTPS client always verifies.
func assertLoopbackSANs(t *testing.T, leaf *x509.Certificate) {
	t.Helper()
	if len(leaf.DNSNames) == 0 {
		t.Fatal("generated cert has no DNS SANs; modern TLS clients reject CN-only certs")
	}
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Fatalf("VerifyHostname(localhost) = %v; want valid (cert lacks a localhost SAN)", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("VerifyHostname(127.0.0.1) = %v; want valid (cert lacks a 127.0.0.1 IP SAN)", err)
	}
	if !hasIPSAN(leaf, net.IPv6loopback) {
		t.Fatalf("generated cert IP SANs %v missing ::1", leaf.IPAddresses)
	}
}

// TestGenerateSelfSignedCertHasSANs is a FAIL-ON-REVERT guard for the #5719
// (codex-review-182 C-API) SAN-less-generated-cert TLS hygiene gap: the
// generated HTTPS cert must carry Subject Alternative Names, not just a
// CommonName. A SAN-less cert is rejected by every modern TLS client for
// hostname verification ("x509: certificate is not valid for any names").
//
// RED on revert: drop the DNSNames/IPAddresses fields from the cert template
// and assertLoopbackSANs fails.
func TestGenerateSelfSignedCertHasSANs(t *testing.T) {
	// A plain ASCII hostname must appear as a DNS SAN alongside the loopback
	// SANs (this is the "hostname SAN is present for a valid hostname"
	// assertion the review asked for).
	leaf := certLeaf(t, "fw-node0")
	assertLoopbackSANs(t, leaf)
	if !hasDNSSAN(leaf, "fw-node0") {
		t.Fatalf("valid hostname not in DNS SANs %v", leaf.DNSNames)
	}
	if leaf.Subject.CommonName != "fw-node0" {
		t.Fatalf("CommonName = %q, want fw-node0", leaf.Subject.CommonName)
	}
}

// TestGenerateSelfSignedCertHostnameSANClassification is a FAIL-ON-REVERT
// guard for the #5719 FOLD-1/FOLD-2 hostname-guard: a non-ASCII kernel
// hostname must NOT abort cert generation (x509 marshals DNSNames as an
// IA5String and HARD-FAILS on non-ASCII — under the #5058 all-or-nothing
// management-server lifecycle that would tear down the whole HTTP+HTTPS
// server), and an IP-literal hostname must land in IPAddresses (a DNS SAN of
// an IP never verifies as an IP), never in DNSNames.
//
// RED on revert:
//   - Remove the isDNSSANSafeHostname guard (append the raw hostname to
//     DNSNames): the "café" / "fw_node\n" cases make generateSelfSignedCertAt
//     return an IA5String error → certLeaf's t.Fatalf fires.
//   - Remove the net.ParseIP → IPAddresses branch: the "10.9.9.9" case has no
//     10.9.9.9 IP SAN (and, if appended to DNSNames instead, VerifyHostname on
//     the IP still fails), tripping the assertions below.
func TestGenerateSelfSignedCertHostnameSANClassification(t *testing.T) {
	t.Run("non_ascii_hostname_degrades_to_loopback", func(t *testing.T) {
		leaf := certLeaf(t, "café")
		assertLoopbackSANs(t, leaf)
		if hasDNSSAN(leaf, "café") {
			t.Fatal("non-ASCII hostname must not be a DNS SAN")
		}
		// CommonName may legally carry the raw (UTF-8) hostname.
		if leaf.Subject.CommonName != "café" {
			t.Fatalf("CommonName = %q, want café", leaf.Subject.CommonName)
		}
	})

	t.Run("control_char_hostname_degrades_to_loopback", func(t *testing.T) {
		leaf := certLeaf(t, "fw_node\n")
		assertLoopbackSANs(t, leaf)
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "localhost" {
			t.Fatalf("malformed hostname must degrade to localhost-only DNS SANs, got %v", leaf.DNSNames)
		}
	})

	t.Run("ip_literal_hostname_goes_to_ip_sans", func(t *testing.T) {
		leaf := certLeaf(t, "10.9.9.9")
		assertLoopbackSANs(t, leaf)
		if hasDNSSAN(leaf, "10.9.9.9") {
			t.Fatal("IP-literal hostname must not be a DNS SAN")
		}
		if !hasIPSAN(leaf, net.ParseIP("10.9.9.9")) {
			t.Fatalf("IP-literal hostname missing from IP SANs %v", leaf.IPAddresses)
		}
		if err := leaf.VerifyHostname("10.9.9.9"); err != nil {
			t.Fatalf("VerifyHostname(10.9.9.9) = %v; want valid", err)
		}
	})

	t.Run("empty_hostname_degrades_to_loopback", func(t *testing.T) {
		leaf := certLeaf(t, "")
		assertLoopbackSANs(t, leaf)
		if leaf.Subject.CommonName != "xpf" {
			t.Fatalf("empty hostname CommonName = %q, want xpf fallback", leaf.Subject.CommonName)
		}
	})
}

// certLeafBind is certLeaf with an explicit HTTPS bind host threaded into cert
// generation (#5719 C001 residual: the configured management bind IP must reach
// the SANs so a remote client verifying by mgmt IP succeeds).
func certLeafBind(t *testing.T, hostname, bindHost string) *x509.Certificate {
	t.Helper()
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return hostname, nil }
	dir, certPath, keyPath := tlsPaths(t)
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, bindHost)
	if err != nil {
		t.Fatalf("hostname=%q bindHost=%q: cert generation aborted: %v", hostname, bindHost, err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// TestGenerateSelfSignedCertBindHostSAN is a FAIL-ON-REVERT guard for the #5719
// C001 residual: the configured HTTPS management bind host must be threaded into
// the cert SANs. Before this fix the cert carried only loopback + kernel-
// hostname SANs, so `https://<mgmt-ip>:8443` strict-verify failed for a remote
// client — the original C001 remote-verification goal #6373 did NOT complete.
//
// RED on revert: drop the bindHost SAN block in generateSelfSignedCertAt and the
// management IP / DNS bind host no longer appears in the cert, tripping the
// mgmt_ip / dns assertions below.
func TestGenerateSelfSignedCertBindHostSAN(t *testing.T) {
	t.Run("mgmt_ip_bind_host_becomes_ip_san", func(t *testing.T) {
		leaf := certLeafBind(t, "fw-node0", "10.0.0.1")
		assertLoopbackSANs(t, leaf)
		if !hasIPSAN(leaf, net.ParseIP("10.0.0.1")) {
			t.Fatalf("management bind IP missing from cert IP SANs %v", leaf.IPAddresses)
		}
		if err := leaf.VerifyHostname("10.0.0.1"); err != nil {
			t.Fatalf("VerifyHostname(10.0.0.1) = %v; want valid (remote mgmt-IP verification must pass)", err)
		}
		// The kernel-hostname DNS SAN and loopback SANs still coexist.
		if !hasDNSSAN(leaf, "fw-node0") {
			t.Fatalf("hostname DNS SAN dropped when bind IP added: %v", leaf.DNSNames)
		}
	})

	t.Run("dns_bind_host_becomes_dns_san", func(t *testing.T) {
		leaf := certLeafBind(t, "fw-node0", "mgmt.example.com")
		assertLoopbackSANs(t, leaf)
		if !hasDNSSAN(leaf, "mgmt.example.com") {
			t.Fatalf("DNS bind host missing from cert DNS SANs %v", leaf.DNSNames)
		}
	})

	t.Run("loopback_bind_host_not_duplicated", func(t *testing.T) {
		leaf := certLeafBind(t, "fw-node0", "127.0.0.1")
		want := net.ParseIP("127.0.0.1")
		n := 0
		for _, s := range leaf.IPAddresses {
			if s.Equal(want) {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("loopback bind host duplicated 127.0.0.1 in IP SANs %v (count=%d)", leaf.IPAddresses, n)
		}
	})

	t.Run("unspecified_bind_host_skipped", func(t *testing.T) {
		leaf := certLeafBind(t, "fw-node0", "0.0.0.0")
		if hasIPSAN(leaf, net.ParseIP("0.0.0.0")) {
			t.Fatalf("wildcard bind host 0.0.0.0 must not be an IP SAN: %v", leaf.IPAddresses)
		}
	})

	t.Run("bind_host_equal_hostname_not_duplicated", func(t *testing.T) {
		leaf := certLeafBind(t, "fw-node0", "fw-node0")
		n := 0
		for _, s := range leaf.DNSNames {
			if s == "fw-node0" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("bind host equal to hostname duplicated DNS SAN fw-node0 (count=%d) in %v", n, leaf.DNSNames)
		}
	})

	t.Run("empty_bind_host_is_loopback_only", func(t *testing.T) {
		// A wildcard bind (":8443") threads bindHost="" — the prior behavior:
		// loopback + hostname SANs, no extra bind SAN.
		leaf := certLeafBind(t, "fw-node0", "")
		assertLoopbackSANs(t, leaf)
	})

	t.Run("bind_host_case_differs_from_hostname_not_duplicated", func(t *testing.T) {
		// DNS SANs are case-insensitive (RFC 4343): a bind host that differs
		// from the kernel hostname only in case must COALESCE, not double-
		// encode. RED on revert: dnsSANsContain drops strings.EqualFold and
		// "FW-NODE0" is appended alongside "fw-node0" (count=2).
		leaf := certLeafBind(t, "fw-node0", "FW-NODE0")
		n := 0
		for _, s := range leaf.DNSNames {
			if strings.EqualFold(s, "fw-node0") {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("case-variant bind host duplicated DNS SAN fw-node0 (count=%d) in %v", n, leaf.DNSNames)
		}
	})
}

// TestLoadedCertBindHostMismatchWarns is a FAIL-ON-REVERT guard for the #5719
// C001 silent-stale-cert-on-rebind residual: generateSelfSignedCertAt LOADS an
// existing on-disk cert AS-IS (the durable #1916 D6 contract — it must NOT
// re-mint on a bind change, which would churn remote clients' TOFU pins). But a
// cert minted for management host A does NOT cover a later rebind to host B, so
// strict remote verification by B silently fails. The load-success path must
// emit a diagnostic naming the uncovered bind host so an operator can re-mint
// (remove /etc/xpf/tls), rather than serving the stale cert in silence.
//
// RED on revert: drop the bindHostWarnable/certCoversHost check on the load-
// success path (or neutralize certCoversHost to always return true) and the
// A→B reload emits no warning — the mismatch subtests below fail.
func TestLoadedCertBindHostMismatchWarns(t *testing.T) {
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })

	// mintThenReload mints a durable cert for firstBind at a fresh temp dir,
	// then RELOADS it (the on-disk pair now exists) for secondBind, returning
	// any slog output the reload emits.
	mintThenReload := func(t *testing.T, hostname, firstBind, secondBind string) string {
		t.Helper()
		resetTLSSeams(t)
		tlsHostname = func() (string, error) { return hostname, nil }
		dir, certPath, keyPath := tlsPaths(t)
		if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, firstBind); err != nil {
			t.Fatalf("first mint (bind %q): %v", firstBind, err)
		}
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, secondBind)
		if err != nil {
			t.Fatalf("reload (bind %q): %v", secondBind, err)
		}
		// The reload must return the SAME durable leaf bytes — the #1916 D6
		// no-re-mint contract the warning exists to compensate for.
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			t.Fatalf("parse reloaded leaf: %v", perr)
		}
		if leaf.Subject.CommonName != hostname && hostname != "" {
			t.Fatalf("reload minted a fresh cert (CN=%q) instead of loading the durable pair", leaf.Subject.CommonName)
		}
		return buf.String()
	}

	const mismatchMsg = "does not cover bind host"

	t.Run("ip_rebind_mismatch_warns", func(t *testing.T) {
		out := mintThenReload(t, "fw-node0", "10.0.0.1", "10.0.0.2")
		if !strings.Contains(out, mismatchMsg) {
			t.Fatalf("A→B management-IP rebind must warn on a stale cert; got log %q", out)
		}
		if !strings.Contains(out, "10.0.0.2") {
			t.Fatalf("warning must name the uncovered bind host 10.0.0.2; got %q", out)
		}
	})

	t.Run("dns_rebind_mismatch_warns", func(t *testing.T) {
		out := mintThenReload(t, "fw-node0", "mgmt-a.example.com", "mgmt-b.example.com")
		if !strings.Contains(out, mismatchMsg) {
			t.Fatalf("A→B DNS rebind must warn on a stale cert; got %q", out)
		}
	})

	t.Run("same_bind_reload_is_silent", func(t *testing.T) {
		out := mintThenReload(t, "fw-node0", "10.0.0.1", "10.0.0.1")
		if strings.Contains(out, mismatchMsg) {
			t.Fatalf("a reload with the SAME covered bind host must not warn; got %q", out)
		}
	})

	t.Run("loopback_rebind_is_silent", func(t *testing.T) {
		// Loopback SANs are always present, so a loopback rebind is covered and
		// not warnable (bindHostWarnable gates it out).
		out := mintThenReload(t, "fw-node0", "10.0.0.1", "127.0.0.1")
		if strings.Contains(out, mismatchMsg) {
			t.Fatalf("a loopback rebind must not warn (loopback SANs always present); got %q", out)
		}
	})
}

// TestCertCoversHostAndWarnable unit-checks the two folded helpers directly so a
// neutralization is caught even if the load-path integration changes.
func TestCertCoversHostAndWarnable(t *testing.T) {
	leaf := certLeafBind(t, "fw-node0", "10.0.0.1")
	if !certCoversHost(leaf, "10.0.0.1") {
		t.Fatal("certCoversHost must be true for the covered mgmt IP")
	}
	if certCoversHost(leaf, "10.0.0.2") {
		t.Fatal("certCoversHost must be false for an uncovered mgmt IP")
	}
	if !certCoversHost(leaf, "127.0.0.1") {
		t.Fatal("certCoversHost must be true for a loopback SAN")
	}

	warnable := []struct {
		host string
		want bool
	}{
		{"10.0.0.1", true},
		{"mgmt.example.com", true},
		{"", false},
		{"localhost", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"::", false},
	}
	for _, c := range warnable {
		if got := bindHostWarnable(c.host); got != c.want {
			t.Errorf("bindHostWarnable(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestBuildHTTPSServerThreadsBindHost is a FAIL-ON-REVERT guard that
// buildHTTPSServer extracts the listener host from the bind addr and passes it
// to certGen. RED on revert: restore the no-arg certGen() call / drop the
// net.SplitHostPort, and the recorded bindHost is "" instead of "10.0.0.1".
func TestBuildHTTPSServerThreadsBindHost(t *testing.T) {
	s := &Server{}
	var got string
	cert := mintCert(t, "fw", "10.0.0.1")
	s.certGen = func(bindHost string) (tls.Certificate, *x509.Certificate, error) {
		got = bindHost
		return cert, nil, nil
	}
	if _, err := s.buildHTTPSServer("10.0.0.1:8443", s.newAuthSlot()); err != nil {
		t.Fatalf("buildHTTPSServer: %v", err)
	}
	if got != "10.0.0.1" {
		t.Fatalf("certGen bindHost = %q, want 10.0.0.1", got)
	}

	// A wildcard bind yields an empty host (no single name to certify).
	got = "sentinel"
	if _, err := s.buildHTTPSServer(":8443", s.newAuthSlot()); err != nil {
		t.Fatalf("buildHTTPSServer wildcard: %v", err)
	}
	if got != "" {
		t.Fatalf("wildcard certGen bindHost = %q, want empty", got)
	}
}

// TestIsDNSSANSafeHostname unit-checks the classifier directly.
func TestIsDNSSANSafeHostname(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"fw-node0", true},
		{"fw.example.com", true},
		{"host123", true},
		{"", false},
		{"café", false},
		{"fw_node\n", false},
		{"has space", false},
		{"under_score", false},
		{"10.9.9.9", false}, // IP literal → IPAddresses, not DNSNames
		{"::1", false},
	}
	for _, c := range cases {
		if got := isDNSSANSafeHostname(c.in); got != c.want {
			t.Errorf("isDNSSANSafeHostname(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestLoadedCertHostNameMismatchWarns is a FAIL-ON-REVERT guard for the SECOND
// half of the #5719 C001 stale-durable-cert residual: the kernel HOST NAME.
//
// The durable cert (#1916 D6) bakes the host name into a DNS SAN at first
// generation and is never re-minted, so a later `set system host-name` leaves
// the cert naming the OLD host. Before this guard that was completely silent:
// warnStaleLoadedCert's predecessor checked only the BIND HOST, so with the
// bind address unchanged (the normal case — renaming a firewall does not move
// its management IP) NOTHING was logged, and an operator connecting by the new
// host name got a bare "certificate is not valid for any names".
//
// RED on revert: delete the warnHost branch in warnStaleLoadedCert (or make
// hostnameSANWarnable always return false) and host_name_change_warns /
// ip_literal_host_name_change_warns fail — the reload emits no host-name
// diagnostic.
func TestLoadedCertHostNameMismatchWarns(t *testing.T) {
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })

	// mintThenRename mints a durable cert as mintHost, then RELOADS it with the
	// kernel host name changed to reloadHost and the bind address UNCHANGED,
	// returning whatever the reload logged.
	mintThenRename := func(t *testing.T, mintHost, reloadHost, bind string) string {
		t.Helper()
		resetTLSSeams(t)
		tlsHostname = func() (string, error) { return mintHost, nil }
		dir, certPath, keyPath := tlsPaths(t)
		if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, bind); err != nil {
			t.Fatalf("first mint (host %q): %v", mintHost, err)
		}
		tlsHostname = func() (string, error) { return reloadHost, nil }
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, bind)
		if err != nil {
			t.Fatalf("reload (host %q): %v", reloadHost, err)
		}
		// The reload must serve the SAME durable leaf — the no-re-mint contract
		// this diagnostic exists to compensate for. If the cert were re-minted
		// the host name would be covered and the warning would be pointless.
		leaf, perr := x509.ParseCertificate(cert.Certificate[0])
		if perr != nil {
			t.Fatalf("parse reloaded leaf: %v", perr)
		}
		if leaf.Subject.CommonName != mintHost {
			t.Fatalf("reload minted a fresh cert (CN=%q, want the durable %q)", leaf.Subject.CommonName, mintHost)
		}
		return buf.String()
	}

	const hostMsg = "does not cover the current host-name"

	t.Run("host_name_change_warns", func(t *testing.T) {
		// `set system host-name new-fw` with the management IP unchanged: the
		// bind host is still covered, so ONLY the host-name check can catch this.
		out := mintThenRename(t, "old-fw", "new-fw", "10.0.0.1")
		if !strings.Contains(out, hostMsg) {
			t.Fatalf("a host-name change must warn on the stale durable cert; got log %q", out)
		}
		if !strings.Contains(out, "new-fw") {
			t.Fatalf("warning must name the uncovered host-name new-fw; got %q", out)
		}
		if strings.Contains(out, "does not cover bind host") {
			t.Fatalf("bind host 10.0.0.1 IS covered and must not warn; got %q", out)
		}
	})

	t.Run("ip_literal_host_name_change_warns", func(t *testing.T) {
		// An IP-literal host name lands in IPAddresses, so it is warnable too.
		out := mintThenRename(t, "10.9.9.9", "10.9.9.10", "mgmt.example.com")
		if !strings.Contains(out, hostMsg) {
			t.Fatalf("an IP-literal host-name change must warn; got %q", out)
		}
	})

	t.Run("unchanged_host_name_is_silent", func(t *testing.T) {
		out := mintThenRename(t, "old-fw", "old-fw", "10.0.0.1")
		if strings.Contains(out, hostMsg) {
			t.Fatalf("an unchanged, covered host-name must not warn; got %q", out)
		}
	})

	t.Run("unencodable_host_name_is_silent", func(t *testing.T) {
		// A non-ASCII host name is DROPPED from the SANs by design
		// (isDNSSANSafeHostname / #5058), so it is uncoverable and a re-mint
		// cannot help. Warning every reload would be permanent noise advising a
		// fix that does not exist.
		out := mintThenRename(t, "old-fw", "café", "10.0.0.1")
		if strings.Contains(out, hostMsg) {
			t.Fatalf("an unencodable host-name must not warn (a re-mint cannot cover it); got %q", out)
		}
	})

	t.Run("empty_host_name_is_silent", func(t *testing.T) {
		out := mintThenRename(t, "old-fw", "", "10.0.0.1")
		if strings.Contains(out, hostMsg) {
			t.Fatalf("an empty host-name must not warn; got %q", out)
		}
	})

	t.Run("bind_host_warning_still_fires", func(t *testing.T) {
		// Regression guard for the refactor into warnStaleLoadedCert: BOTH
		// identities must be reported when BOTH are stale.
		resetTLSSeams(t)
		tlsHostname = func() (string, error) { return "old-fw", nil }
		dir, certPath, keyPath := tlsPaths(t)
		if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, "10.0.0.1"); err != nil {
			t.Fatalf("first mint: %v", err)
		}
		tlsHostname = func() (string, error) { return "new-fw", nil }
		var buf bytes.Buffer
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, "10.0.0.2"); err != nil {
			t.Fatalf("reload: %v", err)
		}
		out := buf.String()
		if !strings.Contains(out, "does not cover bind host") {
			t.Fatalf("stale bind host must still warn; got %q", out)
		}
		if !strings.Contains(out, hostMsg) {
			t.Fatalf("stale host-name must warn alongside it; got %q", out)
		}
	})
}

// TestHostnameSANWarnable unit-checks the host-name predicate directly so a
// neutralization is caught even if the load-path integration changes. The
// contrast with bindHostWarnable is the point: an unencodable host name is NOT
// warnable (a re-mint could never cover it) while any non-loopback bind host is.
func TestHostnameSANWarnable(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"fw-node0", true},
		{"fw.example.com", true},
		{"10.9.9.9", true}, // IP literal → IPAddresses SAN
		{"", false},
		{"localhost", false},
		{"127.0.0.1", false},
		{"::1", false},
		{"0.0.0.0", false},
		{"::", false},
		{"café", false},        // dropped from SANs by design
		{"under_score", false}, // '_' is not DNS-safe here
		{"has space", false},
	}
	for _, c := range cases {
		if got := hostnameSANWarnable(c.in); got != c.want {
			t.Errorf("hostnameSANWarnable(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestWarnStaleLoadedCertEmptyChain pins the standalone helper's defensive
// precondition: an empty certificate chain is a no-op, not a panic.
func TestWarnStaleLoadedCertEmptyChain(t *testing.T) {
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return "fw-node0", nil }
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	warnStaleLoadedCert(tls.Certificate{}, "10.0.0.1")
	if buf.Len() != 0 {
		t.Fatalf("empty chain must produce no diagnostic; got %q", buf.String())
	}
}

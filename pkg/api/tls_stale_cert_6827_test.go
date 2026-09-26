package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// #6827: three defects in the #5719 stale-management-cert diagnostic, all of
// them cases where the check says nothing when it should, or says something when
// it should not. The guards live in their own file because they pin the
// diagnostic's REACH and its FALSE-POSITIVE rule, not the SAN-minting behaviour
// tls_san_5719_test.go covers.

// captureWarn redirects slog to a buffer for the duration of fn and returns what
// was logged at WARN or above.
func captureWarn(t *testing.T, fn func()) string {
	t.Helper()
	restore := slog.Default()
	t.Cleanup(func() { slog.SetDefault(restore) })
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	fn()
	slog.SetDefault(restore)
	return buf.String()
}

// mintCert mints (not loads) a durable pair for hostname + bindHost in a fresh
// temp dir and returns the tls.Certificate. Minting is silent by construction —
// the diagnostic only runs on the LOAD path — so a caller can use the result as
// a fixture without filtering mint-time output.
func mintCert(t *testing.T, hostname, bindHost string) tls.Certificate {
	t.Helper()
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return hostname, nil }
	dir, certPath, keyPath := tlsPaths(t)
	cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, bindHost)
	if err != nil {
		t.Fatalf("mint (host %q bind %q): %v", hostname, bindHost, err)
	}
	return cert
}

// stubLn is a minimal net.Listener so a hand-built listenerLeg satisfies
// listenerLeg.serving() without binding a socket.
type stubLn struct{ closed chan struct{} }

func newStubLn() *stubLn                    { return &stubLn{closed: make(chan struct{})} }
func (l *stubLn) Accept() (net.Conn, error) { <-l.closed; return nil, net.ErrClosed }
func (l *stubLn) Close() error              { close(l.closed); return nil }
func (l *stubLn) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// newLeg hand-builds a listenerLeg holding the field values serving() reports as
// live: a listener installed, `dead` unset, `stopping` unset. It starts NO serve
// goroutine and binds no socket — nothing is accepting connections on this leg,
// and the flags are the test's own, not production's.
//
// That is deliberate, and it is why it may only be used to exercise the
// certificate-selection half of WarnStaleMgmtCertForHostName, which reads just
// leg state + srv. The flags themselves are set by serveLegLocked, and tests
// that assert on THAT drive the real goroutine instead:
// TestDrainFlagIsSetByTheRealServeGoroutine_6827 for `stopping`,
// TestUnexpectedServeExitLeavesADeadInstalledLeg_6827 for `dead`.
func newLeg(cert tls.Certificate, addr string) *listenerLeg {
	return &listenerLeg{
		srv: &http.Server{
			Addr:      addr,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		},
		ln:     newStubLn(),
		stopCh: make(chan struct{}),
	}
}

// legServing returns a Server whose HTTPS leg carries cert at addr in the
// hand-built state newLeg describes (installed and flagged live; no serve
// goroutine).
func legServing(cert tls.Certificate, addr string) *Server {
	s := &Server{}
	s.httpsLeg = newLeg(cert, addr)
	return s
}

// errLn is a listener whose Accept fails PERMANENTLY, which is what drives the
// production unexpected-serve-exit path: http.Server.Serve returns a
// non-net.Error immediately (no retry), so serveLegLocked's serveErr arm runs
// and marks the leg dead while leaving it installed.
type errLn struct{}

func (errLn) Accept() (net.Conn, error) { return nil, errors.New("listener terminated") }
func (errLn) Close() error              { return nil }
func (errLn) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443} }

// startWithDeadHTTPSLeg starts a Server whose HTTPS leg self-terminates and
// returns once that leg is INSTALLED and its serve goroutine has FINISHED.
//
// It asserts the installation — a caller's later assertion must not be satisfied
// by a leg that was never installed at all, which is the state a failed BIND
// leaves and a different case — and it deliberately does NOT assert `dead`.
//
// That is the #6827-round-7 correction. This helper used to poll `dead` on a 5s
// deadline and t.Fatal, which made it a SETUP GUARD on the very flag the M8
// mutation deletes: under that mutation both callers died HERE, at the shared
// precondition, and neither ever reached its own assertion. The matrix recorded
// two reds where there was one timeout on one entry path, and the tell was in
// the durations — 5.00s and 5.00s, round deadline values rather than the cost of
// real work.
//
// Server.Wait is the barrier instead. It blocks until every leg goroutine has
// returned, this server has exactly one leg, and it reads nothing that is under
// test — so when it returns, whatever the exit path stored is settled and the
// CALLER's assertion is the thing that speaks. A mutation that stops the exit
// path storing `dead` now reds on "HTTPSServing must report false" and on "the
// reconcile left the DEAD leg installed", which is what those cells claim to
// bind. (A mutation that stopped the goroutine returning at all would hang here
// rather than fail at 5s; the package timeout catches it with a full goroutine
// dump, which says more than a deadline message.)
func startWithDeadHTTPSLeg(t *testing.T, cert tls.Certificate, addr string) (*Server, context.CancelFunc) {
	t.Helper()
	s := &Server{listen: func(network, a string) (net.Listener, error) { return errLn{}, nil }}
	s.httpsServer = &http.Server{
		Addr:      addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start: %v", err)
	}
	if s.httpsLeg == nil {
		cancel()
		t.Fatal("precondition: the listen call SUCCEEDED, so the leg must be installed — " +
			"a test about a dead installed leg must not silently become a test about a failed bind")
	}
	s.Wait() // join the serve goroutine; assert nothing it stored
	return s, cancel
}

const (
	noSANMsg    = "carries NO subjectAltName"
	hostNameMsg = "does not cover the current host-name"
	bindHostMsg = "does not cover bind host"
)

// TestLoadedCertWithoutSANsWarns_6827 is a FAIL-ON-REVERT guard for the SILENT
// no-SAN certificate (#6827), in two subtests that deliberately differ ONLY in
// the management identities in play — because the two halves of the check are
// observable on DIFFERENT fixtures and one fixture cannot see both.
//
// Both per-identity predicates gate out loopback and "localhost" on the premise
// that "the durable cert always carries the loopback SANs". That premise holds
// for a cert THIS build minted, but the load path takes whatever is on disk: a
// pair persisted by an older build (or placed by an operator) can carry no SAN
// extension at all.
func TestLoadedCertWithoutSANsWarns_6827(t *testing.T) {
	// loadSANLessAs seeds a CN-only pair (genPair carries no DNSNames/IPAddresses
	// at all) so the load path finds a usable-but-SAN-less certificate on disk,
	// then LOADS it under hostName/bindHost and returns what the load logged.
	loadSANLessAs := func(t *testing.T, hostName, bindHost string) string {
		t.Helper()
		resetTLSSeams(t)
		tlsHostname = func() (string, error) { return hostName, nil }
		dir, certPath, keyPath := tlsPaths(t)
		certPEM, keyPEM := genPair(t)
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		return captureWarn(t, func() {
			cert, err := generateSelfSignedCertAt(dir, certPath, keyPath, bindHost)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			leaf, perr := x509.ParseCertificate(cert.Certificate[0])
			if perr != nil {
				t.Fatalf("parse: %v", perr)
			}
			// Precondition: the seeded pair was LOADED as-is, not re-minted (a
			// re-mint would add the loopback SANs and make the case vacuous). Read
			// the leaf directly rather than through certHasNoSANs — the predicate is
			// part of what this test pins, so routing the precondition through it
			// would report a fixture failure when the predicate is what broke.
			if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
				t.Fatalf("fixture re-minted: DNS %v IP %v", leaf.DNSNames, leaf.IPAddresses)
			}
		})
	}

	t.Run("loopback_only_identities_are_still_diagnosed", func(t *testing.T) {
		// The REACH half. With hostname `localhost` and bind 127.0.0.1,
		// bindHostWarnable and hostnameSANWarnable are BOTH false, so the old code
		// returned before it ever parsed the leaf — total silence on the most
		// broken certificate possible, while every modern client rejects it for
		// `https://localhost` AND `https://127.0.0.1` (CN is not consulted without
		// a SAN). Only warnCertNoSANs can speak here, which is what makes this
		// fixture the one that proves the check ADDS reach.
		//
		// RED on revert: drop the warnCertNoSANs call from warnStaleLoadedCert (or
		// make certHasNoSANs always return false) and the load emits NOTHING AT
		// ALL.
		out := loadSANLessAs(t, "localhost", "127.0.0.1")
		if !strings.Contains(out, noSANMsg) {
			t.Fatalf("a SAN-less management cert must be diagnosed; got log %q", out)
		}
	})

	t.Run("the_no_san_diagnostic_is_terminal", func(t *testing.T) {
		// The TERMINAL half, and it needs a fixture with a warnable identity —
		// which the loopback one above is not (#6827 round 6). Keeping only its
		// `return` under test there was vacuous: with `localhost` / 127.0.0.1 both
		// downstream predicates decline independently, so deleting the `return`
		// changed nothing observable and the terminality assertion could not fail.
		//
		// A NON-loopback bind can be reported, so here the two arms genuinely
		// compete. (The host-name line stays silent even on the revert, and
		// unavoidably so: warnStaleHostName's inferred heuristic needs a
		// shape-matching DNS SAN, which a SAN-less leaf cannot have. So the bind
		// host is the only per-identity line a SAN-less cert can ever produce on
		// the load path, and it is the discriminator here.)
		//
		// RED on revert: keep warnCertNoSANs but delete its `return` in
		// warnStaleLoadedCert and the bind-host line joins the no-SAN line.
		out := loadSANLessAs(t, "no-san-fw-6827", "10.0.0.1")
		if !strings.Contains(out, noSANMsg) {
			t.Fatalf("a SAN-less management cert must be diagnosed; got log %q", out)
		}
		if strings.Contains(out, hostNameMsg) || strings.Contains(out, bindHostMsg) {
			t.Fatalf("the no-SAN diagnostic must be terminal — the per-identity lines would each "+
				"report \"does not cover X\" for a cert that covers no X whatsoever, burying the "+
				"finding under symptoms; got %q", out)
		}
	})
}

// TestUnusedKernelHostNameIsSilent_6827 is the FALSE-POSITIVE guard, and its two
// subtests are a matched pair: they differ ONLY in the naming shape of the
// cert's DNS SAN, which is the whole discriminator (#6827).
//
// A box named `fw` whose cert covers `mgmt.example.com` and its management IP is
// verifiable at every URL in use; warning that the cert misses the unused short
// kernel name tells the operator to re-mint (churning remote TOFU pins) to fix
// nothing, and a diagnostic that fires on a healthy box gets muted — taking the
// true positive with it.
//
// RED on revert: delete the hostNameLikelyAccessIdentity gate from
// warnStaleHostName and unused_qualified_cert_identity_is_silent fails.
// Deleting the whole host-name branch instead fails drifted_short_name_warns,
// which is why both halves are asserted here.
//
// unused_qualified_cert_identity_is_silent is ALSO the executable statement of
// the accepted residual documented on hostNameLikelyAccessIdentity: a box whose
// rename crossed the qualified/unqualified boundary BEFORE this diagnostic
// shipped (so no commit ever caught it) stays silent on every boot, because the
// load path cannot distinguish it from the healthy configuration asserted here.
// If that gap is ever closed, this subtest is the one that must change, and
// changing it should be a deliberate decision rather than a surprise.
func TestUnusedKernelHostNameIsSilent_6827(t *testing.T) {
	// mintThenReload mints for mintHost/bind, then RELOADS as reloadHost with the
	// bind UNCHANGED, returning what the reload logged.
	mintThenReload := func(t *testing.T, mintHost, reloadHost, bind string) string {
		t.Helper()
		resetTLSSeams(t)
		tlsHostname = func() (string, error) { return mintHost, nil }
		dir, certPath, keyPath := tlsPaths(t)
		if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, bind); err != nil {
			t.Fatalf("mint as %q: %v", mintHost, err)
		}
		tlsHostname = func() (string, error) { return reloadHost, nil }
		return captureWarn(t, func() {
			if _, err := generateSelfSignedCertAt(dir, certPath, keyPath, bind); err != nil {
				t.Fatalf("reload as %q: %v", reloadHost, err)
			}
		})
	}

	t.Run("unused_qualified_cert_identity_is_silent", func(t *testing.T) {
		// Cert DNS SANs [localhost, mgmt.example.com] + IP SAN 10.0.0.1; the box
		// is now named `fw` and is reached only as https://mgmt.example.com or by
		// IP. Both are covered — nothing is wrong, so nothing may be said.
		out := mintThenReload(t, "mgmt.example.com", "fw", "10.0.0.1")
		if strings.Contains(out, hostNameMsg) {
			t.Fatalf("a short kernel name next to a domain-qualified cert identity is not an access "+
				"identity and must not be diagnosed; got %q", out)
		}
	})

	t.Run("drifted_short_name_warns", func(t *testing.T) {
		// Same shape, but the cert's identity is the UNQUALIFIED `old-fw` — only
		// this package's mint path puts a bare name there, and what it puts there
		// is the kernel host name. So the TLS identity IS the kernel name and it
		// has drifted: diagnose.
		out := mintThenReload(t, "old-fw", "new-fw", "10.0.0.1")
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a drifted unqualified kernel name must still be diagnosed; got %q", out)
		}
	})
}

// TestHostNameLikelyAccessIdentity_6827 unit-checks the narrowing predicate
// directly so a neutralization is caught even if the load-path integration
// changes.
func TestHostNameLikelyAccessIdentity_6827(t *testing.T) {
	shortLeaf := leafOf(t, mintCert(t, "old-fw", "10.0.0.1"))  // DNS: localhost, old-fw
	fqdnLeaf := leafOf(t, mintCert(t, "mgmt.example.com", "")) // DNS: localhost, mgmt.example.com
	loopbackLeaf := leafOf(t, mintCert(t, "localhost", ""))    // DNS: localhost only
	ipLeaf := leafOf(t, mintCert(t, "10.9.9.9", ""))           // IP: loopback + 10.9.9.9

	cases := []struct {
		name string
		leaf *x509.Certificate
		host string
		want bool
	}{
		{"short_name_short_san", shortLeaf, "new-fw", true},
		{"short_name_fqdn_san", fqdnLeaf, "fw", false},
		{"fqdn_name_fqdn_san", fqdnLeaf, "fw2.example.com", true},
		{"fqdn_name_short_san", shortLeaf, "fw.example.com", false},
		{"short_name_loopback_only_san", loopbackLeaf, "fw", false},
		{"ip_name_with_nonloopback_ip_san", ipLeaf, "10.9.9.10", true},
		{"ip_name_loopback_only_ip_san", loopbackLeaf, "10.9.9.10", false},
	}
	for _, c := range cases {
		if got := hostNameLikelyAccessIdentity(c.leaf, c.host); got != c.want {
			t.Errorf("%s: hostNameLikelyAccessIdentity(%q) = %v, want %v (DNS %v IP %v)",
				c.name, c.host, got, c.want, c.leaf.DNSNames, c.leaf.IPAddresses)
		}
	}
}

func leafOf(t *testing.T, cert tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// TestWarnStaleMgmtCertForHostName_6827 is a FAIL-ON-REVERT guard for the second
// entry point — the one a `set system host-name` commit actually reaches.
//
// The load-path diagnostic runs only while a certificate is being loaded, and
// the HTTPS leg reloads only on a TLS/bind change, so a rename on an unchanged
// endpoint never reached it. This entry point takes the host name as a
// PARAMETER, which also removes the apply-ordering hazard: the caller passes the
// name it just applied instead of racing os.Hostname() against the apply order.
//
// RED on revert: delete the WarnStaleMgmtCertForHostName body (return
// immediately) and every warning subtest fails; pass hostNameInferred instead of
// hostNameOperatorSet and operator_chosen_name_overrides_the_heuristic fails.
func TestWarnStaleMgmtCertForHostName_6827(t *testing.T) {
	t.Run("renamed_box_warns_naming_the_new_host_name", func(t *testing.T) {
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a rename onto an uncovered name must warn; got %q", out)
		}
		if !strings.Contains(out, "new-fw") {
			t.Fatalf("the warning must name the NEW host name; got %q", out)
		}
	})

	t.Run("covered_name_is_silent", func(t *testing.T) {
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("old-fw") })
		if strings.Contains(out, hostNameMsg) {
			t.Fatalf("a name the cert covers must not warn; got %q", out)
		}
	})

	t.Run("operator_chosen_name_overrides_the_heuristic", func(t *testing.T) {
		// The same fixture that must stay SILENT on a cert load
		// (TestUnusedKernelHostNameIsSilent_6827) must WARN here: the operator
		// just chose this name for the device, so it is an access identity by
		// direct evidence rather than by inference.
		s := legServing(mintCert(t, "mgmt.example.com", "10.0.0.1"), "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("fw") })
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a name the operator just applied must be diagnosed regardless of the "+
				"load-path heuristic; got %q", out)
		}
	})

	t.Run("bind_host_is_not_re_reported", func(t *testing.T) {
		// The bind host did not change, so a stale one was already reported when
		// the leg bound; repeating it on every rename is noise.
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.2:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if strings.Contains(out, bindHostMsg) {
			t.Fatalf("the rename path must not re-report the bind host; got %q", out)
		}
	})

	t.Run("no_san_cert_is_reported_on_rename_too", func(t *testing.T) {
		certPEM, keyPEM := genPair(t)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("build SAN-less pair: %v", err)
		}
		s := legServing(cert, "10.0.0.1:8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if !strings.Contains(out, noSANMsg) {
			t.Fatalf("a SAN-less cert must be diagnosed on a rename too; got %q", out)
		}
	})

	t.Run("no_live_https_leg_is_a_no_op", func(t *testing.T) {
		out := captureWarn(t, func() { (&Server{}).WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a server with no HTTPS leg serves no management cert; got %q", out)
		}
	})

	t.Run("dead_leg_is_not_diagnosed", func(t *testing.T) {
		// An UNEXPECTED serve exit sets only leg.dead and leaves the leg
		// INSTALLED in s.httpsLeg (listener.go: marking it under lifeMu would
		// deadlock a shutdown racing the exit). A non-nil pointer therefore does
		// not mean a socket is presenting this certificate — diagnosing it would
		// report a cert nobody serves, the same false positive the construction
		// template was rejected for (#6827).
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		s.httpsLeg.dead.Store(true)
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a leg whose serve loop exited must not be diagnosed; got %q", out)
		}
	})

	t.Run("root_shutdown_drained_leg_is_not_diagnosed", func(t *testing.T) {
		// The state a root-context shutdown ACTUALLY leaves behind: the serve
		// goroutine drains and RETURNS without ever setting `dead` and without
		// `stopCh` being closed, leaving the leg installed in s.httpsLeg
		// permanently. A predicate built from `dead` alone misses it entirely —
		// which is why the drain arm stores `stopping` before `Shutdown`, so the
		// root-context path is marked too (#6827).
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		s.httpsLeg.stopping.Store(true)
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a leg whose serve goroutine has returned must not be diagnosed; got %q", out)
		}
	})

	t.Run("reports_whether_it_reached_a_certificate", func(t *testing.T) {
		// The return value is the caller's debt signal: false means the question
		// could not be answered, so the diagnosis is still owed. Clearing a
		// pending diagnosis on a false return loses it permanently, because the
		// durable certificate outlives the listener.
		live := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		if !live.WarnStaleMgmtCertForHostName("new-fw") {
			t.Fatal("a live serving leg must report the question answered")
		}
		if (&Server{}).WarnStaleMgmtCertForHostName("new-fw") {
			t.Fatal("no serving leg must report the question UNanswered so the caller retries")
		}
		draining := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		draining.httpsLeg.stopping.Store(true)
		if draining.WarnStaleMgmtCertForHostName("new-fw") {
			t.Fatal("a draining leg must report the question UNanswered")
		}
	})

	t.Run("leg_without_a_listener_is_not_diagnosed", func(t *testing.T) {
		s := legServing(mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
		s.httpsLeg.ln = nil
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a leg holding no listener must not be diagnosed; got %q", out)
		}
	})

	t.Run("disabled_https_template_is_not_diagnosed", func(t *testing.T) {
		// httpsServer survives a `ReconcileHTTPS(false, ...)` disable while
		// httpsLeg is cleared. Reading the template would warn about a
		// certificate nobody serves.
		s := &Server{httpsServer: &http.Server{
			Addr:      "10.0.0.1:8443",
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{mintCert(t, "old-fw", "10.0.0.1")}},
		}}
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if out != "" {
			t.Fatalf("a disabled HTTPS leg must not be diagnosed; got %q", out)
		}
	})

	t.Run("wildcard_bind_host_still_diagnoses_the_name", func(t *testing.T) {
		// A ":8443" wildcard bind names no single host, so bindHost is "" — the
		// host-name half must still run.
		s := legServing(mintCert(t, "old-fw", ""), ":8443")
		out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
		if !strings.Contains(out, hostNameMsg) {
			t.Fatalf("a wildcard bind must not suppress the host-name diagnostic; got %q", out)
		}
	})
}

// TestWarnStaleMgmtCertForHostNameReadsTheLiveLeg_6827 pins that the diagnostic
// reads the certificate the live leg is SERVING, not a stale construction
// template, by giving the two different certificates.
func TestWarnStaleMgmtCertForHostNameReadsTheLiveLeg_6827(t *testing.T) {
	live := mintCert(t, "old-fw", "10.0.0.1")  // does NOT cover new-fw
	stale := mintCert(t, "new-fw", "10.0.0.1") // DOES cover new-fw
	s := legServing(live, "10.0.0.1:8443")
	s.httpsServer = &http.Server{
		Addr:      "10.0.0.9:8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{stale}},
	}
	out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
	if !strings.Contains(out, hostNameMsg) {
		t.Fatalf("the diagnostic must read the LIVE leg's cert (which misses new-fw), "+
			"not the construction template (which covers it); got %q", out)
	}
}

// TestDrainFlagIsSetByTheRealServeGoroutine_6827 drives the PRODUCTION transition
// instead of asserting on a flag the test set itself.
//
// The earlier subtests store `stopping` directly, so deleting
// `leg.stopping.Store(true)` from serveLegLocked left them all green: they set
// up the state production is supposed to establish, then assert on it. This one
// starts a real leg on a stub listener, cancels the root context, waits for the
// serve goroutine to drain and return, and only then asks serving().
//
// RED on revert: delete `leg.stopping.Store(true)` from serveLegLocked's drain
// arm and `stopping` stays false after the goroutine has returned, so serving()
// reports true and the diagnostic warns about a certificate nothing is serving.
func TestDrainFlagIsSetByTheRealServeGoroutine_6827(t *testing.T) {
	cert := mintCert(t, "old-fw", "10.0.0.1")
	s := &Server{listen: func(network, addr string) (net.Listener, error) { return newStubLn(), nil }}
	s.httpsServer = &http.Server{
		Addr:      "10.0.0.1:8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !s.HTTPSServing() {
		t.Fatal("precondition: the HTTPS leg must be serving before the root context is cancelled")
	}

	cancel()
	s.Wait() // joins the serve goroutine, so its defer has run

	if s.HTTPSServing() {
		t.Fatal("after the serve goroutine returned, the leg must not report serving (#6827): " +
			"stopping is set by serveLegLocked's drain arm, not by the test")
	}
	out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
	if out != "" {
		t.Fatalf("a leg whose goroutine has returned must not be diagnosed; got %q", out)
	}
}

// TestHTTPSBindFailureIsNotReportedAsServing_6827 pins the #6827-round-5
// finding that Start() returns SUCCESS when the HTTPS bind fails: HTTPS is
// best-effort at boot, so a bind failure must leave the HTTP plane up rather
// than fail the whole start. A caller that reads only the error therefore
// cannot conclude HTTPS is up, which is what HTTPSServing exists to answer.
//
// RED on revert: make Start return the HTTPS bind error and the first assertion
// fails.
//
// What this does NOT bind is the SHAPE of the HTTPSServing predicate (#6827
// round 6). The comment here used to claim a bare `s.httpsLeg != nil` would
// report a failed bind as serving; it would not, because ReconcileHTTPS/Start
// install a leg only AFTER the listen call succeeds, so this path leaves the
// pointer nil under every implementation and the second assertion holds
// vacuously. It is kept as the honest negative — nothing serving after a failed
// bind — and the predicate's two real clauses are bound where an INSTALLED leg
// is not serving: `stopping` by TestDrainFlagIsSetByTheRealServeGoroutine_6827,
// `dead` by TestUnexpectedServeExitLeavesADeadInstalledLeg_6827.
func TestHTTPSBindFailureIsNotReportedAsServing_6827(t *testing.T) {
	cert := mintCert(t, "old-fw", "10.0.0.1")
	s := &Server{listen: func(network, addr string) (net.Listener, error) {
		return nil, errors.New("bind refused")
	}}
	s.httpsServer = &http.Server{
		Addr:      "10.0.0.1:8443",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start must stay best-effort for HTTPS and return nil, got %v", err)
	}
	if s.httpsLeg != nil {
		t.Fatal("precondition: a failed bind must install NO leg — if it ever installs one, " +
			"this test silently becomes a test about an installed leg and the assertion below " +
			"stops being vacuous by accident rather than by design")
	}
	if s.HTTPSServing() {
		t.Fatal("a failed HTTPS bind must not report as serving (#6827 round 5)")
	}
}

// TestUnexpectedServeExitLeavesADeadInstalledLeg_6827 binds the `dead` clause of
// listenerLeg.serving() on the state production actually produces: the serve
// loop exits on its own, sets `dead`, and the leg stays INSTALLED in s.httpsLeg
// (it cannot be removed there — that would need lifeMu, which deadlocks a
// shutdown racing the exit, #6401 round 3).
//
// The flag is set by serveLegLocked, not by the test, so this is the complement
// of the hand-built subtests in TestWarnStaleMgmtCertForHostName_6827 — those
// store `dead` themselves and stay green if production stops setting it.
//
// RED on revert: delete `leg.dead.Store(true)` from serveLegLocked's serveErr
// arm, or drop `!l.dead.Load()` from serving(), and a leg whose socket is gone
// reports as serving and gets diagnosed.
func TestUnexpectedServeExitLeavesADeadInstalledLeg_6827(t *testing.T) {
	s, cancel := startWithDeadHTTPSLeg(t, mintCert(t, "old-fw", "10.0.0.1"), "10.0.0.1:8443")
	defer cancel()

	if s.HTTPSServing() {
		t.Fatal("a leg whose serve loop terminated unexpectedly is still INSTALLED, but no " +
			"socket is behind it: HTTPSServing must report false")
	}
	out := captureWarn(t, func() {
		if s.WarnStaleMgmtCertForHostName("new-fw") {
			t.Error("a dead leg presents no certificate, so the question is UNanswered and the " +
				"caller still owes the diagnosis")
		}
	})
	if out != "" {
		t.Fatalf("a dead leg must not be diagnosed; got %q", out)
	}
}

// TestReconcileHTTPSReplacesADeadLeg_6827 is the FAIL-ON-REVERT guard for the
// #6827-round-6 BLOCKER: a dead HTTPS leg was a permanent dead end.
//
// An unexpected serve exit leaves the leg installed with `dead` set. The
// same-address no-op then read `s.httpsLeg != nil && addr matches` and returned
// nil, so even a reconcile aimed directly at the configured address could not
// rebind — HTTPS stayed down for the life of the process on an UNCHANGED
// configuration, and with it every debt that can only be settled against a
// served certificate (the host-name staleness diagnosis). Nothing short of a
// restart escaped it.
//
// RED on revert: restore `case s.httpsLeg != nil && s.httpsLeg.srv.Addr == addr`
// in ReconcileHTTPS and the reconcile returns nil having done nothing — the same
// dead leg is still installed and HTTPSServing stays false.
func TestReconcileHTTPSReplacesADeadLeg_6827(t *testing.T) {
	const addr = "10.0.0.1:8443"
	cert := mintCert(t, "old-fw", "10.0.0.1")
	s, cancel := startWithDeadHTTPSLeg(t, cert, addr)
	defer cancel()
	dead := s.httpsLeg

	// The address is UNCHANGED — this is the reconcile an operator's next commit
	// makes on a configuration they never touched.
	s.certGen = func(string) (tls.Certificate, *x509.Certificate, error) { return cert, nil, nil }
	s.listen = func(network, a string) (net.Listener, error) { return newStubLn(), nil }
	if err := s.ReconcileHTTPS(true, addr); err != nil {
		t.Fatalf("reconcile over a dead leg: %v", err)
	}

	if s.httpsLeg == dead {
		t.Fatal("the reconcile left the DEAD leg installed: a same-address call was treated as " +
			"converged because the pointer was non-nil, so HTTPS can never come back without a " +
			"daemon restart (#6827 round 6)")
	}
	if !s.HTTPSServing() {
		t.Fatal("after a reconcile to the configured address the HTTPS leg must be serving again")
	}
	// The consequence that makes it a blocker rather than a cosmetic one: with a
	// certificate served again, an outstanding diagnosis is deliverable.
	if !s.WarnStaleMgmtCertForHostName("new-fw") {
		t.Fatal("the replacement leg must present a certificate, so a pending host-name " +
			"diagnosis can finally be discharged")
	}
}

// killableLn is a REAL loopback listener whose accept loop can be made to fail
// PERMANENTLY on demand, leaving the connections it already accepted untouched.
//
// That combination is the whole point, and it is what errLn cannot express:
// errLn fails from the first Accept, so a leg built on it never has a connection
// to lose. Production's unexpected serve-loop exit is the other shape — the
// listener dies under a leg that has been serving, and the sockets it handed to
// http.Server outlive it.
type killableLn struct {
	net.Listener
	killed chan struct{}
}

func newKillableLn(t *testing.T) *killableLn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return &killableLn{Listener: ln, killed: make(chan struct{})}
}

func (l *killableLn) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		return c, nil
	}
	select {
	case <-l.killed:
		// Report a plain error rather than the underlying net.ErrClosed: it is
		// not a net.Error, so http.Server.Serve cannot classify it as temporary
		// and retry — it returns, which is the exit serveLegLocked's serveErr arm
		// exists for.
		return nil, errors.New("listener terminated")
	default:
		return nil, err
	}
}

// kill closes the LISTENING socket only. Every connection already accepted stays
// open and stays served by the leg's http.Server — the state the pre-round-7
// code described as "the socket is already closed, nothing left to drain".
func (l *killableLn) kill() { close(l.killed); _ = l.Listener.Close() }

// requestOn replays one authenticated request on an already-established
// connection and returns its status. It writes the request by hand instead of
// using an http.Client so the test controls WHICH connection carries it: a
// Transport is free to open a fresh one, and a fresh connection would reach the
// replacement leg and prove nothing about the dead leg's.
func requestOn(conn net.Conn, br *bufio.Reader, host, user, secret string) (int, error) {
	cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + secret))
	req := "GET /api/v1/system/info HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Authorization: Basic " + cred + "\r\n\r\n"
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return 0, err
	}
	if _, err := io.WriteString(conn, req); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Drain the body so the connection stays reusable for the next replay.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return 0, err
	}
	return resp.StatusCode, nil
}

// TestDeadLegConnectionCannotOutliveRevocation_6827 is the FAIL-ON-REVERT guard
// for the #6827-round-7 credential-lifetime defect: a leg that self-terminated
// went on serving the connections it had already accepted, under a credential
// the operator had since revoked.
//
// The trace has three steps and every one of them is production's:
//
//  1. An unexpected serve-loop exit marked the leg `dead` and returned. Serve
//     closes the LISTENER, so nothing new arrives — but the HTTP/1 keep-alive
//     and HTTP/2 connections it already accepted keep being served by the same
//     http.Server, under the same credential slot. `drained` went up anyway, set
//     by the goroutine's defer, with those connections still live.
//  2. The recovery reconcile (#6827 round 6) installs a replacement and retires
//     the dead leg, which PINS its slot to whatever the server-wide snapshot
//     holds at that instant — the pre-revocation credential.
//  3. The next commit revokes it. ReplaceAuth walks the retiring legs to tighten
//     their pins, but pruneRetiredLocked drops this one FIRST, because `drained`
//     says it is finished. The pin is never intersected, and the surviving
//     connection keeps being admitted by the revoked credential.
//
// The three existing recovery cells cannot see any of it: they drive the exit
// with errLn, which fails from the first Accept, so no connection is ever
// accepted and there is nothing to survive. The case was unreachable in the
// fixture, not absent from production.
//
// RED on revert: delete the `drainLeg(srv)` call from serveLegLocked's serveErr
// arm. The kill leaves the held connection open, and the final replay is
// answered 200 by the dead leg under the revoked credential.
func TestDeadLegConnectionCannotOutliveRevocation_6827(t *testing.T) {
	const user, secret = "operator", "s3cret-6827"
	cert := mintCert(t, "old-fw", "127.0.0.1")

	kln := newKillableLn(t)
	addr := kln.Addr().String()

	s := &Server{
		// The pre-auth base the per-listener auth gate wraps. A bare 200 is the
		// sharpest possible signal for this cell: reaching it means the gate
		// ADMITTED the request, which is the thing under test — not what any
		// particular route would have returned.
		sharedBase: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		certGen: func(string) (tls.Certificate, *x509.Certificate, error) { return cert, nil, nil },
	}
	firstBind := true
	s.listen = func(network, a string) (net.Listener, error) {
		if firstBind {
			firstBind = false
			return kln, nil
		}
		// The replacement leg needs to exist and report serving; nothing in this
		// cell connects to it, so it never has to accept anything.
		return newStubLn(), nil
	}
	s.auth.Store(&AuthConfig{Users: map[string]string{user: secret}})
	// Build the leg the PRODUCTION way, so the handler's slot and the leg's slot
	// are the same object. A hand-built http.Server would leave serveLegLocked
	// substituting a slot the handler never reads, and the pin/tighten path this
	// cell is about would be bypassed entirely.
	s.httpsSlot = s.newAuthSlot()
	srv, err := s.buildHTTPSServer(addr, s.httpsSlot)
	if err != nil {
		t.Fatalf("build HTTPS server: %v", err)
	}
	s.httpsServer = srv

	ctx, cancel := context.WithCancel(context.Background())
	defer s.Wait() // runs after cancel(): joins both legs' serve goroutines
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	dead := s.httpsLeg
	if dead == nil {
		t.Fatal("precondition: the listen call succeeded, so the HTTPS leg must be installed")
	}

	// One connection, held open across everything that follows. The certificate
	// is a self-signed fixture and chain validation is not what this cell is
	// about, so the client skips verification.
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed fixture
	if err != nil {
		t.Fatalf("dial the HTTPS leg: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	code, err := requestOn(conn, br, addr, user, secret)
	if err != nil {
		t.Fatalf("precondition request on the held connection: %v", err)
	}
	if code != http.StatusOK {
		t.Fatalf("precondition: the credential must be ACCEPTED on this connection before "+
			"anything is revoked, otherwise the assertion below passes for the wrong reason; got %d", code)
	}

	// (1) The listener dies under the leg. The held connection is untouched.
	//
	// Wait, not a poll: it joins the one leg this server has, so the exit path
	// has fully run by the time it returns and the state below is settled rather
	// than sampled (#6827 round 7 — a polled precondition on a flag under test
	// reds as a deadline expiry and hides which assertion actually fired).
	kln.kill()
	s.Wait()
	if !dead.dead.Load() || !dead.drained.Load() {
		t.Fatalf("precondition: after the serve goroutine returned, a self-terminated leg must "+
			"read dead AND drained; got dead=%v drained=%v", dead.dead.Load(), dead.drained.Load())
	}

	// (2) Recovery on an UNCHANGED configuration retires the dead leg, pinning
	// its slot at the credential that is about to be revoked.
	if err := s.ReconcileHTTPS(true, addr); err != nil {
		t.Fatalf("recovery reconcile over the dead leg: %v", err)
	}
	if s.httpsLeg == dead {
		t.Fatal("precondition: the recovery reconcile must install a REPLACEMENT leg — without " +
			"the retirement of the dead one there is no pin, and this cell is not testing the " +
			"path it claims (#6827 round 6)")
	}

	// (3) The next commit revokes the credential the held connection is using.
	s.ReplaceAuth(&AuthConfig{Users: map[string]string{"successor": "different-secret"}})

	// `drained` — asserted above, before the recovery — is the flag
	// pruneRetiredLocked spends to stop tightening this leg's pin. The leg's
	// claim is that nothing can still be presenting credentials on it. This is
	// the request that tests the claim.
	code, err = requestOn(conn, br, addr, user, secret)
	if err == nil && code == http.StatusOK {
		t.Fatalf("a connection accepted by a leg that has since died and been retired was still "+
			"admitted (%d) under a REVOKED credential: the leg reports drained, so ReplaceAuth "+
			"has stopped tightening its pinned slot, and nothing else will ever revoke it "+
			"(#6827 round 7)", code)
	}
}

// streamFixture is a leg serving ONE endless streaming response, held open by a
// client, so a test can end the leg underneath an IN-FLIGHT response.
//
// The endlessness is load-bearing. Shutdown closes IDLE connections outright, so
// a fixture whose handler returns leaves nothing for the force-close to do and
// passes with `Close` deleted — vacuously. The handler here keeps writing until
// its connection dies, which is what makes Shutdown WAIT and then give up.
// The fixture keeps the raw CONNECTION and not the response body: the body is a
// chunked reader, and a chunked reader is permanently poisoned by the first read
// deadline — see assertConnSevered (#6827 round 10). The body is still read once
// at construction, where no deadline is in play, to establish the precondition.
type streamFixture struct {
	s    *Server
	leg  *listenerLeg
	kln  *killableLn
	conn net.Conn
}

// newStreamFixture starts an HTTPS leg on a real loopback socket, opens one
// connection, and returns once a streaming response is in flight — headers read
// and at least one chunk received, so the handler is provably past its first
// flush and the connection is ACTIVE rather than idle.
func newStreamFixture(t *testing.T, ctx context.Context) *streamFixture {
	t.Helper()
	cert := mintCert(t, "old-fw", "127.0.0.1")
	kln := newKillableLn(t)
	addr := kln.Addr().String()

	// No WriteTimeout is set by buildHTTPSServer, deliberately (SSE + large
	// scrapes). That property is what gives an in-flight response an unbounded
	// life, so the fixture must not "fix" it with a timeout of its own — doing so
	// would sever the stream for a reason that has nothing to do with drainLeg.
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	s := &Server{
		sharedBase: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			f, ok := w.(http.Flusher)
			if !ok {
				return
			}
			f.Flush()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := io.WriteString(w, "tick\n"); err != nil {
					return // the connection went away: severed, or the test ended
				}
				f.Flush()
				time.Sleep(2 * time.Millisecond)
			}
		}),
		certGen: func(string) (tls.Certificate, *x509.Certificate, error) { return cert, nil, nil },
	}
	s.listen = func(network, a string) (net.Listener, error) { return kln, nil }
	s.httpsSlot = s.newAuthSlot()
	srv, err := s.buildHTTPSServer(addr, s.httpsSlot)
	if err != nil {
		t.Fatalf("build HTTPS server: %v", err)
	}
	s.httpsServer = srv
	if err := s.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	leg := s.httpsLeg
	if leg == nil {
		t.Fatal("precondition: the listen call succeeded, so the HTTPS leg must be installed")
	}

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed fixture
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, "GET /stream HTTP/1.1\r\nHost: "+addr+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response headers: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	buf := make([]byte, 8)
	if _, err := resp.Body.Read(buf); err != nil {
		t.Fatalf("precondition: the response must be IN FLIGHT before the leg ends, so the "+
			"connection is ACTIVE rather than idle and the drain has something to wait on; "+
			"first chunk read failed: %v", err)
	}
	return &streamFixture{s: s, leg: leg, kln: kln, conn: conn}
}

// assertConnSevered blocks until the peer has CLOSED c, and distinguishes that
// from "nothing arrived recently" — which is the whole difficulty (#6827
// round 9). what names the property being asserted; it is prefixed to the
// failure so one helper can serve several cells.
//
// Three ways to get this wrong, all of which this helper shipped at some point:
//
//   - trusting ONE read. After the server closes a connection the client still
//     returns bytes that were already buffered — measured: three reads and 19
//     bytes before the error surfaced — so a single successful read proves
//     nothing about liveness, and a single failed one may just be the buffer
//     boundary.
//   - trusting ANY error. The round-8 version returned on the first error of
//     any kind, including the 250ms read deadline it sets itself. A stream that
//     is merely PAUSED — open, tracked, and free to resume — passes that. The
//     assertion has to be "the peer closed it", not "it went quiet".
//   - reading through the RESPONSE BODY, which round 9 did while claiming a
//     timeout was "a reason to keep waiting" (#6827 round 10). For a chunked
//     body it cannot be: internal/chunked.chunkedReader STORES the first error
//     and guards its loop with `for cr.err == nil`, so every later Read returns
//     that same timeout instantly without touching the socket. Replayed against
//     a connection the server really HAD closed, the round-9 loop spun
//     3,066,552 times in its 3s bound, read 0 bytes, counted 3,066,552
//     timeouts, and reported the connection open. It burned a core to reach a
//     false RED.
//
// So it reads the RAW connection. crypto/tls is explicit that a deadline is not
// sticky — readRecordOrCCS calls setErrorLocked only when the error is not a
// temporary net.Error, and a deadline is both (conn.go, go1.26) — so a timeout
// here really is recoverable and really does mean "ask again". Only a
// non-timeout error (EOF, reset, use-of-closed) proves closure.
//
// If the overall bound expires the failure reports what was MEASURED — reads,
// bytes, timeouts, and whether any bytes arrived during the wait — and nothing
// more. Round 9 labelled the outcome "STILL STREAMING" or "OPEN BUT SILENT"
// from bytes-read-since-loop-start, which is a function of WHEN the loop
// started rather than of the connection's state, so one state could earn either
// label. The two are not distinguishable from this side and the helper no
// longer claims to distinguish them.
func assertConnSevered(t *testing.T, c net.Conn, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 512)
	var total, reads, timeouts int
	for {
		if err := c.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		n, err := c.Read(buf)
		total += n
		reads++
		var ne net.Error
		switch {
		case err == nil:
			// Bytes are still flowing: the response outlived its leg.
		case errors.As(err, &ne) && ne.Timeout():
			// OUR deadline, not the peer's close. Says nothing either way.
			timeouts++
		default:
			return // the peer closed it, which is the assertion
		}
		if time.Now().After(deadline) {
			arrival := "no bytes arrived during the wait"
			if total > 0 {
				arrival = "bytes arrived during the wait"
			}
			t.Fatalf("%s: the connection was still OPEN %v later (%d reads, %d bytes, %d read "+
				"timeouts; %s)", what, 3*time.Second, reads, total, timeouts, arrival)
		}
	}
}

// assertSevered is assertConnSevered aimed at this fixture's one held stream.
func (f *streamFixture) assertSevered(t *testing.T) {
	t.Helper()
	assertConnSevered(t, f.conn, "Shutdown waits for an in-flight response and gives up on it "+
		"at the deadline, so without the force-close a leg reports drained while a client can "+
		"still be attached to it under a policy nothing will ever tighten (#6827 round 8)")
}

// TestInFlightResponseIsSeveredOnEveryLegExit_6827 is the FAIL-ON-REVERT guard
// for `drainLeg`'s FORCE-CLOSE, on all three ways a leg ends.
//
// Round 7 added the drain and wrote "the force-close is not optional" — and
// bound none of it. `_ = srv.Close()` could be deleted, or the retirement and
// root-context arms reverted to the pre-round-7 bare `Shutdown`, with
// `go test ./pkg/api/` still green. The only bound property was that the
// serve-exit arm called `drainLeg` at all.
//
// What escapes without the Close is exactly what the round-7 prose claimed to
// have closed: Shutdown WAITS for an in-flight response and, at the deadline,
// returns and leaves it running. The leg then stores `drained` — the flag
// `pruneRetiredLocked` reads as "nothing left for a revocation to reach" — while
// a response authorized under the old policy is still being delivered.
//
// RED on revert (each measured over the whole package): delete `_ = srv.Close()`
// from drainLeg, or replace the `drainLeg(srv)` call in the stopCh/rootDone arm
// with a bare bounded `srv.Shutdown`, and the stream survives its leg.
//
// SCOPE, because the shape of this cell suggests more than it proves: the
// fixture holds exactly ONE connection. assertSevered's bounded wait is sound
// for that, and it is NOT evidence of a per-leg wall-clock bound. There is no
// such bound, and legDrainTimeout does not supply one for EITHER phase — it is
// a POLL deadline, and both phases put serial per-connection closes in front of
// it: Shutdown reaches its `select { case <-ctx.Done() }` only when
// closeIdleConns() returns false, and closeIdleConns walks the connection set
// one at a time; the Close that follows takes no context at all and walks it
// serially too. On an HTTPS leg each of those closes is a *tls.Conn sending
// close_notify under a five-second write deadline of its OWN, so the real worst
// case grows with connection count in both phases (see legDrainTimeout). What
// this cell binds is that the deadline arm severs rather than abandons, which
// is a property of the arm and holds at any N.
func TestInFlightResponseIsSeveredOnEveryLegExit_6827(t *testing.T) {
	// The deadline arm is what these cases exercise, and reaching it costs the
	// timeout. ONE case pays the production 5s so the shipped value is exercised
	// end to end; the other two shorten it, because what expiry DOES is a
	// property of the arm rather than of the number, and 15s in every future run
	// of this package buys the same assertion three times.
	// TestLegDrainTimeoutDefault_6827 pins the shipped value separately, so a
	// leaked override cannot quietly retune production.
	for _, tc := range []struct {
		name          string
		productionCap bool
		end           func(t *testing.T, f *streamFixture, cancel context.CancelFunc)
	}{
		{
			// serveLegLocked's serveErr arm: the listener dies under a leg that
			// is mid-response. This is the arm the original defect was in, so it
			// is the one that runs at the real 5s deadline.
			name:          "unexpected_serve_exit",
			productionCap: true,
			end:           func(_ *testing.T, f *streamFixture, _ context.CancelFunc) { f.kln.kill() },
		},
		{
			// The stopCh arm, reached the way production reaches it: a commit
			// that turns HTTPS off retires the leg.
			name: "requested_retirement",
			end: func(t *testing.T, f *streamFixture, _ context.CancelFunc) {
				if err := f.s.ReconcileHTTPS(false, ""); err != nil {
					t.Fatalf("disable HTTPS: %v", err)
				}
			},
		},
		{
			// The rootDone arm: daemon shutdown.
			name: "root_context_shutdown",
			end:  func(_ *testing.T, _ *streamFixture, cancel context.CancelFunc) { cancel() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.productionCap {
				restore := legDrainTimeout
				t.Cleanup(func() { legDrainTimeout = restore })
				legDrainTimeout = 150 * time.Millisecond
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := newStreamFixture(t, ctx)

			tc.end(t, f, cancel)
			f.s.Wait() // the leg's goroutine has returned, so the drain is over

			if !f.leg.drained.Load() {
				t.Fatal("precondition: after the serve goroutine returned the leg must report drained")
			}
			f.assertSevered(t)
		})
	}
}

// TestServingFlipsDuringTheDrainNotAfterIt_6827 is the FAIL-ON-REVERT guard for
// the ORDER of the two statements in serveLegLocked's unexpected-serve-exit arm:
// `leg.dead.Store(true)` BEFORE `drainLeg(srv)`, not after.
//
// The order is load-bearing and, until round 10, entirely unbound — moving the
// store below the drain left `go test ./pkg/api/` AND `./pkg/daemon/` green
// (#6827 round 10). Nothing existing could see it: every other dead-leg cell
// (TestUnexpectedServeExitLeavesADeadInstalledLeg_6827,
// TestReconcileHTTPSReplacesADeadLeg_6827) kills a leg that has NO connection,
// so its drain returns in microseconds and both orders look identical. The
// window only opens when there is something to drain — which is the case this
// whole change exists for.
//
// What the window costs, measured: pristine flips serving() false in ~220ns;
// with the store moved, HTTPSServing() is still true a second later, and the
// real width is the whole drain, which has no wall-clock ceiling (see
// legDrainTimeout). Throughout it:
//
//   - ReconcileHTTPS(true, sameAddr) takes the serving() no-op arm and returns
//     nil, so an operator commit does NOT rebuild the leg whose socket is gone;
//   - reconcileTo's `next.TLS && !m.srv.HTTPSServing()` recovery term is false,
//     so the reconciler above it does not even reach that call;
//   - WarnStaleMgmtCertForHostName diagnoses a certificate no socket is
//     presenting — the exact false positive serving() exists to prevent.
//
// The cell asserts BOTH halves, and the second is what stops it going vacuous:
// serving() must go false quickly, AND it must do so while `drained` is still
// unset. Without that, a cell could pass on a leg that simply finished draining,
// which is the state the mutation reaches too, just later.
func TestServingFlipsDuringTheDrainNotAfterIt_6827(t *testing.T) {
	// Long enough that "during the drain" is unambiguous against the poll bound
	// below, short enough that the join at the end is not a 5s tax. What the
	// order DOES is a property of the arm, not of the number; the shipped value
	// is pinned by TestLegDrainTimeoutDefault_6827.
	restore := legDrainTimeout
	t.Cleanup(func() { legDrainTimeout = restore })
	legDrainTimeout = 2 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newStreamFixture(t, ctx)
	if !f.s.HTTPSServing() {
		t.Fatal("precondition: the fixture's leg is bound and streaming, so it must report serving")
	}

	// Kill the LISTENING socket only. The held stream stays up, so the drain
	// that follows has something to wait on and runs for the full deadline.
	start := time.Now()
	f.kln.kill()

	const flipBound = 750 * time.Millisecond
	for f.s.HTTPSServing() {
		if elapsed := time.Since(start); elapsed > flipBound {
			t.Fatalf("HTTPSServing() was STILL true %v after the listening socket died (drained=%v). "+
				"`dead` must be stored BEFORE drainLeg, not after: the drain has no wall-clock "+
				"ceiling, and for its whole width a same-address ReconcileHTTPS takes the "+
				"serving() no-op arm and returns nil — so an operator commit cannot rebuild the "+
				"leg — while WarnStaleMgmtCertForHostName diagnoses a certificate no socket is "+
				"presenting (#6827 round 10)", elapsed, f.leg.drained.Load())
		}
		time.Sleep(200 * time.Microsecond)
	}
	flip := time.Since(start)

	// The observation has to be DURING the drain or it proves nothing about the
	// order — after the drain both versions agree.
	if f.leg.drained.Load() {
		t.Fatalf("serving() went false after %v, but the leg had ALREADY finished draining, so "+
			"this observation cannot tell the two statement orders apart. The fixture holds an "+
			"endless stream and legDrainTimeout is %v, so the drain must still have been running "+
			"here; if it was not, the fixture stopped modelling an in-flight response and this "+
			"cell has gone vacuous (#6827 round 10)", flip, legDrainTimeout)
	}

	f.s.Wait() // join the leg goroutine so the drain does not outlive the test
	if !f.leg.drained.Load() {
		t.Fatal("precondition: after the serve goroutine returned the leg must report drained")
	}
}

// holdStream opens one connection to addr, asks for the endless stream, and
// returns once a chunk of the response has arrived — so the connection is
// ACTIVE rather than idle and the drain has something to wait on. It returns
// the RAW connection for the same reason streamFixture keeps one: a chunked
// body reader is permanently poisoned by its first read deadline, so
// assertConnSevered cannot use it (#6827 round 10).
func holdStream(t *testing.T, addr string, useTLS bool) net.Conn {
	t.Helper()
	var conn net.Conn
	var err error
	if useTLS {
		conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed fixture
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		t.Fatalf("dial %s (tls=%v): %v", addr, useTLS, err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline (tls=%v): %v", useTLS, err)
	}
	if _, err := io.WriteString(conn, "GET /stream HTTP/1.1\r\nHost: "+addr+"\r\n\r\n"); err != nil {
		t.Fatalf("write request (tls=%v): %v", useTLS, err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response headers (tls=%v): %v", useTLS, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if _, err := resp.Body.Read(make([]byte, 8)); err != nil {
		t.Fatalf("precondition (tls=%v): the response must be IN FLIGHT before the shutdown, so "+
			"the connection is ACTIVE rather than idle and the drain has something to wait on; "+
			"first chunk read failed: %v", useTLS, err)
	}
	return conn
}

// TestServeBoundSeversInFlightResponses_6827 is the FAIL-ON-REVERT guard for
// Server.serveBound's drain (#6827 round 10).
//
// serveBound kept the exact shape drainLeg exists to fix long after drainLeg
// existed: a bare Shutdown under a deadline, with no Close, so an in-flight
// response survived the shutdown that was supposed to end it. Round 9 edited its
// doc ("bounded 5s drain" -> "5s-deadline drain") without touching the
// behaviour, which left pkg/api/README.md's package-wide drain invariant FALSE
// about this function and left the shape in the tree for the next reader to
// copy.
//
// It is test-only today — Server.Run has no production caller, the daemon uses
// NewServer + Start — and that is a reason it was cheap to fix, not a reason to
// have shipped it.
//
// RED on revert: replace EITHER drainLeg call in serveBound with a bare
// `Shutdown` and that leg's held stream outlives the call. Both legs are run,
// with a stream held on each, because serveBound drains them through separate
// statements — round 10's own revert mutation flipped BOTH at once, so the
// bound HTTP leg redded the cell and hid the fact that the HTTPS statement was
// unbound (this fixture passed nil for httpsLn). A compound mutation cannot
// localise; #6827 round 11 split it and found the hole.
//
// The returned error is asserted too, for the same reason: it is what drainLeg
// grew a return value for.
func TestServeBoundSeversInFlightResponses_6827(t *testing.T) {
	restore := legDrainTimeout
	t.Cleanup(func() { legDrainTimeout = restore })
	legDrainTimeout = 150 * time.Millisecond // reach the deadline arm cheaply

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	addr := ln.Addr().String()
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback HTTPS listener: %v", err)
	}
	httpsAddr := httpsLn.Addr().String()

	// Endless, for the same reason streamFixture's handler is: Shutdown closes
	// an IDLE connection outright, so a handler that returns leaves the
	// force-close nothing to do and the cell passes vacuously.
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	endless := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, ok := w.(http.Flusher)
		if !ok {
			return
		}
		f.Flush()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := io.WriteString(w, "tick\n"); err != nil {
				return // the connection went away: severed, or the test ended
			}
			f.Flush()
			time.Sleep(2 * time.Millisecond)
		}
	})

	// BOTH legs, sharing ONE handler. serveBound drains the two servers through
	// SEPARATE statements, so each needs its own held stream or the untested one
	// can be reverted with the package still green — which is exactly what an
	// httpsServer-nil fixture allowed until round 11.
	cert := mintCert(t, "fw", "127.0.0.1")
	s := &Server{
		sharedBase: endless,
		certGen:    func(string) (tls.Certificate, *x509.Certificate, error) { return cert, nil, nil },
		httpServer: &http.Server{Addr: addr, Handler: endless},
	}
	s.httpsSlot = s.newAuthSlot()
	httpsSrv, err := s.buildHTTPSServer(httpsAddr, s.httpsSlot)
	if err != nil {
		t.Fatalf("build HTTPS server: %v", err)
	}
	s.httpsServer = httpsSrv

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.serveBound(ctx, ln, httpsLn) }()

	conn := holdStream(t, addr, false)
	tlsConn := holdStream(t, httpsAddr, true)

	cancel()
	select {
	case err := <-done:
		// ASSERTED, not logged (#6827 round 11). drainLeg returns the Shutdown
		// error precisely so serveBound can keep reporting it, and both doc
		// comments say so; with the value only logged, `return err` could become
		// `return nil` and the whole package stayed green. Deterministic here:
		// both connections are ACTIVE, so closeIdleConns can never report
		// quiescence and Shutdown MUST reach its deadline.
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("serveBound returned %v, want a %v: both legs held an ACTIVE stream, so "+
				"each Shutdown had to run out its %v deadline and drainLeg had to hand that "+
				"error back for serveBound to report (#6827 round 11)",
				err, context.DeadlineExceeded, legDrainTimeout)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("serveBound did not return after ctx cancellation")
	}

	const severed = "serveBound returned with an in-flight response still being " +
		"delivered: Shutdown WAITS for it and abandons it at the deadline, so without the " +
		"force-close pkg/api/README.md's package-wide drain invariant is false about this " +
		"function and the shape stays in the tree to be copied (#6827 round 10)"
	assertConnSevered(t, conn, "HTTP leg: "+severed)
	// The HTTPS leg is drained by a SEPARATE statement, and until round 11 no
	// cell reached it: this fixture passed nil for httpsLn, so reverting that
	// one statement to a bare Shutdown left both packages green.
	assertConnSevered(t, tlsConn, "HTTPS leg: "+severed)
}

// #7039: the rename-path host-name WARN fired on a loopback-only HTTPS bind,
// where the BIND-HOST half of the same diagnostic already declines
// (`bindHostWarnable("127.0.0.1")` is false). On that plane no remote client
// exists, so nothing can verify by host name and a re-mint would fix nothing.
//
// THE FIX IS A SUPPRESSION, so the cells that matter are the ones proving it did
// not over-suppress. A test showing only "loopback no longer warns" is satisfied
// by deleting the warning outright, so every silence cell below is paired with a
// bind on which the warning MUST still fire, through the same call, with every
// other condition held identical.
func TestLoopbackOnlyBindSuppressesTheRenameHostNameWarn_7039(t *testing.T) {
	// A cert covering the OLD name plus the loopback SANs the mint path always
	// adds — the shape a loopback-bound appliance actually serves.
	for _, bind := range []string{"127.0.0.1:443", "[::1]:443", "localhost:443"} {
		t.Run("silent_on_"+bind, func(t *testing.T) {
			s := legServing(mintCert(t, "old-fw", "127.0.0.1"), bind)
			out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
			if strings.Contains(out, hostNameMsg) {
				t.Fatalf("a rename on a LOOPBACK-only management bind warned about "+
					"clients verifying by host-name, but no remote client exists on "+
					"that plane — this is the diagnostic firing on a healthy box, "+
					"which is how the true positive gets muted (#7039); got %q", out)
			}
		})
	}

	// THE PAIRED CELLS. Same call, same cert shape, same rename — only the bind
	// differs, and on each of these the warning MUST still fire.
	for _, tc := range []struct {
		name, bind, why string
	}{
		{
			"routable_ip", "10.0.0.1:8443",
			"a routable management bind has remote clients, and the host name is " +
				"exactly the identity they would verify",
		},
		{
			// The cell that separates this fix from the obvious drop-in.
			// bindHostWarnable("0.0.0.0") is FALSE, so suppressing on
			// !bindHostWarnable would silence the diagnostic on the most
			// remote-reachable bind there is.
			"wildcard_v4", "0.0.0.0:8443",
			"a WILDCARD bind is reachable from every interface. bindHostWarnable " +
				"answers false for it — because it names no single host, not because " +
				"it is unreachable — so a fix written as !bindHostWarnable would " +
				"suppress precisely the case the diagnostic exists for",
		},
		{
			"wildcard_v6", "[::]:8443",
			"the v6 wildcard, same reasoning as 0.0.0.0",
		},
	} {
		t.Run("still_warns_on_"+tc.name, func(t *testing.T) {
			s := legServing(mintCert(t, "old-fw", "127.0.0.1"), tc.bind)
			out := captureWarn(t, func() { s.WarnStaleMgmtCertForHostName("new-fw") })
			if !strings.Contains(out, hostNameMsg) {
				t.Fatalf("OVER-SUPPRESSED: a rename on %s must still warn — %s. "+
					"got %q", tc.bind, tc.why, out)
			}
			if !strings.Contains(out, "new-fw") {
				t.Fatalf("the surviving warning must still name the NEW host name; got %q", out)
			}
		})
	}
}

// #7039: `bindIsLoopbackOnly` is NOT the complement of `bindHostWarnable`, and
// this pins the divergence rather than leaving it to a comment.
//
// The two answer different questions — "can only this host reach the listener"
// versus "is there a single concrete host worth warning about" — and they
// disagree on the wildcard binds, which is the disagreement that matters: a fix
// written as `!bindHostWarnable(bindHost)` would silence the host-name
// diagnostic on `0.0.0.0`.
//
// If someone later makes them coincide, this fails and they have to decide
// deliberately rather than discovering it through a muted warning.
func TestLoopbackOnlyIsNotTheComplementOfBindHostWarnable_7039(t *testing.T) {
	cases := []struct {
		bindHost         string
		wantWarnable     bool
		wantLoopbackOnly bool
	}{
		{"", false, false},
		{"localhost", false, true},
		{"127.0.0.1", false, true},
		{"127.0.0.53", false, true},
		{"::1", false, true},
		{"0.0.0.0", false, false},
		{"::", false, false},
		{"10.0.0.1", true, false},
		{"fw.example.com", true, false},
	}
	// Anti-vacuity backstop. It is NOT enough that SOME row has both predicates
	// false: the empty bindHost does too, and that row is a parse FAILURE, not a
	// reachable listener. The claim this table exists to support is specifically
	// that a WILDCARD bind — reachable from everywhere — is suppressed by the
	// `!bindHostWarnable` drop-in and not by this predicate. So the backstop
	// requires a row that actually parses as an unspecified address.
	divergedOnWildcard := false
	for _, tc := range cases {
		gotW, gotL := bindHostWarnable(tc.bindHost), bindIsLoopbackOnly(tc.bindHost)
		if gotW != tc.wantWarnable || gotL != tc.wantLoopbackOnly {
			t.Errorf("bindHost %q: bindHostWarnable=%v (want %v) bindIsLoopbackOnly=%v (want %v)",
				tc.bindHost, gotW, tc.wantWarnable, gotL, tc.wantLoopbackOnly)
		}
		ip := net.ParseIP(tc.bindHost)
		if ip != nil && ip.IsUnspecified() && !gotW && !gotL {
			divergedOnWildcard = true
		}
	}
	if !divergedOnWildcard {
		t.Fatal("no WILDCARD bind (an address that parses and is unspecified) had " +
			"bindHostWarnable=false AND bindIsLoopbackOnly=false, so this table no " +
			"longer demonstrates that the `!bindHostWarnable` drop-in would " +
			"over-suppress the most remote-reachable listener there is (#7039)")
	}
}

package api

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// #7041. The #6827 liveness disjunct in the daemon's reconciler re-enters
// ReconcileHTTPS on EVERY commit while HTTPS is wanted and not serving. That is
// the wanted behaviour — it is what stopped a dead leg being a restart-only dead
// end. But ReconcileHTTPS built the leg BEFORE it bound, and building loads the
// on-disk certificate (certGen has no cache: LoadX509KeyPair re-reads the pair
// and warnStaleLoadedCert re-runs on every call). So on a box whose HTTPS bind
// fails persistently AND whose durable cert is stale, every commit re-emitted
// the full stale-cert diagnostic, forever.
//
// These tests drive the REAL production loader (SetTLSCertDirForTest routes
// through generateSelfSignedCertAt) against a seeded temp dir and count the
// actual operator-visible warning text. They do not count certGen calls: the
// property is what an operator reads in the log, and a call count is a probe
// keyed to the implementation that happens to produce it.

// seedStaleFor writes a durable pair into a fresh temp dir that does NOT cover
// bindHost, and returns the dir. Minting is silent (the diagnostic only runs on
// the LOAD path), so nothing is captured here.
func seedStaleFor(t *testing.T, uncovered string) string {
	t.Helper()
	resetTLSSeams(t)
	tlsHostname = func() (string, error) { return "seed-fw-7041", nil }
	dir := t.TempDir()
	// bindHost "" => loopback/localhost SANs only, so `uncovered` is not covered.
	if _, err := generateSelfSignedCertAt(dir, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), ""); err != nil {
		t.Fatalf("seed durable pair: %v", err)
	}
	// Precondition: a LOAD against the target bind must actually warn, or every
	// count below is trivially zero and the tests prove nothing.
	s := &Server{}
	s.SetTLSCertDirForTest(dir)
	host, _, _ := net.SplitHostPort(uncovered)
	out := captureWarn(t, func() { _, _, _ = s.certGen(host) })
	if !strings.Contains(out, bindHostMsg) {
		t.Fatalf("precondition: a load for bind host %q must emit %q, else these "+
			"cells count an absence that was never possible; got %q", host, bindHostMsg, out)
	}
	return dir
}

// countingLn is a net.Listener whose Close is idempotent and counted, so a test
// can assert the reordered arm does not LEAK the socket it bound. (stubLn's
// Close panics on a second call, which would mask a double-close as a crash.)
type countingLn struct {
	mu     sync.Mutex
	closes int
	done   chan struct{}
}

func newCountingLn() *countingLn                { return &countingLn{done: make(chan struct{})} }
func (l *countingLn) Accept() (net.Conn, error) { <-l.done; return nil, net.ErrClosed }
func (l *countingLn) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 8443} }
func (l *countingLn) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closes++
	if l.closes == 1 {
		close(l.done)
	}
	return nil
}
func (l *countingLn) closeCount() int { l.mu.Lock(); defer l.mu.Unlock(); return l.closes }

const addr7041 = "10.0.0.1:8443"

// TestFailedHTTPSBindDoesNotReloadTheCertificate_7041 is the defect cell. A leg
// that cannot bind serves no client, so there is nothing a certificate can be
// stale FOR until the bind succeeds.
func TestFailedHTTPSBindDoesNotReloadTheCertificate_7041(t *testing.T) {
	dir := seedStaleFor(t, addr7041)
	s := &Server{listen: func(string, string) (net.Listener, error) {
		return nil, errors.New("bind: cannot assign requested address")
	}}
	s.SetTLSCertDirForTest(dir)

	const commits = 3
	out := captureWarn(t, func() {
		for i := 0; i < commits; i++ {
			if err := s.ReconcileHTTPS(true, addr7041); err == nil {
				t.Fatal("precondition: the bind must FAIL in this cell")
			}
		}
	})
	if n := strings.Count(out, bindHostMsg); n != 0 {
		t.Fatalf("a persistently failing HTTPS bind re-emitted the stale-cert diagnostic "+
			"%d time(s) across %d commits. The #6827 liveness disjunct re-enters "+
			"ReconcileHTTPS on every commit, so building the leg (and loading the cert) "+
			"BEFORE binding republishes the whole diagnostic forever on a box that can "+
			"never serve it (#7041); got %q", n, commits, out)
	}
}

// TestFirstHTTPSBindFailureStillReportsTheBindError_7041 is the paired cell for
// the one above: suppressing the CERT diagnostic must not suppress the failure
// itself. The reconcile still errors, every time, so the caller still records
// retry debt and the daemon still logs its own reconcile warnings.
func TestFirstHTTPSBindFailureStillReportsTheBindError_7041(t *testing.T) {
	dir := seedStaleFor(t, addr7041)
	s := &Server{listen: func(string, string) (net.Listener, error) {
		return nil, errors.New("bind: cannot assign requested address")
	}}
	s.SetTLSCertDirForTest(dir)

	for i := 1; i <= 3; i++ {
		err := s.ReconcileHTTPS(true, addr7041)
		if err == nil {
			t.Fatalf("attempt %d: a failing bind must return an error every time — the "+
				"reconcile error is what the daemon turns into retry debt; silencing it "+
				"would convert a noisy fault into an invisible one", i)
		}
		if !strings.Contains(err.Error(), "bind HTTPS listener") {
			t.Fatalf("attempt %d: the error must name the BIND as the failure; got %v", i, err)
		}
	}
	if s.HTTPSServing() {
		t.Fatal("a failing bind must leave HTTPS not serving (fail-closed)")
	}
}

// TestHTTPSCertDiagnosticReturnsWhenTheBindRecovers_7041 is the cell that proves
// the suppression is bounded in TIME, not permanent: the moment a bind succeeds,
// the diagnostic an operator needs is emitted.
func TestHTTPSCertDiagnosticReturnsWhenTheBindRecovers_7041(t *testing.T) {
	dir := seedStaleFor(t, addr7041)
	fail := true
	s := &Server{listen: func(string, string) (net.Listener, error) {
		if fail {
			return nil, errors.New("bind: cannot assign requested address")
		}
		return newCountingLn(), nil
	}}
	s.SetTLSCertDirForTest(dir)
	t.Cleanup(func() { _ = s.ReconcileHTTPS(false, "") })

	// Two commits while the bind is down: silent.
	downOut := captureWarn(t, func() {
		for i := 0; i < 2; i++ {
			_ = s.ReconcileHTTPS(true, addr7041)
		}
	})
	if n := strings.Count(downOut, bindHostMsg); n != 0 {
		t.Fatalf("while the bind was down the diagnostic fired %d time(s); got %q", n, downOut)
	}

	// The address comes back. The very next commit must speak.
	fail = false
	upOut := captureWarn(t, func() {
		if err := s.ReconcileHTTPS(true, addr7041); err != nil {
			t.Fatalf("precondition: the bind must SUCCEED here: %v", err)
		}
	})
	if n := strings.Count(upOut, bindHostMsg); n != 1 {
		t.Fatalf("OVER-SUPPRESSED: once the HTTPS bind recovers the stale-cert diagnostic "+
			"must be emitted exactly once — a listener that can serve has clients that "+
			"will fail strict verification, which is the whole point of the warning. "+
			"got %d occurrence(s) in %q", n, upOut)
	}
	if !s.HTTPSServing() {
		t.Fatal("after a successful bind the HTTPS leg must be serving")
	}
}

// TestHTTPSCertFailureAfterBindClosesTheListener_7041 binds the hazard the
// reordering introduces. Binding first means a cert failure happens with a
// socket already held. Leaking it would keep the port and turn a transient cert
// fault into a PERMANENT EADDRINUSE on every retry — manufacturing the very
// failure this change exists to stop repeating.
func TestHTTPSCertFailureAfterBindClosesTheListener_7041(t *testing.T) {
	ln := newCountingLn()
	certErr := errors.New("cert: unreadable key material")
	s := &Server{
		listen: func(string, string) (net.Listener, error) { return ln, nil },
		certGen: func(string) (tls.Certificate, *x509.Certificate, error) {
			return tls.Certificate{}, nil, certErr
		},
	}
	before := s.httpsLeg

	err := s.ReconcileHTTPS(true, addr7041)
	if err == nil || !errors.Is(err, certErr) {
		t.Fatalf("a cert failure must be returned so the caller retains the previous leg; got %v", err)
	}
	if got := ln.closeCount(); got != 1 {
		t.Fatalf("the listener was closed %d time(s), want exactly 1.\n"+
			"  0 means either the bind never happened (the pre-#7041 order: build "+
			"first, so a cert failure returned before any socket was obtained) or the "+
			"reordered arm obtained one and LEAKED it. The second is the hazard this "+
			"reordering introduces: a held port makes every later retry fail EADDRINUSE, "+
			"turning a transient cert fault into a permanent bind failure — the very "+
			"failure #7041 exists to stop repeating.\n"+
			"  >1 means it was double-closed.", got)
	}
	if s.httpsLeg != before {
		t.Fatal("a cert failure must retain the previous HTTPS state (fail-closed)")
	}
	if s.HTTPSServing() {
		t.Fatal("a cert failure must not leave HTTPS serving")
	}
}

// TestBindErrorWinsWhenBothFail_7041 pins a deliberate, operator-visible
// consequence of the reordering rather than leaving it to be discovered.
//
// Before #7041 the cert was resolved first, so a box with BOTH a failing bind
// and an unreadable cert reported the CERT error. It now reports the BIND error.
// That is the better of the two — the bind is the more fundamental failure, and
// the cert error was describing work done for a listener that could never serve
// — but it IS a change in what the daemon logs and what `errs` carries, so it is
// asserted here rather than left implicit.
func TestBindErrorWinsWhenBothFail_7041(t *testing.T) {
	bindErr, certErr := errors.New("bind: cannot assign requested address"), errors.New("cert: unreadable key material")
	s := &Server{
		listen: func(string, string) (net.Listener, error) { return nil, bindErr },
		certGen: func(string) (tls.Certificate, *x509.Certificate, error) {
			return tls.Certificate{}, nil, certErr
		},
	}
	err := s.ReconcileHTTPS(true, addr7041)
	if err == nil {
		t.Fatal("both legs failing must still return an error")
	}
	if !errors.Is(err, bindErr) {
		t.Fatalf("with both failing the BIND error must be reported (it is the more "+
			"fundamental failure, and the cert was resolved for a listener that can "+
			"never serve); got %v", err)
	}
	if errors.Is(err, certErr) {
		t.Fatalf("the cert error must NOT be reported when the bind already failed — "+
			"binding first means the cert is never resolved on that path, which is the "+
			"whole point of #7041; got %v", err)
	}
}

// TestAChangedBindErrorStillSpeaks_7041 answers the standard failure mode of
// this class of fix directly, even though this fix cannot exhibit it.
//
// The usual way a "stop the repeated noise" change goes wrong is a dedup keyed
// on "still not serving": the second and later attempts are swallowed wholesale,
// so a bind failure that has BECOME A DIFFERENT FAILURE — EADDRNOTAVAIL because
// the interface address went away, then EADDRINUSE because something else took
// the port — is silently absorbed. That transition is precisely the diagnostic
// an operator needs, and it is invisible to a latch that only knows "still down".
//
// This fix carries no dedup at all: it reorders bind and build, so the bind error
// is produced and returned by the same path on every attempt. The cell is here to
// pin that, so a later "optimisation" that adds a latch has to red this test
// rather than discover the consequence in the field. It passes both before and
// after the reordering, which is the right shape for a property the change must
// preserve rather than establish.
func TestAChangedBindErrorStillSpeaks_7041(t *testing.T) {
	dir := seedStaleFor(t, addr7041)
	errs := []error{
		errors.New("cannot assign requested address"),
		errors.New("cannot assign requested address"),
		errors.New("address already in use"), // the failure CHANGED
	}
	i := 0
	s := &Server{listen: func(string, string) (net.Listener, error) {
		e := errs[i]
		i++
		return nil, e
	}}
	s.SetTLSCertDirForTest(dir)

	var got []string
	for range errs {
		err := s.ReconcileHTTPS(true, addr7041)
		if err == nil {
			t.Fatal("every failing attempt must return an error")
		}
		got = append(got, err.Error())
	}
	if !strings.Contains(got[2], "address already in use") {
		t.Fatalf("the THIRD attempt's bind failed for a DIFFERENT reason and that "+
			"change must reach the caller — a dedup keyed on \"still not serving\" "+
			"would swallow it, hiding the transition an operator most needs to see "+
			"(#7041); got %q", got[2])
	}
	if got[0] == got[2] {
		t.Fatalf("the first and third errors must differ; the fixture is not varying "+
			"the failure, so this cell would pass without testing anything: %q", got[0])
	}
	if i != len(errs) {
		t.Fatalf("the listener factory was consulted %d time(s), want %d — a suppressed "+
			"attempt would not have reached it at all", i, len(errs))
	}
}

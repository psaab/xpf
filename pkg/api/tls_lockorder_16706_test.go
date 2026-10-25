package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// #16706: AB-BA lock inversion between HTTPS leg rebuild
// (lifeMu -> tlsCertificateMu in buildHTTPSServer) and the TLS
// monitor's leg recovery (formerly tlsCertificateMu -> lifeMu in
// recoverHTTPSLegsIfNeededLocked). Once wedged, lifeMu is held
// forever so every later commit/apply blocks until daemon restart.
//
// The fix defers recovery until tlsCertificateMu is released, so the
// only nesting is lifeMu -> tlsCertificateMu. These tests force the
// exact overlap that deadlocked. The certGen / listen seams widen
// the windows deterministically; no lock is added by the test.

// TestTLSLockOrderInterleavedRefreshAndRebuild16706 is the
// FAIL-ON-REVERT guard. The refresh goroutine is parked inside its
// cert load (holding tlsCertificateMu) first; the rebuild goroutine
// then takes lifeMu and blocks on tlsCertificateMu in
// buildHTTPSServer. On the pre-fix code, releasing the cert load
// lets refresh install and then block on lifeMu inside recovery
// while STILL holding tlsCertificateMu — permanent deadlock, caught
// by the timeout below. On the fixed code recovery runs after the
// cert lock is released, so both complete.
func TestTLSLockOrderInterleavedRefreshAndRebuild16706(t *testing.T) {
	cert := mintCert(t, "fw", "127.0.0.1")

	refreshInGen := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s := &Server{
		sharedBase: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
		listen: func(string, string) (net.Listener, error) {
			return newStubLn(), nil
		},
	}
	s.tlsCertificateFiles.Store(&managementTLSCertificateFiles{})
	s.certGen = func([]string) (tls.Certificate, *x509.Certificate, error) {
		once.Do(func() { close(refreshInGen) })
		<-release
		return cert, nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.rootCtx = ctx
	s.tlsDesiredConfigured.Store(true)
	s.tlsDesired.Store(true)
	s.httpsDesiredAddrs = []string{"127.0.0.1:0"}
	// With no current state the generated refresh proceeds to certGen
	// (the parked seam above): the reinstall tick the issue requires
	// (rotated/repaired/expired/boot-failure recovery). The rebuild
	// side needs no current state: buildHTTPSServer always loads
	// under tlsCertificateMu.

	refreshDone := make(chan struct{})
	go func() {
		// Monitor tick: tlsCertificateMu -> (install) -> recovery.
		s.refreshManagementTLSCertificate()
		close(refreshDone)
	}()
	select {
	case <-refreshInGen:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh never reached certGen; fixture did not exercise the lock paths")
	}

	reconcileDone := make(chan error, 1)
	go func() {
		// Apply path: lifeMu -> planHTTPSLeg -> buildHTTPSServer
		// -> tlsCertificateMu.
		reconcileDone <- s.ReconcileHTTPSAddrs(true, []string{"127.0.0.1:0"})
	}()
	// Let the rebuild take lifeMu and block on tlsCertificateMu.
	time.Sleep(200 * time.Millisecond)
	close(release)

	deadline := time.After(5 * time.Second)
	var refreshOK, reconcileOK bool
	for !refreshOK || !reconcileOK {
		select {
		case <-refreshDone:
			refreshOK = true
		case err := <-reconcileDone:
			if err != nil {
				t.Fatalf("ReconcileHTTPSAddrs: %v", err)
			}
			reconcileOK = true
		case <-deadline:
			t.Fatalf("DEADLOCK (#16706): refresh done=%v reconcile done=%v after 5s — "+
				"lifeMu/tlsCertificateMu acquired in opposite orders", refreshOK, reconcileOK)
		}
	}
	cancel()
	s.Wait()
}

// TestTLSRefreshDoesNotHoldCertMuDuringRecovery16706 pins the
// mechanism directly: while recovery is parked inside its listen
// seam (holding lifeMu), tlsCertificateMu must be free — a
// concurrent buildHTTPSServer (the rebuild path's cert load) must
// complete. On the pre-fix code recovery ran under tlsCertificateMu,
// so the probe build would block for the whole recovery.
func TestTLSRefreshDoesNotHoldCertMuDuringRecovery16706(t *testing.T) {
	cert := mintCert(t, "fw", "127.0.0.1")

	recoveryEntered := make(chan struct{})
	releaseRecovery := make(chan struct{})
	var once sync.Once
	s := &Server{
		sharedBase: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}),
		listen: func(string, string) (net.Listener, error) {
			once.Do(func() {
				close(recoveryEntered)
				<-releaseRecovery
			})
			return newStubLn(), nil
		},
		certGen: func([]string) (tls.Certificate, *x509.Certificate, error) {
			return cert, nil, nil
		},
	}
	s.tlsCertificateFiles.Store(&managementTLSCertificateFiles{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.rootCtx = ctx
	s.tlsDesiredConfigured.Store(true)
	s.tlsDesired.Store(true)
	s.httpsDesiredAddrs = []string{"127.0.0.1:0"}

	refreshDone := make(chan struct{})
	go func() {
		s.refreshManagementTLSCertificate()
		close(refreshDone)
	}()

	select {
	case <-recoveryEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh never reached HTTPS-leg recovery; fixture broken")
	}

	// Recovery is now parked holding lifeMu. The cert lock must be
	// free: buildHTTPSServer takes tlsCertificateMu -> load -> unlock.
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		srv, err := s.buildHTTPSServer("127.0.0.1:0", s.newAuthSlot())
		if err != nil {
			t.Errorf("buildHTTPSServer during recovery: %v", err)
			return
		}
		if srv == nil {
			t.Error("buildHTTPSServer during recovery returned nil server")
		}
	}()
	select {
	case <-probeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("buildHTTPSServer blocked during recovery: tlsCertificateMu is held " +
			"across recoverHTTPSLegsIfNeeded (tlsCertificateMu -> lifeMu inversion, #16706)")
	}

	close(releaseRecovery)
	select {
	case <-refreshDone:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not finish after recovery was released")
	}
	cancel()
	s.Wait()
}

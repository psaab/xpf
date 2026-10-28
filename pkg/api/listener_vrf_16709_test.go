package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
)

// Unit cells for the #16709 scope bookkeeping (no kernel VRF needed).
// The real-kernel bind is proven by TestWebMgmtVRFBind16709Netns in
// pkg/daemon, which drives the production factory through
// resolveAPIBinds + managementReconciler in a network namespace with
// fxp0 enslaved to vrf-mgmt.
//
// FAIL-ON-REVERT: dropping SetBindDevices' snapshot (or listenAddr's
// scoped branch) leaves bindDeviceFor empty and the first cell RED;
// swallowing the BINDTODEVICE error in bindToDeviceControl makes the
// nonexistent-device cell bind successfully and go RED.

func TestBindDeviceSnapshot16709(t *testing.T) {
	s := &Server{}
	// Bare fixture: no snapshot -> unscoped.
	if got := s.bindDeviceFor("192.0.2.5:443"); got != "" {
		t.Fatalf("bindDeviceFor on bare server = %q, want unscoped", got)
	}
	s.SetBindDevices(map[string]string{"192.0.2.5:443": "vrf-mgmt", "10.0.0.1:80": ""})
	if got := s.bindDeviceFor("192.0.2.5:443"); got != "vrf-mgmt" {
		t.Fatalf("bindDeviceFor scoped = %q, want vrf-mgmt", got)
	}
	// ""-valued entries are dropped by cloneBindDevices.
	if got := s.bindDeviceFor("10.0.0.1:80"); got != "" {
		t.Fatalf("bindDeviceFor empty-valued = %q, want unscoped", got)
	}
	if got := s.BindDevices(); len(got) != 1 || got["192.0.2.5:443"] != "vrf-mgmt" {
		t.Fatalf("BindDevices = %v, want only the vrf-mgmt entry", got)
	}
	// Clearing restores the unscoped default.
	s.SetBindDevices(nil)
	if got := s.bindDeviceFor("192.0.2.5:443"); got != "" {
		t.Fatalf("bindDeviceFor after clear = %q, want unscoped", got)
	}
	if got := s.BindDevices(); got != nil {
		t.Fatalf("BindDevices after clear = %v, want nil", got)
	}
}

// TestReconcileHTTPPreservesHTTPSBindScope16709 is the dual-plane
// control: reconciling HTTP must not erase the still-installed HTTPS
// leg's recorded bind device. The following HTTPS reconcile must adopt
// that socket without attempting a colliding same-address bind.
func TestReconcileHTTPPreservesHTTPSBindScope16709(t *testing.T) {
	const httpAddr = "192.0.2.5:80"
	const httpsAddr = "192.0.2.5:443"
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open HTTP fixture listener: %v", err)
	}
	defer httpLn.Close()
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("open HTTPS fixture listener: %v", err)
	}
	defer httpsLn.Close()

	s := &Server{}
	s.SetBindDevices(map[string]string{httpAddr: "vrf-mgmt", httpsAddr: "vrf-mgmt"})
	s.httpLegs = []*listenerLeg{{srv: &http.Server{Addr: httpAddr}, ln: httpLn}}
	s.httpsLegs = []*listenerLeg{{srv: &http.Server{Addr: httpsAddr}, ln: httpsLn}}
	s.legDevices = map[string]string{httpAddr: "vrf-mgmt", httpsAddr: "vrf-mgmt"}
	bindAttempts := 0
	s.listen = func(_, _ string) (net.Listener, error) {
		bindAttempts++
		return nil, net.ErrClosed
	}
	s.customListen = true
	if err := s.ReconcileHTTPAddrs([]string{httpAddr}); err != nil {
		t.Fatalf("reconcile unchanged HTTP leg: %v", err)
	}
	if err := s.ReconcileHTTPSAddrs(true, []string{httpsAddr}); err != nil {
		t.Fatalf("reconcile unchanged HTTPS leg after HTTP: %v", err)
	}
	if bindAttempts != 0 {
		t.Fatalf("HTTP/HTTPS control attempted %d unnecessary binds", bindAttempts)
	}
	s.lifeMu.Lock()
	gotHTTP := s.legDeviceLocked(httpAddr)
	gotHTTPS := s.legDeviceLocked(httpsAddr)
	s.lifeMu.Unlock()
	if gotHTTP != "vrf-mgmt" {
		t.Fatalf("HTTP scope = %q, want vrf-mgmt", gotHTTP)
	}
	if gotHTTPS != "vrf-mgmt" {
		t.Fatalf("HTTPS scope = %q, want vrf-mgmt", gotHTTPS)
	}
}

// TestScopedSnapshotSurvivesStart16709 pins that a Config-provided
// scope is installed on the server (the daemon's startLocked path
// builds the server from the desired config, whose BindDevices must
// reach listenAddr). It uses an injected factory so no real socket is
// bound to a possibly-nonexistent device, and pins that the injected
// factory is never bypassed by the scoped path.
func TestScopedSnapshotSurvivesStart16709(t *testing.T) {
	regLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("seed listener: %v", err)
	}
	defer regLn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(Config{
		Addr:        "127.0.0.1:0",
		BindDevices: map[string]string{"127.0.0.1:0": "vrf-mgmt"},
		ListenFunc: func(_, _ string) (net.Listener, error) {
			return regLn, nil
		},
	})
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { cancel(); s.Wait() }()
	if got := s.BindDevices(); got["127.0.0.1:0"] != "vrf-mgmt" {
		t.Fatalf("BindDevices after Start = %v, want vrf-mgmt scope recorded", got)
	}
	if !s.listenIsCustom() {
		t.Fatal("injected ListenFunc must mark customListen so the scoped path never bypasses it")
	}
}

// TestBindToDeviceControlNonexistentDeviceFails16709 pins that the
// control propagates the setsockopt failure instead of swallowing it
// into an unscoped bind.
func TestBindToDeviceControlNonexistentDeviceFails16709(t *testing.T) {
	lc := net.ListenConfig{Control: bindToDeviceControl("xpf-no-such-dev-16709")}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err == nil {
		ln.Close()
		t.Fatal("bind scoped to a nonexistent device succeeded; the BINDTODEVICE error was swallowed")
	}
	if !strings.Contains(err.Error(), "xpf-no-such-dev-16709") {
		t.Fatalf("scoped bind error = %v, want it to name the device", err)
	}
}

// TestUnscopedBindUnaffected16709 is the control: with no BindDevices
// the production bind is the plain net.Listen behaviour.
func TestUnscopedBindUnaffected16709(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(Config{Addr: "127.0.0.1:0"})
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start unscoped: %v", err)
	}
	defer func() { cancel(); s.Wait() }()
	addrs := s.EffectiveHTTPAddrs()
	if len(addrs) != 1 {
		t.Fatalf("EffectiveHTTPAddrs = %v, want one leg", addrs)
	}
	assertHTTP200(t, "http://"+addrs[0]+"/health")
}

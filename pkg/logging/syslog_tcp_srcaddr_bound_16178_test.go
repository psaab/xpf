package logging

// #16178: dialTCP/dialTLS resolved the source address with the
// package-level net.ResolveTCPAddr — no context, no deadline — before
// dialing, while the 5 s net.Dialer/tls.Dialer only bounds the remote
// connect. A hostname source address (strict config forces an IP
// literal, but the tolerant/peer-loaded path can hand anything in)
// performs an unbounded DNS lookup that can stall syslog client
// (re)connection indefinitely. The UDP sibling was already fixed by
// #14613 (resolveUDPAddrBounded under a bounded context).
//
// Decisive check mirrors #14613: a lookup seam that blocks until its
// context is cancelled (black-holed DNS) proves the bound exists iff
// dialTCP/dialTLS return promptly with a context.DeadlineExceeded-
// wrapping error and the "resolve source" taxonomy intact. RED
// evidence: with either dial reverted to net.ResolveTCPAddr, the seam
// is never consulted — the blocking cells fail because the error does
// not wrap DeadlineExceeded (real DNS "no such host" for the .invalid
// name) or the 5 s watchdog fires.
//
// Literal/zone/family cells pin resolveTCPAddrBounded against
// net.ResolveTCPAddr semantics without external network; the success
// cells prove a resolved source hostname still binds and delivers over
// real TCP and TLS listeners.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// blockingLookup16178 returns only when ctx is cancelled — the shape of
// a black-holed resolver from the caller's point of view (same seam
// shape as #14613's blockingLookup14613).
func blockingLookup16178(ctx context.Context, host string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func installBlockingLookup16178(t *testing.T) {
	t.Helper()
	origLookup := lookupSyslogIPAddr
	origTimeout := syslogDialTimeout
	lookupSyslogIPAddr = blockingLookup16178
	syslogDialTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		lookupSyslogIPAddr = origLookup
		syslogDialTimeout = origTimeout
	})
}

// dialWithWatchdog16178 runs dial in a goroutine and returns its error,
// failing the test if it does not return within the watchdog window.
func dialWithWatchdog16178(t *testing.T, name string, dial func() (net.Conn, error)) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		conn, err := dial()
		if conn != nil {
			_ = conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("#16178: %s did not return within 5 s against a black-holed "+
			"resolver — source resolution is unbounded (net.ResolveTCPAddr "+
			"carries no deadline)", name)
		return nil
	}
}

func TestTCPSourceAddrResolveBounded16178(t *testing.T) {
	installBlockingLookup16178(t)
	c := &SyslogClient{
		remoteAddr:        "127.0.0.1:6514",
		sourceAddr:        "source-16178.invalid",
		protocol:          "tcp",
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}
	err := dialWithWatchdog16178(t, "dialTCP", c.dialTCP)
	if err == nil {
		t.Fatal("#16178: dialTCP with a hostname source succeeded — the " +
			"blocking resolver seam was not consulted or its cancellation " +
			"was swallowed")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("#16178: dialTCP source resolve error = %v, want it to wrap "+
			"context.DeadlineExceeded (the 5 s bound firing)", err)
	}
	if !strings.Contains(err.Error(), "resolve source") {
		t.Fatalf("#16178: dialTCP error = %q, want the existing \"resolve "+
			"source\" taxonomy preserved", err)
	}
}

func TestTLSSourceAddrResolveBounded16178(t *testing.T) {
	installBlockingLookup16178(t)
	c := &SyslogClient{
		remoteAddr:        "127.0.0.1:6514",
		sourceAddr:        "source-16178.invalid",
		protocol:          "tls",
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}
	err := dialWithWatchdog16178(t, "dialTLS", c.dialTLS)
	if err == nil {
		t.Fatal("#16178: dialTLS with a hostname source succeeded — the " +
			"blocking resolver seam was not consulted or its cancellation " +
			"was swallowed")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("#16178: dialTLS source resolve error = %v, want it to wrap "+
			"context.DeadlineExceeded (the 5 s bound firing)", err)
	}
	if !strings.Contains(err.Error(), "resolve source") {
		t.Fatalf("#16178: dialTLS error = %q, want the existing \"resolve "+
			"source\" taxonomy preserved", err)
	}
}

// Table: literal, zone and family selection of resolveTCPAddrBounded,
// checked against net.ResolveTCPAddr's semantics (no external network:
// every hostname goes through the injected seam, literals parse in-process).
func TestResolveTCPAddrBoundedForms16178(t *testing.T) {
	ctx := context.Background()
	t.Run("ipv4 literal", func(t *testing.T) {
		got, err := resolveTCPAddrBounded(ctx, "tcp", "192.0.2.1:514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("192.0.2.1")) || got.Port != 514 || got.Zone != "" {
			t.Fatalf("got %v, want 192.0.2.1:514", got)
		}
	})
	t.Run("ipv6 literal with zone", func(t *testing.T) {
		got, err := resolveTCPAddrBounded(ctx, "tcp", "[fe80::1%eth0]:514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("fe80::1")) || got.Port != 514 || got.Zone != "eth0" {
			t.Fatalf("got %v, want [fe80::1%%eth0]:514", got)
		}
	})
	t.Run("ipv6 literal with multi-percent zone", func(t *testing.T) {
		// Go splits the zone at the FIRST '%': [fe80::1%eth%0]:0 is the
		// literal fe80::1 with zone "eth%0" (verified against
		// net.ResolveTCPAddr), NOT hostname fe80::1%eth with zone 0.
		// A last-'%' split mis-parses it as a hostname and consults the
		// resolver — install a seam that fails if ever consulted.
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return nil, fmt.Errorf("lookup seam consulted for literal host %q", host)
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		got, err := resolveTCPAddrBounded(ctx, "tcp", "[fe80::1%eth%0]:0")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("fe80::1")) || got.Port != 0 || got.Zone != "eth%0" {
			t.Fatalf("got %v, want [fe80::1%%eth%%0]:0", got)
		}
	})
	t.Run("udp resolver multi-percent zone", func(t *testing.T) {
		// Same first-'%' invariant for the #14613 sibling sharing this
		// split: [fe80::1%eth%0]:0 must stay a literal, never a lookup.
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return nil, fmt.Errorf("lookup seam consulted for literal host %q", host)
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		got, err := resolveUDPAddrBounded(ctx, "udp", "[fe80::1%eth%0]:0")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("fe80::1")) || got.Port != 0 || got.Zone != "eth%0" {
			t.Fatalf("got %v, want [fe80::1%%eth%%0]:0", got)
		}
	})
	t.Run("ipv6 literal", func(t *testing.T) {
		got, err := resolveTCPAddrBounded(ctx, "tcp6", "[2001:db8::1]:514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("2001:db8::1")) || got.Port != 514 {
			t.Fatalf("got %v, want [2001:db8::1]:514", got)
		}
	})
	t.Run("empty host", func(t *testing.T) {
		got, err := resolveTCPAddrBounded(ctx, "tcp", ":514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got.IP != nil || got.Port != 514 {
			t.Fatalf("got %v, want :514 with nil IP", got)
		}
	})
	t.Run("tcp prefers ipv4", func(t *testing.T) {
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("2001:db8::2")},
				{IP: net.ParseIP("192.0.2.2")},
			}, nil
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		got, err := resolveTCPAddrBounded(ctx, "tcp", "src-16178.example:514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("192.0.2.2")) {
			t.Fatalf("got %v, want first IPv4 192.0.2.2", got)
		}
	})
	t.Run("tcp6 skips ipv4", func(t *testing.T) {
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("192.0.2.3")},
				{IP: net.ParseIP("2001:db8::3")},
			}, nil
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		got, err := resolveTCPAddrBounded(ctx, "tcp6", "src-16178.example:514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("2001:db8::3")) {
			t.Fatalf("got %v, want IPv6 2001:db8::3", got)
		}
	})
	t.Run("tcp4 skips ipv6", func(t *testing.T) {
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("2001:db8::4")},
				{IP: net.ParseIP("192.0.2.4")},
			}, nil
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		got, err := resolveTCPAddrBounded(ctx, "tcp4", "src-16178.example:514")
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if !got.IP.Equal(net.ParseIP("192.0.2.4")) {
			t.Fatalf("got %v, want IPv4 192.0.2.4", got)
		}
	})
	t.Run("hostname zone preserved", func(t *testing.T) {
		origLookup := lookupSyslogIPAddr
		// The seam receives the full host (including %zone), matching
		// resolveUDPAddrBounded's contract.
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host != "src-16178.example%eth1" {
				return nil, fmt.Errorf("unexpected lookup host %q", host)
			}
			return []net.IPAddr{{IP: net.ParseIP("fe80::5")}}, nil
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		got, err := resolveTCPAddrBounded(ctx, "tcp", "[src-16178.example%eth1]:514")
		// SplitHostPort strips brackets; the host argument is the bare name+zone.
		if err != nil {
			got2, err2 := resolveTCPAddrBounded(ctx, "tcp", "src-16178.example%eth1:514")
			if err2 != nil {
				t.Fatalf("resolve: bracketed=%v bare=%v", err, err2)
			}
			got = got2
		}
		if !got.IP.Equal(net.ParseIP("fe80::5")) || got.Zone != "eth1" {
			t.Fatalf("got %v, want [fe80::5%%eth1]:514", got)
		}
	})
	t.Run("no suitable address", func(t *testing.T) {
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return nil, nil
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		if _, err := resolveTCPAddrBounded(ctx, "tcp", "src-16178.example:514"); err == nil ||
			!strings.Contains(err.Error(), "no suitable address found") {
			t.Fatalf("err = %v, want \"no suitable address found\"", err)
		}
	})
	t.Run("tcp4 with ipv6 literal fails", func(t *testing.T) {
		if _, err := resolveTCPAddrBounded(ctx, "tcp4", "[2001:db8::1]:514"); err == nil ||
			!strings.Contains(err.Error(), "no suitable address found") {
			t.Fatalf("err = %v, want \"no suitable address found\" (stdlib family filter)", err)
		}
	})
	t.Run("tcp6 with ipv4 literal fails", func(t *testing.T) {
		if _, err := resolveTCPAddrBounded(ctx, "tcp6", "192.0.2.1:514"); err == nil ||
			!strings.Contains(err.Error(), "no suitable address found") {
			t.Fatalf("err = %v, want \"no suitable address found\" (stdlib family filter)", err)
		}
	})
	t.Run("tcp6 with only ipv4 fails", func(t *testing.T) {
		origLookup := lookupSyslogIPAddr
		lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("192.0.2.6")}}, nil
		}
		t.Cleanup(func() { lookupSyslogIPAddr = origLookup })
		if _, err := resolveTCPAddrBounded(ctx, "tcp6", "src-16178.example:514"); err == nil ||
			!strings.Contains(err.Error(), "no suitable address found") {
			t.Fatalf("err = %v, want \"no suitable address found\"", err)
		}
	})
}

// Success control: a hostname source that resolves (via the seam) still
// binds that source and connects over TCP to a real listener.
func TestTCPSourceAddrHostnameBindsAndDials16178(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	origLookup := lookupSyslogIPAddr
	lookupSyslogIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "src-16178.example" {
			return nil, fmt.Errorf("unexpected host %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	t.Cleanup(func() { lookupSyslogIPAddr = origLookup })

	c := &SyslogClient{
		hostname:          "xpf",
		remoteAddr:        net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
		sourceAddr:        "src-16178.example",
		protocol:          "tcp",
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}
	conn, err := c.dialTCP()
	if err != nil {
		t.Fatalf("#16178: hostname source must dial after bounded resolution; got %v", err)
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || !la.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("#16178: bound local addr = %v, want 127.0.0.1 source bind", conn.LocalAddr())
	}
	accepted, err := ln.Accept()
	if err != nil {
		t.Fatalf("listener did not accept the source-bound TCP dial: %v", err)
	}
	_ = accepted.Close()
}

// Success control for TLS: literal source binds and the TLS handshake
// completes against a real TLS listener.
func TestTLSSourceAddrLiteralBindsAndDials16178(t *testing.T) {
	cert, pool := generateTestCert(t)
	tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tlsLn.Close()
	port := tlsLn.Addr().(*net.TCPAddr).Port

	acceptErr := make(chan error, 1)
	go func() {
		conn, err := tlsLn.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		defer conn.Close()
		if tc, ok := conn.(*tls.Conn); ok {
			acceptErr <- tc.Handshake()
			return
		}
		acceptErr <- fmt.Errorf("accepted conn is %T, want *tls.Conn", conn)
	}()

	c := &SyslogClient{
		hostname:          "xpf",
		remoteAddr:        net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
		sourceAddr:        "127.0.0.1",
		protocol:          "tls",
		tlsConfig:         &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"},
		Facility:          FacilityLocal0,
		writeTimeout:      defaultWriteTimeout,
		reconnectCooldown: defaultReconnectCooldown,
	}
	conn, err := c.dialTLS()
	if err != nil {
		t.Fatalf("#16178: literal-source TLS dial must succeed; got %v", err)
	}
	defer conn.Close()
	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || !la.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("#16178: bound local addr = %v, want 127.0.0.1 source bind", conn.LocalAddr())
	}
	select {
	case err := <-acceptErr:
		if err != nil {
			t.Fatalf("TLS handshake with source-bound client failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TLS accept/handshake")
	}
}

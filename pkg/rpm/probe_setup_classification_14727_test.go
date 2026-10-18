package rpm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #14727 (D19-05): every probe-setup failure must carry ErrProbeSetup so
// runSingleTestWithOptions HOLDS state (no SuccFail, no transition, no
// ip-monitoring actuation) instead of counting a never-sent probe as
// path loss. Three legs:
//
//  1. canonicalizeHTTPTarget and the probeHTTP request-construction
//     error returned unwrapped fmt.Errors despite the C179-042 comment
//     promising setup-failure (hold) semantics.
//  2. probeDialer / probeICMP accepted wildcard source-address
//     ("0.0.0.0" / "::"): net.ParseIP returns a non-nil unspecified IP,
//     so the probe bound the wildcard/kernel-chosen source and measured
//     the default path instead of the pinned one — defeating #2492's
//     stated intent ("would bind wildcard source").
//  3. A local source bind that fails with EADDRNOTAVAIL (configured
//     source-address not assigned on this box) surfaced from
//     probeTCP/probeHTTP as an ordinary dial failure counted as path
//     loss, even though the probe never left the box. Decisive check
//     from the issue: dial with LocalAddr = unassigned IP, no VRF opts,
//     and observe the classification.

func TestCanonicalizeHTTPTargetSetupErrors14727(t *testing.T) {
	for _, target := range []string{
		"",                       // no target
		":8080",                  // schemeless, no host (C179-042)
		"http://",                // schemed, no host
		"https://",               // schemed, no host
		"http://:80/health",      // schemed, no host, explicit port
		"ftp://host.example.com", // unsupported scheme
		"gopher://h.example.com", // unsupported scheme
		"http://exa mple.com/",   // url.Parse failure (invalid host char)
		"http://example.com/%zz", // url.Parse failure (invalid escape)
		"http://[fe80::1",        // url.Parse failure (unterminated bracketed host)
	} {
		if _, err := canonicalizeHTTPTarget(target); err == nil {
			t.Errorf("canonicalizeHTTPTarget(%q) = nil error, want ErrProbeSetup rejection", target)
		} else if !errors.Is(err, ErrProbeSetup) {
			t.Errorf("canonicalizeHTTPTarget(%q) err = %v, want ErrProbeSetup — "+
				"anything else is counted as PATH LOSS by runSingleTestWithOptions (#14727)", target, err)
		}
	}
	// Controls: valid targets still canonicalize unchanged.
	for target, want := range map[string]string{
		"server.example.com":       "http://server.example.com",
		"host.example.com:8080":    "http://host.example.com:8080",
		"http://host.example.com":  "http://host.example.com",
		"https://h.example.com/hb": "https://h.example.com/hb",
		"2001:db8::1":              "http://2001:db8::1", // schemeless leniency preserved
	} {
		got, err := canonicalizeHTTPTarget(target)
		if err != nil {
			t.Errorf("canonicalizeHTTPTarget(%q) err = %v, want nil (valid control)", target, err)
		} else if got != want {
			t.Errorf("canonicalizeHTTPTarget(%q) = %q, want %q", target, got, want)
		}
	}
}

func TestProbeHTTPSetupErrorsHold14727(t *testing.T) {
	m := New()
	for _, target := range []string{"", "http://", ":8080", "ftp://host.example.com", "http://exa mple.com/"} {
		test := &config.RPMTest{Name: "t", ProbeType: "http-get", Target: target}
		if _, err := m.probeHTTP(context.Background(), test, probeSockOpts{}); !errors.Is(err, ErrProbeSetup) {
			t.Errorf("probeHTTP(%q) err = %v, want ErrProbeSetup (hold, not path loss)", target, err)
		}
	}
}

func TestProbeDialerWildcardSourceRejected14727(t *testing.T) {
	for _, src := range []string{"0.0.0.0", "::"} {
		d, _, err := probeDialer(5*time.Second, src, probeSockOpts{})
		if !errors.Is(err, ErrProbeSetup) {
			t.Errorf("probeDialer(%q) err = %v, want ErrProbeSetup (wildcard source must not bind)", src, err)
		}
		if d != nil {
			t.Errorf("probeDialer(%q) returned non-nil dialer with error", src)
		}
	}
	// Controls: empty (default) and a concrete source still succeed.
	if d, _, err := probeDialer(5*time.Second, "", probeSockOpts{}); err != nil || d == nil || d.LocalAddr != nil {
		t.Errorf("probeDialer(\"\") = (%v, %v), want default dialer with no LocalAddr", d, err)
	}
	if d, _, err := probeDialer(5*time.Second, "10.0.0.5", probeSockOpts{}); err != nil || d == nil {
		t.Errorf("probeDialer(valid) = (%v, %v), want dialer", d, err)
	}
}

func TestProbeICMPWildcardSourceRejected14727(t *testing.T) {
	for _, src := range []string{"0.0.0.0", "::"} {
		listenCalled := false
		m := New()
		m.icmpListen = func(network, laddr string, opts probeSockOpts) (net.PacketConn, error) {
			listenCalled = true
			return &fakeICMPConn{replies: make(chan fakeReply, 1), failFast: true}, nil
		}
		test := &config.RPMTest{Name: "t", Target: "192.0.2.10", SourceAddress: src}
		if _, err := m.probeICMP(context.Background(), test, probeSockOpts{}); !errors.Is(err, ErrProbeSetup) {
			t.Errorf("probeICMP(source=%q) err = %v, want ErrProbeSetup before any socket is opened", src, err)
		}
		if listenCalled {
			t.Errorf("probeICMP(source=%q) opened a socket; wildcard source must be rejected first", src)
		}
	}
}

// The issue's decisive check, as a regression: a configured source that
// is not assigned locally makes the dial fail at bind (EADDRNOTAVAIL)
// before any packet leaves the box. That is a setup failure.
func TestProbeTCPUnassignedSourceIsSetup14727(t *testing.T) {
	m := New()
	test := &config.RPMTest{Name: "t", ProbeType: "tcp-ping", Target: "127.0.0.1", DestPort: 9, SourceAddress: "192.0.2.77"}
	if _, err := m.probeTCP(context.Background(), test, probeSockOpts{}); !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeTCP(unassigned source) err = %v, want ErrProbeSetup (EADDRNOTAVAIL bind, probe never left the box)", err)
	}
}

func TestProbeHTTPUnassignedSourceIsSetup14727(t *testing.T) {
	m := New()
	test := &config.RPMTest{Name: "t", ProbeType: "http-get", Target: "http://127.0.0.1:9/", SourceAddress: "192.0.2.77"}
	if _, err := m.probeHTTP(context.Background(), test, probeSockOpts{}); !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeHTTP(unassigned source) err = %v, want ErrProbeSetup (EADDRNOTAVAIL bind)", err)
	}
}

// Negative controls for leg 3: genuine path signals with a VALID local
// source (or none) must NOT be reclassified as setup.
func TestProbeGenuineLossNotSetup14727(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	m := New()
	tcpTest := &config.RPMTest{Name: "t", ProbeType: "tcp-ping", Target: "127.0.0.1", DestPort: port}
	if _, err := m.probeTCP(context.Background(), tcpTest, probeSockOpts{}); err == nil || errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeTCP(refused) err = %v, want genuine path failure (not setup)", err)
	}
	httpTest := &config.RPMTest{Name: "t", ProbeType: "http-get", Target: fmt.Sprintf("http://127.0.0.1:%d/", port)}
	if _, err := m.probeHTTP(context.Background(), httpTest, probeSockOpts{}); err == nil || errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeHTTP(refused) err = %v, want genuine path failure (not setup)", err)
	}
	// A refused dial FROM a valid assigned source (loopback) is also loss.
	loopTCP := &config.RPMTest{Name: "t", ProbeType: "tcp-ping", Target: "127.0.0.1", DestPort: port, SourceAddress: "127.0.0.1"}
	if _, err := m.probeTCP(context.Background(), loopTCP, probeSockOpts{}); err == nil || errors.Is(err, ErrProbeSetup) {
		t.Fatalf("probeTCP(refused, valid source) err = %v, want genuine path failure", err)
	}
	// Error text sanity for the canonicalizer message contract.
	if _, err := canonicalizeHTTPTarget("ftp://host.example.com"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported-scheme message changed: %v", err)
	}
}

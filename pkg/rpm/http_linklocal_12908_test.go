package rpm

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #12908: probeTCP and probeICMP resolve the IPv6 link-local scope through
// the shared resolveLinkLocalZone9026 guard (#9026), but probeHTTP was never
// wired into it — and an http-get target carries its host inside a URL, so
// even the probeTCP-style raw split cannot see it. An unscoped fe80:: literal
// reached http.Client, whose dial error this package counts as PATH LOSS
// (SuccFail++, state transition, `services ip-monitoring` failover) for a
// probe that never left the box. These cells bind the WIRING, not just the
// helper — the assertion is the ErrProbeSetup SENTINEL, because "probeHTTP
// returned an error" is satisfied by the defect itself.

// TestProbeHTTPHoldsOnAnUnscopeableLinkLocal12908 drives probeHTTP end to
// end. No network is needed for the defect cells: the guard fires before any
// dial, and on master the unscoped dial itself fails in-kernel with EINVAL
// (connect: invalid argument) without a packet leaving the box.
func TestProbeHTTPHoldsOnAnUnscopeableLinkLocal12908(t *testing.T) {
	m := &Manager{}
	for _, target := range []string{
		"http://[fe80::1]/",         // the issue's literal fixture
		"https://[fe80::1]:8443/hb", // schemed, port and path
		"[fe80::1]:8080",            // schemeless bracketed
		"fe80::1",                   // schemeless bare literal
	} {
		t.Run("hold/"+target, func(t *testing.T) {
			test := &config.RPMTest{Name: "t1", Target: target}
			_, err := m.probeHTTP(context.Background(), test, probeSockOpts{})
			if !errors.Is(err, ErrProbeSetup) {
				t.Fatalf("probeHTTP(%q) err = %v, want ErrProbeSetup.\n"+
					"Anything else is counted as PATH LOSS: SuccFail increments, the test can "+
					"transition, and `services ip-monitoring` can inject a preferred route — from a "+
					"probe that never left the box (#12908).", target, err)
			}
		})
	}

	// CONTROLS. A guard that fired on these would hold every ordinary probe,
	// which is a far worse failure than the one it fixes: an RPM test that
	// never runs cannot detect a real outage either. The scoped cells dial
	// fe80::1%lo (a real kernel zone with no listener) and fe80::1%ge-0-0-3
	// (an absent interface), failing in milliseconds as genuine path signals —
	// matching probeTCP, which treats a configured-but-down link as loss.
	for _, target := range []string{
		"http://[fe80::1%25lo]/",         // explicit valid zone: dials, fails as loss
		"http://[fe80::1%25ge-0/0/3]/hb", // zone names an absent interface: link-down
		// is a genuine path signal, matching probeTCP
		"http://127.0.0.1:1/", // ordinary v4, connection refused
		"http://[::1]:1/",     // global-scope v6 loopback: no scope question, refused fast
		// (No hostname cell: resolving one needs live DNS. A hostname target
		// has no literal for the guard to see — that its scope question is
		// runtime-only is pinned by the unit table below, hermetically.)
	} {
		t.Run("probe/"+target, func(t *testing.T) {
			test := &config.RPMTest{Name: "t2", Target: target}
			_, err := m.probeHTTP(context.Background(), test, probeSockOpts{})
			if errors.Is(err, ErrProbeSetup) {
				t.Errorf("probeHTTP(%q) held as a setup failure; want an ordinary probe outcome: %v",
					target, err)
			}
		})
	}
}

// TestScopeHTTPTargetZoneRewrites12908 pins the pure rewrite: the resolved
// KERNEL zone (Junos slash names normalized) replaces the literal in RFC 6874
// %25 form, preserving scheme, userinfo, port and path. On master these
// targets either dialed unscoped or failed URL parsing outright.
func TestScopeHTTPTargetZoneRewrites12908(t *testing.T) {
	m := &Manager{}
	for _, tc := range []struct {
		target    string
		destIface string
		want      string
	}{
		// Zone derived from destination-interface, Junos name normalized.
		{"http://[fe80::1]/hb", "ge-0/0/3", "http://[fe80::1%25ge-0-0-3]/hb"},
		{"http://[fe80::1]:8080/x", "ge-0/0/3", "http://[fe80::1%25ge-0-0-3]:8080/x"},
		{"fe80::1", "lo", "[fe80::1%25lo]"},
		// Explicit zone normalized in place (either spelling).
		{"https://[fe80::1%25ge-0/0/3]:8443/hb", "", "https://[fe80::1%25ge-0-0-3]:8443/hb"},
		{"[fe80::1%25ge-0/0/3]:8443", "", "[fe80::1%25ge-0-0-3]:8443"},
		{"fe80::1%ge-0/0/3", "", "[fe80::1%25ge-0-0-3]"},
		// Userinfo and port survive the rewrite.
		{"http://user@[fe80::1]:80/x", "lo", "http://user@[fe80::1%25lo]:80/x"},
		// Non-link-local and non-literal hosts pass through untouched.
		{"http://[2001:db8::1]/hb", "", "http://[2001:db8::1]/hb"},
		{"http://192.0.2.1:8080/x", "ge-0/0/3", "http://192.0.2.1:8080/x"},
		{"https://host.example.com/hb", "ge-0/0/3", "https://host.example.com/hb"},
		{"host.example.com:8080", "ge-0/0/3", "host.example.com:8080"},
	} {
		t.Run("rewrite/"+tc.target, func(t *testing.T) {
			got, err := m.scopeHTTPTargetZone12908(tc.target, tc.destIface)
			if err != nil {
				t.Fatalf("scopeHTTPTargetZone12908(%q, %q) unexpected error: %v",
					tc.target, tc.destIface, err)
			}
			if got != tc.want {
				t.Fatalf("scopeHTTPTargetZone12908(%q, %q) = %q, want %q",
					tc.target, tc.destIface, got, tc.want)
			}
		})
	}

	// The unscopeable cell returns the HOLD sentinel, not a rewritten target.
	if _, err := m.scopeHTTPTargetZone12908("http://[fe80::1]/hb", ""); !errors.Is(err, ErrProbeSetup) {
		t.Fatalf("unscopeable link-local err = %v, want ErrProbeSetup", err)
	}
}

// TestScopedHTTPURLCarriesZoneToTheDial12908 closes the loop the issue's
// decisive check asks for: after scoping and canonicalization, the URL handed
// to http.Client must carry the zone in its HOST — that hostname is what the
// transport dials, so the kernel gets a real egress link for fe80::.
func TestScopedHTTPURLCarriesZoneToTheDial12908(t *testing.T) {
	m := &Manager{}
	scoped, err := m.scopeHTTPTargetZone12908("http://[fe80::1]/hb", "ge-0/0/3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	canon, err := canonicalizeHTTPTarget(scoped)
	if err != nil {
		t.Fatalf("canonicalizeHTTPTarget(%q): %v", scoped, err)
	}
	u, err := url.Parse(canon)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", canon, err)
	}
	if want := "fe80::1%ge-0-0-3"; u.Hostname() != want {
		t.Fatalf("dialed hostname = %q, want %q — the zone must survive into the URL the client dials",
			u.Hostname(), want)
	}
}

package ddns

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestParseCheckIPBodyValidV4(t *testing.T) {
	// 93.184.216.34 is a real, non-reserved public address (not in any
	// private/CGNAT/TEST-NET range the validity gate rejects).
	a, ok := parseCheckIPBody("Your IP is 93.184.216.34 today", true, nil)
	if !ok || a.String() != "93.184.216.34" {
		t.Fatalf("expected 93.184.216.34, got %v ok=%v", a, ok)
	}
}

func TestParseCheckIPBodyRejectsTestNet(t *testing.T) {
	// The TEST-NET ranges (192.0.2/198.51.100/203.0.113) used throughout the
	// other tests as stand-in "public" addresses are reserved-documentation and
	// must be rejected by the checkip gate (they can never be a real public IP).
	for _, ip := range []string{"192.0.2.5", "198.51.100.7", "203.0.113.9"} {
		if _, ok := parseCheckIPBody("ip="+ip, true, nil); ok {
			t.Fatalf("TEST-NET address %s must be rejected by the checkip gate", ip)
		}
	}
}

func TestParseCheckIPBodyRejectsPrivate(t *testing.T) {
	// Only a private address present → no usable public address.
	if _, ok := parseCheckIPBody("ip=192.168.1.1", true, nil); ok {
		t.Fatal("a private address must not be accepted as the public IP")
	}
	if _, ok := parseCheckIPBody("ip=10.0.0.5", true, nil); ok {
		t.Fatal("a 10/8 address must be rejected")
	}
	if _, ok := parseCheckIPBody("ip=100.64.0.1", true, nil); ok {
		t.Fatal("a CGNAT address must be rejected")
	}
}

func TestParseCheckIPBodyAllowlistSkipsEmbeddedResolver(t *testing.T) {
	// A /cdn-cgi/trace-style body that embeds the anycast resolver (1.1.1.1)
	// before the real client IP must skip the allowlisted address.
	body := "fl=1\nip=1.1.1.1\nclient=93.184.216.34\n"
	allow := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	a, ok := parseCheckIPBody(body, true, allow)
	if !ok || a.String() != "93.184.216.34" {
		t.Fatalf("allowlist must skip 1.1.1.1 and pick the client IP, got %v ok=%v", a, ok)
	}
}

func TestParseCheckIPBodyV6First(t *testing.T) {
	a, ok := parseCheckIPBody("addr 2606:4700:4700::1111", false, nil)
	if !ok || !a.Is6() {
		t.Fatalf("expected a v6 address, got %v ok=%v", a, ok)
	}
	// Reject ULA + documentation v6.
	if _, ok := parseCheckIPBody("fd00::1", false, nil); ok {
		t.Fatal("ULA fd00::/8 must be rejected")
	}
	if _, ok := parseCheckIPBody("2001:db8::1", false, nil); ok {
		t.Fatal("2001:db8::/32 documentation must be rejected")
	}
}

// TestIsPublicAddrSpecialPurpose is the #2774 fail-on-revert gate for the
// public-address gate. Every IANA special-purpose range the checkip endpoint
// could return must be REJECTED (IsPublicAddr == false), and a genuine
// globally-routable unicast address must be ACCEPTED. This goes RED if the
// specialPurposeV4/V6 prefix tables (or the stdlib predicate guards) are
// removed from IsPublicAddr: each rejected entry below would then be accepted.
func TestIsPublicAddrSpecialPurpose(t *testing.T) {
	reject := []string{
		// IPv4 special-purpose (IANA registry).
		"0.0.0.0",         // 0.0.0.0/8 this-network / unspecified
		"0.1.2.3",         // 0.0.0.0/8 this-network (non-unspecified)
		"10.0.0.5",        // 10/8 private
		"100.64.0.1",      // 100.64/10 CGNAT
		"127.0.0.1",       // 127/8 loopback
		"169.254.1.1",     // 169.254/16 link-local
		"172.16.5.5",      // 172.16/12 private
		"192.0.0.8",       // 192.0.0/24 IETF protocol assignments
		"192.0.2.5",       // 192.0.2/24 TEST-NET-1
		"192.88.99.1",     // 192.88.99/24 6to4 relay anycast
		"192.168.1.1",     // 192.168/16 private
		"198.18.0.1",      // 198.18/15 benchmarking
		"198.19.255.255",  // 198.18/15 benchmarking (upper half)
		"198.51.100.7",    // 198.51.100/24 TEST-NET-2
		"203.0.113.9",     // 203.0.113/24 TEST-NET-3
		"224.0.0.1",       // 224/4 multicast
		"240.0.0.1",       // 240/4 reserved
		"255.255.255.255", // limited broadcast
		// IPv6 special-purpose (IANA registry).
		"::",           // ::/128 unspecified
		"::1",          // ::1/128 loopback
		"64:ff9b::1",   // 64:ff9b::/96 NAT64 well-known
		"100::1",       // 100::/64 discard-only
		"100:0:0:1::1", // 100:0:0:1::/64 dummy prefix (RFC 9780) — outside 100::/64
		"2001:db8::1",  // 2001:db8::/32 documentation
		"2002::1",      // 2002::/16 6to4
		"3fff::1",      // 3fff::/20 documentation (RFC 9637)
		"5f00::1",      // 5f00::/16 SRv6 SIDs (RFC 9602)
		"fc00::1",      // fc00::/7 ULA
		"fd00::1",      // fc00::/7 ULA
		"fe80::1",      // fe80::/10 link-local
		"ff02::1",      // ff00::/8 multicast
	}
	for _, s := range reject {
		a := netip.MustParseAddr(s).Unmap()
		if IsPublicAddr(a) {
			t.Errorf("IsPublicAddr(%s) = true, want false (special-purpose range)", s)
		}
	}
	accept := []string{
		"8.8.8.8",              // Google public DNS
		"93.184.216.34",        // example.com
		"1.0.0.1",              // public unicast
		"203.0.114.1",          // adjacent to TEST-NET-3 but routable
		"198.20.0.1",           // adjacent to 198.18/15 but routable
		"2606:4700:4700::1111", // Cloudflare public DNS
		"2001:4860:4860::8888", // Google public DNS v6
	}
	for _, s := range accept {
		a := netip.MustParseAddr(s).Unmap()
		if !IsPublicAddr(a) {
			t.Errorf("IsPublicAddr(%s) = false, want true (globally-routable unicast)", s)
		}
	}
}

func TestCheckIPThroughMockServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("93.184.216.34\n"))
	}))
	defer srv.Close()
	a, ok, err := CheckIP(context.Background(), srv.Client(), srv.URL, true, nil)
	if !ok || a.String() != "93.184.216.34" || err != nil {
		t.Fatalf("CheckIP returned %v ok=%v err=%v", a, ok, err)
	}
}

// #14372 (DR3-H5, fixture F-DR3-H5-2): the runtime backstop. validateCheckIPURL
// must require https — a plaintext checkip-url that slipped past commit
// (lenient load, peer-sync, hand-built provider) fails closed in CheckIP
// BEFORE any fetch, so a spoofed plaintext response can never become the
// published address. The refusal names the https requirement and carries no
// part of the URL (an embedded API key must not leak, #6545 discipline).
func TestCheckIPRejectsPlaintextURL(t *testing.T) {
	var hits int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&hits, 1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("93.184.216.34\n")),
			Header:     make(http.Header),
			Request:    r,
		}, nil
	})}
	for _, u := range []string{
		"http://checkip.example/",
		"http://user:CHECKIP-SECRET-MUST-NOT-LOG@checkip.example/?apikey=CHECKIP-SECRET-MUST-NOT-LOG",
		"HTTP://checkip.example/",
	} {
		a, ok, err := CheckIP(context.Background(), client, u, true, nil)
		if ok || a.IsValid() {
			t.Fatalf("CheckIP(%q) = %v ok=%v; a plaintext checkip-url must fail closed", u, a, ok)
		}
		if err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("CheckIP(%q) err = %v; want a refusal naming the https requirement", u, err)
		}
		if strings.Contains(err.Error(), "CHECKIP-SECRET-MUST-NOT-LOG") {
			t.Fatalf("CheckIP(%q) refusal leaked the checkip-url credential: %v", u, err)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("CheckIP contacted a plaintext checkip endpoint %d time(s); it must refuse before any fetch", n)
	}
	if err := validateCheckIPURL("http://checkip.example/"); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Fatalf("validateCheckIPURL(http) = %v; want an https refusal", err)
	}
}

func TestParseAllowlist(t *testing.T) {
	got := ParseAllowlist("1.1.1.1, 8.8.8.8 garbage 2606:4700::1")
	if len(got) != 3 {
		t.Fatalf("expected 3 parsed addresses, got %d (%v)", len(got), got)
	}
}

// TestParseAllowlistChecked is the #2839 fail-on-revert gate: a malformed
// allowlist token must be RECOVERABLE (named) instead of silently dropped, while
// every valid token is still retained and a clean list reports no malformed
// tokens. Goes RED if ParseAllowlistChecked reverts to silently discarding bad
// tokens (the old ParseAllowlist behaviour that shrank the bogus-IP safety gate).
func TestParseAllowlistChecked(t *testing.T) {
	// Mixed list: 3 valid + 2 malformed (an operator typo + a bare word).
	list, bad := ParseAllowlistChecked("1.1.1.1, 8.8.8.8x garbage 8.8.8.8 2606:4700::1")
	if len(list) != 3 {
		t.Fatalf("expected 3 valid addresses retained, got %d (%v)", len(list), list)
	}
	wantValid := []string{"1.1.1.1", "8.8.8.8", "2606:4700::1"}
	for i, w := range wantValid {
		if list[i].String() != w {
			t.Fatalf("valid[%d] = %q, want %q (all valid tokens must be retained)", i, list[i].String(), w)
		}
	}
	if len(bad) != 2 {
		t.Fatalf("expected 2 malformed tokens surfaced, got %d (%v)", len(bad), bad)
	}
	// The offending tokens must be NAMED (not silently dropped) so the operator
	// can find the typo.
	if bad[0] != "8.8.8.8x" || bad[1] != "garbage" {
		t.Fatalf("malformed tokens = %v, want [8.8.8.8x garbage]", bad)
	}

	// A clean allowlist surfaces no malformed tokens.
	clean, none := ParseAllowlistChecked("1.1.1.1, 2606:4700::1")
	if len(clean) != 2 || len(none) != 0 {
		t.Fatalf("clean allowlist: got %d valid / %d malformed, want 2 / 0 (%v, %v)", len(clean), len(none), clean, none)
	}

	// Empty / whitespace input: no addresses, no malformed tokens.
	if l, b := ParseAllowlistChecked("   "); l != nil || b != nil {
		t.Fatalf("empty allowlist: got %v / %v, want nil / nil", l, b)
	}
}

// TestValidateCheckIPURL is the #2773 validator gate, tightened by #14372:
// https scheme + a host (http is now refused — the response is an
// unauthenticated oracle for the published DNS record).
// validateCheckIPURL was dead code (no callers) before #2773 wired it into
// CheckIP and (mirrored) into the commit-time warning.
func TestValidateCheckIPURL(t *testing.T) {
	for _, ok := range []string{
		"https://checkip.example/",
		"https://checkip.example:8443/cdn-cgi/trace",
		"https://192.0.2.1/",
		// RFC 3986 §3.1: the scheme is case-INSENSITIVE. Uppercase/mixed-case
		// https schemes must be ACCEPTED (#2842). Goes RED if the validator
		// reverts to a case-sensitive HasPrefix on the raw string.
		"Https://h/",
		"HTTPS://checkip.example:8443/cdn-cgi/trace",
	} {
		if err := validateCheckIPURL(ok); err != nil {
			t.Fatalf("validateCheckIPURL(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"",                        // empty
		"ftp://host/",             // non-https scheme
		"http://checkip.example/", // plaintext oracle (#14372)
		"HTTP://checkip.example/", // plaintext, upper-case scheme (#14372)
		"not a url",               // no scheme
		"http://",                 // scheme but no host
		"https://",                // scheme but no host
		"https:///path",           // empty host
		"javascript:0",            // non-https scheme
		"checkip.example",         // bare host, no scheme
	} {
		if err := validateCheckIPURL(bad); err == nil {
			t.Fatalf("validateCheckIPURL(%q) = nil, want error", bad)
		}
	}
}

// TestCheckIPRejectsMalformedURL is the #2773 runtime fail-on-revert gate: a
// malformed checkip-url must be rejected by CheckIP itself (fail closed), not
// fall through to a fetch and masquerade as a transient failure. Before the
// wiring, http.NewRequest accepted these strings and CheckIP returned ok=false
// only because the *fetch* failed — indistinguishable from a real transient.
// This goes RED if the validateCheckIPURL gate is removed from CheckIP: the
// requests would then reach the transport, which fails the test on contact.
func TestCheckIPRejectsMalformedURL(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Fatalf("CheckIP attempted a request for a malformed URL: %s", r.URL)
		return nil, nil
	})}
	for _, bad := range []string{"ftp://checkip.example/", "http://", "not a url"} {
		_, ok, err := CheckIP(context.Background(), client, bad, true, nil)
		if ok {
			t.Fatalf("CheckIP(%q) ok=true, want false (malformed URL must fail closed)", bad)
		}
		// A malformed checkip-url is a CONFIGURATION error, not a transient —
		// the refusal must be reportable, or it lands right back in the
		// indistinguishable-forever bucket #2773 closed.
		if err == nil {
			t.Fatalf("CheckIP(%q) err=nil; a malformed URL must report WHY it failed, "+
				"not masquerade as an ordinary no-address miss", bad)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

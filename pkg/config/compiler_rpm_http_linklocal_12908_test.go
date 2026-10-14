package config

import (
	"net"
	"strings"
	"testing"
)

// #12908: an http-get target carries its host inside a URL, and the #2494
// link-local zone gate used to split the raw target at '%' and hand the rest
// to net.ParseIP — so http://[fe80::1]/ failed IP parsing, skipped the gate,
// and shipped an unprobeable target past strict commit. These cells pin the
// URL-form rejection; the bare-form cells live in
// compiler_rpm_linklocal_zone_2494_test.go and must keep passing unchanged.

// TestRPMLinkLocalURLFormNoScopeStrictRejects12908 is the defect cell: a URL-form
// IPv6 link-local target with neither a %zone nor a destination-interface is
// hard-rejected on the strict path.
//
// FAILS against master, which accepts the scopeless URL target — a silently
// dead probe feeding ip-monitoring failover.
func TestRPMLinkLocalURLFormNoScopeStrictRejects12908(t *testing.T) {
	for _, target := range []string{
		"http://[fe80::1]/",
		"https://[fe80::1]:8443/hb",
		// Schemeless bracketed form: the runtime canonicalizes it to a URL,
		// so the gate must see the same literal.
		"[fe80::1]:8080",
	} {
		t.Run("reject/"+target, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type http-get",
				"set services rpm probe P test t target " + target,
			}
			tree := buildTree(t, lines)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted scopeless link-local URL target %q; want strict reject", target)
			}
			if !strings.Contains(err.Error(), "link-local") {
				t.Fatalf("err = %v, want substring %q", err, "link-local")
			}
		})
	}
}

// TestRPMLinkLocalURLFormScopedAccepted12908 pins the two legitimate scoped
// spellings so the new rejection cannot over-fire: an RFC 6874 %25 zone in
func TestRPMLinkLocalURLFormScopedAccepted12908(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  []string
		target string
	}{
		{"explicit %25 zone in URL host", nil, "http://[fe80::1%25ge-0-0-3]/hb"},
		{"explicit %25 zone, schemeless bracketed", nil, "[fe80::1%25ge-0/0/3]:8443"},
		{
			"zone from destination-interface",
			[]string{"set services rpm probe P test t destination-interface ge-0/0/3"},
			"http://[fe80::1]/hb",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{
				"set services rpm probe P test t probe-type http-get",
				"set services rpm probe P test t target " + tc.target,
			}, tc.extra...)
			tree := buildTree(t, lines)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("scoped link-local URL target %q must be accepted: %v", tc.target, err)
			}
		})
	}
}

func TestRPMLinkLocalURLFormNonLiteralUnaffected12908(t *testing.T) {
	for _, target := range []string{
		"http://2001:db8::10/hb",      // global v6
		"http://[2001:db8::10]/hb",    // global v6, bracketed
		"http://192.0.2.1:8080/hb",    // v4 with port
		"https://host.example.com/hb", // hostname (DNS is runtime scope)
		"host.example.com:8080",       // schemeless host:port
	} {
		t.Run("ok/"+target, func(t *testing.T) {
			lines := []string{
				"set services rpm probe P test t probe-type http-get",
				"set services rpm probe P test t target " + target,
			}
			tree := buildTree(t, lines)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("target %q must be unaffected by the link-local gate: %v", target, err)
			}
		})
	}
}

// TestRPMLinkLocalURLFormLenientWarns12908 pins the no-brick contract: the
// same scopeless URL target the strict path rejects is TOLERATED on the
// lenient load / peer-sync path as a warning — and the runtime guard added
// with this issue holds the test's state with ErrProbeSetup, so the doctrine
// stays fail-closed end to end.
func TestRPMLinkLocalURLFormLenientWarns12908(t *testing.T) {
	lines := []string{
		"set services rpm probe P test t probe-type http-get",
		"set services rpm probe P test t target http://[fe80::1]/hb",
	}
	tree := buildTree(t, lines)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not fail on a scopeless link-local URL (brick-on-restart): %v", err)
	}
	if !hasWarningSubstr(cfg.Warnings, "rpm link-local zone") {
		t.Fatalf("expected a downgraded rpm link-local-zone warning, warnings=%v", cfg.Warnings)
	}
}

// TestFindTargetIPLiteral12908 pins the shared extraction the strict gate and
// the runtime guard both build on. The span assertions use the substring
// (target[start:end]) rather than offsets so the table reads as "which bytes
// get rewritten".
func TestFindTargetIPLiteral12908(t *testing.T) {
	for _, tc := range []struct {
		target   string
		wantIP   string // "" means no literal found
		wantZone string
		wantLit  string // target[start:end]
	}{
		{"fe80::1", "fe80::1", "", "fe80::1"},
		{"fe80::1%ge-0/0/3", "fe80::1", "ge-0/0/3", "fe80::1%ge-0/0/3"},
		{"2001:db8::1", "2001:db8::1", "", "2001:db8::1"},
		{"192.0.2.1", "192.0.2.1", "", "192.0.2.1"},
		{"[fe80::1]:8080", "fe80::1", "", "[fe80::1]"},
		{"[fe80::1%25ge-0/0/3]:8443", "fe80::1", "ge-0/0/3", "[fe80::1%25ge-0/0/3]"},
		{"http://[fe80::1]/hb", "fe80::1", "", "[fe80::1]"},
		{"https://[fe80::1%25ge-0-0-3]:8443/hb", "fe80::1", "ge-0-0-3", "[fe80::1%25ge-0-0-3]"},
		{"http://user@[fe80::1]:80/x", "fe80::1", "", "[fe80::1]"},
		{"http://host.example.com/hb", "", "", ""},
		{"host.example.com", "", "", ""},
		{"host.example.com:8080", "", "", ""},
		{"http://192.0.2.1:8080/x", "", "", ""},
		{"http://[fe80::1", "", "", ""}, // unclosed bracket
		{"", "", "", ""},
	} {
		t.Run("lit/"+tc.target, func(t *testing.T) {
			ip, zone, start, end := FindTargetIPLiteral(tc.target)
			if tc.wantIP == "" {
				if ip != nil {
					t.Fatalf("FindTargetIPLiteral(%q) = %v, want no literal", tc.target, ip)
				}
				return
			}
			want := net.ParseIP(tc.wantIP)
			if ip == nil || ip.String() != want.String() {
				t.Fatalf("ip = %v, want %s", ip, tc.wantIP)
			}
			if zone != tc.wantZone {
				t.Fatalf("zone = %q, want %q", zone, tc.wantZone)
			}
			if got := tc.target[start:end]; got != tc.wantLit {
				t.Fatalf("literal span = %q, want %q", got, tc.wantLit)
			}
		})
	}
}

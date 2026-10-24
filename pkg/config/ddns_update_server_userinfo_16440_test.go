package config

import (
	"strings"
	"testing"
)

// #16440: an rfc2136 update-server carrying URL userinfo must be rejected
// at strict commit (it can never work — RFC 2136 has no credential slot —
// and pre-fix it re-disclosed the credential into LastError/journald on
// every failed cycle, undoing #15174). The tolerant path warns and boots;
// the rejection itself names only the RedactURL render.

const userinfoSecret16440 = "s3cr3t"

func TestDDNSUpdateServerUserinfoStrictRejects16440(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{"dhcp v4 bare", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			`set system services dhcp-local-server dynamic-dns update-server "user:` + userinfoSecret16440 + `@dns.example.com"`,
		}},
		{"dhcp v4 with port", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			`set system services dhcp-local-server dynamic-dns update-server "user:` + userinfoSecret16440 + `@dns.example.com:53"`,
		}},
		{"dhcp v6", []string{
			"set system services dhcpv6-local-server dynamic-dns enable",
			`set system services dhcpv6-local-server dynamic-dns update-server "user:` + userinfoSecret16440 + `@dns.example.com"`,
		}},
		{"surface-a provider", []string{
			"set system services dynamic-dns provider p1 backend rfc2136",
			`set system services dynamic-dns provider p1 update-server "user:` + userinfoSecret16440 + `@dns.example.com:53"`,
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider p1",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname wan.example.net",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.lines))
			if err == nil {
				t.Fatalf("strict commit accepted userinfo update-server (#16440)")
			}
			if strings.Contains(err.Error(), userinfoSecret16440) {
				t.Fatalf("rejection leaked the credential: %v", err)
			}
			if !strings.Contains(err.Error(), "<redacted>@dns.example.com") {
				t.Fatalf("rejection must name the redacted server, got: %v", err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant load rejected userinfo config (no-brick violated): %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "userinfo") {
					found = true
				}
				if strings.Contains(w, userinfoSecret16440) {
					t.Fatalf("tolerant warning leaked the credential: %q", w)
				}
			}
			if !found {
				t.Fatalf("tolerant load produced no userinfo warning; warnings=%v", cfg.Warnings)
			}
		})
	}
}

// TestDDNSUpdateServerUserinfoControls16440: clean servers and non-rfc2136
// backends commit unchanged.
func TestDDNSUpdateServerUserinfoControls16440(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{"clean host", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server dns.example.com",
		}},
		{"clean host:port", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server dns.example.com:53",
		}},
		{"clean provider", []string{
			"set system services dynamic-dns provider p1 backend rfc2136",
			"set system services dynamic-dns provider p1 update-server 192.0.2.53",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider p1",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname wan.example.net",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, tc.lines)); err != nil {
				t.Fatalf("strict commit rejected a control case: %v", err)
			}
		})
	}
	if ddnsUpdateServerHasUserinfo("dns.example.com:53") || !ddnsUpdateServerHasUserinfo("user:pw@dns.example.com") {
		t.Fatal("ddnsUpdateServerHasUserinfo predicate wrong")
	}
	if ddnsUpdateServerParseable("user:pw@dns.example.com") {
		t.Fatal("userinfo must not be parseable as host[:port]")
	}
}

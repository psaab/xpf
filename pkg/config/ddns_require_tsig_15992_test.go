package config

import (
	"strings"
	"testing"
)

// TestDDNSRequireTSIGStrictRejectsUnsignedNonLoopback15992 pins #15992:
// require-tsig + non-loopback update-server + no tsig-key refuses strict
// commit on both DDNS surfaces; the tolerant path warns and boots.
func TestDDNSRequireTSIGStrictRejectsUnsignedNonLoopback15992(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{"dhcp v4", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns require-tsig",
		}},
		{"dhcp v6", []string{
			"set system services dhcpv6-local-server dynamic-dns enable",
			"set system services dhcpv6-local-server dynamic-dns update-server 2001:db8::53",
			"set system services dhcpv6-local-server dynamic-dns require-tsig",
		}},
		{"surface-a provider", []string{
			"set system services dynamic-dns provider p1 backend rfc2136",
			"set system services dynamic-dns provider p1 update-server 192.0.2.53",
			"set system services dynamic-dns provider p1 require-tsig",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider p1",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname wan.example.net",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, tc.lines)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("strict commit accepted require-tsig without a key (#15992)")
			} else if !strings.Contains(err.Error(), "require-tsig") {
				t.Fatalf("rejection must name require-tsig, got: %v", err)
			}
			cfg, err := CompileConfigLenient(buildTree(t, tc.lines))
			if err != nil {
				t.Fatalf("tolerant load rejected require-tsig config (no-brick violated): %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "require-tsig") {
					found = true
				}
			}
			if !found {
				t.Fatalf("tolerant load produced no require-tsig warning; warnings=%v", cfg.Warnings)
			}
		})
	}
}

// TestDDNSRequireTSIGControls15992 pins the boundaries: loopback servers,
// a configured key, and the default (no require-tsig) posture all commit.
func TestDDNSRequireTSIGControls15992(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
	}{
		{"loopback server, no key", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 127.0.0.1",
			"set system services dhcp-local-server dynamic-dns require-tsig",
		}},
		{"localhost server, no key", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server localhost",
			"set system services dhcp-local-server dynamic-dns require-tsig",
		}},
		{"non-loopback with key", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
			"set system services dhcp-local-server dynamic-dns tsig-key k1",
			"set system services dhcp-local-server dynamic-dns tsig-secret c2VjcmV0",
			"set system services dhcp-local-server dynamic-dns require-tsig",
		}},
		{"default posture, unsigned non-loopback (ACL BIND must keep working)", []string{
			"set system services dhcp-local-server dynamic-dns enable",
			"set system services dhcp-local-server dynamic-dns update-server 192.0.2.53",
		}},
		{"provider keyed", []string{
			"set system services dynamic-dns provider p1 backend rfc2136",
			"set system services dynamic-dns provider p1 update-server 192.0.2.53",
			"set system services dynamic-dns provider p1 tsig-key k1",
			"set system services dynamic-dns provider p1 tsig-secret c2VjcmV0",
			"set system services dynamic-dns provider p1 require-tsig",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider p1",
			"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname wan.example.net",
		}},
		{"provider loopback", []string{
			"set system services dynamic-dns provider p1 backend rfc2136",
			"set system services dynamic-dns provider p1 update-server ::1",
			"set system services dynamic-dns provider p1 require-tsig",
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
	dhcpCfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server dynamic-dns enable",
		"set system services dhcp-local-server dynamic-dns update-server 127.0.0.1",
		"set system services dhcp-local-server dynamic-dns require-tsig",
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if dhcpCfg.System.DHCPServer.DynamicDNS == nil || !dhcpCfg.System.DHCPServer.DynamicDNS.RequireTSIG {
		t.Fatalf("require-tsig flag did not compile into DHCPDynamicDNSConfig")
	}
	provCfg, err := CompileConfig(buildTree(t, []string{
		"set system services dynamic-dns provider p1 backend rfc2136",
		"set system services dynamic-dns provider p1 update-server 127.0.0.1",
		"set system services dynamic-dns provider p1 require-tsig",
		"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns provider p1",
		"set interfaces ge-0-0-2 unit 0 family inet dynamic-dns hostname wan.example.net",
	}))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p := provCfg.System.Services.DynamicDNS.Providers["p1"]
	if p == nil || !p.RequireTSIG {
		t.Fatalf("require-tsig flag did not compile into DDNSProvider")
	}
}

// TestDDNSUpdateServerIsLoopback15992 pins the loopback predicate directly.
func TestDDNSUpdateServerIsLoopback15992(t *testing.T) {
	for server, want := range map[string]bool{
		"127.0.0.1": true, "127.0.0.1:53": true, "::1": true, "[::1]:53": true,
		"localhost": true, "localhost:53": true,
		"192.0.2.53": false, "2001:db8::53": false, "ns1.example.com": false, "": false,
	} {
		if got := ddnsUpdateServerIsLoopback(server); got != want {
			t.Errorf("ddnsUpdateServerIsLoopback(%q) = %v, want %v", server, got, want)
		}
	}
}

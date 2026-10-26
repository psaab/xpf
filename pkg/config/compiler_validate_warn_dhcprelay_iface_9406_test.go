package config

import (
	"strings"
	"testing"
)

// #9406 advisory. The bind fix makes a canonical relay member resolve; this
// makes a member that can never resolve audible. The runtime cannot say it:
// resolveGIAddrWithRetry retries forever with no error, "dhcp-relay: started"
// is logged before any bind, and every RelayStats counter is a forwarding
// counter — so a relay bound to nothing is indistinguishable from an idle
// segment. The commit is the only place that can tell the difference.

const relayIfaces9406 = `
interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit 0 { family inet { address 10.0.1.1/24; } }
        unit 80 { vlan-id 180; family inet { address 10.0.80.1/24; } }
    }
    ge-0/0/2 {
        gigether-options { redundant-parent reth0; }
    }
    reth0 {
        unit 0 { family inet { address 10.0.2.1/24; } }
    }
}
`

func relayWarn9406(t *testing.T, groupBody string) []string {
	t.Helper()
	text := relayIfaces9406 + `
forwarding-options {
    dhcp-relay {
        server-group isp { 192.0.2.1; }
        group g1 { active-server-group isp; ` + groupBody + ` }
    }
}
`
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "#9406") {
			out = append(out, w)
		}
	}
	return out
}

func TestDHCPRelayInterfaceRefWarnings9406(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string // "" = must be silent
	}{
		{
			name: "canonical slash unit-0 reference is silent",
			body: "interface ge-0/0/0.0;",
		},
		{
			name: "canonical tagged unit is silent",
			body: "interface ge-0/0/0.80;",
		},
		{
			name: "reth unit is silent",
			body: "interface reth0.0;",
		},
		{
			name: "dash spelling is silent",
			body: "interface ge-0-0-0;",
		},
		{
			name: "undeclared interface",
			body: "interface ge-0/0/9.0;",
			want: "interface ge-0/0/9.0 names no configured interface",
		},
		{
			name: "declared interface, undeclared unit",
			body: "interface ge-0/0/0.7;",
			want: "interface ge-0/0/0.7 names no configured unit on ge-0/0/0",
		},
		{
			name: "the group is named so the operator knows where to look",
			body: "interface ge-0/0/9.0;",
			want: "forwarding-options dhcp-relay group g1",
		},
		{
			name: "the consequence names the silent symptom",
			body: "interface ge-0/0/9.0;",
			want: "started service with all-zero counters",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := relayWarn9406(t, tc.body)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected silence, got %v", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("no #9406 advisory; want one carrying %q", tc.want)
			}
			if joined := strings.Join(got, "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("advisory %q does not carry %q", joined, tc.want)
			}
		})
	}
}

// TestDHCPRelayInterfaceRefWarningsSilentWithoutRelay9406 pins the early-out:
// no relay stanza, no interface walk, no advisory.
func TestDHCPRelayInterfaceRefWarningsSilentWithoutRelay9406(t *testing.T) {
	tree, perrs := NewParser(relayIfaces9406).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	if got := validateDHCPRelayInterfaceRefWarnings(cfg); len(got) != 0 {
		t.Fatalf("advisories with no relay configured = %v, want none", got)
	}
}

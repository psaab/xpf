package config

import (
	"strings"
	"testing"
)

// #9405 advisory. The render fix makes a canonical reference BIND; this makes a
// reference that can never bind AUDIBLE. Both halves matter: before #9405 an
// operator saw a green commit, a running FRR and no adjacency, with no
// diagnostic on any surface.

func warnFor9405(t *testing.T, text string) []string {
	t.Helper()
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
		if strings.Contains(w, "#9405") {
			out = append(out, w)
		}
	}
	return out
}

const ifaces9405 = `
interfaces {
    ge-0/0/1 {
        unit 0 { family inet { address 10.0.1.1/24; } }
    }
    ge-0/0/2 {
        gigether-options { redundant-parent reth0; }
    }
    reth0 {
        unit 0 { family inet { address 10.0.2.1/24; } }
    }
}
`

func TestProtocolInterfaceRefWarnings9405(t *testing.T) {
	cases := []struct {
		name   string
		text   string
		want   string // substring the advisory must carry, "" = must be silent
		reason string
	}{
		{
			name:   "canonical slash reference is silent",
			text:   ifaces9405 + "protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0; } } }",
			reason: "the spelling this issue exists to make work must not also warn",
		},
		{
			name:   "dash reference is silent",
			text:   ifaces9405 + "protocols { ospf { area 0.0.0.0 { interface ge-0-0-1; } } }",
			reason: "both spellings are legitimate authoring forms (#8829)",
		},
		{
			name:   "reth reference is silent",
			text:   ifaces9405 + "protocols { ospf { area 0.0.0.0 { interface reth0.0; } } }",
			reason: "a RETH unit is resolved by the renderer, not a phantom",
		},
		{
			name: "interface all names the unimplemented wildcard",
			text: ifaces9405 + "protocols { ospf { area 0.0.0.0 { interface all; } } }",
			want: "does not expand the `all` wildcard",
		},
		{
			name: "undeclared interface",
			text: ifaces9405 + "protocols { ospf { area 0.0.0.0 { interface ge-0/0/9.0; } } }",
			want: "names no configured interface",
		},
		{
			name: "declared interface, undeclared unit",
			text: ifaces9405 + "protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.7; } } }",
			want: "names no configured unit on ge-0/0/1",
		},
		{
			name: "isis reaches the same advisory",
			text: ifaces9405 + "protocols { isis { net 49.0001.0000.0000.0001.00; interface ge-0/0/9.0; } }",
			want: "isis interface ge-0/0/9.0 names no configured interface",
		},
		{
			name: "rip reaches the same advisory",
			text: ifaces9405 + "protocols { rip { group g { neighbor ge-0/0/9.0; } } }",
			want: "rip interface ge-0/0/9.0 names no configured interface",
		},
		{
			name: "ospf3 reaches the same advisory",
			text: ifaces9405 + "protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/9.0; } } }",
			want: "ospf3 interface ge-0/0/9.0 names no configured interface",
		},
		{
			name: "routing-instance scope is named in the message",
			text: ifaces9405 + `routing-instances {
    ISP-B {
        instance-type virtual-router;
        protocols { ospf { area 0.0.0.0 { interface ge-0/0/9.0; } } }
    }
}`,
			want: "routing-instances ISP-B protocols ospf interface ge-0/0/9.0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := warnFor9405(t, tc.text)
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("expected silence (%s), got %v", tc.reason, got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatalf("no #9405 advisory emitted; want one carrying %q", tc.want)
			}
			joined := strings.Join(got, "\n")
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("advisory %q does not carry %q", joined, tc.want)
			}
		})
	}
}

// TestProtocolInterfaceRefWarningsSilentWithoutProtocols9405 pins the
// early-out. It is not a micro-optimisation: calling ResolveKernelIfName per
// declared interface rebuilds the tunnel-name map per call, which made the
// tolerant compile quadratic in the interface count and reddened
// TestTunnelNameMapBuildsAreInputSizeIndependent8862 on the first draft of this
// pass. The cheap shape is also the correct one — do nothing when there is
// nothing to check.
func TestProtocolInterfaceRefWarningsSilentWithoutProtocols9405(t *testing.T) {
	tree, perrs := NewParser(ifaces9405).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}
	if got := collectProtocolInterfaceRefs(cfg); len(got) != 0 {
		t.Fatalf("collectProtocolInterfaceRefs on a protocol-free config = %v, want none", got)
	}
	if got := validateProtocolInterfaceRefWarnings(cfg); len(got) != 0 {
		t.Fatalf("advisories on a protocol-free config = %v, want none", got)
	}
}

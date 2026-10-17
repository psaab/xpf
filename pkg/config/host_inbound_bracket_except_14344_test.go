package config

import (
	"strings"
	"testing"
)

// #14344: a child `{ except; }` block on a multi-token parent
// (`[ ssh telnet ] { except; }`) excluded only the parent's final token
// and admitted the rest — a silent host-inbound fail-open. The braced
// modifier has no single operand, so strict commit must reject it
// (matching the inline `[ a b except ]` doctrine) and the tolerant path
// must quarantine the poisoned admission dimension instead of partially
// applying the exclusion.
func TestHostInboundBracketedParentWithChildExceptBlockRejectedStrict(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		want      string
		protocols bool
	}{
		{
			name: "system-services bracketed child",
			body: `security { zones { security-zone trust { host-inbound-traffic { system-services { all; [ ssh telnet ] { except; } } } } } }`,
			want: "ssh",
		},
		{
			name:      "protocols bracketed child",
			body:      `security { zones { security-zone trust { host-inbound-traffic { protocols { all; [ bgp ospf ] { except; } } } } } }`,
			want:      "bgp",
			protocols: true,
		},
		{
			name: "system-services unbracketed multi-token child",
			body: `security { zones { security-zone trust { host-inbound-traffic { system-services { all; ssh telnet { except; } } } } } }`,
			want: "ssh",
		},
		{
			name: "system-services root bracketed body",
			body: `security { zones { security-zone trust { host-inbound-traffic { system-services [ ssh telnet ] { except; } } } } }`,
			want: "ssh",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree, errs := NewParser(tc.body).Parse()
			if len(errs) > 0 {
				t.Fatalf("parse: %v", errs)
			}
			if err := SchemaValidate(tree, nil); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SchemaValidate = %v, want error naming %q", err, tc.want)
			}
			if _, err := CompileConfig(tree); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict CompileConfig = %v, want error naming %q", err, tc.want)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient CompileConfig: %v", err)
			}
			if !hasWarning(cfg.Warnings, tc.want) {
				t.Fatalf("lenient warnings %v do not name %q", cfg.Warnings, tc.want)
			}
			hib := cfg.Security.Zones["trust"].HostInboundTraffic
			if hib == nil {
				t.Fatal("lenient compile dropped the host-inbound stanza")
			}
			// Fail-closed quarantine: the poisoned dimension admits nothing.
			if tc.protocols {
				if len(hib.Protocols) != 0 {
					t.Fatalf("lenient protocols not quarantined: %v", hib.Protocols)
				}
			} else if len(hib.SystemServices) != 0 {
				t.Fatalf("lenient system-services not quarantined: %v", hib.SystemServices)
			}
		})
	}
}

// Control: a single-token parent with a child `{ except; }` and a plain
// bracketed list without a braced body remain supported.
func TestHostInboundBracketedParentControlsStillCompile14344(t *testing.T) {
	single, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic { system-services { all; ssh { except; } } } } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse single: %v", errs)
	}
	if _, err := CompileConfig(single); err != nil {
		t.Fatalf("single-token child except rejected: %v", err)
	}
	plain, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic { system-services { all; [ ssh telnet ]; } } } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse plain: %v", errs)
	}
	cfg, err := CompileConfig(plain)
	if err != nil {
		t.Fatalf("plain bracketed list rejected: %v", err)
	}
	hib := cfg.Security.Zones["trust"].HostInboundTraffic
	found := map[string]bool{}
	for _, tok := range hib.SystemServices {
		found[tok] = true
	}
	if !found["ssh"] || !found["telnet"] {
		t.Fatalf("plain bracketed list lost tokens: %v", hib.SystemServices)
	}
}

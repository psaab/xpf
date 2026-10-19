package config

import (
	"strings"
	"testing"
)

// #15781: `system services netconf ssh` was declared in the schema and
// host-inbound opens tcp/830 for the netconf token, but compileSystem had
// no Netconf field/consumer, systemInertKnobWarnings stayed silent,
// applySSHConfig started no NETCONF server, and `show system services`
// said nothing — the stanza committed as a silent no-op while tcp/830
// looked served. xpf implements no NETCONF daemon (docs/feature-gaps.md:
// NETCONF/YANG Missing), so the chosen behaviour is accept-with-advisory:
// compile records NetconfSSH, emits an explicit inert-knob warning, and
// the show surfaces render it as configured but NOT served.
//
// RED-on-revert: without the compileSystem netconf reader the typed flag
// stays false and without the systemInertKnobWarnings arm no warning
// names netconf — every positive cell below fails.
func TestNetconfSSHInertWarning15781(t *testing.T) {
	cases := []struct {
		name string
		sets []string
		text string
	}{
		{
			name: "braced netconf ssh beside ssh",
			text: "system {\n services {\n  ssh {\n   root-login deny;\n  }\n  netconf {\n   ssh;\n  }\n }\n}\n",
		},
		{
			name: "flat-set chain",
			sets: []string{"set system services netconf ssh"},
		},
		{
			name: "netconf body packed on the netconf line",
			text: "system {\n services {\n  netconf ssh;\n }\n}\n",
		},
		{
			name: "whole body packed on the system line",
			text: "system services netconf ssh;\n",
		},
		{
			name: "second services sibling block",
			text: "system {\n services {\n  ssh {\n   root-login deny;\n  }\n }\n services {\n  netconf {\n   ssh;\n  }\n }\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c *Config
			if tc.text != "" {
				c = compileText13089(t, tc.text)
			} else {
				var err error
				c, err = CompileConfig(buildTree4303(t, tc.sets))
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
			}
			if c.System.Services == nil || !c.System.Services.NetconfSSH {
				t.Fatalf("compiled NetconfSSH = %+v, want true (netconf ssh silently dropped)", c.System.Services)
			}
			all := strings.Join(c.Warnings, "\n")
			if !strings.Contains(all, "system services netconf ssh") ||
				!strings.Contains(all, "NOT") {
				t.Errorf("missing inert-knob advisory for netconf ssh; warnings:\n%s", all)
			}
			if !strings.Contains(all, "830") {
				t.Errorf("advisory must name tcp/830 as not served; warnings:\n%s", all)
			}
		})
	}
}

// TestNetconfSSHQuietWhenAbsent15781 is the negative control: a services
// stanza without netconf ssh (and an empty netconf container without the
// ssh leaf) must not grow the advisory or the typed flag.
func TestNetconfSSHQuietWhenAbsent15781(t *testing.T) {
	for _, text := range []string{
		"system {\n services {\n  ssh {\n   root-login deny;\n  }\n }\n}\n",
		"system {\n services {\n  netconf {\n  }\n }\n}\n",
	} {
		c := compileText13089(t, text)
		if c.System.Services != nil && c.System.Services.NetconfSSH {
			t.Errorf("NetconfSSH set without netconf ssh leaf: %q", text)
		}
		if all := strings.Join(c.Warnings, "\n"); strings.Contains(all, "netconf") {
			t.Errorf("unexpected netconf advisory for %q; warnings:\n%s", text, all)
		}
	}
}

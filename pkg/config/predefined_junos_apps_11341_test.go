package config

import (
	"reflect"
	"testing"
)

// #11341 pins the Junos default-application terms cited in the issue's
// version-bounded dumps. This is not a claim of current-release vSRX parity.
func TestPredefinedJunosApplicationTerms_11341(t *testing.T) {
	cases := []struct {
		set   string
		want  []string
		terms []struct {
			name, protocol, port, alg string
		}
	}{
		{
			set:  "junos-smb",
			want: []string{"junos-netbios-session", "junos-smb-session"},
			terms: []struct {
				name, protocol, port, alg string
			}{
				{"junos-netbios-session", "tcp", "139", ""},
				{"junos-smb-session", "tcp", "445", ""},
			},
		},
		{
			set:  "junos-h323",
			want: []string{"junos-h323-q931", "junos-h323-ras", "junos-h323-tcp-1503", "junos-h323-tcp-389", "junos-h323-tcp-522", "junos-h323-tcp-1731"},
			terms: []struct {
				name, protocol, port, alg string
			}{
				{"junos-h323-q931", "tcp", "1720", "q931"},
				{"junos-h323-ras", "udp", "1719", "ras"},
				{"junos-h323-tcp-1503", "tcp", "1503", ""},
				{"junos-h323-tcp-389", "tcp", "389", ""},
				{"junos-h323-tcp-522", "tcp", "522", ""},
				{"junos-h323-tcp-1731", "tcp", "1731", ""},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.set, func(t *testing.T) {
			if _, ok := ResolveApplication(tc.set, nil); ok {
				t.Fatalf("%s resolves as a bare predefined application; multi-term Junos defaults must resolve as application-sets", tc.set)
			}
			if _, ok := ResolveApplicationSet(tc.set, nil); !ok {
				t.Fatalf("ResolveApplicationSet(%q, nil) = false, want true", tc.set)
			}
			got, err := ExpandApplicationSet(tc.set, &ApplicationsConfig{})
			if err != nil {
				t.Fatalf("ExpandApplicationSet(%q): %v", tc.set, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExpandApplicationSet(%q) = %v, want %v", tc.set, got, tc.want)
			}
			for _, term := range tc.terms {
				app, ok := ResolveApplication(term.name, nil)
				if !ok {
					t.Fatalf("term application %q is not predefined", term.name)
				}
				if app.Protocol != term.protocol || app.DestinationPort != term.port || app.ALG != term.alg {
					t.Errorf("term %q = protocol %q port %q ALG %q, want protocol %q port %q ALG %q",
						term.name, app.Protocol, app.DestinationPort, app.ALG,
						term.protocol, term.port, term.alg)
				}
			}
		})
	}
}

func TestPredefinedJunosApplicationSetPoliciesCommit_11341(t *testing.T) {
	for _, appSet := range []string{"junos-smb", "junos-h323"} {
		t.Run(appSet, func(t *testing.T) {
			cmds := append(append([]string{}, zoneBoilerplate...),
				"set security policies from-zone trust to-zone untrust policy p match source-address any",
				"set security policies from-zone trust to-zone untrust policy p match destination-address any",
				"set security policies from-zone trust to-zone untrust policy p match application "+appSet,
				"set security policies from-zone trust to-zone untrust policy p then permit",
			)
			if _, err := CompileConfig(buildAppMatchTree(t, cmds...)); err != nil {
				t.Fatalf("CompileConfig with predefined application-set %q: %v", appSet, err)
			}
		})
	}
}

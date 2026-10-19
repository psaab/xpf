package config

import (
	"strings"
	"testing"
)

// #15001 (A08-04): an undefined source-NAT from/to zone or destination-NAT
// from zone was only a commit warning (ValidateConfig), yet the dataplane
// compileNAT pre-pass hard-errors on the same reference and aborts every
// apply. Strict commit must reject naming rule-set and zone; tolerant load
// must warn and retain the rule-set so dataplane compile can skip it.
//
// RED on revert: removing validateNATUndefinedZoneStrict (or its dispatch)
// makes strict CompileConfig accept the typo and this test fails; removing
// the dataplane skip makes lenient+pre-pass fail.

func natZoneTree15001(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func TestNATUndefinedZoneStrictRejected15001(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want []string
	}{
		{
			name: "source from-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source pool pool1 address 192.0.2.10",
				"set security nat source rule-set snat-bad from zone untrsut",
				"set security nat source rule-set snat-bad to zone untrust",
				"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
			},
			want: []string{"snat-bad", "untrsut"},
		},
		{
			name: "source to-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source pool pool1 address 192.0.2.10",
				"set security nat source rule-set snat-bad from zone trust",
				"set security nat source rule-set snat-bad to zone untrsut",
				"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
			},
			want: []string{"snat-bad", "untrsut"},
		},
		{
			name: "destination from-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security nat destination pool P1 address 10.0.30.100",
				"set security nat destination rule-set dnat-bad from zone untrsut",
				"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
			},
			want: []string{"dnat-bad", "untrsut"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(natZoneTree15001(t, tc.cmds...))
			if err == nil {
				t.Fatalf("strict CompileConfig accepted undefined NAT zone; want reject naming %v", tc.want)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Fatalf("strict error %q does not name %q", err.Error(), w)
				}
			}
		})
	}
}

func TestNATUndefinedZoneLenientWarns15001(t *testing.T) {
	cases := []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "source from-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security zones security-zone untrust",
				"set security nat source pool pool1 address 192.0.2.10",
				"set security nat source rule-set snat-bad from zone untrsut",
				"set security nat source rule-set snat-bad to zone untrust",
				"set security nat source rule-set snat-bad rule r1 match source-address 10.0.0.0/8",
				"set security nat source rule-set snat-bad rule r1 then source-nat pool pool1",
			},
			want: "snat-bad",
		},
		{
			name: "destination from-zone",
			cmds: []string{
				"set security zones security-zone trust",
				"set security nat destination pool P1 address 10.0.30.100",
				"set security nat destination rule-set dnat-bad from zone untrsut",
				"set security nat destination rule-set dnat-bad rule R1 match destination-address 198.51.100.5/32",
				"set security nat destination rule-set dnat-bad rule R1 then destination-nat pool P1",
			},
			want: "dnat-bad",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfigLenient(natZoneTree15001(t, tc.cmds...))
			if err != nil {
				t.Fatalf("lenient CompileConfig rejected undefined NAT zone (#1960 no-brick): %v", err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, tc.want) && strings.Contains(w, "untrsut") {
					found = true
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no warning naming %q/untrsut; warnings=%v", tc.want, cfg.Warnings)
			}
			// Rule-set must be retained (not omitted at config compile) so
			// the dataplane tolerant skip is the deciding layer; omission
			// here would also pass lenient but diverge from issue direction.
			// We only assert warning here; dataplane test asserts skip.
		})
	}
}

func TestNATDefinedZoneStillCommits15001(t *testing.T) {
	cfg, err := CompileConfig(natZoneTree15001(t,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security nat source pool pool1 address 192.0.2.10",
		"set security nat source rule-set snat-good from zone trust",
		"set security nat source rule-set snat-good to zone untrust",
		"set security nat source rule-set snat-good rule r1 match source-address 10.0.0.0/8",
		"set security nat source rule-set snat-good rule r1 then source-nat pool pool1",
		"set security nat destination pool P1 address 10.0.30.100",
		"set security nat destination rule-set dnat-good from zone untrust",
		"set security nat destination rule-set dnat-good rule R1 match destination-address 198.51.100.5/32",
		"set security nat destination rule-set dnat-good rule R1 then destination-nat pool P1",
	))
	if err != nil {
		t.Fatalf("defined NAT zones rejected: %v", err)
	}
	if cfg == nil {
		t.Fatal("nil cfg")
	}
}

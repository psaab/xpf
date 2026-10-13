package config

import (
	"reflect"
	"strings"
	"testing"
)

// #12645: lenient compile preserves uppercase host-inbound tokens (strict
// rejects them), and enforcement lowercases before matching, so
// `NETCONF-SSH` admits tcp dport {22,830}. But hostInboundFilterExcept
// matched exclusions case-sensitively: `ssh except` did not subtract the
// uppercase alias, leaving 22/830 admitted. FAIL-ON-REVERT: revert the
// case-folding in hostInboundFilterExcept and the uppercase cases below
// re-admit the excluded tuples.

func lenientHostInbound12645(t *testing.T, text string) *HostInboundTraffic {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	zone := cfg.Security.Zones["trust"]
	if zone == nil || zone.HostInboundTraffic == nil {
		t.Fatal("compiled trust zone has no host-inbound-traffic stanza")
	}
	return zone.HostInboundTraffic
}

func TestHostInboundExceptUppercaseAlias12645(t *testing.T) {
	const prefix = `security { zones { security-zone trust { host-inbound-traffic { `
	const suffix = ` } } } }`
	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			// Reported case: uppercase alias re-admits ssh+netconf tuples.
			name: "uppercase-alias-survives-lowercase-exclusion",
			body: `system-services { NETCONF-SSH; ssh except; }`,
			want: nil,
		},
		{
			name: "mixedcase-alias-upper-exclusion",
			body: `system-services { Netconf-Ssh; SSH except; }`,
			want: nil,
		},
		{
			// Lowercase controls: must keep passing pre- and post-fix.
			name: "lowercase-control",
			body: `system-services { netconf-ssh; ssh except; }`,
			want: nil,
		},
		{
			// Uppercase alias NOT excluded must survive (folding must not
			// become deny-all-uppercase).
			name: "uppercase-alias-allowed",
			body: `system-services { NETCONF-SSH; ping except; }`,
			want: []string{"NETCONF-SSH"},
		},
		{
			name: "uppercase-protocol-exclusion",
			body: `protocols { OSPF; OSPF except; } system-services { ssh; }`,
			want: nil, // checked on Protocols below
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lenientHostInbound12645(t, prefix+tc.body+suffix)
			if tc.name == "uppercase-protocol-exclusion" {
				if len(got.Protocols) != 0 {
					t.Fatalf("protocols = %v, want empty (OSPF excluded)", got.Protocols)
				}
				if !reflect.DeepEqual(got.SystemServices, []string{"ssh"}) {
					t.Fatalf("system-services = %v, want [ssh]", got.SystemServices)
				}
				return
			}
			if len(tc.want) == 0 {
				if len(got.SystemServices) != 0 {
					t.Fatalf("system-services = %v, want empty (excluded alias must not survive)", got.SystemServices)
				}
				return
			}
			if !reflect.DeepEqual(got.SystemServices, tc.want) {
				t.Fatalf("system-services = %v, want %v", got.SystemServices, tc.want)
			}
		})
	}
}

// Tuple-level pin for the reported case: no surviving token may admit
// tcp/22 or tcp/830 on either family.
func TestHostInboundExceptUppercaseAliasTuples12645(t *testing.T) {
	got := lenientHostInbound12645(t, `security { zones { security-zone trust { host-inbound-traffic {
		system-services { NETCONF-SSH; ssh except; }
	} } } }`)
	for _, token := range got.SystemServices {
		for _, family := range []string{"ip", "ip6"} {
			for _, m := range HostInboundServiceMatch(strings.ToLower(token), family) {
				for _, pr := range m.Ports {
					if pr.Lo <= 22 && 22 <= pr.Hi || pr.Lo <= 830 && 830 <= pr.Hi {
						t.Fatalf("token %q family %s still admits port in %v (22/830 must be excluded)", token, family, pr)
					}
				}
			}
		}
	}
}
// Both override scopes are lenient-loaded independently before their tokens
// are merged. Pin each direction so alias canonicalization cannot work only
// within a stanza while leaving the physical/unit union exposed.
func TestHostInboundExceptUppercaseAliasCrossScope12645(t *testing.T) {
	cases := []struct {
		name       string
		directives []string
	}{
		{
			name: "physical-uppercase-alias-unit-exclusion",
			directives: []string{
				crossScopePhysical12317 + "system-services NETCONF-SSH",
				crossScopePhysical12317 + "system-services http",
				crossScopeUnit12317 + "system-services ssh except",
			},
		},
		{
			name: "physical-exclusion-unit-uppercase-alias",
			directives: []string{
				crossScopePhysical12317 + "system-services ssh except",
				crossScopeUnit12317 + "system-services NETCONF-SSH",
				crossScopeUnit12317 + "system-services http",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileCrossScopeExcept12317(t, true, tc.directives...)
			effective := ResolveInterfaceHostInbound(cfg)[crossScopeExceptUnit12317]
			if effective == nil {
				t.Fatalf("no effective host-inbound override for %s", crossScopeExceptUnit12317)
			}
			for _, family := range []string{"ip", "ip6"} {
				tuples := hostInboundAdmissionTupleSet12053(effective.SystemServices, family)
				for _, port := range []uint16{22, 830} {
					if _, ok := tuples[hostInboundTupleKey12053{proto: 6, port: port, portSet: true}]; ok {
						t.Errorf("services %v on %s still admit tcp/%d after ssh exclusion",
							effective.SystemServices, family, port)
					}
				}
				if _, ok := tuples[hostInboundTupleKey12053{proto: 6, port: 80, portSet: true}]; !ok {
					t.Errorf("services %v on %s lost unrelated tcp/80 admission",
						effective.SystemServices, family)
				}
			}
		})
	}
}

func TestHostInboundExceptUppercaseAliasStrictRejects12645(t *testing.T) {
	tree, errs := NewParser(`security { zones { security-zone trust { host-inbound-traffic {
		system-services { NETCONF-SSH; ssh except; }
	} } } }`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "NETCONF-SSH") {
		t.Fatalf("strict compile error = %v, want rejection naming wrong-case NETCONF-SSH", err)
	}
}

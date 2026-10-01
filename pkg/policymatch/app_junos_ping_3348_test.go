package policymatch

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestCustomJunosPingApp_EchoOnly is the #3348 end-to-end fail-on-revert: XPF
// preserves a compatibility extension for a USER-DEFINED application whose
// protocol is the junos-ping alias (Junos rejects that protocol leaf). It must
// permit ICMP echo-request (type 8) ONLY, not every ICMP type. Before the
// compiler attached this constraint, the custom app lowered to bare ICMP
// (ICMPType nil) and silently permitted timestamp/redirect/etc. This behavior
// is distinct from the predefined junos-ping application, which is all-ICMP;
// the predefined echo-only object is junos-icmp-ping (#11340).
func TestCustomJunosPingApp_EchoOnly(t *testing.T) {
	cfg := compileFromSet(t, []string{
		"set applications application mgmt-ping protocol junos-ping",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application mgmt-ping",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	})

	tests := []struct {
		name        string
		icmpType    uint8
		wantMatched bool
		wantAction  config.PolicyAction
	}{
		{"echo-request type 8 permitted", 8, true, config.PolicyPermit},
		{"timestamp type 13 denied", 13, false, config.PolicyDeny},
		{"redirect type 5 denied", 5, false, config.PolicyDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ty := tt.icmpType
			q := Query{FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: &ty}
			res := Match(cfg, q)
			if res.Matched != tt.wantMatched || res.Action != tt.wantAction {
				t.Fatalf("custom junos-ping app, ICMP type %d: got matched=%v action=%v, want matched=%v action=%v",
					tt.icmpType, res.Matched, res.Action, tt.wantMatched, tt.wantAction)
			}
		})
	}
}

// The predefined application is separate from XPF's compatibility handling for
// a user-defined `protocol junos-ping` alias above. The version-bounded Junos
// defaults use protocol-only ICMP/ICMPv6 here, with the echo-only object named
// `junos-icmp-ping`.
func predefinedICMPAppCfg11340(name string) *config.Config {
	return cfgWith(config.SecurityConfig{
		DefaultPolicy: config.PolicyDeny,
		Policies: []*config.ZonePairPolicies{
			zonePair("trust", "untrust", permit("permit-predefined",
				config.PolicyMatch{Applications: []string{name}})),
		},
	}, config.ApplicationsConfig{})
}

func TestPredefinedJunosPingMatchesAllICMP_11340(t *testing.T) {
	cases := []struct {
		name, proto string
		types       []uint8
	}{
		{"junos-ping", "icmp", []uint8{0, 3, 5, 11, 13}},
		{"junos-pingv6", "icmpv6", []uint8{1, 2, 3, 133, 134, 135}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := predefinedICMPAppCfg11340(tc.name)
			for _, icmpType := range tc.types {
				ty := icmpType
				code := uint8(1)
				res := Match(cfg, Query{
					FromZone: "trust", ToZone: "untrust", Protocol: tc.proto,
					ICMPType: &ty, ICMPCode: &code,
				})
				if res.ContentRejected || !res.Matched || res.Action != config.PolicyPermit {
					t.Fatalf("%s type=%d/code=1: got matched=%v action=%v rejected=%v, want permit",
						tc.name, ty, res.Matched, res.Action, res.ContentRejected)
				}
			}
		})
	}
}

func TestPredefinedJunosIcmpPingRemainsEchoOnly_11340(t *testing.T) {
	cfg := predefinedICMPAppCfg11340("junos-icmp-ping")
	for _, tc := range []struct {
		icmpType uint8
		want     config.PolicyAction
	}{
		{8, config.PolicyPermit},
		{3, config.PolicyDeny},
		{11, config.PolicyDeny},
	} {
		ty := tc.icmpType
		res := Match(cfg, Query{
			FromZone: "trust", ToZone: "untrust", Protocol: "icmp", ICMPType: &ty,
		})
		if res.ContentRejected || res.Action != tc.want {
			t.Fatalf("junos-icmp-ping type=%d: got action=%v rejected=%v, want %v",
				ty, res.Action, res.ContentRejected, tc.want)
		}
	}
}

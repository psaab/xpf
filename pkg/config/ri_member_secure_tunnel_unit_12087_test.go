package config

import (
	"reflect"
	"testing"
)

// #12087: a routing-instance member `st<N>.0` must resolve to the xfrmi netdev
// the IPsec reconciler actually creates — the AUTHORED bind-interface string —
// not to the unit-zero collapse `st<N>`. Before the fix,
// routingInstanceMemberLinuxName never consulted SecureTunnelUnitNetdev, so a
// member `st0.0` with `bind-interface st0.0` resolved to `st0`, the VRF bind
// warned "interface st0 not found", and the commit still succeeded.
func TestRIMemberSecureTunnelUnitResolvesAuthoredNetdev12087(t *testing.T) {
	for _, tc := range []struct {
		name string
		bind string
		// member is the RI interface-list spelling under test.
		member string
		// want is the single expected Linux device from
		// RoutingInstanceMemberLinuxNames, pinned against the name the
		// xfrmi reconciler creates (XFRMIfNameAndID of the bind).
		want string
	}{
		{
			name:   "explicit unit-zero bind keeps its dot",
			bind:   "st0.0",
			member: "st0.0",
			want:   "st0.0",
		},
		{
			name:   "bare bind resolves the unit ref to the bare netdev",
			bind:   "st0",
			member: "st0.0",
			want:   "st0",
		},
		{
			name:   "nonzero unit keeps its authored spelling",
			bind:   "st0.1",
			member: "st0.1",
			want:   "st0.1",
		},
		{
			name:   "second tunnel index keeps its authored spelling",
			bind:   "st1.0",
			member: "st1.0",
			want:   "st1.0",
		},
		{
			name:   "unbound in-range unit keeps the old collapse reading",
			bind:   "st9.0",
			member: "st0.0",
			want:   "st0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Security.IPsec.VPNs = map[string]*IPsecVPN{
				"vpn0": {Name: "vpn0", BindInterface: tc.bind},
			}
			if tc.bind != "st9.0" {
				if name, _ := XFRMIfNameAndID(tc.bind); name != tc.want {
					t.Fatalf("premise broken: XFRMIfNameAndID(%q) creates %q, want the asserted %q",
						tc.bind, name, tc.want)
				}
			}
			got := RoutingInstanceMemberLinuxNames(cfg, cfg.TunnelNameMap(), tc.member)
			if !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("RoutingInstanceMemberLinuxNames(%q) with bind %q = %q, want [%q]",
					tc.member, tc.bind, got, tc.want)
			}
		})
	}
}

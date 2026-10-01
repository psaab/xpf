package config

import "testing"

// TestPredefinedICMPApplicationsCarryCorrectConstraints pins the Junos
// application definitions. #11340's version-bounded defaults define
// junos-ping/junos-pingv6 as protocol-only; junos-icmp-ping is echo-request only.
func TestPredefinedICMPApplicationsCarryCorrectConstraints(t *testing.T) {
	cases := []struct {
		name      string
		proto     string
		wantType  uint8
		wantTypeP bool
	}{
		{"junos-ping", "icmp", 0, false},
		{"junos-pingv6", "icmpv6", 0, false},
		{"junos-icmp-ping", "icmp", 8, true},
		{"junos-icmp-all", "icmp", 0, false},
		{"junos-icmp6-all", "icmpv6", 0, false},
	}
	for _, tc := range cases {
		app, ok := PredefinedApplications[tc.name]
		if !ok {
			t.Fatalf("predefined application %q missing", tc.name)
		}
		if app.Protocol != tc.proto {
			t.Errorf("%s Protocol = %q, want %q", tc.name, app.Protocol, tc.proto)
		}
		if tc.wantTypeP {
			if app.ICMPType == nil {
				t.Errorf("%s ICMPType = nil, want %d", tc.name, tc.wantType)
			} else if *app.ICMPType != tc.wantType {
				t.Errorf("%s ICMPType = %d, want %d", tc.name, *app.ICMPType, tc.wantType)
			}
		} else if app.ICMPType != nil {
			t.Errorf("%s ICMPType = %d, want nil (unconstrained)", tc.name, *app.ICMPType)
		}
		if app.ICMPCode != nil {
			t.Errorf("%s ICMPCode = %d, want nil", tc.name, *app.ICMPCode)
		}
	}
}

package config

import "testing"

func TestZoneInterfacePackedMemberKeysSkipApplyMeta12835(t *testing.T) {
	for _, tc := range []struct {
		name string
		keys []string
	}{
		{"apply-macro", []string{"ge-0/0/0.0", "apply-macro", "M"}},
		{"apply-groups", []string{"ge-0/0/0.0", "apply-groups", "G"}},
		{"apply-groups-except", []string{"ge-0/0/0.0", "apply-groups-except", "G"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := zoneInterfaceMembers(&Node{Keys: tc.keys})
			if len(got) != 1 || got[0] != "ge-0/0/0.0" {
				t.Fatalf("zoneInterfaceMembers = %v, want [ge-0/0/0.0]", got)
			}
		})
	}
	// The existing body boundary remains distinct from an apply-meta boundary.
	if got := zoneInterfaceMembers(&Node{Keys: []string{"ge-0/0/0.0", "host-inbound-traffic", "system-services"}}); len(got) != 1 {
		t.Fatalf("ordinary body boundary changed membership: got %v", got)
	}
}

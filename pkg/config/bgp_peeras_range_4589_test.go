package config

import "testing"

// #4589 A3 F-01: BGP peer-as / top-level local-as carried no upper-bound
// validator, so an out-of-range ASN slipped through the strict commit schema
// and the compiler's `Atoi -> uint32(v)` cast SILENTLY WRAPPED it to a
// different-but-valid ASN (peer-as 4294967297 -> remote-as 1) or, for a
// negative, to 4294967295 — a wrong-but-valid FRR config Junos would reject.
// The sibling `local-as` (group + neighbor) leaves already carried
// ValidateInteger(1, 4294967295); this pins the same validator onto the two
// peer-as leaves and top-level local-as.
//
// RED-on-revert: drop the validators from schema_routing.go and the
// out-of-range cases below commit clean (SchemaValidate returns nil).
func TestBGPPeerASRangeRejected(t *testing.T) {
	cases := []struct {
		name string
		set  string
	}{
		{"group peer-as wrap", "set protocols bgp group EXT peer-as 4294967296"},
		{"neighbor peer-as wrap", "set protocols bgp group EXT neighbor 10.0.2.1 peer-as 4294967297"},
		{"top-level local-as wrap", "set protocols bgp local-as 4294967296"},
		{"group peer-as negative", "set protocols bgp group EXT peer-as -1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTreeFromSet(t, []string{tc.set})
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("SchemaValidate accepted out-of-range ASN %q; expected rejection", tc.set)
			}
		})
	}
}

// A valid 2-byte ASN and the 4-byte boundary ASN are accepted on every
// peer-as / local-as leaf.
func TestBGPPeerASRangeAccepted(t *testing.T) {
	cases := []string{
		"set protocols bgp group EXT peer-as 65000",
		"set protocols bgp group EXT neighbor 10.0.2.1 peer-as 65000",
		"set protocols bgp local-as 65000",
		"set protocols bgp group EXT peer-as 4294967295",
	}
	for _, set := range cases {
		tree := buildTreeFromSet(t, []string{set})
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("SchemaValidate rejected valid ASN %q: %v", set, err)
		}
	}
}

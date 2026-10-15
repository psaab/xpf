package main

import "testing"

// TestValidatePolicyZoneSelectors is the #4908 (C175-HC-126) RED-on-revert
// guard for the remote CLI `show security policies` path: a from-zone/to-zone
// selector missing its zone value (e.g. "from-zone trust to-zone") must be
// rejected rather than silently dropped, which returned a broader/one-sided
// policy inventory. Removing the validation makes the malformed cases pass.
func TestValidatePolicyZoneSelectors(t *testing.T) {
	good := [][]string{
		{},
		{"brief"},
		{"from-zone", "trust"},
		{"detail", "from-zone", "trust", "to-zone", "untrust"},
		{"hit-count", "from-zone", "trust"},
	}
	for _, args := range good {
		_, err := parsePolicyShowQuery(args)
		if err != nil {
			t.Errorf("parsePolicyShowQuery(%v) = %v, want nil", args, err)
		}
	}
	bad := [][]string{
		{"from-zone"},
		{"to-zone"},
		{"detail", "from-zone", "trust", "to-zone"},
		{"from-zone", "to-zone", "untrust"},
	}
	for _, args := range bad {
		if _, err := parsePolicyShowQuery(args); err == nil {
			t.Errorf("parsePolicyShowQuery(%v) = nil, want an error (malformed selector)", args)
		}
	}
}

package userspace

import "testing"

func TestJunosValidPolicyTraceoptionsKeepsSnapshot12628(t *testing.T) {
	snap := lenientSnapshot5575(t, [][]string{
		{"security", "zones", "security-zone", "trust"},
		{"security", "zones", "security-zone", "untrust"},
		{"security", "policies", "default-policy", "deny-all"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-web", "match", "source-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-web", "match", "destination-address", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-web", "match", "application", "any"},
		{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-web", "then", "permit"},
		{"security", "policies", "traceoptions", "file", "policies.log"},
	})
	if snapshotHasAppSentinel5575(snap) {
		t.Fatal("Junos-valid policy traceoptions caused a poisoned __unsupported__ snapshot")
	}
	if len(snap.Capabilities.PolicyContentRejected) != 0 {
		t.Fatalf("Junos-valid policy traceoptions caused policy rejection: %v", snap.Capabilities.PolicyContentRejected)
	}
}

package userspace

import "testing"

// TestDNATOffEmitsExemptionSnapshot verifies #3844: the DNAT snapshot builder
// EMITS an entry for a `then destination-nat off` rule (Off == true, empty
// PoolAddress) instead of skipping it as a pool-less rule. The entry carries
// the same destination match as a translate rule so the Rust DnatTable can
// scope the exemption identically and short-circuit later DNAT rules.
//
// RED on revert: reverting the nat.go builder change makes it skip the off rule
// (rule.Then.PoolName == "" continue), so no off entry is emitted and the
// snapshot only has the translate rule — the len/Off assertions fail.
func TestDNATOffEmitsExemptionSnapshot(t *testing.T) {
	cfg := compileSet(t, []string{
		"set security zones security-zone untrust",
		"set security nat destination pool p1 address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r-exempt match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-exempt then destination-nat off",
		"set security nat destination rule-set rs1 rule r-dnat match destination-address 192.0.2.10/32",
		"set security nat destination rule-set rs1 rule r-dnat then destination-nat pool p1",
	})
	snaps := buildDestinationNATSnapshots(cfg, nil)
	if len(snaps) != 2 {
		t.Fatalf("expected 2 DNAT snapshot entries (exemption + translate), got %d: %+v", len(snaps), snaps)
	}
	var exempt, dnat *DestinationNATRuleSnapshot
	for i := range snaps {
		switch snaps[i].Name {
		case "r-exempt":
			exempt = &snaps[i]
		case "r-dnat":
			dnat = &snaps[i]
		}
	}
	if exempt == nil {
		t.Fatalf("no snapshot emitted for the `then destination-nat off` rule (the #3844 fail-open)")
	}
	if !exempt.Off {
		t.Errorf("off rule snapshot Off = false, want true")
	}
	if exempt.PoolAddress != "" {
		t.Errorf("off rule snapshot PoolAddress = %q, want empty", exempt.PoolAddress)
	}
	if exempt.DestinationAddress != "192.0.2.10" {
		t.Errorf("off rule snapshot DestinationAddress = %q, want 192.0.2.10", exempt.DestinationAddress)
	}
	// The exemption emits FIRST (config order) so it wins the Rust `.find()`.
	if snaps[0].Name != "r-exempt" {
		t.Errorf("exemption must be emitted before the translate rule; order = [%s, %s]", snaps[0].Name, snaps[1].Name)
	}
	// The translate rule is unaffected: Off false, pool address populated.
	if dnat == nil || dnat.Off || dnat.PoolAddress != "10.0.0.5" {
		t.Errorf("translate snapshot = %+v, want Off=false PoolAddress=10.0.0.5", dnat)
	}
}

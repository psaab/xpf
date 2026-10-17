package userspace

import "testing"

// #14367: prefix-spelled pool + NAT64 coverage for the interface-SNAT overlap detector.
// RED on base: prefix yields no finding (host spelling mismatch), NAT64 yields none.

func TestInterfaceSNATPoolOverlapPrefixMember14367(t *testing.T) {
	snap := overlapSnapshot(ifaceModeRule(), poolRuleOn("172.16.80.0/24"), wanUnit())
	got := detectInterfaceSNATPoolOverlaps(snap)
	if len(got) != 1 || got[0].Address != overlapEgress {
		t.Fatalf("prefix pool member: got %v, want 1 finding for %s", got, overlapEgress)
	}
	// Control: prefix not containing egress.
	snap2 := overlapSnapshot(ifaceModeRule(), poolRuleOn("198.51.100.0/24"), wanUnit())
	if got := detectInterfaceSNATPoolOverlaps(snap2); len(got) != 0 {
		t.Fatalf("disjoint prefix: got %v, want 0", got)
	}
	// Control: range spelling "a-b" if supported as member? Detector must not panic.
	snap3 := overlapSnapshot(ifaceModeRule(), poolRuleOn("172.16.80.0-172.16.80.255"), wanUnit())
	_ = detectInterfaceSNATPoolOverlaps(snap3)
}

func TestInterfaceSNATPoolOverlapNAT64_14367(t *testing.T) {
	snap := overlapSnapshot(ifaceModeRule(), nil, wanUnit())
	snap.NAT64 = []NAT64RuleSnapshot{{Name: "n64", Prefix: "64:ff9b::/96", PoolAddresses: []string{overlapEgress}}}
	got := detectInterfaceSNATPoolOverlaps(snap)
	if len(got) != 1 || got[0].Address != overlapEgress || got[0].PoolRule != "n64" {
		t.Fatalf("NAT64 pool: got %v, want 1 finding naming n64 for %s", got, overlapEgress)
	}
	// NAT64 prefix-spelled pool containing egress.
	snap2 := overlapSnapshot(ifaceModeRule(), nil, wanUnit())
	snap2.NAT64 = []NAT64RuleSnapshot{{Name: "n64p", Prefix: "64:ff9b::/96", PoolAddresses: []string{"172.16.80.0/24"}}}
	got2 := detectInterfaceSNATPoolOverlaps(snap2)
	if len(got2) != 1 || got2[0].PoolRule != "n64p" {
		t.Fatalf("NAT64 prefix pool: got %v, want 1 finding naming n64p", got2)
	}
	// Control disjoint NAT64.
	snap3 := overlapSnapshot(ifaceModeRule(), nil, wanUnit())
	snap3.NAT64 = []NAT64RuleSnapshot{{Name: "n64", Prefix: "64:ff9b::/96", PoolAddresses: []string{"198.51.100.7"}}}
	if got := detectInterfaceSNATPoolOverlaps(snap3); len(got) != 0 {
		t.Fatalf("disjoint NAT64: got %v, want 0", got)
	}
}

func TestInterfaceSNATNAT64ReportDoesNotPanic14367(t *testing.T) {
	// report must not quarantine NAT64 (no PoolUnusable transport on NAT64 snapshot);
	// it only records findings. Just ensure no panic and source pools untouched.
	snap := overlapSnapshot(ifaceModeRule(), poolRuleOn("198.51.100.7"), wanUnit())
	snap.NAT64 = []NAT64RuleSnapshot{{Name: "n64", Prefix: "64:ff9b::/96", PoolAddresses: []string{overlapEgress}}}
	reportInterfaceSNATPoolOverlaps(snap)
	for _, r := range snap.SourceNAT {
		if r.PoolName == "P" && r.PoolUnusable {
			t.Fatalf("NAT64 finding must not quarantine unrelated source pool: %+v", r)
		}
	}
}

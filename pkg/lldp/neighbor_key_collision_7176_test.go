package lldp

import "testing"

// #7176 (C179-026). The neighbor table used a "%s/%s/%s"-joined string key over
// the interface name and two PEER-CONTROLLED TLV strings. Port IDs legitimately
// contain "/" (a Junos-style ge-0/0/1), so the join is ambiguous — and because a
// TTL=0 LLDPDU is an explicit withdrawal that deletes BY KEY, a peer able to
// choose its own ChassisID/PortID could forge the key of a DIFFERENT neighbor
// and evict an entry it does not own.
//
// The fixture is the smallest shape where the ambiguity produces a wrong
// outcome, and both rows format to the SAME legacy string:
//
//	victim:   chassis "aa"    port "bb/cc"  -> "eth0/aa/bb/cc"
//	attacker: chassis "aa/bb" port "cc"     -> "eth0/aa/bb/cc"
//
// Reverting neighborKey to the joined string makes the eviction succeed and
// this test RED.
func TestNeighborKeyCollisionCannotEvictAnotherPeer_7176(t *testing.T) {
	m := New()

	// Built through the PRODUCTION constructor, not by hand. A hand-assembled
	// key cannot see the receive path revert to joining the components, which is
	// where the collision is actually created. Learning is keyed by the same
	// constructor so the stored entry and the lookup cannot drift apart.
	victim := &Neighbor{ChassisID: "aa", PortID: "bb/cc", Interface: "eth0"}
	attacker := &Neighbor{ChassisID: "aa/bb", PortID: "cc", Interface: "eth0"}
	victimKey := neighborKeyFor("eth0", victim)
	attackerKey := neighborKeyFor("eth0", attacker)

	// The two keys must be DISTINCT. Under the old joined-string key they were
	// byte-identical, so this is the property the struct buys and asserting it
	// directly means the test still means something if the withdraw path moves.
	if victimKey == attackerKey {
		t.Fatal("the two keys are equal — the peer-controlled components are still " +
			"joined ambiguously, so a crafted frame can address another neighbor's entry")
	}

	if !m.learnNeighbor(victimKey, victim) {
		t.Fatal("precondition: the victim neighbor must be admitted")
	}
	if got := len(m.Neighbors()); got != 1 {
		t.Fatalf("precondition: %d neighbors, want 1", got)
	}

	// The attacker's TTL=0 shutdown frame. Same interface, chosen ChassisID and
	// PortID, and it addresses a key that does not exist — so it must be a no-op.
	m.withdrawNeighbor(attackerKey)

	if got := len(m.Neighbors()); got != 1 {
		t.Fatalf("a crafted TTL=0 frame from a peer evicted a DIFFERENT peer's neighbor "+
			"entry: %d neighbors remain, want 1 (#7176 C179-026)", got)
	}
}

// The paired cell. Without it, a withdrawNeighbor that never deleted anything
// would satisfy the test above — and the withdrawal path is load-bearing (#5123:
// a peer that announced its departure must disappear now, not up to 10s later).
func TestNeighborWithdrawStillWorksForItsOwnKey_7176(t *testing.T) {
	m := New()
	own := mkNeighborKey("eth0", "aa", "bb/cc")
	if !m.learnNeighbor(own, mkNeighbor("eth0", "aa", "bb/cc")) {
		t.Fatal("precondition: neighbor must be admitted")
	}
	m.withdrawNeighbor(own)
	if got := len(m.Neighbors()); got != 0 {
		t.Fatalf("withdrawNeighbor did not remove its own key: %d neighbors remain, want 0 — "+
			"the #5123 immediate-withdrawal path is broken", got)
	}
}

// A slash-bearing port ID must round-trip through learn and read-back unharmed.
// It is the realistic shape (ge-0/0/1) and the reason a separator key was wrong
// in the first place.
func TestSlashBearingPortIDRoundTrips_7176(t *testing.T) {
	m := New()
	k := mkNeighborKey("eth0", "02:00:00:00:00:01", "ge-0/0/1")
	if !m.learnNeighbor(k, mkNeighbor("eth0", "02:00:00:00:00:01", "ge-0/0/1")) {
		t.Fatal("a neighbor with a slash-bearing port id was not admitted")
	}
	ns := m.Neighbors()
	if len(ns) != 1 {
		t.Fatalf("%d neighbors, want 1", len(ns))
	}
	if ns[0].PortID != "ge-0/0/1" {
		t.Errorf("PortID = %q, want %q", ns[0].PortID, "ge-0/0/1")
	}
}

// Tests for the #1197 publishable predicate and forwarding-
// effective equality.
package userspace

import "testing"

func TestNeighborSnapshotPublishable(t *testing.T) {
	tests := []struct {
		name string
		n    NeighborSnapshot
		want bool
	}{
		{
			"reachable IPv4 with MAC",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "reachable"},
			true,
		},
		{
			"stale IPv4 with MAC — usable for forwarding",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "stale"},
			true,
		},
		{
			"delay state usable",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "delay"},
			true,
		},
		{
			"permanent usable",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "permanent"},
			true,
		},
		{
			"failed unusable",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "failed"},
			false,
		},
		{
			"incomplete unusable",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "incomplete"},
			false,
		},
		{
			"none state rejected (state==0 has no learned MAC info)",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "none"},
			false,
		},
		{
			"empty MAC rejected",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "", State: "reachable"},
			false,
		},
		{
			"malformed MAC rejected",
			NeighborSnapshot{Ifindex: 5, IP: "10.0.0.1", MAC: "not-a-mac", State: "reachable"},
			false,
		},
		{
			"invalid IP rejected",
			NeighborSnapshot{Ifindex: 5, IP: "not-an-ip", MAC: "aa:bb:cc:dd:ee:ff", State: "reachable"},
			false,
		},
		{
			"zero ifindex rejected",
			NeighborSnapshot{Ifindex: 0, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:ff", State: "reachable"},
			false,
		},
		{
			"IPv6 reachable with MAC",
			NeighborSnapshot{Ifindex: 5, IP: "2001:db8::1", MAC: "aa:bb:cc:dd:ee:ff", State: "reachable"},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := neighborSnapshotPublishable(tc.n)
			if got != tc.want {
				t.Errorf("neighborSnapshotPublishable(%+v) = %v, want %v", tc.n, got, tc.want)
			}
		})
	}
}

func TestNeighborsEqualForwarding(t *testing.T) {
	mkN := func(ifindex int, ip, mac, state string) NeighborSnapshot {
		return NeighborSnapshot{
			Ifindex: ifindex, IP: ip, MAC: mac, State: state, Family: "inet",
		}
	}

	t.Run("same MAC, REACHABLE↔STALE churn ignored", func(t *testing.T) {
		a := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "reachable")}
		b := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "stale")}
		if !neighborsEqualForwarding(a, b) {
			t.Error("REACHABLE→STALE on same MAC should be forwarding-equal")
		}
	})

	t.Run("MAC change detected", func(t *testing.T) {
		a := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "reachable")}
		b := []NeighborSnapshot{mkN(5, "10.0.0.1", "11:22:33:44:55:66", "reachable")}
		if neighborsEqualForwarding(a, b) {
			t.Error("MAC change should be detected as forwarding-different")
		}
	})

	t.Run("transition to FAILED detected as key removal", func(t *testing.T) {
		a := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "reachable")}
		b := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "failed")}
		if neighborsEqualForwarding(a, b) {
			t.Error("transition to FAILED should be detected (publishable key removed)")
		}
	})

	t.Run("transition to INCOMPLETE detected as key removal", func(t *testing.T) {
		a := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "reachable")}
		b := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "incomplete")}
		if neighborsEqualForwarding(a, b) {
			t.Error("transition to INCOMPLETE should be detected")
		}
	})

	t.Run("new entry detected", func(t *testing.T) {
		a := []NeighborSnapshot{}
		b := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "reachable")}
		if neighborsEqualForwarding(a, b) {
			t.Error("new publishable entry should be detected")
		}
	})

	t.Run("entry removal detected", func(t *testing.T) {
		a := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "reachable")}
		b := []NeighborSnapshot{}
		if neighborsEqualForwarding(a, b) {
			t.Error("entry removal should be detected")
		}
	})

	t.Run("non-publishable entries ignored on both sides", func(t *testing.T) {
		// Both sides have an unusable INCOMPLETE entry → both
		// publishable-sets are empty → equal.
		a := []NeighborSnapshot{mkN(5, "10.0.0.1", "aa:bb:cc:dd:ee:ff", "incomplete")}
		b := []NeighborSnapshot{mkN(5, "10.0.0.1", "11:22:33:44:55:66", "incomplete")}
		if !neighborsEqualForwarding(a, b) {
			t.Error("two unpublishable entries should compare equal (both empty publishable sets)")
		}
	})

	t.Run("identical empty slices equal", func(t *testing.T) {
		if !neighborsEqualForwarding(nil, []NeighborSnapshot{}) {
			t.Error("nil and empty slice should be forwarding-equal")
		}
	})
}

func TestFilterPublishableNeighbors(t *testing.T) {
	in := []NeighborSnapshot{
		{Ifindex: 1, IP: "10.0.0.1", MAC: "aa:bb:cc:dd:ee:01", State: "reachable", Family: "inet"},
		{Ifindex: 1, IP: "10.0.0.2", MAC: "", State: "incomplete", Family: "inet"},
		{Ifindex: 1, IP: "10.0.0.3", MAC: "aa:bb:cc:dd:ee:03", State: "stale", Family: "inet"},
		{Ifindex: 1, IP: "10.0.0.4", MAC: "aa:bb:cc:dd:ee:04", State: "failed", Family: "inet"},
	}
	out := filterPublishableNeighbors(in)
	if len(out) != 2 {
		t.Fatalf("filterPublishableNeighbors got %d entries, want 2", len(out))
	}
	if out[0].IP != "10.0.0.1" || out[1].IP != "10.0.0.3" {
		t.Errorf("filtered entries unexpected: %+v", out)
	}
}

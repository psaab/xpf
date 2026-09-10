package userspace

import "testing"

// #9016: the multi-port WireGuard advisory in pkg/config asserts a specific
// dataplane fact — that only ONE configured listen-port is steered onto the
// AF_XDP path. This cell pins that fact HERE, at the mechanism, so the two
// cannot drift: if multi-port steering lands (#1434 Increment 2), this reds and
// whoever lands it is sent to the advisory text that describes it.
//
// #9521 moved WHICH port that is out of this package. It used to be "the first
// wireguard row of snapshot.TunnelEndpoints", and this cell pinned that order
// dependence by reversing the rows. Those rows are the configured endpoints
// intersected with the live interface rows, so the order dependence WAS the
// defect: a missing netdev promoted the next tunnel's port, the one the commit
// warning had just called unsteered. The steered port is now
// config.SteeredWireGuardListenPort (name order, pinned in pkg/config), stamped
// onto the snapshot as WgSteeredListenPort, and the reader must ignore the rows
// entirely — which is what the reversed, absent and empty cases below assert.
func TestOnlyFirstWireGuardListenPortIsSteered9016(t *testing.T) {
	rows := []TunnelEndpointSnapshot{
		{ID: 1, Mode: "wireguard", WgListenPort: 51820},
		{ID: 2, Mode: "wireguard", WgListenPort: 51821},
	}
	if got := snapshotWgListenPort(&ConfigSnapshot{TunnelEndpoints: rows, WgSteeredListenPort: 51820}); got != 51820 {
		t.Fatalf("snapshotWgListenPort = %d, want the snapshot's steered port 51820", got)
	}

	// ONE scalar, whatever the rows say. Reversing them must not move it — the
	// pre-#9521 reader returned 51821 here.
	rev := &ConfigSnapshot{
		TunnelEndpoints:     []TunnelEndpointSnapshot{rows[1], rows[0]},
		WgSteeredListenPort: 51820,
	}
	if got := snapshotWgListenPort(rev); got != 51820 {
		t.Fatalf("reversed rows moved the steered port to %d; want 51820", got)
	}

	// The steered tunnel's row ABSENT (its netdev is missing) must not promote
	// the next row. This is the second half of #9521.
	absent := &ConfigSnapshot{TunnelEndpoints: rows[1:], WgSteeredListenPort: 51820}
	if got := snapshotWgListenPort(absent); got != 51820 {
		t.Fatalf("with the steered tunnel's row absent, snapshotWgListenPort = %d; want 51820 — "+
			"a promoted port is a port the commit warning called unsteered", got)
	}

	// A single tunnel is the ordinary case and must be steered.
	if got := snapshotWgListenPort(&ConfigSnapshot{TunnelEndpoints: rows[:1], WgSteeredListenPort: 51820}); got != 51820 {
		t.Fatalf("single-tunnel snapshotWgListenPort = %d, want 51820", got)
	}

	// No steered port on the snapshot means nothing is steered, even with
	// WireGuard rows present: the reader must not fall back to deriving one.
	if got := snapshotWgListenPort(&ConfigSnapshot{TunnelEndpoints: rows}); got != 0 {
		t.Fatalf("a snapshot with no WgSteeredListenPort yielded steered port %d; want 0", got)
	}
	if got := snapshotWgListenPort(nil); got != 0 {
		t.Fatalf("nil snapshot yielded steered port %d; want 0", got)
	}
}

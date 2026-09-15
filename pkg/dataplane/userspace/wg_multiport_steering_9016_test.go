package userspace

import (
	"reflect"
	"testing"
)

// #9587: the multi-port WireGuard advisory in pkg/config asserts a dataplane
// fact — that the SELECTED steered set (at most MaxSteeredWireGuardPorts) is
// what the shim programs. This cell pins that fact HERE, at the mechanism, so
// the two cannot drift: the reader takes the snapshot's steered field and
// nothing derived from endpoint rows.
func TestSnapshotSteeredSetIgnoresEndpointRows9587(t *testing.T) {
	rows := []TunnelEndpointSnapshot{
		{ID: 1, Mode: "wireguard", WgListenPort: 51820},
		{ID: 2, Mode: "wireguard", WgListenPort: 51821},
	}
	want := []uint16{51820, 51821}
	if got := snapshotWgListenPorts(&ConfigSnapshot{TunnelEndpoints: rows, WgSteeredListenPorts: want}); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshotWgListenPorts = %v, want the snapshot's steered set %v", got, want)
	}

	// Rows in ANY order must not move the set — the pre-#9521 reader derived
	// from row order here.
	rev := &ConfigSnapshot{
		TunnelEndpoints:      []TunnelEndpointSnapshot{rows[1], rows[0]},
		WgSteeredListenPorts: want,
	}
	if got := snapshotWgListenPorts(rev); !reflect.DeepEqual(got, want) {
		t.Fatalf("reversed rows moved the steered set to %v; want %v", got, want)
	}

	// A steered tunnel's row ABSENT (its netdev is missing) must not promote
	// anything: the set is the field, not the rows.
	absent := &ConfigSnapshot{TunnelEndpoints: rows[1:], WgSteeredListenPorts: want}
	if got := snapshotWgListenPorts(absent); !reflect.DeepEqual(got, want) {
		t.Fatalf("with a steered tunnel's row absent, snapshotWgListenPorts = %v; want %v", got, want)
	}

	// A single tunnel is the ordinary case and must be steered.
	if got := snapshotWgListenPorts(&ConfigSnapshot{TunnelEndpoints: rows[:1], WgSteeredListenPorts: []uint16{51820}}); !reflect.DeepEqual(got, []uint16{51820}) {
		t.Fatalf("single-tunnel snapshotWgListenPorts = %v, want [51820]", got)
	}

	// No steered set on the snapshot means nothing is steered, even with
	// WireGuard rows present: the reader must not fall back to deriving one.
	if got := snapshotWgListenPorts(&ConfigSnapshot{TunnelEndpoints: rows}); len(got) != 0 {
		t.Fatalf("a snapshot with no WgSteeredListenPorts yielded steered set %v; want empty", got)
	}
	if got := snapshotWgListenPorts(nil); len(got) != 0 {
		t.Fatalf("nil snapshot yielded steered set %v; want empty", got)
	}
}

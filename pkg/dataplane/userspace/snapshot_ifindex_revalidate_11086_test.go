package userspace

import "testing"

// TestRevalidateSnapshotIfindexes11086 pins #11086 Part 1: rows built
// before link churn are refreshed (name re-resolves to a new ifindex) or
// dropped (netdev gone) at apply time — never shipped stale.
func TestRevalidateSnapshotIfindexes11086(t *testing.T) {
	orig := buildLinkSnapshot
	defer func() { buildLinkSnapshot = orig }()
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		switch linuxName {
		case "ge-0-0-0":
			return 21, 1500, "", nil // unchanged
		case "ge-0-0-1":
			return 99, 1500, "", nil // recreated: was 24, now 99
		default:
			return 0, 0, "", nil // vanished
		}
	}
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "ge-0/0/0", LinuxName: "ge-0-0-0", Ifindex: 21},
		{Name: "ge-0/0/1", LinuxName: "ge-0-0-1", Ifindex: 24},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Ifindex: 25},
		{Name: "lo0", LinuxName: "", Ifindex: 1},
	}}
	refreshed, dropped := revalidateSnapshotIfindexes(snap)
	if refreshed != 1 || dropped != 1 {
		t.Fatalf("refreshed=%d dropped=%d, want 1/1", refreshed, dropped)
	}
	if len(snap.Interfaces) != 3 {
		t.Fatalf("want 3 surviving rows, got %d", len(snap.Interfaces))
	}
	for _, row := range snap.Interfaces {
		switch row.Name {
		case "ge-0/0/0":
			if row.Ifindex != 21 {
				t.Errorf("unchanged row moved: %+v", row)
			}
		case "ge-0/0/1":
			if row.Ifindex != 99 {
				t.Errorf("churned row not refreshed: %+v", row)
			}
		case "ge-0/0/2":
			t.Errorf("vanished row survived: %+v", row)
		}
	}
}

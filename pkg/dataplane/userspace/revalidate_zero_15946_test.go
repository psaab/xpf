package userspace

import "testing"

// #15946 H44-02: build-time Ifindex==0 rows (st0) retained; vanished live rows dropped.
func TestRevalidateRetainsBuildTimeZero15946(t *testing.T) {
	orig := buildLinkSnapshot
	defer func() { buildLinkSnapshot = orig }()
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) { return 0, 0, "", nil }
	snap := &ConfigSnapshot{Interfaces: []InterfaceSnapshot{
		{Name: "st0.0", LinuxName: "st0", Ifindex: 0, IsUnit: true, SecureTunnel: true},
		{Name: "ge-0/0/2", LinuxName: "ge-0-0-2", Ifindex: 25},
	}}
	_, dropped := revalidateSnapshotIfindexes(snap)
	if dropped != 1 {
		t.Fatalf("dropped=%d want 1 (only vanished live row)", dropped)
	}
	found := false
	for _, r := range snap.Interfaces {
		if r.Name == "st0.0" {
			found = true
		}
	}
	if !found {
		t.Fatal("st0.0 build-time-zero row must be retained")
	}
}

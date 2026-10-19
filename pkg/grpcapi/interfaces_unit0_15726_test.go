package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15726: GetInterfaces must emit one canonical row for reth0/reth0.0
// with Zone="trust". Pre-fix it emitted both "reth0" (Zone="") and
// "reth0.0" (Zone="trust") resolving to the same kernel device.
func TestGetInterfaces_NoDuplicateUnit0RowAndPreservesZone15726(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	sets := []string{
		"set chassis cluster reth-count 1",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet dhcp",
		"set security zones security-zone trust interfaces reth0.0",
	}
	for _, line := range sets {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	s := &Server{store: store}
	resp, err := s.GetInterfaces(context.Background(), &pb.GetInterfacesRequest{})
	if err != nil {
		t.Fatalf("GetInterfaces: %v", err)
	}
	count := 0
	for _, ii := range resp.Interfaces {
		if strings.HasPrefix(ii.Name, "reth0") {
			count++
			if ii.Zone != "trust" {
				t.Fatalf("row %q zone = %q, want trust", ii.Name, ii.Zone)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row for reth0/reth0.0, got %d: %+v", count, resp.Interfaces)
	}
}

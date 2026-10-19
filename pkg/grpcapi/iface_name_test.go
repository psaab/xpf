package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestGetInterfaces_ResolvesRethToLoopback is the gRPC analogue of the
// REST TestInterfacesHandler_ResolvesRethToLoopback (pkg/api). It pins
// the #3460 fix: GetInterfaces must translate a Junos config name to its
// kernel ifname via (*Config).ResolveKernelIfName before calling
// net.InterfaceByName, exactly like REST /interfaces, /stats/interfaces,
// and the Prometheus collector (#1565).
//
// We synthesize a cfg where reth0's RETH member is literally named "lo"
// — the loopback netdev is the only one guaranteed to exist on any Linux
// test runner. Pre-fix, the raw lookup of "reth0" returns no kernel
// ifindex (RETH names are virtual aliases). Post-fix,
// ResolveKernelIfName("reth0") returns "lo" and the row's ifindex matches
// net.InterfaceByName("lo").Index. Revert the fix (raw ifName lookup) and
// the ifindex assertion goes RED (ifindex=0).
func TestGetInterfaces_ResolvesRethToLoopback(t *testing.T) {
	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("test runner has no lo netdev: %v", err)
	}

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	sets := []string{
		"set chassis cluster reth-count 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
		"set interfaces lo gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set security zones security-zone trust interfaces reth0",
	}
	for _, s := range sets {
		if _, err := store.LoadSet(s); err != nil {
			t.Fatalf("LoadSet(%q): %v", s, err)
		}
	}
	cfg, err := store.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Sanity: the test cfg must actually resolve reth0 -> lo, else we'd be
	// asserting against a false-zero rather than the translation.
	if got := cfg.ResolveKernelIfName("reth0"); got != "lo" {
		t.Fatalf("ResolveKernelIfName(reth0) = %q, want lo (test cfg setup wrong)", got)
	}

	s := &Server{store: store}

	resp, err := s.GetInterfaces(context.Background(), &pb.GetInterfacesRequest{})
	if err != nil {
		t.Fatalf("GetInterfaces: %v", err)
	}

	var rethRow *pb.InterfaceInfo
	for _, ii := range resp.Interfaces {
		if ii.Name == "reth0" {
			rethRow = ii
			break
		}
	}
	if rethRow == nil {
		t.Fatalf("no row for reth0 in GetInterfaces response: %+v", resp.Interfaces)
	}
	if int(rethRow.Ifindex) != loIface.Index {
		t.Errorf("reth0 ifindex = %d, want %d (loopback) — kernel-name translation broken",
			rethRow.Ifindex, loIface.Index)
	}
}

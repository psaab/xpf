package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestClearDHCPClientIdentifierResolves15756 is the #15756 RED/GREEN cell
// for the gRPC surface (the remote CLI forwards here): a scoped clear must
// delete the DUID persisted under the lease key for every legitimate
// operator spelling, and must refuse (deleting nothing) for unknown /
// non-DHCP names. Pre-fix the raw spelling reached ClearDUID: `ge-0/0/0`
// errored at the filename validator (wrong code, file survives) and
// `reth0.0` / `ge-0-0-3.99`-style names returned success with the actual
// unit's file intact.
func TestClearDHCPClientIdentifierResolves15756(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet { dhcp; }
        }
    }
    ge-0/0/3 {
        vlan-tagging;
        unit 7 {
            vlan-id 50;
            family inet6 { dhcpv6; }
        }
    }
    ge-0/0/1 {
        unit 0 {
            family inet { address 192.0.2.1/24; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	newMgr := func(t *testing.T) (*dhcp.Manager, string) {
		t.Helper()
		dir := t.TempDir()
		mgr, err := dhcp.New(dir, nil, nil)
		if err != nil {
			t.Fatalf("dhcp.New: %v", err)
		}
		for _, key := range []string{"ge-0-0-0", "ge-0-0-3.50"} {
			if err := os.WriteFile(filepath.Join(dir, "dhcpv6-duid-"+key), []byte{0, 1}, 0o600); err != nil {
				t.Fatalf("seed DUID %s: %v", key, err)
			}
		}
		return mgr, dir
	}
	present := func(dir, key string) bool {
		_, err := os.Stat(filepath.Join(dir, "dhcpv6-duid-"+key))
		return err == nil
	}

	clears := []struct{ in, key string }{
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0/0/0.0", "ge-0-0-0"},
		{"ge-0/0/3.7", "ge-0-0-3.50"},
		{"ge-0-0-3.50", "ge-0-0-3.50"},
	}
	for _, tc := range clears {
		t.Run("clear "+tc.in, func(t *testing.T) {
			mgr, dir := newMgr(t)
			s := &Server{store: store, dhcp: mgr}
			resp, err := s.ClearDHCPClientIdentifier(context.Background(), &pb.ClearDHCPClientIdentifierRequest{Interface: tc.in})
			if err != nil {
				t.Fatalf("clear %q: %v", tc.in, err)
			}
			if !strings.Contains(resp.Message, "DHCPv6 DUID cleared for "+tc.in) {
				t.Errorf("clear %q message = %q", tc.in, resp.Message)
			}
			if present(dir, tc.key) {
				t.Errorf("clear %q: DUID under lease key %q survived", tc.in, tc.key)
			}
		})
	}
	for _, in := range []string{"ge-0/0/9", "ge-0/0/1", "ge-0-0-3.99"} {
		t.Run("refuse "+in, func(t *testing.T) {
			mgr, dir := newMgr(t)
			s := &Server{store: store, dhcp: mgr}
			_, err := s.ClearDHCPClientIdentifier(context.Background(), &pb.ClearDHCPClientIdentifierRequest{Interface: in})
			if status.Code(err) != codes.NotFound {
				t.Errorf("clear %q code = %v, want NotFound (err=%v)", in, status.Code(err), err)
			}
			if !present(dir, "ge-0-0-0") || !present(dir, "ge-0-0-3.50") {
				t.Errorf("clear %q deleted a DUID despite refusing", in)
			}
		})
	}
	// Lease-key-shaped but unconfigured names clear idempotently on the
	// exact key named (absent file = success), deleting that key's file
	// when present — never a silent no-op on a different unit's DUID.
	for _, in := range []string{"reth0.0"} {
		t.Run("idempotent "+in, func(t *testing.T) {
			mgr, dir := newMgr(t)
			s := &Server{store: store, dhcp: mgr}
			if _, err := s.ClearDHCPClientIdentifier(context.Background(), &pb.ClearDHCPClientIdentifierRequest{Interface: in}); err != nil {
				t.Errorf("clear %q: %v, want idempotent success", in, err)
			}
			if !present(dir, "ge-0-0-0") || !present(dir, "ge-0-0-3.50") {
				t.Errorf("clear %q deleted a different unit's DUID", in)
			}
		})
	}
	// No store: a lease-key-shaped name still clears idempotently; a
	// Junos spelling refuses rather than silently succeeding.
	mgr, dir := newMgr(t)
	if _, err := (&Server{dhcp: mgr}).ClearDHCPClientIdentifier(context.Background(), &pb.ClearDHCPClientIdentifierRequest{Interface: "ge-0-0-0"}); err != nil {
		t.Errorf("no-store lease-key clear: %v, want idempotent success", err)
	}
	if present(dir, "ge-0-0-0") {
		t.Error("no-store lease-key clear left ge-0-0-0 DUID behind")
	}
	mgr, dir = newMgr(t)
	if _, err := (&Server{dhcp: mgr}).ClearDHCPClientIdentifier(context.Background(), &pb.ClearDHCPClientIdentifierRequest{Interface: "ge-0/0/0"}); status.Code(err) != codes.NotFound {
		t.Errorf("no-store Junos clear code = %v, want NotFound (err=%v)", status.Code(err), err)
	}
	if !present(dir, "ge-0-0-0") {
		t.Error("no-store Junos clear deleted the DUID despite refusing")
	}
	mgr, dir = newMgr(t)
	resp, err := (&Server{store: store, dhcp: mgr}).ClearDHCPClientIdentifier(context.Background(), &pb.ClearDHCPClientIdentifierRequest{})
	if err != nil || !strings.Contains(resp.Message, "All DHCPv6 DUIDs cleared") {
		t.Fatalf("clear-all = %q, %v", resp.GetMessage(), err)
	}
	if present(dir, "ge-0-0-0") || present(dir, "ge-0-0-3.50") {
		t.Error("clear-all left a seeded DUID behind")
	}
}

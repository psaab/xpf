package grpcapi

import (
	"context"
	"errors"
	"github.com/psaab/xpf/pkg/factoryreset"
	"path/filepath"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// zeroizeMarker stands in for any prior-tenant secret leaf (IKE PSK, WireGuard
// key, SNMP community). The test proves no file carrying it survives a zeroize
// and that a fresh Store.Load does not resurrect it.
const zeroizeMarker = "MARKER-SECRET-4576-ike-psk"

// TestZeroizeSurfacesWipeError pins #4576 requirement 3: a wipe that fails to
// fully erase config state must surface an error at the RPC boundary, not
// report a clean factory reset.
func TestZeroizeSurfacesWipeError(t *testing.T) {
	t.Cleanup(factoryreset.StubWipeWithLogInventoryForTest(func(_, _, _ string, _ factoryreset.LogInventory, _ factoryreset.Completion) error {
		return errors.New("simulated .configdb wipe failure")
	}))

	dir := t.TempDir()
	store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
	s := &Server{store: store}

	resp, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "zeroize"})
	if err == nil {
		t.Fatalf("SystemAction(zeroize) with failing wipe returned nil error, resp=%v", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("SystemAction(zeroize) error code = %v, want Internal", status.Code(err))
	}
}

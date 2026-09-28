package cli

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"google.golang.org/grpc/metadata"
)

type persistentNATClearCLIBackend10784 struct {
	*dataplane.Manager
	calls int
	count uint64
	err   error
}

func (d *persistentNATClearCLIBackend10784) ClearPersistentNATLeases() (uint64, error) {
	d.calls++
	if d.err != nil {
		return 0, d.err
	}
	d.GetPersistentNAT().Clear()
	return d.count, nil
}

func TestClearPersistentNATUsesAuthorityAndPropagatesToPeer10784(t *testing.T) {
	dp := &persistentNATClearCLIBackend10784{Manager: dataplane.New(), count: 7}
	table := dp.GetPersistentNAT()
	table.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.10"),
		SrcPort:  40000,
		NatIP:    netip.MustParseAddr("192.0.2.10"),
		NatPort:  50000,
		PoolName: "pool-a",
	})
	c := &CLI{dp: dp, cluster: cluster.NewManager(0, 1)}
	peerCalls := 0
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		peerCalls++
		if action != "clear-persistent-nat" {
			t.Errorf("peer action = %q, want clear-persistent-nat", action)
		}
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok || len(md.Get("x-peer-forwarded")) == 0 {
			t.Error("peer clear was not marked as forwarded")
		}
		return "Cleared 3 persistent NAT bindings", nil
	}

	var callErr error
	out := captureStdout(t, func() { callErr = c.clearPersistentNAT() })
	if callErr != nil {
		t.Fatalf("clearPersistentNAT: %v", callErr)
	}
	if dp.calls != 1 {
		t.Fatalf("authoritative clear calls = %d, want 1", dp.calls)
	}
	if table.Len() != 0 {
		t.Fatalf("SHOW mirror has %d bindings after clear, want 0", table.Len())
	}
	if peerCalls != 1 {
		t.Fatalf("peer clear calls = %d, want 1", peerCalls)
	}
	if !strings.Contains(out, "Cleared 7 persistent NAT bindings") ||
		!strings.Contains(out, "Peer: Cleared 3 persistent NAT bindings") {
		t.Fatalf("clear output = %q, missing authoritative/peer result", out)
	}
}

func TestClearPersistentNATLeavesMirrorWhenAuthorityFails10784(t *testing.T) {
	dp := &persistentNATClearCLIBackend10784{
		Manager: dataplane.New(),
		err:     errors.New("helper unavailable"),
	}
	table := dp.GetPersistentNAT()
	table.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.0.11"),
		SrcPort:  40001,
		NatIP:    netip.MustParseAddr("192.0.2.11"),
		NatPort:  50001,
		PoolName: "pool-a",
	})
	c := &CLI{dp: dp}

	err := c.clearPersistentNAT()
	if err == nil || !strings.Contains(err.Error(), "helper unavailable") {
		t.Fatalf("clearPersistentNAT error = %v, want helper failure", err)
	}
	if table.Len() != 1 {
		t.Fatalf("SHOW mirror has %d bindings after failed authority clear, want 1", table.Len())
	}
}

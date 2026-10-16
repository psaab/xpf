package cli

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	"google.golang.org/grpc/metadata"
)

const persistentNATClearTestOrigin14148 = "0123456789abcdef0123456789abcdef"

type persistentNATClearGenerationBackend14148 struct {
	*dataplane.Manager
	legacyCalls     int
	generationCalls int
	gotPeerOrigin   string
	gotPeerGen      uint64
	err             error
}

func (d *persistentNATClearGenerationBackend14148) ClearPersistentNATLeases() (uint64, error) {
	d.legacyCalls++
	if d.err != nil {
		return 0, d.err
	}
	d.GetPersistentNAT().Clear()
	return 7, nil
}

func (d *persistentNATClearGenerationBackend14148) ClearPersistentNATLeasesWithGeneration(peerOrigin string, peerGeneration uint64) (uint64, string, uint64, error) {
	d.generationCalls++
	d.gotPeerOrigin = peerOrigin
	d.gotPeerGen = peerGeneration
	if d.err != nil {
		return 0, "", 0, d.err
	}
	d.GetPersistentNAT().Clear()
	return 7, persistentNATClearTestOrigin14148, 5, nil
}

func TestClearPersistentNATForwardsGenerationToPeer14148(t *testing.T) {
	dp := &persistentNATClearGenerationBackend14148{Manager: dataplane.New()}
	dp.GetPersistentNAT().Save(&dataplane.PersistentNATBinding{
		SrcIP: netip.MustParseAddr("10.0.0.20"), SrcPort: 40010,
		NatIP: netip.MustParseAddr("192.0.2.20"), NatPort: 50010, PoolName: "pool-a",
	})
	c := &CLI{dp: dp, cluster: cluster.NewManager(0, 1)}
	peerCalls := 0
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		peerCalls++
		if action != "clear-persistent-nat" {
			t.Errorf("peer action = %q, want clear-persistent-nat", action)
		}
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("peer clear has no outgoing metadata")
		}
		if len(md.Get("x-peer-forwarded")) != 1 {
			t.Errorf("x-peer-forwarded = %v, want [1]", md.Get("x-peer-forwarded"))
		}
		origins := md.Get("x-peer-persistent-nat-origin")
		if len(origins) != 1 || origins[0] != persistentNATClearTestOrigin14148 {
			t.Errorf("x-peer-persistent-nat-origin = %v, want [%s]", origins, persistentNATClearTestOrigin14148)
		}
		gens := md.Get("x-peer-persistent-nat-generation")
		if len(gens) != 1 || gens[0] != strconv.FormatUint(5, 10) {
			t.Errorf("x-peer-persistent-nat-generation = %v, want [5]", gens)
		}
		return "Cleared 2 persistent NAT bindings", nil
	}
	var callErr error
	out := captureStdout(t, func() { callErr = c.clearPersistentNAT() })
	if callErr != nil {
		t.Fatalf("clearPersistentNAT: %v", callErr)
	}
	if dp.generationCalls != 1 || dp.legacyCalls != 0 {
		t.Fatalf("generationCalls=%d legacyCalls=%d, want 1/0", dp.generationCalls, dp.legacyCalls)
	}
	if dp.gotPeerOrigin != "" || dp.gotPeerGen != 0 {
		t.Fatalf("local clear peer args = %q/%d, want empty/0", dp.gotPeerOrigin, dp.gotPeerGen)
	}
	if peerCalls != 1 {
		t.Fatalf("peer calls = %d, want 1", peerCalls)
	}
	_ = out
}

func TestClearPersistentNATLegacyBackendForwardsNoGeneration14148(t *testing.T) {
	// Backend implementing only the legacy interface: no origin to forward,
	// so peer metadata must carry no generation headers (peer will apply
	// its own local fences, as on the pre-#11486 path).
	dp := &persistentNATClearCLIBackend10784{Manager: dataplane.New(), count: 3}
	c := &CLI{dp: dp, cluster: cluster.NewManager(0, 1)}
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		md, _ := metadata.FromOutgoingContext(ctx)
		if len(md.Get("x-peer-persistent-nat-origin")) != 0 || len(md.Get("x-peer-persistent-nat-generation")) != 0 {
			t.Errorf("legacy peer clear carried generation metadata: %v", md)
		}
		return "ok", nil
	}
	var callErr error
	captureStdout(t, func() { callErr = c.clearPersistentNAT() })
	if callErr != nil {
		t.Fatalf("clearPersistentNAT: %v", callErr)
	}
	if dp.calls != 1 {
		t.Fatalf("legacy calls = %d, want 1", dp.calls)
	}
}

func TestClearPersistentNATGenerationErrorPropagates14148(t *testing.T) {
	dp := &persistentNATClearGenerationBackend14148{Manager: dataplane.New(), err: errors.New("helper unavailable")}
	dp.GetPersistentNAT().Save(&dataplane.PersistentNATBinding{
		SrcIP: netip.MustParseAddr("10.0.0.21"), SrcPort: 40011,
		NatIP: netip.MustParseAddr("192.0.2.21"), NatPort: 50011, PoolName: "pool-a",
	})
	c := &CLI{dp: dp, cluster: cluster.NewManager(0, 1)}
	peerCalled := false
	c.peerSystemActionFn = func(ctx context.Context, action string) (string, error) {
		peerCalled = true
		return "", nil
	}
	err := c.clearPersistentNAT()
	if err == nil || err.Error() == "" {
		t.Fatalf("clearPersistentNAT error = %v, want helper failure", err)
	}
	if dp.generationCalls != 1 {
		t.Fatalf("generationCalls = %d, want 1", dp.generationCalls)
	}
	if peerCalled {
		t.Fatal("peer clear forwarded after local authority failure")
	}
	if dp.GetPersistentNAT().Len() != 1 {
		t.Fatalf("mirror Len = %d, want 1 after failed clear", dp.GetPersistentNAT().Len())
	}
}

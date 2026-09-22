package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type preL3GlobalStatsDP10498 struct {
	*dataplane.Manager
}

func (preL3GlobalStatsDP10498) IsLoaded() bool { return true }

func (preL3GlobalStatsDP10498) ReadGlobalCounter(idx uint32) (uint64, error) {
	return uint64(idx)*1000 + 17, nil
}

func TestGetGlobalStatsSurfacesNamedPreL3Drops10498(t *testing.T) {
	s := newViewServer(t, preL3GlobalStatsDP10498{Manager: dataplane.New()})
	resp, err := s.GetGlobalStats(context.Background(), &pb.GetGlobalStatsRequest{})
	if err != nil {
		t.Fatalf("GetGlobalStats: %v", err)
	}

	wantUnknownVLAN := uint64(dataplane.GlobalCtrUnknownVLANDrops)*1000 + 17
	if resp.UnknownVlanDrops != wantUnknownVLAN {
		t.Fatalf("UnknownVlanDrops = %d, want %d", resp.UnknownVlanDrops, wantUnknownVLAN)
	}
	wantDstMAC := uint64(dataplane.GlobalCtrDstMACDrops)*1000 + 17
	if resp.DstMacDrops != wantDstMAC {
		t.Fatalf("DstMacDrops = %d, want %d", resp.DstMacDrops, wantDstMAC)
	}
	if resp.UnknownVlanDrops == resp.DstMacDrops {
		t.Fatal("named pre-L3 counters must read distinct global indices")
	}
}

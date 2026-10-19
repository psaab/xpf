package grpcapi

import (
	"context"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type summaryFilterDP15236 struct {
	*dataplane.Manager
	v4 []struct {
		key dataplane.SessionKey
		val dataplane.SessionValue
	}
}

func (d *summaryFilterDP15236) IsLoaded() bool { return true }
func (d *summaryFilterDP15236) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, e := range d.v4 {
		if !fn(e.key, e.val) {
			break
		}
	}
	return nil
}
func (d *summaryFilterDP15236) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	return nil
}

func TestGetSessionSummaryFiltered15236(t *testing.T) {
	mk := func(proto uint8, dstPort uint16) struct {
		key dataplane.SessionKey
		val dataplane.SessionValue
	} { var e struct {
		key dataplane.SessionKey
		val dataplane.SessionValue
	}; e.key = dataplane.SessionKey{Protocol: proto, DstPort: hostToNetwork16(dstPort)}; copy(e.key.SrcIP[:], net.ParseIP("10.0.0.1").To4()); copy(e.key.DstIP[:], net.ParseIP("10.0.0.2").To4()); e.val = dataplane.SessionValue{State: dataplane.SessStateEstablished}; return e }
	dp := &summaryFilterDP15236{Manager: dataplane.New()}
	dp.v4 = append(dp.v4, mk(6, 443), mk(17, 53), mk(6, 80))
	s := newSummaryFieldsServer(t, dp)
	resp, err := s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{Protocol: "tcp", DestinationPort: 443})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if resp.ForwardOnly != 1 || resp.Ipv4Sessions != 1 {
		t.Errorf("filtered summary = %+v, want 1 tcp/443 session", resp)
	}
	resp, err = s.GetSessionSummary(context.Background(), &pb.GetSessionSummaryRequest{})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if resp.ForwardOnly != 3 {
		t.Errorf("unfiltered summary = %+v, want 3", resp)
	}
}

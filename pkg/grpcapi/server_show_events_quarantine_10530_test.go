package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

func quarantineEventGRPCServer10530(t *testing.T, eb *logging.EventBuffer) *Server {
	t.Helper()
	store := quarantinePolicyTextStore10530(t)
	id := config.StableZoneID("z174")
	return &Server{
		store:    store,
		eventBuf: eb,
		dp: &quarantineSessionGRPCDP10530{Manager: dataplane.New(), result: &dataplane.ApplyResult{
			ZoneIDs: map[string]uint16{"trust": config.StableZoneID("trust"), "z174": id, "z214": id},
		}},
	}
}

func TestGetEventsQuarantineSurvivorAndStoredName10530(t *testing.T) {
	id := config.StableZoneID("z174")
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id})
	s := quarantineEventGRPCServer10530(t, eb)
	resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("GetEvents returned %d events, want 1", len(resp.Events))
	}
	if resp.Events[0].IngressZoneName != "z174" || resp.Events[0].EgressZoneName != "z174" {
		t.Fatalf("legacy fallback names = %q -> %q, want survivor z174", resp.Events[0].IngressZoneName, resp.Events[0].EgressZoneName)
	}

	stored := logging.NewEventBuffer(16)
	stored.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id, InZoneName: "historical-in", OutZoneName: "historical-out"})
	resp, err = quarantineEventGRPCServer10530(t, stored).GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents stored name: %v", err)
	}
	if got := resp.Events[0].IngressZoneName; got != "historical-in" {
		t.Fatalf("stored ingress name = %q, want historical-in", got)
	}
	if got := resp.Events[0].EgressZoneName; got != "historical-out" {
		t.Fatalf("stored egress name = %q, want historical-out", got)
	}
}

func TestShowSecurityLogQuarantineQualifier10530(t *testing.T) {
	id := config.StableZoneID("z174")
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id, SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2"})
	s := quarantineEventGRPCServer10530(t, eb)
	var out strings.Builder
	s.showSecurityLog("zone z214", &out)
	if !strings.Contains(out.String(), config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("quarantined gRPC event text lacks reference qualifier:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "z174 "+config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("quarantined fallback survivor name lacks qualifier:\n%s", out.String())
	}
}

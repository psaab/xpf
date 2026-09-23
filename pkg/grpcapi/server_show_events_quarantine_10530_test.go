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
	for i := range 100 {
		resp, err := s.GetEvents(context.Background(), &pb.GetEventsRequest{})
		if err != nil {
			t.Fatalf("iteration %d GetEvents: %v", i, err)
		}
		if len(resp.Events) != 1 {
			t.Fatalf("iteration %d GetEvents returned %d events, want 1", i, len(resp.Events))
		}
		if resp.Events[0].IngressZoneName != "z174" || resp.Events[0].EgressZoneName != "z174" {
			t.Fatalf("iteration %d legacy fallback names = %q -> %q, want survivor z174",
				i, resp.Events[0].IngressZoneName, resp.Events[0].EgressZoneName)
		}
	}

	stored := logging.NewEventBuffer(16)
	stored.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id, InZoneName: "historical-in", OutZoneName: "historical-out"})
	resp, err := quarantineEventGRPCServer10530(t, stored).GetEvents(context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents stored name: %v", err)
	}
	if got := resp.Events[0].IngressZoneName; got != "historical-in" {
		t.Fatalf("stored ingress name = %q, want historical-in", got)
	}
	if got := resp.Events[0].EgressZoneName; got != "historical-out" {
		t.Fatalf("stored egress name = %q, want historical-out", got)
	}

	ordinary := logging.NewEventBuffer(16)
	trustID := config.StableZoneID("trust")
	ordinary.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: trustID, OutZone: trustID})
	ordinaryResp, err := quarantineEventGRPCServer10530(t, ordinary).GetEvents(
		context.Background(), &pb.GetEventsRequest{})
	if err != nil {
		t.Fatalf("GetEvents ordinary control: %v", err)
	}
	if len(ordinaryResp.Events) != 1 ||
		ordinaryResp.Events[0].IngressZoneName != "trust" ||
		ordinaryResp.Events[0].EgressZoneName != "trust" {
		t.Fatalf("ordinary event fallback names = %+v, want trust->trust", ordinaryResp.Events)
	}
}

func TestShowSecurityLogQuarantineQualifier10530(t *testing.T) {
	id := config.StableZoneID("z174")
	eb := logging.NewEventBuffer(16)
	eb.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: id, OutZone: id, SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2"})
	s := quarantineEventGRPCServer10530(t, eb)
	for i := range 100 {
		var out strings.Builder
		s.showSecurityLog("zone z214", &out)
		if !strings.Contains(out.String(), config.ZoneQuarantineReferenceQualifier) {
			t.Fatalf("iteration %d quarantined gRPC event text lacks reference qualifier:\n%s", i, out.String())
		}
		if !strings.Contains(out.String(), "z174 "+config.ZoneQuarantineReferenceQualifier) {
			t.Fatalf("iteration %d quarantined fallback survivor name lacks qualifier:\n%s", i, out.String())
		}
	}
	storedText := logging.NewEventBuffer(16)
	storedText.Add(logging.EventRecord{
		Type: "SESSION_OPEN", InZone: id, OutZone: id,
		InZoneName: "z174", OutZoneName: "z174",
	})
	storedServer := quarantineEventGRPCServer10530(t, storedText)
	var storedOut strings.Builder
	storedServer.showSecurityLog("zone z214", &storedOut)
	if !strings.Contains(storedOut.String(), "z174 "+config.ZoneQuarantineReferenceQualifier) {
		t.Fatalf("stored survivor name lacks filter qualifier:\n%s", storedOut.String())
	}

	ordinaryEB := logging.NewEventBuffer(16)
	ordinaryID := config.StableZoneID("trust")
	ordinaryEB.Add(logging.EventRecord{Type: "SESSION_OPEN", InZone: ordinaryID, OutZone: ordinaryID, SrcAddr: "10.0.0.3:3", DstAddr: "10.0.0.4:4"})
	ordinary := quarantineEventGRPCServer10530(t, ordinaryEB)
	var out strings.Builder
	ordinary.showSecurityLog("zone z214 zone trust", &out)
	if strings.Contains(out.String(), config.ZoneQuarantineReferenceQualifier) ||
		!strings.Contains(out.String(), "zone=trust") {
		t.Fatalf("last duplicate zone filter did not win ordinary control:\n%s", out.String())
	}
}

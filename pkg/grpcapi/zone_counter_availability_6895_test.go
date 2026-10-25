package grpcapi

import (
	"context"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// zone_counter_availability_6895_test.go — #6895, the SERVER half.
//
// The renderer in cmd/cli is inert unless GetZones actually stamps the
// availability enum. Deleting the two assignments in server_show_zones.go
// leaves every cmd/cli cell GREEN — those construct ZoneInfo directly — while
// the wire goes back to carrying four indistinguishable zeros and the remote cli
// falls through to its UNKNOWN branch, which is the pre-#6895 behaviour. So the
// stamping is bound here, at the RPC.

// availabilityGRPCDP reports ErrCounterNotPopulated for one zone id and a real
// reading for another, so ONE reply carries both states. A fixture with only the
// unavailable zone could not tell a correct implementation from one that stamps
// UNAVAILABLE unconditionally.
type availabilityGRPCDP struct {
	*dataplane.Manager
	apply       *dataplane.ApplyResult
	populatedID uint32
}

func (d *availabilityGRPCDP) IsLoaded() bool                          { return true }
func (d *availabilityGRPCDP) LastApplyResult() *dataplane.ApplyResult { return d.apply }
func (d *availabilityGRPCDP) ReadZoneCounters(id uint32, dir int) (dataplane.CounterValue, error) {
	if id == d.populatedID {
		if dir == 0 {
			return dataplane.CounterValue{Packets: 11, Bytes: 2200}, nil
		}
		return dataplane.CounterValue{Packets: 3, Bytes: 400}, nil
	}
	return dataplane.CounterValue{}, dataplane.ErrCounterNotPopulated
}

func TestGetZonesStampsCounterAvailability6895(t *testing.T) {
	store := newSchedulerCounterGRPCStore(t)
	s := &Server{
		store: store,
		dp: &availabilityGRPCDP{
			Manager:     dataplane.New(),
			apply:       &dataplane.ApplyResult{ZoneIDs: map[string]uint32{"trust": 40000, "untrust": 41000, "dmz": 42000}},
			populatedID: 41000, // only untrust has a reading
		},
	}

	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones: %v", err)
	}

	byName := map[string]*pb.ZoneInfo{}
	for _, z := range resp.Zones {
		byName[z.Name] = z
	}
	if len(byName) < 2 {
		t.Fatalf("fixture degenerated: expected several zones, got %d", len(byName))
	}

	// The zone WITH a reading.
	untrust := byName["untrust"]
	if untrust == nil {
		t.Fatal("untrust missing from the reply")
	}
	if untrust.PerZoneCounterAvailability !=
		pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE {
		t.Fatalf("a zone with a real reading is stamped %v, want AVAILABLE — the client "+
			"cannot tell its counters are real", untrust.PerZoneCounterAvailability)
	}
	if untrust.IngressPackets != 11 {
		t.Fatalf("untrust ingress = %d, want 11", untrust.IngressPackets)
	}

	// A zone WITHOUT one.
	trust := byName["trust"]
	if trust == nil {
		t.Fatal("trust missing from the reply")
	}
	if trust.PerZoneCounterAvailability !=
		pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE {
		t.Fatalf("a zone with NO published volume is stamped %v, want UNAVAILABLE — the "+
			"client sees four zeros and renders it exactly like an idle zone, which "+
			"is the #6895 defect", trust.PerZoneCounterAvailability)
	}
	if trust.IngressPackets != 0 || trust.EgressPackets != 0 {
		t.Fatalf("an unavailable zone carries counter values: in=%d out=%d",
			trust.IngressPackets, trust.EgressPackets)
	}

	// Both states in ONE reply: an implementation that stamps a constant cannot
	// satisfy both assertions above, which is why the fixture mixes them.
	if untrust.PerZoneCounterAvailability == trust.PerZoneCounterAvailability {
		t.Fatal("both zones got the same availability stamp — the server is not " +
			"discriminating on the read result")
	}
}

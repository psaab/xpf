package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// quarantineGRPCDP records reads so the collision loser can prove that the
// handler suppresses the shared survivor counter rather than merely zeroing it
// after the read.
type quarantineGRPCDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
	reads int
}

func (d *quarantineGRPCDP) IsLoaded() bool {
	return true
}

func (d *quarantineGRPCDP) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}

func (d *quarantineGRPCDP) ReadZoneCounters(id uint16, dir int) (dataplane.CounterValue, error) {
	d.reads++
	return d.Manager.ReadZoneCounters(id, dir)
}

type quarantineGRPCReadErrDP struct {
	*quarantineGRPCDP
	errID uint16
}

func (d *quarantineGRPCReadErrDP) ReadZoneCounters(id uint16, dir int) (dataplane.CounterValue, error) {
	if id == d.errID {
		return dataplane.CounterValue{}, errors.New("trust counter bridge unavailable")
	}
	return d.quarantineGRPCDP.ReadZoneCounters(id, dir)
}

func newQuarantineGRPCFixture(t *testing.T, names ...string) (*Server, *quarantineGRPCDP, map[string]uint16) {
	t.Helper()
	store := newSchedulerCounterGRPCStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = make(map[string]*config.ZoneConfig, len(names))
	ids := make(map[string]uint16, len(names))
	for _, name := range names {
		cfg.Security.Zones[name] = &config.ZoneConfig{Name: name}
		ids[name] = config.StableZoneID(name)
	}
	dp := &quarantineGRPCDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}
	return &Server{store: store, dp: dp}, dp, ids
}

func setQuarantineGRPCCounters(dp *quarantineGRPCDP, id uint16, inPackets, inBytes, outPackets, outBytes uint64) {
	dp.SetZoneCounterOffset(id,
		dataplane.CounterValue{Packets: inPackets, Bytes: inBytes},
		dataplane.CounterValue{Packets: outPackets, Bytes: outBytes})
}

func getGRPCZone(t *testing.T, resp *pb.GetZonesResponse, name string) *pb.ZoneInfo {
	t.Helper()
	for _, zone := range resp.Zones {
		if zone.Name == name {
			return zone
		}
	}
	t.Fatalf("GetZones omitted %q: %+v", name, resp.Zones)
	return nil
}

func TestGetZonesQuarantineCollision10531(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	s, dp, ids := newQuarantineGRPCFixture(t, "z174", "z214", "trust")
	setQuarantineGRPCCounters(dp, ids["z174"], 11, 1100, 22, 2200)
	setQuarantineGRPCCounters(dp, ids["trust"], 33, 3300, 44, 4400)

	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones: %v", err)
	}
	if len(resp.Zones) != 3 {
		t.Fatalf("GetZones returned %d zones, want 3", len(resp.Zones))
	}

	survivor := getGRPCZone(t, resp, "z174")
	if survivor.QuarantineState != pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_NOT_QUARANTINED {
		t.Fatalf("z174 quarantine state = %v, want NOT_QUARANTINED", survivor.QuarantineState)
	}
	if survivor.QuarantineSurvivorZone != "" {
		t.Fatalf("z174 survivor field = %q, want empty", survivor.QuarantineSurvivorZone)
	}
	if survivor.PerZoneCounterAvailability != pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE {
		t.Fatalf("z174 counter availability = %v, want AVAILABLE", survivor.PerZoneCounterAvailability)
	}
	if survivor.IngressPackets != 11 || survivor.IngressBytes != 1100 || survivor.EgressPackets != 22 || survivor.EgressBytes != 2200 {
		t.Fatalf("z174 counters = %d/%d %d/%d, want 11/1100 22/2200", survivor.IngressPackets, survivor.IngressBytes, survivor.EgressPackets, survivor.EgressBytes)
	}

	loser := getGRPCZone(t, resp, "z214")
	if loser.QuarantineState != pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_QUARANTINED {
		t.Fatalf("z214 quarantine state = %v, want QUARANTINED", loser.QuarantineState)
	}
	if loser.QuarantineSurvivorZone != "z174" {
		t.Fatalf("z214 survivor field = %q, want z174", loser.QuarantineSurvivorZone)
	}
	if loser.PerZoneCounterAvailability != pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE {
		t.Fatalf("z214 counter availability = %v, want UNAVAILABLE", loser.PerZoneCounterAvailability)
	}
	if loser.IngressPackets != 0 || loser.IngressBytes != 0 || loser.EgressPackets != 0 || loser.EgressBytes != 0 {
		t.Fatalf("z214 leaked survivor counters: %d/%d %d/%d", loser.IngressPackets, loser.IngressBytes, loser.EgressPackets, loser.EgressBytes)
	}

	ordinary := getGRPCZone(t, resp, "trust")
	if ordinary.QuarantineState != pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_NOT_QUARANTINED || ordinary.QuarantineSurvivorZone != "" {
		t.Fatalf("trust quarantine projection = state %v survivor %q", ordinary.QuarantineState, ordinary.QuarantineSurvivorZone)
	}
	if ordinary.PerZoneCounterAvailability != pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE || ordinary.IngressPackets != 33 {
		t.Fatalf("trust counters/availability = %d/%v, want 33/AVAILABLE", ordinary.IngressPackets, ordinary.PerZoneCounterAvailability)
	}
	if dp.reads != 4 {
		t.Fatalf("ReadZoneCounters calls = %d, want 4 (two non-quarantined rows only)", dp.reads)
	}
}

// TestGetZonesQuarantinePreservesCounterError10531 pins the conjunction of
// quarantine suppression and #3408 fail-loud behavior. The quarantined
// z214 row must skip the shared-id read, while a genuine trust read failure
// still reaches the unconditional Internal return.
func TestGetZonesQuarantinePreservesCounterError10531(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	s, dp, ids := newQuarantineGRPCFixture(t, "z174", "z214", "trust")
	setQuarantineGRPCCounters(dp, ids["z174"], 11, 1100, 22, 2200)
	errDP := &quarantineGRPCReadErrDP{
		quarantineGRPCDP: dp,
		errID:            ids["trust"],
	}
	s.dp = errDP

	_, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("GetZones error code = %v, want Internal; err=%v", status.Code(err), err)
	}
	if dp.reads != 2 {
		t.Fatalf("ReadZoneCounters calls before genuine error = %d, want 2 for survivor only; quarantined z214 must be skipped", dp.reads)
	}
}

func TestGetZonesQuarantineNoCollision10531(t *testing.T) {
	s, dp, ids := newQuarantineGRPCFixture(t, "trust", "untrust", "dmz")
	setQuarantineGRPCCounters(dp, ids["trust"], 7, 70, 8, 80)

	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones: %v", err)
	}
	for _, name := range []string{"trust", "untrust", "dmz"} {
		zone := getGRPCZone(t, resp, name)
		if zone.QuarantineState != pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_NOT_QUARANTINED {
			t.Fatalf("%s quarantine state = %v, want NOT_QUARANTINED", name, zone.QuarantineState)
		}
		if zone.QuarantineSurvivorZone != "" {
			t.Fatalf("%s survivor field = %q, want empty", name, zone.QuarantineSurvivorZone)
		}
	}
	if trust := getGRPCZone(t, resp, "trust"); trust.PerZoneCounterAvailability != pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE || trust.IngressPackets != 7 {
		t.Fatalf("trust counters/availability = %d/%v, want 7/AVAILABLE", trust.IngressPackets, trust.PerZoneCounterAvailability)
	}
	for _, name := range []string{"untrust", "dmz"} {
		zone := getGRPCZone(t, resp, name)
		if zone.PerZoneCounterAvailability != pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE {
			t.Fatalf("%s counter availability = %v, want UNAVAILABLE", name, zone.PerZoneCounterAvailability)
		}
	}
}

func TestGetZonesQuarantineSkewAndWireShape10531(t *testing.T) {
	fields := (&pb.ZoneInfo{}).ProtoReflect().Descriptor().Fields()
	stateField := fields.ByName("quarantine_state")
	if stateField == nil || stateField.Number() != 18 || stateField.Kind() != protoreflect.EnumKind {
		t.Fatalf("quarantine_state descriptor = %v, want enum field 18", stateField)
	}
	survivorField := fields.ByName("quarantine_survivor_zone")
	if survivorField == nil || survivorField.Number() != 19 || survivorField.Kind() != protoreflect.StringKind {
		t.Fatalf("quarantine_survivor_zone descriptor = %v, want string field 19", survivorField)
	}
	for i := range fields.Len() {
		if fields.Get(i).Kind() == protoreflect.BoolKind &&
			strings.HasPrefix(string(fields.Get(i).Name()), "quarantined") {
			t.Fatalf("ZoneInfo contains forbidden bool %q field", fields.Get(i).Name())
		}
	}

	wire, err := proto.Marshal(&pb.ZoneInfo{Name: "legacy"})
	if err != nil {
		t.Fatalf("marshal legacy ZoneInfo: %v", err)
	}
	var decoded pb.ZoneInfo
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal legacy ZoneInfo: %v", err)
	}
	if decoded.QuarantineState != pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_UNKNOWN {
		t.Fatalf("absent quarantine_state decoded as %v, want UNKNOWN", decoded.QuarantineState)
	}
	if decoded.QuarantineSurvivorZone != "" {
		t.Fatalf("absent survivor decoded as %q, want empty", decoded.QuarantineSurvivorZone)
	}

	s, dp, ids := newQuarantineGRPCFixture(t, "z174", "z214", "trust")
	setQuarantineGRPCCounters(dp, ids["z174"], 19, 1900, 29, 2900)
	resp, err := s.GetZones(context.Background(), &pb.GetZonesRequest{})
	if err != nil {
		t.Fatalf("GetZones skew fixture: %v", err)
	}
	loser := getGRPCZone(t, resp, "z214")
	// A pre-#10531 client ignores fields 18/19 but still observes the safe
	// existing-field projection: no survivor volume and UNAVAILABLE counters.
	if loser.IngressPackets != 0 || loser.IngressBytes != 0 || loser.EgressPackets != 0 || loser.EgressBytes != 0 || loser.PerZoneCounterAvailability != pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE {
		t.Fatalf("legacy projection of z214 is unsafe: counters=%d/%d %d/%d availability=%v", loser.IngressPackets, loser.IngressBytes, loser.EgressPackets, loser.EgressBytes, loser.PerZoneCounterAvailability)
	}
}

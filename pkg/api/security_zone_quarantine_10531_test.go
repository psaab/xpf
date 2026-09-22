package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// quarantineRESTDP records reads so the collision loser can prove that
// zonesHandler skips the shared survivor counter entirely.
type quarantineRESTDP struct {
	*descriptorCoverageDP
	reads int
}

func (d *quarantineRESTDP) ReadZoneCounters(id uint16, dir int) (dataplane.CounterValue, error) {
	d.reads++
	return d.Manager.ReadZoneCounters(id, dir)
}

type quarantineRESTReadErrDP struct {
	*quarantineRESTDP
	errID uint16
}

func (d *quarantineRESTReadErrDP) ReadZoneCounters(id uint16, dir int) (dataplane.CounterValue, error) {
	if id == d.errID {
		return dataplane.CounterValue{}, errors.New("trust counter bridge unavailable")
	}
	return d.quarantineRESTDP.ReadZoneCounters(id, dir)
}

func newQuarantineRESTFixture(t *testing.T, names ...string) (*Server, *quarantineRESTDP, map[string]uint16) {
	t.Helper()
	store := newDescriptorCoverageStore(t)
	cfg := store.ActiveConfig()
	cfg.Security.Zones = make(map[string]*config.ZoneConfig, len(names))
	ids := make(map[string]uint16, len(names))
	for _, name := range names {
		cfg.Security.Zones[name] = &config.ZoneConfig{Name: name}
		ids[name] = config.StableZoneID(name)
	}
	dp := &quarantineRESTDP{descriptorCoverageDP: &descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	return &Server{store: store, dp: dp}, dp, ids
}

func setQuarantineRESTCounters(dp *quarantineRESTDP, id uint16, inPackets, inBytes, outPackets, outBytes uint64) {
	dp.SetZoneCounterOffset(id,
		dataplane.CounterValue{Packets: inPackets, Bytes: inBytes},
		dataplane.CounterValue{Packets: outPackets, Bytes: outBytes})
}

func decodeRESTZones10531(t *testing.T, body []byte) ([]ZoneInfo, []map[string]json.RawMessage) {
	t.Helper()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode REST envelope: %v; body=%s", err, body)
	}
	var zones []ZoneInfo
	if err := json.Unmarshal(envelope.Data, &zones); err != nil {
		t.Fatalf("REST data is not a JSON array: %v; data=%s", err, envelope.Data)
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Data, &raw); err != nil {
		t.Fatalf("decode raw REST zone array: %v; data=%s", err, envelope.Data)
	}
	return zones, raw
}

func restZoneByName10531(t *testing.T, zones []ZoneInfo, name string) *ZoneInfo {
	t.Helper()
	for i := range zones {
		if zones[i].Name == name {
			return &zones[i]
		}
	}
	t.Fatalf("REST zones omitted %q: %+v", name, zones)
	return nil
}

func rawRESTZoneByName10531(t *testing.T, raw []map[string]json.RawMessage, name string) map[string]json.RawMessage {
	t.Helper()
	for _, zone := range raw {
		var got string
		if err := json.Unmarshal(zone["name"], &got); err == nil && got == name {
			return zone
		}
	}
	t.Fatalf("raw REST zones omitted %q: %+v", name, raw)
	return nil
}

func TestZonesHandlerQuarantineCollision10531(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	s, dp, ids := newQuarantineRESTFixture(t, "z174", "z214", "trust")
	setQuarantineRESTCounters(dp, ids["z174"], 11, 1100, 22, 2200)
	setQuarantineRESTCounters(dp, ids["trust"], 33, 3300, 44, 4400)

	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	zones, raw := decodeRESTZones10531(t, rr.Body.Bytes())
	if len(zones) != 3 {
		t.Fatalf("zonesHandler returned %d zones, want 3", len(zones))
	}
	if strings.Contains(rr.Body.String(), `"quarantined":`) {
		t.Fatal("REST wire contains a forbidden bool quarantined key")
	}

	loser := restZoneByName10531(t, zones, "z214")
	if loser.Quarantine == nil || loser.Quarantine.State != ZoneQuarantineStateQuarantined || loser.Quarantine.SurvivorZone != "z174" {
		t.Fatalf("z214 quarantine = %+v, want quarantined survivor z174", loser.Quarantine)
	}
	if loser.PerZoneCountersAvailable || loser.IngressPackets != 0 || loser.IngressBytes != 0 || loser.EgressPackets != 0 || loser.EgressBytes != 0 {
		t.Fatalf("z214 leaked survivor counters: available=%v counters=%d/%d %d/%d", loser.PerZoneCountersAvailable, loser.IngressPackets, loser.IngressBytes, loser.EgressPackets, loser.EgressBytes)
	}
	loserRaw := rawRESTZoneByName10531(t, raw, "z214")
	var loserQuarantine map[string]json.RawMessage
	if err := json.Unmarshal(loserRaw["quarantine"], &loserQuarantine); err != nil {
		t.Fatalf("decode z214 quarantine: %v", err)
	}
	var state, survivor string
	if err := json.Unmarshal(loserQuarantine["state"], &state); err != nil {
		t.Fatalf("decode z214 quarantine state: %v", err)
	}
	if err := json.Unmarshal(loserQuarantine["survivor_zone"], &survivor); err != nil {
		t.Fatalf("decode z214 quarantine survivor: %v", err)
	}
	if state != ZoneQuarantineStateQuarantined || survivor != "z174" {
		t.Fatalf("raw z214 quarantine = state %q survivor %q", state, survivor)
	}
	var available bool
	if err := json.Unmarshal(loserRaw["per_zone_counters_available"], &available); err != nil || available {
		t.Fatalf("raw z214 per_zone_counters_available = %s, want false", loserRaw["per_zone_counters_available"])
	}

	for _, name := range []string{"z174", "trust"} {
		zone := restZoneByName10531(t, zones, name)
		if zone.Quarantine == nil || zone.Quarantine.State != ZoneQuarantineStateNotQuarantined || zone.Quarantine.SurvivorZone != "" {
			t.Fatalf("%s quarantine = %+v, want not_quarantined without survivor", name, zone.Quarantine)
		}
		zoneRaw := rawRESTZoneByName10531(t, raw, name)
		var q map[string]json.RawMessage
		if err := json.Unmarshal(zoneRaw["quarantine"], &q); err != nil {
			t.Fatalf("decode %s quarantine: %v", name, err)
		}
		if _, present := q["survivor_zone"]; present {
			t.Fatalf("%s raw quarantine unexpectedly has survivor_zone: %s", name, q["survivor_zone"])
		}
	}
	if survivor := restZoneByName10531(t, zones, "z174"); !survivor.PerZoneCountersAvailable || survivor.IngressPackets != 11 {
		t.Fatalf("z174 counters/availability = %d/%v, want 11/true", survivor.IngressPackets, survivor.PerZoneCountersAvailable)
	}
	if trust := restZoneByName10531(t, zones, "trust"); !trust.PerZoneCountersAvailable || trust.IngressPackets != 33 {
		t.Fatalf("trust counters/availability = %d/%v, want 33/true", trust.IngressPackets, trust.PerZoneCountersAvailable)
	}
	if dp.reads != 4 {
		t.Fatalf("ReadZoneCounters calls = %d, want 4 (two non-quarantined rows only)", dp.reads)
	}

	alias := httptest.NewRecorder()
	s.zoneStatsHandler(alias, httptest.NewRequest(http.MethodGet, "/api/v1/statistics/zones", nil))
	if alias.Code != http.StatusOK {
		t.Fatalf("zoneStatsHandler status = %d, want 200; body=%s", alias.Code, alias.Body.String())
	}
	aliasZones, aliasRaw := decodeRESTZones10531(t, alias.Body.Bytes())
	if !reflect.DeepEqual(zones, aliasZones) {
		t.Fatalf("statistics alias projection differs from security zones: primary=%+v alias=%+v", zones, aliasZones)
	}
	if !reflect.DeepEqual(raw, aliasRaw) {
		t.Fatalf("statistics alias wire rows differ from security zones: primary=%+v alias=%+v", raw, aliasRaw)
	}
	if len(aliasZones) != len(zones) || len(aliasRaw) != len(raw) {
		t.Fatalf("statistics alias shape = %d/%d, want %d/%d", len(aliasZones), len(aliasRaw), len(zones), len(raw))
	}
	if aliasLoser := restZoneByName10531(t, aliasZones, "z214"); aliasLoser.Quarantine == nil || aliasLoser.Quarantine.State != ZoneQuarantineStateQuarantined || aliasLoser.PerZoneCountersAvailable {
		t.Fatalf("statistics alias z214 = %+v, want same quarantine suppression", aliasLoser)
	}
}

// TestZonesHandlerQuarantinePreservesCounterError10531 pins the conjunction
// of quarantine suppression and #3408 fail-loud behavior. The quarantined
// z214 row must skip the shared-id read, while a genuine trust read failure
// still reaches HTTP 500.
func TestZonesHandlerQuarantinePreservesCounterError10531(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	s, dp, ids := newQuarantineRESTFixture(t, "z174", "z214", "trust")
	setQuarantineRESTCounters(dp, ids["z174"], 11, 1100, 22, 2200)
	errDP := &quarantineRESTReadErrDP{
		quarantineRESTDP: dp,
		errID:            ids["trust"],
	}
	s.dp = errDP

	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("zonesHandler status = %d, want 500; body=%s", rr.Code, rr.Body.String())
	}
	if dp.reads != 2 {
		t.Fatalf("ReadZoneCounters calls before genuine error = %d, want 2 for survivor only; quarantined z214 must be skipped", dp.reads)
	}
}

func TestZonesHandlerQuarantineNoCollision10531(t *testing.T) {
	s, dp, ids := newQuarantineRESTFixture(t, "trust", "untrust", "dmz")
	setQuarantineRESTCounters(dp, ids["trust"], 7, 70, 8, 80)
	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	zones, raw := decodeRESTZones10531(t, rr.Body.Bytes())
	for _, name := range []string{"trust", "untrust", "dmz"} {
		zone := restZoneByName10531(t, zones, name)
		if zone.Quarantine == nil || zone.Quarantine.State != ZoneQuarantineStateNotQuarantined || zone.Quarantine.SurvivorZone != "" {
			t.Fatalf("%s quarantine = %+v, want not_quarantined without survivor", name, zone.Quarantine)
		}
		zoneRaw := rawRESTZoneByName10531(t, raw, name)
		var q map[string]json.RawMessage
		if err := json.Unmarshal(zoneRaw["quarantine"], &q); err != nil {
			t.Fatalf("decode %s quarantine: %v", name, err)
		}
		if _, present := q["survivor_zone"]; present {
			t.Fatalf("%s raw quarantine unexpectedly has survivor_zone", name)
		}
	}
	if trust := restZoneByName10531(t, zones, "trust"); !trust.PerZoneCountersAvailable || trust.IngressPackets != 7 {
		t.Fatalf("trust counters/availability = %d/%v, want 7/true", trust.IngressPackets, trust.PerZoneCountersAvailable)
	}
	for _, name := range []string{"untrust", "dmz"} {
		if zone := restZoneByName10531(t, zones, name); zone.PerZoneCountersAvailable {
			t.Fatalf("%s unexpectedly reported available counters", name)
		}
	}
}

func TestZonesHandlerQuarantinePresenceSkew10531(t *testing.T) {
	legacy, err := json.Marshal(ZoneInfo{Name: "legacy"})
	if err != nil {
		t.Fatalf("marshal legacy REST ZoneInfo: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(legacy, &raw); err != nil {
		t.Fatalf("decode legacy REST ZoneInfo: %v", err)
	}
	if _, present := raw["quarantine"]; present {
		t.Fatalf("legacy REST ZoneInfo unexpectedly has quarantine key: %s", legacy)
	}
	var decoded ZoneInfo
	if err := json.Unmarshal(legacy, &decoded); err != nil {
		t.Fatalf("unmarshal legacy REST ZoneInfo: %v", err)
	}
	if decoded.Quarantine != nil {
		t.Fatalf("legacy REST ZoneInfo decoded quarantine = %+v, want nil/UNKNOWN", decoded.Quarantine)
	}

	s, dp, ids := newQuarantineRESTFixture(t, "z174", "z214", "trust")
	setQuarantineRESTCounters(dp, ids["z174"], 19, 1900, 29, 2900)
	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler skew fixture status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	_, rawZones := decodeRESTZones10531(t, rr.Body.Bytes())
	if len(rawZones) == 0 {
		t.Fatal("zonesHandler skew fixture returned no zones")
	}
	if !strings.Contains(rr.Body.String(), `"data":[`) {
		t.Fatalf("REST data is not a bare JSON array: %s", rr.Body.String())
	}
}

func TestZoneQuarantineParityWithCollector10531(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("test premise broken: z174/z214 no longer collide")
	}
	s, dp, ids := newQuarantineRESTFixture(t, "z174", "z214", "trust")
	setQuarantineRESTCounters(dp, ids["z174"], 11, 1100, 22, 2200)
	setQuarantineRESTCounters(dp, ids["trust"], 33, 3300, 44, 4400)

	_, unpopulated := zoneSamples(t, newCollector(s), dp)
	if unpopulated != 1 {
		t.Fatalf("collector unpopulated gauge = %v, want 1 quarantined zone", unpopulated)
	}

	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	zones, _ := decodeRESTZones10531(t, rr.Body.Bytes())
	var restUnavailable float64
	for _, zone := range zones {
		if !zone.PerZoneCountersAvailable {
			restUnavailable++
		}
	}
	if restUnavailable != unpopulated {
		t.Fatalf("REST unavailable count = %v, collector gauge = %v; quarantine disposition drifted", restUnavailable, unpopulated)
	}
}

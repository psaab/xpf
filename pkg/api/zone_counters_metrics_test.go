package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/conntrack"
	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// This file guards the #3651 per-zone Prometheus surface. It replaces the
// #3643 zone_counters_hide_test.go, which pinned the metrics ABSENT — a
// conclusion #3651 deliberately reverses now that the populate path ships. The
// property that still matters, and is preserved here, is the one that made
// #3643 drop the family in the first place: the read must never index a DENSE
// array by zone id, so a stable-hash id >= MaxZones must neither OOB nor
// produce a per-scrape read-error storm on xpf_counter_read_errors_total.

// zoneRealReadDP reuses the fully-wired descriptorCoverageDP (loaded, apply
// result, all OTHER counter reads succeed) but delegates the per-zone counter
// read to the REAL dataplane.Manager instead of the success-stub. That
// exercises the production read path — the Go-side SPARSE offset map — rather
// than a fake that cannot exhibit the defect being guarded against.
type zoneRealReadDP struct {
	*descriptorCoverageDP
}

func (d *zoneRealReadDP) ReadZoneCounters(zoneID uint16, dir int) (dataplane.CounterValue, error) {
	return d.Manager.ReadZoneCounters(zoneID, dir)
}

// errZoneRead is a genuine (non-ErrCounterNotPopulated) per-zone read failure:
// a degraded counter bridge, as opposed to the legitimate "not populated yet"
// steady state.
var errZoneRead = errors.New("zone counter bridge unavailable")

// zoneReadErrDP fails EVERY per-zone read with a genuine error.
type zoneReadErrDP struct {
	*descriptorCoverageDP
}

func (d *zoneReadErrDP) ReadZoneCounters(uint16, int) (dataplane.CounterValue, error) {
	return dataplane.CounterValue{}, errZoneRead
}

// fixtureZoneIDs returns the stable-hash zone ids for the two zones in
// newDescriptorCoverageStore, computed with the PRODUCTION assignment function
// (config.StableZoneID, the #3075 SSOT that the compiler's assignZoneIDs uses),
// and asserts each is >= dataplane.MaxZones.
//
// This is the fixture the #3643 defect needs, and it is genuinely producible
// rather than a shape hand-picked to look alarming: StableZoneID folds into
// [1,65533] while MaxZones is 64, so a real zone name lands >= MaxZones with
// probability ~99.9% — "trust" hashes to 50675 and "untrust" to 20665. The
// assertion below is what makes that a fact of the build rather than a claim in
// a comment: if the hash or MaxZones ever changed such that these ids fell
// inside the dense range, this test would announce that it had stopped
// exercising the OOB case instead of silently passing for the wrong reason.
func fixtureZoneIDs(t *testing.T) map[string]uint16 {
	t.Helper()
	ids := map[string]uint16{}
	for _, name := range []string{"trust", "untrust"} {
		id := config.StableZoneID(name)
		if id < dataplane.MaxZones {
			t.Fatalf("zone %q stable id %d < MaxZones %d — this fixture no longer "+
				"exercises the #3643 dense-array OOB case it exists to guard; "+
				"pick a zone name whose stable id exceeds MaxZones",
				name, id, dataplane.MaxZones)
		}
		ids[name] = id
	}
	return ids
}

// neutralizeKernelCounterReads stubs the pre-dataplane-gate kernel nft/netlink
// counter reads. In a sandbox without live nft these fail and bump
// counterReadErrors, which would mask (or fake) the per-zone read-error
// assertions this file makes.
func neutralizeKernelCounterReads(t *testing.T) {
	t.Helper()
	origDeny := readHostInboundDenyCounters
	readHostInboundDenyCounters = func() ([]xnft.HostInboundDenyCount, xnft.HostInboundTableState, error) {
		return nil, xnft.HostInboundTableAbsent, nil
	}
	t.Cleanup(func() { readHostInboundDenyCounters = origDeny })

	origLo0 := readLo0Counters
	readLo0Counters = func() ([]xnft.Lo0Count, error) { return nil, nil }
	t.Cleanup(func() { readLo0Counters = origLo0 })

	origAccept := readHostInboundAcceptCounters
	readHostInboundAcceptCounters = func() ([]xnft.HostInboundAcceptCount, error) { return nil, nil }
	t.Cleanup(func() { readHostInboundAcceptCounters = origAccept })

	origJH := readHostInboundJunosHostDenyCounters
	readHostInboundJunosHostDenyCounters = func() ([]xnft.HostInboundJunosHostDenyCount, error) {
		return nil, nil
	}
	t.Cleanup(func() { readHostInboundJunosHostDenyCounters = origJH })
}

// Every classification below matches the EXACT fqName (via the package's
// descFQName helper), never a strings.Contains over Desc.String().
//
// That is load-bearing here, not stylistic. Desc.String() renders as
// `Desc{fqName: "...", help: "...", ...}` — it embeds the HELP text — and this
// family deliberately cross-references itself by name: the volume metrics tell
// the operator to consult xpf_zone_counters_unpopulated_zones, and the gauge
// names the two volume metrics it explains. Under the substring idiom used
// elsewhere in this package, an xpf_zone_packets_total sample therefore matches
// the gauge arm first and gets read with GetGauge(), which yields 0 for a
// counter. The first draft of these tests did exactly that and reported "no
// samples emitted" against a collector that was emitting all eight correctly.

// zoneSamples collects one xpfCollector.collectZoneCounters run and returns the
// per-zone samples keyed "<metric>/<zone>/<direction>", plus the value of the
// xpf_zone_counters_unpopulated_zones gauge (-1 if it was never emitted, which
// is itself a failure — the gauge is contractually emitted on every path).
func zoneSamples(t *testing.T, c *xpfCollector, dp apiRuntimeDataPlane) (map[string]float64, float64) {
	t.Helper()
	ch := make(chan prometheus.Metric, 128)
	c.collectZoneCounters(ch, dp)
	close(ch)

	out := map[string]float64{}
	unpopulated := -1.0
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		name := descFQName(m.Desc().String())
		switch name {
		case "xpf_zone_counters_unpopulated_zones":
			unpopulated = pb.GetGauge().GetValue()
		case "xpf_zone_packets_total", "xpf_zone_bytes_total":
			var zone, direction string
			for _, l := range pb.GetLabel() {
				switch l.GetName() {
				case "zone":
					zone = l.GetValue()
				case "direction":
					direction = l.GetValue()
				}
			}
			out[fmt.Sprintf("%s/%s/%s", name, zone, direction)] = pb.GetCounter().GetValue()
		}
	}
	return out, unpopulated
}

// TestCollectZoneCountersEmitsPopulatedVolume is the #3651 RESTORE pin: once
// the populate path has written the offset map, a scrape publishes live
// per-zone volume.
//
// It seeds the map through Manager.SetZoneCounterOffset, the single-row
// TEST-ONLY setter, and reads back through the real Manager. #6843: production
// no longer uses that setter — syncBPFCountersLocked replaces the whole map via
// ReplaceZoneCounterOffsets — so this exercises the READ end against a
// realistic map, not the production write path. The write path is bound
// separately by TestSyncBPFCountersReplacesZoneOffsetsAcrossPolls6843. The zone ids are
// the real stable hashes, i.e. >= MaxZones, so this simultaneously demonstrates
// that a large id now reads back fine instead of OOB'ing.
//
// FAIL-ON-REVERT: dropping collectZoneCounters (or its Collect() call site)
// leaves the sample map empty and the four value assertions fail.
func TestCollectZoneCountersEmitsPopulatedVolume(t *testing.T) {
	ids := fixtureZoneIDs(t)
	mgr := dataplane.New()
	mgr.SetZoneCounterOffset(ids["trust"],
		dataplane.CounterValue{Packets: 11, Bytes: 1100},
		dataplane.CounterValue{Packets: 22, Bytes: 2200})
	mgr.SetZoneCounterOffset(ids["untrust"],
		dataplane.CounterValue{Packets: 33, Bytes: 3300},
		dataplane.CounterValue{Packets: 44, Bytes: 4400})

	srv := &Server{store: newDescriptorCoverageStore(t)}
	dp := &zoneRealReadDP{&descriptorCoverageDP{
		Manager: mgr,
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	srv.dp = dp
	c := newCollector(srv)

	got, unpopulated := zoneSamples(t, c, dp)

	want := map[string]float64{
		"xpf_zone_packets_total/trust/ingress":   11,
		"xpf_zone_bytes_total/trust/ingress":     1100,
		"xpf_zone_packets_total/trust/egress":    22,
		"xpf_zone_bytes_total/trust/egress":      2200,
		"xpf_zone_packets_total/untrust/ingress": 33,
		"xpf_zone_bytes_total/untrust/ingress":   3300,
		"xpf_zone_packets_total/untrust/egress":  44,
		"xpf_zone_bytes_total/untrust/egress":    4400,
	}
	for k, v := range want {
		g, ok := got[k]
		if !ok {
			t.Errorf("sample %q absent; the per-zone metric family must publish "+
				"live volume once the offset map is populated (#3651)", k)
			continue
		}
		if g != v {
			t.Errorf("sample %q = %v, want %v", k, g, v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("emitted %d per-zone samples, want %d: %v", len(got), len(want), got)
	}
	if unpopulated != 0 {
		t.Errorf("xpf_zone_counters_unpopulated_zones = %v, want 0 — every "+
			"configured zone is populated in this fixture", unpopulated)
	}
	if got := c.counterReadErrors.Load(); got != 0 {
		t.Errorf("counterReadErrors = %d on an all-successful per-zone scrape; want 0", got)
	}
}

// TestCollectZoneCountersOmitsUnpopulatedRatherThanPublishingZero is the
// #3651 honesty pin, and the #3643 false-alert pin in one.
//
// With an EMPTY offset map (a helper that has published nothing — pre-#3651
// helper, a zone past the helper's hot-path slot capacity, or simply an idle
// zone; the sparse status snapshot makes these three indistinguishable), every
// read returns ErrCounterNotPopulated. The contract:
//
//   - NO xpf_zone_packets_total / xpf_zone_bytes_total sample is emitted. A 0
//     here would be an authoritative zero over an unknown — right only for the
//     idle case, and silently wrong for the other two.
//   - xpf_zone_counters_unpopulated_zones reports the count, so the omission is
//     explicit rather than indistinguishable from a zone that vanished.
//   - counterReadErrors stays 0. Unpopulated is a legitimate steady state, not
//     a failure. Counting it as one is precisely the per-zone, per-scrape false
//     alert that made #3643 delete this family; the zone ids here are the real
//     stable hashes (>= MaxZones), the exact input that used to trigger it.
//
// FAIL-ON-REVERT: emitting a 0 sample instead of omitting fails the "no
// samples" assertion; routing ErrCounterNotPopulated into counterReadErrors
// fails the == 0 assertion.
func TestCollectZoneCountersOmitsUnpopulatedRatherThanPublishingZero(t *testing.T) {
	ids := fixtureZoneIDs(t)
	srv := &Server{store: newDescriptorCoverageStore(t)}
	// dataplane.New() with no SetZoneCounterOffset call: the sparse offset map
	// is empty, so ReadZoneCounters returns ErrCounterNotPopulated for any id.
	dp := &zoneRealReadDP{&descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	srv.dp = dp
	c := newCollector(srv)

	got, unpopulated := zoneSamples(t, c, dp)

	if len(got) != 0 {
		t.Errorf("emitted %d per-zone samples for zones with UNPOPULATED counters: %v; "+
			"want none — publishing 0 would assert \"no traffic\" when the truth "+
			"is \"not known\" (#3651)", len(got), got)
	}
	if unpopulated != 2 {
		t.Errorf("xpf_zone_counters_unpopulated_zones = %v, want 2 (both configured "+
			"zones unpopulated); the omission must be explicit, not silent", unpopulated)
	}
	if got := c.counterReadErrors.Load(); got != 0 {
		t.Errorf("counterReadErrors = %d after a scrape whose per-zone reads were all "+
			"ErrCounterNotPopulated with stable-hash ids >= MaxZones; want 0 — "+
			"unpopulated is a steady state, and counting it as a read error "+
			"reintroduces the #3643 per-scrape false alert", got)
	}
}

// TestCollectZoneCountersBumpsOnGenuineReadError is the negative control for
// the test above: the not-populated path must be silent on
// xpf_counter_read_errors_total, but a REAL read failure must still bump it.
// Without this, "counterReadErrors == 0" could be satisfied by a collector that
// never bumps at all — the #3345/#3408 skip-and-bump contract would be dead and
// the unpopulated assertion would still pass.
//
// A genuine failure must ALSO not be laundered into the unpopulated gauge:
// "degraded" and "not yet known" are different operator situations.
func TestCollectZoneCountersBumpsOnGenuineReadError(t *testing.T) {
	ids := fixtureZoneIDs(t)
	srv := &Server{store: newDescriptorCoverageStore(t)}
	dp := &zoneReadErrDP{&descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	srv.dp = dp
	c := newCollector(srv)

	got, unpopulated := zoneSamples(t, c, dp)

	if len(got) != 0 {
		t.Errorf("emitted %d per-zone samples on a failed read: %v; want none "+
			"(skip-and-bump, never a misleading 0 — #3345/#3408)", len(got), got)
	}
	if want := uint64(len(ids)); c.counterReadErrors.Load() != want {
		t.Errorf("counterReadErrors = %d after %d genuinely failing per-zone reads, "+
			"want %d — a real degraded counter bridge must stay alertable",
			c.counterReadErrors.Load(), len(ids), want)
	}
	if unpopulated != 0 {
		t.Errorf("xpf_zone_counters_unpopulated_zones = %v after genuine read "+
			"FAILURES, want 0 — a failure must not be laundered into the "+
			"\"not yet known\" signal", unpopulated)
	}
}

// TestZoneUnpopulatedGaugeMatchesRESTAvailability pins the coherence claim the
// collector's doc comment makes: xpf_zone_counters_unpopulated_zones counts
// exactly the zones REST reports per_zone_counters_available:false for.
//
// Two surfaces reporting the same underlying fact through separately written
// code drift silently. This drives BOTH against one shared server/dataplane in
// each of two states — one zone populated, then both populated — and asserts
// they agree, so a change to either surface's disposition logic that is not
// mirrored in the other fails here.
func TestZoneUnpopulatedGaugeMatchesRESTAvailability(t *testing.T) {
	ids := fixtureZoneIDs(t)

	for _, tc := range []struct {
		name      string
		populate  []string
		wantUnpop float64
	}{
		{name: "none populated", populate: nil, wantUnpop: 2},
		{name: "one populated", populate: []string{"trust"}, wantUnpop: 1},
		{name: "both populated", populate: []string{"trust", "untrust"}, wantUnpop: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := dataplane.New()
			for _, z := range tc.populate {
				mgr.SetZoneCounterOffset(ids[z],
					dataplane.CounterValue{Packets: 1, Bytes: 100},
					dataplane.CounterValue{Packets: 2, Bytes: 200})
			}
			srv := &Server{store: newDescriptorCoverageStore(t)}
			dp := &zoneRealReadDP{&descriptorCoverageDP{
				Manager: mgr,
				apply:   &dataplane.ApplyResult{ZoneIDs: ids},
			}}
			srv.dp = dp
			c := newCollector(srv)

			_, unpopulated := zoneSamples(t, c, dp)
			if unpopulated != tc.wantUnpop {
				t.Errorf("xpf_zone_counters_unpopulated_zones = %v, want %v",
					unpopulated, tc.wantUnpop)
			}

			// REST side, same server + dataplane.
			rr := httptest.NewRecorder()
			srv.zonesHandler(rr, httptest.NewRequest("GET", "/api/v1/security/zones", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("zonesHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
			}
			var resp struct {
				Data []ZoneInfo `json:"data"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal zones response: %v; body=%s", err, rr.Body.String())
			}
			var restUnavailable float64
			for _, z := range resp.Data {
				if !z.PerZoneCountersAvailable {
					restUnavailable++
				}
			}
			if restUnavailable != unpopulated {
				t.Errorf("REST reports %v zones with per_zone_counters_available=false "+
					"but the Prometheus gauge reports %v unpopulated; the two "+
					"surfaces must count the same set (#3651)",
					restUnavailable, unpopulated)
			}
		})
	}
}

func TestZoneUnpopulatedGaugeMatchesRESTQuarantineCollision10530(t *testing.T) {
	s, ids := quarantinedZonesConfig10530(t)
	mgr := dataplane.New()
	mgr.SetZoneCounterOffset(ids["z174"],
		dataplane.CounterValue{Packets: 1, Bytes: 100},
		dataplane.CounterValue{Packets: 2, Bytes: 200})
	mgr.SetZoneCounterOffset(ids["trust"],
		dataplane.CounterValue{Packets: 3, Bytes: 300},
		dataplane.CounterValue{Packets: 4, Bytes: 400})
	dp := &zoneRealReadDP{&descriptorCoverageDP{
		Manager: mgr,
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	s.dp = dp
	c := newCollector(s)

	_, unpopulated := zoneSamples(t, c, dp)
	if unpopulated != 1 {
		t.Fatalf("xpf_zone_counters_unpopulated_zones = %v, want 1 quarantined zone", unpopulated)
	}

	rr := httptest.NewRecorder()
	s.zonesHandler(rr, httptest.NewRequest(http.MethodGet, "/api/v1/security/zones", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data []ZoneInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal zones response: %v; body=%s", err, rr.Body.String())
	}
	var restUnavailable int
	for _, z := range resp.Data {
		if !z.PerZoneCountersAvailable {
			restUnavailable++
		}
	}
	if restUnavailable != int(unpopulated) {
		t.Fatalf("REST reports %d unavailable zones but gauge reports %v; collision surfaces diverged",
			restUnavailable, unpopulated)
	}
}

// TestZonesHandlerZoneCountersNotAvailable is the #3643 REST pin, retained: a
// zone whose stable-hash id is >= MaxZones must NOT 500 the /security/zones
// endpoint when its counters are unpopulated. It returns 200 with
// per_zone_counters_available false and the numeric counts unset (not a
// misleading 0).
//
// FAIL-ON-REVERT: restoring a dense-array read in ReadZoneCounters (or handling
// ErrCounterNotPopulated as a genuine failure -> readErr -> 500) makes the
// endpoint 500 for the large-id zone, so the 200 assertion goes RED.
func TestZonesHandlerZoneCountersNotAvailable(t *testing.T) {
	ids := fixtureZoneIDs(t)
	s := &Server{
		store: newDescriptorCoverageStore(t),
		dp: &zoneRealReadDP{&descriptorCoverageDP{
			Manager: dataplane.New(),
			apply:   &dataplane.ApplyResult{ZoneIDs: ids},
		}},
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/security/zones", nil)
	s.zonesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("zonesHandler status = %d, want 200 (a stable-hash zone id >= MaxZones "+
			"must not 500 the endpoint). body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Success bool       `json:"success"`
		Data    []ZoneInfo `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal zones response: %v; body=%s", err, rr.Body.String())
	}
	if !resp.Success || len(resp.Data) == 0 {
		t.Fatalf("success=%v, %d zones; want success + >=1 zone; body=%s",
			resp.Success, len(resp.Data), rr.Body.String())
	}
	for _, z := range resp.Data {
		if z.PerZoneCountersAvailable {
			t.Errorf("zone %q per_zone_counters_available = true, want false "+
				"(the offset map is empty in this fixture)", z.Name)
		}
		if z.IngressPackets != 0 || z.EgressPackets != 0 || z.IngressBytes != 0 || z.EgressBytes != 0 {
			t.Errorf("zone %q reports nonzero per-zone counts (%+v) while marked unavailable",
				z.Name, z)
		}
	}
}

// TestCollectDoesNotFalseAlertOnZoneReads keeps the #3643 guarantee at the
// WHOLE-Collect level, where the false alert actually manifested. A full
// Collect() over a loaded dataplane whose per-zone reads go through the real
// Manager with stable-hash ids >= MaxZones must not bump
// xpf_counter_read_errors_total. All other counter reads succeed and the
// pre-gate kernel reads are neutralized, so a nonzero count could only come
// from the per-zone collector.
//
// Unlike its pre-#3651 form, this no longer asserts the xpf_zone_* family is
// ABSENT — that conclusion is what #3651 reverses. It asserts the family is
// present in Describe() (a checked collector requires it) while the per-zone
// SAMPLES stay omitted for unpopulated zones.
func TestCollectDoesNotFalseAlertOnZoneReads(t *testing.T) {
	neutralizeKernelCounterReads(t)

	ids := fixtureZoneIDs(t)
	store := newDescriptorCoverageStore(t)
	srv := &Server{store: store, gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &zoneRealReadDP{&descriptorCoverageDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			ZoneIDs:   ids,
			FilterIDs: map[string]uint32{"inet:fin": 0, "inet6:fin6": 100},
		},
	}}
	c := newCollector(srv)

	ch := make(chan prometheus.Metric, 512)
	c.Collect(ch)
	close(ch)

	var sawZoneVolumeSample bool
	var sawUnpopulatedGauge bool
	for m := range ch {
		switch descFQName(m.Desc().String()) {
		case "xpf_zone_packets_total", "xpf_zone_bytes_total":
			sawZoneVolumeSample = true
		case "xpf_zone_counters_unpopulated_zones":
			sawUnpopulatedGauge = true
		}
	}
	if sawZoneVolumeSample {
		t.Error("Collect() emitted a per-zone volume sample for zones whose counters " +
			"are unpopulated; the sample must be omitted, not published as 0 (#3651)")
	}
	if !sawUnpopulatedGauge {
		t.Error("Collect() emitted no xpf_zone_counters_unpopulated_zones sample; " +
			"the gauge is emitted on every path so it is alertable and its " +
			"absence is not confusable with a healthy scrape (#3651)")
	}
	if got := c.counterReadErrors.Load(); got != 0 {
		t.Errorf("counterReadErrors = %d after Collect() with stable-hash zone ids >= MaxZones; "+
			"want 0 -- the structural per-zone OOB must no longer false-alert (#3643/#3345)", got)
	}

	// The restored descriptors must be DECLARED even though no volume sample
	// was emitted this scrape: xpfCollector is a checked collector, so a
	// descriptor emitted on a later (populated) scrape without being declared
	// here would error the registry (#1635/#1726).
	declared := describedSet(c)
	for _, name := range []string{
		"xpf_zone_packets_total",
		"xpf_zone_bytes_total",
		"xpf_zone_counters_unpopulated_zones",
	} {
		var found bool
		for d := range declared {
			if descFQName(d.String()) == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("descriptor %q not declared by Describe(); a checked collector "+
				"errors when Collect() emits an undeclared descriptor", name)
		}
	}
}

// TestZoneMetricsFollowTheHelperAcrossSlotLoss is the #6843 end-to-end pin:
// the retention fix must be visible at the METRIC, not just in the manager.
//
// Scenario the gate traced. A zone accumulates traffic and publishes. A later
// config adds enough lower-id zones to exhaust the helper's hot-path slot
// capacity; the zone stays configured but loses its slot, so the helper stops
// publishing its row while its retained totals sit in the store. Prometheus
// must stop emitting that zone's samples and start counting it as unpopulated.
//
// Before the fix the Go status loop only ever SET rows, so the last published
// total stayed in the offset map and the collector kept emitting it forever —
// a frozen counter that under-reports every subsequent packet while looking
// alive. That is strictly worse than the omission this PR exists to produce.
//
// FAIL-ON-REVERT: make `ReplaceZoneCounterOffsets` merge instead of replace and
// the post-transition assertions go RED. Note this test injects offset maps
// directly, so it does NOT bind the status-loop CALL SITE — that is bound by
// TestSyncBPFCountersReplacesZoneOffsetsAcrossPolls6843 in
// pkg/dataplane/userspace.
func TestZoneMetricsFollowTheHelperAcrossSlotLoss(t *testing.T) {
	ids := fixtureZoneIDs(t)
	mgr := dataplane.New()

	// Poll N: both zones hold slots and publish.
	mgr.ReplaceZoneCounterOffsets(map[uint16][2]dataplane.CounterValue{
		ids["trust"]:   {{Packets: 10, Bytes: 1000}, {Packets: 11, Bytes: 1100}},
		ids["untrust"]: {{Packets: 20, Bytes: 2000}, {Packets: 21, Bytes: 2100}},
	})
	srv := &Server{store: newDescriptorCoverageStore(t)}
	dp := &zoneRealReadDP{&descriptorCoverageDP{
		Manager: mgr,
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	srv.dp = dp
	c := newCollector(srv)

	got, unpopulated := zoneSamples(t, c, dp)
	if got["xpf_zone_packets_total/trust/ingress"] != 10 {
		t.Fatalf("poll N: trust ingress = %v, want 10; samples=%v",
			got["xpf_zone_packets_total/trust/ingress"], got)
	}
	if unpopulated != 0 {
		t.Fatalf("poll N: unpopulated = %v, want 0", unpopulated)
	}

	// Poll N+1: `trust` was pushed past slot capacity by a later config. It is
	// still configured (still in ZoneIDs) but the helper no longer publishes
	// it, so the sparse snapshot carries only `untrust`.
	mgr.ReplaceZoneCounterOffsets(map[uint16][2]dataplane.CounterValue{
		ids["untrust"]: {{Packets: 25, Bytes: 2500}, {Packets: 26, Bytes: 2600}},
	})

	got, unpopulated = zoneSamples(t, c, dp)
	for _, k := range []string{
		"xpf_zone_packets_total/trust/ingress",
		"xpf_zone_bytes_total/trust/ingress",
		"xpf_zone_packets_total/trust/egress",
		"xpf_zone_bytes_total/trust/egress",
	} {
		if v, ok := got[k]; ok {
			t.Errorf("sample %q still emitted (=%v) after the zone lost its hot-path "+
				"slot; the helper stopped publishing it, so this value can never "+
				"advance again — a FROZEN counter is worse than an omission because "+
				"it looks alive", k, v)
		}
	}
	if unpopulated != 1 {
		t.Errorf("xpf_zone_counters_unpopulated_zones = %v, want 1 — the zone that "+
			"lost its slot must be counted as not-known, not silently dropped",
			unpopulated)
	}
	// The still-slotted zone keeps advancing: the fix must not blanket-drop.
	if got["xpf_zone_packets_total/untrust/ingress"] != 25 {
		t.Errorf("untrust ingress = %v, want 25 — a sibling losing its slot must not "+
			"disturb a zone that is still reporting",
			got["xpf_zone_packets_total/untrust/ingress"])
	}
	if err := c.counterReadErrors.Load(); err != 0 {
		t.Errorf("counterReadErrors = %d; losing a slot is not a read error", err)
	}
}

// notLoadedDP reports the dataplane as NOT loaded — the degraded / config-only
// boot state. descriptorCoverageDP hardcodes IsLoaded() true, so no existing
// fixture can reach this path.
type notLoadedDP struct{ *descriptorCoverageDP }

func (d *notLoadedDP) IsLoaded() bool { return false }

// TestZoneUnpopulatedGaugeHelpEnumeratesEveryCause is the #6843 round-5 pin on
// the HELP text itself.
//
// The gauge's HELP enumerates the causes an operator triages from. There are
// SIX such causes, reached through THREE increment branches in
// collectZoneCounters — the unloaded and loaded-with-no-apply-result cases
// share a branch, and (a)-(c) all arrive via the ErrCounterNotPopulated
// sentinel. The HELP is keyed to CAUSES, because that is what an operator
// triages; do not read the phrase list below as a branch count. A HELP that
// lists fewer causes sends the operator after causes that do not apply —
// which is the whole
// failure the cause list exists to prevent. Reverting the HELP to any shorter
// enumeration was green before this test: nothing asserted on the string.
//
// Asserted against THIS gauge's own Desc().String() rather than a scrape-wide
// substring search: Desc.String() embeds the HELP, so a loose match can be
// satisfied by a different metric's help text (the same trap that made the
// first draft of zoneSamples misread counters as the gauge).
//
// FAIL-ON-REVERT: drop any clause below from the HELP and the matching
// assertion reds.
func TestZoneUnpopulatedGaugeHelpEnumeratesEveryCause(t *testing.T) {
	c := newCollector(&Server{store: newDescriptorCoverageStore(t)})

	var help string
	for d := range describedSet(c) {
		if descFQName(d.String()) == "xpf_zone_counters_unpopulated_zones" {
			help = d.String()
			break
		}
	}
	if help == "" {
		t.Fatal("xpf_zone_counters_unpopulated_zones not declared by Describe()")
	}

	// One phrase per membership CAUSE (six), not per increment branch (three).
	// Each is chosen to be unique to this gauge's help, not shared with a
	// sibling metric — Desc.String() embeds the HELP, so a phrase that also
	// appears in another metric's help would match the wrong descriptor.
	for _, want := range []string{
		"predates the per-zone populate path", // (a) pre-#3651 helper
		"hot-path slot capacity",              // (b) slot overflow
		"the zone is idle",                    // (c) idle
		"no loaded dataplane at all",          // (d) unloaded
		"no apply result yet",                 // (e) loaded, first apply pending/failed
		"absent from the last apply result",   // (f) store promoted before apply
	} {
		if !strings.Contains(help, want) {
			t.Errorf("gauge HELP does not name the cause %q; an operator paging on "+
				"`> 0` triages from this list, so an unlisted cause is a "+
				"mis-triage by construction.\nHELP: %s", want, help)
		}
	}
}

// TestZoneUnpopulatedGaugeEmittedOnDegradedBoot is the #6843 R1 pin.
//
// The gauge is documented as ALWAYS emitted, so `> 0` is alertable and its
// ABSENCE cannot be confused with a scrape that failed to run. Below the
// dataplane-loaded gate that promise broke exactly where it mattered most: on a
// degraded or config-only boot Collect() returned before reaching the collector,
// so no sample was emitted and the alert silently stopped evaluating precisely
// when per-zone volume was most unavailable — the literal failure the comment
// says cannot happen.
//
// FAIL-ON-REVERT: move the collectZoneCounters call back below the
// `dp == nil || !dp.IsLoaded()` early return and this goes RED with no gauge
// emitted.
func TestZoneUnpopulatedGaugeEmittedOnDegradedBoot(t *testing.T) {
	neutralizeKernelCounterReads(t)

	ids := fixtureZoneIDs(t)
	srv := &Server{store: newDescriptorCoverageStore(t), gc: conntrack.NewGC(nil, time.Minute), startTime: time.Now()}
	srv.dp = &notLoadedDP{&descriptorCoverageDP{
		Manager: dataplane.New(),
		apply:   &dataplane.ApplyResult{ZoneIDs: ids},
	}}
	c := newCollector(srv)

	ch := make(chan prometheus.Metric, 256)
	c.Collect(ch)
	close(ch)

	gauge := -1.0
	sawVolume := false
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("metric write: %v", err)
		}
		switch descFQName(m.Desc().String()) {
		case "xpf_zone_counters_unpopulated_zones":
			gauge = pb.GetGauge().GetValue()
		case "xpf_zone_packets_total", "xpf_zone_bytes_total":
			sawVolume = true
		}
	}

	if gauge < 0 {
		t.Fatal("no xpf_zone_counters_unpopulated_zones sample on a NOT-LOADED " +
			"dataplane; the gauge is contractually always emitted, and its absence " +
			"here silences the alert exactly when per-zone volume is unavailable")
	}
	if gauge != 2 {
		t.Errorf("unpopulated gauge = %v on a degraded boot, want 2 (both configured "+
			"zones unknown)", gauge)
	}
	if sawVolume {
		t.Error("emitted a per-zone volume sample with no loaded dataplane; there is " +
			"nothing to read, so publishing a number would be fabricated")
	}
	if got := c.counterReadErrors.Load(); got != 0 {
		t.Errorf("counterReadErrors = %d on an unloaded dataplane; want 0 — not "+
			"being loaded is a state, not a failed read", got)
	}
}

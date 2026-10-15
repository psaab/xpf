// #13247 (D6-07): zoneByID built by raw map iteration in natPoolStatsHandler /
// GetNATPoolStats / GetNATDestination resolved a StableZoneID collision
// non-deterministically to the quarantined loser (~50% of calls), zeroing the
// survivor zone's NAT session counts; pool output order was also unsorted.
//
// FAIL-ON-REVERT: restoring the raw `for name, id := range cr.ZoneIDs` loops
// or the unsorted SourcePools iteration makes these tests flake/fail.
package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

func quarantine13247Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, t.TempDir()+"/xpf.conf")
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := store.LoadSet(`set security zones security-zone untrust
set security nat source pool zeta address 203.0.113.20/32
set security nat source pool alpha address 203.0.113.10/32
set security nat source pool mid address 203.0.113.15/32
set security nat source rule-set rs-surv from zone z174
set security nat source rule-set rs-surv to zone untrust
set security nat source rule-set rs-surv rule r1 match source-address 0.0.0.0/0
set security nat source rule-set rs-surv rule r1 then source-nat interface`); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	cfg := store.ActiveConfig()
	cfg.Security.Zones["z174"] = &config.ZoneConfig{Name: "z174"}
	cfg.Security.Zones["z214"] = &config.ZoneConfig{Name: "z214"}
	for _, name := range collisionNames13247(t, config.StableZoneID("z174")) {
		cfg.Security.Zones[name] = &config.ZoneConfig{Name: name}
	}
	return store
}

func TestNATPoolStatsQuarantineSurvivor13247(t *testing.T) {
	if config.StableZoneID("z174") != config.StableZoneID("z214") {
		t.Fatal("premise broken: z174/z214 no longer collide")
	}
	collidingID := config.StableZoneID("z174")
	zoneIDs := map[string]uint16{"z174": collidingID, "z214": collidingID, "untrust": 8}
	for _, name := range collisionNames13247(t, collidingID) {
		zoneIDs[name] = collidingID
	}
	dp := &natIfaceSNATSessionsDP{
		Manager: dataplane.New(),
		result:  &dataplane.ApplyResult{ZoneIDs: zoneIDs},
	}
	// Replace the fake's sessions with one SNAT session on the colliding ID.
	dpOverride := &quarantine13247DP{natIfaceSNATSessionsDP: dp, collidingID: collidingID}
	store := quarantine13247Store(t)
	cfg := store.ActiveConfig()
	if config.ZoneQuarantineExcludedReason("z214", cfg) == "" {
		t.Fatal("fixture does not quarantine colliding loser z214")
	}
	if config.ZoneQuarantineExcludedReason("z174", cfg) != "" {
		t.Fatal("fixture quarantines survivor z174")
	}
	s := &Server{store: store, dp: dpOverride}
	for iter := range 50 {
		rr := httptest.NewRecorder()
		s.natPoolStatsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/nat/source/pools", nil))
		if rr.Code != 200 {
			t.Fatalf("iter %d status=%d body=%s", iter, rr.Code, rr.Body.String())
		}
		var resp struct {
			Data []NATPoolStatsInfo `json:"data"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		byName := map[string]NATPoolStatsInfo{}
		names := make([]string, 0, len(resp.Data))
		for _, p := range resp.Data {
			byName[p.Name] = p
			names = append(names, p.Name)
		}
		if got := byName["z174->untrust"].UsedPorts; got != 1 {
			t.Fatalf("iter %d: survivor z174->untrust UsedPorts=%d, want 1 (quarantined loser stole colliding ID)", iter, got)
		}
		// Named pools sorted alpha,mid,zeta before interface rows.
		want := []string{"alpha", "mid", "zeta"}
		for i, w := range want {
			if names[i] != w {
				t.Fatalf("iter %d: pool order %v, want prefix %v", iter, names, want)
			}
		}
	}
}

type quarantine13247DP struct {
	*natIfaceSNATSessionsDP
	collidingID uint16
}

func (d *quarantine13247DP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	fn(dataplane.SessionKey{}, dataplane.SessionValue{Flags: dataplane.SessFlagSNAT, IngressZone: d.collidingID, EgressZone: 8})
	return nil
}

func collisionNames13247(t *testing.T, id uint16) []string {
	t.Helper()
	const want = 15
	names := make([]string, 0, want)
	for candidate := range 5_000_000 {
		name := fmt.Sprintf("zz13247-%d", candidate)
		if config.StableZoneID(name) == id {
			names = append(names, name)
			if len(names) == want {
				return names
			}
		}
	}
	t.Fatalf("found only %d of %d requested zone-ID colliders for %d", len(names), want, id)
	return nil
}

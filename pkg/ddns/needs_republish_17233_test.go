package ddns

import (
	"context"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #17233: needsRepublish is the single settled predicate for both DDNS
// surfaces. Pin its truth table directly: content drift always republishes,
// endpoint drift republishes only when BOTH fingerprints are known and
// differ, and identical/unknown fingerprints stay settled.
func TestNeedsRepublishTruthTable17233(t *testing.T) {
	rec := ownedRecord{}
	cases := []struct {
		name                string
		contentEqual        bool
		storedFP, currentFP string
		want                bool
	}{
		{"settled", true, "fp1-a", "fp1-a", false},
		{"content-changed", false, "fp1-a", "fp1-a", true},
		{"endpoint-changed", true, "fp1-a", "fp1-b", true},
		{"stored-unknown", true, "", "fp1-b", false},
		{"current-unknown", true, "fp1-a", "", false},
		{"both-unknown", true, "", "", false},
		{"content-changed-unknown-fp", false, "", "", true},
	}
	for _, c := range cases {
		if got := needsRepublish(rec, c.contentEqual, c.storedFP, c.currentFP); got != c.want {
			t.Errorf("%s: needsRepublish(contentEqual=%v, stored=%q, current=%q) = %v, want %v",
				c.name, c.contentEqual, c.storedFP, c.currentFP, got, c.want)
		}
	}
}

// #17233 control cell: an in-place endpoint edit must break the Surface A
// settled skip on the first pass (new-endpoint upsert + orphan alarm),
// while an unchanged provider on the next pass stays settled (no repeat
// upsert, no new alarm) and a pre-#3735 unknown-fingerprint record stays
// settled too (never a false alarm).
func TestSurfaceAInPlaceEndpointEditSettlesAfterRepublish17233(t *testing.T) {
	reg := newEndpointRegistry()
	now := time.Unix(1_700_000_000, 0)
	m := newSurfaceAProviderChangeManager(t, reg, func() time.Time { return now })

	scOld, provOld := providerScope("prov", "ns-a.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
		t.Fatalf("initial publish: %v", err)
	}
	// Repeat passes with no change: settled, no extra wire traffic.
	for range 3 {
		if err := m.Reconcile(context.Background(), []SurfaceAScope{scOld}, fixedObserver("203.0.113.5"), nil,
			map[string]*config.DDNSProvider{"prov": provOld}); err != nil {
			t.Fatalf("steady-state pass: %v", err)
		}
	}
	if got := len(reg.get("ns-a.example.net:53").upserts); got != 1 {
		t.Fatalf("unchanged provider must stay settled; ns-a upserts=%d, want 1", got)
	}

	// In-place edit, unchanged address, NO force: first pass republishes.
	scNew, provNew := providerScope("prov", "ns-b.example.net:53", "wan.example.net")
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scNew}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provNew}); err != nil {
		t.Fatalf("in-place edit pass: %v", err)
	}
	if got := len(reg.get("ns-b.example.net:53").upserts); got != 1 {
		t.Fatalf("new endpoint must receive the record on the first pass; upserts=%d, want 1", got)
	}
	if got := len(reg.get("ns-a.example.net:53").deletes); got != 0 {
		t.Fatalf("old endpoint must NOT be auto-withdrawn (#3735 deferred); deletes=%d", got)
	}
	if st := m.Stats(); st.Orphaned != 1 {
		t.Fatalf("in-place edit must raise exactly one orphan alarm on the first pass; stats=%+v", st)
	}

	// After the republish the scope settles again at the new endpoint.
	if err := m.Reconcile(context.Background(), []SurfaceAScope{scNew}, fixedObserver("203.0.113.5"), nil,
		map[string]*config.DDNSProvider{"prov": provNew}); err != nil {
		t.Fatalf("post-transition pass: %v", err)
	}
	if got := len(reg.get("ns-b.example.net:53").upserts); got != 1 {
		t.Fatalf("post-transition pass must stay settled; ns-b upserts=%d, want 1", got)
	}
	if st := m.Stats(); st.Orphaned != 1 {
		t.Fatalf("orphan alarm must not repeat after settling; stats=%+v", st)
	}
}

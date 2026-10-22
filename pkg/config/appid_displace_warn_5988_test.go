package config

import (
	"context"
	"log/slog"
	"testing"
)

// #5988: a user application whose stable name-derived NaturalAppIDCandidate hash-collides
// with an already-placed id is DISPLACED to the lowest free id by
// AssignStableAppIDs. That displaced id is NOT a pure function of the app name
// alone, so the small colliding set can renumber across catalog edits — the one
// case docs/services-application-identification.md says needs operator
// attention. Before #5988 the displacement was SILENT; AssignStableAppIDs now
// emits a slog.Warn naming the app, the natural slot it wanted, and the id it
// was displaced to. This test locks that observability signal.

// displaceCaptureRecord is one slog record captured by displaceCaptureHandler.
type displaceCaptureRecord struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

// displaceCaptureHandler records every slog record so the test can assert the
// displacement warning fired with the expected attributes.
type displaceCaptureHandler struct{ recs *[]displaceCaptureRecord }

func (h displaceCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h displaceCaptureHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]slog.Value{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value
		return true
	})
	*h.recs = append(*h.recs, displaceCaptureRecord{level: r.Level, msg: r.Message, attrs: attrs})
	return nil
}
func (h displaceCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h displaceCaptureHandler) WithGroup(string) slog.Handler      { return h }

// captureDisplaceWarns installs a capturing slog handler as the default logger
// for the test's lifetime and returns the slice records land in.
func captureDisplaceWarns(t *testing.T) *[]displaceCaptureRecord {
	t.Helper()
	recs := &[]displaceCaptureRecord{}
	old := slog.Default()
	slog.SetDefault(slog.New(displaceCaptureHandler{recs: recs}))
	t.Cleanup(func() { slog.SetDefault(old) })
	return recs
}

// TestAssignStableAppIDsDisplacementWarns_5988 constructs a real user-app vs
// user-app fold collision (svc-217 and svc-396 both fold to the same
// NaturalAppIDCandidate), runs AssignStableAppIDs, and asserts a Warn fired for the app
// that lost its natural slot — naming the app, its natural (wanted) id, and the
// displaced id it actually got.
//
// RED on revert: delete the slog.Warn in AssignStableAppIDs' displaced-fill loop
// and no record is captured, so the "expected a displacement Warn" assertion
// fails.
func TestAssignStableAppIDsDisplacementWarns_5988(t *testing.T) {
	const a = "svc-217"
	const b = "svc-396"

	// Fixture guard: the two names must still collide under the fold, and
	// neither may have become a predefined name (a predefined would be placed
	// first and win the slot, changing which app is displaced).
	if NaturalAppIDCandidate(a) != NaturalAppIDCandidate(b) {
		t.Skipf("test fixture stale: %q (id %d) no longer collides with %q (id %d) under the fold",
			a, NaturalAppIDCandidate(a), b, NaturalAppIDCandidate(b))
	}
	if _, ok := PredefinedApplications[a]; ok {
		t.Skipf("test fixture stale: %q is now a predefined application", a)
	}
	if _, ok := PredefinedApplications[b]; ok {
		t.Skipf("test fixture stale: %q is now a predefined application", b)
	}
	natural := NaturalAppIDCandidate(a) // == NaturalAppIDCandidate(b)

	recs := captureDisplaceWarns(t)

	out, err := AssignStableAppIDs([]string{a, b})
	if err != nil {
		t.Fatalf("AssignStableAppIDs(%v) error = %v", []string{a, b}, err)
	}

	// Exactly one of the pair keeps the natural slot; the other is displaced.
	// sort.Strings orders "svc-217" before "svc-396", so svc-217 is placed
	// first and keeps `natural`, and svc-396 is displaced.
	if out[a] != natural {
		t.Fatalf("expected %q to keep its natural id %d, got %d", a, natural, out[a])
	}
	if out[b] == natural {
		t.Fatalf("expected %q to be displaced off id %d, but it kept it", b, natural)
	}
	if out[b] == 0 {
		t.Fatalf("displaced %q got the reserved id 0", b)
	}
	displacedID := out[b]

	// The observability contract: a Warn must name the displaced app, the
	// natural slot it wanted, and the id it was displaced to.
	var found bool
	for _, r := range *recs {
		if r.level != slog.LevelWarn {
			continue
		}
		app, ok := r.attrs["application"]
		if !ok || app.String() != b {
			continue
		}
		found = true

		nat, ok := r.attrs["natural_app_id"]
		if !ok {
			t.Errorf("displacement Warn for %q missing natural_app_id attribute", b)
		} else if got := AssignedAppID(uint16(nat.Uint64())); got != natural {
			t.Errorf("displacement Warn natural_app_id = %d, want the wanted slot %d", got, natural)
		}

		asn, ok := r.attrs["assigned_app_id"]
		if !ok {
			t.Errorf("displacement Warn for %q missing assigned_app_id attribute", b)
		} else if got := AssignedAppID(uint16(asn.Uint64())); got != displacedID {
			t.Errorf("displacement Warn assigned_app_id = %d, want the displaced id %d", got, displacedID)
		}
		break
	}
	if !found {
		t.Fatalf("expected a displacement Warn naming the displaced app %q; captured %d records: %+v",
			b, len(*recs), *recs)
	}
}

// TestAssignStableAppIDsNoDisplacementNoWarn_5988 is the negative control: a
// collision-free catalog must NOT emit any displacement Warn, so the signal is
// meaningful (it fires only on the rare residual, never on the common case).
func TestAssignStableAppIDsNoDisplacementNoWarn_5988(t *testing.T) {
	// Two names that do NOT collide under the fold and are not predefined.
	const a = "svc-217"
	const c = "svc-218"
	if NaturalAppIDCandidate(a) == NaturalAppIDCandidate(c) {
		t.Skipf("test fixture stale: %q and %q now collide under the fold", a, c)
	}

	recs := captureDisplaceWarns(t)

	if _, err := AssignStableAppIDs([]string{a, c}); err != nil {
		t.Fatalf("AssignStableAppIDs(%v) error = %v", []string{a, c}, err)
	}
	for _, r := range *recs {
		if r.level == slog.LevelWarn {
			if _, ok := r.attrs["application"]; ok {
				t.Errorf("no-collision catalog emitted a displacement Warn: %+v", r)
			}
		}
	}
}

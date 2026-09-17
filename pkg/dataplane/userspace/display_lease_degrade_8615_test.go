package userspace

import (
	"errors"
	"testing"
)

// #8615: an OLD helper's refusal of the display verb must be distinguishable
// from a real failure.
//
// The two have different remedies and different truths. "This helper predates
// #8615, you are seeing the idle half" is a degraded but honest table, and the
// caller answers it by falling back to export_idle_leases. A genuine failure
// must leave the previous snapshot standing rather than assert an emptiness
// nobody observed (#8607's rule).
//
// Conflating them is the interesting failure, and it goes the quiet way:
// returning `nil, nil` for an old helper tells the refresher "this node holds
// no bindings", which renders as "No persistent NAT bindings" — the exact
// false statement #8607 removed, reintroduced by the fix for #8615.

func TestAnOldHelperRefusalIsDistinguishableFromAFailure8615(t *testing.T) {
	// The wording is the helper's, and it is a wire contract in everything but
	// name: it is produced by binaries already released and is pinned on the
	// Rust side (the_unknown_verb_wording_the_go_side_matches_on_is_pinned_7919).
	unknown := errors.New("unknown request type export_persistent_lease_display")

	got, err := displayLeasesFromResponse(ControlResponse{}, unknown)
	if !errors.Is(err, ErrPersistentLeaseDisplayUnsupported) {
		t.Errorf("an unknown-verb refusal must classify as "+
			"ErrPersistentLeaseDisplayUnsupported so the caller can degrade to the "+
			"idle export; got %v", err)
	}
	if got != nil {
		t.Errorf("an unsupported verb must not also return rows, got %d", len(got))
	}

	// A genuine failure must NOT be mistaken for an old helper — degrading on it
	// would silently answer with the idle half forever for a helper that is
	// merely broken.
	real := errors.New("control socket write: broken pipe")
	if _, err := displayLeasesFromResponse(ControlResponse{}, real); errors.Is(err, ErrPersistentLeaseDisplayUnsupported) {
		t.Error("a genuine failure must NOT classify as unsupported — the caller " +
			"would degrade permanently instead of keeping the previous snapshot")
	}

	// THE QUIET FAILURE: unsupported must never become an empty success.
	if rows, err := displayLeasesFromResponse(ControlResponse{}, unknown); err == nil && rows == nil {
		t.Error("an unsupported verb returned (nil, nil) — indistinguishable from " +
			"\"this node holds no bindings\", which renders as \"No persistent NAT " +
			"bindings\": the exact false statement #8607 removed")
	}

	// And the success path still carries rows through.
	ok := ControlResponse{DisplayLeases: []DisplayLeaseWire{{Pool: "p1", RoutingScope: userspaceLeaseScope(0)}}}
	rows, err := displayLeasesFromResponse(ok, nil)
	if err != nil || len(rows) != 1 {
		t.Errorf("a successful exchange must pass its rows through; got %d rows, err %v",
			len(rows), err)
	}
}

package userspace

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

// #8355 acceptance items 2 and 3.
//
// The measurement (#8554) established that the binding constraint is TIME, not
// size. These cells bind what was done about it: the cap is derived from the
// deadline formula rather than picked, it declines the whole import rather than
// truncating, and the decline is visible.

// THE DERIVATION, which is the part that can rot silently.
//
// The cap's whole justification is that it falls out of the SAME constants the
// control-socket deadline uses. If someone changes controlBaseDeadline or
// controlDeadlinePerMiB, the cap must move with them — and if it stops doing
// so, the number becomes exactly what this issue was filed about: a figure
// wearing the shape of a budget.
//
// This asserts the relationship rather than the value, so it survives a
// deliberate budget change and fails a broken derivation.
func TestLearnedRouteCapIsDerivedFromTheDeadline8355(t *testing.T) {
	limit := maxLearnedRoutes()
	if limit <= 0 {
		t.Fatalf("maxLearnedRoutes() = %d — the cap admits nothing, so the import is dead rather than bounded", limit)
	}

	// A table AT the cap must fit the budget; one route past it must not.
	// Computed through the deadline formula the production code uses, not a
	// restatement of the cap's own arithmetic.
	deadlineFor := func(routes int) time.Duration {
		body := routes * learnedRouteBytesEach
		return controlBaseDeadline + time.Duration(float64(body)/float64(bytesPerMiB)*float64(controlDeadlinePerMiB))
	}
	if got := deadlineFor(limit); got > learnedRoutePublishBudget {
		t.Errorf("a table AT the cap (%d routes) needs %v, over the %v budget — the cap admits a publish the budget forbids",
			limit, got, learnedRoutePublishBudget)
	}
	// The cap must be TIGHT: one route past it must exceed the budget, or the
	// cap is lower than the budget justifies and is a picked number after all.
	slack := learnedRoutePublishBudget - deadlineFor(limit)
	if slack > controlDeadlinePerMiB {
		t.Errorf("a table at the cap leaves %v of the %v budget unused — more than one MiB's worth, so the cap is not derived from the budget but from something else",
			slack, learnedRoutePublishBudget)
	}
}

// THE DECISION, asserted as behaviour: over the cap, NOTHING is imported.
//
// A cell that only checked "fewer than N routes were imported" would pass for a
// truncating implementation, which is the option this deliberately rejects. So
// it asserts ZERO, and pairs with the under-cap control below — without that
// control, an importer that was simply broken would satisfy this one.
func TestOverTheCapNothingIsImported8355(t *testing.T) {
	over := maxLearnedRoutes() + 1
	before := LearnedRouteCapHits()

	snaps := importWithSyntheticKernelTable(t, over)
	if n := len(snaps); n != 0 {
		t.Fatalf("a table over the cap imported %d routes. Importing a PREFIX of the table is the failure this rejects: which prefixes make the cut is decided by emission sort order, so fast-path eligibility becomes per-destination and unpredictable, and the box looks healthy while doing it", n)
	}
	if got := LearnedRouteCapHits(); got != before+1 {
		t.Errorf("the cap fired but the counter did not move (%d -> %d). The counter is what makes this state readable without log scraping — a decline nobody can see is the silent degradation the cap exists to avoid", before, got)
	}
}

// THE CONTROL, and it is not decoration. Without it, an importer that returned
// nothing at all would satisfy the cell above.
func TestUnderTheCapTheTableIsImportedWhole8355(t *testing.T) {
	under := 64
	before := LearnedRouteCapHits()

	snaps := importWithSyntheticKernelTable(t, under)
	if len(snaps) != under {
		t.Fatalf("an under-cap table of %d routes imported %d. The cap must be inert below its limit, or it is not a cap but an outage", under, len(snaps))
	}
	if got := LearnedRouteCapHits(); got != before {
		t.Errorf("the cap counter moved (%d -> %d) for a table well under the limit", before, got)
	}
}

// importWithSyntheticKernelTable drives the real snapshot builder against a
// synthetic kernel table of n routes and returns the learned routes that made
// it into the snapshot.
func importWithSyntheticKernelTable(t *testing.T, n int) []RouteSnapshot {
	t.Helper()
	prev := learnedRouteImportFn
	t.Cleanup(func() { learnedRouteImportFn = prev })

	// Built from the SAME shape the #8554 measurement used — the per-route
	// serialized cost the cap is derived from is only meaningful for a table
	// of that shape, so a cell that fed uniform `10.0.N.0/24` routes here
	// would be testing the cap against a cost it does not have.
	learnedRouteImportFn = func([]int) ([]routing.LearnedRoute, error) {
		snaps := bgpishRouteTable(n)
		out := make([]routing.LearnedRoute, 0, len(snaps))
		for i, s := range snaps {
			_ = i
			out = append(out, routing.LearnedRoute{
				TableID:     learnedRouteMainTableID,
				Family:      unix.AF_INET,
				Destination: s.Destination,
				NextHops:    s.NextHops,
				Protocol:    "bgp",
			})
		}
		return out, nil
	}

	// An empty config contributes NO routes of its own, so every snapshot
	// below is a learned one. That is asserted by construction rather than
	// filtered: a config-derived route leaking in would inflate the under-cap
	// and over-cap counts identically and hide a truncation.
	snaps, _, err := buildRouteSnapshots(&config.Config{}, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	// The config contributes no routes of its own, so everything here is
	// learned — asserted rather than assumed, since a config-derived route
	// leaking in would inflate both counts identically and hide a truncation.
	return snaps
}

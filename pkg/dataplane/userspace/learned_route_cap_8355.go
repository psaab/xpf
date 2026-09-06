package userspace

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// #8355 acceptance items 2 and 3: the learned-route cap, what it does when it
// binds, and why it does that rather than the alternative.
//
// THE MEASUREMENT THIS RESTS ON (#8554, and it moved the premise). A learned
// route serializes to ~113 bytes, stable to within 1.5% from one route to
// 500,000 — which is what makes a route COUNT derivable from a byte budget at
// all. 500k routes come to ~56 MiB, comfortably under the 64 MiB
// `MaxControlRequestBytes` ceiling, so the size cap admits ~595,000 routes and
// is NOT what stops this.
//
// What stops it is TIME. `controlRoundtripDeadline` grants
// `controlBaseDeadline + controlDeadlinePerMiB` per mebibyte, so a 56 MiB
// publish holds the control socket for 56 seconds — on a socket CLAUDE.md
// already describes as shared by the 1/s status poll, HA sync, session
// installs, snapshot sync and forwarding sync, where "a new control socket
// request at >1/s will starve session installs during bulk sync". A
// minute-long publish does not starve that socket at the margin; it owns it.
//
// THE CAP IS DERIVED, NOT PICKED. `learnedRoutePublishBudget` is the policy
// input — how long one publish may hold the socket — and the route count falls
// out of it through the SAME constants the deadline uses. A hardcoded route
// count would be a number wearing the shape of a budget, which is the failure
// this issue was filed about; deriving it means that if the deadline formula
// or the per-route cost changes, the cap moves with them instead of silently
// becoming wrong.
const (
	// learnedRoutePublishBudget is the tolerance: how long a single snapshot
	// publish may hold the control socket.
	//
	// 10s. Above that is hard to justify against a 1/s status poll — ten
	// polls' worth of head-of-line blocking — and #7437 makes publishes more
	// frequent, which is the interaction that turns a slow publish into a
	// persistent one. Below it, the cap starts excluding table sizes a real
	// eBGP edge carries.
	learnedRoutePublishBudget = 10 * time.Second

	// learnedRouteBytesEach is the measured per-route serialized cost, from
	// the #8554 measurement. Pinned by
	// TestLearnedRoutePublishSizeAndDeadline8355, so this constant cannot
	// drift away from what the wire actually costs without that cell saying
	// so.
	//
	// It is a FLOOR: the measurement uses one next-hop per route, and ECMP
	// multiplies the next-hop array. A table with ECMP hits the budget at
	// fewer routes than the cap admits, which is the safe direction for a
	// bound to be wrong in.
	learnedRouteBytesEach = 113

	bytesPerMiB = 1 << 20
)

// maxLearnedRoutes is the route count whose publish fits inside
// learnedRoutePublishBudget, derived through the deadline formula.
//
// deadline(bytes) = controlBaseDeadline + bytes/MiB * controlDeadlinePerMiB,
// so the admissible byte count is (budget - base) / perMiB mebibytes, and the
// route count is that divided by the per-route cost.
func maxLearnedRoutes() int {
	spare := learnedRoutePublishBudget - controlBaseDeadline
	if spare <= 0 {
		return 0
	}
	mib := float64(spare) / float64(controlDeadlinePerMiB)
	return int(mib * bytesPerMiB / learnedRouteBytesEach)
}

// learnedRouteCapHits counts publishes refused by the cap. Exposed so the
// condition is visible to something other than the log.
var learnedRouteCapHits atomic.Uint64

// LearnedRouteCapHits reports how many snapshot builds have declined the
// learned-route import because the kernel table exceeded the cap.
func LearnedRouteCapHits() uint64 { return learnedRouteCapHits.Load() }

// learnedRouteCapExceeded decides what happens when the kernel table is larger
// than one publish can carry, and reports whether the import is declined.
//
// THE DECISION: DEGRADE TO NO IMPORT, never a bounded subset.
//
// #9054 CORRECTED THE PREMISE THIS ARGUMENT RESTED ON. What follows used to
// open by asserting that neither option was an outage because the kernel kept
// forwarding, and that had been false since #7480 landed: a NoRoute frame is
// adjudicated against the
// #3110 unzoned egress sentinel, no zone-pair or junos-global permit can match
// it, and the DEFAULT action decides — deny on a Junos-default box. So the
// degradation this function chose was not "slower", it was a silent total
// blackhole of the dynamic FIB, with a log line telling the operator the
// opposite.
//
// The cap itself is unchanged and the reasoning below still holds; what changed
// is that the snapshot now CARRIES the fact (ConfigSnapshot.
// LearnedRouteImportCapped), and the helper restores the slow-path delegation
// for NoRoute while the flag is set. That makes "the kernel still forwards"
// true again rather than merely asserted.
//
// Both options leave some destinations resolving `NoRoute` in the helper FIB
// and taking the slow-path reinject. They differ in PREDICTABILITY, and that is
// the whole argument:
//
//   - NO IMPORT is uniform. Every learned destination behaves the same way,
//     the box is in one describable state, and an operator can reason about it
//     from the one diagnostic below.
//   - A BOUNDED SUBSET is per-destination, and which destinations make the cut
//     is decided by the emission sort order — table id, then family, then
//     destination string. That is arbitrary with respect to anything an
//     operator cares about: two prefixes to the same peer land on opposite
//     sides of the cut because of where they sort. The result is a box where
//     some traffic takes the fast path and some does not, with no rule anyone
//     can state, and it presents as intermittent performance rather than as a
//     limit being hit.
//
// The second is the shape this project keeps being bitten by: a degraded state
// that looks healthy from every surface. A partial FIB reports a plausible
// route count, forwards traffic, and gives no signal at all that it is a
// prefix of the intended table.
//
// LOUD, because the issue is right that silently importing a prefix of the
// table is the failure that reads as healthy. The log names the count, the cap
// and the consequence rather than saying "cap exceeded"; the counter makes it
// readable without log scraping.
func learnedRouteCapExceeded(count int) bool {
	limit := maxLearnedRoutes()
	if limit <= 0 || count <= limit {
		return false
	}
	learnedRouteCapHits.Add(1)
	slog.Warn("learned-route import DECLINED — the kernel table is larger than one control-socket publish can carry",
		"learned_routes", count,
		"cap", limit,
		"publish_budget", learnedRoutePublishBudget.String(),
		"bytes_per_route", learnedRouteBytesEach,
		"consequence", "the helper FIB keeps its config-derived routes only; every LEARNED destination resolves NoRoute. The snapshot carries learned_route_import_capped, so while capped the helper DELEGATES those frames to the kernel instead of adjudicating them (#7480) — traffic forwards through the kernel, not on the AF_XDP fast path. On a helper older than snapshot protocol 10 the snapshot is REFUSED outright rather than applied, because such a helper would drop them (#9054)",
		"security_note", "while capped, a NoRoute frame reaches the kernel FIB without zone-policy adjudication — the #6664 delegation #7480 narrowed. The kernel FIB is still the authority, so a destination with no kernel route is still dropped; but a permitted-by-absence path exists that does not exist under an uncapped import",
		"why_not_partial", "a bounded subset would be selected by emission sort order, making fast-path eligibility per-destination and unpredictable rather than a state an operator can describe",
		"remedy", "reduce the imported table (filter what FRR installs into the kernel), or raise the publish budget if holding the control socket that long is acceptable",
		"observability", "xpf_userspace_binding_slow_path_no_route_packets_total advances for the delegated frames; under the pre-#9054 behaviour it stayed flat while the frames were dropped as policy denials instead",
	)
	return true
}

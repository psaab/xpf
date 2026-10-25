package frr

import "github.com/psaab/xpf/pkg/config"

// carved_seq_reserve_16869.go — #16869 render-belt reserves for carved
// tails pkg/config cannot see. config.RouteMapSequenceCount already
// reserves the explicit-default carved escape (+2). The no-default
// single carved tail and the composed carved fall-off pair depend on
// the per-instance/direction carve, known only here, so the render
// belts add the exact extra where the carved flag is known — keeping
// the config count exact for every non-carved shape.

// carvedSingleExtraSeqs16869 returns tail sequences beyond the one
// fallback RouteMapSequenceCount reserves, for a standalone map:
//   - not carved, or explicit default (count's +2 covers it): 0
//   - carved no-default, permit tail, no next-policy: pair (2) - 1 = 1
//   - carved no-default, permit tail, with next-policy: pair +
//     fallback past it (3) - 1 = 2
//   - carved no-default with a non-permit trailing action renders the
//     plain tail (carved branch requires permit): 0
func carvedSingleExtraSeqs16869(carved bool, ps *config.PolicyStatement) uint64 {
	if !carved || ps == nil || ps.DefaultAction != "" {
		return 0
	}
	// The carved branch also requires trailingAction == "permit",
	// which for a no-default policy is exactly bgpAcceptDefault
	// membership; the belt caller is the export render, where a
	// carved name is by construction a BGP export with the permit
	// tail. A non-permit tail cannot occur for a carved name here.
	if policyHasNextPolicyTerm(ps) {
		return 2
	}
	return 1
}

// carvedComposedReserve16869 returns 1 when the composed renderer
// will emit the carved fall-off pair (carved flag set, permit
// fallback, chain not terminated by an unbypassable explicit
// default), else 0. Mirrors the renderer's own `carved` predicate
// inputs: termination is decided by the same member walk.
func carvedComposedReserve16869(po *config.PolicyOptionsConfig, chain []string, carvedBGPOnly bool, fallbackAction string) uint64 {
	if !carvedBGPOnly || fallbackAction != "permit" || po == nil {
		return 0
	}
	for _, name := range chain {
		ps := po.PolicyStatements[name]
		if ps == nil {
			continue
		}
		if (ps.DefaultAction == "accept" || ps.DefaultAction == "reject") &&
			!policyHasNextPolicyTerm(ps) {
			return 0 // terminated: no fall-off tail at all
		}
	}
	return 1
}

// beltTotal16869 adds a carved reserve to a possibly-saturated count
// without wrapping: RouteMapSequenceCount saturates to math.MaxUint64
// on overflow, and MaxUint64+reserve would wrap to a small number and
// pass the ceiling guard. Saturating addition keeps the sentinel
// over the ceiling so the belt quarantines.
func beltTotal16869(count, reserve uint64) uint64 {
	if count > ^uint64(0)-reserve {
		return ^uint64(0)
	}
	return count + reserve
}

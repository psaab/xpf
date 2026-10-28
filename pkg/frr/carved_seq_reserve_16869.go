package frr

import "github.com/psaab/xpf/pkg/config"

// carved_seq_reserve_16869.go — shared #16869 arithmetic for carved
// render belts. pkg/config owns the reserve calculations so the strict
// compiler gate and these belts cannot disagree about carved tail size.

// carvedSingleExtraSeqs16869 returns tail sequences beyond the one fallback
// RouteMapSequenceCount reserves for a standalone map.
func carvedSingleExtraSeqs16869(carved bool, ps *config.PolicyStatement) uint64 {
	return config.CarvedSingleExtraSequences16869(carved, ps)
}

// beltTotal16869 adds a carved reserve to a possibly-saturated count without
// wrapping the sentinel back into the in-bound range.
func beltTotal16869(count, reserve uint64) uint64 {
	return config.AddCarvedSequenceReserve16869(count, reserve)
}

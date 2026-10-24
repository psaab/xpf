package config

import (
	"math"
	"math/bits"
)

// MaxFilterTermExpansion is the representability bound of the per-term
// counter-slot STRIDE that config.FilterTermExpansionCount returns as a uint32.
// It is NOT a policy/feature limit and it does NOT bound the LIVE dataplane —
// it is the clamp threshold that keeps the uint32 stride from wrapping (#5456).
//
// Reachability (why this is a dead-path bound, not a live one):
//
//   - The LIVE userspace dataplane never materializes a term's cross-product.
//     Its filter lowering (pkg/dataplane/userspace ResolveFilterPrefixListAddrs)
//     stores prefix SETS matched by membership, and its per-term counters are
//     ORDINAL-keyed (FirewallFilterTermCounterKey{Family,FilterName,TermOrdinal}, #16460) —
//     immune to any stride. A term referencing two 1500-entry prefix-lists
//     (2.25M cross-product) is enforced natively at negligible cost.
//   - The cross-product (and this stride) live ONLY on the RETIRED-eBPF path:
//     pkg/dataplane.expandFilterTerm materializes one FilterRule per entry and
//     writes a per-rule eBPF counter map; FilterTermExpansionCount strides that
//     map for `show firewall filter` / the Prometheus collector. That Manager is
//     never instantiated on the live build (NewDataPlane returns
//     ErrEBPFBackendRetired), and the readers skip the map when it is absent
//     (hasMap == false), so the stride is unused on the userspace runtime.
//
// The bug this bound fixes is purely the SILENT uint32 TRUNCATION: the old
// `uint32(nSrc*nDst*nDstPorts*nSrcPorts)` cast wrapped a cross-product past 2^32
// to a small wrong stride, which — on the retired-eBPF counter path only — would
// drift a later term onto a neighbour's counter slots. Clamping the uint32
// stride to this bound (well under 2^32) makes the wrap impossible. The same
// bound caps expandFilterTerm's materialized slice so the #3459 drift-guard
// invariant (count == len(expandFilterTerm)) still holds for an over-bound term,
// and bounds that retired-path allocation.
//
// Because the harm is retired-path-only, an over-bound term is NOT rejected at
// commit — it is COMMITTED (the live dataplane enforces it) with an advisory
// warning (warnFilterTermExpansionOverBound). The value (1<<20 = 1,048,576) is
// far above any term whose per-rule eBPF counters an operator might realistically
// inspect, yet well under 2^32.
const MaxFilterTermExpansion = 1 << 20 // 1,048,576 — uint32 stride clamp threshold

// FilterTermExpansionCount returns the number of dataplane filter rules a
// single firewall-filter term expands into: the cross-product
// (literal source addresses + every source-prefix-list prefix) ×
// (literal destination addresses + every destination-prefix-list prefix) ×
// destination-ports × source-ports, each factor clamped to a minimum of 1
// ("any").
//
// This is the SINGLE SOURCE OF TRUTH for the per-term counter-slot stride used
// by the RETIRED-eBPF filter-counter readers — CLI `show firewall filter`, the
// gRPC text mirror, and the Prometheus xpf_filter_hits_total collector when the
// eBPF filter map is present. A reader sums `count` consecutive slots from the
// term's RuleStart offset and advances by the same `count`, so the next term
// reads its OWN slots rather than a neighbour's (#3459). On the LIVE userspace
// build the eBPF filter map is absent (hasMap == false) and per-term counters
// are ordinal-keyed (#16460), so this stride is unused there. It lives here, in the config
// package, because it is pure config-field arithmetic with no dataplane
// dependency — the readers already import config, and it keeps the
// eBPF-retirement import boundary clean.
//
// It counts ALL prefix-list prefixes regardless of the `except` modifier,
// because the dataplane expansion (pkg/dataplane.expandFilterTerm) emits a
// (negated) rule for an except prefix too — excluding them would undercount
// the stride and drift the running offset. The drift-guard test
// TestFilterTermExpansionCountMatchesExpand pins this == len(expandFilterTerm).
//
// #5456: the product is computed in overflow-checked uint64
// (FilterTermExpansionCount64) and NEVER cast through a wrapping uint32. When
// the exact product exceeds MaxFilterTermExpansion the returned stride CLAMPS to
// that bound rather than wrapping — the clamp is consistent with expandFilterTerm
// (which caps its materialized slice at the same bound), so the drift-guard
// invariant holds for an over-bound term too. The normal (in-bound) case is
// unchanged bit-for-bit: the exact product is returned.
func FilterTermExpansionCount(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint32 {
	c := FilterTermExpansionCount64(term, prefixLists)
	if c > MaxFilterTermExpansion {
		return MaxFilterTermExpansion
	}
	return uint32(c)
}

// FilterTermExpansionCount64 returns the exact src×dst×dstPort×srcPort
// cross-product of a firewall-filter term as a uint64, each factor clamped to a
// minimum of 1 ("any"). It is the overflow-safe core of FilterTermExpansionCount
// and the value warnFilterTermExpansionOverBound compares against
// MaxFilterTermExpansion.
//
// Every multiply is checked (math/bits.Mul64): a product that would overflow
// uint64 saturates to math.MaxUint64 rather than wrapping. Overflow requires a
// pathological config far past MaxFilterTermExpansion, so the saturated value
// still lands the term above the bound — it never under-reports an over-bound
// term back down into the in-bound range.
func FilterTermExpansionCount64(term *FirewallFilterTerm, prefixLists map[string]*PrefixList) uint64 {
	nSrc := uint64(len(term.SourceAddresses))
	for _, ref := range term.SourcePrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nSrc += uint64(len(pl.Prefixes))
		}
	}
	if nSrc == 0 {
		nSrc = 1
	}
	nDst := uint64(len(term.DestAddresses))
	for _, ref := range term.DestPrefixLists {
		if pl, ok := prefixLists[ref.Name]; ok {
			nDst += uint64(len(pl.Prefixes))
		}
	}
	if nDst == 0 {
		nDst = 1
	}
	nDstPorts := uint64(len(term.DestinationPorts))
	if nDstPorts == 0 {
		nDstPorts = 1
	}
	nSrcPorts := uint64(len(term.SourcePorts))
	if nSrcPorts == 0 {
		nSrcPorts = 1
	}
	p := checkedMulU64(nSrc, nDst)
	p = checkedMulU64(p, nDstPorts)
	p = checkedMulU64(p, nSrcPorts)
	return p
}

// checkedMulU64 multiplies two uint64 values, saturating to math.MaxUint64 on
// overflow instead of wrapping.
func checkedMulU64(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return math.MaxUint64
	}
	return lo
}

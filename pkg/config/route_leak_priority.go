package config

// RouteLeakRuleKind identifies the two destination-scoped leak rules that
// share the LPM-ordered priority range.
type RouteLeakRuleKind uint8

const RouteLeakRulePriorityStride = 4

const (
	RouteLeakNextTable RouteLeakRuleKind = iota
	RouteLeakRibGroup
)

// RouteLeakNextTableCarveoutPriority returns the slot-0 priority used by
// configured main-table exceptions to next-table leaks.
func RouteLeakNextTableCarveoutPriority(prefixLength, addressBits int) int {
	return RouteLeakRulePriority(prefixLength, addressBits, RouteLeakNextTable)
}

// RouteLeakNextTableLookupPriority returns the target-table lookup priority.
func RouteLeakNextTableLookupPriority(prefixLength, addressBits int) int {
	return RouteLeakNextTableCarveoutPriority(prefixLength, addressBits) + 1
}

// RouteLeakNextTableShadowPriority returns the fail-closed miss priority.
func RouteLeakNextTableShadowPriority(prefixLength, addressBits int) int {
	return RouteLeakNextTableCarveoutPriority(prefixLength, addressBits) + 2
}

// RouteLeakRulePriority returns the first of four priorities reserved for a
// leak prefix. The slots are [configured main carve-out, target lookup,
// unreachable shadow, rib-group], so assigning priorities as
// (addressBits-prefixLength)*4+kind keeps every longer prefix's complete
// sequence before every shorter prefix. Next-table rows use slot 0; kernel-
// model rib-group rows use slot 3. Callers pass parsed prefix and address bits.
func RouteLeakRulePriority(prefixLength, addressBits int, kind RouteLeakRuleKind) int {
	return NextTableRulePriorityBase + RouteLeakRulePriorityStride*(addressBits-prefixLength) + int(kind)*3
}

// Rib-group return rules (#9819/#11062, #14975) live in the open interval
// (1000, 2000): after the kernel l3mdev lookup (1000) and before the VRF
// miss terminator (2000). That window is only 999 priorities wide, so it
// cannot encode every IPv4+IPv6 prefix length injectively across families.
// Priorities are per-family in the kernel RPDB, so RibGroupReturnRulePriority
// encodes longest-prefix order within one family: the offset from the window
// base is proportional to (addressBits - prefixLength), scaled so the
// longest prefix maps nearest the base and the default route nearest the
// terminator. IPv4 uses scale 28 (32*28=896 < 999) and IPv6 uses scale 7
// (128*7=896 < 999); both families therefore share the same worst-case span
// and never collide with 1000 or 2000. Equal-length prefixes in the same
// family share a priority — the kernel evaluates equal-priority rules in
// insertion order, and two equal-length distinct prefixes cannot both match
// the same destination except for identical prefixes (deduplicated by the
// installer), so LPM is preserved.
const (
	// RibGroupReturnRulePriorityBase is the first usable return-rule
	// priority (exclusive lower bound is the l3mdev rule at 1000).
	RibGroupReturnRulePriorityBase = 1001
	// RibGroupReturnRulePriorityWindow is the number of priorities in
	// (1000, 2000), i.e. [1001, 2000).
	RibGroupReturnRulePriorityWindow = 999
	// LegacyRibGroupReturnRulePriority is the pre-#14975 flat priority.
	// Retained only so clear() and the userspace FIB mirror recognize
	// rules installed by an older binary during an in-place upgrade.
	LegacyRibGroupReturnRulePriority = 1500
)

// RibGroupReturnRulePriority returns the LPM-ordered ip-rule priority for a
// rib-group return rule to a peer prefix of the given length. Longer
// prefixes get lower (earlier) priorities within (1000, 2000).
func RibGroupReturnRulePriority(prefixLength, addressBits int) int {
	if addressBits <= 0 {
		return LegacyRibGroupReturnRulePriority
	}
	if prefixLength < 0 {
		prefixLength = 0
	}
	if prefixLength > addressBits {
		prefixLength = addressBits
	}
	scale := 7
	if addressBits <= 32 {
		scale = 28
	}
	return RibGroupReturnRulePriorityBase + (addressBits-prefixLength)*scale
}

package config

// RouteLeakRuleKind identifies the two destination-scoped leak rules that
// share the LPM-ordered priority range.
type RouteLeakRuleKind uint8

const (
	RouteLeakNextTable RouteLeakRuleKind = iota
	RouteLeakRibGroup
)

// RouteLeakRulePriority returns a priority that orders longer prefixes before
// shorter prefixes across next-table and rib-group rules. Each additional
// prefix bit reserves two priorities: next-table precedes rib-group only when
// the prefixes have equal length. Callers pass the parsed prefix and address
// bit lengths.
func RouteLeakRulePriority(prefixLength, addressBits int, kind RouteLeakRuleKind) int {
	return NextTableRulePriorityBase + (addressBits-prefixLength)*2 + int(kind)
}

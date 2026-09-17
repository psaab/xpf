package userspace

type RouteSnapshot struct {
	Table       string   `json:"table"`
	Family      string   `json:"family"`
	Destination string   `json:"destination"`
	NextHops    []string `json:"next_hops,omitempty"`
	Discard     bool     `json:"discard"`
	NextTable   string   `json:"next_table,omitempty"`
	// RulePriority is the kernel ip-rule priority of a NextTable leak (#9955).
	// The kernel resolves inter-VRF leaks in TWO stages: priority-ordered
	// rules with fall-through on a target-table miss, then per-table
	// longest-prefix-match. The helper used to model that as one sorted list
	// per table because this key never crossed the routes.go boundary, so
	// overlapping leaks resolved by prefix length while the kernel resolved
	// by rule priority (5 of 10 generated shapes diverged), a leak lost to a
	// more-specific ordinary route it precedes in the kernel, and a leak
	// into a table that misses blackholed instead of falling through. Every
	// non-empty NextTable is a priority-ordered pre-LPM leak, never an
	// ordinary table route; both producers below carry the ACTUAL kernel
	// priority (config-mirror: NextTableRulePriorityBase + cumulative
	// ingress slots in applier window order; live mirror: rule.Priority
	// verbatim). Ordinary routes carry 0. Additive on the wire: omitempty
	// suppresses the byte for 0, and the Rust side defaults an absent key to 0
	// — but an old helper that ignores the key keeps the prefix-length order
	// that IS the defect, so the field rides ProtocolVersion 24 on top of the
	// v23 DHCPv6 relay contract and the exact-equality gate refuses a
	// mismatched pairing.
	RulePriority uint32 `json:"rule_priority,omitempty"`
	// Preference is the Junos route preference (administrative distance;
	// lower = more preferred, default 5). The Rust FIB tie-breaks two
	// same-prefix routes in a table by preference BEFORE insertion order
	// (#2390); without it, two competing same-prefix statics selected by
	// insertion order, ignoring operator intent. Additive: an old Rust
	// helper ignores it (insertion-order tie-break, the pre-#2390 behavior)
	// and an old Go binary omits it (Rust sees 0, the most-preferred value,
	// which for the common single-route-per-prefix case is a no-op). 0 is a
	// legitimate value (it deserializes back to 0 under serde default), so
	// omitempty only suppresses the wire byte for an explicit preference 0.
	Preference int `json:"preference,omitempty"`
}

type NeighborSnapshot struct {
	Interface string `json:"interface,omitempty"`
	Ifindex   int    `json:"ifindex,omitempty"`
	Family    string `json:"family"`
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	State     string `json:"state,omitempty"`
	Router    bool   `json:"router,omitempty"`
	LinkLocal bool   `json:"link_local,omitempty"`
}

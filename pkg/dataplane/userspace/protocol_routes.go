package userspace

type RouteSnapshot struct {
	Table       string   `json:"table"`
	Family      string   `json:"family"`
	Destination string   `json:"destination"`
	NextHops    []string `json:"next_hops,omitempty"`
	// NextHopWeights parallels NextHops when any weight differs from default 1;
	NextHopWeights []uint32 `json:"next_hop_weights,omitempty"`
	Discard        bool     `json:"discard"`
	Reject         bool     `json:"reject,omitempty"`
	// ClusterTerminal marks a learned cluster-mode Null0 default
	// (#15742). Only the Rust demotion gate reads it: a terminal row
	// carrying it may fabric-redirect when the would-be egress RG is
	// peer-owned. Operator discard/reject rows never carry it and stay
	// local drops. Fenced by the v57 bump.
	ClusterTerminal bool   `json:"cluster_terminal,omitempty"`
	NextTable       string `json:"next_table,omitempty"`
	// RulePriority is the kernel ip-rule priority of a NextTable leak (#9955).
	// Kernel-model rows use a two-stage lookup: priority-ordered rules with
	// fall-through on target-table miss, followed by per-table LPM. Config
	// next-table statics instead carry their target-lookup priority while
	// participating in source-table Junos LPM. Live rows carry their kernel
	// priority verbatim; ordinary routes carry 0. Additive on the wire:
	// omitempty suppresses the byte for 0, and the Rust side defaults an absent
	// key to 0. The shared protocol is version-fenced against helpers that do
	// not understand the priority semantics.
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
	// MTU is the selected route's route-wide L3 MTU (RTAX_MTU). Zero means
	// absent/unknown and imposes no extra constraint. An old helper would
	// ignore it and forward oversized DF packets, so snapshot v38 fences it.
	MTU int `json:"mtu,omitempty"`
	// NextTableRoute marks a CONFIG-AUTHORED next-table static (#16614):
	// in Junos it is a route P in the source table whose next hop hands
	// the lookup to the target table, so it competes in the source
	// table's LPM by prefix length and preference, and a target-table
	// miss is terminal (the target forwarding table ends in a default
	// reject) instead of falling through to a less-specific source-table
	// route. A live target-lookup row replacing this config mirror keeps
	// this marker; unrelated kernel-model leak and return rows leave it false.
	// Fenced by the v73 bump: a v72 helper ignores the field and keeps the
	// fall-through defect.
	NextTableRoute bool `json:"next_table_route,omitempty"`
	// metricTierOrder is an in-process stable-sort hint for config-derived
	// same-preference QNH rows. It is intentionally unexported and never goes
	// on the snapshot wire; row order is the contract consumed by the Rust FIB.
	metricTierOrder int
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

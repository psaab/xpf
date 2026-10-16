package userspace

type IpsecPMechTunnelRowSnapshot struct {
	STN                 string                         `json:"stn"`
	IfID                uint32                         `json:"if_id"`
	LogicalIfindex      int32                          `json:"logical_ifindex"`
	ExplicitSelectors   []IpsecTrafficSelectorSnapshot `json:"explicit_selectors,omitempty"`
	EffectivePrefixes   []string                       `json:"effective_prefixes,omitempty"`
	IngressPrefixes     []string                       `json:"ingress_prefixes,omitempty"`
	DestinationPrefixes []string                       `json:"destination_prefixes,omitempty"`
	InventoryGeneration uint64                         `json:"inventory_generation,omitempty"`
	FIBGeneration       uint32                         `json:"fib_generation,omitempty"`
	SourceKind          string                         `json:"source_kind,omitempty"`
	SelectorProvenance  string                         `json:"selector_provenance,omitempty"`
	InventoryComplete   bool                           `json:"inventory_complete,omitempty"`
	InventoryValid      bool                           `json:"inventory_valid,omitempty"`
	InventoryReason     string                         `json:"inventory_reason,omitempty"`
}

type IpsecPMechInventorySnapshot struct {
	PolicyIdentity string                        `json:"policy_identity,omitempty"`
	Generation     uint64                        `json:"generation,omitempty"`
	FIBGeneration  uint32                        `json:"fib_generation,omitempty"`
	Complete       bool                          `json:"complete,omitempty"`
	MainRoutes     []IpsecMainRouteSnapshot      `json:"main_routes,omitempty"`
	TunnelRows     []IpsecPMechTunnelRowSnapshot `json:"tunnel_rows,omitempty"`
}

// IpsecMainRouteSnapshot is one tunnel-relevant main-table route with every
// resolved nexthop leg: a route with a leg on a tunnel's logical ifindex, a
// route overlapping a remote traffic selector, or an invalid route kept for
// audit because it withholds authority. Other main-table routes are validated
// when the inventory is built but are not carried.
type IpsecMainRouteSnapshot struct {
	Domain      uint32                          `json:"domain"`
	Table       uint32                          `json:"table"`
	Family      string                          `json:"family"`
	Destination string                          `json:"destination"`
	Protocol    uint8                           `json:"protocol"`
	Disposition uint8                           `json:"disposition"`
	NextHops    []IpsecMainRouteNextHopSnapshot `json:"next_hops,omitempty"`
}

type IpsecMainRouteNextHopSnapshot struct {
	Ifindex uint32 `json:"ifindex"`
	Weight  uint32 `json:"weight"`
}

// IpsecBindlessSelectorSnapshot is one complete pair of IPsec traffic-selector
// sides for a policy-based VPN with no bind-interface. Empty sides are not
// published: they resolve to dynamic endpoints rather than a shape the helper
// can classify precisely.
type IpsecBindlessSelectorSnapshot struct {
	LocalTS  string `json:"local_ts"`
	RemoteTS string `json:"remote_ts"`
}

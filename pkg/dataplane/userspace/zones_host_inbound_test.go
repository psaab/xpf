// #3070: buildZoneSnapshots must carry each zone's host-inbound-traffic
// admission set onto the wire so the dataplane can enforce it for host-bound
// (local-delivery) traffic. Before #3070 only Name+ID were emitted and the
// host-inbound set was silently dropped at this boundary (the security gap).
package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestBuildZoneSnapshotsCarriesHostInbound(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name: "wan",
			HostInboundTraffic: &config.HostInboundTraffic{
				SystemServices: []string{"Ping", " GRE "}, // mixed case/space → normalized
				Protocols:      []string{"router-discovery"},
			},
		},
		"lan": {
			Name: "lan",
			HostInboundTraffic: &config.HostInboundTraffic{
				SystemServices: []string{"ssh", "ping"},
			},
		},
		// trust: no host-inbound-traffic stanza → #3405 default-deny (configured
		// with empty token sets).
		"trust": {Name: "trust"},
	}

	snaps := buildZoneSnapshots(cfg)
	byName := make(map[string]ZoneSnapshot, len(snaps))
	for _, z := range snaps {
		byName[z.Name] = z
	}

	wan, ok := byName["wan"]
	if !ok {
		t.Fatal("missing wan zone snapshot")
	}
	if !wan.HostInboundConfigured {
		t.Error("wan: HostInboundConfigured = false, want true")
	}
	// Tokens are lower-cased + trimmed.
	if got, want := wan.HostInboundSystemServices, []string{"ping", "gre"}; !eqStr(got, want) {
		t.Errorf("wan system-services = %v, want %v", got, want)
	}
	if got, want := wan.HostInboundProtocols, []string{"router-discovery"}; !eqStr(got, want) {
		t.Errorf("wan protocols = %v, want %v", got, want)
	}

	lan := byName["lan"]
	if !lan.HostInboundConfigured {
		t.Error("lan: HostInboundConfigured = false, want true")
	}
	if got, want := lan.HostInboundSystemServices, []string{"ssh", "ping"}; !eqStr(got, want) {
		t.Errorf("lan system-services = %v, want %v", got, want)
	}
	if len(lan.HostInboundProtocols) != 0 {
		t.Errorf("lan protocols = %v, want empty", lan.HostInboundProtocols)
	}

	// #3405: trust declared NO stanza but is still HostInboundConfigured=true
	// (Junos default-deny parity). Its token sets are EMPTY, so the Rust
	// classifier inserts an empty ZoneHostInbound -> default-deny, identical to an
	// empty `host-inbound-traffic { }` stanza. Before #3405 this stayed
	// unconfigured (admit-all) — the security gap the issue describes.
	// Fail-on-revert: restore the `HostInboundTraffic != nil` gate in
	// buildZoneSnapshots and HostInboundConfigured flips back to false here.
	trust := byName["trust"]
	if !trust.HostInboundConfigured {
		t.Error("trust: HostInboundConfigured = false, want true (#3405 no-stanza default-deny)")
	}
	if trust.HostInboundSystemServices != nil || trust.HostInboundProtocols != nil {
		t.Errorf("trust: expected nil/empty host-inbound slices (no stanza), got services=%v protocols=%v",
			trust.HostInboundSystemServices, trust.HostInboundProtocols)
	}
}

// TestBuildZoneSnapshotsNilZoneDefaultDenies is the #3705 RED-on-revert guard on
// the Go builder. A tolerant / HA-loaded config can carry a NIL zone value
// (Security.Zones[name] == nil, the #3493 shape). buildZoneSnapshots must STILL
// emit that zone with HostInboundConfigured=true and EMPTY token sets so the Rust
// classifier default-DENIES it (inserts an empty ZoneHostInbound) — identical to
// a no-stanza zone (#3405). Before #3705 a nil zone shipped
// HostInboundConfigured=false, leaving the KNOWN configured zone absent from the
// dataplane's host-inbound table -> `None => true` admit-all -> management-plane
// fail-open.
//
// Fail-on-revert: restore the `if zone != nil` gate on `zs.HostInboundConfigured`
// in buildZoneSnapshots and the nil zone flips back to HostInboundConfigured=false
// (admit-all on the wire), turning the assertion below RED.
func TestBuildZoneSnapshotsNilZoneDefaultDenies(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// A configured zone name whose value is NIL — the tolerant / HA-load shape
		// (#3493). The key exists (the zone is "known"), but the *ZoneConfig is nil.
		"trust": nil,
		// A normal configured zone with a stanza, to prove nil handling does not
		// disturb legit admit sets.
		"wan": {
			Name:               "wan",
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}

	snaps := buildZoneSnapshots(cfg)
	byName := make(map[string]ZoneSnapshot, len(snaps))
	for _, z := range snaps {
		byName[z.Name] = z
	}

	// The nil zone is still emitted (known + addressable) but as a default-deny
	// zone: HostInboundConfigured=true with EMPTY token sets.
	trust, ok := byName["trust"]
	if !ok {
		t.Fatal("nil zone must still emit a snapshot (known zone must be addressable)")
	}
	if !trust.HostInboundConfigured {
		t.Error("nil zone: HostInboundConfigured = false, want true (#3705 fail-closed default-deny)")
	}
	if len(trust.HostInboundSystemServices) != 0 || len(trust.HostInboundProtocols) != 0 {
		t.Errorf("nil zone must carry empty token sets (default-deny), got services=%v protocols=%v",
			trust.HostInboundSystemServices, trust.HostInboundProtocols)
	}
	// The nil zone still gets a valid, addressable id (name-hash, #3704) so
	// policy/host-inbound resolution can reference it.
	if trust.ID == 0 {
		t.Error("nil zone must carry a valid (non-zero) zone id")
	}

	// The non-nil zone is unaffected — legit admit set preserved.
	wan, ok := byName["wan"]
	if !ok {
		t.Fatal("wan zone snapshot missing")
	}
	if !wan.HostInboundConfigured {
		t.Error("wan: HostInboundConfigured = false, want true")
	}
	if got, want := wan.HostInboundSystemServices, []string{"ssh"}; !eqStr(got, want) {
		t.Errorf("wan system-services = %v, want %v", got, want)
	}
}

// TestBuildZoneHostInboundViews verifies the per-zone enforcement view used by
// the kernel-nftables primary path (#3070): every configured zone resolves its
// firewall-local host addresses (including no-stanza zones, which default-deny
// per #3405), and configured management/cluster-control lifeline interfaces are
// excluded from the address sets.
func TestBuildZoneHostInboundViews(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {Number: 50, VlanID: 50, Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"}},
		}},
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.99.0.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}, Protocols: []string{"ospf"}},
		},
		"lan":     {Name: "lan", Interfaces: []string{"reth1.0"}}, // no stanza
		"control": {Name: "control", Interfaces: []string{"em0"}, HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}}},
	}

	views := BuildZoneHostInboundViews(cfg)
	byZone := make(map[string]ZoneHostInboundView, len(views))
	for _, v := range views {
		byZone[v.Zone] = v
	}

	// #3405: lan declared NO stanza but is now enforced (Junos default-deny) — it
	// gets a view scoped to its firewall-local address with an EMPTY match set, so
	// the daemon emits a catch-all DROP (deny every host-bound service/protocol).
	// Before #3405 lan was omitted entirely (admit-all). Fail-on-revert: restore
	// the stanza-required `configured` predicate and this view disappears.
	lanView, ok := byZone["lan"]
	if !ok {
		t.Fatal("lan (no host-inbound stanza) must now have a default-deny view (#3405)")
	}
	if !eqStr(lanView.V4Addrs, []string{"10.0.61.1"}) {
		t.Errorf("lan v4 addrs = %v, want [10.0.61.1]", lanView.V4Addrs)
	}
	if len(lanView.SystemServices) != 0 || len(lanView.Protocols) != 0 {
		t.Errorf("lan (no stanza) must carry an empty match set (default-deny), got services=%v protocols=%v",
			lanView.SystemServices, lanView.Protocols)
	}
	wan, ok := byZone["wan"]
	if !ok {
		t.Fatal("wan view missing")
	}
	if !eqStr(wan.V4Addrs, []string{"172.16.50.8"}) {
		t.Errorf("wan v4 addrs = %v, want [172.16.50.8]", wan.V4Addrs)
	}
	if !eqStr(wan.V6Addrs, []string{"2001:db8:50::8"}) {
		t.Errorf("wan v6 addrs = %v, want [2001:db8:50::8]", wan.V6Addrs)
	}
	if !eqStr(wan.SystemServices, []string{"ssh"}) || !eqStr(wan.Protocols, []string{"ospf"}) {
		t.Errorf("wan tokens services=%v protocols=%v", wan.SystemServices, wan.Protocols)
	}

	// control declares a stanza but its only interface (em0) is a lifeline →
	// the view exists but carries no address (so the daemon emits no deny).
	control, ok := byZone["control"]
	if !ok {
		t.Fatal("control view missing")
	}
	if len(control.V4Addrs) != 0 || len(control.V6Addrs) != 0 {
		t.Errorf("control/em0 lifeline must contribute no addresses, got v4=%v v6=%v",
			control.V4Addrs, control.V6Addrs)
	}
}

// TestNoStanzaZoneDefaultDeniesBothSurfaces is the #3405 RED-on-revert guard. A
// security zone with interfaces but NO `host-inbound-traffic` stanza must
// default-DENY host-bound traffic (Junos/vSRX parity), and the kernel-nft
// primary path and the Rust AF_XDP secondary path must AGREE. It pins both
// surfaces against the single config (a no-stanza zone "edge" with a
// firewall-local address):
//
//   - ZoneSnapshot (Rust wire): HostInboundConfigured=true with EMPTY token
//     sets. The Rust classifier inserts the zone into zone_host_inbound with an
//     empty ZoneHostInbound -> admits() denies every service -> default-deny.
//   - ZoneHostInboundView (kernel nft): a view scoped to the zone's address with
//     an EMPTY match set -> emitHostInboundZone emits ONLY a catch-all DROP.
//
// Fail-on-revert: restore the pre-#3405 "stanza-required" gates (in
// buildZoneSnapshots and BuildZoneHostInboundViews.configured) and the no-stanza
// zone reverts to admit-all — HostInboundConfigured flips to false AND the view
// disappears, turning every assertion below RED.
func TestNoStanzaZoneDefaultDeniesBothSurfaces(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.1/24", "2001:db8:51::1/64"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		// "edge" has an interface + address but NO host-inbound-traffic stanza.
		"edge": {Name: "edge", Interfaces: []string{"ge-0-0-1.0"}},
	}

	// Rust wire surface.
	var edge *ZoneSnapshot
	snaps := buildZoneSnapshots(cfg)
	for i := range snaps {
		if snaps[i].Name == "edge" {
			edge = &snaps[i]
		}
	}
	if edge == nil {
		t.Fatal("edge zone snapshot missing")
	}
	if !edge.HostInboundConfigured {
		t.Error("no-stanza zone must be HostInboundConfigured=true (#3405 default-deny on the Rust wire)")
	}
	if len(edge.HostInboundSystemServices) != 0 || len(edge.HostInboundProtocols) != 0 {
		t.Errorf("no-stanza zone must carry empty token sets, got services=%v protocols=%v",
			edge.HostInboundSystemServices, edge.HostInboundProtocols)
	}

	// Kernel-nft surface.
	views := BuildZoneHostInboundViews(cfg)
	var edgeView *ZoneHostInboundView
	for i := range views {
		if views[i].Zone == "edge" {
			edgeView = &views[i]
		}
	}
	if edgeView == nil {
		t.Fatal("no-stanza zone must have a kernel-nft view (#3405 default-deny)")
	}
	if !eqStr(edgeView.V4Addrs, []string{"198.51.100.1"}) {
		t.Errorf("edge v4 addrs = %v, want [198.51.100.1]", edgeView.V4Addrs)
	}
	if !eqStr(edgeView.V6Addrs, []string{"2001:db8:51::1"}) {
		t.Errorf("edge v6 addrs = %v, want [2001:db8:51::1]", edgeView.V6Addrs)
	}
	if len(edgeView.SystemServices) != 0 || len(edgeView.Protocols) != 0 {
		t.Errorf("no-stanza zone view must carry an empty match set (catch-all drop only), "+
			"got services=%v protocols=%v", edgeView.SystemServices, edgeView.Protocols)
	}
}

// TestBuildZoneHostInboundViewsIncludesVRRPVIP verifies #3172: a zone whose
// RETH unit carries VRRP virtual addresses (VIPs) gets those VIPs into its
// host-inbound destination address set, so the kernel deny is scoped to the VIP
// on BOTH cluster nodes — including the backup, where the VIP is not yet live on
// the kernel interface (and thus absent from the live address snapshot). A
// standalone zone with no VIP is unchanged, and a VIP configured on a lifeline
// interface (em0) is still excluded.
func TestBuildZoneHostInboundViewsIncludesVRRPVIP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{ControlInterface: "em0"}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", Units: map[int]*config.InterfaceUnit{
			50: {
				Number:    50,
				VlanID:    50,
				Addresses: []string{"172.16.50.8/24", "2001:db8:50::8/64"},
				VRRPGroups: map[string]*config.VRRPGroup{
					"172.16.50.8/24":    {ID: 50, VirtualAddresses: []string{"172.16.50.1"}},
					"2001:db8:50::8/64": {ID: 51, VirtualAddresses: []string{"2001:db8:50::1"}},
				},
			},
		}},
		// standalone zone interface — no VRRP, must be unchanged.
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
		// configured lifeline (cluster control plane) with a VRRP group — its VIP
		// must NOT be scoped (denying on em0 could break HA).
		"em0": {Name: "em0", Units: map[int]*config.InterfaceUnit{
			0: {
				Number:    0,
				Addresses: []string{"10.99.0.1/24"},
				VRRPGroups: map[string]*config.VRRPGroup{
					"10.99.0.1/24": {ID: 99, VirtualAddresses: []string{"10.99.0.254"}},
				},
			},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {
			Name:               "wan",
			Interfaces:         []string{"reth0.50"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"lan": {
			Name:               "lan",
			Interfaces:         []string{"reth1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
		"control": {
			Name:               "control",
			Interfaces:         []string{"em0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"all"}},
		},
	}

	views := BuildZoneHostInboundViews(cfg)
	byZone := make(map[string]ZoneHostInboundView, len(views))
	for _, v := range views {
		byZone[v.Zone] = v
	}

	wan, ok := byZone["wan"]
	if !ok {
		t.Fatal("wan view missing")
	}
	// Static interface address first, then the VRRP VIP (#3172). Without the
	// VIP-inclusion the VIP entries are absent and the deny is unscoped for the
	// VIP (fail-open) — this assertion is the fail-on-revert guard.
	if !eqStr(wan.V4Addrs, []string{"172.16.50.8", "172.16.50.1"}) {
		t.Errorf("wan v4 addrs = %v, want [172.16.50.8 172.16.50.1] (static + VIP)", wan.V4Addrs)
	}
	if !eqStr(wan.V6Addrs, []string{"2001:db8:50::8", "2001:db8:50::1"}) {
		t.Errorf("wan v6 addrs = %v, want [2001:db8:50::8 2001:db8:50::1] (static + VIP)", wan.V6Addrs)
	}

	// lan has no VRRP group → byte-identical to pre-#3172 (static only).
	lan, ok := byZone["lan"]
	if !ok {
		t.Fatal("lan view missing")
	}
	if !eqStr(lan.V4Addrs, []string{"10.0.61.1"}) {
		t.Errorf("lan v4 addrs = %v, want [10.0.61.1] (standalone, unchanged)", lan.V4Addrs)
	}
	if len(lan.V6Addrs) != 0 {
		t.Errorf("lan v6 addrs = %v, want empty", lan.V6Addrs)
	}

	// control/em0 is a lifeline → neither its static address nor its VIP is
	// scoped (no deny, can never break HA).
	control, ok := byZone["control"]
	if !ok {
		t.Fatal("control view missing")
	}
	if len(control.V4Addrs) != 0 || len(control.V6Addrs) != 0 {
		t.Errorf("control/em0 lifeline must contribute no addresses (incl. VIP), got v4=%v v6=%v",
			control.V4Addrs, control.V6Addrs)
	}
}

// TestBuildZoneHostInboundViewsScopesKernelLearnedAddr is the #3224
// regression guard, and it deliberately drives the REAL production address
// source — BuildZoneHostInboundViews -> buildInterfaceSnapshots ->
// buildLinkSnapshot -> buildInterfaceAddressSnapshots -> netlink.AddrList(
// FAMILY_ALL) — with NO injected/fake provider.
//
// #3224 was filed on the premise that a DHCP/DHCPv6-learned firewall-local
// address (one that exists only on the kernel netdev, never in the static
// config) would fall out of the host-inbound deny scope and FAIL OPEN to
// `policy accept`. That premise does NOT reproduce: buildInterfaceAddressSnapshots
// enumerates EVERY address via netlink.AddrList(FAMILY_ALL) with no
// scope/flag/dynamic filtering, so a kernel-learned address is captured exactly
// like a static one. This test proves that property on the real path.
//
// We model "a kernel address that is absent from the static config" with the
// loopback interface (always present, no root required): the config maps a zone
// interface onto `lo` and declares NO static address, so 127.0.0.1 / ::1 reach
// the view ONLY through the live kernel snapshot — the identical mechanism that
// captures a DHCP/DHCPv6 lease. If a future refactor ever filters dynamic /
// non-config addresses out of the snapshot path (the gap #3224 feared), this
// test goes RED.
func TestBuildZoneHostInboundViewsScopesKernelLearnedAddr(t *testing.T) {
	// Sanity: the loopback must carry its kernel address (it is not in any config
	// here). If a sandbox somehow lacks it, skip rather than false-fail.
	loSnap := liveZoneHostInboundAddrsForIface(t, "lo")
	if !contains(loSnap, "127.0.0.1") {
		t.Skipf("loopback has no 127.0.0.1 (got %v) — cannot exercise real netlink path", loSnap)
	}

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		// Zone interface mapped onto the real `lo` netdev with NO static address:
		// its only addresses (127.0.0.1/8, ::1/128) come from the live kernel
		// snapshot — exactly how a DHCP/DHCPv6 lease appears (config-absent,
		// kernel-present).
		"lo": {Name: "lo", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
		}},
		// Static-only control: unchanged regardless of the live snapshot.
		"reth1": {Name: "reth1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.61.1/24"}},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {Name: "untrust", Interfaces: []string{"lo.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
		"lan": {Name: "lan", Interfaces: []string{"reth1.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}}},
	}

	// REAL production entry point — no injected dynamic source.
	views := BuildZoneHostInboundViews(cfg)
	byZone := make(map[string]ZoneHostInboundView, len(views))
	for _, v := range views {
		byZone[v.Zone] = v
	}

	// untrust: the kernel-learned (config-absent) v4 address IS scoped. This is
	// the fail-on-revert guard for the #3224 premise — the production snapshot
	// path captures it without any static config address.
	untrust, ok := byZone["untrust"]
	if !ok {
		t.Fatal("untrust view missing")
	}
	if !contains(untrust.V4Addrs, "127.0.0.1") {
		t.Errorf("untrust v4 addrs = %v, want to contain 127.0.0.1 "+
			"(kernel-learned, config-absent address must be scoped — #3224)", untrust.V4Addrs)
	}
	// IPv6 loopback (::1) is standard on Linux; assert it too when present so the
	// guard also covers the v6 dynamic path (DHCPv6).
	if contains(loSnap, "::1") && !contains(untrust.V6Addrs, "::1") {
		t.Errorf("untrust v6 addrs = %v, want to contain ::1 "+
			"(kernel-learned v6 address must be scoped — #3224)", untrust.V6Addrs)
	}

	// lan: static-only, untouched by the live snapshot.
	lan, ok := byZone["lan"]
	if !ok {
		t.Fatal("lan view missing")
	}
	if !eqStr(lan.V4Addrs, []string{"10.0.61.1"}) {
		t.Errorf("lan v4 addrs = %v, want [10.0.61.1] (static only, unchanged)", lan.V4Addrs)
	}
}

// liveZoneHostInboundAddrsForIface returns the bare host IPs the real snapshot
// path resolves for a single live netdev, used only to gate the loopback test on
// the address actually being present (no fake injection).
func liveZoneHostInboundAddrsForIface(t *testing.T, linuxName string) []string {
	t.Helper()
	_, _, _, addrs := buildLinkSnapshot(linuxName)
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if host := hostIPFromCIDR(a.Address); host != "" {
			out = append(out, host)
		}
	}
	return out
}

func TestHostInboundLifelineInterface(t *testing.T) {
	// Only fxp0 is unconditional; bare em0/fab* names are ordinary interfaces.
	def := hostInboundLifelineSet(nil)
	for _, name := range []string{"fxp0", "fxp0.0"} {
		if !hostInboundLifelineInterface(name, def) {
			t.Errorf("%q should be a lifeline interface", name)
		}
	}
	for _, name := range []string{"em0", "em0.0", "fab0", "fab1", "fab1.0",
		"reth0.50", "reth1", "ge-0/0/0.0", "gr-0/0/0.0", "fxp1", "fxp1.0"} {
		if hostInboundLifelineInterface(name, def) {
			t.Errorf("%q must NOT be a lifeline interface without a configured role", name)
		}
	}
}

// TestHostInboundLifelineFromControlInterface is the #3277 fail-on-revert proof
// at the predicate level: configured control/fabric links remain lifelines,
// while bare em0/fab* spellings do not establish a role.
func TestHostInboundLifelineFromControlInterface(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{
		ControlInterface: "fxp1",
		FabricInterface:  "xe-0/0/9",
	}
	set := hostInboundLifelineSet(cfg)
	for _, name := range []string{"fxp1", "fxp1.0", "xe-0/0/9", "xe-0/0/9.0", "fxp0"} {
		if !hostInboundLifelineInterface(name, set) {
			t.Errorf("%q should be a lifeline with configured roles", name)
		}
	}
	for _, name := range []string{"em0", "fab0"} {
		if hostInboundLifelineInterface(name, set) {
			t.Errorf("%q must not be a lifeline without a configured role", name)
		}
	}
	if hostInboundLifelineInterface("reth0.50", set) {
		t.Errorf("reth0.50 must NOT be a lifeline")
	}
}

func eqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

package dataplane

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// that NAMES a declared interface resolves against that stanza (configName =
// the declared base, unit from the REMAINDER) instead of first-dot-cutting
// onto an undeclared first segment with vlanID 0.
func TestResolveInterfaceRefDeclaredDotted9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0:  {Number: 0},
			10: {Number: 10, VlanID: 100},
		}},
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"p.0":      {Name: "p.0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"p.0.1":    {Name: "p.0.1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"irb.5":    {Name: "irb.5", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"st0.1":    {Name: "st0.1", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*config.InterfaceUnit{
			1: {Number: 1, Tunnel: &config.TunnelConfig{Name: "gr-0-0-0u1"}},
		}},
	}}}
	cases := []struct {
		name               string
		ref                string
		wantPhys, wantCfg  string
		wantUnit, wantVlan int
	}{
		{"dotted bare is its own device", "ge-0/0/5.0", "ge-0-0-5.0", "ge-0/0/5.0", 0, 0},
		{"dotted unit resolves stanza vlan", "ge-0/0/5.0.10", "ge-0-0-5.0", "ge-0/0/5.0", 10, 100},
		{"dotted unit zero", "ge-0/0/5.0.0", "ge-0-0-5.0", "ge-0/0/5.0", 0, 0},
		{"both-declared exact is bare", "p.0.1", "p.0.1", "p.0.1", 0, 0},
		{"both-declared sibling unit", "p.0.2", "p.0", "p.0", 2, 0},
		{"padded unit", "ge-0/0/0.01", "ge-0-0-0", "ge-0/0/0", 1, 0},
		{"malformed unit keeps ignored-error zero", "ge-0/0/0.xx", "ge-0-0-0", "ge-0/0/0", 0, 0},
		{"trailing dot is bare-shaped", "ge-0/0/0.", "ge-0-0-0", "ge-0/0/0", 0, 0},
		{"declared irb short-circuits bridge arm", "irb.5", "irb.5", "irb.5", 0, 0},
		{"declared st short-circuits tunnel arms", "st0.1", "st0.1", "st0.1", 0, 0},
		{"unbound st keeps verbatim", "st0.5", "st0.5", "st0", 5, 0},
		{"per-unit tunnel names its device", "gr-0/0/0.1", "gr-0-0-0u1", "gr-0/0/0", 1, 0},
		{"undeclared ref", "unknown.5", "unknown", "unknown", 5, 0},
		{"undeclared bare", "unknown", "unknown", "unknown", 0, 0},
		{"ordinary undotted unit", "ge-0/0/0.0", "ge-0-0-0", "ge-0/0/0", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			phys, cfgName, unit, vlan := resolveInterfaceRef(tc.ref, cfg)
			if phys != tc.wantPhys || cfgName != tc.wantCfg || unit != tc.wantUnit || vlan != tc.wantVlan {
				t.Errorf("resolveInterfaceRef(%q) = (%q,%q,%d,%d), want (%q,%q,%d,%d)",
					tc.ref, phys, cfgName, unit, vlan,
					tc.wantPhys, tc.wantCfg, tc.wantUnit, tc.wantVlan)
			}
		})
	}
}

// shimFakeDP9821 records the dataplane writes mapZoneInterface and
// applyTunnelHostInbound perform, so the fake-link cells assert programming
// without a host.
type shimFakeDP9821 struct {
	DataPlane
	zones []struct {
		ifindex int
		vlan    uint16
		zid     uint16
	}
	vlanInfo []struct {
		sub, parent int
		vlan        uint16
	}
	txPorts []int
	zoneCfg map[uint16]ZoneConfig
}

func (f *shimFakeDP9821) SetZone(ifindex int, vlanID uint16, zoneID uint16, _ uint32, _ uint8, _ uint8, _ uint32) error {
	f.zones = append(f.zones, struct {
		ifindex int
		vlan    uint16
		zid     uint16
	}{ifindex, vlanID, zoneID})
	return nil
}

func (f *shimFakeDP9821) SetVlanIfaceInfo(subIfindex, parentIfindex int, vlanID uint16) error {
	f.vlanInfo = append(f.vlanInfo, struct {
		sub, parent int
		vlan        uint16
	}{subIfindex, parentIfindex, vlanID})
	return nil
}

func (f *shimFakeDP9821) AddTxPort(ifindex int) error {
	f.txPorts = append(f.txPorts, ifindex)
	return nil
}

func (f *shimFakeDP9821) SetZoneConfig(zoneID uint16, cfg ZoneConfig) error {
	if f.zoneCfg == nil {
		f.zoneCfg = map[uint16]ZoneConfig{}
	}
	f.zoneCfg[zoneID] = cfg
	return nil
}

func (f *shimFakeDP9821) GetPersistentNAT() *PersistentNATTable { return nil }

// installShimSeams9821 points every host-touching seam mapZoneInterface can
// reach at fakes for the test's lifetime: VLAN creation, address reconcile,
// MTU write. Link LOOKUPS intentionally fail (no linkCache seeding), so the
// nlErr guards hold and no syscall, ethtool probe, or LinkSetDown can run —
// the Disable decision is still recorded and asserted.
func installShimSeams9821(t *testing.T, vlanSub *struct {
	parent string
	vlan   int
}) {
	t.Helper()
	oldVLANFn, oldByName := ensureVLANSubInterfaceFn, vlanLinkByNameSeam
	oldLink, oldList, oldAdd, oldDel := addrLinkByNameSeam, addrListSeam, addrAddSeam, addrDelSeam
	oldMTU := linkSetMTUSeam
	t.Cleanup(func() {
		ensureVLANSubInterfaceFn, vlanLinkByNameSeam = oldVLANFn, oldByName
		addrLinkByNameSeam, addrListSeam, addrAddSeam, addrDelSeam = oldLink, oldList, oldAdd, oldDel
		linkSetMTUSeam = oldMTU
	})
	ensureVLANSubInterfaceFn = func(parentName string, vlanID int) (int, bool, error) {
		if vlanSub != nil {
			vlanSub.parent, vlanSub.vlan = parentName, vlanID
		}
		return 950, false, nil
	}
	vlanLinkByNameSeam = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 90}}, nil
	}
	addrLinkByNameSeam = func(name string) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 90}}, nil
	}
	addrListSeam = func(netlink.Link, int) ([]netlink.Addr, error) { return nil, nil }
	addrAddSeam = func(netlink.Link, *netlink.Addr) error { return nil }
	addrDelSeam = func(netlink.Link, *netlink.Addr) error { return nil }
	linkSetMTUSeam = func(netlink.Link, int) error {
		t.Errorf("linkSetMTUSeam called — the nlErr guard must hold with no linkCache seeding")
		return nil
	}
}

// shimResult9821 builds a CompileResult with fake-link ifCache entries and a
func shimResult9821(ifaces map[string]int, zones ...string) *CompileResult {
	result := newValidationResult()
	for name, idx := range ifaces {
		result.ifCache[name] = &net.Interface{Index: idx, Name: name}
		result.rxTagStripOffCache[name] = true
	}
	for _, z := range zones {
		result.ZoneIDs[z] = config.StableZoneID(z)
	}
	return result
}

// TestMapZoneInterfaceDottedFakeLink9821 drives the REAL programZoneMaps →
// mapZoneInterface path for a both-declared dotted shape: the zone key lands
// on the declared device's ifindex with the stanza vlan, the VLAN child is
// created under the declared parent, pendingXDP carries both, and the
// desired-MTU plan targets the declared device (D13 + D24-MTU).
func TestMapZoneInterfaceDottedFakeLink9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {
			Name: "ge-0/0/5.0", MTU: 1500,
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, MTU: 1400, Addresses: []string{"2001:db8:a::1/64"}},
				10: {Number: 10, VlanID: 100, Addresses: []string{"2001:db8:b::1/64"}},
			},
		},
	}}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z": {Interfaces: []string{"ge-0/0/5.0", "ge-0/0/5.0.10"}},
	}
	var vlanSub struct {
		parent string
		vlan   int
	}
	installShimSeams9821(t, &vlanSub)
	dp := &shimFakeDP9821{}
	result := shimResult9821(map[string]int{"ge-0-0-5.0": 90}, "z")
	st, err := programZoneMaps(dp, cfg, result)
	if err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	zid := config.StableZoneID("z")
	wantZones := map[[3]int]bool{{90, 0, int(zid)}: true, {90, 100, int(zid)}: true}
	if len(dp.zones) != 2 {
		t.Fatalf("SetZone calls = %v, want exactly the (90,0) and (90,100) keys", dp.zones)
	}
	for _, z := range dp.zones {
		if !wantZones[[3]int{z.ifindex, int(z.vlan), int(z.zid)}] {
			t.Errorf("SetZone call %+v not in the wanted key set %v", z, wantZones)
		}
	}
	if vlanSub.parent != "ge-0-0-5.0" || vlanSub.vlan != 100 {
		t.Errorf("VLAN child created under (%q,%d), want (ge-0-0-5.0,100)", vlanSub.parent, vlanSub.vlan)
	}
	if len(dp.vlanInfo) != 1 || dp.vlanInfo[0].sub != 950 || dp.vlanInfo[0].parent != 90 || dp.vlanInfo[0].vlan != 100 {
		t.Errorf("SetVlanIfaceInfo calls = %+v, want [{950 90 100}]", dp.vlanInfo)
	}
	xdp := map[int]bool{}
	for _, idx := range st.xdpIfindexes {
		xdp[idx] = true
	}
	if !xdp[90] || !xdp[950] {
		t.Errorf("pendingXDP = %v, want both phys 90 and child 950", st.xdpIfindexes)
	}
	pd := st.physDesired["ge-0-0-5.0"]
	if pd == nil || pd.mtu != 1400 {
		t.Errorf("desired-MTU plan for ge-0-0-5.0 = %+v, want mtu 1400 (unit overrides interface)", pd)
	}
	if _, spurious := st.physDesired["ge-0-0-5"]; spurious {
		t.Error("desired-MTU plan contains first-cut ge-0-0-5 — the undeclared truncation must plan nothing")
	}
}

// TestMapZoneInterfaceDottedDisable9821 pins the Disable decision on a
// dotted shape: administratively-down resolves to the declared device, is
// recorded (not silently skipped), and takes no XDP attachment.
func TestMapZoneInterfaceDottedDisable9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/6.0": {
			Name: "ge-0/0/6.0", Disable: true,
			Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
		},
	}}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z": {Interfaces: []string{"ge-0/0/6.0"}},
	}
	installShimSeams9821(t, nil)
	dp := &shimFakeDP9821{}
	result := shimResult9821(map[string]int{"ge-0-0-6.0": 91}, "z")
	st, err := programZoneMaps(dp, cfg, result)
	if err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	for _, idx := range st.xdpIfindexes {
		if idx == 91 {
			t.Errorf("pendingXDP = %v — disabled ge-0-0-6.0 (91) must take no attachment", st.xdpIfindexes)
		}
	}
	found := false
	for _, u := range result.unarmedSurfaces {
		if u.Name == "ge-0-0-6.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("no unarmed-surface record for ge-0-0-6.0 (records: %+v) — the decline must be recorded, not silent",
			result.unarmedSurfaces)
	}
}

// capturingHandler9821 records slog messages so a test asserts which
// compileInfo/compileWarn records fired (the 6918 idiom).
type capturingHandler9821 struct{ msgs *[]string }

func (h capturingHandler9821) Enabled(context.Context, slog.Level) bool { return true }
func (h capturingHandler9821) Handle(_ context.Context, r slog.Record) error {
	*h.msgs = append(*h.msgs, r.Message)
	return nil
}
func (h capturingHandler9821) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h capturingHandler9821) WithGroup(string) slog.Handler      { return h }

func captureSlog9821(t *testing.T) *[]string {
	t.Helper()
	var msgs []string
	prev := slog.Default()
	slog.SetDefault(slog.New(capturingHandler9821{msgs: &msgs}))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &msgs
}

// TestSNATEgressIPDeclaredDotted9821 (R6-5) pins SNAT egress-IP selection on
// the D13-fixed derivation: the live query names the declared parent's vlan
// child (not a first-cut truncation), the info record fires, and the rule
// consumes a pool ID — observed via the FOLLOWING named pool's ID. The
// empty variant warns and consumes nothing.
func TestSNATEgressIPDeclaredDotted9821(t *testing.T) {
	mkcfg := func(members []string) *config.Config {
		cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0},
				10: {Number: 10, VlanID: 100},
			}},
		}}}
		cfg.Security.Zones = map[string]*config.ZoneConfig{
			"trust":   {Interfaces: []string{"ge-0/0/1"}},
			"untrust": {Interfaces: members},
		}
		cfg.Security.NAT.Source = []*config.NATRuleSet{{
			Name: "rs1", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{
				{Name: "r-iface", Then: config.NATThen{Interface: true}},
				{Name: "r-pool", Then: config.NATThen{PoolName: "p1"}},
			},
		}}
		cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
			"p1": {Name: "p1", Addresses: []string{"203.0.113.0/28"}},
		}
		return cfg
	}
	// Distinct parent/child live addresses; the stub records its inputs.
	seen := map[string]bool{}
	live := map[string]net.IP{
		"ge-0-0-5.0":     net.ParseIP("10.0.0.1"),
		"ge-0-0-5.0.100": net.ParseIP("10.0.100.1"),
	}
	oldV4, oldV6 := getInterfaceIPFn, getInterfaceIPv6Fn
	t.Cleanup(func() { getInterfaceIPFn, getInterfaceIPv6Fn = oldV4, oldV6 })
	getInterfaceIPFn = func(name string, _ *CompileResult) (net.IP, error) {
		seen[name] = true
		if ip, ok := live[name]; ok {
			return ip, nil
		}
		return nil, errTestNoAddr9821
	}
	getInterfaceIPv6Fn = func(_ string, _ *CompileResult) (net.IP, error) {
		return nil, errTestNoAddr9821
	}
	msgs := captureSlog9821(t)

	cfg := mkcfg([]string{"ge-0/0/5.0.10"})
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	result.ifCache["ge-0-0-5.0"] = &net.Interface{Index: 90, Name: "ge-0-0-5.0"}
	if err := compileNAT(&shimFakeDP9821{}, cfg, result); err != nil {
		t.Fatalf("compileNAT: %v", err)
	}
	if seen["ge-0-0-5"] {
		t.Errorf("live query inputs = %v — first-cut truncation ge-0-0-5 must never be queried", seen)
	}
	found := false
	for _, m := range *msgs {
		if m == "SNAT egress IP resolved" {
			found = true
		}
	}
	if !found {
		t.Errorf("no 'SNAT egress IP resolved' record (records: %v)", *msgs)
	}
	if result.PoolIDs["p1"] != 1 {
		t.Errorf("following pool p1 id = %d, want 1 (interface rule consumed 0)", result.PoolIDs["p1"])
	}

	// Empty variant: nothing resolves → warn + no consumption.
	*msgs = nil
	for k := range seen {
		delete(seen, k)
	}
	for k := range live {
		delete(live, k)
	}
	cfg2 := mkcfg([]string{"ge-0/0/5.0.10"})
	result2 := newValidationResult()
	assignZoneIDs(result2, cfg2)
	result2.ifCache["ge-0-0-5.0"] = &net.Interface{Index: 90, Name: "ge-0-0-5.0"}
	if err := compileNAT(&shimFakeDP9821{}, cfg2, result2); err != nil {
		t.Fatalf("compileNAT(empty): %v", err)
	}
	found = false
	for _, m := range *msgs {
		if m == "no IP addresses for interface SNAT" {
			found = true
		}
	}
	if !found {
		t.Errorf("no 'no IP addresses for interface SNAT' record (records: %v)", *msgs)
	}
	if result2.PoolIDs["p1"] != 0 {
		t.Errorf("following pool p1 id = %d, want 0 (empty rule consumes nothing)", result2.PoolIDs["p1"])
	}
}

var errTestNoAddr9821 = errors.New("test: no addr seeded")

// TestTunnelHostInboundGREDeclaredDotted9821 (D24-GRE) pins the GRE auto-flag
// on the D13-fixed derivation: a GRE tunnel whose source IP lives on a dotted
// unit flags the zone that members the dotted interface.
func TestTunnelHostInboundGREDeclaredDotted9821(t *testing.T) {
	cfg := &config.Config{Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
		"ge-0/0/5.0": {Name: "ge-0/0/5.0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"198.51.100.7/24"}},
		}},
		"gr-0/0/0": {Name: "gr-0/0/0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Tunnel: &config.TunnelConfig{Mode: "gre", Source: "198.51.100.7"}},
		}},
	}}}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"z": {Interfaces: []string{"ge-0/0/5.0"}},
	}
	dp := &shimFakeDP9821{}
	result := newValidationResult()
	assignZoneIDs(result, cfg)
	applyTunnelHostInbound(dp, cfg, result)
	zid := config.StableZoneID("z")
	got, ok := dp.zoneCfg[zid]
	if !ok || got.HostInbound&HostInboundGRE == 0 {
		t.Errorf("zone z host-inbound = %+v (present=%v) — want the GRE auto-flag (tunnel source lives on the dotted member)", got, ok)
	}
}

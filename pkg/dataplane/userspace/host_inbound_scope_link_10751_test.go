// #10751 R4-1: kernel scope-link addresses (the self-assigned IPv6
// link-local the kernel owns from link-up, IPv4 169.254 fallbacks) never
// satisfy host-inbound RESOLUTION intent. A DHCPv6 client awaiting its first
// lease sits beside an fe80::/64 that has nothing to do with the lease; if
// the pending-intent predicate counted it as "resolved", the early input
// barrier would hand off while the lease's global address is still uncovered
// (fail-open until a later apply). These tests pin that scope-link rows keep
// the zone/interface reported as pending while staying in the INSTALLED deny
// set (the chain is `policy accept`, so removing them from the destinations
// would admit link-local host input post-handoff).
package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// stubScopeLinkAddrs10751 swaps buildLinkSnapshot to report addrs on every
// queried link, so live-address provenance (scope) is fully scripted.
func stubScopeLinkAddrs10751(t *testing.T, addrs []InterfaceAddressSnapshot) {
	t.Helper()
	prev := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = prev })
	buildLinkSnapshot = func(string) (int, int, string, []InterfaceAddressSnapshot) {
		return 7, 1500, "02:00:00:00:00:07", addrs
	}
}

func scopeLinkCfg10751() *config.Config {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-1": {Name: "ge-0-0-1", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0-0-1.0"}},
	}
	return cfg
}

// TestScopeLinkDoesNotResolveEnforcingIntent10751: a dual-DHCP unit whose only
// live address is the kernel's automatic fe80::/64 is still fully pending —
// the zone stays reported and BOTH families stay reported per interface.
// RED on revert: drop the scope filter and the zone scopes (silent) and the
// inet6 family marks resolved (silent), so both assertions fail.
func TestScopeLinkDoesNotResolveEnforcingIntent10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, []InterfaceAddressSnapshot{
		{Family: "inet6", Address: "fe80::7/64", Scope: int(netlink.SCOPE_LINK)},
	})
	cfg := scopeLinkCfg10751()

	zones := AddresslessEnforcingZones(cfg)
	if len(zones) != 1 || zones[0].Zone != "wan" {
		t.Fatalf("AddresslessEnforcingZones = %+v, want exactly [wan]: a zone with only a kernel link-local is still awaiting enforcement scope", zones)
	}

	type key struct{ zone, iface, family string }
	want := map[key]bool{
		{"wan", "ge-0-0-1.0", "inet"}:  true,
		{"wan", "ge-0-0-1.0", "inet6"}: true,
	}
	got := AddresslessEnforcingInterfaces(cfg)
	if len(got) != len(want) {
		t.Fatalf("AddresslessEnforcingInterfaces = %+v, want exactly %v", got, want)
	}
	for _, g := range got {
		k := key{g.Zone, g.Interface, g.Family}
		if !want[k] {
			t.Errorf("unexpected pending window %+v", g)
		}
		if g.Reason != AddresslessDHCPPending {
			t.Errorf("window %+v reason = %q, want %q", g, g.Reason, AddresslessDHCPPending)
		}
		delete(want, k)
	}
	for k := range want {
		t.Errorf("missing pending window %+v (the scope-link row must not satisfy it)", k)
	}
}

// TestScopeLinkStaysInInstalledDeny10751 pins the deliberate split: the
// pending predicate excludes scope-link rows, but the INSTALLED views keep
// them — link-local host input stays denied post-handoff under the chain's
// `policy accept`. Characterization: green before and after the fix.
func TestScopeLinkStaysInInstalledDeny10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, []InterfaceAddressSnapshot{
		{Family: "inet6", Address: "fe80::7/64", Scope: int(netlink.SCOPE_LINK)},
	})
	var v6 []string
	for _, v := range BuildZoneHostInboundViews(scopeLinkCfg10751()) {
		if v.Zone == "wan" {
			v6 = v.V6Addrs
		}
	}
	for _, want := range []string{"fe80::7"} {
		found := false
		for _, a := range v6 {
			found = found || a == want
		}
		if !found {
			t.Fatalf("installed wan V6Addrs = %v, want %q present: scope-link rows must stay in the deny set", v6, want)
		}
	}
}

// TestScopeLinkSequentialAcquisition10751: static v4 + DHCPv6-pending v6 with
// only a kernel fe80::/64 live. The zone is scoped by its v4 (zone-level
// silent) but the inet6 side is still pending per interface.
// RED on revert: drop the hasFam scope filter and inet6 marks resolved.
func TestScopeLinkSequentialAcquisition10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, []InterfaceAddressSnapshot{
		{Family: "inet6", Address: "fe80::7/64", Scope: int(netlink.SCOPE_LINK)},
	})
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-2": {Name: "ge-0-0-2", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"10.0.2.10/24"}, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"dual": {Name: "dual", Interfaces: []string{"ge-0-0-2.0"}},
	}
	if zones := AddresslessEnforcingZones(cfg); len(zones) != 0 {
		t.Fatalf("AddresslessEnforcingZones = %+v, want silent: the static v4 scopes the zone", zones)
	}
	got := AddresslessEnforcingInterfaces(cfg)
	if len(got) != 1 || got[0].Zone != "dual" || got[0].Interface != "ge-0-0-2.0" || got[0].Family != "inet6" {
		t.Fatalf("AddresslessEnforcingInterfaces = %+v, want exactly [dual ge-0-0-2.0 inet6]", got)
	}
}

// TestConfiguredLinkLocalStillResolves10751: an EXPLICITLY configured fe80::/64
// (scope-universe provenance, operator intent — same prefix, different
// provenance than the kernel row) resolves the family. Paired with
// TestScopeLinkDoesNotResolveEnforcingIntent10751, which uses a kernel
// scope-link row for a same-shaped address: provenance, not prefix, decides.
func TestConfiguredLinkLocalStillResolves10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, nil) // no live addresses at all
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-3": {Name: "ge-0-0-3", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, Addresses: []string{"fe80::5/64"}, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"ll": {Name: "ll", Interfaces: []string{"ge-0-0-3.0"}},
	}
	if zones := AddresslessEnforcingZones(cfg); len(zones) != 0 {
		t.Fatalf("AddresslessEnforcingZones = %+v, want silent: an explicitly configured link-local is operator intent", zones)
	}
	if got := AddresslessEnforcingInterfaces(cfg); len(got) != 0 {
		t.Fatalf("AddresslessEnforcingInterfaces = %+v, want empty: configured scope-universe rows resolve", got)
	}
}

// TestScopeLinkLiveGlobalResolves10751 (control): a LIVE address with global
// scope — the shape a landed lease takes in the snapshot — resolves, proving
// the filter keys on scope, not on live-vs-configured.
func TestScopeLinkLiveGlobalResolves10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, []InterfaceAddressSnapshot{
		{Family: "inet6", Address: "2001:db8::7/64", Scope: int(netlink.SCOPE_UNIVERSE)},
	})
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-4": {Name: "ge-0-0-4", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCPv6: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0-0-4.0"}},
	}
	if zones := AddresslessEnforcingZones(cfg); len(zones) != 0 {
		t.Fatalf("AddresslessEnforcingZones = %+v, want silent: a live global resolves", zones)
	}
	if got := AddresslessEnforcingInterfaces(cfg); len(got) != 0 {
		t.Fatalf("AddresslessEnforcingInterfaces = %+v, want empty", got)
	}
}

// TestScopeLinkFallback169254DoesNotResolveDHCP10751: an IPv4 169.254
// scope-link fallback never satisfies a v4 DHCP client's intent.
func TestScopeLinkFallback169254DoesNotResolveDHCP10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, []InterfaceAddressSnapshot{
		{Family: "inet", Address: "169.254.1.5/16", Scope: int(netlink.SCOPE_LINK)},
	})
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0-0-5": {Name: "ge-0-0-5", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0, DHCP: true},
		}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"wan": {Name: "wan", Interfaces: []string{"ge-0-0-5.0"}},
	}
	got := AddresslessEnforcingInterfaces(cfg)
	if len(got) != 1 || got[0].Family != "inet" {
		t.Fatalf("AddresslessEnforcingInterfaces = %+v, want exactly [wan ge-0-0-5.0 inet]", got)
	}
	if zones := AddresslessEnforcingZones(cfg); len(zones) != 1 {
		t.Fatalf("AddresslessEnforcingZones = %+v, want exactly [wan]", zones)
	}
}

// TestFromSnapshotsEquivalence10751 pins the R4-2 threading refactor: the
// ...FromSnapshots builders fed one sample render byte-identical values to
// the fresh builders.
func TestFromSnapshotsEquivalence10751(t *testing.T) {
	stubScopeLinkAddrs10751(t, []InterfaceAddressSnapshot{
		{Family: "inet", Address: "203.0.113.9/24", Scope: int(netlink.SCOPE_UNIVERSE)},
		{Family: "inet6", Address: "fe80::9/64", Scope: int(netlink.SCOPE_LINK)},
	})
	cfg := scopeLinkCfg10751()
	cfg.Interfaces.Interfaces["ge-0-0-1"].Units[0].Addresses = []string{"10.9.9.9/24"}

	snaps := BuildInterfaceSnapshots(cfg)
	if len(snaps) == 0 {
		t.Fatal("fixture produced no snapshots; the equivalence below would be vacuous")
	}
	if got, want := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps), BuildZoneHostInboundViews(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("views FromSnapshots != fresh:\n got=%+v\nwant=%+v", got, want)
	}
	gotV4, gotV6 := BuildUnzonedHostInboundAddrsFromSnapshots(cfg, snaps)
	wantV4, wantV6 := BuildUnzonedHostInboundAddrs(cfg)
	if !reflect.DeepEqual(gotV4, wantV4) || !reflect.DeepEqual(gotV6, wantV6) {
		t.Errorf("unzoned FromSnapshots (%v, %v) != fresh (%v, %v)", gotV4, gotV6, wantV4, wantV6)
	}
	views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
	if got, want := BuildFenceAddrSetsFromSnapshots(cfg, snaps, views), BuildFenceAddrSets(cfg, views); !reflect.DeepEqual(got, want) {
		t.Errorf("fence FromSnapshots != fresh:\n got=%+v\nwant=%+v", got, want)
	}
}

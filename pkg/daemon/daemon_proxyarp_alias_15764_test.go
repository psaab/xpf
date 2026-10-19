package daemon

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15764: aliased Junos refs collapsing to one random junosRef.
//
// reth0, reth0.0 and ge-0/0/0 all resolve to the same kernel netdev
// ge-0-0-0. Pre-fix, proxyARPResponderTargets kept one arbitrary ref
// (Go map iteration) and syncProxyARPResponders looked up only that
// ref's addresses in a junosRef-keyed pool map, so:
//   - the other aliases' IPv4 pool addresses were never answered, and
//   - if the winner carried only IPv6 (which the kernel answers via
//     proxy-NDP, so it never enters the v4 pool), the len(addrs)==0
//     branch cancelled the responder another alias needed for IPv4.
//
// The fixture below is the acceptance shape from the report, extended
// with the member alias: reth0 carries only v6, reth0.0 and ge-0/0/0
// each carry a distinct v4 pool address.
func aliasedProxyARPCfg15764() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"reth0":    {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
				"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			},
		},
		Security: config.SecurityConfig{
			NAT: config.NATConfig{
				ProxyARP: []*config.ProxyARPEntry{
					{Interface: "reth0", Addresses: []string{"2001:db8::10/128"}},
					{Interface: "reth0.0", Addresses: []string{"198.51.100.10/32"}},
					{Interface: "ge-0/0/0", Addresses: []string{"198.51.100.20/32"}},
				},
			},
		},
	}
}

func stubAliasSeams15764(t *testing.T) {
	t.Helper()
	origIfaceIndex := ifaceIndexByName
	t.Cleanup(func() { ifaceIndexByName = origIfaceIndex })
	ifaceIndexByName = func(name string) (int, error) {
		if name == "ge-0-0-0" {
			return 7, nil
		}
		return 0, fmt.Errorf("no such interface %s", name)
	}
	origMAC := proxyARPInterfaceByName
	t.Cleanup(func() { proxyARPInterfaceByName = origMAC })
	proxyARPInterfaceByName = func(_ string) (*net.Interface, error) {
		return &net.Interface{HardwareAddr: net.HardwareAddr{0x02, 0xbf, 0x72, 0x16, 0x01, 0x00}}, nil
	}
}

// The pool collector must union every alias onto the netdev key, and
// must not claim the v6 address (kernel proxy-NDP owns it).
func TestProxyARPPoolAddressesUnionAliasedRefs15764(t *testing.T) {
	cfg := aliasedProxyARPCfg15764()
	got := proxyARPPoolAddressesByInterface(cfg)
	set, ok := got["ge-0-0-0"]
	if !ok {
		t.Fatalf("pool addresses not keyed by resolved netdev ge-0-0-0; got keys %v", keysOf15764(got))
	}
	for _, want := range []string{"198.51.100.10", "198.51.100.20"} {
		if _, ok := set[want]; !ok {
			t.Errorf("aliased pool address %s missing from unioned set %v", want, set)
		}
	}
	if len(set) != 2 {
		t.Errorf("unioned set = %v, want exactly the 2 v4 addresses (v6 is kernel proxy-NDP)", set)
	}
	// No ref-keyed remnants: a junosRef key here is the pre-fix shape.
	for _, ref := range []string{"reth0", "reth0.0", "ge-0/0/0"} {
		if _, ok := got[ref]; ok {
			t.Errorf("pool addresses still keyed by Junos ref %q", ref)
		}
	}
}

// Targets must carry every alias, deterministically, on every call —
// the pre-fix map[string]string returned one random winner.
func TestProxyARPResponderTargetsCarriesAllAliases15764(t *testing.T) {
	stubAliasSeams15764(t)
	cfg := aliasedProxyARPCfg15764()
	wantRefs := []string{"ge-0/0/0", "reth0", "reth0.0"}
	for i := range 50 {
		got := proxyARPResponderTargets(cfg)
		refs, ok := got["ge-0-0-0"]
		if !ok || len(got) != 1 {
			t.Fatalf("iteration %d: targets = %v, want single netdev ge-0-0-0", i, got)
		}
		if !reflect.DeepEqual(refs, wantRefs) {
			t.Fatalf("iteration %d: refs = %v, want sorted %v", i, refs, wantRefs)
		}
	}
}

func TestSyncProxyARPRespondersUnionsAliasedJunosRefs(t *testing.T) {
	stubAliasSeams15764(t)
	cfg := aliasedProxyARPCfg15764()

	d := &Daemon{arpResponders: newProxyARPResponders()}
	t.Cleanup(d.stopProxyARPResponders)

	// Pre-seed a live responder whose only address is stale. Pre-fix,
	// when the random winner was the v6-only reth0 ref, the
	// len(addrs)==0 branch cancelled this responder outright; when the
	// winner was a v4 alias, only that alias's address survived.
	_, cancel := context.WithCancel(context.Background())
	live := &proxyARPResponder{
		cancel:   cancel,
		done:     make(chan struct{}),
		junosRef: "reth0",
		addrs:    map[string]struct{}{"203.0.113.99": {}},
	}
	d.arpResponders.running["ge-0-0-0"] = live

	d.syncProxyARPResponders(cfg, proxyARPResponderTargets(cfg))

	r, ok := d.arpResponders.running["ge-0-0-0"]
	if !ok {
		t.Fatal("responder for ge-0-0-0 was cancelled: an aliased ref with " +
			"only IPv6 (or the random single-ref collapse) must not cancel " +
			"the IPv4 responder another alias needs (#15764)")
	}
	if r != live {
		t.Fatal("live responder was replaced instead of updated in place")
	}
	proxied, junosRef, rgID := r.snapshot("198.51.100.10")
	if !proxied {
		t.Error("198.51.100.10 (reth0.0 alias) not answered after sync")
	}
	_ = junosRef
	if rgID != 1 {
		t.Errorf("rgID = %d, want 1 (reth0 redundancy group)", rgID)
	}
	if proxied, _, _ := r.snapshot("198.51.100.20"); !proxied {
		t.Error("198.51.100.20 (ge-0/0/0 alias) not answered after sync")
	}
	if proxied, _, _ := r.snapshot("203.0.113.99"); proxied {
		t.Error("stale address 203.0.113.99 still answered after sync")
	}
	// The v6 alias address must not be claimed by the v4 responder.
	if proxied, _, _ := r.snapshot("2001:db8::10"); proxied {
		t.Error("IPv6 address claimed by the IPv4 responder; kernel proxy-NDP owns it")
	}
	// Identity is the deterministic smallest alias, not a random winner.
	if _, junosRef, _ := r.snapshot("198.51.100.10"); junosRef != "ge-0/0/0" {
		t.Errorf("responder junosRef = %q, want deterministic %q", junosRef, "ge-0/0/0")
	}

	// Determinism across repeated reconciles (the 30s reassert path):
	// the union and identity must not flap between aliases.
	for i := range 20 {
		d.syncProxyARPResponders(cfg, proxyARPResponderTargets(cfg))
		r = d.arpResponders.running["ge-0-0-0"]
		if r == nil {
			t.Fatalf("iteration %d: responder vanished", i)
		}
		for _, addr := range []string{"198.51.100.10", "198.51.100.20"} {
			if proxied, ref, _ := r.snapshot(addr); !proxied || ref != "ge-0/0/0" {
				t.Fatalf("iteration %d: %s proxied=%v ref=%q, want answered as ge-0/0/0", i, addr, proxied, ref)
			}
		}
	}
}

func keysOf15764(m map[string]map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

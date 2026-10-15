package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #13105/D5-14: a lifeline-shared address first added in the SAME commit that
// tightens the zone to {} lives only in the NEW (compiled) view's
// IngressDenyV4/V6 (the #12229 empty-admit split withholds it from
// V4Addrs/V6Addrs). The old view never held it in any field. The production
// two-generation call must still emit the transition advisory, so the matcher
// must count IngressDenyV4/V6 as address ownership.
func TestTightenedScopesIngressDenyNewGeneration13105(t *testing.T) {
	scopes := []string{"zone:dmz"}
	oldViews := []dpuserspace.ZoneHostInboundView{{Zone: "dmz"}}
	newViews := []dpuserspace.ZoneHostInboundView{{
		Zone: "dmz", IngressNetdevs: []string{"ge-0-0-3"},
		IngressDenyV4: []string{"192.0.2.50"},
		IngressDenyV6: []string{"2001:db8::50"},
	}}
	if !tightenedScopesHaveAddrs10752(scopes, oldViews, newViews) {
		t.Fatal("new-generation IngressDeny-only address must create a transition advisory")
	}
	// Single-family controls: each field alone suffices.
	if !tightenedScopesHaveAddrs10752(scopes, nil, []dpuserspace.ZoneHostInboundView{{Zone: "dmz", IngressDenyV4: []string{"192.0.2.50"}}}) {
		t.Fatal("IngressDenyV4 alone must count")
	}
	if !tightenedScopesHaveAddrs10752(scopes, nil, []dpuserspace.ZoneHostInboundView{{Zone: "dmz", IngressDenyV6: []string{"2001:db8::50"}}}) {
		t.Fatal("IngressDenyV6 alone must count")
	}
	// Negative controls: another zone's deny addresses and an addressless
	// zone must not create the advisory.
	if tightenedScopesHaveAddrs10752(scopes, nil, []dpuserspace.ZoneHostInboundView{{Zone: "other", IngressDenyV4: []string{"192.0.2.50"}}}) {
		t.Fatal("unrelated zone's IngressDeny address must not create advisory")
	}
	if tightenedScopesHaveAddrs10752(scopes, oldViews) {
		t.Fatal("addressless zone must not create a transition advisory")
	}
}
// A live DHCP lease is not in the static interface stanza. When the address
// view groups an overridden unit with a zone-default unit having identical
// tokens, snapshot ownership must prevent attribution to the sibling's zone
// scope.
func TestHostInboundScopesForDHCPLeaseAttribution13105(t *testing.T) {
	cfg := twoUnitWanCfg10752(t, []string{"any-service"})
	cfg.Security.Zones["wan"].InterfaceHostInbound = map[string]*config.HostInboundTraffic{
		"reth0.50": {SystemServices: []string{"any-service"}},
	}
	addr := netip.MustParseAddr("198.51.100.50")
	views := []dpuserspace.ZoneHostInboundView{{
		Zone: "wan", Interfaces: []string{"reth0.50", "reth0.60"},
		V4Addrs: []string{addr.String()},
	}}
	snapshots := []dpuserspace.InterfaceSnapshot{{
		Name: "reth0.50",
		Addresses: []dpuserspace.InterfaceAddressSnapshot{{
			Family: "inet", Address: addr.String() + "/24",
		}},
	}}
	got := hostInboundScopesForAddrs10752(cfg, views, []netip.Addr{addr}, snapshots)
	if len(got[addr]) != 1 || got[addr][0] != "zone:wan|iface:reth0.50" {
		t.Fatalf("DHCP lease scope = %v, want only [zone:wan|iface:reth0.50]", got[addr])
	}
}

package daemon

import (
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

const (
	sharedOnlyV4_12845 = "192.0.2.1"
	sharedOnlyV6_12845 = "2001:db8::1"
	ordinaryV4_12845   = "198.51.100.1"
)

// #12845/D3-11 counterevidence: IngressDeny addresses are lifeline-shared.
// The flush filter matches only the destination address and cannot distinguish
// a data-zone session from an fxp0 management session. Such addresses must not
// be added to its covered set. Data-zone established traffic is instead
// rejected by the #12229 ingress drop before the residual established accept.
func TestIngressDenyOnlyAddressesStayOutsideAddressOnlyFlush12845(t *testing.T) {
	views := []dpuserspace.ZoneHostInboundView{{
		Zone: "untrust", IngressNetdevs: []string{"ge-0-0-0"},
		IngressDenyV4: []string{sharedOnlyV4_12845},
		IngressDenyV6: []string{sharedOnlyV6_12845},
	}}
	if filter := buildHostInboundConntrackFlushFilter(views, nil, nil, nil); filter != nil {
		t.Fatalf("IngressDeny-only lifeline-shared addresses must not create an address-only flush filter: %+v", filter.admit)
	}

	// NEGATIVE CONTROL: a separate ordinary default-deny address must still
	// create a filter and be flushable; do not disable #5566 globally.
	views[0].V4Addrs = []string{ordinaryV4_12845}
	filter := buildHostInboundConntrackFlushFilter(views, nil, nil, nil)
	if filter == nil {
		t.Fatal("ordinary default-deny address must remain covered")
	}
	if _, covered := filter.admit[netip.MustParseAddr(sharedOnlyV4_12845)]; covered {
		t.Fatal("lifeline-shared address entered the address-only covered set")
	}
	if !filter.MatchConntrackFlow(ctFlow(config.HostInboundProtoTCP, ordinaryV4_12845, 22)) {
		t.Fatal("ordinary denied SSH flow must remain flushable")
	}
}

func TestTightenedScopeMatcherUsesBothTransitionGenerations12845(t *testing.T) {
	scopes := []string{"zone:untrust"}
	oldViews := []dpuserspace.ZoneHostInboundView{{
		Zone: "untrust", V4Addrs: []string{sharedOnlyV4_12845},
	}}
	newViews := []dpuserspace.ZoneHostInboundView{{
		Zone: "untrust", IngressNetdevs: []string{"ge-0-0-0"},
		IngressDenyV4: []string{sharedOnlyV4_12845},
	}}
	if !tightenedScopesHaveAddrs10752(scopes, oldViews, newViews) {
		t.Fatal("transition matcher must retain the old generation's address when the new deny-all view withholds it")
	}
	// A current-only probe is not the production call shape: the commit warning
	// passes both old and new generations. It may therefore not establish that
	// the transition advisory is suppressed in production.
	if tightenedScopesHaveAddrs10752(scopes, newViews) {
		t.Fatal("IngressDeny-only new view is not itself an address-owner record")
	}
	if tightenedScopesHaveAddrs10752(scopes, []dpuserspace.ZoneHostInboundView{{Zone: "untrust"}}) {
		t.Fatal("addressless zone must not create a transition advisory")
	}
}

package natshow

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #16647: the detail renderer must show protocol, routing scope and the
// granted remotes, not only the (previously always any-remote-host) permit.

func TestRenderPersistentDetailShowsProtocolScopeAndGrants16647(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:        netip.MustParseAddr("10.0.1.5"),
		SrcPort:      1111,
		NatIP:        netip.MustParseAddr("203.0.113.1"),
		NatPort:      40000,
		PoolName:     "p-src",
		LastSeen:     time.Now(),
		Timeout:      600 * time.Second,
		Permit:       config.PersistentNATPermitTargetHost,
		Protocol:     17,
		RoutingScope: 7,
		PermittedRemotes: []dataplane.PersistentNATRemote{
			{IP: netip.MustParseAddr("8.8.8.8"), Port: 0},
		},
	})
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, &fakeReader{pnat: pnat})
	out := b.String()
	for _, want := range []string{
		"  Protocol:           udp\n",
		"  Routing scope:      7\n",
		"  Permit:             target-host\n",
		"  Permitted remote:   8.8.8.8 (any port)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing %q:\n%s", want, out)
		}
	}
}

// Control: a legacy binding with no protocol still renders (protocol line
// omitted, scope 0 shown) so pre-#16647 rows do not break the golden shape.
func TestRenderPersistentDetailLegacyBindingStillRenders16647(t *testing.T) {
	pnat := dataplane.NewPersistentNATTable()
	pnat.Save(&dataplane.PersistentNATBinding{
		SrcIP:    netip.MustParseAddr("10.0.1.5"),
		SrcPort:  1111,
		NatIP:    netip.MustParseAddr("203.0.113.1"),
		NatPort:  40000,
		PoolName: "p-src",
		LastSeen: time.Now(),
		Timeout:  600 * time.Second,
		Permit:   config.PersistentNATPermitAnyRemoteHost,
	})
	var b strings.Builder
	RenderPersistentDetail(context.Background(), &b, &fakeReader{pnat: pnat})
	out := b.String()
	if !strings.Contains(out, "  Routing scope:      0\n") {
		t.Errorf("legacy detail missing scope line:\n%s", out)
	}
	if strings.Contains(out, "  Protocol:") {
		t.Errorf("legacy binding must not invent a protocol:\n%s", out)
	}
}

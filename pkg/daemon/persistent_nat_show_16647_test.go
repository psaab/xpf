package daemon

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/natshow"
)

// #16647: since #13945 the helper sets remote=None on every lease row and
// records grants in permit_any_remote / permitted_remotes. The Go converter
// keyed Permit on the always-empty RemoteIP, so every binding rendered
// any-remote-host, and persistentNATKey dropped Protocol+RoutingScope so
// distinct helper leases merged into one row.

func displayLease16647(protocol uint8, scope uint32, permitAny bool, remotes []dpuserspace.PersistentNatRemote) dpuserspace.DisplayLeaseWire {
	return dpuserspace.DisplayLeaseWire{
		Pool:             "p1",
		Protocol:         protocol,
		SrcIP:            "10.0.0.1",
		SrcPort:          40000,
		RoutingScope:     persistentNatLeaseScopeDaemon(scope),
		EgressScope:      persistentNatLeaseScopeDaemon(0),
		PermitAnyRemote:  permitAny,
		PermittedRemotes: remotes,
		TranslatedIP:     "203.0.113.1",
		TranslatedPort:   50000,
		RemainingNs:      uint64(time.Minute),
		TimeoutNs:        uint64(5 * time.Minute),
	}
}

func idleLease16647(protocol uint8, scope uint32, permitAny bool, remotes []dpuserspace.PersistentNatRemote) dpuserspace.IdleLeaseWire {
	d := displayLease16647(protocol, scope, permitAny, remotes)
	return dpuserspace.IdleLeaseWire{
		Pool:             d.Pool,
		Protocol:         d.Protocol,
		SrcIP:            d.SrcIP,
		SrcPort:          d.SrcPort,
		RoutingScope:     d.RoutingScope,
		EgressScope:      d.EgressScope,
		PermitAnyRemote:  d.PermitAnyRemote,
		PermittedRemotes: d.PermittedRemotes,
		TranslatedIP:     d.TranslatedIP,
		TranslatedPort:   d.TranslatedPort,
		RemainingNs:      d.RemainingNs,
		TimeoutNs:        d.TimeoutNs,
	}
}

// The acceptance probe: a target-host-port lease (grant 8.8.8.8:53 only, remote
// empty as the helper now sends it) must not render any-remote-host.
func TestPersistentPermitDerivedFromGrantsNotEmptyRemote16647(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name      string
		permitAny bool
		remotes   []dpuserspace.PersistentNatRemote
		want      config.PersistentNATPermit
	}{
		{"any-remote", true, nil, config.PersistentNATPermitAnyRemoteHost},
		{"target-host-port grant", false, []dpuserspace.PersistentNatRemote{{IP: "8.8.8.8", Port: 53}}, config.PersistentNATPermitTargetHostPort},
		{"target-host wildcard grant", false, []dpuserspace.PersistentNatRemote{{IP: "8.8.8.8", Port: 0}}, config.PersistentNATPermitTargetHost},
		{"target-host wildcard among ported", false, []dpuserspace.PersistentNatRemote{{IP: "8.8.8.8", Port: 53}, {IP: "9.9.9.9", Port: 0}}, config.PersistentNATPermitTargetHost},
		{"no grants is not any-remote", false, nil, config.PersistentNATPermitTargetHostPort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			display := persistentNatBindingsFromDisplayLeases([]dpuserspace.DisplayLeaseWire{
				displayLease16647(6, 0, tc.permitAny, tc.remotes),
			}, now)
			if len(display) != 1 || display[0].Permit != tc.want {
				t.Fatalf("display Permit = %v (n=%d), want %v", display, len(display), tc.want)
			}
			idle := persistentNatBindingsFromLeases([]dpuserspace.IdleLeaseWire{
				idleLease16647(6, 0, tc.permitAny, tc.remotes),
			}, now)
			if len(idle) != 1 || idle[0].Permit != tc.want {
				t.Fatalf("idle Permit = %v (n=%d), want %v", idle, len(idle), tc.want)
			}
			if len(tc.remotes) > 0 && len(display[0].PermittedRemotes) != len(tc.remotes) {
				t.Fatalf("grants not carried: %v", display[0].PermittedRemotes)
			}
		})
	}
}

// The merge probe: TCP, UDP and a second routing scope on the same socket
// are three leases and must stay three rows; a distinct port is the control.
func TestPersistentBindingsDoNotMergeAcrossProtocolOrScope16647(t *testing.T) {
	now := time.Now()
	grant := []dpuserspace.PersistentNatRemote{{IP: "8.8.8.8", Port: 53}}
	leases := []dpuserspace.DisplayLeaseWire{
		displayLease16647(6, 0, false, grant),
		displayLease16647(17, 0, false, grant),
		displayLease16647(6, 7, false, grant),
	}
	bindings := persistentNatBindingsFromDisplayLeases(leases, now)
	table := dataplane.NewPersistentNATTable()
	table.ReplaceAll(bindings)
	if got := table.Len(); got != 3 {
		t.Fatalf("ReplaceAll kept %d bindings, want 3 (tcp/udp/tcp@scope7 merged)", got)
	}
	if got := len(table.All()); got != 3 {
		t.Fatalf("All() = %d bindings, want 3", got)
	}
	// Control: a distinct source port was already distinct pre-fix.
	control := displayLease16647(6, 0, false, grant)
	control.SrcPort = 40001
	table2 := dataplane.NewPersistentNATTable()
	table2.ReplaceAll(persistentNatBindingsFromDisplayLeases([]dpuserspace.DisplayLeaseWire{
		displayLease16647(6, 0, false, grant), control,
	}, now))
	if got := table2.Len(); got != 2 {
		t.Fatalf("distinct-port control kept %d bindings, want 2", got)
	}
	// Scoped lookups resolve each tenant/protocol distinctly.
	if b := table.LookupScoped(mustAddr16647("10.0.0.1"), 40000, "p1", 17, 0); b == nil || b.Protocol != 17 {
		t.Fatalf("UDP scoped lookup = %+v", b)
	}
	if b := table.LookupScoped(mustAddr16647("10.0.0.1"), 40000, "p1", 6, 7); b == nil || b.RoutingScope != 7 {
		t.Fatalf("scope-7 scoped lookup = %+v", b)
	}
}

// End to end: the rendered detail shows target-host-port, the grant, the
// protocol and the scope — not a single any-remote-host row.
func TestPersistentDetailRendersGrantsProtocolAndScope16647(t *testing.T) {
	now := time.Now()
	grant := []dpuserspace.PersistentNatRemote{{IP: "8.8.8.8", Port: 53}}
	bindings := persistentNatBindingsFromDisplayLeases([]dpuserspace.DisplayLeaseWire{
		displayLease16647(6, 7, false, grant),
		displayLease16647(17, 7, false, grant),
	}, now)
	table := dataplane.NewPersistentNATTable()
	table.ReplaceAll(bindings)
	dp := dataplane.New()
	dp.PersistentNAT = table
	var b strings.Builder
	natshow.RenderPersistentDetail(context.Background(), &b, dp)
	out := b.String()
	for _, want := range []string{
		"Total persistent NAT bindings: 2",
		"  Permit:             target-host-port\n",
		"  Permitted remote:   8.8.8.8:53\n",
		"  Protocol:           tcp\n",
		"  Protocol:           udp\n",
		"  Routing scope:      7\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered detail missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "any-remote-host") {
		t.Errorf("target-host-port lease still renders any-remote-host:\n%s", out)
	}
	_ = now
}

func mustAddr16647(s string) netip.Addr { return netip.MustParseAddr(s) }

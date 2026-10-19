package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15158 (B07-03): the cluster-mode AD-250 Null0 defaults are internal
// fabric-redirect safety nets, not operator routes. Before the fix they
// rendered untagged, so `from protocol static` selected them exactly like
// an operator static: BGP origination (#14586) and RIP/OSPF/IS-IS
// redistribution advertised 0.0.0.0/0 and ::/0 pointing at a blackhole
// whenever the real default was lost (or permanently, in no-default
// designs).
//
// Fix: the defaults render with a reserved route tag, and every generated
// redistribute map (the per-source `<policy>-static-xpf-redist` maps and
// the QNH metric static/policy maps) leads with a `deny` sequence matching
// that tag. Bare `redistribute static` has no route-map to carry the deny,
// so it is rewritten to a generated deny-tag map whenever cluster mode is
// active. Operator statics are untagged and keep flowing.
//
// The render-level oracle below is the contract FRR evaluates: a tagged
// default hits the leading deny in the static redistribute map, while the
// untagged operator default (and the selected non-default static) fall
// through to the policy's permit.

func clusterNull0PO15158() *config.PolicyOptionsConfig {
	return &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"EXP": {
				Name: "EXP",
				Terms: []*config.PolicyTerm{
					{Name: "static-term", FromProtocols: []string{"static"}, PrefixList: []string{"adv"}, Action: "accept"},
				},
			},
		},
		PrefixLists: map[string]*config.PrefixList{
			"adv": {Name: "adv", Prefixes: []string{"0.0.0.0/0", "::/0", "192.168.50.0/24", "2001:db8:50::/48"}},
		},
	}
}

func clusterNull0Section15158(t *testing.T, fc *FullConfig) string {
	t.Helper()
	return New().buildManagedSection(fc)
}

// routeMapSeqs15158 parses one route-map's sequences in rendered order:
// each entry is "permit|deny <seq>" plus the match lines under it.
func routeMapSeqs15158(t *testing.T, got, name string) []string {
	t.Helper()
	var seqs []string
	inMap := false
	for _, ln := range strings.Split(got, "\n") {
		if strings.HasPrefix(ln, "route-map ") {
			fields := strings.Fields(ln)
			if len(fields) == 4 && fields[1] == name {
				inMap = true
				seqs = append(seqs, fields[2]+" "+fields[3])
				continue
			}
			if inMap {
				// A different route-map header ends this map only when
				// it is not a continuation; FRR groups by name, and the
				// renderer emits one map contiguously.
				if len(fields) == 4 {
					inMap = false
				}
			}
			continue
		}
		if inMap && strings.HasPrefix(ln, " ") {
			seqs[len(seqs)-1] += "|" + strings.TrimSpace(ln)
		}
	}
	if len(seqs) == 0 {
		t.Fatalf("route-map %s not defined:\n%s", name, got)
	}
	return seqs
}

func TestClusterNull0DefaultsTaggedAndDeniedInBGPStaticRedist15158(t *testing.T) {
	fc := &FullConfig{
		ClusterMode:   true,
		PolicyOptions: clusterNull0PO15158(),
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", Preference: 5, NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
			{Destination: "192.168.50.0/24", Preference: 5, NextHops: []config.NextHopEntry{{Address: "192.0.2.1"}}},
		},
		Inet6StaticRoutes: []*config.StaticRoute{
			{Destination: "::/0", Preference: 5, NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
			{Destination: "2001:db8:50::/48", Preference: 5, NextHops: []config.NextHopEntry{{Address: "2001:db8::1"}}},
		},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1", Export: []string{"EXP"},
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
		},
	}
	got := clusterNull0Section15158(t, fc)

	// The internal defaults carry the reserved tag; the operator defaults
	// (same prefixes, gateway next-hops) do not.
	for _, want := range []string{
		"ip route 0.0.0.0/0 Null0 tag 2500 250\n",
		"ipv6 route ::/0 Null0 tag 2500 250\n",
		"ip route 0.0.0.0/0 192.0.2.1 5\n",
		"ipv6 route ::/0 2001:db8::1 5\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ip route 0.0.0.0/0 192.0.2.1 5 tag") || strings.Contains(got, "ipv6 route ::/0 2001:db8::1 5 tag") {
		t.Errorf("operator static default must stay untagged:\n%s", got)
	}

	// BGP still originates statics through the filtered per-source map.
	if !strings.Contains(got, " redistribute static route-map EXP-static-xpf-redist\n") {
		t.Fatalf("BGP static origination lost:\n%s", got)
	}
	// The static redistribute map leads with the tag deny, before any
	// permit, so the tagged internal defaults can never be selected while
	// untagged operator routes fall through to the policy terms.
	seqs := routeMapSeqs15158(t, got, "EXP-static-xpf-redist")
	if !strings.HasPrefix(seqs[0], "deny ") || !strings.Contains(seqs[0], "match tag 2500") {
		t.Errorf("EXP-static-xpf-redist must lead with deny match tag %d, got %v:\n%s", clusterNull0Tag15158, seqs, got)
	}
	joined := strings.Join(seqs, "\n")
	if !strings.Contains(joined, "permit") || !strings.Contains(joined, "adv") {
		t.Errorf("EXP-static-xpf-redist must still permit selected operator statics:\n%s", joined)
	}
}

func TestClusterNull0DeniedInRIPBareAndPolicyRedist15158(t *testing.T) {
	// Bare token: `protocols rip redistribute static` has no policy map, so
	// in cluster mode it must attach the generated deny-tag map instead of
	// the unfiltered verb. The same map shape guards a RIP policy export.
	fc := &FullConfig{
		ClusterMode:   true,
		PolicyOptions: clusterNull0PO15158(),
		RIP:           &config.RIPConfig{Interfaces: []string{"ge-0/0/0.0"}, Redistribute: []string{"static", "EXP"}},
	}
	got := clusterNull0Section15158(t, fc)
	if !strings.Contains(got, " redistribute static route-map "+clusterNull0DenyRouteMap15158+"\n") {
		t.Errorf("bare RIP redistribute static must attach the cluster deny-tag map in cluster mode:\n%s", got)
	}
	if strings.Contains(got, " redistribute static\n") {
		t.Errorf("unfiltered redistribute static survived in cluster mode:\n%s", got)
	}
	seqs := routeMapSeqs15158(t, got, clusterNull0DenyRouteMap15158)
	if len(seqs) != 2 || !strings.HasPrefix(seqs[0], "deny ") || !strings.Contains(seqs[0], "match tag 2500") || !strings.HasPrefix(seqs[1], "permit ") {
		t.Errorf("deny-tag map must be [deny match tag, permit], got %v:\n%s", seqs, got)
	}
	// Policy path keeps its own filtered map, also tag-guarded.
	seqs = routeMapSeqs15158(t, got, "EXP-static-xpf-redist")
	if !strings.HasPrefix(seqs[0], "deny ") || !strings.Contains(seqs[0], "match tag 2500") {
		t.Errorf("RIP policy static map must lead with deny match tag, got %v:\n%s", seqs, got)
	}
}

func TestClusterNull0DeniedInOSPFAndISISRedist15158(t *testing.T) {
	fc := &FullConfig{
		ClusterMode: true,
		OSPF:        &config.OSPFConfig{RouterID: "1.1.1.1", Export: []string{"static"}},
		ISIS:        &config.ISISConfig{Level: "level-2", Export: []string{"static"}},
	}
	got := clusterNull0Section15158(t, fc)
	if !strings.Contains(got, " redistribute static route-map "+clusterNull0DenyRouteMap15158+"\n") {
		t.Errorf("OSPF bare static export must attach the deny-tag map in cluster mode:\n%s", got)
	}
	if !strings.Contains(got, " redistribute ipv4 static level-2 route-map "+clusterNull0DenyRouteMap15158+"\n") ||
		!strings.Contains(got, " redistribute ipv6 static level-2 route-map "+clusterNull0DenyRouteMap15158+"\n") {
		t.Errorf("IS-IS bare static export must attach the deny-tag map in cluster mode:\n%s", got)
	}
}

func TestNoClusterModeNoTagMachinery15158(t *testing.T) {
	// Control: without cluster mode there is no internal default, so no
	// tag, no deny sequence, and bare redistribution stays bare — zero
	// behaviour change outside the cited mechanism.
	fc := &FullConfig{
		PolicyOptions: clusterNull0PO15158(),
		RIP:           &config.RIPConfig{Interfaces: []string{"ge-0/0/0.0"}, Redistribute: []string{"static", "EXP"}},
		BGP: &config.BGPConfig{
			LocalAS: 65001, RouterID: "1.1.1.1", Export: []string{"EXP"},
			Neighbors: []*config.BGPNeighbor{{Address: "192.0.2.2", PeerAS: 65002, FamilyInet: true}},
		},
	}
	got := clusterNull0Section15158(t, fc)
	for _, bad := range []string{"Null0 tag", "match tag", clusterNull0DenyRouteMap15158} {
		if strings.Contains(got, bad) {
			t.Errorf("non-cluster render must not contain %q:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, " redistribute static\n") {
		t.Errorf("non-cluster bare RIP redistribute static must stay bare:\n%s", got)
	}
	seqs := routeMapSeqs15158(t, got, "EXP-static-xpf-redist")
	if strings.HasPrefix(seqs[0], "deny ") && strings.Contains(seqs[0], "match tag") {
		t.Errorf("non-cluster static map must not gain the tag deny, got %v", seqs)
	}
}

func TestClusterNull0QNHStaticMapDenied15158(t *testing.T) {
	// The QNH metric static map is generated only when a qualified
	// next-hop carries a metric; it attaches to `redistribute static`
	// under OSPF/RIP and must also deny the tagged internal defaults.
	fc := &FullConfig{
		ClusterMode: true,
		StaticRoutes: []*config.StaticRoute{
			{Destination: "10.70.0.0/24", Preference: 5, NextHops: []config.NextHopEntry{{Address: "192.0.2.1", HasMetric: true, Metric: 10}}},
		},
		OSPF: &config.OSPFConfig{RouterID: "1.1.1.1", Export: []string{"static"}},
	}
	got := clusterNull0Section15158(t, fc)
	// Find the generated QNH static map name from its attachment.
	var mapName string
	for _, ln := range strings.Split(got, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "redistribute static route-map ") {
			mapName = strings.TrimSpace(strings.TrimPrefix(ln, "redistribute static route-map "))
			break
		}
	}
	if mapName == "" || mapName == clusterNull0DenyRouteMap15158 {
		t.Fatalf("QNH static map attachment missing (got %q):\n%s", mapName, got)
	}
	seqs := routeMapSeqs15158(t, got, mapName)
	if !strings.HasPrefix(seqs[0], "deny ") || !strings.Contains(seqs[0], "match tag 2500") {
		t.Errorf("QNH static map %s must lead with deny match tag, got %v:\n%s", mapName, seqs, got)
	}
}

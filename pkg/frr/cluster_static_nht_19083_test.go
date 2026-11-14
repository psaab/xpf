package frr

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #19083 cells: the static-NHT blackhole deny (cluster_static_nht_19083.go).

const (
	nhtMapA19083 = "xpf-static-nht-xpf-redist"
	nhtMapB19083 = "xpf-static-nht-b-xpf-redist"
)

func clusterFC19083(cluster bool) *FullConfig {
	return &FullConfig{
		ClusterMode: cluster,
		StaticRoutes: []*config.StaticRoute{
			{Destination: "198.51.100.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}},
		},
	}
}

// wantMapBody19083 is the exact definition each map must render: both
// families' blackhole denies, then the permit.
func wantMapBody19083(name string) string {
	return "route-map " + name + " deny 10\n match ip next-hop type blackhole\nexit\n" +
		"route-map " + name + " deny 20\n match ipv6 next-hop type blackhole\nexit\n" +
		"route-map " + name + " permit 30\nexit\n"
}

// TestClusterStaticNHTRender19083: in cluster mode the managed section defines
// both maps exactly and binds staticd's v4 AND v6 next-hop tracking — and only
// staticd's — to the primary map, once each; standalone renders none of it.
func TestClusterStaticNHTRender19083(t *testing.T) {
	m := &Manager{}
	got := m.buildManagedSection(clusterFC19083(true))
	for _, name := range []string{nhtMapA19083, nhtMapB19083} {
		if !strings.Contains(got, wantMapBody19083(name)) {
			t.Errorf("cluster render lacks the exact %s definition:\n%s", name, got)
		}
	}
	lines := strings.Split(got, "\n")
	count := func(pred func(string) bool) (n int) {
		for _, l := range lines {
			if pred(l) {
				n++
			}
		}
		return n
	}
	for _, want := range []string{"ip nht static route-map " + nhtMapA19083, "ipv6 nht static route-map " + nhtMapA19083} {
		if n := count(func(l string) bool { return l == want }); n != 1 {
			t.Errorf("binding %q rendered %d times, want exactly once", want, n)
		}
	}
	if n := count(func(l string) bool { return strings.Contains(l, " nht ") }); n != 2 {
		t.Errorf("%d nht lines rendered, want exactly the two static bindings (no other NHT client, no alternate binding):\n%s", n, got)
	}

	// Without policy-options at all the maps are still defined (the binding
	// would otherwise reference a missing map).
	if !strings.Contains(m.buildManagedSection(&FullConfig{ClusterMode: true}), wantMapBody19083(nhtMapA19083)) {
		t.Error("cluster render without policy-options lacks the map definition")
	}

	standalone := m.buildManagedSection(clusterFC19083(false))
	if strings.Contains(standalone, "xpf-static-nht") || strings.Contains(standalone, " nht ") {
		t.Errorf("standalone render carries the cluster NHT filter:\n%s", standalone)
	}
}

// TestClusterStaticNHTNamesInFinalBelt19083: both generated names are in the
// final-name collision belt exactly when they are emitted (ClusterMode). The
// belt enumerates nothing without policy-options (no operator map can collide
// then), so the fixture carries an empty set.
func TestClusterStaticNHTNamesInFinalBelt19083(t *testing.T) {
	has := func(fc *FullConfig, name string) bool {
		fc.PolicyOptions = &config.PolicyOptionsConfig{}
		for _, id := range beltRouteMapIdentities16867(fc) {
			if id.identity == name {
				return true
			}
		}
		return false
	}
	for _, name := range []string{nhtMapA19083, nhtMapB19083} {
		if !has(clusterFC19083(true), name) {
			t.Errorf("cluster belt lacks %s", name)
		}
		if has(clusterFC19083(false), name) {
			t.Errorf("standalone belt carries %s, which standalone never emits", name)
		}
	}
}

// TestApplyFullRefusesStaticNHTNameCollision19083: the tolerant path (a lenient
// load or a peer-synced config, which only WARN on the reserved suffix) can
// carry an operator policy-statement whose route-map renders to a generated
// NHT map's final name; FRR would merge the two route-maps and the operator's
// sequences would decide static next-hop tracking. ApplyFull must refuse
// before any write or reload. Control: the same operator policy in standalone
// (no generated map) applies.
func TestApplyFullRefusesStaticNHTNameCollision19083(t *testing.T) {
	for _, name := range []string{nhtMapA19083, nhtMapB19083} {
		t.Run(name, func(t *testing.T) {
			confPath := filepath.Join(t.TempDir(), "frr.conf")
			if err := os.WriteFile(confPath, []byte("log syslog informational\n"), 0644); err != nil {
				t.Fatal(err)
			}
			exec := &fakeExecutor{}
			m := &Manager{frrConf: confPath, exec: exec}
			fc := func(cluster bool) *FullConfig {
				return &FullConfig{
					ClusterMode: cluster,
					BGP: &config.BGPConfig{LocalAS: 64512, Neighbors: []*config.BGPNeighbor{
						{Address: "198.51.100.1", PeerAS: 64513, FamilyInet: true, Import: []string{name}},
					}},
					PolicyOptions: &config.PolicyOptionsConfig{PolicyStatements: map[string]*config.PolicyStatement{
						name: {Name: name, Terms: []*config.PolicyTerm{{Name: "t1", Action: "accept"}}},
					}},
				}
			}
			before, _ := os.ReadFile(confPath)
			err := m.ApplyFull(fc(true))
			if err == nil || !strings.Contains(err.Error(), "#16867") || !strings.Contains(err.Error(), name) {
				t.Fatalf("ApplyFull accepted an operator route-map fused with the generated %s; want a #16867 refusal naming it, got %v", name, err)
			}
			if after, _ := os.ReadFile(confPath); string(after) != string(before) {
				t.Fatalf("refused apply rewrote frr.conf:\n%s", after)
			}
			if exec.frrReloadPyCalls != 0 {
				t.Fatalf("refused apply reloaded FRR %d times", exec.frrReloadPyCalls)
			}
			if err := m.ApplyFull(fc(false)); err != nil {
				t.Fatalf("control: standalone renders no generated NHT map, so the same policy must apply: %v", err)
			}
		})
	}
}

// nhtFake19083 records VtyshConfigLines batches.
type nhtFake19083 struct {
	*fakeExecutor
	mu      sync.Mutex
	batches [][]string
}

func (f *nhtFake19083) VtyshConfigLines(_ context.Context, lines []string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batches = append(f.batches, append([]string(nil), lines...))
	return nil, nil
}

func newNHTManager19083(t *testing.T, cluster bool) (*Manager, *nhtFake19083) {
	t.Helper()
	fake := &nhtFake19083{fakeExecutor: &fakeExecutor{}}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), exec: fake, mgrCtx: ctx, mgrCancel: cancel}
	t.Cleanup(m.Stop)
	if err := m.ApplyFull(clusterFC19083(cluster)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return m, fake
}

// TestReevaluateStaticNHTTogglesAndEndsOnPrimary19083: a forced re-evaluation
// binds the identical alternate map and then the primary again, in one batch,
// for both families, so zebra re-evaluates twice and the running config ends
// exactly as frr.conf renders it. It writes nothing to frr.conf and moves no
// write generation.
func TestReevaluateStaticNHTTogglesAndEndsOnPrimary19083(t *testing.T) {
	m, fake := newNHTManager19083(t, true)
	gen, ugen := m.WriteGeneration(), m.UnconditionalWriteGeneration()
	conf, _ := os.ReadFile(m.frrConf)
	if err := m.ReevaluateStaticNHT19083(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip nht static route-map " + nhtMapB19083, "ipv6 nht static route-map " + nhtMapB19083,
		"ip nht static route-map " + nhtMapA19083, "ipv6 nht static route-map " + nhtMapA19083,
	}
	if len(fake.batches) != 1 || strings.Join(fake.batches[0], "|") != strings.Join(want, "|") {
		t.Fatalf("batches = %q, want one batch %q", fake.batches, want)
	}
	if after, _ := os.ReadFile(m.frrConf); string(after) != string(conf) {
		t.Fatal("re-evaluation rewrote frr.conf")
	}
	if m.WriteGeneration() != gen || m.UnconditionalWriteGeneration() != ugen {
		t.Fatal("re-evaluation moved a write generation")
	}
}

// TestReevaluateStaticNHTNoopWhenUnboundOrStopped19083: standalone (the section
// does not bind the map) and a stopped manager run nothing.
func TestReevaluateStaticNHTNoopWhenUnboundOrStopped19083(t *testing.T) {
	m, fake := newNHTManager19083(t, false)
	if err := m.ReevaluateStaticNHT19083(); err != nil || len(fake.batches) != 0 {
		t.Fatalf("standalone: err=%v batches=%q, want no batch", err, fake.batches)
	}
	m2, fake2 := newNHTManager19083(t, true)
	m2.Stop()
	done := make(chan error, 1)
	go func() { done <- m2.ReevaluateStaticNHT19083() }()
	select {
	case err := <-done:
		if err != nil || len(fake2.batches) != 0 {
			t.Fatalf("stopped: err=%v batches=%q, want no batch", err, fake2.batches)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("re-evaluation on a stopped manager hung")
	}
}

// TestStaticNHTMapCoverageBoundary19083 pins WHICH owned-static renderings the
// #19083 map can act on (R22 #1). staticd consults next-hop tracking only for
// a plain gateway (STATIC_IPV4/IPV6_GATEWAY); a gateway with an interface
// (*_GATEWAY_IFNAME) or an interface alone (STATIC_IFNAME) installs whenever
// the interface exists, so the map has no effect on it.
//   - The DEFAULT v4 shape (`next-hop A`) renders a plain gateway: covered.
//   - The default v6 shape on a RETH subnet is interface-qualified by
//     inference: not covered by the map; it goes inactive through zebra's
//     connected-on-that-interface check once the VIP's subnet leaves.
//   - Operator `qualified-next-hop ... interface`, an interface-only next hop,
//     and a v6 link-local gateway stay active after a graceful stop: the
//     documented residual.
//
// A change that starts interface-qualifying the default v4 shape fails here.
func TestStaticNHTMapCoverageBoundary19083(t *testing.T) {
	nh := func(a, ifc string) []config.NextHopEntry { return []config.NextHopEntry{{Address: a, Interface: ifc}} }
	fc := &FullConfig{
		ClusterMode: true,
		RethMap:     map[string]string{"reth0": "ge-0-0-2"},
		// The v4 key is a canary: were the inference ever applied to v4, the
		// default v4 shape would become interface-qualified and leave the map.
		IPv6NextHopInterfaces: map[string]map[string]string{"": {"2001:db8:50::1": "reth0.50", "172.16.50.1": "reth0.50"}},
		StaticRoutes: []*config.StaticRoute{
			{Destination: "198.51.100.0/24", NextHops: nh("172.16.50.1", "")},
			{Destination: "198.51.100.64/26", NextHops: nh("172.16.50.1", "reth0.50")},
			{Destination: "198.51.100.128/26", NextHops: nh("", "reth0.50")},
		},
		Inet6StaticRoutes: []*config.StaticRoute{
			{Destination: "2001:db8:1::/64", NextHops: nh("2001:db8:50::1", "")},
			{Destination: "2001:db8:2::/64", NextHops: nh("fe80::1", "reth0.50")},
		},
	}
	m := &Manager{}
	var b strings.Builder
	for _, sr := range append(append([]*config.StaticRoute(nil), fc.StaticRoutes...), fc.Inet6StaticRoutes...) {
		b.WriteString(renderStaticRouteWithISISDistanceGuard17735(m, sr, "", 0, fc.RethMap, fc.IPv6NextHopInterfaces, fc.DeclaredNetdevs, nil))
	}
	lines := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 {
			lines[f[2]] = l
		}
	}
	class := func(dest string) string {
		f := strings.Fields(lines[dest])
		if len(f) < 4 {
			return "missing"
		}
		hop := f[3:]
		if n := len(hop); n > 0 && isAllDigits19083(hop[n-1]) {
			hop = hop[:n-1] // admin distance
		}
		gw := strings.ContainsAny(hop[0], ".:") && !strings.HasPrefix(hop[0], "ge-")
		switch {
		case gw && len(hop) == 1:
			return "gateway (map applies)"
		case gw && len(hop) == 2:
			return "gateway+ifname (map bypassed)"
		case !gw && len(hop) == 1:
			return "ifname (no NHT)"
		}
		return "unknown " + lines[dest]
	}
	for dest, want := range map[string]string{
		"198.51.100.0/24":   "gateway (map applies)",
		"198.51.100.64/26":  "gateway+ifname (map bypassed)",
		"198.51.100.128/26": "ifname (no NHT)",
		"2001:db8:1::/64":   "gateway+ifname (map bypassed)",
		"2001:db8:2::/64":   "gateway+ifname (map bypassed)",
	} {
		if got := class(dest); got != want {
			t.Errorf("%s: rendered %q, class %q, want %q", dest, lines[dest], got, want)
		}
	}
}

func isAllDigits19083(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

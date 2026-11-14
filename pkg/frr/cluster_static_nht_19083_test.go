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

package daemon

import (
	"net"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// stale_ifindex_fold_refresh_15263_test.go — #15263 (B05-02), the rebuild half.
//
// buildIngressFoldResolver / buildIngressFoldFn capture net.Interfaces()
// once per config apply. A member netdev recreated without a commit (VF
// reset, re-probe) gets a NEW ifindex; RefreshInterfaceRowsForLink rebuilds
// the Manager's snapshot rows but (pre-fix) never rebuilt the daemon
// closures, so the receive side kept resolving a peer fold to the dead
// ifindex and the importer installed the session with owner RG 0, while the
// send side degraded to fold 0, until the next commit.
//
// refreshIngressFoldClosures is the link-refresh-time rebuild. These cells
// drive it with injected builders (the production builders sample the live
// kernel table; the injected cores are the same code over a fake device
// list) and assert the acceptance from the issue: the stale row equals the
// rebuilt row without a commit.
//
// FAIL-ON-REVERT: removing the refreshIngressFoldClosures call from
// refreshInterfaceRowsForLink (or the helper body) leaves the Manager and
// SessionSync holding the apply-time closures; the "after refresh" cells
// below keep the dead ifindex / fold 0 and go RED.

type staleFoldDP15263 struct {
	*policyInvalTestDP
	manager *dpuserspace.Manager
}

func (d *staleFoldDP15263) Manager() *dpuserspace.Manager { return d.manager }

func staleFoldConfig15263() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"reth0":    {Name: "reth0", RedundancyGroup: 1},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
		}},
		Security: config.SecurityConfig{Zones: map[string]*config.ZoneConfig{
			"trust": {Name: "trust", Interfaces: []string{"reth0"}},
		}},
	}
}

// foldBuilders15263 returns resolver/foldFn builders over a fake device list
// carrying ge-0-0-0 at the given ifindex — the state of the kernel table at
// one point in the recreation sequence.
func foldBuilders15263(liveIndex int) (
	func(*config.Config) func(uint32) (uint32, uint16, bool),
	func(*config.Config) func(uint32, uint16) uint32,
) {
	devs := []net.Interface{{Index: liveIndex, Name: "ge-0-0-0"}}
	resolver := func(cfg *config.Config) func(uint32) (uint32, uint16, bool) {
		return buildIngressFoldResolverWithIfaces(cfg, devs)
	}
	foldFn := func(cfg *config.Config) func(uint32, uint16) uint32 {
		nameByIndex := make(map[uint32]string, len(devs))
		for _, ifc := range devs {
			if ifc.Index > 0 {
				nameByIndex[uint32(ifc.Index)] = ifc.Name
			}
		}
		return func(ifindex uint32, vlan uint16) uint32 {
			if ifindex == 0 {
				return 0
			}
			name := nameByIndex[ifindex]
			if name == "" {
				return 0
			}
			return config.StableIfaceID(cfg.ClusterStableIfaceName(name, vlan))
		}
	}
	return resolver, foldFn
}

func TestLinkRefreshRebuildsStaleFoldClosures15263(t *testing.T) {
	const (
		deadIndex = 17
		liveIndex = 29
	)
	cfg := staleFoldConfig15263()
	fold := config.StableIfaceID("reth0")
	if fold == 0 {
		t.Fatal("fixture: reth0 fold is the unknown sentinel")
	}
	// Apply-time state: closures built when ge-0-0-0 was ifindex 17. The
	// Manager starts with no published snapshot, so its fence is inactive
	// and the stale resolver answers the dead ifindex directly — the
	// pre-fix end state this issue is about.
	applyResolver, applyFoldFn := foldBuilders15263(deadIndex)
	mgr := dpuserspace.New()
	mgr.SetIngressFoldResolver(applyResolver(cfg))
	ss := cluster.NewSessionSync(":0", ":0", nil)
	ss.SetZoneOwnership(buildZoneRGMap(cfg, buildZoneIDs(cfg)), buildZoneFoldRGMap(cfg), applyFoldFn(cfg))

	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.setDataplane(&staleFoldDP15263{
		policyInvalTestDP: &policyInvalTestDP{appliedConfig: cfg},
		manager:           mgr,
	})
	d.sessionSync = ss

	if ifindex, _, ok := mgr.ResolveIngressFoldForTesting(fold); !ok || ifindex != deadIndex {
		t.Fatalf("apply-time Manager resolver = (%d, ok=%v), want dead ifindex %d", ifindex, ok, deadIndex)
	}
	if got := ss.StampIngressFoldForTesting(deadIndex, 0); got != fold {
		t.Fatalf("apply-time send fold(%d) = %d, want %d", deadIndex, got, fold)
	}
	if got := ss.StampIngressFoldForTesting(liveIndex, 0); got != 0 {
		t.Fatalf("apply-time send fold(%d) = %d, want 0 (device not yet present)", liveIndex, got)
	}

	// The link refresh fires after the recreation: closures rebuilt against
	// the live table (ge-0-0-0 now at 29).
	liveResolver, liveFoldFn := foldBuilders15263(liveIndex)
	d.refreshIngressFoldClosures(cfg, liveResolver, liveFoldFn)

	// Acceptance: the stale row equals the rebuilt row without a commit —
	// the Manager now names the live ifindex for the peer fold, and the
	// sender folds the live ifindex and no longer folds the dead one.
	if ifindex, _, ok := mgr.ResolveIngressFoldForTesting(fold); !ok || ifindex != liveIndex {
		t.Fatalf("post-refresh Manager resolver = (%d, ok=%v), want live ifindex %d (stale closure survived the link refresh)", ifindex, ok, liveIndex)
	}
	if got := ss.StampIngressFoldForTesting(liveIndex, 0); got != fold {
		t.Fatalf("post-refresh send fold(%d) = %d, want %d (stale closure survived the link refresh)", liveIndex, got, fold)
	}
	if got := ss.StampIngressFoldForTesting(deadIndex, 0); got != 0 {
		t.Fatalf("post-refresh send fold(%d) = %d, want 0 (dead ifindex still folds)", deadIndex, got)
	}
}

func TestRefreshRebuildsResolverFromLiveTable15263(t *testing.T) {
	// The receive-side acceptance, observed end to end: rebuild the resolver
	// the way refreshIngressFoldClosures does (production builder over the
	// live table) and confirm the peer fold now names the live ifindex, not
	// the dead one the apply-time closure captured.
	const (
		deadIndex = 17
		liveIndex = 29
	)
	cfg := staleFoldConfig15263()
	fold := config.StableIfaceID("reth0")

	staleResolver, _ := foldBuilders15263(deadIndex)
	liveResolver, _ := foldBuilders15263(liveIndex)

	ifindex, _, ok := staleResolver(cfg)(fold)
	if !ok || ifindex != deadIndex {
		t.Fatalf("stale resolver = (%d, ok=%v), want dead ifindex %d", ifindex, ok, deadIndex)
	}
	ifindex, _, ok = liveResolver(cfg)(fold)
	if !ok || ifindex != liveIndex {
		t.Fatalf("rebuilt resolver = (%d, ok=%v), want live ifindex %d", ifindex, ok, liveIndex)
	}
}

func TestRefreshFoldClosuresNilSafe15263(t *testing.T) {
	// Control: no dataplane, no session sync, nil config — the refresh must
	// be a no-op, preserving the neighbouring link-refresh behaviour.
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	d.refreshIngressFoldClosures(nil, nil, nil)
	d.refreshIngressFoldClosures(staleFoldConfig15263(), nil, nil)
}

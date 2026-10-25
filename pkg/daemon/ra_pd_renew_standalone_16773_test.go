package daemon

// #16773: standalone DHCPv6-PD same-lifetime renewal never re-applied RA.
//
// On a fixed-lifetime server a Renew Reply stores Obtained=T1 with identical
// granted lifetimes, so delegatedPrefixesChanged stays false and commitLease
// fires only the unchanged-lease hook — no full recompile, and therefore no
// standalone RA applier runs (reconcileClusterRAServices is cluster-only and
// the 30s loop retries only dead senders). The live sender kept
// ValidExpiresAt=T0+valid and omitted the LAN PIO at that instant while the
// delegation was still held.
//
// Fix: onDHCPUnchangedLease also nudges a depth-1 wake channel; the
// standaloneRARenewLoop owner runs a digest-gated RA-only reconcile under
// applySem. A renewal that moves Obtained moves the digest and re-applies
// with the renewed expiry; a renewal that moves nothing leaves the digest
// unchanged and costs no sender restart (#15057 no-churn, #1777 quiet
// full-compile). Cluster mode is untouched (its 2s digest already moves).

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
)

type raSpy16773 struct {
	mu      sync.Mutex
	applies int
	last    []*config.RAInterfaceConfig
	history [][]*config.RAInterfaceConfig
}

func (s *raSpy16773) apply(cfgs []*config.RAInterfaceConfig) error {
	s.mu.Lock()
	s.applies++
	s.last = cfgs
	s.history = append(s.history, cfgs)
	s.mu.Unlock()
	return nil
}

func (s *raSpy16773) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applies
}

func (s *raSpy16773) lastApplied() []*config.RAInterfaceConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// standalonePDDaemon16773 builds a standalone daemon with one PD-fed RA
// interface (ge-0/0/1.0 fed by a PD on ge-0/0/3), an RA applier spy, and the
// renew wake channel. The DHCP manager is seeded through the RA-testing
// seam (which installs the RA target); renewals below replace the stored
// PD set and drive the real unchanged-lease hook.
func standalonePDDaemon16773(t *testing.T, obtained time.Time, pref, valid time.Duration) (*Daemon, *dhcp.Manager, *raSpy16773) {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet6 {
                address 2001:db8:1::1/64;
            }
        }
    }
}
protocols {
    router-advertisement {
        interface ge-0/0/1.0 {
        }
    }
}
security {
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster != nil {
		t.Fatal("fixture must be a standalone committed config")
	}

	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "ge-0/0/1.0", []dhcp.DelegatedPrefix{pdAt16773(obtained, pref, valid)})

	d := &Daemon{
		store:                store,
		applySem:             semaphore.NewWeighted(1),
		dhcp:                 mgr,
		hostInboundGapWakeCh: make(chan struct{}, 1),
		raRenewWakeCh:        make(chan struct{}, 1),
	}
	mgr.SetUnchangedLeaseCallback(d.onDHCPUnchangedLease)

	spy := &raSpy16773{}
	d.raApplyFn = spy.apply
	// Guard the fixture premise: the PD must surface as one RA prefix.
	ras := d.buildRAConfigs(cfg)
	if len(ras) != 1 || len(ras[0].Prefixes) != 1 {
		t.Fatalf("fixture buildRAConfigs = %+v, want one interface/one prefix", ras)
	}
	return d, mgr, spy
}

func pdAt16773(obtained time.Time, pref, valid time.Duration) dhcp.DelegatedPrefix {
	return dhcp.DelegatedPrefix{
		Interface:         "ge-0/0/3",
		Prefix:            netip.MustParsePrefix("2001:db8:1000::/48"),
		PreferredLifetime: pref,
		ValidLifetime:     valid,
		Obtained:          obtained,
	}
}

func onlyAppliedPrefix16773(t *testing.T, cfgs []*config.RAInterfaceConfig) *config.RAPrefix {
	t.Helper()
	for _, c := range cfgs {
		if c != nil && len(c.Prefixes) == 1 {
			return c.Prefixes[0]
		}
	}
	t.Fatalf("want one applied prefix, got %+v", cfgs)
	return nil
}

// TestStandalonePDIdenticalRenewalReappliesRA16773 is the acceptance cell:
// a standalone daemon renews a PD with identical lifetimes (fresh Obtained)
// and the applied RA config must carry the renewed ValidExpiresAt. RED on
// the pre-fix tree: onDHCPUnchangedLease never nudged any RA owner, so the
// renew reconcile applies nothing beyond the initial converge.
func TestStandalonePDIdenticalRenewalReappliesRA16773(t *testing.T) {
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	d, mgr, spy := standalonePDDaemon16773(t, t0, 3600*time.Second, 7200*time.Second)

	// Converge the initial standalone state (as the boot/commit apply would)
	// and sync the digest to it.
	d.reconcileStandaloneRAServices("initial")
	if got := spy.count(); got != 1 {
		t.Fatalf("initial reconcile applies = %d, want 1", got)
	}
	if p := onlyAppliedPrefix16773(t, spy.lastApplied()); p.ValidExpiresAt != t0.Add(7200*time.Second).UnixNano() {
		t.Fatalf("initial ValidExpiresAt = %d, want %d (T0+7200s)", p.ValidExpiresAt, t0.Add(7200*time.Second).UnixNano())
	}

	// Same-lifetime renewal at T1: identical granted lifetimes, fresh
	// Obtained — the exact shape delegatedPrefixesChanged excludes.
	t1 := t0.Add(time.Hour)
	mgr.ReplaceDelegatedPrefixesForTesting("ge-0/0/3", []dhcp.DelegatedPrefix{pdAt16773(t1, 3600*time.Second, 7200*time.Second)})
	d.onDHCPUnchangedLease()

	// The wake must be pending (non-blocking, coalesced) — the hook runs on
	// the DHCP client goroutine and must never apply inline (#16559).
	select {
	case <-d.raRenewWakeCh:
	default:
		t.Fatal("unchanged PD renewal did not nudge the standalone RA renew owner")
	}
	// Re-arm the wake the drain above consumed, then drive the owner once.
	d.nudgeStandaloneRARenew()
	d.reconcileStandaloneRAOnce(context.Background())

	if got := spy.count(); got != 2 {
		t.Fatalf("applies after identical-lifetime PD renewal = %d, want 2 (renewed expiry must reach ra.Apply)", got)
	}
	p := onlyAppliedPrefix16773(t, spy.lastApplied())
	if want := t1.Add(7200 * time.Second).UnixNano(); p.ValidExpiresAt != want {
		t.Fatalf("renewed ValidExpiresAt = %d, want %d (T1+7200s); sender would omit the PIO at the first lease expiry", p.ValidExpiresAt, want)
	}
	if want := t1.Add(3600 * time.Second).UnixNano(); p.PreferredExpiresAt != want {
		t.Fatalf("renewed PreferredExpiresAt = %d, want %d (T1+3600s)", p.PreferredExpiresAt, want)
	}

	// No-churn control: another wake with no further Obtained move must NOT
	// re-apply (#15057). The digest gate, not the wake, decides.
	d.reconcileStandaloneRAOnce(context.Background())
	if got := spy.count(); got != 2 {
		t.Fatalf("applies after a no-move wake = %d, want 2 (digest must gate the re-apply)", got)
	}
}

// TestStandalonePDCommitLeaseRenewalDrivesRA16773 drives the renewal through
// the real dhcp commitLease predicates: identical lifetimes + fresh Obtained
// must fire ONLY the unchanged-lease hook (no recompile timer), and that hook
// must still deliver the renewed expiry to RA. This binds the dhcp->daemon
// signal, not just the daemon half.
func TestStandalonePDCommitLeaseRenewalDrivesRA16773(t *testing.T) {
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	d, mgr, spy := standalonePDDaemon16773(t, t0, 3600*time.Second, 7200*time.Second)
	d.reconcileStandaloneRAServices("initial")
	if got := spy.count(); got != 1 {
		t.Fatalf("initial applies = %d, want 1", got)
	}

	prevPD := pdAt16773(t0, 3600*time.Second, 7200*time.Second)
	prevLease := &dhcp.Lease{Interface: "ge-0/0/3", Family: dhcp.AFInet6, LeaseTime: 7200 * time.Second, Obtained: t0}
	t1 := t0.Add(time.Hour)
	nextPD := pdAt16773(t1, 3600*time.Second, 7200*time.Second)
	nextLease := &dhcp.Lease{Interface: "ge-0/0/3", Family: dhcp.AFInet6, LeaseTime: 7200 * time.Second, Obtained: t1}
	if err := mgr.CommitLeaseWithPDsForTesting("ge-0/0/3", nextLease, prevLease, []dhcp.DelegatedPrefix{nextPD}, []dhcp.DelegatedPrefix{prevPD}); err != nil {
		t.Fatalf("CommitLeaseWithPDsForTesting: %v", err)
	}
	// commitLease ran onDHCPUnchangedLease synchronously; the wake is queued.
	select {
	case <-d.raRenewWakeCh:
	default:
		t.Fatal("real commitLease renewal did not nudge the standalone RA owner (dhcp->daemon signal missing)")
	}
	d.nudgeStandaloneRARenew()
	d.reconcileStandaloneRAOnce(context.Background())
	if got := spy.count(); got != 2 {
		t.Fatalf("applies after real commitLease renewal = %d, want 2", got)
	}
	p := onlyAppliedPrefix16773(t, spy.lastApplied())
	if want := t1.Add(7200 * time.Second).UnixNano(); p.ValidExpiresAt != want {
		t.Fatalf("ValidExpiresAt after commitLease renewal = %d, want %d", p.ValidExpiresAt, want)
	}
}

// TestStandaloneRenewLoopTicks16773 binds the loop body: a wake drives one
// reconcile and the loop stops on cancellation.
func TestStandaloneRenewLoopTicks16773(t *testing.T) {
	t0 := time.Now().Add(-time.Hour).Truncate(time.Second)
	d, mgr, spy := standalonePDDaemon16773(t, t0, 3600*time.Second, 7200*time.Second)
	d.reconcileStandaloneRAServices("initial")
	if got := spy.count(); got != 1 {
		t.Fatalf("initial applies = %d, want 1", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.standaloneRARenewLoop(ctx)
	}()

	t1 := t0.Add(time.Hour)
	mgr.ReplaceDelegatedPrefixesForTesting("ge-0/0/3", []dhcp.DelegatedPrefix{pdAt16773(t1, 3600*time.Second, 7200*time.Second)})
	d.nudgeStandaloneRARenew()

	deadline := time.Now().Add(5 * time.Second)
	for spy.count() != 2 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("renew loop did not re-apply after wake; applies=%d want 2", spy.count())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("standaloneRARenewLoop did not stop on ctx cancel")
	}
}

// TestStandaloneRenewClusterNoop16773: the renew reconcile must not apply a
// standalone desired set in cluster mode — cluster RA stays owned solely by
// reconcileClusterRAServices. RED if the standalone branch leaks into
// cluster (two owners applying different desired sets).
func TestStandaloneRenewClusterNoop16773(t *testing.T) {
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
chassis {
    cluster {
        cluster-id 1;
        node 0;
        authentication-key "cyaLE6jUXcHqZBB6xSJP7CVc5S9dHRBAtF5vTBqFEss=";
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig().Chassis.Cluster == nil {
		t.Fatal("fixture must commit a CLUSTER config")
	}
	spy := &raSpy16773{}
	d := &Daemon{store: store, applySem: semaphore.NewWeighted(1), raApplyFn: spy.apply, raRenewWakeCh: make(chan struct{}, 1)}
	d.reconcileStandaloneRAServices("pd-renewal")
	d.reconcileStandaloneRAOnce(context.Background())
	if got := spy.count(); got != 0 {
		t.Fatalf("standalone renew reconcile applied %d times in cluster mode, want 0 (cluster RA is owned by reconcileClusterRAServices)", got)
	}
}

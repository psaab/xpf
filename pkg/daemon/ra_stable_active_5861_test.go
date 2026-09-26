package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/psaab/xpf/pkg/ra"
	"golang.org/x/sync/semaphore"
)

// recordingSlogHandler records the messages of every slog record it is asked to
// handle at or above its level, so a test can assert whether a particular log
// line fired (and how often). Used to prove a per-poll-tick line was demoted
// below Info (#6036).
type recordingSlogHandler struct {
	mu    sync.Mutex
	level slog.Level
	msgs  []string
}

func (h *recordingSlogHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *recordingSlogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}

func (h *recordingSlogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *recordingSlogHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *recordingSlogHandler) count(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, m := range h.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

// raApplySpy records every desired set handed to ra.Apply so a test can assert
// exactly what the daemon would transmit. It stands in for the concrete
// *ra.Manager via the d.raApplyFn hook (mirrors startupGoodbyeWithdrawFn, #5093).
type raApplySpy struct {
	mu    sync.Mutex
	calls [][]*config.RAInterfaceConfig
}

func (s *raApplySpy) apply(desired []*config.RAInterfaceConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy the slice header so a later in-place reuse by the caller cannot
	// mutate a recorded call.
	cp := append([]*config.RAInterfaceConfig(nil), desired...)
	s.calls = append(s.calls, cp)
	return nil
}

func (s *raApplySpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *raApplySpy) last() []*config.RAInterfaceConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return nil
	}
	return s.calls[len(s.calls)-1]
}

// appliedPrefixes flattens the prefixes of the last applied desired set.
func (s *raApplySpy) lastPrefixes() []string {
	var out []string
	for _, ra := range s.last() {
		for _, p := range ra.Prefixes {
			out = append(out, p.Prefix)
		}
	}
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// raClusterStore builds a real config store committing a single-reth cluster
// config: reth0 in RG1 (members ge-0/0/0 node0 + ge-7/0/0 node1), unit 50 tagged
// VLAN 50, and a router-advertisement on reth0.50 advertising `prefix`. The
// resolved RA interface is "ge-0-0-0.50" (verified against rethInterfacesForRG).
func raClusterStore(t *testing.T, prefix string) *configstore.Store {
	t.Helper()
	s, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set chassis cluster cluster-id 1\n" +
			"set chassis cluster authentication-key test-cluster-psk-6611\n" +
			"set chassis cluster node 0\n" +
			"set chassis cluster redundancy-group 1 node 0 priority 200\n" +
			"set chassis cluster redundancy-group 1 node 1 priority 100\n" +
			"set interfaces reth0 redundant-ether-options redundancy-group 1\n" +
			"set interfaces reth0 unit 50 vlan-id 50\n" +
			"set interfaces ge-0/0/0 gigether-options redundant-parent reth0\n" +
			"set interfaces ge-7/0/0 gigether-options redundant-parent reth0\n" +
			"set protocols router-advertisement interface reth0.50 prefix " + prefix + "\n",
	); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	s.ExitConfigure()
	return s
}

// TestClusterRAStableActiveReappliesOnCommit is the #5861 stable-active
// regression. A day-2 RA edit (a new prefix added) on an RG that stays MASTER —
// with NO ownership transition — must re-apply RA on this active owner. Before
// #5861 the cluster commit path SKIPPED ra.Apply (RA was managed only by VRRP
// ownership events) and the reconcile loop re-applied RA only on an rg_active
// transition (`if tr.Changed`), so the primary kept advertising the OLD prefix
// set until failover/restart.
//
// The test drives the real commit entrypoint (applyServicesReconcile) so it
// binds the actual wiring: reverting the fix (deleting the
// `if isCluster { d.reconcileClusterRAServices("commit") }` call) makes the spy
// never see the new prefix on the stable-active RG → RED.
func TestClusterRAStableActiveReappliesOnCommit(t *testing.T) {
	const p1 = "2001:db8:1::/64"
	const p2 = "2001:db8:aaaa::/64" // added day-2, no ownership change

	s := raClusterStore(t, p1)
	spy := &raApplySpy{}
	d := &Daemon{
		store:     s,
		applySem:  semaphore.NewWeighted(1),
		rgStates:  make(map[int]*rgStateMachine),
		raApplyFn: spy.apply,
	}
	// This node is the CURRENT active owner of RG1 (MASTER). No transition
	// happens for the rest of the test — ownership is stable.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)

	// Initial commit while MASTER: RA senders come up advertising p1.
	if _, _ = d.applyServicesReconcile(s.ActiveConfig()); spy.count() == 0 {
		t.Fatal("initial cluster commit did not apply RA on the active owner")
	}
	if got := spy.lastPrefixes(); !contains(got, p1) {
		t.Fatalf("initial apply missing %s; got prefixes %v", p1, got)
	}
	initialCalls := spy.count()

	// Day-2 RA edit: add prefix p2. Ownership does NOT change.
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadSet(
		"set protocols router-advertisement interface reth0.50 prefix " + p2 + "\n"); err != nil {
		t.Fatalf("LoadSet day-2 edit: %v", err)
	}
	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit day-2 edit: %v", err)
	}
	s.ExitConfigure()

	// The commit reconcile MUST re-apply RA with the new desired set even though
	// no VRRP/cluster transition occurred (#5861 core fix).
	d.applyServicesReconcile(s.ActiveConfig())
	if spy.count() == initialCalls {
		t.Fatal("day-2 RA edit on a stable-active RG did not reach ra.Apply " +
			"(the #5861 bug — RA never re-applies without an ownership transition)")
	}
	got := spy.lastPrefixes()
	if !contains(got, p2) {
		t.Fatalf("stable-active re-apply missing the newly-added prefix %s; got %v", p2, got)
	}
	if !contains(got, p1) {
		t.Fatalf("stable-active re-apply dropped the retained prefix %s; got %v", p1, got)
	}
}

// TestClusterRADemotionRaceDoesNotTransmit is the #5861 demotion-race guard. A
// config apply that RACES a demotion — the node was MASTER for RG1 when the
// commit began but rg-state flipped to BACKUP before the RA apply — must NOT
// re-arm/transmit RA on the now-inactive node. The guard is the at-apply-time
// owner check in desiredClusterRA: the desired set is filtered by the ownership
// snapshot taken under raReconcileMu, and the demote path updates rg-state
// BEFORE it drives the RA reconcile, so under the lock the snapshot always
// reflects the true current owner.
//
// Reverting the guard (dropping the `if !active { continue }` owner filter in
// desiredClusterRA) makes the demoted node keep RG1's interface in the desired
// set → the stale senders keep transmitting → RED.
func TestClusterRADemotionRaceDoesNotTransmit(t *testing.T) {
	const p1 = "2001:db8:1::/64"
	s := raClusterStore(t, p1)
	spy := &raApplySpy{}
	d := &Daemon{
		store:     s,
		rgStates:  make(map[int]*rgStateMachine),
		raApplyFn: spy.apply,
	}

	// Node is MASTER for RG1: prime the active RA senders (advertising p1).
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	d.reconcileClusterRAServices("commit")
	if !contains(spy.lastPrefixes(), p1) {
		t.Fatalf("precondition: active owner must advertise %s; got %v", p1, spy.lastPrefixes())
	}

	// DEMOTION: rg-state flips to BACKUP (this is exactly what the VRRP demote
	// path does BEFORE it drives the RA withdraw). The commit that was in flight
	// now reaches its RA apply — but the node is no longer the owner.
	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	d.reconcileClusterRAServices("commit-racing-demotion")

	// The now-inactive node must NOT be transmitting RG1's RA. The last apply is
	// a withdraw (empty desired set), and no recorded apply after the demotion
	// carries the demoted interface.
	if got := spy.lastPrefixes(); len(got) != 0 {
		t.Fatalf("demoted node still transmitting RA prefixes %v — demotion-race "+
			"guard failed (re-armed RA on an inactive owner)", got)
	}
	for _, ra := range spy.last() {
		if ra.Interface == "ge-0-0-0.50" {
			t.Fatalf("demoted node's desired set still includes %s — the owner "+
				"gate did not drop the demoted RG", ra.Interface)
		}
	}
}

// TestClusterRAMultiPDPrefixOrderStableNoFlap is the #6036 fold guard. When 2+
// DHCPv6-PD-delegated prefixes target the SAME RA interface, buildRAConfigs
// appends them in DelegatedPrefixesForRA's map-iteration order (m.delegatedPDs
// is a map — nondeterministic across ranges). raDesiredHash marshals
// order-sensitively and ra.configEqual compares prefixes index-by-index, so an
// unsorted within-interface order makes the every-2s periodic cluster reconcile
// FLAP the desired-set digest → a spurious ra.Apply (sub-second RA gap + a
// per-poll-tick apply log the project's logging discipline forbids).
//
// desiredClusterRA now sorts each interface's Prefixes by a stable total key, so
// the digest is invariant to the source order. This test seeds two PD sources
// feeding one RA interface (reth0.50), runs reconcileClusterRAServices many times
// on a stable-active owner, and asserts BOTH:
//
//   - ra.Apply is called exactly ONCE across all passes (the hash never flaps),
//     and
//   - the applied prefixes are in deterministic sorted order.
//
// Reverting the sort (the `for _, ra := range desired { sortRAPrefixes(...) }`
// loop in desiredClusterRA) reds both assertions: the applied prefixes come out
// in map order (not sorted → second assertion RED) and that order varies between
// passes (digest flaps → ra.Apply re-fires → first assertion RED).
func TestClusterRAMultiPDPrefixOrderStableNoFlap(t *testing.T) {
	// Static RA prefix sorts into the MIDDLE of the PD prefixes, so no
	// map-iteration interleaving of the two PD sources yields a globally sorted
	// sequence — the sorted-order assertion is deterministically RED on revert.
	const staticPrefix = "2001:db8:50::/64"
	s := raClusterStore(t, staticPrefix)

	// Two PD sources, each contributing two /64s to the SAME RA interface
	// (reth0.50). Each source's own slice is reverse-sorted; combined with the
	// nondeterministic cross-source map order, the pre-fix append order is never
	// sorted.
	mgr := dhcp.NewManagerForTesting(nil)
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/3", "reth0.50", []dhcp.DelegatedPrefix{
		{Interface: "ge-0/0/3", Prefix: netip.MustParsePrefix("2001:db8:40::/64")},
		{Interface: "ge-0/0/3", Prefix: netip.MustParsePrefix("2001:db8:10::/64")},
	})
	mgr.SeedDelegatedPrefixesForRATesting("ge-0/0/4", "reth0.50", []dhcp.DelegatedPrefix{
		{Interface: "ge-0/0/4", Prefix: netip.MustParsePrefix("2001:db8:90::/64")},
		{Interface: "ge-0/0/4", Prefix: netip.MustParsePrefix("2001:db8:60::/64")},
	})

	spy := &raApplySpy{}
	d := &Daemon{
		store:     s,
		dhcp:      mgr,
		rgStates:  make(map[int]*rgStateMachine),
		raApplyFn: spy.apply,
	}
	// Stable-active owner of RG1 — no transition for the rest of the test.
	d.getOrCreateRGState(1).SetVRRP("reth0", true)

	// Capture Info+ logs so we can prove buildRAConfigs' per-PD-prefix line does
	// NOT fire on the periodic path (it is a pure builder re-run every ~2s, so an
	// Info there is per-poll-tick spam — #6036). The handler drops anything below
	// Info, so a correctly-demoted slog.Debug is invisible here.
	rec := &recordingSlogHandler{level: slog.LevelInfo}
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(rec))
	defer slog.SetDefault(prevLogger)

	// Drive the periodic reconcile many times. Each pass re-derives the desired
	// set (re-ranging m.delegatedPDs), so the digest must be invariant to the
	// map order for the hash gate to hold ra.Apply at a single call.
	const passes = 64
	for i := 0; i < passes; i++ {
		d.reconcileClusterRAServices("periodic")
	}

	if got := spy.count(); got != 1 {
		t.Fatalf("cluster RA reconcile flapped: ra.Apply called %d times across %d "+
			"stable reconciles, want exactly 1 (unsorted per-interface prefix order "+
			"made the desired-set digest nondeterministic — #6036)", got, passes)
	}

	got := spy.lastPrefixes()
	want := append([]string(nil), got...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("applied RA prefixes are not in deterministic sorted order:\n got  %v\n want %v\n"+
			"(desiredClusterRA must sort each interface's Prefixes — #6036)", got, want)
	}
	// Sanity: every seeded prefix plus the static one made it through.
	for _, p := range []string{staticPrefix, "2001:db8:40::/64", "2001:db8:10::/64",
		"2001:db8:90::/64", "2001:db8:60::/64"} {
		if !contains(got, p) {
			t.Fatalf("applied RA set dropped prefix %s; got %v", p, got)
		}
	}

	// buildRAConfigs runs on EVERY periodic pass (desiredClusterRA re-derives the
	// set each tick), so its per-PD-prefix advertise line must be below Info or it
	// is per-poll-tick spam. With the demote to slog.Debug it never reaches the
	// Info-level handler. Reverting daemon_ra.go's slog.Debug back to slog.Info
	// makes it fire once per PD prefix per pass (4*64) → this reds.
	if n := rec.count("DHCPv6 PD: advertising prefix via RA"); n != 0 {
		t.Fatalf("buildRAConfigs logged the PD-advertise line at Info %d times across "+
			"%d periodic reconciles — per-poll-tick Info spam; it must be slog.Debug (#6036)",
			n, passes)
	}
}

type sharedLLClearSpy10779 struct {
	calls    [][]string
	statuses []ra.SenderInfo
}

func (s *sharedLLClearSpy10779) ClearInterfacesWithoutGoodbye(names []string) error {
	s.calls = append(s.calls, append([]string(nil), names...))
	return nil
}

func (s *sharedLLClearSpy10779) Status() []ra.SenderInfo { return s.statuses }

func TestStartupGoodbyeSkipsSharedStableRethIdentity10779(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1077:9::/64")
	cfg := store.ActiveConfig()
	d := &Daemon{}
	raConfigs := d.buildRAConfigs(cfg)
	if len(raConfigs) != 1 {
		t.Fatalf("buildRAConfigs returned %d interfaces, want 1", len(raConfigs))
	}
	sharedSource := cluster.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, 1).String()
	if raConfigs[0].SourceLinkLocal != sharedSource {
		t.Fatalf("test config source = %q, want shared source %q",
			raConfigs[0].SourceLinkLocal, sharedSource)
	}

	perNode := *raConfigs[0]
	perNode.Interface = "ge-7-0-0.50"
	perNode.SourceLinkLocal = "fe80::face"
	got := startupGoodbyeConfigs([]*config.RAInterfaceConfig{raConfigs[0], &perNode})
	if len(got) != 1 || got[0] != &perNode {
		t.Fatalf("startup goodbye targets = %v, want only per-node source %q",
			got, perNode.SourceLinkLocal)
	}
}

func TestDemotionStopsOnlySharedSourceRAWithoutGoodbye10779(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1077:9::/64")
	cfg := store.ActiveConfig()
	d := &Daemon{}
	raConfigs := d.buildRAConfigs(cfg)
	perNode := *raConfigs[0]
	perNode.Interface = "ge-7-0-0.50"
	perNode.SourceLinkLocal = "fe80::face"
	clearer := &sharedLLClearSpy10779{
		statuses: []ra.SenderInfo{
			{Interface: raConfigs[0].Interface, SrcAddr: raConfigs[0].SourceLinkLocal, State: "active"},
			{Interface: perNode.Interface, SrcAddr: perNode.SourceLinkLocal, State: "active"},
		},
	}
	if err := clearRethRASendersWithoutGoodbye(clearer, cfg, 1); err != nil {
		t.Fatalf("clear demoted RG senders: %v", err)
	}
	if len(clearer.calls) != 1 {
		t.Fatalf("scoped clear calls = %d, want 1", len(clearer.calls))
	}
	if !reflect.DeepEqual(clearer.calls[0], []string{raConfigs[0].Interface}) {
		t.Fatalf("cleared interfaces = %v, want only shared source %s",
			clearer.calls[0], raConfigs[0].Interface)
	}
}
func TestClusterRADemotionSilentlyClearsSharedIdentity10789(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1::/64")
	spy := &raApplySpy{}
	var events []string
	var cleared [][]string
	d := &Daemon{
		store:                 store,
		rgStates:              make(map[int]*rgStateMachine),
		raStatusFn: func() []ra.SenderInfo {
			return []ra.SenderInfo{{
				Interface: "ge-0-0-0.50",
				SrcAddr:   cluster.StableRethLinkLocal(1, 1).String(),
				State:     "active",
			}}
		},
		raApplyFn:             func(desired []*config.RAInterfaceConfig) error {
			events = append(events, "apply")
			return spy.apply(desired)
		},
		raClearInterfacesFn: func(names []string) error {
			events = append(events, "clear")
			cleared = append(cleared, append([]string(nil), names...))
			return nil
		},
	}
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	d.reconcileClusterRAServices("master")
	if len(cleared) != 0 {
		t.Fatalf("active shared identity was silently cleared: %v", cleared)
	}
	if len(spy.last()) != 1 {
		t.Fatalf("active owner did not retain its RA sender: %+v", spy.last())
	}
	// On demotion, stopping the local sender must not withdraw the shared
	// default-router identity that the peer may already be advertising.
	events = nil
	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	d.clearRethServicesForRG(1)
	if len(cleared) != 1 || !reflect.DeepEqual(cleared[0], []string{"ge-0-0-0.50"}) {
		t.Fatalf("demotion silent-stop names=%v, want [[ge-0-0-0.50]]", cleared)
	}
	if !reflect.DeepEqual(events, []string{"clear", "apply"}) {
		t.Fatalf("demotion RA reconciliation calls=%v, want [clear apply]", events)
	}
	if got := spy.lastPrefixes(); len(got) != 0 {
		t.Fatalf("demoted node remains in desired RA set: %v", got)
	}
}

func TestClusterRADemotionConfigRemovalUsesLiveSharedSource10789(t *testing.T) {
	store := raClusterStore(t, "2001:db8:1::/64")
	sharedSource := cluster.StableRethLinkLocal(1, 1).String()
	var events []string
	var cleared [][]string
	spy := &raApplySpy{}
	d := &Daemon{
		store:    store,
		rgStates: make(map[int]*rgStateMachine),
		raStatusFn: func() []ra.SenderInfo {
			return []ra.SenderInfo{{
				Interface: "ge-0-0-0.50",
				SrcAddr:   sharedSource,
				State:     "active",
			}}
		},
		raApplyFn: func(desired []*config.RAInterfaceConfig) error {
			events = append(events, "apply")
			return spy.apply(desired)
		},
		raClearInterfacesFn: func(names []string) error {
			events = append(events, "clear")
			cleared = append(cleared, append([]string(nil), names...))
			return nil
		},
	}
	d.getOrCreateRGState(1).SetVRRP("reth0", true)
	d.reconcileClusterRAServices("before-config-removal")
	if len(spy.last()) != 1 || len(cleared) != 0 {
		t.Fatalf("test precondition: active owner had applied=%d clear=%v", len(spy.last()), cleared)
	}
	events = nil
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSet("delete protocols router-advertisement"); err != nil {
		t.Fatalf("remove RA config: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("commit RA removal: %v", err)
	}
	store.ExitConfigure()
	if got := len(store.ActiveConfig().Protocols.RouterAdvertisement); got != 0 {
		t.Fatalf("test precondition: retained %d RA configs after deletion", got)
	}

	d.getOrCreateRGState(1).SetVRRP("reth0", false)
	d.clearRethServicesForRG(1)
	if !reflect.DeepEqual(events, []string{"clear", "apply"}) {
		t.Fatalf("demotion after config removal calls=%v, want [clear apply]", events)
	}
	if !reflect.DeepEqual(cleared, [][]string{{"ge-0-0-0.50"}}) {
		t.Fatalf("demotion after config removal cleared=%v, want shared sender", cleared)
	}
	if len(spy.lastPrefixes()) != 0 {
		t.Fatalf("demoted sender remains desired after config removal: %v", spy.lastPrefixes())
	}
}

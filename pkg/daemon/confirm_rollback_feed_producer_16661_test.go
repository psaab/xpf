package daemon

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/feeds"
)

// #16661 (R3-A32-01): a `commit confirmed` that removes or renames a
// dynamic-address feed can leave its rollback target without a producer. C1
// binds dyn1 to `malware`; C2 removes/renames that feed.
//
// #17741: restarting the target producer invokes the real feeds callback.
// Re-applying active C2 there cancels the just-restarted producer and removes
// its snapshot, so every timer can restart the deferral budget forever. The
// daemon now defers that active-config callback while the target producer is
// installed. This regression waits for the real callback to return before the
// next timer fire, then proves the C1 producer and snapshot survived.
//
// Acceptance: remove and rename cases apply C1 with bootstrap=false; controls
// remain unchanged.

// feedTargetText16661 builds C1 (host c1-feed-target) via set commands so the
// feed-server URL can point at the httptest server.
func feedTargetText16661(t *testing.T, url, feedName string) string {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set system host-name c1-feed-target",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security dynamic-address feed-server threat url " + url,
		"set security dynamic-address feed-server threat allow-destination 127.0.0.0/8",
		"set security dynamic-address feed-server threat feed-name " + feedName + " path /malware.txt",
		"set security dynamic-address address-name dyn1 profile feed-name " + feedName,
		"set security policies from-zone trust to-zone untrust policy p1 match source-address dyn1",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then deny",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	return tree.Format()
}

func abandonedText16661(t *testing.T, url, feedName string) string {
	t.Helper()
	if feedName == "" {
		// C2 removes the feed entirely (static config, no dynamic-address).
		tree := &config.ConfigTree{}
		for _, line := range []string{
			"set system host-name c2-abandoned",
			"set security zones security-zone trust",
			"set security zones security-zone untrust",
			"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
			"set security policies from-zone trust to-zone untrust policy p1 match application any",
			"set security policies from-zone trust to-zone untrust policy p1 then permit",
		} {
			path, err := config.ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand: %v", err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath: %v", err)
			}
		}
		return tree.Format()
	}
	// C2 renames the feed malware -> feedName (same server).
	feedPath := "/malware.txt"
	if feedName == "malware2" {
		feedPath = "/malware2.txt"
	}
	tree := &config.ConfigTree{}
	for _, line := range []string{
		"set system host-name c2-abandoned",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security dynamic-address feed-server threat url " + url,
		"set security dynamic-address feed-server threat allow-destination 127.0.0.0/8",
		"set security dynamic-address feed-server threat feed-name " + feedName + " path " + feedPath,
		"set security policies from-zone trust to-zone untrust policy p1 match source-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	} {
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath: %v", err)
		}
	}
	return tree.Format()
}

type harness16661 struct {
	d                     *Daemon
	s                     *configstore.Store
	applied               *[]string
	targetCallbackSettled <-chan struct{}
}

// setup16661: real feeds.Manager against an httptest TLS feed server.
// C1 is committed and its feed fetched; then `commit confirmed 1` of C2
// (via SyncApply of C1 as tolerant ingress + LoadOverride + CommitConfirmed,
// mirroring armWindowOver9615) — but the apply body runs the REAL
// reconcileFeeds(cfg) for every applied config, exactly the production step
// the defect rests on, so arming C2 cancels the target's producer.
func setup16661(t *testing.T, rename bool) *harness16661 {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/malware2.txt" {
			// Keep C2's renamed producer from invoking an unrelated callback;
			// the callback under test belongs to C1's restarted malware feed.
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	t.Cleanup(server.Close)

	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	applied := &[]string{}
	targetCallbackSettled := make(chan struct{}, 1)
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s, daemonCtx: context.Background()}
	// Keep the real onFeedUpdate path and signal only after it returns. The
	// timer loop waits for that signal before its next fire, so the test cannot
	// race the callback's active-config reconciliation.
	d.feeds = feeds.New(func() error {
		targetFeedCallback := d.confirmTargetFeedInstallPending.Load() != 0
		if targetFeedCallback {
			info, ok := d.feeds.AllFeeds()["malware"]
			targetFeedCallback = ok && info.Prefixes > 0
		}
		err := d.onFeedUpdate()
		if targetFeedCallback {
			select {
			case targetCallbackSettled <- struct{}{}:
			default:
			}
		}
		return err
	})
	d.feeds.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	d.feeds.SetLabFeedTLSRoots(pool)
	t.Cleanup(func() { d.feeds.StopAll() })
	// Stubbed apply body runs ONLY reconcileFeeds (production step at
	// daemon_apply_dataplane.go) plus records the applied host-name.
	d.applyBodyForTest = func(cfg *config.Config) {
		d.reconcileFeeds(cfg)
		if cfg != nil {
			*applied = append(*applied, cfg.System.HostName)
		}
	}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	prev := confirmRollbackFeedRetryInterval
	confirmRollbackFeedRetryInterval = time.Hour
	t.Cleanup(func() {
		confirmRollbackFeedRetryInterval = prev
		_ = s.ConfirmCommit()
	})

	c1 := feedTargetText16661(t, server.URL, "malware")
	// Commit C1 normally (tolerant sync ingress, as armWindowOver9615) and
	// apply it so the malware producer starts and fetches.
	if _, err := s.SyncApply(c1, nil); err != nil {
		t.Fatalf("SyncApply(C1): %v", err)
	}
	if err := d.applyConfigLocked(context.Background(), s.ActiveConfig()); err != nil {
		t.Fatalf("apply C1: %v", err)
	}
	// Wait for the feed snapshot to install.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if got := d.feedSnapshotsForConfig(s.ActiveConfig()); len(got["dyn1"]) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("C1 feed never installed: overlay=%v feeds=%v", d.feedSnapshotsForConfig(s.ActiveConfig()), d.feeds.AllFeeds())
		}
		time.Sleep(5 * time.Millisecond)
	}
	*applied = nil // discard the C1 setup apply; assertions count from the window

	// Arm commit confirmed over C1 with C2, then apply C2 (cancels malware
	// producer on remove; on rename, malware producer cancelled, malware2 starts).
	var c2 string
	if rename {
		c2 = abandonedText16661(t, server.URL, "malware2")
	} else {
		c2 = abandonedText16661(t, server.URL, "")
	}
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(c2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed(C2): %v", err)
	}
	s.ExitConfigure()
	if err := d.applyConfigLocked(context.Background(), s.ActiveConfig()); err != nil {
		t.Fatalf("apply C2: %v", err)
	}
	// Premise: the target's producer is gone.
	if _, ok := d.feeds.AllFeeds()["malware"]; ok {
		t.Fatalf("premise: C2 apply must cancel the malware producer; feeds=%v", d.feeds.AllFeeds())
	}
	if got := d.feedSnapshotsForConfig(mustPendingTarget16661(t, s)); len(got) != 0 {
		t.Fatalf("premise: fire-time overlay for C1 must be empty, got %v", got)
	}
	return &harness16661{d: d, s: s, applied: applied, targetCallbackSettled: targetCallbackSettled}
}

func mustPendingTarget16661(t *testing.T, s *configstore.Store) *config.Config {
	t.Helper()
	target, _, ok := s.PendingRollbackTarget(s.ConfirmGenForTesting())
	if !ok || target == nil {
		t.Fatalf("no pending rollback target (ok=%v target=%v)", ok, target)
	}
	return target
}

func fireUntilApplied16661(t *testing.T, h *harness16661) {
	t.Helper()
	gen := h.s.ConfirmGenForTesting()
	// Wait for the real feed callback and the manager's publication-debt update
	// to settle before the next timer fire; C2 reconciliation cannot race it.
	for range confirmRollbackFeedRetryMax + 10 {
		h.s.InvokeRollbackTimerForTesting(gen)
		if !h.s.IsConfirmPending() {
			return
		}
		select {
		case <-h.targetCallbackSettled:
			deadline := time.Now().Add(2 * time.Second)
			for {
				feed, ok := h.d.feeds.AllFeeds()["malware"]
				if !ok || feed.Prefixes == 0 {
					t.Fatalf("rollback-target callback settled without preserving C1 feed: feed=%+v present=%v",
						feed, ok)
				}
				if feed.PublicationDebt {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("feed manager did not settle the deferred callback as publication debt")
				}
				time.Sleep(time.Millisecond)
			}
			if got := len(h.d.feedSnapshotsForConfig(mustPendingTarget16661(t, h.s))["dyn1"]); got != 1 {
				t.Fatalf("target callback settled without a C1 snapshot: overlay size=%d", got)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("rollback-target feed callback did not settle before next timer fire: "+
				"feeds=%v applied=%v", h.d.feeds.AllFeeds(), *h.applied)
		}
	}
	t.Fatalf("rollback never resolved after %d fires: pending=%v applied=%v bootstrap=%v active=%q",
		confirmRollbackFeedRetryMax+10, h.s.IsConfirmPending(), *h.applied, h.d.inBootstrap(), hostName9615(h.s))
}

func assertAppliedC1NoBootstrap16661(t *testing.T, h *harness16661) {
	t.Helper()
	if h.d.inBootstrap() {
		t.Fatal("rollback entered bootstrap for a feed-only refusal whose producer was absent (#16661)")
	}
	if got := hostName9615(h.s); got != "c1-feed-target" {
		t.Fatalf("store must roll back to c1-feed-target, got %q (applied=%v)", got, *h.applied)
	}
	found := false
	for _, a := range *h.applied {
		if a == "c1-feed-target" {
			found = true
		}
	}
	if !found {
		t.Fatalf("c1-feed-target was never applied; applied=%v", *h.applied)
	}
}

// TestFeedRemovedRollbackReconcilesTargetProducer16661 is the defect arm:
// C2 removes the feed. Before the fix: 25 fires, bootstrap=true, C1 never
// applied. After: C1 applied, bootstrap=false.
func TestFeedRemovedRollbackReconcilesTargetProducer16661(t *testing.T) {
	h := setup16661(t, false)
	fireUntilApplied16661(t, h)
	assertAppliedC1NoBootstrap16661(t, h)
}

// TestFeedRenamedRollbackReconcilesTargetProducer16661 is the rename arm:
// C2 renames malware -> malware2 on the same server.
func TestFeedRenamedRollbackReconcilesTargetProducer16661(t *testing.T) {
	h := setup16661(t, true)
	fireUntilApplied16661(t, h)
	assertAppliedC1NoBootstrap16661(t, h)
}

// TestFeedProducerAbsentClassifier16661 pins the classifier: absent producer
// (removed/renamed) vs present-but-unfetched (late feed, #9615) vs no manager.
func TestFeedProducerAbsentClassifier16661(t *testing.T) {
	target := mustCompile16661(t, feedTargetText16661(t, "https://feeds.example/list.txt", "malware"))

	d := &Daemon{daemonCtx: context.Background()}
	// No manager: cannot prove absence.
	if d.rollbackTargetFeedProducersAbsent(target) {
		t.Fatal("no feed manager must not classify as absent")
	}
	d.ensureFeedManager()
	defer d.feeds.StopAll()
	// No producers at all: malware absent.
	if !d.rollbackTargetFeedProducersAbsent(target) {
		t.Fatal("target feed with no producer must classify absent")
	}
	// Producer present (even unfetched — port 1 fails fast): NOT absent.
	d.reconcileFeeds(mustCompile16661(t, feedTargetText16661(t, "https://127.0.0.1:1/list.txt", "malware")))
	if d.rollbackTargetFeedProducersAbsent(target) {
		t.Fatal("present-but-unfetched producer is the late-feed case, not absent")
	}
	// Producer removed again: absent.
	d.reconcileFeeds(feedCfgWith(nil, nil))
	if !d.rollbackTargetFeedProducersAbsent(target) {
		t.Fatal("after removal the target feed must classify absent again")
	}
}

func mustCompile16661(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) != 0 {
		t.Fatalf("Parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

// TestFeedStillDownAfterProducerRestartStillBounded16661 is the control that
// the fix does not make deferral unbounded: producer restarted for the target
// but its server is down, so no snapshot ever installs — after its own
// bounded window the #9615 safe state is still taken (no infinite deferral).
func TestFeedStillDownAfterProducerRestartStillBounded16661(t *testing.T) {
	// Build the harness manually with a dead feed URL for C1 so the
	// restarted producer never installs.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()

	s := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	applied := &[]string{}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s, daemonCtx: context.Background()}
	d.ensureFeedManager()
	d.feeds.SetPrivateFeedAllowlist([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")})
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	d.feeds.SetLabFeedTLSRoots(pool)
	defer d.feeds.StopAll()
	d.applyBodyForTest = func(cfg *config.Config) {
		d.reconcileFeeds(cfg)
		if cfg != nil {
			*applied = append(*applied, cfg.System.HostName)
		}
	}
	s.SetRollbackExecutor(d.executeConfirmedRollback)
	prev := confirmRollbackFeedRetryInterval
	confirmRollbackFeedRetryInterval = time.Hour
	defer func() { confirmRollbackFeedRetryInterval = prev }()
	defer func() { _ = s.ConfirmCommit() }()

	// C1 against the live server, feed installed.
	c1 := feedTargetText16661(t, server.URL, "malware")
	if _, err := s.SyncApply(c1, nil); err != nil {
		t.Fatalf("SyncApply(C1): %v", err)
	}
	if err := d.applyConfigLocked(context.Background(), s.ActiveConfig()); err != nil {
		t.Fatalf("apply C1: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(d.feedSnapshotsForConfig(s.ActiveConfig())["dyn1"]) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("C1 feed never installed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Kill the feed server: the restarted producer can never fetch.
	server.Close()
	*applied = nil

	// C2 removes the feed; arm + apply (cancels malware producer).
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadOverride(abandonedText16661(t, "", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitConfirmed(1); err != nil {
		t.Fatalf("CommitConfirmed: %v", err)
	}
	s.ExitConfigure()
	if err := d.applyConfigLocked(context.Background(), s.ActiveConfig()); err != nil {
		t.Fatalf("apply C2: %v", err)
	}
	gen := s.ConfirmGenForTesting()
	// Fire well past 2x the cap: must eventually resolve (bootstrap safe
	// state), never defer forever, and never apply the refused target.
	for i := 0; i < 3*confirmRollbackFeedRetryMax+5 && s.IsConfirmPending(); i++ {
		s.InvokeRollbackTimerForTesting(gen)
	}
	if s.IsConfirmPending() {
		t.Fatalf("feed-down rollback deferred forever (pending after %d fires)", 3*confirmRollbackFeedRetryMax+5)
	}
	if !d.inBootstrap() {
		t.Fatal("a feed that never installs (server down, producer running) must still take the bounded #9615 safe state")
	}
	for _, a := range *applied {
		if a == "c1-feed-target" {
			t.Fatalf("refused feed-down target was applied: %v", *applied)
		}
	}
}

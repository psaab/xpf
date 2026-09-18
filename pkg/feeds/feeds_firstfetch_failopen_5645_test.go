package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// feeds_firstfetch_failopen_5645_test.go: #5645 (codex-review-181) — a DIRECT
// feed-bound name published as an empty (match-none) slice BEFORE the first
// successful fetch is a firewall fail-open. A policy that DENIES a direct
// feed-bound address compiles the empty set to a match-none address-book row, so
// the deny never fires and traffic that must be blocked is PERMITTED for the
// whole window until the first fetch succeeds. (#5282 already closes the
// RE-FETCH window by carrying a persisted feed's last-good snapshot forward;
// #5645 is the FIRST-fetch case, where there is no prior good snapshot to keep.)
//
// The fix: SnapshotForBindings OMITS a binding whose feeds all lack an installed
// snapshot, leaving the name UNRESOLVED so the policy lowering fails CLOSED
// (unrepresentable -> __unsupported_address__ -> whole-snapshot preflight
// reject; see pkg/dataplane/userspace TestFeedBackedPolicyRoutesAsBookReference,
// whose no-overlay branch proves the absent-name -> sentinel fail-closed path).

// denyBindingCfg wires a feed-server whose first fetch hits url, plus a
// direct feed-bound address binding "denylist" -> feedName, matching the
// SnapshotForBindings input a deny policy referencing "denylist" produces.
func denyBindingCfg(feedName, url string) *config.DynamicAddressConfig {
	return &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"srv": {Name: "srv", URL: url, FeedName: feedName, UpdateInterval: 3600},
		},
		AddressBindings: map[string]*config.AddressBinding{
			"denylist": {Name: "denylist", FeedNames: []string{feedName}},
		},
	}
}

// TestFirstFetchFailedDenyFeedNotPublishedMatchNone is the core #5645
// fail-on-revert. A direct feed-bound DENY binding whose FIRST fetch is blocked
// (HTTP 500) must NOT publish a present-but-empty (match-none) overlay entry —
// the deny must not fail open. Reverting the SnapshotForBindings omission
// publishes "denylist" as a non-nil empty slice, turning both assertions RED.
func TestFirstFetchFailedDenyFeedNotPublishedMatchNone(t *testing.T) {
	m := newLabManager10177(func() error { return nil })

	// First (and only) fetch fails: the endpoint is DOWN (500). There is NO
	// prior good snapshot — this is the first-fetch case, not the re-fetch window.
	down := &bodyServer{}
	down.set("hijacked-or-error", http.StatusInternalServerError)
	ts := httptest.NewServer(down.handler())
	defer ts.Close()

	const feedName = "threat"
	daCfg := denyBindingCfg(feedName, ts.URL)
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	// Let the first (failing) fetch resolve so we assert the STEADY state, not a
	// pre-fetch race: after the failure there is still no installed snapshot.
	waitFor(t, 2*time.Second, func() bool {
		return m.AllFeeds()[feedName].LastError != ""
	}, "first fetch never recorded a failure")

	// The feed has no installed snapshot (first fetch failed, nothing to retain).
	if got := m.GetPrefixes(feedName); len(got) != 0 {
		t.Fatalf("precondition: a failed first fetch must leave no snapshot; got %v", got)
	}

	// THE FAIL-OPEN SURFACE: the enforcement overlay the daemon hands to the
	// dataplane must OMIT "denylist" — an unresolved name (fail-closed), NOT a
	// present-but-empty (match-none) entry that a deny compiles to fail-open.
	overlay := m.SnapshotForBindings(daCfg)
	if _, published := overlay["denylist"]; published {
		t.Fatalf("fail-open: a direct feed-bound DENY binding was published as "+
			"match-none before the first successful fetch; overlay=%v", overlay)
	}
}

// TestFirstFetchSuccessPublishesFeed is the non-tautological companion: once the
// first fetch SUCCEEDS, the binding IS published with its prefixes. This proves
// the omission is scoped to the unready window and does not suppress a resolved
// feed (a PERMIT feed that fetches non-empty enforces those prefixes, and a
// resolved DENY feed enforces its denylist).
func TestFirstFetchSuccessPublishesFeed(t *testing.T) {
	m := newLabManager10177(func() error { return nil })

	good := &bodyServer{}
	good.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(good.handler())
	defer ts.Close()

	const feedName = "threat"
	daCfg := denyBindingCfg(feedName, ts.URL)
	m.Apply(context.Background(), daCfg)
	defer m.StopAll()

	waitFor(t, 2*time.Second, func() bool {
		got := m.SnapshotForBindings(daCfg)["denylist"]
		return len(got) == 1 && got[0] == "203.0.113.0/24"
	}, "first successful fetch never published the binding")
}

// TestPermitFeedNoMembersOmittedNotFailOpen guards the PERMIT direction. A
// permit feed with no members must NOT start matching anything (that would be a
// permit fail-open). Before the first fetch the binding is omitted (unresolved
// -> the referencing policy fails closed); it never resolves to match-ANY. This
// asserts the fix does not invert the permit case into a fail-open.
func TestPermitFeedNoMembersOmittedNotFailOpen(t *testing.T) {
	m := New(nil)
	// No feed ever started: the binding is unresolved.
	overlay := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"allowlist": {"never-fetched"},
	}))
	if _, published := overlay["allowlist"]; published {
		t.Fatalf("a permit feed with no members must stay unresolved (omitted), never "+
			"resolve to a match-any/empty entry; overlay=%v", overlay)
	}
}

// TestCompositeBindingPartialReadinessOmitted is the codex-182 residual
// fail-on-revert for the COMPOSITE case. A binding that unions a READY feed with
// an UNREADY constituent must be OMITTED entirely — publishing the ready subset
// enforces only a PARTIAL deny set and silently drops the unready feed's
// prefixes (fail-OPEN). Covers the report's ready+unready, ready+unknown, and
// ready+hold-expired acceptance cases. Reverting SnapshotForBindings to require
// only that SOME feed is ready (the old len(merged) != 0 gate) publishes
// "denylist" with just feed-ready's prefixes, turning each assertion RED.
func TestCompositeBindingPartialReadinessOmitted(t *testing.T) {
	cases := []struct {
		name string
		prep func(m *Manager)
	}{
		{
			name: "ready+unready-no-first-fetch",
			prep: func(m *Manager) {
				m.installPrefixes("feed-ready", []string{"198.51.100.0/24"})
				// Registered but never fetched: no installed snapshot.
				m.newFeed("feed-unready", "http://example.test/unready", retainForever)
			},
		},
		{
			name: "ready+unknown",
			prep: func(m *Manager) {
				m.installPrefixes("feed-ready", []string{"198.51.100.0/24"})
				// "feed-unready" is never registered at all (typo'd / not started).
			},
		},
		{
			name: "ready+hold-expired-drop",
			prep: func(m *Manager) {
				m.installPrefixes("feed-ready", []string{"198.51.100.0/24"})
				// A feed that HAD a snapshot but was dropped to empty by a
				// hold-interval expiry (#2050): registered, prefixes cleared.
				m.installPrefixes("feed-unready", []string{"203.0.113.0/24"})
				m.mu.Lock()
				m.feeds["feed-unready"].prefixes = nil
				m.feeds["feed-unready"].hasSnapshot = false
				m.mu.Unlock()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := New(nil)
			tc.prep(m)
			overlay := m.SnapshotForBindings(bindingCfg(map[string][]string{
				"denylist": {"feed-ready", "feed-unready"},
			}))
			if got, published := overlay["denylist"]; published {
				t.Fatalf("fail-open: a composite DENY binding with an unready "+
					"constituent was published as a PARTIAL set %v; it must be omitted "+
					"(unresolved -> fail closed) until ALL feeds are ready", got)
			}
		})
	}
}

// TestCompositeBindingAllReadyPublished is the non-tautological companion: once
// EVERY constituent is ready, the composite binding IS published with the full
// deduped union. Proves the omission is scoped to partial readiness and does not
// suppress a fully-resolved composite feed.
func TestCompositeBindingAllReadyPublished(t *testing.T) {
	m := New(nil)
	m.installPrefixes("feed-a", []string{"198.51.100.0/24"})
	m.installPrefixes("feed-b", []string{"203.0.113.0/24"})
	overlay := m.SnapshotForBindings(bindingCfg(map[string][]string{
		"denylist": {"feed-a", "feed-b"},
	}))
	got, published := overlay["denylist"]
	if !published {
		t.Fatalf("a fully-ready composite binding must be published; overlay=%v", overlay)
	}
	want := []string{"198.51.100.0/24", "203.0.113.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composite union = %v, want %v", got, want)
	}
}

// TestReFetchWindowStillPublishesLastGood proves the #5645 first-fetch omission
// does NOT regress the #5282 re-fetch window: once a feed has a good snapshot, a
// later FAILED refresh keeps the last-good prefixes published (retainForever) —
// the binding stays present, never dropping to the omitted/match-none state.
func TestReFetchWindowStillPublishesLastGood(t *testing.T) {
	m := New(func() error { return nil })

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	const feedName = "threat"
	// Directly install a last-good snapshot via a single successful fetch.
	fs := m.newFeed(feedName, ts.URL, retainForever)
	m.fetchFeed(context.Background(), fs)
	daCfg := denyBindingCfg(feedName, ts.URL)
	if got := m.SnapshotForBindings(daCfg)["denylist"]; len(got) != 1 {
		t.Fatalf("precondition: last-good not published: %v", got)
	}

	// A subsequent refresh FAILS; retainForever keeps the last-good installed.
	srv.set("boom", http.StatusInternalServerError)
	m.fetchFeed(context.Background(), fs)

	overlay := m.SnapshotForBindings(daCfg)
	got, published := overlay["denylist"]
	if !published || len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("re-fetch window regressed: a failed refresh must retain the last-good "+
			"overlay (never omit/match-none); got published=%v value=%v", published, got)
	}
}

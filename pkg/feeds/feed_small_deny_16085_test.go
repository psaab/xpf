package feeds

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// #16085 (A9-14): malformed feed lines silently shrink small deny feeds below
// the shrink-guard floor. parseFeed skips malformed lines and installs the
// valid subset; the drastic-shrink guard is inert below its default floors
// (old < 32, drop < 16, retain >= 50%), so a 10-entry deny feed losing 3
// entries to origin corruption installed a 7-entry set and silently stopped
// enforcing those 3 prefixes — fail-open in exactly the direction the guard
// exists to prevent. The fix refuses a degraded candidate that drops a
// previously-enforced (installed) prefix at ANY size, reusing the
// exact-candidate acknowledgement workflow. Clean candidates, degraded
// candidates that drop nothing installed, first fetches, and remembered-
// baseline bootstraps are unchanged.
//
// Helpers reuse newShrinkFeed11059 / shrinkBody11059 (feed_shrink_11059_test.go)
// and mustParse14994 / coldManager14994 (feed_shrink_14994_test.go).

func prefixes16085(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("198.18.160.%d/32", i))
	}
	return out
}

func body16085(lines []string) string {
	return strings.Join(lines, "\n") + "\n"
}

// corrupt16085 returns lines with the entries at idx replaced by malformed text,
// preserving line count so the valid subset is exactly the uncorrupted entries.
func corrupt16085(lines []string, idx ...int) []string {
	out := append([]string(nil), lines...)
	for _, i := range idx {
		out[i] = "not-a-prefix!!corrupt"
	}
	return out
}

// TestSmallDenyMalformedShrinkRefused16085 is the issue's decisive check: a
// 10-entry deny feed (below every default floor) whose next body corrupts 3
// entries into malformed lines must NOT install the 7-entry subset. Last-good
// (10) stays enforced, nothing new publishes, and the refusal is alarmed via
// the shrink-refusal state. Reverting malformedShrinkTripped16085 (or its
// wiring) installs 7 and turns this RED.
func TestSmallDenyMalformedShrinkRefused16085(t *testing.T) {
	updates := 0
	m, server, fs := newShrinkFeed11059(t, "small-deny-16085", retainForever, func() error {
		updates++
		return nil
	})
	good := prefixes16085(10)
	server.set(body16085(good), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 10 {
		t.Fatalf("seed install: got %d prefixes, want 10", got)
	}
	if updates != 1 {
		t.Fatalf("seed published %d updates, want 1", updates)
	}
	lastSuccess := fs.lastSuccess

	server.set(body16085(corrupt16085(good, 2, 5, 7)), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	if got := m.GetPrefixes(fs.name); len(got) != 10 {
		t.Fatalf("malformed small shrink installed: got %d prefixes %v, want last-good 10 retained", len(got), got)
	}
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused || info.ShrinkRefusalID != 1 ||
		info.ShrinkCandidateOldCount != 10 || info.ShrinkCandidateNewCount != 7 ||
		info.ShrinkRefusalCount != 1 || info.ShrinkCandidateHash == "" ||
		info.ShrinkCandidateReason != "malformed lines dropped previously-enforced prefixes" {
		t.Fatalf("small malformed shrink was not refused/alarmed: %+v", info)
	}
	if !strings.Contains(info.LastError, "malformed lines dropped previously-enforced prefixes") {
		t.Fatalf("refusal error does not name the malformed drop: %q", info.LastError)
	}
	if info.StaleSince.IsZero() || fs.lastSuccess != lastSuccess {
		t.Fatalf("refusal did not retain last-good/stale status: info=%+v lastSuccess=%v want %v", info, fs.lastSuccess, lastSuccess)
	}
	if updates != 1 {
		t.Fatalf("refused malformed candidate published: updates=%d, want 1 (seed only)", updates)
	}
	// The refused fetch must not overwrite the installed set's degraded markers:
	// the enforced 10 are the clean seed, not the degraded candidate.
	if info.Degraded || info.InvalidLines != 0 {
		t.Fatalf("refused candidate overwrote installed degraded markers: %+v", info)
	}
}

// TestSmallDenyMalformedShrinkAckInstalls16085: the exact refused candidate
// installs only after its exact acknowledgement (same workflow as drastic
// shrink), and rebases; a stale tuple does not authorize it.
func TestSmallDenyMalformedShrinkAckInstalls16085(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "small-deny-ack-16085", retainForever, nil)
	good := prefixes16085(10)
	server.set(body16085(good), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(body16085(corrupt16085(good, 2, 5, 7)), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	info := m.AllFeeds()[fs.name]
	if !info.ShrinkRefused {
		t.Fatalf("fixture: candidate not refused: %+v", info)
	}
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, info.ShrinkCandidateHash,
		info.ShrinkBaselineHash, info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount+1,
		"operator=alice", "wrong new count"); err == nil {
		t.Fatal("acknowledgement with wrong new-count was accepted")
	}
	if err := m.AcknowledgeFeedShrink(fs.name, info.ShrinkRefusalID, info.ShrinkCandidateHash,
		info.ShrinkBaselineHash, info.ShrinkCandidateOldCount, info.ShrinkCandidateNewCount,
		"operator=alice", "provider confirmed the 3 corrupted entries are withdrawn"); err != nil {
		t.Fatalf("acknowledging exact malformed candidate: %v", err)
	}
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 7 {
		t.Fatalf("acknowledged malformed candidate did not install: got %d, want 7", got)
	}
	after := m.AllFeeds()[fs.name]
	if after.ShrinkRefused || after.ShrinkGuardHighWaterCount != 7 {
		t.Fatalf("acknowledged install did not clear refusal / rebase high-water: %+v", after)
	}
	// The now-installed degraded set reports its invalid lines.
	if !after.Degraded || after.InvalidLines != 3 {
		t.Fatalf("acknowledged degraded install not marked degraded: %+v", after)
	}
}

// TestMalformedNoInstalledDropInstalls16085 is the no-over-refusal control:
// a degraded candidate that drops NO installed prefix (it adds entries beside
// a garbage line) installs normally below the floors — the guard is keyed to
// dropped enforcement, not to the mere presence of a malformed line.
func TestMalformedNoInstalledDropInstalls16085(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "small-grow-16085", retainForever, nil)
	good := prefixes16085(10)
	server.set(body16085(good), http.StatusOK)
	m.fetchFeed(context.Background(), fs)

	grown := append(append([]string(nil), good...), "198.18.161.0/32", "garbage-line")
	server.set(body16085(grown), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 11 {
		t.Fatalf("degraded growth that drops nothing installed was refused: got %d, want 11", got)
	}
	info := m.AllFeeds()[fs.name]
	if info.ShrinkRefused || !info.Degraded || info.InvalidLines != 1 {
		t.Fatalf("degraded growth status = %+v, want installed + degraded(1), not refused", info)
	}
}

// TestMalformedSingleDropRefused16085 pins "any size, any drop": even ONE
// corrupted entry in a 10-entry feed (retained 9/10, far above the 50% floor)
// is refused — there is no minimum-drop exemption for malformed loss.
func TestMalformedSingleDropRefused16085(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "small-one-16085", retainForever, nil)
	good := prefixes16085(10)
	server.set(body16085(good), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(body16085(corrupt16085(good, 4)), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 10 {
		t.Fatalf("single malformed drop installed: got %d, want 10 retained", got)
	}
	if info := m.AllFeeds()[fs.name]; !info.ShrinkRefused || info.ShrinkCandidateNewCount != 9 {
		t.Fatalf("single malformed drop not refused: %+v", info)
	}
}

// TestMalformedFirstFetchInstalls16085: with no installed set, nothing was
// previously enforced, so a degraded first body still bootstraps its valid
// subset (marked degraded) — the guard must not wedge never-fetched feeds.
func TestMalformedFirstFetchInstalls16085(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "small-first-16085", retainForever, nil)
	good := prefixes16085(10)
	server.set(body16085(corrupt16085(good, 2, 5, 7)), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 7 {
		t.Fatalf("degraded first fetch: got %d, want 7 (bootstrap valid subset)", got)
	}
	if info := m.AllFeeds()[fs.name]; info.ShrinkRefused || !info.Degraded || info.InvalidLines != 3 {
		t.Fatalf("degraded first fetch status = %+v, want installed degraded(3), not refused", info)
	}
}

// TestMalformedCleanShrinkBelowFloorStillInstalls16085 is the scope control:
// a CLEAN (no malformed lines) shrink below the floors is a provider-authored
// reduction, not corruption — it keeps installing exactly as before. The
// #16085 guard must not become a general small-feed shrink guard.
func TestMalformedCleanShrinkBelowFloorStillInstalls16085(t *testing.T) {
	m, server, fs := newShrinkFeed11059(t, "small-clean-16085", retainForever, nil)
	good := prefixes16085(10)
	server.set(body16085(good), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	server.set(body16085(good[:7]), http.StatusOK)
	m.fetchFeed(context.Background(), fs)
	if got := len(m.GetPrefixes(fs.name)); got != 7 {
		t.Fatalf("clean below-floor shrink changed behaviour: got %d, want 7 installed", got)
	}
	if info := m.AllFeeds()[fs.name]; info.ShrinkRefused {
		t.Fatalf("clean below-floor shrink was refused (out of #16085 scope): %+v", info)
	}
}

// TestMalformedColdBootstrapNotRefused16085: a remembered-baseline feed with
// no live snapshot (cold restart) whose first body is degraded but at/above
// the #14994 floors installs with the audit warning — the malformed guard is
// live-snapshot only and must not wedge it. (A below-floor cold candidate is
// already refused by #14994, malformed or not.)
func TestMalformedColdBootstrapNotRefused16085(t *testing.T) {
	m0, server0, fs0 := newShrinkFeed11059(t, "cold-malformed-16085", retainForever, nil)
	server0.set(shrinkBody11059(100), http.StatusOK)
	m0.fetchFeed(context.Background(), fs0)
	seedRes := mustParse14994(t, shrinkBody11059(100))
	snap := []ShrinkHighWater{{
		Name: "cold-malformed-16085", Count: 100, Hash: hashHex14994(seedRes.hash),
		Prefixes: append([]string(nil), seedRes.prefixes...), EpochHash: hashHex14994(seedRes.hash),
	}}

	m2, fs2 := coldManager14994(t, snap, "cold-malformed-16085")
	// 60 of the restored 100, plus 5 garbage lines: above the 50% retain floor
	// and a 40 drop (>= 16) — installs under #14994 despite being degraded.
	cand := append(append([]string(nil), seedRes.prefixes[:60]...),
		"junk-1", "junk-2", "junk-3", "junk-4", "junk-5")
	res, err := parseFeed(strings.NewReader(body16085(cand)))
	if err != nil {
		t.Fatal(err)
	}
	if res.invalidLines != 5 {
		t.Fatalf("fixture: invalidLines=%d, want 5", res.invalidLines)
	}
	m2.installSnapshot(fs2, res)
	if got := len(m2.GetPrefixes("cold-malformed-16085")); got != 60 {
		t.Fatalf("degraded cold bootstrap at/above floors: got %d, want 60 installed", got)
	}
	if info := m2.AllFeeds()["cold-malformed-16085"]; info.ShrinkRefused {
		t.Fatalf("degraded cold bootstrap was refused (malformed guard leaked to no-snapshot path): %+v", info)
	}
}

// TestMalformedShrinkTripped16085 unit-pins the helper's truth table,
// including the canonical-order precondition (both slices sorted/deduped, as
// parseFeed and the installed snapshot always are).
func TestMalformedShrinkTripped16085(t *testing.T) {
	installed := prefixes16085(10) // canonicalize-sorted? ensure sorted order below
	// prefixes16085 is already in ascending lexical order for .0-.9 single digits
	// with equal prefix length... verify via canonicalize to be safe.
	installed = canonicalize(installed)
	subset := append([]string(nil), installed[:7]...)
	superset := append(append([]string(nil), installed...), "198.18.161.0/32")
	disjoint := prefixes16085(10)
	for i := range disjoint {
		disjoint[i] = strings.Replace(disjoint[i], "198.18.160.", "198.18.170.", 1)
	}
	disjoint = canonicalize(disjoint)
	for _, tc := range []struct {
		name      string
		invalid   int
		installed []string
		candidate []string
		want      bool
	}{
		{"clean subset", 0, installed, subset, false},
		{"degraded subset drops 3", 3, installed, subset, true},
		{"degraded identical", 2, installed, installed, false},
		{"degraded superset", 1, installed, superset, false},
		{"degraded disjoint swap", 4, installed, disjoint, true},
		{"degraded no installed", 3, nil, subset, false},
		{"clean disjoint (churn guard's job)", 0, installed, disjoint, false},
	} {
		if got := malformedShrinkTripped16085(tc.invalid, tc.installed, tc.candidate); got != tc.want {
			t.Errorf("%s: malformedShrinkTripped16085 = %v, want %v", tc.name, got, tc.want)
		}
	}
}

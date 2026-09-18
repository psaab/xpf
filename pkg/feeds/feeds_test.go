package feeds

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// bodyServer returns an httptest server serving a fixed body with the given
// status. The pointer fields let a test swap the response between fetches.
type bodyServer struct {
	mu     sync.Mutex
	body   string
	status int
}

func (b *bodyServer) set(body string, status int) {
	b.mu.Lock()
	b.body, b.status = body, status
	b.mu.Unlock()
}

func (b *bodyServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b.mu.Lock()
		body, status := b.body, b.status
		b.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// newFeed wires a feedState pointing at url with the given hold window and
// registers it on the manager so AllFeeds/GetPrefixes see it.
func (m *Manager) newFeed(name, url string, hold time.Duration) *feedState {
	m.SetPrivateFeedAllowlist([]netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	})
	fs := &feedState{name: name, url: url, holdInterval: hold}
	m.mu.Lock()
	m.feeds[name] = fs
	m.mu.Unlock()
	return fs
}

// --- parseFeed / canonicalization ---

func TestParseFeedCanonicalizesAndDedups(t *testing.T) {
	body := strings.Join([]string{
		"# a comment",
		"// another comment",
		"192.0.2.5/24", // masked -> 192.0.2.0/24
		"192.0.2.7/24", // duplicate after masking
		"203.0.113.4",  // bare v4 -> /32
		"2001:db8::1",  // bare v6 -> /128
		"not-an-ip",    // skipped silently
		"",
	}, "\n")

	res, err := parseFeed(bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	want := []string{"192.0.2.0/24", "203.0.113.4/32", "2001:db8::1/128"}
	// canonicalize sorts; compute the sorted want for stable comparison.
	got := res.prefixes
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes %v, want %d %v", len(got), got, len(want), want)
	}
	gotSet := map[string]bool{}
	for _, p := range got {
		gotSet[p] = true
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing canonical prefix %q in %v", w, got)
		}
	}
}

// TestParseFeedCountsInvalidLines is the #2993 fail-on-revert test. A feed body
// mixing valid + invalid lines must install the valid prefixes AND surface the
// count (plus a bounded sample) of the skipped invalid lines — not silently
// drop them and report a clean parse. Reverting the parse-side counting makes
// invalidLines == 0 and turns this RED.
func TestParseFeedCountsInvalidLines(t *testing.T) {
	body := strings.Join([]string{
		"192.0.2.0/24",
		"garbage one",                  // invalid
		"203.0.113.0/24",               // valid
		"203.0.113.0/24 trailing-junk", // CIDR + stray text -> invalid
		"not-an-ip",                    // invalid
		"10.0.0.0/8",                   // valid
		"# a comment",                  // skipped, not counted invalid
	}, "\n")

	res, err := parseFeed(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	if len(res.prefixes) != 3 {
		t.Fatalf("got %d valid prefixes %v, want 3 (valid lines still installed)",
			len(res.prefixes), res.prefixes)
	}
	if res.invalidLines != 3 {
		t.Fatalf("invalidLines = %d, want 3 (mixed body must count skipped lines, not silently drop)",
			res.invalidLines)
	}
	if len(res.invalidSample) == 0 {
		t.Fatal("invalidSample empty; want a bounded verbatim sample of skipped lines")
	}
	for _, s := range res.invalidSample {
		if s == "# a comment" || s == "192.0.2.0/24" {
			t.Errorf("invalidSample contains a non-invalid line %q", s)
		}
	}
}

// TestInvalidSampleIsBounded confirms the sample never exceeds maxInvalidSample
// even for a wholesale-garbage body, while the total count is exact.
func TestInvalidSampleIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("192.0.2.0/24\n") // one valid prefix so parse succeeds
	const garbage = 50
	for i := 0; i < garbage; i++ {
		fmt.Fprintf(&b, "junk-line-%d\n", i)
	}
	res, err := parseFeed(strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parseFeed error: %v", err)
	}
	if res.invalidLines != garbage {
		t.Errorf("invalidLines = %d, want %d", res.invalidLines, garbage)
	}
	if len(res.invalidSample) != maxInvalidSample {
		t.Errorf("invalidSample len = %d, want bounded to %d", len(res.invalidSample), maxInvalidSample)
	}
}

// TestMixedFeedDegradedStatus confirms a mixed body installs valid prefixes and
// surfaces a degraded status with the invalid-line count through AllFeeds.
func TestMixedFeedDegradedStatus(t *testing.T) {
	m := New(func() error { return nil })
	srv := &bodyServer{}
	srv.set("192.0.2.0/24\nnot-an-ip\n203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("mixed", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	info := m.AllFeeds()["mixed"]
	if info.Prefixes != 2 {
		t.Errorf("Prefixes = %d, want 2 (valid lines installed)", info.Prefixes)
	}
	if info.InvalidLines != 1 {
		t.Errorf("InvalidLines = %d, want 1", info.InvalidLines)
	}
	if !info.Degraded {
		t.Error("Degraded = false despite a skipped invalid line; want true")
	}
	// #4922: the retained sample entry is an escaped (quoted) prefix, not the
	// verbatim line. A short line is quoted-but-otherwise-intact.
	wantSample := strconv.Quote("not-an-ip")
	if len(info.InvalidSample) != 1 || info.InvalidSample[0] != wantSample {
		t.Errorf("InvalidSample = %v, want [%s]", info.InvalidSample, wantSample)
	}
}

// TestCleanFeedNotDegraded is the no-behaviour-change guard: an all-valid feed
// installs fully with zero invalid lines and is NOT marked degraded.
func TestCleanFeedNotDegraded(t *testing.T) {
	m := New(func() error { return nil })
	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("clean", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	info := m.AllFeeds()["clean"]
	if info.Prefixes != 2 {
		t.Errorf("Prefixes = %d, want 2", info.Prefixes)
	}
	if info.InvalidLines != 0 {
		t.Errorf("InvalidLines = %d, want 0 for a clean feed", info.InvalidLines)
	}
	if info.Degraded {
		t.Error("clean feed marked Degraded")
	}
	if len(info.InvalidSample) != 0 {
		t.Errorf("InvalidSample = %v, want empty for a clean feed", info.InvalidSample)
	}
}

// TestDegradedClearsAfterCleanRefetch confirms a feed that recovers (provider
// fixes the body) drops the degraded markers on the next clean install.
func TestDegradedClearsAfterCleanRefetch(t *testing.T) {
	m := New(func() error { return nil })
	srv := &bodyServer{}
	srv.set("192.0.2.0/24\nbad-line\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()
	m.fetchFeed(ctx, fs)
	if info := m.AllFeeds()["f"]; !info.Degraded || info.InvalidLines != 1 {
		t.Fatalf("first fetch not degraded: %+v", info)
	}

	// Provider fixes the body — a clean content change.
	srv.set("192.0.2.0/24\n198.51.100.0/24\n", http.StatusOK)
	m.fetchFeed(ctx, fs)
	info := m.AllFeeds()["f"]
	if info.Degraded || info.InvalidLines != 0 {
		t.Errorf("degraded markers not cleared after clean refetch: %+v", info)
	}
}

func TestParseFeedZeroPrefixIsError(t *testing.T) {
	// HTTP 200 with only comments / junk -> zero usable prefixes -> suspect.
	res, err := parseFeed(bytes.NewBufferString("# only comments\n// nothing\nbad-line\n"))
	if err == nil {
		t.Fatalf("expected error for zero-prefix body, got prefixes %v", res.prefixes)
	}
}

// TestParseFeedOverlongLineErrors targets the bufio.ErrTooLong / scanner.Err()
// fix. Pre-fix this returned a (possibly truncated) set with no error.
func TestParseFeedOverlongLineErrors(t *testing.T) {
	var b strings.Builder
	b.WriteString("192.0.2.0/24\n")
	// A single line longer than the scanner token cap.
	b.WriteString(strings.Repeat("a", maxLineBytes+1))
	b.WriteString("\n")

	_, err := parseFeed(strings.NewReader(b.String()))
	if err == nil {
		t.Fatal("expected scanner error for overlong line, got nil (silent truncation)")
	}
}

// --- content-based change detection ---

// TestSameCountContentChangeFires is the core #2050 bug test: a content swap
// with identical count must fire onUpdate. The old code compared len only.
func TestSameCountContentChangeFires(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // initial install
	if got := calls.Load(); got != 1 {
		t.Fatalf("initial fetch: onUpdate calls = %d, want 1", got)
	}

	// Same COUNT (1 prefix), different CONTENT.
	srv.set("198.51.100.0/24\n", http.StatusOK)
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 2 {
		t.Fatalf("same-count content swap: onUpdate calls = %d, want 2 (content change must fire)", got)
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("snapshot not replaced: got %v", got)
	}
}

func TestIdenticalContentDoesNotFire(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	srv := &bodyServer{}
	// Same prefixes in a different order each fetch -> canonical hash identical.
	srv.set("192.0.2.0/24\n10.0.0.0/8\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 1 {
		t.Fatalf("initial fetch calls = %d, want 1", got)
	}

	srv.set("10.0.0.0/8\n192.0.2.0/24\n", http.StatusOK) // reordered, same set
	m.fetchFeed(ctx, fs)
	if got := calls.Load(); got != 1 {
		t.Fatalf("identical-content (reordered) refetch fired onUpdate %d times, want still 1", got)
	}
}

// --- no-stamp-on-partial / no-replace-on-error ---

// TestErrorRetainsSnapshotNoStamp targets behaviors 1 + 4: a failed fetch must
// not replace the snapshot and must not stamp lastFetch/lastSuccess.
func TestErrorRetainsSnapshotNoStamp(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()

	m.fetchFeed(ctx, fs)
	goodStamp := fs.lastFetch
	if goodStamp.IsZero() {
		t.Fatal("expected lastFetch stamped on success")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}

	// Now serve an error (500).
	srv.set("hijacked-garbage", http.StatusInternalServerError)
	m.fetchFeed(ctx, fs)

	if fs.lastFetch != goodStamp {
		t.Errorf("lastFetch re-stamped on failed fetch: was %v now %v", goodStamp, fs.lastFetch)
	}
	if fs.lastError == "" {
		t.Error("expected lastError recorded on failed fetch")
	}
	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Errorf("snapshot replaced on failed fetch: got %v, want last-good [192.0.2.0/24]", got)
	}
	if calls.Load() != 1 {
		t.Errorf("onUpdate fired on failed fetch within hold: calls = %d, want 1", calls.Load())
	}
}

// TestZeroPrefixRetainsLastGood targets behavior 5's zero-prefix case: an
// HTTP-200 empty body must NOT wipe the enforced set; it is treated as suspect.
func TestZeroPrefixRetainsLastGood(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	ctx := context.Background()
	m.fetchFeed(ctx, fs)

	// HTTP 200 with an empty body (or only comments) -> retain last-good.
	srv.set("# emptied feed\n", http.StatusOK)
	m.fetchFeed(ctx, fs)

	if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Errorf("zero-prefix 200 wiped enforced set: got %v, want last-good", got)
	}
	if fs.lastError == "" {
		t.Error("expected lastError set for zero-prefix fetch")
	}
}

// TestResolveHoldInterval pins the #2050 default-mapping decision: unset (0)
// and negative map to retainForever (never auto-drop); only an explicit
// positive value yields a timed drop window.
func TestResolveHoldInterval(t *testing.T) {
	if got := resolveHoldInterval(0); got != retainForever {
		t.Errorf("resolveHoldInterval(0) = %v, want retainForever (never drop)", got)
	}
	if got := resolveHoldInterval(-5); got != retainForever {
		t.Errorf("resolveHoldInterval(-5) = %v, want retainForever", got)
	}
	if got := resolveHoldInterval(7200); got != 2*time.Hour {
		t.Errorf("resolveHoldInterval(7200) = %v, want 2h", got)
	}
}

// --- HoldInterval retain-then-drop ---

// TestHoldIntervalRetainThenDrop targets the EXPLICIT opt-in drop: with a
// positive hold-interval configured, retain last-good within the window, then
// drop to empty (fail-closed) after it elapses. This is no longer the default
// (see TestUnsetHoldIntervalRetainsForever) — it requires hold-interval > 0.
func TestHoldIntervalRetainThenDrop(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	cur := base
	m.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		cur = cur.Add(d)
		nowMu.Unlock()
	}

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	const hold = 60 * time.Second
	fs := m.newFeed("f", ts.URL, hold)
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // good snapshot at base
	if calls.Load() != 1 {
		t.Fatalf("install calls = %d, want 1", calls.Load())
	}

	// Start failing.
	srv.set("nope", http.StatusBadGateway)

	// First failure: sets staleSince, retains snapshot. (t=base)
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 1 {
		t.Fatalf("first failure dropped snapshot early: got %v", got)
	}
	if fs.staleSince.IsZero() {
		t.Fatal("staleSince not set on first failure")
	}

	// Within hold window (t=base+30s): still retained.
	advance(30 * time.Second)
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 1 {
		t.Fatalf("snapshot dropped within hold window: got %v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("onUpdate fired during retain window: calls = %d, want 1", calls.Load())
	}

	// At/after hold window (t=base+60s): drop to empty + fire onUpdate.
	advance(30 * time.Second)
	m.fetchFeed(ctx, fs)
	if got := m.GetPrefixes("f"); len(got) != 0 {
		t.Fatalf("snapshot not dropped after hold elapsed: got %v", got)
	}
	if got := m.GetPrefixes("f"); got == nil {
		t.Error("GetPrefixes returned nil after drop; want non-nil empty slice (Copilot #3)")
	}
	if calls.Load() != 2 {
		t.Fatalf("expected onUpdate on drop-to-empty: calls = %d, want 2", calls.Load())
	}
	// Copilot #2: after the drop there is no retained snapshot, so StaleSince
	// must be cleared to match its docstring, and Hash must surface "".
	info := m.AllFeeds()["f"]
	if !info.StaleSince.IsZero() {
		t.Errorf("StaleSince not cleared after drop-to-empty: %v", info.StaleSince)
	}
	if info.Hash != "" {
		t.Errorf("Hash not cleared after drop-to-empty: %q (want \"\")", info.Hash)
	}
}

// TestUnsetHoldIntervalRetainsForever is the core #2050 operator-decision test:
// with hold-interval UNSET (retainForever / 0), repeated failures over an
// arbitrarily long span NEVER drop the last-good snapshot to empty. A stale
// DENYLIST that fail-OPENs is the rejected behaviour. This test would FAIL
// under the old default (resolveHoldInterval(0) -> 2h), which dropped to empty
// after the window elapsed.
func TestUnsetHoldIntervalRetainsForever(t *testing.T) {
	var calls atomic.Int32
	m := New(func() error { calls.Add(1); return nil })

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	cur := base
	m.now = func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return cur
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		cur = cur.Add(d)
		nowMu.Unlock()
	}

	srv := &bodyServer{}
	srv.set("203.0.113.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	// hold-interval UNSET == resolveHoldInterval(0) == retainForever.
	fs := m.newFeed("f", ts.URL, resolveHoldInterval(0))
	if fs.holdInterval != retainForever {
		t.Fatalf("unset hold-interval did not resolve to retainForever: %v", fs.holdInterval)
	}
	ctx := context.Background()

	m.fetchFeed(ctx, fs) // good snapshot at base
	if calls.Load() != 1 {
		t.Fatalf("install calls = %d, want 1", calls.Load())
	}

	srv.set("nope", http.StatusBadGateway) // start failing forever

	// First failure: enters stale, retains.
	m.fetchFeed(ctx, fs)
	staleAt := m.AllFeeds()["f"].StaleSince
	if staleAt.IsZero() {
		t.Fatal("staleSince not set on first failure")
	}

	// Hammer failures across a span far longer than the old 2h default. Under
	// retain-forever, the snapshot is NEVER dropped and onUpdate never fires.
	for i := 0; i < 50; i++ {
		advance(24 * time.Hour) // total well past any plausible hold window
		m.fetchFeed(ctx, fs)
		if got := m.GetPrefixes("f"); len(got) != 1 || got[0] != "203.0.113.0/24" {
			t.Fatalf("retain-forever dropped snapshot at iter %d: got %v", i, got)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("onUpdate fired during retain-forever (drop happened): calls = %d, want 1", calls.Load())
	}
	// StaleSince must remain pinned at the first-failure time across all ticks
	// (set once on entry to stale, never re-stamped) and stay non-zero while a
	// snapshot is retained as stale.
	if got := m.AllFeeds()["f"].StaleSince; !got.Equal(staleAt) {
		t.Errorf("StaleSince moved during retain: was %v now %v", staleAt, got)
	}
}

// TestStartupNoSnapshotFailClosed targets behavior 5 startup semantics: before
// any good fetch, a failing feed has no snapshot and GetPrefixes is empty.
func TestStartupNoSnapshotFailClosed(t *testing.T) {
	m := New(func() error { return nil })
	srv := &bodyServer{}
	srv.set("nope", http.StatusInternalServerError)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("f", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	if got := m.GetPrefixes("f"); len(got) != 0 {
		t.Fatalf("startup-before-first-fetch not fail-closed: got %v", got)
	}
	// Copilot #3: a known feed with no snapshot returns a non-nil empty slice
	// so the JSON encoder emits [] rather than null.
	if got := m.GetPrefixes("f"); got == nil {
		t.Error("GetPrefixes returned nil for a known feed with no snapshot; want non-nil empty slice")
	}
	if fs.hasSnapshot {
		t.Error("hasSnapshot true with no successful fetch")
	}
	if fs.lastError == "" {
		t.Error("expected lastError recorded on startup failure")
	}
	// Copilot #1: with no snapshot installed, Hash must be "" — not 64 zero-hex
	// chars from the zero [32]byte.
	if info := m.AllFeeds()["f"]; info.Hash != "" {
		t.Errorf("Hash = %q with no snapshot; want \"\" (Copilot #1)", info.Hash)
	}
}

// TestAllFeedsStatusFields confirms the additive status fields surface.
func TestAllFeedsStatusFields(t *testing.T) {
	m := New(func() error { return nil })
	srv := &bodyServer{}
	srv.set("192.0.2.0/24\n", http.StatusOK)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	fs := m.newFeed("office", ts.URL, time.Hour)
	m.fetchFeed(context.Background(), fs)

	info := m.AllFeeds()["office"]
	if info.Prefixes != 1 {
		t.Errorf("Prefixes = %d, want 1", info.Prefixes)
	}
	if info.LastSuccess.IsZero() || info.LastFetch.IsZero() {
		t.Error("LastSuccess/LastFetch not stamped")
	}
	if info.Hash == "" || info.Hash == strings.Repeat("0", 64) {
		t.Errorf("Hash not populated: %q", info.Hash)
	}
	if info.LastError != "" {
		t.Errorf("LastError unexpectedly set: %q", info.LastError)
	}
}

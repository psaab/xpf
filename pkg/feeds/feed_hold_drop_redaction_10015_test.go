package feeds

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// feed_hold_drop_redaction_10015_test.go: #10015 — the two recordFailure arms
// #9164 did not bind still logged the RAW transport error object.
//
// Go's transport error quotes the URL it dialled, and a dynamic-address feed
// routinely carries a per-tenant bearer token in its query string. #9164
// redacted the stored field (fs.lastError) and the entered-STALE Warn; but the
// hold-drop Warn (the production-visible path — a persistently-down feed WITH
// an explicit hold-interval reaches it on every drop) and the default Debug
// arm (every repeated failure) kept logging `ferr` verbatim. Each cell below
// drives recordFailure into its arm and binds the LOG sink, so a mutation
// restoring `"err", ferr` in either arm REDs it — the same way the 9164 stale
// cell binds the Warn it covers.
//
// The diagnostic must survive in every cell: host, path and the transport
// failure stay; only the credential goes.

// TestHoldDropWarnDoesNotLogTheCredential10015 drives the dropped arm: a feed
// that entered STALE long ago with an explicit hold-interval now ages out and
// drops to empty at Warn.
func TestHoldDropWarnDoesNotLogTheCredential10015(t *testing.T) {
	const rawURL = "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123"

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	fixed := time.Now()
	fs := &feedState{
		name:         "tenant-feed",
		url:          rawURL,
		hasSnapshot:  true,
		prefixes:     []string{"203.0.113.0/24"},
		holdInterval: time.Minute,
		// Already stale for an hour with a one-minute hold: this failure is
		// the one that drops the snapshot to empty.
		staleSince: fixed.Add(-time.Hour),
	}
	m := &Manager{
		feeds: map[string]*feedState{"tenant-feed": fs},
		now:   func() time.Time { return fixed },
	}

	m.recordFailure(fs, fmt.Errorf(
		"fetch failed: Get %q: dial tcp 127.0.0.1:1: connect: connection refused", rawURL))

	out := buf.String()
	if !strings.Contains(out, "hold interval elapsed") {
		t.Fatalf("the hold-drop Warn did not fire, so this cell observed nothing:\n%s", out)
	}
	if !fs.holdDropped {
		t.Fatalf("the fixture did not reach the dropped arm (holdDropped=false):\n%s", out)
	}
	if strings.Contains(out, "BEARER_TOKEN_ABC123") {
		t.Fatalf("the per-tenant token was written to the LOG on the hold-drop path — "+
			"journald and every support bundle carry it:\n%s", out)
	}
	for _, keep := range []string{"dial tcp", "connection refused", "127.0.0.1", "/list.txt"} {
		if !strings.Contains(out, keep) {
			t.Errorf("the logged diagnostic lost %q:\n%s", keep, out)
		}
	}
}

// TestRepeatedFailureDebugDoesNotLogTheCredential10015 drives the default arm:
// an already-stale feed on the retain-forever default fails again and logs at
// Debug. Debug is still a log sink — a debug-level deployment collects it —
// so the arm is covered by redaction rather than trusted mute.
func TestRepeatedFailureDebugDoesNotLogTheCredential10015(t *testing.T) {
	const rawURL = "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123"

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	fixed := time.Now()
	fs := &feedState{
		name:        "tenant-feed",
		url:         rawURL,
		hasSnapshot: true,
		prefixes:    []string{"203.0.113.0/24"},
		// Already stale, and holdInterval zero (retainForever) so this failure
		// neither enters stale nor drops: the default Debug arm.
		staleSince: fixed.Add(-time.Hour),
	}
	m := &Manager{
		feeds: map[string]*feedState{"tenant-feed": fs},
		now:   func() time.Time { return fixed },
	}

	m.recordFailure(fs, fmt.Errorf(
		"fetch failed: Get %q: dial tcp 127.0.0.1:1: connect: connection refused", rawURL))

	out := buf.String()
	if !strings.Contains(out, "fetch failed, retaining last-good") {
		t.Fatalf("the repeated-failure Debug did not fire, so this cell observed nothing:\n%s", out)
	}
	if strings.Contains(out, "BEARER_TOKEN_ABC123") {
		t.Fatalf("the per-tenant token was written to the LOG on the repeated-failure Debug path:\n%s", out)
	}
	for _, keep := range []string{"dial tcp", "connection refused", "127.0.0.1", "/list.txt"} {
		if !strings.Contains(out, keep) {
			t.Errorf("the logged diagnostic lost %q:\n%s", keep, out)
		}
	}
}

// TestDuplicateFeedNameWarnRedactsCredentialURL10015 is the audit find: Apply's
// duplicate-name safety net logged the loser's configured URL VERBATIM, and a
// configured feed URL routinely carries the per-tenant bearer token. Same bug
// class (credential-bearing URL reaches the journal), same file — bound here.
func TestDuplicateFeedNameWarnRedactsCredentialURL10015(t *testing.T) {
	const tokenURL = "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123"

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	// The winner needs a fetchable URL (its worker starts); the loser never
	// fetches, so its token-bearing URL only reaches the Warn.
	winner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer winner.Close()

	m := newLabManager10177(func() error { return nil })
	// "aaa" sorts first and wins; "bbb" is the duplicate whose URL is logged.
	// Empty Path keeps the token URL byte-identical into the Warn.
	daCfg := &config.DynamicAddressConfig{
		FeedServers: map[string]*config.FeedServer{
			"aaa": {
				Name:        "aaa",
				URL:         winner.URL,
				FeedEntries: []config.FeedEntry{{Name: "dup", Path: "/aaa"}},
			},
			"bbb": {
				Name:        "bbb",
				URL:         tokenURL,
				FeedEntries: []config.FeedEntry{{Name: "dup"}},
			},
		},
	}

	m.Apply(context.Background(), daCfg)
	m.StopAll()

	out := buf.String()
	if !strings.Contains(out, "duplicate feed name ignored") {
		t.Fatalf("the duplicate-name Warn did not fire, so this cell observed nothing:\n%s", out)
	}
	if strings.Contains(out, "BEARER_TOKEN_ABC123") {
		t.Fatalf("the per-tenant token was written to the LOG by the duplicate-name Warn:\n%s", out)
	}
	for _, keep := range []string{"127.0.0.1", "/list.txt"} {
		if !strings.Contains(out, keep) {
			t.Errorf("the logged diagnostic lost %q:\n%s", keep, out)
		}
	}
}

// REFERENCE ARM: a credential-free feed must log its error byte-identical on
// the hold-drop path, so the cells above are measuring redaction rather than
// any rewriting of the sink.
func TestHoldDropWarnKeepsACleanURLAlone10015(t *testing.T) {
	const rawURL = "https://feeds.example.net/list.txt"

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	fixed := time.Now()
	fs := &feedState{
		name:         "public-feed",
		url:          rawURL,
		hasSnapshot:  true,
		prefixes:     []string{"203.0.113.0/24"},
		holdInterval: time.Minute,
		staleSince:   fixed.Add(-time.Hour),
	}
	m := &Manager{
		feeds: map[string]*feedState{"public-feed": fs},
		now:   func() time.Time { return fixed },
	}
	wantErr := fmt.Sprintf("fetch failed: Get %q: dial tcp: refused", rawURL)

	m.recordFailure(fs, fmt.Errorf("%s", wantErr))

	out := buf.String()
	if !strings.Contains(out, "hold interval elapsed") {
		t.Fatalf("the hold-drop Warn did not fire, so this cell observed nothing:\n%s", out)
	}
	// slog's text handler escapes the quotes surrounding the URL in the
	// structured error value; apart from that representation detail, a
	// credential-free error must remain byte-identical.
	escapedWant := strings.ReplaceAll(wantErr, `"`, `\"`)
	if !strings.Contains(out, `err="`+escapedWant+`"`) {
		t.Errorf("a credential-free error was altered on the hold-drop path:\n want: %s\n log:\n%s", wantErr, out)
	}
}

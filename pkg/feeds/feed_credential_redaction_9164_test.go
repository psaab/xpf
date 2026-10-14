package feeds

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"
)

// #9164: a feed URL's credential reached `lastError`, journald and every
// support bundle. Go's transport error quotes the URL it dialled, and this
// product's own docs say dynamic-address feeds "routinely carry per-tenant
// bearer tokens in the URL".
//
// The table the issue asks for: {userinfo password, username, query token, no
// credential}, asserting the stored text carries NO secret and STILL carries
// the transport diagnostic. The no-credential row is the control proving the
// diagnostic survived.
func TestFeedErrorRedactionTable9164(t *testing.T) {
	// Shaped exactly as net/http formats a dial failure, including the
	// stripPassword rewrite it applies to a basic-auth password.
	transportErr := func(rawURL string) error {
		shown := rawURL
		if u, err := url.Parse(rawURL); err == nil && u.User != nil {
			if _, hasPw := u.User.Password(); hasPw {
				masked := *u
				masked.User = url.UserPassword(u.User.Username(), "***")
				shown = masked.String()
			}
		}
		return fmt.Errorf("fetch failed: %w",
			fmt.Errorf("Get %q: dial tcp 127.0.0.1:1: connect: connection refused", shown))
	}

	for _, tc := range []struct {
		name    string
		rawURL  string
		secrets []string // must NOT appear
	}{
		{
			name:    "query token — the shape this product actually has",
			rawURL:  "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123",
			secrets: []string{"BEARER_TOKEN_ABC123"},
		},
		{
			name:   "userinfo username and query key",
			rawURL: "https://apikeyuser@127.0.0.1:1/list.txt?api_key=SEKRIT",
			// net/http masks a PASSWORD but never the username, and the query
			// key is untouched — both are live secrets here.
			secrets: []string{"apikeyuser", "SEKRIT"},
		},
		{
			name:   "userinfo password",
			rawURL: "https://user:hunter2@127.0.0.1:1/list.txt",
			// `hunter2` is already masked by net/http; `user` is not, and it is
			// half a credential.
			secrets: []string{"hunter2", "user:"},
		},
		{
			name:    "no credential — CONTROL",
			rawURL:  "https://feeds.example.net/list.txt",
			secrets: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := transportErr(tc.rawURL).Error()
			got := redactFeedURLInError9164(raw, tc.rawURL)

			for _, sec := range tc.secrets {
				if strings.Contains(got, sec) {
					t.Errorf("SECRET SURVIVED redaction: %q still present.\n  raw:  %s\n  got:  %s\n\n"+
						"This text is stored in FeedStatus.LastError and written to journald "+
						"on every stale transition, so it reaches any support bundle.",
						sec, raw, got)
				}
			}

			// THE DIAGNOSTIC MUST SURVIVE. A redaction that eats the error is a
			// different defect: an operator debugging a dead feed is left with
			// nothing, and "the feed is down" is exactly when they look.
			for _, keep := range []string{"fetch failed", "dial tcp", "connection refused"} {
				if !strings.Contains(got, keep) {
					t.Errorf("the transport diagnostic lost %q; redaction must remove the "+
						"credential, not the error.\n  got: %s", keep, got)
				}
			}
			if !strings.Contains(got, "127.0.0.1") && !strings.Contains(got, "feeds.example.net") {
				t.Errorf("the host is gone from the diagnostic: %s", got)
			}

			if tc.secrets == nil && got != raw {
				t.Errorf("the no-credential control was ALTERED.\n  raw: %s\n  got: %s\n\n"+
					"A URL with nothing to hide must pass through byte-identical, or "+
					"the redaction is doing something other than redacting.", raw, got)
			}
		})
	}
}

// The stored field and the logged field must be the SAME text. #9164 logged the
// error OBJECT while storing a string, so redacting only one would have left
// the journal — the wider channel — carrying the secret.
func TestStoredAndLoggedTextAreTheSame9164(t *testing.T) {
	raw := `fetch failed: Get "https://127.0.0.1:1/l.txt?token=SEKRIT": dial tcp: refused`
	rawURL := "https://127.0.0.1:1/l.txt?token=SEKRIT"
	got := redactFeedURLInError9164(raw, rawURL)
	if strings.Contains(got, "SEKRIT") {
		t.Fatalf("token survived: %s", got)
	}
	// The Warn call passes fs.lastError, which is this function's output — so
	// asserting on it is asserting on what journald receives.
	if got == raw {
		t.Fatal("nothing was redacted at all")
	}
}

// An empty or unparseable input must not panic or lose the diagnostic.
func TestRedactionIsTotal9164(t *testing.T) {
	for _, tc := range []struct{ errText, rawURL string }{
		{"", "https://x/y?token=T"},
		{"some error", ""},
		{"some error", "::::not a url::::"},
		{errors.New("boom").Error(), "https://feeds.example.net/l.txt"},
	} {
		got := redactFeedURLInError9164(tc.errText, tc.rawURL)
		if tc.errText != "" && got == "" {
			t.Errorf("redaction emptied a non-empty error: %q / %q", tc.errText, tc.rawURL)
		}
	}
}

// THE WIRING. The three cells above drive `redactFeedURLInError9164` directly —
// and a mutation restoring `fs.lastError = ferr.Error()` at the call site
// SURVIVED all of them. A redaction helper nothing calls redacts nothing.
//
// This cell drives `recordFailure`, the function that actually stores the field
// and emits the Warn, so severing the call site reds it.
func TestRecordFailureStoresRedactedText9164(t *testing.T) {
	const rawURL = "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123"
	fs := &feedState{
		name:        "tenant-feed",
		url:         rawURL,
		hasSnapshot: true,
		prefixes:    []string{"203.0.113.0/24"},
	}
	// `now` is required: recordFailure calls m.now() before storing, and a nil
	// func panics. My first fixture omitted it and the cell panicked on
	// UNMUTATED code — which also made the mutant score meaningless, since a
	// cell that fails for a fixture reason "kills" every mutant equally.
	m := &Manager{feeds: map[string]*feedState{"tenant-feed": fs}, now: time.Now}

	m.recordFailure(fs, fmt.Errorf(
		"fetch failed: Get %q: dial tcp 127.0.0.1:1: connect: connection refused", rawURL))

	if fs.lastError == "" {
		t.Fatal("recordFailure stored nothing; this cell cannot observe redaction")
	}
	if strings.Contains(fs.lastError, "BEARER_TOKEN_ABC123") {
		t.Fatalf("the per-tenant token is in FeedStatus.LastError, which reaches "+
			"journald and every support bundle:\n  %s", fs.lastError)
	}
	// The diagnostic must still be there — an operator reads this precisely
	// when the feed is down.
	for _, keep := range []string{"fetch failed", "dial tcp", "connection refused"} {
		if !strings.Contains(fs.lastError, keep) {
			t.Errorf("stored error lost %q: %s", keep, fs.lastError)
		}
	}
}

// REFERENCE ARM for the wiring cell: a feed with no credential must store the
// error unchanged, so the cell above is measuring redaction rather than any
// rewriting of the field.
func TestRecordFailureLeavesACleanURLAlone9164(t *testing.T) {
	const rawURL = "https://feeds.example.net/list.txt"
	fs := &feedState{
		name:        "public-feed",
		url:         rawURL,
		hasSnapshot: true,
		prefixes:    []string{"203.0.113.0/24"},
	}
	m := &Manager{feeds: map[string]*feedState{"public-feed": fs}, now: time.Now}
	want := fmt.Sprintf("fetch failed: Get %q: dial tcp: refused", rawURL)

	m.recordFailure(fs, errors.New(want))

	if fs.lastError != want {
		t.Errorf("a credential-free error was altered:\n  want: %s\n  got:  %s", want, fs.lastError)
	}
}

// THE JOURNAL IS THE WHOLE CHANNEL, so it needs its own cell.
//
// `FeedStatus.LastError` has no operator-visible renderer — the CLI and gRPC
// show paths print only the configured (already-redacted) URL, and Prometheus
// reads neither. What actually carries the secret off the box is the `slog.Warn`
// on entry to STALE, and from there journald and every support bundle.
//
// A mutation restoring `"err", ferr` in that Warn — logging the raw error object
// while the stored field stays redacted — SURVIVED every cell above, including
// the call-site one. Storing and logging are two sinks and each needs binding.
func TestStaleWarnDoesNotLogTheCredential9164(t *testing.T) {
	const rawURL = "https://127.0.0.1:1/list.txt?token=BEARER_TOKEN_ABC123"

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)

	fs := &feedState{
		name:        "tenant-feed",
		url:         rawURL,
		hasSnapshot: true,
		prefixes:    []string{"203.0.113.0/24"},
	}
	m := &Manager{feeds: map[string]*feedState{"tenant-feed": fs}, now: time.Now}

	// hasSnapshot + prefixes + a zero staleSince is what makes this the
	// ENTERED-STALE transition, which is the one that logs at Warn.
	m.recordFailure(fs, fmt.Errorf(
		"fetch failed: Get %q: dial tcp 127.0.0.1:1: connect: connection refused", rawURL))

	out := buf.String()
	if !strings.Contains(out, "entered STALE") {
		t.Fatalf("the stale-entry Warn did not fire, so this cell observed nothing:\n%s", out)
	}
	if strings.Contains(out, "BEARER_TOKEN_ABC123") {
		t.Fatalf("the per-tenant token was written to the LOG — journald and every "+
			"support bundle carry it, and that is the only channel this field "+
			"actually reaches:\n%s", out)
	}
	for _, keep := range []string{"dial tcp", "connection refused"} {
		if !strings.Contains(out, keep) {
			t.Errorf("the logged diagnostic lost %q:\n%s", keep, out)
		}
	}
}

// #12883: the transport may quote a DIFFERENT URL than the configured one
// (same-origin redirect, scheme normalization); its query token must not
// survive redaction.
func TestFeedErrorRedactionChangedURL12883(t *testing.T) {
	rawURL := "https://feeds.example.net/list.txt"
	errText := `Get "https://feeds.example.net/redirected.txt?token=REDIRECT_TOKEN_9": dial tcp 10.0.0.1:443: connect: connection refused`
	got := redactFeedURLInError9164(errText, rawURL)
	if strings.Contains(got, "REDIRECT_TOKEN_9") {
		t.Fatalf("redirect token survived: %s", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Fatalf("diagnostic lost: %s", got)
	}
	upper := `Get "HTTPS://user:pass@feeds.example.net/list.txt?token=CASE_TOKEN_1": dial tcp: i/o timeout`
	got = redactFeedURLInError9164(upper, rawURL)
	if strings.Contains(got, "CASE_TOKEN_1") || strings.Contains(got, "user:pass") {
		t.Fatalf("normalized-spelling secret survived: %s", got)
	}
}

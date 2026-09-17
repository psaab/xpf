package feeds

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestFeedFetcherRefusesCrossOriginRedirect9912 is the #9912 fail-on-revert
// cell for redirect policy. The configured origin may redirect within itself,
// but a provider-selected second origin must never receive a fetch.
func TestFeedFetcherRefusesCrossOriginRedirect9912(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/prefixes", http.StatusFound)
	}))
	defer source.Close()

	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	m := New(nil)
	fs := m.newFeed("cross-origin", source.URL+"/feed?token=SECRET", retainForever)
	_, err := m.readFeed(context.Background(), fs)
	if err == nil || !strings.Contains(err.Error(), "unexpected status 302") {
		t.Fatalf("cross-origin redirect error = %v, want refused 302", err)
	}
	if got := targetHits.Load(); got != 0 {
		t.Fatalf("redirect target received %d requests, want 0", got)
	}
	if !strings.Contains(logs.String(), "cross-origin feed redirect refused") {
		t.Fatalf("redirect refusal was not logged: %q", logs.String())
	}
	if strings.Contains(logs.String(), "SECRET") {
		t.Fatalf("redirect refusal log leaked configured query credential: %q", logs.String())
	}
}

// TestFeedFetcherSameOriginRedirectWorks9912 is the legitimate redirect
// control: a path move on the configured origin remains supported.
func TestFeedFetcherSameOriginRedirectWorks9912(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/feed" {
			http.Redirect(w, r, "/prefixes", http.StatusFound)
			return
		}
		if r.URL.Path != "/prefixes" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("198.51.100.0/24\n"))
	}))
	defer server.Close()

	m := New(nil)
	fs := m.newFeed("same-origin", server.URL+"/feed", retainForever)
	res, err := m.readFeed(context.Background(), fs)
	if err != nil {
		t.Fatalf("same-origin redirect: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("same-origin redirect requests = %d, want 2", got)
	}
	if len(res.prefixes) != 1 || res.prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("same-origin redirect prefixes = %v, want [198.51.100.0/24]", res.prefixes)
	}
}

// TestFeedFetcherDirectFetchWorks9912 is the no-redirect control for ordinary
// direct feed reads.
func TestFeedFetcherDirectFetchWorks9912(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/feed" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer server.Close()

	m := New(nil)
	fs := m.newFeed("direct", server.URL+"/feed", retainForever)
	res, err := m.readFeed(context.Background(), fs)
	if err != nil {
		t.Fatalf("direct fetch: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("direct fetch requests = %d, want 1", got)
	}
	if len(res.prefixes) != 1 || res.prefixes[0] != "203.0.113.0/24" {
		t.Fatalf("direct fetch prefixes = %v, want [203.0.113.0/24]", res.prefixes)
	}
}

// TestFeedFetcherIgnoresAmbientProxy9912 launches a fresh test process so the
// standard library's once-cached proxy environment cannot make this cell pass
// or fail based on another test's earlier HTTP request. The synthetic
// non-loopback feed.invalid origin is reachable on master only through the
// configured catcher proxy.
func TestFeedFetcherIgnoresAmbientProxy9912(t *testing.T) {
	proxyHits := atomic.Int32{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		if r.URL.String() != "http://feed.invalid/list.txt" {
			t.Errorf("proxy request URL = %q, want absolute feed URL", r.URL.String())
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer proxy.Close()

	t.Setenv("FEEDS_9912_PROXY_HELPER", "1")
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	cmd := exec.Command(os.Args[0], "-test.run=^TestFeedFetcherProxyHelper9912$", "-test.v")
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("proxy helper: %v\n%s", err, output)
	}
	if got := proxyHits.Load(); got != 0 {
		t.Fatalf("ambient proxy received %d requests, want 0; helper output:\n%s", got, output)
	}
}

func TestFeedFetcherProxyHelper9912(t *testing.T) {
	if os.Getenv("FEEDS_9912_PROXY_HELPER") != "1" {
		t.Skip("subprocess helper")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m := New(nil)
	fs := &feedState{url: "http://feed.invalid/list.txt"}
	if _, err := m.readFeed(ctx, fs); err == nil {
		t.Fatal("synthetic non-loopback origin unexpectedly fetched without proxy")
	}
}

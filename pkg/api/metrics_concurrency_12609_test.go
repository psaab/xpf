package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

func TestMetricsCollectorPassLimitSurvivesResponseTimeout12609(t *testing.T) {
	var entered atomic.Int32
	block := make(chan struct{})
	srv := &Server{
		dp:    dataplane.New(),
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		configPersistDegradedFn: func() bool {
			entered.Add(1)
			<-block
			return false
		},
	}
	ts := httptest.NewServer(newMetricsHandler(newCollector(srv), 40*time.Millisecond))
	defer ts.Close()

	var wg sync.WaitGroup
	statuses := make(chan int, metricsMaxInFlight)
	for range metricsMaxInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := ts.Client().Get(ts.URL)
			if err != nil {
				statuses <- 0
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	deadline := time.Now().Add(time.Second)
	for entered.Load() < metricsMaxInFlight && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := entered.Load(); got != metricsMaxInFlight {
		close(block)
		wg.Wait()
		t.Fatalf("collector passes entered=%d, want %d", got, metricsMaxInFlight)
	}
	// Let all three HTTP timeout responses expire while their collector passes
	// remain blocked. A fourth scrape must be refused rather than starting a
	// fourth pass after promhttp has returned 503 to the first three clients.
	time.Sleep(80 * time.Millisecond)
	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		close(block)
		wg.Wait()
		t.Fatalf("fourth GET /metrics: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		close(block)
		wg.Wait()
		t.Fatalf("fourth scrape status=%d, want 503", resp.StatusCode)
	}
	if got := entered.Load(); got != metricsMaxInFlight {
		close(block)
		wg.Wait()
		t.Fatalf("collector passes entered=%d after timeouts, want bound %d", got, metricsMaxInFlight)
	}
	close(block)
	wg.Wait()
	close(statuses)
	for code := range statuses {
		if code != http.StatusServiceUnavailable {
			t.Errorf("timed-out scrape status=%d, want 503", code)
		}
	}
}

func TestMetricsCanceledLeaderKeepsHealthyJoinerData12609(t *testing.T) {
	c := newSessionGaugeCollector()
	c.sessionGaugeTTLOverride = time.Hour
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		entered: make(chan struct{}, 1),
		gate:    make(chan struct{}),
		v4:      []dataplane.SessionValue{{IsReverse: 0}},
	}
	type result struct {
		snapshot sessionGaugeSnapshot
		ok       bool
	}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderDone := make(chan result, 1)
	go func() {
		snapshot, ok := c.sessionGaugeSnapshotCachedContext(leaderCtx, dp)
		leaderDone <- result{snapshot: snapshot, ok: ok}
	}()
	<-dp.entered
	followerDone := make(chan result, 1)
	go func() {
		snapshot, ok := c.sessionGaugeSnapshotCachedContext(context.Background(), dp)
		followerDone <- result{snapshot: snapshot, ok: ok}
	}()
	time.Sleep(30 * time.Millisecond)
	cancelLeader()
	leader := <-leaderDone
	close(dp.gate)
	follower := <-followerDone
	if leader.ok {
		t.Fatal("canceled leader unexpectedly received a successful census")
	}
	if !follower.ok || follower.snapshot.active != 1 {
		t.Fatalf("healthy joiner got (%+v, %v), want one active session", follower.snapshot, follower.ok)
	}
	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("shared walks=%d, want one", got)
	}
}

func TestMetricsHTTPCanceledLeaderKeepsHealthyJoinerData12609(t *testing.T) {
	dp := &countingSessionDP{
		Manager: dataplane.New(),
		entered: make(chan struct{}, 1),
		gate:    make(chan struct{}),
		v4:      []dataplane.SessionValue{{IsReverse: 0}},
	}
	srv := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	ts := httptest.NewServer(newMetricsHandler(newCollector(srv), 2*time.Second))
	defer ts.Close()

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderReq, err := http.NewRequestWithContext(leaderCtx, http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaderDone := make(chan error, 1)
	go func() {
		resp, err := ts.Client().Do(leaderReq)
		if resp != nil {
			resp.Body.Close()
		}
		leaderDone <- err
	}()
	select {
	case <-dp.entered:
	case <-time.After(time.Second):
		cancelLeader()
		close(dp.gate)
		t.Fatal("leader did not enter the census")
	}

	type scrape struct {
		code int
		body string
		err  error
	}
	followerDone := make(chan scrape, 1)
	go func() {
		resp, err := ts.Client().Get(ts.URL)
		if err != nil {
			followerDone <- scrape{err: err}
			return
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		followerDone <- scrape{code: resp.StatusCode, body: string(body), err: readErr}
	}()
	// Give the healthy scrape time to attach to the already-running refresh.
	time.Sleep(30 * time.Millisecond)
	cancelLeader()
	if err := <-leaderDone; err == nil {
		close(dp.gate)
		t.Fatal("canceled leader unexpectedly received a response")
	}
	close(dp.gate)
	follower := <-followerDone
	if follower.err != nil {
		t.Fatalf("healthy joiner GET /metrics: %v", follower.err)
	}
	if follower.code != http.StatusOK || !strings.Contains(follower.body, "xpf_sessions_breakdown_scrape_ok 1") || !strings.Contains(follower.body, "xpf_sessions_active 1") {
		t.Fatalf("healthy joiner response code=%d lacks the completed census: %s", follower.code, follower.body)
	}
	if got := dp.walks.Load(); got != 1 {
		t.Fatalf("shared walks=%d, want one", got)
	}
}

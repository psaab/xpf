package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
)

type slowMetricsDP12609 struct {
	*dataplane.Manager
	started chan struct{}
	done    chan struct{}
	v6Walks atomic.Int32
}

func (*slowMetricsDP12609) IsLoaded() bool { return true }

func (d *slowMetricsDP12609) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	close(d.started)
	for i := range sessionWalkCancelInterval {
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{}) {
			break
		}
		if i == 0 {
			// Leave ample time for the collector to reach the session census,
			// then make the walk outlive promhttp's response timeout.
			time.Sleep(500 * time.Millisecond)
		}
	}
	close(d.done)
	return nil
}
func (d *slowMetricsDP12609) IterateSessionsV6(func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.v6Walks.Add(1)
	return nil
}

func TestMetricsHTTPTimeoutCompletesSharedSessionWalk12609(t *testing.T) {
	dp := &slowMetricsDP12609{
		Manager: dataplane.New(),
		started: make(chan struct{}),
		done:    make(chan struct{}),
	}
	c := newCollector(&Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))})
	handler := newMetricsHandler(c, 250*time.Millisecond)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /metrics status=%d, want 503", resp.StatusCode)
	}
	select {
	case <-dp.started:
	default:
		t.Fatal("session census did not start before the scrape timeout")
	}
	select {
	case <-dp.done:
	case <-time.After(2 * time.Second):
		t.Fatal("shared walk did not complete after its starter's scrape timed out")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.sessionGaugeMu.Lock()
		valid, snap := c.sessionGaugeValid, c.sessionGaugeSnap
		c.sessionGaugeMu.Unlock()
		if valid && snap.ipv4 == sessionWalkCancelInterval {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.sessionGaugeMu.Lock()
	valid, snap := c.sessionGaugeValid, c.sessionGaugeSnap
	c.sessionGaugeMu.Unlock()
	if !valid || snap.ipv4 != sessionWalkCancelInterval {
		t.Fatalf("timed-out walk did not fill cache: valid=%v snapshot=%+v", valid, snap)
	}
	if got := dp.v6Walks.Load(); got != 1 {
		t.Fatalf("v6 census started %d times, want one completed pass", got)
	}
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("session-walk slot remained held after completed timed-out scrape: %v", err)
	}
	release()
}

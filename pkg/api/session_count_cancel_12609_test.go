package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/psaab/xpf/pkg/dataplane"
	"github.com/psaab/xpf/pkg/diagcmd"
)

const sessionCountCancelRows12609 = 2048

type cancelStatusDP12609 struct {
	*dataplane.Manager
	cancel   context.CancelFunc
	cancelV6 bool
	v4       int
	v6Walks  int
}

func (*cancelStatusDP12609) IsLoaded() bool { return true }

func (d *cancelStatusDP12609) SessionCountContext(ctx context.Context) (int, int, error) {
	for i := range sessionCountCancelRows12609 {
		d.v4++
		if i+1 == sessionWalkCancelInterval && !d.cancelV6 {
			d.cancel()
		}
		if (i+1)%sessionWalkCancelInterval == 0 && ctx.Err() != nil {
			return 0, 0, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	d.v6Walks++
	for i := range sessionCountCancelRows12609 {
		if i+1 == sessionWalkCancelInterval && d.cancelV6 {
			d.cancel()
		}
		if (i+1)%sessionWalkCancelInterval == 0 && ctx.Err() != nil {
			return 0, 0, ctx.Err()
		}
	}
	return 0, 0, nil
}

func TestRESTStatusCancellationWritesNoSuccessBody12609(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { sessionWalkLimiter = orig })
	ctx, cancel := context.WithCancel(context.Background())
	dp := &cancelStatusDP12609{Manager: dataplane.New(), cancel: cancel}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).WithContext(ctx)
	s.statusHandler(rr, req)
	if rr.Body.Len() != 0 {
		t.Fatalf("body=%q, want no success body after cancellation", rr.Body.String())
	}
	if dp.v4 != sessionWalkCancelInterval || dp.v6Walks != 0 {
		t.Fatalf("v4 visits=%d, v6 walks=%d; want sampled stop in v4 and no v6", dp.v4, dp.v6Walks)
	}
	release, err := sessionWalkLimiter.Acquire()
	if err != nil {
		t.Fatalf("walk slot not released: %v", err)
	}
	release()
}

func TestRESTStatusCancellationDuringV612609(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { sessionWalkLimiter = orig })
	ctx, cancel := context.WithCancel(context.Background())
	dp := &cancelStatusDP12609{Manager: dataplane.New(), cancel: cancel, cancelV6: true}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).WithContext(ctx)

	s.statusHandler(rr, req)
	if rr.Body.Len() != 0 {
		t.Fatalf("body=%q, want no success body after v6 cancellation", rr.Body.String())
	}
	if dp.v4 != sessionCountCancelRows12609 || dp.v6Walks != 1 {
		t.Fatalf("v4 visits=%d, v6 walks=%d; want complete v4 and one aborted v6 pass", dp.v4, dp.v6Walks)
	}
}

func TestRESTStatusDeadlineWritesNoSuccessBody12609(t *testing.T) {
	orig := sessionWalkLimiter
	sessionWalkLimiter = diagcmd.NewLimiter(1)
	t.Cleanup(func() { sessionWalkLimiter = orig })
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	dp := &cancelStatusDP12609{Manager: dataplane.New(), cancel: func() {}}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil).WithContext(ctx)
	s.statusHandler(rr, req)
	if rr.Body.Len() != 0 || dp.v6Walks != 0 {
		t.Fatalf("body=%q v6walks=%d, want empty body and no v6 pass after deadline", rr.Body.String(), dp.v6Walks)
	}
}

type cancelMetricsDP12609 struct {
	*dataplane.Manager
	cancelAtV4 bool
	cancelAtV6 bool
	cancel     context.CancelFunc
	v4Walks    int
	v6Walks    int
	completed  chan struct{}
}

func (*cancelMetricsDP12609) IsLoaded() bool { return true }

func (d *cancelMetricsDP12609) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	d.v4Walks++
	for i := range sessionCountCancelRows12609 {
		if d.cancelAtV4 && i+1 == sessionWalkCancelInterval {
			d.cancel()
		}
		if !fn(dataplane.SessionKey{}, dataplane.SessionValue{}) {
			break
		}
	}
	return nil
}

func (d *cancelMetricsDP12609) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	d.v6Walks++
	for i := range sessionCountCancelRows12609 {
		if d.cancelAtV6 && i+1 == sessionWalkCancelInterval {
			d.cancel()
		}
		if !fn(dataplane.SessionKeyV6{}, dataplane.SessionValueV6{}) {
			break
		}
	}
	if d.completed != nil {
		close(d.completed)
	}
	return nil
}

func TestCancelledScrapeDoesNotCancelSharedCensus12609(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cancelV4 bool
		cancelV6 bool
	}{
		{name: "v4", cancelV4: true},
		{name: "v6", cancelV6: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dp := &cancelMetricsDP12609{Manager: dataplane.New(), cancelAtV4: tc.cancelV4, cancelAtV6: tc.cancelV6, cancel: cancel, completed: make(chan struct{})}
			c := newCollector(&Server{})
			prior := sessionGaugeSnapshot{active: 19, established: 13, ipv4: 11, ipv6: 8}
			c.sessionGaugeSnap = prior
			c.sessionGaugeValid = true
			c.sessionGaugeComputedAt = time.Now().Add(-2 * time.Hour)
			ch := make(chan prometheus.Metric, 32)
			c.collectSessionGaugesContext(ctx, ch, dp)
			close(ch)
			scrapeFailed := false
			for m := range ch {
				metric := &dto.Metric{}
				if err := m.Write(metric); err != nil {
					t.Fatalf("metric Write: %v", err)
				}
				if metric.GetGauge() != nil && metric.GetGauge().GetValue() == 0 && m.Desc().String() == c.sessionScrapeOK.String() {
					scrapeFailed = true
				}
			}
			if !scrapeFailed {
				t.Fatal("cancelled scrape did not expose scrape_ok=0")
			}
			select {
			case <-dp.completed:
			case <-time.After(time.Second):
				t.Fatal("shared census did not complete after request cancellation")
			}
			deadline := time.Now().Add(time.Second)
			var valid bool
			var snap sessionGaugeSnapshot
			for time.Now().Before(deadline) {
				c.sessionGaugeMu.Lock()
				valid, snap = c.sessionGaugeValid, c.sessionGaugeSnap
				c.sessionGaugeMu.Unlock()
				if valid && snap.active == sessionCountCancelRows12609*2 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			want := sessionGaugeSnapshot{
				active: sessionCountCancelRows12609 * 2,
				ipv4:   sessionCountCancelRows12609,
				ipv6:   sessionCountCancelRows12609,
			}
			if !valid || snap != want {
				t.Fatalf("completed shared walk cache=%+v valid=%v, want %+v and valid", snap, valid, want)
			}
			if dp.v6Walks != 1 {
				t.Fatalf("v6 walk count=%d want 1 completed shared pass", dp.v6Walks)
			}
			release, err := sessionWalkLimiter.Acquire()
			if err != nil {
				t.Fatalf("walk slot not released after cancelled scrape: %v", err)
			}
			release()
		})
	}
}

func TestSessionGaugeDeadlineSignalsFailedScrape12609(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	dp := &cancelMetricsDP12609{Manager: dataplane.New()}
	c := newCollector(&Server{})
	prior := sessionGaugeSnapshot{active: 3, ipv4: 3}
	c.sessionGaugeSnap = prior
	c.sessionGaugeValid = true
	c.sessionGaugeComputedAt = time.Now().Add(-2 * time.Hour)
	ch := make(chan prometheus.Metric, 32)
	c.collectSessionGaugesContext(ctx, ch, dp)
	close(ch)
	scrapeFailed := false
	for m := range ch {
		metric := &dto.Metric{}
		if err := m.Write(metric); err != nil {
			t.Fatalf("metric Write: %v", err)
		}
		if metric.GetGauge() != nil && metric.GetGauge().GetValue() == 0 && m.Desc().String() == c.sessionScrapeOK.String() {
			scrapeFailed = true
		}
	}
	if !scrapeFailed || c.sessionGaugeSnap != prior || dp.v6Walks != 0 {
		t.Fatalf("scrape_failed=%v snapshot=%+v v6_walks=%d; want failed scrape, unchanged cache and no v6 pass", scrapeFailed, c.sessionGaugeSnap, dp.v6Walks)
	}
}

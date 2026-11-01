package fabricsegment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// sampleFunc runs a sampler for link until ctx is done, feeding tracker. It
// returns nil when ctx ended it, or the error that stopped it early; the
// Monitor then restarts it with backoff. The production implementation is
// the AF_PACKET tap (sampler_linux.go); tests inject their own.
type sampleFunc func(ctx context.Context, link Link, tracker *Tracker) error

// Restart backoff for a sampler that stopped on its own (#18751 review: a
// stopped sampler used to stay registered and was never restarted, so the
// link went blind and a raised alarm never cleared).
const (
	restartBackoffMin = 5 * time.Second
	restartBackoffMax = 5 * time.Minute
	// A sampler that ran at least this long before stopping starts a new
	// failure streak: its next exit is logged again and the backoff resets.
	stableRun = time.Minute
)

// Monitor owns one supervised sampler per armed fabric link.
type Monitor struct {
	mu         sync.Mutex
	sample     sampleFunc
	now        func() time.Time
	backoffMin time.Duration
	backoffMax time.Duration
	transition func(Link, bool, string) // alarm edges; logTransition in production
	running    map[string]*monitored    // by Link.key()
}

type monitored struct {
	link    Link
	tracker *Tracker
	cancel  context.CancelFunc
	// Guarded by Monitor.mu.
	down      bool      // the sampler stopped and is waiting to restart
	downSince time.Time // start of the current failure streak
	lastErr   string
	streak    bool // an exit has been logged and no stable run followed
}

// NewMonitor returns a monitor that starts samplers with sample.
func NewMonitor(sample sampleFunc) *Monitor {
	return &Monitor{
		sample:     sample,
		now:        time.Now,
		backoffMin: restartBackoffMin,
		backoffMax: restartBackoffMax,
		transition: logTransition,
		running:    map[string]*monitored{},
	}
}

var (
	defaultMu      sync.Mutex
	defaultMonitor *Monitor
)

// Default is the process-wide monitor the userspace dataplane manager feeds
// (SyncFabricState) and `show chassis cluster status` reads.
func Default() *Monitor {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultMonitor == nil {
		defaultMonitor = NewMonitor(runTapSampler)
	}
	return defaultMonitor
}

// SwapDefault installs m as the process-wide monitor and returns the one it
// replaced (nil if none had been created). Tests use it to observe what the
// daemon feeds the watcher; production code never calls it.
func SwapDefault(m *Monitor) *Monitor {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	prev := defaultMonitor
	defaultMonitor = m
	return prev
}

// Armable reports whether link has everything the watcher needs: a parent
// netdev and BOTH fabric MACs. Without the peer MAC every peer frame would
// read as foreign, so a link is not armed until the peer resolves.
func Armable(link Link) bool {
	return link.ParentIfindex > 0 && len(link.LocalMAC) == 6 && len(link.PeerMAC) == 6 &&
		!isZeroMAC(link.LocalMAC) && !isZeroMAC(link.PeerMAC)
}

// Update replaces the watched set with links. A link whose identity (parent,
// either MAC) is unchanged keeps its sampler and its evidence; a changed or
// removed link's sampler stops and its tracker is retired (a raised alarm
// logs its clear). Unarmable links are not sampled.
func (m *Monitor) Update(links []Link) {
	if m == nil {
		return
	}
	want := map[string]Link{}
	for _, link := range links {
		if Armable(link) {
			want[link.key()] = link
		}
	}
	var retired []*monitored
	m.mu.Lock()
	for key, mon := range m.running {
		if _, ok := want[key]; !ok {
			mon.cancel()
			delete(m.running, key)
			retired = append(retired, mon)
		}
	}
	for key, link := range want {
		if _, ok := m.running[key]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		mon := &monitored{link: link, tracker: NewTracker(link, m.transition), cancel: cancel}
		m.running[key] = mon
		if m.sample != nil {
			go m.supervise(ctx, mon)
		}
	}
	m.mu.Unlock()
	for _, mon := range retired {
		mon.tracker.Retire("fabric link identity changed or removed")
	}
}

// supervise runs mon's sampler until ctx is done, restarting it with
// exponential backoff whenever it stops on its own. The tracker (and any
// raised alarm) survives a restart. While the sampler is down the hold clock
// keeps running, so a raised alarm still clears on schedule.
func (m *Monitor) supervise(ctx context.Context, mon *monitored) {
	backoff := m.backoffMin
	for {
		started := m.now()
		err := m.sample(ctx, mon.link, mon.tracker)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("sampler returned without an error")
		}
		stable := m.now().Sub(started) >= stableRun
		if stable {
			backoff = m.backoffMin
		}
		m.markDown(mon, err, stable, backoff)
		if !waitTicking(ctx, mon.tracker, backoff) {
			return
		}
		m.mu.Lock()
		mon.down = false
		m.mu.Unlock()
		backoff *= 2
		if backoff > m.backoffMax {
			backoff = m.backoffMax
		}
	}
}

func (m *Monitor) markDown(mon *monitored, err error, stable bool, retry time.Duration) {
	m.mu.Lock()
	if stable {
		mon.streak = false
	}
	first := !mon.streak
	mon.streak = true
	if first {
		mon.downSince = m.now()
	}
	mon.down = true
	mon.lastErr = err.Error()
	m.mu.Unlock()
	if first {
		slog.Warn("fabric segment: watcher stopped; restarting with backoff (#18719)",
			"fabric", mon.link.Name, "parent", mon.link.Parent, "err", err, "retry_in", retry.String())
		return
	}
	slog.Debug("fabric segment: watcher restart failed (#18719)",
		"fabric", mon.link.Name, "parent", mon.link.Parent, "err", err, "retry_in", retry.String())
}

// waitTicking sleeps d (in steps of at most a second, ticking tracker) and
// reports false if ctx ended first.
func waitTicking(ctx context.Context, tracker *Tracker, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return true
		}
		if left > time.Second {
			left = time.Second
		}
		t := time.NewTimer(left)
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
		tracker.Tick(time.Now())
	}
}

// Alarms returns the operator-facing lines, ordered by link name: a raised
// alarm, and a "watcher not running" line for a link whose sampler is down
// (an unwatched link must not read as a clean one).
func (m *Monitor) Alarms() []string {
	if m == nil {
		return nil
	}
	type row struct {
		mon       *monitored
		down      bool
		downSince time.Time
		lastErr   string
	}
	m.mu.Lock()
	rows := make([]row, 0, len(m.running))
	for _, mon := range m.running {
		rows = append(rows, row{mon: mon, down: mon.down, downSince: mon.downSince, lastErr: mon.lastErr})
	}
	now := m.now()
	m.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].mon.link.Name < rows[j].mon.link.Name })
	var out []string
	for _, r := range rows {
		if r.down {
			out = append(out, fmt.Sprintf("fabric link %s (%s): the fabric-segment watcher is not running (down %s: %s); non-peer source MACs on this link are not being watched, retrying (#18719)",
				r.mon.link.Name, r.mon.link.Parent, now.Sub(r.downSince).Round(time.Second), strings.TrimSpace(r.lastErr)))
		}
		if line := r.mon.tracker.Alarm(now); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// Watched returns the armed links, ordered by name.
func (m *Monitor) Watched() []Link {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	out := make([]Link, 0, len(m.running))
	for _, mon := range m.running {
		out = append(out, mon.link)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Stop cancels every sampler.
func (m *Monitor) Stop() {
	if m == nil {
		return
	}
	m.Update(nil)
}

// tracker returns the tracker for a running link key (tests).
func (m *Monitor) trackerFor(link Link) *Tracker {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mon, ok := m.running[link.key()]; ok {
		return mon.tracker
	}
	return nil
}

// logTransition records the alarm edges once each, so the journal carries
// when the segment stopped (or resumed) looking private.
func logTransition(link Link, raised bool, detail string) {
	if raised {
		slog.Warn("fabric segment: non-peer source MAC on the fabric link (#18719)",
			"fabric", link.Name, "parent", link.Parent, "detail", detail)
		return
	}
	slog.Info("fabric segment: alarm cleared (#18719)",
		"fabric", link.Name, "parent", link.Parent, "reason", detail, "hold", AlarmHold.String())
}

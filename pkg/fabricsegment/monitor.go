package fabricsegment

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// sampleFunc runs a sampler for link until ctx is done, feeding tracker.
// The production implementation is the AF_PACKET tap (sampler_linux.go);
// tests inject their own.
type sampleFunc func(ctx context.Context, link Link, tracker *Tracker)

// Monitor owns one sampler per armed fabric link.
type Monitor struct {
	mu      sync.Mutex
	sample  sampleFunc
	now     func() time.Time
	running map[string]*monitored // by Link.key()
}

type monitored struct {
	link    Link
	tracker *Tracker
	cancel  context.CancelFunc
}

// NewMonitor returns a monitor that starts samplers with sample.
func NewMonitor(sample sampleFunc) *Monitor {
	return &Monitor{sample: sample, now: time.Now, running: map[string]*monitored{}}
}

var (
	defaultOnce    sync.Once
	defaultMonitor *Monitor
)

// Default is the process-wide monitor the userspace dataplane manager feeds
// (SyncFabricState) and `show chassis cluster status` reads.
func Default() *Monitor {
	defaultOnce.Do(func() { defaultMonitor = NewMonitor(runTapSampler) })
	return defaultMonitor
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
// removed link's sampler stops. Unarmable links are not sampled.
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
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, mon := range m.running {
		if _, ok := want[key]; !ok {
			mon.cancel()
			delete(m.running, key)
		}
	}
	for key, link := range want {
		if _, ok := m.running[key]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		tracker := NewTracker(link, logTransition)
		m.running[key] = &monitored{link: link, tracker: tracker, cancel: cancel}
		if m.sample != nil {
			go m.sample(ctx, link, tracker)
		}
	}
}

// Alarms returns the raised alarm lines, ordered by link name.
func (m *Monitor) Alarms() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	mons := make([]*monitored, 0, len(m.running))
	for _, mon := range m.running {
		mons = append(mons, mon)
	}
	now := m.now()
	m.mu.Unlock()
	sort.Slice(mons, func(i, j int) bool { return mons[i].link.Name < mons[j].link.Name })
	var out []string
	for _, mon := range mons {
		if line := mon.tracker.Alarm(now); line != "" {
			out = append(out, line)
		}
	}
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
func logTransition(link Link, raised bool, summary string) {
	if raised {
		slog.Warn("fabric segment: non-peer source MAC on the fabric link (#18719)",
			"fabric", link.Name, "parent", link.Parent, "detail", summary)
		return
	}
	slog.Info("fabric segment: no non-peer source MAC seen within the hold window; alarm cleared (#18719)",
		"fabric", link.Name, "parent", link.Parent, "hold", AlarmHold.String())
}

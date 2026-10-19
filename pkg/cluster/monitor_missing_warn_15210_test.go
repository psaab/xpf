package cluster

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15210 (A21-02): pollInterfaceMonitors emitted
// slog.Warn("cluster monitor: local interface missing, treating as down")
// on every 1s poll tick for each absent local monitor, flooding the journal
// and drowning other diagnostics. The warning must be emitted once per
// absence episode per (rg, interface), and again only after the interface
// returns and goes missing again. The missing interface must still count
// as down (#5080 demotion preserved).

type warnLogBuffer15210 struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *warnLogBuffer15210) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *warnLogBuffer15210) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func withCapturedWarnLog15210(t *testing.T) *warnLogBuffer15210 {
	t.Helper()
	buf := new(warnLogBuffer15210)
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return buf
}

func TestMonitor_MissingLocalInterfaceWarnOncePerAbsence15210(t *testing.T) {
	logBuf := withCapturedWarnLog15210(t)

	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	// trust0 is absent from the kernel: LinkByName always errors.
	nlh := newMockNlHandle()

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	const polls = 5
	for range polls {
		mon.poll()
	}

	if got := strings.Count(logBuf.String(), "local interface missing"); got != 1 {
		t.Fatalf("%d polls with missing trust0 produced %d warnings, want 1", polls, got)
	}
	// Neighbouring legitimate behaviour preserved: missing still counts as
	// down and demotes the RG (#5080).
	if states := m.GroupStates(); states[0].Weight != 155 {
		t.Fatalf("weight with missing trust0 = %d, want 155 (demoted)", states[0].Weight)
	}

	// Interface returns: no missing warning, weight recovers.
	nlh.setLink("trust0", true)
	mon.poll()
	if got := strings.Count(logBuf.String(), "local interface missing"); got != 1 {
		t.Fatalf("after trust0 returned, warnings = %d, want still 1", got)
	}
	if states := m.GroupStates(); states[0].Weight != 255 {
		t.Fatalf("weight after trust0 returned = %d, want 255", states[0].Weight)
	}

	// Interface goes missing again: a new absence episode warns once more,
	// and repeated polls in that episode do not flood.
	delete(nlh.links, "trust0")
	for range 3 {
		mon.poll()
	}
	if got := strings.Count(logBuf.String(), "local interface missing"); got != 2 {
		t.Fatalf("second absence episode produced %d total warnings, want 2", got)
	}
	if states := m.GroupStates(); states[0].Weight != 155 {
		t.Fatalf("weight in second absence = %d, want 155 (demoted)", states[0].Weight)
	}
}

func TestMonitor_PresentLocalInterfaceNoMissingWarn15210(t *testing.T) {
	logBuf := withCapturedWarnLog15210(t)

	m := NewManager(0, 1)
	cfg := makeConfig(
		makeRG(0, false, map[int]int{0: 200},
			&config.InterfaceMonitor{Interface: "trust0", Weight: 100},
		),
	)
	m.UpdateConfig(cfg)
	drainEvents(m, 1)

	nlh := newMockNlHandle()
	nlh.setLink("trust0", true)

	mon := NewMonitor(m, cfg.RedundancyGroups)
	mon.nlHandle = nlh
	setNoDampening(mon)

	for range 3 {
		mon.poll()
	}
	if got := strings.Count(logBuf.String(), "local interface missing"); got != 0 {
		t.Fatalf("present trust0 produced %d missing warnings, want 0", got)
	}
	if states := m.GroupStates(); states[0].Weight != 255 {
		t.Fatalf("weight with present trust0 = %d, want 255", states[0].Weight)
	}
}

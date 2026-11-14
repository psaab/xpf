package frr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// zebraNHTFake19083 models zebra's static NHT binding per family and frr-reload
// converging the running config to frr.conf. Every batch, binding read and
// reload is logged in order; a reload event records the binding zebra held
// when frr-reload.py started, which is the state its delete pass acts on.
// failAfter / blockAfter are one-shot: apply that many lines of the next
// batch, then fail, or block until the batch's context is done (honouring
// cancellation and deadlines like the real vtysh exec).
type zebraNHTFake19083 struct {
	*fakeExecutor
	mu            sync.Mutex
	v4, v6        string
	events        []string
	failAfter     int
	blockAfter    int
	ignore        bool
	unreadable    bool
	reloadEntered chan struct{}
	reloadRelease chan struct{}
}

func newZebraNHTFake19083(v4, v6 string) *zebraNHTFake19083 {
	return &zebraNHTFake19083{fakeExecutor: &fakeExecutor{}, v4: v4, v6: v6, failAfter: -1, blockAfter: -1}
}

func (f *zebraNHTFake19083) applyLocked(line string) {
	switch {
	case strings.HasPrefix(line, "ip nht static route-map "):
		f.v4 = strings.TrimPrefix(line, "ip nht static route-map ")
	case strings.HasPrefix(line, "ipv6 nht static route-map "):
		f.v6 = strings.TrimPrefix(line, "ipv6 nht static route-map ")
	}
}

func (f *zebraNHTFake19083) VtyshConfigLines(ctx context.Context, lines []string) ([]byte, error) {
	f.mu.Lock()
	f.events = append(f.events, "batch "+strings.Join(lines, "|"))
	fa, ba := f.failAfter, f.blockAfter
	f.failAfter, f.blockAfter = -1, -1
	n := len(lines)
	if fa >= 0 && fa < n {
		n = fa
	}
	if ba >= 0 && ba < n {
		n = ba
	}
	if !f.ignore {
		for _, l := range lines[:n] {
			f.applyLocked(l)
		}
	}
	f.mu.Unlock()
	if ba >= 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fa >= 0 {
		return []byte("% injected rejection"), errors.New("injected vtysh failure")
	}
	return nil, nil
}

func (f *zebraNHTFake19083) Vtysh(ctx context.Context, cmd string) (string, error) {
	if cmd != "show ip nht route-map" && cmd != "show ipv6 nht route-map" {
		return f.fakeExecutor.Vtysh(ctx, cmd)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "read")
	if f.unreadable {
		return "% Unknown command: " + cmd + "\n", nil
	}
	v := f.v4
	if strings.HasPrefix(cmd, "show ipv6") {
		v = f.v6
	}
	if v == "" {
		v = "none"
	}
	// The FRR 10.6.0 show_vrf_nht_rm layout.
	return "VRF: default\nProtocol                  : route-map\n-------------------------------------\n" +
		fmt.Sprintf("%-24s  : none\n%-24s  : %-10s\n%-24s  : none\n", "system", "static", v, "bgp"), nil
}

func (f *zebraNHTFake19083) FrrReloadPy(ctx context.Context, conf string) error {
	f.mu.Lock()
	f.events = append(f.events, fmt.Sprintf("reload v4=%s v6=%s", f.v4, f.v6))
	entered, release := f.reloadEntered, f.reloadRelease
	f.reloadEntered = nil
	f.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	if data, err := os.ReadFile(conf); err == nil && strings.Contains(string(data), "ip nht static route-map "+nhtMapA19083+"\n") {
		f.mu.Lock()
		f.v4, f.v6 = nhtMapA19083, nhtMapA19083
		f.mu.Unlock()
	}
	return f.fakeExecutor.FrrReloadPy(ctx, conf)
}

func (f *zebraNHTFake19083) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *zebraNHTFake19083) bindings() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.v4, f.v6
}

func (f *zebraNHTFake19083) reset() {
	f.mu.Lock()
	f.events = nil
	f.mu.Unlock()
}

// fc2For19083 differs from clusterFC19083 by one static, so applying it
// rewrites the section and runs a diff reload.
func fc2For19083() *FullConfig {
	fc := clusterFC19083(true)
	fc.StaticRoutes = append(fc.StaticRoutes, &config.StaticRoute{Destination: "192.0.2.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}})
	return fc
}

var restoreBatch19083 = "batch ip nht static route-map " + nhtMapA19083 + "|ipv6 nht static route-map " + nhtMapA19083

// reloadEventsSawAlternate19083 returns every reload event that started with
// the alternate bound in either family.
func reloadEventsSawAlternate19083(events []string) []string {
	var bad []string
	for _, e := range events {
		if strings.HasPrefix(e, "reload ") && strings.Contains(e, nhtMapB19083) {
			bad = append(bad, e)
		}
	}
	return bad
}

func newLiteralNHTManager19083(t *testing.T, fake *zebraNHTFake19083) *Manager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), exec: fake, mgrCtx: ctx, mgrCancel: cancel}
	t.Cleanup(m.Stop)
	if err := m.ApplyFull(clusterFC19083(true)); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	return m
}

// TestStaticNHTInterruptedRebindRestoresPrimaryBeforeReload19083 (Codex P1,
// R22 #5): a rebind that stops after binding the alternate (a rejected line, a
// cancellation, a deadline) leaves the alternate bound. frr-reload.py would
// delete that binding before adding the primary's, an unbound window. The next
// diff reload must therefore start only after the primary is bound by direct
// replacement, and a NEW manager (a previous xpfd killed mid-rebind) must do
// the same on its first reload.
func TestStaticNHTInterruptedRebindRestoresPrimaryBeforeReload19083(t *testing.T) {
	orig := staticNHTReevalTimeout19083
	staticNHTReevalTimeout19083 = 100 * time.Millisecond
	t.Cleanup(func() { staticNHTReevalTimeout19083 = orig })
	for _, tc := range []struct {
		name      string
		interrupt func(f *zebraNHTFake19083)
	}{
		{"rejected after the alternate", func(f *zebraNHTFake19083) { f.failAfter = 2 }},
		{"rejected after one primary line", func(f *zebraNHTFake19083) { f.failAfter = 3 }},
		{"deadline after the alternate", func(f *zebraNHTFake19083) { f.blockAfter = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newZebraNHTFake19083("", "")
			m := newLiteralNHTManager19083(t, fake)
			tc.interrupt(fake)
			if err := m.ReevaluateStaticNHT19083(); err == nil {
				t.Fatal("the interrupted rebind reported success")
			}
			if v4, v6 := fake.bindings(); v4 != nhtMapB19083 && v6 != nhtMapB19083 {
				t.Fatalf("setup: the interruption left %q/%q, want the alternate bound in a family", v4, v6)
			}
			fake.reset()
			if err := m.ApplyFull(fc2For19083()); err != nil {
				t.Fatalf("apply after the interrupted rebind: %v", err)
			}
			ev := fake.snapshot()
			if bad := reloadEventsSawAlternate19083(ev); len(bad) != 0 {
				t.Fatalf("a diff reload started with the alternate bound (unbound window): %q; events %q", bad, ev)
			}
			if !containsInOrder19083(ev, restoreBatch19083, "reload v4="+nhtMapA19083) {
				t.Fatalf("events %q: want the direct primary restore, then the reload", ev)
			}
			if m.staticNHTRestorePending19083 {
				t.Fatal("restore still pending after a verified restore")
			}
		})
	}
	t.Run("new manager after a kill mid-rebind", func(t *testing.T) {
		fake := newZebraNHTFake19083(nhtMapB19083, nhtMapB19083)
		conf := filepath.Join(t.TempDir(), "frr.conf")
		m := NewForTest(conf, fake)
		t.Cleanup(m.Stop)
		if err := m.ApplyFull(clusterFC19083(true)); err != nil {
			t.Fatalf("first apply: %v", err)
		}
		ev := fake.snapshot()
		if bad := reloadEventsSawAlternate19083(ev); len(bad) != 0 || !containsInOrder19083(ev, restoreBatch19083, "reload v4="+nhtMapA19083) {
			t.Fatalf("first reload of a new manager: events %q, want the primary restored before it", ev)
		}
	})
}

// TestStaticNHTRestoreWritesOnlyWhenAlternateBound19083: the restore reads
// zebra first. The primary or no binding at all (a fresh FRR: the reload adds
// it) writes nothing and settles; an unreadable binding writes nothing and
// stays pending (not evidence of the alternate).
func TestStaticNHTRestoreWritesOnlyWhenAlternateBound19083(t *testing.T) {
	for _, tc := range []struct {
		name        string
		v4, v6      string
		unreadable  bool
		wantPending bool
	}{
		{"primary bound", nhtMapA19083, nhtMapA19083, false, false},
		{"nothing bound", "", "", false, false},
		{"unreadable", nhtMapA19083, nhtMapA19083, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newZebraNHTFake19083(tc.v4, tc.v6)
			fake.unreadable = tc.unreadable
			m := NewForTest(filepath.Join(t.TempDir(), "frr.conf"), fake)
			t.Cleanup(m.Stop)
			if err := m.ApplyFull(clusterFC19083(true)); err != nil {
				t.Fatalf("apply: %v", err)
			}
			for _, e := range fake.snapshot() {
				if strings.HasPrefix(e, "batch ") {
					t.Fatalf("restore wrote %q, want no write (events %q)", e, fake.snapshot())
				}
			}
			if m.staticNHTRestorePending19083 != tc.wantPending {
				t.Fatalf("pending = %v, want %v", m.staticNHTRestorePending19083, tc.wantPending)
			}
		})
	}
}

// TestStaticNHTRestoreFailureDoesNotStartReload19083: with the alternate
// observed bound, a restore that fails, or that zebra does not reflect, does
// not start the diff reload (it would open the window); the apply reports the
// failure, the manager is degraded, and the retry restores before it reloads.
func TestStaticNHTRestoreFailureDoesNotStartReload19083(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *zebraNHTFake19083)
		fix   func(f *zebraNHTFake19083)
	}{
		{"restore rejected", func(f *zebraNHTFake19083) { f.failAfter = 0 }, func(*zebraNHTFake19083) {}},
		{"restore not reflected", func(f *zebraNHTFake19083) { f.ignore = true }, func(f *zebraNHTFake19083) {
			f.mu.Lock()
			f.ignore = false
			f.mu.Unlock()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newZebraNHTFake19083(nhtMapB19083, nhtMapB19083)
			tc.setup(fake)
			ctx, cancel := context.WithCancel(context.Background())
			m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), exec: fake, mgrCtx: ctx, mgrCancel: cancel,
				staticNHTRestorePending19083: true}
			t.Cleanup(m.Stop)
			if err := m.ApplyFull(clusterFC19083(true)); err == nil {
				t.Fatal("the apply succeeded although the binding restore failed")
			}
			for _, e := range fake.snapshot() {
				if strings.HasPrefix(e, "reload ") {
					t.Fatalf("a diff reload started after a failed restore: %q", fake.snapshot())
				}
			}
			if !m.ReloadDegraded() {
				t.Fatal("a failed restore did not leave the manager degraded (no retry would follow)")
			}
			tc.fix(fake)
			fake.reset()
			if stop, _ := m.retryReloadOnce(context.Background()); !stop {
				t.Fatalf("the retry did not converge: events %q", fake.snapshot())
			}
			if ev := fake.snapshot(); len(reloadEventsSawAlternate19083(ev)) != 0 || !containsInOrder19083(ev, restoreBatch19083, "reload v4="+nhtMapA19083) {
				t.Fatalf("retry events %q: want the primary restored, then the reload", ev)
			}
		})
	}
}

// TestStaticNHTRebindSerializesWithReload19083 (R22 #4): the rebind takes
// reloadMu, so it cannot land while a diff reload is running (for example
// after frr.conf already binds a map the running config does not define yet).
func TestStaticNHTRebindSerializesWithReload19083(t *testing.T) {
	fake := newZebraNHTFake19083("", "")
	m := newLiteralNHTManager19083(t, fake)
	entered, release := make(chan struct{}), make(chan struct{})
	fake.mu.Lock()
	fake.reloadEntered, fake.reloadRelease = entered, release
	fake.mu.Unlock()
	fake.reset()
	applied := make(chan error, 1)
	go func() { applied <- m.ApplyFull(fc2For19083()) }()
	<-entered
	rebound := make(chan error, 1)
	go func() { rebound <- m.ReevaluateStaticNHT19083() }()
	time.Sleep(200 * time.Millisecond)
	for _, e := range fake.snapshot() {
		if strings.HasPrefix(e, "batch ") {
			close(release)
			t.Fatalf("the rebind ran while a reload held the FRR writer lock: %q", fake.snapshot())
		}
	}
	close(release)
	if err := <-applied; err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := <-rebound; err != nil {
		t.Fatalf("rebind: %v", err)
	}
	ev := fake.snapshot()
	if !containsInOrder19083(ev, "reload v4=", "batch ip nht static route-map "+nhtMapB19083) {
		t.Fatalf("events %q: want the rebind after the reload", ev)
	}
}

// containsInOrder19083 reports whether events has an element with prefix a
// and a LATER element with prefix b.
func containsInOrder19083(events []string, a, b string) bool {
	for i, e := range events {
		if strings.HasPrefix(e, a) {
			for _, f := range events[i+1:] {
				if strings.HasPrefix(f, b) {
					return true
				}
			}
		}
	}
	return false
}

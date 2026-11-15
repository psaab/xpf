package frr

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	applyOnly     int // one-shot: apply only this many lines, report success
	ignore        bool
	unreadable    bool
	cmdDrift      bool          // every binding read fails as vtysh does on a command it does not know
	writeFail     bool          // every batch fails without applying (zebra not answering)
	unreadV4      int           // the next N v4 binding reads are a PARSE MISS
	unreadV6      int           // the next N v6 binding reads are a PARSE MISS
	execFail      bool          // every binding read's exec fails (zebra does not answer)
	execFailV4    int           // the next N v4 binding reads' exec fails
	execFailV6    int           // the next N v6 binding reads' exec fails
	readDelay     time.Duration // each binding read takes this long (honouring its context)
	batchGate     chan struct{}
	onBatch       func() // one-shot, run under mu after a batch applies
	reloadEntered chan struct{}
	reloadRelease chan struct{}
}

func newZebraNHTFake19083(v4, v6 string) *zebraNHTFake19083 {
	return &zebraNHTFake19083{fakeExecutor: &fakeExecutor{}, v4: v4, v6: v6, failAfter: -1, blockAfter: -1, applyOnly: -1}
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
	// Like exec.CommandContext, a context already done refuses to start: FRR
	// never sees the batch (Codex survivor on 18eb95d167: a settle on the
	// cancelled lifetime must not look like a successful rebind).
	// The attempt is still recorded, as "refused ...", so a cell can tell a
	// caller that did not try from one whose exec was refused.
	if err := ctx.Err(); err != nil {
		f.mu.Lock()
		f.events = append(f.events, "refused batch "+strings.Join(lines, "|"))
		f.mu.Unlock()
		return nil, err
	}
	f.mu.Lock()
	if f.writeFail {
		f.events = append(f.events, "failed batch "+strings.Join(lines, "|"))
		f.mu.Unlock()
		return []byte("% zebra did not answer (injected)"), errors.New("injected vtysh write failure")
	}
	f.events = append(f.events, "batch "+strings.Join(lines, "|"))
	fa, ba, ao, gate := f.failAfter, f.blockAfter, f.applyOnly, f.batchGate
	f.failAfter, f.blockAfter, f.applyOnly = -1, -1, -1
	n := len(lines)
	if fa >= 0 && fa < n {
		n = fa
	}
	if ba >= 0 && ba < n {
		n = ba
	}
	if ao >= 0 && ao < n {
		n = ao
	}
	if !f.ignore {
		for _, l := range lines[:n] {
			f.applyLocked(l)
		}
	}
	if fn := f.onBatch; fn != nil {
		f.onBatch = nil
		fn()
	}
	f.mu.Unlock()
	if ba >= 0 {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
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
	delay := f.readDelay
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "read")
	unread, xfail := &f.unreadV4, &f.execFailV4
	if strings.HasPrefix(cmd, "show ipv6") {
		unread, xfail = &f.unreadV6, &f.execFailV6
	}
	if f.cmdDrift {
		// realExecutor's error for vtysh's own parse error: exit 1, the
		// message on stdout (FRR 10.5.1, udp fw1, R24 NEW-A probe).
		return "", fmt.Errorf("vtysh %q: exit status 1: %% Unknown command: %s\n", cmd, cmd)
	}
	if f.execFail || *xfail > 0 {
		if *xfail > 0 {
			*xfail--
		}
		return "", errors.New("vtysh: zebra did not answer (injected)")
	}
	if f.unreadable || *unread > 0 {
		if *unread > 0 {
			*unread--
		}
		// A layout change: zebra answers, but with no "static : <map>" row.
		return "VRF default:\n  static -> route-map (layout changed, injected)\n", nil
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
// it), positively read in both families, writes nothing and settles. A
// standalone section reads nothing and does NOT settle (R24 P3-3: the reload
// it precedes may fail and leave the alternate bound for a later cluster
// apply).
func TestStaticNHTRestoreWritesOnlyWhenAlternateBound19083(t *testing.T) {
	for _, tc := range []struct {
		name        string
		v4, v6      string
		cluster     bool
		wantPending bool
	}{
		{"primary bound", nhtMapA19083, nhtMapA19083, true, false},
		{"nothing bound", "", "", true, false},
		{"standalone keeps pending", nhtMapB19083, nhtMapB19083, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newZebraNHTFake19083(tc.v4, tc.v6)
			m := NewForTest(filepath.Join(t.TempDir(), "frr.conf"), fake)
			t.Cleanup(m.Stop)
			if err := m.ApplyFull(clusterFC19083(tc.cluster)); err != nil {
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
		// Codex: a verification that checks only one family. The write lands
		// for v4 only; v6 stays on the alternate.
		{"restore lands for v4 only", func(f *zebraNHTFake19083) { f.applyOnly = 1 }, func(*zebraNHTFake19083) {}},
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

// TestStaticNHTRestoreUnreadableFailsClosed19083 (Codex P1 / R24 P3-1 on
// d8b6021582; R24 NEW-1 on 9d7abd581a): while a restore is pending, the diff
// reload starts only after the primary is POSITIVELY read in both families,
// or after a direct primary write that vtysh reported successful. An
// unreadable family before the write never lets the reload start unwritten.
// After a successful write:
//   - a read-back zebra did not answer (exec failure) keeps the restore pending
//     and the reload unstarted (fail closed);
//   - a read-back zebra answered but that has no parseable static row (a parse
//     miss, e.g. an FRR layout change) lets the reload start with an ERROR
//     log, so a layout change cannot wedge every apply from startup;
//   - a read command vtysh itself does not know (`% Unknown command`, exit 1;
//     R24 NEW-A) is the same command drift: it never succeeds, so it is a
//     parse miss, not an exec failure.
func TestStaticNHTRestoreUnreadableFailsClosed19083(t *testing.T) {
	for _, tc := range []struct {
		name       string
		setup      func(f *zebraNHTFake19083)
		wantReload bool
	}{
		{"parse miss before, readable after the write", func(f *zebraNHTFake19083) { f.unreadV4, f.unreadV6 = 1, 1 }, true},
		{"partial read: v4 alternate, v6 parse miss", func(f *zebraNHTFake19083) { f.unreadV6 = 1 }, true},
		{"exec failure before, readable after the write", func(f *zebraNHTFake19083) { f.execFailV4, f.execFailV6 = 1, 1 }, true},
		{"read-back parse miss after a successful write", func(f *zebraNHTFake19083) {
			f.onBatch = func() { f.unreadV4, f.unreadV6 = 1, 1 }
		}, true},
		{"parse miss throughout", func(f *zebraNHTFake19083) { f.unreadable = true }, true},
		{"command drift throughout (vtysh: % Unknown command, exit 1)", func(f *zebraNHTFake19083) { f.cmdDrift = true }, true},
		{"read-back exec failure after a successful write", func(f *zebraNHTFake19083) {
			f.onBatch = func() { f.execFailV4, f.execFailV6 = 1, 1 }
		}, false},
		{"read-back exec failure in v6 only", func(f *zebraNHTFake19083) {
			f.onBatch = func() { f.execFailV6 = 1 }
		}, false},
		{"exec failure throughout", func(f *zebraNHTFake19083) { f.execFail = true }, false},
		// Codex survivors on 18eb95d167: a parse miss releases the reload only
		// after a SUCCESSFUL write, and never ahead of the other family's
		// failure.
		{"rejected write, then parse misses", func(f *zebraNHTFake19083) { f.unreadable = true; f.failAfter = 0 }, false},
		{"read-back: v4 parse miss, v6 exec failure", func(f *zebraNHTFake19083) {
			f.onBatch = func() { f.unreadV4, f.execFailV6 = 1, 1 }
		}, false},
		{"read-back: v4 parse miss, v6 still the alternate", func(f *zebraNHTFake19083) {
			f.applyOnly = 1
			f.onBatch = func() { f.unreadV4 = 1 }
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := newZebraNHTFake19083(nhtMapB19083, nhtMapB19083)
			tc.setup(fake)
			ctx, cancel := context.WithCancel(context.Background())
			m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), exec: fake, mgrCtx: ctx, mgrCancel: cancel,
				staticNHTRestorePending19083: true}
			t.Cleanup(m.Stop)
			err := m.ApplyFull(clusterFC19083(true))
			ev := fake.snapshot()
			reloaded := false
			for _, e := range ev {
				if strings.HasPrefix(e, "reload ") {
					reloaded = true
				}
			}
			if bad := reloadEventsSawAlternate19083(ev); len(bad) != 0 {
				t.Fatalf("a diff reload started with the alternate bound: %q (events %q)", bad, ev)
			}
			if tc.wantReload {
				if err != nil || !reloaded || !containsInOrder19083(ev, restoreBatch19083, "reload v4="+nhtMapA19083) || m.staticNHTRestorePending19083 {
					t.Fatalf("err=%v pending=%v events %q: want the primary written, then the reload", err, m.staticNHTRestorePending19083, ev)
				}
				return
			}
			if err == nil || reloaded || !m.staticNHTRestorePending19083 {
				t.Fatalf("err=%v reloaded=%v pending=%v events %q: a read-back zebra did not answer must not start the reload and must stay pending",
					err, reloaded, m.staticNHTRestorePending19083, ev)
			}
		})
	}
}

// TestStaticNHTBindingParserRealFRR19083 (R24 NEW-1): the binding parser reads
// REAL `show ip|ipv6 nht route-map` output, captured on FRR 10.5.1 (udp fw1:
// v4 bound and none 2026-11-13, v6 none 2026-11-15) and FRR 10.6.0 (loss fw1,
// 2026-11-15, both families bound). A file's version is in its name; the
// expected binding is in the table. Five of the eight version x family x state
// cells are captured; both families print through the same zebra function
// (show_vrf_nht_rm, parameterized by AFI), so the layout is family-agnostic.
func TestStaticNHTBindingParserRealFRR19083(t *testing.T) {
	table := map[string]string{
		"show_ip_nht_routemap_bound-10.5.1_19083.txt":   "xpf-cluster-nht-19083",
		"show_ip_nht_routemap_none-10.5.1_19083.txt":    "",
		"show_ipv6_nht_routemap_none-10.5.1_19083.txt":  "",
		"show_ip_nht_routemap_bound-10.6.0_19083.txt":   clusterStaticNHTRouteMap19083,
		"show_ipv6_nht_routemap_bound-10.6.0_19083.txt": clusterStaticNHTRouteMap19083,
	}
	for file, want := range table {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", file))
			if err != nil {
				t.Fatal(err)
			}
			got, ok := parseStaticNHTBinding19083(string(data))
			if !ok || got != want {
				t.Fatalf("parse(%s) = %q ok=%v, want %q", file, got, ok, want)
			}
		})
	}
	// The coverage matrix (Codex on 18eb95d167): every FRR version x family
	// x binding state must be a real capture, or be named here with the
	// reason it is not one yet. Nothing else may be missing.
	uncaptured := map[string]string{
		"show_ipv6_nht_routemap_bound-10.5.1_19083.txt": "needs a vtysh WRITE on a 10.5.1 node (no tcp/udp node binds a map); not read-only",
		"show_ip_nht_routemap_none-10.6.0_19083.txt":    "loss is the only 10.6.0 cluster; captured read-only by lane H2 lab 2's restore phase",
		"show_ipv6_nht_routemap_none-10.6.0_19083.txt":  "loss is the only 10.6.0 cluster; captured read-only by lane H2 lab 2's restore phase",
	}
	for _, v := range []string{"10.5.1", "10.6.0"} {
		for _, af := range []string{"ip", "ipv6"} {
			for _, st := range []string{"bound", "none"} {
				f := fmt.Sprintf("show_%s_nht_routemap_%s-%s_19083.txt", af, st, v)
				_, err := os.Stat(filepath.Join("testdata", f))
				why, excused := uncaptured[f]
				switch {
				case err != nil && !excused:
					t.Errorf("missing real capture %s (not named as uncaptured)", f)
				case err == nil && excused:
					t.Errorf("%s is now captured: drop it from uncaptured (%s) and add it to the parse table", f, why)
				}
			}
		}
	}
	// Every capture on disk is in the parse table above.
	files, _ := filepath.Glob(filepath.Join("testdata", "show_*_nht_routemap_*_19083.txt"))
	for _, f := range files {
		if _, ok := table[filepath.Base(f)]; !ok {
			t.Errorf("capture %s is not in the parse table", f)
		}
	}
}

// TestStaticNHTStopCancelsExecutingRebind19083 (Codex P2): Stop cancels a
// rebind that is executing (its context derives from the manager lifetime, not
// only from its own timeout), and the interrupted rebind leaves the restore
// pending.
func TestStaticNHTStopCancelsExecutingRebind19083(t *testing.T) {
	orig := staticNHTReevalTimeout19083
	staticNHTReevalTimeout19083 = 30 * time.Second
	t.Cleanup(func() { staticNHTReevalTimeout19083 = orig })
	fake := newZebraNHTFake19083("", "")
	m := newLiteralNHTManager19083(t, fake)
	fake.mu.Lock()
	fake.blockAfter = 2
	fake.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- m.ReevaluateStaticNHT19083() }()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if v4, _ := fake.bindings(); v4 == nhtMapB19083 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	m.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a rebind cancelled by Stop reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not cancel the executing rebind (it would run to its own 30 s timeout)")
	}
	m.reloadMu.Lock()
	pending := m.staticNHTRestorePending19083
	m.reloadMu.Unlock()
	if !pending {
		t.Fatal("an interrupted rebind did not leave the restore pending")
	}
}

// TestStaticNHTRebindSerializesWithRetryReload19083 (R24 P3-5): the rebind
// takes reloadMu itself, not buildMu: it cannot land while a degraded-retry
// reload (which holds reloadMu only) is running.
func TestStaticNHTRebindSerializesWithRetryReload19083(t *testing.T) {
	fake := newZebraNHTFake19083("", "")
	m := newLiteralNHTManager19083(t, fake)
	m.degraded.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	fake.mu.Lock()
	fake.reloadEntered, fake.reloadRelease = entered, release
	fake.mu.Unlock()
	fake.reset()
	retried := make(chan struct{})
	go func() { m.retryReloadOnce(context.Background()); close(retried) }()
	<-entered
	rebound := make(chan error, 1)
	go func() { rebound <- m.ReevaluateStaticNHT19083() }()
	time.Sleep(200 * time.Millisecond)
	for _, e := range fake.snapshot() {
		if strings.HasPrefix(e, "batch ") {
			close(release)
			t.Fatalf("the rebind ran while a degraded-retry reload held reloadMu: %q", fake.snapshot())
		}
	}
	close(release)
	<-retried
	if err := <-rebound; err != nil {
		t.Fatalf("rebind: %v", err)
	}
	if ev := fake.snapshot(); !containsInOrder19083(ev, "reload v4=", "batch ip nht static route-map "+nhtMapB19083) {
		t.Fatalf("events %q: want the rebind after the retry's reload", ev)
	}
}

// TestStaticNHTRequestedDrainSerializesWithRetryReload19083 (R24 P3-5 on
// 9d7abd581a): the PRODUCTION rebind path, a requested drain, takes reloadMu:
// it does not land while a degraded-retry reload holds the lock.
func TestStaticNHTRequestedDrainSerializesWithRetryReload19083(t *testing.T) {
	fake := newZebraNHTFake19083("", "")
	m := newLiteralNHTManager19083(t, fake)
	m.degraded.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	fake.mu.Lock()
	fake.reloadEntered, fake.reloadRelease = entered, release
	fake.mu.Unlock()
	fake.reset()
	retried := make(chan struct{})
	go func() { m.retryReloadOnce(context.Background()); close(retried) }()
	<-entered
	m.RequestStaticNHTReeval19083()
	time.Sleep(4 * staticNHTRebindDebounce19083)
	for _, e := range fake.snapshot() {
		if strings.HasPrefix(e, "batch ") {
			close(release)
			t.Fatalf("a requested drain rebound while a degraded-retry reload held reloadMu: %q", fake.snapshot())
		}
	}
	close(release)
	<-retried
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !containsInOrder19083(fake.snapshot(), "reload v4=", "batch ip nht static route-map "+nhtMapB19083) {
		time.Sleep(10 * time.Millisecond)
	}
	if ev := fake.snapshot(); !containsInOrder19083(ev, "reload v4=", "batch ip nht static route-map "+nhtMapB19083) {
		t.Fatalf("events %q: want the requested rebind after the retry's reload", ev)
	}
}

// TestStaticNHTRebindRequestsCoalesce19083 (R22 #2, R24 P2-1/P3-4):
// RequestStaticNHTReeval19083 coalesces a burst into ONE rebind; a request
// made while that rebind is in flight yields exactly one more after it; a
// stopped manager drains nothing.
func TestStaticNHTRebindRequestsCoalesce19083(t *testing.T) {
	rebinds := func(f *zebraNHTFake19083) int {
		n := 0
		for _, e := range f.snapshot() {
			if strings.HasPrefix(e, "batch ip nht static route-map "+nhtMapB19083) {
				n++
			}
		}
		return n
	}
	waitRebinds := func(f *zebraNHTFake19083, n int) int {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && rebinds(f) < n {
			time.Sleep(10 * time.Millisecond)
		}
		return rebinds(f)
	}
	t.Run("burst and one pending", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		gate := make(chan struct{})
		fake.mu.Lock()
		fake.batchGate = gate
		fake.mu.Unlock()
		for i := 0; i < 3; i++ {
			m.RequestStaticNHTReeval19083()
		}
		if got := waitRebinds(fake, 1); got != 1 {
			close(gate)
			t.Fatalf("a burst of 3 requests ran %d rebinds, want 1", got)
		}
		m.RequestStaticNHTReeval19083() // while the first is held in flight
		m.RequestStaticNHTReeval19083()
		time.Sleep(300 * time.Millisecond)
		if got := rebinds(fake); got != 1 {
			close(gate)
			t.Fatalf("%d rebinds while the first was in flight, want 1", got)
		}
		close(gate)
		if got := waitRebinds(fake, 2); got != 2 {
			t.Fatalf("requests made during an in-flight rebind ran %d rebinds in total, want 2", got)
		}
		time.Sleep(4 * staticNHTRebindDebounce19083)
		if got := rebinds(fake); got != 2 {
			t.Fatalf("%d rebinds, want 2 (one running plus one pending)", got)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		m.Stop()
		m.RequestStaticNHTReeval19083()
		time.Sleep(4 * staticNHTRebindDebounce19083)
		if got := rebinds(fake); got != 0 {
			t.Fatalf("a stopped manager ran %d rebinds", got)
		}
		for _, e := range fake.snapshot() {
			if strings.HasPrefix(e, "refused ") {
				t.Fatalf("a stopped manager's drain attempted a rebind (refused only by the exec's done context): %q", e)
			}
		}
	})
}

// rebindBatches19083 counts the rebind batches (alternate first) in events.
func rebindBatches19083(events []string) int {
	n := 0
	for _, e := range events {
		if strings.HasPrefix(e, "batch ip nht static route-map "+nhtMapB19083) {
			n++
		}
	}
	return n
}

// TestStaticNHTStopSettlesOwedRebind19083 (Codex P2 on 137fea64f9): a
// requested rebind no drain has completed is OWED, since a static may have
// registered unfiltered (FRR 10.5.1) after the event that requested it. Stop
// settles it, after its workers exit, with its own bounded context. It never
// drops it and never hangs.
func TestStaticNHTStopSettlesOwedRebind19083(t *testing.T) {
	orig := staticNHTStopBudget19083
	staticNHTStopBudget19083 = 300 * time.Millisecond
	t.Cleanup(func() { staticNHTStopBudget19083 = orig })
	t.Run("requested, Stop before the drain", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		fake.reset()
		m.RequestStaticNHTReeval19083()
		m.Stop()
		if ev := fake.snapshot(); rebindBatches19083(ev) != 1 {
			t.Fatalf("events %q: want the owed rebind settled by Stop", ev)
		}
		if v4, v6 := fake.bindings(); v4 != nhtMapA19083 || v6 != nhtMapA19083 {
			t.Fatalf("bindings %q/%q after the settle, want the primary", v4, v6)
		}
	})
	t.Run("drain in flight, cancelled by Stop", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		fake.reset()
		fake.mu.Lock()
		fake.blockAfter = 4 // the drain's batch applies, then hangs until its context ends
		fake.mu.Unlock()
		m.RequestStaticNHTReeval19083()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && rebindBatches19083(fake.snapshot()) == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		start := time.Now()
		m.Stop()
		if took := time.Since(start); took > 3*time.Second {
			t.Fatalf("Stop took %s", took)
		}
		if ev := fake.snapshot(); rebindBatches19083(ev) != 2 {
			t.Fatalf("events %q: want the interrupted drain's rebind owed again and settled by Stop (2 batches)", ev)
		}
	})
	t.Run("drain woken after the cancel leaves it owed", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		fake.reset()
		m.reloadMu.Lock() // the drain will block here
		m.RequestStaticNHTReeval19083()
		time.Sleep(4 * staticNHTRebindDebounce19083)
		m.mgrCancel()
		m.reloadMu.Unlock() // the drain now runs on a cancelled lifetime
		time.Sleep(100 * time.Millisecond)
		m.Stop()
		if ev := fake.snapshot(); rebindBatches19083(ev) != 1 {
			t.Fatalf("events %q: a drain woken on a stopping manager must leave the rebind owed for Stop", ev)
		}
	})
	t.Run("nothing owed", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		fake.reset()
		m.Stop()
		if ev := fake.snapshot(); len(ev) != 0 {
			t.Fatalf("Stop with nothing owed ran %q", ev)
		}
	})
	t.Run("settle exec stalls past its budget", func(t *testing.T) {
		// Codex survivor on 18eb95d167: the settle's own exec deadline.
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		fake.reset()
		m.nhtRebindMu.Lock()
		m.nhtRebindOwed = true
		m.nhtRebindMu.Unlock()
		fake.mu.Lock()
		fake.blockAfter = 0 // the settle's batch hangs until its context ends
		fake.mu.Unlock()
		stopped := make(chan struct{})
		go func() { m.Stop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Fatal("Stop hung on a stalled settle exec; the settle must bound its own exec")
		}
		if ev := fake.snapshot(); rebindBatches19083(ev) != 1 {
			t.Fatalf("events %q: want the settle's one (stalled) batch", ev)
		}
	})
	t.Run("writer lock busy past the budget", func(t *testing.T) {
		fake := newZebraNHTFake19083("", "")
		m := newLiteralNHTManager19083(t, fake)
		fake.reset()
		m.nhtRebindMu.Lock()
		m.nhtRebindOwed = true
		m.nhtRebindMu.Unlock()
		m.reloadMu.Lock()
		stopped := make(chan struct{})
		go func() { m.Stop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			m.reloadMu.Unlock()
			<-stopped
			t.Fatal("Stop waited on a busy writer lock past its budget; it must give up and return")
		}
		m.reloadMu.Unlock()
		if ev := fake.snapshot(); len(ev) != 0 {
			t.Fatalf("events %q: nothing can run without the writer lock", ev)
		}
	})
}

// TestStaticNHTRestoreReadBudgetsAreIndependent19083 (R24 P3-2; Codex survivor
// 3 on 137fea64f9): every binding read has its own budget. Four reads that each
// fit the budget succeed, although together they exceed it.
func TestStaticNHTRestoreReadBudgetsAreIndependent19083(t *testing.T) {
	orig, origW := staticNHTReadTimeout19083, staticNHTReevalTimeout19083
	staticNHTReadTimeout19083 = 300 * time.Millisecond
	// The write budget is shortened too, below the four reads' sum, so a
	// return to ONE shared budget (read or write) fails this cell (Codex
	// survivor on 18eb95d167).
	staticNHTReevalTimeout19083 = 500 * time.Millisecond
	t.Cleanup(func() { staticNHTReadTimeout19083, staticNHTReevalTimeout19083 = orig, origW })
	fake := newZebraNHTFake19083(nhtMapB19083, nhtMapB19083)
	fake.readDelay = 200 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), exec: fake, mgrCtx: ctx, mgrCancel: cancel,
		staticNHTRestorePending19083: true}
	t.Cleanup(m.Stop)
	if err := m.ApplyFull(clusterFC19083(true)); err != nil {
		t.Fatalf("four 200 ms reads under a 300 ms per-read budget failed: %v (events %q)", err, fake.snapshot())
	}
	if ev := fake.snapshot(); !containsInOrder19083(ev, restoreBatch19083, "reload v4="+nhtMapA19083) {
		t.Fatalf("events %q: want the restore, then the reload", ev)
	}
}

// TestStaticNHTReadClassifiesRealVtyshErrors19083 (R24 NEW-A): the binding read
// through the REAL executor, against a stand-in vtysh binary. vtysh reports a
// command it does not know on STDOUT with exit 1 (FRR 10.5.1, udp fw1:
// `% Unknown command: show ip nht route-mapx`, rc=1); before this fold
// realExecutor dropped stdout from the error, so command drift was
// indistinguishable from zebra not answering and failed closed forever.
func TestStaticNHTReadClassifiesRealVtyshErrors19083(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		want   nhtRead19083
	}{
		{"unknown command on stdout, exit 1", "#!/bin/sh\necho \"% Unknown command: $2\"\nexit 1\n", nhtReadParseMiss19083},
		{"daemon not answering, exit 1", "#!/bin/sh\necho 'Exiting: failed to connect to any daemons.' >&2\nexit 1\n", nhtReadExecFailed19083},
		{"a layout without the static row", "#!/bin/sh\necho 'VRF default:'\nexit 0\n", nhtReadParseMiss19083},
		{"the real 10.6.0 layout", "#!/bin/sh\nprintf 'VRF: default\\nProtocol                  : route-map\\nstatic                    : xpf-static-nht-xpf-redist\\n'\n", nhtReadOK19083},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vtysh")
			if err := os.WriteFile(path, []byte(tc.script), 0o755); err != nil {
				t.Fatal(err)
			}
			orig := vtyshBinary
			vtyshBinary = path
			t.Cleanup(func() { vtyshBinary = orig })
			ctx, cancel := context.WithCancel(context.Background())
			m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), mgrCtx: ctx, mgrCancel: cancel}
			t.Cleanup(m.Stop)
			if _, got := m.readStaticNHTBinding19083("show ip nht route-map"); got != tc.want {
				t.Fatalf("read classified as %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRealExecutorVtyshErrorCarriesBoundedStdout19083 (R24 NEW-A): the error
// carries vtysh's stdout, bounded.
func TestRealExecutorVtyshErrorCarriesBoundedStdout19083(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vtysh")
	script := "#!/bin/sh\necho '% Unknown command: show x'\nhead -c 4096 /dev/zero | tr '\\0' x\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := vtyshBinary
	vtyshBinary = path
	t.Cleanup(func() { vtyshBinary = orig })
	_, err := realExecutor{}.Vtysh(context.Background(), "show x")
	if err == nil || !strings.Contains(err.Error(), "% Unknown command: show x") {
		t.Fatalf("err = %v, want it to carry vtysh's stdout", err)
	}
	if len(err.Error()) > 1024 {
		t.Fatalf("error is %d bytes: stdout is not bounded", len(err.Error()))
	}
}

// TestStaticNHTRestoreRecoversWhenZebraAnswers19083 (Codex P2s on 18eb95d167
// and afd8ae325c; the operator override was REMOVED): with zebra not
// answering, the restore holds every reload, and the held apply arms the
// degraded retry. Once zebra answers again, the SAME manager (no xpfd
// restart) restores the primary on its next retry and reloads. Nothing
// releases the hold except zebra answering, and the ERROR names the recovery.
func TestStaticNHTRestoreRecoversWhenZebraAnswers19083(t *testing.T) {
	var logs strings.Builder
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	fake := newZebraNHTFake19083(nhtMapB19083, nhtMapB19083) // a rebind interrupted on the alternate
	fake.execFail, fake.writeFail = true, true               // zebra wedged: reads and writes fail
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{frrConf: filepath.Join(t.TempDir(), "frr.conf"), exec: fake, mgrCtx: ctx, mgrCancel: cancel,
		staticNHTRestorePending19083: true}
	t.Cleanup(m.Stop)
	reloads := func() int {
		n := 0
		for _, e := range fake.snapshot() {
			if strings.HasPrefix(e, "reload ") {
				n++
			}
		}
		return n
	}
	if err := m.ApplyFull(clusterFC19083(true)); err == nil || reloads() != 0 {
		t.Fatalf("zebra wedged: err=%v events %q, want the apply held", err, fake.snapshot())
	}
	if !m.degraded.Load() || !m.staticNHTRestorePending19083 {
		t.Fatalf("held apply: degraded=%v pending=%v, want the retry armed and the restore still owed",
			m.degraded.Load(), m.staticNHTRestorePending19083)
	}
	if !strings.Contains(logs.String(), "FRR applies HELD") || !strings.Contains(logs.String(), "systemctl restart frr") {
		t.Fatalf("the held apply's ERROR does not name the recovery: %q", logs.String())
	}
	// Persistent: every retry while zebra stays wedged is held too.
	for i := 0; i < 3; i++ {
		if done, _ := m.retryReloadOnce(context.Background()); done || reloads() != 0 {
			t.Fatalf("retry %d with zebra wedged: done=%v events %q, want it held and retrying", i, done, fake.snapshot())
		}
	}
	// Zebra answers again; the next retry restores, then reloads.
	fake.mu.Lock()
	fake.execFail, fake.writeFail = false, false
	fake.events = nil
	fake.mu.Unlock()
	if done, _ := m.retryReloadOnce(context.Background()); !done {
		t.Fatalf("retry after zebra recovered: not converged (events %q)", fake.snapshot())
	}
	ev := fake.snapshot()
	if bad := reloadEventsSawAlternate19083(ev); len(bad) != 0 {
		t.Fatalf("after recovery a diff reload started with the alternate bound: %q (events %q)", bad, ev)
	}
	if !containsInOrder19083(ev, restoreBatch19083, "reload v4="+nhtMapA19083) || m.staticNHTRestorePending19083 || m.degraded.Load() {
		t.Fatalf("events %q pending=%v degraded=%v: want the primary restored, then the reload, then settled",
			ev, m.staticNHTRestorePending19083, m.degraded.Load())
	}
}

// TestStaticNHTRestoreOverrideRemoved19083: the operator override file
// (`/run/xpf/frr-static-nht-restore-override`, folds 4-5) was REMOVED after two
// review rounds found defects in the mechanism itself. No production source
// may read it again, so a stale marker left on a node has no effect. The
// cell scans every non-test Go file in the repository for the path and for
// the mechanism's identifiers. (A behavioural arm would need to write under
// /run/xpf, which a test must not do on a real node.)
func TestStaticNHTRestoreOverrideRemoved19083(t *testing.T) {
	root := filepath.Join("..", "..")
	needles := []string{"frr-static-nht-restore-override", "RestoreOverride", "staticNHTOverrideReload", "staticNHTPendingSince"}
	scanned := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "target", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for _, n := range needles {
			if strings.Contains(string(data), n) {
				t.Errorf("%s still mentions %q: the restore override must stay removed", path, n)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d Go files from %s; the walk is not seeing the repository", scanned, root)
	}
}

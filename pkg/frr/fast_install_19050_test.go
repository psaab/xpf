package frr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// fastFake19050 adds the #19050 fast-path executor surface to fakeExecutor.
// installErr fails VtyshConfigLines (a kill or a rejected line); the test
// output is produced by testOut so a cell can model a LATE apply.
type fastFake19050 struct {
	*fakeExecutor
	mu           sync.Mutex
	installs     [][]string
	installErr   error
	barriers     int
	barrierErr   error
	testOut      func() []byte
	reloads      int
	afterInstall func()
}

func (f *fastFake19050) VtyshConfigLines(_ context.Context, lines []string) ([]byte, error) {
	f.mu.Lock()
	if len(lines) == 0 {
		f.barriers++
		err := f.barrierErr
		f.mu.Unlock()
		return nil, err
	}
	f.installs = append(f.installs, append([]string(nil), lines...))
	err, hook := f.installErr, f.afterInstall
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil, err
}

func (f *fastFake19050) FrrReloadPyTestOutput(context.Context, string) ([]byte, error) {
	f.mu.Lock()
	out := f.testOut
	f.mu.Unlock()
	if out == nil {
		return nil, nil
	}
	return out(), nil
}

func (f *fastFake19050) FrrReloadPy(ctx context.Context, conf string) error {
	f.mu.Lock()
	f.reloads++
	f.mu.Unlock()
	return f.fakeExecutor.FrrReloadPy(ctx, conf)
}

func (f *fastFake19050) snapshot() (installs [][]string, barriers, reloads int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.installs...), f.barriers, f.reloads
}

func newFastTestManager19050(t *testing.T, fake *fastFake19050) *Manager {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		frrConf:      filepath.Join(t.TempDir(), "frr.conf"),
		exec:         fake,
		retryEnabled: true,
		retryDelays:  []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond},
		retrySlow:    2 * time.Millisecond,
		mgrCtx:       ctx,
		mgrCancel:    cancel,
	}
	t.Cleanup(m.Stop)
	return m
}

func writeManagedStatics19050(t *testing.T, m *Manager, lines ...string) {
	t.Helper()
	body := markerBegin + "\n! xpf managed config - do not edit\n" + strings.Join(lines, "\n") + "\n" + markerEnd + "\n"
	if err := os.WriteFile(m.frrConf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const (
	v4Default19050 = "ip route 0.0.0.0/0 172.16.50.1 5"
	v6Default19050 = "ipv6 route ::/0 2001:559:8585:50::1 ge-0-0-2.50 5"
	other19050     = "ip route 10.0.0.0/8 192.0.2.1 5"
)

// TestFastInstallInstallsOnlyMissingLinesV6First19050: the fast set is the
// wanted lines minus the managed section as last written, v6 first, in ONE
// vtysh invocation.
func TestFastInstallInstallsOnlyMissingLinesV6First19050(t *testing.T) {
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}}
	m := newFastTestManager19050(t, fake)
	writeManagedStatics19050(t, m, other19050)

	outcome, lines := m.FastInstallStatics([]string{other19050, v4Default19050, v6Default19050}, func() bool { return true })
	if outcome != FastInstalled {
		t.Fatalf("outcome = %v, want installed", outcome)
	}
	want := []string{v6Default19050, v4Default19050}
	installs, _, _ := fake.snapshot()
	if len(installs) != 1 || strings.Join(installs[0], "|") != strings.Join(want, "|") || strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("installs = %q (returned %q), want ONE batch %q", installs, lines, want)
	}
	if m.FastInDoubt() {
		t.Fatal("a clean install left lines in doubt")
	}
}

// TestFastInstallNothingToDoWhenAlreadyWritten19050: a line already in the
// managed section is never re-sent.
func TestFastInstallNothingToDoWhenAlreadyWritten19050(t *testing.T) {
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}}
	m := newFastTestManager19050(t, fake)
	writeManagedStatics19050(t, m, v4Default19050, v6Default19050)
	if outcome, _ := m.FastInstallStatics([]string{v4Default19050, v6Default19050}, func() bool { return true }); outcome != FastNothingToDo {
		t.Fatalf("outcome = %v, want nothing-to-do", outcome)
	}
	if installs, _, _ := fake.snapshot(); len(installs) != 0 {
		t.Fatalf("installs = %q, want none", installs)
	}
}

// TestFastInstallSkipsWhenPrecheckFails19050: the pre-check runs under
// reloadMu before any exec; a false pre-check installs nothing.
func TestFastInstallSkipsWhenPrecheckFails19050(t *testing.T) {
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}}
	m := newFastTestManager19050(t, fake)
	if outcome, _ := m.FastInstallStatics([]string{v4Default19050}, func() bool { return false }); outcome != FastSkipped {
		t.Fatalf("outcome = %v, want skipped", outcome)
	}
	if installs, _, _ := fake.snapshot(); len(installs) != 0 {
		t.Fatalf("installs = %q, want none", installs)
	}
}

// TestFastInstallLeavesWriteGenerationsUntouched19050 (R4 B4, N2): a fast
// install must not move confGen, writeGen or unconditionalWriteGen, or a
// pending demotion reload's staleness predicate turns false and it skips
// itself, leaking the line.
func TestFastInstallLeavesWriteGenerationsUntouched19050(t *testing.T) {
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}}
	m := newFastTestManager19050(t, fake)
	conf, w, u := m.confGen, m.WriteGeneration(), m.UnconditionalWriteGeneration()
	if outcome, _ := m.FastInstallStatics([]string{v4Default19050}, func() bool { return true }); outcome != FastInstalled {
		t.Fatalf("outcome = %v, want installed", outcome)
	}
	if m.confGen != conf || m.WriteGeneration() != w || m.UnconditionalWriteGeneration() != u {
		t.Fatalf("generations moved: confGen %d->%d writeGen %d->%d unconditional %d->%d",
			conf, m.confGen, w, m.WriteGeneration(), u, m.UnconditionalWriteGeneration())
	}
}

// TestFastInstallRefusedAfterStop19050 and the race cell below (R4 N3): no
// fast install starts once Stop began, and Stop joins one in flight.
func TestFastInstallRefusedAfterStop19050(t *testing.T) {
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}}
	m := newFastTestManager19050(t, fake)
	m.Stop()
	joined := m.fastJoined.Load()
	if outcome, _ := m.FastInstallStatics([]string{v4Default19050}, func() bool { return true }); outcome != FastRefused {
		t.Fatalf("outcome after Stop = %v, want refused", outcome)
	}
	if got := m.fastJoined.Load(); got != joined {
		t.Fatalf("an install entered fastWG after Stop (joined %d -> %d): the WaitGroup contract must not rest on the cancelled context", joined, got)
	}
}

func TestFastInstallRacingStopNeverInstallsAfterStop19050(t *testing.T) {
	for i := 0; i < 50; i++ {
		fake := &fastFake19050{fakeExecutor: &fakeExecutor{}}
		m := newFastTestManager19050(t, fake)
		var stopped sync.WaitGroup
		stopped.Add(1)
		var installedAfter bool
		var mu sync.Mutex
		stopDone := false
		fake.afterInstall = func() {
			mu.Lock()
			installedAfter = installedAfter || stopDone
			mu.Unlock()
		}
		go func() { defer stopped.Done(); m.Stop(); mu.Lock(); stopDone = true; mu.Unlock() }()
		m.FastInstallStatics([]string{v4Default19050}, func() bool { return true })
		stopped.Wait()
		mu.Lock()
		bad := installedAfter
		mu.Unlock()
		if bad {
			t.Fatalf("iteration %d: a fast install ran after Stop returned", i)
		}
	}
}

// inDoubtSetup19050 drives a fast install that FAILS (vtysh killed or a line
// rejected), so its line is in doubt, then a LATE apply: the line shows up in
// the running config after the reload that follows has read it. testOut
// reports the late line in "Lines To Delete" until the authoritative reload
// in the in-doubt resolution removes it.
func inDoubtSetup19050(t *testing.T) (*Manager, *fastFake19050, func() bool) {
	t.Helper()
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}, installErr: errors.New("signal: killed")}
	m := newFastTestManager19050(t, fake)
	var mu sync.Mutex
	lateLinePresent := false
	var reloadsAtLate int
	fake.testOut = func() []byte {
		mu.Lock()
		defer mu.Unlock()
		_, _, reloads := fake.snapshotNoLock()
		if lateLinePresent && reloads > reloadsAtLate {
			lateLinePresent = false // the authoritative reload deleted it
		}
		if lateLinePresent {
			return []byte("Lines To Delete\n===============\n" + v4Default19050 + "\n\nLines To Add\n============\n")
		}
		return []byte("")
	}
	if outcome, _ := m.FastInstallStatics([]string{v4Default19050}, func() bool { return true }); outcome != FastInDoubt {
		t.Fatalf("outcome = %v, want in-doubt", outcome)
	}
	late := func() bool {
		mu.Lock()
		defer mu.Unlock()
		_, _, reloadsAtLate = fake.snapshotNoLock()
		lateLinePresent = true
		return true
	}
	return m, fake, late
}

func (f *fastFake19050) snapshotNoLock() ([][]string, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return nil, f.barriers, f.reloads
}

// TestFastInDoubtSurvivesCleanDemotionReload19050 (R4 B1 + F1): a fast install
// is killed; the DEMOTION reload then runs through the real
// ApplyFullIfCurrent and succeeds, reading a running config that does not yet
// contain the line; FRR applies it LATE. The in-doubt state must survive that
// clean reload, the retry must keep running, and the resolution (barrier,
// then --test, then the authoritative reload) must leave the line gone.
func TestFastInDoubtSurvivesCleanDemotionReload19050(t *testing.T) {
	m, fake, late := inDoubtSetup19050(t)
	// The demotion render no longer contains the line.
	if err := m.ApplyFullIfCurrent(&FullConfig{}, func() bool { return true }); err != nil {
		t.Fatalf("demotion reload: %v", err)
	}
	if !m.FastInDoubt() {
		t.Fatal("a clean demotion reload cleared the in-doubt state; the late line would leak")
	}
	late()
	waitFor(t, "in-doubt resolution", 3*time.Second, func() bool { return !m.FastInDoubt() })
	_, barriers, reloads := fake.snapshot()
	if barriers == 0 {
		t.Fatal("in-doubt cleared without the barrier")
	}
	if reloads < 2 {
		t.Fatalf("FrrReloadPy calls = %d, want the demotion reload plus the in-doubt authoritative reload", reloads)
	}
}

// TestFastInDoubtNotClearedByPlainRetrySuccess19050 (R4 B1): with the manager
// ALSO degraded, the degraded retry's plain reload success must not clear the
// in-doubt state; only the barrier plus --test does.
func TestFastInDoubtNotClearedByPlainRetrySuccess19050(t *testing.T) {
	m, fake, late := inDoubtSetup19050(t)
	late()
	m.reloadMu.Lock()
	m.degraded.Store(true)
	m.reloadMu.Unlock()
	waitFor(t, "in-doubt resolution", 3*time.Second, func() bool { return !m.FastInDoubt() })
	if _, barriers, _ := fake.snapshot(); barriers == 0 {
		t.Fatal("in-doubt cleared by a plain retry reload, without the barrier")
	}
}

// TestFastInDoubtClearsDespiteUnrelatedOverlayDrift19050 (R4 F2): the
// memory-only QNH metric overlay keeps --test dirty forever (#15183). A diff
// that names none of the in-doubt lines must clear them, or the retry
// reloads forever.
func TestFastInDoubtClearsDespiteUnrelatedOverlayDrift19050(t *testing.T) {
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}, installErr: errors.New("signal: killed")}
	m := newFastTestManager19050(t, fake)
	fake.testOut = func() []byte {
		return []byte("Lines To Add\n============\nroute-map xpf-qnh-metric-1 permit 10\n set metric 20\n")
	}
	if outcome, _ := m.FastInstallStatics([]string{v4Default19050}, func() bool { return true }); outcome != FastInDoubt {
		t.Fatalf("outcome = %v, want in-doubt", outcome)
	}
	waitFor(t, "in-doubt cleared despite overlay drift", 3*time.Second, func() bool { return !m.FastInDoubt() })
}

// --- the F2 matcher, pinned with frr-reload.py --test output -------------
//
// R4's implementation condition: the matcher is pinned with REAL output
// (testdata/frr_reload_test_<form>-<frr version>_19050.txt). The 10.6.0 pair
// was captured on loss fw1 (standby) on 2026-11-10; loss runs FRR 10.6.0, udp
// and tcp run 10.5.1. Each file is the raw combined output of
// `frr-reload.py --test` (the INFO log lines come first; production passes
// --stdout, which moves those lines but not the diff). The two forms:
//   - add: the lines are absent from running config. They print under
//     "Lines To Add", the VRF line as a `vrf NAME` block (an empty block, then
//     the block holding the indented line, each closed by `exit`).
//   - delete: the lines are present in running config only. FRR prints their
//     removal as `no ...` lines under "Lines To ADD", not "Lines To Delete";
//     the VRF one indented inside a `vrf NAME` block.
// Both carry real unrelated drift (`no hostname ...` under "Lines To Delete").

func TestReloadTestDiffMentionsMatcher19050(t *testing.T) {
	v6q := "ipv6 route 2001:db8:1905:50::/64 2001:559:8585:50::1 ge-7-0-2.50 254"
	vrf := "ip route 198.51.100.128/25 Null0 254 vrf vrf-mgmt"
	v4 := "ip route 198.51.100.0/24 172.16.50.1 254"
	absent := "ip route 203.0.113.0/24 172.16.50.1 254"
	for _, fx := range readFixtures19050(t) {
		for _, line := range []string{v4, v6q, vrf} {
			if !reloadTestDiffMentions19050(fx.out, []string{line}) {
				t.Errorf("%s: matcher missed %q in:\n%s", fx.name, line, fx.out)
			}
		}
		// Real output must not over-match: its INFO lines, the unrelated
		// drift and the vrf/exit framing name no in-doubt line here.
		if reloadTestDiffMentions19050(fx.out, []string{absent}) {
			t.Errorf("%s: matcher matched the absent line %q", fx.name, absent)
		}
	}
	// Positive control: a present stale line keeps the flag SET.
	stale := []byte("Lines To Delete\n===============\n" + v4 + "\n")
	if !reloadTestDiffMentions19050(stale, []string{v4}) {
		t.Error("positive control: a stale line in Lines To Delete was not matched")
	}
	// Negative: unrelated drift does not match.
	if reloadTestDiffMentions19050([]byte("Lines To Add\n============\nroute-map x permit 10\n"), []string{v4}) {
		t.Error("unrelated drift was matched")
	}
	// Lines outside a diff section are not diff lines.
	if reloadTestDiffMentions19050([]byte(v4+"\n"), []string{v4}) {
		t.Error("a line outside any Lines To Add/Delete section was matched")
	}
}

type fixture19050 struct {
	name string
	out  []byte
}

func readFixtures19050(t *testing.T) []fixture19050 {
	t.Helper()
	paths, _ := filepath.Glob(filepath.Join("testdata", "frr_reload_test_*_19050.txt"))
	var out []fixture19050
	verRE := regexp.MustCompile(`"frr version ([0-9][0-9.]*)"`)
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(p)
		// A fixture names the FRR version it was captured on, and the
		// capture's own "frr version" line must agree: a mislabelled capture
		// would pin one version's format under another's name.
		m := verRE.FindSubmatch(b)
		if m == nil {
			t.Fatalf("%s: no \"frr version\" line; a fixture must be a raw capture", name)
		}
		if !strings.Contains(name, "-"+string(m[1])+"_19050") {
			t.Fatalf("%s: captured on FRR %s, but the name does not say so", name, m[1])
		}
		out = append(out, fixture19050{name: name, out: b})
	}
	if len(out) == 0 {
		t.Fatal("no frr-reload --test fixtures (testdata/frr_reload_test_*_19050.txt)")
	}
	return out
}

// TestRenderStaticLinesByteIdentityUnderRace19050 (R14): every line the fast
// path renders appears verbatim in the managed section the full render
// produces, and RenderStaticLines touches no mutable Manager state (run with
// -race beside a concurrent full build).
func TestRenderStaticLinesByteIdentityUnderRace19050(t *testing.T) {
	m := &Manager{}
	fc := &FullConfig{
		StaticRoutes: []*config.StaticRoute{
			{Destination: "0.0.0.0/0", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}, Preference: 5},
			{Destination: "198.51.100.0/24", NextHops: []config.NextHopEntry{{Address: "172.16.50.1"}}, Preference: 5},
		},
		Inet6StaticRoutes: []*config.StaticRoute{
			{Destination: "::/0", NextHops: []config.NextHopEntry{{Address: "2001:559:8585:50::1"}}, Preference: 5},
		},
		IPv6NextHopInterfaces: map[string]map[string]string{"": {"2001:559:8585:50::1": "ge-0-0-2.50"}},
		Instances: []InstanceConfig{
			{VRFName: "vrf-blue", StaticRoutes: []*config.StaticRoute{{Destination: "203.0.113.0/24", NextHops: []config.NextHopEntry{{Address: "192.0.2.9"}}, Preference: 5}}},
			{TableID: 101, StaticRoutes: []*config.StaticRoute{{Destination: "203.0.113.128/25", NextHops: []config.NextHopEntry{{Address: "192.0.2.10"}}, Preference: 5}}},
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			m.buildManagedSection(fc)
		}
	}()
	var lines []string
	for i := 0; i < 20; i++ {
		lines = m.RenderStaticLines(fc)
	}
	<-done
	section := m.buildManagedSection(fc)
	if len(lines) < 5 {
		t.Fatalf("RenderStaticLines = %q, want the 5 statics", lines)
	}
	have := map[string]bool{}
	for _, l := range strings.Split(section, "\n") {
		have[strings.TrimSpace(l)] = true
	}
	for _, l := range lines {
		if !have[l] {
			t.Errorf("fast line %q is not verbatim in the full render:\n%s", l, section)
		}
	}
}

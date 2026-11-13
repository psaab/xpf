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
// (testdata/frr_reload_test_<form>-<frr version>_19050.txt). Loss runs FRR
// 10.6.0 and udp/tcp run 10.5.1, and both are captured: 10.6.0 on loss fw1
// (standby) on 2026-11-10, 10.5.1 on udp fw1 (standby) on 2026-11-13. Each
// file is the raw combined output of `frr-reload.py --test` (the INFO log
// lines come first; production passes --stdout, which moves those lines but
// not the diff: the 10.5.1 capture ran both and the diffs are identical).
// The two forms:
//   - add: the lines are absent from running config. They print under
//     "Lines To Add", the VRF line as a `vrf NAME` block (an empty block, then
//     the block holding the indented line, each closed by `exit`).
//   - delete: the lines are present in running config only. FRR prints their
//     removal as `no ...` lines under "Lines To ADD", not "Lines To Delete";
//     the VRF one indented inside a `vrf NAME` block. Same on both versions.
//
// Both carry real unrelated drift (`no hostname ...` under "Lines To Delete").
//
// The 10.5.1 capture also staged two lines in a NON-canonical spelling (review
// Codex P1-2): `203.0.113.77/24` (host bits) and the gateway
// `2001:0559:8585:0050:0000:0000:0000:0001`. FRR printed both canonically in
// BOTH forms (`203.0.113.0/24`, `2001:559:8585:50::1`): frr-reload masks and
// normalizes the file side too, not only the running side. So a managed
// section that keeps an operator's spelling can never be matched by string.
func TestReloadTestDiffMentionsMatcher19050(t *testing.T) {
	v6q := "ipv6 route 2001:db8:1905:50::/64 2001:559:8585:50::1 ge-7-0-2.50 254"
	vrf := "ip route 198.51.100.128/25 Null0 254 vrf vrf-mgmt"
	v4 := "ip route 198.51.100.0/24 172.16.50.1 254"
	absent := "ip route 192.0.2.0/24 172.16.50.1 254"
	// The lines as the managed section would spell them, which FRR printed
	// canonically (captured on 10.5.1 only).
	spelled := map[string][]string{"10.5.1": {
		"ip route 203.0.113.77/24 172.16.50.1 254",
		"ipv6 route 2001:db8:1905:51::/64 2001:0559:8585:0050:0000:0000:0000:0001 ge-7-0-2.50 254",
	}}
	versions := map[string]bool{}
	for _, fx := range readFixtures19050(t) {
		versions[fx.version] = true
		for _, line := range append([]string{v4, v6q, vrf}, spelled[fx.version]...) {
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
	// Both FRR versions the labs run must be pinned.
	for _, v := range []string{"10.5.1", "10.6.0"} {
		if !versions[v] {
			t.Errorf("no --test fixture captured on FRR %s", v)
		}
	}
}

type fixture19050 struct {
	name    string
	version string
	out     []byte
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
		out = append(out, fixture19050{name: name, version: string(m[1]), out: b})
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

// --- review Codex P1-2: canonical route identity in the matcher -----------
//
// FRR's reload parser rewrites IPv6 addresses into canonical form and staticd
// masks the prefix, while the managed section keeps the operator's spelling.
// A matcher comparing strings misses the stale line, clears the doubt and
// stops retrying while the line is still installed. Each row names the field
// it pins. Over-matching only delays the clear, so a row that expects a match
// across an attribute the identity omits (distance) pins fail-closed, and a
// row that expects NO match across a VRF or table pins that unrelated drift in
// another routing table cannot hold the episode open forever.
func TestReloadTestDiffMatcherCanonicalIdentity19050(t *testing.T) {
	add := func(body string) []byte { return []byte("Lines To Add\n============\n" + body + "\n") }
	cases := []struct {
		name string
		line string
		diff []byte
		want bool
	}{
		{"expanded-v6-gateway", "ipv6 route ::/0 2001:0559:8585:0050:0000:0000:0000:0001 ge-0-0-2.50 5",
			add("no ipv6 route ::/0 2001:559:8585:50::1 ge-0-0-2.50 5"), true},
		{"expanded-v6-prefix", "ipv6 route 2001:0db8:1905:0050::/64 2001:559:8585:50::1 ge-7-0-2.50 254",
			add("no ipv6 route 2001:db8:1905:50::/64 2001:559:8585:50::1 ge-7-0-2.50 254"), true},
		{"v4-prefix-host-bits", "ip route 198.51.100.7/24 172.16.50.1 254",
			add("no ip route 198.51.100.0/24 172.16.50.1 254"), true},
		{"expanded-v6-in-vrf-context", "ipv6 route 2001:db8::/32 2001:0db8:0000:0000:0000:0000:0000:0001 254 vrf vrf-mgmt",
			add("vrf vrf-mgmt\n no ipv6 route 2001:db8::/32 2001:db8::1 254\nexit"), true},
		{"distance-omitted-fails-closed", "ip route 198.51.100.0/24 172.16.50.1 5",
			add("no ip route 198.51.100.0/24 172.16.50.1 254"), true},
		{"same-table", "ip route 203.0.113.0/24 192.0.2.10 5 table 101",
			add("no ip route 203.0.113.0/24 192.0.2.10 5 table 101"), true},
		{"other-table", "ip route 203.0.113.0/24 192.0.2.10 5 table 101",
			add("no ip route 203.0.113.0/24 192.0.2.10 5 table 102"), false},
		{"other-vrf-context", "ip route 198.51.100.128/25 Null0 254 vrf vrf-a",
			add("vrf vrf-b\n no ip route 198.51.100.128/25 Null0 254\nexit"), false},
		{"other-vrf-inline", "ip route 198.51.100.128/25 Null0 254 vrf vrf-a",
			add("no ip route 198.51.100.128/25 Null0 254 vrf vrf-b"), false},
		{"default-vrf-vs-vrf", "ip route 198.51.100.128/25 Null0 254",
			add("vrf vrf-b\n no ip route 198.51.100.128/25 Null0 254\nexit"), false},
		{"gateway-vs-null0-default", "ip route 0.0.0.0/0 172.16.50.1 5",
			add("ip route 0.0.0.0/0 Null0 tag 1 250"), false},
		{"unparseable-diff-static-fails-closed", "ip route 10.9.0.0/16 192.0.2.1 5",
			add("no ip route 198.51.100.0 255.255.255.0 172.16.50.1"), true},
		{"unparseable-in-doubt-line-fails-closed", "ip route not-a-prefix 192.0.2.1 5",
			add("no ip route 198.51.100.0/24 172.16.50.1 254"), true},
		{"unparseable-in-doubt-line-ignores-non-static-drift", "ip route not-a-prefix 192.0.2.1 5",
			add("route-map xpf-qnh-metric-1 permit 10\n set metric 20"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := reloadTestDiffMentions19050(c.diff, []string{c.line}); got != c.want {
				t.Fatalf("reloadTestDiffMentions19050(%q) = %v, want %v; diff:\n%s", c.line, got, c.want, c.diff)
			}
		})
	}
}

// TestFastInDoubtExpandedIPv6LineResolvedBeforeClear19050 is review Codex
// P1-2's probe: a fast install with an EXPANDED IPv6 next hop is killed after
// FRR applied it, and --test reports its removal in FRR's canonical spelling.
// The doubt must not clear until the authoritative reload has removed the
// line.
func TestFastInDoubtExpandedIPv6LineResolvedBeforeClear19050(t *testing.T) {
	const expanded = "ipv6 route ::/0 2001:0559:8585:0050:0000:0000:0000:0001 ge-0-0-2.50 5"
	const canonicalDelete = "Lines To Add\n============\nno ipv6 route ::/0 2001:559:8585:50::1 ge-0-0-2.50 5\n"
	fake := &fastFake19050{fakeExecutor: &fakeExecutor{}, installErr: errors.New("signal: killed")}
	var mu sync.Mutex
	present := false
	fake.afterInstall = func() { mu.Lock(); present = true; mu.Unlock() } // FRR applied it; the client died
	fake.testOut = func() []byte {
		mu.Lock()
		defer mu.Unlock()
		if present {
			return []byte(canonicalDelete)
		}
		return nil
	}
	fake.fakeExecutor.frrReloadPyHook = func(int) error { mu.Lock(); present = false; mu.Unlock(); return nil }
	m := newFastTestManager19050(t, fake)
	if outcome, _ := m.FastInstallStatics([]string{expanded}, func() bool { return true }); outcome != FastInDoubt {
		t.Fatalf("outcome = %v, want in-doubt", outcome)
	}
	waitFor(t, "in-doubt resolution", 3*time.Second, func() bool { return !m.FastInDoubt() })
	mu.Lock()
	defer mu.Unlock()
	if present {
		t.Fatal("the doubt cleared while the expanded-IPv6 line was still installed: the matcher missed FRR's canonical spelling")
	}
}

// qnhFastExec19050 adds the #19050 fast-path surface to the #15183 ospfd
// route-map model, so the in-doubt resolution runs against a manager whose
// memory-only QNH overlay a reload deletes.
type qnhFastExec19050 struct {
	*qnhFailedReloadExecutor15183
	stale string
	// present: the killed batch's line is in the running config.
	present bool
	// reloadFailures: FrrReloadPy calls still to fail AFTER removing the line
	// (a reload that converged the static and then hit a rejected line).
	reloadFailures int
	// loadFailures: QNH overlay loads (VtyshLoadDaemon) still to fail.
	loadFailures int
	// primaryOK counts FrrReloadPy successes since the last failure.
	primaryOK, primaryFailed int
}

func (e *qnhFastExec19050) VtyshConfigLines(_ context.Context, lines []string) ([]byte, error) {
	if len(lines) == 0 {
		return nil, nil // the barrier
	}
	e.present = true // FRR applied the batch; the client was killed
	return nil, errors.New("signal: killed")
}

func (e *qnhFastExec19050) FrrReloadPyTestOutput(context.Context, string) ([]byte, error) {
	if e.present {
		return []byte("Lines To Add\n============\nno " + e.stale + "\n"), nil
	}
	return nil, nil // the overlay is never in frr.conf, so its loss is no diff
}

func (e *qnhFastExec19050) FrrReloadPy(ctx context.Context, conf string) error {
	e.present = false
	if err := e.qnhFailedReloadExecutor15183.FrrReloadPy(ctx, conf); err != nil {
		return err
	}
	if e.reloadFailures > 0 {
		e.reloadFailures--
		e.primaryOK, e.primaryFailed = 0, e.primaryFailed+1
		return errors.New("frr-reload.py rejected a line")
	}
	e.primaryOK++
	return nil
}

func (e *qnhFastExec19050) VtyshLoadDaemon(ctx context.Context, daemon, conf string) ([]byte, error) {
	if e.loadFailures > 0 {
		e.loadFailures--
		return []byte("% ospfd refused the overlay"), errors.New("ospfd overlay load refused")
	}
	return e.qnhFailedReloadExecutor15183.VtyshLoadDaemon(ctx, daemon, conf)
}

// qnhInDoubt19050 applies the QNH config (overlay present), then leaves one
// fast line in doubt and present in the running config. The retry loop is
// disabled; the cell drives retryReloadOnce itself, one iteration at a time.
func qnhInDoubt19050(t *testing.T) (*Manager, *qnhFastExec19050, string) {
	t.Helper()
	m, base, fc, routeMap := qnhFailedReloadFixture15183(t)
	exec := &qnhFastExec19050{qnhFailedReloadExecutor15183: base, stale: "ip route 198.51.100.0/24 172.16.50.1 5"}
	m.exec = exec
	if err := m.ApplyFull(fc); err != nil {
		t.Fatalf("initial ApplyFull: %v", err)
	}
	wantQNHMetric15183(t, base, routeMap)
	if outcome, _ := m.FastInstallStatics([]string{exec.stale}, func() bool { return true }); outcome != FastInDoubt {
		t.Fatalf("outcome = %v, want in-doubt", outcome)
	}
	return m, exec, routeMap
}

// runRetryUntilStop19050 drives the retry body until it reports stop.
func runRetryUntilStop19050(t *testing.T, m *Manager, after func(i int)) {
	t.Helper()
	for i := 0; i < 10; i++ {
		stop, _ := m.retryReloadOnce(context.Background())
		if after != nil {
			after(i)
		}
		if stop {
			return
		}
	}
	t.Fatal("the retry never stopped in 10 iterations")
}

// TestFastInDoubtQNHRestoreFailureKeepsRetrying19050 is review Codex P1-3's
// probe: the in-doubt resolution's authoritative reload removes the stale
// static (and, like every reload, the memory-only QNH overlay), then the
// overlay restore fails once. The next --test is clean (frr.conf never holds
// the overlay), so an episode that only LOGGED the failure cleared and
// stopped with the metric gone. The failure must keep the retry going until
// the overlay readback succeeds.
func TestFastInDoubtQNHRestoreFailureKeepsRetrying19050(t *testing.T) {
	m, exec, routeMap := qnhInDoubt19050(t)
	exec.loadFailures = 1
	runRetryUntilStop19050(t, m, nil)
	if exec.present {
		t.Fatal("premise: the stale line must be gone when the episode stops")
	}
	if m.FastInDoubt() {
		t.Fatal("the episode stopped with lines still in doubt")
	}
	wantQNHMetric15183(t, exec.qnhFailedReloadExecutor15183, routeMap)
}

// TestFastInDoubtReloadFailureRecordsDegraded19050 (review Codex P1-3, the
// reload arm): the in-doubt resolution's authoritative reload removes the
// stale static and THEN fails. The failure must be recorded in the degraded
// state machine, and the episode may stop only after a primary reload has
// succeeded since: the failed one may have left other config unconverged,
// which the in-doubt --test (it looks only for the in-doubt lines) cannot see.
func TestFastInDoubtReloadFailureRecordsDegraded19050(t *testing.T) {
	m, exec, routeMap := qnhInDoubt19050(t)
	exec.reloadFailures = 1
	degradedSeen := false
	runRetryUntilStop19050(t, m, func(int) {
		if exec.primaryFailed > 0 && m.ReloadDegraded() {
			degradedSeen = true
		}
	})
	if exec.primaryFailed != 1 {
		t.Fatalf("premise: the in-doubt reload must have failed once, failed=%d", exec.primaryFailed)
	}
	if !degradedSeen {
		t.Fatal("the failed in-doubt reload was not recorded as degraded")
	}
	if exec.primaryOK == 0 {
		t.Fatal("the episode stopped without a successful primary reload after the failed one")
	}
	if m.ReloadDegraded() || m.FastInDoubt() {
		t.Fatalf("episode stopped with degraded=%v inDoubt=%v", m.ReloadDegraded(), m.FastInDoubt())
	}
	wantQNHMetric15183(t, exec.qnhFailedReloadExecutor15183, routeMap)
}

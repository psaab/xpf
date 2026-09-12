package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/psaab/xpf/pkg/vrrp"
)

// #9725 cells. The contract is in transit_closed_until_attach_9725.go.
//
// These tests swap package-level seams: the transit sysctl paths, the host
// posture paths, the transit write hook and nftInstaller. So none of them may
// run t.Parallel().

// withTempHostForwardingPosture points hostForwardingPostureSysctls at temp
// files, so the boot policy's default branch runs without touching /proc.
func withTempHostForwardingPosture(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	orig := hostForwardingPostureSysctls
	temp := make(map[string]string, len(orig))
	i := 0
	for _, val := range orig {
		temp[filepath.Join(dir, fmt.Sprintf("posture-%d", i))] = val
		i++
	}
	hostForwardingPostureSysctls = temp
	t.Cleanup(func() { hostForwardingPostureSysctls = orig })
}

// recordTransitWrites9725 appends every transit knob write to events, as
// "write=<value>", for the test's lifetime.
func recordTransitWrites9725(t *testing.T, events *[]string) {
	t.Helper()
	var mu sync.Mutex
	prev := transitForwardWriteHook
	transitForwardWriteHook = func(_, value string) {
		mu.Lock()
		defer mu.Unlock()
		*events = append(*events, "write="+value)
	}
	t.Cleanup(func() { transitForwardWriteHook = prev })
}

// applyDaemon9725 is the daemon the #5679 apply cells use: a real config store,
// networkd writing into a temp dir and a VRRP manager, so applyConfigLocked runs
// to its tail in a unit test.
func applyDaemon9725(t *testing.T) *Daemon {
	t.Helper()
	return &Daemon{
		networkd: networkd.NewInDir(t.TempDir()),
		store:    newConfigStore(t, filepath.Join(t.TempDir(), "config.db")),
		vrrpMgr:  vrrp.NewManager(),
	}
}

// applyAsTheHarnessDoes9725 runs applyConfigLocked with NoDataplane set, as the
// #5679 apply cells do, so the host-only RSS reshape in the tail is skipped. The
// boot transit policy has already run by then, and nothing on the apply path
// reads NoDataplane for the transit gate.
func applyAsTheHarnessDoes9725(d *Daemon) error {
	d.opts.NoDataplane = true
	return d.applyConfigLocked(context.Background(), &config.Config{})
}

func readKnob9725(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.TrimSpace(string(b))
}

// testLinkSetter is a fake runtime whose attached-link count a test controls.
type testLinkSetter interface {
	setTestAttachedLinks(n int)
}

// linksDP wraps a runtime so it reports the attached-link count a test sets.
type linksDP struct {
	dataplane.RuntimeDataPlane
	mu    sync.Mutex
	links int
}

func (l *linksDP) AttachedXDPLinkCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.links
}

func (l *linksDP) setTestAttachedLinks(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.links = n
}

// setAttachedLinksForTest9725 makes d's runtime report n attached shim XDP links,
// wrapping the runtime if it cannot, and lets the gate re-read them as an apply
// does.
func setAttachedLinksForTest9725(d *Daemon, n int) {
	setter, ok := d.dataplane().(testLinkSetter)
	if !ok {
		l := &linksDP{RuntimeDataPlane: d.dataplane()}
		d.setDataplane(l)
		setter = l
	}
	setter.setTestAttachedLinks(n)
	d.reassertTransitGate("test")
}

// attachForTest9725 attaches one shim XDP link, as an apply does.
func attachForTest9725(d *Daemon) { setAttachedLinksForTest9725(d, 1) }

// attachingDP9725 is a runtime whose ApplyConfig is the attach. Inside each
// ApplyConfig it records the kernel path as it stood when the attach began, then
// leaves `attach` links attached, then returns applyErr as a later failing step
// would.
type attachingDP9725 struct {
	armedRecorderDP
	t        *testing.T
	v4, v6   string
	barrier  *fakeNftInstaller
	events   *[]string
	attach   int
	applyErr error
	mu       sync.Mutex
	links    int
	atAttach []string
}

func (f *attachingDP9725) AttachedXDPLinkCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.links
}

func (f *attachingDP9725) ApplyConfig(ctx context.Context, cfg *config.Config) (*dataplane.ApplyResult, error) {
	f.atAttach = append(f.atAttach, fmt.Sprintf("sysctls=%s/%s barrier=%s",
		readKnob9725(f.t, f.v4), readKnob9725(f.t, f.v6), lastBarrierCall(f.barrier)))
	f.mu.Lock()
	f.links = f.attach
	f.mu.Unlock()
	if f.attach > 0 && f.events != nil {
		*f.events = append(*f.events, "attach")
	}
	if f.applyErr != nil {
		return nil, f.applyErr
	}
	return f.armedRecorderDP.ApplyConfig(ctx, cfg)
}

// TestBootKeepsTransitClosedUntilTheFirstAttach9725 is the issue's acceptance
// cell. It drives the production boot order against the seams: the boot transit
// policy, the boot arm, then a real applyConfigLocked whose runtime attaches
// inside ApplyConfig.
//
// The sysctls start at 1, as an older image's sysctl.d and a previous armed run
// leave them. From the boot policy through the attach they must be 0 with the
// barrier installed. Once a link is attached, both must open. The write history
// must show no transit write of 1 before the attach: a gate that opened and
// closed again within one step would leave the knobs at 0 and still route
// transit for that moment.
func TestBootKeepsTransitClosedUntilTheFirstAttach9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withTempHostForwardingPosture(t)
	f := withBarrierRecorder(t)
	var events []string
	recordTransitWrites9725(t, &events)

	d := applyDaemon9725(t)
	dp := &attachingDP9725{t: t, v4: v4, v6: v6, barrier: f, events: &events, attach: 2}
	d.setDataplane(dp)

	d.applyBootTransitPolicy()
	assertTransitForwarding(t, v4, v6, "0", "after the boot transit policy")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("the boot transit policy must install the barrier, last call = %q (calls: %v)", got, f.barrierCalls)
	}
	for path, want := range hostForwardingPostureSysctls {
		if got := readKnob9725(t, path); got != want {
			t.Errorf("host posture knob %s = %q after the boot policy, want %q", path, got, want)
		}
	}
	if d.DataplaneArmed() {
		t.Error("the boot transit policy recorded an arm; it must record nothing about the arm")
	}

	d.armBootDataplane(d.dataplane())
	if !d.DataplaneArmed() {
		t.Fatal("premise: the boot arm must succeed")
	}
	assertTransitForwarding(t, v4, v6, "0", "after a successful boot arm, before any interface is attached")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("a successful boot arm must leave the barrier installed until the attach, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}

	if err := applyAsTheHarnessDoes9725(d); err != nil {
		// Unrelated reconcile steps can fail in a unit test; the assertions
		// below read only the transit gate.
		t.Logf("applyConfigLocked: %v", err)
	}
	if len(dp.atAttach) != 1 {
		t.Fatalf("premise: ApplyConfig ran %d times, want 1", len(dp.atAttach))
	}
	if got, want := dp.atAttach[0], "sysctls=0/0 barrier=install"; got != want {
		t.Errorf("while the first apply attached the XDP programs, the kernel path was %q, want %q: "+
			"transit was open with no program adjudicating it (#9725)", got, want)
	}
	assertTransitForwarding(t, v4, v6, "1", "after the first attach")
	if got := lastBarrierCall(f); got != "remove" {
		t.Errorf("the barrier must be removed once a link is attached, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
	attachAt := -1
	for i, e := range events {
		if e == "attach" {
			attachAt = i
			break
		}
	}
	for i, e := range events {
		if e == "write=1" && (attachAt < 0 || i < attachAt) {
			t.Errorf("transit knob write of 1 at step %d, before the attach at step %d: %v", i, attachAt, events)
			break
		}
	}
}

// TestAnApplyThatFailsAfterItsAttachStillOpensTransit9725: the attach can
// complete before a later step of the apply fails. The programs then adjudicate
// transit, and a gate keyed on the apply's success would keep the node closed.
//
// The two failure classes leave the apply by different exits. An ordinary
// failure continues to the apply tail, which re-reads the gate too. An
// abort-class failure (a required-protocol gate, compileErrorMustAbortApply)
// returns before the tail, so only the re-read right after ApplyConfig can open
// transit.
func TestAnApplyThatFailsAfterItsAttachStillOpensTransit9725(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ordinary failure", errors.New("synthetic HA-state clear failure after the attach (#9725 test)")},
		{"abort-class failure", fmt.Errorf("publish userspace snapshot: %w", dpuserspace.ErrPolicySchedulerProtocolIncompatible)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := withTempTransitForwardSysctls(t, "1")
			withTempHostForwardingPosture(t)
			f := withBarrierRecorder(t)

			d := applyDaemon9725(t)
			dp := &attachingDP9725{t: t, v4: v4, v6: v6, barrier: f, attach: 1, applyErr: tc.err}
			d.setDataplane(dp)
			d.applyBootTransitPolicy()
			d.armBootDataplane(d.dataplane())

			if err := applyAsTheHarnessDoes9725(d); err == nil {
				t.Fatal("premise: applyConfigLocked must report the failed ApplyConfig")
			}
			assertTransitForwarding(t, v4, v6, "1", "after an apply that attached and then failed")
			if got := lastBarrierCall(f); got != "remove" {
				t.Errorf("an apply that attached and then failed must remove the barrier, last call = %q (calls: %v)",
					got, f.barrierCalls)
			}
		})
	}
}

// TestAnApplyThatAttachesNothingKeepsTransitClosed9725: an ApplyConfig can
// succeed with no link attached. Nothing then adjudicates transit, so neither the
// apply nor its tail may open it, even after something raised the knobs.
func TestAnApplyThatAttachesNothingKeepsTransitClosed9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withTempHostForwardingPosture(t)
	f := withBarrierRecorder(t)

	d := applyDaemon9725(t)
	dp := &attachingDP9725{t: t, v4: v4, v6: v6, barrier: f}
	d.setDataplane(dp)
	d.applyBootTransitPolicy()
	d.armBootDataplane(d.dataplane())

	if err := applyAsTheHarnessDoes9725(d); err != nil {
		t.Logf("applyConfigLocked: %v", err)
	}
	if len(dp.atAttach) != 1 {
		t.Fatalf("premise: ApplyConfig ran %d times, want 1", len(dp.atAttach))
	}
	assertTransitForwarding(t, v4, v6, "0", "after an apply that attached nothing")

	for _, p := range []string{v4, v6} {
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("raise %s: %v", p, err)
		}
	}
	d.applyKernelTuning(&config.Config{})
	assertTransitForwarding(t, v4, v6, "0", "after an apply tail with nothing attached")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("an apply tail with nothing attached must keep the barrier installed, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
}

// TestAnApplyThatLeavesNothingAttachedClosesTransitAgain9725: the gate is not
// latched. An apply that detaches every link, for example by removing the last
// zoned interface, leaves nothing to adjudicate transit, so it closes again.
func TestAnApplyThatLeavesNothingAttachedClosesTransitAgain9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	withTempHostForwardingPosture(t)
	f := withBarrierRecorder(t)

	d := applyDaemon9725(t)
	dp := &attachingDP9725{t: t, v4: v4, v6: v6, barrier: f, attach: 1}
	d.setDataplane(dp)
	d.applyBootTransitPolicy()
	d.armBootDataplane(d.dataplane())
	if err := applyAsTheHarnessDoes9725(d); err != nil {
		t.Logf("applyConfigLocked: %v", err)
	}
	assertTransitForwarding(t, v4, v6, "1", "premise: after an apply that attached")

	dp.attach = 0
	if err := applyAsTheHarnessDoes9725(d); err != nil {
		t.Logf("applyConfigLocked: %v", err)
	}
	assertTransitForwarding(t, v4, v6, "0", "after an apply that left no link attached")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("an apply that left no link attached must install the barrier, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
}

// TestAttachedLinksOpenNothingWithoutTheArm9725: the arm is the other half of
// the rule. Links a runtime reports before any Start, or after a stop, open
// nothing.
func TestAttachedLinksOpenNothingWithoutTheArm9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	withBarrierRecorder(t)
	d := &Daemon{}
	d.setDataplane(&linksDP{links: 2})

	d.reassertTransitGate("apply")
	assertTransitForwarding(t, v4, v6, "0", "with links attached but no Start")

	for _, tc := range []struct {
		name  string
		close func(*Daemon)
	}{
		{"arm failure", func(d *Daemon) { d.markDataplaneArmFailed("test", "remediation", errors.New("boom")) }},
		{"not armed", func(d *Daemon) { d.markDataplaneNotArmed("test", "reason") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.markDataplaneArmed("boot")
			assertTransitForwarding(t, v4, v6, "1", "premise: armed with links attached")

			tc.close(d)
			d.reassertTransitGate("apply")
			assertTransitForwarding(t, v4, v6, "0", "after "+tc.name+", with links still attached")
		})
	}
}

// TestTheBootCloseRecordsNothingAboutTheArm9725: closeTransitUntilAttached
// closes both legs, but it is not an arm writer. It must leave dataplaneArmed as
// it found it, and it must not move the RG weight.
func TestTheBootCloseRecordsNothingAboutTheArm9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)
	m := armTrackManager(t)
	d := &Daemon{cluster: m}
	full := rgWeight(t, m, 1)
	d.dataplaneArmed.Store(true)

	d.closeTransitUntilAttached("boot")

	if got := rgWeight(t, m, 1); got != full {
		t.Errorf("closeTransitUntilAttached moved the RG weight from %d to %d", full, got)
	}
	if !d.DataplaneArmed() {
		t.Error("closeTransitUntilAttached cleared the arm; only the arm writers may")
	}
	assertTransitForwarding(t, v4, v6, "0", "after closeTransitUntilAttached")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("closeTransitUntilAttached must install the barrier, last call = %q (calls: %v)", got, f.barrierCalls)
	}
}

// TestAStaleOpenCannotLandAfterAClose9725: an apply re-reading the gate can be
// mid-actuation when a fail-closed stop runs. The stop must wait: the gate's state
// and both of its legs change under one lock. The cell blocks the open inside a
// knob write, waits until the stop has reached the gate lock
// (transitGateAcquireHook), and then requires that the stop neither changes the
// arm nor returns until the open finishes. After that, the stop closes.
func TestAStaleOpenCannotLandAfterAClose9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	f := withBarrierRecorder(t)
	stopAtLock := make(chan struct{})
	var stopOnce sync.Once
	prevAcquire := transitGateAcquireHook
	transitGateAcquireHook = func(caller string) {
		if caller == "markDataplaneNotArmed" {
			stopOnce.Do(func() { close(stopAtLock) })
		}
	}
	t.Cleanup(func() { transitGateAcquireHook = prevAcquire })
	d := &Daemon{}
	d.setDataplane(&linksDP{})
	d.markDataplaneArmed("boot")

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	prev := transitForwardWriteHook
	transitForwardWriteHook = func(_, value string) {
		if value == "1" {
			once.Do(func() {
				close(entered)
				<-release
			})
		}
	}
	t.Cleanup(func() { transitForwardWriteHook = prev })

	opened := make(chan struct{})
	go func() {
		defer close(opened)
		setAttachedLinksForTest9725(d, 1)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("premise: the open never wrote a transit knob")
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		d.markDataplaneNotArmed("shutdown", "fail-closed stop")
	}()
	select {
	case <-stopAtLock:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("premise: the stop never reached the gate lock")
	}
	// The stop is at the gate lock while the open holds it. Until the open is
	// released, the stop must neither change the arm nor return.
	raced := false
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline) && !raced; {
		select {
		case <-stopped:
			raced = true
		default:
			raced = !d.DataplaneArmed()
		}
		runtime.Gosched()
	}
	close(release)
	<-opened
	<-stopped

	if raced {
		t.Error("the stop ran while an open was actuating the gate: the gate state and its legs are not serialized")
	}
	if d.DataplaneArmed() {
		t.Error("the stop did not leave the dataplane unarmed")
	}
	assertTransitForwarding(t, v4, v6, "0", "after a stop that raced an open")
	if got := lastBarrierCall(f); got != "install" {
		t.Errorf("after a stop that raced an open, the barrier's last call is %q, want install (calls: %v)",
			got, f.barrierCalls)
	}
}

// TestAnAttachOutsideApplyConfigOpensAtTheApplyTail9725: Compile, which runs the
// attach, has a caller besides ApplyConfig: the in-process CLI's apply
// (pkg/cli/apply.go). The apply tail re-reads the links too, so such an attach
// opens transit at the next apply's tail.
func TestAnAttachOutsideApplyConfigOpensAtTheApplyTail9725(t *testing.T) {
	v4, v6 := withTempTransitForwardSysctls(t, "0")
	withTempHostForwardingPosture(t)
	f := withBarrierRecorder(t)
	d := applyDaemon9725(t)
	dp := &linksDP{}
	d.setDataplane(dp)
	d.markDataplaneArmed("boot")

	dp.setTestAttachedLinks(1)
	assertTransitForwarding(t, v4, v6, "0", "premise: before anything re-read the links")
	d.applyKernelTuning(&config.Config{})
	assertTransitForwarding(t, v4, v6, "1", "after an apply tail that followed an attach made outside ApplyConfig")
	if got := lastBarrierCall(f); got != "remove" {
		t.Errorf("the apply tail must remove the barrier once a link is attached, last call = %q (calls: %v)",
			got, f.barrierCalls)
	}
}

// TestThePublishedRuntimeReportsItsAttachedLinks9725: the gate keys on an optional
// capability, and the daemon publishes the userspace ADAPTER, not the manager. A
// capability the adapter does not forward is invisible, which is exactly why the
// #7191 arm-coverage proof never gates (#9804). Without this, production transit
// would never open.
func TestThePublishedRuntimeReportsItsAttachedLinks9725(t *testing.T) {
	rt := dpuserspace.Boot()
	if _, ok := rt.(attachedLinksSource); !ok {
		t.Fatalf("the published runtime %T does not report its attached XDP links: kernel transit would never open", rt)
	}
}

// TestTheImageAndTestVMsStartWithForwardingClosed9725 pins the sysctl.d defaults.
// A 1 there re-opens the kernel path at every boot, before xpfd starts.
func TestTheImageAndTestVMsStartWithForwardingClosed9725(t *testing.T) {
	// Not "persists 0" but "persists NEITHER value". systemd-sysctl re-applies
	// every sysctl.d file whenever it runs, so a persisted knob is reimposed
	// under a RUNNING xpfd by something as routine as `systemctl restart
	// systemd-sysctl`, and it fights the gate in whichever direction it was
	// written: a persisted 1 (images baked before #9725) opens transit the gate
	// had closed, and a persisted 0 closes transit the gate had opened, breaking
	// route-based IPsec plaintext, SNAT'd frames passed up for kernel routing and
	// the #7409 slow-path reinject until the next apply. Both knobs default to 0,
	// so closing at boot needs no persisted value at all.
	for _, rel := range []string{"scripts/image/bake.py", "test/incus/setup.sh", "test/incus/cluster-setup.sh"} {
		b, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		body := string(b)
		for _, bad := range []string{"net.ipv4.ip_forward=", "net.ipv6.conf.all.forwarding="} {
			if strings.Contains(body, bad) {
				t.Errorf("%s writes %s into a persistent sysctl file. xpfd's transit gate owns that knob, and "+
					"systemd-sysctl re-applies sysctl.d files under a running daemon", rel, bad)
			}
		}
	}

	// What DOES close them at boot: the oneshot, enabled by the image.
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts/image/bake.py"))
	if err != nil {
		t.Fatalf("read bake.py: %v", err)
	}
	for _, want := range []string{"xpf-transit-closed.service", "systemctl enable xpf-transit-closed.service"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("bake.py no longer ships or enables %q, so nothing closes kernel transit between "+
				"systemd-sysctl and xpfd", want)
		}
	}

	// And an image baked BEFORE #9725 still has the knobs persisted, so the
	// package must scrub them on upgrade rather than leave them to be re-applied.
	p, err := os.ReadFile(filepath.Join("..", "..", "debian", "xpf.postinst"))
	if err != nil {
		t.Fatalf("read xpf.postinst: %v", err)
	}
	for _, want := range []string{"SYSCTL_D=/etc/sysctl.d", "99-xpf.conf", "ipv6.conf.all.forwarding"} {
		if !strings.Contains(string(p), want) {
			t.Errorf("the postinst does not scrub %q from a legacy image's sysctl.d, so systemd-sysctl "+
				"re-applies the old value under a running xpfd. SYSCTL_D must name the REAL directory: a "+
				"scrub pointed elsewhere passes a string check while cleaning nothing", want)
		}
	}
}

// TestThePackageKeepsForwardingClosedFromBoot9725: an image baked before #9725
// keeps forwarding=1 in /etc/sysctl.d/99-xpf.conf, and systemd-sysctl applies it
// at every boot, before xpfd starts. The package ships a boot-only oneshot that
// writes 0 after systemd-sysctl and before networking, and the image enables it
// too. It is not a sysctl.d file: systemd-sysctl re-applies those whenever it
// runs, which would close transit under a running, attached xpfd.
func TestThePackageKeepsForwardingClosedFromBoot9725(t *testing.T) {
	const unit = "xpf-transit-closed.service"
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "image", unit))
	if err != nil {
		t.Fatalf("read %s: %v", unit, err)
	}
	lines := map[string][]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unparsable unit line %q", line)
		}
		lines[k] = append(lines[k], v)
	}
	has := func(key, want string) bool {
		for _, v := range lines[key] {
			for _, f := range strings.Fields(v) {
				if f == want {
					return true
				}
			}
		}
		return false
	}
	for _, c := range []struct{ key, want string }{
		{"Type", "oneshot"},
		{"DefaultDependencies", "no"},
		{"After", "systemd-sysctl.service"},
		{"Before", "network-pre.target"},
		{"Before", "systemd-networkd.service"},
		{"Before", "frr.service"},
		{"Before", "xpfd.service"},
		{"WantedBy", "sysinit.target"},
	} {
		if !has(c.key, c.want) {
			t.Errorf("%s: %s= does not include %s", unit, c.key, c.want)
		}
	}
	exec := strings.Join(lines["ExecStart"], " ")
	for _, want := range []string{"echo 0 > /proc/sys/net/ipv4/ip_forward", "echo 0 > /proc/sys/net/ipv6/conf/all/forwarding"} {
		if !strings.Contains(exec, want) {
			t.Errorf("%s: ExecStart does not run %q", unit, want)
		}
	}

	rules, err := os.ReadFile(filepath.Join("..", "..", "debian", "rules"))
	if err != nil {
		t.Fatalf("read debian/rules: %v", err)
	}
	for _, c := range []struct{ target, want string }{
		{"override_dh_auto_build", "cp scripts/image/" + unit + " debian/xpf." + unit},
		{"override_dh_installsystemd", "dh_installsystemd --no-start --no-stop-on-upgrade --name=xpf-transit-closed"},
	} {
		recipe, err := makeRecipe9725(string(rules), c.target)
		if err != nil {
			t.Fatalf("debian/rules: %v", err)
		}
		found := false
		for _, cmd := range recipe {
			if cmd == c.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s does not run %q", c.target, c.want)
		}
	}
	install, err := makeRecipe9725(string(rules), "override_dh_auto_install")
	if err != nil {
		t.Fatalf("debian/rules: %v", err)
	}
	for _, cmd := range install {
		if strings.Contains(cmd, "sysctl.d") {
			t.Errorf("override_dh_auto_install still installs into sysctl.d (%q); systemd-sysctl would re-apply it under a running xpfd", cmd)
		}
	}

	bake, err := os.ReadFile(filepath.Join("..", "..", "scripts", "image", "bake.py"))
	if err != nil {
		t.Fatalf("read bake.py: %v", err)
	}
	for _, want := range []string{unit + ":/usr/lib/systemd/system", "systemctl enable " + unit} {
		if !strings.Contains(string(bake), want) {
			t.Errorf("bake.py does not stage the unit into the image: %q is missing", want)
		}
	}
}

// makeRecipe9725 returns the commands a Makefile target runs: its tab-indented
// lines, with backslash continuations joined, whitespace collapsed, and comment
// lines (`#` or `@#`) dropped. A target defined more than once is an error,
// because make runs only the last definition's recipe.
func makeRecipe9725(makefile, target string) ([]string, error) {
	defs := 0
	for _, line := range strings.Split(makefile, "\n") {
		if strings.HasPrefix(line, target+":") {
			defs++
		}
	}
	if defs != 1 {
		return nil, fmt.Errorf("target %s is defined %d times, want once", target, defs)
	}
	var out []string
	in := false
	pending := ""
	for _, line := range strings.Split(makefile, "\n") {
		if !in {
			in = strings.HasPrefix(line, target+":")
			continue
		}
		if !strings.HasPrefix(line, "\t") && pending == "" {
			if strings.TrimSpace(line) == "" {
				continue
			}
			break
		}
		body := strings.TrimSpace(line)
		if pending == "" && (strings.HasPrefix(body, "#") || strings.HasPrefix(body, "@#")) {
			continue
		}
		if strings.HasSuffix(body, "\\") {
			pending += strings.TrimSuffix(body, "\\") + " "
			continue
		}
		out = append(out, strings.Join(strings.Fields(pending+body), " "))
		pending = ""
	}
	return out, nil
}

// TestAPersistentBarrierFailureLogsOncePerEpisode9725: a barrier install or remove
// that keeps failing is logged at ERROR once, not on every apply, and its recovery
// is logged once. Both directions are driven, because each keeps its own episode.
func TestAPersistentBarrierFailureLogsOncePerEpisode9725(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)
	buf, restore := captureSlog(t)
	defer restore()

	failures := 0
	fail := func() error {
		if failures > 0 {
			failures--
			return errors.New("bridge: synthetic barrier failure (#9725 test)")
		}
		return nil
	}

	d := &Daemon{}
	failures = 2
	f.barrierInstall = fail
	for i := 0; i < 3; i++ {
		d.reassertTransitGate("apply-tail") // unarmed, so every pass installs
	}

	f.barrierInstall = nil
	d.markDataplaneArmed("test")
	failures = 2
	f.barrierRemove = fail
	attachForTest9725(d)
	for i := 0; i < 3; i++ {
		d.reassertTransitGate("apply-tail") // armed and attached, so every pass removes
	}

	logs := buf.String()
	for _, c := range []struct {
		text string
		want int
	}{
		{`level=ERROR msg="failed to install the transit barrier`, 1},
		{`msg="transit barrier install succeeded after earlier failures"`, 1},
		{`level=ERROR msg="failed to remove the transit barrier`, 1},
		{`msg="transit barrier remove succeeded after earlier failures"`, 1},
	} {
		if got := strings.Count(logs, c.text); got != c.want {
			t.Errorf("%q logged %d times, want %d\n%s", c.text, got, c.want, logs)
		}
	}
}

// TestTheBootOneshotFailsWhenEitherWriteFails9725: the unit's ExecStart must
// attempt both knobs and exit non-zero when either write fails, so a failed IPv4
// write is not masked by a successful IPv6 one. It runs the unit's own script
// against temp files.
func TestTheBootOneshotFailsWhenEitherWriteFails9725(t *testing.T) {
	unit := filepath.Join("..", "..", "scripts", "image", "xpf-transit-closed.service")
	raw, err := os.ReadFile(unit)
	if err != nil {
		t.Fatalf("read %s: %v", unit, err)
	}
	var script string
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "ExecStart=/bin/sh -c '"); ok {
			script = strings.TrimSuffix(strings.TrimSpace(rest), "'")
		}
	}
	if script == "" {
		t.Fatalf("premise: %s has no /bin/sh -c ExecStart", unit)
	}
	// systemd expands a single $ as a unit variable, so the unit must spell the
	// status as $$rc; the cell unescapes it only after checking that.
	if !strings.Contains(script, "exit $$rc") {
		t.Errorf("%s: ExecStart must exit with $$rc, got %q", unit, script)
	}
	script = strings.ReplaceAll(script, "$$", "$") // systemd's literal dollar sign

	dir := t.TempDir()
	v4, v6 := filepath.Join(dir, "v4"), filepath.Join(dir, "v6")
	missing := filepath.Join(dir, "missing")
	for _, tc := range []struct {
		name     string
		v4, v6   string
		wantFail bool
	}{
		{"both writable", v4, v6, false},
		{"IPv4 unwritable", filepath.Join(missing, "v4"), v6, true},
		{"IPv6 unwritable", v4, filepath.Join(missing, "v6"), true},
	} {
		for _, p := range []string{v4, v6} {
			if err := os.WriteFile(p, []byte("1"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		s := strings.NewReplacer(
			"/proc/sys/net/ipv4/ip_forward", tc.v4,
			"/proc/sys/net/ipv6/conf/all/forwarding", tc.v6,
		).Replace(script)
		err := exec.Command("/bin/sh", "-c", s).Run()
		if (err != nil) != tc.wantFail {
			t.Errorf("%s: the unit's script returned err=%v, want failure=%v", tc.name, err, tc.wantFail)
		}
		for _, p := range []string{tc.v4, tc.v6} {
			if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "0" {
				t.Errorf("%s: %s = %q, want 0: each write must be attempted", tc.name, p, b)
			}
		}
	}
}

// TestTheDeferredMACReapplyReReadsTheTransitGate9725: reapplyAfterDeferredMAC is the
// second ApplyConfig caller. A reapply that leaves no link attached must close
// transit at once, whether it succeeds or fails, without waiting for an apply tail.
func TestTheDeferredMACReapplyReReadsTheTransitGate9725(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"reapply succeeds", nil},
		{"reapply fails", errors.New("synthetic deferred-MAC reapply failure (#9725 test)")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v4, v6 := withTempTransitForwardSysctls(t, "0")
			withTempHostForwardingPosture(t)
			f := withBarrierRecorder(t)

			d := applyDaemon9725(t)
			dp := &attachingDP9725{t: t, v4: v4, v6: v6, barrier: f, attach: 1}
			d.setDataplane(dp)
			d.markDataplaneArmed("test")
			if _, err := dp.ApplyConfig(context.Background(), &config.Config{}); err != nil {
				t.Fatalf("premise: the attaching apply failed: %v", err)
			}
			d.reassertTransitGate("apply")
			assertTransitForwarding(t, v4, v6, "1", "premise: armed with one attached link")

			dp.attach, dp.applyErr = 0, tc.err
			d.reapplyAfterDeferredMAC(&config.Config{})
			assertTransitForwarding(t, v4, v6, "0", "right after a deferred-MAC reapply that left no link attached")
			if got := lastBarrierCall(f); got != "install" {
				t.Errorf("the reapply must re-install the barrier, last call = %q (calls: %v)", got, f.barrierCalls)
			}
		})
	}
}

// TestABarrierFailureEpisodeEndsWhenTheGateChangesDirection9725: a failure episode
// left open when the gate switches direction must not swallow the next failure
// after it switches back. Both operations are driven.
func TestABarrierFailureEpisodeEndsWhenTheGateChangesDirection9725(t *testing.T) {
	withTempTransitForwardSysctls(t, "1")
	f := withBarrierRecorder(t)
	buf, restore := captureSlog(t)
	defer restore()
	fail := func() error { return errors.New("bridge: synthetic barrier failure (#9725 test)") }

	d := &Daemon{}
	f.barrierInstall = fail
	d.reassertTransitGate("apply-tail") // closed: the install fails
	d.markDataplaneArmed("test")        // still closed: the same install episode
	setAttachedLinksForTest9725(d, 1)
	d.reassertTransitGate("apply-tail") // open: the remove succeeds
	setAttachedLinksForTest9725(d, 0)
	d.reassertTransitGate("apply-tail") // closed again: the install fails again

	f.barrierInstall, f.barrierRemove = nil, fail
	setAttachedLinksForTest9725(d, 1)
	d.reassertTransitGate("apply-tail") // open: the remove fails
	setAttachedLinksForTest9725(d, 0)
	d.reassertTransitGate("apply-tail") // closed: the install succeeds
	setAttachedLinksForTest9725(d, 1)
	d.reassertTransitGate("apply-tail") // open again: the remove fails again

	logs := buf.String()
	for _, op := range []string{"install", "remove"} {
		text := `level=ERROR msg="failed to ` + op + ` the transit barrier`
		if got := strings.Count(logs, text); got != 2 {
			t.Errorf("%s failures logged at ERROR %d times, want 2: once before the gate switched direction and once after it switched back\n%s",
				op, got, logs)
		}
	}
}

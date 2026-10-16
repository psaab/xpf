package daemon

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/upgrade"
)

// #6495: the hold string must AGREE across the two surfaces, and must name the
// hold that is actually in force.
//
// `show chassis cluster status` renders the manager's stored reason directly;
// `show system kernel-upgrade` renders whatever the daemon puts in
// ChannelStatus.HoldReason. pkg/upgrade cannot import pkg/cluster (its own
// tests already import pkg/cluster — a cycle), so the value is carried across
// HERE, and here is the only place both are reachable to assert they agree.
//
// RED on revert: substitute a literal in kernelUpgradeStatus, or read the
// yes/no predicate instead of the reason, and the equality below flips while
// both commands still "work".
func TestKernelUpgradeHoldReasonAgreesAcrossSurfaces(t *testing.T) {
	for _, reason := range []string{
		cluster.KernelUpgradeHoldCandidate,
		cluster.KernelUpgradeHoldUnreadableJournal,
	} {
		m := cluster.NewManager(0, 1)
		m.SetKernelUpgradeHold(reason)
		d := &Daemon{cluster: m}

		st := d.kernelUpgradeStatus()
		if st.HoldReason == "" {
			t.Fatalf("hold %q: a held node reported no reason — the operator sees "+
				"the node parked SECONDARY with nothing naming the gate", reason)
		}
		if st.HoldReason != reason {
			t.Fatalf("hold reason diverged between surfaces:\n"+
				"  show system kernel-upgrade: %q\n"+
				"  show chassis cluster status: %q", st.HoldReason, reason)
		}

		var chanBuf bytes.Buffer
		upgrade.RenderChannelStatus(&chanBuf, st)
		if !strings.Contains(chanBuf.String(), reason) {
			t.Errorf("`show system kernel-upgrade` does not render %q:\n%s",
				reason, chanBuf.String())
		}
		if !strings.Contains(m.FormatStatus(), reason) {
			t.Errorf("`show chassis cluster status` does not render %q", reason)
		}
	}
}

// The two holds must reach the kernel-upgrade surface as DIFFERENT strings.
// A single literal here would satisfy the agreement test above (both surfaces
// would render the same wrong thing) while telling the operator that a
// fail-closed hold is waiting on a promotion marker that may never be written.
func TestKernelUpgradeStatusDistinguishesTheTwoHolds(t *testing.T) {
	armed := cluster.NewManager(0, 1)
	armed.SetKernelUpgradeHold(cluster.KernelUpgradeHoldCandidate)
	failClosed := cluster.NewManager(0, 1)
	failClosed.SetKernelUpgradeHold(cluster.KernelUpgradeHoldUnreadableJournal)

	a := (&Daemon{cluster: armed}).kernelUpgradeStatus().HoldReason
	f := (&Daemon{cluster: failClosed}).kernelUpgradeStatus().HoldReason
	if a == f {
		t.Fatalf("both holds surface the same reason %q", a)
	}
	if strings.Contains(f, "promotion marker confirms") {
		t.Errorf("the fail-closed hold claims a promotion marker will resolve "+
			"it: %q", f)
	}
}

// An UNHELD node must report no hold. A status that always claims one is worse
// than one that never does: mid-roll the operator would wait for a gate that
// is not there.
func TestKernelUpgradeStatusReportsNoHoldWhenNotHeld(t *testing.T) {
	m := cluster.NewManager(0, 1)
	d := &Daemon{cluster: m}
	if got := d.kernelUpgradeStatus(); got.HoldReason != "" {
		t.Errorf("unheld node reported HoldReason = %q", got.HoldReason)
	}
}

// A standalone (non-clustered) daemon must not panic reaching for a cluster
// manager that does not exist.
func TestKernelUpgradeStatusOnAStandaloneDaemon(t *testing.T) {
	d := &Daemon{}
	st := d.kernelUpgradeStatus()
	if st.HoldReason != "" {
		t.Errorf("standalone daemon reported a cluster hold: %q", st.HoldReason)
	}
	var b bytes.Buffer
	upgrade.RenderChannelStatus(&b, st)
	if b.Len() == 0 {
		t.Error("standalone daemon rendered nothing")
	}
}

// ── the fail-closed -> armed transition (#5682 self-heal x #6495) ─────
//
// reconcileKernelUpgradeHold converts a fail-closed hold into an ordinary armed
// hold in place when the journal becomes readable AND a candidate is armed. The
// RENDERED reason must follow that transition: without it the status keeps
// telling the operator the journal is unreadable on a node whose journal is now
// fine, sending them to repair a filesystem that is healthy.
func TestFailClosedHoldBecomesACandidateHoldInTheRender(t *testing.T) {
	dir := t.TempDir()
	jpath := filepath.Join(dir, "kernel-upgrade.state")

	m := cluster.NewManager(0, 1)
	d := &Daemon{cluster: m}

	// Boot-time fail-closed hold: the journal exists but is unparseable.
	if err := os.WriteFile(jpath, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	d.kernelRunnerFn = func() (*upgrade.KernelRunner, error) {
		return upgrade.NewKernelRunner(upgrade.KernelConfig{
			JournalPath: jpath, Sys: kernelStatusFakeSys{},
		})
	}
	d.holdSecondaryIfKernelCandidateArmed()
	if got := m.KernelUpgradeHoldReason(); got != cluster.KernelUpgradeHoldUnreadableJournal {
		t.Fatalf("boot-time reason = %q, want the unreadable-journal reason", got)
	}

	// The journal becomes readable and a candidate IS armed.
	j := upgrade.KernelJournal{
		CandidateVersion: "6.19.0-1-generic",
		KnownGoodVersion: "6.18.4-11-generic",
		ActiveSlot:       upgrade.SlotA, InactiveSlot: upgrade.SlotB,
		State: upgrade.KernelStateArmed,
	}
	data, err := json.Marshal(&j)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(jpath, data, 0o644); err != nil {
		t.Fatalf("write journal: %v", err)
	}
	// The promotion-marker gate must NOT release the hold here (no marker), so
	// the reconcile falls through after converting the reason.
	d.kernelSystemFn = func() upgrade.KernelSystem {
		return kernelStatusFakeSys{running: "6.19.0-1-generic"}
	}
	d.reconcileKernelUpgradeHold()

	if !m.KernelUpgradeHeld() {
		t.Fatal("an armed candidate must still be held")
	}
	if got := m.KernelUpgradeHoldReason(); got != cluster.KernelUpgradeHoldCandidate {
		t.Fatalf("after self-heal the reason is %q — the operator is still being "+
			"told the journal is unreadable on a node whose journal is fine", got)
	}
	if got := d.kernelUpgradeStatus().HoldReason; got != cluster.KernelUpgradeHoldCandidate {
		t.Errorf("the kernel-upgrade surface still reports %q", got)
	}
}

// kernelStatusFakeSys implements the KernelSystem methods this file's paths
// call. It does NOT embed upgrade.KernelSystem: an embedded nil interface
// satisfies the type at compile time and panics at call time, so widening the
// interface (as #6495 did, with WriteLastRoll/ReadLastRoll) would turn a
// compile error into a runtime panic. Naming the methods keeps the enumeration
// honest — the compiler now tells us when the interface grows.
type kernelStatusFakeSys struct {
	running  string
	promoted string
	lastRoll upgrade.KernelRollOutcome
}

func (f kernelStatusFakeSys) RunningKernel() (string, error)       { return f.running, nil }
func (f kernelStatusFakeSys) ReadPromotionMarker() (string, error) { return f.promoted, nil }
func (f kernelStatusFakeSys) ReadLastRoll() (upgrade.KernelRollOutcome, error) {
	return f.lastRoll, nil
}

// The remaining KernelSystem surface is not reached by the status/hold paths.
// They are spelled out rather than obtained by embedding upgrade.KernelSystem:
// an embedded nil interface satisfies the type at COMPILE time and panics at
// call time, so widening the interface — as #6495 did — silently converts a
// compile error into a runtime panic in every such fake. Listing them keeps the
// compiler as the enumeration, which is the whole point.
func (f kernelStatusFakeSys) IsUEFI() bool                            { return true }
func (f kernelStatusFakeSys) EfibootmgrOK() bool                      { return true }
func (f kernelStatusFakeSys) BootEntries() (map[string]string, error) { return nil, nil }
func (f kernelStatusFakeSys) BootOrder() ([]string, error)            { return nil, nil }
func (f kernelStatusFakeSys) GrubSubmenuDisabled() (bool, error)      { return true, nil }
func (f kernelStatusFakeSys) WatchdogStatus() (bool, bool)            { return true, true }
func (f kernelStatusFakeSys) FreeBytes(string) (uint64, error)        { return 1 << 40, nil }
func (f kernelStatusFakeSys) KernelHeld() (bool, error)               { return false, nil }
func (f kernelStatusFakeSys) InstallCandidateKernel(string) (string, error) {
	return "", nil
}
func (f kernelStatusFakeSys) DefaultBootEntry() (string, error)                { return "", nil }
func (f kernelStatusFakeSys) WriteSlotSelector(string, string) error           { return nil }
func (f kernelStatusFakeSys) ReadSlotSelector(string) (string, error)          { return "", nil }
func (f kernelStatusFakeSys) SetBootNext(string) error                         { return nil }
func (f kernelStatusFakeSys) GetBootNext() (string, error)                     { return "", nil }
func (f kernelStatusFakeSys) ClearBootNext() error                             { return nil }
func (f kernelStatusFakeSys) ArmWatchdog() error                               { return nil }
func (f kernelStatusFakeSys) Reboot() error                                    { return nil }
func (f kernelStatusFakeSys) WritePromotionMarker(string) error                { return nil }
func (f kernelStatusFakeSys) ClearPromotionMarker() error                      { return nil }
func (f kernelStatusFakeSys) ClearRollLease() error                            { return nil }
func (f kernelStatusFakeSys) WriteLastRoll(upgrade.KernelRollOutcome) error    { return nil }
func (f kernelStatusFakeSys) BootCurrent() (string, error)                     { return "", nil }
func (f kernelStatusFakeSys) VerifyDataplane() (bool, error)                   { return true, nil }
func (f kernelStatusFakeSys) ForwardBeacon(time.Duration) (bool, error)        { return true, nil }
func (f kernelStatusFakeSys) SetBootOrderFront(string) error                   { return nil }
func (f kernelStatusFakeSys) DisarmWatchdog() error                            { return nil }
func (f kernelStatusFakeSys) RestoreInactiveSlotSelector(string, string) error { return nil }
func (f kernelStatusFakeSys) PruneInactiveSlot(string, string, string) error {
	return nil
}
func (f kernelStatusFakeSys) Now() time.Time { return time.Unix(1755792000, 0) }

var _ upgrade.KernelSystem = kernelStatusFakeSys{}

// The status path must go through the daemon's injectable KernelSystem seam
// (newKernelSystem / kernelSystemFn) rather than reaching for the real system
// directly — otherwise it cannot be tested at all, and it silently diverges
// from every other kernel path in this package.
func TestKernelUpgradeStatusUsesTheInjectableSystemSeam(t *testing.T) {
	d := &Daemon{}
	d.kernelSystemFn = func() upgrade.KernelSystem {
		return kernelStatusFakeSys{
			running:  "6.19.0-1-generic",
			promoted: "6.19.0-1-generic",
			lastRoll: upgrade.KernelRollOutcome{
				Version: "6.19.0-1-generic", Outcome: upgrade.RollOutcomePromoted,
				UnixSec: 1755792000,
			},
		}
	}
	st := d.kernelUpgradeStatus()
	if st.RunningVersion != "6.19.0-1-generic" {
		t.Errorf("RunningVersion = %q — the injected system was not consulted, so "+
			"this path reached the real host instead", st.RunningVersion)
	}
	if st.PromotedVersion != "6.19.0-1-generic" {
		t.Errorf("PromotedVersion = %q", st.PromotedVersion)
	}
	if !st.LastRoll.Recorded() {
		t.Error("LastRoll not read through the seam")
	}
}

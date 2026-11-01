package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"golang.org/x/sync/semaphore"
)

// #18746, AG on #18759: the handoff re-verify reads TableEnforcing, which is
// generation-bracketed since c6cde9d858. Any nft commit landing during that
// read made it unreadable, and an unreadable re-verify refuses the handoff
// and reinstalls the guard. At boot nothing then re-drove the handoff, so a
// single concurrent commit could leave the box closed until the next commit.

func handoffFake18746(t *testing.T, enforcing func() (bool, error)) (*fakeNftInstaller, *int) {
	t.Helper()
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })
	reads := 0
	fake := &fakeNftInstaller{tableEnforcing: func(string) (bool, error) {
		reads++
		return enforcing()
	}}
	nftInstaller = fake
	return fake, &reads
}

func handoff18746(d *Daemon) error {
	return d.removeEarlyInputBarrierAtHandoff(&config.Config{}, []string{xnft.HostInboundTableName}, map[string]struct{}{})
}

var moved18746 = &xnft.GenerationChangedError{CommitsObserved: 1, Before: 7, After: 8}

// One commit lands during the first read; the immediate re-read sees one
// ruleset and the handoff goes ahead.
func TestHandoffReverifyRereadsAcrossAMovedGeneration18746(t *testing.T) {
	first := true
	fake, reads := handoffFake18746(t, func() (bool, error) {
		if first {
			first = false
			return false, moved18746
		}
		return true, nil
	})
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	buf, restore := captureSlog(t)
	defer restore()
	if err := handoff18746(d); err != nil {
		t.Fatalf("handoff across one moved generation = %v, want it to re-read and proceed", err)
	}
	if !strings.Contains(buf.String(), "handoff re-verify re-read after concurrent nft commits") || !strings.Contains(buf.String(), "rereads=1") {
		t.Errorf("the handoff re-read left no Info evidence:\n%s", buf.String())
	}
	if *reads != 2 {
		t.Errorf("re-verify read %d times, want 2 (the moved read and one re-read)", *reads)
	}
	if slices.Contains(fake.earlyInputBarrierCalls, "install-lifeline") {
		t.Errorf("guard reinstalled after a re-read that succeeded: %v", fake.earlyInputBarrierCalls)
	}
	if d.earlyInputHandoffRetryOwed18746.Load() {
		t.Error("a handoff that went ahead left the retry debt owed")
	}
}

// Steady churn: every read moves. The re-reads are bounded, the handoff still
// fails closed with the guard reinstalled, and the refusal is handed to the
// retry owner instead of waiting for a commit that may never come.
func TestHandoffReverifyUnderChurnRefusesAndOwesARetry18746(t *testing.T) {
	fake, reads := handoffFake18746(t, func() (bool, error) { return false, moved18746 })
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	buf, restore := captureSlog(t)
	defer restore()
	err := handoff18746(d)
	if err == nil || !strings.Contains(err.Error(), "unreadable after barrier removal") {
		t.Fatalf("handoff under constant churn = %v, want refused as unreadable", err)
	}
	if want := 1 + xnft.GenerationChangeRereads; *reads != want {
		t.Errorf("re-verify read %d times under churn, want %d (bounded)", *reads, want)
	}
	if !slices.Contains(fake.earlyInputBarrierCalls, "install-lifeline") {
		t.Errorf("guard not reinstalled after a refused handoff: %v", fake.earlyInputBarrierCalls)
	}
	if !d.earlyInputHandoffRetryOwed18746.Load() {
		t.Fatal("a refused handoff owes no retry: at boot nothing would re-drive it")
	}
	if got := strings.Count(buf.String(), "re-assert loop will re-apply"); got != 1 {
		t.Errorf("retry-owner Warn logged %d times, want 1:\n%s", got, buf.String())
	}
	// A second refusal in the same episode does not Warn again.
	buf.Reset()
	_ = handoff18746(d)
	if strings.Contains(buf.String(), "re-assert loop will re-apply") {
		t.Errorf("the retry-owner Warn repeated within one episode:\n%s", buf.String())
	}
}

// A real read failure is not a generation change: no re-read, and the
// refusal still owes a retry.
func TestHandoffReverifyDoesNotRereadARealError18746(t *testing.T) {
	_, reads := handoffFake18746(t, func() (bool, error) { return false, errors.New("netlink: permission denied") })
	d := &Daemon{applySem: semaphore.NewWeighted(1)}
	if err := handoff18746(d); err == nil {
		t.Fatal("handoff over an unreadable table went ahead")
	}
	if *reads != 1 {
		t.Errorf("a non-generation error was read %d times, want 1 (no re-read)", *reads)
	}
	if !d.earlyInputHandoffRetryOwed18746.Load() {
		t.Error("a refused handoff owes no retry")
	}
}

// The owner: reassertHostInboundGapOnce re-applies while the debt is owed and
// the handoff is not done, and a completed handoff discharges it.
func TestRefusedHandoffIsRedrivenByTheReassertOwner18746(t *testing.T) {
	origReassert := hostInboundGapReassertFn
	t.Cleanup(func() { hostInboundGapReassertFn = origReassert })
	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	applies := 0
	hostInboundGapReassertFn = func(*Daemon) error { applies++; return nil }

	d.reassertHostInboundGapOnce(context.Background())
	if applies != 0 {
		t.Fatalf("owner applied %d times with nothing owed, want 0", applies)
	}
	d.noteEarlyInputHandoffRefused18746(errors.New("refused"))
	d.reassertHostInboundGapOnce(context.Background())
	d.reassertHostInboundGapOnce(context.Background())
	if applies != 2 {
		t.Fatalf("owner applied %d times over 2 ticks with a refused handoff owed, want 2", applies)
	}
	if err := d.setEarlyInputHandoffDone(); err != nil {
		t.Fatalf("setEarlyInputHandoffDone: %v", err)
	}
	t.Cleanup(clearEarlyInputHandoffMarker)
	if d.earlyInputHandoffRetryOwed18746.Load() {
		t.Error("a completed handoff did not discharge the retry debt")
	}
	d.reassertHostInboundGapOnce(context.Background())
	if applies != 2 {
		t.Errorf("owner kept applying after the handoff completed: %d applies", applies)
	}
}

// AG on #18759 (NIT 1): once the handoff is done the owner owes nothing,
// whatever the retry debt or the pending bound still says. A barrierOwed that
// dropped its "handoff not done" term re-applied every 30 s forever on such a
// box, and no other daemon cell noticed.
func TestReassertOwnerIdlesOnceHandedOff18746(t *testing.T) {
	origReassert := hostInboundGapReassertFn
	t.Cleanup(func() { hostInboundGapReassertFn = origReassert })
	for name, owe := range map[string]func(*Daemon){
		"retry debt owed":       func(d *Daemon) { d.earlyInputHandoffRetryOwed18746.Store(true) },
		"pending bound expired": func(d *Daemon) { d.earlyInputPendingBoundSince = time.Now().Add(-time.Hour) },
	} {
		s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
		applies := 0
		hostInboundGapReassertFn = func(*Daemon) error { applies++; return nil }
		owe(d)
		d.reassertHostInboundGapOnce(context.Background())
		if applies != 1 {
			t.Fatalf("%s: control: before the handoff the owner applied %d times, want 1", name, applies)
		}
		d.earlyInputHandoffDone.Store(true)
		d.reassertHostInboundGapOnce(context.Background())
		if applies != 1 {
			t.Errorf("%s: after the handoff the owner applied again (%d applies), want none", name, applies)
		}
	}
}

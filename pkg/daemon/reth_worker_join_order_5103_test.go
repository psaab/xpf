package daemon

import (
	"errors"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// #5103: the AF_XDP worker join must happen BEFORE the RETH MAC link DOWN/UP,
// not after it.
//
// PrepareLinkCycle's contract is that no thread touches UMEM once it returns,
// so it has to precede the NIC queue/link teardown. The daemon used to call
// programRethMAC first and only join workers afterwards, once it saw
// linkCycled=true — its own comment conceded the workers "may have been
// accessing UMEM during the DOWN/UP". A same-plan apply with defer_workers does
// not stop already-running workers, so the barrier really did land after the
// transition.
//
// The join cannot simply be hoisted above programRethMAC: whether a cycle is
// needed at all is only knowable by ATTEMPTING the live MAC set, and joining
// workers unconditionally would pay a forwarding outage on every apply for the
// drivers (mlx5, virtio) that support IFF_LIVE_ADDR_CHANGE and need no cycle.
// So the join is a hook invoked on the fallback path only, after the live set
// has failed and before the first mutation.

// recordingRethOps is a fake netlink seam that records the ORDER of the link
// operations, so the test asserts a sequence rather than a set.
type recordingRethOps struct {
	events   *[]string
	liveFail bool // reject the live (link-UP) setHardwareAddr, forcing a cycle
	link     netlink.Link
}

func newRecordingRethOps(t *testing.T, events *[]string, curMAC net.HardwareAddr, liveFail bool) rethLinkOps {
	t.Helper()
	la := netlink.NewLinkAttrs()
	la.Name = "ge-0-0-1"
	la.HardwareAddr = curMAC
	link := &netlink.Device{LinkAttrs: la}
	r := &recordingRethOps{events: events, liveFail: liveFail, link: link}
	return rethLinkOps{
		interfaces: func() ([]net.Interface, error) { return nil, nil },
		byName:     func(string) (netlink.Link, error) { return r.link, nil },
		byIndex:    func(int) (netlink.Link, error) { return r.link, nil },
		setDown: func(netlink.Link) error {
			*r.events = append(*r.events, "link-down")
			return nil
		},
		setUp: func(netlink.Link) error {
			*r.events = append(*r.events, "link-up")
			return nil
		},
		setName: func(netlink.Link, string) error { return nil },
		setHardwareAddr: func(_ netlink.Link, _ net.HardwareAddr) error {
			// The live attempt is the one made while the link is still UP,
			// i.e. before any link-down has been recorded.
			live := true
			for _, e := range *r.events {
				if e == "link-down" {
					live = false
				}
			}
			if live {
				*r.events = append(*r.events, "set-mac-live")
				if r.liveFail {
					return errors.New("EBUSY: device busy (no IFF_LIVE_ADDR_CHANGE)")
				}
				return nil
			}
			*r.events = append(*r.events, "set-mac-cycled")
			return nil
		},
	}
}

func withRethOps(t *testing.T, ops rethLinkOps) {
	t.Helper()
	saved := rethLinkOpsFn
	rethLinkOpsFn = ops
	t.Cleanup(func() { rethLinkOpsFn = saved })
}

var (
	curMAC5103  = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	virtMAC5103 = net.HardwareAddr{0x02, 0xbf, 0x72, 0x01, 0x01, 0x00}
)

// TestRethMACJoinsWorkersBeforeLinkCycle_5103 is the ordering guard. It asserts
// the full sequence, not just that the join happened: stop_workers must precede
// link-down, and the MAC write and link-up must follow it.
func TestRethMACJoinsWorkersBeforeLinkCycle_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))

	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		events = append(events, "stop_workers")
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if !cycled {
		t.Fatalf("expected a link cycle when the live MAC set is rejected")
	}

	want := []string{"set-mac-live", "stop_workers", "link-down", "set-mac-cycled", "link-up"}
	if strings.Join(events, ",") != strings.Join(want, ",") {
		t.Fatalf("link-cycle sequence = %v, want %v.\nThe worker join must land BEFORE "+
			"link-down: once the NIC tears down its queues, a worker still touching UMEM "+
			"races the driver unmapping those pages (#5103)", events, want)
	}
}

// TestRethMACAbortsCycleWhenJoinFails_5103 is the fail-closed half. A join that
// cannot be completed leaves worker state unknown, so the link must NOT be
// cycled — and because the abort happens before the first mutation, the link is
// left exactly as it was found.
func TestRethMACAbortsCycleWhenJoinFails_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))

	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		events = append(events, "stop_workers")
		return errors.New("stop_workers: helper did not respond")
	})

	if err == nil {
		t.Fatal("a failed worker join must abort the MAC program — proceeding would cycle " +
			"the link with workers possibly still touching UMEM (#5103)")
	}
	if cycled {
		t.Error("linkCycled must be false when the cycle was aborted; a true return would " +
			"drive the caller's post-cycle rebind for a cycle that never happened")
	}
	for _, e := range events {
		if e == "link-down" || e == "link-up" || e == "set-mac-cycled" {
			t.Fatalf("the link was MUTATED after the join failed (%q in %v). The abort must "+
				"happen before setDown so there is nothing to unwind", e, events)
		}
	}
	if got := strings.Join(events, ","); got != "set-mac-live,stop_workers" {
		t.Errorf("sequence = %v, want the live attempt then the failed join only", events)
	}
}

// TestRethMACNoJoinWhenLiveSetSucceeds_5103 is the over-rejection guard, and
// the reason the join is a hook rather than an unconditional pre-step. On a
// driver with IFF_LIVE_ADDR_CHANGE (mlx5, virtio — the cluster's own NICs) no
// cycle happens, so the workers must NOT be stopped: joining them here would
// impose a forwarding outage on every apply that touches a RETH MAC.
func TestRethMACNoJoinWhenLiveSetSucceeds_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, false /* live set works */))

	joined := false
	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		joined = true
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if cycled {
		t.Error("no link cycle should be reported when the live MAC set succeeds")
	}
	if joined {
		t.Error("workers were joined even though no link cycle was needed — that is a " +
			"forwarding outage on every RETH MAC apply on IFF_LIVE_ADDR_CHANGE drivers")
	}
	if got := strings.Join(events, ","); got != "set-mac-live" {
		t.Errorf("sequence = %v, want just the successful live set", events)
	}
}

// TestRethMACNoJoinWhenMACAlreadyCorrect_5103 pins the early return: a member
// already carrying its virtual MAC needs neither a cycle nor a join, which is
// the steady-state case on every re-apply.
func TestRethMACNoJoinWhenMACAlreadyCorrect_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, virtMAC5103, true))

	joined := false
	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		joined = true
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if cycled || joined || len(events) != 0 {
		t.Errorf("a member already on its virtual MAC must be a no-op; cycled=%v joined=%v "+
			"events=%v", cycled, joined, events)
	}
}

// goIDFromStack reads this goroutine's id out of the runtime.Stack header
// ("goroutine 42 [running]:\n..."). It returns 0 for any header it does not
// recognise, and every caller below FATALS on 0: a reader that quietly returned
// a constant would make the identity comparison it feeds trivially true, which
// is the one way this test could go green while proving nothing.
func goIDFromStack() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	const prefix = "goroutine "
	s := string(buf[:n])
	if !strings.HasPrefix(s, prefix) {
		return 0
	}
	s = s[len(prefix):]
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	id, err := strconv.ParseUint(s[:i], 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// TestRethMACHookRunsOnTheCallersGoroutine_6871 is the dependency the #6871
// acquisition-site guard cannot see, made checkable.
//
// The daemon's ONE link-cycle lease acquisition is written inside the
// beforeCycle closure in programRethMACWithWorkerJoin, and what keeps that lease
// inside applyDataplaneAndHACore's deferred abandonLinkCycleLease is not where
// the call is WRITTEN — it is that programRethMAC INVOKES the callback
// synchronously. The static guard
// (pkg/dataplane/userspace/link_cycle_acquisition_site_6871_test.go) marks that
// site "[in a func literal]" precisely because no AST fact establishes this, and
// its linkCycleUnprovenFormBindings map names THIS test as the substitute. Do
// not rename it without updating that entry — the map checks the name exists.
//
// The assertion is goroutine identity, which is the strongest available form: a
// hook body that executes on the caller's goroutine necessarily runs inside the
// dynamic extent of the programRethMAC call, so it has completed before
// programRethMAC returns and therefore before programRethMACWithWorkerJoin does.
//
// It is deliberately STRICTER than the property strictly required. A hook
// dispatched to another goroutine and then joined before returning would also be
// contained, and would fail here. That is the wanted direction: it would be a
// real change to the containment argument, and it should have to be re-argued
// rather than pass silently.
//
// A hook that ran on another goroutine WITHOUT being joined fails in two ways
// and neither is a pass: unsynchronised writes to `ran`/`hookGoID` are a data
// race that -race reports, and without -race the reads most likely see the zero
// values and fatal on "never ran".
func TestRethMACHookRunsOnTheCallersGoroutine_6871(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true /* force the cycle */))

	caller := goIDFromStack()
	if caller == 0 {
		t.Fatal("fixture: could not read the test goroutine's id from the runtime.Stack " +
			"header, so the identity comparison below would compare 0 against 0")
	}

	ran := false
	var hookGoID uint64
	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, func() error {
		ran = true
		hookGoID = goIDFromStack()
		return nil
	})
	if err != nil {
		t.Fatalf("programRethMAC: %v", err)
	}
	if !cycled {
		t.Fatal("expected the refused live set to force a cycle; on any other path the hook " +
			"is not invoked at all and this test would assert nothing")
	}
	if !ran {
		t.Fatal("the beforeCycle hook never ran on the cycle path")
	}
	if hookGoID != caller {
		t.Fatalf("beforeCycle ran on goroutine %d but programRethMAC was called from %d.\n"+
			"The daemon takes its link-cycle lease inside this hook, and the only thing "+
			"bounding that lease is applyDataplaneAndHACore's deferred "+
			"abandonLinkCycleLease. A hook that does not complete within the "+
			"programRethMAC call can take the lease after that defer has run, and since "+
			"#6871 round 8 the lease renews itself — so it would suppress the 1 Hz "+
			"reconcile for the life of the process (#6871 round 14)", hookGoID, caller)
	}
}

// TestRethMACNilBeforeCycleStillCycles_5103 covers the caller with no dataplane
// attached: a nil hook means "no join needed", not "abort".
func TestRethMACNilBeforeCycleStillCycles_5103(t *testing.T) {
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, curMAC5103, true))

	cycled, _, err := programRethMAC("ge-0-0-1", virtMAC5103, nil)
	if err != nil {
		t.Fatalf("programRethMAC with a nil hook: %v", err)
	}
	if !cycled {
		t.Error("a nil hook must not suppress the cycle")
	}
	if got := strings.Join(events, ","); got != "set-mac-live,link-down,set-mac-cycled,link-up" {
		t.Errorf("sequence = %v", events)
	}
}

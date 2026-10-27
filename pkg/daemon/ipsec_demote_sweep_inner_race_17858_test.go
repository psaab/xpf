// #17858: the #16820 ownership re-check in terminateDemotedRGIPsecSAs ran
// at the daemon wrapper boundary, but the real terminate is
// ipsec.Manager.TerminateConnection, which performs ANOTHER blocking
// `swanctl --list-sas` (to resolve the IKE connection name) before the
// `--terminate --ike --force` exec. A demotion sweep that passed the
// re-check and then stalled in that inner read survives a complete
// failback — epoch bump, takeover belt, initiate — and its terminate then
// lands on the replacement SA (same IKE name), leaving the final operation
// terminate instead of initiate: the #15194 failback black hole recreated
// on the node that owns the RG.
//
// These cells therefore drive the REAL manager path (d.ipsec with a
// swanctl exec double; ipsecTerminateFn is deliberately NOT set — a seam
// that replaces the whole terminate cannot see inside it, which is exactly
// how the #16820 suite stayed green over this window).
//
// SUBJECT cell: failback completes while the sweep is blocked in the
// terminate path's OWN live-SA read. The sweep must issue NO terminate
// after the failback initiate; the final event must be the initiate.
// CONTROL cell: no failback — the sweep must still terminate the demoted
// RG's SA exactly as #15194 requires (the guard must not over-abort).
//
// Completion is JOINED (sweepDone), not sleep-polled: the sweep either
// execs the stale terminate before it can exit (pre-fix, RED) or returns
// from the guarded terminate without execing (post-fix).

package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/ipsec"
)

// cannedSAs17858 is the `swanctl --list-sas` answer the double returns for
// the terminate path's inner read. The IKE SA is gateway-named (gw-rg1,
// #15024) and carries the vpn-rg1 child — the same names whether the SA
// is the demoted original or the failback replacement, which is why a
// stale terminate by IKE name kills the replacement.
const cannedSAs17858 = `gw-rg1: #4, ESTABLISHED, IKEv2, 8f7c..._i* 4d3c..._r
  local  '10.0.1.1' @ 10.0.1.1[500]
  remote '198.51.100.1' @ 198.51.100.1[500]
  vpn-rg1: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128
`

// innerRaceHarness17858 builds the two-RG fixture with a REAL ipsec.Manager
// whose swanctl exec double records terminate/initiate events in order and
// blocks the FIRST --list-sas (the demotion sweep's inner read) until
// released. Later --list-sas calls (the takeover belt's) return
// immediately so the belt cannot deadlock against the gate.
type innerRaceHarness17858 struct {
	d          *Daemon
	cm         *cluster.Manager
	eventsMu   sync.Mutex
	events     []string
	listCount  int
	listGate   chan struct{}
	release    chan struct{}
	releaseOne sync.Once
}

func newInnerRaceHarness17858(t *testing.T) *innerRaceHarness17858 {
	t.Helper()
	store, cm := demotionFixture15194(t)
	h := &innerRaceHarness17858{
		cm:       cm,
		listGate: make(chan struct{}),
		release:  make(chan struct{}),
	}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-rg1"})

	m := ipsec.NewWithConfigDir(t.TempDir())
	m.SetSwanctlForTesting(func(args ...string) ([]byte, error) {
		switch args[0] {
		case "--list-sas":
			h.eventsMu.Lock()
			h.listCount++
			n := h.listCount
			h.eventsMu.Unlock()
			if n == 1 {
				// Only the sweep's inner read blocks: the belt's read
				// must complete or the failback could never finish.
				h.releaseOne.Do(func() { close(h.listGate) })
				<-h.release
			}
			return []byte(cannedSAs17858), nil
		case "--terminate":
			// args: --terminate --ike <name> --force
			h.eventsMu.Lock()
			h.events = append(h.events, "terminate:"+args[2])
			h.eventsMu.Unlock()
			return nil, nil
		case "--initiate":
			// args: --initiate --child <name> --timeout 5
			h.eventsMu.Lock()
			h.events = append(h.events, "initiate:"+args[2])
			h.eventsMu.Unlock()
			return nil, nil
		}
		return nil, nil
	})

	h.d = &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsec:       m,
		ipsecActiveNamesFn: func() ([]string, error) {
			return []string{"vpn-rg1"}, nil
		},
	}
	return h
}

func (h *innerRaceHarness17858) snapshot() []string {
	h.eventsMu.Lock()
	defer h.eventsMu.Unlock()
	return append([]string(nil), h.events...)
}

func (h *innerRaceHarness17858) terminateCount() int {
	n := 0
	for _, e := range h.snapshot() {
		if e == "terminate:gw-rg1" {
			n++
		}
	}
	return n
}

// launchSweep17858 demotes RG1 and runs the sweep JOINABLY: the epoch is
// captured exactly as clearRethServicesForRG does, but the sweep runs on a
// channel the test can join, so completion (or the stale exec) is observed
// deterministically instead of by sleeping.
func (h *innerRaceHarness17858) launchSweep17858() (sweepDone <-chan struct{}) {
	h.cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	rg1Epoch := h.d.bumpIPsecRGOwnershipEpoch(1) // what clearRethServicesForRG does
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.d.terminateDemotedRGIPsecSAs(1, rg1Epoch)
	}()
	return done
}

// SUBJECT: the sweep passes its ownership re-check, blocks in the
// terminate path's OWN --list-sas, and the RG fails back completely
// (epoch bump + belt terminate + initiate) before that read returns. The
// sweep must not terminate anything after the initiate.
func TestDemotionSweepBlockedInTerminateReadAbortsOnFailback17858(t *testing.T) {
	h := newInnerRaceHarness17858(t)
	sweepDone := h.launchSweep17858()

	select {
	case <-h.listGate:
	case <-time.After(5 * time.Second):
		t.Fatal("#17858: sweep did not reach the terminate path's inner SA read")
	}

	// Failback: node becomes RG1 primary again; the promotion edge bumps
	// the epoch FIRST (what applyRethServicesForRG does), then the
	// re-initiate leg runs the belt (terminate the stale local duplicate
	// by IKE name) and the initiate. Driven synchronously for a
	// deterministic event order — the sweep is parked in its blocked read
	// and holds nothing the promotion needs.
	h.cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	h.d.bumpIPsecRGOwnershipEpoch(1)
	h.d.reinitiateIPsecSAsForRG(1)

	// Now the sweep's inner read returns — listing the SA now living
	// under the same gw-rg1/vpn-rg1 names (the replacement).
	close(h.release)
	<-sweepDone

	events := h.snapshot()
	if len(events) == 0 {
		t.Fatal("#17858: no events recorded; failback initiate never ran")
	}
	if last := events[len(events)-1]; last != "initiate:vpn-rg1" {
		t.Fatalf("#17858: failback-during-blocked-terminate-read must end "+
			"with initiate:vpn-rg1, got events=%v (the demotion sweep "+
			"terminated the replacement SA after the failback initiate)", events)
	}
	if n := h.terminateCount(); n != 1 {
		t.Fatalf("#17858: expected exactly 1 terminate (the takeover belt's), "+
			"got %d in events=%v (a second terminate is the stale demotion "+
			"sweep firing after the inner SA read)", n, events)
	}
}

// CONTROL: identical harness, no failback. The sweep must still terminate
// the demoted RG's SA — the ownership guard must gate only the raced
// window, never weaken the #15194 demotion teardown.
func TestDemotionSweepBlockedInTerminateReadStillTerminates17858(t *testing.T) {
	h := newInnerRaceHarness17858(t)
	sweepDone := h.launchSweep17858()

	select {
	case <-h.listGate:
	case <-time.After(5 * time.Second):
		t.Fatal("#17858: sweep did not reach the terminate path's inner SA read")
	}

	// No failback: release the read and let the sweep finish.
	close(h.release)
	<-sweepDone

	events := h.snapshot()
	if len(events) != 1 || events[0] != "terminate:gw-rg1" {
		t.Fatalf("#17858: no-failback control must issue exactly the demotion "+
			"terminate:gw-rg1, got events=%v", events)
	}
}

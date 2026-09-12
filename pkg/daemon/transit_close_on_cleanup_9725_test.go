package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #9725: `xpfd cleanup` destroys the pinned XDP links a hitless stop left
// attached — with kernel transit OPEN on the strength of their surviving — and
// runs in its own process with no daemon to observe it. So it must close the
// gate itself.
func TestCleanupClosesKernelTransit9725(t *testing.T) {
	v4, v6, fake := seamTransitClose9686(t)

	CloseKernelTransitForCleanup()

	for i, fam := range []string{"IPv4 ip_forward", "IPv6 conf.all.forwarding"} {
		if got := readKnob9725(t, []string{v4, v6}[i]); got != "0" {
			t.Errorf("#9725: %s = %q after cleanup, want \"0\". Cleanup has just destroyed every pinned "+
				"XDP link, so nothing adjudicates transit until xpfd starts", fam, got)
		}
	}
	if len(fake.barrierCalls) == 0 || fake.barrierCalls[len(fake.barrierCalls)-1] != "install" {
		t.Errorf("#9725: cleanup did not install the #7191 barrier: %v. Bridged frames ignore the sysctls, "+
			"so the barrier is the only leg that stops them", fake.barrierCalls)
	}
}

// Unconditional and idempotent: after cleanup nothing adjudicates transit
// whatever the knobs said before, and a second run must converge rather than
// depend on the first.
func TestCleanupClosesKernelTransitWhateverItFinds9725(t *testing.T) {
	for _, seed := range []string{"0", "1"} {
		t.Run("knobs start at "+seed, func(t *testing.T) {
			v4, v6 := withTempTransitForwardSysctls(t, seed)
			withBarrierRecorder(t)
			CloseKernelTransitForCleanup()
			CloseKernelTransitForCleanup()
			for i, fam := range []string{"IPv4 ip_forward", "IPv6 conf.all.forwarding"} {
				if got := readKnob9725(t, []string{v4, v6}[i]); got != "0" {
					t.Errorf("%s = %q after two cleanups from %q, want \"0\"", fam, got, seed)
				}
			}
		})
	}
}

// #9804's lesson applied to a command: a close that nothing calls is invisible.
// The cleanup subcommand must actually invoke it, and the source is where that
// is visible — the command exits the process, so there is no seam to observe.
func TestTheCleanupCommandClosesKernelTransit9725(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "cmd", "xpfd", "main.go"))
	if err != nil {
		t.Fatalf("read cmd/xpfd/main.go: %v", err)
	}
	src := string(b)
	idx := strings.Index(src, "case cmdCleanup:")
	if idx < 0 {
		t.Fatal("cmd/xpfd/main.go no longer has a cmdCleanup case")
	}
	rest := src[idx:]
	if end := strings.Index(rest, "\n\tcase "); end > 0 {
		rest = rest[:end]
	}
	if !strings.Contains(rest, "daemon.CloseKernelTransitForCleanup()") {
		t.Error("#9725: the cleanup subcommand does not call daemon.CloseKernelTransitForCleanup(). " +
			"Cleanup unpins and destroys the shim XDP links a hitless stop left attached, and no daemon " +
			"is running to re-evaluate the gate, so the node keeps forwarding transit with nothing " +
			"adjudicating it until xpfd starts")
	}
	if !strings.Contains(rest, "dataplane.Cleanup()") {
		t.Error("premise: the cleanup subcommand no longer calls dataplane.Cleanup(), so this cell is " +
			"pinning the wrong thing")
	}
}

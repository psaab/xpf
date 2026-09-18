package daemon

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func withFabricMTUSeams10216(t *testing.T, links map[string]netlink.Link, set func(netlink.Link, int) error) {
	t.Helper()
	oldLookup, oldSet := fabricLinkByName10216, fabricLinkSetMTU10216
	fabricLinkByName10216 = func(name string) (netlink.Link, error) {
		link, ok := links[name]
		if !ok {
			return nil, errors.New("no such device")
		}
		return link, nil
	}
	fabricLinkSetMTU10216 = set

	t.Cleanup(func() {
		fabricLinkByName10216, fabricLinkSetMTU10216 = oldLookup, oldSet
	})
}

// TestApplyFabricConfiguredMTUReachesEnsure_10216 proves the configured value
// survives the daemon's apply wiring (including the retry seam), rather than
// only testing the lower-level setter in isolation.
func TestApplyFabricConfiguredMTUReachesEnsure_10216(t *testing.T) {
	cfg := fabricCfg6791()
	cfg.Interfaces.Interfaces["fab0"].MTU = 9500
	old := fabricEnsureFn
	var got int
	fabricEnsureFn = func(_ string, _ string, _ []string, mtu int) error {
		got = mtu
		return nil
	}
	t.Cleanup(func() { fabricEnsureFn = old })

	if err := (&Daemon{}).applyFabricIPVLAN(cfg); err != nil {
		t.Fatalf("applyFabricIPVLAN: %v", err)
	}
	if got != 9500 {
		t.Fatalf("configured MTU passed to fabric ensure = %d, want 9500", got)
	}
}

// TestApplyFabricConfiguredMTUFailureIsRejected_10216 proves a refused
// configured-MTU reconcile reaches the commit-facing apply error after the
// existing bounded retries; it is not reduced to a warn-only success.
func TestApplyFabricConfiguredMTUFailureIsRejected_10216(t *testing.T) {
	cfg := fabricCfg6791()
	cfg.Interfaces.Interfaces["fab0"].MTU = 9500
	boom := errors.New("jumbo MTU refused")
	oldFn, oldDelay := fabricEnsureFn, fabricIPVLANRetryDelay
	fabricIPVLANRetryDelay = time.Millisecond
	fabricEnsureFn = func(_ string, _ string, _ []string, mtu int) error {
		if mtu != 9500 {
			t.Fatalf("configured MTU passed to failing ensure = %d, want 9500", mtu)
		}
		return boom
	}
	t.Cleanup(func() {
		fabricEnsureFn, fabricIPVLANRetryDelay = oldFn, oldDelay
	})

	err := (&Daemon{}).applyFabricIPVLAN(cfg)
	if err == nil {
		t.Fatal("applyFabricIPVLAN returned nil after configured MTU refusal")
	}
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "fab0") {
		t.Fatalf("apply error = %v, want configured MTU cause naming fab0", err)
	}
}

// TestFabricConfiguredMTUAboveFloorIsAppliedAndVerified_10216 is the
// configured-MTU acceptance cell. The floor is still the lower bound, but a
// configured fabric MTU above 9000 is now the exact target; the fresh lookup
// after the write is the verification that prevents a warn-only false claim.
//
// FAIL-ON-REVERT: restoring the old hard-coded 9000 floor makes the write and
// readback assertions RED (the operator's configured 9500 is applied by
// nobody).
func TestFabricConfiguredMTUAboveFloorIsAppliedAndVerified_10216(t *testing.T) {
	link := &fakeFabricLink{attrs: netlink.LinkAttrs{Name: "ge-0-0-0", MTU: 1500}}
	var writes []int
	var lookups int
	oldLookup, oldSet := fabricLinkByName10216, fabricLinkSetMTU10216
	fabricLinkByName10216 = func(name string) (netlink.Link, error) {
		lookups++
		if name != "ge-0-0-0" {
			t.Fatalf("verification lookup name = %q, want ge-0-0-0", name)
		}
		return link, nil
	}
	fabricLinkSetMTU10216 = func(l netlink.Link, mtu int) error {
		writes = append(writes, mtu)
		l.Attrs().MTU = mtu
		return nil
	}
	t.Cleanup(func() { fabricLinkByName10216, fabricLinkSetMTU10216 = oldLookup, oldSet })

	want := fabricMTU10216(9500)
	if want != 9500 {
		t.Fatalf("configured MTU target = %d, want 9500", want)
	}
	if err := reconcileFabricMTU10216("ge-0-0-0", link, want); err != nil {
		t.Fatalf("reconcileFabricMTU10216: %v", err)
	}
	if got := link.Attrs().MTU; got != 9500 {
		t.Fatalf("live MTU = %d, want configured 9500", got)
	}
	if len(writes) != 1 || writes[0] != 9500 {
		t.Fatalf("MTU writes = %v, want exactly [9500]", writes)
	}
	if lookups != 1 {
		t.Fatalf("fresh MTU readback lookups = %d, want exactly 1", lookups)
	}
}

// TestFabricMTUWriteFailureIsRejectedWithDiagnostic_10216 pins the failure
// half: a floor/configured write refusal must return an error that names the
// desired value, rather than logging and continuing with a stale parent.
func TestFabricMTUWriteFailureIsRejectedWithDiagnostic_10216(t *testing.T) {
	link := &fakeFabricLink{attrs: netlink.LinkAttrs{Name: "ge-0-0-1", MTU: 1500}}
	boom := errors.New("operation not supported")
	withFabricMTUSeams10216(t, map[string]netlink.Link{"ge-0-0-1": link}, func(netlink.Link, int) error {
		return boom
	})

	err := reconcileFabricMTU10216("ge-0-0-1", link, fabricMTU10216(9500))
	if err == nil {
		t.Fatal("reconcileFabricMTU10216 returned nil after a refused configured-MTU write")
	}
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), "9500") {
		t.Fatalf("error = %v, want write cause and configured MTU 9500", err)
	}
}

// TestFabricMTUReadbackMismatchIsRejected_10216 prevents a successful syscall
// from being treated as convergence when the kernel readback still differs.
func TestFabricMTUReadbackMismatchIsRejected_10216(t *testing.T) {
	link := &fakeFabricLink{attrs: netlink.LinkAttrs{Name: "ge-0-0-2", MTU: 1500}}
	withFabricMTUSeams10216(t, map[string]netlink.Link{"ge-0-0-2": link}, func(netlink.Link, int) error {
		return nil // driver accepted the request but did not converge the link
	})

	err := reconcileFabricMTU10216("ge-0-0-2", link, fabricMTU10216(9500))
	if err == nil {
		t.Fatal("reconcileFabricMTU10216 returned nil after divergent readback")
	}
	if !strings.Contains(err.Error(), "observed 1500") {
		t.Fatalf("error = %v, want observed live MTU 1500", err)
	}
}

// TestFabricMTUFloorRemainsTheLowerBound_10216 preserves #9927/#9975: a
// configured value below the fabric floor still attempts the 9000 floor.
func TestFabricMTUFloorRemainsTheLowerBound_10216(t *testing.T) {
	if got := fabricMTU10216(1400); got != fabricMTUFloor10216 {
		t.Fatalf("fabric target = %d, want floor %d", got, fabricMTUFloor10216)
	}
	if got := fabricMTU10216(9000); got != fabricMTUFloor10216 {
		t.Fatalf("floor target = %d, want floor %d", got, fabricMTUFloor10216)
	}
}

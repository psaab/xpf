package routing

import (
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type transientLookupOps13120 struct {
	vrfOps
	err error
}

func (o transientLookupOps13120) LinkByName(name string) (netlink.Link, error) {
	if name == "vrf-boom" {
		return nil, o.err
	}
	return o.vrfOps.LinkByName(name)
}

// #13120: a failed #9819 miss-terminator install must fail closed: no new
// VRF link may be materialized (its misses would fall through to main), in
// either Create or Reconcile.
func TestVRFCreateTerminatorFailureFailsClosed13120(t *testing.T) {
	var events []string
	links := newFakeVRFLinks9819(&events)
	term := newFakeTerm9819(&events)
	term.addErr = unix.EPERM
	mgr := &vrfManager{ops: links, term: term}

	err := mgr.Create("red", 100)
	if err == nil || !errors.Is(err, unix.EPERM) {
		t.Fatalf("Create error = %v, want terminator EPERM", err)
	}
	if links.links["vrf-red"] != nil {
		t.Fatal("Create materialized vrf-red despite missing miss terminator")
	}
	if mgr.IsManaged("red") {
		t.Fatal("Create tracked vrf-red despite missing miss terminator")
	}
	for _, e := range events {
		if strings.HasPrefix(e, "link-add") {
			t.Fatalf("Create performed %q despite terminator failure; events=%v", e, events)
		}
	}
}

func TestVRFReconcileTerminatorFailureFailsClosed13120(t *testing.T) {
	var events []string
	links := newFakeVRFLinks9819(&events)
	term := newFakeTerm9819(&events)
	mgr := &vrfManager{ops: links, term: term}
	if err := mgr.Create("red", 100); err != nil {
		t.Fatalf("seed Create: %v", err)
	}

	term.addErr = unix.EPERM
	events = nil
	err := mgr.Reconcile([]VRFSpec{{Name: "red", TableID: 100}, {Name: "blue", TableID: 200}})
	if err == nil || !errors.Is(err, unix.EPERM) {
		t.Fatalf("Reconcile error = %v, want terminator EPERM", err)
	}
	if links.links["vrf-blue"] != nil {
		t.Fatal("Reconcile materialized vrf-blue despite missing miss terminator")
	}
	if links.links["vrf-red"] == nil {
		t.Fatal("Reconcile deleted pre-existing vrf-red on terminator failure")
	}
	if !mgr.IsManaged("red") || mgr.IsManaged("blue") {
		t.Fatalf("tracked set changed on terminator failure: red=%v blue=%v",
			mgr.IsManaged("red"), mgr.IsManaged("blue"))
	}
	for _, e := range events {
		if strings.HasPrefix(e, "link-add") || strings.HasPrefix(e, "link-del") {
			t.Fatalf("Reconcile performed %q despite terminator failure; events=%v", e, events)
		}
	}
}

// #13120: Create on an already-existing link must apply the same checks as
// reconcile (#12062 foreign-type rejection, table verification, #12136
// LinkSetUp propagation) and must adopt a valid VRF into the tracked set.
func TestVRFCreateExistingLinkChecks13120(t *testing.T) {
	t.Run("foreign non-VRF is rejected and never brought up", func(t *testing.T) {
		ops := newInjectable()
		ops.overlay["vrf-foreign"] = &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "vrf-foreign", Index: 77}}
		ops.failSetUpFor = "vrf-foreign"
		mgr := &vrfManager{ops: ops}
		if err := mgr.Create("foreign", 300); err == nil {
			t.Fatal("Create on foreign Bridge returned nil error")
		}
		if mgr.IsManaged("foreign") {
			t.Fatal("Create adopted foreign Bridge")
		}
		if ops.setUps != 0 {
			t.Fatalf("Create called LinkSetUp %d times on foreign link, want 0", ops.setUps)
		}
	})

	t.Run("matching VRF is adopted and brought up", func(t *testing.T) {
		ops := newInjectable()
		ops.seed("vrf-a", 100)
		mgr := &vrfManager{ops: ops}
		if err := mgr.Create("a", 100); err != nil {
			t.Fatalf("Create on matching VRF: %v", err)
		}
		if !mgr.IsManaged("a") {
			t.Fatal("Create did not adopt existing matching VRF")
		}
		if ops.setUps != 1 {
			t.Fatalf("LinkSetUp calls = %d, want 1", ops.setUps)
		}
	})

	t.Run("table mismatch recreates with desired table", func(t *testing.T) {
		ops := newInjectable()
		ops.seed("vrf-a", 999)
		mgr := &vrfManager{ops: ops}
		if err := mgr.Create("a", 100); err != nil {
			t.Fatalf("Create on table-mismatched VRF: %v", err)
		}
		if !mgr.IsManaged("a") {
			t.Fatal("Create did not adopt recreated VRF")
		}
		if got := ops.links["vrf-a"].Table; got != 100 {
			t.Fatalf("VRF table = %d, want 100", got)
		}
		if ops.dels != 1 || ops.adds != 1 {
			t.Fatalf("LinkDel/LinkAdd = %d/%d, want 1/1", ops.dels, ops.adds)
		}
		if ops.setUps != 1 {
			t.Fatalf("Create called LinkSetUp %d times on recreated VRF, want 1", ops.setUps)
		}
	})

	t.Run("LinkSetUp failure propagates but keeps ownership for retry", func(t *testing.T) {
		ops := newInjectable()
		ops.seed("vrf-a", 100)
		ops.failSetUpFor = "vrf-a"
		mgr := &vrfManager{ops: ops}
		if err := mgr.Create("a", 100); err == nil {
			t.Fatal("Create swallowed LinkSetUp failure")
		}
		if !mgr.IsManaged("a") {
			t.Fatal("Create dropped ownership after LinkSetUp failure; reconcile could not retry")
		}
	})

	t.Run("transient lookup error is not treated as absence", func(t *testing.T) {
		base := newInjectable()
		ops := transientLookupOps13120{vrfOps: base, err: unix.EBUSY}
		mgr := &vrfManager{ops: ops}
		err := mgr.Create("boom", 100)
		if err == nil || !errors.Is(err, unix.EBUSY) {
			t.Fatalf("Create error = %v, want wrapped EBUSY", err)
		}
		if base.adds != 0 {
			t.Fatalf("Create attempted LinkAdd %d times after transient lookup error", base.adds)
		}
		if mgr.IsManaged("boom") {
			t.Fatal("Create tracked VRF after transient lookup error")
		}
	})

	t.Run("recreating tracked missing VRF does not duplicate ownership", func(t *testing.T) {
		ops := newInjectable()
		mgr := &vrfManager{ops: ops, vrfs: []string{"vrf-a"}}
		if err := mgr.Create("a", 100); err != nil {
			t.Fatalf("Create on missing tracked VRF: %v", err)
		}
		if len(mgr.vrfs) != 1 || mgr.vrfs[0] != "vrf-a" {
			t.Fatalf("tracked VRFs = %v, want [vrf-a]", mgr.vrfs)
		}
	})

	t.Run("recreating tracked table mismatch does not duplicate ownership", func(t *testing.T) {
		ops := newInjectable()
		ops.seed("vrf-a", 999)
		mgr := &vrfManager{ops: ops, vrfs: []string{"vrf-a"}}
		if err := mgr.Create("a", 100); err != nil {
			t.Fatalf("Create on table-mismatched tracked VRF: %v", err)
		}
		if len(mgr.vrfs) != 1 || mgr.vrfs[0] != "vrf-a" {
			t.Fatalf("tracked VRFs = %v, want [vrf-a]", mgr.vrfs)
		}
	})
}

package routing

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

type countingLinkListOps12657 struct {
	*linkListFakeOps11443
	linkDelCalls []string
}

func (f *countingLinkListOps12657) LinkDel(link netlink.Link) error {
	f.linkDelCalls = append(f.linkDelCalls, link.Attrs().Name)
	return f.fakeLinkOps.LinkDel(link)
}

// #12657 (PR #12578 Opus R1 residual, mutant M2): the xfrm orphan sweep
// in xfrmManager.Apply must SKIP names already in x.xfrmis — the tracked
// delete/retry pass below the sweep owns those names. If the sweep stops
// skipping tracked names, it makes an extra LinkDel attempt before the
// tracked pass. With LinkDel failing for this tracked name, that extra
// attempt leaks into the call count and risks duplicate error handling.
//
// The pre-existing TestXfrmOrphanReapRemoveWhileDown11443 only exercises
// an EMPTY tracked set (fresh manager), so M2 passed the whole
// pkg/routing suite. This test counts all LinkDel attempts, including
// failed attempts, for a tracked, undesired xfrmi.
//
// FAIL-ON-MUTANT: remove the `if _, tracked := x.xfrmis[name]; tracked
// { continue }` skip in xfrm.go Apply and st0.5 receives two LinkDel
// attempts instead of one; the exact-count assertion fails RED.

func countDels12657(delNames []string, name string) int {
	n := 0
	for _, d := range delNames {
		if d == name {
			n++
		}
	}
	return n
}

// TestXfrmOrphanSweepSkipsTrackedNames12657 pins that the orphan sweep
// never LinkDel's a tracked name, while still reaping a genuine orphan
// exactly once and never touching foreign links.
func TestXfrmOrphanSweepSkipsTrackedNames12657(t *testing.T) {
	base := newFakeLinkOps()
	listOps := &linkListFakeOps11443{fakeLinkOps: base}
	ops := &countingLinkListOps12657{linkListFakeOps11443: listOps}

	// Tracked + undesired (VPN removed): owned by the tracked pass.
	// Seeded as a kernel Xfrmi so the sweep WOULD reap it if the
	// tracked skip were missing.
	seedXfrmi11443(base, "st0.5", 71, 6)
	// Genuine orphan: xfrmi, well-formed name, neither tracked nor desired.
	seedXfrmi11443(base, "st0.9", 72, 0x10)
	// Tracked + still desired: neither sweep nor tracked pass deletes it.
	seedXfrmi11443(base, "st0.1", 73, 2)
	// Foreign links the sweep must never claim.
	seedDummy11443(base, "st9", 74)            // st* name, not an Xfrmi
	seedXfrmi11443(base, "corp-vpn", 75, 0x99) // Xfrmi, not an xpf-shaped name

	_, trackedID := config.XFRMIfNameAndID("st0.1")
	xm := &xfrmManager{
		ops: ops,
		xfrmis: map[string]uint32{
			"st0.5": 6, // tracked, no longer desired
			"st0.1": trackedID,
		},
	}
	// The tracked deletion fails and remains tracked for retry. The sweep
	// must not attempt it first; otherwise the same failed delete is tried
	// twice in one Apply and its error is reported through both paths.
	base.delFail["st0.5"] = errors.New("injected LinkDel failure")
	vpns := map[string]*config.IPsecVPN{
		"vpn1": {Name: "vpn1", BindInterface: "st0.1"},
	}
	if err := xm.Apply(vpns); err == nil {
		t.Fatal("Apply must surface the injected tracked LinkDel failure")
	}

	// The tracked-undesired name receives EXACTLY ONE LinkDel attempt —
	// from the tracked pass (deleteLocked), not the orphan sweep. M2
	// (sweep does not skip tracked names) attempts it twice and fails.
	if got := countDels12657(ops.linkDelCalls, "st0.5"); got != 1 {
		t.Errorf("tracked undesired st0.5 LinkDel attempts = %d, want exactly 1 (tracked pass only; orphan sweep must skip tracked names): calls=%v", got, ops.linkDelCalls)
	}
	// The genuine orphan is reaped exactly once by the sweep.
	if got := countDels12657(ops.linkDelCalls, "st0.9"); got != 1 {
		t.Errorf("orphan st0.9 LinkDel attempts = %d, want exactly 1: calls=%v", got, ops.linkDelCalls)
	}
	// Nothing else is ever deleted: tracked+desired and both foreign
	// links survive untouched.
	for _, keep := range []string{"st0.1", "st9", "corp-vpn"} {
		if got := countDels12657(ops.linkDelCalls, keep); got != 0 {
			t.Errorf("%s LinkDel attempts = %d, want 0: calls=%v", keep, got, ops.linkDelCalls)
		}
		if _, err := base.LinkByName(keep); err != nil {
			t.Errorf("link %s must survive Apply: %v", keep, err)
		}
	}
	if len(ops.linkDelCalls) != 2 {
		t.Errorf("total LinkDel attempts = %v, want exactly [st0.5 st0.9] in some order", ops.linkDelCalls)
	}
	if _, err := base.LinkByName("st0.9"); err == nil {
		t.Error("orphan st0.9 should be deleted after Apply")
	}
	if len(xm.xfrmis) != 2 {
		t.Errorf("tracked xfrmis = %v, want st0.1 and failed-delete st0.5 retained", xm.xfrmis)
	}
	if _, ok := xm.xfrmis["st0.5"]; !ok {
		t.Errorf("failed tracked deletion must retain st0.5 for retry: %v", xm.xfrmis)
	}
}

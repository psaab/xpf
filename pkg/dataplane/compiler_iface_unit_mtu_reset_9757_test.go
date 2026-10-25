package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9757: deleting a unit's `family inet mtu` left the VLAN sub-interface's
// kernel MTU at the old value, and with it the userspace egress MTU, which
// `pkg/dataplane/userspace/interfaces.go` reads from that same device.
//
// The apply wrote the MTU only when `unit.MTU > 0` and had no other branch, and
// nothing else writes a VLAN unit's MTU. So after the statement was removed the
// committed configuration no longer described the running state: DF-set traffic
// between the old MTU and the link MTU kept drawing Frag-Needed from the box,
// and DF-clear traffic kept recording the #9328
// `egress_mtu_exceeded_forwarded_no_df` exception.
//
// Measured on the loss userspace cluster at `5f28e89ac`: after
// `delete interfaces reth0 unit 80 family inet mtu`, `show configuration` had no
// mtu statement while `ge-0-0-2.80` and `ge-7-0-2.80` both stayed at 1400, read
// nine seconds after the commit. The only repair was to commit an explicit
// `mtu 1500` and delete it again.
//
// The reset target is the PARENT's MTU after the apply (#16633: the same-pass
// plan when one exists, else the parent link's live MTU), which is what a
// freshly created VLAN child inherits — so the device lands where it would
// have been had the statement never existed, rather than at a number this
// code invented.

// noUnitMTUConfig9757 is taggedOnlyConfig9757's shape: unit 50 keeps an explicit
// unit MTU, unit 80 has none. The two live side by side deliberately, so one
// apply covers both branches and a fix that simply stopped writing MTUs cannot
// pass.
func noUnitMTUConfig9757() *config.Config {
	cfg := taggedOnlyConfig9761()
	// Unit 80 already carries no MTU in that fixture; assert it rather than
	// trusting the shared fixture not to drift.
	if u := cfg.Interfaces.Interfaces[taggedParent9761].Units[80]; u == nil || u.MTU != 0 {
		panic("fixture drift: unit 80 must carry no MTU statement for #9757")
	}
	return cfg
}

// A unit with NO mtu statement whose device carries a stale lowered value is
// reset to the parent's planned MTU (#16633: the same-pass plan, here the
// interface-level 1400, not the parent's cached live value).
func TestDeletedUnitMTUResetsTheSubInterface9757(t *testing.T) {
	cfg := noUnitMTUConfig9757()
	sub80 := taggedParent9761 + ".80"

	// The fixture plans 1400 on the parent; the parent link is still cached
	// at 1500 and the stale 1400 on the child is what the deleted statement
	// left behind. The reset target is the planned 1400.
	h, _ := applyTaggedParent9761(t, cfg, 1500, 1300, 1400)

	if got := h.mtu[sub80]; got != 1400 {
		t.Fatalf("#9757/#16633: %s kept MTU %d after the mtu statement was deleted, want the parent's planned 1400.\n"+
			"The committed configuration no longer describes the running state: DF-set traffic between "+
			"the stale value and the link MTU keeps drawing Frag-Needed from the box, and the userspace "+
			"egress MTU is read from this same device", sub80, got)
	}
	// The child already sits at the planned value, so the reset is a no-op
	// write-wise; the parent itself must still converge 1500 -> 1400.
	if got := h.mtu[taggedParent9761]; got != 1400 {
		t.Fatalf("parent %s mtu = %d, want its planned 1400", taggedParent9761, got)
	}

	// CONTROL, in the same apply: the unit that DOES carry a statement still
	// gets its own value, not the parent's. A fix that reset everything to the
	// parent would pass the row above and break this one.
	sub50 := taggedParent9761 + ".50"
	if got := h.mtu[sub50]; got != 1300 {
		t.Fatalf("control: %s must keep its configured unit MTU 1300, got %d", sub50, got)
	}
}

// Idempotence: a device already at the parent's planned MTU draws no write.
// Without this, the reset could re-write the same value on every apply —
// churn on a path that runs on every commit, and the kind of thing that only
// shows up as log noise until someone counts.
func TestUnitMTUResetIsIdempotent9757(t *testing.T) {
	cfg := noUnitMTUConfig9757()
	sub80 := taggedParent9761 + ".80"

	// Already where the reset wants it: parent and child both at the planned
	// 1400 (the fixture's interface-level mtu).
	h, writes := applyTaggedParent9761(t, cfg, 1400, 1300, 1400)

	if got := h.mtu[sub80]; got != 1400 {
		t.Fatalf("%s must stay at 1400, got %d", sub80, got)
	}
	if writes[sub80] != 0 {
		t.Fatalf("#9757: %s drew %d MTU writes while already at the parent's planned MTU; the reset must be "+
			"a no-op when the device is already correct", sub80, writes[sub80])
	}
}

// The reset follows the PARENT'S PLAN, not a constant and not the parent's
// stale live value. A parent raised by an interface-level `mtu` in this same
// commit is the value a new child would inherit, so an unstatemented unit
// must land there too — 1500 is not hardcoded anywhere. The parent link here
// still reads its OLD 1500 live (cached, pre-write) while the plan is 9000;
// on the pre-#16633 code the reset targeted 1500 and left the child there.
func TestUnitMTUResetFollowsTheParent9757(t *testing.T) {
	cfg := noUnitMTUConfig9757()
	cfg.Interfaces.Interfaces[taggedParent9761].MTU = 9000
	sub80 := taggedParent9761 + ".80"

	h, _ := applyTaggedParent9761(t, cfg, 1500, 1300, 1400)

	if got := h.mtu[taggedParent9761]; got != 9000 {
		t.Fatalf("premise: parent mtu = %d, want its planned 9000 after the apply", got)
	}
	if got := h.mtu[sub80]; got != 9000 {
		t.Fatalf("#9757/#16633: %s reset to %d, want the parent's planned 9000. The reset target must be the parent "+
			"MTU after this apply — what a freshly created VLAN child inherits — not a constant and not the "+
			"parent's cached pre-write MTU", sub80, got)
	}
}

package dataplane

import (
	"log/slog"

	"github.com/psaab/xpf/pkg/config"
)

// applyVLANSubInterfaceMTU9757 writes a VLAN sub-interface's MTU, and RESETS it
// to the parent's when the unit carries no MTU statement.
//
// #9757: the write used to happen only when `unit.MTU > 0` and had no other
// branch, and nothing else writes a VLAN unit's MTU — `git grep -E
// "LinkSetMTU|linkSetMTUSeam|MTUBytes" -- pkg/` finds no second writer. So
// deleting `family inet mtu` left the kernel device at the old value, and with
// it the userspace egress MTU, which `pkg/dataplane/userspace/interfaces.go`
// reads from that same device via `buildLinkSnapshot`.
//
// The committed configuration then stopped describing the running state:
// DF-set traffic between the stale value and the link MTU kept drawing
// Frag-Needed from the box, and DF-clear traffic kept recording the #9328
// `egress_mtu_exceeded_forwarded_no_df` exception. Measured on the loss
// userspace cluster at `5f28e89ac`: after
// `delete interfaces reth0 unit 80 family inet mtu`, `show configuration` had no
// mtu statement while `ge-0-0-2.80` and `ge-7-0-2.80` both sat at 1400, read
// nine seconds after the commit. The only repair was to commit an explicit
// `mtu 1500` and delete it again.
//
// THE RESET TARGET IS THE PARENT'S LIVE MTU, not a constant. That is what a
// freshly created VLAN child inherits, so the device lands where it would have
// been had the statement never existed. A constant would be wrong the moment an
// interface-level `mtu` lowers the parent, and
// TestUnitMTUResetFollowsTheParent9757 is the cell that says so.
//
// `family inet6 mtu` compiles into the same `unit.MTU`, so both families are
// covered by this one branch.
//
// The write happens only on a real difference. This path runs on every commit,
// so an unconditional write would churn the link and the log — asserted by
// TestUnitMTUResetIsIdempotent9757 rather than left to review.
//
// It lives in its own file because adding it inline pushed compiler_iface.go
// past the 2000 LOC modularity floor. The rule in docs/engineering-style.md is
// to split rather than to record an exception, and a bugfix is a poor reason to
// spend one.
func applyVLANSubInterfaceMTU9757(
	cfg *config.Config,
	result *CompileResult,
	cfgName string,
	unitNum int,
	physName string,
	subName string,
) {
	ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]
	if !ok || ifCfg == nil {
		return
	}

	wantMTU := 0
	if unit, ok := ifCfg.Units[unitNum]; ok && unit != nil && unit.MTU > 0 {
		wantMTU = unit.MTU
	} else if parent, err := result.cachedLinkByName(physName); err == nil {
		wantMTU = parent.Attrs().MTU
	}
	if wantMTU <= 0 {
		// No statement and no readable parent: leave the device alone rather
		// than invent a value. This is the pre-#9757 behaviour, which is the
		// safe direction when the reset target cannot be determined.
		return
	}

	nl, err := result.cachedLinkByName(subName)
	if err != nil {
		return
	}
	if nl.Attrs().MTU == wantMTU {
		return
	}
	if err := linkSetMTUSeam(nl, wantMTU); err != nil {
		slog.Warn("failed to set VLAN sub-interface MTU",
			"name", subName, "mtu", wantMTU, "err", err)
		return
	}
	slog.Info("set VLAN sub-interface MTU", "name", subName, "mtu", wantMTU)
}

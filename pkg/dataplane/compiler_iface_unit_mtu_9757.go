package dataplane

import (
	"fmt"
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
//
// #9841: every failure to read or write the MTU now records an MTUUnconverged
// (commit warning + show field) instead of succeeding silently. Lookups retry
// once uncached with identity validation (mtuCtx carries ensure's proved
// ifindexes); the parent's same-pass plan grades ordering transients. A
// write success clears any pending record for the child — this runs once per
// zone reference, so a later reference (or #9845's future post-parent retry
// landing inside this attempt) converging must not leave a stale warning.
func applyVLANSubInterfaceMTU9757(
	cfg *config.Config,
	result *CompileResult,
	ifaceRef string,
	cfgName string,
	unitNum int,
	physName string,
	subName string,
	mtuCtx vlanMTUContext9841,
) {
	ifCfg, ok := cfg.Interfaces.Interfaces[cfgName]
	if !ok || ifCfg == nil {
		return
	}
	// The record's ConfigRef is the AUTHORED zone reference verbatim, never
	// rebuilt from the parsed unit number: "reth0.080" and "reth0.80" are
	// distinct zone spellings of one unit (#5878), and the renderers match
	// li.ifaceRef plus leftover prefixes against the authored form. Itoa
	// canonicalization here would hide the record from its own row.
	configRef := ifaceRef

	wantMTU := 0
	if unit, ok := ifCfg.Units[unitNum]; ok && unit != nil && unit.MTU > 0 {
		wantMTU = unit.MTU
	} else {
		parent, perr := result.cachedLinkByName(physName)
		if perr != nil {
			var rerr error
			parent, rerr = result.retryLinkByName9841(physName, mtuCtx.parentIfindex, 0, false)
			if rerr != nil {
				// No statement and no readable parent. Leaving the device
				// alone is still the only safe actuation — but it is now a
				// RECORDED one: the reset is required convergence behavior,
				// and silence here reinstates the exact #9757 harm (stale
				// device, statement-less config) with no trace at all.
				slog.Warn("failed to resolve parent for VLAN MTU reset; leaving MTU unconverged",
					"name", subName, "parent", physName, "first", perr, "retry", rerr)
				result.recordMTUUnconverged(MTUUnconverged{
					Name: subName, ConfigRef: configRef,
					WantMTU: mtuUnknown9841, LiveMTU: liveChildMTU9841(result, subName, mtuCtx),
					Grade:         MTUGradeResetTargetUnresolved,
					Detail:        fmt.Sprintf("no MTU statement; parent %s unreadable after one retry (first: %v; retry: %v)", physName, perr, rerr),
					ExpectIfindex: mtuCtx.subIfindex, ExpectParentIfindex: mtuCtx.parentIfindex,
				})
				return
			}
			slog.Info("parent link resolved on retry", "name", physName)
		}
		wantMTU = parent.Attrs().MTU
	}
	if wantMTU <= 0 {
		// No statement and the parent reads MTU 0 (degenerate), or no
		// statement and no readable parent handled above. Either way there
		// is no sane target to write; leave the device alone rather than
		// invent a value. This is the pre-#9757 behaviour, which is the
		// safe direction when the reset target cannot be determined.
		return
	}

	child, cerr := result.cachedLinkByName(subName)
	if cerr != nil {
		var rerr error
		child, rerr = result.retryLinkByName9841(subName, mtuCtx.subIfindex, mtuCtx.parentIfindex, true)
		if rerr != nil {
			slog.Warn("failed to resolve VLAN sub-interface for MTU; leaving MTU unconverged",
				"name", subName, "mtu", wantMTU, "first", cerr, "retry", rerr)
			result.recordMTUUnconverged(MTUUnconverged{
				Name: subName, ConfigRef: configRef,
				WantMTU: wantMTU, LiveMTU: mtuUnknown9841,
				Grade:         MTUGradeLookupFailed,
				Detail:        fmt.Sprintf("link lookup failed after one retry (first: %v; retry: %v)", cerr, rerr),
				ExpectIfindex: mtuCtx.subIfindex, ExpectParentIfindex: mtuCtx.parentIfindex,
			})
			return
		}
		slog.Info("VLAN sub-interface link resolved on retry", "name", subName)
	}
	if child == nil || child.Attrs() == nil {
		// Defensive: a nil-seeded cache entry. Production lookups error
		// instead of returning nil; a nil must record rather than panic or
		// skip silently.
		slog.Warn("failed to resolve VLAN sub-interface for MTU; leaving MTU unconverged",
			"name", subName, "mtu", wantMTU, "err", "resolved to nil link")
		result.recordMTUUnconverged(MTUUnconverged{
			Name: subName, ConfigRef: configRef,
			WantMTU: wantMTU, LiveMTU: mtuUnknown9841,
			Grade:         MTUGradeLookupFailed,
			Detail:        "link lookup resolved to a nil link",
			ExpectIfindex: mtuCtx.subIfindex, ExpectParentIfindex: mtuCtx.parentIfindex,
		})
		return
	}
	if child.Attrs().MTU == wantMTU {
		// Converged (or a cached-equality skip): no write, and deliberately
		// no clear — under #8119 a cached match can predate a write this
		// same apply already failed. See clearMTUUnconverged.
		return
	}
	if err := linkSetMTUSeam(child, wantMTU); err != nil {
		slog.Warn("failed to set VLAN sub-interface MTU",
			"name", subName, "mtu", wantMTU, "err", err)
		recordChildMTUWriteFailure9841(result, subName, configRef, physName, wantMTU, mtuCtx, err)
		return
	}
	result.clearMTUUnconverged(subName, configRef)
	slog.Info("set VLAN sub-interface MTU", "name", subName, "mtu", wantMTU)
}

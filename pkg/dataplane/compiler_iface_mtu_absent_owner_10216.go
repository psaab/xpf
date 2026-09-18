package dataplane

import (
	"fmt"
	"log/slog"
)

// recordAbsentInterfaceMTU10216 is the actuator half of #9985's unusable
// tunnel decision. The planner deliberately retains an explicit MTU when the
// routing owner rejects a tunnel as unusable; if the resolved netdev is then
// absent, mapZoneInterface's normal soft skip would otherwise leave the
// operator's target with no writer and no signal.
//
// A materialized Linux default is intentionally not recorded. It is an
// internal convergence target used to reset stale state on devices that are
// present; an interface legitimately absent on this chassis has no operator
// statement to diagnose. Explicit interface- or unit-level MTUs are different:
// they are configuration promises and must be surfaced when no device can
// receive them. presenceKnown is false when netdev enumeration failed, so the
// detail must not claim the interface is absent in that case.
func recordAbsentInterfaceMTU10216(result *CompileResult, pd *physDesired, physName, cfgName string, presenceKnown bool) {
	if result == nil || pd == nil || physName == "" || cfgName == "" {
		return
	}
	if !pd.mtuExplicit || pd.mtu <= 0 {
		return
	}

	status := fmt.Sprintf("netdev %s is absent; no owner can apply it", physName)
	if !presenceKnown {
		status = fmt.Sprintf("netdev %s lookup failed; presence is unknown and no owner can verify it", physName)
	}
	detail := fmt.Sprintf("configured MTU %d could not be reconciled: %s",
		pd.mtu, status)
	slog.Warn("configured interface MTU could not be reconciled",
		"interface", physName, "config", cfgName, "mtu", pd.mtu,
		"presence_known", presenceKnown, "issue", "#10216")
	result.recordMTUUnconverged(MTUUnconverged{
		Name:          physName,
		ConfigRef:     cfgName,
		WantMTU:       pd.mtu,
		LiveMTU:       mtuUnknown9841,
		Grade:         MTUGradeLookupFailed,
		Detail:        detail,
		ExpectIfindex: 0,
	})
}

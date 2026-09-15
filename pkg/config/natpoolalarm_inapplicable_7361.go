package config

import (
	"fmt"
	"sort"
)

// natPoolAlarmInapplicableWarnings reports every source-NAT pool whose
// configured `pool-utilization-alarm` can NEVER fire because the pool is
// address-only (#7361) or deterministic (#9902 F-026).
//
// THE DEFECT. `used_ports` is a popcount over the allocator's occupancy
// bitmaps. `reserve_address_only` never touches occupancy — it records
// ownership in `live.address_only_owners`. So for a `port no-translation` pool
// UsedPorts is permanently 0, the utilization percentage is permanently 0, and
// the raise-threshold cannot be crossed.
//
// THE HARM IS NOT THE MISSING PERCENTAGE. It is that the configuration reads as
// working: `show` renders the alarm, and 0% utilization is indistinguishable
// from a healthy pool. An operator who set a raise-threshold has no way to learn
// it cannot arrive — the alarm's silence looks exactly like the silence of a
// pool with plenty of headroom.
//
// WHY AN ADVISORY AND NOT A REDEFINED DENOMINATOR. #7361 proposes capacity =
// AddressCount, used = distinct addresses currently allocated. That models an
// exhaustion mode this pool class does not have: addresses are handed out
// round-robin and freely REUSED across flows with different destination tuples,
// so an address-only pool exhausts on reverse-identity collision, not on running
// out of addresses. A one-address pool would report 100% utilization after its
// first flow and stay there while serving thousands more — an alarm that fires
// on the first packet and never clears. That is worse than the current silence,
// because it trains operators to ignore the alarm that DOES work on
// port-bearing pools.
//
// If a genuine early warning is wanted for this class, the signal is the denial
// rate (the AllocatorExhausted / collision path), not a utilization ratio. That
// is a different mechanism with its own threshold semantics and deserves its
// own specification.
//
// WARN, NEVER REJECT. The combination is not invalid — `port no-translation`
// and a global `pool-utilization-alarm` are each legitimate, and the alarm
// applies correctly to every OTHER pool. Rejecting would refuse a config that
// works, for a diagnostic (#4316 accept-with-advisory, and the tolerant
// load/peer-sync path must keep booting per #1960).
func natPoolAlarmInapplicableWarnings(cfg *Config) []string {
	if cfg == nil || cfg.Security.NAT.PoolUtilizationAlarm == nil {
		return nil
	}
	if cfg.Security.NAT.PoolUtilizationAlarm.RaiseThreshold <= 0 {
		return nil // no threshold configured — nothing claims to fire
	}
	// Only a pool a rule actually REFERENCES is monitored, mirroring the
	// monitor's own eligibility walk. Warning about an unreferenced pool would
	// report an alarm that was never going to be evaluated for a different
	// reason, which is a less useful sentence.
	referenced := map[string]bool{}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			referenced[rule.Then.PoolName] = true
		}
	}
	var out []string
	for _, name := range sortedReferencedPools(referenced) {
		p, ok := cfg.Security.NAT.SourcePools[name]
		if !ok || p == nil {
			continue
		}
		// #9902 F-026: deterministic FIRST. The old shape (address-only
		// filter, then a deterministic skip) made the deterministic arm
		// unreachable behind the `!PortNoTranslation` gate for
		// deterministic+port-bearing pools — the class this sentence is
		// about. A deterministic+address-only pool reports the
		// deterministic sentence only (the block structure, not the port
		// mode, is the operative cause).
		if p.Deterministic != nil {
			out = append(out, fmt.Sprintf(
				"security nat source pool %q is deterministic (per-subscriber "+
					"blocks), so the configured `pool-utilization-alarm "+
					"raise-threshold %d` can NEVER fire for it: aggregate "+
					"utilization cannot predict per-block exhaustion. The alarm "+
					"still applies to port-bearing pools",
				name, cfg.Security.NAT.PoolUtilizationAlarm.RaiseThreshold))
			continue
		}
		if !p.PortNoTranslation {
			continue
		}
		out = append(out, fmt.Sprintf(
			"security nat source pool %q has `port no-translation`, so the configured "+
				"`pool-utilization-alarm raise-threshold %d` can NEVER fire for it: an "+
				"address-only pool allocates no ports, so its measured utilization is "+
				"permanently 0%%. The alarm still applies to port-bearing pools. This "+
				"pool exhausts on reverse-identity collision rather than on port "+
				"capacity, which a utilization percentage cannot express",
			name, cfg.Security.NAT.PoolUtilizationAlarm.RaiseThreshold))
	}
	return out
}

// sortedReferencedPools returns m's keys in sorted order, so the advisory is
// deterministic across runs — map iteration is randomized, and a warning list
// that reorders makes a golden or a diff useless.
func sortedReferencedPools(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

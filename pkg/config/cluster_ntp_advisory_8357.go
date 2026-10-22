package config

// clusterNTPAdvisory is the commit-time advisory text for a chassis cluster
// configured with no `system ntp server`.
//
// #8357: it names FABRIC RPC, not "the clock", and that is the whole point.
// #6708's finding was that the symptom the operator saw named SESSIONS ("fw0
// has only 1 established sessions") while the cause was the clock, and closing
// that distance cost an investigation. An advisory that says only "no NTP
// configured" recreates the same gap one layer earlier — the operator has to
// know that fabric RPC depends on the clock to act on it. Saying what BREAKS
// is what makes it actionable at the moment it is emitted.
const clusterNTPAdvisory = "chassis cluster is configured but `system ntp server` is empty: " +
	"cross-node fabric RPC authenticates with a 30-second time window and fails " +
	"permanently once the nodes' clocks drift apart (#6708 measured 141s of skew " +
	"with no NTP, which killed every cross-node RPC). Configure `set system ntp " +
	"server <address>` on both nodes."

// appendClusterNTPAdvisoryLocked adds the #8357 advisory when a chassis cluster
// is configured with no NTP server.
//
// SHARED by both compile entries (`compileTree` and
// `compileTree node branch`) rather than written out at each: the two
// entries already carry near-identical warning blocks, and a condition
// duplicated across them is one that drifts. One helper means a change to what
// counts as "no time source" cannot apply to only one of the paths.
//
// A WARNING, never an error, on every path. An operator legitimately configures
// a cluster before NTP is reachable — off-net staging, a box being built — and
// hard-rejecting that would make this worse than the fault it prevents.
//
// `opts.suppressClusterNTPAdvisory` silences it on the TOLERANT paths. Those
// back `Store.Load` (persisted-config boot) and `Store.SyncApply` (HA peer
// sync), so without the suppression this would fire on every boot and every
// peer sync of a config committed long ago. A warning an operator sees on every
// boot for a decision they already made is one they learn to skip, which costs
// more than it buys.
func appendClusterNTPAdvisoryLocked(cfg *Config, opts compileOpts) {
	if cfg == nil || opts.suppressClusterNTPAdvisory {
		return
	}
	// Cluster-specific by design. A standalone node with no NTP has ordinary
	// clock-drift consequences; it has no cross-node fabric RPC to lose, so the
	// advisory would be noise on the majority of deployments.
	if cfg.Chassis.Cluster == nil {
		return
	}
	if len(cfg.System.NTPServers) > 0 {
		return
	}
	cfg.Warnings = append(cfg.Warnings, clusterNTPAdvisory)
}

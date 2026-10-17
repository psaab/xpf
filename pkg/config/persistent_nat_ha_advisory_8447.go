package config

// #8447/#8573: the persistent-NAT-on-a-pool predicate, single-sourced.
//
// WHAT USED TO BE HERE, and why it is not. #8447 added a commit-time ADVISORY
// warning that `persistent-nat` on a rule-referenced pool would DISARM
// FORWARDING on a chassis-cluster member (#1449), because the disarm happened
// invisibly: the config committed cleanly and transit stopped, so it presented
// as a link failure and the issue spent five rounds of cluster measurement
// rediscovering it.
//
// #8573 removed the disarm, having measured on the loss userspace cluster that
// its stated reason was false — a persistent lease created on the active
// reaches the standby, survives a failover, and is HONOURED by the new active,
// which hands the same source identity the same translated identity. The
// advisory went with it: an advisory in front of a gate that no longer exists
// is worse than none, and #8573 names "a reworded advisory in front of an
// unchanged disarm" as the shape that made #8447 take five rounds. Both halves
// moved together, which is what the single-sourcing below was for.
//
// WHY THE PREDICATE STAYS. It has a SECOND consumer that has nothing to do with
// the retired gate: `ensurePersistentSourceNATProtocolLocked` refuses to publish
// a persistent-NAT snapshot to a helper too old to understand it
// (MinProtocolPersistentSourceNAT). That is a live fail-closed check, so the
// predicate is load-bearing even with the advisory and the disarm gone.
//
// WHY IT LIVES IN pkg/config. `pkg/dataplane/userspace` imports config, not the
// reverse, so a predicate both planes need has to be here. The tree's older
// habit for this shape was to MIRROR it with a comment saying so; a mirror is a
// drift surface, and the failure mode is one copy silently disagreeing with the
// other.

// UsesPersistentSourceNATPool reports whether any source-NAT rule effectively
// carries persistence — via its pool's `persistent-nat` stanza or a rule-level
// `then source-nat pool P persistent-nat ...` tail (#14626).
//
// Keyed on the RULE, not on the pool table: a pool defined but referenced by no
// rule translates nothing, so it demands nothing of the helper. That is the
// same shape the retired capability gate had, it is what the surviving
// protocol-floor consumer needs, and it is why the loop walks rule-sets rather
// than `SourcePools`.
//
// The file name still says "advisory" for the #8447 breadcrumb; the advisory
// itself is gone (see the header).
func UsesPersistentSourceNATPool(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	for _, rs := range cfg.Security.NAT.Source {
		if rs == nil {
			continue
		}
		for _, rule := range rs.Rules {
			if rule == nil || rule.Then.PoolName == "" {
				continue
			}
			if _, ok := rule.EffectivePersistentNAT(cfg); ok {
				return true
			}
		}
	}
	return false
}

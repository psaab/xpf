package userspace

type FirewallFilterTermCounterKey struct {
	Family     string
	FilterName string
	TermName   string
}

func BuildFirewallFilterTermCounterIndex(status *ProcessStatus) map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus {
	index := make(map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus)
	if status == nil {
		return index
	}
	for _, counter := range status.FilterTermCounters {
		key := FirewallFilterTermCounterKey{
			Family:     counter.Family,
			FilterName: counter.FilterName,
			TermName:   counter.TermName,
		}
		// #15192: a duplicated (family,filter,term) key — two same-named
		// terms in one filter, each with its own runtime counter — must
		// SUM, not last-wins. Every consumer of this index (Prometheus,
		// CLI, gRPC) keys by the same triple, so last-wins silently
		// dropped one term's hits.
		if existing, ok := index[key]; ok {
			counter.Packets += existing.Packets
			counter.Bytes += existing.Bytes
		}
		index[key] = counter
	}
	return index
}

// BuildThreeColorPolicerStatusIndex maps each userspace-published three-color
// policer status by its policer name so a `show firewall` term rendering can
// look up the per-color (green/yellow/red) conform/exceed counters for the
// policer a `then policer <name>` term references. Legacy single-rate `firewall
// policer` definitions are lowered into the same three-color runtime at compile
// (#4514), so both the `firewall policer` and `firewall three-color-policer`
// namespaces surface here keyed by the config name a filter term references.
// Unnamed entries (defensive) are skipped. A nil status yields an empty index,
// mirroring BuildFirewallFilterTermCounterIndex.
func BuildThreeColorPolicerStatusIndex(status *ProcessStatus) map[string]ThreeColorPolicerStatus {
	index := make(map[string]ThreeColorPolicerStatus)
	if status == nil {
		return index
	}
	for _, policer := range status.ThreeColorPolicerCounters {
		if policer.Name == "" {
			continue
		}
		index[policer.Name] = policer
	}
	return index
}

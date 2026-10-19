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

// ThreeColorPolicerStatusKey scopes a userspace-published three-color
// policer status to the exact (family, filter, term, policer) instance
// that produced it (#15680). Junos policers are term-specific by default:
// two terms referencing the same configured policer own independent
// token buckets and counters.
type ThreeColorPolicerStatusKey struct {
	Family     string
	FilterName string
	TermName   string
	Policer    string
}

// BuildThreeColorPolicerStatusIndex maps each userspace-published
// three-color policer status by its (family, filter, term, policer)
// scope so a `show firewall` term rendering shows only that term's own
// per-color counters. Legacy single-rate `firewall policer` definitions
// are lowered into the same three-color runtime at compile (#4514), so
// both namespaces surface here. Rows without a term scope (unreferenced
// definitions, or an older helper that predates the scoped fields) are
// skipped: rendering an aggregate under a specific term would misattribute
// other terms' traffic. A nil status yields an empty index, mirroring
// BuildFirewallFilterTermCounterIndex.
func BuildThreeColorPolicerStatusIndex(status *ProcessStatus) map[ThreeColorPolicerStatusKey]ThreeColorPolicerStatus {
	index := make(map[ThreeColorPolicerStatusKey]ThreeColorPolicerStatus)
	if status == nil {
		return index
	}
	for _, policer := range status.ThreeColorPolicerCounters {
		if policer.Name == "" || policer.Family == "" || policer.FilterName == "" || policer.TermName == "" {
			continue
		}
		key := ThreeColorPolicerStatusKey{
			Family:     policer.Family,
			FilterName: policer.FilterName,
			TermName:   policer.TermName,
			Policer:    policer.Name,
		}
		if existing, ok := index[key]; ok {
			policer.GreenPackets += existing.GreenPackets
			policer.GreenBytes += existing.GreenBytes
			policer.YellowPackets += existing.YellowPackets
			policer.YellowBytes += existing.YellowBytes
			policer.RedPackets += existing.RedPackets
			policer.RedBytes += existing.RedBytes
			policer.DropPackets += existing.DropPackets
			policer.DropBytes += existing.DropBytes
			if policer.ID == 0 || (existing.ID != 0 && existing.ID < policer.ID) {
				policer.ID = existing.ID
			}
		}
		index[key] = policer
	}
	return index
}

// AggregateThreeColorPolicerCountersByName folds the per-term scoped rows
// back into one row per configured policer name for name-scoped consumers
// (Prometheus series, the dataplane status summary) that have no term
// dimension (#15680). Unscoped (unreferenced-definition) rows participate
// under their name. Callers that render sort themselves.
func AggregateThreeColorPolicerCountersByName(status *ProcessStatus) []ThreeColorPolicerStatus {
	if status == nil {
		return nil
	}
	var out []ThreeColorPolicerStatus
	index := make(map[string]int)
	for _, policer := range status.ThreeColorPolicerCounters {
		if policer.Name == "" {
			continue
		}
		i, ok := index[policer.Name]
		if !ok {
			index[policer.Name] = len(out)
			out = append(out, policer)
			continue
		}
		agg := &out[i]
		if agg.ID == 0 || (policer.ID != 0 && policer.ID < agg.ID) {
			agg.ID = policer.ID
		}
		agg.GreenPackets += policer.GreenPackets
		agg.GreenBytes += policer.GreenBytes
		agg.YellowPackets += policer.YellowPackets
		agg.YellowBytes += policer.YellowBytes
		agg.RedPackets += policer.RedPackets
		agg.RedBytes += policer.RedBytes
		agg.DropPackets += policer.DropPackets
		agg.DropBytes += policer.DropBytes
	}
	return out
}

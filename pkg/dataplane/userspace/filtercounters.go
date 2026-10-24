package userspace

import "github.com/psaab/xpf/pkg/config"

type FirewallFilterTermCounterKey struct {
	Family     string
	FilterName string
	TermName   string
}

// CloneCounterFold16464 maps a suppressed-member clone filter name to its
// authored source filter for one family (#16464). Empty when the clone is
// unknown to cfg, so callers keep the clone counters unattributed rather
// than guessing.
type CloneCounterFold16464 map[string]string

// BuildCloneCounterFold16464 derives the clone->source fold for both families
// from cfg, keyed by family then clone name. Built once per render / scrape
// from the same active config the counters are paired with.
func BuildCloneCounterFold16464(cfg *config.Config) map[string]CloneCounterFold16464 {
	out := make(map[string]CloneCounterFold16464)
	if cfg == nil {
		return out
	}
	add := func(family string, filters map[string]*config.FirewallFilter) {
		for name, f := range filters {
			if f == nil {
				continue
			}
			if source, _ := f.SuppressedMemberFBF11321(); source != "" {
				m := out[family]
				if m == nil {
					m = make(CloneCounterFold16464)
					out[family] = m
				}
				m[name] = source
			}
		}
	}
	add("inet", cfg.Firewall.FiltersInet)
	add("inet6", cfg.Firewall.FiltersInet6)
	return out
}

// FoldCloneFilterName16464 returns the operator-visible filter name for a
// helper-published counter row: the authored source when filterName is a
// suppressed-member clone in this family, otherwise filterName unchanged.
func FoldCloneFilterName16464(fold map[string]CloneCounterFold16464, family, filterName string) string {
	if m, ok := fold[family]; ok {
		if source, ok := m[filterName]; ok && source != "" {
			return source
		}
	}
	return filterName
}

// BuildFirewallFilterTermCounterIndex indexes helper counters by
// (family,filter,term), summing duplicates (#15192). Clone rows are NOT
// folded here: this builder has no config, so callers that pair counters
// with an active config must fold first via
// BuildFirewallFilterTermCounterIndexForConfig (#16464).
func BuildFirewallFilterTermCounterIndex(status *ProcessStatus) map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus {
	return buildFilterTermCounterIndex(status, nil)
}

// BuildFirewallFilterTermCounterIndexForConfig is
// BuildFirewallFilterTermCounterIndex with each suppressed-member clone
// row folded into its authored source filter (same family, same term
// name; the clone carries identical term names/order) before summing, so
// member-unit hits are not lost when readers skip clones (#16464).
func BuildFirewallFilterTermCounterIndexForConfig(status *ProcessStatus, cfg *config.Config) map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus {
	if cfg == nil {
		return BuildFirewallFilterTermCounterIndex(status)
	}
	return buildFilterTermCounterIndex(status, BuildCloneCounterFold16464(cfg))
}

func buildFilterTermCounterIndex(status *ProcessStatus, fold map[string]CloneCounterFold16464) map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus {
	index := make(map[FirewallFilterTermCounterKey]FirewallFilterTermCounterStatus)
	if status == nil {
		return index
	}
	for _, counter := range status.FilterTermCounters {
		counter.FilterName = FoldCloneFilterName16464(fold, counter.Family, counter.FilterName)
		key := FirewallFilterTermCounterKey{
			Family:     counter.Family,
			FilterName: counter.FilterName,
			TermName:   counter.TermName,
		}
		// #15192: a duplicated (family,filter,term) key must SUM, not
		// last-wins. Folding a clone into its source deliberately
		// creates such a duplicate (authored + member hits).
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
	return buildThreeColorPolicerStatusIndex(status, nil)
}

// BuildThreeColorPolicerStatusIndexForConfig is
// BuildThreeColorPolicerStatusIndex with suppressed-member clone rows
// folded into their authored source filter before summing (#16464), so a
// policer term rendered under the source also shows member-unit policer
// counters instead of dropping them with the hidden clone.
func BuildThreeColorPolicerStatusIndexForConfig(status *ProcessStatus, cfg *config.Config) map[ThreeColorPolicerStatusKey]ThreeColorPolicerStatus {
	if cfg == nil {
		return BuildThreeColorPolicerStatusIndex(status)
	}
	return buildThreeColorPolicerStatusIndex(status, BuildCloneCounterFold16464(cfg))
}

func buildThreeColorPolicerStatusIndex(status *ProcessStatus, fold map[string]CloneCounterFold16464) map[ThreeColorPolicerStatusKey]ThreeColorPolicerStatus {
	index := make(map[ThreeColorPolicerStatusKey]ThreeColorPolicerStatus)
	if status == nil {
		return index
	}
	for _, policer := range status.ThreeColorPolicerCounters {
		if policer.Name == "" || policer.Family == "" || policer.FilterName == "" || policer.TermName == "" {
			continue
		}
		policer.FilterName = FoldCloneFilterName16464(fold, policer.Family, policer.FilterName)
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

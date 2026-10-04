package config

import "sort"

// StaticRouteNextHopTier groups next-hops at one effective preference and
// metric. Equal groups remain ECMP; the ordered list of groups is failover.
type StaticRouteNextHopTier struct {
	Preference     int
	Metric         int
	ManagementPrio int
	NextHops       []NextHopEntry
}

// StaticRouteNextHopTiers returns next-hops grouped and ordered by effective
// preference, then qualified-next-hop metric. An absent or out-of-range metric
// is treated as zero, matching the metric available to the static install
// consumers; equal preference/metric paths remain in one ECMP group.
//
// ManagementPrio is a monotone encoding for Linux's single RTA_PRIORITY field,
// which cannot carry preference and metric separately. Other consumers must
// keep Preference and Metric separate rather than use this synthetic value.
func StaticRouteNextHopTiers(route *StaticRoute) []StaticRouteNextHopTier {
	if route == nil || len(route.NextHops) == 0 {
		return nil
	}
	type key struct {
		preference int
		metric     int
	}
	groups := make(map[key][]NextHopEntry, len(route.NextHops))
	for _, nextHop := range route.NextHops {
		preference := route.Preference
		if nextHop.HasPreference {
			preference = nextHop.Preference
		}
		metric := 0
		if nextHop.HasMetric && nextHop.Metric >= 0 && uint64(nextHop.Metric) <= uint64(^uint32(0)) {
			metric = nextHop.Metric
		}
		k := key{preference: preference, metric: metric}
		groups[k] = append(groups[k], nextHop)
	}

	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].preference != keys[j].preference {
			return keys[i].preference < keys[j].preference
		}
		return keys[i].metric < keys[j].metric
	})

	tiers := make([]StaticRouteNextHopTier, 0, len(keys))
	lastManagementPrio := int64(-1)
	for _, k := range keys {
		managementPrio := int64(k.preference)
		if managementPrio <= lastManagementPrio {
			managementPrio = lastManagementPrio + 1
		}
		tiers = append(tiers, StaticRouteNextHopTier{
			Preference:     k.preference,
			Metric:         k.metric,
			ManagementPrio: int(managementPrio),
			NextHops:       groups[k],
		})
		lastManagementPrio = managementPrio
	}

	// Kernel route priority is u32. Keep ordered tiers distinct near the ceiling
	// by shifting the single route's encoded priorities down together.
	const maxManagementPrio = int64(^uint32(0))
	if lastManagementPrio > maxManagementPrio {
		shift := lastManagementPrio - maxManagementPrio
		for i := range tiers {
			priority := int64(tiers[i].ManagementPrio) - shift
			if priority < 0 {
				priority = 0
			}
			tiers[i].ManagementPrio = int(priority)
		}
	}
	return tiers
}

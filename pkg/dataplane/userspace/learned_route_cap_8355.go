package userspace

import (
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/psaab/xpf/pkg/routing"
)

// #8355 acceptance items 2 and 3: the learned-route cap, what it does when it
// binds, and why it does that rather than the alternative.
//
// THE MEASUREMENT THIS RESTS ON (#8554, and it moved the premise). A learned
// route serializes to ~113 bytes, stable to within 1.5% from one route to
// 500,000 — which is what makes a route COUNT derivable from a byte budget at
// all. 500k routes come to ~56 MiB, comfortably under the 64 MiB
// `MaxControlRequestBytes` ceiling, so the size cap admits ~595,000 routes and
// is NOT what stops this.
//
// What stops it is TIME. `controlRoundtripDeadline` grants
// `controlBaseDeadline + controlDeadlinePerMiB` per mebibyte, so a 56 MiB
// publish holds the control socket for 56 seconds — on a socket CLAUDE.md
// already describes as shared by the 1/s status poll, HA sync, session
// installs, snapshot sync and forwarding sync, where "a new control socket
// request at >1/s will starve session installs during bulk sync". A
// minute-long publish does not starve that socket at the margin; it owns it.
//
// THE CAP IS DERIVED, NOT PICKED. `learnedRoutePublishBudget` is the policy
// input — how long one publish may hold the socket — and the route count falls
// out of it through the SAME constants the deadline uses. A hardcoded route
// count would be a number wearing the shape of a budget, which is the failure
// this issue was filed about; deriving it means that if the deadline formula
// or the per-route cost changes, the cap moves with them instead of silently
// becoming wrong.
const (
	// learnedRoutePublishBudget is the tolerance: how long a single snapshot
	// publish may hold the control socket.
	//
	// 10s. Above that is hard to justify against a 1/s status poll — ten
	// polls' worth of head-of-line blocking — and #7437 makes publishes more
	// frequent, which is the interaction that turns a slow publish into a
	// persistent one. Below it, the cap starts excluding table sizes a real
	// eBGP edge carries.
	learnedRoutePublishBudget = 10 * time.Second

	// learnedRouteBytesEach is the measured per-route serialized cost, from
	// the #8554 measurement. Pinned by
	// TestLearnedRoutePublishSizeAndDeadline8355, so this constant cannot
	// drift away from what the wire actually costs without that cell saying
	// so.
	//
	// It is a FLOOR: the measurement uses one next-hop per route, and ECMP
	// multiplies the next-hop array. A table with ECMP hits the budget at
	// fewer routes than the cap admits, which is the safe direction for a
	// bound to be wrong in.
	learnedRouteBytesEach = 113

	bytesPerMiB = 1 << 20
)

// maxLearnedRoutes is the route count whose publish fits inside
// learnedRoutePublishBudget, derived through the deadline formula.
//
// deadline(bytes) = controlBaseDeadline + bytes/MiB * controlDeadlinePerMiB,
// so the admissible byte count is (budget - base) / perMiB mebibytes, and the
// route count is that divided by the per-route cost.
func maxLearnedRoutes() int {
	spare := learnedRoutePublishBudget - controlBaseDeadline
	if spare <= 0 {
		return 0
	}
	mib := float64(spare) / float64(controlDeadlinePerMiB)
	return int(mib * bytesPerMiB / learnedRouteBytesEach)
}

// learnedRouteCapHits counts snapshot builds that shed at least one learned
// route group. Exposed so the condition is visible to something other than the log.
var learnedRouteCapHits atomic.Uint64

// LearnedRouteCapHits reports how many snapshot builds exceeded the
// learned-route publish budget and shed one or more protocol/table groups.
func LearnedRouteCapHits() uint64 { return learnedRouteCapHits.Load() }

// learnedRouteCapProtocolHits records cap-triggered protocol/table groups.
// Known protocols start at zero so the metric emits stable series.
var learnedRouteCapProtocolHits = struct {
	sync.Mutex
	counts map[string]uint64
}{
	counts: map[string]uint64{
		"bgp":       0,
		"connected": 0,
		"dhcp":      0,
		"isis":      0,
		"ospf":      0,
		"rip":       0,
		"static":    0,
	},
}

// LearnedRouteCapHitsByProtocol reports cap-triggered group sheds by the
// kernel protocol name. The returned map is a snapshot and may be modified.
func LearnedRouteCapHitsByProtocol() map[string]uint64 {
	learnedRouteCapProtocolHits.Lock()
	defer learnedRouteCapProtocolHits.Unlock()
	out := make(map[string]uint64, len(learnedRouteCapProtocolHits.counts))
	for protocol, count := range learnedRouteCapProtocolHits.counts {
		out[protocol] = count
	}
	return out
}

func noteLearnedRouteCapProtocolHit(protocol string) {
	if protocol == "" {
		protocol = "unknown"
	}
	learnedRouteCapProtocolHits.Lock()
	learnedRouteCapProtocolHits.counts[protocol]++
	learnedRouteCapProtocolHits.Unlock()
}

type learnedRouteQuotaKey struct {
	tableID  int
	protocol string
}

// capLearnedRouteGroups sheds whole (table, protocol) groups rather than
// refusing every learned route when the combined kernel dump exceeds the
// publish budget. Oversized groups are shed first. BGP groups are then shed
// before other protocols; remaining groups are shed largest-first until the
// combined set fits. A BGP flood cannot remove unrelated routes, and no group
// is partially imported.
func capLearnedRouteGroups(routes []routing.LearnedRoute) ([]routing.LearnedRoute, bool) {
	limit := maxLearnedRoutes()
	if limit <= 0 || len(routes) <= limit {
		return routes, false
	}

	counts := make(map[learnedRouteQuotaKey]int)
	keys := make([]learnedRouteQuotaKey, 0)
	for _, route := range routes {
		key := learnedRouteQuotaKey{tableID: route.TableID, protocol: route.Protocol}
		if _, exists := counts[key]; !exists {
			keys = append(keys, key)
		}
		counts[key]++
	}

	dropped := make(map[learnedRouteQuotaKey]struct{})
	remaining := len(routes)
	for _, key := range keys {
		if counts[key] > limit {
			dropped[key] = struct{}{}
			remaining -= counts[key]
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		isBGPi, isBGPj := keys[i].protocol == "bgp", keys[j].protocol == "bgp"
		if isBGPi != isBGPj {
			return isBGPi
		}
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		if keys[i].protocol != keys[j].protocol {
			return keys[i].protocol < keys[j].protocol
		}
		return keys[i].tableID < keys[j].tableID
	})
	for _, key := range keys {
		if remaining <= limit {
			break
		}
		if _, alreadyDropped := dropped[key]; alreadyDropped {
			continue
		}
		dropped[key] = struct{}{}
		remaining -= counts[key]
	}

	if len(dropped) == 0 {
		return routes, false
	}
	if !learnedRouteCapExceeded(len(routes)) {
		return routes, false
	}
	for _, key := range keys {
		if _, shed := dropped[key]; !shed {
			continue
		}
		protocol := key.protocol
		if protocol == "" {
			protocol = "unknown"
		}
		noteLearnedRouteCapProtocolHit(protocol)
		slog.Warn("learned-route protocol/table group shed to keep the snapshot within its publish budget",
			"table_id", key.tableID,
			"protocol", protocol,
			"learned_routes", counts[key],
			"cap", limit,
			"publish_budget", learnedRoutePublishBudget.String(),
		)
	}
	kept := routes[:0]
	for _, route := range routes {
		key := learnedRouteQuotaKey{tableID: route.TableID, protocol: route.Protocol}
		if _, shed := dropped[key]; !shed {
			kept = append(kept, route)
		}
	}
	return kept, true
}

// learnedRouteCapExceeded records a build that exceeded the combined
// publish budget. capLearnedRouteGroups decides which complete protocol/table
// groups to shed; this predicate records the build-level counter and diagnostic.
//
// #9522 owns the disposition above the cap. Capped NoRoute frames are
// adjudicated against the configured policy, and denied results are dropped as
// PolicyDenied. The cap does not delegate NoRoute to the kernel.
//
// Whole-group shedding avoids selecting an arbitrary route prefix by emission
// sort order. Each cap hit records the affected protocol separately, while
// unrelated groups remain eligible for the helper FIB.
func learnedRouteCapExceeded(count int) bool {
	limit := maxLearnedRoutes()
	if limit <= 0 || count <= limit {
		return false
	}
	learnedRouteCapHits.Add(1)
	slog.Warn("learned-route publish budget exceeded — complete protocol/table groups are being shed",
		"learned_routes", count,
		"cap", limit,
		"publish_budget", learnedRoutePublishBudget.String(),
		"bytes_per_route", learnedRouteBytesEach,
		"consequence", "only complete (table, protocol) groups are omitted; remaining groups stay imported. Missing-group NoRoute frames are ADJUDICATED and DROPPED as policy denials on a deny-default box; xpf_policy_denies_total counts them and xpf_learned_route_import_capped reports the capped state. On a helper older than snapshot protocol 27 the snapshot is REFUSED outright rather than applied (#9522)",
		"security_note", "the capped state does not delegate NoRoute to the kernel: the #7480 policy adjudication applies above and below the cap, and only a PolicyAction::Permit result keeps normal slow-path delegation",
		"why_not_partial", "a whole (table, protocol) group is shed, never a prefix chosen by route sort order",
		"remedy", "reduce the imported table (filter what FRR installs into the kernel), or raise the publish budget if holding the control socket that long is acceptable",
		"observability", "xpf_learned_route_cap_hits_total counts capped builds; xpf_learned_route_cap_group_sheds_total counts group sheds by protocol; LearnedRouteCapHitsByProtocol exposes those counts to Go callers; xpf_learned_route_import_capped reports the live capped state; xpf_policy_denies_total advances for denied capped NoRoute frames",
	)
	return true
}

package dataplane

import (
	"errors"
	"sort"
)

// GlobalCounterReader is the minimal read surface ReadGlobalCounters needs.
// Every dataplane runtime (Manager, LegacyDataPlaneAdapter, daemon
// liveDataPlane, and the per-package test doubles) already satisfies it via
// its existing ReadGlobalCounter method.
type GlobalCounterReader interface {
	ReadGlobalCounter(idx uint32) (uint64, error)
}

// GlobalCounterSnapshot is the single classified result of reading a set of
// global counters (#17193). Values holds only counters that read cleanly;
// Unavailable holds the canonical names (GlobalCounterName) of counters the
// dataplane explicitly does not populate (ErrCounterNotPopulated, #13274);
// Err is the first genuine read failure, if any. Unavailable is NOT an error:
// "counter unavailable != zero" (#3345) and "known-unsourced != read failure"
// (#13274) are the same distinction on every surface.
type GlobalCounterSnapshot struct {
	Values      map[uint32]uint64
	Unavailable []uint32
	Err         error
}

// Value returns the read value for idx and whether it is available. An
// unavailable or failed counter reports ok=false, never a fabricated 0.
func (s GlobalCounterSnapshot) Value(idx uint32) (uint64, bool) {
	v, ok := s.Values[idx]
	return v, ok
}

// IsUnavailable reports whether idx was classified unavailable.
func (s GlobalCounterSnapshot) IsUnavailable(idx uint32) bool {
	for _, u := range s.Unavailable {
		if u == idx {
			return true
		}
	}
	return false
}

// UnavailableNames returns the canonical names of the unavailable counters,
// in the order the indexes were requested.
func (s GlobalCounterSnapshot) UnavailableNames() []string {
	if len(s.Unavailable) == 0 {
		return nil
	}
	names := make([]string, 0, len(s.Unavailable))
	for _, idx := range s.Unavailable {
		names = append(names, GlobalCounterName(idx))
	}
	return names
}

// globalCounterNames is the canonical operator/API name for every global
// counter index that any surface renders by name. It is the single source
// for the `unavailable_counters` strings REST (#13274) and gRPC (#17193)
// emit, so the two structured surfaces cannot drift.
var globalCounterNames = map[uint32]string{
	GlobalCtrRxPackets:             "rx_packets",
	GlobalCtrTxPackets:             "tx_packets",
	GlobalCtrDrops:                 "drops",
	GlobalCtrSessionsNew:           "sessions_created",
	GlobalCtrSessionsClosed:        "sessions_closed",
	GlobalCtrScreenDrops:           "screen_drops",
	GlobalCtrPolicyDeny:            "policy_denies",
	GlobalCtrNATAllocFail:          "nat_alloc_failures",
	GlobalCtrHostInboundDeny:       "host_inbound_denies",
	GlobalCtrTCEgressPackets:       "tc_egress_packets",
	GlobalCtrNAT64Xlate:            "nat64_translations",
	GlobalCtrHostInbound:           "host_inbound_allowed",
	GlobalCtrFabricRedirect:        "fabric_redirects",
	GlobalCtrFabricFwdDrop:         "fabric_forward_drops",
	GlobalCtrFabricRedirectFab0:    "fabric_redirects_fab0",
	GlobalCtrFabricRedirectFab1:    "fabric_redirects_fab1",
	GlobalCtrFabricRedirectZone:    "fabric_redirects_zone",
	GlobalCtrFlowCacheHit:          "flow_cache_hits",
	GlobalCtrFlowCacheMiss:         "flow_cache_misses",
	GlobalCtrFlowCacheFlush:        "flow_cache_flushes",
	GlobalCtrFlowCacheInvalidate:   "flow_cache_invalidations",
	GlobalCtrUnknownVLANDrops:      "unknown_vlan_drops",
	GlobalCtrDstMACDrops:           "dst_mac_drops",
	GlobalCtrSyncookieSent:         "syncookie_sent",
	GlobalCtrSyncookieValid:        "syncookie_valid",
	GlobalCtrSyncookieInvalid:      "syncookie_invalid",
	GlobalCtrSyncookieBypass:       "syncookie_bypass",
	GlobalCtrSyncookieActiveBudget: "syncookie_active_budget",
}

// GlobalCounterName returns the canonical name for a global counter index.
// Indexes without a named surface fall back to their screen-reason key when
// they are screen counters, and to "" otherwise.
func GlobalCounterName(idx uint32) string {
	if name, ok := globalCounterNames[idx]; ok {
		return name
	}
	for i := range ScreenReasonCounters {
		if ScreenReasonCounters[i].Index == idx {
			return ScreenReasonCounters[i].Reason
		}
	}
	return ""
}

// ReadGlobalCounters reads each requested global counter index exactly once
// through r and classifies every result once (#17193):
//
//   - success: recorded in Values;
//   - ErrCounterNotPopulated (#13274 known-unsourced): recorded in
//     Unavailable, never in Values, never in Err;
//   - any other error: the first such error is recorded in Err (subsequent
//     genuine failures do not replace it, matching the historic first-error
//     closures) and the counter is recorded in neither map.
//
// Duplicate indexes are read once. Unavailable preserves request order.
// This is the ONLY classification site: REST, Prometheus, gRPC, and both CLI
// families must consume the snapshot instead of re-implementing the
// sentinel check per surface (the six-copy drift that left gRPC returning
// codes.Internal and the text surfaces printing a fabricated 0).
func ReadGlobalCounters(r GlobalCounterReader, indexes ...uint32) GlobalCounterSnapshot {
	snap := GlobalCounterSnapshot{Values: make(map[uint32]uint64, len(indexes))}
	seen := make(map[uint32]bool, len(indexes))
	for _, idx := range indexes {
		if seen[idx] {
			continue
		}
		seen[idx] = true
		v, err := r.ReadGlobalCounter(idx)
		switch {
		case err == nil:
			snap.Values[idx] = v
		case errors.Is(err, ErrCounterNotPopulated):
			snap.Unavailable = append(snap.Unavailable, idx)
		default:
			if snap.Err == nil {
				snap.Err = err
			}
		}
	}
	return snap
}

// AllGlobalCounterIndexes returns every global counter index in ascending
// order: the dense 0..GlobalCtrMax-1 range every surface that renders the
// full counter set iterates.
func AllGlobalCounterIndexes() []uint32 {
	indexes := make([]uint32, 0, GlobalCtrMax)
	for idx := uint32(0); idx < GlobalCtrMax; idx++ {
		indexes = append(indexes, idx)
	}
	return indexes
}

// SortedUnavailableNames is UnavailableNames sorted, for surfaces that emit
// a deterministic list regardless of read order.
func (s GlobalCounterSnapshot) SortedUnavailableNames() []string {
	names := s.UnavailableNames()
	sort.Strings(names)
	return names
}

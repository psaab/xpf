package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/nat"
	"github.com/psaab/xpf/pkg/natshow"
)

// runtimeSourceNATPools returns the userspace helper's live source-NAT pool
// status, deduplicated by pool name. Rules sharing a pool reference the same
// Arc<PortAllocatorShared> and report identical occupancy, so a single entry
// per pool is kept (never summed) — matching the AppliedNATView dedup contract
// in pkg/dataplane/userspace/applied_nat_view.go.
//
// This is the SSOT for in-use / capacity under the AF_XDP userspace dataplane
// (#2938): the helper publishes the authoritative AddressCount / PortLow /
// PortHigh / UsedPorts (it rejects malformed addresses, splits pools by IP
// family, and shares allocator state across rules), which config text and the
// retired-eBPF port counter cannot. Returns nil when the helper is not running
// or does not expose a runtime status — callers then fall back to the
// config-derived view.
//
// Returns (nil, nil) when the helper is not running or does not expose a
// runtime status — callers then fall back to the config-derived view. But a
// Status() READ FAILURE returns a non-nil error: a telemetry-bridge failure is
// NOT "no pools in use", and the caller must surface it as unavailable rather
// than silently defaulting to a healthy zero-usage view (#5046, #3345
// counter-error contract).
func (s *Server) runtimeSourceNATPools() (map[string]dpuserspace.SourceNATPoolStatus, error) {
	if s.dp == nil || !s.dp.IsLoaded() {
		return nil, nil
	}
	provider, ok := s.dpProbe().(interface {
		Status() (dpuserspace.ProcessStatus, error)
	})
	if !ok {
		return nil, nil
	}
	status, err := provider.Status()
	if err != nil {
		return nil, err
	}
	// #8606: single-sourced. The dedup contract (one entry per pool name,
	// never summed -- rules sharing a pool share one allocator and report
	// identical UsedPorts) now lives with the type, so the four surfaces that
	// report occupancy cannot drift apart on it.
	return dpuserspace.SourceNATPoolOccupancy(status), nil
}

// appliedNATView projects the userspace manager's last-applied NAT snapshot
// into a nat.AppliedView for the deterministic-mapping lookup. Reads only
// cached in-memory state; returns an unavailable view when the dataplane is
// not the userspace manager, is not running, or has applied nothing (#5794).
func (s *Server) appliedNATView() nat.AppliedView {
	if s.dp == nil {
		return nat.AppliedView{Available: false}
	}
	provider, ok := s.dpProbe().(interface {
		AppliedNATView() dpuserspace.AppliedNATView
	})
	if !ok {
		return nat.AppliedView{Available: false}
	}
	v := provider.AppliedNATView()
	if !v.Available || v.Config == nil {
		return nat.AppliedView{Available: false}
	}
	return nat.AppliedView{Config: v.Config, Generation: v.AppliedGeneration, Available: true}
}

// natDeterministicHandler resolves a deterministic source-NAT mapping
// (#5794). Forward:  GET .../deterministic?internal-host=<ip>[&pool=<name>].
// Reverse:  GET .../deterministic?nat-ip=<ip>&nat-port=<n>[&pool=<name>].
// Every outcome (including a lookup failure) is returned as a 200 typed
// NATDeterministicInfo body so the REST answer is identical to the gRPC and
// CLI answer; the stable ErrorCode drives machine consumers.
func (s *Server) natDeterministicHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pool := q.Get("pool")
	internal := q.Get("internal-host")
	natIP := q.Get("nat-ip")
	natPortStr := q.Get("nat-port")
	view := s.appliedNATView()

	switch {
	case internal != "":
		res, lerr := nat.LookupForward(view, pool, internal)
		if lerr != nil {
			writeOK(w, natDeterministicErrInfo("forward", lerr))
			return
		}
		writeOK(w, natForwardInfo(res))
	case natIP != "":
		port, err := strconv.Atoi(natPortStr)
		if err != nil || port < 1 || port > 65535 {
			writeOK(w, NATDeterministicInfo{
				Found:       false,
				Direction:   "reverse",
				ErrorCode:   nat.ErrCodeMalformedInput,
				ErrorDetail: "nat-port must be 1-65535",
			})
			return
		}
		res, lerr := nat.LookupReverse(view, pool, natIP, uint16(port))
		if lerr != nil {
			writeOK(w, natDeterministicErrInfo("reverse", lerr))
			return
		}
		writeOK(w, natReverseInfo(res))
	default:
		writeOK(w, NATDeterministicInfo{
			Found:       false,
			ErrorCode:   nat.ErrCodeMalformedInput,
			ErrorDetail: "specify internal-host=<ip> (forward) or nat-ip=<ip>&nat-port=<n> (reverse)",
		})
	}
}

func natForwardInfo(r *nat.ForwardResult) NATDeterministicInfo {
	return NATDeterministicInfo{
		Found:             true,
		Direction:         "forward",
		Pool:              r.Pool,
		Mode:              uint8(r.Mode),
		InternalHost:      r.InternalHost,
		ExternalIP:        r.ExternalIP,
		PortLow:           r.PortLow,
		PortHigh:          r.PortHigh,
		BlockSize:         r.BlockSize,
		BlockIndex:        r.BlockIndex,
		AppliedGeneration: r.AppliedGeneration,
	}
}

func natReverseInfo(r *nat.ReverseResult) NATDeterministicInfo {
	return NATDeterministicInfo{
		Found:             true,
		Direction:         "reverse",
		Pool:              r.Pool,
		Mode:              uint8(r.Mode),
		InternalHost:      r.InternalHost,
		InternalPrefixLen: r.InternalPrefixLen,
		ExternalIP:        r.ExternalIP,
		NATPort:           r.NATPort,
		PortLow:           r.PortLow,
		PortHigh:          r.PortHigh,
		BlockSize:         r.BlockSize,
		BlockIndex:        r.BlockIndex,
		AppliedGeneration: r.AppliedGeneration,
	}
}

func natDeterministicErrInfo(direction string, lerr *nat.LookupError) NATDeterministicInfo {
	return NATDeterministicInfo{
		Found:       false,
		Direction:   direction,
		ErrorCode:   lerr.Code,
		ErrorDetail: lerr.Detail,
	}
}

func (s *Server) natSourceHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATSourceInfo{})
		return
	}

	var result []NATSourceInfo
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			info := NATSourceInfo{
				FromZone: rs.FromZone,
				ToZone:   rs.ToZone,
			}
			if rule.Then.Interface {
				info.Type = "interface"
			} else if rule.Then.PoolName != "" {
				info.Type = "pool"
				info.Pool = rule.Then.PoolName
			}
			// #7473: carry the builder's verdict. Without it this object says
			// "type: pool, pool: p1" for a rule that translates nothing.
			if reason := config.SourceNATRuleNotInstalledReason(cfg, rule); reason != "" {
				info.NotInstalled = true
				info.NotInstalledReason = config.SourceNATDisarmReasonText(reason)
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) natDestHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil || cfg.Security.NAT.Destination == nil {
		writeOK(w, []NATDestInfo{})
		return
	}

	var result []NATDestInfo
	for _, rs := range cfg.Security.NAT.Destination.RuleSets {
		for _, rule := range rs.Rules {
			info := NATDestInfo{
				Name:    rule.Name,
				DstAddr: rule.Match.DestinationAddress,
			}
			if rule.Match.DestinationPort > 0 {
				info.DstPort = uint16(rule.Match.DestinationPort)
			}
			if pool, ok := cfg.Security.NAT.Destination.Pools[rule.Then.PoolName]; ok {
				info.TranslateIP = pool.Address
				if pool.Port > 0 {
					info.TranslatePort = uint16(pool.Port)
				}
			}
			// #7473: the destination predicate returns operator prose already,
			// so it is carried verbatim rather than expanded like the source
			// token.
			if reason := config.DestinationNATRuleNotInstalledReason(cfg, rule); reason != "" {
				info.NotInstalled = true
				info.NotInstalledReason = reason
			}
			result = append(result, info)
		}
	}
	writeOK(w, result)
}

func (s *Server) natPoolStatsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATPoolStatsInfo{})
		return
	}

	var result []NATPoolStatsInfo
	var cr *dataplane.ApplyResult
	if s.dp != nil && s.dp.IsLoaded() {
		cr = s.applyResult()
	}

	// #2938: in-use / capacity must come from the userspace helper's live
	// runtime status, not config text + the retired-eBPF port counter. The
	// helper rejects malformed addresses, splits pools by IP family, reports
	// actual used ports, and shares allocator state across rules — config text
	// can over-report capacity and the legacy ReadNATPortCounter is dead under
	// the AF_XDP dataplane. runtime[name] is the SSOT when present.
	//
	// A runtime status READ FAILURE must fail closed as unavailable (HTTP 500),
	// not fall through to a config-derived zero-usage view that reads as
	// "healthy idle" (#5046, #3345 counter-error contract).
	runtime, err := s.runtimeSourceNATPools()
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"NAT pool runtime status read failed: "+err.Error())
		return
	}

	// Named pools
	overBudgetPools := config.SourceNATAggregateOverBudgetPools(cfg)
	for name, pool := range cfg.Security.NAT.SourcePools {
		// Config-derived fallback for capacity (used only when the helper has
		// no runtime entry for this pool — e.g. before the first apply lands).
		portLow, portHigh := pool.PortLow, pool.PortHigh
		if portLow == 0 {
			portLow = 1024
		}
		if portHigh == 0 {
			portHigh = 65535
		}
		// #7000: the CONFIG-derived fallback (used when the helper has no
		// runtime entry, or reports 0) now comes from the compiler's verdict.
		// `len(pool.Addresses)` reported capacity for a pool the dataplane
		// REFUSED — and because the `rp.AddressCount > 0` guard below PRESERVES
		// this value when the runtime says 0, a refused pool's fabricated count
		// survived even once the helper was running and had told us it installed
		// nothing. It also under-reported every prefix member and missed the
		// singular `address` field.
		addrCount, poolDisarm := config.SourceNATPoolReportableAddresses(pool, name, overBudgetPools)
		used := 0
		usedKnown := false

		if rp, ok := runtime[name]; ok {
			// Runtime SSOT: the helper's applied address count, port window,
			// and live used-port occupancy.
			if rp.AddressCount > 0 {
				addrCount = rp.AddressCount
			}
			if rp.PortLow != 0 {
				portLow = int(rp.PortLow)
			}
			if rp.PortHigh != 0 {
				portHigh = int(rp.PortHigh)
			}
			used = int(rp.UsedPorts)
			usedKnown = true
		}
		// #8606: there is deliberately NO legacy-counter fallback here any
		// more. It existed so the surface would not be blank when the helper
		// had no entry, but `nat_port_counters` is seeded with `rand.Uint64()`
		// and has had no writer since #1476 deleted the eBPF pipeline, so the
		// fallback filled the blank with a RANDOM number. A fallback is worth
		// having only when its value is true; this one reported noise as a
		// measurement, which is strictly worse than reporting nothing.

		// #6553: one shared formula across all four surfaces (this guard used
		// to exist only here).
		totalPorts := int(config.NATPoolTotalPorts(portLow, portHigh, addrCount))

		avail := totalPorts - used
		if avail < 0 {
			avail = 0
		}
		// #8606: "unknown" is a third state. With the legacy random-seed
		// fallback gone, a pool the helper is not reporting has NO occupancy
		// measurement, and rendering "0 used / 0.0%" would be a fabricated
		// healthy reading -- the same fake zero #7473 removed elsewhere on
		// this object. `used_ports_known` false marks it; the numeric fields
		// stay zero-valued so existing consumers keep their shape.
		// #9995: `port no-translation` preserves the source port and its
		// PortLow/PortHigh fields are irrelevant. The helper's structurally
		// zero UsedPorts is not a port-utilization measurement, so gate all
		// port-capacity/usage fields instead of reporting a healthy-looking
		// full-availability and 0.0% view.
		util := "unknown"
		if pool.PortNoTranslation && poolDisarm == "" {
			totalPorts = 0
			used = 0
			usedKnown = false
			avail = 0
			util = "NOT APPLICABLE"
		} else if usedKnown {
			util = "0.0%"
			if totalPorts > 0 {
				util = fmt.Sprintf("%.1f%%", float64(used)/float64(totalPorts)*100)
			}
		}
		// #7473: the reason was already computed above for the capacity
		// fallback and discarded; binding it carries the builder's verdict onto
		// the object instead of leaving a consumer to infer it from a zero
		// capacity, which is ambiguous (no members, malformed member, and the
		// aggregate budget all produce 0 and have different remedies).
		info := NATPoolStatsInfo{
			Name:           name,
			Address:        strings.Join(pool.Addresses, ","),
			TotalPorts:     totalPorts,
			UsedPorts:      used,
			UsedPortsKnown: usedKnown,
			AvailablePorts: avail,
			Utilization:    util,
		}
		if poolDisarm != "" {
			info.NotInstalled = true
			info.NotInstalledReason = config.SourceNATDisarmReasonText(poolDisarm)
		}
		result = append(result, info)
	}

	// Interface-mode pools. Count forward SNAT sessions ONCE, keyed by the
	// ingress/egress zone pair, so each interface-mode rule set reports only
	// the sessions that traversed its own from/to zone — not the firewall-wide
	// SNAT total attributed to every row (#3417). A partial scan under-counts
	// interface-mode NAT usage; fail rather than report a healthy-but-low
	// figure (#2469).
	hasInterfaceRule := false
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				hasInterfaceRule = true
			}
		}
	}
	ruleSetUsed := map[[2]string]int{}
	if hasInterfaceRule && s.dp != nil && s.dp.IsLoaded() {
		// #6216: this full-table session walk must draw from the shared
		// sessionWalkLimiter (#5708/#5433) like every other REST scan
		// endpoint, so a burst of NAT-pool-stats requests cannot each drive
		// an unbounded IterateSessions concurrently and starve session
		// installs / the periodic sweep on the shared control socket. Acquire
		// once at this external trust boundary and honor the returned
		// admission-lease context for early cancellation on client disconnect.
		release, walkCtx, err := sessionWalkLimiter.AcquireCtx(r.Context())
		if err != nil {
			writeError(w, http.StatusTooManyRequests,
				"nat pool stats concurrency limit reached; retry shortly")
			return
		}
		defer release()

		// Map zone ID -> name so the per-session ingress/egress zone IDs can
		// be attributed to the configured from/to zone pair. Without the zone
		// map (no apply result yet) attribution is impossible, so rows report
		// 0 rather than a wrong aggregate.
		var zoneByID map[uint16]string
		if cr != nil {
			zoneByID = make(map[uint16]string, len(cr.ZoneIDs))
			for name, id := range cr.ZoneIDs {
				zoneByID[id] = name
			}
		}
		if err := s.dp.IterateSessions(func(_ dataplane.SessionKey, val dataplane.SessionValue) bool {
			if walkCtx.Err() != nil {
				return false // client gone / lease cancelled — stop the walk
			}
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 && zoneByID != nil {
				ruleSetUsed[[2]string{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions: "+err.Error())
			return
		}
		// #5328 (A8-b1-F6): interface-mode SNAT usage must count IPv6 sessions
		// too. The v4 walk above alone systematically under-reports usage on a
		// dual-stack firewall — the gRPC/CLI NAT helpers count both families, so
		// a REST-only v4 tally is a silent parity gap. Reuse the SAME admission
		// lease/context acquired above (no second AcquireCtx) and the same zone
		// map; the v6 session value carries identical IsReverse/Flags/zone fields.
		if err := s.dp.IterateSessionsV6(func(_ dataplane.SessionKeyV6, val dataplane.SessionValueV6) bool {
			if walkCtx.Err() != nil {
				return false // client gone / lease cancelled — stop the walk
			}
			if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 && zoneByID != nil {
				ruleSetUsed[[2]string{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
			}
			return true
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "iterate sessions v6: "+err.Error())
			return
		}
	}
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.Interface {
				result = append(result, NATPoolStatsInfo{
					Name:        fmt.Sprintf("%s->%s", rs.FromZone, rs.ToZone),
					Address:     "interface",
					UsedPorts:   ruleSetUsed[[2]string{rs.FromZone, rs.ToZone}],
					IsInterface: true,
				})
			}
		}
	}

	if result == nil {
		result = []NATPoolStatsInfo{}
	}
	writeOK(w, result)
}

func (s *Server) natRuleStatsHandler(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []NATRuleStatsInfo{})
		return
	}

	ruleSetFilter := r.URL.Query().Get("rule_set")
	var result []NATRuleStatsInfo
	var cr *dataplane.ApplyResult
	if s.dp != nil && s.dp.IsLoaded() {
		cr = s.applyResult()
	}

	for _, rs := range cfg.Security.NAT.Source {
		if ruleSetFilter != "" && rs.Name != ruleSetFilter {
			continue
		}
		for _, rule := range rs.Rules {
			// #8580: one shared computation for every surface. This copy
			// defaulted to "interface", so a `then source-nat off` exemption
			// was reported as its exact opposite and an ACTIONLESS rule as
			// translating (#7640); and it read only the singular address
			// field, so an address-book-scoped rule reported as matching
			// EVERYTHING (#7363). Both had been fixed in pkg/natshow and left
			// live here.
			action := natshow.SourceRuleAction(rule)
			srcMatch := natshow.RuleMatchSource(rule)
			dstMatch := natshow.RuleMatchDestination(rule)

			var hitPkts, hitBytes uint64
			if cr != nil {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := s.dp.ReadNATRuleCounter(uint32(cid))
					if err != nil {
						// A counter read FAILURE must surface as unavailable, not
						// render as a healthy zero hit count (#5046).
						writeError(w, http.StatusInternalServerError,
							"NAT rule counter read failed: "+err.Error())
						return
					}
					hitPkts = cnt.Packets
					hitBytes = cnt.Bytes
				}
			}

			// #7473: this object is the issue's archetype — it attaches a hit
			// counter to a rule the dataplane may never have installed, where
			// the 0 reads as "no traffic matched" rather than "not armed".
			// This handler walks `NAT.Source` only, so the source predicate is
			// the whole verdict here.
			info := NATRuleStatsInfo{
				RuleSet:    rs.Name,
				RuleName:   rule.Name,
				FromZone:   rs.FromZone,
				ToZone:     rs.ToZone,
				Action:     action,
				SrcMatch:   srcMatch,
				DstMatch:   dstMatch,
				HitPackets: hitPkts,
				HitBytes:   hitBytes,
			}
			if reason := config.SourceNATRuleNotInstalledReason(cfg, rule); reason != "" {
				info.NotInstalled = true
				info.NotInstalledReason = config.SourceNATDisarmReasonText(reason)
			}
			result = append(result, info)
		}
	}

	if result == nil {
		result = []NATRuleStatsInfo{}
	}
	writeOK(w, result)
}

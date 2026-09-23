package grpcapi

import (
	"context"
	"errors"
	"sort"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (s *Server) GetZones(_ context.Context, _ *pb.GetZonesRequest) (*pb.GetZonesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetZonesResponse{}, nil
	}

	cr := s.applyResult()
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for zoneName := range cfg.Security.Zones {
		zoneNames = append(zoneNames, zoneName)
	}
	quarantinedZones := config.ZoneQuarantineExclusions(zoneNames)

	// #3408: a per-zone counter read failure must surface as codes.Internal
	// rather than a clean-zero field, mirroring GetGlobalStats (#3345).
	var readErr error
	resp := &pb.GetZonesResponse{}
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		zi := &pb.ZoneInfo{
			Name:        zoneName,
			Description: zone.Description,
			Interfaces:  zone.Interfaces,
			TcpRst:      zone.TCPRst,
		}
		_, quarantined := quarantinedZones[zoneName]
		if quarantined {
			zi.QuarantineState = pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_QUARANTINED
			zi.QuarantineSurvivorZone = config.StableZoneIDOwner(
				zoneNames, config.StableZoneID(zoneName))
		} else {
			zi.QuarantineState = pb.ZoneQuarantineState_ZONE_QUARANTINE_STATE_NOT_QUARANTINED
		}
		if quarantined {
			// Do not read the survivor's counters under the quarantined name.
			// The four counter fields remain zero and explicitly unavailable.
			zi.PerZoneCounterAvailability =
				pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}
		// #3328: surface the host-inbound admission posture distinctly. The
		// legacy host_inbound_services list stays as a flattened back-compat
		// alias (system-services + protocols), but the split fields below let
		// automation tell a service (ssh, ping) apart from a protocol (ospf,
		// bgp). Post-#3405 the admitted set — empty = deny-all — is the
		// discriminating signal (host_inbound_configured is true for every
		// configured zone; see below).
		if zone.HostInboundTraffic != nil {
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.Protocols...)
			zi.HostInboundSystemServices = append(zi.HostInboundSystemServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundProtocols = append(zi.HostInboundProtocols, zone.HostInboundTraffic.Protocols...)
		}
		// host_inbound_configured mirrors ZoneSnapshot.HostInboundConfigured
		// (#3070/#3362/#3405). Post-#3405 EVERY configured security zone is
		// host-inbound ENFORCING (Junos default-deny parity): a zone with no
		// `host-inbound-traffic` stanza default-DENIES host-bound traffic
		// exactly like an explicit empty stanza. buildZoneSnapshots sets
		// HostInboundConfigured=true unconditionally for every non-nil zone
		// (dataplane/userspace/zones.go). Re-deriving the bit from config shape
		// (stanza-or-override) reported false for a no-stanza zone — the API's
		// own "false = admit-all" contract, the exact OPPOSITE of the runtime
		// default-deny (#3653). Report the dataplane truth: enforcing. The
		// admitted token set (which may be empty = deny-all) lives in the split
		// fields below.
		zi.HostInboundConfigured = true
		for _, ref := range zone.SortedInterfaceHostInboundRefs() {
			hib := zone.InterfaceHostInbound[ref]
			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, &pb.InterfaceHostInbound{
				Interface:      ref,
				Configured:     true,
				SystemServices: append([]string{}, hib.SystemServices...),
				Protocols:      append([]string{}, hib.Protocols...),
			})
		}
		// #3682: surface the management / cluster-control lifeline interfaces
		// EXCLUDED from this zone's host-inbound deny scoping (always-admitted),
		// so the remote CLI and any structured consumer can render the implicit
		// exemption instead of it being an invisible bypass.
		zi.LifelineInterfaces = zone.HostInboundViewWithLifelines(
			config.HostInboundLifelineSet(cfg)).LifelineInterfaces
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}
		if zi.HostInboundServices == nil {
			zi.HostInboundServices = []string{}
		}

		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.Id = uint32(id)
				if !quarantined && s.dp != nil && s.dp.IsLoaded() {
					ing, errIn := s.dp.ReadZoneCounters(id, 0)
					eg, errOut := s.dp.ReadZoneCounters(id, 1)
					switch {
					case errors.Is(errIn, dataplane.ErrCounterNotPopulated) ||
						errors.Is(errOut, dataplane.ErrCounterNotPopulated):
						// #6843: per-zone counters ARE sourced (#3651). This
						// branch means the dataplane published nothing for THIS
						// zone -- pre-#3651 helper, a zone past the helper's
						// hot-path slot capacity (traffic genuinely uncounted),
						// or an idle zone.
						// Leave the counter fields unset (proto3 omit) rather
						// than Internal-erroring the RPC on the structural
						// stable-hash-id OOB.
						//
						// #6895: SAY SO on the wire. Before this the client saw
						// four zeros and could not tell them from a real reading
						// of zero, so the remote cli omitted the section and an
						// unavailable zone rendered exactly like an idle one.
						zi.PerZoneCounterAvailability =
							pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_UNAVAILABLE
					case errIn != nil:
						if readErr == nil {
							readErr = errIn
						}
					case errOut != nil:
						if readErr == nil {
							readErr = errOut
						}
					default:
						// #6895: an actual reading, even if it is zero.
						zi.PerZoneCounterAvailability =
							pb.ZoneCounterAvailability_ZONE_COUNTER_AVAILABILITY_AVAILABLE
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		resp.Zones = append(resp.Zones, zi)
	}
	if readErr != nil {
		return nil, status.Errorf(codes.Internal, "reading zone counter: %v", readErr)
	}
	sort.Slice(resp.Zones, func(i, j int) bool { return resp.Zones[i].Name < resp.Zones[j].Name })
	return resp, nil
}

func (s *Server) GetPolicies(_ context.Context, _ *pb.GetPoliciesRequest) (*pb.GetPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetPoliciesResponse{}, nil
	}

	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): per-policy hit counters are populated only when policy-stats
	// is enabled system-wide (default off), matching the Prometheus
	// collector and the CLI/gRPC text surfaces. When the knob is off,
	// HitPackets/HitBytes stay 0 (we skip the dataplane read).
	statsEnabled := cfg.Security.PolicyStatsEnabled
	// #3408: surface a per-policy counter read failure as codes.Internal.
	var readErr error
	// #4344: read the whole policy set from ONE snapshot (O(P+C), one brief
	// dataplane lock) via the #3965 bulk reader instead of a per-policy
	// ReadPolicyCounters loop that rebuilt the ruleID->counter index and
	// rescanned the config under the policy mutex on every rule. Built only
	// when the dataplane is loaded; falls back to the per-policy read for
	// dataplanes without the bulk snapshot (test fakes / retired eBPF), so the
	// returned HitPackets/HitBytes are identical. cfg is the config walked
	// below, so the snapshot's handles line up with the handles computed here.
	var readPolicy func(uint32) (dataplane.CounterValue, error)
	if s.dp != nil && s.dp.IsLoaded() {
		readPolicy = dpuserspace.NewPolicyCounterReader(s.dp, cfg, s.dp.ReadPolicyCounters)
	}
	// #8177: put the SECOND input of the eligibility gate on the wire. Without
	// it, "stats on, count=false" (a read that returned 0) and "stats off,
	// count=false" (no read at all) are byte-identical, so a structured consumer
	// cannot tell an authoritative zero from an unmeasured one — the same defect
	// #7776 fixed on the text surfaces. Neither `count` nor
	// `hit_counters_unavailable` changes meaning; see the field comment in
	// xpf.proto for why reusing the latter would have been wrong.
	resp := &pb.GetPoliciesResponse{PolicyStatsEnabled: statsEnabled}
	// #3336: span-accumulated runtime/RT_FLOW policy IDs, keyed
	// [policySetID, sliceIndex] — the same identity the event path logs, so
	// automation can join a policy_id back to a rule. The raw ordinal stays the
	// counter handle below.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	// #3624: live per-scheduler active-state, the same view the #3062 text
	// policy-detail surface uses (server_show_policies_text.go). haveSched
	// gates the lookup: when the provider is unavailable (early boot /
	// NoDataplane) the inventory reports every rule active (inactive=false),
	// matching the text surface's fail-open display rather than the
	// fail-closed match-policies simulator (#3414).
	schedActive, haveSched := s.policySchedulerActiveState()
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		// #3476: skip a nil zone-pair set (tolerant / HA-sync path) while
		// advancing the policy-set ID, mirroring the runtime walker, rather
		// than dereferencing zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		pi := &pb.PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for i, rule := range zpp.Policies {
			// #3476: skip a nil rule like the runtime walker does.
			if rule == nil {
				continue
			}
			pr := &pb.PolicyRule{
				Name:        rule.Name,
				Description: rule.Description,
				Action:      policyActionStr(rule.Action),
				// #3358: unqualify synthetic zone-local keys (#3061) so the
				// inventory exposes the authored book name, not the internal
				// compiler token. DisplayAddressNames returns a new slice.
				SrcAddresses: config.DisplayAddressNames(rule.Match.SourceAddresses),
				DstAddresses: config.DisplayAddressNames(rule.Match.DestinationAddresses),
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
				// #3336: match-inversion flags — without these an audit reading
				// src/dst_addresses sees a `source-address-excluded` rule's
				// meaning inverted. Additive; false for an un-inverted rule.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				// #3336: independent session-init / session-close log modes the
				// collapsed `log` bool hides.
				LogSessionInit:  rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose: rule.Log != nil && rule.Log.SessionClose,
				// #3336: runtime identity for event correlation. #3623: proto3
				// explicit presence — the first zone-pair set's first rule has id
				// 0, which a bare scalar would omit on the wire; always set it so
				// the join key survives even at 0.
				PolicyId: proto.Uint32(dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i))),
				RuleId:   dpuserspace.StablePolicyRuleID(zpp.FromZone, zpp.ToZone, rule.Name),
				// #3624: scheduler binding + runtime scheduler state, mirroring
				// the #3062 text detail (State: inactive, Scheduler: <name>).
				SchedulerName: rule.SchedulerName,
				Inactive:      haveSched && dpuserspace.PolicyInactive(rule.SchedulerName, schedActive),
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if (statsEnabled || rule.Count) && readPolicy != nil {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				ctrs, err := readPolicy(policyID)
				switch {
				case err == nil:
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					// #7016: the helper has published no counter for THIS rule
					// id yet -- the pre-first-status-poll warm-up window, or
					// config skew after a non-abort-class apply failure (#5679).
					// That is a per-rule NO-DATA condition, not a read failure:
					// flag the rule and keep serving the inventory instead of
					// answering codes.Internal for the whole RPC and discarding
					// every other row. Same split the zone loop above makes for
					// dataplane.ErrCounterNotPopulated (#6843).
					pr.HitCountersUnavailable = true
				default:
					if readErr == nil {
						readErr = err
					}
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
		policySetID++
	}

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 {
		pi := &pb.PolicyInfo{
			FromZone: "*",
			ToZone:   "*",
		}
		for i, rule := range cfg.Security.GlobalPolicies {
			// #3476: skip a nil global rule (GlobalPolicies is []*Policy)
			// like the runtime walker does.
			if rule == nil {
				continue
			}
			pr := &pb.PolicyRule{
				Name:        rule.Name,
				Description: rule.Description,
				Action:      policyActionStr(rule.Action),
				// #3358: unqualify synthetic zone-local keys (#3061) so the
				// inventory exposes the authored book name, not the internal
				// compiler token. DisplayAddressNames returns a new slice.
				SrcAddresses: config.DisplayAddressNames(rule.Match.SourceAddresses),
				DstAddresses: config.DisplayAddressNames(rule.Match.DestinationAddresses),
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
				// #3286/#4626: a scoped global policy (#3148) narrows the
				// all-zones group to a zone SET. Carry the configured
				// scope so the inventory shows the real scope instead of
				// the group-level "*"/"*". The singular fields keep the
				// first zone for backward compatibility; the plural fields
				// carry the full set. Empty for an unscoped (all-zones)
				// global — no regression.
				MatchFromZone:  config.ScopeSingular(rule.Match.FromZones),
				MatchToZone:    config.ScopeSingular(rule.Match.ToZones),
				MatchFromZones: rule.Match.FromZones,
				MatchToZones:   rule.Match.ToZones,
				// #3336: match-inversion flags + log modes + runtime identity.
				// Global rule_id uses the "junos-global" sentinel zones, matching
				// the snapshot builder so the rule_id joins to the same event.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				LogSessionInit:             rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose:            rule.Log != nil && rule.Log.SessionClose,
				// #3623: proto3 explicit presence for the runtime id (see above).
				PolicyId: proto.Uint32(dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i))),
				RuleId:   dpuserspace.StablePolicyRuleID("junos-global", "junos-global", rule.Name),
				// #3624: scheduler binding + runtime scheduler state (see above).
				SchedulerName: rule.SchedulerName,
				Inactive:      haveSched && dpuserspace.PolicyInactive(rule.SchedulerName, schedActive),
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if (statsEnabled || rule.Count) && readPolicy != nil {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				ctrs, err := readPolicy(policyID)
				switch {
				case err == nil:
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					// #7016: the helper has published no counter for THIS rule
					// id yet -- the pre-first-status-poll warm-up window, or
					// config skew after a non-abort-class apply failure (#5679).
					// That is a per-rule NO-DATA condition, not a read failure:
					// flag the rule and keep serving the inventory instead of
					// answering codes.Internal for the whole RPC and discarding
					// every other row. Same split the zone loop above makes for
					// dataplane.ErrCounterNotPopulated (#6843).
					pr.HitCountersUnavailable = true
				default:
					if readErr == nil {
						readErr = err
					}
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
	}

	// #3363: the IMPLICIT default-policy catch-all has a reserved hit counter
	// (read via the DefaultPolicySentinelID handle). Surface it as a final
	// synthetic policy set ("-"/"-") with one rule named
	// dataplane.DefaultPolicyName so structured automation reading GetPolicies
	// sees the same default-deny/permit row REST/CLI/text/Prometheus render.
	// Counts gate on policy-stats like every other rule.
	{
		// #7422 row 13: EFFECTIVE flags, shared with the #3534 advisory.
		defLogInit, defLogClose := config.EffectiveDefaultPolicyLogFlags(cfg)
		defRule := &pb.PolicyRule{
			Name:         dataplane.DefaultPolicyName,
			Action:       policyActionStr(cfg.Security.DefaultPolicy),
			SrcAddresses: []string{},
			DstAddresses: []string{},
			Applications: []string{},
			// #3670: mirror the implicit default-policy's own RT_FLOW log intent
			// (DefaultPolicyLogSessionInit/Close, threaded to the dataplane via
			// ConfigSnapshot.DefaultLogSessionInit/Close in the #3534 builder)
			// onto the synthetic row, using the same Log/LogSessionInit/
			// LogSessionClose fields the configured rows set (#3336). Without
			// this, structured automation reading GetPolicies sees the
			// default-deny/permit boundary as unlogged while the dataplane emits
			// default-verdict session-init/close records.
			// #7422 row 13: the flags as they BEHAVE — inert under a
			// default-DENY/REJECT, which installs no session for the
			// session-init/close records to fire on.
			Log:             defLogInit || defLogClose,
			LogSessionInit:  defLogInit,
			LogSessionClose: defLogClose,
			// #3623: presence-wrapped; the default row always carries the sentinel.
			PolicyId: proto.Uint32(dataplane.DefaultPolicySentinelID),
			RuleId:   dataplane.DefaultPolicyName,
		}
		if statsEnabled && readPolicy != nil {
			ctrs, err := readPolicy(dataplane.DefaultPolicySentinelID)
			switch {
			case err == nil:
				defRule.HitPackets = ctrs.Packets
				defRule.HitBytes = ctrs.Bytes
			case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
				// #7016: same per-rule no-data disposition as the configured
				// rows -- an applied helper publishes the default sentinel
				// unconditionally, so a miss here is the warm-up/skew window.
				defRule.HitCountersUnavailable = true
			default:
				if readErr == nil {
					readErr = err
				}
			}
		}
		resp.Policies = append(resp.Policies, &pb.PolicyInfo{
			FromZone: "-",
			ToZone:   "-",
			Rules:    []*pb.PolicyRule{defRule},
		})
	}

	if readErr != nil {
		return nil, status.Errorf(codes.Internal, "reading policy counter: %v", readErr)
	}
	return resp, nil
}

func (s *Server) GetScreen(_ context.Context, _ *pb.GetScreenRequest) (*pb.GetScreenResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetScreenResponse{}, nil
	}

	resp := &pb.GetScreenResponse{}
	for name, profile := range cfg.Security.Screen {
		si := &pb.ScreenInfo{
			Name:   name,
			Checks: screenChecks(profile),
		}
		if si.Checks == nil {
			si.Checks = []string{}
		}
		if th := config.ScreenThresholds(profile); len(th) > 0 {
			si.Thresholds = make(map[string]int64, len(th))
			for k, v := range th {
				si.Thresholds[k] = int64(v)
			}
		}
		resp.Screens = append(resp.Screens, si)
	}
	sort.Slice(resp.Screens, func(i, j int) bool { return resp.Screens[i].Name < resp.Screens[j].Name })
	return resp, nil
}

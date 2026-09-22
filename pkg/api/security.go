package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/logging"
	"github.com/psaab/xpf/pkg/policymatch"
)

func (s *Server) zonesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ZoneInfo{})
		return
	}

	cr := s.applyResult()
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for zoneName := range cfg.Security.Zones {
		zoneNames = append(zoneNames, zoneName)
	}
	quarantinedZones := config.ZoneQuarantineExclusions(zoneNames)
	// #3408: a per-zone counter read failure must not be reported as a clean
	// 0 — surface it as HTTP 500 after building, mirroring the global
	// /stats/global contract (#3345).
	var readErr error
	var zones []ZoneInfo
	for zoneName, zone := range cfg.Security.Zones {
		if zone == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
			continue
		}
		zi := ZoneInfo{
			Name:        zoneName,
			Description: zone.Description,
			TcpRst:      zone.TCPRst,
			Interfaces:  zone.Interfaces,
		}
		_, quarantined := quarantinedZones[zoneName]
		if quarantined {
			zi.Quarantine = &ZoneQuarantineInfo{
				State:        ZoneQuarantineStateQuarantined,
				SurvivorZone: config.StableZoneIDOwner(zoneNames, config.StableZoneID(zoneName)),
			}
			// Do not publish the survivor's counters under the quarantined
			// name. The numeric counter fields remain their zero values.
			zi.PerZoneCountersAvailable = false
		} else {
			zi.Quarantine = &ZoneQuarantineInfo{
				State: ZoneQuarantineStateNotQuarantined,
			}
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}

		// Host-inbound services. #3328: surface the admission posture
		// distinctly. HostInbound stays the flattened back-compat alias, but the
		// split fields let automation tell a service (ssh, ping) apart from a
		// protocol (ospf, bgp). Post-#3405 the admitted set — empty = deny-all —
		// is the discriminating signal (HostInboundConfigured is true for every
		// configured zone; see below).
		if zone.HostInboundTraffic != nil {
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.SystemServices...)
			zi.HostInbound = append(zi.HostInbound, zone.HostInboundTraffic.Protocols...)
			zi.HostInboundSystemServices = append(zi.HostInboundSystemServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundProtocols = append(zi.HostInboundProtocols, zone.HostInboundTraffic.Protocols...)
		}
		// HostInboundConfigured mirrors ZoneSnapshot.HostInboundConfigured
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
			zi.InterfaceHostInbound = append(zi.InterfaceHostInbound, ZoneInterfaceHostInbound{
				Interface:      ref,
				Configured:     true,
				SystemServices: append([]string{}, hib.SystemServices...),
				Protocols:      append([]string{}, hib.Protocols...),
			})
		}
		if zi.HostInbound == nil {
			zi.HostInbound = []string{}
		}
		if zi.HostInboundSystemServices == nil {
			zi.HostInboundSystemServices = []string{}
		}
		if zi.HostInboundProtocols == nil {
			zi.HostInboundProtocols = []string{}
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}

		// Zone ID + counters
		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.ID = id

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
						// Flag unavailable and leave the counts unset rather
						// than reporting a misleading 0 or 500'ing the whole
						// endpoint on the structural stable-hash-id OOB.
						zi.PerZoneCountersAvailable = false
					case errIn != nil:
						if readErr == nil {
							readErr = errIn
						}
					case errOut != nil:
						if readErr == nil {
							readErr = errOut
						}
					default:
						zi.PerZoneCountersAvailable = true
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		// #7181: attach the APPLIED state of the host-inbound surface. The stanza
		// rendered above is DESIRED config; without this a zone reports its
		// host-inbound posture as configured while no kernel table may exist.
		// Omitted when the callback is unwired, so an absent daemon claims nothing.
		if s.hostInboundAppliedFn != nil {
			if snap := s.hostInboundAppliedFn(); snap.Known {
				zi.HostInboundApplied = hostInboundAppliedInfo(snap)
			}
		}
		zones = append(zones, zi)
	}
	if readErr != nil {
		writeError(w, http.StatusInternalServerError,
			"zone counter read failed: "+readErr.Error())
		return
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
	writeOK(w, zones)
}

func (s *Server) policiesHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []PolicyInfo{})
		return
	}

	// Honor `set security policy-stats system-wide enable` (#2008 M4 /
	// #2118): per-policy hit counters are populated only when policy-stats
	// is enabled system-wide (default off), matching the Prometheus
	// collector and the CLI/gRPC display surfaces. When the knob is off,
	// hit_packets/hit_bytes stay 0 (we skip the dataplane read).
	statsEnabled := cfg.Security.PolicyStatsEnabled
	// #10530: policy inventory remains an authored-config view, but a rule
	// whose endpoint/scope is quarantined would be scrubbed from the applied
	// snapshot. Reuse the config verdict once per request so the existing
	// fields can distinguish "0 hits" from "no live attribution" without
	// changing the REST schema.
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	quarantinedZones := config.ZoneQuarantineExclusions(zoneNames)
	isQuarantinedZone := func(name string) bool {
		_, ok := quarantinedZones[name]
		return ok
	}
	appendPolicyQualifier := func(description string) string {
		if strings.Contains(description, config.ZoneQuarantinePoliciesQualifier) {
			return description
		}
		if description == "" {
			return config.ZoneQuarantinePoliciesQualifier
		}
		return description + " " + config.ZoneQuarantinePoliciesQualifier
	}
	pruneQuarantinedScope := func(scope []string) ([]string, bool) {
		if len(scope) == 0 {
			return scope, false
		}
		pruned := make([]string, 0, len(scope))
		touched := false
		for _, name := range scope {
			if isQuarantinedZone(name) {
				touched = true
				continue
			}
			pruned = append(pruned, name)
		}
		if !touched {
			return scope, false
		}
		// Keep an explicitly empty result as an empty display scope. Do not
		// turn a configured side whose every member was quarantined into the
		// all-zones wildcard; the qualifier marks it as a scrubbed candidate.
		// PolicyRule uses omitempty for the plural fields, so a fully-pruned
		// side may be absent on the wire; consumers must not read empty/missing
		// plural scope alone as an all-zones wildcard.
		return pruned, true
	}
	// #3408: surface a per-policy counter read failure as HTTP 500 after
	// building, rather than reporting clean-zero hit counts.
	var readErr error
	// #3965: read the policy set from ONE snapshot (O(P+C), one brief dataplane
	// lock) instead of a per-policy ReadPolicyCounters loop that held the policy
	// mutex across an O(P*(P+C)) walk. Built only when the dataplane is loaded so
	// no snapshot is taken on a config-only boot; falls back to the per-policy
	// read for dataplanes without the bulk snapshot (test fakes / retired eBPF).
	var readPolicy func(uint32) (dataplane.CounterValue, error)
	if s.dp != nil && s.dp.IsLoaded() {
		readPolicy = dpuserspace.NewPolicyCounterReader(s.dp, cfg, s.dp.ReadPolicyCounters)
	}
	// #3336: span-accumulated runtime/RT_FLOW policy IDs keyed
	// [policySetID, sliceIndex] — the identity the event path logs, so
	// automation can join a policy_id back to a rule. The raw ordinal stays the
	// counter handle below.
	runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
	// #3624: live per-scheduler active-state, the same view the #3062 text
	// policy-detail surface uses (cli_show_security.go / server_show_policies_
	// text.go). haveSched gates the lookup: when the accessor is not wired or
	// returns ok=false (early boot / NoDataplane) the inventory reports every
	// rule active (inactive=false), matching the text surface's fail-open
	// display rather than the fail-closed match-policies simulator (#3414).
	var schedActive map[string]bool
	var haveSched bool
	if s.policySchedActiveFn != nil {
		schedActive, haveSched = s.policySchedActiveFn()
	}
	var policySetID uint32
	var result []PolicyInfo
	for _, zpp := range cfg.Security.Policies {
		// #3476: the tolerant / HA-sync config path can leave a nil
		// zone-pair set (Policies is []*ZonePairPolicies); the runtime
		// walker skips it while advancing the policy-set ID. Mirror that so
		// the inventory does not panic on zpp.FromZone.
		if zpp == nil {
			policySetID++
			continue
		}
		pi := PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
			// #8177: see the field comment in types.go for why this
			// system-wide knob is repeated per zone-pair block.
			PolicyStatsEnabled: statsEnabled,
		}
		for i, rule := range zpp.Policies {
			// #3476: skip a nil rule (Policies is []*Policy) like the
			// runtime walker does, rather than dereferencing rule.Name.
			if rule == nil {
				continue
			}
			ruleQuarantined := isQuarantinedZone(zpp.FromZone) || isQuarantinedZone(zpp.ToZone)
			pr := PolicyRule{
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
				// #3336: surface the match-inversion flags so an audit does not
				// read a `source-address-excluded` rule's meaning inverted, the
				// independent session-init/close log modes the Log bool hides,
				// and the runtime identity (policy_id matches the event path,
				// rule_id the snapshot) for event<->rule correlation.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				LogSessionInit:             rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose:            rule.Log != nil && rule.Log.SessionClose,
				PolicyID:                   dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)),
				RuleID:                     dpuserspace.StablePolicyRuleID(zpp.FromZone, zpp.ToZone, rule.Name),
				// #3624: scheduler binding + runtime scheduler state, mirroring
				// the #3062 text detail (Scheduler: line + State: inactive).
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
			if ruleQuarantined {
				pr.Description = appendPolicyQualifier(pr.Description)
				if statsEnabled || rule.Count {
					pr.HitCountersUnavailable = true
				}
			}

			if !ruleQuarantined && (statsEnabled || rule.Count) {
				if readPolicy != nil {
					// #3474: the counter read handle MUST use the RAW slice
					// index i, not len(pi.Rules) (the compacted, nil-skipped
					// count). The resolver (policyRuleIDForCounter) and every
					// other caller — metrics_counters.go's
					// policyCounterID(policySetID, i), cli_show_security*.go,
					// server_show_policies_text.go, and this function's OWN
					// global-policy loop below (+ uint32(i)) — key off the raw
					// slice index. With a nil rule before a real rule
					// len(pi.Rules) would lag i and mis-resolve this rule's
					// counter; using i keeps every counter handle on the one
					// raw-slice-index SSOT. (Nil rules are not reachable via any
					// production config path today; this is defensive
					// SSOT-alignment, like #3476/#3494.)
					policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					ctrs, err := readPolicy(policyID)
					switch {
					case err == nil:
						pr.HitPackets = ctrs.Packets
						pr.HitBytes = ctrs.Bytes
					case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
						// #7016: the helper has published no counter for THIS
						// rule id yet. Per-rule "no counter source", NOT a read
						// failure — flag it like the unloaded case below rather
						// than 500'ing the whole inventory, exactly as the zone
						// handler above treats ErrCounterNotPopulated (#6843).
						pr.HitCountersUnavailable = true
					default:
						if readErr == nil {
							readErr = err
						}
					}
				} else {
					// #5580: the rule is counter-eligible but no runtime counter
					// source exists (dataplane unloaded — readPolicy was not
					// built). Mark the 0/0 counts non-authoritative so a monitor
					// does not read them as "rule matched no traffic".
					pr.HitCountersUnavailable = true
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
		policySetID++
	}

	// Global policies (#3045): the CLI, gRPC GetPolicies, and the
	// Prometheus collector all expose globals; the REST inventory
	// endpoint must too, otherwise automation/dashboards cannot audit
	// rules the dataplane actively enforces. Emit a single global row
	// with from_zone="*"/to_zone="*" (matching gRPC) after the zone-pair
	// rows, preserving the policy-counter ID ordering: global counter IDs
	// start after the zone-pair policy-set count (policySetID continues
	// from the loop above).
	if len(cfg.Security.GlobalPolicies) > 0 {
		pi := PolicyInfo{
			FromZone:           "*",
			ToZone:             "*",
			PolicyStatsEnabled: statsEnabled, // #8177
		}
		for i, rule := range cfg.Security.GlobalPolicies {
			if rule == nil {
				continue
			}
			displayFromZones, fromScopeQuarantined := pruneQuarantinedScope(rule.Match.FromZones)
			displayToZones, toScopeQuarantined := pruneQuarantinedScope(rule.Match.ToZones)
			scopeQuarantined := fromScopeQuarantined || toScopeQuarantined
			pr := PolicyRule{
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
				// #3286/#4626: surface the scoped-global zone SET (#3148) so
				// a global narrowed to a zone list is not reported as
				// all-zones. The singular fields keep the first zone for
				// backward compatibility; the plural fields carry the full
				// set. Empty for an unscoped global — no regression. Keep
				// these authored singular fields even when a quarantined
				// member is pruned from the new plural display copies: this
				// REST compatibility split intentionally differs from the
				// runtime snapshot, which regenerates singulars from survivors.
				MatchFromZone:  config.ScopeSingular(rule.Match.FromZones),
				MatchToZone:    config.ScopeSingular(rule.Match.ToZones),
				MatchFromZones: displayFromZones,
				MatchToZones:   displayToZones,
				// #3336: match-inversion flags + independent log modes + runtime
				// identity. The global rule_id uses the "junos-global" sentinel
				// zones, matching the snapshot builder so it joins to the same
				// event.
				SourceAddressExcluded:      rule.Match.SourceAddressExcluded,
				DestinationAddressExcluded: rule.Match.DestinationAddressExcluded,
				LogSessionInit:             rule.Log != nil && rule.Log.SessionInit,
				LogSessionClose:            rule.Log != nil && rule.Log.SessionClose,
				PolicyID:                   dpuserspace.RuntimePolicyIndex(runtimeIDs, policySetID, uint32(i)),
				RuleID:                     dpuserspace.StablePolicyRuleID("junos-global", "junos-global", rule.Name),
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
			if scopeQuarantined {
				pr.Description = appendPolicyQualifier(pr.Description)
				if statsEnabled || rule.Count {
					pr.HitCountersUnavailable = true
				}
			}

			if !scopeQuarantined && (statsEnabled || rule.Count) {
				if readPolicy != nil {
					policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					ctrs, err := readPolicy(policyID)
					switch {
					case err == nil:
						pr.HitPackets = ctrs.Packets
						pr.HitBytes = ctrs.Bytes
					case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
						// #7016: unpublished global-rule counter — flag, do not
						// fail the inventory (see the zone-pair loop).
						pr.HitCountersUnavailable = true
					default:
						if readErr == nil {
							readErr = err
						}
					}
				} else {
					// #5580: counter-eligible global rule, dataplane unloaded —
					// mark the zero counts non-authoritative (see zone-pair loop).
					pr.HitCountersUnavailable = true
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []PolicyRule{}
		}
		result = append(result, pi)
	}

	// #3363: the IMPLICIT default-policy catch-all now has a reserved hit
	// counter (read via the DefaultPolicySentinelID handle). Surface it as a
	// final synthetic policy set ("-"/"-") with one rule named
	// dataplane.DefaultPolicyName so automation/dashboards can audit
	// default-deny/permit hits — the most security-relevant boundary — without
	// scraping logs. Counts gate on policy-stats like every other rule.
	{
		// #7422 row 13: EFFECTIVE flags, shared with the #3534 advisory.
		defLogInit, defLogClose := config.EffectiveDefaultPolicyLogFlags(cfg)
		defRule := PolicyRule{
			Name:         dataplane.DefaultPolicyName,
			Action:       policyActionStr(cfg.Security.DefaultPolicy),
			SrcAddresses: []string{},
			DstAddresses: []string{},
			Applications: []string{},
			// #3670: the implicit default-policy carries its own RT_FLOW log
			// intent (DefaultPolicyLogSessionInit/Close, threaded to the
			// dataplane via ConfigSnapshot.DefaultLogSessionInit/Close in the
			// #3534 builder). Surface it on the synthetic row exactly as the
			// configured rows expose Log/LogSessionInit/LogSessionClose (#3336)
			// so audit tooling does not read the most security-relevant
			// boundary as unlogged while the dataplane is emitting the records.
			// #7422 row 13: report the flags as they BEHAVE, not as configured.
			// A default-DENY/REJECT installs no session, so the
			// session-init/close records never fire and reporting them true
			// tells audit tooling the boundary is logged when nothing logs.
			// Shared with the #3534 commit advisory so the two cannot disagree.
			Log:             defLogInit || defLogClose,
			LogSessionInit:  defLogInit,
			LogSessionClose: defLogClose,
			PolicyID:        dataplane.DefaultPolicySentinelID,
			RuleID:          dataplane.DefaultPolicyName,
		}
		// #4344 (M02): the default-policy row now reads through the SAME #3965
		// bulk reader as the configured rows above (readPolicy), instead of a
		// standalone per-policy s.dp.ReadPolicyCounters call that took a second
		// dataplane snapshot for a single sentinel handle. readPolicy != nil
		// implies the dataplane is loaded (built above under that guard); the
		// bulk snapshot already includes the DefaultPolicySentinelID handle
		// (ReadAllPolicyCounters puts it), so the value is identical.
		if statsEnabled {
			if readPolicy != nil {
				ctrs, err := readPolicy(dataplane.DefaultPolicySentinelID)
				switch {
				case err == nil:
					defRule.HitPackets = ctrs.Packets
					defRule.HitBytes = ctrs.Bytes
				case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
					// #7016: the implicit default-policy sentinel is published
					// unconditionally by an applied helper, so this is the
					// warm-up / config-skew window — flag it rather than
					// discarding the whole inventory.
					defRule.HitCountersUnavailable = true
				default:
					if readErr == nil {
						readErr = err
					}
				}
			} else {
				// #5580: the implicit default-policy row is counter-eligible
				// whenever system-wide policy-stats is on; with the dataplane
				// unloaded there is no counter source, so its 0/0 is not
				// authoritative. (The default row has no `then count`, so
				// eligibility gates on statsEnabled alone.)
				defRule.HitCountersUnavailable = true
			}
		}
		result = append(result, PolicyInfo{
			FromZone: "-",
			ToZone:   "-",
			Rules:    []PolicyRule{defRule},
		})
	}

	if readErr != nil {
		writeError(w, http.StatusInternalServerError,
			"policy counter read failed: "+readErr.Error())
		return
	}
	writeOK(w, result)
}

func (s *Server) screenHandler(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		writeOK(w, []ScreenInfo{})
		return
	}

	var result []ScreenInfo
	for name, profile := range cfg.Security.Screen {
		si := ScreenInfo{Name: name}
		si.Checks = screenChecks(profile)
		if si.Checks == nil {
			si.Checks = []string{}
		}
		si.Thresholds = config.ScreenThresholds(profile)
		result = append(result, si)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	writeOK(w, result)
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	if s.eventBuf == nil {
		writeOK(w, []EventEntry{})
		return
	}

	// #4926: parse `limit` STRICTLY so a present-but-malformed, negative, or
	// over-cap value fails closed with HTTP 400 — mirroring the sibling `zone`
	// filter below — instead of silently defaulting the caller's requested
	// scope. The lenient queryInt returned the 50 default on `limit=abc` /
	// `limit=-1`, a fail-open that hid a client bug and could silently
	// under-report the event window. An ABSENT/empty `limit` still defaults to
	// 50 (queryIntStrict returns (def, true) for an empty value), matching the
	// zone filter's "absent = no constraint" semantics. queryIntStrict rejects
	// malformed/negative/non-canonical values; the explicit upper-bound check
	// then rejects a value past the 10000 cap rather than the old silent clamp,
	// so a caller asking for more than the buffer can return is told, not
	// quietly truncated. Valid `limit=10000` still works.
	limit, ok := queryIntStrict(r, "limit", 50)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid limit: "+r.URL.Query().Get("limit"))
		return
	}
	if limit > 10000 {
		writeError(w, http.StatusBadRequest, "invalid limit: "+r.URL.Query().Get("limit")+" exceeds maximum 10000")
		return
	}

	filter := logging.EventFilter{
		Action:   r.URL.Query().Get("action"),
		Protocol: r.URL.Query().Get("protocol"),
	}
	// Zone filter: presence of the `zone` query parameter selects the filter,
	// so zone 0 — the "unknown" / unassigned zone carried by pre-classification
	// and host-inbound events — is selectable (#3338). Zone IDs are 1-based, so
	// 0 used to be swallowed by the `0 = no filter` sentinel and those events
	// were invisible to any zone-filtered query. The word sentinels "unknown"
	// and "none" are accepted as aliases for 0, mirroring the unknown-zone label
	// used elsewhere. An absent parameter leaves the filter unset (match-all); a
	// malformed/out-of-range value fails closed with HTTP 400.
	if zoneStr := r.URL.Query().Get("zone"); zoneStr != "" {
		z, ok := parseEventZoneFilter(zoneStr)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid zone filter: "+zoneStr)
			return
		}
		filter.Zone = z
		filter.HasZone = true
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	result := make([]EventEntry, len(events))
	for i, ev := range events {
		result[i] = eventEntryFromRecord(ev)
	}
	writeOK(w, result)
}

// parseEventZoneFilter parses a security-event zone filter value. It accepts a
// 1-based numeric zone ID (0..65535) and the case-insensitive word sentinels
// "unknown"/"none" as aliases for zone 0, the unassigned/pre-classification
// zone (#3338). It returns (0,false) for a malformed or out-of-range value so
// the caller fails closed with HTTP 400 rather than silently widening the query
// (mirrors queryUint16Strict's fail-closed contract).
func parseEventZoneFilter(s string) (uint16, bool) {
	switch strings.ToLower(s) {
	case "unknown", "none":
		return 0, true
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(n), true
}

// hostInboundToREST projects the shared host-inbound-traffic classifier verdict
// (policymatch.Result.HostInbound, #3627 B1a) onto the REST JSON struct so a
// match-policies caller sees WHICH host-inbound-traffic system-service/protocol
// token admits a host-bound tuple — the same detail the gRPC host_inbound field
// and the local CLI `show security match-policies` line carry (#4352). It reads
// the same SSOT-backed classifier, so the three surfaces cannot drift (#3375).
// Returns nil (field omitted from the JSON) for a nil admission (an off-host
// query has no host-inbound gate) or a not-computed status, matching the CLI,
// which prints nothing in those cases.
func hostInboundToREST(a *dpuserspace.HostInboundAdmission) *MatchPoliciesHostInbound {
	if a == nil || a.Status == dpuserspace.HostInboundNotComputed {
		return nil
	}
	return &MatchPoliciesHostInbound{
		Status:      a.Status.String(),
		Token:       a.Token,
		Kind:        a.Kind,
		Description: a.Describe(),
	}
}

// matchPoliciesSelectorKeys is the exact, ordered set of query-string
// selectors the match-policies handler consults. It is the SINGLE source of
// truth for BOTH the #3709 duplicate-scalar check AND the #5316 unknown-key
// allowlist: a selector is added here (and only here), and both the reads and
// the two validation passes derive from it, so a new dimension cannot be
// duplicate-checked-but-not-allowlisted (or vice versa) and a caller typo can
// never silently re-open the fail-open gap.
var matchPoliciesSelectorKeys = []string{
	"from_zone", "to_zone", "src_ip", "dst_ip",
	"src_port", "dst_port", "protocol", "icmp_type", "icmp_code",
	// #5572: non-first-fragment (l4_present == false) discriminator. A boolean
	// param ("true"/"1"/"false"/"0"/absent); absent = a normal L4 packet.
	"non_first_fragment",
	// #5579: ingress-interface selector — scopes a `to-zone junos-host`
	// host-inbound query to ONE interface's effective host-inbound view (admit vs
	// deny) instead of the zone-wide first-admit fold. A free-form interface ref
	// validated against the live config (zone membership + lifeline reject);
	// absent = zone-scoped classification.
	"ingress_interface",
}

// isMatchPoliciesSelector reports whether key is a recognized match-policies
// selector (a member of matchPoliciesSelectorKeys).
func isMatchPoliciesSelector(key string) bool {
	for _, k := range matchPoliciesSelectorKeys {
		if k == key {
			return true
		}
	}
	return false
}

func (s *Server) matchPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	// #3709: validate request grammar BEFORE the cfg == nil verdict so a
	// malformed / duplicate / missing-zone query fails the SAME way during the
	// boot window (no active config) as it does once a config is live. Before
	// this, the cfg == nil branch returned 200 default-deny before ANY grammar
	// check ran, so `dst_port=abc` or `?from_zone=a&from_zone=b` returned 200 at
	// boot but 400 once a config existed — inconsistent validation during the
	// exact window monitors poll.
	q := r.URL.Query()

	// #3709: reject a DUPLICATE scalar selector (e.g.
	// `?from_zone=trust&from_zone=dmz`). r.URL.Query().Get returns the FIRST of
	// repeated values, so REST silently FIRST-won while the CLI/gRPC surfaces
	// LAST-won — the three surfaces disagreed on WHICH duplicate the simulator
	// tested, each certifying a verdict for a packet the operator may not have
	// typed. There is no correct silent pick, so a repeat is a 400, matching the
	// strict CLI/gRPC parsers (policymatch.ParseSelectorArgs / showTestPolicy).
	for _, key := range matchPoliciesSelectorKeys {
		if len(q[key]) > 1 {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("selector %q specified more than once", key))
			return
		}
	}

	// #5316: reject an UNKNOWN / misspelled selector key (fail closed). The
	// handler reads ONLY matchPoliciesSelectorKeys; any other key is never
	// examined, so a typo such as `protcol` for `protocol` silently degrades
	// that dimension to the wildcard-any default — q.Get("protocol") returns
	// "" — and the shared simulator can certify a broad PERMIT for a packet
	// class the caller never intended to test. That is a FAIL-OPEN on a
	// security-verification endpoint. Enumerate every key the caller supplied
	// and 400 any that is not in the selector allowlist, naming the offender.
	// The allowlist is the SAME slice the reads use, so adding a selector later
	// cannot re-open the gap. Absent keys are unchanged: an unspecified
	// dimension is still the intentional match-any wildcard — only UNKNOWN keys
	// are rejected, not missing ones. Reached AFTER the duplicate check so a
	// repeated known selector still surfaces its #3709 duplicate error, and
	// (like the checks above) BEFORE the cfg == nil verdict so the boot window
	// rejects an unknown key identically to the config-present path.
	var unknown []string
	for key := range q {
		if !isMatchPoliciesSelector(key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		// Sort so the reported key is deterministic when a caller supplies
		// several unknown keys (map iteration order is randomized).
		sort.Strings(unknown)
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown selector parameter: %s", unknown[0]))
		return
	}

	fromZone := q.Get("from_zone")
	toZone := q.Get("to_zone")

	// #3355 (H06): the CLI surfaces (show security match-policies / test
	// policy) require BOTH zones; REST accepted a missing zone and evaluated as
	// if the empty string were a zone, which the #3355 defined-zone guard would
	// then send straight to the default-policy — a misleading silent verdict for
	// what is really a malformed query. Reject it for parity with the CLI.
	if fromZone == "" || toZone == "" {
		writeError(w, http.StatusBadRequest, "from_zone and to_zone are required")
		return
	}

	// A non-empty but malformed src_ip/dst_ip would parse to nil and be
	// treated as a wildcard by matchPolicyAddr, yielding a false-positive
	// PERMIT verdict in the simulator (#1711). Reject it with 400. An
	// empty value still means "unspecified" (match any).
	srcIPStr := r.URL.Query().Get("src_ip")
	if srcIPStr != "" && net.ParseIP(srcIPStr) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid src_ip %q", srcIPStr))
		return
	}
	dstIPStr := r.URL.Query().Get("dst_ip")
	if dstIPStr != "" && net.ParseIP(dstIPStr) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid dst_ip %q", dstIPStr))
		return
	}

	srcIP := net.ParseIP(srcIPStr)
	dstIP := net.ParseIP(dstIPStr)
	// A malformed dst_port/src_port must not silently become 0 (the "any
	// port" wildcard) — that yields a misleading PERMIT/DENY verdict in the
	// simulator (#2934). Fail closed with 400. queryIntStrict rejects
	// malformed/negative values; policymatch.ValidatePort additionally
	// rejects an out-of-range port (>65535) that cannot describe a real
	// packet (#3116). 0/absent stays the unspecified wildcard.
	dstPort, ok := queryIntStrict(r, "dst_port", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid dst_port: "+r.URL.Query().Get("dst_port"))
		return
	}
	if err := policymatch.ValidatePort(dstPort); err != nil {
		writeError(w, http.StatusBadRequest, "invalid dst_port: "+err.Error())
		return
	}
	srcPort, ok := queryIntStrict(r, "src_port", 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid src_port: "+r.URL.Query().Get("src_port"))
		return
	}
	if err := policymatch.ValidatePort(srcPort); err != nil {
		writeError(w, http.StatusBadRequest, "invalid src_port: "+err.Error())
		return
	}
	// A non-empty but unknown/out-of-range protocol token (e.g. "tcpp", "999")
	// must NOT silently become "any protocol" — the shared matcher's matchApp
	// short-circuits to match-any for an empty/unresolvable protocol, yielding a
	// misleading PERMIT/DENY verdict for a policy using `application any`
	// (#3108). Reject it with 400. An empty value still means "unspecified"
	// (match any protocol), unchanged.
	proto := r.URL.Query().Get("protocol")
	if err := policymatch.ValidateProtocol(proto); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// #3284: optional ICMP/ICMPv6 type/code so a type-constrained application
	// term (junos-ping = type 8) is honored. An empty value is unspecified (a
	// type-constrained term then fails closed, mirroring the dataplane); a
	// malformed/out-of-range value is rejected, never coerced.
	icmpType, err := policymatch.ParseICMPValue(r.URL.Query().Get("icmp_type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid icmp_type: "+err.Error())
		return
	}
	icmpCode, err := policymatch.ParseICMPValue(r.URL.Query().Get("icmp_code"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid icmp_code: "+err.Error())
		return
	}
	// #5572: the non-first-fragment (l4_present == false) discriminator. A
	// malformed value must NOT silently become the normal-packet default — that
	// would answer a DIFFERENT question than asked on a security-verification
	// endpoint — so a non-empty value that is not a canonical bool is a 400. An
	// empty/absent value is the unchanged normal L4-present packet.
	nonFirstFrag := false
	if v := r.URL.Query().Get("non_first_fragment"); v != "" {
		parsed, perr := strconv.ParseBool(v)
		if perr != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid non_first_fragment %q", v))
			return
		}
		nonFirstFrag = parsed
	}

	cfg := s.store.ActiveConfig()
	if cfg == nil {
		// #3375: no active config is the deterministic fail-closed default deny.
		// Surface the explicit string AND the typed default_used bit (same SSOT
		// renderer the gRPC surface uses). #3709: reached only AFTER the grammar
		// checks above, so a malformed / duplicate / missing-zone query returns
		// 400 here too — the boot window is now grammar-consistent with the
		// config-present path, not a 200 default-deny that skips validation.
		nilRes := policymatch.Result{DefaultUsed: true, Action: config.PolicyDeny}
		writeOK(w, MatchPoliciesResult{
			Action:      nilRes.DisplayAction(),
			DefaultUsed: true,
			// #3627 M06: echo the queried zone pair even on the no-config
			// fail-closed default deny so a stored diagnostic proves which zone
			// pair produced the verdict.
			QueriedFromZone: fromZone,
			QueriedToZone:   toZone,
		})
		return
	}

	// #5579: validate the optional ingress-interface selector against the live
	// config — it must name an interface assigned to from_zone and must not be a
	// management/cluster lifeline (served unconditionally). An unknown /
	// zone-mismatched / lifeline ref is a fail-closed 400, mirroring the src_ip /
	// port / protocol validators above, so the host-inbound classifier is only
	// ever scoped to a real interface of the queried zone. Reached after cfg !=
	// nil so zone membership is resolvable.
	ingressIface := q.Get("ingress_interface")
	if err := dpuserspace.ResolveHostInboundIngressInterface(cfg, fromZone, ingressIface); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// #3042: delegate to the single shared simulator so REST agrees with the
	// runtime evaluator (exact zone-pair -> wildcard-zone tiers (#3090) ->
	// scoped global (#3148) -> default-policy, predefined + nested-app-set +
	// literal-CIDR + any-ipv4/any-ipv6 + exclusion + feed overlay). The
	// pre-#3042 hand-written loop skipped globals, hard-coded "deny (default)",
	// and missed predefined apps / literal CIDRs.
	var overlay map[string][]string
	if s.feedOverlayFn != nil {
		overlay = s.feedOverlayFn()
	}
	// #3104: thread live per-scheduler active-state so the simulator skips a
	// scheduler-inactive policy exactly like the runtime (policy.rs
	// try_match_rule), falling through to the next active rule / default-policy.
	//
	// #3414: always bind a non-nil predicate so the unavailable-state path
	// fails the SAME direction as the dataplane. When the accessor is not
	// wired or returns ok=false (early boot / NoDataplane), schedState is nil,
	// and PolicyInactiveFn(nil) treats every scheduler-bound policy as inactive
	// — exactly as the snapshot builder does (policyRuleInactive: nil map =>
	// dropped) until live state arrives. Previously the closure stayed nil and
	// scheduled policies were simulated as-if-active, so the REST diagnostic
	// could certify a permit/deny the dataplane actually skips (#3414). A
	// NON-scheduled policy (empty scheduler name) is unaffected: PolicyInactiveFn
	// returns false for it regardless of the (possibly nil) state map.
	var schedState map[string]bool
	if s.policySchedActiveFn != nil {
		schedState, _ = s.policySchedActiveFn()
	}
	inactiveFn := dpuserspace.PolicyInactiveFn(schedState)
	res := policymatch.Match(cfg, policymatch.Query{
		FromZone: fromZone,
		ToZone:   toZone,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		// #6377: colon-strict text family from the RAW query strings so the
		// unsupported-tuple gate does not fold an IPv4-mapped IPv6 source to v4.
		// Classify srcIPStr/dstIPStr (the un-parsed operator text) — srcIP/dstIP
		// are net.ParseIP results that have already discarded the ':'.
		SrcFamily:        config.NATAddrFamily(srcIPStr),
		DstFamily:        config.NATAddrFamily(dstIPStr),
		Protocol:         proto,
		SrcPort:          srcPort,
		DstPort:          dstPort,
		ICMPType:         icmpType,
		ICMPCode:         icmpCode,
		NonFirstFragment: nonFirstFrag,
		// #5579: scope the host-inbound classifier to this ingress interface's
		// effective view (validated above). "" = zone-scoped, unchanged.
		IngressInterface: ingressIface,
		FeedOverlay:      overlay,
		PolicyInactiveFn: inactiveFn,
	})
	// #3285: a `to-zone junos-host` query that matched no host-bound policy is
	// not a transit default — the dataplane host gate returns None (local
	// delivery; no global/default fallback). Surface it explicitly so the
	// caller does not read a misleading default-policy verdict for the host
	// path.
	if res.ContentRejected {
		// #3727: the dataplane fails this config closed (unexpandable
		// application-set) and enforces none of its policies. Surface the
		// fail-closed retention + the offending content, NOT a fabricated
		// permit/deny/default verdict.
		writeOK(w, MatchPoliciesResult{
			ContentRejected:         true,
			ContentRejectionReasons: res.ContentRejectionReasons,
			Action:                  res.DisplayAction(),
			QueriedFromZone:         fromZone,
			QueriedToZone:           toZone,
		})
		return
	}
	if res.HostInboundUnmatched {
		writeOK(w, MatchPoliciesResult{
			HostInboundUnmatched: true,
			Action:               res.DisplayAction(),
			// #3627 M06: echo the queried zone pair on the host-inbound path so
			// the diagnostic names the tested zones (the host gate returns no
			// matched-policy scope to fill FromZone/ToZone).
			QueriedFromZone: fromZone,
			QueriedToZone:   toZone,
			// #3627 B1a: name the admitting host-inbound-traffic token (or report
			// deny / global-accept / indeterminate) so a REST client sees WHICH
			// system-service/protocol governs local delivery for this tuple, the
			// same detail the gRPC surface + local CLI carry (#4352). nil off-host.
			HostInbound: hostInboundToREST(res.HostInbound),
		})
		return
	}
	if !res.Matched {
		writeOK(w, MatchPoliciesResult{
			Action:      res.DisplayAction(),
			DefaultUsed: res.DefaultUsed,
			// #8318: carried so a structured consumer can tell an unconditional
			// unzoned-ingress deny from a default-deny without parsing Action.
			// DefaultUsed is false on that arm, which is necessary but not
			// sufficient — ContentRejected and the host-inbound arm share it.
			UnzonedIngress: res.UnzonedIngress,
			// #3627 M06: echo the queried zone pair on the no-match/default path
			// so a stored default-deny diagnostic proves which zone pair was
			// tested (FromZone/ToZone carry matched-policy scope, unset here).
			QueriedFromZone: fromZone,
			QueriedToZone:   toZone,
			// #4373 (E4/H2/H7): a multicast/broadcast/unspecified/loopback
			// destination is dropped at route before policy, so even the default
			// verdict does not describe real forwarding — carry the advisory.
			RouteDropBeforePolicy: res.RouteDropBeforePolicy,
			RouteDropClass:        res.RouteDropClass,
			RouteDropNote:         res.RouteDropNote(),
		})
		return
	}
	matchedID := res.PolicyID
	writeOK(w, MatchPoliciesResult{
		Matched:    true,
		PolicyName: res.PolicyName,
		Global:     res.Global,
		FromZone:   res.FromZone,
		ToZone:     res.ToZone,
		// #3627 M06: also echo the queried zone pair on a positive match. It is
		// the query context, distinct from FromZone/ToZone (the matched policy's
		// declared scope), which can differ for a wildcard-zone or global match.
		QueriedFromZone: fromZone,
		QueriedToZone:   toZone,
		// #3623: set the pointer only on a match (the two early returns above
		// leave it nil), so a matched first policy (id 0) is emitted as
		// "policy_id":0 rather than dropped and mistaken for no match.
		PolicyID: &matchedID,
		// #3668: the stable rule identity (inventory join key) + the
		// address-exclusion flags so a positive verdict against a
		// source/destination-address-excluded rule does not read backwards.
		RuleID: res.RuleID,
		// #3685 M05: carry the matched policy's description (ticket / change
		// context) so the match verdict is not weaker than the inventory /
		// local CLI answers over the same policymatch.Result.
		Description: res.Description,
		// #3685 M06: name the scheduler time-gate and confirm it is currently
		// admitting the rule. A positive match here is by construction active
		// (inactiveFn above already skipped a scheduler-inactive rule, #3414),
		// so SchedulerActive tracks whether the matched rule is scheduler-gated
		// at all — true only for a scheduled policy, omitted for an always-on
		// one.
		SchedulerName:              res.SchedulerName,
		SchedulerActive:            res.SchedulerName != "",
		Action:                     res.DisplayAction(),
		SrcAddresses:               res.SrcAddresses,
		DstAddresses:               res.DstAddresses,
		SourceAddressExcluded:      res.SourceAddressExcluded,
		DestinationAddressExcluded: res.DestinationAddressExcluded,
		Applications:               res.Applications,
		// #3627 B1a: a matched `to-zone junos-host` policy still passes through
		// the separate host-inbound-traffic admission gate, so carry the
		// classifier verdict here too (present for any host-bound query; nil for
		// a transit/global match, which has no host gate).
		HostInbound: hostInboundToREST(res.HostInbound),
		// #4373 (E4/H2/H7): a matched policy for a multicast/broadcast/
		// unspecified/loopback destination still does not forward — the flow is
		// dropped at route before policy. Carry the advisory so a positive match
		// verdict is not read as real forwarding.
		RouteDropBeforePolicy: res.RouteDropBeforePolicy,
		RouteDropClass:        res.RouteDropClass,
		RouteDropNote:         res.RouteDropNote(),
		// #5572: a non-first fragment whose permit was overridden to this
		// overlapping port-bearing deny — the result is attributed to the
		// enforcing deny above; carry the advisory so the REST answer explains
		// the over-drop identically to the CLI + gRPC surfaces.
		FragmentAssociatedDeny: res.FragmentAssociatedDeny,
		FragmentDenyNote:       res.FragmentDenyNote(),
	})
}

func policyActionStr(a config.PolicyAction) string {
	switch a {
	case config.PolicyPermit:
		return "permit"
	case config.PolicyDeny:
		return "deny"
	case config.PolicyReject:
		return "reject"
	default:
		return "unknown"
	}
}

// screenChecks delegates to config.ScreenChecks, the single source of truth
// shared with gRPC (#3327). A nil profile (reachable on the tolerant / HA-sync
// config path the runtime walker pkg/dataplane/userspace/screens.go skips)
// renders as "no checks" rather than panicking on p.TCP.SynFlood (#3476).
func screenChecks(p *config.ScreenProfile) []string {
	return config.ScreenChecks(p)
}

// hostInboundAppliedInfo maps the daemon's applied-state snapshot to the REST
// projection.
//
// The ORDER of these arms is the whole point. `Established` is sticky-true, so
// testing it first and reporting "current" would render a box whose latest
// render FAILED as healthy — the exact conflation #7181 exists to remove.
func hostInboundAppliedInfo(snap HostInboundAppliedSnapshot) *HostInboundAppliedInfo {
	out := &HostInboundAppliedInfo{
		Generation:         snap.Generation,
		LastFailureUnixSec: snap.LastFailureUnixSec,
		GapFenceActive:     snap.GapFenceActive,
	}
	switch {
	case !snap.Established:
		out.State = HostInboundAppliedNotEstablished
	case snap.LastApplyFailed:
		out.State = HostInboundAppliedStale
	default:
		out.State = HostInboundAppliedCurrent
	}
	return out
}

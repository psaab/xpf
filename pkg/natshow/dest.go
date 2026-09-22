package natshow

import (
	"context"
	"fmt"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	"io"
	"sort"
	"strings"
)

// RenderDestRuleDetail renders detailed destination NAT rule
// information, including pool address/port, translation hit counters,
// and active session counts per rule-set.
//
// The nil/empty guard reproduces the gRPC contract verbatim
// (cfg == nil, no Destination config, or no rule-sets all emit the same
// "No destination NAT rules configured" line). The CLI dispatcher keeps
// its own pre-guard; for the non-empty path it routes here and renders
// identically.
//
// ctx is the admission-lease context (#7315); the v4+v6 session tally below
// stops on cancellation via the shared walkSessionValues authority.
//
// crFn lazily supplies the apply result; like RenderSourceRuleDetail it
// is invoked only after the empty-config guard, preserving the master
// ordering where applyResult() ran after the guard.
func RenderDestRuleDetail(ctx context.Context, w io.Writer, cfg *config.Config, dp Reader, crFn func() *dataplane.ApplyResult) {
	if cfg == nil || cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		io.WriteString(w, "No destination NAT rules configured\n")
		return
	}
	dnat := cfg.Security.NAT.Destination
	var cr *dataplane.ApplyResult
	if crFn != nil {
		cr = crFn()
	}
	type ruleSetKey struct{ from, to string }
	rsSessions := make(map[ruleSetKey]int)
	var scanErr error
	// #7423 rows 3+4: ONE armed predicate. The session scan already had this
	// test; the translation-hits read did not, and the session count rendered a
	// bare 0 whether the dataplane had reported or never been armed. All three
	// now read the same thing, so they cannot disagree about whether the numbers
	// below are measurements.
	//
	// #7315 keeps `armed` EXACTLY as #7423 defined it and calls the shared walk
	// authority inside it. An earlier revision of #7315 hoisted the
	// `dp != nil && dp.IsLoaded()` half down into walkSessionValues and left
	// only `cr != nil` here — which would have widened `armed` for the two
	// renders below that have nothing to do with the walk (the translation-hits
	// gate and the rule-set aggregate line), reintroducing exactly the
	// unmeasured-state claim #7423 removed.
	armed := dp != nil && dp.IsLoaded() && cr != nil
	if armed {
		zoneByID := make(map[uint16]string, len(cr.ZoneIDs))
		names := make([]string, 0, len(cr.ZoneIDs))
		for name := range cr.ZoneIDs {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			id := cr.ZoneIDs[name]
			owner := config.StableZoneIDOwner(names, id)
			if owner == "" {
				if _, exists := zoneByID[id]; exists {
					continue
				}
				owner = name
			}
			if owner == name {
				zoneByID[id] = name
			}
		}
		// walkSessionValues re-tests dp/IsLoaded internally — see the note in
		// RenderSourceRuleDetail on why that double-check is deliberate.
		scanErr = walkSessionValues(ctx, dp,
			func(val dataplane.SessionValue) {
				if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			},
			func(val dataplane.SessionValueV6) {
				if val.IsReverse == 0 && val.Flags&dataplane.SessFlagDNAT != 0 {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			})
	}

	noteSessionScanError(w, scanErr)
	ruleIdx := 0
	for _, rs := range dnat.RuleSets {
		for _, rule := range rs.Rules {
			ruleIdx++
			// #9877: the rule-level exclusion verdict, hoisted for the two
			// readers below: the NOT INSTALLED annotation and the
			// translation-hits gate (the source renderer's #8185 shape). A
			// skipped rule ships no snapshot row and owns no counter, so the
			// hits line must not print for one.
			excludedReason := config.DestinationNATRuleExcludedReason(dnat, rule)
			// #7640: as in the source renderer, do not claim an action the
			// rule does not carry. This defaulted to "off", so an ACTIONLESS
			// destination rule displayed as an explicit exemption the operator
			// never wrote. The observable disposition happens to match (the
			// builder skips such a rule), but the display asserted intent.
			action := "none"
			switch {
			case rule.Then.PoolName != "":
				action = "pool " + rule.Then.PoolName
			case rule.Then.Off:
				action = "off"
			}
			// #7363: the FULL match — bracket list and address-book names —
			// not just the singular back-compat field.
			dstMatch := natMatchAddresses(
				rule.Match.DestinationAddress, rule.Match.DestinationAddresses,
				rule.Match.DestinationAddressName, rule.Match.DestinationAddressNames)
			if dstMatch == "" {
				dstMatch = "0.0.0.0/0"
			}
			fromZone, toZone := rs.FromZone, rs.ToZone
			if config.ZoneQuarantineExcludedReason(fromZone, cfg) != "" {
				fromZone += " " + config.ZoneQuarantineReferenceQualifier
			}
			if config.ZoneQuarantineExcludedReason(toZone, cfg) != "" {
				toZone += " " + config.ZoneQuarantineReferenceQualifier
			}
			fmt.Fprintf(w, "destination NAT rule: %s\n", rule.Name)
			fmt.Fprintf(w, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(w, "    From zone: %s    To zone: %s\n", fromZone, toZone)
			fmt.Fprintf(w, "    Match:\n")
			fmt.Fprintf(w, "      Destination addresses: %s\n", dstMatch)
			if rule.Match.DestinationPort != 0 {
				fmt.Fprintf(w, "      Destination port:      %d\n", rule.Match.DestinationPort)
			}
			if protos := rule.Match.ProtocolList(); len(protos) > 0 {
				fmt.Fprintf(w, "      IP protocol:           %s\n", strings.Join(protos, " "))
			}
			if apps := rule.Match.ApplicationList(); len(apps) > 0 {
				fmt.Fprintf(w, "      Application:           %s\n", strings.Join(apps, " "))
			}
			fmt.Fprintf(w, "    Action:                  %s\n", action)
			// #6534: buildDestinationNATSnapshotsWithFeeds publishes NO entry
			// for these rules, so the pool address/port printed below is config
			// the dataplane never installed.
			noteNotInstalled(w, excludedReason)
			// #9879: a broad `off` exemption a narrower later translate rule
			// re-enters. Unlike the exclusion above this rule IS installed —
			// only the re-entered subspace translates — so the warning leads
			// with PARTIALLY SHADOWED, never NOT INSTALLED.
			noteDNATOffShadowed(w, config.DNATOffShadowReason(dnat, rs, rule))
			// #6823: #7640 wired this annotation on the SOURCE renderer only,
			// while its record and gauge both walk source AND destination
			// (TestOffendersCoverBothKinds7640). So the operator-facing half
			// covered one kind: `show security nat destination rule detail`
			// never said a rule had been admitted by a tolerant load, on
			// exactly the paths — boot, peer-sync, rollback — where such a
			// rule is the only kind that can exist. An enumerator that finds
			// both kinds and a view that shows one is a coverage gap that
			// looks identical to healthy from the operator's side.
			//
			// #9874: suppressed for a rule whose authored match constrains
			// nothing — the NOT INSTALLED line above already carries that
			// verdict (via the predicate's marker clause) and the operative
			// cause, so the terminal-action note would only repeat the
			// admission.
			if !rule.LenientMatchDropped {
				noteLenientTerminalAction(w, cfg, "destination", rs.Name, rule.Name)
			}

			if rule.Then.PoolName != "" && dnat.Pools != nil {
				if pool, ok := dnat.Pools[rule.Then.PoolName]; ok {
					fmt.Fprintf(w, "    Pool address:            %s\n", pool.Address)
					if pool.Port != 0 {
						fmt.Fprintf(w, "    Pool port:               %d\n", pool.Port)
					}
				}
			}

			// #7423 row 3: gate the hits read on the SAME `armed` predicate the
			// session scan above uses. `Manager.ReadNATRuleCounter` is a map
			// read with no error path — it returns `(zero, nil)` when the
			// helper has never reported — so on a published-but-UNARMED
			// dataplane `err == nil` holds and this rendered a confident
			// `Translation hits: 0`. The `err == nil` guard is NOT dead code
			// (other implementations of the interface do error), it simply
			// cannot fire for the production Manager, which is why the zero got
			// through. The REST sibling already refuses instead (#5046).
			// #9877: a rule the builder skipped owns no counter — printing
			// `Translation hits: 0` for one would read as armed-but-idle (the
			// #7473 lie). The NOT INSTALLED line above is its whole story.
			if armed && excludedReason == "" {
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeDest, rs.Name, rule.Name)
				if cid, ok := cr.NATCounterIDs[ruleKey]; ok {
					cnt, err := dp.ReadNATRuleCounter(uint32(cid))
					if err == nil {
						fmt.Fprintf(w, "    Translation hits:        %d packets  %d bytes\n",
							cnt.Packets, cnt.Bytes)
					}
				}
			} else if dp != nil && excludedReason == "" {
				fmt.Fprintf(w, "    Translation hits:        %s\n", natCounterUnarmed)
			}
			fmt.Fprint(w, "\n")
		}
		// #7423 row 4: this count is a ZONE-PAIR aggregate — every destination-NAT
		// session between `rs.FromZone` and `rs.ToZone`, which the scan above
		// keys on the session's ingress/egress zone ids. It used to print
		// inside the rule loop, so five rules over four hundred sessions
		// printed `400` five times and summing the column gave five times the
		// truth. Junos reports this per RULE; the dataplane cannot, because a
		// session carries zone ids and no rule identity, so there is nothing to
		// attribute with. Reporting it once at the scope it actually measures
		// is the honest form available: the number is real, it was labelled
		// with the wrong noun.
		quarantinedPair := config.ZoneQuarantineExcludedReason(rs.FromZone, cfg) != "" ||
			config.ZoneQuarantineExcludedReason(rs.ToZone, cfg) != ""
		if quarantinedPair {
			fmt.Fprintf(w, "  Rule-set %s: sessions for this zone pair: %s\n\n",
				rs.Name, config.ZoneQuarantineLiveCountersUnavailable)
		} else if armed {
			fmt.Fprintf(w, "  Rule-set %s: sessions for this zone pair: %d\n\n",
				rs.Name, rsSessions[ruleSetKey{rs.FromZone, rs.ToZone}])
		} else if dp != nil {
			fmt.Fprintf(w, "  Rule-set %s: sessions for this zone pair: %s\n\n",
				rs.Name, natCounterUnarmed)
		}
	}
}

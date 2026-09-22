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

// RenderSourceRuleDetail renders detailed source NAT rule information,
// including pool details, translation hit counters, and active session
// counts per rule-set.
//
// ctx is the admission-lease context (#7315); the v4+v6 session tally below
// stops on cancellation via the shared walkSessionValues authority.
//
// crFn lazily supplies the apply result (zone-ID and NAT-counter maps);
// it is invoked only after the empty-config guard, preserving the
// master ordering where the consumer's applyResult() was called after
// the guard (so an empty config never touches dataplane state). A nil
// crFn, or a crFn returning nil, reproduces the "not loaded" path (no
// session counts, no translation hits).
func RenderSourceRuleDetail(ctx context.Context, w io.Writer, cfg *config.Config, dp Reader, crFn func() *dataplane.ApplyResult) {
	if cfg == nil || len(cfg.Security.NAT.Source) == 0 {
		io.WriteString(w, "No source NAT rules configured\n")
		return
	}
	var cr *dataplane.ApplyResult
	if crFn != nil {
		cr = crFn()
	}
	// Count active SNAT sessions per rule-set
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
		// walkSessionValues re-tests dp/IsLoaded internally. That is a
		// deliberate double-check, not dead code: `armed` also gates the
		// translation-hits read and the rule-set aggregate below, so it
		// cannot be narrowed to the walk; and the helper is shared with
		// RenderPersistentDetail, which has no `armed` and needs the guard
		// of its own. Neither is removable in favour of the other.
		scanErr = walkSessionValues(ctx, dp,
			func(val dataplane.SessionValue) {
				if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			},
			func(val dataplane.SessionValueV6) {
				if val.IsReverse == 0 && val.Flags&dataplane.SessFlagSNAT != 0 {
					rsSessions[ruleSetKey{zoneByID[val.IngressZone], zoneByID[val.EgressZone]}]++
				}
			})
	}

	noteSessionScanError(w, scanErr)
	// #6534: the aggregate pool-cardinality budget is a per-CONFIG walk, so
	// hoist it out of the rule loop. The builder
	// (buildSourceNATSnapshots) hoists the identical call for the identical
	// reason; SourceNATPoolDisarmedReason composes it with the pool's own
	// definition verdict in the builder's precedence order.
	overBudgetPools := config.SourceNATAggregateOverBudgetPools(cfg)
	ruleIdx := 0
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			ruleIdx++
			// #9877: the rule-level exclusion verdict, hoisted for the two
			// readers below: the NOT INSTALLED annotation and the
			// translation-hits gate. A skipped rule ships no snapshot row and
			// owns no counter, so the hits line must not print for one (#8185).
			excludedReason := config.SourceNATRuleExcludedReason(rule)
			// #7640: render the action the rule ACTUALLY carries. This
			// defaulted to "interface" whenever neither a pool nor `off` was
			// set — so an ACTIONLESS rule (one the strict gate rejects, and
			// which a tolerant load can still admit) displayed an action it
			// does not have and will not perform. That is the worst possible
			// output for the one rule shape an operator most needs to find.
			action := SourceRuleAction(rule)
			// #7363: the FULL match on BOTH sides. The source renderer had the
			// same singular-field shape as the destination one, so a fix to
			// only one would leave `show security nat source rule` still
			// rendering a name-scoped rule as 0.0.0.0/0.
			srcMatch := RuleMatchSource(rule)
			dstMatch := RuleMatchDestination(rule)
			fromZone, toZone := rs.FromZone, rs.ToZone
			if config.ZoneQuarantineExcludedReason(fromZone, cfg) != "" {
				fromZone += " " + config.ZoneQuarantineReferenceQualifier
			}
			if config.ZoneQuarantineExcludedReason(toZone, cfg) != "" {
				toZone += " " + config.ZoneQuarantineReferenceQualifier
			}
			fmt.Fprintf(w, "source NAT rule: %s\n", rule.Name)
			fmt.Fprintf(w, "  Rule-set: %s                        ID: %d\n", rs.Name, ruleIdx)
			fmt.Fprintf(w, "    From zone: %s    To zone: %s\n", fromZone, toZone)
			fmt.Fprintf(w, "    Match:\n")
			fmt.Fprintf(w, "      Source addresses:      %s\n", srcMatch)
			fmt.Fprintf(w, "      Destination addresses: %s\n", dstMatch)
			if protos := rule.Match.ProtocolList(); len(protos) > 0 {
				fmt.Fprintf(w, "      IP protocol:           %s\n", strings.Join(protos, " "))
			}
			fmt.Fprintf(w, "    Action:                  %s\n", action)
			// #9877: a rule-level exclusion (dropped match leaves) annotates for
			// EVERY mode — pool, interface, actionless — so it is asked BEFORE
			// the pool-mode gate, in the builder's precedence. The reason is
			// Go-side prose (a skipped rule ships nothing to expand).
			if excludedReason != "" {
				noteNotInstalled(w, excludedReason)
			} else if rule.LenientMatchDropped {
				// #9874: a rule whose authored match constrains nothing claims
				// in-scope flows and the dataplane drops them. That is the operative
				// cause, so it is printed INSTEAD OF the notes below — see
				// noteLenientMatchDropped for why those would mislead beside it.
				noteLenientMatchDropped(w)
			} else {
				// #6534: a pool-mode rule whose pool the builder marks unusable
				// ships PoolUnusable=true and the Rust source-NAT path declines to
				// translate — but every field above rendered from config as if the
				// rule were armed. Interface-mode NAT has no pool, so gate on a
				// non-empty pool name exactly as the builder does.
				if rule.Then.PoolName != "" {
					noteNotInstalled(w, config.SourceNATDisarmReasonText(
						config.SourceNATPoolDisarmedReason(
							cfg.Security.NAT.SourcePools[rule.Then.PoolName],
							rule.Then.PoolName, overBudgetPools)))
				}
				noteLenientTerminalAction(w, cfg, "source", rs.Name, rule.Name)
			}

			if rule.Then.PoolName != "" && cfg.Security.NAT.SourcePools != nil {
				if pool, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; ok {
					if pool.PersistentNAT != nil {
						fmt.Fprintf(w, "    Persistent NAT:          enabled\n")
					}
					if len(pool.Addresses) > 0 {
						fmt.Fprintf(w, "    Pool addresses:          %s\n", strings.Join(pool.Addresses, ", "))
					}
					// #7173: a `port no-translation` pool does not translate the
					// source port at all — the dataplane takes the address-only
					// path and ignores the range entirely (see the #3906 note in
					// pkg/dataplane/userspace/nat_source.go). Printing
					// "Port range: 1024-65535" for one told the operator the pool
					// uses a port range it does not use, and the number shown was
					// a default this display invented locally rather than
					// anything configured.
					if pool.PortNoTranslation {
						fmt.Fprintf(w, "    Port translation:        disabled (source port preserved)\n")
					} else {
						portLow, portHigh := pool.PortLow, pool.PortHigh
						if portLow == 0 {
							portLow = 1024
						}
						if portHigh == 0 {
							portHigh = 65535
						}
						fmt.Fprintf(w, "    Port range:              %d-%d\n", portLow, portHigh)
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
				ruleKey := dataplane.NATCounterKey(dataplane.NATCounterTypeSource, rs.Name, rule.Name)
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
		// #7423 row 4: this count is a ZONE-PAIR aggregate — every source-NAT
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

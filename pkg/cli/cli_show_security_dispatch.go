// Dispatcher methods for `show security ...` and `show security screen ...`
// plus the small helpers consumed exclusively by the security presenters.
//
// Worker methods (showZonesDisplay, showPoliciesHitCount, showScreen, etc.)
// live in cli_show_security.go; this file holds only the dispatchers that
// route args to those workers and the helper functions that the workers
// share with the dispatchers.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/policymatch"
)

// enabledStr returns "enabled" or "disabled" for a boolean flag.
func enabledStr(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

// policySchedulerStateProvider is the optional dataplane capability the
// policy-detail show surfaces use to learn the live per-scheduler
// active-state map (#3062). The userspace dataplane adapter implements
// it; offline/legacy runtimes do not, in which case the show surfaces
// fall back to rendering every policy enabled (bit-identical to today).
type policySchedulerStateProvider interface {
	PolicySchedulerActiveState() map[string]bool
}

// policySchedulerActiveState returns the live scheduler active-state map
// and whether it could be queried. When ok is false the caller must not
// claim any policy is scheduler-inactive (the runtime state is unknown).
func (c *CLI) policySchedulerActiveState() (state map[string]bool, ok bool) {
	if c == nil || c.dp == nil {
		return nil, false
	}
	p, isProvider := c.dpProbe().(policySchedulerStateProvider)
	if !isProvider {
		return nil, false
	}
	return p.PolicySchedulerActiveState(), true
}

// policyInactiveFn returns a per-policy scheduler-inactivity predicate bound to
// the live active-state snapshot for use as policymatch.Query.PolicyInactiveFn
// (#3104). It always returns a non-nil predicate so the simulator agrees with
// the dataplane in BOTH directions (#3414): when the runtime scheduler state
// cannot be queried (no provider / early boot), state is nil, and
// PolicyInactiveFn(nil) marks every scheduler-bound policy inactive — exactly
// what the snapshot builder does (policyRuleInactive: nil map => dropped) until
// live state arrives, so the diagnostic never certifies a verdict for a
// scheduled policy the dataplane is currently skipping. A NON-scheduled policy
// (empty scheduler name) is always active regardless of the (possibly nil)
// state map, so its verdict is unchanged.
func (c *CLI) policyInactiveFn() func(string) bool {
	state, _ := c.policySchedulerActiveState()
	return dpuserspace.PolicyInactiveFn(state)
}

// policyDetailState renders the Junos "State:" token for a policy detail
// line: "inactive" when the policy is bound to a scheduler that is
// currently runtime-inactive, otherwise "enabled". haveSched gates the
// lookup so that when the runtime state cannot be queried the output
// stays bit-identical to the pre-#3062 unconditional "enabled".
func policyDetailState(schedulerName string, activeState map[string]bool, haveSched bool) string {
	if haveSched && dpuserspace.PolicyInactive(schedulerName, activeState) {
		return "inactive"
	}
	return "enabled"
}

// policyShowQuery is the parsed tail of a `show security policies` command:
// the from-zone/to-zone selector pair, the display keyword that selects the
// view ("" = the standard view), whether `global` scopes the output to
// global policies, and the selector tail in operator order for a text
// surface.
type policyShowQuery struct {
	fromZone, toZone string
	view             string // "", "brief", "detail", "hit-count"
	globalOnly       bool
	filterText       string
}

// parsePolicyShowQuery walks the whole argument tail in ONE
// position-independent pass and returns everything the dispatcher must
// honour: the selector pair, the display keyword, and `global`.
//
// #12902 (D9-12): the validator admitted brief/detail/hit-count/global at
// any unconsumed position while the dispatch tested only `args[1]`**, so a
// modifier after the zone selectors (`from-zone X to-zone Y detail`) or a
// second keyword (`brief global`) was validated and then silently
// DISCARDED — the operator got the standard, unscoped view and a success
// return. One walk for admission AND dispatch removes the mismatch:
// everything the parse admits is honoured wherever it sits, and a
// combination no view can render — two display keywords, or a display
// keyword with `global` — is REJECTED (fail-closed) instead of narrowed. A
// display keyword repeated verbatim is idempotent and therefore admitted.
//
// The token following from-zone/to-zone is consumed as its value
// unconditionally, so a zone literally named "detail" is a selector value,
// never a display keyword — exactly the rule validatePolicyZoneFilter
// applies. The loop stays a classic counted for: the body advances i past
// a consumed value, which a range loop cannot do.
func parsePolicyShowQuery(args []string) (q policyShowQuery, err error) {
	var filterParts []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone", "to-zone":
			if i+1 >= len(args) || args[i+1] == "from-zone" || args[i+1] == "to-zone" {
				return q, fmt.Errorf("missing zone name after %q", args[i])
			}
			filterParts = append(filterParts, args[i], args[i+1])
			if args[i] == "from-zone" {
				q.fromZone = args[i+1]
			} else {
				q.toZone = args[i+1]
			}
			i++ // skip the consumed value
		case "brief", "detail", "hit-count":
			if q.view != "" && q.view != args[i] {
				return q, fmt.Errorf("conflicting display keywords %q and %q (choose one of brief, detail, hit-count)",
					q.view, args[i])
			}
			q.view = args[i]
		case "global":
			q.globalOnly = true
		default:
			return q, fmt.Errorf("unrecognized filter token %q (expected from-zone/to-zone)", args[i])
		}
	}
	if q.view != "" && q.globalOnly {
		return q, fmt.Errorf("keyword %q cannot be combined with %q", q.view, "global")
	}
	q.filterText = strings.Join(filterParts, " ")
	return q, nil
}

// validatePolicyZoneFilter rejects BOTH a from-zone/to-zone selector missing
// its zone value (e.g. "... from-zone trust to-zone") AND an unrecognized
// filter token (e.g. a typo'd `from-zonee`, or a stray word). Before #4908
// the local `show security policies` dispatch extracted the from-zone/to-zone
// pair with a loose scan and silently DROPPED every other token, so a
// mistyped selector key (`from-zonee trust`) left that filter dimension
// empty and WIDENED the view to every zone — an operator could read a
// narrow policy set as the whole table (#4908 / C175-HC-116/126 cohort /
// #5557). Rejecting the unknown key here mirrors the daemon-side gRPC
// parseZoneFilter's default-error rule
// (pkg/grpcapi/server_show_policies_text.go). Since #12902 the grammar
// lives in parsePolicyShowQuery; this predicate is its error face.
func validatePolicyZoneFilter(args []string) error {
	_, err := parsePolicyShowQuery(args)
	return err
}

// joinDisplayAddressNames joins an address-token list for an operator-facing
// flat render, unqualifying any synthetic zone-local key (#3061,
// zone-local/<zone>/<name>) back to the authored book name (#3358). The zone is
// already shown by the surrounding "From zone:" / "To zone:" header, so the
// bare name is unambiguous and the internal compiler namespace never leaks.
func joinDisplayAddressNames(addrs []string) string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = config.DisplayAddressName(a)
	}
	return strings.Join(out, ", ")
}

// flatMatchAddresses renders one standard-view address list — the joined
// display names, annotated " (except)" when the match sense is inverted
// (source-address-excluded / destination-address-excluded, #3336). The
// standard view prints the set on ONE line, so the inversion marker rides the
// list rather than the header, matching the remote flat renderer
// (cmd/cli/show_security.go). Without it a rule matching every address
// EXCEPT the listed ones rendered identically to one matching exactly them —
// the operator read the rule's reachability backwards.
func flatMatchAddresses(addrs []string, excluded bool) string {
	s := joinDisplayAddressNames(addrs)
	if excluded {
		s += " (except)"
	}
	return s
}

// resolveAddressDetail looks up the CIDR for a named address in the global
// address book, falling back to the name itself if not found.
//
// #9523: a match-all keyword is never looked up as a name (see
// config.IsPolicyAddressWildcardKeyword), so the detail shows the keyword the
// dataplane enforces rather than a tolerant-loaded object of the same name.
func resolveAddressDetail(cfg *config.Config, name string) string {
	if config.IsPolicyAddressWildcardKeyword(name) {
		return name
	}
	ab := cfg.Security.AddressBook
	if ab != nil {
		if addr, ok := ab.Addresses[name]; ok && addr.Value != "" {
			return addr.Value
		}
	}
	return name
}

// printAppDetail prints Junos-style application detail lines (protocol, ports, timeout).
// #15652 V12-04: resolve via canonical resolver — predefined, term-based
// (implicit-set) and set-backed names expand via ExpandApplicationSet +
// ResolveApplication (user-first) instead of a direct user-map index that
// silently printed nothing for those names.
func (c *CLI) printAppDetail(cfg *config.Config, appName string) {
	if appName == "any" {
		fmt.Printf("    IP protocol: 0, ALG: 0, Inactivity timeout: 0\n")
		fmt.Printf("      Source port range: [0-0]\n")
		fmt.Printf("      Destination ports: [0-0]\n")
		return
	}
	if cfg == nil {
		return
	}
	printOne := func(app *config.Application) {
		if app == nil {
			return
		}
		proto := app.Protocol
		if proto == "" {
			proto = "0"
		}
		timeoutStr := "0"
		if app.InactivityTimeoutNever {
			timeoutStr = "never"
		} else if app.InactivityTimeout > 0 {
			timeoutStr = fmt.Sprintf("%d", app.InactivityTimeout)
		}
		algVal := "0"
		if app.ALG != "" {
			algVal = app.ALG
		}
		fmt.Printf("    IP protocol: %s, ALG: %s, Inactivity timeout: %s\n", proto, algVal, timeoutStr)
		srcPort := "0-0"
		if app.SourcePort != "" {
			srcPort = app.SourcePort
		}
		dstPort := "0-0"
		if app.DestinationPort != "" {
			dstPort = app.DestinationPort
		}
		fmt.Printf("      Source port range: [%s]\n", srcPort)
		fmt.Printf("      Destination ports: [%s]\n", dstPort)
		if app.ICMPType != nil {
			fmt.Printf("      ICMP type: %d\n", *app.ICMPType)
		}
		if app.ICMPCode != nil {
			fmt.Printf("      ICMP code: %d\n", *app.ICMPCode)
		}
	}
	if app, ok := config.ResolveApplication(appName, cfg.Applications.Applications); ok && app != nil {
		printOne(app)
		return
	}
	if _, isSet := config.ResolveApplicationSet(appName, cfg.Applications.ApplicationSets); isSet {
		members, err := config.ExpandApplicationSet(appName, &cfg.Applications)
		if err != nil {
			return
		}
		for _, m := range members {
			if app, ok := config.ResolveApplication(m, cfg.Applications.Applications); ok && app != nil {
				fmt.Printf("    Application member: %s\n", m)
				printOne(app)
			}
		}
	}
}

func (c *CLI) handleShowSecurity(args []string) error {
	secTree := operationalTree["show"].Children["security"].Children
	if len(args) == 0 {
		fmt.Println("show security:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(secTree))
		return nil
	}

	resolved, err := resolveCommand(args[0], keysFromTree(secTree))
	if err != nil {
		return err
	}
	args[0] = resolved

	cfg := c.store.ActiveConfig()
	if cfg == nil && args[0] != "statistics" && args[0] != "ipsec" && args[0] != "alarms" && args[0] != "wireguard" {
		fmt.Println("no active configuration")
		return nil
	}

	switch args[0] {
	case "wireguard":
		// #1865: dataplane WG telemetry — works without an active
		// config (reads helper status only, like statistics).
		// #1434 Increment 1: `public-key` prints the local public key
		// per tunnel (the key to hand the peer).
		if len(args) >= 2 && args[1] == "public-key" {
			return c.showSecurityWireguardPublicKey()
		}
		return c.showSecurityWireguard(len(args) >= 2 && args[1] == "detail")

	case "zones":
		// #13552: split zone selectors from modifiers by the command tree,
		// irrespective of their order. The positional args[1] ladder silently
		// turned `detail trust` into an unfiltered detail dump.
		zsplit := cmdtree.SplitModifiers(
			operationalTree["show"].Children["security"].Children["zones"].Children,
			args[1:])
		if len(zsplit.Ambiguous) > 0 {
			return fmt.Errorf("ambiguous keyword %q after `show security zones`",
				zsplit.Ambiguous[0])
		}
		if len(zsplit.Extra) > 0 {
			return fmt.Errorf("unexpected argument %q: `show security zones` takes at "+
				"most one zone name", zsplit.Extra[0])
		}
		if len(zsplit.Modifiers) > 1 {
			return fmt.Errorf("`show security zones` takes one modifier, got %v", zsplit.Modifiers)
		}
		// Selector+modifier is honoured (detail view filtered by zone).
		return c.showZonesDisplay(cfg, zsplit.Has("detail"), zsplit.Selector)

	case "policies":
		// #12902: ONE position-independent parse owns admission AND
		// dispatch. Testing only args[1] for brief/detail/hit-count/global
		// while validatePolicyZoneFilter admitted them anywhere silently
		// discarded a trailing modifier (`from-zone X to-zone Y detail`)
		// and a second keyword (`brief global`); the parse below now
		// honours every admitted keyword wherever it sits and rejects the
		// combinations no view can render.
		q, err := parsePolicyShowQuery(args[1:])
		if err != nil {
			return err
		}
		fromZone, toZone, globalOnly := q.fromZone, q.toZone, q.globalOnly
		// "show security policies hit-count" — Junos-style hit count table
		if q.view == "hit-count" {
			return c.showPoliciesHitCount(cfg, fromZone, toZone)
		}
		// "show security policies detail" — expanded Junos-style detail view
		if q.view == "detail" {
			return c.showPoliciesDetail(cfg, fromZone, toZone)
		}
		brief := q.view == "brief"
		if brief {
			// Honor `set security policy-stats system-wide enable`
			// (#2008 M4 / #2118): the brief view's "Hits" column is
			// per-policy hit-count display, so it must obey the same
			// knob as the hit-count table, the gRPC/REST surfaces, and
			// the Prometheus collector. When the knob is off the column
			// reads 0 (we skip the dataplane read).
			statsEnabled := cfg.Security.PolicyStatsEnabled
			// #12901: mirror the hit-count/detail quarantine doctrine
			// (#10530/#5577) — a rule whose zone is quarantined was scrubbed
			// from the applied snapshot, so the helper will NEVER publish its
			// counter. Reading it anyway failed with
			// ErrPolicyCounterUnpublished, the Hits cell read "n/a", and the
			// trailing note blamed "not yet published by the dataplane" — a
			// wait-that-ends promise for a counter that is not coming. Such
			// rows instead carry the live-counter-unavailable disposition and
			// the zone qualifier, exactly like the hit-count twin one
			// dispatcher over.
			quarantinedZones := config.ZoneQuarantineExclusionsForConfig(cfg)
			isQuarantined := func(name string) bool {
				_, ok := quarantinedZones[name]
				return ok
			}
			qualifyZone := func(name string) string {
				if isQuarantined(name) {
					return name + " " + config.ZoneQuarantinePoliciesQualifier
				}
				return name
			}
			qualifyScopeLabel := func(zones []string, placeholder string) string {
				label := config.ScopeLabelOr(zones, placeholder)
				if len(zones) == 0 || config.IsWildcardZoneSet(zones) {
					return label
				}
				parts := strings.Fields(label)
				for i, name := range parts {
					parts[i] = qualifyZone(name)
				}
				return strings.Join(parts, " ")
			}
			// #3408: surface a per-policy counter read failure as a warning
			// AFTER all reads rather than rendering a clean "0" hits column.
			var readErr error
			// #7016: an UNPUBLISHED per-rule counter is not a read failure --
			// the helper has published nothing for that rule id yet (warm-up
			// before the first status poll, or config skew after a
			// non-abort-class apply failure). Render it "n/a" and explain it in
			// a trailing note instead of a "read failed" warning naming a fault
			// that does not exist.
			var unpublished int
			// #8177: rows whose counter was NOT read because policy-stats is
			// disabled and the rule carries no `count`. Counted separately from
			// `unpublished` because they are different facts: unpublished means
			// the helper has not reported yet, this means nobody looked.
			var statsDisabled int
			// #4344: read the whole policy set from ONE snapshot (O(P+C), one
			// brief dataplane lock) via the #3965 bulk reader instead of a
			// per-policy ReadPolicyCounters loop. Built only when the dataplane
			// is loaded; falls back to the per-policy read for dataplanes
			// without the bulk snapshot (test fakes / retired eBPF), so the
			// displayed hits are identical. cfg is the config walked below.
			var readPolicy func(uint32) (dataplane.CounterValue, error)
			if c.dp != nil && c.dp.IsLoaded() {
				readPolicy = dpuserspace.NewPolicyCounterReader(c.dp, cfg, c.dp.ReadPolicyCounters)
			}
			// Brief tabular summary
			fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
				"From", "To", "Name", "Action", "Hits")
			passes := 1
			if fromZone != "" || toZone != "" {
				passes = 3
			}
			pairFilter := policymatch.NewZonePairPolicyFilter(cfg, fromZone, toZone)
			for tier := range passes {
				for setIdx, zpp := range cfg.Security.Policies {
					// #3476: skip a nil zone-pair set (tolerant / HA-sync path).
					if zpp == nil {
						continue
					}
					if !policymatch.ZonePairPolicyAppliesToFilterPair(pairFilter, zpp.FromZone, zpp.ToZone) {
						continue
					}
					policySetID := uint32(setIdx)
					if passes > 1 && policymatch.ZonePairPolicyFilterTier(zpp.FromZone, zpp.ToZone) != tier {
						continue
					}
					for i, pol := range zpp.Policies {
						// #3476: skip a nil rule like the runtime walker does.
						if pol == nil {
							continue
						}
						action := "permit"
						switch pol.Action {
						case 1:
							action = "deny"
						case 2:
							action = "reject"
						}
						// #12901: a quarantined endpoint scrubs the whole
						// zone-pair rule; its counter is never coming, so the
						// read below (and its "not yet published" bookkeeping)
						// must not run for it.
						ruleQuarantined := isQuarantined(zpp.FromZone) || isQuarantined(zpp.ToZone)
						ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
						// Default to "0" (consistent with the hit-count table
						// and the gRPC/REST surfaces, which render 0 whenever
						// the counter is unavailable or the knob is off);
						// overwrite only on a successful gated read.
						hits := "0"
						if ruleQuarantined {
							hits = config.ZoneQuarantineLiveCountersUnavailable
						} else if (statsEnabled || pol.Count) && readPolicy != nil {
							counters, err := readPolicy(ruleID)
							switch {
							case err == nil:
								hits = fmt.Sprintf("%d", counters.Packets)
							case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
								hits = "n/a" // #7016
								unpublished++
							default:
								if readErr == nil {
									readErr = err
								}
							}
						} else if !statsEnabled && !pol.Count {
							// #8177: the "0" above was never read. Explicit rather
							// than an `else`, because the other way into this branch
							// is readPolicy == nil (dataplane not loaded), which is
							// a different fact and must not be counted here.
							statsDisabled++
						}
						fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
							qualifyZone(zpp.FromZone), qualifyZone(zpp.ToZone), pol.Name, action, hits)
					}
				}
			}
			policySetID := uint32(len(cfg.Security.Policies))
			// Global policies in brief view. #3357: a from/to-zone filter no
			// longer suppresses the globals — show the unscoped globals (every
			// transit pair; never junos-host, #12523) plus any scoped global
			// (#3148) targeting the filtered pair.
			if len(cfg.Security.GlobalPolicies) > 0 {
				for i, pol := range cfg.Security.GlobalPolicies {
					// #3476: skip a nil global rule like the runtime walker.
					if pol == nil {
						continue
					}
					// #3357: drop a scoped global for a different zone pair.
					if !policymatch.GlobalPolicyAppliesToZonePairInZones(pol.Match.FromZones, pol.Match.ToZones, fromZone, toZone, policymatch.DefinedZoneNames(cfg)) {
						continue
					}
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					// #12897: mirror the runtime scrub (#5577) — only a configured
					// side EMPTIED by quarantine drops the whole global rule; a
					// mixed scope stays enforced for its live members, so its
					// counter stays live and only the quarantined member carries
					// the qualifier in the From/To columns.
					ruleQuarantined := config.ScopedGlobalQuarantineDropped(pol.Match.FromZones, pol.Match.ToZones, quarantinedZones)
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					// Default to "0" for the same cross-surface
					// consistency reason as the zone-pair branch above.
					hits := "0"
					if ruleQuarantined {
						hits = config.ZoneQuarantineLiveCountersUnavailable
					} else if (statsEnabled || pol.Count) && readPolicy != nil {
						counters, err := readPolicy(ruleID)
						switch {
						case err == nil:
							hits = fmt.Sprintf("%d", counters.Packets)
						case errors.Is(err, dpuserspace.ErrPolicyCounterUnpublished):
							hits = "n/a" // #7016
							unpublished++
						default:
							if readErr == nil {
								readErr = err
							}
						}
					} else if !statsEnabled && !pol.Count {
						// #8177: the "0" above was never read. Explicit rather
						// than an `else`, because the other way into this branch
						// is readPolicy == nil (dataplane not loaded), which is
						// a different fact and must not be counted here.
						statsDisabled++
					}
					// #3286/#4626: a scoped global (#3148) shows its zone SET
					// in the From/To columns instead of the all-zones "*"; an
					// unscoped global still reads "*"/"*".
					briefFrom := qualifyScopeLabel(pol.Match.FromZones, "*")
					briefTo := qualifyScopeLabel(pol.Match.ToZones, "*")
					fmt.Printf("%-12s %-12s %-20s %-8s %s\n",
						briefFrom, briefTo, pol.Name, action, hits)
				}
			}
			if readErr != nil {
				fmt.Printf("warning: policy counter read failed (hit counts may be incomplete): %v\n", readErr)
			}
			if unpublished > 0 {
				fmt.Printf("note: %d policy counter(s) not yet published by the dataplane "+
					"(shown as n/a; the helper has not reported these rules yet)\n", unpublished)
			}
			// #8177: the detail/brief table renders a well-formed "0" for every
			// row when the knob is off, and an operator reads "this policy has
			// not matched" when the surface was never asked to look. Wording is
			// byte-identical to the #7776 hit-count twins so the four renderers
			// cannot drift into saying different things about one state.
			if statsDisabled > 0 {
				fmt.Printf("note: %d policy count(s) read 0 because policy-stats is disabled "+
					"system-wide, not because no traffic matched (enable with "+
					"`set security policy-stats system-wide enable`, or add `count` to an "+
					"individual policy)\n", statsDisabled)
			}
			return nil
		}

		// #14363: mirror the brief branch above / detail view — a rule whose
		// zone is quarantined was scrubbed from the applied snapshot, so its
		// zone header (and a scoped global's zone scope) must carry the
		// qualifier; otherwise the standard view presents scrubbed rules
		// as plain State: enabled live enforcement.
		quarantinedZones := config.ZoneQuarantineExclusionsForConfig(cfg)
		isQuarantined := func(name string) bool {
			_, ok := quarantinedZones[name]
			return ok
		}
		qualifyZone := func(name string) string {
			if isQuarantined(name) {
				return name + " " + config.ZoneQuarantinePoliciesQualifier
			}
			return name
		}
		qualifyScopeLabel := func(zones []string, placeholder string) string {
			label := config.ScopeLabelOr(zones, placeholder)
			if len(zones) == 0 || config.IsWildcardZoneSet(zones) {
				return label
			}
			parts := strings.Fields(label)
			for i, name := range parts {
				parts[i] = qualifyZone(name)
			}
			return strings.Join(parts, " ")
		}
		schedActive, haveSched := c.policySchedulerActiveState()
		// #3063: render the detail Index from the span-accumulated runtime
		// policy-ID namespace so it matches the RT_FLOW/event log policy ID.
		runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
		policySetID := uint32(len(cfg.Security.Policies))
		if !globalOnly {
			passes := 1
			if fromZone != "" || toZone != "" {
				passes = 3
			}
			pairFilter := policymatch.NewZonePairPolicyFilter(cfg, fromZone, toZone)
			for tier := range passes {
				for setIdx, zpp := range cfg.Security.Policies {
					// #3476: skip a nil zone-pair set (tolerant / HA-sync path).
					if zpp == nil {
						continue
					}
					if !policymatch.ZonePairPolicyAppliesToFilterPair(pairFilter, zpp.FromZone, zpp.ToZone) {
						continue
					}
					policySetID := uint32(setIdx)
					if passes > 1 && policymatch.ZonePairPolicyFilterTier(zpp.FromZone, zpp.ToZone) != tier {
						continue
					}
					// Junos format: "From zone: X, To zone: Y" header
					fmt.Printf("From zone: %s, To zone: %s\n", qualifyZone(zpp.FromZone), qualifyZone(zpp.ToZone))
					for i, pol := range zpp.Policies {
						// #3476: skip a nil rule like the runtime walker does.
						if pol == nil {
							continue
						}
						action := "permit"
						switch pol.Action {
						case 1:
							action = "deny"
						case 2:
							action = "reject"
						}
						ruleID := runtimePolicyIndex(runtimeIDs, policySetID, uint32(i))
						// Junos: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
						// #3062: a scheduler-inactive policy reports State: inactive.
						state := policyDetailState(pol.SchedulerName, schedActive, haveSched)
						fmt.Printf("  Policy: %s, State: %s, Index: %d, Scope Policy: 0, Sequence number: %d\n",
							pol.Name, state, ruleID, i+1)
						if pol.Description != "" {
							fmt.Printf("    Description: %s\n", pol.Description)
						}
						fmt.Printf("    Source addresses: %s\n",
							flatMatchAddresses(pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded))
						fmt.Printf("    Destination addresses: %s\n",
							flatMatchAddresses(pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded))
						fmt.Printf("    Applications: %s\n",
							strings.Join(pol.Match.Applications, ", "))
						actionStr := action
						// #12901: an EMPTY log block (a leniently-loaded bare
						// `then log`, #3060 — the strict commit path rejects it)
						// emits no session records and must not read as
						// logging. SessionLogModes is the SSOT the detail
						// renderers already gate on, so the standard view
						// cannot drift from them.
						if len(pol.Log.SessionLogModes()) > 0 {
							actionStr += ", log"
						}
						fmt.Printf("    Action: %s\n", actionStr)
					}
				}
			}
		}
		// Global policies. #3357: a from/to-zone filter no longer suppresses the
		// global block (only `global`-only and the unfiltered view did before) —
		// the filtered standard view must show an unscoped global (every transit
		// pair; never junos-host, #12523) and a scoped global (#3148) targeting
		// the filtered pair. When globalOnly the filter is empty so every global
		// is selected (no regression).
		if len(cfg.Security.GlobalPolicies) > 0 {
			// #3357: print the "Global policies:" header lazily so a filter that
			// selects no global does not leave a dangling empty header.
			globalHeaderPrinted := false
			for i, pol := range cfg.Security.GlobalPolicies {
				// #3476: skip a nil global rule like the runtime walker.
				if pol == nil {
					continue
				}
				// #3357: drop a scoped global for a different zone pair.
				if !policymatch.GlobalPolicyAppliesToZonePairInZones(pol.Match.FromZones, pol.Match.ToZones, fromZone, toZone, policymatch.DefinedZoneNames(cfg)) {
					continue
				}
				if !globalHeaderPrinted {
					fmt.Println("Global policies:")
					globalHeaderPrinted = true
				}
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				ruleID := runtimePolicyIndex(runtimeIDs, policySetID, uint32(i))
				// Junos global: Policy: <name>, State: enabled, Index: <N>, Scope Policy: 0, Sequence number: <N>
				// #3062: a scheduler-inactive global policy reports State: inactive.
				state := policyDetailState(pol.SchedulerName, schedActive, haveSched)
				fmt.Printf("  Policy: %s, State: %s, Index: %d, Scope Policy: 0, Sequence number: %d\n",
					pol.Name, state, ruleID, i+1)
				if pol.Description != "" {
					fmt.Printf("    Description: %s\n", pol.Description)
				}
				// #3286/#4626: render the scoped-global zone SET (#3148)
				// instead of the all-zones "any" placeholder. An unscoped
				// global still shows any/any — no regression.
				globalFromZone := qualifyScopeLabel(pol.Match.FromZones, "any")
				globalToZone := qualifyScopeLabel(pol.Match.ToZones, "any")
				fmt.Printf("    From zones: %s\n", globalFromZone)
				fmt.Printf("    To zones: %s\n", globalToZone)
				fmt.Printf("    Source addresses: %s\n",
					flatMatchAddresses(pol.Match.SourceAddresses, pol.Match.SourceAddressExcluded))
				fmt.Printf("    Destination addresses: %s\n",
					flatMatchAddresses(pol.Match.DestinationAddresses, pol.Match.DestinationAddressExcluded))
				fmt.Printf("    Applications: %s\n",
					strings.Join(pol.Match.Applications, ", "))
				actionStr := action
				// #12901: same empty-log gate as the zone-pair branch above.
				if len(pol.Log.SessionLogModes()) > 0 {
					actionStr += ", log"
				}
				fmt.Printf("    Action: %s\n", actionStr)
			}
		}
		return nil

	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			return c.showFlowSession(args[2:])
		}
		if len(args) >= 2 && args[1] == "traceoptions" {
			return c.showFlowTraceoptions()
		}
		if len(args) >= 2 && args[1] == "statistics" {
			return c.showFlowStatistics()
		}
		if len(args) == 1 {
			return c.showFlowTimeouts()
		}
		return fmt.Errorf("unknown show security flow target")

	case "screen":
		return c.handleShowScreen(args[1:])

	case "nat":
		return c.handleShowNAT(args[1:])

	case "address-book":
		return c.showAddressBook(args[1:])

	case "applications":
		return c.showApplications(args[1:])

	case "log":
		return c.showSecurityLog(args[1:])

	case "statistics":
		detail := len(args) >= 2 && args[1] == "detail"
		return c.showStatistics(detail)

	case "ipsec":
		return c.showIPsec(args[1:])

	case "ike":
		return c.showIKE(args[1:])

	case "alarms":
		return c.showSecurityAlarms(args[1:])

	case "alg":
		// Accept optional "status" subcommand
		return c.showALG()

	case "dynamic-address":
		return c.showDynamicAddress()

	case "match-policies":
		return c.showMatchPolicies(cfg, args[1:])

	case "vrrp":
		return c.showVRRP()

	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *CLI) handleShowScreen(args []string) error {
	if len(args) == 0 {
		return c.showScreen()
	}
	switch args[0] {
	case "ids-option":
		// #14687: a dangling ids-option selector must error, not widen to
		// the all-profiles listing the RBAC gate did not judge.
		if len(args) < 2 {
			return fmt.Errorf("usage: show security screen ids-option <name> [detail]")
		}
		if len(args) >= 3 && args[2] == "detail" {
			return c.showScreenIdsOptionDetail(args[1])
		}
		return c.showScreenIdsOption(args[1])
	case "statistics":
		if len(args) >= 2 && args[1] == "zone" {
			if len(args) < 3 {
				return fmt.Errorf("usage: show security screen statistics zone <zone>")
			}
			return c.showScreenStatistics(args[2])
		}
		return c.showScreenStatisticsAll()
	default:
		return c.showScreen()
	}
}

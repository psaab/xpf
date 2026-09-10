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

// isPolicyFilterKeyword reports whether tok is a leading `show security
// policies` subcommand keyword (brief/detail/hit-count/global) rather than a
// zone filter. These carry no value and are not from-zone/to-zone selectors, so
// the selector validator permits them while still rejecting a genuinely
// unrecognized token.
func isPolicyFilterKeyword(tok string) bool {
	switch tok {
	case "brief", "detail", "hit-count", "global":
		return true
	}
	return false
}

// validatePolicyZoneFilter rejects BOTH a from-zone/to-zone selector missing its
// zone value (e.g. "... from-zone trust to-zone") AND an unrecognized filter
// token (e.g. a typo'd `from-zonee`, or a stray word). The local `show security
// policies` dispatch extracts the from-zone/to-zone pair with
// parsePolicyZoneFilter and silently DROPS every other token, so a mistyped
// selector key (`from-zonee trust`) left that filter dimension empty and WIDENED
// the view to every zone — an operator could read a narrow policy set as the
// whole table (#4908 / C175-HC-116/126 cohort / #5557). Rejecting the unknown
// key here mirrors the daemon-side gRPC parseZoneFilter's default-error rule
// (pkg/grpcapi/server_show_policies_text.go). A leading subcommand keyword is
// permitted; the token following from-zone/to-zone is consumed as its value
// unconditionally.
func validatePolicyZoneFilter(args []string) error {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "from-zone", "to-zone":
			if i+1 >= len(args) || args[i+1] == "from-zone" || args[i+1] == "to-zone" {
				return fmt.Errorf("missing zone name after %q", args[i])
			}
			i++ // skip the consumed value
		default:
			if isPolicyFilterKeyword(args[i]) {
				continue
			}
			return fmt.Errorf("unrecognized filter token %q (expected from-zone/to-zone)", args[i])
		}
	}
	return nil
}

// parsePolicyZoneFilter extracts from-zone/to-zone filters from args.
func parsePolicyZoneFilter(args []string) (fromZone, toZone string) {
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "from-zone":
			fromZone = args[i+1]
		case "to-zone":
			toZone = args[i+1]
		}
	}
	return
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
func (c *CLI) printAppDetail(cfg *config.Config, appName string) {
	if appName == "any" {
		fmt.Printf("    IP protocol: 0, ALG: 0, Inactivity timeout: 0\n")
		fmt.Printf("      Source port range: [0-0]\n")
		fmt.Printf("      Destination ports: [0-0]\n")
		return
	}
	if cfg.Applications.Applications == nil {
		return
	}
	app, ok := cfg.Applications.Applications[appName]
	if !ok {
		return
	}
	proto := app.Protocol
	if proto == "" {
		proto = "0"
	}
	timeout := 0
	if app.InactivityTimeout > 0 {
		timeout = app.InactivityTimeout
	}
	algVal := "0"
	if app.ALG != "" {
		algVal = app.ALG
	}
	fmt.Printf("    IP protocol: %s, ALG: %s, Inactivity timeout: %d\n", proto, algVal, timeout)
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
		detail := false
		filterZone := ""
		if len(args) >= 2 {
			if args[1] == "detail" {
				detail = true
			} else {
				filterZone = args[1]
				if len(args) >= 3 && args[2] == "detail" {
					detail = true
				}
			}
		}
		return c.showZonesDisplay(cfg, detail, filterZone)

	case "policies":
		// Parse optional zone-pair filter: from-zone X to-zone Y
		if err := validatePolicyZoneFilter(args[1:]); err != nil {
			return err
		}
		fromZone, toZone := parsePolicyZoneFilter(args[1:])
		// "show security policies global" — only show global policies
		globalOnly := len(args) >= 2 && args[1] == "global"
		// "show security policies hit-count" — Junos-style hit count table
		if len(args) >= 2 && args[1] == "hit-count" {
			return c.showPoliciesHitCount(cfg, fromZone, toZone)
		}
		// "show security policies detail" — expanded Junos-style detail view
		if len(args) >= 2 && args[1] == "detail" {
			return c.showPoliciesDetail(cfg, fromZone, toZone)
		}
		brief := len(args) >= 2 && args[1] == "brief"
		if brief {
			// Honor `set security policy-stats system-wide enable`
			// (#2008 M4 / #2118): the brief view's "Hits" column is
			// per-policy hit-count display, so it must obey the same
			// knob as the hit-count table, the gRPC/REST surfaces, and
			// the Prometheus collector. When the knob is off the column
			// reads 0 (we skip the dataplane read).
			statsEnabled := cfg.Security.PolicyStatsEnabled
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
			policySetID := uint32(0)
			for _, zpp := range cfg.Security.Policies {
				// #3476: skip a nil zone-pair set (tolerant / HA-sync path)
				// while advancing the policy-set ID, like the runtime walker.
				if zpp == nil {
					policySetID++
					continue
				}
				if fromZone != "" && zpp.FromZone != fromZone {
					policySetID++
					continue
				}
				if toZone != "" && zpp.ToZone != toZone {
					policySetID++
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
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					// Default to "0" (consistent with the hit-count table
					// and the gRPC/REST surfaces, which render 0 whenever
					// the counter is unavailable or the knob is off);
					// overwrite only on a successful gated read.
					hits := "0"
					if (statsEnabled || pol.Count) && readPolicy != nil {
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
						zpp.FromZone, zpp.ToZone, pol.Name, action, hits)
				}
				policySetID++
			}
			// Global policies in brief view. #3357: a from/to-zone filter no
			// longer suppresses the globals — show the unscoped globals (every
			// pair) plus any scoped global (#3148) targeting the filtered pair.
			if len(cfg.Security.GlobalPolicies) > 0 {
				for i, pol := range cfg.Security.GlobalPolicies {
					// #3476: skip a nil global rule like the runtime walker.
					if pol == nil {
						continue
					}
					// #3357: drop a scoped global for a different zone pair.
					if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZones, pol.Match.ToZones, fromZone, toZone) {
						continue
					}
					action := "permit"
					switch pol.Action {
					case 1:
						action = "deny"
					case 2:
						action = "reject"
					}
					ruleID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
					// Default to "0" for the same cross-surface
					// consistency reason as the zone-pair branch above.
					hits := "0"
					if (statsEnabled || pol.Count) && readPolicy != nil {
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
					briefFrom := config.ScopeLabelOr(pol.Match.FromZones, "*")
					briefTo := config.ScopeLabelOr(pol.Match.ToZones, "*")
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

		schedActive, haveSched := c.policySchedulerActiveState()
		// #3063: render the detail Index from the span-accumulated runtime
		// policy-ID namespace so it matches the RT_FLOW/event log policy ID.
		runtimeIDs := dpuserspace.RuntimePolicyIDs(cfg)
		policySetID := uint32(0)
		if !globalOnly {
			for _, zpp := range cfg.Security.Policies {
				// #3476: skip a nil zone-pair set (tolerant / HA-sync path)
				// while advancing the policy-set ID, like the runtime walker.
				if zpp == nil {
					policySetID++
					continue
				}
				if fromZone != "" && zpp.FromZone != fromZone {
					policySetID++
					continue
				}
				if toZone != "" && zpp.ToZone != toZone {
					policySetID++
					continue
				}
				// Junos format: "From zone: X, To zone: Y" header
				fmt.Printf("From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
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
						joinDisplayAddressNames(pol.Match.SourceAddresses))
					fmt.Printf("    Destination addresses: %s\n",
						joinDisplayAddressNames(pol.Match.DestinationAddresses))
					fmt.Printf("    Applications: %s\n",
						strings.Join(pol.Match.Applications, ", "))
					actionStr := action
					if pol.Log != nil {
						actionStr += ", log"
					}
					fmt.Printf("    Action: %s\n", actionStr)
				}
				policySetID++
			}
		} else {
			// When globalOnly, still count zone-pair policy sets to get correct global ruleID base
			policySetID = uint32(len(cfg.Security.Policies))
		}
		// Global policies. #3357: a from/to-zone filter no longer suppresses the
		// global block (only `global`-only and the unfiltered view did before) —
		// the filtered standard view must show an unscoped global (every pair)
		// and a scoped global (#3148) targeting the filtered pair. When globalOnly
		// the filter is empty so every global is selected (no regression).
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
				if !policymatch.GlobalPolicyAppliesToZonePair(pol.Match.FromZones, pol.Match.ToZones, fromZone, toZone) {
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
				globalFromZone := config.ScopeLabelOr(pol.Match.FromZones, "any")
				globalToZone := config.ScopeLabelOr(pol.Match.ToZones, "any")
				fmt.Printf("    From zones: %s\n", globalFromZone)
				fmt.Printf("    To zones: %s\n", globalToZone)
				fmt.Printf("    Source addresses: %s\n",
					joinDisplayAddressNames(pol.Match.SourceAddresses))
				fmt.Printf("    Destination addresses: %s\n",
					joinDisplayAddressNames(pol.Match.DestinationAddresses))
				fmt.Printf("    Applications: %s\n",
					strings.Join(pol.Match.Applications, ", "))
				actionStr := action
				if pol.Log != nil {
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
		if len(args) < 2 {
			return c.showScreen()
		}
		if len(args) >= 3 && args[2] == "detail" {
			return c.showScreenIdsOptionDetail(args[1])
		}
		return c.showScreenIdsOption(args[1])
	case "statistics":
		if len(args) >= 2 && args[1] == "zone" && len(args) >= 3 {
			return c.showScreenStatistics(args[2])
		}
		return c.showScreenStatisticsAll()
	default:
		return c.showScreen()
	}
}

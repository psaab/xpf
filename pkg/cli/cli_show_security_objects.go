package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/feeds"
)

func (c *CLI) showAddressBook(args []string) error {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil {
		fmt.Println("No address book configured")
		return nil
	}
	ab := cfg.Security.AddressBook

	// Optional filter by name
	filterName := ""
	if len(args) > 0 {
		filterName = args[0]
	}

	if len(ab.Addresses) > 0 {
		if filterName == "" {
			fmt.Println("Addresses:")
		}
		for _, addr := range ab.Addresses {
			if addr == nil {
				// #7197: a present-but-nil *Address map value is admitted by
				// the tolerant-load / peer-sync path (#1960) — the SAME
				// nil-tolerant class #3494 codifies for AddressBook.Addresses
				// itself (compiler_validate_warn_nil_3494_test.go injects
				// "zz-nil-addr": nil as part of that contract) and the one
				// the #5221 guard above already skips for application sets.
				// Skip it rather than dereferencing addr.Name / addr.Value
				// and panicking the CLI display.
				continue
			}
			if filterName != "" && addr.Name != filterName {
				continue
			}
			fmt.Printf("  %-24s %s\n", addr.Name, addr.Value)
		}
	}

	if len(ab.AddressSets) > 0 {
		if filterName == "" {
			fmt.Println("Address sets:")
		}
		for _, as := range ab.AddressSets {
			if as == nil {
				// #7197: mirrors the #3494 nil-tolerant contract for
				// AddressBook.AddressSets ("zz-nil-set": nil in the same
				// compiler_validate_warn_nil_3494_test.go fixture) and the
				// #5221 application-set guard's shape. Skip rather than
				// dereferencing as.Name / as.Addresses / as.AddressSets.
				continue
			}
			if filterName != "" && as.Name != filterName {
				continue
			}
			var parts []string
			for _, a := range as.Addresses {
				parts = append(parts, a)
			}
			for _, s := range as.AddressSets {
				parts = append(parts, "set:"+s)
			}
			fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(parts, ", "))
			// If filtering by name, show member details. ab.Addresses is keyed
			// by address NAME, so a direct map lookup replaces the O(n*m)
			// nested scan the pre-fix code ran (an inner range over every
			// address book entry, for every member, with no early exit even
			// after a match) — #6218 item 13.
			if filterName != "" {
				for _, a := range as.Addresses {
					if addr, ok := ab.Addresses[a]; ok && addr != nil {
						fmt.Printf("    %-22s %s\n", addr.Name, addr.Value)
					}
				}
			}
		}
	}

	if filterName == "" && len(ab.Addresses) == 0 && len(ab.AddressSets) == 0 {
		fmt.Println("Address book is empty")
	}

	return nil
}

func (c *CLI) showApplications(args []string) error {
	cfg := c.store.ActiveConfig()

	// Parse sub-commands: detail, <name>
	detail := false
	filterName := ""
	for _, a := range args {
		switch a {
		case "detail":
			detail = true
		default:
			filterName = a
		}
	}

	// Helper to print application detail
	printApp := func(app *config.Application, indent string) {
		if detail || filterName != "" {
			fmt.Printf("%sApplication: %s\n", indent, app.Name)
			if app.Description != "" {
				fmt.Printf("%s  Description: %s\n", indent, app.Description)
			}
			if app.Protocol != "" {
				fmt.Printf("%s  IP protocol: %s\n", indent, app.Protocol)
			}
			if app.DestinationPort != "" {
				fmt.Printf("%s  Destination port: %s\n", indent, app.DestinationPort)
			}
			if app.SourcePort != "" {
				fmt.Printf("%s  Source port: %s\n", indent, app.SourcePort)
			}
			if app.ICMPType != nil {
				// #14365 (cf. #12903 gRPC twin, #11340): render the ICMP
				// type constraint so a type-constrained application does
				// not read identically to an unconstrained icmp one.
				fmt.Printf("%s  ICMP type: %d\n", indent, *app.ICMPType)
			}
			if app.ICMPCode != nil {
				fmt.Printf("%s  ICMP code: %d\n", indent, *app.ICMPCode)
			}
			if app.InactivityTimeoutNever {
				fmt.Printf("%s  Inactivity timeout: never\n", indent)
			} else if app.InactivityTimeout > 0 {
				fmt.Printf("%s  Inactivity timeout: %ds\n", indent, app.InactivityTimeout)
			}
			if app.ALG != "" {
				fmt.Printf("%s  ALG: %s\n", indent, app.ALG)
			}
		} else {
			port := app.DestinationPort
			if port == "" {
				port = "-"
			}
			// Match the gRPC twin's icmp-type=/icmp-code= SSOT (#12903).
			icmp := ""
			if app.ICMPType != nil {
				icmp += fmt.Sprintf(" icmp-type=%d", *app.ICMPType)
			}
			if app.ICMPCode != nil {
				icmp += fmt.Sprintf(" icmp-code=%d", *app.ICMPCode)
			}
			fmt.Printf("%s%-24s protocol: %-6s port: %s%s\n", indent, app.Name, app.Protocol, port, icmp)
		}
	}

	// User-defined applications
	if cfg != nil && len(cfg.Applications.Applications) > 0 {
		if filterName == "" {
			fmt.Println("User-defined applications:")
		}
		names := make([]string, 0, len(cfg.Applications.Applications))
		for name := range cfg.Applications.Applications {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			app := cfg.Applications.Applications[name]
			if app == nil {
				// #14365: present-but-nil application map values reach this
				// render via the tolerant-load / peer-sync path (#1960);
				// the application-set loop below (#5221) and the gRPC twin
				// (#12903) already tolerate them. Skip rather than
				// dereferencing app.Name and panicking the CLI display.
				continue
			}
			if filterName != "" && app.Name != filterName {
				continue
			}
			printApp(app, "  ")
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// User-defined application-sets
	if cfg != nil && len(cfg.Applications.ApplicationSets) > 0 {
		names := make([]string, 0, len(cfg.Applications.ApplicationSets))
		for name := range cfg.Applications.ApplicationSets {
			names = append(names, name)
		}
		sort.Strings(names)

		if filterName == "" {
			fmt.Println("Application sets:")
		}
		for _, name := range names {
			as := cfg.Applications.ApplicationSets[name]
			if as == nil {
				// #5221: a present-but-nil application-set map value is admitted
				// by the tolerant-load / peer-sync path (#1960) that the resolver
				// (#5179) already tolerates. Skip it rather than dereferencing
				// as.Name / as.Applications and panicking the CLI display.
				continue
			}
			if filterName != "" && as.Name != filterName {
				continue
			}
			if detail || filterName != "" {
				fmt.Printf("  Application set: %s\n", as.Name)
				fmt.Printf("    Members:\n")
				// #15652: expand via canonical resolver so nested sets,
				// predefined members and term-generated members render
				// protocol/port/ALG instead of raw names only.
				members := as.Applications
				if cfg != nil {
					if expanded, err := config.ExpandApplicationSet(as.Name, &cfg.Applications); err == nil && len(expanded) > 0 {
						members = expanded
					}
				}
				for _, member := range members {
					fmt.Printf("      %s\n", member)
					if filterName != "" && cfg != nil {
						if app, ok := config.ResolveApplication(member, cfg.Applications.Applications); ok && app != nil {
							printApp(app, "        ")
						}
					}
				}
			} else {
				fmt.Printf("  %-24s members: %s\n", as.Name, strings.Join(as.Applications, ", "))
			}
		}
		if filterName == "" {
			fmt.Println()
		}
	}

	// #15207 A18-01: predefined apps/sets, shadow-aware.
	if filterName != "" {
		_, userHasApp := cfgApps(cfg)[filterName]
		_, userHasSet := cfgSets(cfg)[filterName]
		if app, ok := config.PredefinedApplications[filterName]; ok && app != nil {
			if userHasApp {
				fmt.Println("Predefined application (shadowed by user definition; not in effect):")
			} else {
				fmt.Println("Predefined application:")
			}
			printApp(app, "  ")
			return nil
		}
		if set, ok := config.PredefinedApplicationSets[filterName]; ok && set != nil {
			if userHasSet {
				fmt.Println("Predefined application set (shadowed by user definition; not in effect):")
			} else {
				fmt.Println("Predefined application set:")
			}
			fmt.Printf("  Application set: %s\n", set.Name)
			fmt.Printf("    Members:\n")
			for _, m := range set.Applications {
				fmt.Printf("      %s\n", m)
				if app, ok := config.ResolveApplication(m, cfgApps(cfg)); ok && app != nil {
					printApp(app, "        ")
				}
			}
			return nil
		}
		return nil
	}
	fmt.Println("Predefined applications:")
	names := make([]string, 0, len(config.PredefinedApplications))
	for n := range config.PredefinedApplications {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		app := config.PredefinedApplications[n]
		if app == nil {
			continue
		}
		printApp(app, "  ")
		if _, shadowed := cfgApps(cfg)[n]; shadowed {
			fmt.Println("    (shadowed by user definition; not in effect)")
		}
	}
	fmt.Println()
	fmt.Println("Predefined application sets:")
	setNames := make([]string, 0, len(config.PredefinedApplicationSets))
	for n := range config.PredefinedApplicationSets {
		setNames = append(setNames, n)
	}
	sort.Strings(setNames)
	for _, n := range setNames {
		set := config.PredefinedApplicationSets[n]
		if set == nil {
			continue
		}
		if detail {
			fmt.Printf("  Application set: %s\n", set.Name)
			fmt.Printf("    Members:\n")
			for _, m := range set.Applications {
				fmt.Printf("      %s\n", m)
			}
		} else {
			fmt.Printf("  %-24s members: %s\n", set.Name, strings.Join(set.Applications, ", "))
		}
		if _, shadowed := cfgSets(cfg)[n]; shadowed {
			fmt.Println("    (shadowed by user definition; not in effect)")
		}
	}
	return nil
}

func cfgApps(cfg *config.Config) map[string]*config.Application {
	if cfg == nil {
		return nil
	}
	return cfg.Applications.Applications
}
func cfgSets(cfg *config.Config) map[string]*config.ApplicationSet {
	if cfg == nil {
		return nil
	}
	return cfg.Applications.ApplicationSets
}

func (c *CLI) showDynamicAddress() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	// Get runtime feed status if available.
	var runtimeFeeds map[string]feeds.FeedInfo
	if c.feedsFn != nil {
		runtimeFeeds = c.feedsFn()
	}
	renderDynamicAddress(os.Stdout, cfg, runtimeFeeds)
	return nil
}

// renderDynamicAddress writes the `show security dynamic-address` body.
//
// #9689: the show surface must agree with what is enforced.
//   - An omitted hold-interval RETAINS last-good indefinitely (the feeds code
//     and the schema's own description). This used to print a 7200s default
//     that nothing applied.
//   - A feed dropped by its hold-interval, or serving a stale last-good set, is
//     reported as such.
//   - Each binding reports what the dataplane is enforcing for it, mirroring
//     feeds.Manager.SnapshotForBindings: current or stale prefixes; an empty or
//     partial set under `fail-mode drop`; or unresolved, in which case policies
//     referencing it are rejected and the previous-good policy set stays
//     enforced.
//
// It takes an io.Writer so the rows can be asserted without a configstore.
func renderDynamicAddress(w io.Writer, cfg *config.Config, runtimeFeeds map[string]feeds.FeedInfo) {
	if len(cfg.Security.DynamicAddress.FeedServers) == 0 {
		fmt.Fprintln(w, "No dynamic address feeds configured")
		return
	}

	fmt.Fprintln(w, "Dynamic Address Feed Servers:")
	serverNames := make([]string, 0, len(cfg.Security.DynamicAddress.FeedServers))
	for name := range cfg.Security.DynamicAddress.FeedServers {
		serverNames = append(serverNames, name)
	}
	sort.Strings(serverNames)
	for _, name := range serverNames {
		fs := cfg.Security.DynamicAddress.FeedServers[name]
		updateInt := fs.UpdateInterval
		if updateInt == 0 {
			updateInt = 3600
		}
		fmt.Fprintf(w, "  Feed Server: %s\n", name)
		if fs.URL != "" {
			// Redact embedded basic-auth userinfo / query-string token before
			// printing to the on-box console (#5521).
			fmt.Fprintf(w, "    URL: %s\n", config.RedactURL(fs.URL))
		}
		if fs.FeedName != "" {
			fmt.Fprintf(w, "    Feed name: %s\n", fs.FeedName)
		}
		fmt.Fprintf(w, "    Update interval: %d seconds\n", updateInt)
		if fs.HoldInterval > 0 {
			fmt.Fprintf(w, "    Hold interval:   %d seconds, then the last-good set is dropped\n", fs.HoldInterval)
		} else {
			fmt.Fprintf(w, "    Hold interval:   none (last-good set retained indefinitely)\n")
		}

		runtimeNames := dynamicAddressFeedNames(name, fs)
		minOld := fs.ShrinkGuardMinOldCount
		minRetain := fs.ShrinkGuardMinRetainPercent
		minDrop := fs.ShrinkGuardMinDrop
		if len(runtimeNames) > 0 {
			if fi, ok := runtimeFeeds[runtimeNames[0]]; ok {
				if fi.ShrinkGuardMinOldCount > 0 {
					minOld = fi.ShrinkGuardMinOldCount
				}
				if fi.ShrinkGuardMinRetainPercent > 0 {
					minRetain = fi.ShrinkGuardMinRetainPercent
				}
				if fi.ShrinkGuardMinDrop > 0 {
					minDrop = fi.ShrinkGuardMinDrop
				}
			}
		}
		if minOld < 1 || minOld > config.MaxDynamicAddressFeedPrefixes {
			minOld = config.DefaultDynamicAddressShrinkGuardMinOldCount
		}
		if minRetain < 1 || minRetain > 100 {
			minRetain = config.DefaultDynamicAddressShrinkGuardRetainPct
		}
		if minDrop < 1 || minDrop >= config.MaxDynamicAddressFeedPrefixes {
			minDrop = config.DefaultDynamicAddressShrinkGuardMinDrop
		}
		fmt.Fprintf(w, "    Shrink guard: high-water >= %d prefixes; refuse candidates below %d%% of baseline with a drop of at least %d\n",
			minOld, minRetain, minDrop)
		fmt.Fprintf(w, "    Content churn guard: installed >= %d prefixes; refuse below %d%% exact-prefix overlap\n",
			minOld, minRetain)

		for _, runtimeName := range runtimeNames {
			fi, ok := runtimeFeeds[runtimeName]
			if !ok {
				continue
			}
			indent := "    "
			if runtimeName != name || len(runtimeNames) > 1 {
				fmt.Fprintf(w, "    Feed: %s\n", runtimeName)
				indent = "      "
			}
			renderDynamicAddressFeedStatus(w, indent, fi)
		}
	}

	bindings := cfg.Security.DynamicAddress.AddressBindings
	if len(bindings) == 0 {
		return
	}
	names := make([]string, 0, len(bindings))
	for name := range bindings {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(w, "Dynamic Address Bindings:")
	for _, name := range names {
		b := bindings[name]
		if b == nil {
			continue
		}
		mode := b.FailMode
		if mode == "" {
			mode = "retain"
		}
		fmt.Fprintf(w, "  %s: feeds %s, fail-mode %s\n", name, strings.Join(b.FeedNames, ", "), mode)
		fmt.Fprintf(w, "    Enforced: %s\n", feeds.BindingEnforcement(b, runtimeFeeds))
	}
}

func (c *CLI) showALG() error {
	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("No active configuration")
		return nil
	}
	renderALG(os.Stdout, &cfg.Security.ALG)
	return nil
}

// renderALG writes the `show security alg` body.
//
// #7423 row 6: this used to print SIXTEEN rows, twelve of them hard-coded
// literals with no config behind them — eight of those claiming `Enabled` for
// ALGs (H323, MGCP, MSRPC, PPTP, RTSP, SCCP, SUNRPC, TALK) that do not exist
// anywhere in this product. `security alg` has exactly four schema children,
// and the gRPC and REST surfaces render only those four, so the fabrication
// was CLI-only.
//
// The four real ones are also reported more carefully than "Enabled". Nothing
// in the userspace dataplane does data-channel pinholing: the ALG bits reach
// exactly one consumer, `alg_type_for_session`, which stamps a tag on the
// conntrack row for `show security flow session` and nothing else. So
// "enabled" would overstate three of them, and TFTP has no `alg_type` at all —
// its wire bit is `#[allow(dead_code)]` in the Rust helper, whose own comment
// says it "has no consumer here".
//
// Failure direction is availability, not a security hole: an operator
// believing an ALG is inspecting traffic may leave a pinhole unconfigured.
//
// Deleting the ghost rows alone would have introduced a SECOND honesty defect
// in the opposite direction. `security alg <proto>` for a proto outside the
// four is ACCEPTED at commit and recorded in UnsupportedProtos (#4232), which
// drives an accepted-but-inert advisory — so an operator can have `alg h323`
// in the running config. Printing only the four would make that stanza
// invisible here, where before it at least appeared (as a fabricated
// `Enabled`). Those protos are therefore rendered too, marked as what they
// are, which is also what makes the closing note true.
//
// It takes an io.Writer rather than printing directly so the rows can be
// asserted without a configstore round-trip.
func renderALG(w io.Writer, alg *config.ALGConfig) {
	fmt.Fprintln(w, "ALG Status:")

	printALG := func(name, status string) {
		fmt.Fprintf(w, "  %-9s: %s\n", name, status)
	}
	for _, proto := range config.ALGModeledProtos() {
		printALG(config.ALGDisplayName(proto), config.ALGStatusText(proto, alg.ALGDisabled(proto)))
	}
	for _, proto := range alg.ALGUnmodeledConfigured() {
		printALG(config.ALGDisplayName(proto), config.ALGStatusUnmodeled())
	}
	fmt.Fprintln(w, "  (DNS, FTP, SIP and TFTP are the only ALGs this product models)")
}
func dynamicAddressFeedNames(server string, fs *config.FeedServer) []string {
	if fs == nil {
		return []string{server}
	}
	if len(fs.FeedEntries) > 0 {
		names := make([]string, 0, len(fs.FeedEntries))
		seen := make(map[string]struct{}, len(fs.FeedEntries))
		for _, entry := range fs.FeedEntries {
			if entry.Name == "" {
				continue
			}
			if _, ok := seen[entry.Name]; ok {
				continue
			}
			seen[entry.Name] = struct{}{}
			names = append(names, entry.Name)
		}
		if len(names) > 0 {
			return names
		}
	}
	if fs.FeedName != "" {
		return []string{fs.FeedName}
	}
	return []string{server}
}

func renderDynamicAddressFeedStatus(w io.Writer, indent string, fi feeds.FeedInfo) {
	fmt.Fprintf(w, "%sPrefixes: %d\n", indent, fi.Prefixes)
	if !fi.LastFetch.IsZero() {
		age := time.Since(fi.LastFetch).Truncate(time.Second)
		fmt.Fprintf(w, "%sLast fetch: %s (%s ago)\n", indent, fi.LastFetch.Format("2006-01-02 15:04:05"), age)
	} else {
		fmt.Fprintf(w, "%sLast fetch: never\n", indent)
	}
	switch {
	case fi.HoldDropped:
		fmt.Fprintf(w, "%sHOLD-DROPPED: fetches failed past the hold interval; the last-good set was dropped\n", indent)
	case !fi.StaleSince.IsZero():
		fmt.Fprintf(w, "%sSTALE since %s: fetches failing; last-good set retained\n", indent, fi.StaleSince.Format("2006-01-02 15:04:05"))
	}
	if fi.PublicationDebt {
		published := fi.PublishedHash
		if !fi.HasPublished {
			published = "none"
		}
		fmt.Fprintf(w, "%sPUBLICATION-DEBT: installed snapshot sha256=%s was not confirmed applied; last published sha256=%s (dataplane may still enforce the previous-good snapshot)\n",
			indent, fi.Hash, published)
	}
	if fi.ShrinkRefusalCount > 0 {
		fmt.Fprintf(w, "%sShrink refusals: %d\n", indent, fi.ShrinkRefusalCount)
	}
	if fi.ShrinkGuardHighWaterCount > 0 {
		fmt.Fprintf(w, "%sShrink high-water baseline: %d prefixes sha256=%s\n",
			indent, fi.ShrinkGuardHighWaterCount, fi.ShrinkGuardHighWaterHash)
	}
	if fi.ShrinkRefused {
		if fi.Hash != "" {
			fmt.Fprintf(w, "%sInstalled snapshot sha256=%s\n", indent, fi.Hash)
		}
		fmt.Fprintf(w, "%sSHRINK-HELD: candidate %d prefixes vs guard baseline %d; refusal #%d; candidate_sha256=%s baseline_sha256=%s\n",
			indent, fi.ShrinkCandidateNewCount, fi.ShrinkCandidateOldCount,
			fi.ShrinkRefusalID, fi.ShrinkCandidateHash, fi.ShrinkBaselineHash)
		if fi.ShrinkCandidateReason != "" {
			fmt.Fprintf(w, "%sGuard reason: %s\n", indent, fi.ShrinkCandidateReason)
		}
		if fi.ShrinkAckPending {
			fmt.Fprintf(w, "%sSHRINK-ACKED: exact candidate #%d awaiting next fetch\n", indent, fi.ShrinkRefusalID)
			fmt.Fprintf(w, "%s  Acked candidate_sha256=%s baseline_sha256=%s by %s; reason: %q\n",
				indent, fi.ShrinkAckHash, fi.ShrinkAckBaselineHash, fi.ShrinkAckActor, fi.ShrinkAckReason)
		} else {
			fmt.Fprintf(w, "%sSHRINK-HELD: requires authorized acknowledgement with a reason\n", indent)
		}
	}
	if fi.Degraded {
		fmt.Fprintf(w, "%sDEGRADED: %d invalid line(s) skipped (partial set installed)\n", indent, fi.InvalidLines)
		if len(fi.InvalidSample) > 0 {
			fmt.Fprintf(w, "%s  Sample: %s\n", indent, strings.Join(fi.InvalidSample, ", "))
		}
	}
}

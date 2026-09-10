package config

import "fmt"

// #9525: the tolerant load / HA peer-sync path (lenientApplicationSpecs,
// #2142) downgrades the application spec, syntax and structure gates to
// warnings so a persisted or peer-synced config still boots (#1960). The
// documented contract of that downgrade is that "a leniently-loaded bad app is
// inert rather than silently mis-matching", because the userspace expansion
// refuses what it cannot represent. That held only for the drops the expansion
// could SEE: an unparsable port, an unresolvable or missing protocol. Every
// other gate member left a well-formed-looking term on the wire that matched
// something other than what was authored, and PolicyContentRejectionReasons
// stayed empty:
//
//   - a destination-port on a protocol with no L4 ports never matches, so a
//     referencing deny never fires (#3373);
//   - a source-port on icmp/icmpv6 is compared with the ICMP query Identifier,
//     a value the SENDER chooses, so a deny fires for some senders only;
//   - a malformed icmp-type/icmp-code is dropped and the term matches every
//     type or every code (#3348, UnknownICMP);
//   - an icmp field on a non-ICMP protocol, or an icmp-code without a type,
//     is refused by the helper (#3712 InvalidApplicationIcmpFields) while the
//     Go mirror certified a concrete verdict;
//   - a value-taking match leaf with no value is dropped with its constraint,
//     widening the term (#6564 / #8339);
//   - conflicting values of one match leaf keep only the last (#3366 / #6766);
//   - a direct match body mixed with `term` blocks is discarded (#3366).
//
// ApplicationReferenceMatchDrops names those drops so the expansion refuses the
// reference and the policy lowers to the #3261 __unsupported__ sentinel: the
// helper rejects the whole snapshot (a running node keeps its previous one)
// and the mirror names the application.
//
// Deliberately NOT a drop here: an UNRECOGNIZED statement (UnknownDirectLeaves,
// UnknownTermLeaves, an application-set's UnknownMembers). #6524's
// TestStrayStatementDoesNotDisarmSiblingLeaves decided that a stray statement
// must leave an otherwise well-formed application armed on the tolerant path;
// that decision is not overridden here. Nor are the settings leaves below
// (a bad or conflicting timeout or alg), which do not change what matches.

// applicationMatchLeaves9525 names the value-taking application leaves whose
// value decides WHICH packets a term matches; applicationSettingLeaves9525
// names the ones that only tune a session already matched. Together they
// partition valueTakingApplicationLeaves (bound by
// TestApplicationLeafPartition9525), so a new value-taking leaf cannot be added
// without being classified.
var applicationMatchLeaves9525 = map[string]bool{
	"protocol":         true,
	"destination-port": true,
	"source-port":      true,
	"icmp-type":        true,
	"icmp-code":        true,
}

var applicationSettingLeaves9525 = map[string]bool{
	"inactivity-timeout": true,
	"timeout":            true,
	"alg":                true,
}

// ApplicationMatchDrops returns why the match compiled for app differs from the
// match its configuration authored. Empty means the compiled term is the
// authored one (or the expansion already refuses it for another reason).
func ApplicationMatchDrops(app *Application) []string {
	if app == nil {
		return nil
	}
	var out []string
	proto := app.Protocol
	if proto != "" && !protocolIsPortBearing(proto) {
		if app.DestinationPort != "" {
			out = append(out, fmt.Sprintf(
				"destination-port %q on protocol %q, which presents no destination port, so the term never matches",
				app.DestinationPort, proto))
		}
		if app.SourcePort != "" {
			if protocolIsICMPFamily(proto) {
				out = append(out, fmt.Sprintf(
					"source-port %q on protocol %q, which the dataplane compares with the sender-chosen ICMP query Identifier",
					app.SourcePort, proto))
			} else {
				out = append(out, fmt.Sprintf(
					"source-port %q on protocol %q, which presents no source port, so the term never matches",
					app.SourcePort, proto))
			}
		}
	}
	for _, tok := range app.UnknownICMP {
		out = append(out, fmt.Sprintf(
			"icmp-type/icmp-code %q is not an integer in 0..255 and was dropped, leaving the term unconstrained", tok))
	}
	if proto != "" && (app.ICMPType != nil || app.ICMPCode != nil) && !protocolIsICMPFamily(proto) {
		out = append(out, fmt.Sprintf(
			"icmp-type/icmp-code on non-ICMP protocol %q, so the term never matches", proto))
	}
	if app.ICMPCode != nil && app.ICMPType == nil {
		out = append(out, "icmp-code without icmp-type")
	}
	out = appendMatchLeafDrops9525(out, app.IncompleteDirectLeaves,
		"statement %q is missing its value, so its constraint was dropped")
	out = appendMatchLeafDrops9525(out, app.IncompleteTermLeaves,
		"term statement %q is missing its value, so its constraint was dropped")
	out = appendMatchLeafDrops9525(out, app.DuplicateDirectLeaves,
		"conflicting %q values, of which only the last is enforced")
	out = appendMatchLeafDrops9525(out, app.DuplicateTermLeaves,
		"conflicting %q values inside a term, of which only the last is enforced")
	return out
}

func appendMatchLeafDrops9525(out, leaves []string, format string) []string {
	for _, leaf := range leaves {
		if applicationMatchLeaves9525[leaf] {
			out = append(out, fmt.Sprintf(format, leaf))
		}
	}
	return out
}

// ApplicationReferenceMatchDrops resolves a policy's `match application` name
// the way the userspace expansion does (an application first, else an
// application-set, through nested sets) and returns every drop on that path,
// each prefixed with the application that carries it: ApplicationMatchDrops for
// every application reached, and, for every application-set reached, a direct
// match body the compiler discarded because the same application also defined
// `term` blocks (MixedDirectTermApps).
func ApplicationReferenceMatchDrops(name string, apps *ApplicationsConfig) []string {
	if apps == nil || name == "" || name == "any" {
		return nil
	}
	var out []string
	seenApps := make(map[string]bool)
	addApp := func(appName string, app *Application) {
		if seenApps[appName] {
			return
		}
		seenApps[appName] = true
		for _, d := range ApplicationMatchDrops(app) {
			out = append(out, fmt.Sprintf("application %q: %s", appName, d))
		}
	}
	if app, ok := ResolveApplication(name, apps.Applications); ok {
		addApp(name, app)
		return out
	}
	mixed := make(map[string]bool, len(apps.MixedDirectTermApps))
	for _, n := range apps.MixedDirectTermApps {
		mixed[n] = true
	}
	seenSets := make(map[string]bool)
	var walkSet func(setName string, depth int)
	walkSet = func(setName string, depth int) {
		// Past the expansion's own nesting limit the expansion already fails.
		if depth > 3 || seenSets[setName] {
			return
		}
		seenSets[setName] = true
		if mixed[setName] {
			out = append(out, fmt.Sprintf(
				"application %q: its direct match body was discarded because it also defines term blocks",
				setName))
		}
		set, ok := lookupApplicationSet(setName, apps.ApplicationSets)
		if !ok {
			return
		}
		for _, member := range set.Applications {
			if memberIsNestedSet(member, apps) {
				walkSet(member, depth+1)
				continue
			}
			if app, found := ResolveApplication(member, apps.Applications); found {
				addApp(member, app)
			}
		}
	}
	walkSet(name, 0)
	return out
}

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
// An UNRECOGNIZED statement (UnknownDirectLeaves, UnknownTermLeaves, an
// application-set's UnknownMembers) is a drop only on the structural line
// #9595 draws (application_unknown_statement_9595.go): a constraint-shaped
// value on an application that is otherwise protocol-wide, or a misspelled set
// member that names a real application. #6524's stray statement beside a
// well-formed match stays armed. The settings leaves below (a bad or
// conflicting timeout or alg) are not drops either; they do not change what
// matches.

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
	if reason := unknownStatementProtocolWide9595(app); reason != "" {
		out = append(out, reason)
	}
	if reason := unimplementedJunosApplicationLeaf9603(app); reason != "" {
		out = append(out, reason)
	}
	return out
}

// ApplicationMatchWidened reports whether the match compiled for app is
// WIDER than the match its configuration authored — the subset of
// ApplicationMatchDrops that lost a constraint rather than retaining an
// unsatisfiable one. A dropped value-less leaf, a malformed icmp-type, a
// conflicting duplicate (only the last value kept), a discarded direct
// body, an unrecognized constraint-shaped statement on a protocol-wide
// application, and an unimplemented Junos match leaf (#9603) all leave the
// compiled term matching traffic the authored term did not. The remaining
// drops (a port on a protocol presenting no such port, an icmp field on a
// non-ICMP protocol, an icmp-code without a type) retain a constraint the
// dataplane cannot satisfy, so the term never matches; refusing a POLICY
// reference is still correct there (#9525), but an identification catalog
// must not treat the app as widened merely because its retained port can
// never match — the catalog row for such an app already matches nothing.
//
// pkg/appid (#14355) uses this predicate: a widened application compiles
// to a protocol-wide shape and would stamp every session of its protocol,
// so BuildCatalog and the tuple fallback keep it inert, while a
// never-matching application (e.g. `protocol 0 destination-port 80`,
// #4008) keeps its faithful catalog row.
func ApplicationMatchWidened(app *Application) bool {
	if app == nil {
		return false
	}
	// Each arm mirrors one widening member of ApplicationMatchDrops; the
	// never-matching members (a retained port on a protocol presenting no
	// such port, an icmp field on a non-ICMP protocol) are deliberately
	// absent. Leaf arms reuse the match-leaf filter so a settings leaf
	// (timeout/alg) never counts as widening.
	if len(app.UnknownICMP) > 0 {
		return true
	}
	if app.ICMPCode != nil && app.ICMPType == nil {
		return true
	}
	for _, leaves := range [][]string{
		app.IncompleteDirectLeaves, app.IncompleteTermLeaves,
		app.DuplicateDirectLeaves, app.DuplicateTermLeaves,
	} {
		if len(appendMatchLeafDrops9525(nil, leaves, "%q")) > 0 {
			return true
		}
	}
	if unknownStatementProtocolWide9595(app) != "" {
		return true
	}
	return unimplementedJunosApplicationLeaf9603(app) != ""
}

func appendMatchLeafDrops9525(out, leaves []string, format string) []string {
	for _, leaf := range leaves {
		if applicationMatchLeaves9525[leaf] {
			out = append(out, fmt.Sprintf(format, leaf))
		}
	}
	return out
}

// applicationReferenceCollisionAction controls what a caller does after a
// collision is reported while walking an application reference.
type applicationReferenceCollisionAction uint8

const (
	applicationReferenceContinue applicationReferenceCollisionAction = iota
	applicationReferenceStop
)

// walkApplicationReference visits collisions, sets and applications using the
// same precedence and depth bound as application-set expansion. The top-level
// token resolves application-first; members use memberIsNestedSet so a user
// set wins over a same-named predefined application. Nested member collisions
// are reported before deciding whether the member names a set or application.
// seenSets is global to this walk and is never cleared on return: collision
// status is path-independent, and every set body is visited at most once.
func walkApplicationReference(
	name string,
	apps *ApplicationsConfig,
	onCollision func(kind, setName, member string) applicationReferenceCollisionAction,
	onApplication func(name string, app *Application),
	onSet func(name string),
	onSetMembers func(name string, set *ApplicationSet),
) {
	if apps == nil || name == "" || name == "any" {
		return
	}
	if _, collision := apps.CollidingNames[name]; collision {
		onCollision("reference", name, "")
		return
	}
	if app, ok := ResolveApplication(name, apps.Applications); ok {
		if onApplication != nil {
			onApplication(name, app)
		}
		return
	}

	seenSets := make(map[string]bool)
	var walkSet func(setName string, depth int) bool
	walkSet = func(setName string, depth int) bool {
		// Past the expansion's own nesting limit the expansion already fails.
		if depth > 3 {
			return false
		}
		if seenSets[setName] {
			return false
		}
		seenSets[setName] = true
		if onSet != nil {
			onSet(setName)
		}
		set, ok := lookupApplicationSet(setName, apps.ApplicationSets)
		if !ok {
			return false
		}
		if onSetMembers != nil {
			onSetMembers(setName, set)
		}
		for _, member := range set.Applications {
			if _, collision := apps.CollidingNames[member]; collision {
				if onCollision("member", setName, member) == applicationReferenceStop {
					return true
				}
				continue
			}
			if memberIsNestedSet(member, apps) {
				if walkSet(member, depth+1) {
					return true
				}
				continue
			}
			if onApplication != nil {
				if app, found := ResolveApplication(member, apps.Applications); found {
					onApplication(member, app)
				}
			}
		}
		return false
	}
	walkSet(name, 0)
}

// applicationReferenceCollides reports whether an application reference reaches
// a colliding name. It uses the same bounded set-first member walk as
// ApplicationReferenceMatchDrops and the junos-host projection.
func applicationReferenceCollides(name string, apps *ApplicationsConfig) bool {
	if apps == nil || len(apps.CollidingNames) == 0 {
		return false
	}
	collides := false
	walkApplicationReference(name, apps, func(_, _, _ string) applicationReferenceCollisionAction {
		collides = true
		return applicationReferenceStop
	}, nil, nil, nil)
	return collides
}

// ApplicationReferenceMatchDrops resolves a top-level policy `match
// application` token application-first, then as an application-set. Within a
// set, members follow `memberIsNestedSet` precedence, matching expansion. It
// returns every drop on the path, each prefixed with the application that
// carries it: ApplicationMatchDrops for every application reached and, for
// each application-set reached, a direct match body the compiler discarded
// because the same application also defined `term` blocks (MixedDirectTermApps).
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
	mixed := make(map[string]bool, len(apps.MixedDirectTermApps))
	for _, n := range apps.MixedDirectTermApps {
		mixed[n] = true
	}
	walkApplicationReference(name, apps, func(kind, setName, member string) applicationReferenceCollisionAction {
		switch kind {
		case "reference":
			out = append(out, fmt.Sprintf("application %q: its name is ambiguous due to a collision", setName))
			return applicationReferenceStop
		default:
			out = append(out, fmt.Sprintf("application-set %q: member %q has an ambiguous colliding name", setName, member))
			return applicationReferenceContinue
		}
	}, addApp, func(setName string) {
		if mixed[setName] {
			out = append(out, fmt.Sprintf(
				"application %q: its direct match body was discarded because it also defines term blocks",
				setName))
		}
	}, func(setName string, set *ApplicationSet) {
		for _, ref := range unknownMemberReferences9595(set, apps) {
			out = append(out, fmt.Sprintf(
				"application-set %q: an unrecognized member statement names %q, which resolves as an application, so the set is missing a member",
				setName, ref))
		}
	})
	return out
}

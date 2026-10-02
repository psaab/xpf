package cmdtree

// #8058: the ShowText topic <-> operational command correspondence, owned here
// so it exists ONCE.
//
// ── IF YOU ARE ABOUT TO WRITE THIS DOWN SOMEWHERE ELSE, DON'T ───────────
//
// This fact used to live twice, on opposite sides of a trust boundary: the
// remote `cli` binary turned a command into a topic (client-side, nested
// switches over args[N]), and pkg/grpcapi turned a topic back into a command
// for deny-commands matching (server-side). Nothing made them agree. A topic
// re-attributed to a different command on one side left the other pricing an
// authorization decision against a command string no operator could type.
//
// It lives in cmdtree for the same reason cos_filter_topic.go does: the package
// is already the SSOT for "the same command means the same thing on the local
// CLI, the remote CLI, and gRPC", and BOTH surfaces already import it. Both now
// read this table, so a divergence is not a bug to be caught by a mirrored test
// table — it is unrepresentable.
//
// An agreement test was the obvious alternative and it cannot be made sound.
// Recovering the command that reaches each topic needs an AST walk of the
// client's nested switches, and 18 of these topics are COMPUTED at their call
// sites rather than written as literals, so a literal scan certifies the
// majority and reports clean on the rest with nothing in its output
// distinguishing the two. Measured at the time of the move: a literal scan of
// cmd/cli sees 104 of the 123 base topics. That is existence standing in for
// coverage.
//
// ── WHY BOTH SIDES IMPORTING THIS IS NOT A TRUST VIOLATION ──────────────
//
// The server must never import the CLIENT's table — an authorization decision
// cannot derive from client-side data. Both sides importing a leaf is not that.
// This is a compile-time constant in the daemon binary that no client can
// influence at runtime, and the server already derives authz input from this
// package: #8057 canonicalizes every entry against Canonicalize. If importing
// cmdtree were a trust violation, that would already be one.
//
// ── WHAT MAKES AN ENTRY CORRECT ─────────────────────────────────────────
//
// Every value must be a command that Canonicalize resolves TO ITSELF — a real,
// already-canonical operational command. pkg/grpcapi machine-checks that
// (#8057, which caught 12 hand-authored errors) and pins this key set against
// its own ShowText dispatcher in both directions. Those checks stay where they
// are: they are properties of the SERVER's dispatcher, and this file is the
// data they check.
//
// A key ending in ':' is the PREFIX form of a parameter-packed topic, spelled
// exactly as the dispatcher spells it. Prefix keys are deliberately EXCLUDED
// from the command -> topic direction: a command like `show class-of-service
// classifier` keys both the bare topic and its prefix form, so the reverse
// lookup would be ambiguous. Those 18 topics are built by explicit encoders at
// their call sites (see CoSNameTypeTopic in cos_filter_topic.go for the shape).
// Among the bare keys the reverse map is one-to-one, and
// TestShowTextTopicReverseMapIsUnambiguous_8058 keeps it that way.

import (
	"strings"
	"sync"
)

var showTextTopicCommand = map[string]string{
	// `show security ...`
	"address-book":     "show security address-book",
	"alg":              "show security alg",
	"applications":     "show security applications",
	"dynamic-address":  "show security dynamic-address",
	"ike":              "show security ike",
	"ipsec-statistics": "show security ipsec statistics",
	"security-alarms":  "show security alarms",
	// `detail` is a keyword child, so this is a longer real command rather
	// than the same path with an argument.
	"security-alarms-detail": "show security alarms detail",
	"security-log":           "show security log",
	"zones-detail":           "show security zones detail",
	"wireguard":              "show security wireguard",
	"wireguard-detail":       "show security wireguard detail",
	"wireguard-public-key":   "show security wireguard public-key",

	// `show security flow ...`. The bare `show security flow` renders the
	// configured timeouts, which is why the topic is named for the render and
	// the command is not.
	"flow-timeouts":        "show security flow",
	"flow-statistics":      "show security flow statistics",
	"flow-traceoptions":    "show security flow traceoptions",
	"sessions-top:bytes":   "show security flow session sort-by bytes",
	"sessions-top:packets": "show security flow session sort-by packets",

	// `show security policies ...`. The from-zone/to-zone selectors travel in
	// the request's FILTER field, not the topic, so these paths are complete.
	"policies-detail":    "show security policies detail",
	"policies-hit-count": "show security policies hit-count",

	// `show security screen ...`. The two ids-option topics differ by a
	// `detail` keyword that follows the option NAME, so the common
	// argument-free prefix is the same for both.
	"screen":                    "show security screen",
	"screen-ids-option:":        "show security screen ids-option",
	"screen-ids-option-detail:": "show security screen ids-option",
	// #8597 K47: a `request` verb served over ShowText because it produces
	// text and mutates nothing. The canonical command is the one the operator
	// types, not a `show` spelling that does not exist.
	"policies-check": "request security policies check",

	"screen-statistics-all": "show security screen statistics",
	"screen-statistics:":    "show security screen statistics zone",

	// `show security nat ...`
	"nat-static":             "show security nat static",
	"nat-nptv6":              "show security nat nptv6",
	"nat64":                  "show security nat nat64",
	"nat-source-rule-detail": "show security nat source rule detail",
	"nat-dest-rule-detail":   "show security nat destination rule detail",
	"persistent-nat":         "show security nat source persistent-nat-table",
	"persistent-nat-detail":  "show security nat source persistent-nat-table detail",

	// `show chassis ...`
	"chassis":                       "show chassis",
	"chassis-environment":           "show chassis environment",
	"chassis-forwarding":            "show chassis forwarding",
	"chassis-hardware":              "show chassis hardware",
	"chassis-device-map":            "show chassis device-map",
	"chassis-device-map-candidates": "show chassis device-map candidates",

	// `show chassis cluster ...`
	"chassis-cluster":                          "show chassis cluster",
	"chassis-cluster-status":                   "show chassis cluster status",
	"chassis-cluster-interfaces":               "show chassis cluster interfaces",
	"chassis-cluster-information":              "show chassis cluster information",
	"chassis-cluster-statistics":               "show chassis cluster statistics",
	"chassis-cluster-control-plane-statistics": "show chassis cluster control-plane statistics",
	"chassis-cluster-data-plane-statistics":    "show chassis cluster data-plane statistics",
	"chassis-cluster-data-plane-interfaces":    "show chassis cluster data-plane interfaces",
	"chassis-cluster-data-plane-fairness":      "show chassis cluster data-plane fairness",
	"chassis-cluster-data-plane-flows":         "show chassis cluster data-plane flows",
	"chassis-cluster-fabric-statistics":        "show chassis cluster fabric statistics",
	"chassis-cluster-ip-monitoring-status":     "show chassis cluster ip-monitoring status",

	// `show class-of-service ...`. The bare `class-of-service` topic is the
	// unfiltered `interface` view, NOT the umbrella command — cmd/cli emits it
	// only from `case "interface"`.
	"class-of-service":     "show class-of-service interface",
	"class-of-service:":    "show class-of-service interface",
	"cos-classifier":       "show class-of-service classifier",
	"cos-classifier:":      "show class-of-service classifier",
	"cos-rewrite-rule":     "show class-of-service rewrite-rule",
	"cos-rewrite-rule:":    "show class-of-service rewrite-rule",
	"cos-scheduler-map":    "show class-of-service scheduler-map",
	"cos-scheduler-map:":   "show class-of-service scheduler-map",
	"cos-forwarding-class": "show class-of-service forwarding-class",

	// `show system ...`
	"alarms":              "show system alarms",
	"backup-router":       "show system backup-router",
	"bootstrap-import":    "show system bootstrap-import",
	"buffers":             "show system buffers",
	"buffers-detail":      "show system buffers detail",
	"commit-history":      "show system commit history",
	"core-dumps":          "show system core-dumps",
	"internet-options":    "show system internet-options",
	"kernel-upgrade":      "show system kernel-upgrade",
	"login":               "show system login",
	"ntp":                 "show system ntp",
	"root-authentication": "show system root-authentication",
	"storage":             "show system storage",
	"system-services":     "show system services",
	"system-syslog":       "show system syslog",

	// `show interfaces ...`. `tunnels` is the odd one: the command keyword is
	// singular (`tunnel`), the topic is plural.
	"interfaces-detail":     "show interfaces detail",
	"interfaces-extensive":  "show interfaces extensive",
	"interfaces-statistics": "show interfaces statistics",
	"interfaces-queue":      "show interfaces queue",
	"interfaces-queue:":     "show interfaces queue",
	"tunnels":               "show interfaces tunnel",

	// `show route ...`. `route-all` is the bare `show route`; `route-prefix:`
	// is the same command with a destination in a value slot, so it resolves
	// to the same argument-free path.
	"route-all":       "show route",
	"route-fib":       "show route fib",
	"route-prefix:":   "show route",
	"route-detail":    "show route detail",
	"route-instance":  "show route instance",
	"route-protocol:": "show route protocol",
	"route-summary":   "show route summary",
	"route-table:":    "show route table",
	"route-terse":     "show route terse",

	// `show firewall ...`. `firewall-effective-filter:` is
	// `show firewall filter <name> effective`, whose argument-free prefix stops
	// at the filter name — the same prefix as `firewall-filter:`.
	"firewall":                   "show firewall",
	"firewall-effective":         "show firewall effective",
	"firewall-effective:":        "show firewall effective",
	"firewall-filter:":           "show firewall filter",
	"firewall-effective-filter:": "show firewall filter",

	// `show services ...`
	"rpm":                               "show services rpm",
	"services-dynamic-dns":              "show services dynamic-dns",
	"services-dynamic-dns-detail":       "show services dynamic-dns detail",
	"services-ip-monitoring-status":     "show services ip-monitoring status",
	"application-identification-status": "show services application-identification status",

	// `show dhcp-server ...` / `show dhcp-relay`
	"dhcp-relay":                     "show dhcp-relay",
	"dhcp-server":                    "show dhcp-server",
	"dhcp-server-detail":             "show dhcp-server detail",
	"dhcp-server-dynamic-dns":        "show dhcp-server dynamic-dns",
	"dhcp-server-dynamic-dns-detail": "show dhcp-server dynamic-dns detail",

	// Top-level `show ...` singletons.
	"bfd-peers":                         "show protocols bfd peers",
	"event-options":                     "show event-options",
	"flow-monitoring":                   "show flow-monitoring",
	"flow-monitoring-statistics":        "show flow-monitoring statistics",
	"forwarding-options":                "show forwarding-options",
	"forwarding-options-port-mirroring": "show forwarding-options port-mirroring",
	"ipv6-router-advertisement":         "show ipv6 router-advertisement",
	"lldp":                              "show lldp",
	"lldp-neighbors":                    "show lldp neighbors",
	"log":                               "show log",
	"log:":                              "show log",
	"monitor-security-flow":             "show monitor security flow",
	"policy-options":                    "show policy-options",
	"route-map":                         "show route-map",
	"routing-instances":                 "show routing-instances",
	"routing-instances-detail":          "show routing-instances detail",
	"routing-options":                   "show routing-options",
	"schedulers":                        "show schedulers",
	"snmp":                              "show snmp",
	"snmp-v3":                           "show snmp v3",
	"task":                              "show task",
	"version":                           "show version",
	"vlans":                             "show vlans",

	// The `test ...` family. These are the three topics that are NOT a `show`,
	// which is the same distinction showTextElevatedTopics prices at
	// PermControl — and getting it wrong there is how a read-only class briefly
	// held policy reconnaissance (#5278). The topic name is not the command:
	// `test-zone:` is `test security-zone`.
	"test-policy:":  "test policy",
	"test-routing:": "test routing",
	"test-zone:":    "test security-zone",
}

// ShowTextTopicCommands returns the topic -> canonical command table.
//
// The returned map is a COPY: callers hold it for the life of the process
// (pkg/grpcapi assigns it once at package init) and must not be able to mutate
// the SSOT out from under the other surface.
func ShowTextTopicCommands() map[string]string {
	out := make(map[string]string, len(showTextTopicCommand))
	for topic, command := range showTextTopicCommand {
		out[topic] = command
	}
	return out
}

// CommandForShowTextTopic returns the canonical operational command that emits
// a ShowText topic. This is the direction pkg/grpcapi needs: it holds a decoded
// topic and must price it against deny-commands.
func CommandForShowTextTopic(topic string) (string, bool) {
	command, ok := showTextTopicCommand[topic]
	return command, ok
}

var showTextCommandTopic = sync.OnceValue(func() map[string]string {
	// Bare keys only — see the prefix-form note in this file's header. A
	// prefix key shares its command with the bare form, so including them
	// would make this lookup depend on map iteration order.
	out := make(map[string]string, len(showTextTopicCommand))
	for topic, command := range showTextTopicCommand {
		if strings.HasSuffix(topic, ":") {
			continue
		}
		out[command] = topic
	}
	return out
})

// ShowTextTopicForCommand returns the ShowText topic that a canonical
// operational command emits. This is the direction the remote `cli` binary
// needs: it knows the command the operator typed and must name a topic to send.
//
// Naming the COMMAND at the call site rather than the topic is what removes the
// second transcription. The command is self-evident where it is written — it is
// the switch arm the reader is already looking at — while a topic string is an
// encoding detail that has to be looked up somewhere to be checked.
//
// Reports ok=false for a command with no topic, which callers must treat as a
// programming error rather than falling back to a guessed topic: a guess is how
// the client would start disagreeing with the server again.
func ShowTextTopicForCommand(command string) (string, bool) {
	topic, ok := showTextCommandTopic()[command]
	return topic, ok
}

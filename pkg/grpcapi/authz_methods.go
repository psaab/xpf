package grpcapi

import (
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// authz_methods.go is the method -> required-permission table the #5278
// interceptor consults, plus the SystemAction verb table underneath it.
//
// # Where the numbers come from
//
// Every entry mirrors what pkg/cli/permissions.go requiredPermission charges
// for the COMMAND that reaches the RPC, so the server and the CLI cannot
// disagree about what an action costs:
//
//	show / ping / traceroute / monitor  -> PermView
//	clear                               -> PermClear
//	request / test                      -> PermControl
//	configure                           -> PermConfig
//	request system {reboot,halt,power-off,zeroize},
//	request system software in-service-upgrade,
//	request chassis cluster failover    -> PermMaint
//
// The mapping is command-shaped rather than verb-shaped on purpose. `ShowConfig`
// is PermView because `show configuration` is a `show`, not because reading
// config feels safe: config-viewer and read-only are exactly the classes Junos
// gives that reach, and #4051/#4099 already redact secrets on this render path
// unconditionally. `CommitCheck` is PermConfig because it reads a candidate a
// caller must already have held the configure permission to stage.
//
// TWO methods are multiplexed and cannot be priced by their name alone —
// `SystemAction` by its action verb and `ShowText` by its topic, each of which
// spans more than one command family. Both are priced from the DECODED request
// (a unary interceptor is handed it), and the name-level entry for each is the
// FLOOR used when the request cannot be read. Their tables get their own
// completeness guards, because a complete METHOD table says nothing about
// whether a verb or a topic was classified.
//
// # Fail closed
//
// A method absent from this table is charged unmappedMethodPermission, which no
// class but super-user holds, and the miss is logged at Error. That is the
// weaker half of the guarantee; the strong half is
// TestEveryServiceMethodHasAPermission_5278, which enumerates the generated
// SERVICE DESCRIPTOR and fails the build in BOTH directions — a new RPC with no
// entry, and a stale entry naming no RPC. Enumerating the descriptor rather
// than a hand-written list is the point: a guard that compares literals a human
// typed against a count the same human typed cannot fire (the shape caught in
// pkg/dataplane/userspace/ingress_exclusions.go).

// unmappedMethodPermission is what an unmapped method costs: PermAll, which
// only `super-user` holds.
//
// It is not a blanket denial, and the difference is deliberate. Denying uid 0
// would be theater under the shipped pkg/authz contract — root owns the config
// DB on disk and the daemon process — and it would turn a missing table row
// into a totally dead RPC rather than a restricted one. Every class the issue
// is about (read-only, operator, config-viewer, a custom class, an account
// outside the login model) is denied.
const unmappedMethodPermission = config.PermAll

// methodPermissions prices every RPC on BpfrxService by its SHORT method name.
// The key set is pinned to the generated descriptor in both directions by
// TestEveryServiceMethodHasAPermission_5278.
var methodPermissions = map[string]config.LoginClassPermission{
	// --- Config lifecycle: `configure` and everything inside it. -----------
	"EnterConfigure":  config.PermConfig,
	"ExitConfigure":   config.PermConfig,
	"Set":             config.PermConfig,
	"Delete":          config.PermConfig,
	"Load":            config.PermConfig,
	"Commit":          config.PermConfig,
	"CommitCheck":     config.PermConfig,
	"CommitConfirmed": config.PermConfig,
	"ConfirmCommit":   config.PermConfig,
	"Rollback":        config.PermConfig,

	// Config RENDER paths. `show configuration`, `show | compare`, `show system
	// rollback` and `show system commit` are all `show` in the CLI's table, and
	// the raw-AST render redacts secrets unconditionally (#4051/#4099).
	//
	// The PermView below is the FLOOR, not the whole price, for the two RPCs
	// that can render uncommitted configuration: the candidate-read gate
	// (authz_config_target_9324.go, charged in authorizeRPC beside the coarse
	// check) additionally requires PermConfig for ShowConfig with a CANDIDATE
	// target (#9324) and for ShowCompare on both arms (#9889).
	"ShowConfig":   config.PermView,
	"ShowCompare":  config.PermView,
	"ShowRollback": config.PermView,
	"ListHistory":  config.PermView,

	// --- Operational show RPCs: the `show` family. -------------------------
	"GetConfigModeStatus":      config.PermView,
	"GetStatus":                config.PermView,
	"GetGlobalStats":           config.PermView,
	"GetZones":                 config.PermView,
	"GetPolicies":              config.PermView,
	"GetSessions":              config.PermView,
	"GetSessionSummary":        config.PermView,
	"GetZonePairSummary":       config.PermView,
	"GetNATSource":             config.PermView,
	"GetNATDestination":        config.PermView,
	"GetScreen":                config.PermView,
	"GetEvents":                config.PermView,
	"GetInterfaces":            config.PermView,
	"ShowInterfacesDetail":     config.PermView,
	"GetDHCPLeases":            config.PermView,
	"GetDHCPClientIdentifiers": config.PermView,
	"GetRoutes":                config.PermView,
	"GetOSPFStatus":            config.PermView,
	"GetBGPStatus":             config.PermView,
	"GetRIPStatus":             config.PermView,
	"GetISISStatus":            config.PermView,
	"GetIPsecSA":               config.PermView,
	"GetNATPoolStats":          config.PermView,
	"GetNATRuleStats":          config.PermView,
	"GetNATDeterministic":      config.PermView,
	"GetVRRPStatus":            config.PermView,
	"MatchPolicies":            config.PermView, // `show security match-policies`
	"GetSystemInfo":            config.PermView,
	// ShowText multiplexes ~127 topics across TWO command families. The entry
	// here is the FLOOR for a request whose topic the gate cannot read; a
	// decoded request is priced by showTextTopicPermission below. The floor is
	// the highest tier any topic needs, so an unreadable request cannot buy a
	// cheaper one.
	"ShowText": config.PermControl,

	// --- Diagnostics: `ping` / `traceroute` are view-tier verbs on Junos and
	// in the CLI's own table, despite being state-changing-looking streams.
	"Ping":       config.PermView,
	"Traceroute": config.PermView,

	// --- Monitor streams: the `monitor` family is view-tier. The two verbs the
	// CLI elevates to PermControl — `monitor traffic` (a root tcpdump, #4067)
	// and `monitor security flow file|start` (a root-privileged on-disk trace
	// write, #5038) — are NOT reachable through either of these RPCs: neither
	// spawns a capture nor opens a trace file. MonitorPacketDrop is the
	// terminal-only drop stream and MonitorInterface is interface statistics,
	// both of which the CLI itself gates at PermView.
	"MonitorPacketDrop": config.PermView,
	"MonitorInterface":  config.PermView,

	// --- Mutations: the `clear` family. ------------------------------------
	"ClearSessions":             config.PermClear,
	"ClearCounters":             config.PermClear,
	"ClearDHCPClientIdentifier": config.PermClear,

	// --- Tab completion. Completion answers "what could I type here", which is
	// a read of the command tree and (for config-mode value slots) of config
	// the same class may already `show`. View-tier, so a read-only operator
	// keeps a usable CLI; the `unauthorized` class, which holds nothing, loses
	// it along with everything else.
	"Complete": config.PermView,

	// --- The multiplexed system-action verb. The entry here is the FLOOR for a
	// request the interceptor cannot inspect; a decoded request is priced by
	// systemActionPermission below. See methodPermission.
	"SystemAction": config.PermMaint,
}

// systemActionPermissions prices each SystemAction verb the way the CLI prices
// the command that sends it.
//
// SystemAction is one RPC multiplexing three very different permission tiers,
// and folding it up to its destructive floor — which is what pkg/api's REST
// gate must do, because that middleware deliberately never decodes a request
// body — would take `clear arp`, `clear system config-lock`, `request protocols
// bgp clear` and `request dhcp renew` away from the `operator` class that holds
// them today. A unary gRPC interceptor is handed the DECODED request, so the
// verb is available without buffering anything the caller controls.
//
// The key set is pinned to the handler's own switch by
// TestEverySystemActionVerbHasAPermission_5278, which reads the case labels out
// of server_diag_system_action.go rather than from a list typed here.
var systemActionPermissions = map[string]config.LoginClassPermission{
	// Destructive maintenance. `operator` deliberately lacks PermMaint on
	// Junos and here (#4108 F21).
	"reboot":             config.PermMaint,
	"halt":               config.PermMaint,
	"power-off":          config.PermMaint,
	"zeroize":            config.PermMaint,
	"in-service-upgrade": config.PermMaint, // drains this node to secondary (#4859)

	// The `clear ...` family: `clear system config-lock`, `clear arp`,
	// `clear interfaces statistics`, `clear ipv6 neighbors`, and the counter
	// clears — all reached from cmd/cli/clear.go, i.e. parts[0] == "clear".
	"clear-config-lock":           config.PermClear,
	"clear-arp":                   config.PermClear,
	"clear-interfaces-statistics": config.PermClear,
	"clear-ipv6-neighbors":        config.PermClear,
	"clear-policy-counters":       config.PermClear,
	"clear-firewall-counters":     config.PermClear,
	"clear-nat-counters":          config.PermClear,
	"clear-persistent-nat":        config.PermClear,

	// The `request ...` family that is not maintenance: these are sent from
	// cmd/cli/request.go (`request protocols ospf|bgp clear`, `request security
	// ipsec sa clear`, `request dhcp renew`, `request system dynamic-dns
	// update|check`), i.e. parts[0] == "request" without a maintenance verb.
	"ospf-clear":         config.PermControl,
	"bgp-clear":          config.PermControl,
	"ipsec-sa-clear":     config.PermControl,
	"dhcp-renew":         config.PermControl,
	"dynamic-dns-update": config.PermControl,
	"dynamic-dns-check":  config.PermControl,
	// #8597 K47: `request system configuration rescue save|delete`. Explicit
	// rather than left to the PermMaint default, because pkg/cli charges
	// PermControl — an absent entry would make the remote surface STRICTER
	// than the console, which is the same parity defect in the other
	// direction.
	"rescue-save":   config.PermControl,
	"rescue-delete": config.PermControl,
}

// systemActionPermission prices one SystemAction verb.
//
// An action absent from the table costs PermMaint. That covers the PREFIX-form
// verbs the handler's default branch parses — `cluster-failover*` (#5810) and
// the `userspace-*` dataplane control forms — and any verb added in future.
//
// For cluster-failover that is exactly right: `request chassis cluster failover`
// is PermMaint in the CLI too. For the `userspace-*` forms it OVER-restricts by
// one tier in one direction, and the trade is stated rather than hidden: the
// CLI charges PermMaint for the destructive halves (`disarm`, `unregister`,
// `inject-packet`) and PermControl for the restorative ones (`arm`,
// `register`), so an `operator` loses the ability to RE-ARM a binding over
// gRPC. Recovering that one tier would mean re-implementing three argument
// parsers (ParseForwardingCommand / ParseQueueCommand / ParseBindingCommand)
// inside the authorization gate, where a parse that disagreed with the
// handler's would be a bypass rather than a cosmetic bug. Over-restricting a
// deep dataplane-diagnostic verb to super-user is the cheaper error.
func systemActionPermission(action string) config.LoginClassPermission {
	if p, ok := systemActionPermissions[action]; ok {
		return p
	}
	return config.PermMaint
}

// methodPermission returns the permission a full gRPC method requires, and
// whether the method was found in the table at all.
//
// req is the DECODED request for a unary call and nil for a stream. It is read
// for exactly one method: SystemAction, whose verb selects the tier. A
// SystemAction whose request is missing or of an unexpected type falls back to
// the methodPermissions entry (PermMaint, the destructive floor) — the same
// answer pkg/api's body-agnostic gate gives, reached only when the verb cannot
// be seen.
func methodPermission(fullMethod string, req any) (config.LoginClassPermission, bool) {
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return unmappedMethodPermission, false
	}
	perm, mapped := methodPermissions[method]
	if !mapped {
		return unmappedMethodPermission, false
	}
	switch method {
	case systemActionMethodName:
		if sa, isAction := req.(*pb.SystemActionRequest); isAction && sa != nil {
			return systemActionPermission(sa.GetAction()), true
		}
	case showTextMethodName:
		if st, isShow := req.(*pb.ShowTextRequest); isShow && st != nil {
			// An unknown topic reports mapped=false so the interceptor logs
			// the miss, exactly as an unknown METHOD does.
			return showTextTopicPermission(st.GetTopic())
		}
	}
	return perm, true
}

// systemActionMethodName is the one method whose permission depends on its
// request. Named rather than spelled inline so the two places that care about
// it (methodPermission and the verb-table completeness test) cannot drift.
const systemActionMethodName = "SystemAction"

// ShowText is the SECOND multiplexed method on this service, and the first
// revision of this file got it wrong: it was priced flat at PermView with the
// comment "every topic is a `show ...`". That is false. Three topics are
// emitted by the top-level word `test`, which pkg/cli/permissions.go charges at
// PermControl:
//
//	cmd/cli `test policy ...`         -> "test-policy:from=...,to=..."
//	cmd/cli `test routing ...`        -> "test-routing:dest=..."
//	cmd/cli `test security-zone ...`  -> "test-zone:interface=..."
//
// `test policy` is policy reconnaissance — it answers which rule matches a
// given 5-tuple — so a read-only class reaching it is exactly the tier
// confusion this file exists to prevent. Not a regression (before #5278 a
// read-only caller had everything), but the file asserted an invariant that
// did not hold, which is worse than an acknowledged gap.
//
// The completeness guard that DID pass is the reason it survived:
// TestEveryServiceMethodHasAPermission_5278 enumerates the service descriptor,
// i.e. METHODS. Topic pricing is a different property, so a complete method
// table is a VACUOUS pass for it. A guard proves the property it enumerates and
// nothing adjacent to it. Hence the sibling guard,
// TestEveryShowTextTopicHasAPermission_5278, which enumerates the topic
// literals out of the dispatcher in server_show.go.

// showTextElevatedTopics prices the topics that cost MORE than the `show`
// family's view tier. A key ending in ':' is a PREFIX rule (the topic is a
// delimiter-packed parameter string); any other key is an exact topic.
var showTextElevatedTopics = map[string]config.LoginClassPermission{
	// #8597 K47: a `request` verb, not a `show` one. pkg/cli charges the
	// `request` family's PermControl for `request security policies check`
	// (it is not in requestSubcommandIsMaintenance's destructive set), so
	// pricing it at the view tier here would make the remote surface LOOSER
	// than the console.
	"policies-check": config.PermControl,

	"test-policy:":  config.PermControl,
	"test-routing:": config.PermControl,
	"test-zone:":    config.PermControl,
}

// showTextViewTopics is every OTHER topic the ShowText dispatcher serves — all
// of them reached from a `show ...` command. It is a hand-written list that is
// machine-checked against production source in both directions
// (TestEveryShowTextTopicHasAPermission_5278 parses server_show.go), which is
// what makes it a coverage claim rather than an assertion of good intent. Keys
// ending in ':' are prefix rules, exactly as above.
//
// #6496: "bootstrap-import" sits here at PermView, matching the coarse model
// the rest of `show` uses (PermView gates every show command) and matching
// "login" below, which renders login configuration at the same level. Its
// error detail is withheld from /health because that endpoint is
// UNAUTHENTICATED (#5031) — a different distinction from privilege level;
// every caller reaching here has authenticated.
var showTextViewTopics = map[string]bool{
	"address-book":                      true,
	"alarms":                            true,
	"alg":                               true,
	"application-identification-status": true,
	"applications":                      true,
	"backup-router":                     true,
	"bfd-peers":                         true,
	"bootstrap-import":                  true,
	"buffers":                           true,
	"buffers-detail":                    true,
	"chassis":                           true,
	"chassis-cluster":                   true,
	"chassis-cluster-control-plane-statistics": true,
	"chassis-cluster-data-plane-fairness":      true,
	"chassis-cluster-data-plane-flows":         true,
	"chassis-cluster-data-plane-interfaces":    true,
	"chassis-cluster-data-plane-statistics":    true,
	"chassis-cluster-fabric-statistics":        true,
	"chassis-cluster-information":              true,
	"chassis-cluster-interfaces":               true,
	"chassis-cluster-ip-monitoring-status":     true,
	"chassis-cluster-statistics":               true,
	"chassis-cluster-status":                   true,
	"chassis-device-map":                       true,
	"chassis-device-map-candidates":            true,
	"chassis-environment":                      true,
	"chassis-forwarding":                       true,
	"chassis-hardware":                         true,
	"class-of-service":                         true,
	"class-of-service:":                        true,
	"commit-history":                           true,
	"core-dumps":                               true,
	"cos-classifier":                           true,
	"cos-classifier:":                          true,
	"cos-forwarding-class":                     true,
	"cos-rewrite-rule":                         true,
	"cos-rewrite-rule:":                        true,
	"cos-scheduler-map":                        true,
	"cos-scheduler-map:":                       true,
	"dhcp-relay":                               true,
	"dhcp-server":                              true,
	"dhcp-server-detail":                       true,
	"dhcp-server-dynamic-dns":                  true,
	"dhcp-server-dynamic-dns-detail":           true,
	"dynamic-address":                          true,
	"event-options":                            true,
	"firewall":                                 true,
	"firewall-effective":                       true,
	"firewall-effective-filter:":               true,
	"firewall-effective:":                      true,
	"firewall-filter:":                         true,
	"flow-monitoring":                          true,
	"flow-monitoring-statistics":               true,
	"flow-statistics":                          true,
	"flow-timeouts":                            true,
	"flow-traceoptions":                        true,
	"forwarding-options":                       true,
	"forwarding-options-port-mirroring":        true,
	"ike":                                      true,
	"interfaces-detail":                        true,
	"interfaces-extensive":                     true,
	"interfaces-queue":                         true,
	"interfaces-queue:":                        true,
	"interfaces-statistics":                    true,
	"internet-options":                         true,
	"ipsec-statistics":                         true,
	"ipv6-router-advertisement":                true,
	"kernel-upgrade":                           true,
	"lldp":                                     true,
	"lldp-neighbors":                           true,
	"log":                                      true,
	"log:":                                     true,
	"login":                                    true,
	"monitor-security-flow":                    true,
	"nat-dest-rule-detail":                     true,
	"nat-nptv6":                                true,
	"nat-source-rule-detail":                   true,
	"nat-static":                               true,
	"nat64":                                    true,
	"ntp":                                      true,
	"persistent-nat":                           true,
	"persistent-nat-detail":                    true,
	"policies-detail":                          true,
	"policies-hit-count":                       true,
	"policy-options":                           true,
	"root-authentication":                      true,
	"route-all":                                true,
	"route-detail":                             true,
	"route-instance":                           true,
	"route-map":                                true,
	"route-prefix:":                            true,
	"route-protocol:":                          true,
	"route-summary":                            true,
	"route-table:":                             true,
	"route-terse":                              true,
	"routing-instances":                        true,
	"routing-instances-detail":                 true,
	"routing-options":                          true,
	"rpm":                                      true,
	"schedulers":                               true,
	"screen":                                   true,
	"screen-ids-option-detail:":                true,
	"screen-ids-option:":                       true,
	"screen-statistics-all":                    true,
	"screen-statistics:":                       true,
	"security-alarms":                          true,
	"security-alarms-detail":                   true,
	"security-log":                             true,
	"services-dynamic-dns":                     true,
	"services-dynamic-dns-detail":              true,
	"services-ip-monitoring-status":            true,
	"sessions-top:bytes":                       true,
	"sessions-top:packets":                     true,
	"snmp":                                     true,
	"snmp-v3":                                  true,
	"storage":                                  true,
	"system-services":                          true,
	"system-syslog":                            true,
	"task":                                     true,
	"tunnels":                                  true,
	"version":                                  true,
	"vlans":                                    true,
	"wireguard":                                true,
	"wireguard-detail":                         true,
	"wireguard-public-key":                     true,
	"zones-detail":                             true,
}

// showTextPrefixRule is one prefix-keyed topic rule, pre-resolved at init so
// the lookup is deterministic: rules are sorted longest-key-first, so an
// unambiguous longest match wins rather than whichever key map iteration
// reached first. TestShowTextPrefixRulesAreUnambiguous_5278 additionally
// asserts no rule is a prefix of another, so the ordering never has to
// arbitrate a genuine overlap.
type showTextPrefixRule struct {
	prefix string
	perm   config.LoginClassPermission
}

var (
	showTextExact  = map[string]config.LoginClassPermission{}
	showTextPrefix []showTextPrefixRule
)

func init() {
	add := func(key string, perm config.LoginClassPermission) {
		if strings.HasSuffix(key, ":") {
			showTextPrefix = append(showTextPrefix, showTextPrefixRule{key, perm})
			return
		}
		showTextExact[key] = perm
	}
	for k, p := range showTextElevatedTopics {
		add(k, p)
	}
	for k := range showTextViewTopics {
		add(k, config.PermView)
	}
	sort.Slice(showTextPrefix, func(i, j int) bool {
		if len(showTextPrefix[i].prefix) != len(showTextPrefix[j].prefix) {
			return len(showTextPrefix[i].prefix) > len(showTextPrefix[j].prefix)
		}
		return showTextPrefix[i].prefix < showTextPrefix[j].prefix
	})
}

// showTextTopicPermission prices one ShowText topic.
//
// An UNKNOWN topic costs unmappedMethodPermission — the strictest tier, not the
// view floor — for the same reason an unmapped METHOD does: a topic nobody
// priced is a topic nobody classified, and the dispatcher's own answer for it
// is InvalidArgument anyway, so the strict default costs a super-user-only
// error message rather than access. ok=false reports the miss so the caller can
// log it.
func showTextTopicPermission(topic string) (config.LoginClassPermission, bool) {
	if p, ok := showTextExact[topic]; ok {
		return p, true
	}
	for _, r := range showTextPrefix {
		if strings.HasPrefix(topic, r.prefix) {
			return r.perm, true
		}
	}
	return unmappedMethodPermission, false
}

// showTextMethodName is the second method whose permission depends on its
// request. See systemActionMethodName.
const showTextMethodName = "ShowText"

package grpcapi

import (
	"strings"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/optopic"
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
	// GetStatus / GetConfigModeStatus are session plumbing probes priced
	// at PermView and exempt from the deny/allow-commands regex gate
	// (#15077); they are not the `show version` command.
	"GetConfigModeStatus": config.PermView,
	"GetStatus":           config.PermView,
	"GetGlobalStats":      config.PermView,
	"GetZones":            config.PermView,
	"GetPolicies":         config.PermView,
	"GetSessions":         config.PermView,
	"GetSessionSummary":   config.PermView,
	"GetZonePairSummary":  config.PermView,
	"GetNATSource":        config.PermView,
	"GetNATDestination":   config.PermView,
	"GetScreen":           config.PermView,
	"GetEvents":           config.PermView,
	// #14709: the D11 ledger documents "uid 0 or the configured super-user
	// class" and its handler enforces PermAll; pricing it PermMaint here
	// would let a maintenance-only custom class through the interceptor
	// to a handler that must then deny it — and any future handler that
	// trusted the coarse gate would be a bypass. Price matches handler.
	"GetD11AttestationLedger":  config.PermAll,
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
	// #11077: one price for one simulator. MatchPolicies runs the identical
	// verdict as ShowText test-policy:, which this file prices at PermControl
	// (policy reconnaissance gated from read-only classes + CLI `test`-family
	// parity). Pricing this surface at PermView let a read-only caller dial
	// past the control tier, so it costs PermControl too.
	"MatchPolicies": config.PermControl, // `show security match-policies`
	"GetSystemInfo": config.PermView,
	// #17095: typed equivalent of `show chassis cluster` — the
	// ShowText topics chassis-cluster* are PermView in pkg/optopic,
	// so the typed channel costs the same.
	"GetClusterHAState": config.PermView,
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

	// --- Tab completion. Operational completion answers "what could I type
	// here" from the command tree, which is a view-tier read, so a read-only
	// operator keeps a usable CLI; the `unauthorized` class, which holds
	// nothing, loses it along with everything else.
	//
	// #14952: that price is only the FLOOR. A ConfigMode=true request
	// completes configuration-mode lines (`set security …`) from the active
	// configuration, which is a configure-mode activity: methodPermission
	// charges PermConfig for that arm (mirroring how #9324 charges the
	// candidate arm of a PermView-priced RPC), so a view-only principal
	// denied `show configuration` cannot enumerate the configuration by
	// flipping the mode bit. Operational completion stays PermView.
	"Complete": config.PermView,

	// --- The multiplexed system-action verb. The entry here is the FLOOR for a
	// request the interceptor cannot inspect; a decoded request is priced by
	// systemActionPermission below. See methodPermission.
	"SystemAction": config.PermMaint,
}

// systemActionPermissions is now a view onto the optopic registry
// (#16136): exact SystemAction verbs with their price, derived from
// optopic.SystemActionEntries. Retained as a named map because the
// completeness tests and the REST/CLI parity readers address it by that
// name; it is built once from the registry, never hand-edited. Add or
// reprice a verb in pkg/optopic, not here.
//
// SystemAction is one RPC multiplexing three very different permission
// tiers, and folding it up to its destructive floor — which is what
// pkg/api's REST gate must do, because that middleware deliberately never
// decodes a request body — would take `clear arp`, `clear system
// config-lock`, `request protocols bgp clear` and `request dhcp renew`
// away from the `operator` class that holds them today. A unary gRPC
// interceptor is handed the DECODED request, so the verb is available
// without buffering anything the caller controls.
//
// The key set is pinned to the handler's own switch by the census in
// authz_registry_census_16136_test.go, which reads the case labels out of
// server_diag_system_action.go rather than from a list typed here or in
// the registry.
var systemActionPermissions = func() map[string]config.LoginClassPermission {
	out := make(map[string]config.LoginClassPermission)
	for _, e := range optopic.SystemActionEntries() {
		if !e.IsPrefix() {
			out[e.Key] = e.Permission
		}
	}
	return out
}()

// systemActionPermission prices one SystemAction verb (#16136: prices
// live in pkg/optopic; this is the grpcapi lookup over them).
//
// An action absent from the registry costs PermMaint. That covers the
// PREFIX-form verbs the handler's default branch parses —
// `cluster-failover*` (#5810) and the `userspace-*` dataplane control
// forms (all registered as PermMaint prefix families in optopic) — and
// any verb added in future.
//
// For cluster-failover that is exactly right: `request chassis cluster
// failover` is PermMaint in the CLI too. For the `userspace-*` forms it
// OVER-restricts by one tier in one direction, and the trade is stated
// rather than hidden: the CLI charges PermMaint for the destructive
// halves (`disarm`, `unregister`, `inject-packet`) and PermControl for
// the restorative ones (`arm`, `register`), so an `operator` loses the
// ability to RE-ARM a binding over gRPC. Recovering that one tier would
// mean re-implementing three argument parsers (ParseForwardingCommand /
// ParseQueueCommand / ParseBindingCommand) inside the authorization
// gate, where a parse that disagreed with the handler's would be a
// bypass rather than a cosmetic bug. Over-restricting a deep
// dataplane-diagnostic verb to super-user is the cheaper error.
func systemActionPermission(action string) config.LoginClassPermission {
	// #14709: the D11 attestation arm re-arms the proof-of-life authority
	// and its handler requires root or the configured super-user class.
	// It is a PREFIX verb (`userspace-attest:arm:<run>:<epoch>:<marker>`),
	// so it has no exact registry key; price it PermAll to match the
	// handler (optopic.AttestArmPermission).
	if strings.HasPrefix(action, optopic.AttestArmPrefix) {
		return optopic.AttestArmPermission
	}
	if e, ok := optopic.LookupSystemAction(action); ok {
		return e.Permission
	}
	return config.PermMaint
}

// completeMethodName is one of the request-priced methods (with
// SystemAction and ShowText): its ConfigMode bit selects the tier.
// Which methods are request-dependent is declared per method in
// methodPermission / rpcCanonicalCommand / rpcArgumentForms and, for
// streams, in streamRequestSpec17175 (#17175) — no method's
// request-dependence is singular.
const completeMethodName = "Complete"

// methodPermission returns the permission a full gRPC method requires, and
// whether the method was found in the table at all.
//
// req is the DECODED request for a unary call, the decoded first
// message for a stream (authzRecvStream, #17175), and nil only for the
// stream open-time coarse price. It is read for the request-priced
// methods: SystemAction, whose verb selects the tier, ShowText, whose
// topic selects it, and Complete (#14952), whose ConfigMode bit
// selects it. A request-priced method whose request is missing or of
// an unexpected type falls back to the methodPermissions entry — for
// Complete that is the PermView floor, reached only when the mode bit
// cannot be seen (stream open or an unreadable decode); a decoded
// ConfigMode=true request is charged PermConfig.
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
	case completeMethodName:
		// #14952: config-mode completion enumerates the configuration the
		// caller could `set`; operational completion only walks the public
		// command tree. Charge the configure tier for the former so the
		// mode bit cannot be flipped by a view-only principal to buy the
		// config-mode read at the view price.
		if cr, isComplete := req.(*pb.CompleteRequest); isComplete && cr != nil && cr.GetConfigMode() {
			return config.PermConfig, true
		}
	}
	return perm, true
}

// systemActionMethodName is one of the request-priced methods (with
// ShowText and Complete). Named rather than spelled inline so the two
// places that care about it (methodPermission and the verb-table
// completeness test) cannot drift.
const systemActionMethodName = "SystemAction"
const getSystemInfoMethodName = "GetSystemInfo"

const getBGPStatusMethodName = "GetBGPStatus"

const getNATRuleStatsMethodName = "GetNATRuleStats"

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

// showTextElevatedTopics / showTextViewTopics are views onto the optopic
// registry (#16136), retained under their historical names because the
// completeness and tier tests address them. They are derived once from
// pkg/optopic — add or reprice a topic THERE, never here. A key ending in
// ':' is a PREFIX rule (the topic is a delimiter-packed parameter string);
// any other key is an exact topic.
//
// ShowText topics are priced by the command that emits them: the `test`
// family and `policies-check` (a `request` verb served over ShowText) cost
// PermControl; every `show` topic costs PermView. See pkg/optopic for the
// per-entry provenance.
//
// #6496: "bootstrap-import" sits at PermView, matching the coarse model
// the rest of `show` uses (PermView gates every show command) and matching
// "login" below, which renders login configuration at the same level. Its
// error detail is withheld from /health because that endpoint is
// UNAUTHENTICATED (#5031) — a different distinction from privilege level;
// every caller reaching here has authenticated.
var (
	showTextElevatedTopics = func() map[string]config.LoginClassPermission {
		out := make(map[string]config.LoginClassPermission)
		for _, e := range optopic.ShowTextEntries() {
			if e.Permission != config.PermView {
				out[e.Key] = e.Permission
			}
		}
		return out
	}()
	showTextViewTopics = func() map[string]bool {
		out := make(map[string]bool)
		for _, e := range optopic.ShowTextEntries() {
			if e.Permission == config.PermView {
				out[e.Key] = true
			}
		}
		return out
	}()
)

// showTextPrefix mirrors the registry's prefix rules for the ambiguity
// census (TestShowTextPrefixRulesAreUnambiguous_5278): pre-resolved from
// pkg/optopic, longest-key-first. The registry itself panics at init on a
// shadowed prefix, so this list can never contain a genuine overlap.
var showTextPrefix = func() []showTextPrefixRule {
	entries := optopic.ShowTextEntries()
	out := make([]showTextPrefixRule, 0, len(entries))
	for _, e := range entries {
		if e.IsPrefix() {
			out = append(out, showTextPrefixRule{prefix: e.Key, perm: e.Permission})
		}
	}
	// Registry order is lexical; lookups go through optopic (which sorts
	// longest-first). Sort here too so any reader iterating this list
	// sees the resolution order.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if len(out[j].prefix) > len(out[i].prefix) ||
				(len(out[j].prefix) == len(out[i].prefix) && out[j].prefix < out[i].prefix) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}()

// showTextPrefixRule is one prefix-keyed topic rule from the registry.
type showTextPrefixRule struct {
	prefix string
	perm   config.LoginClassPermission
}

// showTextTopicPermission prices one ShowText topic (#16136: the price
// lives in pkg/optopic; this is the grpcapi lookup over it).
//
// An UNKNOWN topic costs unmappedMethodPermission — the strictest tier, not
// the view floor — for the same reason an unmapped METHOD does: a topic
// nobody priced is a topic nobody classified, and the dispatcher's own
// answer for it is InvalidArgument anyway, so the strict default costs a
// super-user-only error message rather than access. ok=false reports the
// miss so the caller can log it.
func showTextTopicPermission(topic string) (config.LoginClassPermission, bool) {
	if e, ok := optopic.LookupShowText(topic); ok {
		return e.Permission, true
	}
	return unmappedMethodPermission, false
}

// showTextMethodName is one of the request-priced methods (with
// SystemAction and Complete). See systemActionMethodName.
const showTextMethodName = "ShowText"

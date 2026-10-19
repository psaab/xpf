package grpcapi

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// authz_command_gate_7172.go is #7172 cut 5b: the command tables built in cuts
// 5a and 5a-2 are now READ, and `deny-commands` is enforced on the gRPC
// listener.
//
// It runs AFTER the #5278 coarse permission check, never instead of it — Junos
// authorizes the command family with the permission bits first and the regexes
// narrow within that, so a caller reaching here without the coarse gate has
// skipped a check rather than replaced one.
//
// ── WHAT THIS SURFACE CAN AND CANNOT MATCH ───────────────────────────────
//
// READ THIS BEFORE ASSUMING THE TWO SURFACES AGREE. They do not, the
// difference is structural rather than a bug to be fixed later, and a populated
// table is NOT evidence that they match the same thing.
//
// pkg/cli's cut-3 gate matches a deny regex against the FULL canonicalized
// line, including argument VALUES and the output pipe. This gate matches the
// canonical command PATH, because that is all the server has: the remote `cli`
// parses the line client-side and sends a typed RPC, so `ping 10.0.0.1` arrives
// as Ping{Host:"10.0.0.1"} and `show route table secret-vrf` as
// ShowText{Topic:"route-table:secret-vrf"}. The tables hold argument-free paths
// (`ping`, `show route table`) for the reason authz_command_table_topics.go
// gives: the alternative is 129 bespoke inverse decoders, each a new place the
// remote string can disagree with the on-box one, and a decoder that disagreed
// with the client's encoder would itself be the bypass.
//
// So, precisely:
//
//   - a deny written against a command PATH — `deny-commands "request system
//     reboot"`, the shape Junos' own examples use — is enforced IDENTICALLY on
//     both surfaces, because matching is partial rather than anchored.
//   - a deny written against ARGUMENT text — `deny-commands "show route table
//     secret-vrf"` — is enforced on the box and NOT here. Under #7172's
//     allow-over-deny model that is an under-deny, i.e. fail-OPEN for that
//     class of pattern.
//
// The second bullet is not left for an operator to discover. unenforceableDenyPatterns
// below MEASURES, per pattern, whether it can ever fire on this surface, and
// the answer is logged for the class. That check is exact and
// spelling-independent — it asks whether the pattern matches any command this
// surface can produce — which matters because the obvious implementation does
// not have that property: regexp.LiteralPrefix returns "" for `^show route
// table secret-vrf`, so a literal-prefix heuristic would silently cover the
// unanchored spelling and miss the ANCHORED one, which is the spelling
// Juniper's own guidance tells operators to write.
//
// ── FAIL CLOSED, AND ONLY FOR A CLASS THAT ASKED FOR IT ──────────────────
//
// Every uncertain path denies, and every one of them applies ONLY to a class
// that configured regexes. A class with none is unaffected by any of this and
// pays nothing — no lookup it would otherwise pass starts failing:
//
//   - a class whose regexes do not COMPILE denies. They are validated at
//     commit, so reaching here means a config arrived by a path that did not
//     validate.
//   - an RPC with NO canonical command denies. Not knowing which command we are
//     holding, we cannot know that a deny regex fails to match it — treating
//     "cannot resolve" as "no match, allow" is exactly the bypass the tables
//     exist to close. This covers the config-mode methods (governed by
//     deny-CONFIGURATION, not deny-commands), the four routing-status RPCs with
//     no cmdtree command, an unknown ShowText topic, and — the one a reader is
//     most likely to assume is handled — a PREFIX-FORM SystemAction verb.
//
// PREFIX-FORM VERBS ARE THE TRAP. `cluster-failover:1:node0` and the
// `userspace-*` dataplane control forms are parsed out of a packed string by
// the handler's DEFAULT branch, so they have no case label, cannot appear in
// systemActionVerbCommand, and cannot be added to it. The verb table's
// completeness guard enumerates case labels, so it is a floor over what the
// handler DISPATCHES, not a census of what it ACCEPTS. Reading a complete-looking
// table as covering them is how they would silently become allow-by-omission.
// They deny here, explicitly, by the same rule as any other unmapped verb.

// authorizeRPCCommand enforces the calling class's `deny-commands` regexes
// against the canonical command this RPC performs.
//
// Returns nil when the class configured no regexes, which is the overwhelmingly
// common case and is checked before anything else is computed.
func (s *Server) authorizeRPCCommand(cfg *config.Config, class, fullMethod string, req any) error {
	if class == "" {
		return nil
	}
	rules, ok, err := config.OperationalLoginRegexesFor(cfg, class)
	if err != nil {
		return fmt.Errorf("login class %q has an invalid command regex: %w", class, err)
	}
	if !ok {
		return nil
	}

	s.warnUnenforceableDenyPatternsOnce(class, rules)

	// #14952: Complete is listed in configModeMethods9633, but it is NOT
	// exempt from the operational gate. Unlike the other config-mode
	// RPCs it carries the typed line, so there is an operational command
	// to evaluate (`show configuration …`, or the line embedded after
	// config-mode `run`). Adjudicate it below; an unreadable request
	// denies for a restricted class.
	if isConfigModeMethod9633(fullMethod) && !isCompleteMethod(fullMethod) {
		return nil
	}
	if isCompleteMethod(fullMethod) {
		return authorizeCompleteRPCCommand(class, rules, req)
	}

	// #9633: config-mode RPCs are governed by the `*-configuration` regexes
	// (authorizeRPCConfigMutation), exactly as the on-box CLI's dispatchConfig
	// applies only checkConfigRegex. Denying them here as "no canonical command"
	// locked any class with an operational pattern out of configuration over gRPC.

	cmd, resolved := rpcCanonicalCommand(fullMethod, req)
	if !resolved {
		return fmt.Errorf(
			"login class %q restricts commands and this RPC has no canonical command to "+
				"evaluate, so the restriction cannot be applied to it", class)
	}
	if decision := rules.Evaluate(cmd); !decision.Allowed {
		return fmt.Errorf("login class %q denies %q (%s)", class, cmd, decision.Reason)
	}
	return nil
}

// isCompleteMethod reports whether fullMethod is the Complete RPC.
func isCompleteMethod(fullMethod string) bool {
	service, method, ok := splitFullMethod(fullMethod)
	return ok && service == serviceName && method == completeMethodName
}

// authorizeCompleteRPCCommand applies the class's operational
// allow/deny-commands rules to a Complete request (#14952).
//
// Unlike the other config-mode RPCs, Complete carries the typed line, so
// there IS an operational command to evaluate: the line itself. The
// handler adjudicates typed prefixes against these same rules for live
// values (completionAuth.operationalAllowed), but that only suppresses
// live candidates — the RPC itself was admitted at PermView with no
// operational verdict at all, so a class with an allow-commands
// allowlist that permits no completion line, or a deny on the bare
// `show configuration` command, still received schema candidates for a
// command it may not run. This gate is the admission verdict.
//
// The full line is adjudicated with EvaluateForms unanimity: the full
// spelling plus the bare `show configuration` alternative where spelled
// (so `^show configuration$` denies its sub-paths and an allowlist
// exception written against the full command admits the line, mirroring
// showConfigPathAllowed). Ancestor denies still fire because the deny
// regexes match the full line partially unless anchored, and an
// anchored ancestor deny is re-checked via the typed-prefix walk below
// for the deny side only. Fail closed: an unreadable request denies
// for a restricted class.
func authorizeCompleteRPCCommand(class string, rules config.CompiledLoginRegexes, req any) error {
	cr, isComplete := req.(*pb.CompleteRequest)
	if !isComplete || cr == nil {
		return fmt.Errorf(
			"login class %q restricts commands and this Complete request cannot be "+
				"read, so the restriction cannot be applied to it", class)
	}
	full, prefixes, isShowConfig := completeLineForms(cr)
	if full == "" {
		return nil
	}
	if isShowConfig {
		if decision := rules.EvaluateForms(full, "show configuration"); !decision.Allowed {
			return fmt.Errorf("login class %q denies %q (%s)", class, full, decision.Reason)
		}
	} else if decision := rules.Evaluate(full); !decision.Allowed {
		return fmt.Errorf("login class %q denies %q (%s)", class, full, decision.Reason)
	}
	// Anchored ancestor deny: `^show configuration$`-style rules do not
	// match the full line, so walk the typed prefixes for a tier denial.
	// An allowlist-only miss on a prefix does not veto (EvaluateForms
	// above already required the full line to be affirmatively allowed).
	for _, prefix := range prefixes {
		if decision := rules.Evaluate(prefix); !decision.Allowed && isTierDeny(decision) {
			return fmt.Errorf("login class %q denies %q (%s)", class, prefix, decision.Reason)
		}
	}
	return nil
}

// completeLineForms decomposes a Complete line into the full operational
// command spelling, its typed prefixes, and whether it spells
// `show configuration …`. Config-mode `run <line>` embeds a full
// operational command, so the embedded line is the full form there.
// Text after a `|` is pipe-filter text, not command text, and is dropped.
func completeLineForms(req *pb.CompleteRequest) (full string, prefixes []string, isShowConfig bool) {
	text := req.GetLine()
	if req.GetPos() >= 0 && int(req.GetPos()) < len(text) {
		text = text[:req.GetPos()]
	}
	if idx := strings.LastIndex(text, "|"); idx >= 0 {
		text = text[:idx]
	}
	words := strings.Fields(text)
	if req.GetConfigMode() && len(words) >= 2 && words[0] == "run" {
		words = words[1:]
	}
	if len(words) == 0 {
		return "", nil, false
	}
	full = strings.Join(words, " ")
	for i := 1; i < len(words); i++ {
		prefixes = append(prefixes, strings.Join(words[:i], " "))
	}
	_, isShowConfig = resolveShowConfigurationWords(words)
	return full, prefixes, isShowConfig
}

// isTierDeny reports whether a decision was denied by a deny regex
// winning/tieing the precedence tiers, as opposed to an allowlist miss.
func isTierDeny(decision config.LoginRegexDecision) bool {
	return !decision.Allowed && decision.DecidedBy == config.LoginRegexDeny
}

// rpcCanonicalCommand resolves the canonical operational command an RPC
// performs, from the three tables cuts 5a and 5a-2 built.
//
// resolved=false is a DELIBERATE answer, not a lookup failure to paper over:
// the caller denies on it for a restricted class. It covers a config-mode
// method, a method named absent in methodsWithoutCanonicalCommand, an unknown
// ShowText topic, and a SystemAction verb the handler parses in its default
// branch.
func rpcCanonicalCommand(fullMethod string, req any) (string, bool) {
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return "", false
	}
	switch method {
	case showTextMethodName:
		st, isShow := req.(*pb.ShowTextRequest)
		if !isShow || st == nil {
			// A ShowText whose request the gate cannot read. The topic selects
			// the command, so without it there is no command — deny, exactly as
			// methodPermission falls back to the strictest tier for the same
			// reason.
			return "", false
		}
		return showTextTopicCanonicalCommand(st.GetTopic())
	case systemActionMethodName:
		sa, isAction := req.(*pb.SystemActionRequest)
		if !isAction || sa == nil {
			return "", false
		}
		cmd, mapped := systemActionVerbCommand[sa.GetAction()]
		return cmd, mapped
	case getSystemInfoMethodName:
		info, isInfo := req.(*pb.GetSystemInfoRequest)
		if !isInfo || info == nil {
			return "", false
		}
		return systemInfoCanonicalCommand(info.GetType())
	case getBGPStatusMethodName:
		bgp, isBGP := req.(*pb.GetBGPStatusRequest)
		if !isBGP || bgp == nil {
			return "", false
		}
		return bgpStatusCanonicalCommand(bgp.GetType())
	case getNATRuleStatsMethodName:
		nat, isNAT := req.(*pb.GetNATRuleStatsRequest)
		if !isNAT || nat == nil {
			return "", false
		}
		return natRuleStatsCanonicalCommand(nat.GetNatType())
	}
	cmd, mapped := methodCanonicalCommand[method]
	return cmd, mapped
}

// systemInfoCanonicalCommand attributes each multiplexed system-info request
// to the operational command that dispatched it. The RPC type is server input,
// not caller-supplied command text, so restricted login classes cannot use a
// different GetSystemInfo type to evade deny-commands.
func systemInfoCanonicalCommand(infoType string) (string, bool) {
	switch infoType {
	case "uptime":
		return "show system uptime", true
	case "memory":
		return "show system memory", true
	case "processes":
		return "show system processes", true
	case "processes-summary":
		return "show system processes summary", true
	case "rescue-configuration":
		return "show system configuration rescue", true
	case "storage":
		return "show system storage", true
	case "users":
		return "show system users", true
	case "connections":
		return "show system connections", true
	case "boot-messages":
		return "show system boot-messages", true
	case "arp":
		return "show arp", true
	case "ipv6-neighbors":
		return "show ipv6 neighbors", true
	default:
		return "", false
	}
}

// bgpStatusCanonicalCommand attributes each GetBGPStatus selection to the
// `show protocols bgp …` command the remote cli line performs (#15076).
// The argument-free charge drops the neighbor IP, exactly as the other
// tables drop argument values. Unknown and `groups` selections have no
// cmdtree command and return unresolved, so a restricted class denies
// rather than receiving the summary charge.
func bgpStatusCanonicalCommand(typ string) (string, bool) {
	switch {
	case typ == "" || typ == "summary":
		return "show protocols bgp summary", true
	case typ == "routes":
		return "show protocols bgp routes", true
	case typ == "neighbor":
		return "show protocols bgp neighbor", true
	case strings.HasPrefix(typ, "neighbor:"):
		if ip := strings.TrimPrefix(typ, "neighbor:"); ip != "" && net.ParseIP(ip) != nil {
			return "show protocols bgp neighbor", true
		}
		return "", false
	case strings.HasPrefix(typ, "advertised-routes:"):
		if ip := strings.TrimPrefix(typ, "advertised-routes:"); ip != "" && net.ParseIP(ip) != nil {
			return "show protocols bgp neighbor advertised-routes", true
		}
		return "", false
	case strings.HasPrefix(typ, "received-routes:"):
		if ip := strings.TrimPrefix(typ, "received-routes:"); ip != "" && net.ParseIP(ip) != nil {
			return "show protocols bgp neighbor received-routes", true
		}
		return "", false
	default:
		return "", false
	}
}

// natRuleStatsCanonicalCommand attributes GetNATRuleStats by nat_type
// (#15076). The handler accepts only "", "source" and "destination";
// any other selector is unresolved here so a restricted class denies
// instead of receiving the source charge. The rule-set name is an
// argument value and stays dropped, exactly as the topic tables drop
// theirs — both the `rule` and `rule-set <name>` lines perform this RPC
// for the same family charge.
func natRuleStatsCanonicalCommand(natType string) (string, bool) {
	switch natType {
	case "", "source":
		return "show security nat source rule", true
	case "destination":
		return "show security nat destination rule", true
	default:
		return "", false
	}
}

var bgpNATCanonicalCommands15076 = []string{
	"show protocols bgp summary",
	"show protocols bgp routes",
	"show protocols bgp neighbor",
	"show protocols bgp neighbor advertised-routes",
	"show protocols bgp neighbor received-routes",
	"show security nat source rule",
	"show security nat destination rule",
}

// showTextTopicCanonicalCommand resolves one ShowText topic, using the SAME
// exact-then-longest-prefix rule showTextTopicPermission uses to PRICE it.
//
// The two lookups must agree about which key a topic resolves to, or a request
// could be priced by one rule and command-matched by another — the sibling
// guard TestTopicCommandAndPermissionResolveTheSameKey7172 asserts they do over
// the dispatcher's own topic list.
func showTextTopicCanonicalCommand(topic string) (string, bool) {
	if cmd, ok := showTextTopicCommand[topic]; ok {
		return cmd, true
	}
	for _, r := range showTextCommandPrefix {
		if strings.HasPrefix(topic, r.prefix) {
			return r.command, true
		}
	}
	return "", false
}

// showTextCommandPrefixRule is one prefix-keyed topic → command rule,
// pre-resolved at init and sorted longest-key-first for the same reason
// showTextPrefix is: an unambiguous longest match must win rather than whichever
// key map iteration reached first.
type showTextCommandPrefixRule struct {
	prefix  string
	command string
}

var showTextCommandPrefix []showTextCommandPrefixRule

func init() {
	for k, cmd := range showTextTopicCommand {
		if strings.HasSuffix(k, ":") {
			showTextCommandPrefix = append(showTextCommandPrefix, showTextCommandPrefixRule{k, cmd})
		}
	}
	sort.Slice(showTextCommandPrefix, func(i, j int) bool {
		if len(showTextCommandPrefix[i].prefix) != len(showTextCommandPrefix[j].prefix) {
			return len(showTextCommandPrefix[i].prefix) > len(showTextCommandPrefix[j].prefix)
		}
		return showTextCommandPrefix[i].prefix < showTextCommandPrefix[j].prefix
	})
}

// allCanonicalCommands is every command string this surface can ever present to
// a deny regex — the union of the tables plus the request-decoded
// GetSystemInfo / GetBGPStatus / GetNATRuleStats charges (#15076). Built once.
var allCanonicalCommands = sync.OnceValue(func() []string {
	seen := map[string]bool{}
	for _, m := range []map[string]string{
		methodCanonicalCommand, showTextTopicCommand, systemActionVerbCommand,
	} {
		for _, cmd := range m {
			seen[cmd] = true
		}
	}
	for _, infoType := range []string{"uptime", "memory", "processes", "processes-summary", "rescue-configuration", "storage", "users", "connections", "boot-messages", "arp", "ipv6-neighbors"} {
		if cmd, ok := systemInfoCanonicalCommand(infoType); ok {
			seen[cmd] = true
		}
	}
	for _, cmd := range bgpNATCanonicalCommands15076 {
		seen[cmd] = true
	}
	out := make([]string, 0, len(seen))
	for cmd := range seen {
		out = append(out, cmd)
	}
	sort.Strings(out)
	return out
})

// unenforceableDenyPatterns reports whether the class's deny pattern can ever
// fire on THIS surface, by asking whether it matches any command this surface
// can produce.
//
// EXACT AND SPELLING-INDEPENDENT, which the obvious implementation is not. The
// tempting version inspects the pattern — regexp.LiteralPrefix, and deny when
// the literal extends a mapped command. Measured, that returns "" for
// `^show route table secret-vrf`, so it would cover the unanchored spelling and
// silently miss the ANCHORED one — and anchors are what Juniper's guidance tells
// operators to use for anything complex. A guard that works on one spelling of
// the same intent is worse than none, because it reads as coverage.
//
// Asking the pattern to match the ACTUAL command set has no such dependence:
// whatever the operator wrote, either some command this surface produces
// matches it or none does.
//
// A pattern that matches nothing here is NOT rejected. It is valid, it is
// enforced on the box, and refusing it would refuse a legitimate restriction
// because one of two surfaces cannot see it. It is reported so the operator
// knows which half of their posture it covers.
// #8189: this surface registers what it can produce so the COMMIT-time
// advisory in pkg/config can reason about it. The import direction forbids the
// reverse — pkg/grpcapi imports pkg/config, and the tables cannot move because
// showTextTopicCommand is derived from cmdtree, which imports pkg/config too.
//
// The registered name is what an operator sees in the commit warning.
// grpcSurfaceName is the one spelling, used by both the registration and the
// lookup below. A literal repeated in two places would let the delegation
// silently stop finding its own surface after a rename.
const grpcSurfaceName = "the gRPC surface"

func init() {
	config.RegisterCommandSurface(grpcSurfaceName, allCanonicalCommands)
}

// unenforceableDenyPatterns now DELEGATES to pkg/config rather than keeping its
// own loop (#8189). Two implementations of "can this pattern ever fire" would
// be two things to keep in agreement, and the authorization-path answer
// disagreeing with the commit-path answer is precisely the confusion the
// commit-time advisory exists to remove.
func unenforceableDenyPatterns(rules config.CompiledLoginRegexes) []string {
	src, ok := rules.DenySource()
	if !ok {
		return nil
	}
	// Scoped to THIS surface, not "any registered surface". They are the same
	// set while gRPC is the only registrant, and they stop being the same the
	// moment a second one registers — at which point an unscoped check would
	// quietly answer a different question than its name promises.
	found := false
	for _, name := range config.UnenforceableDenySurfaces(rules) {
		if name == grpcSurfaceName {
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	return []string{src}
}

// unenforceableDenyAlternatives is the #9340 per-alternative answer for THIS
// surface: the alternatives of the class's deny pattern that can never fire
// here although the pattern as a whole can. It delegates to pkg/config for the
// same single-implementation reason as unenforceableDenyPatterns: the commit
// advisory and this log line must not disagree.
func unenforceableDenyAlternatives(rules config.CompiledLoginRegexes) []string {
	for _, f := range config.UnenforceableDenyAlternatives(rules) {
		if f.Surface == grpcSurfaceName {
			return f.Alternatives
		}
	}
	return nil
}

// warnUnenforceableDenyPatternsOnce logs the finding once per class per daemon
// lifetime.
//
// Once, because this is a property of the CONFIG, not of the request: repeating
// it per RPC would flood the log at request rate, which this project's logging
// rules forbid outright for anything on a per-request path.
//
// The dedup is checked BEFORE the answer is computed (#9340). The answer is a
// pure function of the class's allow and deny sources, since the registered
// command set is fixed at init. Computing it first would re-run the
// per-alternative analysis, a regexp parse plus one evaluation per alternative
// per command, on every restricted RPC. Keying on both sources keeps the
// "a commit that changes the pattern warns again" property.
func (s *Server) warnUnenforceableDenyPatternsOnce(class string, rules config.CompiledLoginRegexes) {
	denySrc, _ := rules.DenySource()
	allowSrc, allowSet := rules.AllowSource()
	key := fmt.Sprintf("%s\x00%t\x00%s\x00%s", class, allowSet, allowSrc, denySrc)
	if _, loaded := s.unenforceableDenyWarned.LoadOrStore(key, true); loaded {
		return
	}
	if unenforceableAllowOnGRPC9633(rules) {
		slog.Warn("login class allow-commands pattern permits no command on the gRPC surface, so every "+
			"restricted RPC is refused for this class (#9633)",
			"class", class,
			"pattern", allowSrc)
	}
	if pats := unenforceableDenyPatterns(rules); len(pats) > 0 {
		slog.Warn("login class deny-commands pattern cannot be enforced on the gRPC surface "+
			"and restricts the on-box CLI only (#7172)",
			"class", class,
			"pattern", strings.Join(pats, ", "),
			"reason", "it matches no command this listener can produce: the remote CLI parses "+
				"the line client-side, so this gate matches the canonical command PATH and "+
				"never argument values")
		return
	}
	if alts := unenforceableDenyAlternatives(rules); len(alts) > 0 {
		slog.Warn("login class deny-commands pattern is only partly enforceable on the gRPC surface: "+
			"some alternatives restrict the on-box CLI only (#9340)",
			"class", class,
			"pattern", denySrc,
			"alternatives", strings.Join(alts, ", "),
			"reason", "those alternatives match no command this listener can produce: the remote CLI "+
				"parses the line client-side, so this gate matches the canonical command PATH and "+
				"never argument values")
	}
}

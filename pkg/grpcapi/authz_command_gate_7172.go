package grpcapi

import (
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/psaab/xpf/pkg/cmdtree"
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
// ── WHAT THIS SURFACE MATCHES ───────────────────────────────────────────
//
// pkg/cli's cut-3 gate matches a deny regex against the FULL canonicalized
// line, including argument VALUES and the output pipe. Since #16067 this
// gate matches that same full line, reconstructed server-side from the
// decoded request (authz_command_args_16067.go): `ping 10.0.0.1` arrives
// as Ping{Target:"10.0.0.1"} and `show route table secret-vrf` as
// ShowText{Topic:"route-table:secret-vrf"}, and both rebuild the line the
// operator typed. The argument-free path stays an additional form, so an
// anchored path deny (`^show route table$`) still fires with arguments
// present, exactly as the on-box gate's prefix form does (#9022).
//
// So, precisely:
//
//   - a deny written against a command PATH — `deny-commands "request system
//     reboot"`, the shape Junos' own examples use — is enforced IDENTICALLY on
//     both surfaces, because matching is partial rather than anchored.
//   - a deny written against ARGUMENT text — `deny-commands "show route table
//     secret-vrf"`, `^ping 10\.99\.`, `^show log .*` — is likewise enforced
//     on both surfaces (#16067). A request whose arguments cannot be
//     reconstructed (a malformed packed topic, an unnameable selector)
//     denies for a restricted class rather than being judged on its
//     argument-free path alone.
//
// unenforceableDenyPatterns below MEASURES, per pattern, whether it can
// ever fire on this surface, and the answer is logged for the class. That
// check is exact and spelling-independent — it asks whether the pattern
// matches any command this surface can produce, argument-free or
// argument-bearing — which matters because the obvious implementation does
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
	// #15077: session-plumbing probes are exempt from the operational
	// regex gate; the coarse PermView check in authorizeRPCContext
	// already ran. Charging them to `show version` locked every member
	// of a version-denying (or allowlist) class out of the cli, whose
	// startup probe runs before any command is dispatched.
	if isSessionPlumbingMethod(fullMethod) {
		return nil
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
	// #16067: judge the argument-bearing forms too, so an
	// argument-scoped pattern (`^show route table secret-vrf`,
	// `^ping 10\.99\.`) fires here as it does on the box. The forms
	// are alternative spellings of the one command; EvaluateForms
	// unanimity lets a deny that wins on any spelling veto it, while
	// the argument-free charge stays a form so anchored path rules
	// keep firing. An unreconstructable argument string denies.
	//
	// #16472: the form set now also carries the canonical base /
	// keyword-full / selector spellings of the executed line and of
	// the charge (see rpcArgumentForms / canonicalArgumentForms), so
	// an anchored deny on the BASE spelling of a selector-bearing
	// command (`^show firewall$` over `firewall-filter:F1`) fires
	// here exactly as the console's canonicalForms make it fire
	// there. The console's #14687 distinct-narrower rescue is applied
	// in remoteDistinctRescue16472 via the shared cmdtree helper.
	forms, named := rpcArgumentForms(cfg, fullMethod, req, cmd)
	if !named {
		return fmt.Errorf(
			"login class %q restricts commands and this RPC's arguments cannot be "+
				"named as a command, so the restriction cannot be applied to it", class)
	}
	// #16605: judge every remote-cli line that performs this RPC, not
	// only the fixed charge — the typed-line aliases are alternative
	// spellings of the same executed command.
	_, method16605, _ := splitFullMethod(fullMethod)
	forms = withAliasForms16605(method16605, req, forms)
	if decision := rules.EvaluateForms(forms[0], forms[0], forms[1:]...); !decision.Allowed {
		if remoteDistinctRescue16472(rules, forms) {
			return nil
		}
		if aliasFormsDenyRescued16605(rules, method16605, req, forms) {
			return nil
		}
		return fmt.Errorf("login class %q denies %q (%s)", class, cmd, decision.Reason)
	}
	return nil
}

// remoteDistinctRescue16472 applies the #14687 distinct-narrower
// rescue over the reconstructed form set, via the shared
// cmdtree.DistinctNarrowerAllowed the console uses (#16472). The
// executed spelling is forms[0] as rpcArgumentForms built it; its
// chain form comes from CanonicalForms over its canonicalisation.
// Free-text filter forms that do not canonicalise have no chain form
// and are never rescued. Unlike the console it has no pipe text, so
// matched == command and the shared pipe arms never engage.
func remoteDistinctRescue16472(rules config.CompiledLoginRegexes, forms []string) bool {
	if len(forms) == 0 {
		return false
	}
	executed := forms[0]
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(executed))
	if res != cmdtree.CanonicalOK || strings.Join(canon, " ") != executed {
		return false
	}
	baseForm, fullForm, selectorForms, chainForm := canonicalFormsOf16472(canon)
	if chainForm == "" {
		return false
	}
	return cmdtree.DistinctNarrowerAllowed(rules, executed, executed, baseForm, fullForm, selectorForms)
}

// aliasFormsDenyRescued16605 is the cross-spelling deny-with-exceptions
// rescue for #16605. Adding alias spellings must not turn a charge and
// its typed line into mutual lockout: deny `^show interfaces detail$`
// beside allow `^show interfaces$` is an operator excepting the bare
// line from the detail spelling, and the reverse pair excepts the
// charge spelling. The rescue fires only when some form is
// affirmatively allowed (DecidedBy==Allow, Allowed), no executed
// spelling (forms[0] / the request-discriminated typed line) is
// tier-denied — a deny naming what was actually executed always
// vetoes — and every tier-denied form is a sibling spelling answered
// by that affirmative allow. A denied form's own allow that lost its
// tier comparison does not count: Evaluate(f) is that comparison and
// it denied.
func aliasFormsDenyRescued16605(rules config.CompiledLoginRegexes, method string, req any, forms []string) bool {
	if _, ok := rpcAliasCommands16605[method]; !ok {
		return false
	}
	executed := executedSpellings16605(method, req, forms)
	anyAllowed := false
	for _, f := range forms {
		if d := rules.Evaluate(f); d.Allowed && d.DecidedBy == config.LoginRegexAllow {
			anyAllowed = true
		}
	}
	if !anyAllowed {
		return false
	}
	for _, f := range forms {
		d := rules.Evaluate(f)
		if d.Allowed || !isTierDeny(d) {
			continue
		}
		if executed[f] {
			return false
		}
		rescued := false
		for _, g := range forms {
			if g == f {
				continue
			}
			if gd := rules.Evaluate(g); gd.Allowed && gd.DecidedBy == config.LoginRegexAllow {
				rescued = true
				break
			}
		}
		if !rescued {
			return false
		}
	}
	return true
}

// isCompleteMethod reports whether fullMethod is the Complete RPC.
func isCompleteMethod(fullMethod string) bool {
	service, method, ok := splitFullMethod(fullMethod)
	return ok && service == serviceName && method == completeMethodName
}

// isSessionPlumbingMethod reports whether fullMethod is one of the two
// session-plumbing probes (#15077): GetStatus (the cli's pre-dispatch
// reachability probe, also the prompt's cluster-facts refresh) and
// GetConfigModeStatus (the per-prompt config-mode/dirty poll). They
// return liveness facts, not command output, so there is no operational
// command to price; authorizeRPCCommand exempts them from the regex
// gate and the coarse PermView price governs them.
func isSessionPlumbingMethod(fullMethod string) bool {
	service, method, ok := splitFullMethod(fullMethod)
	if !ok || service != serviceName {
		return false
	}
	switch method {
	case statusMethodName, configModeStatusMethodName:
		return true
	}
	return false
}

// Named so the plumbing set has one spelling, mirroring
// completeMethodName / showTextMethodName.
const (
	statusMethodName           = "GetStatus"
	configModeStatusMethodName = "GetConfigModeStatus"
)

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
//
// The judged forms are the canonical spelling (canonicalOperationalWords,
// #16073): the raw typed line must not be judged, or a unique abbreviation
// (`sh conf`, `sh sec pol`) steps around an anchored deny/allow written
// against the canonical command — the same string the data-source twin
// (operationalAllowed) already judges. Config-mode `set …`/`run …` lines
// are not operational commands and keep their raw form: `set` is not in
// the operational tree, and `run`'s embedded line is canonicalised after
// the `run` word is stripped.
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
//
// For operational lines (everything except a config-mode non-`run`
// line) the returned forms are canonicalised (canonicalCompleteWords,
// #16073), so admission judges the same spelling as the data-source
// gate. Ambiguous or unresolvable abbreviations are left raw by the
// lenient expansion — that is fail-safe here, not fail-open: the raw
// form cannot match an anchored canonical deny, but a restricted
// class's allowlist also cannot be affirmatively matched by it, and
// the handler's data-source gate applies the same canonicalisation
// before any live value is read.
func completeLineForms(req *pb.CompleteRequest) (full string, prefixes []string, isShowConfig bool) {
	text := req.GetLine()
	if req.GetPos() >= 0 && int(req.GetPos()) < len(text) {
		text = text[:req.GetPos()]
	}
	if idx := strings.LastIndex(text, "|"); idx >= 0 {
		text = text[:idx]
	}
	words := strings.Fields(text)
	configLine := false
	if req.GetConfigMode() {
		// Config-mode `run <line>` embeds a full operational command.
		// The handler resolves the top word against ConfigTopLevel with
		// ResolveUniquePrefix (completeConfigPairsAuth), so an
		// abbreviated `ru`/`r` is dispatched as `run` there; admission
		// must strip the same word or it judges the raw `ru …` line and
		// anchored operational denies never fire (#16073 fold).
		if resolved, ok := cmdtree.ResolveUniquePrefix(cmdtree.KeysFromTree(cmdtree.ConfigTopLevel), firstWord(words)); ok && resolved == "run" && len(words) >= 2 {
			words = words[1:]
		} else {
			configLine = true
		}
	}
	if len(words) == 0 {
		return "", nil, false
	}
	_, isShowConfig = resolveShowConfigurationWords(words)
	if !configLine {
		words = canonicalCompleteWords(words)
		if _, ok := resolveShowConfigurationWords(words); ok {
			isShowConfig = true
		}
	}
	full = strings.Join(words, " ")
	for i := 1; i < len(words); i++ {
		prefixes = append(prefixes, strings.Join(words[:i], " "))
	}
	return full, prefixes, isShowConfig
}

func firstWord(words []string) string {
	if len(words) == 0 {
		return ""
	}
	return words[0]
}

// canonicalCompleteWords canonicalises a typed operational line for
// admission judging (#16073). A successful strict Canonicalize is
// authoritative and is never discarded: its result already expands
// every keyword — including a trailing keyword that fills a value
// slot opened by the head (`… family inet`, where the head alone
// ends at the required `family` value and strict-canonicalising it
// fails). Only when strict canonicalisation fails (the trailing
// word is still being completed, is a free-form value, or is
// ambiguous/unresolvable) does the lenient twin
// canonicalOperationalWords expansion apply, exactly as the
// data-source gate judges it.
func canonicalCompleteWords(words []string) []string {
	if canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, words); res == cmdtree.CanonicalOK {
		return canon
	}
	return canonicalOperationalWords(words)
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
// instead of receiving the source charge. This prices only the family;
// the rule_set/rule argument text is reconstructed by
// natRuleStatsArgumentForms (#17184).
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
	// #16605: the typed-line aliases are also commands this surface
	// presents to a deny regex, so the #8189 advisory must know them.
	for _, aliases := range rpcAliasCommands16605 {
		for _, cmd := range aliases {
			seen[cmd] = true
		}
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
			"reason", "it matches no command this listener can produce, in its "+
				"argument-free or reconstructed argument-bearing spellings (#16067)")
		return
	}
	if alts := unenforceableDenyAlternatives(rules); len(alts) > 0 {
		slog.Warn("login class deny-commands pattern is only partly enforceable on the gRPC surface: "+
			"some alternatives restrict the on-box CLI only (#9340)",
			"class", class,
			"pattern", denySrc,
			"alternatives", strings.Join(alts, ", "),
			"reason", "those alternatives match no command this listener can produce, in its "+
				"argument-free or reconstructed argument-bearing spellings (#16067)")
	}
}

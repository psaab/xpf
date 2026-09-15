// Package natshow renders the security/NAT operational show topics that
// the gRPC ShowText path (pkg/grpcapi/server_show_nat.go) and the CLI
// show path (pkg/cli/cli_show_nat.go) previously duplicated verbatim.
//
// Background (#1687, promoted from #1661 item 3): the broad "shared
// security/NAT/flow presentation package" premise was killed at plan
// time — the security topics (alg, address-book, applications, screen,
// ike, security-log, dynamic-address) are independently authored,
// structurally divergent operator contracts and are intentionally NOT
// shared. The NAT detail/table renderers, by contrast, were
// byte-identical between the two consumers (differing only in the
// output sink: gRPC writes a *strings.Builder, the CLI prints to
// os.Stdout, plus a return/return-nil wrapper). Those six renderers
// move here behind an io.Writer sink so both consumers single-source
// them. Golden tests on both consumers assert byte-identical output
// vs the pre-extraction master behavior.
//
// The functions take the gRPC behavior as the canonical contract (the
// gRPC nil/empty guards are reproduced verbatim; the trailing-newline
// shape is the gRPC "\n\n" form, which equals the CLI's
// fmt.Printf("...\n")+fmt.Println() byte-for-byte).
//
// This package imports root pkg/dataplane only for the session/counter
// types named by the session-iteration callbacks and counter reads
// (SessionKey/Value, CounterValue, PersistentNATTable). That import is
// tracked in the #1451 retirement-boundary canary allowlist
// (pkg/dataplane/retirement_boundary_canary_test.go) and the docs table
// in docs/pr/1373-retire-ebpf-dataplane/README.md — it is a net-neutral
// consolidation of the import that already lived in the two source
// files, not #1451 regressing. natshow must never import pkg/grpcapi or
// pkg/cli.
//
// # Session walks and cancellation
//
// Three of the renderers here tally live sessions by walking the FULL v4+v6
// conntrack table: RenderPersistentDetail, RenderSourceRuleDetail and
// RenderDestRuleDetail. Each takes a context.Context and routes its walk
// through the single walkSessionValues authority (walk.go), which is the ONLY
// place that samples the context — a per-renderer visitor cannot decide to
// keep walking, so a renderer added later inherits the check.
//
// The context is the caller's ADMISSION-LEASE context on the gRPC ShowText
// path (diagcmd.Limiter.AcquireCtx via pkg/grpcapi/server_show_nat.go) and
// context.Background() on the local CLI path, which has no request to cancel.
// Admission bounds how MANY walks run at once; the lease bounds how LONG one
// runs for a client that has already disconnected. Both matter because REST
// and gRPC alias ONE 4-slot diagcmd.SessionWalkLimiter (#6553 admission,
// #7315 cancellation).
//
// RenderPersistent is NOT one of the walking renderers and takes no context:
// its only dataplane read is PersistentNATTable.All(), an in-process snapshot
// copy. Renderers that read config alone (RenderStatic, RenderStaticRule,
// RenderNPTv6) take no context for the same reason.
package natshow

import (
	"errors"
	"fmt"
	"io"

	"github.com/psaab/xpf/pkg/config"

	"github.com/psaab/xpf/pkg/dataplane"
)

// noteSessionScanError emits a caveat line when a dataplane session scan
// that backs the per-rule / per-binding "active session" counts failed.
// The detail renderers scan the conntrack table to tally sessions; a
// transient read error (map busy, dataplane reload) otherwise left the
// counts silently understated — a zero that reads as "no sessions"
// rather than "could not read". Surfacing the error tells the operator
// the displayed counts are partial (#5557).
//
// A walk stopped by cancellation (ErrSessionWalkCancelled, #9902 F-096)
// maps to a "counts are partial" caveat rather than the error line: there
// is no error value to format, and the partial tally still prints.
func noteSessionScanError(w io.Writer, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, ErrSessionWalkCancelled) {
		fmt.Fprintln(w, "Warning: active session counts are partial (session walk cancelled)")
		return
	}
	fmt.Fprintf(w, "Warning: active session counts may be incomplete: %v\n", err)
}

// noteNotInstalled emits the #6534 exclusion annotation for a NAT object the
// userspace snapshot builder drops or disarms. reason is the operator-facing
// text from the shared pkg/config predicate that the BUILDER also consults, so
// the annotation cannot claim something the dataplane disagrees with.
//
// Nothing is printed when reason is empty, so an installed rule's output is
// byte-identical to the pre-#6534 form — the golden tests on both consumers
// keep asserting the same bytes for every healthy config, and only a rule the
// dataplane is genuinely not enforcing gains a line.
//
// The wording leads with NOT INSTALLED rather than appending a parenthetical to
// the Action line: an operator scanning a long rule list is looking down the
// left margin, and a rule that is silently unenforced is exactly the thing that
// must not read as a footnote.
func noteNotInstalled(w io.Writer, reason string) {
	if reason == "" {
		return
	}
	fmt.Fprintf(w, "    Status:                  NOT INSTALLED — %s\n", reason)
}

// noteDNATOffShadowed emits the #9879 partial-shadow warning for a
// destination-NAT `off` rule a narrower later translate rule re-enters. reason
// is the operator-facing text from the shared pkg/config predicate
// (config.DNATOffShadowReason) the COMMIT GATE also consults, so the
// annotation cannot claim something the gate disagrees with. This is
// deliberately NOT a noteNotInstalled: the `off` entry IS installed and still
// exempts the non-overlapping remainder — only the re-entered subspace
// translates. Saying NOT INSTALLED would promise fall-through that does not
// happen (the same reason noteLenientMatchDropped is not one). Nothing is
// printed when reason is empty, so a healthy rule's output is byte-identical
// to the pre-#9879 form.
func noteDNATOffShadowed(w io.Writer, reason string) {
	if reason == "" {
		return
	}
	fmt.Fprintf(w, "    Warning:                 PARTIALLY SHADOWED — %s\n", reason)
}

// noteLenientTerminalAction annotates a rule that the TOLERANT config path
// admitted despite the strict terminal-action cardinality gate rejecting it
// (#7640).
//
// It reads config.Config.LenientNATTerminalActionRules rather than re-deriving
// the predicate, so the annotation, the xpf_nat_rules_lenient_terminal_action
// gauge and the compile-time warning can never disagree about which rules are
// affected.
//
// This is the surface that was missing. The warning reaches an operator through
// the commit RESPONSE and an apply-time log line — and a tolerant LOAD (boot,
// peer-sync, rollback) has neither. Those are exactly the paths on which such a
// rule survives, so an operator looking at the rule was the one person
// guaranteed not to be told.
//
// The text names the consequence per arity rather than saying "invalid",
// because the two arities fail differently and the difference is what an
// operator has to act on.
func noteLenientTerminalAction(w io.Writer, cfg *config.Config, kind, ruleSet, rule string) {
	if cfg == nil {
		return
	}
	for _, r := range cfg.LenientNATTerminalActionRules {
		if r.Kind != kind || r.RuleSet != ruleSet || r.Rule != rule {
			continue
		}
		var consequence string
		switch {
		case r.Actions == 0:
			// #6823: ONE arm for both kinds, because the decision is that the
			// CONSEQUENCE is kind-independent — an actionless rule is
			// NON-TERMINAL either way. Source NAT reaches that by publishing
			// the rule and letting the Rust matcher's `else` arm continue;
			// destination NAT by not publishing it at all. Naming the
			// MECHANISM per kind is what went wrong before: the destination
			// arm said only "the rule is not published to the dataplane at
			// all", which is true and reads as INERT — the exact framing the
			// #5717/#6820 work retired — so the operator whose DNAT exemption
			// silently does nothing was told the reassuring half of the
			// sentence. The mechanism is already covered on that side by the
			// #6534 NOT INSTALLED line; the consequence is what this one owes.
			consequence = "it installs no translation and does NOT stop rule " +
				"evaluation, so matching traffic falls through to any later " +
				"broader rule"
		default:
			consequence = fmt.Sprintf("it carries %d mutually-exclusive actions; "+
				"all but one are discarded by a fixed precedence, not by "+
				"configuration order", r.Actions)
		}
		fmt.Fprintf(w, "    Status:                  ADMITTED BY TOLERANT LOAD — "+
			"a commit would REJECT this rule: %s\n", consequence)
		return
	}
}

// noteLenientMatchDropped annotates a source-NAT rule the TOLERANT config path
// admitted despite its authored `match` constraining nothing (#9874).
//
// It reads rule.LenientMatchDropped directly — the same marker the snapshot
// builder ships and the Rust table fails closed on — so the annotation and the
// dataplane disposition cannot disagree. The rule IS installed (it occupies a
// table slot), which is why this is NOT a noteNotInstalled: it claims in-scope
// flows and the dataplane DROPS them (drop + count) instead of translating,
// and rule evaluation STOPS there rather than falling through. Saying "not
// installed" would tell the operator traffic falls through to later rules,
// which is exactly wrong. The #7640 ADMITTED shape fits instead: the rule
// survives only on the tolerant load / peer-sync / rollback paths, and a
// commit would reject it.
//
// Operative-cause precedence: when this marker is set it is printed INSTEAD
// OF the pool-disarm and tolerant-terminal-action notes, not beside them.
// The poison check runs before action handling in the Rust match loop, so a
// marked rule drops no matter what its pool or action arity is — and the
// terminal-action note's "falls through to any later broader rule" would be
// false beside it. Callers gate those notes on !LenientMatchDropped.
func noteLenientMatchDropped(w io.Writer) {
	fmt.Fprintf(w, "    Status:                  ADMITTED BY TOLERANT LOAD — "+
		"a commit would REJECT this rule: the match block constrains nothing, "+
		"so matching traffic is dropped and rule evaluation stops here (#9874)\n")
}

// noteNotInstalledStatic is noteNotInstalled at the static-NAT renderers' wider
// label column ("Match destination-address:" / "Then static-nat prefix:"), so
// the annotation lines up with the fields it is qualifying instead of hanging
// four columns short of them.
func noteNotInstalledStatic(w io.Writer, reason string) {
	if reason == "" {
		return
	}
	fmt.Fprintf(w, "    Status:                    NOT INSTALLED — %s\n", reason)
}

// Reader is the narrow dataplane surface the NAT renderers need. Both
// the gRPC grpcRuntime (pkg/grpcapi/runtime.go) and the CLI cliRuntime
// (pkg/cli/runtime.go) already satisfy it structurally. A nil Reader is
// permitted and reproduces the "not loaded" / unavailable branches.
// natCounterUnarmed is what a NAT counter renders as when the dataplane is not
// armed (#7423 rows 3+4). It is a positive statement rather than an omitted
// line: a missing row is easy to read past, and the defect being fixed is
// precisely an operator trusting a number that was never measured. One constant
// so the hits row and the session row cannot drift into saying different things
// about the same condition.
const natCounterUnarmed = "n/a (dataplane not armed)"

type Reader interface {
	IsLoaded() bool
	IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error
	IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error
	ReadNATRuleCounter(counterID uint32) (dataplane.CounterValue, error)
	GetPersistentNAT() *dataplane.PersistentNATTable
}

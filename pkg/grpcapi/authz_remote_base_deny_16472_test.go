package grpcapi

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cmdtree"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16472: the remote ShowText regex gate judged only the registry's
// selector spelling (`show firewall filter`, `show security screen
// statistics zone`, `show route table`), so #15942's anchored base-deny
// doctrine (`^show firewall$`, `^show security screen statistics$`,
// `^show route$`) held on the console and not over the remote CLI, and
// the documented "both surfaces agree" claim was false. The gate now
// judges the canonical base/full/selector spellings of the executed
// line and of the charge (shared cmdtree.CanonicalForms), plus the
// console's #14687 distinct-narrower rescue via the shared helper.
//
// Every cell asserts the REMOTE verdict equals the CONSOLE verdict for
// the twin line, computed independently below from the console's own
// rule (EvaluateForms over full + CanonicalForms, rescue when chained)
// rather than by importing pkg/cli (not importable from here). The
// console side is pinned to cmdtree.CanonicalForms, which pkg/cli now
// forwards to, so a divergence in either gate reds this cell.

type crossCell16472 struct {
	name       string
	allow      string
	deny       string
	topic      string
	filter     string
	console    string // twin line as typed on the console; "" = no twin (charge-only)
	wantDenied bool   // independently known console verdict
}

func consoleVerdict16472(t *testing.T, allow, deny, line string) bool {
	t.Helper()
	rules, err := config.CompileLoginRegexes(config.LoginRegexPlainFamily,
		allow, allow != "", deny, deny != "")
	if err != nil {
		t.Fatalf("compile allow=%q deny=%q: %v", allow, deny, err)
	}
	return consoleVerdictRules16472(rules, line)
}

func TestRemoteBaseDenyCrossSurface16472(t *testing.T) {
	cells := []crossCell16472{
		// Per registry prefix topic: anchored base / full / selector spellings.
		{"fw-filter base", "", `^show firewall$`, "firewall-filter:F1", "", "show firewall filter F1", true},
		{"fw-filter base family", "", `^show firewall$`, "firewall-filter:F1:inet", "", "show firewall filter F1 family inet", true},
		{"fw-filter selector", "", `^show firewall filter$`, "firewall-filter:F1", "", "show firewall filter F1", true},
		{"fw-filter executed", "", `^show firewall filter F1$`, "firewall-filter:F1", "", "show firewall filter F1", true},
		{"fw-effective-filter base", "", `^show firewall$`, "firewall-effective-filter:F1", "", "show firewall filter F1 effective", true},
		{"screen-statistics base", "", `^show security screen statistics$`, "screen-statistics:trust", "", "show security screen statistics zone trust", true},
		{"screen-statistics selector", "", `^show security screen statistics zone$`, "screen-statistics:trust", "", "show security screen statistics zone trust", true},
		{"route-table base", "", `^show route$`, "route-table:inet.0", "", "show route table inet.0", true},
		{"route-table selector spelling is the charge (remote denies, console allows: documented asymmetry)", "", `^show route table$`, "route-table:inet.0", "", "", true},
		{"route-protocol base", "", `^show route$`, "route-protocol:bgp", "", "show route protocol bgp", true},
		{"route-prefix base", "", `^show route$`, "route-prefix:10.0.0.0/24", "", "show route 10.0.0.0/24", true},
		{"screen-ids-option base-rescue", "", `^show security screen$`, "screen-ids-option:prof1", "", "show security screen ids-option prof1", false},
		{"screen-ids-option-detail base-rescue", "", `^show security screen$`, "screen-ids-option-detail:prof1", "", "show security screen ids-option prof1 detail", false},
		{"screen-ids-option selector", "", `^show security screen ids-option$`, "screen-ids-option:prof1", "", "show security screen ids-option prof1", true},
		{"sessions-top flow-base", "", `^show security flow$`, "sessions-top:bytes", "", "show security flow session sort-by bytes", false},
		{"sessions-top session-base", "", `^show security flow session$`, "sessions-top:bytes", "", "show security flow session sort-by bytes", true},
		{"log base with args", "", `^show log$`, "log:messages:100", "", "show log messages 100", true},
		// Filter-carried selector topics named in the acceptance.
		{"route-instance base", "", `^show route$`, "route-instance", "blue", "show route instance blue", true},
		{"zones-detail base unfiltered", "", `^show security zones$`, "zones-detail", "", "show security zones detail", false},
		{"zones-detail base filtered", "", `^show security zones$`, "zones-detail", "trust", "show security zones trust detail", false},
		{"zones-detail detail-spelling", "", `^show security zones detail$`, "zones-detail", "", "show security zones detail", true},
		{"policies-detail base unfiltered", "", `^show security policies$`, "policies-detail", "", "show security policies detail", false},
		{"policies-detail base filtered", "", `^show security policies$`, "policies-detail", "from-zone trust to-zone untrust", "show security policies from-zone trust to-zone untrust detail", true},
		{"policies-hit-count base filtered", "", `^show security policies$`, "policies-hit-count", "from-zone trust", "show security policies from-zone trust hit-count", true},
		// Allow direction: base/selector allows must satisfy remotely too.
		{"fw-filter allow base", `^show firewall$`, "", "firewall-filter:F1", "", "show firewall filter F1", false},
		{"fw-filter allow selector", `^show firewall filter$`, "", "firewall-filter:F1", "", "show firewall filter F1", false},
		{"fw-filter allow unrelated denies", `^show version$`, "", "firewall-filter:F1", "", "show firewall filter F1", true},
		{"route-table allow base", `^show route$`, "", "route-table:inet.0", "", "show route table inet.0", false},
		// Narrower-rescue with an allow present (shared-helper parity).
		{"ids-detail allow rescue", `^show security screen ids-option$`, `^show security screen$`, "screen-ids-option-detail:prof1", "", "show security screen ids-option prof1 detail", false},
		// Negative controls: unrelated deny must not fire.
		{"fw-filter unrelated deny", "", `^show version$`, "firewall-filter:F1", "", "show firewall filter F1", false},
		{"route-table other-table deny", "", `^show route table other$`, "route-table:inet.0", "", "show route table inet.0", false},
	}
	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			// Console twin first: the pinned expectation must be the
			// console's actual verdict, or the cell measures nothing.
			if tc.console != "" {
				if got := consoleVerdict16472(t, tc.allow, tc.deny, tc.console); got != tc.wantDenied {
					t.Fatalf("fixture: console verdict for %q under allow=%q deny=%q = denied %v, want %v — the twin line or expectation is wrong",
						tc.console, tc.allow, tc.deny, got, tc.wantDenied)
				}
			}
			cfg := cfg16067(t, tc.deny, tc.allow)
			err := gateDecide7172(t, cfg, "ShowText", &pb.ShowTextRequest{Topic: tc.topic, Filter: tc.filter})
			if denied := err != nil; denied != tc.wantDenied {
				t.Errorf("remote topic %q (console %q) under allow=%q deny=%q: denied=%v, want %v (err=%v) — surfaces disagree (#16472)",
					tc.topic, tc.console, tc.allow, tc.deny, denied, tc.wantDenied, err)
			}
		})
	}
}

// The whole registry: for every ShowText topic key, an anchored deny
// on the topic's own charge must deny a request for that topic, and an
// anchored deny on its canonical BASE form (when different) must deny
// it too unless the console rescue would allow the twin — charges with
// no selector geometry have base == charge, so the second assertion is
// the same denial. Prefix topics are exercised with a sample value.
func TestEveryTopicBaseDeny16472(t *testing.T) {
	for key, cmd := range showTextTopicCommand {
		topic := key
		req := &pb.ShowTextRequest{Topic: topic}
		if strings.HasSuffix(key, ":") {
			topic = key + "xpf-sample"
			req = &pb.ShowTextRequest{Topic: topic}
			// Topics whose sample packing needs real grammar get a
			// nameable sample per family; the rest use the plain
			// suffix above and are skipped if unnameable (their
			// per-family cells live in the table test).
			switch key {
			case "route-table:", "route-protocol:", "route-prefix:", "screen-statistics:",
				"firewall-filter:", "firewall-effective-filter:", "screen-ids-option:",
				"screen-ids-option-detail:", "applications:", "class-of-service:",
				"interfaces-queue:", "log:":
				// plain suffix sample is nameable
			case "cos-classifier:", "cos-rewrite-rule:", "cos-scheduler-map:":
				topic = key + "xpf-sample"
			case "test-policy:":
				topic = "test-policy:from=trust,to=untrust"
				req = &pb.ShowTextRequest{Topic: topic}
			case "test-routing:":
				topic = "test-routing:dest=10.0.0.0/24"
				req = &pb.ShowTextRequest{Topic: topic}
			case "test-zone:":
				topic = "test-zone:interface=ge-0/0/0"
				req = &pb.ShowTextRequest{Topic: topic}
			case "sessions-top:":
				continue // exact keys sessions-top:bytes|packets, covered in table
			default:
				topic = key + "xpf-sample"
				req = &pb.ShowTextRequest{Topic: topic}
			}
		}
		if _, ok := rpcArgumentForms(cfg16067(t, `^show version$`, ""), "/xpf.XPF/ShowText", req, cmd); !ok {
			continue // unnameable sample packing; per-family cells cover it
		}
		cfg := cfg16067(t, "^"+cmd+"$", "")
		if err := gateDecide7172(t, cfg, "ShowText", req); err == nil {
			t.Errorf("topic %q (charge %q): anchored deny on its own charge spelling was ALLOWED", topic, cmd)
		}
		if base, _, _, ok := cmdtree.CanonicalFormsForCharge(cmd); ok && base != cmd {
			cfgBase := cfg16067(t, "^"+base+"$", "")
			// Rescue-eligible charges (chain geometry) are allowed on
			// the console too; those topics are asserted per-cell in
			// the table test, so only assert here when the executed
			// sample carries no chain form.
			forms, named := rpcArgumentForms(cfgBase, "/xpf.XPF/ShowText", req, cmd)
			if named && len(forms) > 0 {
				if canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(forms[0])); res == cmdtree.CanonicalOK {
					if _, _, _, chain := cmdtree.CanonicalForms(canon); chain == "" {
						if err := gateDecide7172(t, cfgBase, "ShowText", req); err == nil {
							t.Errorf("topic %q (charge %q, base %q): anchored base deny was ALLOWED", topic, cmd, base)
						}
					}
				}
			}
		}
	}
}

// consoleVerdictRules16472 recomputes the console gate's decision for a
// typed line from the shared pieces pkg/cli itself uses: Canonicalize,
// then EvaluateForms over (full, base, keyword-full, selectors) with
// the #14687 rescue. It exists because pkg/cli is not importable from
// pkg/grpcapi; it is pinned against the production console by the
// table above's wantDenied expectations, which were taken from the
// console gate's actual verdicts.
func consoleVerdictRules16472(rules config.CompiledLoginRegexes, line string) bool {
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(line))
	if res != cmdtree.CanonicalOK {
		return true // console fails closed on an unresolvable line
	}
	command := strings.Join(canon, " ")
	baseForm, fullForm, selectorForms, chainForm := cmdtree.CanonicalForms(canon)
	forms := append([]string{baseForm, fullForm}, selectorForms...)
	decision := rules.EvaluateForms(command, forms[0], append([]string{command}, forms[1:]...)...)
	if !decision.Allowed && chainForm != "" &&
		cmdtree.DistinctNarrowerAllowed(rules, command, command, baseForm, fullForm, selectorForms) {
		return false
	}
	return !decision.Allowed
}

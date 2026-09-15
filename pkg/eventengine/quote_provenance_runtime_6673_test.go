package eventengine

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Round-10 RUNTIME guard for the #6673 quote-provenance fix.
//
// The compile-level table in pkg/config asserts the VALUE COUNT. This asserts
// what that count is FOR: whether the remediation batch executes.
//
// `then change-configuration commands [ "set" "system host-name pwned" ]` is a
// two-member list whose first member is the bare word `set`. classifyPlan
// requires every member to start `set ` or `delete ` (with the trailing space),
// so the bare member fails and the WHOLE batch is declined — that is the
// fail-closed direction the compiler comment promises for a genuinely ambiguous
// authoring.
//
// Under the pre-#6673 text rule the two members FUSED into the single string
// `set system host-name pwned`. That string starts `set `, parses, and becomes
// one executable op: the batch was ACCEPTED and a config change the operator
// never authored was applied. The assertion here is therefore ok == false with
// zero ops, and the control immediately below it is the same batch written the
// way an operator who meant one command would write it, which must still be
// accepted — so a fix that simply declines more batches cannot pass both.
func TestClassifyPlan6673FusedMemberBatchIsDeclined(t *testing.T) {
	e := &Engine{}
	for _, tc := range []struct {
		name    string
		cfg     string
		wantOK  bool
		wantOps int
	}{
		{
			name:    "quoted one-word member beside a quoted remainder is DECLINED",
			cfg:     `commands [ "set" "system host-name pwned" ]`,
			wantOK:  false,
			wantOps: 0,
		},
		{
			name:    "quoted one-word DELETE member is DECLINED",
			cfg:     `commands [ "delete" "system host-name" ]`,
			wantOK:  false,
			wantOps: 0,
		},
		{
			// CONTROL: the single unquoted command. Same words, one authored
			// value, and it must still execute.
			name:    "the same words as ONE unquoted command still execute",
			cfg:     `commands set system host-name pwned`,
			wantOK:  true,
			wantOps: 1,
		},
		{
			// CONTROL: the single quoted command.
			name:    "one quoted command still executes",
			cfg:     `commands "set system host-name pwned"`,
			wantOK:  true,
			wantOps: 1,
		},
		{
			// CONTROL: a well-formed two-member list still executes as two ops.
			name:    "two well-formed quoted members still execute",
			cfg:     `commands [ "set system host-name a" "delete system host-name" ]`,
			wantOK:  true,
			wantOps: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := compileCommandsPolicy6673(t, tc.cfg)
			ops, ok := e.classifyPlan(pol)
			if ok != tc.wantOK {
				t.Fatalf("classifyPlan(%s) ok = %v, want %v — compiled commands were %q; "+
					"a batch whose members FUSE into one plausible command must be "+
					"declined, not applied", tc.cfg, ok, tc.wantOK, pol.ThenCommands)
			}
			if len(ops) != tc.wantOps {
				t.Fatalf("classifyPlan(%s) produced %d ops, want %d (commands %q)",
					tc.cfg, len(ops), tc.wantOps, pol.ThenCommands)
			}
		})
	}
}

// TestClassifyPlan6673FusedMemberDeclinedViaFlatSet is the same runtime
// assertion reached through the OTHER authoring path — and the one that binds
// the production wiring rather than a test-only helper.
//
// It goes through config.ParseSetCommandGrouped + SetPathQuotedGrouped, which is
// exactly the pair configstore.Store.SetFromInputAs calls for every `set` an
// operator types at the CLI, over gRPC, or over the REST API (unified on
// #9881). If either half of that wiring stopped carrying provenance, the
// flat-set tree would fall back to the text rule and this batch would be
// ACCEPTED again.
func TestClassifyPlan6673FusedMemberDeclinedViaFlatSet(t *testing.T) {
	e := &Engine{}
	line := `set event-options policy p then change-configuration commands ` +
		`[ "set" "system host-name pwned" ]`
	path, quoted, grouped, err := config.ParseSetCommandGrouped(line)
	if err != nil {
		t.Fatalf("ParseSetCommandGrouped: %v", err)
	}
	tree := &config.ConfigTree{}
	if err := tree.SetPathQuotedGrouped(path, quoted, grouped); err != nil {
		t.Fatalf("SetPathQuotedGrouped: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled %d policies, want 1", len(cfg.EventOptions))
	}
	pol := cfg.EventOptions[0]
	if len(pol.ThenCommands) != 2 {
		t.Fatalf("flat-set authoring compiled to %d commands %q, want 2 — the two "+
			"authored members must not fuse", len(pol.ThenCommands), pol.ThenCommands)
	}
	if ops, ok := e.classifyPlan(pol); ok || len(ops) != 0 {
		t.Fatalf("classifyPlan accepted the flat-set batch (ok=%v, %d ops, commands %q); "+
			"the bare `set` member must decline the whole batch", ok, len(ops), pol.ThenCommands)
	}
}

func compileCommandsPolicy6673(t *testing.T, commandsStanza string) *config.EventPolicy {
	t.Helper()
	src := "event-options { policy p { then { change-configuration { " +
		commandsStanza + "; } } } }"
	tree, perrs := config.NewParser(src).Parse()
	if len(perrs) != 0 {
		t.Fatalf("parse %q: %v", src, perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	if len(cfg.EventOptions) != 1 {
		t.Fatalf("compiled %d policies, want 1", len(cfg.EventOptions))
	}
	return cfg.EventOptions[0]
}

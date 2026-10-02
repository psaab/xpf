package daemon

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11896, daemon half: #11893's lenient poison (term.Action="discard") is
// propagated VERBATIM by toNftLo0Term, so a conflicting term installs a REAL
// DROP on the lo0 chain. Like the #9875 from-markers, the conflict evidence
// (term.TerminalActions) must travel the FromUnrepresentable channel instead:
// the netlink builder refuses the whole plan and the text oracle emits the
// constant refusal bareword, retaining the prior generation on both sides.
// Reverting either arm makes its assert FAIL. Helpers (lo0Cfg9875,
// lowerLo0Term9875) are shared with lo0_from_unrepresentable_9875_test.go.

// TestTerminalConflictReachesLo0Builder11896 pins the netlink reachability
// half: the lowered DTO must carry the marker the builder refuses on.
func TestTerminalConflictReachesLo0Builder11896(t *testing.T) {
	term := lowerLo0Term9875(t, lo0Cfg9875(&config.FirewallFilterTerm{
		Name: "conflict", Protocols: []string{"tcp"},
		TerminalActions: []string{"accept", "discard"}, Action: "discard",
	}))
	if !term.FromUnrepresentable {
		t.Error("#11896: conflicting TerminalActions must set FromUnrepresentable — " +
			"without it the builder installs the poisoned discard as a real DROP")
	}
}

// TestLo0TextOracleRefusesTerminalConflict11896 pins the text-oracle half: a
// conflicting term must refuse the load with the constant bareword.
func TestLo0TextOracleRefusesTerminalConflict11896(t *testing.T) {
	payload := buildLo0FilterPayload(lo0Cfg9875(&config.FirewallFilterTerm{
		Name: "conflict", Protocols: []string{"tcp"},
		TerminalActions: []string{"accept", "discard"}, Action: "discard",
	}), "protect-re", "")
	if !strings.Contains(payload, nftRefuseUnrepresentableFrom) {
		t.Fatalf("#11896: the oracle must emit the constant refusal rule for a conflicting "+
			"term so the nft load fails closed; payload:\n%s", payload)
	}
	if strings.Contains(payload, " drop") {
		t.Errorf("#11896: the oracle must not emit a verdict for a conflicting term; payload:\n%s", payload)
	}
}

// TestLo0TerminalConflictEndToEnd11896 proves the production path: a
// leniently-loaded conflicting lo0 term warns, refuses on BOTH renderers,
// and never renders a fresh drop.
func TestLo0TerminalConflictEndToEnd11896(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter protect-re term t from protocol tcp",
		"set firewall family inet filter protect-re term t then accept",
		"set firewall family inet filter protect-re term t then discard",
		"set interfaces lo0 unit 0 family inet filter input protect-re",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile must remain bootable (#1960 no-brick): %v", err)
	}
	foundWarning := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "firewall filter terminal-action conflict") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("tolerant compile must warn about the conflict; warnings=%v", cfg.Warnings)
	}
	oracle := buildLo0FilterPayload(cfg, "protect-re", "")
	if !strings.Contains(oracle, "__xpf_refuse_unrepresentable_from__") {
		t.Errorf("text side lost the refusal evidence; payload:\n%s", oracle)
	}
	lowered := lowerLo0Term9875(t, cfg)
	if !lowered.FromUnrepresentable {
		t.Error("netlink side lost the refusal evidence: FromUnrepresentable is false")
	}
}

// TestLo0TerminalConflictNegative11896 is the over-refusal guard: a repeated
// SAME terminal must render exactly as before on both mirrors.
func TestLo0TerminalConflictNegative11896(t *testing.T) {
	term := &config.FirewallFilterTerm{
		Name: "redundant", Protocols: []string{"tcp"},
		TerminalActions: []string{"discard", "discard"}, Action: "discard",
	}
	cfg := lo0Cfg9875(term)
	if lowered := lowerLo0Term9875(t, cfg); lowered.FromUnrepresentable {
		t.Error("a repeated same terminal is not a conflict and must not set FromUnrepresentable")
	}
	if payload := buildLo0FilterPayload(cfg, "protect-re", ""); strings.Contains(payload, "__xpf_refuse_unrepresentable_from__") {
		t.Errorf("a repeated same terminal must not carry the refusal bareword; payload:\n%s", payload)
	}
}

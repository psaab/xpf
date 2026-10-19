package config

import (
	"strings"
	"testing"
)

// #15025 (A16-02): DPD `threshold` is rendered as swanctl `dpd_timeout`,
// which strongSwan honours for IKEv1 only ("Timeout for DPD checks
// (IKEV1 only)" in swanctl.conf). On IKEv2 — the version charon
// negotiates when the gateway carries no `version` pin (the dual
// default) and the only version on a `v2-only` gateway — a dead peer
// is instead declared after charon's global retransmission budget
// (retransmit_timeout 4s × base 1.8 ^ tries 5 ≈ 165s), regardless of
// interval × threshold. The threshold knob was therefore inert on the
// default path with no operator signal.
//
// The fix is a commit advisory (the issue's accepted alternative to
// programming charon's global retransmit settings, which are
// daemon-global and cannot honour per-gateway thresholds): a gateway
// that sets an explicit DPD threshold and can negotiate IKEv2 (dual
// default or v2-only) warns at commit that `threshold` applies to
// IKEv1 only. A v1-only gateway (threshold fully effective) and a
// gateway with no explicit threshold stay silent.

func compile15025(t *testing.T, cmds []string, compile func(*ConfigTree) (*Config, error)) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := compile(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

func hasDPDThresholdAdvisory15025(cfg *Config) bool {
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "dead-peer-detection threshold") && strings.Contains(w, "IKEv1") {
			return true
		}
	}
	return false
}

// dpdCmds15025 builds a minimal gateway stanza. version is "" (dual
// default), "v1-only", or "v2-only"; threshold <= 0 omits the leaf.
func dpdCmds15025(version string, threshold int) []string {
	cmds := []string{
		"set security ike gateway gw1 address 192.0.2.1",
		"set security ike gateway gw1 dead-peer-detection interval 2",
	}
	if version != "" {
		cmds = append(cmds, "set security ike gateway gw1 version "+version)
	}
	if threshold > 0 {
		cmds = append(cmds, "set security ike gateway gw1 dead-peer-detection threshold 3")
	}
	return cmds
}

func TestDPDThresholdIKEv2Advisory15025(t *testing.T) {
	// Dual default (no version pin): charon initiates IKEv2, so the
	// threshold feeding dpd_timeout is inert. Must warn.
	cfg := compile15025(t, dpdCmds15025("", 3), CompileConfig)
	if !hasDPDThresholdAdvisory15025(cfg) {
		t.Fatalf("dual-default gateway with DPD threshold 3 must warn that threshold "+
			"is IKEv1-only; warnings=%q (#15025)", cfg.Warnings)
	}

	// v2-only: IKEv2 is the only version; same inert threshold.
	cfg = compile15025(t, dpdCmds15025("v2-only", 3), CompileConfig)
	if !hasDPDThresholdAdvisory15025(cfg) {
		t.Fatalf("v2-only gateway with DPD threshold 3 must warn that threshold "+
			"is IKEv1-only; warnings=%q (#15025)", cfg.Warnings)
	}

	// Control: v1-only gateway — dpd_timeout is honoured, threshold is
	// fully effective. Must NOT warn.
	cfg = compile15025(t, dpdCmds15025("v1-only", 3), CompileConfig)
	if hasDPDThresholdAdvisory15025(cfg) {
		t.Fatalf("v1-only gateway must not carry the IKEv2 DPD-threshold advisory; "+
			"warnings=%q (#15025)", cfg.Warnings)
	}

	// Control: dual gateway with interval only (no explicit threshold)
	// — the operator never set the inert knob. Must NOT warn.
	cfg = compile15025(t, dpdCmds15025("", 0), CompileConfig)
	if hasDPDThresholdAdvisory15025(cfg) {
		t.Fatalf("gateway without an explicit DPD threshold must not warn; "+
			"warnings=%q (#15025)", cfg.Warnings)
	}

	// Control: no DPD stanza at all.
	cfg = compile15025(t, []string{"set security ike gateway gw1 address 192.0.2.1"}, CompileConfig)
	if hasDPDThresholdAdvisory15025(cfg) {
		t.Fatalf("gateway without DPD must not warn; warnings=%q (#15025)", cfg.Warnings)
	}

	// The advisory is a warning, never a commit failure, and it is
	// suppressed on the tolerant load / peer-sync paths so it does not
	// repeat on every boot of an already-committed config (#8357
	// doctrine).
	cfg = compile15025(t, dpdCmds15025("", 3), CompileConfigLenient)
	if hasDPDThresholdAdvisory15025(cfg) {
		t.Fatalf("tolerant path must suppress the DPD-threshold advisory; "+
			"warnings=%q (#15025)", cfg.Warnings)
	}
}

package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15269 B18-01: unset SYN-flood sub-thresholds render "(default)" against
// Junos defaults, but the snapshot publishes 0 and Rust treats 0 as
// disabled. The Value column must say disabled; the Default column must
// say the Junos value is not applied. Timeout shows the effective
// opening window (per-zone override, else flow initial-timeout, else 20).

func syn15269(attack, initial int) *config.ScreenProfile {
	p := &config.ScreenProfile{Name: "p", TCP: config.TCPScreen{
		SynFlood: &config.SynFloodConfig{AttackThreshold: attack},
	}}
	_ = initial
	return p
}

func TestSynFloodSubThresholdDisplay15269(t *testing.T) {
	prof := syn15269(200, 0)
	if got := SynFloodSubThresholdValue(prof.TCP.SynFlood.AlarmThreshold); got != "disabled" {
		t.Errorf("alarm unset = %q, want disabled", got)
	}
	if got := SynFloodSubThresholdValue(512); got != "512" {
		t.Errorf("alarm set = %q, want 512", got)
	}
	if SynFloodSubThresholdDefault(0, 512) != "512 (not applied)" {
		t.Errorf("default = %q", SynFloodSubThresholdDefault(0, 512))
	}
	// Timeout: unset + no flow -> 20; unset + flow initial 30 -> 30; set -> itself.
	cfg := &config.Config{}
	if got := EffectiveSynFloodTimeout(prof, cfg); got != 20 {
		t.Errorf("timeout unset no-flow = %d, want 20", got)
	}
	cfg.Security.Flow.TCPSession = &config.TCPSessionConfig{InitialTimeout: 30}
	if got := EffectiveSynFloodTimeout(prof, cfg); got != 30 {
		t.Errorf("timeout unset flow30 = %d, want 30", got)
	}
	prof.TCP.SynFlood.Timeout = 45
	if got := EffectiveSynFloodTimeout(prof, cfg); got != 45 {
		t.Errorf("timeout set = %d, want 45", got)
	}
	if got := EffectiveSynFloodTimeout(nil, cfg); got != 30 {
		t.Errorf("nil profile = %d, want 30", got)
	}
}

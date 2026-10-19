package userspace

import (
	"strconv"

	"github.com/psaab/xpf/pkg/config"
)

// #15269 B18-01: SYN-flood sub-threshold display must match enforcement.
// buildScreenSnapshots publishes a sub-threshold only when >0 and Rust
// treats 0 as disabled (no sketch; alarm maps to u32::MAX), so an unset
// value is NOT the Junos default — rendering "(default)" beside 512/4000
// claimed an applied cap that does not exist.

// SynFloodSubThresholdValue renders one SYN-flood sub-threshold's Value.
func SynFloodSubThresholdValue(v int) string {
	if v > 0 {
		return strconv.Itoa(v)
	}
	return "disabled"
}

// SynFloodSubThresholdDefault renders the Default column: plain Junos
// default when the value is applied (configured >0), else annotated
// "(not applied)" since enforcement treats 0 as disabled.
func SynFloodSubThresholdDefault(v, junosDefault int) string {
	if v > 0 {
		return strconv.Itoa(junosDefault)
	}
	return strconv.Itoa(junosDefault) + " (not applied)"
}

// EffectiveSynFloodTimeout resolves the Timeout row to the effective
// half-open opening window: the profile's syn-flood timeout when set,
// else security flow tcp-session initial-timeout, else the dataplane
// DEFAULT_TCP_OPENING_TIMEOUT_NS (20s).
func EffectiveSynFloodTimeout(p *config.ScreenProfile, cfg *config.Config) int {
	if p != nil && p.TCP.SynFlood != nil && p.TCP.SynFlood.Timeout > 0 {
		return p.TCP.SynFlood.Timeout
	}
	if cfg != nil && cfg.Security.Flow.TCPSession != nil && cfg.Security.Flow.TCPSession.InitialTimeout > 0 {
		return cfg.Security.Flow.TCPSession.InitialTimeout
	}
	return 20
}

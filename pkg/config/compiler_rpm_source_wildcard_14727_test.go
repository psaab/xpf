package config

import (
	"strings"
	"testing"
)

// #14727 leg 2 (commit-time half): an unspecified source-address
// ("0.0.0.0" / "::") parses to a non-nil IP, so the #2492 strict gate
// accepted it and the runtime bound the wildcard — measuring the
// default uplink while the operator believes a source-specific path
// is monitored. Strict must reject it like an unparseable source; the
// lenient path must warn (not brick, #1960); the runtime guard in
// pkg/rpm (validateProbeSourceAddress) holds the test if a wildcard
// still reaches it via lenient load or peer sync.
func TestRPMSourceAddressWildcardStrictRejects14727(t *testing.T) {
	for _, src := range []string{"0.0.0.0", "::"} {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target 1.1.1.1",
			"set services rpm probe P test t source-address " + src,
		}
		tree := buildTree(t, lines)
		_, err := CompileConfig(tree)
		if err == nil {
			t.Fatalf("CompileConfig accepted wildcard source-address %q; want strict reject", src)
		}
		if !strings.Contains(err.Error(), "source-address: invalid IP address") {
			t.Fatalf("err = %v, want substring %q", err, "source-address: invalid IP address")
		}
	}
}

func TestRPMSourceAddressWildcardLenientWarns14727(t *testing.T) {
	for _, src := range []string{"0.0.0.0", "::"} {
		lines := []string{
			"set services rpm probe P test t probe-type tcp-ping",
			"set services rpm probe P test t target 1.1.1.1",
			"set services rpm probe P test t source-address " + src,
		}
		tree := buildTree(t, lines)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("CompileConfigLenient must not fail on wildcard source %q (brick-on-restart): %v", src, err)
		}
		if !hasWarningSubstr(cfg.Warnings, "rpm source-address") {
			t.Fatalf("source %q: expected a downgraded rpm source-address warning, warnings=%v", src, cfg.Warnings)
		}
	}
}

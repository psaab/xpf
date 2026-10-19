package config

import (
	"strings"
	"testing"
)

// #15275 (C05-02): deterministic pool with `host address 0.0.0.0/0` committed
// clean on master — no reject, no #4559 advisory — while the dataplane builder
// (deterministicSourceNATFields, hostBits >= 32) and the forensic lookup
// (pkg/nat poolParams) both refuse a /0 and fall back to round-robin PAT.
// The strict capacity gate computed 1<<32 (fits uint64) and no realistic
// pool covers 2^32 blocks, so it rejected it for the wrong reason
// (insufficient capacity) rather than the /0 itself; and the warn predicate
// (bits == 32) treated it as enforced. The RED probe below shows the real
// failure mode: any pool that DOES cover the claimed capacity commits
// silently. Master capacity for /0 needs poolHosts*blocksPerIP >= 2^32;
// with the default port range 1024-65535 (64512 ports) and block-size 1,
// blocksPerIP = 64512, so a pool of >= 66578 v4 addresses covers it —
// a /16 pool member (65536 addrs) is just short, so use two such members
// covering 131072 addresses -> 131072*64512 blocks >> 2^32.

func detSlash0Cmds15275(blockSize, subscriber string) []string {
	return []string{
		"set security nat source pool CG address 203.0.113.0/16",
		"set security nat source pool CG address 198.51.100.0/16",
		"set security nat source pool CG port deterministic block-size " + blockSize,
		"set security nat source pool CG port deterministic host address " + subscriber,
	}
}

// FAIL-ON-REVERT: on master this commits clean with no advisory (bits==32
// in deterministicIPv4Enforced). After the fix the strict gate must reject
// /0 outright (fail-closed), regardless of pool capacity.
func TestDeterministicSlash0HostRejected15275(t *testing.T) {
	_, err := CompileConfig(natOverlapTree(t, detSlash0Cmds15275("1", "0.0.0.0/0")...))
	if err == nil {
		t.Fatal("#15275: deterministic host 0.0.0.0/0 must be rejected at commit (dataplane falls back to round-robin); committed clean on master")
	}
	if !strings.Contains(err.Error(), "/0") && !strings.Contains(err.Error(), "0.0.0.0/0") {
		t.Fatalf("#15275: reject must name the /0 host prefix, got: %v", err)
	}
	// Must NOT be the capacity error — /0 is rejected per se, not because
	// this (huge) pool is too small.
	if strings.Contains(err.Error(), "insufficient capacity") {
		t.Fatalf("#15275: /0 must be rejected as an unenforceable prefix, not via capacity; got: %v", err)
	}
}

// CONTROL: /1 still commits enforced — huge subscriber count (2^31) but
// capacity covers it (131072 addrs * 64512 blocks), and it must carry no
// #4559 advisory (mode 1 is genuinely enforced for /1: hostBits=31 < 32).
func TestDeterministicSlash1StillCommitsEnforced15275(t *testing.T) {
	cfg, err := CompileConfig(natOverlapTree(t, detSlash0Cmds15275("1", "0.0.0.0/1")...))
	if err != nil {
		t.Fatalf("#15275 control: /1 deterministic host must still commit; got: %v", err)
	}
	if deterministicAdvisoryPresent(cfg) {
		t.Fatalf("#15275 control: /1 is enforced (mode 1) and must NOT emit the #4559 advisory; got: %v", cfg.Warnings)
	}
}

// CONTROL: ordinary enforced prefix (/25, existing fixture shape) unchanged.
func TestDeterministicSlash25StillCommitsNoAdvisory15275(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, deterministicNATLines("2016", "100.64.0.0/25")))
	if err != nil {
		t.Fatalf("#15275 control: /25 must commit; got: %v", err)
	}
	if deterministicAdvisoryPresent(cfg) {
		t.Fatalf("#15275 control: /25 must not emit advisory; got: %v", cfg.Warnings)
	}
}

// Unit pin on the gate-vs-builder predicate split: the warn predicate must
// agree with deterministicSourceNATFields / poolParams (hostBits < 32).
func TestDeterministicIPv4EnforcedSlash0False15275(t *testing.T) {
	if deterministicIPv4Enforced(&DeterministicNATConfig{BlockSize: 1, HostAddress: "0.0.0.0/0"}) {
		t.Fatal("#15275: deterministicIPv4Enforced(0.0.0.0/0) must be false — builder returns mode 0 for hostBits>=32")
	}
	if !deterministicIPv4Enforced(&DeterministicNATConfig{BlockSize: 1, HostAddress: "0.0.0.0/1"}) {
		t.Fatal("#15275: deterministicIPv4Enforced(0.0.0.0/1) must stay true (hostBits=31, enforced)")
	}
	if !deterministicIPv4Enforced(&DeterministicNATConfig{BlockSize: 2016, HostAddress: "100.64.0.0/25"}) {
		t.Fatal("#15275: deterministicIPv4Enforced(/25) must stay true")
	}
}

// Lenient path: the strict reject downgrades to a warning and the pool is
// retained (#1960 no-brick), AND the #4559 accepted-but-not-enforced
// advisory must now fire for /0 (pre-fix deterministicIPv4Enforced returned
// true for bits==32, suppressing it). The retained pool still builds mode 0
// in the builder, so the operator must see both signals.
func TestDeterministicSlash0LenientWarnsAndAdvises15275(t *testing.T) {
	cfg, err := CompileConfigLenient(natOverlapTree(t, detSlash0Cmds15275("1", "0.0.0.0/0")...))
	if err != nil {
		t.Fatalf("#15275: lenient load must not brick on /0; got: %v", err)
	}
	if !deterministicAdvisoryPresent(cfg) {
		t.Fatalf("#15275: lenient /0 pool must emit the #4559 not-enforced advisory; got warnings: %v", cfg.Warnings)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "/0") {
			found = true
		}
	}
	if !found {
		t.Fatalf("#15275: lenient /0 pool must warn naming /0 (downgraded strict reject); got: %v", cfg.Warnings)
	}
}

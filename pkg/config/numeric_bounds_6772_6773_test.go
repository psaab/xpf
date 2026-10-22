package config

import (
	"math"
	"strings"
	"testing"
)

// #6772 / #6773: two typed leaves were min-only, and each fed a downstream
// domain that WRAPS rather than failing.
//
// They are the same class — "the schema admits a value the runtime's arithmetic
// cannot represent" — but they need different fixes, which is why both are here
// with their own cases:
//
//   - #6773 `system services dhcp-local-server … ttl` reaches a 32-bit unsigned
//     DNS RR header field. A single max bound at the wire domain fixes it.
//   - #6772 `chassis cluster heartbeat-threshold` is MULTIPLIED by
//     heartbeat-interval into a time.Duration. Neither field alone can be
//     capped usefully — a threshold safe at a 1 ms interval overflows at a large
//     one — so the PRODUCT is what must be validated.

// schemaCheck6773 drives SchemaValidate, which is where a typed-leaf validator
// runs. CompileConfig does NOT invoke it, so a test that only compiled would
// report the TTL bound as absent even when it is present — measured.
func schemaCheck6773(t *testing.T, sets ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range sets {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	return SchemaValidate(tree)
}

func compile6772(t *testing.T, sets ...string) error {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range sets {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	_, err := CompileConfig(tree)
	return err
}

func clusterSets6772(interval, threshold string) []string {
	return []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		// #6611 precondition: an unkeyed cluster is rejected on its own, which
		// would make every case below pass for the wrong reason.
		"set chassis cluster authentication-key test-cluster-psk-6772",
		"set chassis cluster heartbeat-interval " + interval,
		"set chassis cluster heartbeat-threshold " + threshold,
	}
}

// TestHeartbeatTimeoutProductMustBeRepresentable6772 is #6772's defect.
func TestHeartbeatTimeoutProductMustBeRepresentable6772(t *testing.T) {
	// interval 1000 ms with a threshold near MaxInt64: the product
	// time.Duration(threshold)*interval wraps negative, and a negative timeout
	// reads as already-expired.
	err := compile6772(t, clusterSets6772("1000", "9223372036854775807")...)
	if err == nil {
		t.Fatal("a heartbeat-threshold whose product with the interval overflows " +
			"time.Duration compiled CLEANLY. The dead-peer timeout wraps NEGATIVE, so both " +
			"nodes declare the peer lost on the first check — the liveness guard the " +
			"threshold exists to provide is inverted by the value that configures it")
	}
	if !strings.Contains(err.Error(), "heartbeat-threshold") {
		t.Errorf("rejected for the wrong reason: %v", err)
	}
}

// TestHeartbeatGraceDoublingIsAccountedFor6772 pins the factor of two.
//
// failover.go computes `2*time.Duration(threshold)*interval + slack`, so the
// DOUBLED form overflows first. A check written against the plain timeout would
// pass a pair that still inverts the transfer grace — and every test above
// would still be green.
func TestHeartbeatGraceDoublingIsAccountedFor6772(t *testing.T) {
	// Chosen to fit the PLAIN product and overflow the doubled one.
	const interval = int64(1000)
	justOverDoubled := MaxDurationMillis/(2*interval) + 1
	if justOverDoubled > MaxDurationMillis/interval {
		t.Fatalf("fixture broken: %d must fit the plain product", justOverDoubled)
	}

	err := compile6772(t, clusterSets6772("1000", itoa6772(justOverDoubled))...)
	if err == nil {
		t.Errorf("threshold %d with a 1000ms interval fits the plain timeout but overflows "+
			"the DOUBLED failover transfer grace, and compiled cleanly — the check is "+
			"written against the wrong expression", justOverDoubled)
	}
}

// TestOrdinaryHeartbeatSettingsStillCompile6772 is the TIGHTENING control.
//
// The shipped defaults and the Junos-documented range must keep compiling. A
// product check written with the comparison inverted, or with a stray factor,
// would satisfy both tests above while rejecting every real cluster config —
// and this validator runs on the commit path.
func TestOrdinaryHeartbeatSettingsStillCompile6772(t *testing.T) {
	for _, tc := range []struct{ interval, threshold string }{
		{"1000", "3"},   // Junos minimum threshold
		{"1000", "5"},   // xpf default
		{"1000", "8"},   // Junos maximum threshold
		{"30", "5"},     // the shipped 30ms RETH advertisement cadence
		{"200", "5"},    // the interval named throughout pkg/cluster
		{"60000", "10"}, // a deliberately slow cluster
	} {
		if err := compile6772(t, clusterSets6772(tc.interval, tc.threshold)...); err != nil {
			t.Errorf("interval=%s threshold=%s was REJECTED: %v — this is an ordinary "+
				"cluster configuration and the validator runs at commit",
				tc.interval, tc.threshold, err)
		}
	}
}

// TestUnsetIntervalStillBoundsTheThreshold6772 pins the zero contract, and it
// exists because a mutation found the gap.
//
// An earlier version SKIPPED validation when either field was unset, reasoning
// that zero means "use the default". But the runtime substitutes that default
// (group_state.go assigns only when > 0), so an unset interval paired with a
// huge threshold still overflows at run time — and skipping accepted exactly
// that pair. The validator now models the substitution instead.
func TestUnsetIntervalStillBoundsTheThreshold6772(t *testing.T) {
	err := compile6772(t,
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-6772",
		"set chassis cluster heartbeat-threshold 9223372036854775807",
	)
	if err == nil {
		t.Error("a huge heartbeat-threshold with an UNSET interval compiled cleanly. The " +
			"runtime substitutes its default interval, so the product still overflows and " +
			"the dead-peer timeout still wraps negative — an unset field is not 'no value'")
	}
}

// TestUnsetHeartbeatFieldsAreLeftAlone6772 pins the other side: a cluster with
// NEITHER field set must still compile, since the substituted defaults are
// small and cannot overflow.
func TestUnsetHeartbeatFieldsAreLeftAlone6772(t *testing.T) {
	if err := compile6772(t,
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-6772",
	); err != nil {
		t.Errorf("a cluster with neither heartbeat field set was rejected: %v", err)
	}
}

// TestDDNSTTLIsBoundedAtTheWireDomain6773 is #6773's defect.
func TestDDNSTTLIsBoundedAtTheWireDomain6773(t *testing.T) {
	base := []string{
		"set system services dhcp-local-server group g interface ge-0/0/0.0",
		"set system services dhcp-local-server dynamic-dns domain example.net",
	}
	// 2^32 is the first value that wraps to 0 in the RR header's uint32 TTL.
	// A zero TTL tells every resolver not to cache the record at all.
	err := schemaCheck6773(t, append(append([]string{}, base...),
		"set system services dhcp-local-server dynamic-dns ttl 4294967296")...)
	if err == nil {
		t.Error("a DDNS ttl of 2^32 compiled cleanly. The DNS RR header TTL is a 32-bit " +
			"unsigned wire field, so it WRAPS to 0 — telling every resolver not to cache " +
			"the record, which is a materially different answer from the one configured")
	}

	// And the largest representable TTL must still be accepted, or the bound is
	// off by one in the direction that rejects a legal value.
	if err := schemaCheck6773(t, append(append([]string{}, base...),
		"set system services dhcp-local-server dynamic-dns ttl 4294967295")...); err != nil {
		t.Errorf("the maximum representable TTL (2^32-1) was rejected: %v", err)
	}
}

// TestOrdinaryDDNSTTLStillCompiles6773 is the tightening control for the TTL
// bound — a max written too low would reject ordinary values.
func TestOrdinaryDDNSTTLStillCompiles6773(t *testing.T) {
	for _, ttl := range []string{"1", "300", "3600", "86400"} {
		err := schemaCheck6773(t,
			"set system services dhcp-local-server group g interface ge-0/0/0.0",
			"set system services dhcp-local-server dynamic-dns domain example.net",
			"set system services dhcp-local-server dynamic-dns ttl "+ttl)
		if err != nil {
			t.Errorf("ordinary DDNS ttl %s was rejected: %v", ttl, err)
		}
	}
}

// TestMaxDNSTTLMatchesTheWireField6773 pins the constant to the wire domain it
// claims, rather than to a hand-copied literal that can drift from its meaning.
func TestMaxDNSTTLMatchesTheWireField6773(t *testing.T) {
	if MaxDNSTTLSeconds != int64(math.MaxUint32) {
		t.Errorf("MaxDNSTTLSeconds = %d, want math.MaxUint32 (%d) — the bound must BE the "+
			"wire field's domain, not a literal that resembles it",
			MaxDNSTTLSeconds, int64(math.MaxUint32))
	}
}

func itoa6772(v int64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

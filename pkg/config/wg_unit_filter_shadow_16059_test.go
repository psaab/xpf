package config

import (
	"strings"
	"testing"
)

// #16059: units of an interface-level WireGuard tunnel share one wgN
// device/ifindex, and the dataplane keys interface filters by ifindex
// alone — differing per-unit filters would last-win (Rust now refuses
// the snapshot). The commit advisory must fire for differing input AND
// output filters, and stay silent for uniform, single-claimant,
// single-unit, per-unit-stanza, and GRE shapes (#10816 owns GRE input).
// Fail-on-revert: unhook the advisory and the firing assertions go RED.
func TestWgUnitFilterShadowAdvisory16059(t *testing.T) {
	compile := func(t *testing.T, lines []string) *Config {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range lines {
			p, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(p); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		return cfg
	}
	const priv = "21a8e89546569ec63441fbc82a72e6a59c0528cb39896d0adf84e77c4758e6b3"
	const peer = "258ca6d9d6515c4e5b2166b183d9cd1efacfb2ee6d1337cf525843c940b022ff"
	base := []string{
		"set firewall family inet filter F1 term t1 then accept",
		"set firewall family inet filter F2 term t1 then discard",
		"set firewall family inet6 filter F6 term t1 then accept",
		"set firewall family inet6 filter F7 term t1 then discard",
		"set interfaces wg0 tunnel mode wireguard",
		"set interfaces wg0 tunnel wireguard listen-port 51820",
		"set interfaces wg0 tunnel wireguard private-key " + priv,
		"set interfaces wg0 tunnel wireguard peer " + peer + " allowed-ips 10.66.0.0/24",
		"set interfaces wg0 unit 0 family inet address 10.5.5.1/30",
		"set interfaces wg0 unit 1 family inet address 10.6.6.1/30",
	}
	with := func(extra ...string) []string {
		return append(append([]string{}, base...), extra...)
	}

	// (a) differing OUTPUT v4 filters → exactly one #16059 warning.
	cfgA := compile(t, with(
		"set interfaces wg0 unit 0 family inet filter output F1",
		"set interfaces wg0 unit 1 family inet filter output F2",
	))
	gotA := warningsMentioning(cfgA, "#16059")
	if len(gotA) != 1 {
		t.Fatalf("(a) differing WG output filters must warn once, got %d: %v", len(gotA), cfgA.Warnings)
	}
	for _, want := range []string{"wg0.0", "wg0.1", "output"} {
		if !strings.Contains(gotA[0], want) {
			t.Fatalf("(a) warning must mention %q: %q", want, gotA[0])
		}
	}

	// (b) differing INPUT v6 filters → warns (WG input arm, not #10816).
	cfgB := compile(t, with(
		"set interfaces wg0 unit 0 family inet6 filter input F6",
		"set interfaces wg0 unit 1 family inet6 filter input F7",
		"set interfaces wg0 unit 0 family inet6 address fd00:5::1/64",
		"set interfaces wg0 unit 1 family inet6 address fd00:6::1/64",
	))
	if got := warningsMentioning(cfgB, "#16059"); len(got) != 1 {
		t.Fatalf("(b) differing WG input filters must warn once, got: %v", cfgB.Warnings)
	}

	// (c) uniform filters → silent.
	cfgC := compile(t, with(
		"set interfaces wg0 unit 0 family inet filter output F1",
		"set interfaces wg0 unit 1 family inet filter output F1",
	))
	if got := warningsMentioning(cfgC, "#16059"); len(got) != 0 {
		t.Fatalf("(c) uniform filters must be silent, got: %v", got)
	}

	// (d) single claimant (other unit names no filter) → silent: the one
	// configured filter deterministically applies.
	cfgD := compile(t, with(
		"set interfaces wg0 unit 0 family inet filter output F1",
	))
	if got := warningsMentioning(cfgD, "#16059"); len(got) != 0 {
		t.Fatalf("(d) single claimant must be silent, got: %v", got)
	}

	// (e) per-unit WG stanza on unit 1 (own device) → silent.
	cfgE := compile(t, with(
		"set interfaces wg0 unit 0 family inet filter output F1",
		"set interfaces wg0 unit 1 tunnel mode wireguard",
		"set interfaces wg0 unit 1 family inet filter output F2",
	))
	if got := warningsMentioning(cfgE, "#16059"); len(got) != 0 {
		t.Fatalf("(e) per-unit-stanza sibling must be silent, got: %v", got)
	}

	// (f) GRE interface tunnel with differing output filters is not this
	// advisory's shape (no WG device sharing).
	cfgF := compile(t, []string{
		"set firewall family inet filter F1 term t1 then accept",
		"set firewall family inet filter F2 term t1 then discard",
		"set interfaces gr-0/0/0 tunnel source 10.1.1.1",
		"set interfaces gr-0/0/0 tunnel destination 10.1.1.2",
		"set interfaces gr-0/0/0 unit 0 family inet address 10.255.192.42/30",
		"set interfaces gr-0/0/0 unit 0 family inet filter output F1",
		"set interfaces gr-0/0/0 unit 1 family inet address 10.255.193.42/30",
		"set interfaces gr-0/0/0 unit 1 family inet filter output F2",
	})
	if got := warningsMentioning(cfgF, "#16059"); len(got) != 0 {
		t.Fatalf("(f) GRE parent must be silent for #16059, got: %v", got)
	}
}

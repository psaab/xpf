package config

import (
	"strings"
	"testing"
)

// #3348: Junos rejects a user-defined `protocol junos-ping` (or junos-pingv6)
// leaf, but XPF retains it as a compatibility extension. Before that extension
// attached an echo type, custom apps lowered to bare ICMP and silently widened
// policies to every ICMP type. The compiler must keep the custom alias
// echo-constrained AND support explicit icmp-type/icmp-code grammar on custom
// applications. This differs from the predefined objects: junos-ping is
// all-ICMP (#11340), while junos-icmp-ping is echo-only.
//
// Trees are built from flat `set` commands via flatTreeFromSets — the only
// correct way to exercise the flat-set AST shape (see
// compiler_application_specs_test.go).

func refApp(name string, props ...string) []string {
	sets := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy p match source-address any",
		"set security policies from-zone trust to-zone untrust policy p match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p match application " + name,
		"set security policies from-zone trust to-zone untrust policy p then permit",
	}
	for _, p := range props {
		sets = append(sets, "set applications application "+name+" "+p)
	}
	return sets
}

// Core fail-on-revert: custom-app `protocol junos-ping` (XPF's compatibility
// extension) must lower to ICMP type 8. Revert the compiler change (alias
// default removed) and app.ICMPType stays nil, so this assertion goes RED.
func TestApplicationJunosPing_AttachesEchoType(t *testing.T) {
	cases := []struct {
		proto    string
		wantType uint8
	}{
		{"junos-ping", 8},
		{"junos-pingv6", 128},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("ping-app", "protocol "+c.proto)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept protocol %s: %v", c.proto, err)
			}
			app := cfg.Applications.Applications["ping-app"]
			if app == nil {
				t.Fatalf("application ping-app missing from compiled config")
			}
			if app.ICMPType == nil {
				t.Fatalf("protocol %s must attach an ICMP echo type; got nil (matches ALL ICMP — the #3348 widening)", c.proto)
			}
			if *app.ICMPType != c.wantType {
				t.Fatalf("protocol %s must lower to ICMP type %d, got %d", c.proto, c.wantType, *app.ICMPType)
			}
			if app.ICMPCode != nil {
				t.Fatalf("protocol %s must not pin a code, got %d", c.proto, *app.ICMPCode)
			}
		})
	}
}

// The all-ICMP aliases stay UNCONSTRAINED (nil type) — they intentionally match
// every ICMP type and must not gain the echo constraint.
func TestApplicationJunosIcmpAll_StaysUnconstrained(t *testing.T) {
	for _, proto := range []string{"junos-icmp-all", "junos-icmp6-all"} {
		t.Run(proto, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("all-icmp", "protocol "+proto)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept protocol %s: %v", proto, err)
			}
			if app := cfg.Applications.Applications["all-icmp"]; app == nil || app.ICMPType != nil {
				t.Fatalf("protocol %s must stay unconstrained (ICMPType nil), got %+v", proto, app)
			}
		})
	}
}

// Inline custom-app term: `term t protocol junos-ping` must attach the echo
// type to the generated term application too.
func TestApplicationJunosPing_InlineTerm_AttachesEchoType(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("ping-term", "term t protocol junos-ping")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept inline term protocol junos-ping: %v", err)
	}
	app := cfg.Applications.Applications["ping-term-t"]
	if app == nil {
		t.Fatalf("inline-term application ping-term-t missing; have %v", appNames(cfg))
	}
	if app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("inline term protocol junos-ping must lower to ICMP type 8, got %v", app.ICMPType)
	}
}

// Explicit grammar: `protocol icmp icmp-type 8 icmp-code 0` must wire through to
// the typed fields. Fail-on-revert: without the icmp-type/icmp-code schema
// leaves the set command is rejected at commit (unknown leaf), and without the
// compiler cases the fields stay nil.
func TestApplicationExplicitICMPTypeCode(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("echo", "protocol icmp", "icmp-type 8", "icmp-code 0")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept icmp-type/icmp-code grammar: %v", err)
	}
	app := cfg.Applications.Applications["echo"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("explicit icmp-type 8 must set ICMPType=8, got %+v", app)
	}
	if app.ICMPCode == nil || *app.ICMPCode != 0 {
		t.Fatalf("explicit icmp-code 0 must set ICMPCode=0, got %v", app.ICMPCode)
	}
}

// An explicit icmp-type wins over the custom-app junos-ping alias default.
func TestApplicationExplicitICMPTypeOverridesAlias(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("ovr", "protocol junos-ping", "icmp-type 13")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept explicit icmp-type override: %v", err)
	}
	app := cfg.Applications.Applications["ovr"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 13 {
		t.Fatalf("explicit icmp-type 13 must override the junos-ping echo default, got %+v", app)
	}
}

// #6868 note, recorded here because this is the file a future reader edits.
//
// The two guards below assert BARE `icmp-type` / `icmp-code` against messages
// that are not quoted-leaf messages, and they were deliberately left alone
// when #6868 converted the duplicate-leaf assertions to the quoted form. The
// reason is narrower than it first appears, and getting it wrong would lead a
// later sweep to exclude a site that IS vulnerable:
//
//   NOT because "the messages name both leaves on purpose". Both messages do
//   contain both tokens — `:154`'s names `icmp-type` twice — so a wrong-leaf
//   outcome IS detectable in principle: if either gate emitted the other's
//   message, both tests would still pass.
//
//   What actually saves these two is that the ALTERNATIVE REJECT IS
//   UNREACHABLE FOR THE INPUT. The icmp-code-without-type case compiles
//   `protocol icmp`, so the non-ICMP-protocol gate cannot fire; if its own
//   gate were removed the config would compile clean and the `err == nil`
//   check catches it.
//
// So the test to apply at a similar site is "can the other message reach this
// input?", not "does the message mention more than one leaf".

// Strict guard: icmp-type on a non-ICMP protocol is a never-match term — reject
// at commit (#3348, mirroring the #3373 port-on-non-port-protocol gate).
func TestApplicationICMPTypeOnNonICMPProtocol_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("bad", "protocol tcp", "icmp-type 8")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT icmp-type on protocol tcp")
	} else if !strings.Contains(err.Error(), "icmp-type") {
		t.Fatalf("error should mention icmp-type, got: %v", err)
	}
}

// Strict guard: an icmp-code without an icmp-type is an ambiguous half
// constraint — reject at commit.
func TestApplicationICMPCodeWithoutType_Rejected(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("bad2", "protocol icmp", "icmp-code 3")...)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("expected commit to REJECT icmp-code without icmp-type")
	} else if !strings.Contains(err.Error(), "icmp-code") {
		t.Fatalf("error should mention icmp-code, got: %v", err)
	}
}

// #4410 (F4): a protocol-less application that carries an icmp-type / icmp-code
// constraint is rejected by the #3109 "no protocol specified" gate. The reject
// message must NAME the icmp-type/icmp-code the operator already set — an
// operator who typed `icmp-type 8` and forgot `protocol` should be pointed at
// `protocol icmp` / `icmpv6`, not just told to "set a protocol". Fail-on-revert:
// without the icmpConstraintDesc hint the message omits the concrete
// `icmp-type 8` token and these assertions go RED (the bare "no protocol"
// message never contains "icmp-type 8").
func TestApplicationProtocolLessICMPType_RejectNamesConstraint(t *testing.T) {
	cases := []struct {
		name  string
		props []string
		want  string
	}{
		{"icmp-type only", []string{"icmp-type 8"}, "icmp-type 8"},
		{"icmp-type + icmp-code", []string{"icmp-type 8", "icmp-code 0"}, "icmp-type 8 icmp-code 0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("pinglike", c.props...)...)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to REJECT protocol-less icmp-type application")
			}
			if !strings.Contains(err.Error(), "no protocol specified") {
				t.Fatalf("error should still be the no-protocol reject, got: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("reject message must name the ICMP constraint %q, got: %v", c.want, err)
			}
		})
	}
}

// #3348 inline-term edge case 1 (widening INVERSION): an inline term that lists
// BOTH a custom-app junos-ping alias AND an unconstrained ICMP alias normalizes
// both to "icmp" and dedups to ONE term. The union of "echo" and "all-ICMP" is
// all-ICMP (the Rust matcher ORs separate app terms), so the collapsed term
// must stay UNCONSTRAINED — the custom alias echo type must NOT spuriously
// narrow it. Fail-on-revert: without the unconstrainedICMP suppression the term
// gets ICMPType=8 and this assertion goes RED.
func TestApplicationJunosPing_InlineTerm_MixedAllICMP_StaysUnconstrained(t *testing.T) {
	cases := []struct {
		name string
		term string
	}{
		{"ping-then-all", "term t protocol junos-ping protocol junos-icmp-all"},
		{"all-then-ping", "term t protocol junos-icmp-all protocol junos-ping"},
		{"ping-then-bare-icmp", "term t protocol junos-ping protocol icmp"},
		{"pingv6-then-all6", "term t protocol junos-pingv6 protocol junos-icmp6-all"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("mixed", c.term)...)
			cfg, err := CompileConfig(tree)
			if err != nil {
				t.Fatalf("expected commit to accept %q: %v", c.term, err)
			}
			app := cfg.Applications.Applications["mixed-t"]
			if app == nil {
				t.Fatalf("inline-term application mixed-t missing; have %v", appNames(cfg))
			}
			if app.ICMPType != nil {
				t.Fatalf("a term mixing junos-ping with an all-ICMP alias must stay UNCONSTRAINED (ICMPType nil — union is all-ICMP), got type %d", *app.ICMPType)
			}
		})
	}
}

// #3348 inline-term edge case 2 (fail-open): a malformed inline-term icmp-type
// must NOT be silently dropped (which would leave the term matching ALL ICMP).
// The schema does not validate inside an opaque `term`, so the compiler records
// it on UnknownICMP and the strict gate rejects it at commit. Fail-on-revert:
// without the badICMP recording the value is dropped, the term compiles
// unconstrained, CompileConfig succeeds, and this assertion goes RED.
func TestApplicationICMPType_InlineTerm_Malformed_Rejected(t *testing.T) {
	cases := []string{
		"term t protocol icmp icmp-type 999",
		"term t protocol icmp icmp-type notanumber",
		"term t protocol icmp icmp-type 8 icmp-code 300",
	}
	for _, term := range cases {
		t.Run(term, func(t *testing.T) {
			tree := flatTreeFromSets(t, refApp("badterm", term)...)
			if _, err := CompileConfig(tree); err == nil {
				t.Fatalf("expected commit to REJECT malformed inline icmp-type/code %q", term)
			} else if !strings.Contains(err.Error(), "icmp-type/icmp-code") {
				t.Fatalf("error should mention icmp-type/icmp-code, got: %v", err)
			}
		})
	}
}

// A WELL-FORMED inline-term icmp-type still wires through (guards the above
// against over-rejection).
func TestApplicationICMPType_InlineTerm_Valid(t *testing.T) {
	tree := flatTreeFromSets(t, refApp("okterm", "term t protocol icmp icmp-type 8")...)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("expected commit to accept inline icmp-type 8: %v", err)
	}
	app := cfg.Applications.Applications["okterm-t"]
	if app == nil || app.ICMPType == nil || *app.ICMPType != 8 {
		t.Fatalf("inline term icmp-type 8 must set ICMPType=8, got %+v", app)
	}
}

func appNames(cfg *Config) []string {
	var n []string
	for name := range cfg.Applications.Applications {
		n = append(n, name)
	}
	return n
}

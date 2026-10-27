package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6524 review fold — the VERDICT-level guard on unknown-token recovery.
//
// Once the compiler follows the flat-set chain, an unrepresentable token in the
// direct body must POISON the rest of that run rather than be skipped so a later
// recognized keyword can be compiled. Recovering the keyword is a fail-open on
// the TOLERANT path (boot load / HA SyncApply), where the strict reject is only
// a warning:
//
//	set applications application myapp bogus value protocol tcp
//
// Master ignored the unrecognized child node whole, leaving `myapp`
// PROTOCOL-LESS and therefore unrepresentable — the matcher reports
// ContentRejected and the #2124 capability gate refuses to arm, so nothing is
// permitted. Skipping `bogus` and compiling `protocol tcp` turns that inert
// residual into an ACTIVE all-TCP permit.
//
// This is asserted on the VERDICT, not on a warning or a struct field. Every
// previous guard in this PR family asserted on structure and missed a widening;
// "a warning was emitted" is compatible with the traffic being permitted.
//
// RED-on-revert: change the unknown-token branch of applicationDirectLeaves
// back to `i++; continue` (skip and keep scanning) and both subtests report
// Matched=true / PolicyPermit for tcp/22 instead of the fail-closed retention.
func unknownRecoveryCfg(t *testing.T, appLine string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		appLine,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application myapp",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// The TOLERANT path is the one at risk: it downgrades the strict reject to
	// a warning and keeps enforcing whatever compiled.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}

func TestUnknownDirectTokenDoesNotArmAPermit(t *testing.T) {
	cases := []struct {
		name string
		set  string
	}{
		{
			// A typo'd statement followed by a real one.
			name: "unknown statement then protocol",
			set:  "set applications application myapp bogus value protocol tcp",
		},
		{
			// A bracket tail followed by a real statement — same root, different
			// ordering.
			name: "bracket tail then protocol",
			set:  "set applications application myapp destination-port [ 22 23 ] protocol tcp",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := unknownRecoveryCfg(t, c.set)
			res := Match(cfg, Query{
				FromZone: "trust", ToZone: "untrust",
				SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
				Protocol: "tcp", SrcPort: PortPtr(40000), DstPort: PortPtr(22),
			})
			if res.Matched && res.Action == config.PolicyPermit {
				t.Fatalf("tcp/22 was PERMITTED by an application whose body contains "+
					"unrepresentable content (%q) — the token after it was RECOVERED, "+
					"arming a protocol the operator never authored. Master left this "+
					"application protocol-less and fail-closed; the tolerant path must "+
					"not be WIDER than master (#6524)", c.set)
			}
			// Positive half: it is fail-closed for the same reason master was —
			// the application is unrepresentable, so the whole snapshot is
			// retained rather than a fabricated verdict being reported.
			if !res.ContentRejected {
				t.Fatalf("expected ContentRejected (the protocol-less application is "+
					"unrepresentable, matching master's behaviour), got %+v", res)
			}
		})
	}
}

// TestStrayStatementDoesNotDisarmSiblingLeaves is the paired over-reach guard at
// the verdict level: poisoning is scoped to the node carrying the unparsable
// token. A stray statement on its own `set` line must leave a well-formed
// application fully armed — master compiled those sibling leaves normally, and
// over-poisoning would silently turn a working permit into a fail-closed
// snapshot for the entire config.
func TestStrayStatementDoesNotDisarmSiblingLeaves(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set applications application myapp protocol tcp",
		"set applications application myapp destination-port 8080",
		"set applications application myapp bogus value",
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy allow match source-address any",
		"set security policies from-zone trust to-zone untrust policy allow match destination-address any",
		"set security policies from-zone trust to-zone untrust policy allow match application myapp",
		"set security policies from-zone trust to-zone untrust policy allow then permit",
		"set security policies default-policy deny-all",
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
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	q := func(port int) Result {
		return Match(cfg, Query{
			FromZone: "trust", ToZone: "untrust",
			SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
			Protocol: "tcp", SrcPort: PortPtr(40000), DstPort: PortPtr(uint16(port)),
		})
	}
	if res := q(8080); !res.Matched || res.Action != config.PolicyPermit {
		t.Fatalf("tcp/8080 = matched:%v action:%v rejected:%v, want PERMIT — a stray "+
			"SIBLING statement must not disarm leaves master compiled normally",
			res.Matched, res.Action, res.ContentRejected)
	}
	if res := q(22); res.Matched && res.Action == config.PolicyPermit {
		t.Fatalf("tcp/22 was PERMITTED — the sibling leaves must still constrain " +
			"the port")
	}
}

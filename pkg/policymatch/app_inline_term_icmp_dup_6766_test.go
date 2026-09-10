package policymatch

import (
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6766 review fold — the VERDICT-level guard on inline-term ICMP duplicates.
//
// The strict gate rejects a conflicting `icmp-type` / `icmp-code` repeat inside
// one inline term, but the TOLERANT path (boot load / HA SyncApply) downgrades
// that reject to a warning. The compiled term keeps only the LAST value, so what
// the tolerant path does with that term is an enforcement outcome, not
// bookkeeping: under `default-policy permit-all` every discarded value would
// escape the deny.
//
// #6766 and #6814 pinned the keep-last narrowing here, at the verdict, so that a
// keep-first regression flipped a concrete permit/deny. #9525 changed the
// verdict: the userspace expansion now refuses an application whose conflicting
// match leaf kept only one value (config.ApplicationReferenceMatchDrops), the
// policy lowers to the #3261 sentinel, and the simulator reports the snapshot as
// REFUSED for the last and the first value alike. Which value survives no longer
// reaches a traffic decision; it is still pinned at the compiled struct in
// pkg/config/compiler_application_term_icmp_dup_6766_test.go.
//
// RED-on-revert: delete the #6766 duplicate tracking, or the #9525 duplicate
// arms, and nothing refuses the policy: the last value is denied again and the
// first falls through, so every refusal assertion below fails.

// inlineICMPDupCfg builds a deny policy referencing an application whose single
// inline term repeats an ICMP leaf with conflicting values, then compiles it on
// the TOLERANT path.
//
// It also BINDS THE DUPLICATE RECORDING (#6814 gate). Before #9525, deleting the
// #6766 tracking outright left every verdict unchanged, because the compiled
// values were identical whether or not the conflict was recorded, so the two
// checks below were the only binding. The refusal now depends on the recording
// too, and the checks stay: the recording is also what makes strict reject and
// what puts the operator-visible warning on the tolerant path.
func inlineICMPDupCfg(t *testing.T, appLine, leaf string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		appLine,
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security policies from-zone trust to-zone untrust policy blockit match source-address any",
		"set security policies from-zone trust to-zone untrust policy blockit match destination-address any",
		"set security policies from-zone trust to-zone untrust policy blockit match application badapp",
		"set security policies from-zone trust to-zone untrust policy blockit then deny",
		// permit-all is what the narrowed-away traffic escapes into. It is the
		// reason the narrowing is a fail-OPEN and not merely a lost match.
		"set security policies default-policy permit-all",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// The conflict must be RECORDED: strict commit refuses it and names the leaf.
	serr := func() error { _, e := config.CompileConfig(tree); return e }()
	if serr == nil {
		t.Fatalf("strict commit must REJECT the conflicting inline %q — if it does not, "+
			"the #6766 duplicate recording is gone and the narrowing below is "+
			"reachable through a green commit", leaf)
	}
	// The leaf name is matched in its QUOTED form. The rejection text ends with a
	// static enumeration of every trackable leaf —
	// "(destination-port / source-port / ... / icmp-type / icmp-code)" — so a bare
	// substring check for the leaf is satisfied by that boilerplate no matter
	// which leaf actually conflicted, and a swapped label would sail through.
	// Only the identifying occurrence is quoted (`conflicting duplicate
	// "icmp-type" inside`), so quoting is what makes "names the leaf" true.
	if !strings.Contains(serr.Error(), "duplicate") || !strings.Contains(serr.Error(), `"`+leaf+`"`) {
		t.Fatalf("strict rejection should name the duplicate leaf %q (quoted, so the "+
			"static leaf enumeration in the message cannot satisfy this), got: %v", leaf, serr)
	}

	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must not brick on a conflicting inline ICMP repeat: %v", err)
	}
	// ...and the tolerant path must still SAY so. This is the only signal an
	// operator gets on the path that keeps forwarding, so it is part of the
	// contract these verdict tests characterize.
	warned := false
	for _, w := range cfg.Warnings {
		// Quoted, for the same reason as the strict assertion above.
		if strings.Contains(w, "duplicate") && strings.Contains(w, `"`+leaf+`"`) {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatalf("tolerant path must record a downgrade warning naming %q — the "+
			"narrowing asserted below is otherwise completely silent; warnings: %v",
			leaf, cfg.Warnings)
	}
	return cfg
}

func icmpQuery(icmpType, icmpCode *uint8) Query {
	return Query{
		FromZone: "trust", ToZone: "untrust",
		SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"),
		Protocol: "icmp",
		ICMPType: icmpType, ICMPCode: icmpCode,
	}
}

// TestInlineTermICMPTypeDupRefusedOnTolerantPath_6766 pins what the tolerant
// path does with a conflicting inline icmp-TYPE, at the verdict: it refuses the
// policy for the LAST authored type (which it used to deny) and for the FIRST
// (which used to fall through to permit-all).
func TestInlineTermICMPTypeDupRefusedOnTolerantPath_6766(t *testing.T) {
	// Authored `icmp-type 8` then `icmp-type 3`: the compiled term keeps 3.
	cfg := inlineICMPDupCfg(t,
		"set applications application badapp term t1 protocol icmp icmp-type 8 icmp-type 3",
		"icmp-type")
	assertRefused6766(t, Match(cfg, icmpQuery(u8(3), nil)), "ICMP type 3 (the LAST authored icmp-type)")
	assertRefused6766(t, Match(cfg, icmpQuery(u8(8), nil)), "ICMP type 8 (the FIRST authored icmp-type)")
}

// TestInlineTermICMPCodeDupRefusedOnTolerantPath_6766 is the icmp-CODE analogue.
func TestInlineTermICMPCodeDupRefusedOnTolerantPath_6766(t *testing.T) {
	// Authored `icmp-code 1` then `icmp-code 2` under a fixed type 3.
	cfg := inlineICMPDupCfg(t,
		"set applications application badapp term t1 protocol icmp icmp-type 3 icmp-code 1 icmp-code 2",
		"icmp-code")
	assertRefused6766(t, Match(cfg, icmpQuery(u8(3), u8(2))), "ICMP type 3 code 2 (the LAST authored icmp-code)")
	assertRefused6766(t, Match(cfg, icmpQuery(u8(3), u8(1))), "ICMP type 3 code 1 (the FIRST authored icmp-code)")
}

// assertRefused6766 asserts the simulator reports the snapshot as refused and
// names the application. ContentRejected is set only by the content-rejection
// gate, so unlike an "action is permit" check (PolicyPermit is the zero value,
// the #6814 trap) it cannot be satisfied by a Result nothing populated.
func assertRefused6766(t *testing.T, res Result, what string) {
	t.Helper()
	if !res.ContentRejected {
		t.Fatalf("%s: want ContentRejected — the tolerant path must refuse a policy whose "+
			"application kept only one of two conflicting values (#9525) instead of enforcing "+
			"the narrowed term; got matched=%v action=%v default_used=%v",
			what, res.Matched, res.Action, res.DefaultUsed)
	}
	if res.Matched || res.DefaultUsed {
		t.Fatalf("%s: a refused snapshot must not also report a policy or default verdict; "+
			"got matched=%v default_used=%v", what, res.Matched, res.DefaultUsed)
	}
	named := false
	for _, r := range res.ContentRejectionReasons {
		if strings.Contains(r, `application "badapp"`) {
			named = true
		}
	}
	if !named {
		t.Fatalf("%s: the refusal must name application \"badapp\"; reasons: %v",
			what, res.ContentRejectionReasons)
	}
}

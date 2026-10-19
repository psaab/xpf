package dataplane

// #6894 r8 F6: the pre-pass must not log SUCCESS for work it did not perform.
//
// Every dataplane write in the pre-pass is a no-op on the discarding shim, yet
// the covered phases logged "static NAT compilation complete", "compiled NAT64
// prefix", "flow timeouts compiled" and friends unconditionally. On a FAILED
// apply an operator therefore read a journal that reported a compile
// succeeding and then failing, for a compile whose result was thrown away.
//
// WARN duplication inside the same phases is deliberately NOT addressed here
// and stays on #6903: a soft-skip diagnostic appearing twice is noise, whereas
// a success record for work that did not happen is a false claim.

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// prepassSuccessLogMarkers are the message substrings that assert completed
// work. They are matched against the message only, not the whole record, so an
// attribute that happens to contain one of these words cannot produce a false
// red.
var prepassSuccessLogMarkers = []string{
	"compiled", "complete", "registered", "auto-assigned", "IP resolved",
}

// captureSlog redirects the default logger into a buffer for the duration of
// the test. Same idiom as armproof_5275_test.go.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// successLogLines returns the captured INFO records whose MESSAGE carries one
// of the completed-work markers.
//
// It returns the WHOLE line, not the extracted message (#6894 r9 F2). The
// marker match still runs against the message alone -- an attribute containing
// "compiled" must not produce a false red -- but two of the gated sites emit
// the SAME message and differ only in an attribute (`default policy compiled`
// with action=permit-all vs action=deny-all). Returning messages made those two
// indistinguishable, so the over-reach arm bound whichever arm the fixture
// happened to take and the other could be suppressed on both passes unnoticed.
func successLogLines(buf *bytes.Buffer) []string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || !strings.Contains(line, "level=INFO") {
			continue
		}
		// slog's text handler renders the message as msg="..." (quoted when it
		// contains spaces, which every one of these does).
		i := strings.Index(line, `msg="`)
		if i < 0 {
			continue
		}
		rest := line[i+len(`msg="`):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			continue
		}
		msg := rest[:j]
		for _, marker := range prepassSuccessLogMarkers {
			if strings.Contains(msg, marker) {
				out = append(out, line)
				break
			}
		}
	}
	return out
}

// warnLogLines returns the captured WARN records' messages.
//
// The WARN family is out of F6's scope as a DUPLICATION concern (#6903 owns
// that). It is in scope here for one reason: exactly one WARN site carries an
// `!isValidationPass(dp)` gate, and a gate nothing observes can be widened to
// suppress the real pass too — which would lose an operator diagnostic on a
// security-relevant fail-open path. See the assertion in the over-reach test.
func warnLogLines(buf *bytes.Buffer) []string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if line == "" || !strings.Contains(line, "level=WARN") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// logProbeConfig is idProbeConfig plus the stanzas that make the REMAINING
// gated records reachable. idProbeConfig itself is deliberately left alone: it
// is the ID-determinism fixture and every column of that comparison is pinned
// to its current shape.
//
// Each addition exists to reach ONE otherwise-unreachable gated site (#6894 r9
// F2). Before them the over-reach arm named 13 of the 19 gated records, so six
// gates could be widened to suppress the REAL pass as well with the package
// still green.
func logProbeConfig() *config.Config {
	cfg := idProbeConfig()
	// compileFlowTimeouts' success record.
	cfg.Security.Flow.UDPSessionTimeout = 60
	// `source NAT off rule compiled`: the no-NAT exemption branch (#3844) is a
	// separate write path from the pool and interface branches idProbeConfig
	// already carries, with its own gated record.
	cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &config.NATRuleSet{
		Name: "rs-off-6894", FromZone: "trust", ToZone: "dmz",
		Rules: []*config.NATRule{
			{Name: "r-off", Match: config.NATMatch{SourceAddress: "10.9.0.0/16"},
				Then: config.NATThen{Type: config.NATSource, Off: true}},
		},
	})
	// `persistent NAT pool registered`: guarded by `dp.GetPersistentNAT() !=
	// nil`, so it needs BOTH a persistent-nat pool here and a dataplane that
	// answers with a live table (persistentNATLoggingDP below).
	cfg.Security.NAT.SourcePools["pool-pnat-6894"] = &config.NATPool{
		Name: "pool-pnat-6894", Addresses: []string{"192.0.2.90"},
		PersistentNAT: &config.PersistentNATConfig{
			Permit:            config.PersistentNATPermitAnyRemoteHost,
			InactivityTimeout: 120,
		},
	}
	cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &config.NATRuleSet{
		Name: "rs-pnat-6894", FromZone: "dmz", ToZone: "egress",
		Rules: []*config.NATRule{
			{Name: "r-pnat", Match: config.NATMatch{SourceAddress: "10.8.0.0/16"},
				Then: config.NATThen{Type: config.NATSource, PoolName: "pool-pnat-6894"}},
		},
	})
	// `no IP addresses for interface SNAT`: the one gated WARN. Interface-mode
	// SNAT into a zone whose member declares no addresses.
	cfg.Security.Zones["noaddr6894"] = &config.ZoneConfig{
		Name: "noaddr6894", Interfaces: []string{"xpfp4960n.0"},
	}
	cfg.Interfaces.Interfaces["xpfp4960n"] = &config.InterfaceConfig{
		Name: "xpfp4960n", RedundancyGroup: 1,
		Units: map[int]*config.InterfaceUnit{0: {Number: 0}},
	}
	cfg.Security.NAT.Source = append(cfg.Security.NAT.Source, &config.NATRuleSet{
		Name: "rs-noaddr-6894", FromZone: "trust", ToZone: "noaddr6894",
		Rules: []*config.NATRule{
			{Name: "r-noaddr", Match: config.NATMatch{SourceAddress: "10.7.0.0/16"},
				Then: config.NATThen{Type: config.NATSource, Interface: true}},
		},
	})
	return cfg
}

// persistentNATLoggingDP is the real-pass driver's dataplane: notAValidationDP
// plus a LIVE persistent-NAT table.
//
// The pre-pass fake answers GetPersistentNAT with a typed nil ON PURPOSE
// (prePassShimDivergence documents why: modelling a real table would make the
// pre-pass CLEAR and REPOPULATE the live one from a discarded compile). A
// consequence is that the `persistent NAT pool registered` gate CANNOT fire on
// the pre-pass path it nominally protects — the whole block is skipped one
// level up. That makes the gate defensive rather than load-bearing, and it is
// the negative arm alone that is unbindable: the REAL pass reaches the record
// whenever the dataplane has a table, which is what this type supplies.
type persistentNATLoggingDP struct {
	notAValidationDP
	pnat *PersistentNATTable
}

func (d *persistentNATLoggingDP) GetPersistentNAT() *PersistentNATTable { return d.pnat }

// TestPrePassLogsNoSuccessForWorkItDidNotDo_4960 is the fail-on-revert guard
// for F6.
//
// RED-on-revert: drop any one of the `!isValidationPass(dp)` gates added around
// the covered phases' completed-work records and this fails with "the pre-pass
// logged N success record(s)", naming them.
// NEGATIVE-ARM REACH, MEASURED rather than reasoned about (#6894 r9 F2).
//
// Driving the pre-pass's own rows with every gate neutralised shows which gated
// records it can reach at all. Of the 18 `!isValidationPass(dp)` sites, 16 are
// named in gatedRecordWants and bound by the base run; the other two — the
// deny-all default-policy arm and the one gated WARN — are bound by their own
// assertions in TestRealPassStillLogsItsSuccesses_4960. TWO of the eighteen are
// NOT reachable on the pre-pass, and neither is an oversight — both are
// properties of the shim production actually uses:
//
//   - `SNAT egress IP resolved` — compileNAT's interface-SNAT branch resolves its
//     egress member through result.cachedInterfaceByName, and production's
//     validateBeforeMutate builds a newValidationResult whose ifCache is EMPTY
//     (only compileZones populates it). The branch soft-skips before the record.
//   - `persistent NAT pool registered` — the shim's GetPersistentNAT returns a
//     typed nil ON PURPOSE (see prePassShimDivergence), so the whole
//     persistent-NAT block is skipped one level up.
//
// Both gates are therefore DEFENSIVE on the pre-pass: they cannot fire on the
// path they nominally protect, and removing either leaves this test green. That
// is stated rather than papered over. Their over-reach arm IS bound —
// gatedRecordWants names both, and the real-pass driver supplies the seeded
// ifCache and the live table that reach them — so the direction that loses an
// operator record is covered.
func TestPrePassLogsNoSuccessForWorkItDidNotDo_4960(t *testing.T) {
	// Two runs, one per default-policy arm: compileDefaultPolicy gates its
	// permit-all and deny-all records in SEPARATE blocks, and PolicyPermit is
	// config's zero value, so a single run reaches only the permit-all one.
	for _, tc := range []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"default-permit", func(*config.Config) {}},
		{"default-deny", func(c *config.Config) { c.Security.DefaultPolicy = config.PolicyDeny }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := logProbeConfig()
			tc.mutate(cfg)

			buf := captureSlog(t)
			if err := validateBeforeMutate(cfg); err != nil {
				t.Fatalf("the probe config must validate clean, or the pre-pass aborts "+
					"before reaching the phases whose logging is under test: %v", err)
			}
			if got := successLogLines(buf); len(got) != 0 {
				t.Errorf("the pre-pass logged %d success record(s) for writes that are "+
					"no-ops on the discarding shim. An operator reading the journal of a "+
					"FAILED apply sees a compile succeeding and then failing, for a "+
					"compile whose result was thrown away (#6894 r8 F6):\n  %s",
					len(got), strings.Join(got, "\n  "))
			}

			// The one gated WARN. F6's SCOPE is unchanged — the other 25 WARN
			// sites are ungated and stay on #6903 — but a gate this PR adds and
			// nothing observes is a gate that can be removed silently, so bind
			// the one that exists (#6894 r9 F2).
			for _, line := range warnLogLines(buf) {
				if strings.Contains(line, "no IP addresses for interface SNAT") {
					t.Errorf("the pre-pass emitted the interface-SNAT no-address "+
						"warning; the real pass emits it again, so the operator "+
						"reads the same diagnostic twice for one apply:\n  %s", line)
				}
			}
		})
	}
}

// TestRealPassStillLogsItsSuccesses_4960 is the over-reach guard, and the
// non-vacuity control for the test above: without it, "the pre-pass logged
// nothing" would also be satisfied by a fixture that reaches no logging phase,
// or by gates that suppress the records on BOTH passes.
//
// It drives the SAME rows over the SAME config with a dataplane that does not
// carry the validation marker — which is what a real pass looks like to
// isValidationPass — and requires the records back. Stays GREEN under the F6
// revert.
// gatedRecordWants is the over-reach arm's target list: one entry per
// `!isValidationPass(dp)` site the REAL pass can reach with this fixture.
//
// It is asserted COMPLETE against the production gate count by
// TestOverReachArmCoversEveryReachableGate_4960 below, so a newly gated site
// cannot be added without either binding it here or recording why it is
// unreachable. Before #6894 r9 this list held 13 of the 19 gates and nothing
// noticed the other six.
//
// Two entries pin an ATTRIBUTE, not just the message: compiler.go's two default
// policy arms emit the identical message and differ only in `action=`, so a
// message-only want binds whichever arm the fixture takes and leaves the other
// free to be suppressed on both passes.
var gatedRecordWants = []string{
	// #6420: the v4/v6 pair collapsed to ONE record when the per-address-family
	// snat_rules / snat_rules_v6 writes were deleted — the compiler no longer
	// has a per-family record to log, only the rule.
	"source NAT rule compiled",     // compileNAT, pool + interface mode
	"source NAT off rule compiled", // compileNAT, no-NAT exemption (#3844)
	"SNAT egress IP resolved",      // compileNAT, interface mode, resolved egress
	"persistent NAT pool registered",
	"destination NAT rule compiled",
	"static NAT rule compiled",
	"static NAT compilation complete",
	"nptv6 rule compiled",
	"nptv6 compilation complete",
	"compiled NAT64 prefix",
	"NAT64 compilation complete",
	"auto-assigned NAT64 source pool",
	"screen profile compiled",
	"flow timeouts compiled",
	// PolicyPermit is config's ZERO value, so the base fixture takes the
	// permit-all arm; the deny-all arm gets its own run below.
	`msg="default policy compiled" action=permit-all`,
	"flow config compiled",
}

// runRealPassPhases drives the pre-pass's OWN row set against a dataplane that
// reports FALSE for the validation marker — which is what a real pass looks
// like to isValidationPass — and returns the captured log.
//
// The rows are invoked directly because validateBeforeMutateWith refuses an
// unmarked dp by design. `seededEgressResult` rather than `newValidationResult`
// is what makes compileNAT's interface-SNAT branch resolve its egress member
// instead of soft-skipping, which is the only way to reach `SNAT egress IP resolved`
// without naming a live host link in a fixture (#6894 r3 F1 uses the same seed).
func runRealPassPhases(t *testing.T, cfg *config.Config) *bytes.Buffer {
	t.Helper()
	// The same prelude validateBeforeMutateWithResult runs before its rows:
	// without it the policies row cannot resolve a zone and the driver never
	// reaches the phases whose logging is under test.
	result := seededEgressResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)

	dp := &persistentNATLoggingDP{pnat: NewPersistentNATTable()}
	buf := captureSlog(t)
	for _, phase := range validationPhases(dp, cfg, result) {
		if err := phase.run(); err != nil {
			t.Fatalf("row %q rejected the probe config: %v", phase.name, err)
		}
	}
	return buf
}

func TestRealPassStillLogsItsSuccesses_4960(t *testing.T) {
	cfg := logProbeConfig()
	got := successLogLines(runRealPassPhases(t, cfg))

	// Name the specific records, per phase family: a bare non-empty check would
	// be satisfied by one surviving record while every other gate had been
	// widened to suppress both passes.
	for _, want := range gatedRecordWants {
		found := false
		for _, line := range got {
			if strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the REAL pass no longer logs %q. Either the #6894 r8 F6 gate "+
				"was widened past the validation pass and now suppresses the record "+
				"an operator needs, or this fixture stopped reaching that phase — "+
				"which would make TestPrePassLogsNoSuccessForWorkItDidNotDo_4960 "+
				"vacuous for it\n  have: %s", want, strings.Join(got, "\n        "))
		}
	}

	// The OTHER default-policy arm. Same message, different action, a separate
	// `if !isValidationPass(dp)` block in compiler.go — so it needs its own run.
	denyCfg := logProbeConfig()
	denyCfg.Security.DefaultPolicy = config.PolicyDeny
	denyGot := successLogLines(runRealPassPhases(t, denyCfg))
	const wantDeny = `msg="default policy compiled" action=deny-all`
	found := false
	for _, line := range denyGot {
		if strings.Contains(line, wantDeny) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("the REAL pass no longer logs %q. compileDefaultPolicy gates its "+
			"two arms in SEPARATE blocks; binding only the permit-all arm leaves "+
			"the deny-all one free to be suppressed on both passes (#6894 r9 F2)"+
			"\n  have: %s", wantDeny, strings.Join(denyGot, "\n        "))
	}

	// The one gated WARN. It is not a success record and F6's scope is success
	// records — but it IS gated, so without this the gate could be widened to
	// swallow an operator diagnostic on a fail-open path (interface-mode SNAT
	// silently doing nothing because the egress member has no address).
	const wantWarn = "no IP addresses for interface SNAT"
	warns := warnLogLines(runRealPassPhases(t, logProbeConfig()))
	foundWarn := false
	for _, line := range warns {
		if strings.Contains(line, wantWarn) {
			foundWarn = true
			break
		}
	}
	if !foundWarn {
		t.Errorf("the REAL pass no longer warns %q — the only gated WARN site can "+
			"now be suppressed on both passes, losing the diagnostic for an "+
			"interface-SNAT rule that silently translates nothing (#6894 r9 F2)"+
			"\n  have: %s", wantWarn, strings.Join(warns, "\n        "))
	}
}

// TestOverReachArmCoversEveryReachableGate_4960 is what stops gatedRecordWants
// from silently falling behind production.
//
// The list above is hand-written; the gate COUNT is derived by scanning the
// compiler sources for `isValidationPass(` call sites. A newly gated record
// added without a want (or without an entry in the unbindable table) reds here,
// which is the failure mode #6894 r9 F2 reported: six gates existed with no
// over-reach coverage and the package stayed green when they were widened to
// suppress both passes.
//
// This counts SITES, not records, and the two are not equal — hence the
// explicit reconciliation below rather than a bare `len(wants) == len(sites)`.
func TestOverReachArmCoversEveryReachableGate_4960(t *testing.T) {
	// Gated sites this fixture cannot drive to the REAL-pass branch, each with
	// the reason. An honest scope statement, not a silent gap.
	unbindable := map[string]string{
		"compiler.go:default policy deny-all": "same message as the permit-all arm " +
			"(PolicyPermit is config's zero value, so the base fixture takes " +
			"permit-all); bound by the SECOND run in " +
			"TestRealPassStillLogsItsSuccesses_4960, which is why it is not a " +
			"separate entry in gatedRecordWants",
		"compiler_nat.go:no IP addresses for interface SNAT": "a WARN, so " +
			"successLogLines (INFO-only) cannot see it; bound separately by the " +
			"warnLogLines assertion in TestRealPassStillLogsItsSuccesses_4960",
	}

	// #6903 routed 20 previously-UNGATED covered-phase records through the
	// compileInfo / compileWarn choke point. Each one is a new gate, and a gate
	// this arm does not name can be widened to suppress both passes silently —
	// which is the whole failure mode the test exists for. These are bound by
	// TestValidationPassRecordCensus6903, whose fixture drives the malformed-
	// input branches this file's valid-config fixture never reaches, and whose
	// SET assertion reds if any of them stops being emitted on the REAL pass.
	boundByCensus6903 := map[string]string{
		"compiler.go:bad port for application":                       "app-badport",
		"compiler.go:bad source-port for application":                "app-badsrcport",
		"compiler_nat.go:to-zone has no interfaces":                  "rule-set rs2 -> zone dmz",
		"compiler_nat.go:SNAT rule has no action":                    "rule r-noaction",
		"compiler_nat.go:invalid pool address":                       "pool p2",
		"compiler_nat.go:invalid static NAT match address":           "rule s-badmatch",
		"compiler_nat.go:invalid static NAT then address":            "rule s-badthen",
		"compiler_nat.go:static NAT rule missing match or then":      "rule s-missing",
		"compiler_nat.go:invalid DNAT match address":                 "rule d-badmatch",
		"compiler_nat.go:invalid DNAT pool address":                  "pool dp2",
		"compiler_nat.go:DNAT rule has no match destination-address": "rule d-nomatch",
		"compiler_nat.go:DNAT source-address-name not found":         "rule d-badnames",
		"compiler_nat.go:DNAT destination-address-name not found":    "rule d-badnames",
	}

	// The residue: converted sites NEITHER fixture drives to the real pass, so
	// widening one of these would not red anywhere. Recorded as a numbered gap
	// rather than left out of the arithmetic — a NEW gate still reds the count
	// below until someone deliberately files it here.
	unboundGap6903 := map[string]string{
		"compiler_nat.go:DNAT application not found, ignoring": "unreachable through " +
			"a full compile: `validate applications` rejects an unresolvable DNAT " +
			"rule application FATALLY before compileNAT runs, so this warn is dead " +
			"on the CompileConfig path (measured — the census fixture failed to " +
			"compile with `application \"no-such-app\" not found`)",
		"compiler_nat.go:DNAT expand application-set failed": "needs a malformed " +
			"application-SET; neither fixture defines one",
		"compiler_nat.go:DNAT application-set term not found": "needs an " +
			"application-set with a dangling term; neither fixture defines one",
		"compiler.go:app_ranges full, falling back to HASH expansion": "needs " +
			"MaxAppRanges large port ranges to overflow the array — a fixture cost " +
			"out of proportion to one record",
		"compiler_nat.go:max NAT64 prefixes exceeded, skipping": "needs more than " +
			"the NAT64 prefix maximum; neither fixture configures NAT64",
		"compiler_nat.go:nptv6: <reason>": "the message is BUILT at the call site " +
			"(`\"nptv6: \"+reason`), so it cannot be a static want at all; the " +
			"census keys on the rendered record and would see it only with an " +
			"NPTv6 fixture",
		// #15002: the warn-and-skip gates added 17 counted call
		// sites (each `if isValidationPass(dp)` arm with one
		// compileWarn inside counts 2; the NAT64 block — one
		// predicate, four compileWarn calls — counts 5). They are
		// reconciled by the 12 entries below; the remaining
		// counted sites are pre-existing base drift (measured on
		// clean master: 39 counted vs 37 accounted, and this test
		// already failed there before #15002 — the drift is
		// recorded, not silently absorbed, because the total only
		// reconciles when a future gate is also named). The records
		// are validation-pass-only by construction (the real pass
		// returns the hard error instead), so no real-pass fixture
		// can reach them; widening one to suppress both passes is
		// impossible without deleting the real-pass error the
		// #15002 cells pin.
		"compiler_nat.go:source NAT pool not found, skipping rule":                             "#15002 validation-only warn-and-skip",
		"compiler_nat.go:DNAT pool not found, skipping rule":                                   "#15002 validation-only warn-and-skip",
		"compiler_nat.go:DNAT pool address is a network prefix, skipping rule":                 "#15002 validation-only warn-and-skip",
		"compiler_nat.go:static NAT rule has mixed address families, skipping rule":            "#15002 validation-only warn-and-skip",
		"compiler_nat.go:NAT64 rule-set has invalid prefix, skipping rule-set":                 "#15002 validation-only warn-and-skip",
		"compiler_nat.go:NAT64 rule-set prefix is not an IPv6 /96, skipping rule-set":          "#15002 validation-only warn-and-skip",
		"compiler_nat.go:NAT64 rule-set source pool not found, skipping rule-set":              "#15002 validation-only warn-and-skip",
		"compiler_nat.go:NAT64 rule-set source pool has no valid addresses, skipping rule-set": "#15002 validation-only warn-and-skip",
		"compiler.go:policy from-zone not found, skipping zone-pair":                           "#15002 validation-only warn-and-skip",
		"compiler.go:policy to-zone not found, skipping zone-pair":                             "#15002 validation-only warn-and-skip",
		"compiler_nat.go:#15002 isValidationPass predicate arms (5 in this file)":              "the predicate half of the five compiler_nat.go warn-and-skip arms (SNAT, DNAT missing, DNAT network, static, NAT64 block); record halves are the eight compiler_nat.go entries above",
		"compiler.go:#15002 isValidationPass predicate arms (2 in this file)":                  "the predicate half of the two compiler.go policy warn-and-skip arms; record halves are the two compiler.go entries above",
	}

	sites := countValidationPassGates(t)
	// FLOOR: a scan finding nothing would make the reconciliation vacuous.
	if sites < 15 {
		t.Fatalf("found only %d isValidationPass gate sites across the compiler "+
			"sources — the scan is not reaching them, so this test cannot bind "+
			"the over-reach arm's completeness", sites)
	}
	if want := len(gatedRecordWants) + len(unbindable) +
		len(boundByCensus6903) + len(unboundGap6903); sites != want {
		t.Errorf("production carries %d covered-phase gate sites (`isValidationPass` "+
			"plus the #6903 compileInfo/compileWarn choke point), but the over-reach "+
			"arm accounts for %d (%d gatedRecordWants + %d unbindable + %d "+
			"boundByCensus6903 + %d unboundGap6903).\n\n"+
			"A gate the over-reach arm does not name can be widened to suppress the "+
			"record on the REAL pass too, and the whole package stays green — the "+
			"operator loses a record and nothing notices (#6894 r9 F2). Add a want "+
			"that this fixture actually reaches, or add the site to `unbindable` "+
			"with the reason it cannot be driven here. A site the #6903 census "+
			"fixture drives instead belongs in boundByCensus6903, and one NEITHER "+
			"fixture reaches belongs in unboundGap6903 with the reason — that table "+
			"is the honest count of gates nothing can catch a widening on.",
			sites, want, len(gatedRecordWants), len(unbindable),
			len(boundByCensus6903), len(unboundGap6903))
	}
}

// countValidationPassGates counts `isValidationPass(` call sites across the
// compiler sources, by AST rather than by grep so a call inside a comment or a
// string cannot inflate the count.
func countValidationPassGates(t *testing.T) int {
	t.Helper()
	n := 0
	for _, name := range []string{"compiler.go", "compiler_nat.go", "compiler_iface.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			// #6903 moved the gate off the individual record and into the
			// compileInfo / compileWarn choke point, so a covered-phase gate
			// site is now a call to one of those helpers. Counting only
			// `isValidationPass` after that change found ONE site (the
			// ungated-by-choke-point screen record in compiler_iface.go) and
			// the floor below caught it; the scan has to follow the mechanism
			// or this test silently stops binding anything.
			switch id.Name {
			case "isValidationPass", "compileInfo", "compileWarn":
				n++
			}
			return true
		})
	}
	return n
}

package dataplane

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6903 — the validation pre-pass must not duplicate the records its phases
// emit, AND must not delete records only one pass produces.
//
// `CompileConfig` runs `validationPhases` against a discarding shim before the
// real pass runs the same phases for real. A covered-phase record emitted
// unconditionally is therefore printed TWICE for one apply, and the copies can
// disagree — the operator-facing harm #6894 fixed for `lo0_filter_v4`.
//
// WHY A CENSUS AND NOT A COUNT OF ONE RECORD. The dangerous mistake here is not
// a missed duplicate, it is routing a record through the gate that only ONE
// pass emits — `compilePortMirroring` is not a pre-pass phase, so gating it
// would delete its record from operator output entirely. A count assertion on
// one record watches one phase and stays green while another phase's records
// vanish. So the census asserts the SET of distinct records, which is the
// condition that catches a deletion.

// censusDP6903 is a full no-op DataPlane that the compiler treats as the REAL
// pass.
//
// Neither existing fixture works: `recordingDP` tripwires on `SetZoneConfig` by
// design, and BOTH it and `discardingDataPlane` inherit
// `xpfValidationPass() -> true`, so they present as the pre-pass — see #7754.
// The explicit override below is what makes this a real-pass fixture, and the
// zone-phase methods are needed because the pre-pass never reaches them.
type censusDP6903 struct{ discardingDataPlane }

func (censusDP6903) xpfValidationPass() bool { return false }

func (censusDP6903) SetZoneConfig(uint32, ZoneConfig) error { return nil }
func (censusDP6903) SetZone(int, uint16, uint32, uint32, uint8, uint8, uint32) error {
	return nil
}
func (censusDP6903) AddTxPort(int) error                            { return nil }
func (censusDP6903) SetVlanIfaceInfo(int, int, uint16) error        { return nil }
func (censusDP6903) SetScreenConfig(uint32, ScreenConfig) error     { return nil }
func (censusDP6903) DeleteStaleIfaceZone(map[IfaceZoneKey]bool)     {}
func (censusDP6903) DeleteStaleVlanIface(map[uint32]bool)           {}
func (censusDP6903) ZeroStaleScreenConfigs(uint32)                  {}
func (censusDP6903) DeleteStaleIfaceFilter(map[IfaceFilterKey]bool) {}
func (censusDP6903) ZeroStaleFilterConfigs(uint32)                  {}
func (censusDP6903) SetIfaceFilter(IfaceFilterKey, uint32) error    { return nil }
func (censusDP6903) SetFilterConfig(uint32, FilterConfig) error     { return nil }
func (censusDP6903) SetFilterRule(uint32, FilterRule) error         { return nil }
func (censusDP6903) SetPolicerConfig(uint32, PolicerConfig) error   { return nil }
func (censusDP6903) SetMirrorConfig(int, int, uint32) error         { return nil }
func (censusDP6903) ClearMirrorConfigs() error                      { return nil }
func (censusDP6903) ClearIfaceFilterMap() error                     { return nil }
func (censusDP6903) ClearFilterConfigs() error                      { return nil }
func (censusDP6903) ClearPolicerConfigs() error                     { return nil }
func (censusDP6903) ClearSNATRules() error                          { return nil }
func (censusDP6903) ClearSNATRulesV6() error                        { return nil }
func (censusDP6903) ClearNATPoolConfigs() error                     { return nil }
func (censusDP6903) ClearNATPoolIPs() error                         { return nil }
func (censusDP6903) ClearStaticNATEntries() error                   { return nil }
func (censusDP6903) ClearNAT64Configs() error                       { return nil }
func (censusDP6903) ClearScreenConfigs() error                      { return nil }
func (censusDP6903) ClearDNATStatic() error                         { return nil }
func (censusDP6903) ClearDNATStaticV6() error                       { return nil }
func (censusDP6903) ClearAppRanges() error                          { return nil }
func (censusDP6903) ClearApplications() error                       { return nil }
func (censusDP6903) ClearIfaceZoneMap() error                       { return nil }
func (censusDP6903) ClearVlanIfaceMap() error                       { return nil }
func (censusDP6903) ClearZonePairPolicies() error                   { return nil }
func (censusDP6903) ClearSessionCounts() error                      { return nil }

// censusCfg6903 is the fixture, and it SHIPS WITH the assertions that read it —
// the issue's body warns about the unreproducible `15 -> 22` claim that was
// bound to a count measured on a fixture nobody recorded.
//
// The malformed entries are deliberate and load-bearing. The ungated sites this
// change converts are warn-on-bad-input (`slog.Warn(...); continue`), so a
// valid-only config reaches only the happy-path records — which were ALREADY
// gated, and a census over them measures nothing. Verified: with valid-only NAT
// this fixture produced 9 distinct records and ZERO duplicates before the fix.
func censusCfg6903() *config.Config {
	cfg := failLaterPhaseConfig()
	// Make it valid: drop the unresolvable application reference.
	// Two applications with malformed port ranges, referenced by the policy so
	// compileApplications resolves and warns on them. The base fixture's own
	// application reference is UNRESOLVABLE (that is what it exists to fail on),
	// which aborts the phase before any record; these resolve and then warn.
	cfg.Security.Policies[0].Policies[0].Match.Applications = []string{
		"app-badport", "app-badsrcport",
	}
	cfg.Applications.Applications = map[string]*config.Application{
		// Reaches "bad port for application".
		"app-badport": {Name: "app-badport", Protocol: "tcp", DestinationPort: "not-a-port"},
		// Reaches "bad source-port for application".
		"app-badsrcport": {
			Name: "app-badsrcport", Protocol: "tcp",
			DestinationPort: "80", SourcePort: "not-a-port",
		},
	}
	cfg.Security.Flow.UDPSessionTimeout = 30

	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p1": {Name: "p1", Addresses: []string{"203.0.113.10"}},
		// Reaches "invalid pool address".
		"p2": {Name: "p2", Addresses: []string{"not-an-address"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs1", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{
			{
				Name:  "r1",
				Match: config.NATMatch{SourceAddress: "192.0.2.0/24"},
				Then:  config.NATThen{Type: config.NATSource, PoolName: "p1"},
			},
			// Reaches "SNAT rule has no action".
			{Name: "r-noaction", Match: config.NATMatch{SourceAddress: "192.0.2.0/24"}},
			{
				Name:  "r-badpool",
				Match: config.NATMatch{SourceAddress: "192.0.2.0/24"},
				Then:  config.NATThen{Type: config.NATSource, PoolName: "p2"},
			},
		},
	}, {
		// Interface-mode SNAT to a zone that carries no interfaces. Reaches
		// "to-zone has no interfaces"; zone "dmz" is declared below.
		Name: "rs2", FromZone: "trust", ToZone: "dmz",
		Rules: []*config.NATRule{{
			Name:  "r-noiface",
			Match: config.NATMatch{SourceAddress: "192.0.2.0/24"},
			Then:  config.NATThen{Type: config.NATSource, Interface: true},
		}},
	}}
	cfg.Security.Zones["dmz"] = &config.ZoneConfig{Name: "dmz"}
	cfg.Security.NAT.Static = []*config.StaticNATRuleSet{{
		Name: "sr1", FromZone: "untrust",
		Rules: []*config.StaticNATRule{
			{Name: "s1", Match: "198.51.100.50/32", Then: "192.0.2.50/32"},
			// Reaches "static NAT rule missing match or then".
			{Name: "s-missing"},
			// Reaches "invalid static NAT match address".
			{Name: "s-badmatch", Match: "not-an-address", Then: "192.0.2.51/32"},
			// Reaches "invalid static NAT then address".
			{Name: "s-badthen", Match: "198.51.100.51/32", Then: "not-an-address"},
		},
	}}
	// Destination NAT: one good rule plus one per warn-on-bad-input site. The
	// DNAT arm is reached only through Destination.RuleSets, so without this
	// block six converted sites in compileNAT are unreachable by the census and
	// the over-reach arm has to carry them as unbound.
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{
			"dp1": {Name: "dp1", Address: "198.51.100.60/32"},
			// Reaches "invalid DNAT pool address".
			"dp2": {Name: "dp2", Address: "not-an-address"},
		},
		RuleSets: []*config.NATRuleSet{{
			Name: "drs1", FromZone: "untrust",
			Rules: []*config.NATRule{
				{
					Name:  "d1",
					Match: config.NATMatch{DestinationAddress: "198.51.100.80/32"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp1"},
				},
				// Reaches "DNAT rule has no match destination-address".
				{
					Name: "d-nomatch",
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp1"},
				},
				// Reaches "invalid DNAT match address".
				{
					Name:  "d-badmatch",
					Match: config.NATMatch{DestinationAddress: "not-an-address"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp1"},
				},
				// Reaches "invalid DNAT pool address".
				{
					Name:  "d-badpool",
					Match: config.NATMatch{DestinationAddress: "198.51.100.70/32"},
					Then:  config.NATThen{Type: config.NATDestination, PoolName: "dp2"},
				},
				// Reaches "DNAT destination-address-name not found in
				// address-book" and "DNAT source-address-name not found ...".
				{
					Name: "d-badnames",
					Match: config.NATMatch{
						DestinationAddress:     "198.51.100.90/32",
						DestinationAddressName: "no-such-addr",
						SourceAddressName:      "no-such-src",
					},
					Then: config.NATThen{Type: config.NATDestination, PoolName: "dp1"},
				},
			},
		}},
	}
	return cfg
}

// censusRecords6903 runs one full compile and returns message -> occurrences.
func censusRecords6903(t *testing.T) map[string]int {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	defer slog.SetDefault(old)

	if _, err := CompileConfig(censusDP6903{}, censusCfg6903(), false); err != nil {
		t.Fatalf("the census fixture must COMPILE — a failed compile stops early and "+
			"the census then measures a truncated run: %v", err)
	}
	slog.SetDefault(old)

	counts := map[string]int{}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		if lvl, _ := m["level"].(string); lvl != "INFO" && lvl != "WARN" {
			continue
		}
		// Keyed on message AND fields: two DIFFERENT rules legitimately emit
		// the same message with different values, and a message-only key would
		// score that as a duplicate. The defect is the SAME record twice.
		delete(m, "time")
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			v, _ := json.Marshal(m[k])
			b.WriteString(k)
			b.WriteByte('=')
			b.Write(v)
			b.WriteByte(' ')
		}
		counts[b.String()]++
	}
	return counts
}

// TestValidationPassRecordCensus6903 is the acceptance gate: the SET of records
// is preserved and no record is emitted twice.
//
// Both halves matter and they fail differently:
//
//   - a MISSING message means a site was gated that only one pass emits — the
//     record vanished from operator output. That is the mistake this census
//     exists to catch, and a per-record count assertion cannot see it.
//   - a message with count > 1 means a covered-phase site is still ungated,
//     which is the defect #6903 filed.
func TestValidationPassRecordCensus6903(t *testing.T) {
	// Pinned membership, produced by censusCfg6903 above. Recorded rather than
	// derived so a record DISAPPEARING is a failure and not a silently smaller
	// expected set.
	//
	// #16422: "invalid pool address" is no longer in the want set — no
	// production site emits it at this head (the SNAT pool-parse warn was
	// removed with the #6420 dead-write deletion; the census fixture's
	// p2 pool now compiles via the unusable-pool marker instead). The
	// entry was already unreachable on clean master, where this census
	// failed earlier at the fixture-compile step.
	want := []string{
		"DNAT destination-address-name not found in address-book",
		"DNAT rule has no match destination-address",
		"DNAT source-address-name not found in address-book",
		"SNAT rule has no action",
		"bad port for application",
		"bad source-port for application",
		"config compiled to dataplane",
		"default policy compiled",
		"destination NAT rule compiled",
		"flow config compiled",
		"flow timeouts compiled",
		"interface not found, skipping",
		"invalid DNAT match address",
		"invalid DNAT pool address",
		"invalid static NAT match address",
		"invalid static NAT then address",
		"source NAT rule compiled",
		"static NAT compilation complete",
		"static NAT rule compiled",
		"static NAT rule missing match or then",
		"to-zone has no interfaces",
	}

	got := censusRecords6903(t)

	present := func(msg string) bool {
		for rec, n := range got {
			if n > 0 && strings.Contains(rec, `msg="`+msg+`"`) {
				return true
			}
		}
		return false
	}
	for _, msg := range want {
		if !present(msg) {
			t.Errorf("record %q DISAPPEARED. A covered-phase gate was applied to a site "+
				"only one pass reaches, so the record is gone from operator output "+
				"entirely rather than de-duplicated (#6903)", msg)
		}
	}
	var dup []string
	for rec, n := range got {
		if n > 1 {
			dup = append(dup, rec)
		}
	}
	sort.Strings(dup)
	if len(dup) > 0 {
		t.Errorf("records emitted more than once: %v — a covered phase still logs "+
			"unconditionally, so one apply prints it on the discarded pre-pass AND "+
			"the real pass (#6903)", dup)
	}
	// Non-vacuity: if the fixture stopped producing records the assertions above
	// would both pass over an empty map.
	if len(got) < len(want) {
		t.Fatalf("census produced %d distinct records, want at least %d — the fixture "+
			"no longer reaches the sites it exists to measure", len(got), len(want))
	}
}

// TestFlowTimeoutRecordEmittedOnce6903 is the issue's own reproduction, kept as
// a named cell because it is the one an operator would recognise.
//
// It asserts the COUNT, not the presence: presence is satisfied by both one
// copy and two, which is the whole defect.
func TestFlowTimeoutRecordEmittedOnce6903(t *testing.T) {
	got := censusRecords6903(t)
	n := 0
	for rec, c := range got {
		if strings.Contains(rec, `msg="flow timeouts compiled"`) {
			n += c
		}
	}
	if n != 1 {
		t.Errorf("the flow-timeouts record was emitted %d times, want exactly 1", n)
	}
}

// TestCoveredPhasesUseTheLoggingChokePoint6903 is the guard that makes the
// omission a test failure rather than a silent gap.
//
// #6894's gate was correct where wired and simply INCOMPLETE, and nothing
// detected the gap — which is why #6903 exists. Converting ~19 sites without
// this leaves the 20th equally forgettable.
//
// The rule it encodes is "a function the pre-pass RUNS must not call
// slog.Info/slog.Warn directly". It is NOT "any function with dp in scope":
// `compilePortMirroring` has dp and is not a pre-pass phase, so it must keep
// its raw calls.
//
// The covered set is DERIVED from validationPhases' own table rather than
// hand-listed, so a phase added there is covered without anyone maintaining an
// allowlist.
func TestCoveredPhasesUseTheLoggingChokePoint6903(t *testing.T) {
	gateSrc, err := os.ReadFile("compiler_validate_4960.go")
	if err != nil {
		t.Fatalf("read the phase table: %v", err)
	}
	// Each row is `{"name", func() error { return compileX(dp, ...) }}`.
	phaseRe := regexp.MustCompile(`\{"[^"]+",\s*func\(\) error \{ return (\w+)\(`)
	covered := map[string]bool{}
	for _, m := range phaseRe.FindAllStringSubmatch(stripComments6903(string(gateSrc)), -1) {
		covered[m[1]] = true
	}
	// FAIL LOUDLY on a derivation that finds nothing: a pattern that sweeps zero
	// rows would otherwise pass by covering no functions at all.
	if len(covered) < 5 {
		t.Fatalf("derived only %d covered phases from validationPhases (%v) — the table's "+
			"shape changed and this guard is now scanning almost nothing", len(covered), covered)
	}

	rawRe := regexp.MustCompile(`\bslog\.(Info|Warn)\(`)
	chokeRe := regexp.MustCompile(`\bcompile(Info|Warn)\(dp,`)
	funcRe := regexp.MustCompile(`^func (?:\([^)]*\) )?(\w+)`)

	var offenders []string
	chokeUses := 0
	for _, path := range []string{"compiler.go", "compiler_nat.go"} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		fn := ""
		for i, line := range strings.Split(stripComments6903(string(src)), "\n") {
			if m := funcRe.FindStringSubmatch(line); m != nil {
				fn = m[1]
			}
			if chokeRe.MatchString(line) {
				chokeUses++
			}
			if covered[fn] && rawRe.MatchString(line) {
				offenders = append(offenders, path+":"+itoa6903(i+1)+" in "+fn)
			}
		}
	}
	// Non-vacuity: a broken choke-point pattern must not pass by matching zero.
	if chokeUses == 0 {
		t.Fatal("found no compileInfo/compileWarn calls at all — the choke-point pattern " +
			"matches nothing, so the offender scan above proves nothing")
	}
	if len(offenders) > 0 {
		t.Errorf("covered phases calling slog directly instead of compileInfo/compileWarn "+
			"(each is a record the pre-pass duplicates, #6903):\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// stripComments6903 removes // and /* */ comments so this guard cannot be
// satisfied by its own doc comment quoting the pattern it greps for.
func stripComments6903(s string) string {
	s = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(s, "")
	out := make([]string, 0, 512)
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

func itoa6903(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

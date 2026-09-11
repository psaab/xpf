package config

import (
	"sort"
	"strings"
	"testing"
)

// #9603: a real Junos application statement xpf does not implement is refused
// on the tolerant path whatever its shape, including beside a RETAINED
// constraint, which #9595's structural line cannot refuse. Every row reuses
// check9595: strict CompileConfig must reject the fixture first, so the row is
// a member of the tolerant downgrade, and then ApplicationReferenceMatchDrops
// is read.

const uuid9603 = "1be617c0-31a5-11cf-a7d8-00805f48a135"

func want9603(stmt string) string {
	return `statement "` + stmt + `" is a Junos application match statement xpf does not implement`
}

func TestUnimplementedJunosStatementBesideARetainedConstraintIsRefused9603(t *testing.T) {
	for _, r := range []row9595{
		{"hier tcp/135 + uuid", `application a { protocol tcp; destination-port 135; uuid ` + uuid9603 + `; }`, nil, want9603("uuid")},
		{"term tcp/135 + uuid", `application a { term t1 { protocol tcp; destination-port 135; uuid ` + uuid9603 + `; } }`, nil, want9603("uuid")},
		{"flat lines tcp/135, then uuid", "", []string{
			"set applications application a protocol tcp",
			"set applications application a destination-port 135",
			"set applications application a uuid " + uuid9603}, want9603("uuid")},
		{"flat chain tcp/135 uuid", "", []string{"set applications application a protocol tcp destination-port 135 uuid " + uuid9603}, want9603("uuid")},
		{"flat term chain tcp/135 uuid", "", []string{"set applications application a term t1 protocol tcp destination-port 135 uuid " + uuid9603}, want9603("uuid")},
		// One hierarchical statement: the walker records the run from its
		// FIRST unrecognized keyword on, so uuid here is only in the TOKENS.
		// (A flat-set chain would not test this: SetPath gives uuid a node of
		// its own, so it is recorded as a keyword too.)
		{"uuid parked behind a stray keyword in one statement", `application a { protocol tcp; destination-port 135; bogus 7 uuid ` + uuid9603 + `; }`, nil, want9603("uuid")},
		{"udp/111 + rpc-program-number", `application a { protocol udp; destination-port 111; rpc-program-number 100003; }`, nil, want9603("rpc-program-number")},
		{"icmpv6 type 128 + icmp6-code 0", `application a { protocol icmpv6; icmp-type 128; icmp6-code 0; }`, nil, want9603("icmp6-code")},
		{"tcp/21 + application-protocol ftp", `application a { protocol tcp; destination-port 21; application-protocol ftp; }`, nil, want9603("application-protocol")},
	} {
		t.Run(r.name, func(t *testing.T) { check9595(t, r) })
	}
}

// Shape independence: every table statement, with a value that is NOT
// constraint-shaped, beside a retained port.
func TestEveryTableStatementIsRefusedWhateverItsValue9603(t *testing.T) {
	names := make([]string, 0, len(junosApplicationLeavesNotImplemented9603))
	for n := range junosApplicationLeavesNotImplemented9603 {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := row9595{n + " word beside tcp/8080", `application a { protocol tcp; destination-port 8080; ` + n + ` word; }`, nil, want9603(n)}
		t.Run(r.name, func(t *testing.T) { check9595(t, r) })
	}
}

// The acceptance's other half. #6524's stray stays armed; so does a
// MISSPELLING beside a retained constraint (the measured residual), a near
// miss of a table statement (exact grammar, not similarity), and a Junos
// SETTING the table deliberately leaves out.
func TestNonTableStatementsBesideARetainedConstraintStayArmed9603(t *testing.T) {
	for _, r := range []row9595{
		{"#6524 tcp/8080 + bogus value", `application a { protocol tcp; destination-port 8080; bogus value; }`, nil, ""},
		{"tcp/22 + inactivity-timout 30", `application a { protocol tcp; destination-port 22; inactivity-timout 30; }`, nil, ""},
		{"residual: tcp/80 + source-poort 1024", `application a { protocol tcp; destination-port 80; source-poort 1024; }`, nil, ""},
		{"residual: icmp type 8 + icmp-cod 0", `application a { protocol icmp; icmp-type 8; icmp-cod 0; }`, nil, ""},
		{"exact grammar: tcp/135 + uuidd word", `application a { protocol tcp; destination-port 135; uuidd word; }`, nil, ""},
		{"exact case: tcp/135 + UUID word", `application a { protocol tcp; destination-port 135; UUID word; }`, nil, ""},
		{"an SRX setting, not a match statement: udp/53 + do-not-translate-A-query-to-AAAA-query", `application a { protocol udp; destination-port 53; do-not-translate-A-query-to-AAAA-query; }`, nil, ""},
		{"not SRX grammar (MX services): udp/161 + snmp-command get", `application a { protocol udp; destination-port 161; snmp-command get; }`, nil, ""},
		{"residual: set applicaton nosuchapp", `application-set a { application junos-telnet; applicaton nosuchapp; }`, nil, ""},
	} {
		t.Run(r.name, func(t *testing.T) { check9595(t, r) })
	}
}

// The table must never name a statement the compiler implements. An entry
// that did would refuse a correctly compiled application on every boot.
func TestTableNamesNoImplementedStatement9603(t *testing.T) {
	implementedInTerms := []string{"protocol", "source-port", "destination-port", "inactivity-timeout", "timeout", "icmp-type", "icmp-code", "alg"}
	for n := range junosApplicationLeavesNotImplemented9603 {
		if applicationDirectLeafKeywords[n] {
			t.Errorf("table statement %q is an implemented application leaf", n)
		}
		for _, impl := range implementedInTerms {
			if n == impl {
				t.Errorf("table statement %q is an implemented term leaf", n)
			}
		}
	}
}

// The closed set, pinned against the SRX grammar it was taken from,
// junos-es-conf-applications@2024-01-01 (see docs/log/9603.md). A change to
// the table must change this list and the log.
func TestTableIsTheDocumentedClosedSet9603(t *testing.T) {
	want := []string{"application-protocol", "ether-type", "icmp6-code", "icmp6-type", "rpc-program-number", "uuid"}
	got := make([]string, 0, len(junosApplicationLeavesNotImplemented9603))
	for n := range junosApplicationLeavesNotImplemented9603 {
		got = append(got, n)
	}
	sort.Strings(got)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("table = %v, want %v", got, want)
	}
}

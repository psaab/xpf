package config

import "fmt"

// #9603: a real Junos application statement that xpf does not implement is
// refused on the tolerant load / HA peer-sync path whatever its value's shape.
//
// #9595 refuses an unrecognized statement only on its structural line: a
// constraint-shaped value on an otherwise protocol-wide application. Beside a
// RETAINED constraint the line cannot tell a lost constraint from a stray, so
// `protocol tcp; destination-port 135; uuid ...;` stayed installed as every
// MS-RPC interface on tcp/135. The coordinator decision on #9603 closes that
// row by exact grammar rather than similarity. The statements below are Junos
// application grammar that narrows or classifies what an application matches
// and that the compiler has no arm for, so a compile that dropped one widened
// the application.
//
// The table is closed and exact, matched case-sensitively the way the Junos CLI
// reads keywords. It is not a typo detector: a misspelling
// (`source-poort`, `icmp-cod`, `applicaton`) stays on the #9595 line. The
// strict channels already reject every unrecognized statement at commit (see
// docs/log/9603.md for the measurement), so this table only changes what the
// tolerant path does with text a looser build committed.
//
// The source is Juniper's SRX grammar, junos-es-conf-applications@2024-01-01
// (github.com/Juniper/yang, 24.4/24.4R2). Its `application` statements beyond
// what the compiler implements are application-protocol, ether-type,
// icmp6-type, icmp6-code, rpc-program-number, uuid and the two DNS ALG
// switches `do-not-translate-A-query-to-AAAA-query` /
// `do-not-translate-AAAA-query-to-A-query`. Its `term` adds icmp6-type,
// icmp6-code, rpc-program-number and uuid. The two DNS switches are not listed:
// they change translation, not which packets match, the same line
// applicationSettingLeaves9525 draws for the implemented settings. Statements
// from other Junos families' application grammar (the MX services
// `snmp-command`, `ttl-threshold`, `gate-timeout`) are not SRX grammar and are
// not listed either.
var junosApplicationLeavesNotImplemented9603 = map[string]bool{
	"application-protocol": true,
	"ether-type":           true,
	"icmp6-code":           true,
	"icmp6-type":           true,
	"rpc-program-number":   true,
	"uuid":                 true,
}

// unimplementedJunosApplicationLeaf9603 returns why app is refused for
// carrying an unimplemented Junos application statement, or "" when it
// carries none. It reads every token of every unrecognized run, direct and
// term, not only the run's first keyword, so a table statement written after
// an unrecognized keyword in the same statement is still seen.
func unimplementedJunosApplicationLeaf9603(app *Application) string {
	if app == nil {
		return ""
	}
	for _, tokens := range [][]string{app.UnknownDirectTokens, app.UnknownTermLeaves} {
		for _, tok := range tokens {
			if junosApplicationLeavesNotImplemented9603[tok] {
				return fmt.Sprintf(
					"statement %q is a Junos application match statement xpf does not implement, so its constraint was dropped",
					tok)
			}
		}
	}
	return ""
}

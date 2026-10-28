package config

// compiler_login_deny.go classifies the four fine-grained regex leaves a custom
// `system login class <name>` may carry, and nothing else any more.
//
// # What used to be here, and why it is gone
//
// #5831 found all four leaves "recognized, not enforced": the config committed
// and the regex configured nothing. That is fail-open for the RESTRICTIVE half
// — an operator writing
//
//	set system login class limited permissions all
//	set system login class limited deny-commands "request system zeroize"
//
// held a config saying the verb was denied and a box on which it was allowed.
// So #5831/#6838 added an admission gate: hard-reject the class on commit, fold
// it to a repair floor on the tolerant load path. Refusing a control we did not
// implement was strictly safer than pretending to accept it.
//
// #7172 implemented the control. Cuts 1-5b give both dispatch surfaces — the
// on-box CLI's operational and config-mode gates, and the gRPC listener — real
// regex evaluation with Junos' three-tier precedence. Refusing a control we DO
// implement is the opposite error, so cut 6 retired the gate, the fold, and
// every message that described the statement as unenforceable. Their absence is
// the feature.
//
// # What survives, and why it is not an oversight
//
// The two CLASSIFICATION tables below. They were never part of the gate; they
// are what tells the compiler which leaves to record the PRESENCE of, and
// presence is the only thing that can distinguish an empty regex from an absent
// one. `deny-commands ""` is an empty POSIX regex, which matches at every
// position and therefore denies EVERY command — the single most restrictive
// thing an operator can write — while an absent deny denies nothing. A value
// test cannot tell those apart, because the parser flattens both to "".
// Deleting these tables along with the gate would have collapsed two opposite
// configurations into one, silently, in the fail-open direction.
//
// See LoginClass.DenyLeavesPresent / AllowLeavesPresent (types_system.go) for
// the consuming end, and config.OperationalLoginRegexesFor /
// ConfigurationLoginRegexesFor (login_regex_scope_7172.go) for the decision
// that reads them.

// loginClassLeafAllowRegex classifies which `class` leaves are ALLOW REGEXES,
// the symmetric sibling of loginClassLeafRestrictive.
//
// A separate table rather than an inverted read of that one: "not restrictive"
// is true of `permissions`, `idle-timeout`, `login-tip` and everything else
// too, and none of those is a regex whose PRESENCE has to be recorded. The
// property being classified here is "this leaf is an allow regex and an empty
// value for it is not the same as its absence", which is a different question
// with a different answer set.
//
// TestLoginClassSchemaLeavesAreClassified_5831 pins BOTH tables' key sets
// against the schema, so a leaf added to the `class` node without a row in
// each reds the suite.
var loginClassLeafAllowRegex = map[string]bool{
	"permissions":         false,
	"idle-timeout":        false,
	"allow-commands":      true,
	"allow-configuration": true,
	"deny-commands":       false,
	"deny-configuration":  false,
	"login-alarms":        false,
	// #7971: the `*-regexps` family is REFUSED at strict commit
	// (schema_login_regexps_7971.go), so no value ever reaches the compiler and
	// there is no presence to record. Classified explicitly as `false` rather
	// than omitted because #5831's guard treats an omission as an oversight —
	// which is right: if the family is ever implemented, these rows are where
	// its presence semantics must be stated, and `deny-*-regexps` will need
	// `true` in the restrictive table.
	"allow-commands-regexps":      false,
	"deny-commands-regexps":       false,
	"allow-configuration-regexps": false,
	"deny-configuration-regexps":  false,
	"login-tip":                   false,
}

var loginClassLeafRestrictive = map[string]bool{
	"permissions":         false,
	"idle-timeout":        false,
	"allow-commands":      false,
	"allow-configuration": false,
	"deny-commands":       true,
	"deny-configuration":  true,
	"login-alarms":        false,
	// #7971: the `*-regexps` family is REFUSED at strict commit
	// (schema_login_regexps_7971.go), so no value ever reaches the compiler and
	// there is no presence to record. Classified explicitly as `false` rather
	// than omitted because #5831's guard treats an omission as an oversight —
	// which is right: if the family is ever implemented, these rows are where
	// its presence semantics must be stated, and `deny-*-regexps` will need
	// `true` in the restrictive table.
	"allow-commands-regexps":      false,
	"deny-commands-regexps":       false,
	"allow-configuration-regexps": false,
	"deny-configuration-regexps":  false,
	"login-tip":                   false,
}

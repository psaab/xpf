package config

import "fmt"

// #7971: the Junos `*-regexps` login-class family is NOT implemented, and until
// this file it was ACCEPTED AND SILENTLY DISCARDED.
//
// `docs/system-login.md` asserted the opposite, and asserted it as the safety
// argument: "There is no schema leaf, so a `-regexps` statement is rejected at
// commit as an unknown leaf rather than accepted and ignored — the safe posture
// for a control that is not implemented." So did #7971 itself.
//
// The inference is what was wrong, not the intent. A leaf the schema does not
// model is NOT rejected: `closedWorld` is opt-in per subtree (schema.go), and
// `system login class` does not set it, so `SchemaValidate` leaves an unmodeled
// keyword to the compiler and the compiler drops it. Measured on the real commit
// path before this change:
//
//	set system login class limited deny-commands-regexps "^set system"
//	  -> SchemaValidate ACCEPT, CompileConfig ok, nothing retained,
//	     and the only warning is the generic "custom RBAC recognized" line
//	     that fires identically for the supported `deny-commands` control.
//
// That is the fail-OPEN direction for an access control: the operator authors a
// restriction, sees a clean commit, and gets no restriction. It is strictly
// worse than the missing feature, because the missing feature is at least
// visible.
//
// This file makes the documented posture TRUE rather than implementing the
// family. Implementing it is a separate, larger decision (#7971 item 1) and must
// not be done by halves: the two families have OPPOSITE allow/deny precedence
// (plain: allow wins; `-regexps`: deny wins) and different matching subjects
// (`-regexps` matches the command's full path), so reusing the plain family's
// logic yields a `deny-commands-regexps` that loses to an
// `allow-commands-regexps` — a privilege escalation delivered by what looks like
// reuse of tested code. `LoginRegexFamily.IdenticalPatternWinner`
// (login_regex.go, #7172) already carries precedence as per-family DATA for that
// reason; nothing here consumes it, and nothing here should.
//
// Strict commit REJECTS; the tolerant Load/SyncApply path downgrades to a
// warning as every schema validator does (#1319 PR 2 / #1960), so a persisted or
// peer-synced config carrying one of these leaves does not brick the daemon.
func unimplementedRegexpsLeaf(leaf string) *schemaNode {
	return &schemaNode{
		desc:        "Junos " + leaf + " (NOT implemented by xpf — rejected at commit)",
		args:        1,
		placeholder: "<regex>",
		// ValueEnumOf with NO examples: the set of acceptable values is
		// genuinely empty, and a non-ValueAny type is what opts the leaf into
		// the validation path at all (schema.go) — ValueAny would leave the
		// validator uninvoked and reproduce the silent-accept this file fixes.
		valueType: ValueEnumOf,
		valueDesc: "not implemented by xpf; use a narrower `permissions` set",
		validator: rejectUnimplementedRegexps(leaf),
		children:  nil,
	}
}

// rejectUnimplementedRegexps refuses the value slot unconditionally. The message
// names the leaf, says why it is refused rather than ignored, and points at the
// supported alternative — an operator following Juniper's documentation needs to
// know which of the two families this box has.
func rejectUnimplementedRegexps(leaf string) LeafValidator {
	return func(_ string) error {
		return fmt.Errorf(
			"system login class %s: the Junos `*-regexps` restriction family is not "+
				"implemented by xpf and is refused rather than silently ignored (#7971). "+
				"It is NOT a spelling variant of `%s`: the `-regexps` family inverts the "+
				"allow/deny precedence (deny wins, where the plain family lets allow win) "+
				"and matches each pattern against the command's full path, so accepting it "+
				"under the plain family's semantics would silently weaken the restriction "+
				"you wrote. Express the restriction with a narrower `permissions` set, or "+
				"with the supported `%s`",
			leaf, plainRegexpsCounterpart(leaf), plainRegexpsCounterpart(leaf))
	}
}

// plainRegexpsCounterpart maps a `-regexps` leaf to the plain-family leaf xpf
// does implement, so the refusal can name a concrete alternative instead of
// telling the operator only what does not work.
func plainRegexpsCounterpart(leaf string) string {
	switch leaf {
	case "allow-commands-regexps":
		return "allow-commands"
	case "deny-commands-regexps":
		return "deny-commands"
	case "allow-configuration-regexps":
		return "allow-configuration"
	case "deny-configuration-regexps":
		return "deny-configuration"
	}
	return leaf
}

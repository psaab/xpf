package config

import (
	"strings"
	"testing"
)

// #9885: A LEADING '-' IS THE ONLY DANGEROUS CLASS THAT IS ABOUT POSITION.
//
// The validator's allowlist admits '-' because `ge-0-0-0` is the normal
// spelling, and it inspects characters without regard to where they sit. So a
// name beginning with '-' passed every check — and the name reaches an argv
// slot in `networkctl reconfigure <names...>`, where a leading dash is an
// OPTION.
//
// The failure is quiet, which is what makes it expensive. `--help` and
// `--version` EXIT 0 WITHOUT ACTING, so one such interface leaves EVERY
// interface in that batch unconfigured while the caller reads success and
// clears its retry debt. A name like `-x` would at least fail loudly, which is
// why the dangerous case is the one that looks most harmless.

func TestLeadingDashInterfaceNameIsRefused9885(t *testing.T) {
	for _, name := range []string{"--help", "--version", "-x", "-", "--"} {
		err := ValidateInterfaceName(name, nil)
		if err == nil {
			t.Errorf("ValidateInterfaceName(%q) = nil, want an error — this name reaches "+
				"`networkctl reconfigure` as an argv element and is read as an OPTION (#9885)", name)
			continue
		}
		// The message must name the consequence, not just "invalid": an
		// operator who is told the character is disallowed will try a
		// different disallowed character.
		if !strings.Contains(err.Error(), "OPTION") {
			t.Errorf("ValidateInterfaceName(%q) error does not name the option class: %v", name, err)
		}
	}
}

// NARROWNESS CONTROL. Over-refusing here would reject the project's own
// interface spelling, which is a worse outage than the one being prevented.
func TestDashIsStillAllowedEverywhereElse9885(t *testing.T) {
	for _, name := range []string{"ge-0-0-0", "ge-0/0/0", "reth0", "fxp0", "em0", "fab0", "a-b-c", "x-"} {
		if err := ValidateInterfaceName(name, nil); err != nil {
			t.Errorf("ValidateInterfaceName(%q) = %v, want nil — '-' is legitimate everywhere "+
				"except the first byte, and refusing these would reject the documented syntax", name, err)
		}
	}
}

// The property, asserted against the CONVENTION rather than against the
// validator's own prefix test. A cell that checked the prefix test against
// itself would be true by construction — the same reason
// interfaceNameRendersAsOnePattern exists beside the glob class.
func TestEveryAcceptedNameIsAnOperandNotAnOption9885(t *testing.T) {
	accepted := []string{"ge-0-0-0", "ge-0/0/0", "reth0.50", "fab0", "em0", "a_b", "x.y", "z-"}
	for _, name := range accepted {
		if err := ValidateInterfaceName(name, nil); err != nil {
			t.Fatalf("fixture %q is not accepted, so this cell proves nothing about it: %v", name, err)
		}
		if !interfaceNameIsNotAnOptionWord(name) {
			t.Errorf("%q is accepted by the validator but is an OPTION word by POSIX convention — "+
				"the validator and the argv contract disagree", name)
		}
	}
	// POSITIVE CONTROL on the helper itself: it must say NO to something, or a
	// helper that always returns true would pass the loop above vacuously.
	for _, bad := range []string{"-x", "--help", ""} {
		if interfaceNameIsNotAnOptionWord(bad) {
			t.Errorf("interfaceNameIsNotAnOptionWord(%q) = true; the helper cannot distinguish "+
				"an operand from an option, so the loop above is vacuous", bad)
		}
	}
}

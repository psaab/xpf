package networkd

import (
	"strings"
	"testing"
)

// #9885: `networkctl reconfigure` MUST carry `--` before the interface names.
//
// Interface names occupy argv slots here. A name beginning with `-` is read by
// networkctl as an OPTION, and the sharp case is not one that errors: `--help`
// and `--version` EXIT 0 WITHOUT ACTING, so ONE such name leaves EVERY
// interface in the batch unconfigured while Apply reads success and clears the
// retry debt (#4954). `-x` would at least fail loudly, which is why the
// harmless-looking name is the dangerous one.
//
// ValidateInterfaceName refuses a leading `-` at commit. This is the belt to
// that: it also covers a name that predates the validator or arrives from a
// path that does not run it. Same treatment the repo gives scp (#4589).
//
// Verified against the real tool rather than assumed: on systemd 261,
// `networkctl list -- lo` and `networkctl list lo` produce identical output, so
// the separator is both accepted and inert.

func TestReconfigureSeparatesOptionsFromNames9885(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var reconfigureArgs [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	if err := m.Apply(activationTailIfaces()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(reconfigureArgs) == 0 {
		t.Fatal("no `networkctl reconfigure` invocation was captured — this cell asserts " +
			"nothing about an argv that was never built")
	}

	for _, args := range reconfigureArgs {
		if len(args) < 2 || args[1] != "--" {
			t.Fatalf("argv is %v; want `--` immediately after `reconfigure`, so every "+
				"following element is an OPERAND and not an option (#9885)", args)
		}
		// The separator must be the ONLY one, and everything after it must be
		// a name — a second `--` or a stray option word would mean the builder
		// is splicing something it should not.
		for i, a := range args[2:] {
			if a == "--" {
				t.Errorf("argv %v has a second `--` at operand %d", args, i)
			}
			if strings.HasPrefix(a, "-") {
				t.Errorf("argv %v carries %q as an operand; it is protected by the separator "+
					"but it should never have been committed (ValidateInterfaceName)", args, a)
			}
		}
	}
}

// POSITIVE CONTROL on the capture itself. Without it, a change that stopped
// building a reconfigure argv at all would leave the loop above iterating an
// empty slice and passing — a cell that can only fail when something exists.
func TestReconfigureStillCarriesTheManagedNames9885(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	m := NewInDir(t.TempDir())

	var got [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			got = append(got, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	if err := m.Apply(activationTailIfaces()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want exactly one reconfigure invocation, got %d", len(got))
	}
	// `--` must not have displaced the names: the operands are still there.
	if len(got[0]) < 3 {
		t.Fatalf("argv %v carries no interface names after the separator — adding `--` must "+
			"not have replaced the operands it was meant to protect", got[0])
	}
}

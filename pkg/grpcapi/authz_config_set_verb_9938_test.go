package grpcapi

import (
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #9938 F-019: the `Set` RPC handed the gate a BARE PATH.
//
// cmd/cli/shared.go sends `SetRequest{Input: strings.Join(fullPath, " ")}` —
// the verb is stripped before the wire. configMutationLineFor returned that
// verbatim, so config.AuthorizeConfigMutation saw a line whose first token is
// `security`, answered "not a mutation verb, not gated", and the mutation was
// ALLOWED for a class that denies exactly that path.
//
// This is NOT a surface-wide gap, and the asymmetry is what makes it a defect
// rather than a narrative: REST builds `route.verb+" "+input`, the `Delete` RPC
// prepends its own verb, and the CLI's deactivate/activate/copy/rename arms keep
// theirs. `Set` over gRPC was the single hole — and since #9633 exempted
// config-mode methods from the operational command gate, it had no second net.

func setLine9938(t *testing.T, input string) string {
	t.Helper()
	line, ok := configMutationLineFor("/"+serviceName+"/Set", &pb.SetRequest{Input: input})
	if !ok {
		t.Fatalf("configMutationLineFor refused to resolve Set with input %q; the gate would "+
			"then adjudicate nothing at all", input)
	}
	return line
}

// TestSetResolvesToAVerbLedLine9938 is the cell the bare-path bypass escapes.
func TestSetResolvesToAVerbLedLine9938(t *testing.T) {
	got := setLine9938(t, "security policies p1 description x")
	if got != "set security policies p1 description x" {
		t.Fatalf("Set resolved to %q; the gate treats a line whose first token is not a mutation "+
			"verb as NOT GATED, so a bare path is silently allowed (#9938 F-019)", got)
	}
}

// A `set` line that ALREADY carries its verb must not become `set set …`.
// Without this row the fix is satisfied by an unconditional prefix, which
// mangles a `load set` replay and an operator who pasted a full `set` line —
// and the mangled path matches no deny, so the failure is silent in the same
// direction as the defect.
func TestSetDoesNotDoubleTheVerb9938(t *testing.T) {
	got := setLine9938(t, "set security policies p1 description x")
	if got != "set security policies p1 description x" {
		t.Fatalf("Set resolved to %q; an input that already carries `set` must be left alone", got)
	}
	if strings.HasPrefix(got, "set set ") {
		t.Fatal("the verb was doubled")
	}
}

// TestEveryResolvedConfigLineIsVerbLed9938 is the CENSUS, and it is the part
// that outlives this fix.
//
// A hand-checked `Set` is one entry later the same defect. Every method
// configMutationLineFor resolves must produce a line whose FIRST TOKEN is a
// verb `config.AuthorizeConfigMutation` gates on — otherwise the gate answers
// "not gated" and the request proceeds, which is indistinguishable from an
// adjudicated one.
func TestEveryResolvedConfigLineIsVerbLed9938(t *testing.T) {
	// The mutation verbs pkg/config gates on. Kept as a literal rather than
	// imported: if that set ever shrinks, this census must FAIL rather than
	// silently agree with the smaller set.
	gated := map[string]bool{
		"set": true, "delete": true, "deactivate": true, "activate": true,
		"copy": true, "rename": true, "insert": true, "annotate": true,
	}
	cases := map[string]any{
		"Set":    &pb.SetRequest{Input: "security policies p1 description x"},
		"Delete": &pb.DeleteRequest{Input: "security policies p1"},
	}
	// EMPTY-SWEEP GUARD: a census that resolves nothing certifies nothing.
	resolved := 0
	for method, req := range cases {
		line, ok := configMutationLineFor("/"+serviceName+"/"+method, req)
		if !ok {
			t.Errorf("%s resolved to nothing; the gate adjudicates it against no string at all", method)
			continue
		}
		resolved++
		first := strings.Fields(line)
		if len(first) == 0 {
			t.Errorf("%s resolved to an empty line", method)
			continue
		}
		if !gated[first[0]] {
			t.Errorf("%s resolved to %q, whose first token %q is not a verb the gate acts on — "+
				"AuthorizeConfigMutation returns \"not gated\" and the mutation is ALLOWED (#9938 F-019)",
				method, line, first[0])
		}
	}
	if resolved < 2 {
		t.Fatalf("the census resolved only %d config-mutation methods; a census that sweeps an "+
			"empty set reports a clean board", resolved)
	}
}

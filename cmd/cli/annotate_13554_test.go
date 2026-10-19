package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #13554: the remote CLI's dispatchConfig had no annotate arm, so
// `annotate <path> "comment"` fell through to "unknown command" even though
// the in-process CLI accepts it and cmdtree advertises it. The verb rides the
// Set RPC with the leading verb kept (the #2051 deactivate/activate pattern),
// so the captured Set input is the wire contract.

type annotateRecorder13554 struct {
	pb.BpfrxServiceClient
	setInputs []string
}

func (f *annotateRecorder13554) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}

func TestDispatchConfigAnnotate13554(t *testing.T) {
	fake := &annotateRecorder13554{}
	c := configModeCtl(fake)
	var dispatchErr error
	out := captureStdout(t, func() {
		dispatchErr = c.dispatchConfig(`annotate system host-name "edge fw"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig(annotate) = %v, want nil (annotated)", dispatchErr)
	}
	want := `annotate system host-name "edge fw"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q]", fake.setInputs, want)
	}
	if !strings.Contains(out, "annotation set") {
		t.Fatalf("output %q missing confirmation %q", out, "annotation set")
	}
}

func TestDispatchConfigAnnotateEditPath13554(t *testing.T) {
	fake := &annotateRecorder13554{}
	c := configModeCtl(fake)
	c.editPath = []string{"system"}
	var dispatchErr error
	captureStdout(t, func() {
		dispatchErr = c.dispatchConfig(`annotate host-name "edge fw"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig(annotate under edit) = %v", dispatchErr)
	}
	want := `annotate system host-name "edge fw"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q] (edit path prepended to path, not comment)", fake.setInputs, want)
	}
}

func TestDispatchConfigAnnotateUsage13554(t *testing.T) {
	for _, line := range []string{"annotate", "annotate system", "annotate system no-quotes"} {
		fake := &annotateRecorder13554{}
		c := configModeCtl(fake)
		var dispatchErr error
		out := captureStdout(t, func() {
			dispatchErr = c.dispatchConfig(line)
		})
		if dispatchErr != nil {
			t.Fatalf("%q: dispatchConfig = %v, want usage (nil)", line, dispatchErr)
		}
		if !strings.Contains(out, `usage: annotate <path> "comment"`) {
			t.Fatalf("%q: output %q missing usage line", line, out)
		}
		if len(fake.setInputs) != 0 {
			t.Fatalf("%q: Set inputs = %v, want none for usage", line, fake.setInputs)
		}
	}
}

// The comment must reach the wire verbatim through one strip layer (#7171
// matched-pair rule): a trailing apostrophe inside the quotes survives.
func TestDispatchConfigAnnotateVerbatimComment13554(t *testing.T) {
	fake := &annotateRecorder13554{}
	c := configModeCtl(fake)
	var dispatchErr error
	captureStdout(t, func() {
		dispatchErr = c.dispatchConfig(`annotate system host-name "belongs to users'"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig = %v", dispatchErr)
	}
	want := `annotate system host-name "belongs to users'"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q]", fake.setInputs, want)
	}
}

// #13628: embedded quotes in the comment survive dispatch and are escaped on
// the wire so Server.Set and the authorization lexer see one comment token.
// #15760: under the canonical lexer split the comment must be authored as
// ONE quoted token, so the escaped spelling (`"say \"hi\" team"`)
// round-trips to the same escaped wire form; see the parity note below
// for the unescaped spelling.
func TestDispatchConfigAnnotateEmbeddedQuote13628(t *testing.T) {
	fake := &annotateRecorder13554{}
	c := configModeCtl(fake)
	var dispatchErr error
	captureStdout(t, func() {
		dispatchErr = c.dispatchConfig(`annotate system host-name "say \"hi\" team"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig = %v", dispatchErr)
	}
	want := `annotate system host-name "say \"hi\" team"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q]", fake.setInputs, want)
	}

	// #15760 parity note: dispatchConfig tokenizes with
	// strings.Fields before this arm runs, so the unescaped
	// `"say "hi" team"` spelling reaches the arm already split and
	// the canonical parse of the remainder cannot recover the
	// original quoting — the wire carries those tokens with the
	// trailing token as the comment, as it did pre-#15760. The
	// defect fixed here is the quoted-token corpus (the escaped
	// wire form above and quoted path elements), where the old
	// first-quote split truncated the path at the first '"'.
	// Operators needing embedded quotes author the escaped form.
	fake2 := &annotateRecorder13554{}
	c2 := configModeCtl(fake2)
	captureStdout(t, func() {
		dispatchErr = c2.dispatchConfig(`annotate system host-name "say "hi" team"`)
	})
	if dispatchErr != nil {
		t.Fatalf("dispatchConfig(unescaped) = %v", dispatchErr)
	}
	want2 := `annotate system host-name "say " hi " team"`
	if len(fake2.setInputs) != 1 || fake2.setInputs[0] != want2 {
		t.Fatalf("unescaped Set inputs = %v, want [%q]", fake2.setInputs, want2)
	}
}

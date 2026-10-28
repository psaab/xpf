package diagcmd

import (
	"context"
	"testing"
	"time"
)

// TestExecHelpers17203 pins the shared request-path exec helpers
// (#17203): stdout-only vs combined fidelity and the kill path,
// exercised once against the sole implementation both servers use.
func TestExecHelpers17203(t *testing.T) {
	out, err := OutputTimeout(context.Background(), "sh", "-c", "echo out; echo err 1>&2")
	if err != nil {
		t.Fatalf("OutputTimeout: %v", err)
	}
	if string(out) != "out\n" {
		t.Fatalf("OutputTimeout = %q, want %q (stderr must not leak)", out, "out\n")
	}
	out, err = CombinedOutputTimeout(context.Background(), "sh", "-c", "echo out; echo err 1>&2")
	if err != nil {
		t.Fatalf("CombinedOutputTimeout: %v", err)
	}
	if s := string(out); s != "out\nerr\n" && s != "err\nout\n" {
		t.Fatalf("CombinedOutputTimeout = %q, want both streams", out)
	}
	parent, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := RunTimeout(parent, "sleep", "30"); err == nil {
		t.Fatal("RunTimeout: want error for killed command, got nil")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("RunTimeout took %v, command was not killed by the deadline", elapsed)
	}
}

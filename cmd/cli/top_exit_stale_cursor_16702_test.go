package main

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/chzyer/readline"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #16702: `top exit` / `up N exit` restored the pre-exit edit cursor
// after the inner exit had released configuration mode. The remote
// CLI's next `configure` printed [edit] (the root) but later commands
// were prefixed with the stale cursor, so a root statement could be
// staged under e.g. routing-instances RI1. FAIL-ON-REVERT: restoring
// the unconditional restore in dispatchTopUp15082 (and dropping the
// editPath=nil on configure) turns every defect cell here RED.

type topExitFake16702 struct {
	pb.BpfrxServiceClient
	setInputs []string
	exitCalls int
}

func (f *topExitFake16702) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}

func (f *topExitFake16702) ExitConfigure(_ context.Context, _ *pb.ExitConfigureRequest, _ ...grpc.CallOption) (*pb.ExitConfigureResponse, error) {
	f.exitCalls++
	return &pb.ExitConfigureResponse{}, nil
}

func (f *topExitFake16702) GetConfigModeStatus(_ context.Context, _ *pb.GetConfigModeStatusRequest, _ ...grpc.CallOption) (*pb.GetConfigModeStatusResponse, error) {
	return &pb.GetConfigModeStatusResponse{InConfigMode: true}, nil
}

func (f *topExitFake16702) EnterConfigure(_ context.Context, _ *pb.EnterConfigureRequest, _ ...grpc.CallOption) (*pb.EnterConfigureResponse, error) {
	return &pb.EnterConfigureResponse{}, nil
}

func discardCtl16702(t *testing.T, fake pb.BpfrxServiceClient) *ctl {
	t.Helper()
	rl, err := readline.NewEx(&readline.Config{Stdin: io.NopCloser(strings.NewReader("")), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("readline.NewEx: %v", err)
	}
	t.Cleanup(func() { rl.Close() })
	c := &ctl{client: fake, rl: rl, username: "u", hostname: "h"}
	c.configMode.Store(true)
	return c
}

// The prompt string itself is not observable in a unit test
// (chzyer/readline keeps it inside its RuneBuffer and exports no
// getter), so the cells below assert the state that determines it:
// configMode (remote) — production calls
// rl.SetPrompt(operationalPrompt()) exactly when it clears
// configMode on a successful top-level exit, and
// rl.SetPrompt(configPrompt()) exactly when it restores the cursor.
// A stale '#' prompt is therefore equivalent to configMode still
// being set (or, locally, configOwned still being set).

func TestRemoteTopExitDoesNotRestoreStaleCursor16702(t *testing.T) {
	for _, line := range []string{"top exit", "top quit"} {
		fake := &topExitFake16702{}
		c := discardCtl16702(t, fake)
		c.editPath = []string{"routing-instances", "RI1"}
		c.rl.SetPrompt(c.configPrompt())
		var err error
		out := captureStdout(t, func() { err = c.dispatchConfig(line) })
		if err != nil {
			t.Fatalf("%q: %v (#16702)", line, err)
		}
		if !strings.Contains(out, "Exiting configuration mode") {
			t.Fatalf("%q: missing exit banner: %q (#16702)", line, out)
		}
		if fake.exitCalls != 1 {
			t.Fatalf("%q: ExitConfigure calls = %d, want 1 (#16702)", line, fake.exitCalls)
		}
		if c.configMode.Load() {
			t.Fatalf("%q: still in configuration mode after top-level exit (#16702)", line)
		}
		if len(c.editPath) != 0 {
			t.Fatalf("%q: editPath = %v, want empty after release — stale cursor restored (#16702)", line, c.editPath)
		}

		// Re-enter: configure promises [edit] at the root, so the next
		// set must go to the root, not under the stale cursor.
		out = captureStdout(t, func() { err = c.dispatchOperational("configure") })
		if err != nil {
			t.Fatalf("%q: re-enter configure: %v (#16702)", line, err)
		}
		if !strings.Contains(out, "[edit]") {
			t.Fatalf("%q: configure did not print [edit]: %q (#16702)", line, out)
		}
		if len(c.editPath) != 0 {
			t.Fatalf("%q: editPath after configure = %v, want root (#16702)", line, c.editPath)
		}
		captureStdout(t, func() { err = c.dispatchConfig("set system host-name edge") })
		if err != nil {
			t.Fatalf("%q: set after re-enter: %v (#16702)", line, err)
		}
		if len(fake.setInputs) != 1 || fake.setInputs[0] != "system host-name edge" {
			t.Fatalf("%q: Set inputs = %v, want exactly [\"system host-name edge\"] at the root, not prefixed by the stale cursor (#16702)", line, fake.setInputs)
		}
	}
}

// Control: a top-prefixed mutation that stays in configuration mode
// still restores the cursor (the #15082 contract is unchanged).
func TestRemoteTopSetStillRestoresCursor16702(t *testing.T) {
	fake := &topExitFake16702{}
	c := discardCtl16702(t, fake)
	c.editPath = []string{"routing-instances", "RI1"}
	var err error
	captureStdout(t, func() { err = c.dispatchConfig("top set system host-name edge") })
	if err != nil {
		t.Fatalf("top set: %v (#16702 control)", err)
	}
	if !c.configMode.Load() {
		t.Fatal("top set left configuration mode (#16702 control)")
	}
	if got := strings.Join(c.editPath, " "); got != "routing-instances RI1" {
		t.Fatalf("editPath = %q, want cursor restored after top set (#16702 control)", got)
	}
	if len(fake.setInputs) != 1 || fake.setInputs[0] != "system host-name edge" {
		t.Fatalf("Set inputs = %v, want root path (#16702 control)", fake.setInputs)
	}
}

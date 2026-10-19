package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #15237 (A53-02/A53-03/A53-06/A53-07) remote surface: identity `up`,
// exit-as-up with dirty warning only at the top, edit_path on the
// Complete wire, and raw-remainder set preserving quoted whitespace.
// FAIL-ON-REVERT: restoring Fields+Join / unconditional ExitConfigure
// / root completion turns each cell RED.

type navRecorder15237 struct {
	pb.BpfrxServiceClient
	setInputs    []string
	deleteInputs []string
	completeReqs []*pb.CompleteRequest
	exitCalls    int
	dirty        bool
}

func (f *navRecorder15237) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}
func (f *navRecorder15237) Delete(_ context.Context, in *pb.DeleteRequest, _ ...grpc.CallOption) (*pb.DeleteResponse, error) {
	f.deleteInputs = append(f.deleteInputs, in.GetInput())
	return &pb.DeleteResponse{}, nil
}
func (f *navRecorder15237) ExitConfigure(_ context.Context, _ *pb.ExitConfigureRequest, _ ...grpc.CallOption) (*pb.ExitConfigureResponse, error) {
	f.exitCalls++
	return &pb.ExitConfigureResponse{}, nil
}
func (f *navRecorder15237) GetConfigModeStatus(_ context.Context, _ *pb.GetConfigModeStatusRequest, _ ...grpc.CallOption) (*pb.GetConfigModeStatusResponse, error) {
	return &pb.GetConfigModeStatusResponse{InConfigMode: true, Dirty: f.dirty}, nil
}
func (f *navRecorder15237) Complete(_ context.Context, in *pb.CompleteRequest, _ ...grpc.CallOption) (*pb.CompleteResponse, error) {
	f.completeReqs = append(f.completeReqs, in)
	return &pb.CompleteResponse{Candidates: []string{"host-name"}}, nil
}

func TestRemoteUpPopsZoneIdentity15237(t *testing.T) {
	fake := &navRecorder15237{}
	c := configModeCtl(fake)
	c.editPath = []string{"security", "zones", "security-zone", "trust"}
	var err error
	captureStdout(t, func() { err = c.dispatchConfig("up") })
	if err != nil {
		t.Fatalf("up: %v", err)
	}
	if got := strings.Join(c.editPath, " "); got != "security zones" {
		t.Fatalf("editPath after up = %q, want %q (#15237 A53-02)", got, "security zones")
	}
	// Control: next set stages under security zones, not a junk zone.
	captureStdout(t, func() { err = c.dispatchConfig("set security-zone dmz") })
	if err != nil {
		t.Fatalf("set after up: %v", err)
	}
	if len(fake.setInputs) != 1 || fake.setInputs[0] != "security zones security-zone dmz" {
		t.Fatalf("Set inputs = %v, want under security zones (#15237 A53-02)", fake.setInputs)
	}
}

func TestRemoteExitAtDepthActsAsUp15237(t *testing.T) {
	fake := &navRecorder15237{dirty: true}
	c := configModeCtl(fake)
	c.editPath = []string{"security", "policies"}
	var err error
	out := captureStdout(t, func() { err = c.dispatchConfig("exit") })
	if err != nil {
		t.Fatalf("exit at depth: %v", err)
	}
	if fake.exitCalls != 0 {
		t.Fatalf("exit at depth called ExitConfigure %d times, want 0 (#15237 A53-03)", fake.exitCalls)
	}
	if !c.configMode.Load() {
		t.Fatal("exit at depth left configuration mode (#15237 A53-03)")
	}
	if got := strings.Join(c.editPath, " "); got != "security" {
		t.Fatalf("editPath after exit-at-depth = %q, want security (#15237 A53-03)", got)
	}
	if strings.Contains(out, "Exiting configuration mode") {
		t.Fatalf("exit at depth printed exit banner: %q", out)
	}
	// Now at [security]: another exit pops to [edit], still no release.
	captureStdout(t, func() { err = c.dispatchConfig("exit") })
	if err != nil || fake.exitCalls != 0 || len(c.editPath) != 0 {
		t.Fatalf("second exit: err=%v calls=%d path=%v", err, fake.exitCalls, c.editPath)
	}
	// At top with dirty candidate: warns, then releases exactly once.
	out = captureStdout(t, func() { err = c.dispatchConfig("exit") })
	if err != nil {
		t.Fatalf("exit at top: %v", err)
	}
	if !strings.Contains(out, "warning: uncommitted changes") {
		t.Fatalf("dirty top exit did not warn: %q (#15237 A53-03)", out)
	}
	if fake.exitCalls != 1 || c.configMode.Load() {
		t.Fatalf("top exit: calls=%d configMode=%v, want 1/false", fake.exitCalls, c.configMode.Load())
	}
}

func TestRemoteSetPreservesQuotedWhitespace15237(t *testing.T) {
	fake := &navRecorder15237{}
	c := configModeCtl(fake)
	c.editPath = []string{"system"}
	var err error
	captureStdout(t, func() { err = c.dispatchConfig(`set services ssh message "a  b"`) })
	if err != nil {
		t.Fatalf("set message: %v", err)
	}
	if len(fake.setInputs) != 1 || !strings.Contains(fake.setInputs[0], `"a  b"`) {
		t.Fatalf("Set inputs = %v, want quoted doubled-space value preserved (#15237 A53-07)", fake.setInputs)
	}
	if !strings.HasPrefix(fake.setInputs[0], "system ") {
		t.Fatalf("Set input %q missing edit-path prefix", fake.setInputs[0])
	}
}

func TestRemoteCompleteSendsEditPath15237(t *testing.T) {
	fake := &navRecorder15237{}
	c := configModeCtl(fake)
	c.editPath = []string{"system"}
	rc := &remoteCompleter{ctl: c}
	rc.Do([]rune("set host"), len([]rune("set host")))
	if len(fake.completeReqs) != 1 {
		t.Fatalf("Complete calls = %d, want 1", len(fake.completeReqs))
	}
	if got := strings.Join(fake.completeReqs[0].GetEditPath(), " "); got != "system" {
		t.Fatalf("Complete edit_path = %q, want system (#15237 A53-06)", got)
	}
}

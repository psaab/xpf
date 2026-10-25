package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #16790 (R3-A53-04 + folded R3-A54-03): remote config-mode
// deactivate/activate and `show <path>` built their path from
// strings.Fields, so a quoted element (`policy "allow web"`) was split
// into `policy`, `"allow`, `web"` and JoinConfigPathTokens re-quoted
// those literal fragments — the daemon then looked up a path that does
// not exist (fail-closed: not found), and comment words leaked into the
// path. These cells pin the wire to the canonical config lexer, as the
// console and the remote set/delete arms already use.

type lexRecorder16790 struct {
	pb.BpfrxServiceClient
	setInputs   []string
	configPath  []string
	configCalls int
	comparePath []string
}

func (f *lexRecorder16790) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}

func (f *lexRecorder16790) ShowConfig(_ context.Context, in *pb.ShowConfigRequest, _ ...grpc.CallOption) (*pb.ShowConfigResponse, error) {
	f.configCalls++
	f.configPath = append([]string(nil), in.GetPath()...)
	return &pb.ShowConfigResponse{Output: "stub"}, nil
}

func (f *lexRecorder16790) ShowCompare(_ context.Context, in *pb.ShowCompareRequest, _ ...grpc.CallOption) (*pb.ShowCompareResponse, error) {
	f.comparePath = append([]string(nil), in.GetPath()...)
	return &pb.ShowCompareResponse{Output: "stub"}, nil
}

func TestRemoteDeactivateActivateUsesLexedPath16790(t *testing.T) {
	// Quoted whitespace-bearing policy name round-trips as ONE element.
	fake := &lexRecorder16790{}
	c := configModeCtl(fake)
	if err := c.dispatchConfig(`deactivate security policies from-zone trust to-zone untrust policy "allow web"`); err != nil {
		t.Fatalf("dispatchConfig deactivate: %v", err)
	}
	want := `deactivate security policies from-zone trust to-zone untrust policy "allow web"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q] (#16790)", fake.setInputs, want)
	}

	fake2 := &lexRecorder16790{}
	c2 := configModeCtl(fake2)
	if err := c2.dispatchConfig(`activate security policies from-zone trust to-zone untrust policy "allow web"`); err != nil {
		t.Fatalf("dispatchConfig activate: %v", err)
	}
	want2 := `activate security policies from-zone trust to-zone untrust policy "allow web"`
	if len(fake2.setInputs) != 1 || fake2.setInputs[0] != want2 {
		t.Fatalf("Set inputs = %v, want [%q] (#16790)", fake2.setInputs, want2)
	}

	// Comment words must not leak into the wire path.
	fake3 := &lexRecorder16790{}
	c3 := configModeCtl(fake3)
	if err := c3.dispatchConfig(`deactivate system /* note */ host-name`); err != nil {
		t.Fatalf("dispatchConfig deactivate comment: %v", err)
	}
	if len(fake3.setInputs) != 1 || fake3.setInputs[0] != "deactivate system host-name" {
		t.Fatalf("Set inputs = %v, want [deactivate system host-name] (#16790)", fake3.setInputs)
	}

	// Control: plain path is unchanged (unquoted).
	fake4 := &lexRecorder16790{}
	c4 := configModeCtl(fake4)
	if err := c4.dispatchConfig(`deactivate system name-server 9.9.9.9`); err != nil {
		t.Fatalf("dispatchConfig deactivate plain: %v", err)
	}
	if len(fake4.setInputs) != 1 || fake4.setInputs[0] != "deactivate system name-server 9.9.9.9" {
		t.Fatalf("Set inputs = %v, want plain control (#16790)", fake4.setInputs)
	}

	// Edit cursor with a whitespace-bearing element prefixes correctly.
	fake5 := &lexRecorder16790{}
	c5 := configModeCtl(fake5)
	c5.editPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust"}
	if err := c5.dispatchConfig(`deactivate policy "allow web"`); err != nil {
		t.Fatalf("dispatchConfig deactivate at cursor: %v", err)
	}
	want5 := `deactivate security policies from-zone trust to-zone untrust policy "allow web"`
	if len(fake5.setInputs) != 1 || fake5.setInputs[0] != want5 {
		t.Fatalf("Set inputs = %v, want [%q] (#16790)", fake5.setInputs, want5)
	}

	// Malformed lexing is refused before any RPC (fail closed).
	fake6 := &lexRecorder16790{}
	c6 := configModeCtl(fake6)
	if err := c6.dispatchConfig(`deactivate policy "allow web`); err == nil {
		t.Fatalf("unterminated quote deactivate returned nil; want refusal (#16790)")
	}
	if len(fake6.setInputs) != 0 {
		t.Fatalf("refused line still sent RPC: %v (#16790)", fake6.setInputs)
	}
	// Bare verb still refused before any RPC (ParseDeactivateActivateCommand
	// requires a path, so this surfaces as invalid path).
	if err := c6.dispatchConfig(`deactivate`); err == nil || !strings.Contains(err.Error(), "invalid path") {
		t.Fatalf("bare deactivate err = %v, want invalid path (#16790)", err)
	}
}

func TestRemoteConfigShowUsesLexedPath16790(t *testing.T) {
	// Quoted element reaches ShowConfig as ONE token.
	fake := &lexRecorder16790{}
	c := configModeCtl(fake)
	if err := c.dispatchConfig(`show security zones security-zone "lan in"`); err != nil {
		t.Fatalf("dispatchConfig show: %v", err)
	}
	if fake.configCalls != 1 || !reflect.DeepEqual(fake.configPath, []string{"security", "zones", "security-zone", "lan in"}) {
		t.Fatalf("ShowConfig calls=%d path=%v, want [security zones security-zone \"lan in\"] (#16790)", fake.configCalls, fake.configPath)
	}

	// Pipe survives, and a quoted "|" is data, not a pipe.
	fake2 := &lexRecorder16790{}
	c2 := configModeCtl(fake2)
	if err := c2.dispatchConfig(`show security zones security-zone "a|b" | display set`); err != nil {
		t.Fatalf("dispatchConfig show display: %v", err)
	}
	if fake2.configCalls != 1 || !reflect.DeepEqual(fake2.configPath, []string{"security", "zones", "security-zone", "a|b"}) {
		t.Fatalf("ShowConfig calls=%d path=%v, want quoted-pipe element (#16790)", fake2.configCalls, fake2.configPath)
	}

	// Plain control + compare pipe.
	fake3 := &lexRecorder16790{}
	c3 := configModeCtl(fake3)
	if err := c3.dispatchConfig(`show interfaces`); err != nil {
		t.Fatalf("dispatchConfig show plain: %v", err)
	}
	if !reflect.DeepEqual(fake3.configPath, []string{"interfaces"}) {
		t.Fatalf("ShowConfig path=%v, want [interfaces] (#16790)", fake3.configPath)
	}
	fake4 := &lexRecorder16790{}
	c4 := configModeCtl(fake4)
	if err := c4.dispatchConfig(`show "lan in" | compare`); err != nil {
		t.Fatalf("dispatchConfig show compare: %v", err)
	}
	if !reflect.DeepEqual(fake4.comparePath, []string{"lan in"}) {
		t.Fatalf("ShowCompare path=%v, want [lan in] (#16790)", fake4.comparePath)
	}

	// Malformed lexing is refused before any RPC.
	fake5 := &lexRecorder16790{}
	c5 := configModeCtl(fake5)
	if err := c5.dispatchConfig(`show "lan in`); err == nil {
		t.Fatalf("unterminated quote show returned nil; want refusal (#16790)")
	}
	if fake5.configCalls != 0 {
		t.Fatalf("refused show still sent RPC (#16790)")
	}
}

package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #14147: the remote CLI split copy/rename/insert with strings.Fields
// before re-joining for the Set RPC, so the wire line carried the
// Fields endpoints while the server gate adjudicated the lexed ones.
// These cells assert the wire input is built from the canonical
// lexer split.

type splitRecorder14147 struct {
	pb.BpfrxServiceClient
	setInputs []string
}

func (f *splitRecorder14147) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}

func TestRemoteCopyRenameWireUsesLexedSplit14147(t *testing.T) {
	fake := &splitRecorder14147{}
	c := configModeCtl(fake)
	// Comment form: the comment words must not reach the wire as path
	// tokens; the lexed endpoints are ssh -> telnet.
	if err := c.dispatchConfig(`rename system services /* to */ ssh to system services telnet`); err != nil {
		t.Fatalf("dispatchConfig: %v", err)
	}
	want := "rename system services ssh to system services telnet"
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q] (#14147)", fake.setInputs, want)
	}

	// Quoted-"to" form: the quoted token is a path element, so the
	// lexed source is [system services ssh to foo] and the only bare
	// separator is the second `to`.
	fake2 := &splitRecorder14147{}
	c2 := configModeCtl(fake2)
	if err := c2.dispatchConfig(`rename system services ssh "to" foo to system root-authentication`); err != nil {
		t.Fatalf("dispatchConfig: %v", err)
	}
	want2 := "rename system services ssh to foo to system root-authentication"
	if len(fake2.setInputs) != 1 || fake2.setInputs[0] != want2 {
		t.Fatalf("Set inputs = %v, want [%q] (#14147)", fake2.setInputs, want2)
	}
}

func TestRemoteInsertWireUsesLexedSplit14147(t *testing.T) {
	fake := &splitRecorder14147{}
	c := configModeCtl(fake)
	if err := c.dispatchConfig(`insert system services ssh /* after */ foo after bar`); err != nil {
		t.Fatalf("dispatchConfig: %v", err)
	}
	want := "insert system services ssh foo after bar"
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q] (#14147)", fake.setInputs, want)
	}
}

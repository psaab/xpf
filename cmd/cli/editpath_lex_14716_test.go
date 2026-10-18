package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #14716: the remote CLI stored its edit cursor as raw strings.Fields
// tokens and re-joined them into the wire input. A decorated cursor
// (`edit /* interfaces */ "system"`) reached the server gate as the raw
// spelling while the store executed the lexed path. The cursor must be
// lexed at edit time and normalized before every wire join.

type editRecorder14716 struct {
	pb.BpfrxServiceClient
	setInputs    []string
	deleteInputs []string
}

func (f *editRecorder14716) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}

func (f *editRecorder14716) Delete(_ context.Context, in *pb.DeleteRequest, _ ...grpc.CallOption) (*pb.DeleteResponse, error) {
	f.deleteInputs = append(f.deleteInputs, in.GetInput())
	return &pb.DeleteResponse{}, nil
}

func TestDispatchConfigDecoratedEditPathWire14716(t *testing.T) {
	fake := &editRecorder14716{}
	c := configModeCtl(fake)
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`edit /* interfaces */ "system"`)
	})
	if err != nil {
		t.Fatalf("dispatchConfig(edit decorated): %v", err)
	}
	if got := strings.Join(c.editPath, " "); got != "system" {
		t.Fatalf("editPath = %q, want lexed %q (#14716)", got, "system")
	}
	captureStdout(t, func() {
		err = c.dispatchConfig("set root-authentication plain-text-password hunter2")
	})
	if err != nil {
		t.Fatalf("dispatchConfig(set): %v", err)
	}
	want := "system root-authentication plain-text-password hunter2"
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want [%q] — the wire must carry the lexed resolved path the server gate adjudicates (#14716)", fake.setInputs, want)
	}
}

func TestDispatchConfigQuotedEditPathWire14716(t *testing.T) {
	fake := &editRecorder14716{}
	c := configModeCtl(fake)
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`edit "system"`)
	})
	if err != nil {
		t.Fatalf("dispatchConfig(edit quoted): %v", err)
	}
	captureStdout(t, func() {
		err = c.dispatchConfig("delete root-authentication")
	})
	if err != nil {
		t.Fatalf("dispatchConfig(delete): %v", err)
	}
	want := "system root-authentication"
	if len(fake.deleteInputs) != 1 || fake.deleteInputs[0] != want {
		t.Fatalf("Delete inputs = %v, want [%q] (#14716)", fake.deleteInputs, want)
	}
}

func TestDispatchConfigMalformedEditRejected14716(t *testing.T) {
	fake := &editRecorder14716{}
	c := configModeCtl(fake)
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`edit system /*`)
	})
	if err == nil {
		t.Fatal("an unterminated-comment edit fragment was stored; it must be refused so a later set cannot complete it into a denied path (#14716)")
	}
	if len(c.editPath) != 0 {
		t.Fatalf("editPath = %v, want empty after a refused edit", c.editPath)
	}
}

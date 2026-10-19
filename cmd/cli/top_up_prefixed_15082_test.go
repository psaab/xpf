package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// #15082 A53-01 (remote surface): `top delete ...` printed [edit],
// sent no Delete RPC, and returned nil — the permit policy stayed
// in the candidate and committed. The prefixed form must send
// exactly one Delete for the un-prefixed (top-relative) path and
// restore the cursor, or return a non-nil error.

type topUpRecorder15082 struct {
	pb.BpfrxServiceClient
	setInputs         []string
	deleteInputs      []string
	showConfigFormats []pb.ConfigFormat
}

func (f *topUpRecorder15082) Set(_ context.Context, in *pb.SetRequest, _ ...grpc.CallOption) (*pb.SetResponse, error) {
	f.setInputs = append(f.setInputs, in.GetInput())
	return &pb.SetResponse{}, nil
}

func (f *topUpRecorder15082) Delete(_ context.Context, in *pb.DeleteRequest, _ ...grpc.CallOption) (*pb.DeleteResponse, error) {
	f.deleteInputs = append(f.deleteInputs, in.GetInput())
	return &pb.DeleteResponse{}, nil
}

func (f *topUpRecorder15082) ShowConfig(_ context.Context, in *pb.ShowConfigRequest, _ ...grpc.CallOption) (*pb.ShowConfigResponse, error) {
	f.showConfigFormats = append(f.showConfigFormats, in.GetFormat())
	return &pb.ShowConfigResponse{}, nil
}

func TestRemoteTopDeleteSendsOneDelete15082(t *testing.T) {
	fake := &topUpRecorder15082{}
	c := configModeCtl(fake)
	c.editPath = []string{"security", "policies", "from-zone", "trust"}
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig("top delete security policies from-zone trust to-zone untrust policy allow-all")
	})
	if err != nil {
		t.Fatalf("top delete ... = %v, want one Delete RPC (#15082)", err)
	}
	want := "security policies from-zone trust to-zone untrust policy allow-all"
	if len(fake.deleteInputs) != 1 || fake.deleteInputs[0] != want {
		t.Fatalf("Delete inputs = %v, want exactly [%q] — nil with no RPC is the #15082 defect", fake.deleteInputs, want)
	}
	if len(fake.setInputs) != 0 {
		t.Fatalf("Set inputs = %v, want none for a delete", fake.setInputs)
	}
	if got := strings.Join(c.editPath, " "); got != "security policies from-zone trust" {
		t.Fatalf("editPath = %q, want cursor restored after top <cmd> (#15082)", got)
	}
}

func TestRemoteUpDeleteSendsOneDelete15082(t *testing.T) {
	// #15237 A53-02: up pops one IDENTITY (policy allow-all), so the
	// relative delete names the policy under the zone pair.
	for _, line := range []string{"up delete policy allow-all", "up 1 delete policy allow-all"} {
		fake := &topUpRecorder15082{}
		c := configModeCtl(fake)
		c.editPath = []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "allow-all"}
		var err error
		captureStdout(t, func() { err = c.dispatchConfig(line) })
		if err != nil {
			t.Fatalf("%q = %v, want one Delete RPC (#15082)", line, err)
		}
		// up pops ONE level: [... policy allow-all] -> [... policy],
		// so `delete allow-all` resolves under .../policy.
		want := "security policies from-zone trust to-zone untrust policy allow-all"
		if len(fake.deleteInputs) != 1 || fake.deleteInputs[0] != want {
			t.Fatalf("%q: Delete inputs = %v, want exactly [%q] (#15082)", line, fake.deleteInputs, want)
		}
		if got := strings.Join(c.editPath, " "); got != "security policies from-zone trust to-zone untrust policy allow-all" {
			t.Fatalf("%q: editPath = %q, want cursor restored (#15082)", line, got)
		}
	}
}

func TestRemoteTopUpBareUnchanged15082(t *testing.T) {
	fake := &topUpRecorder15082{}
	c := configModeCtl(fake)
	c.editPath = []string{"security", "policies", "from-zone"}
	if err := c.dispatchConfig("up 2"); err != nil {
		t.Fatalf("up 2: %v", err)
	}
	if got := strings.Join(c.editPath, " "); got != "security" {
		t.Fatalf("up 2: editPath = %q, want security", got)
	}
	if err := c.dispatchConfig("top"); err != nil {
		t.Fatalf("top: %v", err)
	}
	if len(c.editPath) != 0 {
		t.Fatalf("top: editPath = %v, want empty", c.editPath)
	}
	if len(fake.deleteInputs) != 0 || len(fake.setInputs) != 0 {
		t.Fatalf("bare navigation sent RPCs: set=%v delete=%v", fake.setInputs, fake.deleteInputs)
	}
}

func TestRemoteTopUpInvalidFailsClosed15082(t *testing.T) {
	for _, line := range []string{"top frobnicate x", "up 99 delete system host-name", "up x delete system host-name"} {
		fake := &topUpRecorder15082{}
		c := configModeCtl(fake)
		c.editPath = []string{"security", "policies"}
		var err error
		captureStdout(t, func() { err = c.dispatchConfig(line) })
		if err == nil {
			t.Fatalf("%q returned nil; must fail closed, never nil with no RPC (#15082)", line)
		}
		if len(fake.deleteInputs) != 0 || len(fake.setInputs) != 0 {
			t.Fatalf("%q sent RPCs despite failing: set=%v delete=%v", line, fake.setInputs, fake.deleteInputs)
		}
		if got := strings.Join(c.editPath, " "); got != "security policies" {
			t.Fatalf("%q: editPath = %q, want cursor restored", line, got)
		}
	}
}

// #15759: the remote surface must send the quoted value byte-for-
// byte — the old token re-join split "wan  uplink" and collapsed
// its doubled spaces before the Set RPC.
func TestRemoteTopUpQuotedSurvives15759(t *testing.T) {
	fake := &topUpRecorder15082{}
	c := configModeCtl(fake)
	c.editPath = []string{"interfaces", "ge-0/0/0"}
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig(`up set description "wan  uplink"`)
	})
	if err != nil {
		t.Fatalf("up set quoted = %v (#15759)", err)
	}
	want := `interfaces description "wan  uplink"`
	if len(fake.setInputs) != 1 || fake.setInputs[0] != want {
		t.Fatalf("Set inputs = %v, want exactly [%q] (#15759)", fake.setInputs, want)
	}
	if got := strings.Join(c.editPath, " "); got != "interfaces ge-0/0/0" {
		t.Fatalf("editPath = %q, want cursor restored (#15759)", got)
	}
}

// #15759: `top show | display set` on the remote surface must issue
// the display-set ShowConfig RPC, not a bare show.
func TestRemoteTopShowDisplaySet15759(t *testing.T) {
	fake := &topUpRecorder15082{}
	c := configModeCtl(fake)
	c.editPath = []string{"security", "policies"}
	var err error
	captureStdout(t, func() {
		err = c.dispatchConfig("top show | display set")
	})
	if err != nil {
		t.Fatalf("top show | display set = %v (#15759)", err)
	}
	if len(fake.showConfigFormats) != 1 || fake.showConfigFormats[0] != pb.ConfigFormat_SET {
		t.Fatalf("ShowConfig formats = %v, want [SET] (#15759)", fake.showConfigFormats)
	}
}

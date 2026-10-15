package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type fake13551 struct {
	pb.BpfrxServiceClient
	showTextTopics []string
	showConfig     []*pb.ShowConfigRequest
	systemInfo     []string
}

func (f *fake13551) ShowText(_ context.Context, req *pb.ShowTextRequest, _ ...grpc.CallOption) (*pb.ShowTextResponse, error) {
	f.showTextTopics = append(f.showTextTopics, req.Topic)
	return &pb.ShowTextResponse{Output: "text:" + req.Topic + "\n"}, nil
}
func (f *fake13551) ShowConfig(_ context.Context, req *pb.ShowConfigRequest, _ ...grpc.CallOption) (*pb.ShowConfigResponse, error) {
	f.showConfig = append(f.showConfig, req)
	return &pb.ShowConfigResponse{Output: "rescue-config\n"}, nil
}
func (f *fake13551) GetSystemInfo(_ context.Context, req *pb.GetSystemInfoRequest, _ ...grpc.CallOption) (*pb.GetSystemInfoResponse, error) {
	f.systemInfo = append(f.systemInfo, req.Type)
	return &pb.GetSystemInfoResponse{Output: "info:" + req.Type + "\n"}, nil
}

func TestDispatchParity13551_ConfigurationRescue(t *testing.T) {
	f := &fake13551{}
	c := &ctl{client: f}
	out := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"configuration", "rescue"}); err != nil {
			t.Fatalf("handleShowSystem: %v", err)
		}
	})
	if len(f.systemInfo) != 1 || f.systemInfo[0] != "rescue-configuration" {
		t.Fatalf("GetSystemInfo types=%v, want [rescue-configuration]", f.systemInfo)
	}
	if !strings.Contains(out, "info:rescue-configuration") {
		t.Fatalf("output %q missing rescue config", out)
	}
}

func TestDispatchParity13551_ProcessesSummary(t *testing.T) {
	f := &fake13551{}
	c := &ctl{client: f}
	captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"processes", "summary"}); err != nil {
			t.Fatalf("handleShowSystem processes summary: %v", err)
		}
	})
	if len(f.systemInfo) != 1 || f.systemInfo[0] != "processes-summary" {
		t.Fatalf("GetSystemInfo types=%v, want [processes-summary] (summary token must not be dropped)", f.systemInfo)
	}
	// Bare processes still plain.
	f2 := &fake13551{}
	c2 := &ctl{client: f2}
	captureStdout(t, func() {
		if err := c2.handleShowSystem([]string{"processes"}); err != nil {
			t.Fatal(err)
		}
	})
	if len(f2.systemInfo) != 1 || f2.systemInfo[0] != "processes" {
		t.Fatalf("bare processes types=%v", f2.systemInfo)
	}
}

func TestDispatchParity13551_SystemStorage(t *testing.T) {
	f := &fake13551{}
	c := &ctl{client: f}
	out := captureStdout(t, func() {
		if err := c.handleShowSystem([]string{"storage"}); err != nil {
			t.Fatalf("handleShowSystem storage: %v", err)
		}
	})
	if len(f.showTextTopics) != 1 || f.showTextTopics[0] != "storage" {
		t.Fatalf("ShowText topics=%v, want [storage]", f.showTextTopics)
	}
	if !strings.Contains(out, "text:storage") {
		t.Fatalf("output %q missing storage text", out)
	}
}

func TestDispatchParity13551_NATStaticRuleDetail(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		topic string
	}{
		{[]string{"static", "rule"}, "nat-static-rule"},
		{[]string{"static", "rule", "detail"}, "nat-static-rule-detail"},
		{[]string{"static"}, "nat-static"},
	} {
		f := &fake13551{}
		c := &ctl{client: f}
		captureStdout(t, func() {
			if err := c.handleShowNAT(tc.args); err != nil {
				t.Fatalf("%v: %v", tc.args, err)
			}
		})
		if len(f.showTextTopics) != 1 || f.showTextTopics[0] != tc.topic {
			t.Fatalf("%v: topics=%v want [%s]", tc.args, f.showTextTopics, tc.topic)
		}
	}
}

package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func TestGetSystemInfoDenyCommandsUsesRequestedView13551(t *testing.T) {
	cfg := gateCfg7172(t, "^show system configuration rescue$", true)
	if err := gateDecide7172(t, cfg, "GetSystemInfo",
		&pb.GetSystemInfoRequest{Type: "rescue-configuration"}); err == nil {
		t.Fatal("GetSystemInfo{rescue-configuration} bypassed deny-commands for show system configuration rescue")
	}
	if err := gateDecide7172(t, cfg, "GetSystemInfo",
		&pb.GetSystemInfoRequest{Type: "processes-summary"}); err != nil {
		t.Fatalf("processes summary unrelated to rescue deny was refused: %v", err)
	}

	processCfg := gateCfg7172(t, "^show system processes summary$", true)
	if err := gateDecide7172(t, processCfg, "GetSystemInfo",
		&pb.GetSystemInfoRequest{Type: "processes-summary"}); err == nil {
		t.Fatal("GetSystemInfo{processes-summary} bypassed deny-commands for show system processes summary")
	}
	if err := gateDecide7172(t, processCfg, "GetSystemInfo",
		&pb.GetSystemInfoRequest{Type: "processes"}); err != nil {
		t.Fatalf("plain processes unrelated to summary deny was refused: %v", err)
	}
	if err := gateDecide7172(t, cfg, "GetSystemInfo", &pb.GetSystemInfoRequest{Type: "unknown"}); err == nil {
		t.Fatal("unknown GetSystemInfo type was admitted despite command-deny policy")
	}
}

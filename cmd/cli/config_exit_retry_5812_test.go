package main

// #5812: an explicit `exit`/`quit` in REMOTE CLI configuration mode used to
// discard the ExitConfigure RPC error and UNCONDITIONALLY clear local
// config-mode state (configMode / editPath / prompt). A transport
// timeout/disconnect before the release reached the daemon left the
// server-side configuration lock + candidate owned by this session while the
// client dropped to operational mode believing it released — throwing away the
// only immediate in-process retry path.
//
// The fix treats explicit exit as transactional: on an ExitConfigure error,
// surface it and STAY in configuration mode (configMode/editPath preserved) so
// the operator can retry; only clear on RPC success. The EOF/teardown path
// (main.go exitConfigureBounded) stays best-effort and is NOT exercised here.
//
// MOCK: exitConfigureFakeClient embeds pb.BpfrxServiceClient (so only
// ExitConfigure is stubbed; any other RPC nil-panics, which never happens on
// this path) and returns a configurable error, counting calls. Same embedding
// pattern as the #5053 exitConfigureRecorderClient.
//
// FAIL-ON-REVERT: restore `_, _ = c.client.ExitConfigure(...)` + the
// unconditional clear, and the error case silently transitions to operational
// mode → TestConfigExitRPCErrorStaysInConfigMode_5812 goes RED (configMode is
// false and the error is nil).

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type exitConfigureFakeClient struct {
	pb.BpfrxServiceClient
	err   error
	calls int32
}

func (f *exitConfigureFakeClient) ExitConfigure(
	_ context.Context, _ *pb.ExitConfigureRequest, _ ...grpc.CallOption,
) (*pb.ExitConfigureResponse, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return nil, f.err
	}
	return &pb.ExitConfigureResponse{}, nil
}

// #15237: the top-level exit warns on Dirty via GetConfigModeStatus
// before releasing; the fake reports clean so no warning interferes.
func (f *exitConfigureFakeClient) GetConfigModeStatus(
	_ context.Context, _ *pb.GetConfigModeStatusRequest, _ ...grpc.CallOption,
) (*pb.GetConfigModeStatusResponse, error) {
	return &pb.GetConfigModeStatusResponse{InConfigMode: true}, nil
}

func newConfigModeCtl(fake pb.BpfrxServiceClient) *ctl {
	c := &ctl{client: fake}
	c.configMode.Store(true)
	// #15237 A53-03: exit at a non-empty edit path now acts as `up`
	// and never reaches ExitConfigure, so the #5812 release-RPC
	// fixture must sit at the top level to exercise the release.
	c.editPath = nil
	return c
}

// TestConfigExitRPCErrorStaysInConfigMode_5812 is the core security/correctness
// assertion: an ExitConfigure error must NOT clear local config-mode state.
func TestConfigExitRPCErrorStaysInConfigMode_5812(t *testing.T) {
	for _, verb := range []string{"exit", "quit"} {
		t.Run(verb, func(t *testing.T) {
			fake := &exitConfigureFakeClient{err: status.Error(codes.Unavailable, "transport closing")}
			c := newConfigModeCtl(fake)

			err := c.dispatchConfig(verb)
			if err == nil {
				t.Fatalf("%s: ExitConfigure error was swallowed; want it surfaced", verb)
			}
			if fake.calls != 1 {
				t.Fatalf("%s: ExitConfigure called %d times, want 1", verb, fake.calls)
			}
			// State MUST be preserved so the operator can retry `exit`.
			if !c.configMode.Load() {
				t.Fatalf("%s: dropped out of configuration mode on RPC error (lost retry path)", verb)
			}
			if len(c.editPath) != 0 {
				t.Fatalf("%s: editPath was cleared on RPC error: %v", verb, c.editPath)
			}
		})
	}
}

// TestConfigExitRPCSuccessClearsState_5812 guards the happy path: a successful
// release clears config-mode state exactly once.
func TestConfigExitRPCSuccessClearsState_5812(t *testing.T) {
	for _, verb := range []string{"exit", "quit"} {
		t.Run(verb, func(t *testing.T) {
			fake := &exitConfigureFakeClient{err: nil}
			c := newConfigModeCtl(fake)

			if err := c.dispatchConfig(verb); err != nil {
				t.Fatalf("%s: unexpected error on successful release: %v", verb, err)
			}
			if fake.calls != 1 {
				t.Fatalf("%s: ExitConfigure called %d times, want 1", verb, fake.calls)
			}
			if c.configMode.Load() {
				t.Fatalf("%s: still in configuration mode after a successful release", verb)
			}
			if c.editPath != nil {
				t.Fatalf("%s: editPath not cleared after a successful release: %v", verb, c.editPath)
			}
		})
	}
}

// TestConfigExitRetryAfterErrorRecovers_5812 proves the idempotent recovery
// contract: a failed release leaves the session in config mode, and a retry
// that succeeds (the server having released, or a fresh success) transitions
// cleanly to operational mode.
func TestConfigExitRetryAfterErrorRecovers_5812(t *testing.T) {
	fake := &exitConfigureFakeClient{err: errors.New("simulated lost response")}
	c := newConfigModeCtl(fake)

	if err := c.dispatchConfig("exit"); err == nil {
		t.Fatal("first exit: want surfaced error")
	}
	if !c.configMode.Load() {
		t.Fatal("first exit: must remain in configuration mode")
	}

	// Operator retries; the release now succeeds (idempotent server-side).
	fake.err = nil
	if err := c.dispatchConfig("exit"); err != nil {
		t.Fatalf("retry exit: want clean success, got %v", err)
	}
	if c.configMode.Load() {
		t.Fatal("retry exit: must transition to operational mode")
	}
	if fake.calls != 2 {
		t.Fatalf("ExitConfigure called %d times across the two attempts, want 2", fake.calls)
	}
}

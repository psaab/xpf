package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// #13050: Server.MonitorInterface is served by BOTH listeners. The fabric one
// authenticates streams with the control-link PSK; the loopback one serves the
// local CLI, which sends no token at all. Before the split, every tokenless
// LOCAL stream incremented xpf_fabric_stream_args_unbound_total, so the
// #11524 Phase-2 predicate (counter at zero across a full upgrade cycle)
// could never be observed on a box that merely ran `monitor interface`
// locally. These cells pin the two contexts SEPARATELY, as the #11524 review
// required: fabric keeps strict args-token refusal plus the counted legacy
// fallback; local keeps working and never moves the counter.

// monitorInterfaceStreamAdapter13050 adapts an interceptor-wrapped
// grpc.ServerStream to the generated server-streaming interface the handler
// takes. Driving the handler through the PRODUCTION fabric stream
// interceptor (rather than stamping the context by hand) is what proves the
// marker is wired into the listener chain and not just present in the
// package.
type monitorInterfaceStreamAdapter13050 struct{ grpc.ServerStream }

func (monitorInterfaceStreamAdapter13050) Send(*pb.MonitorInterfaceResponse) error { return nil }

// runMonitorStream13050 drives one MonitorInterface stream at the handler.
//
// fabric=true routes through the production fabric stream interceptor with a
// valid method-only token (the connection gate), the way the fabric listener
// delivers a peer stream. fabric=false invokes the handler directly with no
// fabric metadata at all, the way the loopback listener delivers a local CLI
// stream after its marker-stripping chain.
//
// An accepted stream runs until its context is cancelled, so reaching the
// 5s bound with no error IS the accept signal (same contract as the #11082
// cells).
func runMonitorStream13050(t *testing.T, req *pb.MonitorInterfaceRequest, argsTok string, fabric bool) error {
	t.Helper()
	s := monitorBudgetStore9891(t)
	s.fabricAuthKeyFn = func() []byte { return streamArgsTestKey11082 }

	md := metadata.MD{}
	if fabric {
		md.Set(fabricAuthMetadataKey,
			fabricAuthTokenHex(streamArgsTestKey11082, time.Now(), pb.BpfrxService_MonitorInterface_FullMethodName))
	}
	if argsTok != "" {
		md.Set(fabricAuthArgsBoundKey, argsTok)
	}
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
	defer cancel()
	st := &capMonitorStream9891{ctx: ctx, cancel: cancel}
	errc := make(chan error, 1)
	if !fabric {
		go func() { errc <- s.MonitorInterface(req, st) }()
	} else {
		go func() {
			errc <- s.fabricAuthStreamInterceptor(nil, st,
				&grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName},
				func(srv interface{}, ss grpc.ServerStream) error {
					return s.MonitorInterface(req, monitorInterfaceStreamAdapter13050{ss})
				})
		}()
	}
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		cancel()
		<-errc
		return nil
	}
}

// TestMonitorInterfaceUnboundCounterFabricOnly13050 is the #13050 defect
// cell: a tokenless LOCAL stream must keep working and must NOT move the
// fabric migration counter, while a tokenless FABRIC (legacy-peer) stream
// keeps counting the fallback (#11524 Phase 2 still ships it).
//
// FAIL-ON-REVERT: restoring the listener-blind counter makes the local cell
// fire (counter moved); removing the fallback branch makes the fabric cell
// fire (legacy stream rejected).
func TestMonitorInterfaceUnboundCounterFabricOnly13050(t *testing.T) {
	req := &pb.MonitorInterfaceRequest{InterfaceName: "lo"}

	before := FabricStreamArgsUnboundTotal()
	if err := runMonitorStream13050(t, req, "", false); err != nil {
		t.Fatalf("tokenless LOCAL monitor stream broke: %v", err)
	}
	if got := FabricStreamArgsUnboundTotal(); got != before {
		t.Fatalf("local loopback stream moved xpf_fabric_stream_args_unbound_total: %d -> %d "+
			"(the #11524 Phase-2 zero predicate can never hold while local CLI traffic counts)", before, got)
	}

	if err := runMonitorStream13050(t, req, "", true); err != nil && status.Code(err) == codes.Unauthenticated {
		t.Fatalf("legacy method-only FABRIC stream must not be rejected by the handler: %v", err)
	}
	if got := FabricStreamArgsUnboundTotal(); got != before+1 {
		t.Fatalf("fabric legacy stream counter = %d, want %d (fallback must stay counted until Phase 2)", got, before+1)
	}
}

// TestMonitorInterfaceLocalArgsHeaderIgnored13050 pins the other half of the
// split: fabric token semantics do not apply on the loopback listener. A
// local stream carrying a stray (here: garbage) args-bound header must keep
// working — the loopback surface authenticates by peer credentials (#5278),
// and judging it by fabric PSK machinery it has no key for would break local
// monitoring on a keyless standalone node.
func TestMonitorInterfaceLocalArgsHeaderIgnored13050(t *testing.T) {
	req := &pb.MonitorInterfaceRequest{InterfaceName: "lo"}
	before := FabricStreamArgsUnboundTotal()
	if err := runMonitorStream13050(t, req, "not-a-real-token", false); err != nil {
		t.Fatalf("local stream with a stray fabric-args header broke: %v", err)
	}
	if got := FabricStreamArgsUnboundTotal(); got != before {
		t.Fatalf("local stream with stray args header moved the fabric counter: %d -> %d", before, got)
	}
}

// TestMonitorInterfaceFabricArgsReplayStillRefused13050 re-pins the #11082
// replay refusal THROUGH the production fabric chain after the #13050 split:
// the fabric cell must not have been weakened while carving out the local
// one, and a refused replay must not count as an unbound fallback either.
func TestMonitorInterfaceFabricArgsReplayStillRefused13050(t *testing.T) {
	const method = pb.BpfrxService_MonitorInterface_FullMethodName
	reqA := &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/0"}
	reqB := &pb.MonitorInterfaceRequest{InterfaceName: "ge-0/0/1"}
	before := FabricStreamArgsUnboundTotal()
	err := runMonitorStream13050(t, reqB, mintStreamArgsToken11082(t, method, reqA), true)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("fabric stream replaying ge-0/0/0's token for ge-0/0/1 must stay Unauthenticated "+
			"after the #13050 split, got: %v", err)
	}
	if got := FabricStreamArgsUnboundTotal(); got != before {
		t.Fatalf("refused replay moved the unbound counter: %d -> %d (only accepted legacy streams count)", before, got)
	}
}

// TestFabricStreamInterceptorMarksFabricContext13050 pins the wiring itself:
// the fabric stream interceptor stamps the marker the split reads, and the
// loopback stream chain does not. Without this cell the marker helpers could
// be deleted from the interceptor (leaving the split permanently local-only,
// the fallback counter silently dead) while every other test still passes.
func TestFabricStreamInterceptorMarksFabricContext13050(t *testing.T) {
	s := keyedServer(fabricTestKey)
	const method = pb.BpfrxService_MonitorInterface_FullMethodName

	marked := false
	err := s.fabricAuthStreamInterceptor(nil,
		fakeServerStream{ctx: ctxWithToken(fabricAuthTokenHex([]byte(fabricTestKey), time.Now(), method))},
		&grpc.StreamServerInfo{FullMethod: method},
		func(srv interface{}, ss grpc.ServerStream) error {
			marked = fabricAuthStreamContext(ss.Context())
			return nil
		})
	if err != nil {
		t.Fatalf("valid fabric stream token rejected: %v", err)
	}
	if !marked {
		t.Fatal("the fabric stream interceptor does not stamp the fabric-listener marker the handler reads: " +
			"#13050 cannot distinguish listeners")
	}

	_, loopChain := loopbackServerInterceptors()
	if len(loopChain) == 0 {
		t.Fatal("the loopback gRPC server installs no stream interceptor chain")
	}
	loopMarked := false
	err = loopChain[0](nil,
		fakeServerStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{})},
		&grpc.StreamServerInfo{FullMethod: method},
		func(srv interface{}, ss grpc.ServerStream) error {
			loopMarked = fabricAuthStreamContext(ss.Context())
			return nil
		})
	if err != nil {
		t.Fatalf("loopback stream chain rejected a stream: %v", err)
	}
	if loopMarked {
		t.Fatal("the loopback stream chain stamped the fabric-listener marker")
	}
}

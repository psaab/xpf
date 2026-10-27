package grpcapi

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #17175: the stream interceptor and the #9051 re-auth tick passed a nil
// request to request-dependent authz, so since #16067 every class with
// any deny/allow-commands regex was refused Ping, Traceroute and
// MonitorInterface over gRPC. The #16067 cells called authorizeRPCCommand
// directly with a decoded request — a shape production never takes for
// streams — so they could not see it.
//
// These cells drive the REAL principalStreamInterceptor (bufconn cells
// drive the real generated stream handlers over the real chain) with
// regex-bearing classes. RED pre-fix: every admitted cell below was
// PermissionDenied "this RPC's arguments cannot be named as a command".

const streamAuthzConfig17175 = `
system {
    host-name authz-17175;
    login {
        class ping-deny {
            permissions view;
            deny-commands "^ping 10\.99\.";
        }
        class reboot-deny {
            permissions view;
            deny-commands "^request system reboot";
        }
        class diag-allow {
            permissions view;
            allow-commands "^ping|^traceroute|^monitor";
        }
        user opsuser {
            class ping-deny;
        }
        user rebootuser {
            class reboot-deny;
        }
        user allowuser {
            class diag-allow;
        }
    }
}
`

const streamAuthzPasswd17175 = `root:x:0:0:root:/root:/bin/bash
opsuser:x:4242:4242::/home/opsuser:/bin/bash
rebootuser:x:4247:4247::/home/rebootuser:/bin/bash
allowuser:x:4246:4246::/home/allowuser:/bin/bash
adminuser:x:4244:4244::/home/adminuser:/bin/bash
`

const (
	uidPingDeny17175   = 4242 // opsuser -> ping-deny
	uidRebootDeny17175 = 4247 // rebootuser -> reboot-deny (unrelated deny)
	uidDiagAllow17175  = 4246 // allowuser -> diag-allow
)

// stream17175 swaps the passwd fixture to one naming both test users and
// returns a server with a config whose classes carry regexes.
func streamServer17175(t *testing.T, cfgText string) *Server {
	t.Helper()
	usePasswdFixture17175(t)
	return NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, cfgText)})
}

func usePasswdFixture17175(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(streamAuthzPasswd17175), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
}

// drivingStream17175 is a fake grpc.ServerStream whose RecvMsg delivers
// one pre-decoded request, exactly as the generated server-streaming
// wrapper drives it (one RecvMsg, then the handler body). It records
// every Send so a cell can prove no output escaped before the verdict.
type drivingStream17175 struct {
	grpc.ServerStream
	ctx context.Context
	req any
}

func (f *drivingStream17175) Context() context.Context { return f.ctx }

func (f *drivingStream17175) RecvMsg(m any) error {
	// Field-wise copy: assigning the whole proto struct would copy its
	// MessageState lock (go vet copylocks).
	switch dst := m.(type) {
	case *pb.PingRequest:
		if src, ok := f.req.(*pb.PingRequest); ok {
			dst.Target, dst.Source, dst.RoutingInstance, dst.Count, dst.Size = src.Target, src.Source, src.RoutingInstance, src.Count, src.Size
		}
	case *pb.TracerouteRequest:
		if src, ok := f.req.(*pb.TracerouteRequest); ok {
			dst.Target, dst.Source, dst.RoutingInstance = src.Target, src.Source, src.RoutingInstance
		}
	case *pb.MonitorInterfaceRequest:
		if src, ok := f.req.(*pb.MonitorInterfaceRequest); ok {
			dst.InterfaceName, dst.SummaryMode = src.InterfaceName, src.SummaryMode
		}
	case *pb.MonitorPacketDropRequest:
		if src, ok := f.req.(*pb.MonitorPacketDropRequest); ok {
			dst.SourcePrefix, dst.DestinationPrefix, dst.Protocol, dst.FromZone, dst.Interface, dst.Node = src.SourcePrefix, src.DestinationPrefix, src.Protocol, src.FromZone, src.Interface, src.Node
			dst.SourcePort, dst.DestinationPort, dst.Count = src.SourcePort, src.DestinationPort, src.Count
		}
	}
	return nil
}

// recv17175 performs the single RecvMsg the generated wrapper performs.
func recv17175(stream grpc.ServerStream, req any) error {
	return stream.RecvMsg(req)
}

// runStream17175 drives principalStreamInterceptor with a handler that
// performs the generated wrapper's single RecvMsg into req, then blocks
// until its context ends (the production handler shape). It returns a
// channel for the interceptor's verdict and a channel closed when the
// handler body was entered.
func runStream17175(t *testing.T, s *Server, uid uint32, fullMethod string, req any) (errc chan error, entered chan struct{}, cancel func()) {
	t.Helper()
	ctx, cancelFn := context.WithCancel(ctxWithPeerUID(uid))
	entered = make(chan struct{})
	var once sync.Once
	handler := func(_ any, stream grpc.ServerStream) error {
		if err := recv17175(stream, req); err != nil {
			return err
		}
		once.Do(func() { close(entered) })
		<-stream.Context().Done()
		return nil
	}
	fs := &drivingStream17175{ctx: ctx, req: req}
	errc = make(chan error, 1)
	go func() {
		errc <- s.principalStreamInterceptor(nil, fs,
			&grpc.StreamServerInfo{FullMethod: fullMethod}, handler)
	}()
	return errc, entered, cancelFn
}

func fullMethod17175(method string) string {
	return "/" + pb.BpfrxService_ServiceDesc.ServiceName + "/" + method
}

// TestStreamFirstMessageAdmitsUnrelatedAndAllowlist17175 is the defect
// cell: under an unrelated deny and under an allowlist that explicitly
// admits ^ping|^traceroute|^monitor, Ping/Traceroute/MonitorInterface
// must stream (handler entered) and survive 3 re-auth ticks.
func TestStreamFirstMessageAdmitsUnrelatedAndAllowlist17175(t *testing.T) {
	shortenStreamReauth9051(t)
	cells := []struct {
		name   string
		uid    uint32
		method string
		req    any
	}{
		{"unrelated-deny Ping", uidRebootDeny17175, "Ping", &pb.PingRequest{Target: "10.98.1.1"}},
		{"allowlist Ping", uidDiagAllow17175, "Ping", &pb.PingRequest{Target: "10.98.1.1"}},
		{"allowlist Traceroute", uidDiagAllow17175, "Traceroute", &pb.TracerouteRequest{Target: "10.98.1.1"}},
		{"allowlist MonitorInterface", uidDiagAllow17175, "MonitorInterface", &pb.MonitorInterfaceRequest{}},
	}
	for _, tc := range cells {
		t.Run(tc.name, func(t *testing.T) {
			s := streamServer17175(t, streamAuthzConfig17175)
			errc, entered, cancel := runStream17175(t, s, tc.uid, fullMethod17175(tc.method), tc.req)
			defer cancel()
			select {
			case <-entered:
			case err := <-errc:
				t.Fatalf("%s was refused through the real stream interceptor: %v — "+
					"a regex-bearing class must be judged on the decoded first message, not nil (#17175)", tc.name, err)
			case <-time.After(5 * time.Second):
				t.Fatal("handler never entered")
			}
			// Survive 3 re-auth ticks (interval shortened to 15ms).
			select {
			case err := <-errc:
				t.Fatalf("%s was terminated by a re-auth tick re-pricing nil: %v (#17175)", tc.name, err)
			case <-time.After(3*streamReauthInterval9051 + 100*time.Millisecond):
			}
			cancel()
			select {
			case <-errc:
			case <-time.After(5 * time.Second):
				t.Fatal("stream did not end on hangup")
			}
		})
	}
}

// TestStreamFirstMessageArgumentDeny17175 is the argument-scoped half:
// under deny-commands "^ping 10\.99\.", Ping{10.99.1.1} is
// PermissionDenied at the first message (handler body never entered, no
// output), while Ping{10.98.1.1} streams.
func TestStreamFirstMessageArgumentDeny17175(t *testing.T) {
	shortenStreamReauth9051(t)
	s := streamServer17175(t, streamAuthzConfig17175)

	// Denied target.
	errc, entered, cancel := runStream17175(t, s, uidPingDeny17175,
		fullMethod17175("Ping"), &pb.PingRequest{Target: "10.99.1.1"})
	defer cancel()
	select {
	case <-entered:
		t.Fatal("Ping{10.99.1.1} entered the handler under deny-commands ^ping 10\\.99\\. — " +
			"the argument-scoped deny must fire on the first message (#17175)")
	case err := <-errc:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("Ping{10.99.1.1} verdict = %v (code %v), want PermissionDenied", err, status.Code(err))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no verdict for the denied Ping")
	}

	// Admitted target (control): a fix that denied every Ping for this
	// class would pass the arm above.
	errc2, entered2, cancel2 := runStream17175(t, s, uidPingDeny17175,
		fullMethod17175("Ping"), &pb.PingRequest{Target: "10.98.1.1"})
	defer cancel2()
	select {
	case <-entered2:
	case err := <-errc2:
		t.Fatalf("Ping{10.98.1.1} was refused under a deny naming only 10.99.*: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never entered for the admitted Ping")
	}
	cancel2()
	select {
	case <-errc2:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted stream did not end on hangup")
	}
}

// TestStreamReauthUsesRetainedMessage17175 pins the tick half: a class
// edit committed mid-stream that makes the RETAINED arguments denied
// must terminate the stream, while the same stream survives ticks when
// the edit does not name its arguments. Pre-fix the tick re-priced nil,
// so the first arm terminated every regex stream (including this
// control's twin) and argument edits were judged on nothing.
func TestStreamReauthUsesRetainedMessage17175(t *testing.T) {
	shortenStreamReauth9051(t)

	// Control: no edit — survives ticks (also covered above, kept here
	// so the revoked arm's difference is attributable to the edit).
	s := streamServer17175(t, streamAuthzConfig17175)
	errc, entered, cancel := runStream17175(t, s, uidDiagAllow17175,
		fullMethod17175("Ping"), &pb.PingRequest{Target: "10.98.1.1"})
	defer cancel()
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("control stream refused at first message: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("control handler never entered")
	}
	select {
	case err := <-errc:
		t.Fatalf("control stream terminated without any edit: %v", err)
	case <-time.After(3*streamReauthInterval9051 + 100*time.Millisecond):
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("control stream did not end on hangup")
	}

	// Revoked-by-argument-edit: commit a config whose allowlist no
	// longer admits ping (allow only traceroute). The retained
	// Ping{10.98.1.1} must now fail the tick.
	s2 := streamServer17175(t, streamAuthzConfig17175)
	errc2, entered2, cancel2 := runStream17175(t, s2, uidDiagAllow17175,
		fullMethod17175("Ping"), &pb.PingRequest{Target: "10.98.1.1"})
	defer cancel2()
	select {
	case <-entered2:
	case err := <-errc2:
		t.Fatalf("stream refused at first message before the edit: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never entered before the edit")
	}
	const narrowed = `
system {
    host-name authz-17175;
    login {
        class diag-allow {
            permissions view;
            allow-commands "^traceroute";
        }
        user allowuser {
            class diag-allow;
        }
    }
}
`
	store := s2.store
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(narrowed); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()

	select {
	case err := <-errc2:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("mid-stream argument revocation must end PermissionDenied, got %v (code %v)", err, status.Code(err))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stream outlived the mid-stream edit that revoked its retained arguments (#17175 tick must re-price the retained message, not nil)")
	}
}

// TestStreamRequestSpecCoversEveryStream17175 is the census (fix
// direction 3+4): every served stream is declared in
// streamRequestSpec17175, the table names no non-stream, and no stream
// is client-streaming — a client-streaming RPC would break the
// first-message-only design and must fail here, not silently inherit it.
func TestStreamRequestSpecCoversEveryStream17175(t *testing.T) {
	desc := pb.BpfrxService_ServiceDesc
	if len(desc.Streams) == 0 {
		t.Fatal("the service descriptor lists no streams — the enumeration source is broken")
	}
	served := make(map[string]bool, len(desc.Streams))
	for _, sd := range desc.Streams {
		if sd.ClientStreams {
			t.Errorf("stream %q is client-streaming: the first-message authorization design (#17175) does not cover it — declare and handle it explicitly", sd.StreamName)
		}
		if !sd.ServerStreams {
			t.Errorf("stream %q is not server-streaming; the census premise is broken", sd.StreamName)
		}
		full := "/" + desc.ServiceName + "/" + sd.StreamName
		served[full] = true
		if _, ok := streamRequestSpec17175[full]; !ok {
			t.Errorf("stream %q (%s) has no entry in streamRequestSpec17175: its request-dependence is undeclared, so the interceptor cannot know whether nil is safe (#17175)", sd.StreamName, full)
		}
	}
	for full := range streamRequestSpec17175 {
		if !served[full] {
			t.Errorf("streamRequestSpec17175 declares %q, which BpfrxService does not serve as a stream — a stale entry hides an undeclared real stream (#17175)", full)
		}
	}
	// The three request-dependent streams must be declared as such; a
	// table that marked them request-independent would re-create the
	// nil-request denial at open.
	for _, m := range []string{"Ping", "Traceroute", "MonitorInterface"} {
		if !streamNeedsRequest17175(fullMethod17175(m)) {
			t.Errorf("%s must be declared request-dependent in streamRequestSpec17175 (#17175)", m)
		}
	}
}

// TestStreamBufconnArgumentDeny17175 is the acceptance cell over the
// wire: through bufconn, the real generated Ping handler and the real
// interceptor chain, Ping{10.99.1.1} is PermissionDenied under
// "^ping 10\.99\." and Ping{10.98.1.1} is NOT PermissionDenied (it
// proceeds to the handler, which fails on the sandbox's missing ping
// binary / completes — either way the authz verdict is admission).
// TestStreamBufconnArgumentDeny17175Real drives bufconn with the peer
// lookup injected to the ping-deny user.
func TestStreamBufconnArgumentDeny17175Real(t *testing.T) {
	usePasswdFixture17175(t)
	s := NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, streamAuthzConfig17175)})
	s.peerLookupFn = fixedPeerUID5278(uidPingDeny17175)

	lis := bufconn.Listen(1 << 20)
	server := grpc.NewServer(
		grpc.ChainStreamInterceptor(s.principalStreamInterceptor),
		grpc.StatsHandler(&peerAuthStatsHandler{s: s}),
	)
	pb.RegisterBpfrxServiceServer(server, &pingOnlyServer17175{})
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := pb.NewBpfrxServiceClient(conn)

	// Denied: Ping{10.99.1.1} under ^ping 10\.99\.
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stream, err := client.Ping(ctx, &pb.PingRequest{Target: "10.99.1.1"})
		if err != nil {
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("Ping{10.99.1.1} open error = %v, want PermissionDenied", err)
			}
			return
		}
		_, err = stream.Recv()
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("Ping{10.99.1.1} recv error = %v (code %v), want PermissionDenied — "+
				"the argument-scoped deny must fire on the first message over the wire (#17175)", err, status.Code(err))
		}
	}()

	// Admitted: Ping{10.98.1.1} reaches the stub handler, which sends
	// one frame then closes — proof the authz verdict admitted it.
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stream, err := client.Ping(ctx, &pb.PingRequest{Target: "10.98.1.1"})
		if err != nil {
			t.Fatalf("Ping{10.98.1.1} open error: %v", err)
		}
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Ping{10.98.1.1} must be admitted under a deny naming only 10.99.* (first recv: %v)", err)
		}
		if resp.GetOutput() != "ok" {
			t.Fatalf("Ping{10.98.1.1} first frame = %q, want the stub handler's frame", resp.GetOutput())
		}
		if _, err := stream.Recv(); err != io.EOF {
			t.Fatalf("Ping{10.98.1.1} second recv = %v, want EOF after the stub frame", err)
		}
	}()
}

// pingOnlyServer17175 is a minimal BpfrxServiceServer whose Ping sends
// one frame; every other method is unimplemented. It lets the bufconn
// cell prove admission without exec'ing a real ping binary.
type pingOnlyServer17175 struct {
	pb.UnimplementedBpfrxServiceServer
}

func (p *pingOnlyServer17175) Ping(_ *pb.PingRequest, stream grpc.ServerStreamingServer[pb.PingResponse]) error {
	return stream.Send(&pb.PingResponse{Output: "ok"})
}

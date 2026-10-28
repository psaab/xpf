package grpcapi

import (
	"context"
	"fmt"
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
	"github.com/psaab/xpf/pkg/config"
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

// TestStreamSecondRecvMsgDoesNotReplaceRetained17175 pins F1: only
// the first RecvMsg is authorized and retained. A second RecvMsg into
// a denied target (unreachable in production — the generated wrapper
// receives exactly once) must neither replace the retained message
// nor terminate the stream on a tick with no config change; pre-fold
// it overwrote retained and the tick priced the swapped message.
func TestStreamSecondRecvMsgDoesNotReplaceRetained17175(t *testing.T) {
	shortenStreamReauth9051(t)
	s := streamServer17175(t, streamAuthzConfig17175)
	ctx, cancelFn := context.WithCancel(ctxWithPeerUID(uidPingDeny17175))
	defer cancelFn()
	entered := make(chan struct{})
	var once sync.Once
	handler := func(_ any, stream grpc.ServerStream) error {
		first := &pb.PingRequest{}
		if err := stream.RecvMsg(first); err != nil {
			return err
		}
		second := &pb.PingRequest{}
		if err := stream.RecvMsg(second); err != nil {
			return err
		}
		once.Do(func() { close(entered) })
		<-stream.Context().Done()
		return nil
	}
	// The fake delivers its one pre-decoded request on every RecvMsg,
	// so the interceptor arm proves a second RecvMsg is harmless; the
	// direct wrapper arm below proves the denied-target swap case.
	fs := &drivingStream17175{ctx: ctx, req: &pb.PingRequest{Target: "10.98.1.1"}}
	errc := make(chan error, 1)
	go func() {
		errc <- s.principalStreamInterceptor(nil, fs,
			&grpc.StreamServerInfo{FullMethod: fullMethod17175("Ping")}, handler)
	}()
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("stream refused: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never entered")
	}
	select {
	case err := <-errc:
		t.Fatalf("stream terminated after second RecvMsg with no config change: %v", err)
	case <-time.After(3*streamReauthInterval9051 + 100*time.Millisecond):
	}
	cancelFn()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end on hangup")
	}

	// Direct wrapper arm: first message admitted, second message with
	// a denied target must leave retained pointing at the first.
	recv := &authzRecvStream{
		ServerStream: &drivingStream17175{ctx: ctx, req: &pb.PingRequest{Target: "10.98.1.1"}},
		s:            s,
		fullMethod:   fullMethod17175("Ping"),
		baseCtx:      ctxWithPeerUID(uidPingDeny17175),
	}
	first := &pb.PingRequest{}
	if err := recv.RecvMsg(first); err != nil {
		t.Fatalf("first RecvMsg: %v", err)
	}
	recv.ServerStream = &drivingStream17175{ctx: ctx, req: &pb.PingRequest{Target: "10.99.1.1"}}
	second := &pb.PingRequest{}
	if err := recv.RecvMsg(second); err != nil {
		t.Fatalf("second RecvMsg must not re-authorize: %v", err)
	}
	retained, decided := recv.retainedRequest()
	if !decided {
		t.Fatal("retainedRequest reports undecided after first message")
	}
	if got, ok := retained.(*pb.PingRequest); !ok || got != first || got.GetTarget() != "10.98.1.1" {
		t.Fatalf("retained = %v, want the first message (10.98.1.1) — a second RecvMsg replaced it", retained)
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
	// F3: a needsRequest=false declaration is a claim that NO
	// request-priced arm can distinguish the typed empty request from
	// a populated request (or from nil). If a future arm is added for
	// such a method, open (typed-empty) and first-message/tick
	// (retained decoded message) would silently diverge. Assert it
	// structurally: for
	// every needsRequest=false stream, the empty request, a populated
	// request and nil must name the same argument forms, resolve the
	// same canonical command, price the same method permission,
	// require no config-target price, carry no alias forms, and not
	// be a config-read/commit-priced method.
	for full, needs := range streamRequestSpec17175 {
		if needs {
			continue
		}
		empty := emptyStreamRequest17175(full)
		if empty == nil {
			t.Errorf("%s is needsRequest=false but has no typed empty request in emptyStreamRequest17175", full)
			continue
		}
		populated := populatedStreamRequest17175(full)
		if populated == nil {
			t.Errorf("%s is needsRequest=false but has no populated probe request", full)
			continue
		}
		_, method, _ := splitFullMethod(full)
		base, resolved := rpcCanonicalCommand(full, empty)
		if !resolved {
			t.Errorf("%s needsRequest=false: empty request has no canonical command", full)
			continue
		}
		if got, ok := rpcCanonicalCommand(full, populated); !ok || got != base {
			t.Errorf("%s needsRequest=false: canonical command differs for populated request %q vs empty %q — a request-priced arm exists", full, got, base)
		}
		if got, ok := rpcCanonicalCommand(full, nil); !ok || got != base {
			t.Errorf("%s needsRequest=false: canonical command differs for nil request %q vs empty %q — a request-priced arm reads nil", full, got, base)
		}
		cfg := streamCensusCfg17175(t)
		emptyForms, emptyNamed := rpcArgumentForms(cfg, full, empty, base)
		popForms, popNamed := rpcArgumentForms(cfg, full, populated, base)
		if emptyNamed != popNamed || fmt.Sprint(emptyForms) != fmt.Sprint(popForms) {
			t.Errorf("%s needsRequest=false: rpcArgumentForms differs empty=%v/%v populated=%v/%v — a request-priced arm exists", full, emptyForms, emptyNamed, popForms, popNamed)
		}
		nilForms, nilNamed := rpcArgumentForms(cfg, full, nil, base)
		if nilNamed != emptyNamed || fmt.Sprint(nilForms) != fmt.Sprint(emptyForms) {
			t.Errorf("%s needsRequest=false: rpcArgumentForms differs nil=%v/%v empty=%v/%v — a request-priced arm reads nil", full, nilForms, nilNamed, emptyForms, emptyNamed)
		}
		p1, _ := methodPermission(full, empty)
		if p2, _ := methodPermission(full, populated); p1 != p2 {
			t.Errorf("%s needsRequest=false: methodPermission differs empty=%v populated=%v", full, p1, p2)
		}
		if p3, _ := methodPermission(full, nil); p1 != p3 {
			t.Errorf("%s needsRequest=false: methodPermission differs empty=%v nil=%v", full, p1, p3)
		}
		if _, ok := configTargetReadPermission(full, nil); ok {
			t.Errorf("%s needsRequest=false: configTargetReadPermission prices the nil request", full)
		}
		if _, ok := configTargetReadPermission(full, populated); ok {
			t.Errorf("%s needsRequest=false: configTargetReadPermission prices the populated request", full)
		}
		if _, ok := rpcAliasCommands16605[method]; ok {
			t.Errorf("%s needsRequest=false: rpcAliasCommands16605 has an arm for %s", full, method)
		}
		switch method {
		case "ShowConfig", "ShowCompare", "ShowRollback", "Commit", "CommitConfirmed":
			t.Errorf("%s needsRequest=false: %s is config-read/commit-priced", full, method)
		}
	}
}

func streamCensusCfg17175(t *testing.T) *config.Config {
	t.Helper()
	s := streamServer17175(t, streamAuthzConfig17175)
	return s.activeConfig()
}

// populatedStreamRequest17175 returns a fully-populated request for a
// request-independent stream, so the census can prove no gate reads it.
func populatedStreamRequest17175(fullMethod string) any {
	switch fullMethod {
	case pb.BpfrxService_MonitorPacketDrop_FullMethodName:
		return &pb.MonitorPacketDropRequest{SourcePrefix: "10.99.1.0/24", DestinationPrefix: "10.98.0.0/16", Protocol: "tcp", FromZone: "trust", Interface: "ge-0/0/0", SourcePort: 1234, DestinationPort: 443, Count: 7}
	}
	return nil
}

// TestStreamMonitorPacketDropAdmitDeny17175 drives MonitorPacketDrop
// (the needsRequest=false stream) through the real interceptor: a
// class whose bare `monitor security packet-drop` charge is denied
// must be refused, and a class that admits it must stream even with a
// populated filter request and survive ticks. Ticks re-price the
// retained decoded message, which decides identically to the typed
// empty request priced at open (census-enforced). No behavioural
// cell can distinguish retained-message from nil pricing for this
// method — the census proves nil and empty name identical forms, so
// both price identically; the never-nil tick is a code invariant
// (the watcher prices only retainedRequest's non-nil message or the
// open price), guarded structurally by that census.
// TestStreamMonitorPacketDropTickRevocation17175 adds the mid-stream
// revocation arm on the same tick.
func TestStreamMonitorPacketDropAdmitDeny17175(t *testing.T) {
	shortenStreamReauth9051(t)
	const cfgText = `
system {
    host-name authz-17175;
    login {
        class drop-deny {
            permissions view;
            deny-commands "^monitor security packet-drop";
        }
        class drop-allow {
            permissions view;
            allow-commands "^monitor";
        }
        user opsuser {
            class drop-deny;
        }
        user allowuser {
            class drop-allow;
        }
    }
}
`
	populated := &pb.MonitorPacketDropRequest{SourcePrefix: "10.99.1.0/24", Protocol: "tcp", Count: 1}

	// Deny: the bare charge is denied, so open must refuse before the
	// handler is entered, regardless of the populated filters.
	s := streamServer17175(t, cfgText)
	errc, entered, cancel := runStream17175(t, s, uidPingDeny17175,
		fullMethod17175("MonitorPacketDrop"), populated)
	defer cancel()
	select {
	case <-entered:
		t.Fatal("MonitorPacketDrop entered the handler under deny-commands ^monitor security packet-drop")
	case err := <-errc:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("MonitorPacketDrop deny verdict = %v (code %v), want PermissionDenied", err, status.Code(err))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no verdict for denied MonitorPacketDrop")
	}

	// Admit: the allowlist admits ^monitor, so the populated request
	// streams and survives ticks (ticks re-price the retained decoded
	// message, identically to the typed empty request).
	s2 := streamServer17175(t, cfgText)
	errc2, entered2, cancel2 := runStream17175(t, s2, uidDiagAllow17175,
		fullMethod17175("MonitorPacketDrop"), populated)
	defer cancel2()
	select {
	case <-entered2:
	case err := <-errc2:
		t.Fatalf("MonitorPacketDrop was refused under allow-commands ^monitor: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never entered for admitted MonitorPacketDrop")
	}
	select {
	case err := <-errc2:
		t.Fatalf("admitted MonitorPacketDrop terminated on tick: %v", err)
	case <-time.After(3*streamReauthInterval9051 + 100*time.Millisecond):
	}
	cancel2()
	select {
	case <-errc2:
	case <-time.After(5 * time.Second):
		t.Fatal("admitted MonitorPacketDrop did not end on hangup")
	}
}

// TestStreamMonitorPacketDropTickRevocation17175 pins the re-auth
// tick with an observable revocation: an admitted MonitorPacketDrop
// stream whose class is narrowed mid-stream to deny the bare
// `monitor security packet-drop` charge must terminate PermissionDenied
// on a tick that prices the retained decoded message.
func TestStreamMonitorPacketDropTickRevocation17175(t *testing.T) {
	shortenStreamReauth9051(t)
	s := streamServer17175(t, streamAuthzConfig17175)
	// allowuser (diag-allow, allow-commands ^ping|^traceroute|^monitor)
	// admits the bare charge at open and on ticks.
	populated := &pb.MonitorPacketDropRequest{SourcePrefix: "10.99.1.0/24", Protocol: "tcp", Count: 1}
	errc, entered, cancel := runStream17175(t, s, uidDiagAllow17175,
		fullMethod17175("MonitorPacketDrop"), populated)
	defer cancel()
	select {
	case <-entered:
	case err := <-errc:
		t.Fatalf("MonitorPacketDrop refused at open under allow ^monitor: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("handler never entered for admitted MonitorPacketDrop")
	}
	const narrowed = `
system {
    host-name authz-17175;
    login {
        class diag-allow {
            permissions view;
            deny-commands "^monitor security packet-drop";
        }
        user allowuser {
            class diag-allow;
        }
    }
}
`
	store := s.store
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
	case err := <-errc:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("mid-stream drop revocation must end PermissionDenied, got %v (code %v)", err, status.Code(err))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the drop stream outlived the mid-stream edit denying its bare charge (#17175 tick must re-price the typed empty request retained at open)")
	}
}

// TestStreamBufconnArgumentDeny17175 is the acceptance cell over the
// wire: through bufconn, the real generated Ping handler and the real
// interceptor chain, Ping{10.99.1.1} is PermissionDenied under
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

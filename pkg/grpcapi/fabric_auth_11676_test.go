package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const fabricAuth11676RolloutGrace = 5 * time.Minute

func fabricAuth11676ReadOnlyCall(s *Server) (*unaryCallProbe, error) {
	method := pb.BpfrxService_GetSessions_FullMethodName
	info := &grpc.UnaryServerInfo{FullMethod: method}
	probe := &unaryCallProbe{}
	_, err := s.fabricAuthUnaryInterceptor(context.Background(), &pb.GetSessionsRequest{}, info,
		func(ctx context.Context, req interface{}) (interface{}, error) {
			return s.fabricAllowlistUnaryInterceptor(ctx, req, info, probe.handler)
		})
	return probe, err
}

// A keyed node with a never-armed peer may admit read-only tokenless RPCs only
// during the bounded rolling-upgrade window. At its exact expiry, the auth
// interceptor must deny the call before the fabric allowlist reaches the
// handler. Before #11676 this fixture stays accepted indefinitely.
func TestFabricAuth11676_ReadOnlyRolloutGraceExpires(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	s := keyedServer(fabricTestKey)
	s.fabricAuthNowFn = func() time.Time { return now }

	probe, err := fabricAuth11676ReadOnlyCall(s)
	if err != nil || !probe.called {
		t.Fatalf("unarmed tokenless read RPC during rollout grace: called=%t err=%v", probe.called, err)
	}

	now = now.Add(fabricAuth11676RolloutGrace - time.Nanosecond)
	probe, err = fabricAuth11676ReadOnlyCall(s)
	if err != nil || !probe.called {
		t.Fatalf("read-only call just before grace expiry: called=%t err=%v", probe.called, err)
	}

	now = now.Add(time.Nanosecond)
	probe, err = fabricAuth11676ReadOnlyCall(s)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tokenless read-only call at grace expiry: err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
	if probe.called {
		t.Fatal("tokenless read-only call after grace expiry reached the handler")
	}
}

func TestFabricAuth11676_DelayedFirstReadUsesKeyConfigTime(t *testing.T) {
	manager := cluster.NewManager(0, 1)
	manager.UpdateConfig(&config.ClusterConfig{ControlLinkAuthKey: config.Secret(fabricTestKey)})
	configuredAt := manager.ControlLinkAuthKeyConfiguredAt()
	if configuredAt.IsZero() {
		t.Fatal("keyed cluster config did not publish its configuration time")
	}

	now := configuredAt.Add(fabricAuth11676RolloutGrace + time.Second)
	s := &Server{
		cluster:         manager,
		fabricAuthNowFn: func() time.Time { return now },
	}
	probe, err := fabricAuth11676ReadOnlyCall(s)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("first tokenless read after the configured grace: err=%v (%s), want Unauthenticated",
			err, status.Code(err))
	}
	if probe.called {
		t.Fatal("delayed first tokenless read reached the handler after key-configured grace expired")
	}
}

func TestFabricAuth11676_StreamReadOnlyRolloutGraceExpires(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	s := keyedServer(fabricTestKey)
	s.fabricAuthNowFn = func() time.Time { return now }
	info := &grpc.StreamServerInfo{FullMethod: pb.BpfrxService_MonitorInterface_FullMethodName}
	handlerCalled := false
	handler := func(interface{}, grpc.ServerStream) error {
		handlerCalled = true
		return nil
	}

	err := s.fabricAuthStreamInterceptor(nil, fakeServerStream{ctx: context.Background()}, info, handler)
	if err != nil || !handlerCalled {
		t.Fatalf("unarmed tokenless stream during rollout grace: called=%t err=%v", handlerCalled, err)
	}

	now = now.Add(fabricAuth11676RolloutGrace)
	handlerCalled = false
	err = s.fabricAuthStreamInterceptor(nil, fakeServerStream{ctx: context.Background()}, info, handler)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("tokenless stream at grace expiry: err=%v (%s), want Unauthenticated", err, status.Code(err))
	}
	if handlerCalled {
		t.Fatal("tokenless stream after grace expiry reached the handler")
	}
}

// The unarmed condition is an operator-visible system alarm while the key is
// configured and neither auth channel has armed. It escalates after the grace
// expires and clears as soon as the peer authenticates.
func TestShowSystemAlarmsReportsUnarmedFabricAuth11676(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	s := &Server{
		store:           newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		fabricAuthKeyFn: func() []byte { return []byte(fabricTestKey) },
		fabricAuthNowFn: func() time.Time { return now },
	}

	var buf strings.Builder
	s.showAlarms(&buf)
	if out := buf.String(); !strings.Contains(out, "WARNING: fabric authentication is unarmed") ||
		!strings.Contains(out, "rollout grace") {
		t.Fatalf("show system alarms omitted the unarmed fabric-auth status during grace:\n%s", out)
	}

	now = now.Add(fabricAuth11676RolloutGrace)
	buf.Reset()
	s.showAlarms(&buf)
	if out := buf.String(); !strings.Contains(out, "CRITICAL: fabric authentication remains unarmed") ||
		!strings.Contains(out, "grace expired") {
		t.Fatalf("show system alarms omitted the expired unarmed fabric-auth alarm:\n%s", out)
	}

	s.fabricPeerAuthSeen.Store(true)
	buf.Reset()
	s.showAlarms(&buf)
	if strings.Contains(buf.String(), "fabric authentication") {
		t.Fatalf("fabric-auth alarm remained active after fabric authentication:\n%s", buf.String())
	}

	s.fabricPeerAuthSeen.Store(false)
	s.heartbeatAuthSeenFn = func() bool { return true }
	buf.Reset()
	s.showAlarms(&buf)
	if strings.Contains(buf.String(), "fabric authentication") {
		t.Fatalf("fabric-auth alarm remained active after authenticated heartbeat:\n%s", buf.String())
	}
}

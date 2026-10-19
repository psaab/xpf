package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// #15077: GetStatus and GetConfigModeStatus were charged to the canonical
// command `show version`, so a class whose login regexes deny `show
// version` (or an allow-commands list that names anything else) was
// refused the cli's own session plumbing: cmd/cli calls GetStatus before
// EVERY dispatched command (its reachability probe, cmd/cli/main.go) and
// GetConfigModeStatus at every config-mode prompt. Every member of such
// a class was locked out of SSH management with a misleading "cannot
// reach xpfd", while `show version` itself — ShowText{topic:version} —
// stayed denied. The probes return liveness facts (uptime, cluster role,
// dirty flag), not the version banner, so they are plumbing, not a
// command: exempt from the operational regex gate, governed by the
// coarse PermView price alone. These cells drive the real
// authorizeRPCContext so a fix that only patched the unit gate would
// still fail here.
//
// RED on pre-fix: GetStatus/GetConfigModeStatus denied under the version
// deny (charged to "show version").

const versionDenyConfig15077 = `
system {
    host-name authz-15077;
    login {
        class ops {
            permissions all;
            deny-commands "^show version$";
        }
        class allowlist {
            permissions all;
            allow-commands "^show interfaces$";
        }
        user opsuser {
            class ops;
        }
        user allowuser {
            class allowlist;
        }
    }
}
`

const passwd15077 = `root:x:0:0:root:/root:/bin/bash
opsuser:x:4242:4242::/home/opsuser:/bin/bash
allowuser:x:4246:4246::/home/allowuser:/bin/bash
adminuser:x:4244:4244::/home/adminuser:/bin/bash
`

const (
	uidOps15077       = 4242
	uidAllowlist15077 = 4246
)

func probeServer15077(t *testing.T) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(passwd15077), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(path))
	return NewServer("127.0.0.1:0", Config{Store: authzStore5278(t, versionDenyConfig15077)})
}

func authorize15077(s *Server, ctx context.Context, method string, req any) error {
	return s.authorizeRPC(ctx, "/"+pb.BpfrxService_ServiceDesc.ServiceName+"/"+method, req)
}

func TestPlumbingProbesSurviveVersionDeny15077(t *testing.T) {
	s := probeServer15077(t)
	ctx := ctxWithPeerUID(uidOps15077)

	// The defective cells: both probes must be admitted.
	if err := authorize15077(s, ctx, "GetStatus", &pb.GetStatusRequest{}); err != nil {
		t.Errorf("GetStatus denied for a show-version-denying class: %v — the cli probes it before every command, so this locks the class out of SSH management (#15077)", err)
	}
	if err := authorize15077(s, ctx, "GetConfigModeStatus", &pb.GetConfigModeStatusRequest{}); err != nil {
		t.Errorf("GetConfigModeStatus denied for a show-version-denying class: %v — the cli polls it at every config-mode prompt (#15077)", err)
	}

	// `show version` itself stays denied, through the path that
	// actually serves it.
	if err := authorize15077(s, ctx, "ShowText", &pb.ShowTextRequest{Topic: "version"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ShowText{version} (the real `show version`) must stay denied; got %v", err)
	}

	// Neighbouring legitimate operations stay admitted.
	if err := authorize15077(s, ctx, "GetInterfaces", &pb.GetInterfacesRequest{}); err != nil {
		t.Errorf("GetInterfaces (show interfaces) must stay admitted under a version-only deny: %v", err)
	}
	if err := authorize15077(s, ctx, "GetZones", &pb.GetZonesRequest{}); err != nil {
		t.Errorf("GetZones must stay admitted under a version-only deny: %v", err)
	}
}

func TestPlumbingProbesSurviveAllowlist15077(t *testing.T) {
	s := probeServer15077(t)
	ctx := ctxWithPeerUID(uidAllowlist15077)

	if err := authorize15077(s, ctx, "GetStatus", &pb.GetStatusRequest{}); err != nil {
		t.Errorf("GetStatus denied for an allowlist class: %v — an allow-list that permits no `show version` still must not lock the cli probe out (#15077)", err)
	}
	if err := authorize15077(s, ctx, "GetConfigModeStatus", &pb.GetConfigModeStatusRequest{}); err != nil {
		t.Errorf("GetConfigModeStatus denied for an allowlist class: %v (#15077)", err)
	}
	// The allow-listed command runs; the unlisted ones do not.
	if err := authorize15077(s, ctx, "GetInterfaces", &pb.GetInterfacesRequest{}); err != nil {
		t.Errorf("GetInterfaces is the allow-listed command and must be admitted: %v", err)
	}
	if err := authorize15077(s, ctx, "ShowText", &pb.ShowTextRequest{Topic: "version"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("ShowText{version} is outside the allow-list and must stay denied; got %v", err)
	}
	if err := authorize15077(s, ctx, "GetZones", &pb.GetZonesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("GetZones is outside the allow-list and must stay denied; got %v", err)
	}
}

// The plumbing probes are NOT free for a class without the coarse
// permission: `unauthorized` (and any view-less class) still loses them
// at the PermView check, so the exemption narrows only the regex gate.
func TestPlumbingProbesStillNeedView15077(t *testing.T) {
	s := probeServer15077(t)
	// uid 4245 (stranger) is not a login user at all.
	if err := authorize15077(s, ctxWithPeerUID(4245), "GetStatus", &pb.GetStatusRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("GetStatus for a non-login uid must stay PermissionDenied (coarse gate), got %v", err)
	}
}

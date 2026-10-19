package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #14952: Complete with ConfigMode=true bypassed PermConfig and the
// operational deny-commands / allow-commands rules.
//
// Before the fix, Complete was priced flat at PermView and listed in
// configModeMethods9633, so authorizeRPCCommand exempted it from the
// operational regexes entirely. A PermView principal whose class denies
// `show configuration` (deny-commands "^show configuration") — a class
// ShowConfig correctly refuses — could send Complete{ConfigMode:true,
// Line:"set security zones security-zone "} and enumerate the active
// configuration one Tab press at a time. #14144/#14708 filtered the live
// values by *-configuration, but the RPC was still admitted at the view
// price with no operational verdict at all: an allow-commands allowlist
// that permits no config-mode completion still received schema
// candidates, and the mode bit cost nothing.
//
// The fix prices the ConfigMode arm at PermConfig (methodPermission,
// mirroring #9324's candidate arm) and adjudicates the typed line under
// the operational regexes (authorizeCompleteRPCCommand). Operational
// completion stays PermView with the #14144/#14708 data-source filters.

const complete14952Config = `
system {
    login {
        class limited-view {
            permissions [ view ];
            deny-configuration "^security";
        }
        class limited-op {
            permissions [ view configure ];
            deny-commands "^show configuration";
        }
        class view-allowlist {
            permissions [ view ];
            allow-commands "^show version";
        }
        class open-view {
            permissions [ view ];
        }
        class configurator {
            permissions [ view configure ];
        }
        user limiteduser { class limited-view; }
        user limitedop { class limited-op; }
        user allowlistuser { class view-allowlist; }
        user openuser { class open-view; }
        user configuser { class configurator; }
    }
}
security {
    zones {
        security-zone trust {
            description "SECRET-TRUST-DESC-14952";
            host-inbound-traffic { system-services [ ssh ]; }
            interfaces [ ge-0/0/0.0 ];
        }
        security-zone untrust {
            description "SECRET-UNTRUST-DESC-14952";
            host-inbound-traffic { system-services [ https ]; }
            interfaces [ ge-0/0/1.0 ];
        }
    }
    address-book {
        global {
            address web-net 203.0.113.0/24;
            address db-net 198.51.100.0/24;
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy allow-web {
                description "SECRET-POLICY-DESC-14952";
                match { source-address web-net; destination-address db-net; application junos-http; }
                then { permit; }
            }
        }
    }
}
interfaces {
    ge-0/0/0 { unit 0 { description "SECRET-IFACE-DESC-14952"; family inet { address 10.0.0.1/24; } } }
    ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } }
}
`

const complete14952Passwd = `root:x:0:0:root:/root:/bin/bash
limiteduser:x:4250:4250::/home/limiteduser:/bin/bash
limitedop:x:4251:4251::/home/limitedop:/bin/bash
allowlistuser:x:4252:4252::/home/allowlistuser:/bin/bash
openuser:x:4253:4253::/home/openuser:/bin/bash
configuser:x:4254:4254::/home/configuser:/bin/bash
`

const (
	uidLimitedView14952  = 4250
	uidLimitedOp14952    = 4251
	uidAllowlist14952    = 4252
	uidOpenView14952     = 4253
	uidConfigurator14952 = 4254
)

func complete14952Server(t *testing.T) *Server {
	t.Helper()
	passwdPath := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(passwdPath, []byte(complete14952Passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authz.SetPasswdPathForTest(passwdPath))

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(complete14952Config); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	return &Server{store: store}
}

func complete14952Method() string { return "/" + serviceName + "/Complete" }

func wantCompleteDenied14952(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s was ALLOWED, want PermissionDenied (#14952)", what)
		return
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("%s denial code = %s, want PermissionDenied (err=%v)", what, status.Code(err), err)
	}
}

// TestCompleteConfigModeCostsConfigure14952 is the price arm: a decoded
// ConfigMode=true request costs PermConfig, ConfigMode=false (and an
// unreadable request) stays at the PermView floor.
//
// RED-on-revert: without the completeMethodName arm, the first cell
// returns PermView.
func TestCompleteConfigModeCostsConfigure14952(t *testing.T) {
	full := complete14952Method()
	if perm, mapped := methodPermission(full, &pb.CompleteRequest{Line: "set ", ConfigMode: true}); !mapped || perm != config.PermConfig {
		t.Errorf("Complete{ConfigMode:true} priced %s (mapped=%v), want %s (#14952: config-mode completion enumerates the configuration)",
			permName(perm), mapped, permName(config.PermConfig))
	}
	if perm, mapped := methodPermission(full, &pb.CompleteRequest{Line: "show "}); !mapped || perm != config.PermView {
		t.Errorf("Complete{ConfigMode:false} priced %s (mapped=%v), want %s (operational completion stays view-tier)",
			permName(perm), mapped, permName(config.PermView))
	}
	if perm, mapped := methodPermission(full, nil); !mapped || perm != config.PermView {
		t.Errorf("Complete with no readable request priced %s (mapped=%v), want the %s floor",
			permName(perm), mapped, permName(config.PermView))
	}
}

// TestCompleteConfigModeDeniedForViewOnly14952 is the end-to-end arm
// through the real interceptor (authorizeRPC): the claimed principal —
// PermView, denied `show configuration` — cannot buy config-mode
// completion by flipping ConfigMode, while operational completion and
// a configure-holding class keep working.
//
// RED-on-revert: pre-fix every ConfigMode:true cell below is admitted
// (Complete priced PermView, exempt from the operational gate), so the
// limited-view / limited-op / allowlist denials fail.
func TestCompleteConfigModeDeniedForViewOnly14952(t *testing.T) {
	s := complete14952Server(t)
	full := complete14952Method()
	cfgLine := "set security zones security-zone "
	showCfgLine := "show configuration security zones security-zone "

	// The claimed principal: view-only, deny-configuration ^security.
	// Config-mode completion must be refused at the configure price —
	// the same principal is refused `show configuration` by ShowConfig.
	wantCompleteDenied14952(t, "limited-view Complete{ConfigMode:true, set security…}",
		s.authorizeRPC(ctxWithPeerUID(uidLimitedView14952), full,
			&pb.CompleteRequest{Line: cfgLine, Pos: int32(len(cfgLine)), ConfigMode: true}))
	// Even a config-mode `show configuration` line is a config-mode read.
	wantCompleteDenied14952(t, "limited-view Complete{ConfigMode:true, show configuration…}",
		s.authorizeRPC(ctxWithPeerUID(uidLimitedView14952), full,
			&pb.CompleteRequest{Line: showCfgLine, Pos: int32(len(showCfgLine)), ConfigMode: true}))
	// Operational completion of an allowed subtree stays admitted for the
	// same principal (the #14144 data-source filter, not the price, is
	// what conceals the denied subtree there).
	if err := s.authorizeRPC(ctxWithPeerUID(uidLimitedView14952), full,
		&pb.CompleteRequest{Line: "show interfaces ", Pos: int32(len("show interfaces "))}); err != nil {
		t.Errorf("limited-view operational Complete{show interfaces} must stay admitted: %v", err)
	}

	// deny-commands "^show configuration": the operational gate now
	// adjudicates the typed line in BOTH modes. Pre-fix the ConfigMode
	// arm was exempt and the operational arm's live-value filter let the
	// RPC itself through.
	wantCompleteDenied14952(t, "limited-op Complete{ConfigMode:true, show configuration…}",
		s.authorizeRPC(ctxWithPeerUID(uidLimitedOp14952), full,
			&pb.CompleteRequest{Line: showCfgLine, Pos: int32(len(showCfgLine)), ConfigMode: true}))
	wantCompleteDenied14952(t, "limited-op Complete{ConfigMode:false, show configuration…}",
		s.authorizeRPC(ctxWithPeerUID(uidLimitedOp14952), full,
			&pb.CompleteRequest{Line: showCfgLine, Pos: int32(len(showCfgLine))}))
	// Config-mode `run` embeds the same operational line.
	runLine := "run show configuration security "
	wantCompleteDenied14952(t, "limited-op Complete{ConfigMode:true, run show configuration…}",
		s.authorizeRPC(ctxWithPeerUID(uidLimitedOp14952), full,
			&pb.CompleteRequest{Line: runLine, Pos: int32(len(runLine)), ConfigMode: true}))
	// A denied ancestor command fires on its sub-paths too.
	wantCompleteDenied14952(t, "limited-op Complete{show configuration via typed prefix}",
		s.authorizeRPC(ctxWithPeerUID(uidLimitedOp14952), full,
			&pb.CompleteRequest{Line: "show configuration ", Pos: int32(len("show configuration "))}))

	// allow-commands allowlist ("^show version" only): neither mode's
	// configuration completion is on the list, so both deny; the one
	// listed command still completes.
	wantCompleteDenied14952(t, "allowlist Complete{ConfigMode:true, set …}",
		s.authorizeRPC(ctxWithPeerUID(uidAllowlist14952), full,
			&pb.CompleteRequest{Line: cfgLine, Pos: int32(len(cfgLine)), ConfigMode: true}))
	wantCompleteDenied14952(t, "allowlist Complete{ConfigMode:false, show configuration…}",
		s.authorizeRPC(ctxWithPeerUID(uidAllowlist14952), full,
			&pb.CompleteRequest{Line: showCfgLine, Pos: int32(len(showCfgLine))}))
	if err := s.authorizeRPC(ctxWithPeerUID(uidAllowlist14952), full,
		&pb.CompleteRequest{Line: "show version ", Pos: int32(len("show version "))}); err != nil {
		t.Errorf("allowlist Complete{show version} is the listed command and must stay admitted: %v", err)
	}

	// Controls: an unrestricted view class keeps OPERATIONAL completion,
	// and a configure-holding class keeps CONFIG-MODE completion. Without
	// these arms a gate that denied every Complete would pass.
	if err := s.authorizeRPC(ctxWithPeerUID(uidOpenView14952), full,
		&pb.CompleteRequest{Line: "show ", Pos: int32(len("show "))}); err != nil {
		t.Errorf("open-view operational Complete must stay admitted: %v", err)
	}
	if err := s.authorizeRPC(ctxWithPeerUID(uidConfigurator14952), full,
		&pb.CompleteRequest{Line: cfgLine, Pos: int32(len(cfgLine)), ConfigMode: true}); err != nil {
		t.Errorf("configurator Complete{ConfigMode:true} must stay admitted (it holds configure): %v", err)
	}
	// limited-op holds configure, so its config-mode SET completion is
	// admitted by the price; only its `show configuration` lines deny.
	if err := s.authorizeRPC(ctxWithPeerUID(uidLimitedOp14952), full,
		&pb.CompleteRequest{Line: cfgLine, Pos: int32(len(cfgLine)), ConfigMode: true}); err != nil {
		t.Errorf("limited-op Complete{ConfigMode:true, set …} must stay admitted (deny is on show configuration only): %v", err)
	}
}

// TestCompleteConfigModeHandlerStillFilters14952 pins the handler-level
// contract that remains after the price change: a configure-holding
// principal with deny-configuration still gets no live values for the
// denied subtree through the real Complete handler (#14144 behaviour,
// exercised here in ConfigMode for the #14952 principal shapes).
func TestCompleteConfigModeHandlerStillFilters14952(t *testing.T) {
	s := complete14952Server(t)

	// Control through the handler: configurator receives live zone names.
	ctx := ctxWithPeerUID(uidConfigurator14952)
	// authorizeRPCContext stamps the admitted principal the handler reads.
	actx, err := s.authorizeRPCContext(ctx, complete14952Method(),
		&pb.CompleteRequest{Line: "set security zones security-zone ", ConfigMode: true})
	if err != nil {
		t.Fatalf("configurator authorization: %v", err)
	}
	resp, err := s.Complete(actx, &pb.CompleteRequest{
		Line: "set security zones security-zone ", Pos: int32(len("set security zones security-zone ")), ConfigMode: true})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	found := false
	for _, c := range resp.Candidates {
		if c == "trust" {
			found = true
		}
	}
	if !found {
		t.Fatalf("control: configurator missing trust zone, test would be vacuous: %v", resp.Candidates)
	}

	// The view-only principal never reaches the handler post-fix (the
	// interceptor denies above), but a direct handler call with its
	// stamped principal must still conceal the denied subtree — the
	// handler posture keeps in-process calls safe (#14144).
	limitedCtx := ctxWithAuthorizedPrincipal(ctxWithPeerUID(uidLimitedView14952),
		authz.Principal{Source: authz.SourcePeerUID, UID: uidLimitedView14952, Class: "limited-view"})
	resp, err = s.Complete(limitedCtx, &pb.CompleteRequest{
		Line: "set security zones security-zone ", Pos: int32(len("set security zones security-zone ")), ConfigMode: true})
	if err != nil {
		t.Fatalf("Complete direct: %v", err)
	}
	joined := strings.Join(resp.Candidates, " ") + " " + strings.Join(resp.Descriptions, " ")
	for _, secret := range []string{"SECRET-TRUST-DESC-14952", "SECRET-UNTRUST-DESC-14952", "web-net", "trust", "untrust"} {
		if strings.Contains(joined, secret) {
			t.Errorf("direct limited-view Complete leaked %q in %v / %v", secret, resp.Candidates, resp.Descriptions)
		}
	}
}

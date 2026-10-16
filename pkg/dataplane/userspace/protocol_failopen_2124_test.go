package userspace

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// #2124 — a policy application term whose named protocol the Rust matcher could
// not parse (sctp/esp/ah/vrrp/igmp/pim/egp) silently failed OPEN to match-any.
// These tests pin the Go-side defenses: the capability gate fails closed on an
// unrepresentable protocol/port, canonicalizes the supported named protocols to
// their numeric wire form, and emits the __unsupported__ fail-closed sentinel
// (never nil) on a failed expansion so the published snapshot cannot fail open.

func twoZonePolicyCfg(app *config.Application, appName string) *config.Config {
	cfg := &config.Config{}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Applications.Applications = map[string]*config.Application{app.Name: app}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan": {Name: "lan", Interfaces: []string{"reth1"}},
		"wan": {Name: "wan", Interfaces: []string{"reth0.80"}},
	}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "lan",
		ToZone:   "wan",
		Policies: []*config.Policy{{
			Name: "p",
			Match: config.PolicyMatch{
				SourceAddresses:      []string{"any"},
				DestinationAddresses: []string{"any"},
				Applications:         []string{appName},
			},
			Action: config.PolicyPermit,
		}},
	}}
	return cfg
}

// colorAwarePolicerCfg returns a config whose ONLY unsupported feature is a
// color-AWARE three-color policer — a class-(ii) genuine semantic gap with no
// fail-closed snapshot representation. deriveUserspaceCapabilities sets
// ForwardingSupported=false (the legitimate disarm), and crucially leaves
// PolicyContentRejected empty (it is NOT the #3261 keep-armed class).
func colorAwarePolicerCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Firewall.ThreeColorPolicers = map[string]*config.ThreeColorPolicerConfig{
		"tcp-3color": {
			Name:       "tcp-3color",
			ColorBlind: false, // color-aware: unsupported (class ii)
			ThenAction: "discard",
			CIR:        1_000_000,
			CBS:        100_000,
		},
	}
	return cfg
}

func TestUserspaceGateAcceptsAndCanonicalizesNamedProtocol(t *testing.T) {
	// esp must be supported (so a legit esp-only policy works) AND canonicalized
	// to its numeric wire form so an older helper that lacks the named-protocol
	// arms still parses it.
	cfg := twoZonePolicyCfg(&config.Application{Name: "esp-only", Protocol: "esp"}, "esp-only")
	terms, ok := expandUserspacePolicyApplications(cfg, []string{"esp-only"})
	if !ok {
		t.Fatal("expandUserspacePolicyApplications = ok=false, want true for esp")
	}
	if len(terms) != 1 {
		t.Fatalf("len(terms) = %d, want 1", len(terms))
	}
	if terms[0].Protocol != "50" {
		t.Fatalf("esp canonicalized Protocol = %q, want \"50\"", terms[0].Protocol)
	}
}

func TestUserspaceGateFailsClosedOnUnknownProtocol(t *testing.T) {
	// A user-defined application with a protocol neither the Rust matcher nor
	// the centralized appid table can represent must fail the content gate so
	// buildOneRuleSnapshot emits the __unsupported__ sentinel. Pre-#2124 the
	// expansion returned ok=true (the term-level fail-open).
	cfg := twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird")
	if _, ok := expandUserspacePolicyApplications(cfg, []string{"weird"}); ok {
		t.Fatal("expandUserspacePolicyApplications = ok=true, want false for unknown protocol")
	}
}

func TestUserspaceGateFailsClosedOnMalformedPort(t *testing.T) {
	for _, port := range []string{"99999", "5-1", "0", "abc"} {
		cfg := twoZonePolicyCfg(
			&config.Application{Name: "badport", Protocol: "tcp", DestinationPort: port},
			"badport",
		)
		if _, ok := expandUserspacePolicyApplications(cfg, []string{"badport"}); ok {
			t.Fatalf("expandUserspacePolicyApplications = ok=true for malformed port %q, want false", port)
		}
	}
}

func TestUserspaceGateAcceptsValidPortsAndAliases(t *testing.T) {
	for _, port := range []string{"", "443", "8080-8090", "https", "dns"} {
		cfg := twoZonePolicyCfg(
			&config.Application{Name: "okport", Protocol: "tcp", DestinationPort: port},
			"okport",
		)
		if _, ok := expandUserspacePolicyApplications(cfg, []string{"okport"}); !ok {
			t.Fatalf("expandUserspacePolicyApplications = ok=false for valid port %q, want true", port)
		}
	}
}

func TestBuildOneRuleSnapshotEmitsUnsupportedSentinel(t *testing.T) {
	// When expansion fails, the published rule must carry the __unsupported__
	// sentinel term (so Rust fails the whole snapshot closed), NEVER nil (which
	// Rust would read as genuine match-any — the publish-window fail-open).
	cfg := twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird")
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	if len(snap.Policies) != 1 {
		t.Fatalf("len(Policies) = %d, want 1", len(snap.Policies))
	}
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 1 {
		t.Fatalf("ApplicationTerms = %+v, want exactly the sentinel term", terms)
	}
	if terms[0].Protocol != unsupportedApplicationSentinel {
		t.Fatalf("sentinel Protocol = %q, want %q", terms[0].Protocol, unsupportedApplicationSentinel)
	}
}

func TestBuildOneRuleSnapshotNoSentinelForSupportedApp(t *testing.T) {
	// A supported named protocol must NOT trigger the sentinel; the rule carries
	// a normal canonicalized term.
	cfg := twoZonePolicyCfg(&config.Application{Name: "esp-only", Protocol: "esp"}, "esp-only")
	snap := mustBuildSnapshot(t, cfg, config.UserspaceConfig{}, 1, 0)
	terms := snap.Policies[0].ApplicationTerms
	if len(terms) != 1 || terms[0].Protocol != "50" {
		t.Fatalf("ApplicationTerms = %+v, want one esp term canonicalized to \"50\"", terms)
	}
}

func TestUserspacePortSpecRepresentableMirrorsRust(t *testing.T) {
	ok := []string{"", "1", "443", "65535", "80-90", "0-10", "https", "ftp-data", "syslog"}
	for _, s := range ok {
		if !userspacePortSpecRepresentable(s) {
			t.Errorf("userspacePortSpecRepresentable(%q) = false, want true", s)
		}
	}
	// Aliases are CASE-SENSITIVE to mirror Rust parse_port_spec exactly: the
	// uppercase forms are NOT recognized by Rust (it would drop the term), so
	// the gate must reject them here too rather than accept-then-mismatch.
	bad := []string{
		"0", "65536", "99999", "5-1", "abc", "80-", "-80", "80-abc",
		"HTTP", "Https", "DNS",
	}
	for _, s := range bad {
		if userspacePortSpecRepresentable(s) {
			t.Errorf("userspacePortSpecRepresentable(%q) = true, want false", s)
		}
	}
}

// recordingControlServer accepts control requests, records them, and replies OK
// with an enabled+forwarding-armed status so applyHelperStatusLocked succeeds.
func recordingControlServer(t *testing.T) (string, chan ControlRequest) {
	t.Helper()
	// Use a short os.MkdirTemp path (NOT t.TempDir(), whose long subtest-named
	// path can exceed the ~108-char unix sun_path limit -> bind: invalid arg).
	dir, err := os.MkdirTemp("", "xpf2124")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	reqCh := make(chan ControlRequest, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			var req ControlRequest
			if err := json.NewDecoder(conn).Decode(&req); err == nil {
				reqCh <- req
				_ = json.NewEncoder(conn).Encode(ControlResponse{
					OK:     true,
					Status: &ProcessStatus{Enabled: true, ForwardingArmed: false},
				})
			}
			conn.Close()
		}
	}()
	return sock, reqCh
}

// snapForDisarm builds a publishable snapshot (with feed-aware Capabilities)
// for the disarm-gate tests, mirroring the real publish path which passes the
// built snapshot — not the raw cfg — to disarmBeforeUnsupportedPublishLocked.
func snapForDisarm(t *testing.T, cfg *config.Config) *ConfigSnapshot {
	t.Helper()
	snap, err := buildSnapshot(cfg, config.UserspaceConfig{}, 1, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	return snap
}

func TestDisarmBeforeUnsupportedPublishLocked(t *testing.T) {
	t.Run("genuinely-unsupported semantic disarms before publish", func(t *testing.T) {
		sock, reqCh := recordingControlServer(t)
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = sock
		m.lastStatus.ForwardingArmed = true
		m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion // current helper
		// A class-(ii) genuine semantic gap (a color-AWARE three-color policer)
		// has no fail-closed snapshot representation -> ForwardingSupported=false
		// -> the legitimate disarm still fires regardless of helper version.
		snap := snapForDisarm(t, colorAwarePolicerCfg())
		// The disarm CONTROL REQUEST is the security-critical behavior under
		// test. applyHelperStatusLocked touches a BPF map that is absent in a
		// unit test ("userspace_ctrl map not loaded"), so the function may
		// return that local-bookkeeping error AFTER the wire disarm succeeds;
		// that env artifact must not mask the assertion that the disarm was
		// actually issued.
		_ = m.disarmBeforeUnsupportedPublishLocked(snap)
		select {
		case req := <-reqCh:
			if req.Type != "set_forwarding_state" || req.Forwarding == nil || req.Forwarding.Armed {
				t.Fatalf("got request %+v, want set_forwarding_state{Armed:false}", req)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no disarm request sent for genuinely-unsupported semantic")
		}
	})

	t.Run("unrepresentable content does NOT disarm a current helper (#3261)", func(t *testing.T) {
		// #3261: class-(i) unrepresentable policy CONTENT must NOT disarm a
		// current helper. The published snapshot carries the __unsupported__
		// sentinel and the helper integrity preflight rejects it while staying
		// armed (previous-good retained). Disarming here is the kernel
		// fail-OPEN this fixes. Revert the keep-armed change and this RED-flips.
		sock, reqCh := recordingControlServer(t)
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = sock
		m.lastStatus.ForwardingArmed = true
		m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion // current helper
		snap := snapForDisarm(t, twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird"))
		if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
		}
		select {
		case req := <-reqCh:
			t.Fatalf("unexpected disarm for unrepresentable content on current helper: %+v", req)
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("unrepresentable content DOES disarm a pre-preflight helper", func(t *testing.T) {
		// The one exception: an OLDER local helper (snapshot protocol version <
		// current) cannot be trusted to reject the sentinel, so the narrow
		// version-keyed disarm still fires for class-(i) content.
		sock, reqCh := recordingControlServer(t)
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = sock
		m.lastStatus.ForwardingArmed = true
		m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion - 1 // old helper
		snap := snapForDisarm(t, twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird"))
		_ = m.disarmBeforeUnsupportedPublishLocked(snap)
		select {
		case req := <-reqCh:
			if req.Type != "set_forwarding_state" || req.Forwarding == nil || req.Forwarding.Armed {
				t.Fatalf("got request %+v, want set_forwarding_state{Armed:false}", req)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("no disarm request sent for unrepresentable content on pre-preflight helper")
		}
	})

	t.Run("supported config does not disarm", func(t *testing.T) {
		sock, reqCh := recordingControlServer(t)
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = sock
		m.lastStatus.ForwardingArmed = true
		m.lastStatus.ConfigSnapshotProtocolVersion = ProtocolVersion
		snap := snapForDisarm(t, twoZonePolicyCfg(&config.Application{Name: "esp-only", Protocol: "esp"}, "esp-only"))
		if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
		}
		select {
		case req := <-reqCh:
			t.Fatalf("unexpected control request for supported config: %+v", req)
		case <-time.After(200 * time.Millisecond):
		}
	})

	t.Run("no helper is a no-op", func(t *testing.T) {
		m := New()
		m.lastStatus.ForwardingArmed = true
		snap := snapForDisarm(t, twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird"))
		if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked with no helper: %v", err)
		}
	})

	t.Run("already disarmed is a no-op", func(t *testing.T) {
		sock, reqCh := recordingControlServer(t)
		m := New()
		m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
		m.cfg.ControlSocket = sock
		m.lastStatus.ForwardingArmed = false
		snap := snapForDisarm(t, twoZonePolicyCfg(&config.Application{Name: "weird", Protocol: "definitely-not-a-proto"}, "weird"))
		if err := m.disarmBeforeUnsupportedPublishLocked(snap); err != nil {
			t.Fatalf("disarmBeforeUnsupportedPublishLocked: %v", err)
		}
		select {
		case req := <-reqCh:
			t.Fatalf("unexpected control request when already disarmed: %+v", req)
		case <-time.After(200 * time.Millisecond):
		}
	})
}

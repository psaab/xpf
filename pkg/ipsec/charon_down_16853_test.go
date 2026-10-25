package ipsec

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16853: a total --load-all failure while charon is down (vici
// unreachable) is not "charon rejected the candidate and still runs
// the prior generation" (#10712). Charon runs nothing, so the
// candidate must stay on disk for charon's next start, and the
// clear's removed file must stay removed — otherwise the next
// charon start resurrects a deleted/rotated VPN.

type charonDown16853 struct {
	down bool
}

func (c *charonDown16853) run(args ...string) ([]byte, error) {
	if c.down {
		return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed: No such file or directory")
	}
	return nil, nil
}

// del-down (acceptance): deleting the last VPN while charon is down
// leaves no xpf.conf, so the peer cannot re-establish after charon
// restarts. Pre-fix the prior file is restored -> RED.
func TestClearWhileCharonDownKeepsFileRemoved16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	if _, err := os.Stat(m.configPath); err != nil {
		t.Fatalf("FIXTURE: config must exist after initial apply: %v", err)
	}
	ch.down = true
	err := m.Clear()
	if err == nil {
		t.Fatal("Clear while charon is down must return the reload error")
	}
	if _, statErr := os.Stat(m.configPath); !os.IsNotExist(statErr) {
		t.Fatalf("del-down: xpf.conf must stay removed while charon is down, stat err=%v", statErr)
	}
	if m.tracks("vpn1") {
		t.Fatal("del-down: prevConnNames must advance to the empty set")
	}
}

// rot-down (acceptance): rotating a PSK while charon is down keeps
// the candidate (new key) on disk, so the old key cannot establish
// after charon restarts. Pre-fix the prior file is restored -> RED.
func TestApplyWhileCharonDownKeepsCandidate16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	rotated := vpnCfg("vpn1")
	rotated.VPNs["vpn1"].PSK = config.NewSecret("secret-rotated")
	ch.down = true
	if err := m.Apply(rotated); err == nil {
		t.Fatal("Apply while charon is down must return the reload error")
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("rot-down: candidate must stay on disk: %v", err)
	}
	if string(got) == string(prior) {
		t.Fatal("rot-down: prior file was restored; charon restart would load the old PSK")
	}
	if !strings.Contains(string(got), "secret-rotated") && !strings.Contains(string(got), "vpn1") {
		t.Fatalf("rot-down: candidate file unexpected:\n%s", got)
	}
	if !m.tracks("vpn1") {
		t.Fatal("rot-down: candidate set must be promoted")
	}
}

// del-down via Apply(nil) (the commit path shape).
func TestApplyNilWhileCharonDownKeepsFileRemoved16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	ch.down = true
	if err := m.Apply(nil); err == nil {
		t.Fatal("Apply(nil) while charon is down must return the reload error")
	}
	if _, statErr := os.Stat(m.configPath); !os.IsNotExist(statErr) {
		t.Fatalf("del-down: xpf.conf must stay removed, stat err=%v", statErr)
	}
}

// Control (unchanged): charon UP but rejecting the candidate keeps
// the #10712 restore. The probe (--list-conns) succeeds here, so the
// unreachable branch must not fire.
func TestRejectedWhileCharonUpStillRestoresPrior16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("vpn-old")); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	rejectErr := errors.New("candidate rejected")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return []byte("unable to load candidate"), rejectErr
		}
		// --list-conns / --list-sas via scSplit fallback: charon answers.
		return []byte("list-conns reply {}\n"), nil
	}
	if err := m.Apply(vpnCfg("vpn-new")); !errors.Is(err, rejectErr) {
		t.Fatalf("Apply error = %v, want reject error", err)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(prior) {
		t.Fatal("charon-up rejection must still restore the prior file (#10712)")
	}
	if m.tracks("vpn-new") {
		t.Fatal("rejected candidate must not be promoted")
	}
	if !m.tracks("vpn-old") {
		t.Fatal("prior set must stay tracked after rejection")
	}
}

// Transient probe success must classify as charon-up: the probe
// answers on a later attempt, so the prior file is restored.
func TestCharonReturningDuringProbeRestoresPrior16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("vpn-old")); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	probes := 0
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "--load-all" {
			return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed")
		}
		if len(args) > 0 && args[0] == "--list-conns" {
			probes++
			if probes >= 2 {
				return []byte("list-conns reply {}\n"), nil
			}
			return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed")
		}
		return nil, nil
	}
	if err := m.Apply(vpnCfg("vpn-new")); err == nil {
		t.Fatal("Apply must return the reload error")
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(prior) {
		t.Fatal("charon answering during the probe window must restore the prior file")
	}
}

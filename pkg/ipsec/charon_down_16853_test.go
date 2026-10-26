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

func poolsForPrior17882(t *testing.T, prior []byte) []byte {
	t.Helper()
	generation, ok := generationFromConfigText17882(prior, true)
	if !ok {
		t.Fatal("FIXTURE: prior config must carry a known generation marker")
	}
	return []byte("get-pools reply {xpf-gen-" + generation + " {base=192.0.2.1 size=1 online=0 offline=0}}\n")
}

func listConnsForRendered17882(t *testing.T, rendered []byte) []byte {
	t.Helper()
	root := parseSwanctlDoc(t, string(rendered))
	connections := root.at(t, "connections")
	var b strings.Builder
	for _, name := range connections.childNames() {
		conn := connections.at(t, name)
		addresses := func(key string) string {
			if values := conn.settings[key]; len(values) != 0 {
				return strings.Join(values, ",")
			}
			return "%any"
		}
		b.WriteString("list-conn event {" + name + " {local_addrs=[" + addresses("local_addrs") +
			"] remote_addrs=[" + addresses("remote_addrs") + "] children {")
		for _, child := range conn.at(t, "children").childNames() {
			b.WriteString(child + " {}")
		}
		b.WriteString("}}}\n")
	}
	b.WriteString("list-conns reply {}\n")
	return []byte(b.String())
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

// Control: when the generation marker proves the old charon still runs the
// prior file, a rejected candidate keeps the #10712 restore.
func TestRejectedWhileCharonUpStillRestoresPrior16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	oldGeneration := strings.Repeat("a", 64)
	newGeneration := strings.Repeat("b", 64)
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.ApplyGeneration(vpnCfg("vpn-old"), oldGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	rejectErr := errors.New("candidate rejected")
	priorMarker := []byte("get-pools reply {xpf-gen-" + oldGeneration + " {base=192.0.2.1 size=1 online=0 offline=0}}\n")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return []byte("unable to load candidate"), rejectErr
			case "--list-pools":
				return priorMarker, nil
			}
		}
		return listConnsForRendered17882(t, prior), nil
	}
	if err := m.ApplyGeneration(vpnCfg("vpn-new"), newGeneration, ApplyHooks{}); !errors.Is(err, rejectErr) {
		t.Fatalf("ApplyGeneration error = %v, want reject error", err)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(prior) {
		t.Fatal("charon reporting the prior generation must restore the prior file (#10712)")
	}
	if m.tracks("vpn-new") {
		t.Fatal("rejected candidate must not be promoted")
	}
	if !m.tracks("vpn-old") {
		t.Fatal("prior set must stay tracked after rejection")
	}
}

// A successful VICI response with malformed connection output cannot prove
// which configuration charon loaded; the candidate must remain on disk.
func TestMalformedListConnsDoesNotProvePriorGeneration17882(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	oldGeneration := strings.Repeat("a", 64)
	newGeneration := strings.Repeat("b", 64)
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.ApplyGeneration(vpnCfg("vpn-old"), oldGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	rejectErr := errors.New("candidate rejected")
	priorMarker := []byte("get-pools reply {xpf-gen-" + oldGeneration + " {base=192.0.2.1 size=1 online=0 offline=0}}\n")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return []byte("unable to load candidate"), rejectErr
			case "--list-pools":
				return priorMarker, nil
			case "--list-conns":
				return []byte("list-conn event {vpn-old {children {\n"), nil
			}
		}
		return nil, nil
	}
	if err := m.ApplyGeneration(vpnCfg("vpn-new"), newGeneration, ApplyHooks{}); !errors.Is(err, rejectErr) {
		t.Fatalf("ApplyGeneration error = %v, want reject error", err)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read candidate: %v", err)
	}
	if string(got) == string(prior) || !strings.Contains(string(got), "vpn-new") {
		t.Fatal("malformed list-conns output must not restore the prior file")
	}
}

// A successful empty list-conns reply cannot prove a revoked prior connection
// remains loaded, even when the generation pool still names the prior file.
func TestSuccessfulEmptyLoadedConnsDoesNotRestorePrior17882(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	oldGeneration := strings.Repeat("a", 64)
	newGeneration := strings.Repeat("b", 64)
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.ApplyGeneration(vpnCfg("vpn1"), oldGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	rejectErr := errors.New("candidate rejected")
	priorMarker := []byte("get-pools reply {xpf-gen-" + oldGeneration + " {base=192.0.2.1 size=1 online=0 offline=0}}\n")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return []byte("unable to load candidate"), rejectErr
			case "--list-pools":
				return priorMarker, nil
			case "--list-conns":
				return []byte("list-conns reply {}\n"), nil
			}
		}
		return nil, nil
	}
	rotated := vpnCfg("vpn1")
	rotated.VPNs["vpn1"].PSK = config.NewSecret("secret-rotated")
	if err := m.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); !errors.Is(err, rejectErr) {
		t.Fatalf("ApplyGeneration error = %v, want reject error", err)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read candidate: %v", err)
	}
	if string(got) == string(prior) || !strings.Contains(string(got), "secret-rotated") {
		t.Fatal("an empty loaded-connection set must not restore the revoked prior PSK")
	}
}

// A probe that first cannot reach charon and then sees the prior generation
// must still restore the prior file.
func TestCharonReturningDuringProbeRestoresPrior16853(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	oldGeneration := strings.Repeat("a", 64)
	newGeneration := strings.Repeat("b", 64)
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.ApplyGeneration(vpnCfg("vpn-old"), oldGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	probes := 0
	priorMarker := []byte("get-pools reply {xpf-gen-" + oldGeneration + " {base=192.0.2.1 size=1 online=0 offline=0}}\n")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed")
			case "--list-pools":
				probes++
				if probes >= 2 {
					return priorMarker, nil
				}
				return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed")
			}
		}
		return listConnsForRendered17882(t, prior), nil
	}
	if err := m.ApplyGeneration(vpnCfg("vpn-new"), newGeneration, ApplyHooks{}); err == nil {
		t.Fatal("ApplyGeneration must return the reload error")
	}
	if probes < 2 {
		t.Fatalf("generation probes = %d, want retry after first failure", probes)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(prior) {
		t.Fatal("charon answering with the prior generation must restore the prior file")
	}
}

// A fresh charon can answer successfully after starting with the candidate
// already on disk. Its empty loaded-connections result is not proof that the
// old generation remains loaded; restoring it would resurrect the revoked PSK.
func TestCharonRestartProbeKeepsRotatedCandidate17882(t *testing.T) {
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
	newGeneration := generationMarkerToken("", m.generateConfig(rotated))
	newMarker := []byte("get-pools reply {xpf-gen-" + newGeneration + " {base=192.0.2.1 size=1 online=0 offline=0}}\n")
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed")
			case "--list-conns":
				// The restarted charon answers with no loaded connections.
				return []byte("list-conns reply {}\n"), nil
			case "--list-pools":
				// The marker proves it loaded the candidate written before
				// the restart, not the prior generation.
				return newMarker, nil
			}
		}
		return nil, nil
	}
	if err := m.Apply(rotated); err == nil {
		t.Fatal("Apply must return the reload error")
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("rotated candidate must stay on disk: %v", err)
	}
	if string(got) == string(prior) {
		t.Fatal("prior PSK was restored after a fresh charon loaded the candidate")
	}
	if !strings.Contains(string(got), "secret-rotated") {
		t.Fatal("rotated candidate PSK is missing from the retained config")
	}
	if strings.Contains(string(got), "secret-vpn1") {
		t.Fatal("revoked prior PSK remains on disk")
	}
	if !m.tracks("vpn1") {
		t.Fatal("the committed candidate set must be promoted")
	}
}

// Clearing while a fresh charon answers an empty probe must not restore the
// removed prior file and resurrect the revoked connection.
func TestClearAfterRestartProbeKeepsFileRemoved17882(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.Apply(vpnCfg("vpn1")); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return nil, errors.New("connecting to 'unix:///var/run/charon.vici' failed")
			case "--list-pools":
				return []byte("get-pools reply {}\n"), nil
			case "--list-conns":
				return []byte("list-conns reply {}\n"), nil
			}
		}
		return nil, nil
	}
	if err := m.Clear(); err == nil {
		t.Fatal("Clear must return the reload error")
	}
	if _, err := os.Stat(m.configPath); !os.IsNotExist(err) {
		t.Fatalf("the removed file must stay absent: stat err=%v", err)
	}
	if m.tracks("vpn1") {
		t.Fatal("the empty clear set must be promoted when the prior generation is absent")
	}
}

// A live superset is neither the prior nor candidate render. The candidate
// remains staged, but its fingerprints must not be promoted: a later successful
// apply still needs to tear down and re-establish the changed SA.
//
// fail-on-revert: promoting the candidate on the first ambiguous probe makes
// the later same-candidate apply skip teardown and re-initiation.
func TestIndeterminateSupersetPreservesChangedFingerprint17882(t *testing.T) {
	m := NewWithConfigDir(t.TempDir())
	oldGeneration := strings.Repeat("a", 64)
	newGeneration := strings.Repeat("b", 64)
	oldCfg := vpnCfg("vpn1")
	oldCfg.VPNs["vpn1"].EstablishTunnels = "immediately"
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.ApplyGeneration(oldCfg, oldGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}
	prior, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("FIXTURE: read prior: %v", err)
	}
	m.mu.Lock()
	oldHash := m.prevConnHashes["vpn1"]
	m.mu.Unlock()

	reloadErr := errors.New("candidate reload rejected")
	priorConns := strings.TrimSuffix(string(listConnsForRendered17882(t, prior)), "list-conns reply {}\n")
	priorConns += "list-conn event {extra {local_addrs=[%any] remote_addrs=[%any] children {extra {}}}}\n"
	rec := &reloadRecorder{
		failLoadAll: true,
		loadErr:     reloadErr,
		listPools:   poolsForPrior17882(t, prior),
		listConns:   []byte(priorConns + "list-conns reply {}\n"),
		listSAs:     liveSA("vpn1"),
	}
	m.swanctl = rec.run
	rotated := vpnCfg("vpn1")
	rotated.VPNs["vpn1"].EstablishTunnels = "immediately"
	rotated.VPNs["vpn1"].PSK = config.NewSecret("secret-rotated")
	if err := m.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); !errors.Is(err, reloadErr) {
		t.Fatalf("ambiguous ApplyGeneration error = %v, want reload error", err)
	}
	got, err := os.ReadFile(m.configPath)
	if err != nil {
		t.Fatalf("read staged candidate: %v", err)
	}
	if string(got) == string(prior) || !strings.Contains(string(got), "secret-rotated") {
		t.Fatal("ambiguous live set must leave the rotated candidate on disk")
	}
	m.mu.Lock()
	if gotHash := m.prevConnHashes["vpn1"]; gotHash != oldHash {
		m.mu.Unlock()
		t.Fatalf("indeterminate reload promoted candidate fingerprint %q; prior hash is %q", gotHash, oldHash)
	}
	m.mu.Unlock()
	if got := rec.terminated(); len(got) != 1 || got[0] != "vpn1" {
		t.Fatalf("indeterminate reload must tear down the stale vpn1 SA, got %v", got)
	}
	initiates := func() int {
		n := 0
		for _, call := range rec.calls {
			if len(call) > 0 && call[0] == "--initiate" {
				n++
			}
		}
		return n
	}
	if got := initiates(); got != 1 {
		t.Fatalf("indeterminate reload must re-establish vpn1 under charon's still-loaded config, got %d initiates", got)
	}

	// The same candidate now loads successfully. Because the prior fingerprint
	// was preserved, this converging apply must again tear down and re-initiate.
	rec.failLoadAll = false
	if err := m.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("successful convergence apply: %v", err)
	}
	if got := rec.terminated(); len(got) != 2 || got[1] != "vpn1" {
		t.Fatalf("converging apply must retry changed-SA teardown, got %v", got)
	}
	if got := initiates(); got != 2 {
		t.Fatalf("converging apply must re-initiate the changed tunnel, got %d initiates", got)
	}
	m.mu.Lock()
	newHash := m.prevConnHashes["vpn1"]
	m.mu.Unlock()
	if newHash == oldHash {
		t.Fatal("successful convergence did not promote the candidate fingerprint")
	}
}

// A stable config-store digest may accompany different rendered local_addrs
// after a DHCP rebind. The connection listing, not the marker alone, separates
// the still-loaded old endpoint from a restarted charon that loaded the new one.
func TestSameDigestDifferentRenderedLocalAddressProbe17882(t *testing.T) {
	generation := strings.Repeat("c", 64)
	for _, tc := range []struct {
		name        string
		liveNewAddr bool
		wantPrior   bool
	}{
		{name: "old address remains loaded", wantPrior: true},
		{name: "restarted charon loaded new address", liveNewAddr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewWithConfigDir(t.TempDir())
			priorCfg := vpnCfg("vpn1")
			ch := &charonDown16853{}
			m.swanctl = ch.run
			if err := m.ApplyGeneration(priorCfg, generation, ApplyHooks{}); err != nil {
				t.Fatalf("FIXTURE: initial apply: %v", err)
			}
			prior, err := os.ReadFile(m.configPath)
			if err != nil {
				t.Fatalf("FIXTURE: read prior: %v", err)
			}
			candidateCfg := vpnCfg("vpn1")
			candidateCfg.VPNs["vpn1"].LocalAddr = "10.0.1.2"
			liveConfig := prior
			if tc.liveNewAddr {
				liveConfig = []byte(m.generateConfig(candidateCfg))
			}
			reloadErr := errors.New("reload failed during DHCP rebind")
			m.swanctl = func(args ...string) ([]byte, error) {
				if len(args) > 0 {
					switch args[0] {
					case "--load-all":
						return nil, reloadErr
					case "--list-pools":
						return poolsForPrior17882(t, prior), nil
					case "--list-conns":
						return listConnsForRendered17882(t, liveConfig), nil
					}
				}
				return nil, nil
			}
			if err := m.ApplyGeneration(candidateCfg, generation, ApplyHooks{}); !errors.Is(err, reloadErr) {
				t.Fatalf("ApplyGeneration error = %v, want reload error", err)
			}
			got, err := os.ReadFile(m.configPath)
			if err != nil {
				t.Fatalf("read post-probe config: %v", err)
			}
			if tc.wantPrior {
				if string(got) != string(prior) {
					t.Fatal("old-address control must restore the prior config")
				}
				return
			}
			if string(got) == string(prior) || !strings.Contains(string(got), "local_addrs = 10.0.1.2") {
				t.Fatal("same-digest new-address probe must keep the candidate config")
			}
		})
	}
}

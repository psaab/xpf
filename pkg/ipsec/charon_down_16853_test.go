package ipsec

import (
	"errors"
	"os"
	"path/filepath"
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
// remains staged, but its fingerprints must not be promoted. Changed SAs are
// torn down without re-initiation from the unproven config; deferred-start
// debt is persisted before teardown so a later proven candidate load can
// restore the eager tunnel even after a restart or a successful teardown
// leaves no live SA. Candidate-only additions are likewise recorded so a
// later rotation or removal still terminates their live SAs.
func TestIndeterminateSupersetPreservesChangedFingerprint17882(t *testing.T) {
	for _, tc := range []struct {
		name               string
		failFirstTerminate bool
	}{
		{name: "successful teardown leaves no live SA"},
		{name: "failed teardown retains live SA", failFirstTerminate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
			m := NewWithConfigDir(t.TempDir())
			m.statePath = statePath
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
			termErr := errors.New("stale SA termination refused")
			priorConns := strings.TrimSuffix(string(listConnsForRendered17882(t, prior)), "list-conns reply {}\n")
			priorConns += "list-conn event {extra {local_addrs=[%any] remote_addrs=[%any] children {extra {}}}}\n"
			rec := &reloadRecorder{
				failLoadAll: true,
				loadErr:     reloadErr,
				listPools:   poolsForPrior17882(t, prior),
				listConns:   []byte(priorConns + "list-conns reply {}\n"),
				listSAs:     liveSA("vpn1"),
			}
			failFirstTerminate := tc.failFirstTerminate
			m.swanctl = func(args ...string) ([]byte, error) {
				if failFirstTerminate && len(args) > 0 && args[0] == "--terminate" {
					failFirstTerminate = false
					rec.calls = append(rec.calls, args)
					return []byte("terminate failed"), termErr
				}
				out, err := rec.run(args...)
				if len(args) > 0 && args[0] == "--terminate" && err == nil {
					rec.listSAs = "list-sas reply {}\n"
				}
				return out, err
			}

			rotated := vpnCfg("vpn1")
			rotated.VPNs["vpn1"].EstablishTunnels = "immediately"
			rotated.VPNs["vpn1"].PSK = config.NewSecret("secret-rotated")
			if err := m.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); err == nil || !errors.Is(err, reloadErr) {
				t.Fatalf("ambiguous ApplyGeneration error = %v, want reload error and teardown debt", err)
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
				t.Fatalf("indeterminate reload must attempt stale-SA teardown, got %v", got)
			}
			initiates := func(rec *reloadRecorder) int {
				n := 0
				for _, call := range rec.calls {
					if len(call) > 0 && call[0] == "--initiate" {
						n++
					}
				}
				return n
			}
			if got := initiates(rec); got != 0 {
				t.Fatalf("indeterminate reload must not re-establish from unproven config; got %d initiates", got)
			}
			state := readState9687(t, statePath)
			if tc.failFirstTerminate {
				if len(state.PendingReinitiate) != 0 {
					t.Fatalf("failed teardown must drop deferred re-initiation, got %+v", state.PendingReinitiate)
				}
				if len(state.PendingChanged) != 1 || state.PendingChanged[0] != "vpn1" {
					t.Fatalf("failed teardown must persist changed-connection debt, got %+v", state.PendingChanged)
				}
			} else {
				if len(state.PendingReinitiate) != 1 || state.PendingReinitiate[0] != "vpn1" {
					t.Fatalf("successful indeterminate teardown must persist deferred re-initiation, got %+v", state.PendingReinitiate)
				}
				if len(state.PendingChanged) != 0 {
					t.Fatalf("successful teardown must not leave changed teardown debt, got %+v", state.PendingChanged)
				}
			}

			retrySAs := "list-sas reply {}\n"
			if tc.failFirstTerminate {
				retrySAs = liveSA("vpn1")
			}
			rec2 := &reloadRecorder{listSAs: retrySAs}
			m2 := NewWithConfigDir(t.TempDir())
			m2.statePath = statePath
			m2.swanctl = func(args ...string) ([]byte, error) {
				out, err := rec2.run(args...)
				if len(args) > 0 && args[0] == "--terminate" && err == nil {
					rec2.listSAs = "list-sas reply {}\n"
				}
				return out, err
			}
			if err := m2.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); err != nil {
				t.Fatalf("successful candidate retry: %v", err)
			}
			wantTerminations := 0
			if tc.failFirstTerminate {
				wantTerminations = 1
			}
			if got := rec2.terminated(); len(got) != wantTerminations {
				t.Fatalf("retry teardown count = %v, want %d", got, wantTerminations)
			}
			if got := initiates(rec2); got != 1 {
				t.Fatalf("proven candidate must restore the eager tunnel despite no live SA; got %d initiates", got)
			}
			m2.mu.Lock()
			newHash := m2.prevConnHashes["vpn1"]
			m2.mu.Unlock()
			if newHash == oldHash {
				t.Fatal("successful convergence did not promote the candidate fingerprint")
			}
			state = readState9687(t, statePath)
			if len(state.PendingReinitiate) != 0 || len(state.PendingChanged) != 0 {
				t.Fatalf("successful retry must clear deferred-initiation and changed-termination debt, got %+v", state)
			}
		})
	}
}

// Candidate-only connections staged by an indeterminate apply must not be
// forgotten: they have no prior fingerprint, so only the persisted
// pending-candidate fingerprint lets a later proven apply see their rotation
// (terminate + re-initiate) or removal (terminate, no re-initiate).
// Crash injection between terminate and persistence is covered separately:
// the deferred-start debt must already be on disk while terminate runs.
func TestIndeterminateCandidateOnlyConnectionIsRemembered17882(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove bool
	}{
		{name: "rotation terminates and re-initiates"},
		{name: "removal terminates without re-initiation", remove: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
			m := NewWithConfigDir(t.TempDir())
			m.statePath = statePath
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

			candidate := vpnCfg("vpn1", "vpn2")
			candidate.VPNs["vpn1"].EstablishTunnels = "immediately"
			candidate.VPNs["vpn2"].EstablishTunnels = "immediately"
			if err := m.ApplyGeneration(candidate, newGeneration, ApplyHooks{}); err == nil || !errors.Is(err, reloadErr) {
				t.Fatalf("ambiguous ApplyGeneration error = %v, want reload error", err)
			}
			state := readState9687(t, statePath)
			if state.PendingCandidate["vpn2"] == "" {
				t.Fatalf("candidate-only vpn2 fingerprint must persist, got %+v", state.PendingCandidate)
			}
			// vpn1 is unchanged here (its prior fingerprint still matches),
			// and vpn2 has no live SA in this fixture, so neither may gain
			// deferred-start debt merely from being in the candidate render.
			if len(state.PendingReinitiate) != 0 {
				t.Fatalf("unchanged vpn1 and SA-less candidate-only vpn2 must not gain deferred-start debt, got %+v", state.PendingReinitiate)
			}

			// Rotate the candidate-only connection and prove the candidate.
			next := vpnCfg("vpn1")
			next.VPNs["vpn1"].EstablishTunnels = "immediately"
			if !tc.remove {
				next = vpnCfg("vpn1", "vpn2")
				next.VPNs["vpn1"].EstablishTunnels = "immediately"
				next.VPNs["vpn2"].EstablishTunnels = "immediately"
				next.VPNs["vpn2"].PSK = config.NewSecret("secret-vpn2-rotated")
			}
			rec2 := &reloadRecorder{listSAs: liveSA("vpn2")}
			m2 := NewWithConfigDir(t.TempDir())
			m2.statePath = statePath
			m2.swanctl = rec2.run
			if err := m2.ApplyGeneration(next, newGeneration, ApplyHooks{}); err != nil {
				t.Fatalf("proven candidate apply: %v", err)
			}
			if got := rec2.terminated(); len(got) != 1 || got[0] != "vpn2" {
				t.Fatalf("later apply must terminate candidate-only vpn2 SA, got %v", got)
			}
			initiates := 0
			for _, call := range rec2.calls {
				if len(call) > 0 && call[0] == "--initiate" {
					initiates++
				}
			}
			wantInitiates := 0
			if !tc.remove {
				wantInitiates = 1
			}
			if initiates != wantInitiates {
				t.Fatalf("candidate-only rotation initiate count = %d, want %d", initiates, wantInitiates)
			}
			state = readState9687(t, statePath)
			if tc.remove {
				if len(state.PendingCandidate) != 0 {
					t.Fatalf("removal must clear the staged candidate fingerprint, got %+v", state.PendingCandidate)
				}
			} else if state.PendingCandidate["vpn2"] == "" {
				t.Fatalf("rotation must retain the staged candidate fingerprint as the loaded baseline, got %+v", state.PendingCandidate)
			}

			// THIRD apply with the identical proven candidate must diff
			// clean: the refreshed staged fingerprint (or the promoted
			// baseline) matches, so no terminate and no re-initiate — the
			// perpetual-flap regression. A fresh Manager over the same
			// durable state proves the staged record survives restart.
			if !tc.remove {
				rec3 := &reloadRecorder{listSAs: liveSA("vpn2")}
				m3 := NewWithConfigDir(t.TempDir())
				m3.statePath = statePath
				m3.swanctl = rec3.run
				if err := m3.ApplyGeneration(next, newGeneration, ApplyHooks{}); err != nil {
					t.Fatalf("identical third apply: %v", err)
				}
				if got := rec3.terminated(); len(got) != 0 {
					t.Fatalf("identical proven apply must not terminate the staged candidate SA (perpetual flap), got %v", got)
				}
				thirdInitiates := 0
				for _, call := range rec3.calls {
					if len(call) > 0 && call[0] == "--initiate" {
						thirdInitiates++
					}
				}
				if thirdInitiates != 0 {
					t.Fatalf("identical proven apply must not re-initiate, got %d initiates", thirdInitiates)
				}
			}
		})
	}
}

// Crash injection: the deferred-start debt for a changed connection must be
// durable BEFORE terminateRemovedConns destroys its SA. The wrapper snapshots
// the durable state while terminate is executing and restores it afterwards,
// simulating a crash+restart at that exact point.
func TestIndeterminateDeferredDebtPersistedBeforeTerminate17882(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	m := NewWithConfigDir(t.TempDir())
	m.statePath = statePath
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
	var captured []byte
	m.swanctl = func(args ...string) ([]byte, error) {
		out, err := rec.run(args...)
		if len(args) > 0 && args[0] == "--terminate" && err == nil {
			data, rerr := os.ReadFile(statePath)
			if rerr != nil {
				t.Errorf("read state during terminate: %v", rerr)
			} else {
				captured = append([]byte(nil), data...)
			}
			rec.listSAs = "list-sas reply {}\n"
		}
		return out, err
	}

	rotated := vpnCfg("vpn1")
	rotated.VPNs["vpn1"].EstablishTunnels = "immediately"
	rotated.VPNs["vpn1"].PSK = config.NewSecret("secret-rotated")
	if err := m.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); err == nil || !errors.Is(err, reloadErr) {
		t.Fatalf("ambiguous ApplyGeneration error = %v, want reload error", err)
	}
	if captured == nil {
		t.Fatal("FICTION: terminate did not run during the indeterminate apply")
	}
	// Simulate crash+restart: restore the durable bytes as they were while
	// terminate was executing (i.e. before any post-terminate persistence).
	if err := os.WriteFile(statePath, captured, 0o600); err != nil {
		t.Fatalf("restore crash-injected state: %v", err)
	}
	state := readState9687(t, statePath)
	if len(state.PendingReinitiate) != 1 || state.PendingReinitiate[0] != "vpn1" {
		t.Fatalf("deferred-start debt must be durable before terminate destroys the SA, got %+v", state.PendingReinitiate)
	}

	rec2 := &reloadRecorder{listSAs: "list-sas reply {}\n"}
	m2 := NewWithConfigDir(t.TempDir())
	m2.statePath = statePath
	m2.swanctl = rec2.run
	if err := m2.ApplyGeneration(rotated, newGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("successful candidate retry after crash: %v", err)
	}
	initiates := 0
	for _, call := range rec2.calls {
		if len(call) > 0 && call[0] == "--initiate" {
			initiates++
		}
	}
	if initiates != 1 {
		t.Fatalf("crash-restored deferred debt must re-initiate the eager tunnel, got %d initiates", initiates)
	}
	state = readState9687(t, statePath)
	if len(state.PendingReinitiate) != 0 {
		t.Fatalf("successful retry must clear deferred debt, got %+v", state.PendingReinitiate)
	}
}

// Crash injection on the committed-candidate branch (charon unreachable, so
// the candidate is promoted for its next start): deferred-start debt for the
// changed connection must be durable BEFORE terminateRemovedConns runs,
// exactly as on the indeterminate branch.
func TestCommittedCandidateDeferredDebtPersistedBeforeTerminate17882(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	m := NewWithConfigDir(t.TempDir())
	m.statePath = statePath
	oldGeneration := strings.Repeat("a", 64)
	oldCfg := vpnCfg("vpn1")
	oldCfg.VPNs["vpn1"].EstablishTunnels = "immediately"
	ch := &charonDown16853{}
	m.swanctl = ch.run
	if err := m.ApplyGeneration(oldCfg, oldGeneration, ApplyHooks{}); err != nil {
		t.Fatalf("FIXTURE: initial apply: %v", err)
	}

	rotated := vpnCfg("vpn1")
	rotated.VPNs["vpn1"].EstablishTunnels = "immediately"
	rotated.VPNs["vpn1"].PSK = config.NewSecret("secret-rotated")
	reloadErr := errors.New("charon vici unreachable")
	var captured []byte
	m.swanctl = func(args ...string) ([]byte, error) {
		if len(args) > 0 {
			switch args[0] {
			case "--load-all":
				return nil, reloadErr
			case "--list-pools", "--list-conns":
				// Unreachable probe: no marker/conns answer, so the
				// candidate is committed for charon's next start.
				return nil, reloadErr
			case "--list-sas":
				return []byte(liveSA("vpn1")), nil
			case "--terminate":
				data, rerr := os.ReadFile(statePath)
				if rerr != nil {
					t.Errorf("read state during terminate: %v", rerr)
				} else {
					captured = append([]byte(nil), data...)
				}
				return nil, nil
			}
		}
		return nil, nil
	}
	if err := m.ApplyGeneration(rotated, strings.Repeat("b", 64), ApplyHooks{}); err == nil {
		t.Fatal("unreachable reload must return an error")
	}
	if captured == nil {
		t.Fatal("FICTION: terminate did not run on the committed-candidate branch")
	}
	if err := os.WriteFile(statePath, captured, 0o600); err != nil {
		t.Fatalf("restore crash-injected state: %v", err)
	}
	state := readState9687(t, statePath)
	if len(state.PendingReinitiate) != 1 || state.PendingReinitiate[0] != "vpn1" {
		t.Fatalf("committed-candidate deferred debt must be durable before terminate, got %+v", state.PendingReinitiate)
	}
}

func TestEraseConnStateIfEmptyPreservesPendingCandidateDebt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ipsec-conn-state.json")
	state := `{"loaded":[],"pending_terminate":[],"pending_candidate":{"site-a":"abc"}}`
	if err := os.WriteFile(path, []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EraseConnStateIfEmpty(path); err == nil {
		t.Fatal("pending candidate fingerprints must refuse erasure")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != state {
		t.Fatalf("failed erase changed staged-candidate authority: body=%q err=%v", got, err)
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

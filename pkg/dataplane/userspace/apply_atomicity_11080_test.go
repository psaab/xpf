package userspace

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestPublishedTailFailureReturnsAndRecordsEnforcedApply11080(t *testing.T) {
	cfg := &config.Config{}
	ucfg := deriveUserspaceConfig(cfg)
	previous, err := buildSnapshot(cfg, ucfg, 7, 0)
	if err != nil {
		t.Fatalf("build previous snapshot: %v", err)
	}

	m := New()
	m.lastSnapshot = previous
	m.generation = previous.Generation
	m.publishedSnapshot = previous.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(previous)
	m.cfg = ucfg
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.xskLivenessProven = true
	m.helperStatusCtrlMapHook = &fakeCtrlMap{updateErr: errors.New("status map write failed")}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && status != nil {
			*status = ProcessStatus{
				ConfigSnapshotProtocolVersion: ProtocolVersion,
				LastSnapshotGeneration:        req.Snapshot.Generation,
				LastFIBGeneration:             req.Snapshot.FIBGeneration,
				Enabled:                       true,
				Workers:                       1,
				Capabilities:                  UserspaceCapabilities{ForwardingSupported: true},
			}
		}
		return nil
	}
	m.compileUserspaceShimHook = func(_ *config.Config, preflight func(*dataplane.CompileResult) error) (*dataplane.CompileResult, error) {
		result := &dataplane.CompileResult{}
		if err := preflight(result); err != nil {
			return nil, err
		}
		return result, nil
	}
	t.Cleanup(func() {
		m.mu.Lock()
		cancel := m.syncCancel
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})

	result, applyErr := m.ApplyConfig(context.Background(), cfg)
	if applyErr == nil {
		t.Fatal("apply returned nil after helper-status reconciliation failed")
	}
	if !strings.Contains(applyErr.Error(), "is already enforced") {
		t.Fatalf("tail error does not distinguish enforced from reported state: %v", applyErr)
	}

	m.mu.Lock()
	published := m.publishedSnapshot
	loopStarted := m.syncCancel != nil
	m.mu.Unlock()
	if published == 0 {
		t.Fatal("premise: helper did not accept the new snapshot")
	}
	if result == nil || result.Generation != published {
		t.Fatalf("ApplyConfig result generation = %v, published generation = %d; caller must receive the enforced state",
			result, published)
	}
	last := m.LastApplyResult()
	if last == nil || last.Generation != published {
		t.Fatalf("LastApplyResult generation = %v, published generation = %d; accepted tables were not recorded",
			last, published)
	}
	if !loopStarted {
		t.Fatal("post-publish failure left no status-loop reconciler running")
	}
}

func TestSnapshotValidationPrecedesShimMutation11080(t *testing.T) {
	defer forceAddressBookCollision(t)()

	mutated := false
	m := New()
	m.compileUserspaceShimHook = func(_ *config.Config, preflight func(*dataplane.CompileResult) error) (*dataplane.CompileResult, error) {
		result := &dataplane.CompileResult{}
		if err := preflight(result); err != nil {
			return nil, err
		}
		mutated = true // manager-level stand-in for CompileUserspaceShim's host mutation
		return result, nil
	}
	_, err := m.Compile(collidingBookCfg(3))
	var collision *AddressBookIDCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("Compile error = %v, want AddressBookIDCollisionError", err)
	}
	if mutated {
		t.Fatal("snapshot validation rejected the config only after the shim compile had mutated the host")
	}
}
func TestCompileUsesPostCompileVLANSnapshot11080(t *testing.T) {
	const vlanIfindex = 42
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {
			Name:        "ge-0/0/0",
			VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{
				100: {
					Number: 100,
					VlanID: 100,
					Tunnel: &config.TunnelConfig{
						Mode:        "gre",
						Source:      "192.0.2.1",
						Destination: "198.51.100.2",
					},
				},
			},
		},
	}

	vlanCreated := true
	previousLinkSnapshot := buildLinkSnapshot
	t.Cleanup(func() { buildLinkSnapshot = previousLinkSnapshot })
	buildLinkSnapshot = func(linuxName string) (int, int, string, []InterfaceAddressSnapshot) {
		if linuxName == "ge-0-0-0.100" && vlanCreated {
			return vlanIfindex, 1500, "02:00:00:00:00:42", nil
		}
		return 0, 0, "", nil
	}
	ucfg := deriveUserspaceConfig(cfg)
	previous, err := buildSnapshot(cfg, ucfg, 7, 0)
	if err != nil {
		t.Fatalf("build previous snapshot: %v", err)
	}
	if len(previous.TunnelEndpoints) != 1 || previous.TunnelEndpoints[0].Ifindex != vlanIfindex {
		t.Fatalf("fixture previous tunnel endpoints = %+v, want one VLAN-bound endpoint at ifindex %d",
			previous.TunnelEndpoints, vlanIfindex)
	}
	vlanCreated = false

	m := New()
	m.lastSnapshot = previous
	m.generation = previous.Generation
	m.publishedSnapshot = previous.Generation
	m.publishedPlanKey = snapshotBindingPlanKey(previous)
	m.cfg = ucfg
	m.proc = &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}
	m.xskLivenessProven = true
	m.helperStatusCtrlMapHook = &fakeCtrlMap{}
	m.helperStatusBindingsMapHook = &fakeBindingsMap{}
	m.syncClassifierMapsHook = func(*ConfigSnapshot) error { return nil }
	m.clearHelperHAStateHook = func() error { return nil }
	m.lastStatus = ProcessStatus{ConfigSnapshotProtocolVersion: ProtocolVersion}
	m.helperStatusObserved = true

	var published *ConfigSnapshot
	m.controlRequestHook = func(req ControlRequest, status *ProcessStatus) error {
		if req.Type == "apply_snapshot" && req.Snapshot != nil {
			published = req.Snapshot
			if status != nil {
				*status = ProcessStatus{
					ConfigSnapshotProtocolVersion: ProtocolVersion,
					LastSnapshotGeneration:        req.Snapshot.Generation,
					LastFIBGeneration:             req.Snapshot.FIBGeneration,
					Enabled:                       true,
					Workers:                       1,
					Capabilities:                  UserspaceCapabilities{ForwardingSupported: true},
				}
			}
		}
		return nil
	}
	m.compileUserspaceShimHook = func(_ *config.Config, preflight func(*dataplane.CompileResult) error) (*dataplane.CompileResult, error) {
		result := &dataplane.CompileResult{}
		if err := preflight(result); err != nil {
			return nil, err
		}
		vlanCreated = true // CompileConfig Phase 2 creates the VLAN netdev.
		return result, nil
	}
	t.Cleanup(func() {
		m.mu.Lock()
		cancel := m.syncCancel
		m.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	})

	if _, err := m.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatalf("ApplyConfig: %v", err)
	}
	if published == nil {
		t.Fatal("helper received no published snapshot")
	}
	if len(published.TunnelEndpoints) != 1 {
		t.Fatalf("published tunnel endpoints = %+v, want the newly-created VLAN endpoint",
			published.TunnelEndpoints)
	}
	if got := published.TunnelEndpoints[0].Ifindex; got != vlanIfindex {
		t.Fatalf("published tunnel endpoint ifindex = %d, want post-compile VLAN ifindex %d",
			got, vlanIfindex)
	}
}

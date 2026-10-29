package dataplane

// #16787: deleting speed/duplex (or setting duplex auto) must undo a link
// mode xpf previously forced with `ethtool -s`, by issuing
// `ethtool -s <if> autoneg on` once. A netdev never forced gets no write.
// Each compile is a fresh CompileResult (as CompileConfig builds one per
// apply), so these tests prove the forced record survives across compiles
// via the process registry, not via per-result state.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// ethtoolRecorder16787 installs a fake runEthtool that records every call.
// failOn, when non-nil, is consulted per call and may fail specific calls.
func ethtoolRecorder16787(t *testing.T, failOn func(args []string) error) *[][]string {
	t.Helper()
	oldRegistryPath := configstore.EthtoolForcedRegistryPath
	configstore.EthtoolForcedRegistryPath = filepath.Join(t.TempDir(), "state", "ethtool-forced.json")
	resetEthtoolForcedForTest()
	t.Cleanup(func() {
		resetEthtoolForcedForTest()
		configstore.EthtoolForcedRegistryPath = oldRegistryPath
	})
	var calls [][]string
	mockEthtool(t, func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if failOn != nil {
			if err := failOn(args); err != nil {
				return []byte("boom"), err
			}
		}
		return nil, nil
	})
	return &calls
}

func newEthtoolResult16787() *CompileResult {
	return &CompileResult{ethtoolApplied: make(map[string]bool)}
}

func TestEthtoolAutonegRevertAcrossCompiles_16787(t *testing.T) {
	calls := ethtoolRecorder16787(t, nil)
	const iface = "ge-0-0-3"

	// Step 1 (acceptance): forced 100m/half.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "100m", Duplex: "half"})
	want := [][]string{{"-s", iface, "speed", "100", "duplex", "half"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commit1 calls = %v, want %v", *calls, want)
	}

	// Step 2 (acceptance): duplex auto, speed deleted -> autoneg on.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Duplex: "auto"})
	want = append(want, []string{"-s", iface, "autoneg", "on"})
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commit2 (duplex auto) calls = %v, want %v", *calls, want)
	}

	// Already reverted: repeating the auto shape in a later compile is a
	// no-op (issued once, not per commit).
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Duplex: "auto"})
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commit2-repeat calls = %v, want unchanged %v", *calls, want)
	}

	// Re-force, then step 3 (acceptance): speed+duplex deleted -> autoneg on.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "100m", Duplex: "half"})
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	want = append(want,
		[]string{"-s", iface, "speed", "100", "duplex", "half"},
		[]string{"-s", iface, "autoneg", "on"})
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("commit3 (deleted) calls = %v, want %v", *calls, want)
	}
}

func TestEthtoolNeverForcedGetsNoAutonegWrite_16787(t *testing.T) {
	calls := ethtoolRecorder16787(t, nil)
	const iface = "ge-0-0-3"

	// An interface that was never forced gets no write for any auto shape.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Duplex: "auto"})
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "auto"})
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "auto", Duplex: "auto"})
	if len(*calls) != 0 {
		t.Fatalf("never-forced interface got ethtool calls %v, want none", *calls)
	}
}

func TestEthtoolExplicitDuplexUnchanged_16787(t *testing.T) {
	calls := ethtoolRecorder16787(t, nil)
	const iface = "ge-0-0-3"

	// Step 4 (acceptance, positive control): duplex full alone still forces
	// exactly as before, and a subsequent auto shape reverts it.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Duplex: "full"})
	want := [][]string{{"-s", iface, "duplex", "full"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("duplex full calls = %v, want %v", *calls, want)
	}
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Duplex: "auto"})
	want = append(want, []string{"-s", iface, "autoneg", "on"})
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("duplex full then auto calls = %v, want %v", *calls, want)
	}
}

func TestEthtoolFailedForceDoesNotMarkForced_16787(t *testing.T) {
	calls := ethtoolRecorder16787(t, func(args []string) error {
		// Fail only forced -s writes (those carrying speed/duplex).
		for _, a := range args {
			if a == "speed" || a == "duplex" {
				return errors.New("ethtool refused")
			}
		}
		return nil
	})
	const iface = "ge-0-0-3"

	// A failed force (virtio/VF-style rejection) must not mark the netdev:
	// the following auto compile owes no revert and issues no write.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "100m", Duplex: "half"})
	before := len(*calls)
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	if len(*calls) != before {
		t.Fatalf("failed force marked netdev forced; auto compile issued %v", (*calls)[before:])
	}
}

func TestEthtoolFailedAutonegRevertRetriesNextCompile_16787(t *testing.T) {
	failAutoneg := true
	calls := ethtoolRecorder16787(t, func(args []string) error {
		if failAutoneg {
			for _, a := range args {
				if a == "autoneg" {
					return errors.New("ethtool refused")
				}
			}
		}
		return nil
	})
	const iface = "ge-0-0-3"

	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "1g", Duplex: "full"})
	// Revert attempt fails: the forced mark is kept, so the next auto
	// compile retries instead of assuming convergence.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	failAutoneg = false
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	want := [][]string{
		{"-s", iface, "speed", "1000", "duplex", "full"},
		{"-s", iface, "autoneg", "on"},
		{"-s", iface, "autoneg", "on"},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
	// Converged now: a further auto compile is silent.
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("post-converge calls = %v, want unchanged %v", *calls, want)
	}
}

func TestEthtoolPerInterfaceForcedTracking_16787(t *testing.T) {
	calls := ethtoolRecorder16787(t, nil)

	// Forcing one netdev must not cause a revert write on another.
	newEthtoolResult16787().applyEthtool("ge-0-0-3", &config.InterfaceConfig{Speed: "100m"})
	newEthtoolResult16787().applyEthtool("ge-0-0-4", &config.InterfaceConfig{})
	want := [][]string{{"-s", "ge-0-0-3", "speed", "100"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
	newEthtoolResult16787().applyEthtool("ge-0-0-3", &config.InterfaceConfig{})
	want = append(want, []string{"-s", "ge-0-0-3", "autoneg", "on"})
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls = %v, want %v", *calls, want)
	}
}

func TestEthtoolForcedRegistryPersistsAcrossRestart17790(t *testing.T) {
	calls := ethtoolRecorder16787(t, nil)
	const iface = "ge-0-0-3"
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "100m"})

	resetEthtoolForcedForTest()
	ethtoolForcedMu.Lock()
	ethtoolForcedLive = readEthtoolForcedRegistry()
	ethtoolForcedMu.Unlock()
	if !ethtoolForcedContains(iface) {
		t.Fatal("fresh registry instance did not load the forced interface")
	}
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "100m"})
	if err := os.Remove(configstore.EthtoolForcedRegistryPath); err != nil {
		t.Fatalf("simulate factory-reset registry erase: %v", err)
	}

	resetEthtoolForcedForTest()
	ethtoolForcedMu.Lock()
	ethtoolForcedLive = readEthtoolForcedRegistry()
	ethtoolForcedMu.Unlock()
	if ethtoolForcedContains(iface) {
		t.Fatal("fresh registry instance loaded an interface after factory reset")
	}
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})

	want := [][]string{
		{"-s", iface, "speed", "100"},
		{"-s", iface, "autoneg", "on"},
		{"-s", iface, "speed", "100"},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("simulated restart/reset calls = %v, want %v", *calls, want)
	}
}

func TestEthtoolForcedRegistryPersistenceFailureIsSoft17790(t *testing.T) {
	calls := ethtoolRecorder16787(t, nil)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	configstore.EthtoolForcedRegistryPath = filepath.Join(blocker, "registry.json")
	const iface = "ge-0-0-3"

	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{Speed: "100m"})
	newEthtoolResult16787().applyEthtool(iface, &config.InterfaceConfig{})
	want := [][]string{
		{"-s", iface, "speed", "100"},
		{"-s", iface, "autoneg", "on"},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("persistence failure changed in-memory behavior: calls = %v, want %v", *calls, want)
	}
}

func TestEthtoolForcedRegistryCorruptFileFailsSoft17790(t *testing.T) {
	ethtoolRecorder16787(t, nil)
	if err := os.MkdirAll(filepath.Dir(configstore.EthtoolForcedRegistryPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configstore.EthtoolForcedRegistryPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded := readEthtoolForcedRegistry(); len(loaded) != 0 {
		t.Fatalf("corrupt registry loaded entries %v, want empty in-memory state", loaded)
	}
}

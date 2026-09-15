package dataplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type fakePinnedTCLink struct {
	path     string
	unpinned bool
	closed   bool
	unpinErr error
	closeErr error
}

func (f *fakePinnedTCLink) Unpin() error {
	if f.unpinErr != nil {
		return f.unpinErr
	}
	f.unpinned = true
	return os.Remove(f.path)
}

func (f *fakePinnedTCLink) Close() error {
	if f.closeErr != nil {
		return f.closeErr
	}
	f.closed = true
	return nil
}

func TestUserspaceShimDNATMapCapacityMatchesLegacyPinnedMap(t *testing.T) {
	t.Parallel()

	specs := userspaceShimSharedMapSpecs()
	byName := make(map[string]uint32, len(specs))
	flagsByName := make(map[string]uint32, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec.MaxEntries
		flagsByName[spec.Name] = spec.Flags
	}
	for _, name := range []string{"dnat_table", "dnat_table_v6"} {
		if got := byName[name]; got != userspaceShimMaxSessions {
			t.Fatalf("%s max_entries = %d, want legacy-compatible %d",
				name, got, userspaceShimMaxSessions)
		}
		if flagsByName[name]&unix.BPF_F_NO_PREALLOC == 0 {
			t.Fatalf("%s flags = %#x, want BPF_F_NO_PREALLOC",
				name, flagsByName[name])
		}
	}
}

func TestEmbeddedUserspaceShimDNATMapMatchesSharedPinnedMap(t *testing.T) {
	t.Parallel()

	spec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load Rust userspace XDP spec: %v", err)
	}
	dnat := spec.Maps["dnat_table"]
	if dnat == nil {
		t.Fatal("Rust userspace XDP spec missing dnat_table")
	}
	if dnat.MaxEntries != userspaceShimMaxSessions {
		t.Fatalf("embedded dnat_table max_entries = %d, want %d",
			dnat.MaxEntries, userspaceShimMaxSessions)
	}
	if dnat.Flags&unix.BPF_F_NO_PREALLOC == 0 {
		t.Fatalf("embedded dnat_table flags = %#x, want BPF_F_NO_PREALLOC",
			dnat.Flags)
	}
}

func TestValidateUserspaceShimSpecDriftMentionsUserspaceXDPGenerate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		spec *ebpf.CollectionSpec
	}{
		{
			name: "bindings",
			spec: &ebpf.CollectionSpec{
				Maps: map[string]*ebpf.MapSpec{
					"userspace_bindings": {MaxEntries: BindingArrayMaxEntries - 1},
				},
			},
		},
		{
			name: "ingress-ifaces",
			spec: &ebpf.CollectionSpec{
				Maps: map[string]*ebpf.MapSpec{
					"userspace_bindings":       {MaxEntries: BindingArrayMaxEntries},
					"userspace_ingress_ifaces": {MaxEntries: MaxInterfaces - 1},
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateUserspaceShimSpec(tt.spec)
			if err == nil {
				t.Fatal("validateUserspaceShimSpec succeeded, want drift error")
			}
			if !strings.Contains(err.Error(), "Re-run `make generate-userspace-xdp`.") {
				t.Fatalf("err = %v, want userspace XDP regeneration target", err)
			}
			if strings.Contains(err.Error(), "Re-run `make generate`.") {
				t.Fatalf("err = %v, should not point at legacy bpf2go generation", err)
			}
		})
	}
}

// validABIBaseSpec builds a shim spec that passes every pre-#5307 check
// (presence + MaxEntries + NO_PREALLOC) AND the new dnat_table expected-shape
// check, so the ONLY thing that can reject it is the #5307 live-pin ABI
// comparison. Shapes mirror the real embedded shim (Type/KeySize/ValueSize).
func validABIBaseSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"userspace_bindings":       {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: BindingArrayMaxEntries},
			"userspace_ingress_ifaces": {Type: ebpf.Hash, KeySize: 4, ValueSize: 1, MaxEntries: MaxInterfaces},
			"dnat_table":               {Type: ebpf.Hash, KeySize: 12, ValueSize: 8, MaxEntries: userspaceShimMaxSessions, Flags: unix.BPF_F_NO_PREALLOC},
			// #9587: the ctrl value grew 40 -> 56 (count+array replacing the
			// steering scalar); the drift cells below still catch any other
			// ValueSize.
			"userspace_ctrl": {Type: ebpf.Array, KeySize: 4, ValueSize: 56, MaxEntries: 1},
			// #7497: the slot-keyed maps. Present here so the base spec still
			// reaches the checks that follow them; their own drift arm is
			// exercised by TestValidateUserspaceShimSpecSlotMapDrift.
			"userspace_heartbeat": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: BindingSlotMapMaxEntries},
			"userspace_xsk_map":   {Type: ebpf.XSKMap, KeySize: 4, ValueSize: 4, MaxEntries: BindingSlotMapMaxEntries},
		},
	}
}

// TestValidateUserspaceShimSpecSlotMapDrift covers the #7497 arm: the two maps
// keyed by the binding VALUE's slot field must match BindingSlotMapMaxEntries.
//
// Each case drifts ONE map and leaves the other correct, because a single case
// that drifted both would stay green if the loop only ever checked its first
// element. The base spec is otherwise valid, so the slot-map arm is the only
// thing that can reject it.
func TestValidateUserspaceShimSpecSlotMapDrift(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"userspace_heartbeat", "userspace_xsk_map"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			spec := validABIBaseSpec()
			spec.Maps[name] = &ebpf.MapSpec{
				Type:       spec.Maps[name].Type,
				KeySize:    spec.Maps[name].KeySize,
				ValueSize:  spec.Maps[name].ValueSize,
				MaxEntries: BindingSlotMapMaxEntries / 2,
			}

			err := validateUserspaceShimSpec(spec)
			if err == nil {
				t.Fatalf("validateUserspaceShimSpec(%s drifted) succeeded, want drift error", name)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("err = %v, want the drifted map named", err)
			}
			// The message must name the LIMIT, not just report a mismatch:
			// an operator reading it has to know what value to restore.
			if !strings.Contains(err.Error(), fmt.Sprintf("expected=%d", BindingSlotMapMaxEntries)) {
				t.Fatalf("err = %v, want expected=%d named", err, BindingSlotMapMaxEntries)
			}
			if !strings.Contains(err.Error(), "binding_index.rs") {
				t.Fatalf("err = %v, want the authoritative constant's file named", err)
			}
		})
	}

	// Control: the undrifted base spec must NOT be rejected by this arm. Without
	// it, an arm that rejected every spec would pass both cases above.
	t.Run("valid-spec-not-rejected", func(t *testing.T) {
		t.Parallel()

		if err := validateUserspaceShimSpec(validABIBaseSpec()); err != nil {
			if strings.Contains(err.Error(), "userspace_heartbeat") || strings.Contains(err.Error(), "userspace_xsk_map") {
				t.Fatalf("slot-map arm rejected a valid spec: %v", err)
			}
		}
	})
}

// pinReaderWithOverride returns a fake live-pin reader that reports each map's
// pinned shape as the spec's shape, unless overridden. An override models a
// running daemon whose pin has a different ABI than the new shim.
func pinReaderWithOverride(spec *ebpf.CollectionSpec, overrides map[string]userspaceMapABI) userspacePinnedMapABIReader {
	return func(path string) (userspaceMapABI, bool, error) {
		name := filepath.Base(path)
		if s, ok := overrides[name]; ok {
			return s, true, nil
		}
		if ms, ok := spec.Maps[name]; ok {
			return mapABIFromSpec(ms), true, nil
		}
		return userspaceMapABI{}, false, nil
	}
}

func noPinReader() userspacePinnedMapABIReader {
	return func(string) (userspaceMapABI, bool, error) { return userspaceMapABI{}, false, nil }
}

// legacyPresenceMaxEntriesValidate replicates the pre-#5307 validator (presence
// + MaxEntries + NO_PREALLOC only, no ABI / live-pin comparison). It exists so
// the tests can prove RED-on-revert: a spec the new validator rejects for an
// ABI/live-pin mismatch is ACCEPTED here, i.e. before #5307 the incompatibility
// was invisible until the post-stop load.
func legacyPresenceMaxEntriesValidate(spec *ebpf.CollectionSpec) error {
	if ms, ok := spec.Maps["userspace_bindings"]; !ok {
		return fmt.Errorf("missing userspace_bindings")
	} else if ms.MaxEntries != BindingArrayMaxEntries {
		return fmt.Errorf("userspace_bindings max_entries drift")
	}
	if ms, ok := spec.Maps["userspace_ingress_ifaces"]; !ok {
		return fmt.Errorf("missing userspace_ingress_ifaces")
	} else if ms.MaxEntries != MaxInterfaces {
		return fmt.Errorf("userspace_ingress_ifaces max_entries drift")
	}
	if ms, ok := spec.Maps["dnat_table"]; !ok {
		return fmt.Errorf("missing dnat_table")
	} else if ms.MaxEntries != userspaceShimMaxSessions {
		return fmt.Errorf("dnat_table max_entries drift")
	} else if ms.Flags&unix.BPF_F_NO_PREALLOC == 0 {
		return fmt.Errorf("dnat_table flags drift")
	}
	return nil
}

// TestValidateUserspaceShimSpecLivePinABI is the #5307 core: a shim whose map
// ABI (Type/KeySize/ValueSize/MaxEntries/Flags) differs from the RUNNING
// daemon's live pin is rejected at the pre-flight — before the old daemon is
// stopped — instead of failing ErrMapIncompatible at the post-stop load. Each
// mismatch spec passes the legacy presence+MaxEntries validator, so reverting
// the ABI/live-pin comparison turns every reject case RED (nil error, the
// incompatibility only surfaces at load).
func TestValidateUserspaceShimSpecLivePinABI(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		overrides map[string]userspaceMapABI
		wantMap   string // "" => expect the spec to PASS
		wantField string
	}{
		{name: "matching-live-pin", overrides: nil, wantMap: ""},
		{
			name:      "value-size-reorder-on-userspace_ctrl",
			overrides: map[string]userspaceMapABI{"userspace_ctrl": {Type: ebpf.Array, KeySize: 4, ValueSize: 48, MaxEntries: 1}},
			wantMap:   "userspace_ctrl", wantField: "ValueSize",
		},
		{
			name:      "key-size-on-dnat_table",
			overrides: map[string]userspaceMapABI{"dnat_table": {Type: ebpf.Hash, KeySize: 16, ValueSize: 8, MaxEntries: userspaceShimMaxSessions, Flags: unix.BPF_F_NO_PREALLOC}},
			wantMap:   "dnat_table", wantField: "KeySize",
		},
		{
			name:      "type-on-userspace_ingress_ifaces",
			overrides: map[string]userspaceMapABI{"userspace_ingress_ifaces": {Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: MaxInterfaces}},
			wantMap:   "userspace_ingress_ifaces", wantField: "Type",
		},
		{
			name:      "flags-on-dnat_table",
			overrides: map[string]userspaceMapABI{"dnat_table": {Type: ebpf.Hash, KeySize: 12, ValueSize: 8, MaxEntries: userspaceShimMaxSessions, Flags: 0}},
			wantMap:   "dnat_table", wantField: "Flags",
		},
		{
			name:      "max-entries-on-userspace_bindings",
			overrides: map[string]userspaceMapABI{"userspace_bindings": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: BindingArrayMaxEntries + 1}},
			wantMap:   "userspace_bindings", wantField: "MaxEntries",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := validABIBaseSpec()

			// RED-on-revert guard: the pre-#5307 validator accepts the base spec,
			// so the ONLY reject signal here is the new ABI/live-pin comparison.
			if err := legacyPresenceMaxEntriesValidate(base); err != nil {
				t.Fatalf("legacy validator rejected the base spec (%v); cannot prove RED-on-revert", err)
			}

			err := validateUserspaceShimSpecWith(base, pinReaderWithOverride(base, tt.overrides))
			if tt.wantMap == "" {
				if err != nil {
					t.Fatalf("unexpected error on matching pins: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want ABI mismatch on %s, got nil (would brick post-stop after ErrMapIncompatible)", tt.wantMap)
			}
			// #5363: a live-pin mismatch is a STALE-PIN case (the running
			// daemon's pin predates this build's shim ABI), so the remediation
			// must be the stale-pin guidance
			// (`userspaceShimStalePinRemediation` — since #6928 the TARGETED
			// single-pin unlink, not a "full reload"), NOT `make generate` —
			// the embedded shim is the intended target, not broken.
			for _, want := range []string{tt.wantMap, tt.wantField, "ABI-incompatible", userspaceShimStalePinRemediation} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %v, want substring %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "make generate-userspace-xdp") {
				t.Fatalf("err = %v, live-pin mismatch must NOT tell the operator to rebuild the shim", err)
			}
		})
	}
}

// TestValidateUserspaceShimSpecSkipsDisposableFallbackStatsPin guards the
// #4113 interaction: the disposable counter map (userspace_fallback_stats) is
// reset on an intended shape change by reconcileDisposableCollectionPin, so the
// #5307 ABI pre-flight must NOT reject a shape-changed pin for it — doing so
// would re-brick the very upgrade the reconcile unblocks.
func TestValidateUserspaceShimSpecSkipsDisposableFallbackStatsPin(t *testing.T) {
	t.Parallel()

	base := validABIBaseSpec()
	base.Maps[userspaceFallbackStatsMapName] = &ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 16}
	// Live pin is the stale #4113 Array shape — an ABI mismatch for any other map.
	reader := pinReaderWithOverride(base, map[string]userspaceMapABI{
		userspaceFallbackStatsMapName: {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 16},
	})
	if err := validateUserspaceShimSpecWith(base, reader); err != nil {
		t.Fatalf("live-pin ABI check must skip disposable %s (reconciled separately), got: %v",
			userspaceFallbackStatsMapName, err)
	}
}

// TestValidateUserspaceShimSpecNoLivePinSkips proves a fresh node (no pins)
// passes the live-pin comparison without a false failure — only the
// expected-value checks apply.
func TestValidateUserspaceShimSpecNoLivePinSkips(t *testing.T) {
	t.Parallel()

	base := validABIBaseSpec()
	if err := validateUserspaceShimSpecWith(base, noPinReader()); err != nil {
		t.Fatalf("fresh node (no pins) must pass, got: %v", err)
	}
}

// TestValidateUserspaceShimSpecDNATExpectedABIDrift covers the expected-value
// arm: an embedded dnat_table whose Type/KeySize/ValueSize drifts from the Go
// single source of truth is rejected even on a fresh node with no live pin. The
// legacy validator accepts these (RED-on-revert).
func TestValidateUserspaceShimSpecDNATExpectedABIDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ebpf.MapSpec)
		field  string
	}{
		{"value-size", func(m *ebpf.MapSpec) { m.ValueSize = 16 }, "value_size"},
		{"key-size", func(m *ebpf.MapSpec) { m.KeySize = 16 }, "key_size"},
		{"type", func(m *ebpf.MapSpec) { m.Type = ebpf.LRUHash }, "type"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			base := validABIBaseSpec()
			tt.mutate(base.Maps["dnat_table"])

			if err := legacyPresenceMaxEntriesValidate(base); err != nil {
				t.Fatalf("legacy validator rejected base (%v); cannot prove RED-on-revert", err)
			}

			err := validateUserspaceShimSpecWith(base, noPinReader())
			if err == nil {
				t.Fatalf("want dnat_table %s drift error on fresh node, got nil", tt.field)
			}
			if !strings.Contains(err.Error(), "dnat_table") || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("err = %v, want dnat_table %s drift", err, tt.field)
			}
		})
	}
}

// TestValidateUserspaceShimSpecLivePinReadErrorSurfaces proves an unexpected
// live-pin read error is not swallowed (it aborts the pre-flight rather than
// silently proceeding to a possibly-incompatible load).
func TestValidateUserspaceShimSpecLivePinReadErrorSurfaces(t *testing.T) {
	t.Parallel()

	base := validABIBaseSpec()
	sentinel := errors.New("bpffs read boom")
	reader := func(string) (userspaceMapABI, bool, error) { return userspaceMapABI{}, false, sentinel }
	if err := validateUserspaceShimSpecWith(base, reader); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped reader error", err)
	}
}

// TestReadPinnedShimMapABISkipsMissingPin proves the production reader treats a
// missing pin as "skip" (fresh node), not an error.
func TestReadPinnedShimMapABISkipsMissingPin(t *testing.T) {
	t.Parallel()

	_, exists, err := readPinnedShimMapABI(filepath.Join(t.TempDir(), "not-pinned"))
	if err != nil {
		t.Fatalf("missing pin: unexpected err %v", err)
	}
	if exists {
		t.Fatal("missing pin reported as existing")
	}
}

// TestReadPinnedShimMapABISkipsUnsearchablePinDir mirrors the real deployment:
// /sys/fs/bpf is mode 700, so an unprivileged inspector cannot search it. The
// reader must skip (nil error) rather than fail the pre-flight; the real deploy
// pre-flight runs as root and can read the pins.
func TestReadPinnedShimMapABISkipsUnsearchablePinDir(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory search permission")
	}
	sub := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	_, exists, err := readPinnedShimMapABI(filepath.Join(sub, "dnat_table"))
	if err != nil {
		t.Fatalf("unsearchable pin dir: want skip (nil err), got %v", err)
	}
	if exists {
		t.Fatal("unsearchable pin reported as existing")
	}
}

func TestLoadOrCreatePinnedShimMapRefusesIncompatiblePinnedMap(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pin := filepath.Join(dir, "sessions")
	if err := os.WriteFile(pin, []byte("existing state"), 0600); err != nil {
		t.Fatalf("write pinned map marker: %v", err)
	}
	loadCalls := 0
	_, err := loadOrCreatePinnedShimMapWith(
		&ebpf.MapSpec{Name: "sessions"},
		dir,
		func(spec *ebpf.MapSpec, opts ebpf.MapOptions) (*ebpf.Map, error) {
			loadCalls++
			if spec.Name != "sessions" {
				t.Fatalf("spec.Name = %q, want sessions", spec.Name)
			}
			if opts.PinPath != dir {
				t.Fatalf("PinPath = %q, want %q", opts.PinPath, dir)
			}
			return nil, ebpf.ErrMapIncompatible
		},
	)
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Fatalf("err = %v, want ErrMapIncompatible", err)
	}
	if !strings.Contains(err.Error(), "refusing to reset incompatible userspace shim map") {
		t.Fatalf("err = %v, want fail-closed reset refusal", err)
	}
	if loadCalls != 1 {
		t.Fatalf("load calls = %d, want no destructive retry", loadCalls)
	}
	if got, err := os.ReadFile(pin); err != nil || string(got) != "existing state" {
		t.Fatalf("pinned map marker = %q, %v; want preserved state", got, err)
	}
}

func TestDisposablePinShapeMatches(t *testing.T) {
	t.Parallel()

	// The #4113 target spec: userspace_fallback_stats is a PerCpuArray<u64>
	// with 16 reason slots keyed by u32.
	want := &ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 16}
	tests := []struct {
		name       string
		pinType    ebpf.MapType
		keySize    uint32
		valueSize  uint32
		maxEntries uint32
		match      bool
	}{
		{"stale-array-from-old-daemon", ebpf.Array, 4, 8, 16, false},
		{"already-migrated-percpu", ebpf.PerCPUArray, 4, 8, 16, true},
		{"value-size-drift", ebpf.PerCPUArray, 4, 16, 16, false},
		{"max-entries-drift", ebpf.PerCPUArray, 4, 8, 32, false},
		{"key-size-drift", ebpf.PerCPUArray, 8, 8, 16, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := disposablePinShapeMatches(tt.pinType, tt.keySize, tt.valueSize, tt.maxEntries, want)
			if got != tt.match {
				t.Fatalf("disposablePinShapeMatches(%v, k=%d v=%d n=%d) = %v, want %v",
					tt.pinType, tt.keySize, tt.valueSize, tt.maxEntries, got, tt.match)
			}
		})
	}
}

// TestReconcileDisposableCollectionPinMigratesArrayToPerCPUArray reproduces the
// #4113 upgrade-brick: an old daemon left an Array pin for
// userspace_fallback_stats; the new daemon's PerCpuArray spec is incompatible,
// so the PinByName load fails with ErrMapIncompatible. The reconcile must drop
// the stale pin so the load recreates it fresh. Requires root + bpffs.
func TestReconcileDisposableCollectionPinMigratesArrayToPerCPUArray(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock (needs root): %v", err)
	}

	// Pins must live on a bpffs mount; t.TempDir() is tmpfs and cannot hold BPF
	// pins. Use a unique subdir under the real bpffs.
	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("xpf-test-4113-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Skipf("create bpffs test dir %s (needs root+bpffs): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	pinPath := filepath.Join(dir, userspaceFallbackStatsMapName)

	// Old daemon: a shared Array<u64> pinned counter map.
	oldArray, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       userspaceFallbackStatsMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("create Array map (needs root): %v", err)
	}
	if err := oldArray.Pin(pinPath); err != nil {
		oldArray.Close()
		t.Skipf("pin Array map at %s: %v", pinPath, err)
	}
	oldArray.Close() // fd closed; pin persists, as across a daemon restart

	// New daemon spec: PerCpuArray, pinned by name (mirrors the collection load).
	newSpec := &ebpf.MapSpec{
		Name:       userspaceFallbackStatsMapName,
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
		Pinning:    ebpf.PinByName,
	}

	// Without the reconcile, PinByName load against the stale Array pin bricks.
	bricked, err := ebpf.NewMapWithOptions(newSpec, ebpf.MapOptions{PinPath: dir})
	if err == nil {
		bricked.Close()
		t.Fatal("PinByName load succeeded against stale Array pin; expected ErrMapIncompatible (brick)")
	}
	if !errors.Is(err, ebpf.ErrMapIncompatible) {
		t.Fatalf("PinByName load err = %v, want ErrMapIncompatible", err)
	}

	// The reconcile drops the incompatible disposable pin.
	if err := reconcileDisposableCollectionPin(pinPath, newSpec); err != nil {
		t.Fatalf("reconcileDisposableCollectionPin: %v", err)
	}
	if _, statErr := os.Stat(pinPath); !os.IsNotExist(statErr) {
		t.Fatalf("stale pin still present after reconcile: statErr=%v", statErr)
	}

	// Now the PinByName load succeeds and produces a PerCpuArray.
	migrated, err := ebpf.NewMapWithOptions(newSpec, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Fatalf("PinByName load after reconcile: %v", err)
	}
	defer func() {
		_ = migrated.Unpin()
		_ = migrated.Close()
	}()
	if migrated.Type() != ebpf.PerCPUArray {
		t.Fatalf("migrated map type = %v, want PerCPUArray", migrated.Type())
	}

	// Idempotent: a second reconcile against the now-compatible pin is a no-op
	// (accumulated counters survive an ordinary restart).
	if err := reconcileDisposableCollectionPin(pinPath, newSpec); err != nil {
		t.Fatalf("reconcile on compatible pin: %v", err)
	}
	if _, statErr := os.Stat(pinPath); statErr != nil {
		t.Fatalf("compatible pin was removed by reconcile: %v", statErr)
	}
}

// TestReconcileDisposableCollectionPinNoOpOnRealEmbeddedSpec guards against a
// silent regression where the reconcile resets the counter on EVERY restart
// (losing accumulated counts) because the embedded PerCpuArray spec's reported
// shape does not match what a freshly created+pinned map of that spec reads
// back. It uses the REAL embedded userspace_fallback_stats spec, not a
// hand-built one. Requires root + bpffs.
func TestReconcileDisposableCollectionPinNoOpOnRealEmbeddedSpec(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock (needs root): %v", err)
	}
	collSpec, err := loadRustUserspaceXDP()
	if err != nil {
		t.Fatalf("load Rust userspace XDP spec: %v", err)
	}
	spec := collSpec.Maps[userspaceFallbackStatsMapName]
	if spec == nil {
		t.Fatalf("embedded spec missing %s", userspaceFallbackStatsMapName)
	}
	if spec.Type != ebpf.PerCPUArray {
		t.Fatalf("embedded %s type = %v, want PerCPUArray (F13)", userspaceFallbackStatsMapName, spec.Type)
	}

	dir := filepath.Join("/sys/fs/bpf", fmt.Sprintf("xpf-test-4113r-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Skipf("create bpffs test dir %s (needs root+bpffs): %v", dir, err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pinPath := filepath.Join(dir, userspaceFallbackStatsMapName)

	pinSpec := spec.Copy()
	pinSpec.Pinning = ebpf.PinByName
	m, err := ebpf.NewMapWithOptions(pinSpec, ebpf.MapOptions{PinPath: dir})
	if err != nil {
		t.Skipf("create+pin embedded spec (needs root): %v", err)
	}
	defer func() {
		_ = m.Unpin()
		_ = m.Close()
	}()

	// The reconcile must treat a pin created from the real embedded spec as
	// compatible (no reset), so counters survive an ordinary restart.
	if err := reconcileDisposableCollectionPin(pinPath, spec); err != nil {
		t.Fatalf("reconcile on real-spec pin: %v", err)
	}
	if _, statErr := os.Stat(pinPath); statErr != nil {
		t.Fatalf("reconcile removed a compatible real-spec pin: %v", statErr)
	}
}

func TestCleanupUserspaceShimLegacyOnlyMapPinsRemovesOnlyLegacyPins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{
		"xdp_progs",
		"tc_progs",
		"policer_states",
		"dnat_table",
		"sessions",
		"xdp_progs.bak",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := cleanupUserspaceShimLegacyOnlyMapPinsIn(dir, userspaceShimLegacyOnlyMapPins); err != nil {
		t.Fatalf("cleanup legacy-only map pins: %v", err)
	}

	for _, name := range userspaceShimLegacyOnlyMapPins {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after cleanup, err=%v", name, err)
		}
	}
	for _, name := range []string{"dnat_table", "sessions", "xdp_progs.bak"} {
		if got, err := os.ReadFile(filepath.Join(dir, name)); err != nil || string(got) != "pin" {
			t.Fatalf("%s = %q, %v; want preserved pin marker", name, got, err)
		}
	}
}

func TestCleanupUserspaceShimLegacyTCLinksDetachesTCPinsOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"tc_1", "tc_22", "tc_bad", "tc_", "xdp_1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	links := make(map[string]*fakePinnedTCLink)
	var loaded []string
	err := cleanupUserspaceShimLegacyTCLinksIn(dir, func(path string) (pinnedTCLink, error) {
		loaded = append(loaded, filepath.Base(path))
		link := &fakePinnedTCLink{path: path}
		links[filepath.Base(path)] = link
		return link, nil
	})
	if err != nil {
		t.Fatalf("cleanup legacy TC links: %v", err)
	}

	sort.Strings(loaded)
	if want := []string{"tc_1", "tc_22"}; !reflect.DeepEqual(loaded, want) {
		t.Fatalf("loaded pins = %v, want %v", loaded, want)
	}
	for _, name := range loaded {
		link := links[name]
		if link == nil || !link.unpinned || !link.closed {
			t.Fatalf("%s link state = %#v, want unpinned and closed", name, link)
		}
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after cleanup, err=%v", name, err)
		}
	}
	for _, name := range []string{"tc_bad", "tc_", "xdp_1"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s should be left alone, stat err=%v", name, err)
		}
	}
}

func TestCleanupUserspaceShimLegacyTCLinksContinuesAfterPinError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range []string{"tc_1", "tc_2"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("pin"), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	links := make(map[string]*fakePinnedTCLink)
	err := cleanupUserspaceShimLegacyTCLinksIn(dir, func(path string) (pinnedTCLink, error) {
		name := filepath.Base(path)
		link := &fakePinnedTCLink{path: path}
		if name == "tc_1" {
			link.unpinErr = errors.New("unpin failed")
		}
		links[name] = link
		return link, nil
	})
	if err == nil || !strings.Contains(err.Error(), "unpin failed") {
		t.Fatalf("err = %v, want aggregated first-pin failure", err)
	}
	if !links["tc_1"].closed {
		t.Fatalf("tc_1 close was not attempted after unpin failure")
	}
	if !links["tc_2"].unpinned || !links["tc_2"].closed {
		t.Fatalf("tc_2 state = %#v, want cleanup despite tc_1 failure", links["tc_2"])
	}
	if _, err := os.Stat(filepath.Join(dir, "tc_2")); !os.IsNotExist(err) {
		t.Fatalf("tc_2 still exists after cleanup, err=%v", err)
	}
}

func TestCleanupUserspaceShimLegacyTCLinksRemovesUnreadablePins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pin := filepath.Join(dir, "tc_9")
	if err := os.WriteFile(pin, []byte("pin"), 0600); err != nil {
		t.Fatalf("write pin: %v", err)
	}

	err := cleanupUserspaceShimLegacyTCLinksIn(dir, func(string) (pinnedTCLink, error) {
		return nil, errors.New("cannot load pinned link")
	})
	if err != nil {
		t.Fatalf("cleanup unreadable legacy TC link: %v", err)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatalf("unreadable TC pin still exists, err=%v", err)
	}
}

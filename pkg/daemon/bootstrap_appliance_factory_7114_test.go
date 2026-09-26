package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #7114: a factory boot of the xpf APPLIANCE IMAGE left every NIC down and
// unrenamed — no fxp0, no DHCP, reachable only from the hypervisor console.
//
// Mechanism: the bake purges cloud-init and deletes every netplan /
// interfaces.d file, so on a no-config-drive boot nothing but xpfd ever
// configures a NIC. xpfd enters #1922 bootstrap mode; setupBootstrapLifeline
// identifies the management NIC by the ACTIVE DEFAULT ROUTE; with every port
// down there is no route; so it declined to touch anything. That refusal is
// right on a FOREIGN host (xpf is a guest there and the operator's own network
// config is the lifeline) but wrong on the appliance, where the image's
// vNIC#1 -> fxp0 factory contract (PR #1906, docs/install-images.md) is the
// shipped behaviour and there is provably nothing to preserve.
//
// The fix adds ONE discriminator — the bake-written /etc/xpf/appliance marker,
// AND-ed with "never committed" — and falls back to the first enumerated NIC
// only when both hold.
//
// FAIL-ON-REVERT: dropping the appliance branch from chooseBootstrapLifeline
// reds TestChooseBootstrapLifeline/appliance_factory_boot_no_route AND the
// wiring test below. Dropping the everCommitted half of the pure gate reds
// TestIsApplianceFactoryBoot/marker_but_already_committed; dropping only the
// production binding (M13, #10749) reds the committed-appliance wiring row,
// which writes a .network.

func TestIsApplianceFactoryBoot(t *testing.T) {
	tests := []struct {
		name          string
		markerPresent bool
		everCommitted bool
		want          bool
	}{
		{
			// The #7114 case: a baked appliance that has never been
			// configured. This is the ONLY combination that may claim a NIC.
			name:          "marker present and never committed",
			markerPresent: true,
			everCommitted: false,
			want:          true,
		},
		{
			// #1960 fail-closed: a box whose committed config no longer
			// compiles is ALSO in bootstrap mode, but its operator-intended
			// interface bindings are real and unknown (possibly a device-map
			// that never wants an auto-fxp0). Claiming NIC 0 there is the
			// mis-binding #1960 exists to refuse.
			name:          "marker but already committed (#1960 fail-closed boot)",
			markerPresent: true,
			everCommitted: true,
			want:          false,
		},
		{
			// A foreign host with the .deb installed: no marker, so the
			// #1922 console-only refusal stands even on a fresh box.
			name:          "no marker, never committed (foreign .deb install)",
			markerPresent: false,
			everCommitted: false,
			want:          false,
		},
		{
			name:          "no marker, already committed",
			markerPresent: false,
			everCommitted: true,
			want:          false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isApplianceFactoryBoot(tt.markerPresent, tt.everCommitted); got != tt.want {
				t.Fatalf("isApplianceFactoryBoot(%v, %v) = %v, want %v",
					tt.markerPresent, tt.everCommitted, got, tt.want)
			}
		})
	}
}

func TestChooseBootstrapLifeline(t *testing.T) {
	tests := []struct {
		name             string
		routeIface       string
		firstNIC         string
		applianceFactory bool
		wantName         string
		wantSource       string
		wantOK           bool
	}{
		{
			// Unchanged #1922 behaviour: a default route is direct evidence
			// of where the operator reaches the box.
			name:       "default route selects the route interface",
			routeIface: "enp5s0",
			firstNIC:   "enp1s0",
			wantName:   "enp5s0",
			wantSource: lifelineSourceDefaultRoute,
			wantOK:     true,
		},
		{
			// The default route still wins on the appliance — the fallback is
			// for the case where there is no evidence at all, not a general
			// override of the route signal.
			name:             "default route wins over the appliance fallback",
			routeIface:       "enp5s0",
			firstNIC:         "enp1s0",
			applianceFactory: true,
			wantName:         "enp5s0",
			wantSource:       lifelineSourceDefaultRoute,
			wantOK:           true,
		},
		{
			// The #7114 fix.
			name:             "appliance factory boot, no route",
			firstNIC:         "enp5s0",
			applianceFactory: true,
			wantName:         "enp5s0",
			wantSource:       lifelineSourceApplianceFactory,
			wantOK:           true,
		},
		{
			// The #1922 refusal, preserved for every non-appliance host.
			name:     "no route, not an appliance factory boot",
			firstNIC: "enp5s0",
			wantOK:   false,
		},
		{
			// A diskless/NIC-less enumeration must not select the empty
			// string as an interface name.
			name:             "appliance factory boot with no NICs enumerated",
			applianceFactory: true,
			wantOK:           false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, source, ok := chooseBootstrapLifeline(tt.routeIface, tt.firstNIC, tt.applianceFactory)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if name != "" || source != "" {
					t.Fatalf("refusal must select nothing, got name=%q source=%q", name, source)
				}
				return
			}
			if name != tt.wantName {
				t.Fatalf("name = %q, want %q", name, tt.wantName)
			}
			if source != tt.wantSource {
				t.Fatalf("source = %q, want %q", source, tt.wantSource)
			}
		})
	}
}

// TestSetupBootstrapLifelineAppliance binds the WIRING, not just the pure
// cores: it drives the real setupBootstrapLifeline with the world-readers
// faked (no default route and one enumerated NIC named enp5s0) and asserts the
// observable outcomes the image gate checks. The committed-appliance row also
// proves that production reads EverCommitted: dropping that argument writes
// fxp0's .network and renames the NIC on a fail-closed boot.
func TestSetupBootstrapLifelineAppliance(t *testing.T) {
	tests := []struct {
		name         string
		writeMarker  bool
		commitConfig bool
		wantNetwork  bool
		wantRename   bool
	}{
		{
			name:        "appliance factory boot writes the bootstrap fxp0 .network",
			writeMarker: true,
			wantNetwork: true,
			wantRename:  true,
		},
		{
			// The #1922 guard, intact: no marker means no NIC is claimed even
			// though the enumeration and the (absent) route are identical.
			name:        "foreign host with no marker claims nothing",
			writeMarker: false,
			wantNetwork: false,
		},
		{
			// A committed appliance may still boot fail-closed, but it is
			// not a factory boot and must not claim its first NIC.
			name:         "committed appliance in bootstrap claims nothing (#10749)",
			writeMarker:  true,
			commitConfig: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			// Repoint every path/effect this code path can reach.
			oldLinkDir := linkDir
			linkDir = filepath.Join(dir, "network")
			if err := os.MkdirAll(linkDir, 0o755); err != nil {
				t.Fatalf("mkdir linkDir: %v", err)
			}
			oldMarker := applianceMarkerFile
			applianceMarkerFile = filepath.Join(dir, "appliance")
			oldRecord := lifelineRecordFileForTest
			lifelineRecordFileForTest = filepath.Join(dir, "lifeline-interface")
			oldDetect := detectLifelineInterfaceFn
			oldEnum := enumeratePCINICsFn
			oldRename := renameInterfaceFn
			oldReload := networkctlReloadFn
			t.Cleanup(func() {
				linkDir = oldLinkDir
				applianceMarkerFile = oldMarker
				lifelineRecordFileForTest = oldRecord
				detectLifelineInterfaceFn = oldDetect
				enumeratePCINICsFn = oldEnum
				renameInterfaceFn = oldRename
				networkctlReloadFn = oldReload
			})

			// No default route — the #7114 precondition.
			detectLifelineInterfaceFn = func() (string, bool, error) { return "", false, nil }
			// One NIC whose current name differs from fxp0. The factory
			// row exercises the rename seam; the other rows must not call it.
			enumeratePCINICsFn = func() ([]pciNIC, error) {
				return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: "enp5s0"}}, nil
			}
			renamed := false
			renameInterfaceFn = func(_, _ string) error { renamed = true; return nil }
			reloaded := false
			networkctlReloadFn = func() error { reloaded = true; return nil }

			if tt.writeMarker {
				if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
					t.Fatalf("write marker: %v", err)
				}
			}

			store := newConfigStore(t, filepath.Join(dir, "xpf.conf"))
			if tt.commitConfig {
				if err := store.EnterConfigure(); err != nil {
					t.Fatalf("EnterConfigure: %v", err)
				}
				if err := store.LoadOverride("system { host-name ever-committed; }"); err != nil {
					t.Fatalf("LoadOverride: %v", err)
				}
				if _, err := store.Commit(); err != nil {
					t.Fatalf("Commit: %v", err)
				}
				store.ExitConfigure()
			}
			if got := store.EverCommitted(); got != tt.commitConfig {
				t.Fatalf("EverCommitted() = %v, want %v", got, tt.commitConfig)
			}
			d := &Daemon{store: store}
			d.setupBootstrapLifeline()

			netPath := filepath.Join(linkDir, linkPrefix+"fxp0.network")
			data, err := os.ReadFile(netPath)
			switch {
			case tt.wantNetwork && err != nil:
				t.Fatalf("expected the bootstrap fxp0 .network at %s: %v", netPath, err)
			case !tt.wantNetwork && err == nil:
				t.Fatalf("no NIC may be claimed in %q, but %s was written:\n%s",
					tt.name, netPath, data)
			}
			if renamed != tt.wantRename {
				t.Fatalf("renameInterface called = %v, want %v", renamed, tt.wantRename)
			}
			if !tt.wantNetwork {
				if reloaded {
					t.Fatal("networkctl reload ran on a host that claims nothing")
				}
				return
			}
			if got := string(data); !strings.Contains(got, "DHCP=yes") || !strings.Contains(got, "Name=fxp0") {
				t.Fatalf("bootstrap .network is not an fxp0 DHCP config:\n%s", got)
			}
			if !reloaded {
				t.Fatal("networkd was never reloaded, so the new .network never takes effect")
			}
		})
	}
}

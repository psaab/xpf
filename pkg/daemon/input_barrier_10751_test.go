package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestEarlyInputBarrierHandoffFollowsEnforcement10751(t *testing.T) {
	orig := nftInstaller
	t.Cleanup(func() { nftInstaller = orig })

	t.Run("real host-inbound install", func(t *testing.T) {
		var events []string
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(hostInboundTestConfig()); err != nil {
			t.Fatalf("apply host-inbound: %v", err)
		}
		if got := strings.Join(events, ","); got != "real,remove-input-barrier" {
			t.Fatalf("host-input lifecycle = %q, want enforcement before barrier removal", got)
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("real host-inbound table did not publish enforcement before handoff")
		}
	})

	t.Run("address-scoped fallback fence", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "fallback")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) {
			t.Fatalf("fallback apply error = %v, want real install error", err)
		}
		if got := strings.Join(events, ","); got != "real,fallback,remove-input-barrier" {
			t.Fatalf("fallback lifecycle = %q, want fence installed before barrier removal", got)
		}
		if !d.hostInboundEnforced.Load() {
			t.Fatal("address-scoped fallback did not publish enforcement before handoff")
		}
	})

	t.Run("failed fallback keeps barrier", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		fenceErr := errors.New("fallback fence load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "fallback")
				return fenceErr
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		err := d.applyHostInboundFilter(hostInboundTestConfig())
		if !errors.Is(err, installErr) || !errors.Is(err, fenceErr) {
			t.Fatalf("failed fallback error = %v, want both real and fallback failures", err)
		}
		if got := strings.Join(events, ","); got != "real,fallback" {
			t.Fatalf("failed fallback lifecycle = %q, early barrier must remain installed", got)
		}
		if d.hostInboundEnforced.Load() {
			t.Fatal("failed real and fallback installs must not publish enforcement")
		}
	})

	t.Run("zero-drop fallback keeps barrier", func(t *testing.T) {
		var events []string
		installErr := errors.New("real host-inbound load failed")
		nftInstaller = &fakeNftInstaller{
			hostInbound: func(xnft.HostInboundSpec) error {
				events = append(events, "real")
				return installErr
			},
			coldBootFence: func(xnft.FenceSpec) error {
				events = append(events, "zero-drop-fallback")
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(addresslessProgramOnlyConfig10751(t)); !errors.Is(err, installErr) {
			t.Fatalf("zero-drop fallback error = %v, want real install error", err)
		}
		if got := strings.Join(events, ","); got != "real,zero-drop-fallback" {
			t.Fatalf("zero-drop fallback lifecycle = %q, early barrier must remain until an address-scoped fence or real install", got)
		}
		if d.hostInboundEnforced.Load() {
			t.Fatal("zero-drop fallback must not claim enforcement")
		}
	})

	t.Run("no-enforcement teardown", func(t *testing.T) {
		var events []string
		nftInstaller = &fakeNftInstaller{
			del: func(name string) error {
				events = append(events, "delete:"+name)
				return nil
			},
			earlyInputBarrierRemove: func() error {
				events = append(events, "remove-input-barrier")
				return nil
			},
		}
		d := &Daemon{}
		if err := d.applyHostInboundFilter(&config.Config{}); err != nil {
			t.Fatalf("empty host-inbound teardown: %v", err)
		}
		want := []string{
			"delete:" + xnft.HostInboundTableName,
			"delete:" + xnft.HostInboundGapTableName,
			"remove-input-barrier",
		}
		if got := strings.Join(events, ","); got != strings.Join(want, ",") {
			t.Fatalf("no-enforcement lifecycle = %q, want deletions before barrier handoff %q", got, strings.Join(want, ","))
		}
	})
}

func addresslessProgramOnlyConfig10751(t *testing.T) *config.Config {
	t.Helper()
	unit := &config.InterfaceUnit{Number: 0, DHCP: true}
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"xpf10751wan": {Name: "xpf10751wan", Units: map[int]*config.InterfaceUnit{0: unit}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"untrust": {
			Name:               "untrust",
			Interfaces:         []string{"xpf10751wan.0"},
			HostInboundTraffic: &config.HostInboundTraffic{SystemServices: []string{"ssh"}},
		},
	}
	cfg.Security.AddressBook = &config.AddressBook{Addresses: map[string]*config.Address{
		"blocked-host": {Name: "blocked-host", Value: "10.0.0.5/32"},
	}}
	cfg.Security.Policies = []*config.ZonePairPolicies{{
		FromZone: "untrust",
		ToZone:   "junos-host",
		Policies: []*config.Policy{{
			Name:   "block-host",
			Action: config.PolicyDeny,
			Match:  config.PolicyMatch{SourceAddresses: []string{"blocked-host"}, Applications: []string{"any"}},
		}},
	}}
	if len(dpuserspace.BuildJunosHostPrograms(cfg)) == 0 {
		t.Fatal("program-only fixture did not produce a host-input deny program")
	}
	return cfg
}

func TestEarlyInputBarrierBootUnitAndStaging10751(t *testing.T) {
	root := transitBarrierRepoRoot9852(t)
	unit := transitBarrierReadFile9852(t, root+"/scripts/image/xpf-input-closed.service")
	code := transitBarrierUnitCodeOnly9852(unit)
	unitSection := transitBarrierSection9852(code, "Unit")
	serviceSection := transitBarrierSection9852(code, "Service")
	installSection := transitBarrierSection9852(code, "Install")
	for _, check := range []struct {
		section string
		want    string
	}{
		{section: unitSection, want: "After=nftables.service"},
		{section: unitSection, want: "Before=network-pre.target systemd-networkd.service frr.service xpfd.service"},
		{section: installSection, want: "RequiredBy=systemd-networkd.service"},
		{section: serviceSection, want: "ExecStart=/usr/local/sbin/xpfd input-barrier close"},
		{section: serviceSection, want: "Type=oneshot"},
		{section: serviceSection, want: "RemainAfterExit=yes"},
	} {
		if !strings.Contains(check.section, check.want) {
			t.Errorf("early input unit missing %q in effective section", check.want)
		}
	}
	if strings.Contains(serviceSection, "ExecStart=-") || strings.Contains(code, "transit-barrier") {
		t.Error("early host-input unit suppresses failure or shares the forward-only transit command")
	}

	checks := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "debian package",
			path: root + "/debian/rules",
			want: []string{
				"cp scripts/image/xpf-input-closed.service debian/xpf.xpf-input-closed.service",
				"dh_installsystemd --no-start --no-stop-on-upgrade --name=xpf-input-closed",
			},
		},
		{
			name: "baked image",
			path: root + "/scripts/image/bake.py",
			want: []string{
				"--copy-in\", f\"{HERE}/xpf-input-closed.service:/usr/lib/systemd/system",
				"systemctl enable xpf-input-closed.service",
			},
		},
		{
			name: "standalone Incus",
			path: root + "/test/incus/setup.sh",
			want: []string{
				"${PROJECT_ROOT}/scripts/image/xpf-input-closed.service",
				"systemctl enable --now xpf-input-closed.service",
			},
		},
		{
			name: "cluster Incus",
			path: root + "/test/incus/cluster-setup.sh",
			want: []string{
				"${PROJECT_ROOT}/scripts/image/xpf-input-closed.service",
				"systemctl enable --now xpf-input-closed.service",
			},
		},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			source := transitBarrierReadFile9852(t, check.path)
			for _, want := range check.want {
				if !strings.Contains(source, want) {
					t.Errorf("%s missing %q", check.path, want)
				}
			}
		})
	}
}

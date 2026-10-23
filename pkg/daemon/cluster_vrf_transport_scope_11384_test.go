package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

func TestClusterVRFDeviceFollowsTransportMembership11384(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		members map[string]bool
		wantVRF bool
	}{
		{
			name:    "non-member control link with unrelated management interface",
			iface:   "hb0",
			members: map[string]bool{"fxp0": true},
		},
		{
			name:    "em management transport remains in vrf-mgmt",
			iface:   "em0",
			members: map[string]bool{"em0": true, "fxp0": true},
			wantVRF: true,
		},
		{
			name:    "fabric management transport remains in vrf-mgmt",
			iface:   "fab0",
			members: map[string]bool{"fab0": true, "fxp0": true},
			wantVRF: true,
		},
		{
			name:    "Linux interface name is normalized before membership lookup",
			iface:   "fab0/0",
			members: map[string]bool{"fab0-0": true},
			wantVRF: true,
		},
		{
			name:    "different Linux interface is not mistaken for a member",
			iface:   "fab0/1",
			members: map[string]bool{"fab0-0": true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := vrfBindingTestDaemon11384(tc.members, tc.iface)
			want := ""
			if tc.wantVRF {
				want = config.ManagementVRFDeviceName
			}
			got := d.resolveClusterVRFDevice(tc.iface)
			if got != want {
				t.Errorf("resolveClusterVRFDevice(%q) = %q, want %q", tc.iface, got, want)
			}
		})
	}
}

func TestClusterSyncVRFDeviceUsesSelectedTransport11384(t *testing.T) {
	tests := []struct {
		name    string
		cc      *config.ClusterConfig
		members map[string]bool
		wantVRF bool
	}{
		{
			name: "non-member control link selected despite a management fabric",
			cc: &config.ClusterConfig{
				ControlInterface:  "hb0",
				PeerAddress:       "192.0.2.2",
				FabricInterface:   "fab0",
				FabricPeerAddress: "192.0.2.3",
			},
			members: map[string]bool{"fxp0": true, "fab0": true},
		},
		{
			name: "selected management fabric remains in vrf-mgmt",
			cc: &config.ClusterConfig{
				ControlInterface:  "hb0",
				FabricInterface:   "fab0",
				FabricPeerAddress: "192.0.2.3",
			},
			members: map[string]bool{"fxp0": true, "fab0": true},
			wantVRF: true,
		},
		{
			name: "dual fabric VRF selection follows its primary member",
			cc: &config.ClusterConfig{
				FabricInterface:    "fab0",
				FabricPeerAddress:  "192.0.2.3",
				Fabric1Interface:   "fab1",
				Fabric1PeerAddress: "192.0.2.4",
			},
			members: map[string]bool{"fab0": true, "fab1": true},
			wantVRF: true,
		},
		{
			name: "secondary outside the VRF does not veto primary binding",
			cc: &config.ClusterConfig{
				FabricInterface:    "fab0",
				FabricPeerAddress:  "192.0.2.3",
				Fabric1Interface:   "hb1",
				Fabric1PeerAddress: "192.0.2.4",
			},
			members: map[string]bool{"fab0": true, "fxp0": true},
			wantVRF: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iface := clusterSyncVRFTransportIface(tc.cc)
			d := vrfBindingTestDaemon11384(tc.members, iface)
			want := ""
			if tc.wantVRF {
				want = config.ManagementVRFDeviceName
			}
			got := d.resolveClusterSyncVRFDevice(tc.cc)
			if got != want {
				t.Errorf("resolveClusterSyncVRFDevice() = %q, want %q", got, want)
			}
		})
	}
}

func TestClusterVRFDeviceWarnsWhenTransportIsOutsideManagementVRF11384(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	if got := d.resolveClusterVRFDevice("hb0"); got != "" {
		t.Fatalf("non-member control interface was bound to %q, want no VRF binding", got)
	}
	if !strings.Contains(logs.String(), "leaving sockets unbound to VRF") {
		t.Errorf("unhonored VRF request did not warn: %s", logs.String())
	}
}

func TestClusterVRFBindingWarnsForPublishedStripped12168(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	d := vrfBindingTestDaemon11384(map[string]bool{"em0": true}, "em0")
	link, err := d.fabricLinkByName("em0")
	if err != nil {
		t.Fatal(err)
	}
	link.Attrs().MasterIndex = 0
	if got := d.transportVRFBinding(true, "em0"); got != "" {
		t.Fatalf("published but stripped interface resolved VRF device %q", got)
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("published-but-stripped interface did not warn: %s", logs.String())
	}
	for _, field := range []string{"master_index=0", "vrf=vrf-mgmt", "vrf_index=77"} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("stripped interface warning lacks %q: %s", field, logs.String())
		}
	}
}

func TestUnboundControlTransportStartsHeartbeatSocket11384(t *testing.T) {
	if local := resolveClusterInterfaceAddr(nil, "lo", "127.0.0.1", ""); local == "" {
		t.Skip("loopback has no usable IPv4 address")
	}

	manager := cluster.NewManager(0, 1)
	d := &Daemon{cluster: manager}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	vrfDevice := d.resolveClusterVRFDevice("lo")
	if vrfDevice != "" {
		t.Fatalf("non-member loopback transport was bound to %q, want main-table routing", vrfDevice)
	}

	ctx, cancel := context.WithCancel(context.Background())
	commsCtx, gen, cancelComms := d.beginClusterCommsEpoch(ctx)
	defer cancelComms()
	defer cancel()
	t.Cleanup(manager.StopHeartbeat)
	d.startHeartbeatWithRetryForEpoch(commsCtx, "lo", "127.0.0.1", gen)
	if !manager.HeartbeatRunning() {
		t.Fatal("heartbeat socket did not start without a VRF binding")
	}
}

func vrfBindingTestDaemon11384(members map[string]bool, selected ...string) *Daemon {
	vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77}}
	links := map[string]netlink.Link{config.ManagementVRFDeviceName: vrf}
	for name := range members {
		links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: len(links) + 10}}
	}
	for _, iface := range selected {
		if iface == "" {
			continue
		}
		name := config.LinuxIfName(iface)
		if _, ok := links[name]; !ok {
			links[name] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: len(links) + 10}}
		}
	}
	for name := range members {
		links[name].Attrs().MasterIndex = vrf.Attrs().Index
	}
	d := &Daemon{
		linkByNameFn: func(name string) (netlink.Link, error) {
			link, ok := links[name]
			if !ok {
				return nil, errors.New("unknown test link")
			}
			return link, nil
		},
	}
	d.publishMgmtVRFIfaces(members)
	return d
}

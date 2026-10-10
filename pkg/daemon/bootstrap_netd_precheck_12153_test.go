package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestBootstrapLifelineRefusesRenameWhenNetworkdInactive12153(t *testing.T) {
	st := staticLifelineSeams(t)
	networkdActiveFn = func() error { return errors.New("systemd-networkd is inactive") }
	detectLifelineInterfaceFn = func() (string, bool, error) {
		return "enp5s0", true, nil
	}
	enumeratePCINICsFn = func() ([]pciNIC, error) {
		return []pciNIC{{sortKey: 0, busAddr: "0000:05:00.0", name: "enp5s0"}}, nil
	}
	lifelineLinkByName = func(string) (netlink.Link, error) { return okLink(), nil }
	lifelineAddrList = func(netlink.Link, int) ([]netlink.Addr, error) {
		return []netlink.Addr{staticAddr("192.0.2.10/24")}, nil
	}
	lifelineRouteList = func(netlink.Link, int) ([]netlink.Route, error) { return nil, nil }

	dir := t.TempDir()
	d := &Daemon{store: newConfigStore(t, filepath.Join(dir, "xpf.conf"))}
	d.setupBootstrapLifeline()

	if got := filesIn(t, st.linkDir); len(got) != 0 {
		t.Errorf("inactive networkd must leave bootstrap network files untouched, got %v", got)
	}
	if _, err := os.Stat(lifelineRecordFileForTest); !os.IsNotExist(err) {
		t.Errorf("inactive networkd must not persist a lifeline record, stat err = %v", err)
	}
	if *st.renamed {
		t.Error("inactive networkd must not rename or cycle the management NIC")
	}
	if *st.reloaded {
		t.Error("inactive networkd must not trigger networkctl reload")
	}
}

func TestSystemdNetworkdActiveOnlyAcceptsActiveState12153(t *testing.T) {
	oldRun := runCommandTimeout
	t.Cleanup(func() { runCommandTimeout = oldRun })

	tests := []struct {
		name    string
		output  string
		command error
		wantErr bool
	}{
		{name: "active", output: "active\n"},
		{name: "inactive", output: "inactive\n", command: errors.New("exit status 3"), wantErr: true},
		{name: "activating", output: "activating\n", wantErr: true},
		{name: "probe failed", command: errors.New("unit unavailable"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runCommandTimeout = func(string, ...string) ([]byte, error) {
				return []byte(tt.output), tt.command
			}
			err := systemdNetworkdActive()
			if (err != nil) != tt.wantErr {
				t.Fatalf("systemdNetworkdActive() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

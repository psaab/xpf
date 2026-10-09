package dataplane

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/networkd"
	"github.com/vishvananda/netlink"
)

func TestStripUnmanagedInterfacesDeletesExternallyMatchedStaleBond12135(t *testing.T) {
	const ifindex = 4231
	bondMAC, err := net.ParseMAC("52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	bond := &netlink.Bond{LinkAttrs: netlink.LinkAttrs{
		Name:         "bond0",
		Index:        ifindex,
		HardwareAddr: bondMAC,
	}}

	oldLister, oldDelete := interfaceLister, linkDelete
	t.Cleanup(func() { interfaceLister, linkDelete = oldLister, oldDelete })
	interfaceLister = func() ([]net.Interface, error) {
		return []net.Interface{{
			Index:        ifindex,
			Name:         "bond0",
			HardwareAddr: bondMAC,
		}}, nil
	}
	var deleted netlink.Link
	linkDelete = func(link netlink.Link) error {
		deleted = link
		return nil
	}

	// An empty config represents rollback of the config that created bond0.
	// The external MAC rule matches the bond because it inherits the member MAC.
	externalDir := t.TempDir()
	externalConfig := "[Match]\nMACAddress=52:54:00:aa:bb:cc\n"
	if err := os.WriteFile(filepath.Join(externalDir, "20-external.network"), []byte(externalConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	result := &CompileResult{
		linkIdxMap: map[int]netlink.Link{ifindex: bond},
	}
	external := networkd.FindExternallyManaged(externalDir)
	if !external.Matches("bond0", bondMAC.String()) {
		t.Fatal("fixture MAC rule must match the bond")
	}
	stripUnmanagedInterfaces(&config.Config{}, result, map[string]bool{}, external)

	if deleted != bond {
		t.Fatalf("stale bond was not deleted despite external MAC match: got %v", deleted)
	}
	if len(result.ManagedInterfaces) != 0 {
		t.Fatalf("deleted stale bond was also marked unmanaged: %+v", result.ManagedInterfaces)
	}
}

// FAIL-ON-REVERT: removing the external match check in
// stripUnmanagedInterfaces must make this interface appear in
// ManagedInterfaces, proving that the compiler-side half of #12135 is live.
func TestStripUnmanagedInterfacesSkipsExternallyMatchedName12135(t *testing.T) {
	const ifindex = 4232
	mac, err := net.ParseMAC("52:54:00:aa:bb:cc")
	if err != nil {
		t.Fatal(err)
	}
	oldLister := interfaceLister
	t.Cleanup(func() { interfaceLister = oldLister })
	interfaceLister = func() ([]net.Interface, error) {
		return []net.Interface{{
			Index:        ifindex,
			Name:         "enp9s0",
			HardwareAddr: mac,
		}}, nil
	}

	externalDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(externalDir, "20-external.network"),
		[]byte("[Match]\nName=en*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	external := networkd.FindExternallyManaged(externalDir)
	result := &CompileResult{linkIdxMap: map[int]netlink.Link{
		ifindex: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Index: ifindex,
			Name:  "enp9s0",
		}},
	}}
	stripUnmanagedInterfaces(&config.Config{}, result, map[string]bool{}, external)

	if len(result.ManagedInterfaces) != 0 {
		t.Fatalf("externally matched interface was stripped under xpf control: %+v", result.ManagedInterfaces)
	}
}

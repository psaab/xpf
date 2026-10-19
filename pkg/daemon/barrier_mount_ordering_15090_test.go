package daemon

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestBarrierMountOrdering15090 is the fail-on-revert proof for #15090
// (A57-02). Both early fences use DefaultDependencies=no and exec
// /usr/local/sbin/xpfd, which after first-install seeding resolves through
// /var/lib/xpf/versions/current (pkg/upgrade runner.go DefaultVersionsDir
// + DefaultSbinDir). Without RequiresMountsFor, systemd has no ordering
// or requirement on the mount backing /var, so on a foreign host with a
// separate /var the fences can exec before var.mount, fail to resolve
// their binary, and — via RequiredBy= — block systemd-networkd (and, for
// the input fence, xpfd) from starting at all.
func TestBarrierMountOrdering15090(t *testing.T) {
	root := transitBarrierRepoRoot9852(t)
	const requiresMounts = "RequiresMountsFor=/var/lib/xpf /usr/local/sbin"

	cases := []struct {
		name       string
		file       string
		execWants  []string
		installReq []string
	}{
		{
			name: "input-closed",
			file: "xpf-input-closed.service",
			execWants: []string{
				"ExecStart=/usr/local/sbin/xpfd input-barrier ensure",
				"ExecReload=/usr/local/sbin/xpfd input-barrier ensure",
			},
			installReq: []string{
				"RequiredBy=systemd-networkd.service",
				"RequiredBy=xpfd.service",
			},
		},
		{
			name: "transit-closed",
			file: "xpf-transit-closed.service",
			execWants: []string{
				"ExecStart=/usr/local/sbin/xpfd transit-barrier close",
			},
			installReq: []string{
				"RequiredBy=systemd-networkd.service",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit := transitBarrierReadFile9852(t, filepath.Join(root, "scripts", "image", tc.file))
			code := transitBarrierUnitCodeOnly9852(unit)
			unitSection := transitBarrierSection9852(code, "Unit")
			serviceSection := transitBarrierSection9852(code, "Service")
			installSection := transitBarrierSection9852(code, "Install")

			// The cited mechanism: mount requirement in [Unit], so it
			// pulls in and orders after the mount(s) backing both the
			// sbin symlink and the versioned runtime it resolves to.
			if !strings.Contains(unitSection, requiresMounts) {
				t.Errorf("%s [Unit] missing %q; on a separate-/var host the fence can exec before var.mount", tc.file, requiresMounts)
			}
			// Control: neighbouring early-boot shape is unchanged —
			// the fence stays a DefaultDependencies=no pre-networkd unit.
			for _, want := range []string{
				"DefaultDependencies=no",
				"After=nftables.service",
				"Before=network-pre.target systemd-networkd.service frr.service xpfd.service",
			} {
				if !strings.Contains(unitSection, want) {
					t.Errorf("%s [Unit] missing control %q", tc.file, want)
				}
			}
			for _, want := range tc.execWants {
				if !strings.Contains(serviceSection, want) {
					t.Errorf("%s [Service] missing control %q", tc.file, want)
				}
			}
			for _, want := range []string{"Type=oneshot", "RemainAfterExit=yes"} {
				if !strings.Contains(serviceSection, want) {
					t.Errorf("%s [Service] missing control %q", tc.file, want)
				}
			}
			for _, want := range tc.installReq {
				if !strings.Contains(installSection, want) {
					t.Errorf("%s [Install] missing control %q", tc.file, want)
				}
			}
		})
	}
}

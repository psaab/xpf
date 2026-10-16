package daemon

import "testing"

// #13930 (H05-03): the shim XDP_PASSes every ARP frame to the kernel, and no
// xpf writer set arp_ignore, so the kernel answered at its default
// arp_ignore=0 — replying on every interface for every IPv4 address the host
// owns in the same routing instance, including addresses configured only on
// OTHER interfaces/zones. An L2-adjacent peer on an untrust segment could
// thus enumerate internal interface addresses and attract wrong-segment ARP
// ownership. Linux arp_ignore=1 replies only when the target address is
// configured on the receiving interface; arp_announce=2 avoids using a
// foreign-interface local address as the ARP sender. Both must be part of
// the host posture applied at bring-up, at the all+default scopes (new
// interfaces inherit default).
//
// These cells are fail-on-revert: deleting either scope from
// hostForwardingPostureSysctls (or changing its value) makes the
// corresponding row fail. The kernel's arp_ignore=1 behavior preserves answers
// for addresses on the receiving interface while declining addresses owned
// only by another interface.
func TestHostPostureARPIgnore13930(t *testing.T) {
	cases := []struct {
		path string
		want string
		why  string
	}{
		{"/proc/sys/net/ipv4/conf/all/arp_ignore", "1",
			"arp_ignore=1: kernel answers ARP only for target addresses configured on the receiving interface"},
		{"/proc/sys/net/ipv4/conf/default/arp_ignore", "1",
			"arp_ignore=1 must be the default so interfaces created after bring-up inherit it"},
		{"/proc/sys/net/ipv4/conf/all/arp_announce", "2",
			"arp_announce=2: ARP sender address must belong to the outgoing interface's subnet"},
		{"/proc/sys/net/ipv4/conf/default/arp_announce", "2",
			"arp_announce=2 must be the default so later-created interfaces inherit it"},
	}
	for _, tc := range cases {
		got, ok := hostForwardingPostureSysctls[tc.path]
		if !ok {
			t.Errorf("host posture missing %s (%s); pre-fix the kernel default leaves cross-interface ARP answering on (#13930)", tc.path, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("host posture %s = %q, want %q (%s)", tc.path, got, tc.want, tc.why)
		}
	}
}

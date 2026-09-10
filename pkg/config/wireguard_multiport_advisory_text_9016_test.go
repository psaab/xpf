package config

import (
	"strings"
	"testing"
)

func wgMultiportTree9016(t *testing.T, ports ...string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const peer = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	for i, p := range ports {
		name := "wg" + string(rune('0'+i))
		for _, c := range []string{
			"set interfaces " + name + " tunnel mode wireguard",
			"set interfaces " + name + " tunnel wireguard listen-port " + p,
			"set interfaces " + name + " tunnel wireguard private-key " + key,
			"set interfaces " + name + " tunnel wireguard peer " + peer + " allowed-ips 10.99.0.0/24",
		} {
			cmd, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("parse %q: %v", c, err)
			}
			if err := tree.SetPath(cmd); err != nil {
				t.Fatalf("setpath %q: %v", c, err)
			}
		}
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}

// #9016: the advisory told the operator the unsteered tunnel was "dead while
// appearing configured" and that "no handshake ever completes". Both were
// false: the host-inbound filter admits EVERY configured listen-port (see
// TestHostInboundAdmitsEveryWireGuardPort9016 in pkg/daemon) and the helper
// binds a socket per wireguard endpoint, so the unsteered port was served by
// the KERNEL path — not by nothing — and its plaintext was forwarded by the
// kernel with no zone policy.
//
// #9521 closed that bypass: the helper now DROPS a transport record that
// reaches an unsteered port's socket. That does not make "dead" or "no
// handshake ever" true — the tunnel still handshakes and still sends — so both
// stay forbidden. What changes is the description of the unsteered posture:
// #9016's "served by the KERNEL path" was the truth until the drop landed, and
// left in place it would now tell an operator their inbound traffic is being
// forwarded.
//
// Nothing bound this text before #9016, which is how a false security-relevant
// claim survived in a warning that reads as authoritative.
func TestMultiportAdvisoryDoesNotClaimTheTunnelIsDead9016(t *testing.T) {
	cfg := wgMultiportTree9016(t, "51820", "51821")
	adv := validateWireguardSingleSteeredPort(cfg)
	if len(adv) != 1 {
		t.Fatalf("two distinct listen-ports must produce exactly one advisory, got %d: %v",
			len(adv), adv)
	}
	text := adv[0]

	// The retracted claims. Each asserted a fact about the wire that is not true.
	for _, forbidden := range []string{
		"dead while appearing configured",
		"no handshake ever",
		"no inbound WireGuard transport reaches",
		"silently down",
		"and works",
		// #9521: the pre-drop description of the unsteered port. True under
		// #9016, false once the helper stopped delivering that plaintext.
		"served by the KERNEL path",
		"still receives inbound transport",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("advisory still claims %q, which is not what the unsteered port does:\n\n%s",
				forbidden, text)
		}
	}

	// What it must say instead: the port is unsteered, its kernel-path transport
	// is DROPPED, and it is NOT inert — it still handshakes.
	for _, required := range []string{"51821", "steered", "DROPPED", "Handshakes still complete"} {
		if !strings.Contains(text, required) {
			t.Fatalf("advisory omits %q:\n\n%s", required, text)
		}
	}

	// THE ASYMMETRY. This assertion was inverted once already, and the
	// inversion is the lesson.
	//
	// It used to demand that the advisory deny any difference — "no WireGuard
	// tunnel's plaintext is zone-adjudicated, steered or not". That was written
	// from the #5618 advisory, which describes the PRE-#8274 world. #8274 moved
	// the steered port's transport data into the worker, where it is adjudicated
	// under the tunnel's logical ingress zone (userspace-xdp/src/lib.rs, the
	// #8274 step 3 arm; poll_descriptor/mod.rs at the stage_wg_decap call).
	//
	// So the steered port IS adjudicated, and the other ports are different —
	// under #9016 because their plaintext was kernel-forwarded, under #9521
	// because it is dropped. Either way an advisory that denied the difference
	// would erase the one fact an operator needs, in the one message that reads
	// as authoritative on the subject.
	for _, required := range []string{
		"adjudicated under the tunnel's ingress zone",
		"REFUSED rather than forwarded unadjudicated",
		"instead of being written to its wgN TUN",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("advisory must state what differs between the steered and the "+
				"unsteered port (missing %q):\n\n%s", required, text)
		}
	}
	if strings.Contains(text, "steered or not") {
		t.Fatalf("advisory still denies the asymmetry:\n\n%s", text)
	}

	// CONTROL: one tunnel, no advisory. A check that fired always would satisfy
	// every assertion above.
	if adv := validateWireguardSingleSteeredPort(wgMultiportTree9016(t, "51820")); len(adv) != 0 {
		t.Fatalf("a single listen-port must produce NO multi-port advisory, got: %v", adv)
	}

	// CONTROL: two tunnels sharing ONE port are not a multi-port config either.
	if adv := validateWireguardSingleSteeredPort(wgMultiportTree9016(t, "51820", "51820")); len(adv) != 0 {
		t.Fatalf("two tunnels on the SAME port are all steered; no advisory is due, got: %v", adv)
	}
}

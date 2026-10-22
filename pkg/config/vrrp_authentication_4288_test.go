package config

import (
	"strings"
	"testing"
)

// #4288 (fable-review-167 I-1): VRRP authentication-type / authentication-key
// are parsed, stored on the VRRPGroup, and copied into the VRRP instance
// (pkg/vrrp/vrrp.go), but the packet build/receive path never enforces them —
// the native dataplane is RFC 5798 VRRPv3, which REMOVED authentication.
// Silently accepting the config lets an operator believe adverts are
// authenticated when they are not (a rogue host can hijack mastership). The
// honest posture is to REJECT the dead-security statement at strict commit and,
// on the tolerant load / peer-sync path, DROP the auth-carrying vrrp-group
// (fail-closed) + warn loudly — never leave it ACTIVE claiming the VIP with
// unauthenticated adverts while the operator REQUIRED auth (#5834). No-brick is
// preserved: only the one group is dropped, the base address and the rest of the
// config still boot (#1960).

// Strict commit rejects authentication-type (flat-set shape). RED-on-revert:
// dropping the #4288 gate makes CompileConfig return nil (the inert auth config
// is silently accepted — the false-security posture).
func TestVRRPAuthenticationTypeRejectedFlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-type md5",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key secret123",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of VRRP authentication, got nil")
	}
	if !strings.Contains(err.Error(), "authentication") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

const vrrpAuthHier = `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 {
                        virtual-address 10.0.61.1/24;
                        priority 200;
                        authentication-type md5;
                        authentication-key secret123;
                    }
                }
            }
        }
    }
}`

// Strict commit rejects authentication in the hierarchical (braced) shape too.
func TestVRRPAuthenticationRejectedHierarchical(t *testing.T) {
	_, err := CompileConfig(parseHierText(t, vrrpAuthHier))
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of VRRP authentication (hier), got nil")
	}
	if !strings.Contains(err.Error(), "authentication") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// Lenient (load / peer-sync): the reject downgrades to a warning so an
// already-persisted or peer-synced config an older binary silently accepted
// still boots (no-brick). RED-on-revert: without the gate there is no warning.
//
// #5834: the group must NOT be left ACTIVE. A warn-but-activate posture
// compiled the authenticated vrrp-group into unit.VRRPGroups, so pkg/vrrp
// instantiated it and it CLAIMED the VIP + exchanged UNAUTHENTICATED adverts
// while the operator REQUIRED auth — a false-security, unauthenticated group
// left running. Fail-closed: the group is DROPPED (not compiled), warned loudly.
func TestVRRPAuthenticationLenientWarns(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHierText(t, vrrpAuthHier))
	if err != nil {
		t.Fatalf("CompileConfigLenient: VRRP auth must downgrade to a warning, got error: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "authentication") && strings.Contains(w, "#4288") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a #4288 VRRP authentication warning on the lenient path, got: %v", cfg.Warnings)
	}
	// #5834 fail-closed: the auth-carrying group must NOT be compiled as an
	// active VRRP instance — it must be dropped, not left claiming the VIP with
	// unauthenticated adverts.
	if vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24"); vg != nil {
		t.Fatalf("lenient path left an auth-required vrrp-group ACTIVE (claims VIP with "+
			"unauthenticated adverts) — it must be dropped fail-closed; got: %+v", vg)
	}
}

// #5834 (fail-on-revert, flat-set shape): a tolerant load of a config whose
// vrrp-group carries authentication must DROP the group — not compile it into an
// active instance that claims the VIP and exchanges unauthenticated adverts. The
// operator's REQUIRE-auth intent wins over availability. This binds the
// validateVRRPAuthenticationAST lenient prune (compiler_interfaces.go): reverting
// it to warn-but-keep re-adds the group to unit.VRRPGroups and makes this RED.
func TestVRRPAuthenticationLenientDropsGroup_FlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-type md5",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key secret123",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: auth vrrp-group must not brick the load, got: %v", err)
	}
	// The group is dropped fail-closed — no active VRRP instance claims the VIP.
	if vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24"); vg != nil {
		t.Fatalf("flat-set lenient load left an auth-required vrrp-group ACTIVE: %+v", vg)
	}
	// Belt-and-suspenders: the whole unit must carry no compiled VRRP group.
	if ifc := cfg.Interfaces.Interfaces["reth0"]; ifc != nil {
		if unit := ifc.Units[0]; unit != nil && len(unit.VRRPGroups) != 0 {
			t.Fatalf("expected 0 compiled VRRP groups on the tolerant path, got %d: %+v",
				len(unit.VRRPGroups), unit.VRRPGroups)
		}
	}
	// And it must be a loud, value-free warning, not a silent drop.
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#5834") && strings.Contains(w, "vrrp-group 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a loud #5834 drop warning naming the group, got: %v", cfg.Warnings)
	}
}

// #5834 control: the base interface ADDRESS survives the group drop — only the
// VRRP VIP claim is failed-closed, the real address stays configured. A tolerant
// prune that nuked the whole address (or interface) would be an availability
// regression beyond the security intent.
func TestVRRPAuthenticationLenientKeepsBaseAddress(t *testing.T) {
	cfg, err := CompileConfigLenient(parseHierText(t, vrrpAuthHier))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["reth0"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatal("reth0 unit 0 must still compile — only the vrrp-group is dropped")
	}
	found := false
	for _, a := range ifc.Units[0].Addresses {
		if strings.HasPrefix(a, "10.0.61.10") {
			found = true
		}
	}
	if !found {
		t.Fatalf("base address 10.0.61.10/24 must survive the vrrp-group drop, got: %+v",
			ifc.Units[0].Addresses)
	}
}

// authentication-key WITHOUT authentication-type is also rejected — either
// statement is the misleading dead-security config.
func TestVRRPAuthenticationKeyOnlyRejected(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key onlykey",
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig: expected rejection of VRRP authentication-key, got nil")
	}
	if !strings.Contains(err.Error(), "authentication-key") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

// A normal vrrp-group WITHOUT authentication commits cleanly — the gate must
// not over-reject legitimate VRRP configs.
func TestVRRPNoAuthenticationCommits(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 priority 200",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 preempt",
	})
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: a vrrp-group without authentication must commit cleanly, got: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4288") {
			t.Fatalf("unexpected #4288 warning on a vrrp-group without authentication: %q", w)
		}
	}
	if vg := firstVRRPGroupWithVIP(t, cfg, "10.0.61.1/24"); vg == nil {
		t.Fatal("expected the vrrp-group to compile")
	}
}

// SECURITY (Copilot fable-167 review): the reject error / lenient warning must
// NOT echo the authentication-key VALUE (it is a secret). In the Keys-packed
// hierarchical leaf spelling `vrrp-group 1 authentication-key <secret>;` the
// value rides on the vrrp-group node's Keys run, so a message built from the
// full Keys would leak it into logs + CLI. The message must carry only the
// group IDENTITY (`vrrp-group 1`). RED-on-revert: building the path from n.Keys
// puts the secret into the error string.
const vrrpAuthSecret = "SUPERSECRETVRRPKEY"

func TestVRRPAuthenticationRejectDoesNotLeakSecret_KeysPacked(t *testing.T) {
	// Hierarchical leaf form packs the value onto the vrrp-group node's Keys.
	tree := parseHierText(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 authentication-key `+vrrpAuthSecret+`;
                }
            }
        }
    }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected rejection of Keys-packed VRRP authentication-key, got nil")
	}
	if strings.Contains(err.Error(), vrrpAuthSecret) {
		t.Fatalf("reject error LEAKED the authentication-key secret: %v", err)
	}
	// It must still identify the offending group without any leaf value.
	if !strings.Contains(err.Error(), "vrrp-group 1") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("reject error must name the group identity + #4288, got: %v", err)
	}
}

func TestVRRPAuthenticationRejectDoesNotLeakSecret_FlatSet(t *testing.T) {
	tree := replaySetLines(t, []string{
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 virtual-address 10.0.61.1/24",
		"set interfaces reth0 unit 0 family inet address 10.0.61.10/24 vrrp-group 1 authentication-key " + vrrpAuthSecret,
	})
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("expected rejection of flat-set VRRP authentication-key, got nil")
	}
	if strings.Contains(err.Error(), vrrpAuthSecret) {
		t.Fatalf("reject error LEAKED the authentication-key secret: %v", err)
	}
	if !strings.Contains(err.Error(), "vrrp-group 1") || !strings.Contains(err.Error(), "#4288") {
		t.Fatalf("reject error must name the group identity + #4288, got: %v", err)
	}
}

// The lenient warning must also be value-free.
func TestVRRPAuthenticationWarnDoesNotLeakSecret_KeysPacked(t *testing.T) {
	tree := parseHierText(t, `interfaces {
    reth0 {
        unit 0 {
            family inet {
                address 10.0.61.10/24 {
                    vrrp-group 1 authentication-key `+vrrpAuthSecret+`;
                }
            }
        }
    }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	sawWarn := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#4288") {
			sawWarn = true
			if strings.Contains(w, vrrpAuthSecret) {
				t.Fatalf("lenient warning LEAKED the authentication-key secret: %q", w)
			}
		}
	}
	if !sawWarn {
		t.Fatalf("expected a #4288 lenient warning, got: %v", cfg.Warnings)
	}
}

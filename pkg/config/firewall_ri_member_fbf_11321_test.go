package config

import (
	"strings"
	"testing"
)

func memberFBFTree11321(t *testing.T, family, ownerType string) *ConfigTree {
	t.Helper()
	filterFamily := family
	filterName := "member-fbf"
	member := "ge-0/0/1.0"
	if family == "inet6" {
		filterName = "member-fbf6"
	}
	source := "192.0.2.0/24"
	if family == "inet6" {
		source = "2001:db8::/64"
	}
	commands := []string{
		"set routing-instances member-ri instance-type " + ownerType,
		"set routing-instances member-ri interface " + member,
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family " + filterFamily + " filter " + filterName + " term steer from source-address " + source,
		"set firewall family " + filterFamily + " filter " + filterName + " term steer then routing-instance steer-ri",
		"set interfaces ge-0/0/1 unit 0 family " + filterFamily + " filter input " + filterName,
	}
	return buildFilterTree(t, commands...)
}

// #11321: a VRF member's kernel lookup is intercepted by the earlier l3mdev
// lookup / pref-2000 miss terminator before the FBF band, while the Rust
// session-miss helper honors explicit PBR. Strict commit rejects this divergent
// shape; tolerant load must keep booting but suppress the FBF override on both
// planes and surface the degradation. Both address families are covered.
func TestFBFOnRoutingInstanceMemberIsGatedAtCommit11321(t *testing.T) {
	for _, family := range []string{"inet", "inet6"} {
		t.Run(family, func(t *testing.T) {
			tree := memberFBFTree11321(t, family, "vrf")
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("%s FBF on a VRF member committed even though the kernel l3mdev rule and miss terminator precede the PBR band", family)
			}
			for _, want := range []string{"#11321", "routing-instance member interface", "member-ri", "pref 1000", "pref 2000", "29000-29999"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("commit error %q does not name %q", err, want)
				}
			}
		})
	}
}

func TestFBFOnRoutingInstanceMemberWarnsOnTolerantLoad11321(t *testing.T) {
	tree := memberFBFTree11321(t, "inet", "vrf")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant load must keep the prior config bootable: %v", err)
	}
	if got := cfg.Firewall.FiltersInet["member-fbf"].Terms[0].RoutingInstance; got != "steer-ri" {
		t.Fatalf("tolerant load must preserve the authored filter: got routing-instance %q, want steer-ri", got)
	}
	cloneName := cfg.Interfaces.Interfaces["ge-0/0/1"].Units[0].FilterInputV4
	clone := cfg.Firewall.FiltersInet[cloneName]
	if cloneName == "member-fbf" || clone == nil || len(clone.Terms) != 1 ||
		clone.Terms[0].RoutingInstance != "" || clone.Terms[0].Action != "accept" {
		t.Fatalf("tolerant load must rebind only the member attachment to a stripped terminal-accept clone: filter=%q clone=%+v", cloneName, clone)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "#11321") &&
			strings.Contains(warning, `filter "member-fbf"`) &&
			strings.Contains(warning, `term "steer"`) &&
			strings.Contains(warning, `member-ri`) &&
			strings.Contains(warning, "29000-29999") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant config lacks the member-FBF warning: %v", cfg.Warnings)
	}
}

// Bare RI membership fans down to every configured unit. The FBF gate must
// catch an attachment on unit 1 even when the membership names only the base.
func TestFBFOnBareRoutingInstanceMemberFansOutForGate11321(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances member-ri instance-type virtual-router",
		"set routing-instances member-ri interface ge-0/0/1",
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family inet filter member-fbf term steer from source-address 192.0.2.0/24",
		"set firewall family inet filter member-fbf term steer then routing-instance steer-ri",
		"set interfaces ge-0/0/1 unit 1 family inet filter input member-fbf",
	)
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), `member interface "ge-0/0/1.1"`) {
		t.Fatalf("bare routing-instance member must gate an FBF filter on configured unit 1, got %v", err)
	}
}

// The Linux spelling of a unit reference must resolve to the declared
// interface key used by filter attachments and the daemon's VRF binder.
func TestFBFOnLinuxAliasRoutingInstanceMemberIsGated11321(t *testing.T) {
	tree := buildFilterTree(t,
		"set routing-instances member-ri instance-type vrf",
		"set routing-instances member-ri interface ge-0-0-1.0",
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family inet filter member-fbf term steer from source-address 192.0.2.0/24",
		"set firewall family inet filter member-fbf term steer then routing-instance steer-ri",
		"set interfaces ge-0/0/1 unit 0 family inet filter input member-fbf",
	)
	_, err := CompileConfig(tree)
	if err == nil || !strings.Contains(err.Error(), "#11321") {
		t.Fatalf("Linux-name alias of a VRF member must be gated by #11321, got %v", err)
	}
}

// Forwarding instances do not bind a Linux VRF, so #11321 itself must exclude
// them from the VRF-member FBF gate. A separate #11312 validator rejects
// forwarding-instance interface members. Unattached filters also cannot make
// this specific kernel/userspace member divergence.
func TestFBFMemberGateExcludesForwardingAndUnattachedInterfaces11321(t *testing.T) {
	tree := memberFBFTree11321(t, "inet", "forwarding")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile for forwarding-member gate control: %v", err)
	}
	if warnings := memberFBFKernelBandWarnings11321(cfg); len(warnings) != 0 {
		t.Fatalf("forwarding-instance members must remain outside the VRF-member FBF gate: %v", warnings)
	}

	tree = buildFilterTree(t,
		"set routing-instances member-ri instance-type vrf",
		"set routing-instances member-ri interface ge-0/0/1.0",
		"set routing-instances steer-ri instance-type forwarding",
		"set firewall family inet filter unattached term steer from source-address 192.0.2.0/24",
		"set firewall family inet filter unattached term steer then routing-instance steer-ri",
	)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("unattached FBF definition should not be gated: %v", err)
	}
}

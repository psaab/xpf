package userspace

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7273 remaining acceptance (reopened 2026-10-19): on the tolerant /
// peer-sync path a partially-malformed referenced prefix-list must set the
// fail-closed AddressUnrepresentable wire marker, so the Rust filter
// compiler rejects the whole snapshot instead of enforcing the narrowed
// subset (Rust parse_address drops the bad entry per-token; a host in the
// dropped range would fall through to implicit accept — fail-OPEN).
//
// The strict half was already covered by
// pkg/config/prefix_list_entry_validation_7273_test.go and the snapshot
// half by #14946; this file pins the EXACT reopened scratch shape —
// filter protect-re bound as lo0 input, entries [10.0.0.0/8, 10.0.0.0/99] —
// through the public BuildFirewallFilterSnapshots entry point (the value
// buildSnapshot threads into ConfigSnapshot.Filters and `show firewall
// effective` renders), so a regression that only bypasses the internal
// builder cannot pass.
//
// FAIL-ON-REVERT: drop the referencedPrefixListHasMalformedEntry arm from
// the AddressUnrepresentable assignment in buildFilterTermSnapshots and
// TestFilterSnapshotMalformedReferencedPrefix7273 goes RED
// (addrUnrep=false, fromUnrep=false, warning only).
func TestFilterSnapshotMalformedReferencedPrefix7273(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set policy-options prefix-list mgmt 10.0.0.0/99",
		"set firewall family inet filter protect-re term t1 from source-prefix-list mgmt",
		"set firewall family inet filter protect-re term t1 then discard",
		"set interfaces lo0 unit 0 family inet filter input protect-re",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}

	// Strict control: the commit gate rejects, naming the entry.
	if _, err := config.CompileConfig(tree); err == nil {
		t.Fatal("strict compile must reject the malformed referenced entry (#7273)")
	} else {
		for _, want := range []string{"mgmt", "10.0.0.0/99", "protect-re", "t1"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("strict error does not name %q: %v", want, err)
			}
		}
	}

	// Tolerant path: warns and still boots, but the wire marker must be set.
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must remain bootable: %v", err)
	}
	if !strings.Contains(strings.Join(cfg.Warnings, "\n"), "10.0.0.0/99") {
		t.Fatalf("lenient compile must warn on the malformed entry, got %v", cfg.Warnings)
	}
	term := cfg.Firewall.FiltersInet["protect-re"].Terms[0]
	if len(term.UnknownAddresses) != 0 {
		t.Fatalf("prefix-list provenance must not masquerade as a literal record, got UnknownAddresses=%v", term.UnknownAddresses)
	}

	snaps := BuildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("snapshots = %+v, want one filter with one term", snaps)
	}
	got := snaps[0].Terms[0]
	if !got.AddressUnrepresentable {
		t.Fatalf("partially-malformed referenced prefix-list must set AddressUnrepresentable on the tolerant path (#7273 fail-open), got %+v", got)
	}
	if strings.Join(got.SourceAddresses, ",") != "10.0.0.0/8,10.0.0.0/99" {
		t.Errorf("wire addrs = %v, want verbatim [10.0.0.0/8 10.0.0.0/99] (Rust rejects the whole snapshot on the marker, never a narrowed subset)", got.SourceAddresses)
	}
	if !got.SourceConstrained {
		t.Errorf("source direction must stay constrained, got %+v", got)
	}
}

// Destination / inet6 twin through the same tolerant compile, because the
// families and directions are separate maps and arms.
func TestFilterSnapshotMalformedReferencedPrefixDest6_7273(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set policy-options prefix-list mgmt6 2001:db8::/32",
		"set policy-options prefix-list mgmt6 2001:db8::/999",
		"set firewall family inet6 filter f6 term t6 from destination-prefix-list mgmt6",
		"set firewall family inet6 filter f6 term t6 then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must remain bootable: %v", err)
	}
	snaps := BuildFirewallFilterSnapshots(cfg)
	if len(snaps) != 1 || len(snaps[0].Terms) != 1 {
		t.Fatalf("snapshots = %+v, want one filter with one term", snaps)
	}
	if !snaps[0].Terms[0].AddressUnrepresentable {
		t.Fatalf("malformed inet6 destination prefix-list entry must set AddressUnrepresentable (#7273), got %+v", snaps[0].Terms[0])
	}
}

// Control on the identical tolerant-compile path: a fully parseable
// referenced list must NOT be marked, or every legitimate prefix-list
// filter would refuse its snapshot.
func TestFilterSnapshotCleanReferencedPrefixNotMarked7273(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set policy-options prefix-list mgmt 10.0.0.0/8",
		"set policy-options prefix-list mgmt 192.168.0.0/16",
		"set firewall family inet filter protect-re term t1 from source-prefix-list mgmt",
		"set firewall family inet filter protect-re term t1 then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("set %q: %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	got := BuildFirewallFilterSnapshots(cfg)[0].Terms[0]
	if got.AddressUnrepresentable {
		t.Fatalf("clean referenced prefix-list must not set AddressUnrepresentable, got %+v", got)
	}
	if len(got.SourceAddresses) != 2 {
		t.Fatalf("clean entries must all ride the wire, got %v", got.SourceAddresses)
	}
}

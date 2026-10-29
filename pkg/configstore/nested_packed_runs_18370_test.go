package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestSyncApplyRefusesPackedNestedValueListRuns18370(t *testing.T) {
	const lists = `policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl2 { 10.1.0.0/16; }
}`
	const natPrefix = `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source { rule-set rs {
        from zone trust;
        to zone untrust;
        rule r match source-address %s { unexpected { 192.0.2.0/24; } }
    } } }
}`
	cases := []struct {
		name, text, leaf string
	}{
		{
			name: "firewall bracketed prefix-list run",
			text: lists + ` firewall { family inet { filter f {
                term t from source-prefix-list [ pl1 pl2 ] {
                    unexpected { 10.0.0.0/8; }
                }
            } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed single prefix-list with except block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list run with except block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 pl2 ] except { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed destination prefix-list with except block",
			text: lists + ` firewall { family inet { filter f { term t {
                from destination-prefix-list [ pl1 ] except { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "destination-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list with bogus postfix block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] bogus { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list except name group with block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except pl2 { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list except destination-list group with block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except destination-prefix-list [ pl2 ] { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed destination prefix-list with bogus postfix block",
			text: lists + ` firewall { family inet { filter f { term t {
                from destination-prefix-list [ pl1 ] bogus { unexpected { 10.0.0.0/8; } }
                then accept; } } } }`,
			leaf: "destination-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list except payload block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except { 10.0.0.0/8; }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list except leaf-only block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except { unexpected; }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "firewall bracketed prefix-list except empty block",
			text: lists + ` firewall { family inet { filter f { term t {
                from source-prefix-list [ pl1 ] except { }
                then accept; } } } }`,
			leaf: "source-prefix-list",
		},
		{
			name: "NAT bracketed address with bogus postfix block",
			text: fmtNATPrefix18370(natPrefix, "[ 10.0.0.0/8 ] bogus"),
			leaf: "source-address",
		},
		{
			name: "NAT bracketed source-address with except postfix block",
			text: fmtNATPrefix18370(natPrefix, "[ 10.0.0.0/8 ] except"),
			leaf: "source-address",
		},
		{
			name: "NAT bracketed destination-address with except postfix block",
			text: `security {
    zones { security-zone trust; security-zone untrust; }
    nat { source { rule-set rs {
        from zone trust;
        to zone untrust;
        rule r match destination-address [ 10.0.0.0/8 ] except { unexpected { 192.0.2.0/24; } }
    } } }
}`,
			leaf: "destination-address",
		},
		{
			name: "NAT bracketed address run",
			text: fmtNATPrefix18370(natPrefix, "[ 10.0.0.0/8 192.168.0.0/16 ]"),
			leaf: "source-address",
		},
		{
			name: "NAT unbracketed address run",
			text: fmtNATPrefix18370(natPrefix, "10.0.0.0/8 192.168.0.0/16"),
			leaf: "source-address",
		},
		{
			name: "apply-groups inherited unbracketed prefix-list run",
			text: lists + ` groups { g { firewall { family inet { filter f {
                term t from source-prefix-list pl1 pl2 {
                    unexpected { 10.0.0.0/8; }
                }
            } } } } }
            firewall { apply-groups g; }`,
			leaf: "source-prefix-list",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
			baseline, err := s.SyncApply(`system { host-name baseline; }`, nil)
			if err != nil || baseline == nil {
				t.Fatalf("install control baseline: cfg=%v err=%v", baseline, err)
			}
			beforeSet := s.ShowActiveSet()

			cfg, err := s.SyncApply(tc.text, nil)
			if err == nil || !config.IsNestedListContentSchemaError(err) {
				t.Fatalf("SyncApply must hard-reject nested content under %s, got cfg=%v err=%v", tc.leaf, cfg, err)
			}
			if !strings.Contains(err.Error(), tc.leaf) || !strings.Contains(err.Error(), "nested content") {
				t.Fatalf("nested-content error %q must name %s", err, tc.leaf)
			}
			if cfg != nil || s.ActiveConfig() != baseline {
				t.Fatalf("SyncApply replaced active config after refusal: cfg=%v active=%p baseline=%p", cfg, s.ActiveConfig(), baseline)
			}
			if got := s.ShowActiveSet(); got != beforeSet {
				t.Fatalf("SyncApply changed active config after refusal:\nbefore:\n%s\nafter:\n%s", beforeSet, got)
			}
		})
	}
}

func fmtNATPrefix18370(template, values string) string {
	return strings.Replace(template, "%s", values, 1)
}

func TestSyncApplyAcceptsValidBracketedPrefixList18370(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl2 { 10.1.0.0/16; }
}
firewall { family inet { filter f { term t from source-prefix-list [ pl1 pl2 ] then accept; } } }`, nil)
	if err != nil || cfg == nil {
		t.Fatalf("SyncApply rejected valid bracketed prefix-list references: cfg=%v err=%v", cfg, err)
	}
}

func TestSyncApplyAcceptsValidBracketedNATSourceAddresses18370(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`security {
    zones { security-zone trust; security-zone untrust; }
    nat { source { rule-set rs {
        from zone trust;
        to zone untrust;
        rule r match source-address [ 10.0.0.0/8 192.168.0.0/16 ] then source-nat interface;
    } } }
}`, nil)
	if err != nil || cfg == nil {
		t.Fatalf("SyncApply rejected valid bracketed NAT source-address list: cfg=%v err=%v", cfg, err)
	}
}

func TestSyncApplyAcceptsValidUnbracketedPrefixListBeforeThen18370(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
}
firewall { family inet { filter f { term t from source-prefix-list pl1 then accept; } } }`, nil)
	if err != nil || cfg == nil {
		t.Fatalf("SyncApply rejected valid unbracketed prefix-list before then sibling: cfg=%v err=%v", cfg, err)
	}
}

func TestSyncApplyAcceptsValidBracketedPrefixListExcept18370(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
}
firewall { family inet { filter f { term t {
    from { source-prefix-list [ pl1 ] except; }
    then accept;
} } } }`, nil)
	if err != nil || cfg == nil {
		t.Fatalf("SyncApply rejected valid bracketed prefix-list except: cfg=%v err=%v", cfg, err)
	}
}

func TestSyncApplyAcceptsNoBlockExceptNameGroup18370(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`policy-options {
    prefix-list pl1 { 10.0.0.0/8; }
    prefix-list pl2 { 10.1.0.0/16; }
}
firewall { family inet { filter f { term t {
    from source-prefix-list [ pl1 ] except pl2;
    then accept;
} } } }`, nil)
	if err != nil || cfg == nil {
		t.Fatalf("SyncApply rejected valid no-block except name group: cfg=%v err=%v", cfg, err)
	}
}

func TestSyncApplyAcceptsPackedNATMatchWithBracedThenSibling18370(t *testing.T) {
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	cfg, err := s.SyncApply(`security {
    zones { security-zone trust; security-zone untrust; }
    nat { source { rule-set rs {
        from zone trust;
        to zone untrust;
        rule r match source-address [ 10.0.0.0/8 ] {
            then { source-nat interface; }
        }
    } } }
}`, nil)
	if err != nil || cfg == nil {
		t.Fatalf("SyncApply rejected valid packed NAT match with braced then sibling: cfg=%v err=%v", cfg, err)
	}
}

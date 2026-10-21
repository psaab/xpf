package config

import (
	"strconv"
	"strings"
	"testing"
)

func TestOSPFAreaInterfaceReuseRejected11400(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmds []string
		want string
	}{
		{
			name: "ospfv2 global",
			cmds: []string{
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
				"set protocols ospf area 0.0.0.1 interface ge-0/0/1.0",
			},
			want: "OSPF",
		},
		{
			name: "ospfv3 global",
			cmds: []string{
				"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0",
				"set protocols ospf3 area 0.0.0.1 interface ge-0/0/1.0",
			},
			want: "OSPFv3",
		},
		{
			name: "resolved aliases in a routing instance",
			cmds: []string{
				"set routing-instances blue instance-type virtual-router",
				"set routing-instances blue protocols ospf area 0.0.0.0 interface ge-0/0/1.0",
				"set routing-instances blue protocols ospf area 0.0.0.1 interface ge-0-0-1.0",
			},
			want: "routing-instances \"blue\"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileConfig(buildTree(t, tc.cmds))
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "multiple areas") {
				t.Fatalf("strict compile error = %v, want a cross-area interface diagnostic containing %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "ge-0-0-1") {
				t.Fatalf("diagnostic does not name the resolved Linux interface: %v", err)
			}
		})
	}
}

func TestOSPFAreaInterfaceReuseLenientWarns11400(t *testing.T) {
	cfg, err := CompileConfigLenient(buildTree(t, []string{
		"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0",
		"set protocols ospf3 area 0.0.0.1 interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("lenient compile rejected an existing cross-area interface: %v", err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "OSPF interface area membership") &&
			strings.Contains(warning, "OSPFv3") && strings.Contains(warning, "multiple areas") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("lenient compile did not warn about OSPFv3 cross-area membership: %v", cfg.Warnings)
	}
	if cfg.Protocols.OSPFv3 == nil || len(cfg.Protocols.OSPFv3.Areas) != 2 {
		t.Fatalf("lenient compile must preserve the configured areas for readback: %+v", cfg.Protocols.OSPFv3)
	}
}

func TestOSPFAreaInterfaceReuseEquivalentIDsAccepted11400(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 1 interface ge-0/0/1.0",
		"set protocols ospf area 0.0.0.1 interface ge-0/0/1.0",
	}))
	if err != nil {
		t.Fatalf("equivalent integer and dotted-quad spellings of area 1 are one area: %v", err)
	}
}

func TestOSPFAreaInterfaceAliasConflictsStrict12186(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol string
		left     string
		right    string
		field    string
		secrets  []string
	}{
		{name: "v2 cost", protocol: "ospf", left: "cost 10", right: "cost 20", field: "cost"},
		{name: "v2 hello", protocol: "ospf", left: "hello-interval 5", right: "hello-interval 10", field: "hello-interval"},
		{name: "v2 dead", protocol: "ospf", left: "dead-interval 20", right: "dead-interval 40", field: "dead-interval"},
		{name: "v2 retransmit", protocol: "ospf", left: "retransmit-interval 3", right: "retransmit-interval 5", field: "retransmit-interval"},
		{name: "v2 explicit zero priority", protocol: "ospf", left: "priority 0", right: "priority 1", field: "priority"},
		{name: "v2 network type", protocol: "ospf", left: "interface-type point-to-point", right: "interface-type broadcast", field: "interface-type"},
		{name: "v2 simple secret", protocol: "ospf", left: "authentication simple-password SECRET-A", right: "authentication simple-password SECRET-B", field: "authentication simple-password", secrets: []string{"SECRET-A", "SECRET-B"}},
		{name: "v2 auth type", protocol: "ospf", left: "authentication md5 7 key SECRET-A", right: "authentication simple-password SECRET-B", field: "authentication-type", secrets: []string{"SECRET-A", "SECRET-B"}},
		{name: "v2 MD5 same ID secret", protocol: "ospf", left: "authentication md5 7 key SECRET-A", right: "authentication md5 7 key SECRET-B", field: "authentication md5 key", secrets: []string{"SECRET-A", "SECRET-B"}},
		{name: "v2 BFD interval", protocol: "ospf", left: "bfd-liveness-detection minimum-interval 100", right: "bfd-liveness-detection minimum-interval 200", field: "bfd-liveness-detection minimum-interval"},
		{name: "v2 BFD multiplier", protocol: "ospf", left: "bfd-liveness-detection multiplier 3", right: "bfd-liveness-detection multiplier 5", field: "bfd-liveness-detection multiplier"},
		{name: "v3 cost", protocol: "ospf3", left: "cost 10", right: "cost 20", field: "cost"},
		{name: "v3 hello", protocol: "ospf3", left: "hello-interval 5", right: "hello-interval 10", field: "hello-interval"},
		{name: "v3 dead", protocol: "ospf3", left: "dead-interval 20", right: "dead-interval 40", field: "dead-interval"},
		{name: "v3 retransmit", protocol: "ospf3", left: "retransmit-interval 3", right: "retransmit-interval 5", field: "retransmit-interval"},
		{name: "v3 explicit zero priority", protocol: "ospf3", left: "priority 0", right: "priority 1", field: "priority"},
		{name: "v3 BFD interval", protocol: "ospf3", left: "bfd-liveness-detection minimum-interval 100", right: "bfd-liveness-detection minimum-interval 200", field: "bfd-liveness-detection minimum-interval"},
		{name: "v3 BFD multiplier", protocol: "ospf3", left: "bfd-liveness-detection multiplier 3", right: "bfd-liveness-detection multiplier 5", field: "bfd-liveness-detection multiplier"},
	} {
		for _, reverse := range []bool{false, true} {
			t.Run(tc.name+"/reverse="+strconv.FormatBool(reverse), func(t *testing.T) {
				left := "set protocols " + tc.protocol + " area 0 interface ge-0/0/1.0 " + tc.left
				right := "set protocols " + tc.protocol + " area 0 interface ge-0-0-1.0 " + tc.right
				if reverse {
					left, right = right, left
				}
				_, err := CompileConfig(buildTree(t, []string{left, right}))
				if err == nil || !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("strict compile error = %v, want conflict field %q", err, tc.field)
				}
				if !strings.Contains(err.Error(), "ge-0-0-1") {
					t.Fatalf("strict conflict must name the resolved Linux interface: %v", err)
				}
				for _, secret := range tc.secrets {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("strict diagnostic leaked an authentication value: %v", err)
					}
				}
			})
		}
	}
}

func TestOSPFAreaInterfaceEquivalentAreaConflictStrict12186(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run("reverse="+strconv.FormatBool(reverse), func(t *testing.T) {
			first := "set protocols ospf area 1 interface ge-0-0-1 cost 10"
			second := "set protocols ospf area 0.0.0.1 interface ge-0-0-1 cost 20"
			if reverse {
				first, second = second, first
			}
			_, err := CompileConfig(buildTree(t, []string{first, second}))
			if err == nil || !strings.Contains(err.Error(), "cost") {
				t.Fatalf("equivalent-area conflict error = %v, want cost conflict", err)
			}
		})
	}
}

func TestOSPFAreaInterfaceAliasConflictLenientWarns12186(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run("reverse="+strconv.FormatBool(reverse), func(t *testing.T) {
			first := "set protocols ospf area 0 interface ge-0/0/1.0 authentication simple-password SECRET-A"
			second := "set protocols ospf area 0 interface ge-0-0-1.0 authentication simple-password SECRET-B"
			if reverse {
				first, second = second, first
			}
			cfg, err := CompileConfigLenient(buildTree(t, []string{first, second}))
			if err != nil {
				t.Fatalf("lenient compile rejected an alias conflict: %v", err)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "OSPF interface area membership") &&
					strings.Contains(warning, "authentication simple-password") {
					found = true
				}
				if strings.Contains(warning, "SECRET-A") || strings.Contains(warning, "SECRET-B") {
					t.Fatalf("lenient diagnostic leaked an authentication value: %q", warning)
				}
			}
			if !found {
				t.Fatalf("lenient compile did not warn about the alias auth conflict: %v", cfg.Warnings)
			}
			if cfg.Protocols.OSPF == nil || len(cfg.Protocols.OSPF.Areas) != 1 ||
				len(cfg.Protocols.OSPF.Areas[0].Interfaces) != 2 {
				t.Fatalf("lenient compile must preserve both authored aliases for readback: %+v", cfg.Protocols.OSPF)
			}
		})
	}
}

func TestOSPFAreaInterfaceUnionDefaultsAndMD5Rollover12186(t *testing.T) {
	var union OSPFInterfaceUnion12186
	keys := []OSPFMD5Key12186{{ID: 7, Key: NewSecret("rollover-seven")}}
	first := &OSPFInterface{
		Name: "ge-0/0/1.0", Cost: 10, Passive: true, BFD: true,
		AuthType: "md5", AuthKeyID: 7, AuthKey: keys[0].Key, AuthMD5Keys: keys,
	}
	if conflicts := union.Merge(first); len(conflicts) != 0 {
		t.Fatalf("first MD5 fragment conflicts: %v", conflicts)
	}
	second := &OSPFInterface{
		Name: "ge-0-0-1.0", HelloInterval: 5, NoPassive: true,
		HasPriority: true, Priority: 0,
		AuthType: "md5", AuthKeyID: 8, AuthKey: NewSecret("rollover-eight"),
		AuthMD5Keys: []OSPFMD5Key12186{{ID: 8, Key: NewSecret("rollover-eight")}},
	}
	if conflicts := union.Merge(second); len(conflicts) != 0 {
		t.Fatalf("disjoint/default fields or distinct MD5 IDs conflicted: %v", conflicts)
	}
	if conflicts := union.Merge(&OSPFInterface{
		AuthType: "md5", AuthMD5Keys: []OSPFMD5Key12186{{ID: 7, Key: NewSecret("rollover-seven")}},
	}); len(conflicts) != 0 || len(union.MD5Keys) != 2 {
		t.Fatalf("repeated identical key ID should be idempotent: conflicts=%v keys=%v", conflicts, union.MD5Keys)
	}
	if conflicts := union.Merge(&OSPFInterface{Cost: 20}); len(conflicts) != 1 ||
		conflicts[0] != "cost" || union.Cost != 10 {
		t.Fatalf("scalar conflict should report its field and retain the first value: conflicts=%v cost=%d", conflicts, union.Cost)
	}
	var incompleteKeyUnion OSPFInterfaceUnion12186
	incompleteKeyUnion.Merge(&OSPFInterface{
		AuthType: "md5", AuthKeyID: 9,
		AuthMD5Keys: []OSPFMD5Key12186{{ID: 9}},
	})
	if conflicts := incompleteKeyUnion.Merge(&OSPFInterface{
		AuthType: "md5", AuthKeyID: 9, AuthKey: NewSecret("filled-key"),
		AuthMD5Keys: []OSPFMD5Key12186{{ID: 9, Key: NewSecret("filled-key")}},
	}); len(conflicts) != 0 || len(incompleteKeyUnion.MD5Keys) != 1 ||
		incompleteKeyUnion.MD5Keys[0].Key != NewSecret("filled-key") {
		t.Fatalf("an absent same-ID key should be filled, not conflict: conflicts=%v keys=%v", conflicts, incompleteKeyUnion.MD5Keys)
	}
	if union.Name != first.Name || union.Cost != 10 || union.HelloInterval != 5 ||
		!union.Passive || !union.NoPassive || !union.BFD || !union.HasPriority ||
		union.Priority != 0 || len(union.MD5Keys) != 2 {
		t.Fatalf("union did not preserve first-present values and combine disjoint settings: %+v", union)
	}
	first.AuthMD5Keys[0].Key = NewSecret("mutated-input")
	if union.MD5Keys[0].Key != NewSecret("rollover-seven") {
		t.Fatal("union aliases the source MD5 key slice")
	}

	cfg, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 7 key rollover-seven",
		"set protocols ospf area 0 interface ge-0-0-1.0 authentication md5 8 key rollover-eight",
	}))
	if err != nil {
		t.Fatalf("distinct MD5 rollover IDs on equivalent aliases must compile: %v", err)
	}
	var retained int
	for _, iface := range cfg.Protocols.OSPF.Areas[0].Interfaces {
		retained += len(iface.AuthMD5Keys)
	}
	if retained != 2 {
		t.Fatalf("compiler retained %d rollover keys, want both IDs", retained)
	}
}

func TestOSPFCompilerKeepsSameInterfaceMD5Rollover12186(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 7 key same-interface-seven",
		"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 8 key same-interface-eight",
	}))
	if err != nil {
		t.Fatalf("multiple MD5 key IDs on one authored interface must compile: %v", err)
	}
	ifaces := cfg.Protocols.OSPF.Areas[0].Interfaces
	if len(ifaces) != 1 {
		t.Fatalf("same authored interface compiled to %d model entries, want one", len(ifaces))
	}
	iface := ifaces[0]
	wantKeys := map[int]Secret{7: NewSecret("same-interface-seven"), 8: NewSecret("same-interface-eight")}
	if len(iface.AuthMD5Keys) != len(wantKeys) {
		t.Fatalf("same-interface MD5 rollover retained %d keys, want %d: %+v", len(iface.AuthMD5Keys), len(wantKeys), iface.AuthMD5Keys)
	}
	for _, key := range iface.AuthMD5Keys {
		if want, ok := wantKeys[key.ID]; !ok || key.Key != want {
			t.Fatalf("same-interface MD5 rollover key ID %d has unexpected secret", key.ID)
		}
	}
	if iface.AuthKeyID != 8 || iface.AuthKey != NewSecret("same-interface-eight") {
		t.Fatalf("legacy MD5 fields no longer expose the last configured key: ID=%d", iface.AuthKeyID)
	}
}

func TestOSPFAreaInterfaceConflictIsolationNamespaces12186(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0 interface ge-0/0/1.0 cost 10",
		"set protocols ospf3 area 1 interface ge-0/0/1.0 cost 20",
		"set routing-instances blue instance-type virtual-router",
		"set routing-instances blue protocols ospf area 0 interface ge-0/0/1.0 cost 30",
	}))
	if err != nil {
		t.Fatalf("global and VRF OSPF settings have independent namespaces: %v", err)
	}
}

func TestOSPFAreaInterfaceMD5SameIDConflictRedacted12186(t *testing.T) {
	const secretA = "conflicting-md5-key-A"
	const secretB = "conflicting-md5-key-B"
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 7 key " + secretA,
		"set protocols ospf area 0 interface ge-0-0-1.0 authentication md5 7 key " + secretB,
	}))
	if err == nil || !strings.Contains(err.Error(), "authentication md5 key") {
		t.Fatalf("same-ID MD5 key conflict error = %v, want redacted key conflict", err)
	}
	if strings.Contains(err.Error(), secretA) || strings.Contains(err.Error(), secretB) {
		t.Fatalf("same-ID MD5 conflict diagnostic leaked a key value: %v", err)
	}
}

func TestOSPFAreaInterfaceAuthTypeConflictDoesNotCrossApply12186(t *testing.T) {
	const md5Key = "md5-key-value"
	const simpleKey = "simple-key-value"
	var md5First OSPFInterfaceUnion12186
	md5First.Merge(&OSPFInterface{
		AuthType: "md5", AuthKeyID: 7, AuthKey: NewSecret(md5Key),
		AuthMD5Keys: []OSPFMD5Key12186{{ID: 7, Key: NewSecret(md5Key)}},
	})
	conflicts := md5First.Merge(&OSPFInterface{AuthType: "simple", AuthKey: NewSecret(simpleKey)})
	if len(conflicts) != 1 || conflicts[0] != "authentication-type" ||
		len(md5First.MD5Keys) != 1 || md5First.MD5Keys[0].Key != NewSecret(md5Key) {
		t.Fatalf("MD5-first merge cross-applied incompatible simple auth: conflicts=%v state=%+v", conflicts, md5First)
	}

	var simpleFirst OSPFInterfaceUnion12186
	simpleFirst.Merge(&OSPFInterface{AuthType: "simple", AuthKey: NewSecret(simpleKey)})
	conflicts = simpleFirst.Merge(&OSPFInterface{
		AuthType: "md5", AuthKeyID: 7, AuthKey: NewSecret(md5Key),
		AuthMD5Keys: []OSPFMD5Key12186{{ID: 7, Key: NewSecret(md5Key)}},
	})
	if len(conflicts) != 1 || conflicts[0] != "authentication-type" ||
		len(simpleFirst.MD5Keys) != 0 || simpleFirst.AuthKey != NewSecret(simpleKey) {
		t.Fatalf("simple-first merge cross-applied incompatible MD5 auth: conflicts=%v state=%+v", conflicts, simpleFirst)
	}
}

func TestOSPFAreaInterfaceMD5RangeChecksEveryRolloverKey12186(t *testing.T) {
	_, err := CompileConfig(buildTree(t, []string{
		"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 999 key invalid-first-key",
		"set protocols ospf area 0 interface ge-0/0/1.0 authentication md5 7 key valid-last-key",
	}))
	if err == nil || !strings.Contains(err.Error(), "999") {
		t.Fatalf("strict compile error = %v, want rejection of the out-of-range rollover key ID", err)
	}
}

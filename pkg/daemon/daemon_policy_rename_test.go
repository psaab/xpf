package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"golang.org/x/sync/semaphore"
)

func TestZoneRenamePathRequiresTerminalSecurityZone(t *testing.T) {
	tests := []struct {
		name string
		path []string
		want string
		ok   bool
	}{
		{
			name: "full config path",
			path: []string{"security", "zones", "security-zone", "trust"},
			want: "trust",
			ok:   true,
		},
		{
			name: "nested leaf is not a zone rename",
			path: []string{"security", "zones", "security-zone", "trust", "interfaces", "ge-0/0/0.0"},
		},
		{
			name: "missing zone name",
			path: []string{"security", "zones", "security-zone"},
		},
		{
			name: "wrong parent",
			path: []string{"security", "zones", "zone", "trust"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := zoneRenamePath(tt.path)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("zoneRenamePath(%q) = (%q, %v), want (%q, %v)", tt.path, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestPolicyRulePathKeyRequiresTerminalPolicy(t *testing.T) {
	valid := []string{"security", "policies", "from-zone", "trust", "to-zone", "untrust", "policy", "web"}
	if from, to, name, ok := policyRulePathKey(valid); !ok || from != "trust" || to != "untrust" || name != "web" {
		t.Fatalf("policyRulePathKey(%q) = (%q, %q, %q, %v), want trust/untrust/web/true", valid, from, to, name, ok)
	}
	nested := append(append([]string(nil), valid...), "match", "source-address")
	if _, _, _, ok := policyRulePathKey(nested); ok {
		t.Fatalf("policyRulePathKey(%q) accepted a nested policy leaf", nested)
	}
	global := []string{"security", "policies", "global", "policy", "web"}
	if from, to, name, ok := policyRulePathKey(global); !ok ||
		from != config.JunosGlobalZoneName || to != config.JunosGlobalZoneName || name != "web" {
		t.Fatalf("policyRulePathKey(%q) = (%q, %q, %q, %v), want global/global/web/true", global, from, to, name, ok)
	}
}

func TestRenameZoneWireIdentityKeepsSpecialScopesExplicit(t *testing.T) {
	zones := map[uint16]string{config.StableZoneID("trust"): "trust"}
	tests := []struct {
		name string
		zone string
		id   uint16
		any  bool
		ok   bool
	}{
		{name: "concrete", zone: "trust", id: config.StableZoneID("trust"), ok: true},
		{name: "wildcard", zone: "any", any: true, ok: true},
		{name: "global", zone: config.JunosGlobalZoneName, id: ^uint16(0), ok: true},
		{name: "host", zone: "junos-host", id: config.ZoneIDReservedMin, ok: true},
		{name: "unknown concrete", zone: "missing", id: config.StableZoneID("missing")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, any, ok := renameZoneWireIdentity(tt.zone, zones)
			if id != tt.id || any != tt.any || ok != tt.ok {
				t.Fatalf("renameZoneWireIdentity(%q) = (%d, %v, %v), want (%d, %v, %v)", tt.zone, id, any, ok, tt.id, tt.any, tt.ok)
			}
		})
	}
}

func policyRenameEvaluatorConfig(ruleName string, action config.PolicyAction) *config.Config {
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"lan":   {Name: "lan"},
		"other": {Name: "other"},
		"wan":   {Name: "wan"},
	}
	cfg.Security.DefaultPolicy = config.PolicyDeny
	cfg.Security.PolicyRematchExtensive = true
	cfg.Security.Policies = []*config.ZonePairPolicies{
		{
			FromZone: "other",
			ToZone:   "wan",
			Policies: []*config.Policy{{Name: "p-seed", Action: config.PolicyDeny}},
		},
		{
			FromZone: "lan",
			ToZone:   "wan",
			Policies: []*config.Policy{
				{Name: ruleName, Action: action},
				{Name: "p-alternate", Action: config.PolicyPermit},
			},
		},
	}
	return cfg
}

func policyRenameDescriptor(source, destination string) configstore.RenameDescriptor {
	return configstore.RenameDescriptor{
		SourcePath: []string{
			"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", source,
		},
		DestinationPath: []string{
			"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", destination,
		},
	}
}

func TestExpandAndRematchPolicyRenameEvaluator10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	bindings, wire, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok || len(bindings) != 1 || len(wire) != 1 {
		t.Fatalf("valid policy rename was rejected: bindings=%v wire=%v ok=%v", bindings, wire, ok)
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding, ok := bindings[oldID]
	if !ok {
		t.Fatalf("missing binding for old policy id %d: %v", oldID, bindings)
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 0, 10},
		DstIP:    [4]byte{10, 0, 0, 20},
		SrcPort:  1234,
		DstPort:  443,
		Protocol: 6,
	}
	value := dataplane.SessionValue{
		PolicyID:    oldID,
		IngressZone: config.StableZoneID("lan"),
		EgressZone:  config.StableZoneID("wan"),
	}
	record, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value)
	if !permitted {
		t.Fatal("matching renamed session was not retained")
	}
	if record.RuleID != "lan->wan/p-new" || record.PolicyID == 0 ||
		record.IngressZone != config.StableZoneID("lan") ||
		record.EgressZone != config.StableZoneID("wan") {
		t.Fatalf("renamed record lost identity: %+v", record)
	}
	if record.SrcIP != "10.0.0.10" || record.DstIP != "10.0.0.20" ||
		record.Protocol != 6 {
		t.Fatalf("renamed record lost tuple: %+v", record)
	}
}

func TestPolicyRenameEvaluatorHonorsInjectedSchedulerState10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	oldCfg.Security.Policies[1].Policies[0].SchedulerName = "all-day"
	newCfg.Security.Policies[1].Policies[0].SchedulerName = "all-day"
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	value := dataplane.SessionValue{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
	}
	binding := bindings[oldID]
	binding.policyInactiveFn = func(string) bool { return true }
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value); permitted {
		t.Fatal("scheduler-inactive renamed policy was retained")
	}
	binding.policyInactiveFn = func(string) bool { return false }
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, binding, key, value); !permitted {
		t.Fatal("scheduler-active renamed policy was not retained")
	}
}

func TestPolicyRenameEvaluatorHandlesDNATV4AndV6Rows10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	// Scope the renamed rule to the TRANSLATED dsts only: the wire dsts must
	// not match, so a revert that drops the DNAT-dst consult queries the wire
	// dst, misses, and fails this cell instead of passing on match-any.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses =
			[]string{"10.0.0.1/32", "2001:db8::30/128"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	binding := bindings[oldID]
	v4Key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	v4Value := dataplane.SessionValue{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags: dataplane.SessFlagDNAT, NATDstIP: 0x0100000a, NATDstPort: 8443,
	}
	record, permitted := rematchRenamedV4(oldCfg, newCfg, binding, v4Key, v4Value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("DNAT v4 row was not rematched through the renamed permit: %+v permitted=%v", record, permitted)
	}
	// Fixture guard: without translation the wire tuple must NOT match the
	// renamed rule. If the scope above ever widens to cover it, this reds;
	// without it the positive assertion would pass vacuously on the wire.
	plainV4 := v4Value
	plainV4.Flags, plainV4.NATDstIP, plainV4.NATDstPort = 0, 0, 0
	if record, _ := rematchRenamedV4(oldCfg, newCfg, binding, v4Key, plainV4); record.RuleID == "lan->wan/p-new" {
		t.Fatalf("untranslated v4 wire tuple matched the renamed rule: %+v", record)
	}
	v6Key := dataplane.SessionKeyV6{
		SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
		DstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	v6Value := dataplane.SessionValueV6{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags:      dataplane.SessFlagDNAT,
		NATDstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30},
		NATDstPort: 8443,
	}
	record, permitted = rematchRenamedV6(oldCfg, newCfg, binding, v6Key, v6Value)
	if !permitted || record.RuleID != "lan->wan/p-new" {
		t.Fatalf("DNAT v6 row was not rematched through the renamed permit: %+v permitted=%v", record, permitted)
	}
	plainV6 := v6Value
	plainV6.Flags, plainV6.NATDstPort = 0, 0
	plainV6.NATDstIP = [16]byte{}
	if record, _ := rematchRenamedV6(oldCfg, newCfg, binding, v6Key, plainV6); record.RuleID == "lan->wan/p-new" {
		t.Fatalf("untranslated v6 wire tuple matched the renamed rule: %+v", record)
	}
}

// Inbound NPTv6 populates decision.nat.rewrite_dst with the translated
// internal dst and no port rewrite
// (userspace-dp/src/afxdp/poll_descriptor/mod.rs, MissingNeighbor cold-path
// comment), and session flags derive solely from rewrite_src/rewrite_dst
// (bpf_map/mod.rs: no SESS_FLAG_NPTV6 exists on the helper; the Go constant is
// ABI width documentation only and nothing stamps it). So an NPTv6 row reaches
// the capture indistinguishable from DNAT — DNAT flag, translated NATDstIP,
// zero port — and rematches through the same translated-dst path. This cell
// pins that shape explicitly: dropping the DNAT-dst consult would fail to
// retain it, while a port-rewrite requirement would wrongly reject it.
func TestPolicyRenameEvaluatorRematchesNPTv6ShapedRow10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	// Scope the renamed rule to the translated internal dst: the public wire
	// dst must not match, so the cell reds unless the rematch consults the
	// translated dst carried on the DNAT channel.
	for _, cfg := range []*config.Config{oldCfg, newCfg} {
		cfg.Security.Policies[1].Policies[0].Match.DestinationAddresses =
			[]string{"fd00::20/128"}
	}
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	key := dataplane.SessionKeyV6{
		SrcIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a},
		DstIP:   [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x14},
		SrcPort: 1234, DstPort: 443, Protocol: 6,
	}
	value := dataplane.SessionValueV6{
		PolicyID: oldID, IngressZone: config.StableZoneID("lan"), EgressZone: config.StableZoneID("wan"),
		Flags:    dataplane.SessFlagDNAT,
		NATDstIP: [16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20},
	}
	record, permitted := rematchRenamedV6(oldCfg, newCfg, bindings[oldID], key, value)
	if !permitted {
		t.Fatal("NPTv6-shaped row (translated dst, no port rewrite) was not rematched")
	}
	if record.RuleID != "lan->wan/p-new" {
		t.Fatalf("NPTv6-shaped row rebound unexpected rule: %+v", record)
	}
	// Fixture guard: the same row without translation must NOT match the
	// renamed rule (it falls through to the alternate/default verdict). If
	// the scope above ever widens to cover the wire dst, this reds — without
	// it the positive assertion above would pass vacuously on the wire tuple.
	plain := value
	plain.Flags = 0
	plain.NATDstIP = [16]byte{}
	if record, _ := rematchRenamedV6(oldCfg, newCfg, bindings[oldID], key, plain); record.RuleID == "lan->wan/p-new" {
		t.Fatalf("untranslated wire tuple matched the renamed rule; the scope no longer discriminates: %+v", record)
	}
}

func TestPolicyRenameEvaluatorRejectsAmbiguousOrChangedProof10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	changed := policyRenameEvaluatorConfig("p-new", config.PolicyDeny)
	if bindings, wire, ok := expandPolicyRenameAncestry(
		oldCfg, changed, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	); ok || bindings != nil || wire != nil {
		t.Fatalf("fingerprint-changing rename was retained: bindings=%v wire=%v ok=%v", bindings, wire, ok)
	}
	duplicate := []configstore.RenameDescriptor{
		policyRenameDescriptor("p-old", "p-new"),
		policyRenameDescriptor("p-old", "p-alternate"),
	}
	if bindings, wire, ok := expandPolicyRenameAncestry(oldCfg, policyRenameEvaluatorConfig("p-new", config.PolicyPermit), duplicate); ok || bindings != nil || wire != nil {
		t.Fatalf("duplicate source ancestry was retained: bindings=%v wire=%v ok=%v", bindings, wire, ok)
	}
}

func TestRematchRenamedV4RejectsUnknownGREDiscriminator10511(t *testing.T) {
	oldCfg := policyRenameEvaluatorConfig("p-old", config.PolicyPermit)
	newCfg := policyRenameEvaluatorConfig("p-new", config.PolicyPermit)
	bindings, _, ok := expandPolicyRenameAncestry(
		oldCfg, newCfg, []configstore.RenameDescriptor{policyRenameDescriptor("p-old", "p-new")},
	)
	if !ok {
		t.Fatal("valid policy ancestry rejected")
	}
	oldID := dpuserspace.PolicyIDsByStableKey(oldCfg)["lan->wan/p-old"]
	value := dataplane.SessionValue{
		PolicyID:            oldID,
		IngressZone:         config.StableZoneID("lan"),
		EgressZone:          config.StableZoneID("wan"),
		TunnelDiscriminator: 0,
	}
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 0, 10}, DstIP: [4]byte{10, 0, 0, 20},
		SrcPort: 1234, DstPort: 443, Protocol: 47,
	}
	if _, permitted := rematchRenamedV4(oldCfg, newCfg, bindings[oldID], key, value); permitted {
		t.Fatal("GRE discriminator zero must fail closed because BPF omitted the discriminator")
	}
}

// Ownership of rename lineage transfers from the store to the daemon copy at
// bind time in commitWithGenBinding: the consumed store generation retires
// immediately, and no apply outcome — converged, terminally failed, or fatal
// — retains store-side state. Retiring only on success leaked one dead entry
// per failed rename commit: promotion already advanced the candidate past the
// consumed generation, and the mutation carry moves only the current
// generation's entry, so a retained entry is unreachable by every future
// commit (#10511 MIN-14). The daemon-side copy is the sole post-bind owner,
// retained for peer retry/reconnect and pruned by the next commit's bind.
func TestRenameAncestryOwnershipTransfersAtBindTime10511(t *testing.T) {
	store := newConfigStore(t, t.TempDir())
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"security zones security-zone lan",
		"security zones security-zone wan",
		"security policies default-policy deny-all",
		"security policies from-zone lan to-zone wan policy p-old match source-address any",
		"security policies from-zone lan to-zone wan policy p-old match destination-address any",
		"security policies from-zone lan to-zone wan policy p-old match application any",
		"security policies from-zone lan to-zone wan policy p-old then permit",
	} {
		if err := store.SetFromInput(line); err != nil {
			t.Fatalf("SetFromInput(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("initial Commit: %v", err)
	}
	oldActive := store.ActiveConfig()
	src := []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", "p-old"}
	dst := []string{"security", "policies", "from-zone", "lan", "to-zone", "wan", "policy", "p-new"}
	if err := store.Rename(src, dst); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	_, candGen, err := store.CompileCandidateGen()
	if err != nil {
		t.Fatalf("CompileCandidateGen: %v", err)
	}
	if got := store.PendingRenameAncestryForGeneration(candGen); len(got) != 1 {
		t.Fatalf("rename did not record exactly one lineage descriptor: %#v", got)
	}
	d := &Daemon{store: store, applyBodyForTest: func(*config.Config) {}}
	d.applySem = semaphore.NewWeighted(1)
	if err := d.applySem.Acquire(context.Background(), 1); err != nil {
		t.Fatalf("applySem acquire: %v", err)
	}
	defer d.applySem.Release(1)
	oldActive, compiled, err := d.commitWithGenBinding(
		func(*config.Config) error { return nil },
		func(gen uint64) (*config.Config, error) { return store.CommitWithDescriptionGen("", gen) },
	)
	if err != nil {
		t.Fatalf("commitWithGenBinding: %v", err)
	}
	activeGen, _ := store.ActiveSnapshot()
	// The bind transferred ownership: the daemon holds the descriptors and
	// the store holds nothing — for this generation or any other.
	pending, ok := d.pendingRenameApplies[activeGen]
	if !ok || len(pending.descriptors) != 1 {
		t.Fatalf("bind did not transfer the descriptor to the daemon copy: %#v", d.pendingRenameApplies)
	}
	if got := store.PendingRenameAncestryForGeneration(candGen); len(got) != 0 {
		t.Fatalf("bind left the consumed store generation behind: %#v", got)
	}
	if got := store.PendingRenameAncestry(); len(got) != 0 {
		t.Fatalf("bind left store-side lineage behind: %#v", got)
	}
	// Every apply outcome retains the daemon copy and resurrects nothing
	// store-side: fatal (publication skipped), non-fatal tail error, success.
	for _, tc := range []struct {
		name     string
		applyErr error
		wantNil  bool
	}{
		{"fatal", dpuserspace.ErrPolicySchedulerProtocolIncompatible, true},
		{"non-fatal", errors.New("apply networkd config: simulated best-effort failure"), false},
		{"success", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.applyErrForTest = tc.applyErr
			got, err := d.applyAndSyncCommitted(oldActive, compiled, peerSyncNever)
			if tc.applyErr == nil && err != nil {
				t.Fatalf("converging apply returned %v", err)
			}
			if tc.applyErr != nil && err == nil {
				t.Fatal("failing apply returned nil; the retention below is untested")
			}
			if tc.wantNil && got != nil {
				t.Fatal("fatal apply must fail without a commit result")
			}
			if _, ok := d.pendingRenameApplies[activeGen]; !ok {
				t.Fatalf("%s apply dropped the daemon-side descriptor copy", tc.name)
			}
			if got := store.PendingRenameAncestry(); len(got) != 0 {
				t.Fatalf("%s apply resurrected store-side lineage: %#v", tc.name, got)
			}
		})
	}
}

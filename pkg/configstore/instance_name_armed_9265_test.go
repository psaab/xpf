package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9265 — arming the schema-blind instance-name containers, with END-TO-END
// evidence per container instead of a schema-flag re-read.
//
// CHANNEL: `configstore.CheckText`, which is `compileTreeStrict` — the exact gate
// sequence an operator commit goes through (typed-leaf SchemaValidate on the
// apply-groups-expanded view, then strict compile). That is the channel #9091's
// own 102-container headline was measured on, and it is deliberately NOT the
// schema walk: #9091's ratchet bounds the SCHEMA-SIDE set (a strict superset),
// and this file is the narrowing measurement the ratchet cannot make.
//
// WHY THE SUPERSET IS THE WRONG THING TO DRIVE WORK FROM, measured rather than
// restated. Two of the sixteen containers this change considered are schema-blind
// and NOT fail-open end to end:
//
//	/snmp/trap-group     bogus keyword -> REJECTED  ("snmp trap-group \"tg1\":
//	                     unknown statement \"xpfbogus\" (valid: targets, version,
//	                     categories)") — a later compiler gate catches it
//	/system/ntp/server   bogus keyword -> REJECTED  ("system ntp server: unknown
//	                     modifier \"xpfbogus\"")
//
// Neither is armed here. Arming a container that a downstream gate already covers
// spends the #1960 no-brick budget on a path that was never fail-open, which is
// precisely the distinction #9265 filed this issue to preserve. They are recorded
// as rows below so the evidence survives, with `coveredDownstream`.
//
// WHY closedWorld IS ONLY ARMED ON ALL-TERMINAL CONTAINERS. `closedWorld`
// INHERITS (`childClosed := closed || childSchema.closedWorld`, schema_walk.go),
// so arming a container closes its ENTIRE subtree. That is not a theory: #9017
// records arming `firewall family` closing the whole filter grammar beneath it and
// rejecting `from source-prefix-list trusted`, which is valid and shipped. Every
// container armed here has only TERMINAL children, so the inheritance reaches
// nothing past its own body. Of the 158 blind containers, 63 have that shape;
// this change takes 16 of them.

// instanceNameArmed9265Row is one container's evidence: the configuration that
// must still COMMIT, and the same configuration plus one undeclared keyword.
type instanceNameArmed9265Row struct {
	path  string
	clean string
	bogus string
	// packed is the FLAT-SET spelling of the same body, as a single `set` line.
	// It exists because the braced fixture alone answers the wrong question: a
	// flat-set chain NESTS each statement under the previous leaf, so an armed
	// container's INHERITED closed world can refuse a keyword that is legal at
	// the container level. That is how both of the `armed: false` rows below were
	// caught, and only by `go test ./...` — the braced acceptance row passed for
	// each of them. Empty means the container has no multi-leaf body worth
	// packing.
	packed string
	// verdict is the MEASURED end-to-end state. THREE states, not two, because
	// "not armed" covers two different facts and collapsing them would hide the
	// one that still matters:
	//
	//	armedClosed        this change armed it; an undeclared keyword is REJECTED
	//	coveredDownstream  NOT armed, and a later compiler gate refuses it anyway
	//	                   — the evidence that schema blindness is an UPPER BOUND
	//	stillFailOpen      NOT armed, and an undeclared keyword is still ACCEPTED.
	//	                   A recorded gap, with the reason arming was refused
	//
	// A two-state model would have to score a stillFailOpen row as "rejected",
	// which is a false green, or drop it from the table, which loses the only
	// record that the container is open.
	verdict verdict9265
}

type verdict9265 int

const (
	armedClosed verdict9265 = iota
	coveredDownstream
	stillFailOpen
)

func instanceNameArmed9265Rows() []instanceNameArmed9265Row {
	const cl = `authentication-key "xpfpsk0123456789"; `
	return []instanceNameArmed9265Row{
		{path: "/system/login/class", verdict: armedClosed,
			packed: "set system login class c1 permissions view",
			clean:  "system { login { class c1 { permissions view; } } }",
			bogus:  "system { login { class c1 { permissions view; xpfbogus 5; } } }"},

		{path: "/system/backup-router", verdict: armedClosed,
			packed: "set system backup-router 10.0.0.1 destination 10.9.0.0/16",
			clean:  "system { backup-router 10.0.0.1 { destination 10.9.0.0/16; } }",
			bogus:  "system { backup-router 10.0.0.1 { destination 10.9.0.0/16; xpfbogus 5; } }"},
		{path: "/policy-options/community", verdict: armedClosed,
			packed: "set policy-options community c1 members 65000:1",
			clean:  "policy-options { community c1 { members 65000:1; } }",
			bogus:  "policy-options { community c1 { members 65000:1; xpfbogus 5; } }"},
		{path: "/chassis/cluster/control-ports/fpc", verdict: armedClosed,
			packed: "set chassis cluster control-ports fpc 0 port 0",
			clean:  "chassis { cluster { " + cl + "control-ports { fpc 0 { port 0; } } } }",
			bogus:  "chassis { cluster { " + cl + "control-ports { fpc 0 { port 0; xpfbogus 5; } } } }"},
		{path: "/chassis/cluster/redundancy-group/node", verdict: armedClosed,
			packed: "set chassis cluster redundancy-group 1 node 0 priority 200",
			clean:  "chassis { cluster { " + cl + "redundancy-group 1 { node 0 { priority 200; } } } }",
			bogus:  "chassis { cluster { " + cl + "redundancy-group 1 { node 0 { priority 200; xpfbogus 5; } } } }"},
		{path: "/chassis/device-map/interface", verdict: armedClosed,
			packed: "set chassis device-map interface ge-0/0/0 pci 0000:05:00.0",
			clean:  "chassis { device-map { interface ge-0/0/0 { pci 0000:05:00.0; } } }",
			bogus:  "chassis { device-map { interface ge-0/0/0 { pci 0000:05:00.0; xpfbogus 5; } } }"},
		{path: "/security/nat/proxy-arp/interface", verdict: armedClosed,
			packed: "set security nat proxy-arp interface ge-0/0/0.0 address 10.0.0.50",
			clean:  "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.50; } } } } }",
			bogus:  "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.50; } xpfbogus 5; } } } }"},
		{path: "/class-of-service/scheduler-maps/forwarding-class", verdict: armedClosed,
			packed: "set class-of-service scheduler-maps sm1 forwarding-class best-effort scheduler s1",
			clean:  "class-of-service { scheduler-maps sm1 { forwarding-class best-effort { scheduler s1; } } schedulers { s1 { transmit-rate percent 10; } } }",
			bogus:  "class-of-service { scheduler-maps sm1 { forwarding-class best-effort { scheduler s1; xpfbogus 5; } } schedulers { s1 { transmit-rate percent 10; } } }"},
		{path: "/interfaces/*/unit/family/inet/address/vrrp-group/track-interface", verdict: armedClosed,
			packed: "set interfaces reth0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 track-interface ge-0/0/1 priority-cost 10",
			clean:  "interfaces { reth0 { unit 0 { family inet { address 10.0.0.1/24 { vrrp-group 1 { virtual-address 10.0.0.254/24; track-interface ge-0/0/1 { priority-cost 10; } } } } } } }",
			bogus:  "interfaces { reth0 { unit 0 { family inet { address 10.0.0.1/24 { vrrp-group 1 { virtual-address 10.0.0.254/24; track-interface ge-0/0/1 { priority-cost 10; xpfbogus 5; } } } } } } }"},
		{path: "/interfaces/*/unit/family/inet6/address/vrrp-group/track-interface", verdict: armedClosed,
			packed: "set interfaces reth0 unit 0 family inet6 address 2001:db8::1/64 vrrp-group 1 track-interface ge-0/0/1 priority-cost 10",
			clean:  "interfaces { reth0 { unit 0 { family inet6 { address 2001:db8::1/64 { vrrp-group 1 { virtual-address 2001:db8::254/64; track-interface ge-0/0/1 { priority-cost 10; } } } } } } }",
			bogus:  "interfaces { reth0 { unit 0 { family inet6 { address 2001:db8::1/64 { vrrp-group 1 { virtual-address 2001:db8::254/64; track-interface ge-0/0/1 { priority-cost 10; xpfbogus 5; } } } } } } }"},

		{path: "/system/services/dhcp-local-server/group/pool/static-binding", verdict: armedClosed,
			packed: "set system services dhcp-local-server group g1 pool p1 static-binding 00:11:22:33:44:55 fixed-address 10.0.0.50",
			clean:  "system { services { dhcp-local-server { group g1 { pool p1 { static-binding 00:11:22:33:44:55 { fixed-address 10.0.0.50; } } } } } }",
			bogus:  "system { services { dhcp-local-server { group g1 { pool p1 { static-binding 00:11:22:33:44:55 { fixed-address 10.0.0.50; xpfbogus 5; } } } } } }"},
		{path: "/system/services/dhcpv6-local-server/group/pool/static-binding", verdict: armedClosed,
			packed: "set system services dhcpv6-local-server group g1 pool p1 static-binding 00:11:22:33:44:55 fixed-address 2001:db8::50",
			clean:  "system { services { dhcpv6-local-server { group g1 { pool p1 { static-binding 00:11:22:33:44:55 { fixed-address 2001:db8::50; } } } } } }",
			bogus:  "system { services { dhcpv6-local-server { group g1 { pool p1 { static-binding 00:11:22:33:44:55 { fixed-address 2001:db8::50; xpfbogus 5; } } } } } }"},
		{path: "/security/address-book/global/address-set", verdict: armedClosed,
			packed: "set security address-book global address a1 10.0.0.0/24\nset security address-book global address-set s1 address a1",
			clean:  "security { address-book { global { address a1 10.0.0.0/24; address-set s1 { address a1; } } } }",
			bogus:  "security { address-book { global { address a1 10.0.0.0/24; address-set s1 { address a1; xpfbogus 5; } } } }"},
		{path: "/security/zones/security-zone/address-book/address-set", verdict: armedClosed,
			packed: "set security zones security-zone z1 address-book address a1 10.0.0.0/24\nset security zones security-zone z1 address-book address-set s1 address a1",
			clean:  "security { zones { security-zone z1 { address-book { address a1 10.0.0.0/24; address-set s1 { address a1; } } } } }",
			bogus:  "security { zones { security-zone z1 { address-book { address a1 10.0.0.0/24; address-set s1 { address a1; xpfbogus 5; } } } } }"},

		// NOT armed, REFUSED BY AN ACCEPTANCE ROW RATHER THAN BY THE UPPER-BOUND
		// ARGUMENT. Both were armed in a first pass and `go test ./...` caught
		// them; they are the reason criterion 3 exists.
		//
		//	/snmp/community  fails TWICE.
		//	  #4306 S-5 deliberately ACCEPTS an undeclared `view` knob with an
		//	  advisory (TestSNMPInertKnobAdvisories); a closed world refuses it.
		//	  And #9416's supported packed spelling
		//	  `community <c> client-list-name <n> authorization read-only` puts a
		//	  legal community-level keyword UNDER the terminal
		//	  `client-list-name` leaf via the flat-set chain, where the INHERITED
		//	  closed world refuses it
		//	  (TestSNMPClientListFlatSetSpellings9416/reference_BEFORE_authorization).
		//	/protocols/router-advertisement/interface/prefix
		//	  the packed flag spelling `prefix <p> no-autonomous no-onlink` is
		//	  ACCEPTED today and a closed world refuses it -- "unknown
		//	  configuration keyword \"no-onlink\" under closed-world subtree".
		//
		// Both rows stay, as `stillFailOpen`, so the bogus keyword they still
		// accept is RECORDED rather than quietly dropped from the board.
		{path: "/snmp/community", verdict: stillFailOpen,
			// #9416's supported packed spelling. This line is the FAIL-ON-REVERT
			// guard for the decision not to arm `snmp community`: arming it makes
			// the inherited closed world refuse `authorization` under the terminal
			// `client-list-name` leaf, and this row reds.
			packed: "set snmp client-list trusted 10.0.0.0/8\nset snmp community public client-list-name trusted authorization read-only",
			clean:  "snmp { community public { authorization read-only; view myview; } }",
			bogus:  "snmp { community public { authorization read-only; xpfbogus 5; } }"},
		{path: "/protocols/router-advertisement/interface/prefix", verdict: stillFailOpen,
			// The packed flag spelling, ACCEPTED today. Arming this container
			// refuses it ("unknown configuration keyword \"no-onlink\" under
			// closed-world subtree"), so this row is the fail-on-revert guard for
			// that decision too.
			packed: "set protocols router-advertisement interface ge-0/0/0.0 prefix 2001:db8::/64 no-autonomous no-onlink",
			clean:  "protocols { router-advertisement { interface ge-0/0/0.0 { prefix 2001:db8::/64 { no-autonomous; } } } }",
			bogus:  "protocols { router-advertisement { interface ge-0/0/0.0 { prefix 2001:db8::/64 { no-autonomous; xpfbogus 5; } } } }"},

		// NOT armed: schema-blind, already refused downstream. Kept as rows so
		// the evidence for "schema blindness is an upper bound" is asserted
		// rather than asserted-about in a comment.
		{path: "/snmp/trap-group", verdict: coveredDownstream,
			clean: "snmp { trap-group tg1 { version v2; targets { 10.0.0.9; } } }",
			bogus: "snmp { trap-group tg1 { version v2; targets { 10.0.0.9; } xpfbogus 5; } }"},
		{path: "/system/ntp/server", verdict: coveredDownstream,
			clean: "system { ntp { server 10.0.0.3 { prefer; } } }",
			bogus: "system { ntp { server 10.0.0.3 { prefer; xpfbogus 5; } } }"},
	}
}

// TestInstanceNameArmedRefusesUnknownKeywords9265 is the fix, and the row that
// matters most is the one that must still be ACCEPTED.
//
// "The container refuses an unknown keyword" is satisfiable by refusing
// EVERYTHING, and that would be a far worse defect than the silent drop being
// closed: a container that stops committing is an outage at the next commit, and
// under #1960 it still BOOTS (Store.Load is lenient), so the operator gets a
// config that loads, warns, and truncates. The #4191 over-rejection class. So the
// clean body is asserted FIRST, on every row, and a failure there is fatal.
func TestInstanceNameArmedRefusesUnknownKeywords9265(t *testing.T) {
	for _, row := range instanceNameArmed9265Rows() {
		t.Run(row.path, func(t *testing.T) {
			// THE LOAD-BEARING ROW, and it is asserted in BOTH spellings.
			if _, err := CheckText(row.clean, -1); err != nil {
				t.Fatalf("#9265 OVER-REJECTION (braced): the container's own DECLARED body no "+
					"longer commits: %v\n\nconfig:\n%s\n\nArming closedWorld must refuse only "+
					"UNDECLARED keywords. A container that stops committing is an outage at "+
					"the next commit and still boots under #1960 — it loads, warns and "+
					"truncates — which is worse than the silent drop this change closes.",
					err, row.clean)
			}
			if row.packed != "" {
				if v := packedVerdict9265(row.packed); v != "" {
					t.Fatalf("#9265 OVER-REJECTION (PACKED): the flat-set spelling of the same "+
						"body no longer commits: %s\n\nline: %s\n\nA flat-set chain NESTS each "+
						"statement under the previous leaf, so an armed container's INHERITED "+
						"closed world can refuse a keyword that is legal at the container level. "+
						"The braced fixture above cannot see that — it is how both stillFailOpen "+
						"rows below were caught, and only by `go test ./...`.", v, row.packed)
				}
			}
			_, err := CheckText(row.bogus, -1)
			switch row.verdict {
			case armedClosed:
				if err == nil {
					t.Errorf("#9265: %s ACCEPTS an undeclared keyword at configstore.CheckText, "+
						"so arming closedWorld did not take effect. A mistyped keyword here "+
						"commits clean and is silently ignored — no value and no complaint "+
						"(#8928's shape).\n\nconfig:\n%s", row.path, row.bogus)
					return
				}
				// NOT just "it failed": it must have failed for the RIGHT REASON.
				// A fixture that broke for an unrelated reason would otherwise
				// score as a working guard.
				if !strings.Contains(err.Error(), "xpfbogus") {
					t.Errorf("#9265: %s rejected the config, but not for the undeclared keyword — "+
						"the message does not name it, so this row is passing on an unrelated "+
						"failure and says nothing about closedWorld: %v", row.path, err)
				}
			case coveredDownstream:
				if err == nil {
					t.Errorf("#9265: %s now ACCEPTS an undeclared keyword end to end. It was "+
						"recorded as schema-blind but covered by a DOWNSTREAM gate, which is the "+
						"whole basis for not arming it. If that gate went away the container is "+
						"now genuinely fail-open and belongs in the armed set.", row.path)
				}
			case stillFailOpen:
				if err != nil {
					t.Errorf("#9265: %s now REJECTS an undeclared keyword. This row records a "+
						"container this change DECLINED to arm because arming changed a "+
						"spelling's acceptance — so something else closed it, and the reason "+
						"recorded beside this row needs re-reading before the row is deleted: %v",
						row.path, err)
				}
			}
		})
	}
}

// #10828: a login-class idle timeout has no runtime consumer on any supported
// session surface, so strict commits must reject the leaf rather than promise
// an unenforced deadline. The flat chained spelling exercises the shape whose
// compiler-visible leaf must be checked even if schema validation cannot name
// the unsupported setting directly.
func TestCommitCheck_RejectsLoginClassIdleTimeout10828(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"flat chained after allow-commands", `system login class ops allow-commands "show .*" idle-timeout 1`, "idle-timeout"},
		{"positive timeout", "system login class ops idle-timeout 1", "idle-timeout is not enforced by xpf"},
		{"explicit zero", "system login class ops idle-timeout 0", "idle-timeout is not enforced by xpf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.SetFromInput(tc.input); err != nil {
				t.Fatalf("SetFromInput: %v", err)
			}
			_, err := s.CommitCheck()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("CommitCheck error = %v, want strict idle-timeout refusal containing %q", err, tc.want)
			}
			if _, err := s.Commit(); err == nil {
				t.Fatal("Commit accepted an unenforced login-class idle-timeout")
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Commit error = %v, want explicit idle-timeout refusal containing %q", err, tc.want)
			}
		})
	}

	// A class without the unsupported leaf remains committable.
	s := newTestStoreAt(t, filepath.Join(t.TempDir(), "config"))
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("control EnterConfigure: %v", err)
	}
	if err := s.SetFromInput("system login class ops permissions view"); err != nil {
		t.Fatalf("control SetFromInput: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("control CommitCheck: %v", err)
	}
}

func TestPeerCommitCheckRejectsLoginClassIdleTimeout10828(t *testing.T) {
	text := `groups {
    node0 {
        chassis { cluster { node 0; } }
    }
    node1 {
        chassis { cluster { node 1; } }
        system {
            login {
                class ops {
                    permissions view;
                    idle-timeout 1;
                }
            }
        }
    }
}
chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        authentication-key "peer-idletimeout-10828-long-enough";
    }
}
apply-groups "${node}";
`
	_, err := CheckText(text, 0)
	if err == nil {
		t.Fatal("CheckText accepted a shared config with idle-timeout in the peer's effective view")
	}
	for _, want := range []string{"peer node1", "idle-timeout is not enforced by xpf"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckText error = %v, want %q", err, want)
		}
	}
}

func TestLoad_ToleratesLegacyLoginClassIdleTimeout10828(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config")
	writeStoredConfig(t, cfgPath, "set system login class ops idle-timeout 0")

	s := newTestStoreAt(t, cfgPath)
	if err := s.Load(); err != nil {
		t.Fatalf("Load must tolerate legacy idle-timeout, got %v", err)
	}
	active := s.ActiveConfig()
	if active == nil || active.System.Login == nil || len(active.System.Login.Classes) != 1 {
		t.Fatalf("legacy idle-timeout did not load into the active config: %+v", active)
	}
	class := active.System.Login.Classes[0]
	if !class.IdleTimeoutSet || class.IdleTimeout != 0 {
		t.Fatalf("legacy explicit zero was not retained: %+v", class)
	}
	found := false
	for _, warning := range active.Warnings {
		if strings.Contains(warning, "idle-timeout") && strings.Contains(warning, "NOT enforced") {
			found = true
		}
	}
	if !found {
		t.Fatalf("legacy load must warn that idle-timeout is not enforced, warnings=%v", active.Warnings)
	}
}

// packedVerdict9265 drives a flat-set line through the same typed schema walk
// configstore.CheckText runs, and returns "" when it is accepted.
//
// It does not go through CheckText itself because CheckText takes hierarchical
// TEXT, and the whole point of this probe is the spelling CheckText cannot be
// handed: one `set` line whose statements SetPath nests into a chain. The gate is
// the same function compileTreeStrict calls.
func packedVerdict9265(line string) string {
	tr := &config.ConfigTree{}
	for _, l := range strings.Split(line, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		toks, err := config.ParseSetCommand(l)
		if err != nil {
			return "PARSE ERROR: " + err.Error()
		}
		if err := tr.SetPath(toks); err != nil {
			return "SETPATH ERROR: " + err.Error()
		}
	}
	if err := config.SchemaValidateWithDefinitions(tr, tr, nil); err != nil {
		return err.Error()
	}
	return ""
}

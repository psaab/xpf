package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// #8258, starting point 1: `secretIndices` versus the typed secret-masking
// pass. Two surfaces render every operator secret in this tree, a defect fixed
// on one has repeatedly not been carried to the other, and until this file
// nothing compared them.
//
// This is the #8104 census's predicate applied to the OTHER redaction pair.
// #8104 covered URL-SHAPED leaves (redacted by transform, RedactURL). This
// covers SECRET leaves (redacted by replacement, SecretDataPlaceholder). The
// two passes are siblings in ast_redact.go and have the identical asymmetry:
//
//   - the TYPED route is self-maintaining. A secret field is declared as the
//     `Secret` type (secret.go), and `Secret.MarshalJSON` redacts. Adding a
//     secret field to the compiled config is one type annotation and the
//     REST/JSON route is covered from that moment, with no list to update.
//
//   - the AST route is hand-maintained. `secretIndices` matches KEYWORDS in a
//     flattened []string path. There is no type to reflect over, so its
//     population can only be enumerated deliberately.
//
// A fix on the self-maintaining side therefore exerts no pressure on the
// hand-maintained side. That asymmetry is the mechanism #8258 names, and it is
// how `archive-sites ... password` rendered in full on the AST surface after
// #7510 had already fixed the typed one (#7511) — the same story as #8104's
// FeedServer.Hostname, in the secret pass instead of the URL pass.
//
// THE PREDICATE, in the form #8258 asks for: a config leaf is secret-bearing
// IFF THE TYPED ROUTE DECLARES ITS FIELD AS `Secret`. It asserts the AGREEMENT
// between the two surfaces and pins neither to a heuristic — a heuristic
// encodes which side you trust, and the defect is precisely that the sides
// disagreed.
//
// WHY REFLECTION AND NOT A REGEX. The #8104 census had to scan source text for
// helper CALLS, and its own comment records the trap: defining a set as
// "things that call X" is a claim that X is the only route to the behaviour,
// and its first draft silently missed the archive-sites class that reaches
// RedactURL through a wrapper. Here the population is a TYPE, so reflection
// over the compiled `Config` enumerates it exactly — no wrapper can hide from
// it and no naming convention is assumed. That makes this census strictly
// self-maintaining in the direction that matters: declaring a new field
// `Secret` enrols it here on the next run, whether or not anyone remembers
// this file exists.

// secretFieldCensus walks the compiled Config type and returns every exported
// field whose type is `Secret`, as "TypeName.FieldName".
//
// It descends through pointers, slices, arrays and map values so a secret
// nested inside a per-interface or per-neighbour struct is reached. Recursion
// into a struct type already on the current path is skipped so a self-
// referential type cannot loop; the type is released on the way out, so a type
// legitimately reachable by two different routes is still visited.
func secretFieldCensus() []string {
	secretType := reflect.TypeOf(Secret(""))
	var out []string
	onPath := map[reflect.Type]bool{}

	var walk func(rt reflect.Type)
	walk = func(rt reflect.Type) {
		switch rt.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map:
			walk(rt.Elem())
		case reflect.Struct:
			if onPath[rt] {
				return
			}
			onPath[rt] = true
			defer delete(onPath, rt)
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				if f.PkgPath != "" { // unexported: no marshal route, no render route
					continue
				}
				if f.Type == secretType {
					out = append(out, rt.Name()+"."+f.Name)
					continue
				}
				walk(f.Type)
			}
		}
	}
	walk(reflect.TypeOf(Config{}))

	sort.Strings(out)
	uniq := out[:0]
	var last string
	for _, s := range out {
		if s != last {
			uniq = append(uniq, s)
			last = s
		}
	}
	return uniq
}

// secretLeafClaim maps one `Secret`-typed field to the config leaf that must
// ALSO redact on the AST route.
type secretLeafClaim struct {
	// set is a `set` command with a single %s for the planted secret.
	set string
	// accepted, when non-empty, records that this leaf deliberately does NOT
	// redact on the AST route, with the reason. It is a strong claim — the
	// typed route DOES redact it — so it is reserved for the unsatisfiable
	// class and each entry owes a justification.
	accepted string
}

// astLeafForSecretField is the mapping every `Secret` field must have. It is
// NOT the population: the population is discovered by reflection above, and an
// unmapped field fails the census. That direction is the whole point — a new
// secret field cannot be added without either covering it here or explaining
// why it cannot be covered.
var astLeafForSecretField = map[string]secretLeafClaim{
	"APIAuthKey.Secret": {
		set: `set system services web-management api-auth key k1 secret "%s"`,
	},
	"APIAuthUser.Password": {
		set: `set system services rest api-auth user u1 password "%s"`,
	},
	"BGPNeighbor.AuthPassword": {
		set: `set protocols bgp group g1 neighbor 10.0.0.1 authentication-key "%s"`,
	},
	"ClusterConfig.ControlLinkAuthKey": {
		set: `set chassis cluster authentication-key "%s"`,
	},
	"ClusterConfig.ControlLinkAuthKeyAlt": {
		set: `set chassis cluster additional-authentication-key "%s"`,
	},
	"DDNSProvider.APIToken": {
		set: `set system services dynamic-dns provider p1 api-token "%s"`,
	},
	"DDNSProvider.AWSSecretAccessKey": {
		set: `set system services dynamic-dns provider p1 aws-secret-key "%s"`,
	},
	"DDNSProvider.Password": {
		set: `set system services dynamic-dns provider p1 password "%s"`,
	},
	"DDNSProvider.TSIGSecret": {
		set: `set system services dynamic-dns provider p1 tsig-secret "%s"`,
	},
	"DHCPDynamicDNSConfig.TSIGSecret": {
		set: `set system services dhcp-server dynamic-dns tsig-secret "%s"`,
	},
	"IKEPolicy.PSK": {
		set: `set security ike policy p1 pre-shared-key ascii-text "%s"`,
	},
	"IPsecVPN.PSK": {
		set: `set security ipsec vpn v1 pre-shared-key ascii-text "%s"`,
	},
	"ISISConfig.AuthKey": {
		set: `set protocols isis authentication-key "%s"`,
	},
	"ISISInterface.AuthKey": {
		set: `set protocols isis interface ge-0/0/0.0 authentication-key "%s"`,
	},
	"LoginUser.EncryptedPassword": {
		set: `set system login user u1 authentication encrypted-password "%s"`,
	},
	"OSPFInterface.AuthKey": {
		set: `set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key "%s"`,
	},
	"RIPConfig.AuthKey": {
		set: `set protocols rip authentication-key "%s"`,
	},
	"RootAuthConfig.EncryptedPassword": {
		set: `set system root-authentication encrypted-password "%s"`,
	},
	// #8258 point 3: NOT a `Secret`-typed field. `SNMPCommunity.Name` is a
	// plain string converted to `Secret` inside MarshalJSON/MarshalYAML, so the
	// reflection census above cannot see it and the coercion census in
	// ast_secret_coercion_census_8258_test.go enrols it instead. The secret here
	// is the CONTAINER-IDENTITY token — the community string IS the SNMP v1/v2c
	// authenticator, which is why `secretIndices` masks the token after
	// `community` rather than a child leaf.
	"SNMPCommunity.Name": {
		set: `set snmp community "%s" authorization read-only`,
	},
	"SNMPv3User.AuthPassword": {
		set: `set snmp v3 usm local-engine user u1 authentication-sha authentication-password "%s"`,
	},
	"SNMPv3User.PrivPassword": {
		set: `set snmp v3 usm local-engine user u1 privacy-aes128 privacy-password "%s"`,
	},
	"TunnelConfig.WgLocalPrivkeyHex": {
		set: `set interfaces wg0 tunnel wireguard private-key "%s"`,
	},
	"VRRPGroup.AuthKey": {
		set: `set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group 1 authentication-key "%s"`,
	},
	"WgPeerConfig.PresharedKeyHex": {
		set: `set interfaces wg0 tunnel wireguard peer p1 preshared-key "%s"`,
	},
}

// TestEverySecretFieldIsMapped is the census half. It fails if the typed route
// declares a `Secret` field this file does not account for.
//
// This is the direction that makes the file self-maintaining, and it is the
// direction the #8104 pair lacked for years: the typed side grows on its own,
// so without this the AST side simply falls behind in silence.
func TestEverySecretFieldIsMapped(t *testing.T) {
	population := secretFieldCensus()

	// A floor, not a pin, and its job is narrower than it looks — this is what
	// was measured rather than what was first assumed.
	//
	// A PARTIAL walk break is NOT caught here. Removing the slice/array arm of
	// the descent loses exactly the two slice-reachable fields
	// (BGPNeighbor.AuthPassword, ISISInterface.AuthKey) and leaves 20, well
	// above any floor worth setting. What catches that is the stale-mapping
	// check at the bottom of this function, which names those two fields
	// precisely — a better detector than a count, because it says WHICH.
	//
	// The floor earns its place on TOTAL collapse only. With the walk disabled
	// entirely the population is empty, and without this the reader gets 22
	// "the field was renamed" errors pointing at the mapping table when the
	// mapping table is fine and the WALK is broken. The Fatalf short-circuits
	// them and names the real fault. That is a diagnostic guarantee, not a
	// detection one, and it is worth one line.
	//
	// The number is deliberately well below the current population so it does
	// not have to be edited for each new secret.
	const collapseFloor = 15
	if len(population) < collapseFloor {
		t.Fatalf("reflection found only %d Secret-typed fields (%v). That is below the "+
			"collapse floor of %d, so the walk itself is broken — every other "+
			"assertion in this file would pass vacuously.",
			len(population), population, collapseFloor)
	}

	for _, field := range population {
		if _, ok := astLeafForSecretField[field]; !ok {
			t.Errorf("%s is declared `Secret`, so the typed/JSON config route redacts it "+
				"automatically — but this census has no entry for it, so nothing checks "+
				"whether `show configuration` and the gRPC config RPCs redact the same "+
				"value.\n\n"+
				"This is the #8258 class. Add an entry to astLeafForSecretField with the "+
				"`set` command that populates the leaf. If the AST route genuinely cannot "+
				"redact it, add the entry with `accepted` and the reason.", field)
		}
	}

	// The reverse: a mapping for a field that no longer exists is a row that
	// asserts something about nothing. It passes, it looks like coverage, and
	// it is exactly the residue that outlives a rename.
	//
	// The population for THIS direction is the UNION of the two routes by which
	// a leaf redacts on the typed surface: declared `Secret` (reflection, this
	// function) and CONVERTED to `Secret` at marshal time (go/ast, the coercion
	// census in ast_secret_coercion_census_8258_test.go). A row enrolled by the
	// coercion route is not reflection-visible and must not be reported as
	// stale here — that check would be measuring the wrong population, and it
	// fired on exactly this case when the second route was added (#8258 point
	// 3). Both routes feed one map so the behavioural verdict covers both with
	// one implementation.
	inPopulation := make(map[string]bool, len(population))
	for _, f := range population {
		inPopulation[f] = true
	}
	for _, f := range secretCoercionCensus(t) {
		inPopulation[f] = true
	}
	for field := range astLeafForSecretField {
		if !inPopulation[field] {
			t.Errorf("astLeafForSecretField maps %q, but no `Secret`-typed field by that "+
				"name exists in the compiled Config. The field was renamed, retyped or "+
				"removed; this row now guards nothing. Remove it or correct the name.", field)
		}
	}
}

// TestASTRouteRedactsEverySecretLeaf is the behavioural verdict. It plants a
// distinctive secret in each mapped leaf, renders through RedactedClone on
// every format the config-read route can emit, and requires the secret to be
// gone.
//
// The assertion is on BEHAVIOUR — does the planted secret appear in the render
// — never on the presence of a case in secretIndices. A case can exist and be
// gated so it never fires, and by inspection that is indistinguishable from a
// correct one; the three generic keywords in secretIndices (`password`, `key`,
// `community`) are ALL gated on ancestor context, so this is the failure mode
// this pass is most exposed to.
func TestASTRouteRedactsEverySecretLeaf(t *testing.T) {
	for name, claim := range astLeafForSecretField {
		t.Run(name, func(t *testing.T) {
			// Contains no character that appears in a config path and is not a
			// substring of any keyword, so a match in the render is the planted
			// value and nothing else. A value that could collide with the
			// leaf's own name would make this test pass on the test's own
			// fixture rather than on the redaction.
			const secret = "PLANTED8258SECRETVALUE"
			line := fmt.Sprintf(claim.set, secret)

			toks, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v — the census entry does not parse, so "+
					"this row asserts nothing", line, err)
			}
			tree := &ConfigTree{}
			if err := tree.SetPath(toks); err != nil {
				t.Fatalf("SetPath(%q): %v — the census entry is not a real leaf, so this "+
					"row asserts nothing", line, err)
			}

			// POSITIVE CONTROL on the fixture itself. If the planted value is
			// not in the UNREDACTED render, the set command did not put it
			// where we think it did, and the redacted render would be clean for
			// a reason that has nothing to do with redaction. Without this, a
			// typo'd leaf name yields a green row.
			if !strings.Contains(tree.Format(), secret) {
				t.Fatalf("the planted secret is absent from the UNREDACTED render of %q.\n"+
					"The set command did not place the value at the leaf this row claims, so "+
					"a clean redacted render would prove nothing.\n\nrender:\n%s",
					line, tree.Format())
			}

			red := tree.RedactedClone()
			renders := map[string]string{
				"Format":     red.Format(),
				"FormatSet":  red.FormatSet(),
				"FormatJSON": red.FormatJSON(),
				"FormatXML":  red.FormatXML(),
			}

			if claim.accepted != "" {
				leaked := false
				for _, out := range renders {
					if strings.Contains(out, secret) {
						leaked = true
					}
				}
				if !leaked {
					t.Errorf("%s is on the accepted list (%q) but the AST route now REDACTS "+
						"it. The acceptance is stale — remove it. An accepted entry that has "+
						"stopped being true excuses a leaf that no longer needs excusing, and "+
						"the next reader will trust it.", name, claim.accepted)
				}
				return
			}

			for format, out := range renders {
				if strings.Contains(out, secret) {
					t.Errorf("%s: the typed config route redacts this field (it is declared "+
						"`Secret`), but the AST route rendered the planted secret VERBATIM "+
						"in %s.\n  set: %s\n\n"+
						"This is the #8258 class: two surfaces over one value, only one "+
						"redacting. Either extend secretIndices to cover the leaf, or record "+
						"it here as `accepted` with the reason it cannot be redacted.",
						name, format, line)
				}
			}
		})
	}
}

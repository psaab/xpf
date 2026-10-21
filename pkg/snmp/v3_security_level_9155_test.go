package snmp

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// v3_security_level_9155_test.go — #9155.
//
// The per-user security floor was keyed on DERIVED KEY PRESENCE. A key is
// derived only from a password, and BOTH keys are derived with the AUTH hash
// function — so any configuration naming a protocol that produced no key had NO
// FLOOR AT ALL and was answered at whatever level the request asked for.
//
// The commit gates added in pkg/config reject the two configurations that reach
// that state. They cannot help a config already on disk or arriving by peer
// sync, which is what this floor is for.

// buildV3NoAuthRequest builds a noAuthNoPriv GetRequest naming `userName`:
// msgFlags 0, empty authParams, no HMAC. That is the request an attacker sends
// — usernames are not secret — and the one the old floor answered.
func buildV3NoAuthRequest(t *testing.T, userName string, engineID []byte, boots, tm int, oid []int) []byte {
	t.Helper()
	usmFields := berEncodeTLV(tagOctetString, engineID)
	usmFields = append(usmFields, berEncodeIntegerTLV(boots)...)
	usmFields = append(usmFields, berEncodeIntegerTLV(tm)...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, []byte(userName))...)
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // authParams: empty
	usmFields = append(usmFields, berEncodeTLV(tagOctetString, nil)...) // privParams
	usmOctet := berEncodeTLV(tagOctetString, berEncodeTLV(tagSequence, usmFields))

	hdr := berEncodeIntegerTLV(11)
	hdr = append(hdr, berEncodeIntegerTLV(maxPacketSize)...)
	hdr = append(hdr, berEncodeTLV(tagOctetString, []byte{0})...) // msgFlags: noAuthNoPriv
	hdr = append(hdr, berEncodeIntegerTLV(usmSecurityModel)...)
	hdrSeq := berEncodeTLV(tagSequence, hdr)

	scopedBody := berEncodeTLV(tagOctetString, engineID)
	scopedBody = append(scopedBody, berEncodeTLV(tagOctetString, nil)...)
	vb := berEncodeTLV(tagObjectIdentifier, berEncodeOID(oid))
	vb = append(vb, berEncodeTLV(tagNull, nil)...)
	vbList := berEncodeTLV(tagSequence, berEncodeTLV(tagSequence, vb))
	pduBody := berEncodeIntegerTLV(77)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(0)...)
	pduBody = append(pduBody, vbList...)
	scopedBody = append(scopedBody, berEncodeTLV(pduGetRequest, pduBody)...)
	scopedPDU := berEncodeTLV(tagSequence, scopedBody)

	msgBody := berEncodeIntegerTLV(snmpVersion3)
	msgBody = append(msgBody, hdrSeq...)
	msgBody = append(msgBody, usmOctet...)
	msgBody = append(msgBody, scopedPDU...)
	return berEncodeTLV(tagSequence, msgBody)
}

// THE DEFECT, at request level. A user configured for authentication whose key
// FAILED TO DERIVE must be refused, not answered in clear.
//
// Per the issue's acceptance, this is driven by making DERIVATION fail — the
// user keeps its configured `authProto` and has a nil `authKey` — rather than by
// removing the configuration. Removing the config would produce a genuinely
// noAuthNoPriv user, which is a legitimate thing to be and answers correctly;
// that fixture would measure a different question and pass either way.
//
// Fail-on-revert: key the floor on `user.authKey != nil` again and this is
// answered, because the whole point is that authKey is nil here.
func TestUserWithFailedKeyDerivationIsRefused9155(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xDE, 0xAD, 0xBE, 0xEF}
	a := &Agent{
		engineID:    engineID,
		engineBoots: 5,
		v3Users:     map[string]*usmUser{},
		startTime:   nowMinus(1000),
	}
	// Derivation failed: the protocol is configured, the key is absent.
	a.v3Users["eve"] = &usmUser{name: "eve", authProto: "sha256"}

	pkt := buildV3NoAuthRequest(t, "eve", engineID, 5, 1000, oidSysDescr)
	a.lastPacket = pkt
	if resp := driveV3(t, a, pkt); resp != nil {
		t.Fatalf("a noAuthNoPriv request naming a user CONFIGURED for authentication "+
			"was ANSWERED (%d bytes). The user's key failed to derive, so keying the "+
			"floor on key presence left it with no floor at all — an authentication and "+
			"confidentiality bypass reachable by anyone who knows the username, and "+
			"usernames are not secret.", len(resp))
	}

	// Same for privacy: configured, no key.
	a.v3Users["mallory"] = &usmUser{name: "mallory", authProto: "sha256", privProto: "aes128"}
	pkt = buildV3NoAuthRequest(t, "mallory", engineID, 5, 1000, oidSysDescr)
	a.lastPacket = pkt
	if resp := driveV3(t, a, pkt); resp != nil {
		t.Fatalf("a noAuthNoPriv request naming an authPriv-configured user was "+
			"ANSWERED (%d bytes)", len(resp))
	}
}

// REFERENCE ARM: a genuinely noAuthNoPriv user — no protocol configured — must
// still be ANSWERED. Without this, the assertions above are satisfied by a floor
// that refuses everything, which is consistency achieved by levelling down and
// would silently break every noAuthNoPriv deployment.
func TestGenuinelyNoAuthUserIsStillAnswered9155(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xDE, 0xAD, 0xBE, 0xEF}
	a := &Agent{
		engineID:    engineID,
		engineBoots: 5,
		v3Users:     map[string]*usmUser{},
		startTime:   nowMinus(1000),
	}
	a.v3Users["public"] = &usmUser{name: "public"}

	pkt := buildV3NoAuthRequest(t, "public", engineID, 5, 1000, oidSysDescr)
	a.lastPacket = pkt
	if resp := driveV3(t, a, pkt); resp == nil {
		t.Fatal("a user configured with NO auth and NO privacy was refused; " +
			"noAuthNoPriv is a legitimate configured level and this floor must not " +
			"reject it, or the fix trades a bypass for an outage")
	}
}

// The derived-key half of the acceptance table: what each configuration
// actually produces. This is where Hole B is visible as a mechanism rather than
// as a rule — privacy keys are derived with the AUTH hash, so a user with
// privacy and no authentication derives NO privacy key.
func TestDerivedKeyTable9155(t *testing.T) {
	engineID := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0xDE, 0xAD, 0xBE, 0xEF}
	a := &Agent{engineID: engineID}

	for _, tc := range []struct {
		name                     string
		authProto, authPw        string
		privProto, privPw        string
		wantAuthKey, wantPrivKey bool
	}{
		{name: "no auth, no priv", wantAuthKey: false, wantPrivKey: false},
		{name: "auth only", authProto: "sha256", authPw: "s3cretpass", wantAuthKey: true},
		{
			name: "auth + priv", authProto: "sha256", authPw: "s3cretpass",
			privProto: "aes128", privPw: "p4ssphrase", wantAuthKey: true, wantPrivKey: true,
		},
		{
			// HOLE B's mechanism: privacy configured, no auth protocol, so
			// authHashFunc returns nil and NEITHER key is derived. The config
			// reads authPriv and the agent has nothing to encrypt with.
			name: "priv only", privProto: "aes128", privPw: "p4ssphrase",
			wantAuthKey: false, wantPrivKey: false,
		},
		{
			// HOLE A's mechanism: the unknown spelling never reached the
			// compiler's switch, so AuthProtocol is empty here — the same state
			// as "no auth", from a config that asked for authentication.
			name: "unknown auth spelling (compiles to empty)", authPw: "s3cretpass",
			wantAuthKey: false, wantPrivKey: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.SNMPConfig{V3Users: map[string]*config.SNMPv3User{
				"u": {
					Name:         "u",
					AuthProtocol: tc.authProto,
					AuthPassword: config.NewSecret(tc.authPw),
					PrivProtocol: tc.privProto,
					PrivPassword: config.NewSecret(tc.privPw),
				},
			}}
			users := a.deriveV3Users(cfg)
			u := users["u"]
			if u == nil {
				t.Fatal("no user derived")
			}
			if got := u.authKey != nil; got != tc.wantAuthKey {
				t.Errorf("authKey present = %v, want %v", got, tc.wantAuthKey)
			}
			if got := u.privKey != nil; got != tc.wantPrivKey {
				t.Errorf("privKey present = %v, want %v — privacy keys are derived with "+
					"the AUTH hash, so privacy without authentication derives nothing",
					got, tc.wantPrivKey)
			}
		})
	}
}

// The floor decision, driven directly — every arm, including the two that are
// unobservable through a request because downstream code refuses too.
//
// This table is why the extraction happened: inline, the "configured but no
// key" arms survived mutation, because with the flags set the downstream auth
// check and decryptPDU already refuse and nothing could observe the difference.
// A guard whose rejected input cannot be driven is a guard nobody can check.
func TestUSMServableAtLevelTable9155(t *testing.T) {
	const (
		noAuthNoPriv = byte(0)
		authNoPriv   = msgFlagAuth
		authPriv     = msgFlagAuth | msgFlagPriv
	)
	key := []byte{1, 2, 3, 4}

	for _, tc := range []struct {
		name  string
		user  *usmUser
		flags byte
		want  string // "" = servable
	}{
		{"nil user", nil, authPriv, "unknown user"},
		{"noAuthNoPriv user, noAuth request", &usmUser{name: "p"}, noAuthNoPriv, ""},
		{"noAuthNoPriv user, authPriv request", &usmUser{name: "p"}, authPriv, ""},

		{"auth user, auth request", &usmUser{authProto: "sha256", authKey: key}, authNoPriv, ""},
		{
			"auth user, noAuth request — THE BYPASS",
			&usmUser{authProto: "sha256", authKey: key}, noAuthNoPriv,
			"request below user minimum security level (auth required)",
		},
		{
			// Unobservable through a request; drivable here.
			"auth configured, derivation FAILED",
			&usmUser{authProto: "sha256"}, authNoPriv,
			"user names an authentication protocol but has no derived key",
		},
		{
			// The state Hole A and Hole B both produce, meeting a request that
			// declines auth: refused on the FIRST arm, before the key is
			// consulted at all.
			"auth configured, derivation failed, noAuth request",
			&usmUser{authProto: "sha256"}, noAuthNoPriv,
			"request below user minimum security level (auth required)",
		},

		{
			"priv user, authNoPriv request",
			&usmUser{authProto: "sha256", authKey: key, privProto: "aes128", privKey: key}, authNoPriv,
			"request below user minimum security level (priv required)",
		},
		{
			"priv user, authPriv request",
			&usmUser{authProto: "sha256", authKey: key, privProto: "aes128", privKey: key}, authPriv, "",
		},
		{
			"priv configured, derivation FAILED",
			&usmUser{authProto: "sha256", authKey: key, privProto: "aes128"}, authPriv,
			"user names a privacy protocol but has no derived key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := usmUserServableAtLevel9155(tc.user, tc.flags)
			if got != tc.want {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

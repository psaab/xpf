package snmp

import (
	"net"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// decodeTrapCommunity walks an SNMP trap message and returns the message
// version field and the community octet-string.
func decodeTrapCommunity(t *testing.T, pkt []byte) (version int, community string) {
	t.Helper()
	tag, body, err := berDecodeHeader(pkt)
	if err != nil || tag != tagSequence {
		t.Fatalf("outer SEQUENCE: tag=0x%02x err=%v", tag, err)
	}
	version, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	comm, _, err := berDecodeOctetString(rest)
	if err != nil {
		t.Fatalf("decode community: %v", err)
	}
	return version, string(comm)
}

// recvTrapPairs fires one linkDown for cfg (whose single target must be the
// placeholder "TARGET", replaced with the listener address) and returns the
// (version, community) of each of the want UDP packets received.
func recvTrapPairs(t *testing.T, cfg *config.SNMPConfig, want int) [][2]interface{} {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()
	for _, tg := range cfg.TrapGroups {
		for i, tgt := range tg.Targets {
			if tgt == "TARGET" {
				tg.Targets[i] = addr
			}
		}
	}
	a := &Agent{cfg: cfg, startTime: time.Now().Add(-10 * time.Second)}
	a.NotifyLinkDown(3, "ge-0-0-1")

	var got [][2]interface{}
	buf := make([]byte, 4096)
	for i := range want {
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read trap %d/%d: %v", i+1, want, err)
		}
		v, comm := decodeTrapCommunity(t, append([]byte(nil), buf[:n]...))
		got = append(got, [2]interface{}{v, comm})
	}
	return got
}

// TestTrapCommunityIsTrapGroupName15052 is the RED-on-base guard for #15052
// (A20-04). Junos sends v1/v2c traps with the trap-group NAME as the
// community. Pre-fix, sendLinkTraps used selectTrapCommunity(cfg) — the
// alphabetically-first configured QUERY community — for every group, so a
// group named "trapdest" emitted community "aaa-query" (here the
// alphabetically-first query community), disclosing that query credential
// to every trap target. Post-fix every version leg must carry "trapdest".
func TestTrapCommunityIsTrapGroupName15052(t *testing.T) {
	// Alphabetically-first query community is "aaa-query"; it must never
	// appear on the trap wire. A read-write query community is included to
	// pin the disclosure severity from the report.
	communities := map[string]*config.SNMPCommunity{
		"aaa-query": {Name: "aaa-query", Authorization: "read-write"},
		"zzz-query": {Name: "zzz-query", Authorization: "read-only"},
	}
	cases := []struct {
		name    string
		version string
		want    int
		wantVer int // -1 means both v1 and v2c legs accepted (checked as set)
	}{
		{name: "v1", version: "v1", want: 1, wantVer: snmpVersion1},
		{name: "v2", version: "v2", want: 1, wantVer: snmpVersion2c},
		{name: "unspecified", version: "", want: 1, wantVer: snmpVersion2c},
		{name: "all", version: "all", want: 2, wantVer: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.SNMPConfig{
				Communities: communities,
				TrapGroups: map[string]*config.SNMPTrapGroup{
					"trapdest": {Name: "trapdest", Targets: []string{"TARGET"}, Version: tc.version},
				},
			}
			got := recvTrapPairs(t, cfg, tc.want)
			sawVersions := map[int]bool{}
			for _, p := range got {
				v := p[0].(int)
				comm := p[1].(string)
				sawVersions[v] = true
				if comm != "trapdest" {
					t.Fatalf("version %s: trap community = %q, want trap-group name %q (query communities must not leak to trap targets)", tc.version, comm, "trapdest")
				}
				if tc.wantVer >= 0 && v != tc.wantVer {
					t.Fatalf("version %s: message version = %d, want %d", tc.version, v, tc.wantVer)
				}
			}
			if tc.wantVer == -1 && (!sawVersions[snmpVersion1] || !sawVersions[snmpVersion2c]) {
				t.Fatalf("version all: saw versions %v, want both v1(%d) and v2c(%d)", sawVersions, snmpVersion1, snmpVersion2c)
			}
		})
	}
}

// TestTrapCommunityPerGroupDistinct15052 pins that two trap groups with
// different names each send their OWN name — not a single global community.
// Pre-fix both groups would carry "aaa-query".
func TestTrapCommunityPerGroupDistinct15052(t *testing.T) {
	pcA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer pcA.Close()
	pcB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer pcB.Close()

	cfg := &config.SNMPConfig{
		Communities: map[string]*config.SNMPCommunity{
			"aaa-query": {Name: "aaa-query", Authorization: "read-write"},
		},
		TrapGroups: map[string]*config.SNMPTrapGroup{
			"alpha-dest": {Name: "alpha-dest", Targets: []string{pcA.LocalAddr().String()}, Version: "v2"},
			"omega-dest": {Name: "omega-dest", Targets: []string{pcB.LocalAddr().String()}, Version: "v1"},
		},
	}
	a := &Agent{cfg: cfg, startTime: time.Now().Add(-10 * time.Second)}
	a.NotifyLinkDown(3, "ge-0-0-1")

	readOne := func(pc net.PacketConn, wantComm string, wantVer int) {
		t.Helper()
		buf := make([]byte, 4096)
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read trap for %q: %v", wantComm, err)
		}
		v, comm := decodeTrapCommunity(t, append([]byte(nil), buf[:n]...))
		if comm != wantComm {
			t.Fatalf("trap community = %q, want trap-group name %q", comm, wantComm)
		}
		if v != wantVer {
			t.Fatalf("trap for %q: version = %d, want %d", wantComm, v, wantVer)
		}
	}
	readOne(pcA, "alpha-dest", snmpVersion2c)
	readOne(pcB, "omega-dest", snmpVersion1)
}

// TestTrapCommunityForGroupFallback15052 pins the helper contract: a named
// group yields its name, an unnamed/nil group falls back to "public" rather
// than emitting an empty community.
func TestTrapCommunityForGroupFallback15052(t *testing.T) {
	if got := trapCommunityForGroup(&config.SNMPTrapGroup{Name: "trapdest"}); got != "trapdest" {
		t.Fatalf("trapCommunityForGroup(named) = %q, want %q", got, "trapdest")
	}
	if got := trapCommunityForGroup(&config.SNMPTrapGroup{}); got != "public" {
		t.Fatalf("trapCommunityForGroup(unnamed) = %q, want %q", got, "public")
	}
	if got := trapCommunityForGroup(nil); got != "public" {
		t.Fatalf("trapCommunityForGroup(nil) = %q, want %q", got, "public")
	}
}

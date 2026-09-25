package snmp

import (
	"errors"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

// trapRequestIDOf builds a link trap and decodes the request-ID from the PDU,
// following the same BER path as TestBuildLinkTrap_LinkDown.
func trapRequestIDOf(t *testing.T, agent *Agent) int {
	t.Helper()
	pkt := agent.buildLinkTrap("public", false, 5, "trust0")
	tag, body, err := berDecodeHeader(pkt)
	if err != nil || tag != tagSequence {
		t.Fatalf("decode outer sequence: tag=0x%02x err=%v", tag, err)
	}
	_, rest, err := berDecodeInteger(body)
	if err != nil {
		t.Fatalf("decode version: %v", err)
	}
	body = rest
	_, rest, err = berDecodeOctetString(body)
	if err != nil {
		t.Fatalf("decode community: %v", err)
	}
	body = rest
	pduTag, pduBody, err := berDecodeHeader(body)
	if err != nil || pduTag != pduSNMPv2Trap {
		t.Fatalf("decode PDU header: tag=0x%02x err=%v", pduTag, err)
	}
	id, _, err := berDecodeInteger(pduBody)
	if err != nil {
		t.Fatalf("decode request-id: %v", err)
	}
	return id
}

func testTrapAgent10726() *Agent {
	return &Agent{
		cfg: &config.SNMPConfig{
			Communities: map[string]*config.SNMPCommunity{
				"public": {Name: "public", Authorization: "read-only"},
			},
		},
		startTime: time.Now().Add(-10 * time.Second),
	}
}

// TestTrapRequestIDUsesCryptoEntropy10726 pins #10726 A9-F1 at the encoded
// trap boundary. Injected entropy must determine the request-ID; reverting
// buildLinkTrap to math/rand.Int31() leaves the injected bytes unused and makes
// the decoded ID disagree with the injected value.
func TestTrapRequestIDUsesCryptoEntropy10726(t *testing.T) {
	oldRead := trapRandRead
	t.Cleanup(func() { trapRandRead = oldRead })
	trapRandRead = func(p []byte) (int, error) {
		copy(p, []byte{0x89, 0xab, 0xcd, 0xef})
		return len(p), nil
	}
	const want = 0x09abcdef // high bit masked to preserve the nonnegative Int31 range
	if got := trapRequestIDOf(t, testTrapAgent10726()); got != want {
		t.Fatalf("encoded trap request-ID = %#x, want %#x from injected crypto entropy", got, want)
	}
}

// A transient entropy failure must not prevent delivery of a trap.
func TestTrapRequestIDEntropyFailure10726(t *testing.T) {
	oldRead := trapRandRead
	t.Cleanup(func() { trapRandRead = oldRead })
	trapRandRead = func([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
	if got := trapRequestIDOf(t, testTrapAgent10726()); got != 0 {
		t.Fatalf("request-ID after entropy failure = %d, want valid zero ID", got)
	}
}

// TestTrapRequestIDRange10726 pins request-IDs to [0, 2^31), so the BER
// INTEGER remains non-negative as it was with math/rand.Int31().
func TestTrapRequestIDRange10726(t *testing.T) {
	agent := testTrapAgent10726()
	for range 32 {
		if id := trapRequestIDOf(t, agent); id < 0 || id >= 1<<31 {
			t.Fatalf("trap request-ID %d out of [0, 2^31)", id)
		}
	}
}


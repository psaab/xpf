package dataplane

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestConfigureRSSHashKeyUsesStablePerBootRandomKey11057(t *testing.T) {
	original := runEthtool
	var commands [][]string
	runEthtool = func(args ...string) ([]byte, error) {
		commands = append(commands, append([]string(nil), args...))
		return nil, nil
	}
	t.Cleanup(func() { runEthtool = original })

	configureRSSHashKey("eth0")
	configureRSSHashKey("eth1")
	if len(commands) != 2 {
		t.Fatalf("ethtool calls = %d, want 2", len(commands))
	}
	for i, iface := range []string{"eth0", "eth1"} {
		wantPrefix := []string{"-X", iface, "hkey"}
		if len(commands[i]) != 4 || strings.Join(commands[i][:3], " ") != strings.Join(wantPrefix, " ") {
			t.Fatalf("ethtool args[%d] = %v, want prefix %v plus key", i, commands[i], wantPrefix)
		}
	}
	if commands[0][3] != commands[1][3] {
		t.Fatalf("RSS key changed between interfaces in one process: %q != %q", commands[0][3], commands[1][3])
	}
	key, err := rssHashKeyForBoot()
	if err != nil {
		t.Fatalf("generate boot key: %v", err)
	}
	if got, want := commands[0][3], formatRSSHashKey(key); got != want {
		t.Fatalf("ethtool key = %q, want process boot key %q", got, want)
	}
	if got, want := len(strings.Split(commands[0][3], ":")), rssHashKeySize; got != want {
		t.Fatalf("key bytes = %d, want %d", got, want)
	}
	if commands[0][3] == "6d:5a:56:da:25:5b:0e:c2:41:67:25:3d:43:a3:8f:b0:d0:ca:2b:cb:ae:7b:30:b4:77:cb:2d:a3:80:30:f2:0c:8c:da:5b:6a:25:30:17:9a" {
		t.Fatal("RSS key reused the fleet-wide static key")
	}
}

func TestRSSKeyConfiguredWhenRingQueryFails11057(t *testing.T) {
	original := runEthtool
	var commands [][]string
	runEthtool = func(args ...string) ([]byte, error) {
		commands = append(commands, append([]string(nil), args...))
		if len(args) > 0 && args[0] == "-g" {
			return nil, errors.New("ring query unsupported")
		}
		return nil, nil
	}
	t.Cleanup(func() { runEthtool = original })

	result := &CompileResult{ethtoolApplied: make(map[string]bool)}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth-fallback", TxQLen: 10000}}
	result.tuneInterfaceBuffers(link)
	if len(commands) != 2 || commands[0][0] != "-g" {
		t.Fatalf("ethtool calls = %v, want ring query followed by RSS key", commands)
	}
	if got := commands[1]; len(got) != 4 || got[0] != "-X" || got[1] != "eth-fallback" || got[2] != "hkey" {
		t.Fatalf("RSS call after ring-query failure = %v, want -X eth-fallback hkey <key>", got)
	}
}

func TestDeterministicRSSKeySpreadsTuplesCraftedForStaticKey11057(t *testing.T) {
	// This is the pre-fix fleet-wide key, retained only as an adversarial
	// fixture to generate tuples that all targeted queue zero.
	oldKeyBytes, err := hex.DecodeString("6d5a56da255b0ec24167253d43a38fb0d0ca2bcbae7b30b477cb2da38030f20c8cda5b6a2530179a")
	if err != nil || len(oldKeyBytes) != rssHashKeySize {
		t.Fatalf("decode old test fixture: bytes=%d err=%v", len(oldKeyBytes), err)
	}
	var oldKey [rssHashKeySize]byte
	copy(oldKey[:], oldKeyBytes)

	const workers = 4
	const tupleCount = 32
	crafted := make([][]byte, 0, tupleCount)
	for port := 1024; port <= 65535 && len(crafted) < tupleCount; port++ {
		tuple := rssTestIPv4Tuple(uint16(port))
		if toeplitzTestHash(oldKey, tuple)%workers == 0 {
			crafted = append(crafted, tuple)
		}
	}
	if len(crafted) != tupleCount {
		t.Fatalf("found %d tuples targeting the same old-key queue, want %d", len(crafted), tupleCount)
	}

	// A fixed, deterministic key stands in for one node's random boot key;
	// configureRSSHashKeyWithKey is the documented test seam.
	var newKey [rssHashKeySize]byte
	for i := range newKey {
		newKey[i] = byte(i*37 + 11)
	}
	var command []string
	original := runEthtool
	runEthtool = func(args ...string) ([]byte, error) {
		command = append([]string(nil), args...)
		return nil, nil
	}
	t.Cleanup(func() { runEthtool = original })
	configureRSSHashKeyWithKey("eth0", newKey)
	if len(command) != 4 || command[3] != formatRSSHashKey(newKey) {
		t.Fatalf("configured key command = %v, want key %q", command, formatRSSHashKey(newKey))
	}

	queues := make(map[uint32]bool, workers)
	for _, tuple := range crafted {
		if got := toeplitzTestHash(oldKey, tuple) % workers; got != 0 {
			t.Fatalf("fixture tuple shifted from old queue zero to %d", got)
		}
		queues[toeplitzTestHash(newKey, tuple)%workers] = true
	}
	if len(queues) != workers {
		t.Fatalf("crafted tuple set reached %d of %d workers with per-boot key; queues=%v", len(queues), workers, queues)
	}
}

func rssTestIPv4Tuple(srcPort uint16) []byte {
	tuple := []byte{203, 0, 113, 7, 198, 51, 100, 9, 0, 0, 1, 187}
	binary.BigEndian.PutUint16(tuple[8:10], srcPort)
	return tuple
}

func toeplitzTestHash(key [rssHashKeySize]byte, input []byte) uint32 {
	var hash uint32
	for bit := 0; bit < len(input)*8; bit++ {
		if input[bit/8]&(1<<uint(7-bit%8)) == 0 {
			continue
		}
		var window uint32
		for offset := 0; offset < 32; offset++ {
			keyBit := bit + offset
			window <<= 1
			if key[keyBit/8]&(1<<uint(7-keyBit%8)) != 0 {
				window |= 1
			}
		}
		hash ^= window
	}
	return hash
}

func TestReadRSSHashKeyDeterministicReader11057(t *testing.T) {
	input := make([]byte, rssHashKeySize)
	for i := range input {
		input[i] = byte(i)
	}
	key, err := readRSSHashKey(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("read deterministic key: %v", err)
	}
	if !bytes.Equal(key[:], input) {
		t.Fatalf("read key %x, want %x", key, input)
	}
	if got, want := formatRSSHashKey(key), "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24:25:26:27"; got != want {
		t.Fatalf("formatted key = %q, want %q", got, want)
	}
	if _, err := readRSSHashKey(bytes.NewReader(input[:rssHashKeySize-1])); err == nil {
		t.Fatal("short deterministic source unexpectedly produced a complete RSS key")
	}
}

package fabricsegment

import (
	"encoding/binary"
	"net"

	"golang.org/x/net/bpf"
)

// snapLen is how much of an accepted frame the kernel copies up: the
// Ethernet header is all the watcher reads.
const snapLen = 64

// knownSourceFilter assembles the kernel cBPF program attached to the fabric
// tap. It DROPS every frame whose Ethernet source is this node's fabric MAC
// or the peer's (the normal fabric traffic), and accepts everything else, so
// the userspace reader wakes only for a candidate foreign source. The xpf
// synthetic-namespace check stays in userspace (Tracker.IsForeignSource):
// such frames are rare on the kernel path and keeping the program to two
// fixed comparisons keeps it obviously correct.
//
// Layout: source MAC = frame[6:12], compared as a 4-byte word at offset 6
// and a 2-byte half-word at offset 10.
func knownSourceFilter(local, peer net.HardwareAddr) ([]bpf.RawInstruction, error) {
	localHi, localLo := macWords(local)
	peerHi, peerLo := macWords(peer)
	prog := []bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 6, Size: 4},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: localHi, SkipTrue: 0, SkipFalse: 2},
		/* 2 */ bpf.LoadAbsolute{Off: 10, Size: 2},
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: localLo, SkipTrue: 5, SkipFalse: 0},
		/* 4 */ bpf.LoadAbsolute{Off: 6, Size: 4},
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: peerHi, SkipTrue: 0, SkipFalse: 2},
		/* 6 */ bpf.LoadAbsolute{Off: 10, Size: 2},
		/* 7 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: peerLo, SkipTrue: 1, SkipFalse: 0},
		/* 8 */ bpf.RetConstant{Val: snapLen},
		/* 9 */ bpf.RetConstant{Val: 0},
	}
	return bpf.Assemble(prog)
}

// macWords splits a MAC into the big-endian 32-bit high word and 16-bit low
// half-word cBPF LoadAbsolute reads (network byte order). A malformed MAC
// yields zero words, which never match a real frame's source.
func macWords(m net.HardwareAddr) (uint32, uint32) {
	if len(m) != 6 {
		return 0, 0
	}
	return binary.BigEndian.Uint32(m[0:4]), uint32(binary.BigEndian.Uint16(m[4:6]))
}

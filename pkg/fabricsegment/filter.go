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
// tap. It DROPS every frame whose Ethernet source is this node's fabric MAC,
// the peer's, or in xpf's synthetic namespace (02:bf:72:* V1 zone stamps and
// RETH MACs, 02:bf:73:* V2 scope stamps), and accepts everything else, so the
// userspace reader wakes only for a candidate foreign source. The synthetic
// check is repeated in userspace (Tracker.IsForeignSource) as a second layer.
//
// Layout: source MAC = frame[6:12], compared as a 4-byte word at offset 6
// and a 2-byte half-word at offset 10. The synthetic namespace is the first
// three source bytes 02:bf:72 or 02:bf:73, i.e. word[6] & 0xfffffe00 ==
// 0x02bf7200 (0x72 and 0x73 differ only in the low bit).
func knownSourceFilter(local, peer net.HardwareAddr) ([]bpf.RawInstruction, error) {
	localHi, localLo := macWords(local)
	peerHi, peerLo := macWords(peer)
	prog := []bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 6, Size: 4},
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: localHi, SkipTrue: 0, SkipFalse: 2},
		/* 2 */ bpf.LoadAbsolute{Off: 10, Size: 2},
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: localLo, SkipTrue: 8, SkipFalse: 0},
		/* 4 */ bpf.LoadAbsolute{Off: 6, Size: 4},
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: peerHi, SkipTrue: 0, SkipFalse: 2},
		/* 6 */ bpf.LoadAbsolute{Off: 10, Size: 2},
		/* 7 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: peerLo, SkipTrue: 4, SkipFalse: 0},
		/* 8 */ bpf.LoadAbsolute{Off: 6, Size: 4},
		/* 9 */ bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xfffffe00},
		/* 10 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02bf7200, SkipTrue: 1, SkipFalse: 0},
		/* 11 */ bpf.RetConstant{Val: snapLen},
		/* 12 */ bpf.RetConstant{Val: 0},
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

"""#16188 code-motion verifier.

Reconstructs nat64.rs from the nat64/ split and compares it byte-for-byte
with the pre-split file (origin/master at the lane base), allowing ONLY
the visibility widenings enumerated below. Any other difference -- a
reordered statement, a changed literal, a dropped comment -- fails.

Run from the repo root of a checkout containing the split, with the
pre-split file available as origin/master:userspace-dp/src/nat64.rs
(or pass its path/ref as argv[1], e.g. a saved copy).
"""
import subprocess
import sys

if len(sys.argv) > 1:
    with open(sys.argv[1]) as f:
        BASE = f.read().split("\n")
else:
    BASE = subprocess.run(
        ["git", "show", "origin/master:userspace-dp/src/nat64.rs"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")

# Line ranges in the pre-split file (1-based, inclusive). Derived by
# CONTENT at the lane base ba55ef764a: each seam's first and last line
# was matched in the file and the span checked to hold exactly the
# items the submodule header names. If master moves text inside
# nat64.rs, re-derive by content, never by arithmetic.
# Three seams start at the doc-comment block of their first item,
# because that doc moved WITH its item across the seam (a dangling
# /// at a submodule EOF is a hard error): reserve at the
# release_nat64_allocation_with_mode doc (2070), icmp at the
# map_icmpv6_error_to_icmpv4 doc (3870), frames at the
# write_v6_to_v4_nonfirst_translate doc (4845).
SEAMS = [
    ("state", 198, 2069),
    ("reserve", 2070, 2682),
    ("translate", 2684, 3869),
    ("icmp", 3870, 4685),
    ("checksum", 4687, 4844),
    ("frames", 4845, 5371),
]

# The visibility bill: private -> pub(super), plus the fields of the
# three embedded-quote structs (constructed/read cross-submodule).
# Struct-field entries are listed under icmp.
WIDEN = {
    "state": [
        ("const NAT64_PORT_LOW", "pub(super) const NAT64_PORT_LOW"),
        ("const NAT64_PORT_HIGH", "pub(super) const NAT64_PORT_HIGH"),
        ("fn parse_pool_v4", "pub(super) fn parse_pool_v4"),
        ("fn nat64_rule_identity", "pub(super) fn nat64_rule_identity"),
        ("fn build_deterministic_v6", "pub(super) fn build_deterministic_v6"),
        ("fn prev_prefix_is_deterministic", "pub(super) fn prev_prefix_is_deterministic"),
        ("    fn embedded_v4_is_non_global", "    pub(super) fn embedded_v4_is_non_global"),
    ],
    "reserve": [
        ("fn release_nat64_allocation_with_mode", "pub(super) fn release_nat64_allocation_with_mode"),
    ],
    "translate": [
        ("const ICMPV6_ECHO_REQUEST", "pub(super) const ICMPV6_ECHO_REQUEST"),
        ("const ICMPV6_ECHO_REPLY", "pub(super) const ICMPV6_ECHO_REPLY"),
        ("const ICMP_ECHO_REQUEST", "pub(super) const ICMP_ECHO_REQUEST"),
        ("const ICMP_ECHO_REPLY", "pub(super) const ICMP_ECHO_REPLY"),
        ("const ICMPV6_DEST_UNREACHABLE", "pub(super) const ICMPV6_DEST_UNREACHABLE"),
        ("const ICMPV6_PACKET_TOO_BIG", "pub(super) const ICMPV6_PACKET_TOO_BIG"),
        ("const ICMPV6_TIME_EXCEEDED", "pub(super) const ICMPV6_TIME_EXCEEDED"),
        ("const ICMPV6_PARAMETER_PROBLEM", "pub(super) const ICMPV6_PARAMETER_PROBLEM"),
        ("const ICMP_DEST_UNREACHABLE", "pub(super) const ICMP_DEST_UNREACHABLE"),
        ("const ICMP_TIME_EXCEEDED", "pub(super) const ICMP_TIME_EXCEEDED"),
        ("const ICMP_PARAMETER_PROBLEM", "pub(super) const ICMP_PARAMETER_PROBLEM"),
        ("const IPV6_MIN_MTU", "pub(super) const IPV6_MIN_MTU"),
        ("const NAT64_HEADER_DELTA", "pub(super) const NAT64_HEADER_DELTA"),
        ("const MAX_EMBEDDED_LEN", "pub(super) const MAX_EMBEDDED_LEN"),
        ("fn rfc1191_plateau_mtu", "pub(super) fn rfc1191_plateau_mtu"),
        ("fn next_frag_id", "pub(super) fn next_frag_id"),
        ("fn map_frag_id", "pub(super) fn map_frag_id"),
        ("fn ipv6_l4_offset_and_protocol", "pub(super) fn ipv6_l4_offset_and_protocol"),
        ("fn nat64_v6_translation_ineligible", "pub(super) fn nat64_v6_translation_ineligible"),
        ("fn ipv6_is_non_first_fragment", "pub(super) fn ipv6_is_non_first_fragment"),
        ("fn write_v6_to_v4_translate", "pub(super) fn write_v6_to_v4_translate"),
        ("fn write_v4_to_v6_translate", "pub(super) fn write_v4_to_v6_translate"),
        ("fn checked_ipv6_payload_len", "pub(super) fn checked_ipv6_payload_len"),
    ],
    "icmp": [
        ("struct EmbeddedV6ToV4 {", "pub(super) struct EmbeddedV6ToV4 {"),
        ("struct EmbeddedV6ToV4Layout", "pub(super) struct EmbeddedV6ToV4Layout"),
        ("struct EmbeddedV4ToV6 {", "pub(super) struct EmbeddedV4ToV6 {"),
        ("fn embedded_v6_to_v4_layout", "pub(super) fn embedded_v6_to_v4_layout"),
        ("fn translated_icmpv6_error_l4_len", "pub(super) fn translated_icmpv6_error_l4_len"),
        ("fn translate_icmpv6_message_to_icmpv4", "pub(super) fn translate_icmpv6_message_to_icmpv4"),
        ("fn translate_icmpv4_message_to_icmpv6", "pub(super) fn translate_icmpv4_message_to_icmpv6"),
        ("fn translate_embedded_v6_to_v4", "pub(super) fn translate_embedded_v6_to_v4"),
        ("fn translate_embedded_v4_to_v6", "pub(super) fn translate_embedded_v4_to_v6"),
        ("fn recompute_l4_checksum_after_nat64_v6_to_v4", "pub(super) fn recompute_l4_checksum_after_nat64_v6_to_v4"),
        ("fn recompute_l4_checksum_after_nat64_v4_to_v6", "pub(super) fn recompute_l4_checksum_after_nat64_v4_to_v6"),
        ("fn canonicalize_zero_checksum", "pub(super) fn canonicalize_zero_checksum"),
        ("fn map_icmpv6_error_to_icmpv4", "pub(super) fn map_icmpv6_error_to_icmpv4"),
        ("fn map_icmpv4_error_to_icmpv6", "pub(super) fn map_icmpv4_error_to_icmpv6"),
        ("fn embedded_icmpv6_type_to_icmpv4", "pub(super) fn embedded_icmpv6_type_to_icmpv4"),
        ("fn embedded_icmpv4_type_to_icmpv6", "pub(super) fn embedded_icmpv4_type_to_icmpv6"),
        ("fn finalize_icmpv4_checksum", "pub(super) fn finalize_icmpv4_checksum"),
        ("fn write_icmpv4_error_with_embedded", "pub(super) fn write_icmpv4_error_with_embedded"),
        ("fn write_icmpv6_error_with_embedded", "pub(super) fn write_icmpv6_error_with_embedded"),
        ("    mapped_embedded_src: Ipv4Addr,", "    pub(super) mapped_embedded_src: Ipv4Addr,"),
        ("    mapped_embedded_dst: Ipv4Addr,", "    pub(super) mapped_embedded_dst: Ipv4Addr,"),
        ("    mapped_embedded_dst_port: Option<u16>,", "    pub(super) mapped_embedded_dst_port: Option<u16>,"),
        ("    l4: &'a [u8],", "    pub(super) l4: &'a [u8],"),
        ("    traffic_class: u8,", "    pub(super) traffic_class: u8,"),
        ("    hop_limit: u8,", "    pub(super) hop_limit: u8,"),
        ("    ipv4_protocol: u8,", "    pub(super) ipv4_protocol: u8,"),
        ("    advertised_total: usize,", "    pub(super) advertised_total: usize,"),
        ("    fragment_word: u16,", "    pub(super) fragment_word: u16,"),
        ("    identification: u16,", "    pub(super) identification: u16,"),
        ("    l4_protocol: u8,", "    pub(super) l4_protocol: u8,"),
        ("    mapped_embedded_src: Ipv6Addr,", "    pub(super) mapped_embedded_src: Ipv6Addr,"),
        ("    prefix_bytes: [u8; 12],", "    pub(super) prefix_bytes: [u8; 12],"),
        ("    mapped_embedded_src_port: Option<u16>,", "    pub(super) mapped_embedded_src_port: Option<u16>,"),
    ],
    "checksum": [
        ("fn checksum16(data", "pub(super) fn checksum16(data"),
        ("fn checksum16_add", "pub(super) fn checksum16_add"),
        ("fn checksum16_fold", "pub(super) fn checksum16_fold"),
        ("fn checksum16_ipv4_pseudo", "pub(super) fn checksum16_ipv4_pseudo"),
        ("fn checksum16_ipv6_pseudo", "pub(super) fn checksum16_ipv6_pseudo"),
        ("fn checksum16_incremental", "pub(super) fn checksum16_incremental"),
        ("fn adjust_l4_checksum_v6_to_v4_incremental", "pub(super) fn adjust_l4_checksum_v6_to_v4_incremental"),
        ("fn adjust_l4_checksum_v4_to_v6_incremental", "pub(super) fn adjust_l4_checksum_v4_to_v6_incremental"),
    ],
    "frames": [
        ("fn write_v6_to_v4_nonfirst_translate", "pub(super) fn write_v6_to_v4_nonfirst_translate"),
        ("fn write_v4_to_v6_nonfirst_translate", "pub(super) fn write_v4_to_v6_nonfirst_translate"),
        ("fn frame_l3_offset", "pub(super) fn frame_l3_offset"),
    ],
}


def submodule_body(name):
    lines = open(f"userspace-dp/src/nat64/{name}.rs").read().split("\n")
    i = lines.index("use super::*;")  # header ends at the glob import
    body = lines[i + 2:]  # skip the blank line after it
    while body and body[-1] == "":
        body.pop()  # trailing newline the writer added
    return body


# 1. Un-apply the allowed edits, so what remains must be IDENTICAL to base.
recon = {}
for name, a, b in SEAMS:
    body_lines = submodule_body(name)
    for old, new in WIDEN[name]:
        hits = [i for i, l in enumerate(body_lines) if l.startswith(new)]
        assert len(hits) == 1, f"{name}: expected exactly one {new!r}, got {len(hits)}"
        i = hits[0]
        body_lines[i] = old + body_lines[i][len(new):]
    recon[name] = body_lines

# 1b. Un-apply the use relocation: the two mid-file use lines
# (pre-split 2736-2737) now sit in nat64/mod.rs's import block.
# Drop them from the residual header and re-insert them in the
# translate body immediately before the MAX_EMBEDDED_LEN doc block,
# where they sat in the flat file.
MOVED_USES = [
    "use crate::ip_proto::{PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP};",
    "use std::sync::atomic::AtomicU32;",
]
_tr = recon["translate"]
_anchor = next(
    i for i, l in enumerate(_tr)
    if l.startswith("/// Maximum embedded (quoted) original-packet bytes")
)
# In the flat file the order at the seam is: blank, use, use, blank,
# doc. The translate body still carries both blanks; insert the uses
# between them.
assert _tr[_anchor - 1] == "" and _tr[_anchor - 2] == ""
recon["translate"] = _tr[:_anchor - 1] + MOVED_USES + _tr[_anchor - 1:]

# 2. Rebuild the original line sequence: mod.rs header (pre-split lines
# 1-197) + seam bodies in order + the seams' framing lines the split
# dropped (2683 blank, 2684-2686 banner is IN translate's body, 4686
# blank) + mod.rs tail (pre-split lines 5372-end).
mod_lines = open("userspace-dp/src/nat64/mod.rs").read().split("\n")
start = next(i for i, l in enumerate(mod_lines) if l.startswith("// #16188: nat64.rs split"))
end = next(i for i, l in enumerate(mod_lines) if l.startswith("pub(crate) use translate::*;"))
# Strip the inserted block: banner (preceded by its // --- separator
# line) + mod decls + re-exports + the blank line after them. Keep
# the header's own trailing blank (pre-split line 197). The blank at
# pre-split line 5372 (before the Tests banner) was consumed as the
# separator after the re-exports, so it is re-supplied in GAPS below.
residual = mod_lines[:start - 1] + mod_lines[end + 2:]
# residual = header (197 lines) + blank + tail. The tail's test path was
# respelled for the new directory depth; un-apply it.
residual = [
    '#[path = "nat64_tests.rs"]' if l == '#[path = "../nat64_tests.rs"]' else l
    for l in residual
    if l not in MOVED_USES
]

out = []
ri = 0
taken = set()
# Blank lines that sat BETWEEN seams in the flat file and belong to no
# submodule body (the split drops them; each is a single empty line):
# 2069 / 3869 / 4844 (before a doc block that moved with its item),
# 2683 (after reserve, before the translate banner), 4686 (after
# icmp, before the checksum banner), and 5372 (before the Tests
# banner, consumed as the separator after the mod.rs re-exports).
GAPS = {2683, 4686, 5372}
# The blank line immediately BEFORE these seam-start lines (a doc
# block that moved with its item) belongs to no submodule body;
# re-supply it before the body. (Seam bodies are emitted at their
# start line; interior lines are skipped by the seam-range check.)
PRE_GAPS = {2070, 3870, 4845}
for n in range(1, len(BASE) + 1):
    hit = [s for s in SEAMS if s[1] == n]
    if hit:
        if n in PRE_GAPS:
            assert BASE[n - 2] == "", f"pre-gap line {n - 1} is not blank in the pre-split file"
            out.append("")
        out.extend(recon[hit[0][0]])
        taken.add(hit[0][0])
        continue
    if any(a < n <= b for _, a, b in SEAMS):
        continue
    if n in GAPS:
        assert BASE[n - 1] == "", f"gap line {n} is not blank in the pre-split file"
        out.append("")
        continue
    assert ri < len(residual), f"residual exhausted at pre-split line {n}"
    out.append(residual[ri])
    ri += 1

assert len(taken) == len(SEAMS), f"missed submodules: {set(s[0] for s in SEAMS) - taken}"
if ri != len(residual):
    print(f"FAIL: {len(residual) - ri} residual mod.rs lines unaccounted for")
    sys.exit(1)

if out == BASE:
    total = sum(len(v) for v in WIDEN.values())
    print(f"PASS: the split reconstructs nat64.rs EXACTLY ({len(BASE)} lines).")
    print(f"      Allowed edits, and nothing else: {total} visibility widenings")
    for name, lst in WIDEN.items():
        for old, new in lst:
            print(f"        {name}.rs: {old.strip()}  ->  {new.strip()}")
    sys.exit(0)

import difflib

print("FAIL: reconstruction differs from the pre-split file:")
for d in list(difflib.unified_diff(BASE, out, "pre-split", "reconstructed", lineterm="", n=1))[:80]:
    print(d)
sys.exit(1)

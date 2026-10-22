"""#16135 code-motion verifier (deterministic -> occupancy, first two phases).

Reconstructs the pre-split nat/allocator.rs from nat/allocator/{mod,
deterministic,occupancy}.rs and compares it byte-for-byte with the
pre-split file at the base commit, allowing ONLY the visibility
widenings enumerated below. Any other difference — a reordered
statement, a changed literal, a dropped comment, a changed atomic
ordering — fails. This is the #6988 discipline applied to the
allocator: the header invariants (allocator.rs:1-43, lock-free claim +
FIFO recycle + global -> recycle lock order) are inside the compared
byte range, so an edit to them fails here too.

Usage: python3 scripts/verify-nat-allocator-split-16135.py [base-ref]
"""
import subprocess, sys

BASE_REF = sys.argv[1] if len(sys.argv) > 1 else '974028945cff6421f3af0a5160a85ccbcf9584a2'
BASE = subprocess.run(['git', 'show', f'{BASE_REF}:userspace-dp/src/nat/allocator.rs'],
                      capture_output=True, text=True, check=True).stdout.split('\n')

W = 'pub(in crate::nat::allocator) '
ALLOWED = [
    (f'{W}struct RecycleRing {{', 'struct RecycleRing {'),
    (f'    {W}queue: VecDeque<u16>,', '    queue: VecDeque<u16>,'),
    (f'    {W}fn new(range: u32) -> Self {{', '    fn new(range: u32) -> Self {'),
    (f'    {W}fn push(&mut self, port: u16, offset: Option<u32>) -> bool {{',
     '    fn push(&mut self, port: u16, offset: Option<u32>) -> bool {'),
    (f'{W}struct AddressOccupancy {{', 'struct AddressOccupancy {'),
    (f'    {W}words: Vec<AtomicU64>,', '    words: Vec<AtomicU64>,'),
    (f'    {W}cursor: AtomicU32,', '    cursor: AtomicU32,'),
    (f'    {W}recycle: Mutex<RecycleRing>,', '    recycle: Mutex<RecycleRing>,'),
    (f'    {W}probe_word_loads: AtomicU64,', '    probe_word_loads: AtomicU64,'),
    (f'    {W}probe_claim_rmws: AtomicU64,', '    probe_claim_rmws: AtomicU64,'),
    (f'    {W}occupied: AtomicU32,', '    occupied: AtomicU32,'),
    (f'    {W}recycle_scan_pops: AtomicU64,', '    recycle_scan_pops: AtomicU64,'),
    (f'    {W}recycle_scan_walks: AtomicU64,', '    recycle_scan_walks: AtomicU64,'),
    (f'    {W}port_low: u16,', '    port_low: u16,'),
    (f'    {W}range: u32,', '    range: u32,'),
    (f'    {W}fn new(port_low: u16, range: u32) -> Self {{',
     '    fn new(port_low: u16, range: u32) -> Self {'),
    (f'    {W}fn offset_of(&self, port: u16) -> Option<u32> {{',
     '    fn offset_of(&self, port: u16) -> Option<u32> {'),
    (f'    {W}fn port_of(&self, offset: u32) -> Option<u16> {{',
     '    fn port_of(&self, offset: u32) -> Option<u16> {'),
    (f'    {W}fn is_occupied(&self, offset: u32) -> bool {{',
     '    fn is_occupied(&self, offset: u32) -> bool {'),
    (f'    {W}fn claim(&self) -> Option<u16> {{', '    fn claim(&self) -> Option<u16> {'),
    (f'    {W}fn free_recycle(&self, port: u16) -> bool {{',
     '    fn free_recycle(&self, port: u16) -> bool {'),
    (f'    {W}fn free_no_recycle(&self, port: u16) -> bool {{',
     '    fn free_no_recycle(&self, port: u16) -> bool {'),
    (f'    {W}fn reserve(&self, port: u16) -> bool {{',
     '    fn reserve(&self, port: u16) -> bool {'),
    (f'    {W}fn claim_in_block(&self, start_port: u16, end_port: u16) -> Option<u16> {{',
     '    fn claim_in_block(&self, start_port: u16, end_port: u16) -> Option<u16> {'),
    (f'    {W}fn occupied_count(&self) -> usize {{',
     '    fn occupied_count(&self) -> usize {'),
]

OLD_VIS = ('// - The remaining types (LiveAllocation, AddressOccupancy, PortAllocatorShared\n'
           '//   and its private fields, GC constants, capacity/sticky helpers) stay\n'
           '//   fully private to this file.')
NEW_VIS = ('// - The remaining types (LiveAllocation, PortAllocatorShared\n'
           '//   and its private fields, GC constants, capacity/sticky helpers) stay\n'
           '//   fully private to this file.')

def submodule_body(path, use_marker):
    lines = open(path).read().split('\n')
    i = lines.index(use_marker)
    body = lines[i + 2:]
    while body and body[-1] == '':
        body.pop()
    return body

def unapply(body_lines):
    body = '\n'.join(body_lines)
    for new, old in ALLOWED:
        if new in body:
            assert body.count(new) == 1, f'expected exactly one {new!r}'
            body = body.replace(new, old)
    return body.split('\n')

det = unapply(submodule_body('userspace-dp/src/nat/allocator/deterministic.rs',
                             'use std::net::{Ipv4Addr, Ipv6Addr};'))
occ = unapply(submodule_body('userspace-dp/src/nat/allocator/occupancy.rs',
                             'use std::sync::Mutex;'))

mod_lines = open('userspace-dp/src/nat/allocator/mod.rs').read().split('\n')
start = next(i for i, l in enumerate(mod_lines) if l == 'mod deterministic;')
end = next(i for i, l in enumerate(mod_lines) if l == 'use occupancy::{AddressOccupancy, RecycleRing};')
residual = mod_lines[:start] + mod_lines[end + 2:]
txt = '\n'.join(residual)
assert txt.count(NEW_VIS) == 1
txt = txt.replace(NEW_VIS, OLD_VIS)
rlines = txt.split('\n')
hs = next(i for i, l in enumerate(rlines) if l.startswith('// #16135: deterministic -> occupancy split'))
he_indices = [i for i, l in enumerate(rlines) if l.startswith('// un-applying exactly the enumerated widenings.')]
assert len(he_indices) >= 1
he = he_indices[-1]
assert rlines[hs - 1] == '//'
rlines = rlines[:hs - 1] + rlines[he + 1:]
residual = rlines

# Pre-split seam line ranges (1-based), derived by content at split time:
# deterministic starts at '/// #4559: IPv4 deterministic' (734) and ends
# at the closing brace of reverse_deterministic_v6 (996);
# occupancy starts at '/// #7174 (M13): the FIFO' (1654) and ends at the
# closing brace of AddressOccupancy::occupied_count's impl (2169).
SEAMS = [('det', 734, 996), ('occ', 1654, 2169)]
recon = {'det': det, 'occ': occ}
out, ri, taken = [], 0, set()
for n in range(1, len(BASE) + 1):
    hit = [s for s in SEAMS if s[1] == n]
    if hit:
        out.extend(recon[hit[0][0]]); taken.add(hit[0][0]); continue
    if any(a < n <= b for _, a, b in SEAMS):
        continue
    out.append(residual[ri]); ri += 1

assert len(taken) == len(SEAMS), f'missed submodules: {set(s[0] for s in SEAMS) - taken}'
if ri != len(residual):
    print(f'FAIL: {len(residual) - ri} residual mod.rs lines unaccounted for'); sys.exit(1)

if out == BASE:
    print(f'PASS: the split reconstructs nat/allocator.rs EXACTLY ({len(BASE)} lines).')
    print(f'      Allowed edits, and nothing else: {len(ALLOWED)} widenings (occupancy), 0 (deterministic)')
    sys.exit(0)

import difflib
print('FAIL: reconstruction differs from the pre-split file:')
for d in list(difflib.unified_diff(BASE, out, 'pre-split', 'reconstructed', lineterm='', n=1))[:80]:
    print(d)
sys.exit(1)

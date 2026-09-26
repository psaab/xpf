#!/usr/bin/env python3
"""The image inventory format (#6500) — ONE definition, two readers.

The bake signs a per-version manifest that `docs/install-images.md` calls "the
traceability record", but it recorded only the BUILD HOST's kernel
(`bake_host_kernel`) and nothing about what the image actually SHIPS: not the
guest kernel the #1930 LANE-1 channel promotes, and none of the apt package
versions `virt-customize` installed from a floating mirror. Two bakes from the
same git commit on different days produce different images, and nothing signed
recorded the difference — so "does release X ship openssl 3.x.y (CVE-YYYY)?"
and "which kernel does image X carry, so I can plan a LANE-1 arm?" both
required booting or mounting the image.

The inventory closes that. `bake.py` writes it INSIDE the image (so the running
appliance carries its own record too), reads it back out offline with
`virt-cat`, and emits it as the `xpf-<ver>.pkgs` sidecar covered by the signed
`xpf-<ver>.SHA256SUMS` — the #5042 pattern, so it is authenticated the moment
the manifest signature verifies. `publish.py` refuses a release without it,
fail-closed, alongside `validated` and `base_image_pinned`.

WHY THIS IS ITS OWN MODULE. bake.py WRITES the format and publish.py READS it.
A divergence between those two is ALWAYS a bug — never a legitimate difference
— so the format is single-sourced here rather than duplicated and bound by a
canary. Both scripts already put `scripts/dist` on sys.path for `sign`, so
neither needed a new import path.

Format (line-oriented, no parser dependency — the guest half is POSIX sh):

    # xpf appliance image inventory
    guest_kernel: 7.0.0-15-generic
    packages:
    adduser=3.152
    apt=3.1.5
    xpf=0.0.675+g0123456789ab
    ...
"""

from __future__ import annotations

# Where bake.py's virt-customize step writes the inventory inside the image.
# It stays in the shipped image on purpose: an operator on the box can answer
# the same CVE question without the dist tree.
INVENTORY_GUEST_PATH = "/etc/xpf/image-inventory"

# A bake of the appliance's runtime set installs several hundred packages. A
# floor well below that catches a collapsed enumeration — the failure mode that
# aborted every bake twice during #1926, when bake.py's apt-mark hold fragment
# produced an empty list from an unexpanded ${Package} and then from
# dpkg-query returning never-installed names — without pinning a number that
# ordinary package churn would move.
MIN_PACKAGES = 50

HEADER = "# xpf appliance image inventory"
KERNEL_KEY = "guest_kernel"
PACKAGES_KEY = "packages:"


class InventoryError(ValueError):
    """A malformed, empty, or absent image inventory."""


def sidecar_name(ver):
    """The dist-tree basename for a version's inventory sidecar."""
    return f"xpf-{ver}.pkgs"


# The in-guest writer, run by bake.py's virt-customize. POSIX sh, `set -e`, and
# it FAILS THE BAKE rather than shipping an empty or kernel-less inventory: a
# traceability record that records nothing is worse than an absent one, because
# it satisfies a presence check.
#
# `${db:Status-Status}` filters to genuinely INSTALLED packages — `dpkg-query
# -W` matches every package dpkg knows OF, including purged and
# never-installed names that are only somebody else's dependency. The format
# string is SINGLE-quoted so the guest's `sh -c` (virt-customize's one and only
# shell layer) passes `${...}` through to dpkg-query literally. bake.py's
# neighbouring hold fragment escapes `\${...}` instead because it double-quotes;
# both reach dpkg-query with the same bytes, and getting this wrong collapses
# the format to a bare newline and the inventory to nothing (#1926).
#
# The count is taken with awk, not `grep -c`: `grep -c` exits 1 on zero
# matches, and under `set -e` that would abort with dpkg's exit status standing
# in for "the inventory is empty", losing the diagnosis.
WRITE_CMD = (
    "set -e; mkdir -p /etc/xpf; "
    "kv=$(ls /lib/modules | sort -V | tail -1); "
    '[ -n "$kv" ] || { echo "FATAL: no kernel in /lib/modules — cannot record '
    'the guest kernel in the image inventory" >&2; exit 1; }; '
    "{ "
    f'echo "{HEADER}"; '
    f'echo "{KERNEL_KEY}: $kv"; '
    f'echo "{PACKAGES_KEY}"; '
    "dpkg-query -W -f='${db:Status-Status} ${Package}=${Version}\\n' "
    "| awk '$1==\"installed\"{print $2}' | sort; "
    f"}} > {INVENTORY_GUEST_PATH}; "
    f"chmod 0644 {INVENTORY_GUEST_PATH}; "
    f"n=$(awk -F= 'NF>1{{c++}} END{{print c+0}}' {INVENTORY_GUEST_PATH}); "
    f'[ "$n" -ge {MIN_PACKAGES} ] || {{ echo "FATAL: image inventory recorded '
    f'only $n packages (expected >= {MIN_PACKAGES}) — the dpkg enumeration '
    'collapsed" >&2; exit 1; }; '
    'echo "#6500: recorded image inventory ($n packages, guest kernel $kv)"'
)


def parse(text):
    """Parse an inventory into (guest_kernel, [name=version, ...]).

    Raises InventoryError with an actionable message on anything that would
    make the record useless: no kernel line, an empty kernel, or fewer than
    MIN_PACKAGES entries. Callers get a REFUSAL rather than a hollow record —
    a present-but-empty inventory passes a presence check and answers no
    question, which is strictly worse than an absent one.
    """
    if not text or not text.strip():
        raise InventoryError("image inventory is empty")
    kernel = None
    pkgs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(KERNEL_KEY + ":"):
            kernel = line.split(":", 1)[1].strip()
            continue
        if line == PACKAGES_KEY:
            continue
        if "=" in line:
            name, _, ver = line.partition("=")
            if name.strip() and ver.strip():
                pkgs.append(line)
    if not kernel:
        raise InventoryError(
            f"image inventory records no {KERNEL_KEY} — the guest kernel is "
            "the exact artifact the #1930 LANE-1 channel promotes, so an "
            "inventory without it cannot answer the question it exists for")
    if len(pkgs) < MIN_PACKAGES:
        raise InventoryError(
            f"image inventory lists only {len(pkgs)} packages (expected >= "
            f"{MIN_PACKAGES}) — the dpkg enumeration collapsed, so this record "
            "cannot answer a CVE-triage question. Refusing to treat it as an "
            "inventory")
    return kernel, pkgs


def guest_kernel(text):
    """The guest kernel recorded in an inventory. Raises InventoryError."""
    return parse(text)[0]

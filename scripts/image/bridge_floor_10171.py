"""Shared #10171 bridge nf_tables kernel-floor shell snippets."""

from __future__ import annotations


# Keep the two predicates in one module. The bake runs the offline form inside
# the image root while virt-customize is building it; validation runs the live
# form in the booted guest. Both assert the same two kernel configuration
# symbols, so a change cannot make the bake and bring-up gates disagree.
_CONFIG_ASSERT = r'''config="$root/boot/config-$kver"
if [ ! -r "$config" ]; then
    echo "FATAL: #10171 bridge nf_tables floor cannot read $config" >&2
    exit 1
fi
if ! grep -Eq '^[[:space:]]*CONFIG_BRIDGE=(m|y)$' "$config"; then
    echo "FATAL: #10171 target kernel $kver lacks CONFIG_BRIDGE=(m|y)" >&2
    exit 1
fi
if ! grep -Eq '^[[:space:]]*CONFIG_NF_TABLES_BRIDGE=(m|y)$' "$config"; then
    echo "FATAL: #10171 target kernel $kver lacks CONFIG_NF_TABLES_BRIDGE=(m|y)" >&2
    exit 1
fi
echo "bridge nf_tables kernel floor OK: $kver (CONFIG_BRIDGE + CONFIG_NF_TABLES_BRIDGE)"
'''


def bridge_floor_offline_snippet(*, test_seams: bool = False) -> str:
    """Return the bake-time check, which inspects the target root, not host.

    ``test_seams`` is intentionally opt-in and is never used by bake.py. It
    gives the hermetic tests a temporary root and kernel name without making
    either production check bypassable through the environment.
    """
    if test_seams:
        prefix = (
            "root=${XPF_FLOOR_ROOT:-/}\n"
            "kver=${XPF_FLOOR_KVER:-}\n"
        )
    else:
        prefix = "root=/\nkver=\n"
    return (
        "set -eu\n"
        + prefix
        + "if [ -z \"$kver\" ]; then\n"
        + "    set -- \"$root\"/lib/modules/*\n"
        + "    if [ \"$#\" -ne 1 ] || [ ! -d \"$1\" ]; then\n"
        + "        echo \"FATAL: #10171 cannot identify exactly one target kernel under $root/lib/modules\" >&2\n"
        + "        exit 1\n"
        + "    fi\n"
        + "    kver=${1##*/}\n"
        + "fi\n"
        + _CONFIG_ASSERT
    )


def bridge_floor_live_snippet(*, test_seams: bool = False) -> str:
    """Return the live-boot check, defaulting to the running kernel.

    ``test_seams`` is the same opt-in-only fixture escape described above.
    """
    if test_seams:
        prefix = (
            "root=${XPF_FLOOR_ROOT:-/}\n"
            "kver=${XPF_FLOOR_KVER:-$(uname -r)}\n"
        )
    else:
        prefix = "root=/\nkver=$(uname -r)\n"
    return "set -eu\n" + prefix + _CONFIG_ASSERT

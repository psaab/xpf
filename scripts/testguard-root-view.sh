#!/usr/bin/env bash
# scripts/testguard-root-view.sh -- the throwaway whole-root view that a ROOT
# run of testguard-run.sh executes in (#19084). It is not run on its own.
#
# Usage, inside `unshare -m --propagation private`, i.e. a private mount
# namespace of real root created before any user namespace exists:
#
#   testguard-root-view.sh SCRATCH CWD [PASS-THROUGH ...] -- COMMAND [ARG ...]
#
# THE CONTRACT (#19084, decided 2026-11-15): the view stops a WELL-BEHAVED
# test's ACCIDENTAL writes to production state on a disposable, VM-marked
# runner: a write, unlink, rename, chmod or device open made through an
# ordinary path, a symlink, a relative path from the caller's cwd, or an
# inherited descriptor above 2. It is NOT a containment boundary against a
# test that sets out to escape. Out of contract, and not defended here:
#   - deliberate device access: creating device nodes, mounting, loop or
#     device-mapper setup, or driving an allowlisted device's I/O at the host;
#   - metadata changes made through an INHERITED stdio descriptor (fd 0-2)
#     that the caller pointed at a host device or file, e.g. fchmod(1) when
#     the caller redirected stdout to the host's /dev/null (#19124);
#   - device-filesystem aliases the host already had: a devtmpfs or procfs
#     mounted outside /dev or /proc is REFUSED (the run does not start), not
#     isolated;
#   - concurrent replacement of a validated path (a symlink swapped between
#     validation and use);
#   - everything listed under "Its limits" in docs/testing.md (sysfs,
#     sysctls, host IPC, the VM-proof path's real root).
#
# What it builds, in that mount namespace only:
#
#  - "/" itself becomes an overlay. The lower layer is the host's root
#    filesystem and the upper layer is a tmpfs mounted on SCRATCH, which
#    exists only in this namespace and is discarded with it. Every write,
#    unlink, rename or chmod on the root filesystem lands in the upper, by
#    whatever path or directory symlink it was reached (Codex F1 on
#    11eaccc637: a four-tree enumeration let /var/log/xpf -> /srv/... escape).
#  - Every other mount from the host's table is classified by filesystem type
#    and depth, and NOTHING is left writable by omission:
#      * a procfs anywhere but /proc (a host-process alias) is refused, even
#        below a pass-through or /run (checked before either skip);
#      * /proc and /sys are bound in recursively (pseudo filesystems); a
#        mount below them is kept if it is a pseudo filesystem; if it is
#        storage, its imported copy is detached and the path overlaid, so no
#        writable host mount sits beneath the view; anything else is refused;
#      * the host's /dev and everything mounted below it are NOT carried in
#        (see /dev below);
#      * /run gets its own overlay. Host submounts below /run are NOT carried
#        into it: their mountpoints read as empty directories (R18 R3);
#      * any other storage mount (ext4, xfs, btrfs, tmpfs such as /tmp, ...)
#        is overlaid the same way as "/";
#      * filesystems overlayfs cannot use as a lower layer (vfat, as on
#        /boot/efi; read-only media) are bound in READ-ONLY;
#      * any other type is REFUSED (exit 2) before the command runs.
#    Every overlay and read-only bind is mounted nodev, so a device node on
#    the host's storage outside /dev cannot be opened in the view either.
#  - /dev is PRIVATE: a fresh nodev tmpfs holding only an allowlist (Codex P1
#    on 468f7d2371). The previous design bound the host's /dev in and masked
#    the block nodes present at setup. That was an enumeration: a node that
#    devtmpfs or udev creates LATER (loop, dm, NVMe) appeared in the shared
#    tree unmasked, and the mask's `find -xdev` skipped submounts. Now:
#      * the allowlisted CHARACTER devices (null, zero, full, random,
#        urandom, tty, net/tun) are read-only binds of the host's nodes. A
#        device's reads and writes ignore the read-only flag; chmod, chown
#        and utimes on the host inode do not;
#      * /dev/pts is a fresh devpts instance, with /dev/ptmx -> pts/ptmx, so
#        a pty is allocated there and not in the host's instance;
#      * /dev/shm is a fresh tmpfs;
#      * /dev/fd, stdin, stdout and stderr are the usual /proc/self/fd links.
#    No block node is carried, and nodev makes any node created in /dev
#    later, by anyone, unopenable.
#  - The PASS-THROUGH directories (the checkout, the TMPDIR scratch, GOCACHE,
#    GOMODCACHE, GOTMPDIR; chosen by testguard-run.sh) are bound in from the
#    host, writable and nodev. They are the only writable host storage in the view, so
#    build output and t.TempDir() land on disk, not in the tmpfs upper.
#  - pivot_root into the view and detach the old root, so the host's root
#    filesystem is not attached anywhere in this mount namespace; then cd to
#    CWD inside the view, refusing if it is not reachable there (Codex F2).
#  - Close every inherited descriptor above 2 (Codex F2), run COMMAND, and
#    report the tmpfs upper's peak use (sampled every second) on stderr.
#
# Any setup failure exits 2 before COMMAND runs. Otherwise the exit status is
# COMMAND's.
set -u

refuse() {
	echo "testguard-run: REFUSED: $*; refusing a root run that could write host state (#19084)" >&2
	exit 2
}

(($# >= 3)) || refuse "usage: testguard-root-view.sh SCRATCH CWD [PASS-THROUGH ...] -- COMMAND ..."
S=$1
cwd=$2
shift 2
pass=()
while (($#)) && [[ $1 != -- ]]; do
	pass+=("$1")
	shift
done
[[ ${1:-} == -- ]] && shift || refuse "no -- before the command"
(($#)) || refuse "no command"

# Filesystem types by treatment. A type in none of these lists is refused.
pseudo_types=" proc sysfs devtmpfs devpts mqueue cgroup cgroup2 bpf tracefs debugfs securityfs configfs fusectl hugetlbfs pstore efivarfs binfmt_misc nsfs selinuxfs "
# Accepted only below /proc, /sys or /dev, where the recursive bind carries
# them (systemd's binfmt_misc automount). Elsewhere an automount can attach
# real storage, so it is refused.
tree_only_types=" autofs rpc_pipefs "
overlay_types=" ext2 ext3 ext4 xfs btrfs f2fs tmpfs overlay zfs "
readonly_types=" vfat msdos exfat iso9660 squashfs erofs udf "

# Paths go into overlayfs option strings (comma- and colon-separated) and
# into this script's own word lists: refuse anything that would need quoting.
plain_path() { [[ $1 == /* && $1 != *[,:\\[:space:]]* ]]; }

under() { # $1 path, $2 tree: is $1 the tree itself or below it?
	[[ $2 == / || $1 == "$2" || $1 == "$2"/* ]]
}

# The host's mount table as this namespace inherited it, read before SCRATCH
# is mounted: "depth mountpoint fstype", parents before children, and for a
# mountpoint listed twice (a mount stacked on another) the later, visible one.
mounts=$(awk '{
	for (i = 7; i <= NF; i++) if ($i == "-") break
	mp = $5; t = $(i + 1)
	if (!(mp in type)) order[++n] = mp
	type[mp] = t
} END {
	for (k = 1; k <= n; k++) {
		mp = order[k]; d = (mp == "/") ? 0 : gsub("/", "/", mp)
		print d, order[k], type[order[k]]
	}
}' /proc/self/mountinfo | sort -n -s -k1,1) || refuse "cannot read the mount table"
[[ -n $mounts ]] || refuse "empty mount table"

root_type=$(awk '$2 == "/" {print $3}' <<<"$mounts")
[[ $overlay_types == *" $root_type "* ]] || refuse "the root filesystem is $root_type, which overlayfs cannot cover"

for p in "${pass[@]}"; do
	plain_path "$p" && [[ $p != / ]] || refuse "pass-through path '$p' is not a plain absolute path below /"
done
plain_path "$S" || refuse "scratch path '$S' is not a plain absolute path"

mount -t tmpfs -o mode=0700 testguard-overlay "$S" || refuse "cannot mount the overlay scratch tmpfs on $S"
m=$S/merged
mkdir "$m" || refuse "cannot create $m"

n=0
overlay_onto() { # $1 lower (host path), $2 target in the view, $3 source tag
	n=$((n + 1))
	mkdir "$S/$n.upper" "$S/$n.work" || refuse "cannot create the upper for $1"
	mount -t overlay "$3" -o "nodev,lowerdir=$1,upperdir=$S/$n.upper,workdir=$S/$n.work" "$2" ||
		refuse "cannot cover $1 with a throwaway overlay"
}

overlay_onto / "$m" testguard-root

while read -r _ mp fstype; do
	[[ $mp == / ]] && continue
	# A procfs other than /proc itself (an alias such as /srv/hostproc) is
	# the HOST pid namespace's: /srv/hostproc/1/root/etc reaches the host's
	# root filesystem past the view (Codex P1 on 41dcb74e6d). The run's own
	# /proc is replaced by its pid namespace's procfs; an alias would not be.
	# Checked BEFORE the skips below: a procfs selected as a pass-through
	# (GOCACHE=/srv/hostproc) was skipped as "the host's, by intent" and then
	# bound in writable with the pass-through (Codex P1 on 468f7d2371).
	[[ $fstype == proc && $mp != /proc ]] && refuse "$mp is a procfs other than /proc, a host-process alias"
	# A devtmpfs other than /dev itself (a bind of the host's /dev at
	# /srv/chroot/dev, say) is the HOST's device tree, later-created nodes
	# included: an ordinary open of a disk node there reaches the disk, and a
	# chmod of its null reaches the host inode. The private /dev cannot cover
	# it, so the run is refused, before the skips below, like a procfs alias
	# (Codex P1 on 26517e7917).
	[[ $fstype == devtmpfs && $mp != /dev ]] && refuse "$mp is a devtmpfs other than /dev, a host device-tree alias"
	# The host's /dev and its submounts (/dev/pts, /dev/shm, /dev/mqueue,
	# /dev/hugepages, ...) are replaced by the private /dev built below.
	under "$mp" /dev && continue
	skip=0
	for p in "${pass[@]}"; do under "$mp" "$p" && skip=1; done
	((skip)) && continue           # below a pass-through: the host's, by intent
	under "$mp" /run && [[ $mp != /run ]] && continue # hidden by /run's overlay (R18 R3)
	plain_path "$mp" || refuse "mountpoint '$mp' ($fstype) needs quoting; cannot place it in the view"
	case $mp in
	/proc | /sys)
		[[ $pseudo_types == *" $fstype "* ]] || refuse "$mp is $fstype, not a pseudo filesystem"
		mount --rbind "$mp" "$m$mp" || refuse "cannot bind $mp into the view"
		continue
		;;
	esac
	in_tree=0
	under "$mp" /proc || under "$mp" /sys && in_tree=1
	if [[ $pseudo_types == *" $fstype "* ]] || { ((in_tree)) && [[ $tree_only_types == *" $fstype "* ]]; }; then
		# Below /proc or /sys it came with the recursive bind.
		((in_tree)) && continue
		mount --bind "$mp" "$m$mp" || refuse "cannot bind $mp ($fstype) into the view"
		continue
	fi
	# Storage below /proc or /sys (a root-fs bind) came in with the recursive
	# bind as the HOST's writable mount.
	# Detach that copy before covering the path, so no writable host storage
	# sits beneath the view's overlay (Codex P1 on 41dcb74e6d). The lower
	# layer below is still the host's mount, reached outside the view.
	if ((in_tree)); then
		umount -l "$m$mp" || refuse "cannot detach the imported $mp beneath its cover"
	fi
	if [[ $overlay_types == *" $fstype "* ]]; then
		overlay_onto "$mp" "$m$mp" "testguard-$fstype"
	elif [[ $readonly_types == *" $fstype "* ]]; then
		mount --bind "$mp" "$m$mp" && mount -o remount,bind,ro,nodev "$m$mp" ||
			refuse "cannot bind $mp ($fstype) into the view read-only"
	else
		refuse "$mp is $fstype, which this wrapper can neither overlay nor bind read-only"
	fi
done <<<"$mounts"

# The private /dev (Codex P1 on 468f7d2371; see the header). nodev on the
# tmpfs: a node created in it later, by anyone, cannot be opened. The
# allowlisted character devices are binds of the host's nodes, so their own
# mounts keep the host devtmpfs's dev permission, and they are remounted
# read-only so the host inode's mode, owner and times cannot change.
d=$m/dev
mount -t tmpfs -o mode=0755,nosuid,nodev,size=1m testguard-dev "$d" || refuse "cannot mount the private /dev"
for name in null zero full random urandom tty net/tun; do
	if [[ ! -c /dev/$name || -L /dev/$name ]]; then
		[[ $name == net/tun ]] && continue # no tun module: nothing to carry
		refuse "the host has no character device /dev/$name for the private /dev"
	fi
	mkdir -p "$(dirname "$d/$name")" && : >"$d/$name" &&
		mount --bind "/dev/$name" "$d/$name" && mount -o remount,bind,ro "$d/$name" ||
		refuse "cannot carry /dev/$name into the private /dev"
done
tty_gid=$(getent group tty | cut -d: -f3)
mkdir "$d/pts" "$d/shm" &&
	mount -t devpts -o "newinstance,ptmxmode=0666,mode=0620${tty_gid:+,gid=$tty_gid},nosuid,noexec" testguard-devpts "$d/pts" &&
	ln -s pts/ptmx "$d/ptmx" ||
	refuse "cannot mount a private devpts"
mount -t tmpfs -o mode=1777,nosuid,nodev testguard-shm "$d/shm" || refuse "cannot mount a private /dev/shm"
ln -s /proc/self/fd "$d/fd" && ln -s /proc/self/fd/0 "$d/stdin" &&
	ln -s /proc/self/fd/1 "$d/stdout" && ln -s /proc/self/fd/2 "$d/stderr" ||
	refuse "cannot create the /dev/fd links"

# The writable pass-through, parents before children.
while read -r p; do
	[[ -n $p ]] || continue
	# nodev: permission to write build files is not permission to open a
	# device node that happens to sit in the checkout, TMPDIR or a Go cache
	# (Codex P1 on 26517e7917). A bind copies its source mount's flags.
	mount --bind "$p" "$m$p" && mount -o remount,bind,nodev "$m$p" ||
		refuse "cannot bind the pass-through $p into the view (nodev)"
done < <(for p in "${pass[@]}"; do printf '%s %s\n' "$(tr -cd / <<<"$p" | wc -c)" "$p"; done | sort -n -s -k1,1 | cut -d' ' -f2-)

# Enter the view. pivot_root, not chroot: after the old root is detached the
# host's root filesystem is attached nowhere in this namespace, so neither a
# chroot escape nor detaching a mount inside the view can reach it. util-linux
# no longer ships pivot_root(8) on Debian, so the syscall comes from perl.
exec 8<"$S" || refuse "cannot hold the scratch tmpfs open"
mkdir "$m/.testguard-oldroot" || refuse "cannot create the old-root mountpoint"
cd "$m" || refuse "cannot enter $m"
perl -e 'require "syscall.ph"; syscall(&SYS_pivot_root, $ARGV[0], $ARGV[1]) == 0 or die "pivot_root: $!\n"' \
	. .testguard-oldroot || refuse "pivot_root into the view failed"
cd / || refuse "cannot cd to the view's root"
umount -l /.testguard-oldroot || refuse "cannot detach the host root from the view"
rmdir /.testguard-oldroot 2>/dev/null
cd -- "$cwd" 2>/dev/null || refuse "the working directory $cwd is not reachable inside the view"

used_kib() { # the scratch tmpfs's use, via the descriptor held open above
	local b
	read -ra b < <(stat -f -c '%b %f %S' /proc/self/fd/8 2>/dev/null) && ((${#b[@]} == 3)) || return 1
	echo $(((b[0] - b[1]) * b[2] / 1024))
}
(
	exec </dev/null >/dev/null 2>&1
	peak=0
	while u=$(used_kib); do
		((u > peak)) && peak=$u && echo "$peak" >/proc/self/fd/8/.peak-kib
		sleep 1
	done
) &
sampler=$!

# Run the command with no inherited descriptor above 2: a directory or file
# descriptor opened on the host before the view existed would still reach the
# host's storage (Codex F2).
(
	for fd in /proc/self/fd/*; do
		fd=${fd##*/}
		((fd > 2)) && eval "exec $fd>&-"
	done
	exec "$@"
) &
child=$!
trap 'kill -TERM "$child" 2>/dev/null' TERM INT HUP
while :; do
	wait "$child"
	rc=$?
	kill -0 "$child" 2>/dev/null || break
done
trap - TERM INT HUP
kill "$sampler" 2>/dev/null
wait "$sampler" 2>/dev/null
final=$(used_kib) || final='?'
peak=$(cat /proc/self/fd/8/.peak-kib 2>/dev/null) || peak=0
[[ $final =~ ^[0-9]+$ ]] && ((final > peak)) && peak=$final
echo "testguard-run: root view: tmpfs upper peak ${peak} KiB (sampled every 1 s), ${final} KiB at exit (#19084)" >&2
exit "$rc"

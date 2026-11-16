#!/bin/bash
# scripts/provision-testrunner.sh -- provision an xpf test-runner VM (#19035).
#
# Tests never run on the workstation; they run in these VMs on the lab hosts
# through scripts/vm-test-run.sh. To create a runner (example: udp):
#
#   incus init images:debian/14/cloud udp:xpf-testrunner --vm \
#       --storage default --network incusbr-udp \
#       -c limits.cpu=8 -c limits.memory=32GiB -c limits.cpu.priority=1 \
#       -c security.secureboot=false
#   incus config device set udp:xpf-testrunner root size=150GiB
#   incus start udp:xpf-testrunner
#   scripts/provision-testrunner.sh --runner udp:xpf-testrunner
#
# The low limits.cpu.priority keeps the lab firewall VMs ahead of test load,
# so gate measurement on the same host keeps priority.
#
# Run from the workstation, --runner derives the toolchain versions from this
# checkout, pushes this script into the VM, runs it there as root, and then
# checks that scripts/resolve-deadcode-go.sh resolves for the runner user:
#   - the build Go: go.mod's `toolchain` line if present, else its `go` line;
#   - the deadcode Go: DEADCODE_GO_VERSION in scripts/resolve-deadcode-go.sh.
#     The pinned deadcode analyser panics under other Go series, so it needs
#     this toolchain beside the build one. Without it, `make test-go`'s
#     deadcode leg on a runner was a silent NOT-EXAMINED (#19152).
#     It goes to /usr/lib/go-<version>, which the resolver finds for root
#     and runner alike, and /etc/profile.d/xpf-testrunner.sh exports
#     XPF_DEADCODE_REQUIRE=1, so on a provisioned runner a missing deadcode
#     toolchain is a FAIL, not a skip.
#
#   scripts/provision-testrunner.sh --runner <remote:instance> [--toolchains-only | --gc-toolchains]
#   scripts/provision-testrunner.sh --print-versions
#
# Toolchains are never replaced in place (fold of Codex on b7f). Each Go
# release lives in its own versioned directory, /usr/local/go-<version> (build)
# and /usr/lib/go-<version> (deadcode), created once: unpacked beside it,
# checked to report that version, then renamed into the empty path. The build
# Go is PUBLISHED by pointing /usr/local/bin/go, /usr/bin/go (and gofmt) at it,
# each flipped atomically (a new symlink renamed over the old one), so a crash
# leaves the old link or the new one, never a missing path, and a lane already
# running keeps its old tree. /usr/local/go becomes a symlink too on a fresh
# runner; an older runner's real /usr/local/go directory is left alone.
#
# Old versions are never deleted automatically. --gc-toolchains removes the
# unpublished versions, that legacy directory and stale staging directories,
# and is refused (exit 75) while a lane is live (a runner process, a process
# under /work, or a held --root lane lock).
#
# --toolchains-only installs and publishes only the two Go toolchains and the
# profile entry, skipping apt, rustup and the account setup: use it to bring
# an already provisioned runner up to date; it is safe with lanes running.
# --print-versions prints the derived versions and touches nothing. A runner
# that is not RUNNING (a FROZEN one is paused by a gate cell) is refused with
# exit 75 and left alone.
set -euo pipefail

# derive_versions: set go_ver and dc_ver from this checkout.
derive_versions() {
	local root
	root=$(cd "$(dirname "$0")/.." && pwd)
	go_ver=$(awk '$1 == "toolchain" { t = $2; sub(/^go/, "", t) } $1 == "go" { g = $2 } END { print (t != "" ? t : g) }' "$root/go.mod")
	dc_ver=$(sed -n 's/^DEADCODE_GO_VERSION=//p' "$root/scripts/resolve-deadcode-go.sh")
	local v
	for v in "$go_ver" "$dc_ver"; do
		if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
			echo "provision-testrunner: cannot derive a full Go release from go.mod and scripts/resolve-deadcode-go.sh (got build '$go_ver', deadcode '$dc_ver')" >&2
			exit 2
		fi
	done
}

# Sourced (scripts/provision-testrunner-selftest.sh): define the functions
# below and stop; the selftest calls them against a scratch tree.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
case "${1:-}" in
--print-versions)
	derive_versions
	echo "go $go_ver"
	echo "deadcode-go $dc_ver"
	exit 0
	;;
--runner)
	runner=${2:-}
	scope=full
	case "${3:-}" in
	"") ;;
	--toolchains-only) scope=toolchains ;;
	--gc-toolchains) scope=gc ;;
	*) runner= ;;
	esac
	if [[ -z "$runner" ]]; then
		echo "usage: $0 --runner <remote:instance> [--toolchains-only | --gc-toolchains] | --print-versions" >&2
		exit 2
	fi
	derive_versions
	status=$(incus info "$runner" 2>/dev/null | sed -n 's/^Status: //p')
	if [[ "$status" != RUNNING ]]; then
		echo "provision-testrunner: $runner is '${status:-unknown}', not RUNNING; refusing (a FROZEN runner is paused by a gate cell)" >&2
		exit 75
	fi
	echo "provision-testrunner: $runner ($scope): go $go_ver, deadcode go $dc_ver"
	incus file push "$0" "$runner/root/provision-testrunner.sh"
	incus exec "$runner" --env XPF_GO_VERSION="$go_ver" --env XPF_DEADCODE_GO_VERSION="$dc_ver" \
		--env XPF_PROVISION_SCOPE="$scope" -- bash /root/provision-testrunner.sh
	# The acceptance check, run the way vm-test-run.sh runs a lane: a login
	# shell as runner, so the profile entry applies.
	resolved=$(incus exec "$runner" -- su - runner -c 'sh -s' <"$(dirname "$0")/resolve-deadcode-go.sh")
	echo "provision-testrunner: $runner: the deadcode resolver picks $resolved"
	exit 0
	;;
esac
fi

# lane_activity: print evidence of a live test lane, nothing when idle. A lane
# is any `runner` process except its idle systemd --user session, any process
# whose cwd is under /work, or a --root lane holding vm-test-run's runner lock
# (#19162).
lane_activity() {
	local p c
	ps -eo user=,pid=,args= | awk '$1 == "runner" && $3 != "/usr/lib/systemd/systemd" && $3 != "(sd-pam)" { print "runner process: " $0 }'
	for p in /proc/[0-9]*; do
		c=$(readlink "$p/cwd" 2>/dev/null) || continue
		case "$c" in /work/*) echo "pid ${p#/proc/} has cwd $c" ;; esac
	done
	if [[ -e /run/xpf-root-lane.lock ]] && ! flock -n /run/xpf-root-lane.lock true; then
		echo "a --root lane holds /run/xpf-root-lane.lock"
	fi
}

# fetch_go <version> <dest>: unpack the go<version> release tarball into
# <dest> (creating <dest>/go).
fetch_go() {
	curl -fsSL "https://go.dev/dl/go${1}.linux-amd64.tar.gz" | tar -C "$2" -xzf -
}

# install_go_version <version> <dir>: make <dir> (a versioned path such as
# /usr/local/go-1.24.9) hold go<version>. Never replaces: a present <dir> that
# holds that version is left alone, and one that does not is an error (only
# --gc-toolchains removes it). The tree is unpacked beside <dir>, checked, and
# renamed into the empty path, so <dir> is either absent or complete.
install_go_version() {
	local ver=$1 dir=$2 stage
	if [[ -e "$dir" || -L "$dir" ]]; then
		if "$dir/bin/go" version 2>/dev/null | grep -q " go$ver "; then
			return 0
		fi
		echo "provision-testrunner: $dir exists but does not hold go$ver; it is never replaced in place (remove it with --gc-toolchains on an idle runner)" >&2
		return 2
	fi
	stage=$(mktemp -d "$(dirname "$dir")/.go-$ver.stage.XXXXXX")
	if ! fetch_go "$ver" "$stage" || ! "$stage/go/bin/go" version 2>/dev/null | grep -q " go$ver "; then
		rm -rf "$stage"
		echo "provision-testrunner: the downloaded toolchain is not go$ver; nothing installed" >&2
		return 2
	fi
	mv -T "$stage/go" "$dir"
	rmdir "$stage"
}

# publish_link <target> <link>: point <link> at <target> atomically. A new
# symlink is made beside it and renamed over it; rename(2) replaces the old
# link in one step, so <link> always resolves to the old target or the new.
# A <link> that is a real directory (a pre-versioned /usr/local/go) is left
# alone: it is not ours to replace, and --gc-toolchains removes it.
publish_link() {
	local target=$1 link=$2 tmp
	if [[ -d "$link" && ! -L "$link" ]]; then
		return 0
	fi
	tmp="$(dirname "$link")/.$(basename "$link").publish.$$"
	ln -sfn "$target" "$tmp"
	rename_into_place "$tmp" "$link" || { rm -f "$tmp"; return 2; }
}
# rename_into_place <src> <dst>: the one rename (a hook for the selftest).
rename_into_place() { mv -T "$1" "$2"; }

# gc_toolchains <keep-build-dir> <keep-dc-dir>: remove every other versioned
# toolchain, a pre-versioned /usr/local/go directory and stale staging dirs.
# Refused (75) while a lane is live. GO_ROOTS lists the parents to sweep.
gc_toolchains() {
	local keep_build=$1 keep_dc=$2 busy d
	busy=$(lane_activity)
	if [[ -n "$busy" ]]; then
		echo "provision-testrunner: refusing --gc-toolchains while a lane is live; drain the runner first:" >&2
		printf '  %s\n' "$busy" | head -5 >&2
		return 75
	fi
	for d in "${GC_LOCAL:-/usr/local}"/go "${GC_LOCAL:-/usr/local}"/go-* "${GC_LIB:-/usr/lib}"/go-* \
		"${GC_LOCAL:-/usr/local}"/.go-* "${GC_LIB:-/usr/lib}"/.go-*; do
		[[ -e "$d" || -L "$d" ]] || continue
		[[ "$d" == "$keep_build" || "$d" == "$keep_dc" ]] && continue
		if [[ "$d" == */go && -L "$d" ]]; then
			continue # the published /usr/local/go link itself
		fi
		echo "provision-testrunner: gc: removing $d" >&2
		rm -rf "$d"
	done
}

[[ "${BASH_SOURCE[0]}" == "$0" ]] || return 0

# In the VM, as root.
systemd-detect-virt --vm -q || { echo "provision-testrunner: refusing to run outside a VM" >&2; exit 2; }
go_ver=${XPF_GO_VERSION:?run this from the workstation as: scripts/provision-testrunner.sh --runner <remote:instance>}
dc_ver=${XPF_DEADCODE_GO_VERSION:?run this from the workstation as: scripts/provision-testrunner.sh --runner <remote:instance>}
scope=${XPF_PROVISION_SCOPE:-full}

if [[ "$scope" == full ]]; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries
	apt-get install -y -qq build-essential clang llvm lld libbpf-dev libxdp-dev libelf-dev zlib1g-dev libzstd-dev \
	  pkg-config git make python3 python3-venv iproute2 nftables ethtool tcpdump iperf3 bpftool kmod \
	  debhelper devscripts shellcheck jq curl ca-certificates protobuf-compiler rsync sudo util-linux \
	  "linux-headers-$(uname -r)" >/dev/null
	# The crate's build.rs pins libelf >= 0.195 (#9931, userspace-dp/build_support/libversions.rs);
	# Ubuntu 26.04 ships 0.194, so runners use Debian 14 (forky) like the deb-building workstation.
	elf_ver=$(dpkg-query -W -f='${Version}' libelf-dev | sed 's/-.*//')
	if ! dpkg --compare-versions "$elf_ver" ge 0.195; then
	  echo "provision-testrunner: libelf-dev $elf_ver < 0.195 (#9931); use a Debian 14 image" >&2
	  exit 2
	fi
fi
build_dir="/usr/local/go-$go_ver"
dc_dir="/usr/lib/go-$dc_ver"
if [[ "$scope" == gc ]]; then
	gc_toolchains "$build_dir" "$dc_dir"
	exit $?
fi
install_go_version "$go_ver" "$build_dir"
# Some selftests pin PATH to "...:/usr/bin:/bin" (deploy-lib-selftest's
# clean-PATH make-deb guard), and the workstation's Go is in /usr/bin.
for tool in go gofmt; do
	publish_link "$build_dir/bin/$tool" "/usr/local/bin/$tool"
	publish_link "$build_dir/bin/$tool" "/usr/bin/$tool"
done
publish_link "$build_dir" /usr/local/go
install_go_version "$dc_ver" "$dc_dir"
cat > /etc/profile.d/xpf-testrunner.sh <<'PROFILE'
# Written by scripts/provision-testrunner.sh (#19152). This runner carries the
# deadcode toolchain (/usr/lib/go-<version>), so a missing one must FAIL the
# deadcode gates here, not skip them as NOT-EXAMINED (exit 77).
export XPF_DEADCODE_REQUIRE=1
PROFILE
if [[ "$scope" == full ]]; then
	id runner >/dev/null 2>&1 || useradd -m -s /bin/bash runner
	echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner
	su - runner -c 'command -v rustup >/dev/null 2>&1 || (curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain 1.98.1 >/dev/null)'
	su - runner -c '. ~/.cargo/env; rustup toolchain install 1.98.1 --profile minimal -c rustfmt -c clippy >/dev/null; rustup default 1.98.1 >/dev/null; rustc --version; cargo --version'
	mkdir -p /work && chown runner:runner /work
	install -d -o runner -g runner /home/runner/.cache /home/runner/.cache/go-build
	install -d -m 1777 /wtgt
	echo "xpf-testrunner: provisioned $(date -u +%FT%TZ)" > /etc/xpf-testrunner
fi
go version
"/usr/lib/go-$dc_ver/bin/go" version

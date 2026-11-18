#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./install.sh [--server] [--wheel FILE] [--choice known-good|latest] [--image] [-- SETUP-ARGS]

  --server   set up an Ubuntu server: a service behind Caddy with HTTPS (run with sudo)
  --wheel    install this wheel instead of the tag's release (or a build from this folder)
  --choice   the scanners: known-good (the versions this GitMortem was tested with) or
             latest (each tool's newest compatible release at least 7 days old)
  --image    stop once GitMortem is installed (the Docker image's build)
  -- ...     with --server, the rest goes to `gitmortem setup-server`, e.g.
             -- --address gm.example.org --admin alice --password-stdin
USAGE
}

say() { printf '%s\n' "$*"; }
ok() { say "[+] $*"; }
info() { say "[*] $*"; }
die() { say "[!] $*" >&2; exit 1; }

server=0
image=0
wheel=""
choice=""
setup_args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --) shift; setup_args=("$@"); break ;;
        --server) server=1 ;;
        --image) image=1 ;;
        --wheel) [ $# -ge 2 ] || { usage >&2; exit 2; }; wheel="$2"; shift ;;
        --choice) [ $# -ge 2 ] || { usage >&2; exit 2; }; choice="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) say "[!] unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
case "$choice" in ""|known-good|latest) ;; *) die "--choice is known-good or latest" ;; esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$here"

if [ "$server" = 1 ] && [ "$(id -u)" != 0 ]; then
    die "--server sets up a system service, so run it with sudo"
fi

need() { command -v "$1" >/dev/null 2>&1; }
if ! need git && [ "$server" = 1 ] && need apt-get; then
    info "installing git from Ubuntu's packages"
    DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q git >/dev/null
fi
need git || die "git is needed: install git 2.34 or newer and run this again"
need curl || die "curl is needed: install curl and run this again"

version_of_wheel() {
    basename "$1" | sed -n 's/^gitmortem-\([0-9][0-9.]*\)-py3-none-any\.whl$/\1/p'
}

build=0
if [ -n "$wheel" ]; then
    [ -f "$wheel" ] || die "no wheel at $wheel"
    wheel="$(cd "$(dirname "$wheel")" && pwd -P)/$(basename "$wheel")"
    version="$(version_of_wheel "$wheel")"
    [ -n "$version" ] || die "$wheel is not a GitMortem wheel"
elif [ -e "$here/.git" ]; then
    top="$(git rev-parse --show-toplevel 2>&1)" ||
        die "git cannot read this checkout, so its release tag cannot be read: $(printf '%s' "$top" | head -n 1)"
    [ "$(cd "$top" 2>/dev/null && pwd -P)" = "$here" ] ||
        die "git reads $top as this checkout's top, not $here: run this from the checkout's top"
    if tag="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null)"; then
        version="${tag#v}"
    else
        build=1
        from="commit $(git rev-parse --short HEAD 2>/dev/null || echo "not yet made")"
        [ -z "$(git status --porcelain 2>/dev/null)" ] || from="$from, with uncommitted changes"
        info "this checkout is not at a release tag: building GitMortem from it ($from)"
    fi
else
    build=1
    info "this folder is no release tag's checkout: building GitMortem from it"
fi

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) target=x86_64-unknown-linux-gnu ;;
    Linux-aarch64|Linux-arm64) target=aarch64-unknown-linux-gnu ;;
    Darwin-x86_64) target=x86_64-apple-darwin ;;
    Darwin-arm64) target=aarch64-apple-darwin ;;
    *) die "no install for $(uname -s) on $(uname -m): Linux or macOS on x86_64 or arm64 only" ;;
esac

if [ "$server" = 1 ] || [ "$image" = 1 ]; then
    root="/opt/gitmortem"
else
    root="${XDG_DATA_HOME:-$HOME/.local/share}/gitmortem-app"
fi
umask 022
mkdir -p "$root/bin"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

sha256_of() {
    if need sha256sum; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 2 -o "$2" "$1"; }

pins="$here/packaging/uv-version.txt"
uv_version="$(awk '$1 == "version" { print $2 }' "$pins")"
uv_sha="$(awk -v t="$target" '$1 == "sha256" && $2 == t { print $3 }' "$pins")"
if [ -z "$uv_version" ] || [ -z "$uv_sha" ]; then
    die "$pins names no uv for $target"
fi
uv="$root/bin/uv"
if [ ! -x "$uv" ] || [ "$("$uv" --version 2>/dev/null | cut -d' ' -f2)" != "$uv_version" ]; then
    info "uv $uv_version"
    fetch "https://github.com/astral-sh/uv/releases/download/$uv_version/uv-$target.tar.gz" "$work/uv.tar.gz"
    [ "$(sha256_of "$work/uv.tar.gz")" = "$uv_sha" ] || die "uv $uv_version does not match the SHA-256 recorded for it"
    tar -xzf "$work/uv.tar.gz" --no-same-owner --no-same-permissions -C "$work" "uv-$target/uv"
    install -m 0755 "$work/uv-$target/uv" "$uv.new"
    mv -f "$uv.new" "$uv"
fi

node_fits() {
    local v major minor
    v="$("$1" --version 2>/dev/null)" || return 1
    v="${v#v}"
    major="${v%%.*}"
    minor="${v#*.}"
    minor="${minor%%.*}"
    case "$major" in "" | *[!0-9]*) return 1 ;; esac
    case "$minor" in "" | *[!0-9]*) return 1 ;; esac
    if [ "$major" -eq 20 ]; then [ "$minor" -ge 19 ]; return; fi
    if [ "$major" -eq 22 ]; then [ "$minor" -ge 12 ]; return; fi
    [ "$major" -ge 23 ]
}

use_node() {
    if need node && need npm && node_fits node; then
        info "the frontend, with Node.js $(node --version) from this machine"
        return
    fi
    local pins="$here/packaging/node-version.txt" node_version plat node_sha dir
    node_version="$(awk '$1 == "version" { print $2 }' "$pins")"
    plat="$(awk -v t="$target" '$1 == "sha256" && $2 == t { print $3 }' "$pins")"
    node_sha="$(awk -v t="$target" '$1 == "sha256" && $2 == t { print $4 }' "$pins")"
    if [ -z "$node_version" ] || [ -z "$plat" ] || [ -z "$node_sha" ]; then
        die "no Node.js 20.19+ or 22.12+ here, and $pins names none for $target: install Node.js and run this again, or pass --wheel FILE"
    fi
    dir="$root/node/$node_version-$target"
    if [ -e "$root/node" ]; then
        local loose
        loose="$(find "$root/node" \( ! -user "$(id -u)" -o \( ! -type l \( -perm -0020 -o -perm -0002 \) \) \) -print -quit 2>/dev/null)" ||
            die "$root/node cannot be read: remove it and run this again"
        [ -z "$loose" ] ||
            die "$loose is owned by another user or writable by others, who could change the Node.js that builds GitMortem: remove $root/node and run this again"
    fi
    if [ ! -x "$dir/bin/node" ] || [ "$("$dir/bin/node" --version 2>/dev/null)" != "$node_version" ]; then
        info "Node.js $node_version, for the frontend (this machine has none 20.19+ or 22.12+)"
        fetch "https://nodejs.org/dist/$node_version/node-$node_version-$plat.tar.gz" "$work/node.tar.gz"
        [ "$(sha256_of "$work/node.tar.gz")" = "$node_sha" ] ||
            die "Node.js $node_version does not match the SHA-256 recorded for it"
        mkdir -p "$work/node"
        tar -xzf "$work/node.tar.gz" --no-same-owner --no-same-permissions -C "$work/node"
        local fresh="$work/node/node-$node_version-$plat" ran
        if [ "$(id -u)" = 0 ]; then
            chown -R 0:0 "$fresh"
        fi
        if ! ran="$("$fresh/bin/node" --version 2>&1)"; then
            die "Node.js $node_version does not run on this machine: $(printf '%s' "$ran" | head -n 1). Install what it names (libatomic.so.1 is in Debian's and Ubuntu's libatomic1: sudo apt-get install libatomic1) and run this again, or pass --wheel FILE"
        fi
        [ "$ran" = "$node_version" ] || die "the Node.js unpacked says it is $ran, not $node_version"
        mkdir -p "$root/node"
        rm -rf "$dir"
        mv "$fresh" "$dir"
    else
        info "the frontend, with Node.js $node_version from $dir"
    fi
    PATH="$dir/bin:$PATH"
}

npm_step() {
    local name="$1"
    shift
    if ! npm_config_update_notifier=false npm --prefix "$here/frontend" "$@" >"$work/npm.log" 2>&1; then
        tail -n 40 "$work/npm.log" >&2
        die "the frontend did not build (npm $name)"
    fi
}

build_wheel() {
    export TMPDIR="$work/tmp" NODE_COMPILE_CACHE="$work/node-compile-cache"
    mkdir -m 0700 "$TMPDIR" "$NODE_COMPILE_CACHE"
    use_node
    npm_step ci ci --no-audit --no-fund
    npm_step "run build" run build
    info "the wheel, its build dependencies by hash from uv.lock"
    "$uv" export -q --project "$here" --frozen --only-group build --no-emit-project \
        --format requirements-txt --output-file "$work/build-constraints.txt"
    "$uv" build -q --wheel --python "$python" --build-constraints "$work/build-constraints.txt" \
        --require-hashes --out-dir "$work/dist" "$here"
    set -- "$work/dist"/gitmortem-*-py3-none-any.whl
    if [ $# != 1 ] || [ ! -f "$1" ]; then
        die "uv build left no single GitMortem wheel in $work/dist"
    fi
    local said
    said="$("$python" -I "$here/scripts/build_package.py" --check "$1")" ||
        die "the wheel built from this checkout is not whole: ${said#\[!\] }"
    wheel="$1"
    version="$(version_of_wheel "$wheel")"
    [ -n "$version" ] || die "$wheel is not a GitMortem wheel"
}

export UV_PYTHON_INSTALL_DIR="$root/python" UV_CACHE_DIR="$root/cache" UV_NO_CONFIG=1
"$uv" python install -q 3.12
python="$("$uv" python find --managed-python 3.12)"
if [ "$build" = 1 ]; then
    build_wheel
elif [ -z "$wheel" ]; then
    origin="$(git remote get-url origin 2>/dev/null || true)"
    slug="$(printf '%s' "$origin" | sed -n -E 's#^(https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/.]+)(\.git)?/?$#\2#p')"
    [ -n "$slug" ] || die "origin is not a GitHub repository, so the release's wheel cannot be found: pass --wheel FILE"
    name="gitmortem-$version-py3-none-any.whl"
    base="https://github.com/$slug/releases/download/$tag"
    info "GitMortem $version from $slug's release $tag"
    for file in "$name" SHA256SUMS; do
        fetch "$base/$file" "$work/$file" ||
            die "GitHub did not serve $file for release $tag of $slug: once the release is published and the repository public, run this again, or pass --wheel FILE"
    done
    listed="$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1 }' "$work/SHA256SUMS")"
    if [ -z "$listed" ] || [ "$(sha256_of "$work/$name")" != "$listed" ]; then
        die "$name does not match the release's SHA256SUMS"
    fi
    fetch "https://api.github.com/repos/$slug/releases/tags/$tag" "$work/release.json" ||
        die "GitHub did not answer for release $tag, so the wheel cannot be checked against its record: GitHub answers 60 such requests an hour from one address, so try again later"
    digest="$("$python" -I - "$work/release.json" "$name" <<'PY'
import json, sys
path, name = sys.argv[1:]
try:
    with open(path, encoding="utf-8") as held:
        release = json.load(held)
except (OSError, ValueError):
    release = {}
assets = release.get("assets", []) if isinstance(release, dict) else []
named = [a for a in assets if isinstance(a, dict) and a.get("name") == name]
digest = named[0].get("digest") if named else None
print(digest if isinstance(digest, str) else "")
PY
)"
    [ -n "$digest" ] || die "GitHub's record of release $tag names no digest for $name"
    [ "$digest" = "sha256:$listed" ] || die "$name does not match GitHub's digest for it"
    wheel="$work/$name"
fi
wheel_sha="$(sha256_of "$wheel")"

release="$root/releases/$version-${wheel_sha:0:12}"
marker="$release/.gitmortem-complete"
if [ -f "$marker" ] && [ "$(cat "$marker")" = "$wheel_sha" ]; then
    ok "GitMortem $version already in $release"
else
    info "Python 3.12 and GitMortem $version's environment"
    "$uv" venv -q --clear --python 3.12 "$release"
    "$uv" export -q --project "$here" --format requirements-txt --no-dev --no-emit-project --frozen \
        --output-file "$work/requirements.txt"
    "$uv" pip install -q --python "$release" --require-hashes -r "$work/requirements.txt"
    "$uv" pip install -q --python "$release" --no-deps "$wheel"
    printf '%s\n' "$wheel_sha" > "$marker"
    ok "GitMortem $version in $release"
fi

find "$root" -xdev -type f -perm -0002 -exec chmod go-w {} +

if [ "$image" = 1 ]; then
    ln -sfn "$release" "$root/current"
    exit 0
fi

ask_choice() {
    [ -n "$choice" ] && return
    [ -r /dev/tty ] || die "pass --choice known-good or --choice latest"
    say "Install the scanners known-good (the versions this GitMortem was tested with)"
    say "or latest (each tool's newest compatible release at least 7 days old)?"
    while :; do
        printf '[known-good/latest] ' >/dev/tty
        read -r choice </dev/tty || die "no answer given"
        case "$choice" in known-good|latest) break ;; *) say "Type known-good or latest." ;; esac
    done
}

if [ "$server" = 1 ]; then
    ask_choice
    rm -rf -- "$work"
    trap - EXIT
    exec "$release/bin/gitmortem" setup-server --choice "$choice" "${setup_args[@]+"${setup_args[@]}"}"
fi
ask_choice
mkdir -p "$HOME/.local/bin"
ln -sfn "$release/bin/gitmortem" "$HOME/.local/bin/gitmortem"
"$release/bin/gitmortem" install-scanners --choice "$choice"
case ":$PATH:" in
    *":$HOME/.local/bin:"*) ok "Run: gitmortem local" ;;
    *) ok "Run: $HOME/.local/bin/gitmortem local (add $HOME/.local/bin to your PATH to type gitmortem alone)" ;;
esac

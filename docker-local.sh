#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./docker-local.sh [--repos DIR]... [--port N] [--scanners known-good|latest|none]
                         [--name NAME] [--no-browser]

  --repos       a folder of repositories to scan, mounted read-only at /repos/<its name>;
                repeatable. Without one, only uploads can be scanned.
  --port        the port on 127.0.0.1 (default 8766, beside gitmortem local's 8765)
  --scanners    what the first start installs into the volume (default known-good)
  --name        the image, the container, its network and its volume (default gitmortem-local)
  --no-browser  do not open the browser once GitMortem answers
USAGE
}

say() { printf '%s\n' "$*"; }
info() { say "[*] $*"; }
die() { say "[!] $*" >&2; exit 1; }

LOCAL_ARGS=(--allowed-host localhost --allowed-host 127.0.0.1 --insecure-cookies --key-file /data/instance.key --scan-root-base /repos)
HARDENING=(--cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs "/tmp:rw,nosuid,nodev,size=512m" --pids-limit 512)
LABEL=gitmortem.local

port=8766
scanners=known-good
name=gitmortem-local
browser=1
repos=()
while [ $# -gt 0 ]; do
    case "$1" in
        --repos) [ $# -ge 2 ] || { usage >&2; exit 2; }; repos+=("$2"); shift ;;
        --port) [ $# -ge 2 ] || { usage >&2; exit 2; }; port="$2"; shift ;;
        --scanners) [ $# -ge 2 ] || { usage >&2; exit 2; }; scanners="$2"; shift ;;
        --name) [ $# -ge 2 ] || { usage >&2; exit 2; }; name="$2"; shift ;;
        --no-browser) browser=0 ;;
        -h|--help) usage; exit 0 ;;
        *) say "[!] unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

case "$port" in "" | *[!0-9]*) die "--port is a number from 1 to 65535" ;; esac
port=$((10#$port))
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then die "--port is a number from 1 to 65535"; fi
case "$scanners" in known-good | latest | none) ;; *) die "--scanners is known-good, latest or none" ;; esac
[[ "$name" =~ ^[a-z0-9][a-z0-9_.-]*$ ]] ||
    die "--name is lower-case letters, digits, '.', '_' and '-', starting with a letter or digit"
case "$name" in
    host | bridge | none | default) die "--name $name is one of Docker's own networks: name another" ;;
esac

mounts=()
names=()
for dir in "${repos[@]+"${repos[@]}"}"; do
    [ -d "$dir" ] || die "no folder at $dir"
    abs="$(cd "$dir" && pwd -P)"
    [ "$abs" != / ] || die "--repos / would mount the whole machine: name a folder of repositories"
    case "$abs" in
        *,* | *$'\n'*) die "$abs holds a comma or a line break, which Docker's --mount cannot carry" ;;
    esac
    base="$(basename "$abs")"
    for seen in "${names[@]+"${names[@]}"}"; do
        [ "$seen" != "$base" ] ||
            die "two --repos folders are named $base: each is mounted as /repos/<its name>"
    done
    names+=("$base")
    mounts+=(--mount "type=bind,source=$abs,target=/repos/$base,readonly")
done

command -v docker >/dev/null 2>&1 ||
    die "Docker is needed: install Docker Desktop or Docker Engine and run this again"
engine="$(docker info --format '{{.ServerVersion}} {{.OperatingSystem}}' 2>/dev/null)" ||
    die "Docker is not running: start it and run this again"
if [ "$(uname -s)" = Linux ]; then
    case "$engine" in
        *"Docker Desktop"*) ;;
        *)
            major="${engine%%.*}"
            case "$major" in "" | *[!0-9]*) die "Docker Engine's version could not be read from: $engine" ;; esac
            [ "$major" -ge 28 ] ||
                die "Docker Engine ${engine%% *} lets other machines on your network reach a port published on 127.0.0.1: upgrade to Docker Engine 28 or newer, or use Docker Desktop"
            ;;
    esac
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
info "the image $name, built from this checkout (the first build takes several minutes)"
docker build -f "$here/docker/gitmortem.Dockerfile" -t "$name" "$here"
if owner="$(docker network inspect --format "{{index .Labels \"$LABEL\"}}" "$name" 2>/dev/null)"; then
    [ "$owner" = "$name" ] ||
        die "a Docker network named $name exists that this script did not make: remove it with docker network rm $name, or pass another --name"
else
    docker network create --label "$LABEL=$name" "$name" >/dev/null
fi
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    die "something already answers on 127.0.0.1:$port: stop it, or pass another --port"
fi

url="http://127.0.0.1:$port/"
poller=""
trap 'if [ -n "$poller" ]; then kill "$poller" 2>/dev/null || true; fi' EXIT
if [ "$browser" = 1 ]; then
    opener=""
    if [ "$(uname -s)" = Darwin ] && command -v open >/dev/null 2>&1; then
        opener=open
    elif command -v xdg-open >/dev/null 2>&1; then
        opener=xdg-open
    fi
    if [ -n "$opener" ]; then
        parent=$$
        (
            until [ "$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null)" = true ] &&
                curl -s -o /dev/null --max-time 2 "$url"; do
                kill -0 "$parent" 2>/dev/null || exit 0
                sleep 1
            done
            "$opener" "$url" >/dev/null 2>&1 || true
        ) &
        poller=$!
    fi
fi

tty=()
if [ -t 0 ] && [ -t 1 ]; then tty=(-t); fi
info "GitMortem at $url, its data in the volume $name; Ctrl-C stops it"
status=0
docker run --rm -i "${tty[@]+"${tty[@]}"}" --pull never --name "$name" --network "$name" \
    "${HARDENING[@]}" -p "127.0.0.1:$port:8080" -v "$name:/data" -e "GITMORTEM_SCANNERS=$scanners" \
    "${mounts[@]+"${mounts[@]}"}" "$name" "${LOCAL_ARGS[@]}" || status=$?
exit "$status"

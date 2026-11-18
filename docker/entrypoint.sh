#!/bin/sh
set -eu
gitmortem=/opt/gitmortem/current/bin/gitmortem
choice="${GITMORTEM_SCANNERS:-known-good}"
case "$choice" in
    none) ;;
    known-good|latest)
        "$gitmortem" install-scanners --choice "$choice" --tools-dir /data/tools --if-missing ;;
    *)
        echo "[!] GITMORTEM_SCANNERS is known-good, latest or none, not $choice" >&2
        exit 1 ;;
esac
exec "$gitmortem" serve --host 0.0.0.0 --port 8080 --data-dir /data/data --tools-dir /data/tools "$@"

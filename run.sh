#!/usr/bin/env bash

set -euo pipefail

installed="$HOME/.local/bin/gitmortem"
if [ ! -x "$installed" ]; then
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
    printf '[!] GitMortem is not installed for this user: run %s/install.sh first\n' "$here" >&2
    exit 1
fi
exec "$installed" local "$@"

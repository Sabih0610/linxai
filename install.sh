#!/bin/sh
# Ordinary-user application only. No package/service/PAM/model provisioning.
set -eu
if [ "$(/usr/bin/id -u)" = 0 ] || [ "$(/usr/bin/id -u)" != "$(/usr/bin/id -ur)" ] || [ "$(/usr/bin/id -g)" != "$(/usr/bin/id -gr)" ]; then
    echo 'Run LINxAI installation as an ordinary user, without sudo/set-ID.' >&2
    exit 2
fi
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
exec "${LINXAI_PYTHON:-python3}" -I "$script_dir/scripts/install_app.py" "$@"

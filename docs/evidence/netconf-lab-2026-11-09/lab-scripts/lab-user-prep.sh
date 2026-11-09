#!/bin/bash
# Owner part: copy the current LINxAI tree, pin the device host key (lab trust-on-first-use), write the asset.
set -e
SRC="/mnt/e/FYP/code 2/linxai"; DST=$HOME/linxai-dev
rm -rf "$DST"; mkdir -p "$DST"
cd "$SRC" && git ls-files -co --exclude-standard | grep -v '^docs/' | tar -cf - -T - | tar -xf - -C "$DST"
python3 - <<'PY'
import base64, hashlib, json, os
from ncclient import manager
home = os.path.expanduser("~/.linxai-netlab")
with manager.connect(host="127.0.0.1", port=2830, username="admin", key_filename=home + "/id_ed25519",
                     hostkey_verify=False, allow_agent=False, look_for_keys=False, timeout=30) as m:
    key = m._session._transport.get_remote_server_key()
    pin = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
assets = {"srl1": {"platform": "netconf", "host": "127.0.0.1", "port": 2830, "username": "admin",
                   "key_path": home + "/id_ed25519", "host_key_sha256": pin, "state_dir": home + "/state",
                   "ports": ["ethernet-1/1"]}}
path = home + "/assets.json"
open(path, "w").write(json.dumps(assets, indent=2)); os.chmod(path, 0o600)
print("pinned", key.get_name(), pin)
PY

#!/bin/bash
# Ordinary-user SSH peer setup on the lab VM for accept_remote.py (no sudo).
set -euo pipefail
mkdir -p ~/.ssh && chmod 700 ~/.ssh
[ -f ~/.ssh/linxai_peer ] || ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/linxai_peer -C linxai-peer
touch ~/.ssh/authorized_keys
grep -q linxai-peer ~/.ssh/authorized_keys || echo "restrict $(cat ~/.ssh/linxai_peer.pub)" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
install -d -m 700 ~/.linxai-peer
ssh-keyscan -T 5 -t ed25519 127.0.0.1 "$IP" 2>/dev/null > ~/.linxai-peer/known_hosts
chmod 644 ~/.linxai-peer/known_hosts
[ -x ~/.local/share/linxai/peer-venv/bin/python3 ] || python3 -m venv --without-pip ~/.local/share/linxai/peer-venv
SP=$(~/.local/share/linxai/peer-venv/bin/python3 -c 'import site; print(site.getsitepackages()[0])')
echo "$HOME/linxai-lab/src-dev" > "$SP/linxai.pth"
python3 - "$IP" <<'PY'
import json, os, sys
home = os.path.expanduser("~")
base = {"platform": "linux_ssh", "username": "linxai", "port": 22, "expected_uid": os.getuid(),
        "python": home + "/.local/share/linxai/peer-venv/bin/python3", "key_path": home + "/.ssh/linxai_peer",
        "known_hosts": home + "/.linxai-peer/known_hosts"}
assets = {"vmloop": {**base, "host": "127.0.0.1"}, "vmnat": {**base, "host": sys.argv[1]}}
path = home + "/.linxai-peer/assets.json"
open(path, "w").write(json.dumps(assets, indent=2)); os.chmod(path, 0o600)
print("assets:", list(assets), "nat ip", sys.argv[1])
PY
wc -l < ~/.linxai-peer/known_hosts

#!/bin/bash
# Ordinary-user agentless lab on the VM: a harmless user unit and agentless assets
# reusing the pinned key/known_hosts from remote-setup.sh (no sudo, nothing installed).
set -euo pipefail
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/linxai-agentless-demo.service <<UNIT
[Unit]
Description=LINxAI agentless lab demo (harmless)
[Service]
ExecStart=/usr/bin/sleep infinity
UNIT
systemctl --user daemon-reload
systemctl --user stop linxai-agentless-demo.service 2>/dev/null || true
IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
python3 - "$IP" <<'PY'
import json, os, sys
home = os.path.expanduser("~")
base = {"platform": "linux_agentless", "username": "linxai", "port": 22, "key_path": home + "/.ssh/linxai_peer",
        "known_hosts": home + "/.linxai-peer/known_hosts"}
assets = {"vmloop": {**base, "host": "127.0.0.1", "systemd_scope": "system"},
          "vmloop-user": {**base, "host": "127.0.0.1", "systemd_scope": "user"},
          "vmnat": {**base, "host": sys.argv[1], "systemd_scope": "system"}}
path = home + "/.linxai-peer/agentless.json"; open(path, "w").write(json.dumps(assets, indent=2)); os.chmod(path, 0o600)
print("agentless assets", list(assets))
PY

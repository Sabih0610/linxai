#!/bin/bash
# Owner: pin srl2 (lab trust-on-first-use) and write a two-device asset file for the batch test.
python3 - <<'PY'
import base64, hashlib, json, os
from ncclient import manager
h = os.path.expanduser("~/.linxai-netlab"); os.makedirs(h + "/state2", mode=0o700, exist_ok=True); os.chmod(h + "/state2", 0o700)
with manager.connect(host="127.0.0.1", port=2831, username="admin", key_filename=h + "/id_ed25519", hostkey_verify=False,
                     allow_agent=False, look_for_keys=False, timeout=30) as m:
    key = m._session._transport.get_remote_server_key()
pin = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
a = json.load(open(h + "/assets.json"))
feats = ["system.hostname", "interface.description", "system.ntp_server"]
srl1 = dict(a["srl1"], features=feats)
srl2 = dict(srl1, port=2831, host_key_sha256=pin, state_dir=h + "/state2", ports=["ethernet-1/1"])
p = h + "/assets-batch.json"; open(p, "w").write(json.dumps({"srl1": srl1, "srl2": srl2}, indent=2)); os.chmod(p, 0o600)
print("srl2 pinned", pin)
PY

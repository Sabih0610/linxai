#!/bin/bash
# LINxAI Gate D lab deployment for the ISOLATED Ubuntu 24.04 test VM only.
# Run as: sudo bash deploy-sensor.sh   (needs /etc/linxai/broker.json from deploy-broker.sh)
# Reinstalls the trusted bundle (LF build of the same commit), installs and STARTS
# the root BCC sensor unit. Nothing is enabled at boot. Undo: sudo bash uninstall-sensor.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
[ -f /etc/linxai/broker.json ] || { echo "missing /etc/linxai/broker.json (owner config)"; exit 1; }
/usr/bin/python3 -I -c "import bcc; print('OS BCC import ok')"
[ -d "/lib/modules/$(uname -r)/build" ] || { echo "missing kernel headers for $(uname -r)"; exit 1; }

tar -xf "$HERE/linxai-trusted-lf.tar" -C "$STAGE" --no-same-owner
python3 -I - "$STAGE" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "usr/share/doc/linxai/broker-manifest.json").read_text())
for name, digest in manifest.items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
        sys.exit("manifest mismatch: " + name)
print(f"manifest verified: {len(manifest)} files")
PY

rm -rf /usr/lib/linxai-trusted
cp -r "$STAGE/usr/lib/linxai-trusted" /usr/lib/linxai-trusted
chown -R root:root /usr/lib/linxai-trusted
find /usr/lib/linxai-trusted -type d -exec chmod 0755 {} +
find /usr/lib/linxai-trusted -type f -exec chmod 0644 {} +
install -o root -g root -m 0644 "$STAGE/usr/lib/systemd/system/linxai-sensor.service" /etc/systemd/system/linxai-sensor.service

# Legacy June eBPF/core daemons attach their own probes and auto-kill; keep them off.
for u in linxai-core.service linxai-ebpf.service; do
  systemctl is-active --quiet "$u" && systemctl stop "$u" && echo "stopped legacy $u for this test"
done
systemctl daemon-reload
systemctl restart linxai-broker.service   # same commit, LF bytes
systemctl restart linxai-sensor.service
echo "waiting for probe compilation/attachment..."
for i in $(seq 1 60); do [ -S /run/linxai-sensor/events.sock ] && break; sleep 1; done
sleep 5
systemctl --no-pager --lines=8 status linxai-sensor.service || true
ls -l /run/linxai-sensor/
bpftool prog show 2>/dev/null | grep -cE "kprobe" | sed 's/^/kprobe programs loaded: /' || true
echo "SENSOR DEPLOYED. Not enabled at boot."

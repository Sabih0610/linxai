#!/bin/bash
# LINxAI Gate B lab deployment for an ISOLATED Ubuntu 24.04 test VM only.
# Run as: sudo bash deploy-broker.sh   (from the directory holding linxai-broker.tar)
# Installs only the broker, its polkit action file, a harmless fixture service
# and /etc/linxai/broker.json. Nothing is enabled at boot. Undo: sudo bash uninstall-broker.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
OWNER_UID="${SUDO_UID:?run via sudo from the owner account}"
[ "$OWNER_UID" -gt 0 ] || { echo "owner must be an ordinary user"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Ubuntu Server may not ship polkit; it is the OS authorization mechanism the broker uses.
if [ ! -x /usr/bin/pkcheck ] || [ ! -x /usr/bin/pkttyagent ]; then
  apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq polkitd pkexec
fi
for c in /usr/bin/python3 /usr/bin/pkcheck /usr/bin/pkttyagent /usr/bin/systemctl /usr/bin/ss; do
  [ -x "$c" ] || { echo "missing $c"; exit 1; }
done

tar -xf "$HERE/linxai-broker.tar" -C "$STAGE" --no-same-owner
# Verify every staged file against the bundle manifest before installing.
python3 -I - "$STAGE" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "usr/share/doc/linxai/broker-manifest.json").read_text())
for name, digest in manifest.items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
        sys.exit("manifest mismatch: " + name)
print(f"manifest verified: {len(manifest)} files")
PY

# Trusted code: root-owned, not group/world writable.
rm -rf /usr/lib/linxai-trusted
cp -r "$STAGE/usr/lib/linxai-trusted" /usr/lib/linxai-trusted
chown -R root:root /usr/lib/linxai-trusted
find /usr/lib/linxai-trusted -type d -exec chmod 0755 {} +
find /usr/lib/linxai-trusted -type f -exec chmod 0644 {} +

install -o root -g root -m 0644 "$STAGE/usr/share/polkit-1/actions/org.linxai.service.policy" /usr/share/polkit-1/actions/
install -o root -g root -m 0644 "$STAGE/usr/lib/systemd/system/linxai-broker.service" /etc/systemd/system/linxai-broker.service

install -d -o root -g root -m 0755 /etc/linxai
printf '{"owner_uid":%s,"services":["linxai-lab-acceptance.service"]}\n' "$OWNER_UID" > /etc/linxai/broker.json
chown root:root /etc/linxai/broker.json && chmod 0644 /etc/linxai/broker.json

# Harmless fixture the acceptance run is allowed to start/restart/stop.
cat > /etc/systemd/system/linxai-lab-acceptance.service <<'UNIT'
[Unit]
Description=LINxAI harmless broker acceptance fixture
[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
DynamicUser=yes
UNIT

systemctl daemon-reload
# Legacy June root daemons (/opt/linxai) include automatic process killing; stop
# them for a clean test. Not disabled or removed: they return at next boot.
for u in linxai-core.service linxai-ebpf.service; do
  systemctl is-active --quiet "$u" && systemctl stop "$u" && echo "stopped legacy $u for this test"
done
systemctl stop linxai-lab-acceptance.service 2>/dev/null || true
systemctl restart linxai-broker.service
sleep 2
systemctl --no-pager --lines=5 status linxai-broker.service || true
ls -l /run/linxai/broker.sock
pkaction --action-id org.linxai.service.manage --verbose | grep implicit
echo "DEPLOYED for owner uid $OWNER_UID. Not enabled at boot."

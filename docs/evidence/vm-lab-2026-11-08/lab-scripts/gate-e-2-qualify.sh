#!/bin/bash
# Gate E step 2, after the reboot (isolated LINxAI test VM only):
#     sudo bash ~/linxai-lab/gate-e-2-qualify.sh
# Starts sensor + broker + policy daemon (nothing enabled at boot) and runs the real
# kernel qualification: scoped deny, uid/port/address/UDP near-matches, revoke, expiry.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
OWNER_UID="${SUDO_UID:?run via sudo from the owner account}"
LAB="$(cd "$(dirname "$0")" && pwd)"
echo "active LSMs: $(cat /sys/kernel/security/lsm)"
case ",$(cat /sys/kernel/security/lsm)," in *,bpf,*) ;; *) echo "bpf LSM not active - run step 1 and reboot"; exit 1;; esac
for u in linxai-core.service linxai-ebpf.service; do
  systemctl is-active --quiet "$u" && systemctl stop "$u" && echo "stopped legacy $u for this test"
done
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
tar -xf "$LAB/linxai-trusted-dev.tar" -C "$STAGE" --no-same-owner
install -o root -g root -m 0644 "$STAGE/usr/lib/systemd/system/linxai-policy.service" /etc/systemd/system/linxai-policy.service
install -d -o root -g root -m 0755 /etc/linxai
printf '{"owner_uid":%s,"targets":[{"address":"127.0.0.1","port":4444}],"max_duration":300,"max_active":16,"auto_enabled":false}\n' "$OWNER_UID" > /etc/linxai/response.json
chown root:root /etc/linxai/response.json && chmod 0644 /etc/linxai/response.json
systemctl daemon-reload
systemctl start linxai-broker.service linxai-sensor.service
for i in $(seq 1 90); do [ -S /run/linxai-sensor/events.sock ] && break; sleep 1; done
systemctl start linxai-policy.service
for i in $(seq 1 60); do [ -S /run/linxai-policy/control.sock ] && break; sleep 1; done
systemctl --no-pager --lines=4 status linxai-policy.service || true
mkdir -p "$LAB/runs"
cd "$LAB/src-dev"
LINXAI_TEST_KERNEL=1 /usr/bin/python3 -I -B scripts/accept_policy.py > "$LAB/runs/gate-e-qualify.json" 2> "$LAB/runs/gate-e-qualify.err"
rc=$?
chown "$OWNER_UID" "$LAB/runs/gate-e-qualify.json" "$LAB/runs/gate-e-qualify.err"
cat "$LAB/runs/gate-e-qualify.json"; tail -3 "$LAB/runs/gate-e-qualify.err"
echo "== Gate E qualification exit code: $rc  (0 = PASS). Tell Claude the result."

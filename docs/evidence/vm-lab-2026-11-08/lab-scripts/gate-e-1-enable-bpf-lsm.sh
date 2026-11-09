#!/bin/bash
# Gate E step 1 (isolated LINxAI test VM only): enable the BPF LSM at boot.
#     sudo bash ~/linxai-lab/gate-e-1-enable-bpf-lsm.sh     then: sudo reboot
# Undo: sudo rm /etc/default/grub.d/99-linxai-bpf-lsm.cfg && sudo update-grub && sudo reboot
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
grep -q '^CONFIG_BPF_LSM=y' "/boot/config-$(uname -r)" || { echo "kernel lacks CONFIG_BPF_LSM"; exit 1; }
CURRENT=$(cat /sys/kernel/security/lsm)
case ",$CURRENT," in *,bpf,*) echo "bpf LSM already active: $CURRENT"; exit 0;; esac
LSM="$CURRENT,bpf"
install -d -m 0755 /etc/default/grub.d
printf '# LINxAI Gate E lab: enable BPF LSM (appended to the active list)\nGRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX lsm=%s"\n' "$LSM" > /etc/default/grub.d/99-linxai-bpf-lsm.cfg
update-grub 2>&1 | tail -2
grep -c "lsm=$LSM" /boot/grub/grub.cfg | sed 's/^/grub entries with new lsm: /'
echo "STEP 1 DONE. Now run: sudo reboot"

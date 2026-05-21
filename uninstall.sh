#!/bin/bash
echo "Removing LINxAI..."
sudo systemctl stop linxai-ebpf linxai-core 2>/dev/null
sudo systemctl disable linxai-ebpf linxai-core 2>/dev/null
sudo rm -f /etc/systemd/system/linxai-ebpf.service
sudo rm -f /etc/systemd/system/linxai-core.service
sudo rm -f /usr/local/bin/linxai
sudo rm -f /usr/local/bin/linxai-logs
sudo rm -f /usr/local/bin/linxai-status
sudo rm -f /lib/x86_64-linux-gnu/security/pam_linxai_face.so
sudo rm -rf /etc/linxai
sudo systemctl daemon-reload
echo "LINxAI removed. Code at /opt/linxai, logs at /var/log/linxai"

# LINxAI — Complete Environment Setup Guide

This document records every step taken to set up the development
environment from scratch. If the VM is ever lost, follow this
exactly to recreate it.

---

## Host Machine

- OS: Windows 11
- RAM: 16GB
- Storage: E drive for all FYP work
- Tool: Multipass 1.16.1 via Windows Hyper-V

---

## Step 1 — Windows Setup

```powershell
# Enable Hyper-V (requires restart)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# Create folder structure
New-Item -ItemType Directory -Force -Path "E:\FYP"
New-Item -ItemType Directory -Force -Path "E:\FYP\code"
New-Item -ItemType Directory -Force -Path "E:\FYP\multipass"
New-Item -ItemType Directory -Force -Path "E:\FYP\snapshots"

# Set Multipass storage to E drive (via Registry)
Set-ItemProperty `
  -Path "HKLM:System\CurrentControlSet\Control\Session Manager\Environment" `
  -Name MULTIPASS_STORAGE `
  -Value "E:\FYP\multipass"

# Install Multipass from https://multipass.run/download/windows
# Enable privileged mounts
multipass set local.privileged-mounts=true
```

---

## Step 2 — Create and Configure VM

```powershell
# Create VM
multipass launch 22.04 --name linxai-dev --cpus 4 --memory 8G --disk 40G

# Mount code folder
multipass mount E:\FYP\code linxai-dev:/opt/linxai

# Verify
multipass info linxai-dev
```

**VM Specs:**
- Name: linxai-dev
- OS: Ubuntu 22.04.5 LTS
- Kernel: 5.15.0-174-generic
- CPUs: 4
- RAM: 8GB
- Disk: 40GB
- IP: 172.23.181.118

---

## Step 3 — Inside the VM

```bash
# Enter VM
multipass shell linxai-dev

# System update
sudo apt update && sudo apt upgrade -y

# Core packages
sudo apt install -y \
  python3 python3-pip python3-dev \
  git curl wget build-essential \
  linux-headers-$(uname -r) \
  linux-tools-$(uname -r) \
  linux-tools-common \
  bpfcc-tools python3-bpfcc libbpfcc-dev \
  nginx net-tools \
  libssl-dev libffi-dev \
  portaudio19-dev ffmpeg \
  v4l-utils libpam0g-dev gcc

# Ollama
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl start ollama
sudo systemctl enable ollama
ollama pull qwen2.5:1.5b

# Python packages
pip3 install \
  langgraph langchain langchain-community \
  requests paramiko psutil \
  opencv-python-headless \
  faster-whisper webrtcvad pyaudio \
  pytest

# PATH fix
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# Project structure
sudo chown -R ubuntu:ubuntu /opt/linxai
mkdir -p ~/.linxai ~/.linxai/face
sudo systemctl stop nginx && sudo systemctl disable nginx
```

---

## Step 4 — Verification

```bash
python3 -c "import bcc; print('BCC OK')"
python3 -c "import langgraph, paramiko, cv2, psutil; print('Packages OK')"
ollama list  # must show qwen2.5:1.5b
systemctl is-active ollama  # must show active
```

---

## Daily Startup Commands

```powershell
# PowerShell every morning
multipass start linxai-dev
multipass mount E:\FYP\code linxai-dev:/opt/linxai
multipass shell linxai-dev
```

```bash
# Inside VM — warm up model
ollama run qwen2.5:1.5b "say: ready"
cd /opt/linxai
```

---

## Snapshot Commands

```powershell
# Take snapshot
multipass stop linxai-dev
multipass snapshot linxai-dev --name <snapshot-name>
multipass start linxai-dev

# Restore snapshot
multipass stop linxai-dev
multipass restore linxai-dev --snapshot <snapshot-name>
multipass start linxai-dev

# List snapshots
multipass info linxai-dev
```

---

## Known Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Mount drops on restart | Multipass behaviour | Run mount command every session |
| df -h hangs | Multipass mount point | Known VM limitation, works on native Ubuntu |
| First AI call times out | Model cold start | Run ollama warmup command first |
| `cannot connect to socket` | Multipass service crashed | Stop-Service Multipass then Start-Service Multipass |

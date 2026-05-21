#!/bin/bash
# LINxAI Voice Module Installer
# Installs offline speech-to-text capability
#
# Usage: sudo bash modules/install-voice.sh

set -e
[ "$EUID" -ne 0 ] && echo "Run as root: sudo bash modules/install-voice.sh" && exit 1

echo ""
echo "Installing LINxAI Voice Module..."
echo ""

# Install system audio deps
apt-get install -y -qq portaudio19-dev ffmpeg

# Install Python packages
pip3 install -q faster-whisper webrtcvad pyaudio

# Download Whisper model
echo "Downloading Whisper large-v3 model (~1.5GB)..."
python3 -c "
from faster_whisper import WhisperModel
print('Downloading...')
m = WhisperModel('large-v3', device='cpu', compute_type='int8')
print('Model ready.')
"

# Enable voice in config
CONFIG=/etc/linxai/config.yaml
if [ -f "$CONFIG" ]; then
    sed -i 's/voice_enabled: false/voice_enabled: true/' "$CONFIG"
    echo "Voice enabled in /etc/linxai/config.yaml"
fi

echo ""
echo "✓ Voice module installed."
echo "  Speak commands when running: linxai --interactive"
echo ""
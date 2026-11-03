> **Current development entry (2 November 2026):** Read [docs/CLOUD_HANDOFF.md](docs/CLOUD_HANDOFF.md) for agreed scope, gates A–H, current source, locked setup and test commands. The older README content below is retained as historical context; its completion and sudo-installer instructions are not current Cloud setup. Gate A replaces the legacy installer with an ordinary-user typed CLI install: `sh install.sh`. See [docs/INSTALLATION.md](docs/INSTALLATION.md) for supported platforms and current commands; the historical sudo/model/service instructions below do not apply.

# LINxAI — Intelligent Linux Administration Layer

An autonomous AI-driven system layer for Linux that sits between user commands
and the Linux kernel. Natural language input → AI classification → system state
validation → safe execution → audit logging.

**University:** Mohammad Ali Jinnah University (MAJU)  
**Supervisor:** Ms. Huma Rashid  
**Team:** Sabih Aamir · Syed Muhammad Hassan · Syed Naviyan Shahzad  

---

## Architecture

```
User Input (text/voice)
        ↓
AI Engine (Qwen2.5:1.5b via Ollama)
        ↓
Command Intelligence Engine (CIE)
        ↓
Execution Controller (subprocess + PAM)
        ↓
Audit Logger (JSON Lines)
        ↑
eBPF Daemon (kernel monitoring, nanosecond detection)
```

## Why LINxAI is Different

- **eBPF kernel monitoring** — syscall-level detection in nanoseconds vs
  Prometheus polling every 15 seconds
- **Pre-execution validation** — CIE checks system state BEFORE running
  any command, not after failure
- **Local AI inference** — Qwen2.5:1.5b runs entirely offline via Ollama,
  no cloud API, no data leaves the machine
- **Natural language interface** — type or speak Linux commands in plain
  English

---

## Requirements

- Ubuntu 22.04 LTS
- Linux kernel 5.15+ (required for eBPF ring buffers)
- 4GB RAM minimum (8GB recommended)
- 20GB disk space

---

## Quick Install (Fresh Ubuntu 22.04)

```bash
git clone https://github.com/Sabih0610/linxai.git /opt/linxai
cd /opt/linxai
sudo bash install.sh
sudo reboot
```

After reboot, eBPF daemon starts automatically. Run interactively:

```bash
sudo python3 /opt/linxai/main.py
```

---

## Module Status

| Module | Files | Test Score | Status |
|--------|-------|-----------|--------|
| AI Engine | ai/ | 94% (47/50) | Complete |
| Voice Interface | voice/ | pending mic | Code done |
| Command Intelligence Engine | cie/ | 100% (40/40) | Complete |
| Execution Controller | executor/ | 95.5% (21/22) | Complete |
| Demo Pipeline | main.py, demo.py | 100% (8/8) | Complete |
| eBPF Daemon | ebpf/ | — | In progress |
| Resource Manager | resource/ | — | Pending |
| VPS Manager | vps/ | — | Pending |

---

## Project Structure

```
linxai/
├── ai/                  AI Engine — Qwen2.5:1.5b, LangGraph, context memory
├── cie/                 Command Intelligence Engine — 20 system state checks
├── executor/            Execution Controller — subprocess, PAM, face auth
│   └── pam/             PAM C module for face authentication
├── logger/              Audit Logger — JSON Lines writer and CLI viewer
├── voice/               Voice Interface — Faster-Whisper, VAD, PyAudio
├── ebpf/                eBPF Daemon — kernel monitoring (in progress)
│   └── probes/          eBPF C programs — execve, connect, openat
├── resource/            Resource Manager (pending)
├── vps/                 VPS Manager (pending)
├── config/              settings.json
├── systemd/             systemd service files
├── main.py              Pipeline entry point — terminal interface
├── demo.py              Jury demonstration script
├── test_pipeline.py     End-to-end smoke test
├── install.sh           One-shot installer for Ubuntu 22.04
└── verify.sh            Post-install verification
```

---

## Development Environment

Built and tested on:
- **Host:** Windows 11, 16GB RAM
- **VM:** Multipass linxai-dev — Ubuntu 22.04.5 LTS, kernel 5.15
- **VM specs:** 4 CPUs, 8GB RAM, 40GB disk
- **Mount:** E:\FYP\code ↔ /opt/linxai (live sync)

---

## Running Tests

```bash
# AI Engine accuracy test (50 cases, target 90%)
python3 ai/test_engine.py

# CIE validation test (40 cases, target 95%)
python3 cie/test_cie.py

# Executor test (22 cases)
sudo python3 executor/test_executor.py

# Full pipeline smoke test (8 cases)
sudo python3 test_pipeline.py

# Jury demo (automated, two scenarios)
sudo python3 demo.py
```

---

## Daily Development Workflow

```powershell
# Windows PowerShell — every morning
multipass start linxai-dev
multipass mount E:\FYP\code linxai-dev:/opt/linxai
multipass shell linxai-dev
```

```bash
# Inside VM — warm up model before running tests
ollama run qwen2.5:1.5b "say: ready"
```

---

## Snapshots

| Snapshot | Contents |
|----------|----------|
| clean-slate | Bare Ubuntu 22.04 |
| after-setup | All dependencies installed |
| after-phase3-ai-engine | AI Engine complete |
| after-phase5-cie | CIE complete |
| after-phase6-executor | Executor complete |
| after-phase7-M7 | Demo pipeline complete, M7 achieved |
| after-phase7-progress | Latest working state |

---

## License

Academic project — MAJU FYP 2026

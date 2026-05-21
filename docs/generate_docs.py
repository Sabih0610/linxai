# docs/generate_docs.py
# LINxAI Phase 12 Documentation Generator
#
# Generates:
# - SRS.md
# - SDS.md
# - PHASE_STATUS.md
# - README.md
#
# Run:
#   python3 docs/generate_docs.py

import os
from datetime import datetime
from pathlib import Path


DOCS_DIR = Path(__file__).resolve().parent


SRS = """# LINxAI Software Requirements Specification

## 1. Introduction

LINxAI is an offline intelligent Linux administration layer that runs on top of Ubuntu Linux. It accepts natural language or voice commands, understands user intent through a local small language model, validates live system state before execution, safely executes approved operations, monitors kernel-level activity using eBPF, and writes all important events to a structured audit log.

LINxAI is not a replacement for Linux. It is a safer and smarter control layer between the user and the Linux operating system.

## 2. Purpose

The purpose of LINxAI is to reduce human error in Linux administration. A normal Linux shell executes commands blindly. LINxAI follows a safer flow:

User input -> AI/SLM intent plan -> Command Intelligence Engine validation -> Safe execution -> eBPF monitoring -> Audit logging.

## 3. Scope

LINxAI supports the following major capabilities:

- Natural language Linux command input
- Local SLM-based intent classification
- Context-aware command validation
- Safe command execution
- eBPF kernel monitoring
- Resource monitoring and priority optimization
- VPS remote command execution through SSH
- Structured audit logging
- Voice command support
- Future GUI/dashboard support

The project does not aim to replace Ubuntu, Kubernetes, Prometheus, Ansible, or a full SIEM platform.

## 4. Intended Users

The intended users are:

- DevOps engineers
- Linux administrators
- Junior system operators
- Cybersecurity students
- Managed service providers
- Final Year Project evaluation panel

## 5. Functional Requirements

### FR-01 Natural Language Command Input

The system shall accept plain English Linux administration commands.

Example: restart nginx only if port 80 is free.

### FR-02 AI/SLM Intent Classification

The system shall classify user input into a structured execution plan containing intent, target, command, sudo requirement, explanation, and preconditions.

### FR-03 Context Memory

The system shall store recent command history and results for session-level context.

### FR-04 Command Intelligence Engine

The system shall validate commands before execution by checking live system state such as active ports, services, processes, users, files, CPU, memory, and related system information.

### FR-05 Safe Execution Controller

The system shall execute only approved commands and return structured output containing status, stdout, stderr, return code, duration, and command issued.

### FR-06 Dangerous Command Blocking

The system shall block dangerous command patterns such as disk wiping, unsafe recursive deletion, reboot/shutdown commands, fork bombs, and destructive permission changes.

### FR-07 eBPF Kernel Monitoring

The system shall monitor kernel-level activity using eBPF probes for process execution, outbound network connections, and file access.

### FR-08 Resource Management

The system shall monitor CPU and memory usage and lower the priority of background processes when CPU usage crosses the configured threshold.

### FR-09 VPS Management

The system shall connect to remote Ubuntu servers through SSH key authentication using Paramiko and execute safe remote commands.

### FR-10 Structured Audit Logging

The system shall write all important events to a central JSON Lines audit log. Logged events include AI classification, CIE validation, command execution, eBPF events, resource actions, VPS commands, voice events, and system startup/shutdown.

### FR-11 Voice Interface

The system shall support offline speech-to-text input through Faster-Whisper and voice activity detection.

### FR-12 Documentation and Testing

Each project phase shall include a test script or validation process before the phase is considered complete.

## 6. Non-Functional Requirements

### NFR-01 Offline Operation

The system shall operate without cloud AI APIs during normal usage.

### NFR-02 Low Resource Usage

The system shall avoid heavy LLM requirements and should remain practical for normal machines.

### NFR-03 Security

The system shall validate commands before execution and block known dangerous patterns.

### NFR-04 Auditability

The system shall provide structured logs for traceability and debugging.

### NFR-05 Performance

The system should respond within interactive command-line latency.

### NFR-06 Reliability

Each phase must pass its test suite before the project moves to the next phase.

### NFR-07 Modularity

The system shall be organized into independent modules such as AI, CIE, Executor, eBPF, Resources, VPS, Logger, and Voice.

## 7. Assumptions

- The target operating system is Ubuntu 22.04.
- The development environment is a Multipass Ubuntu VM.
- The kernel supports eBPF/BCC.
- The user has sudo access where needed.
- VPS testing can initially use localhost SSH before real VPS servers are added.

## 8. Constraints

- eBPF requires root privileges.
- Voice testing requires a working microphone.
- Face authentication requires a camera.
- VPS testing requires SSH server availability.
- SLM output must remain structured and machine-readable.

## 9. Acceptance Criteria

The system is acceptable for FYP-I if the following are achieved:

- AI engine passes classification testing.
- CIE passes validation tests.
- Executor passes safety and command execution tests.
- Demo pipeline works end-to-end.
- eBPF captures execve, connect, and openat events.
- Resource Manager passes its test suite.
- VPS Manager passes its test suite.
- Central logging integration passes its test suite.
- SRS and SDS documentation files are generated and validated.
"""


SDS = """# LINxAI Software Design Specification

## 1. System Overview

LINxAI is designed as a modular intelligent Linux administration layer. It separates input handling, AI planning, command validation, execution, monitoring, logging, and remote server management into independent modules.

## 2. High-Level Architecture

The main command flow is:

User Input -> AI Engine -> Command Intelligence Engine -> Execution Controller -> Linux OS -> eBPF Monitoring -> Audit Logger.

Supporting modules include:

- Voice Interface
- Context Memory
- Resource Manager
- VPS Manager
- Central Audit Logger
- Future GUI/dashboard

## 3. Module Design

### 3.1 AI Engine

The AI Engine receives the user's natural language command and converts it into a structured execution plan.

Responsibilities:

- Accept user input
- Use a local SLM through Ollama
- Classify intent
- Generate JSON execution plan
- Use context memory for recent commands

Example output fields:

- intent
- target
- command
- requires_sudo
- pre_conditions
- explanation

### 3.2 Command Intelligence Engine

The Command Intelligence Engine validates the AI-generated plan before execution.

Responsibilities:

- Check live system state
- Validate ports
- Validate services
- Validate processes
- Validate files and users
- Approve or block execution

Output examples:

- approve with reason
- block with reason

### 3.3 Execution Controller

The Execution Controller runs only approved commands.

Responsibilities:

- Execute command through subprocess
- Capture stdout
- Capture stderr
- Capture return code
- Enforce timeout
- Block dangerous patterns
- Return structured result

### 3.4 eBPF Daemon

The eBPF Daemon provides kernel-level monitoring.

Responsibilities:

- Load BCC/eBPF programs
- Attach to syscall/kernel events
- Capture process execution
- Capture network connections
- Capture file access
- Forward events to audit logging

Implemented probes:

- execve kprobe
- connect kprobe
- openat tracepoint

### 3.5 Resource Manager

The Resource Manager monitors CPU, RAM, and process activity.

Responsibilities:

- Poll CPU usage
- Poll memory usage
- Classify processes as foreground, background, or system
- Renice background processes under high CPU load
- Restore priorities when load decreases

### 3.6 VPS Manager

The VPS Manager handles remote Linux server management.

Responsibilities:

- Load server details from config/servers.yaml
- Connect through Paramiko SSH
- Execute safe remote commands
- Return structured results
- Support run_many for multiple servers
- Block dangerous remote commands

### 3.7 Audit Logger

The Audit Logger is the central logging layer.

Responsibilities:

- Write JSON Lines logs
- Support module/event/session filtering
- Support statistics
- Support CLI log viewer
- Support live follow mode
- Integrate with AI, CIE, Executor, eBPF, Resource Manager, and VPS Manager

Log record schema:

timestamp, session_id, host, module, event_type, level, payload.

## 4. Data Storage Design

LINxAI uses:

- JSON Lines for audit logs
- SQLite for context memory
- YAML for VPS server configuration
- Python modules for runtime orchestration

## 5. Deployment Design

Development environment:

Windows host -> Multipass Ubuntu VM -> /opt/linxai project directory.

Target demo environment:

Ubuntu 22.04 -> LINxAI CLI -> eBPF daemon -> audit logger -> optional systemd services later.

Future product deployment:

- install.sh
- pip-installable modules
- optional packages
- bootable Ubuntu USB
- GUI/dashboard

## 6. Security Design

LINxAI uses layered safety:

1. AI does not execute directly.
2. CIE validates every plan.
3. Executor blocks dangerous commands.
4. eBPF watches kernel behavior.
5. Audit logger records every important decision.
6. VPS Manager uses SSH key-based authentication.
7. Face/PAM authentication may be added for privileged operations.

## 7. Sequence Design: Demo Command

Command:

restart nginx only if port 80 is free.

Sequence:

1. User enters command.
2. AI Engine creates plan.
3. CIE checks port 80 and nginx service.
4. Executor runs command only if validation approves.
5. eBPF captures kernel activity.
6. Audit Logger records each step.
7. User receives result.

## 8. Testing Strategy

Each phase has a validation test:

- AI Engine test
- Voice code verification
- CIE test
- Executor test
- Demo pipeline test
- eBPF test
- Resource Manager test
- VPS Manager test
- Logger test
- Documentation test

No phase is considered complete until its test passes.

## 9. Known Risks

- eBPF behavior may differ across kernels.
- Multipass networking may differ from native Ubuntu.
- Voice testing requires real microphone hardware.
- Face authentication requires careful PAM handling.
- AI output must be kept strict and structured.
- VPS remote execution must remain guarded.

## 10. Future Enhancements

- PyQt6 desktop GUI
- Flask dashboard
- Plugin package architecture
- Real VPS fleet testing
- Better eBPF anomaly detection
- Windows support through ETW/WMI equivalents
"""


PHASE_STATUS = """# LINxAI Phase Status

## Completed Phases

### Phase 3 — AI Engine

Status: Complete.

The local SLM-based AI engine is working with structured JSON command planning.

### Phase 4 — Voice Interface

Status: Code complete.

Voice pipeline code is prepared. Physical microphone verification is pending on native Ubuntu.

### Phase 5 — Command Intelligence Engine

Status: Complete.

CIE validates live system state before execution.

### Phase 6 — Execution Controller

Status: Complete.

Safe execution wrapper and dangerous command guard are working.

### Phase 7 — Demo Pipeline

Status: Complete.

AI -> CIE -> Executor -> Logger pipeline is working.

### Phase 8 — eBPF Daemon

Status: Complete.

All 3 probes are working:

- execve
- connect
- openat

### Phase 9 — Resource Manager

Status: Complete.

Resource Manager test passed 19/19.

### Phase 10 — VPS Manager

Status: Complete.

VPS Manager test passed 22/22.

### Phase 11 — Logging Integration

Status: Complete.

Central audit logging test passed.

### Phase 12 — SRS/SDS Documentation

Status: In progress.

Documentation files are generated by docs/generate_docs.py and validated by docs/test_docs.py.

## Next Work After Phase 12

The next work is final integration and demo rehearsal:

- Wire all modules into main.py
- Prepare final CLI demo flow
- Prepare screenshots
- Prepare SRS/SDS Word document if required
- Prepare defense explanation
- Optional systemd service setup
"""


README = """# LINxAI Documentation Pack

This folder contains the Phase 12 documentation pack for LINxAI.

Generated files:

- SRS.md — Software Requirements Specification
- SDS.md — Software Design Specification
- PHASE_STATUS.md — Current project status

Generate documents:

python3 docs/generate_docs.py

Validate documents:

python3 docs/test_docs.py
"""


def write_file(name: str, content: str):
    path = DOCS_DIR / name

    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")

    print(f"Wrote {path}")


def main():
    os.makedirs(DOCS_DIR, exist_ok=True)

    generated_at = datetime.now().isoformat()

    write_file("SRS.md", SRS)
    write_file("SDS.md", SDS)
    write_file("PHASE_STATUS.md", PHASE_STATUS)

    readme = README + f"\nGenerated at: {generated_at}\n"
    write_file("README.md", readme)

    print()
    print("Phase 12 documentation generated successfully.")


if __name__ == "__main__":
    main()
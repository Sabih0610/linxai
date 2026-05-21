# LINxAI Software Design Specification

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

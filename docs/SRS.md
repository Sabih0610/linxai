# LINxAI Software Requirements Specification

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

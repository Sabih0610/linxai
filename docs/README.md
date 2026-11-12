> **Current development entry (2 November 2026):** Read [CLOUD_HANDOFF.md](CLOUD_HANDOFF.md) for agreed scope, gates A–H, current source, locked setup and test commands. The older README content below is retained as historical context; its completion and sudo-installer instructions are not current Cloud setup. Do not run the legacy installer for routine development.

> **Current status (13 November 2026):** start at the repository [README](../README.md),
> the [requirement matrix](REQUIREMENTS_TRACEABILITY.md) and [PROGRESS.md](PROGRESS.md).
> Network work: [NETWORK_DEVICES.md](NETWORK_DEVICES.md) and [DISCOVERY.md](DISCOVERY.md).

# LINxAI Documentation Pack

This folder contains the Phase 12 documentation pack for LINxAI.

Generated files:

- SRS.md — Software Requirements Specification
- SDS.md — Software Design Specification
- PHASE_STATUS.md — Current project status

Generate documents:

python3 docs/generate_docs.py

Validate documents:

python3 docs/test_docs.py

Generated at: 2026-05-21T06:28:34.737735

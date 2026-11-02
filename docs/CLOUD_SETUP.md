# Codex Cloud setup inputs

Read `CLOUD_HANDOFF.md`, then `DEVELOPMENT_ENVIRONMENT.md`. Load the existing
`Sabih0610/linxai` repository, branch `codex/cloud-handoff-2026-11-02`, at the
handoff commit reported by the local task. An old `main` at 51e54c6 lacks the
registry/service and cannot reproduce this handoff. Confirm `git rev-parse HEAD`
and the presence of `operations/service.py` before working.

The checked-in scripts are tested setup commands, not a claim that a Cloud account
or saved environment was configured from this Windows chat. This task cannot
certify capabilities of a Cloud machine that has not been opened. Re-run the
capability report there; do not transplant the WSL report as Cloud evidence.

In the current Cloud environment setup, select the existing repository and provide
these commands for its Install script (or equivalent setup conversation):

```sh
python3 --version
python3 scripts/setup_dev.py
.venv/bin/python -B scripts/test.py offline
.venv/bin/python -B scripts/test.py linux
.venv/bin/python -B scripts/capabilities.py --output capabilities.json
```

Supply these Start skill instructions:

> Use the repository's .venv interpreter explicitly. Confirm the checked-out commit
> and capability report. The default application entry is .venv/bin/linxai --help;
> no background service is needed for ordinary development. Do not start Ollama,
> pull models, attach BPF, open hardware, run legacy installers or change security
> settings. Run the offline group and eligible unprivileged Linux integration.
> Keep unavailable kernel/GUI/hardware/model acceptance pending and preserve the
> existing registry/service architecture.

Allow package-manager access to PyPI/artifact hosts for initial setup as required
by the environment's existing network policy. The routine app/test setup needs no
API token, cloud inference key, SSH key, biometric material or model weights.
Keep optional tests gated. Do not enable arbitrary network access to repair a
missing repository/account connection. Follow the platform's access controls.

If the environment is root-only, offline tests may run but native application
integration must report skipped/pending until an ordinary-user execution context
exists. Do not remove root rejection, create privileged users, grant capabilities,
or infer dedicated-kernel ownership from UID 0. Use ordinary hosted CI for the
supported checks and a separately selected Linux desktop/lab for final acceptance.

Review and publish the prepared Cloud environment through the product's environment
controls after its own setup results are available. Re-run locked setup when the
lockfile changes; repository refresh is not a substitute for dependency sync.

Official guidance checked 2 November 2026: [Cloud environments](https://learn.chatgpt.com/docs/environments/cloud-environments).
It distinguishes installation commands, startup instructions and published saved
state. This repository supplies those inputs; local saved environments and this
chat are not prerequisites for a new task once the handoff commit is available.

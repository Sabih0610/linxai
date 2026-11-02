# Ordinary-user agent, durable jobs and Linux desktop

Gate C implementation uses the existing fast planner, schema, adapt_plan,
ActionRegistry and OperationService. PySide6 6.10.0 is selected from the existing
pinned optional profile as a reversible desktop default. Qt is a thin client;
it cannot grant OS privileges. The agent remains alive when the window closes.

```sh
sh install.sh --desktop
# In a terminal, or a separately enabled user service:
"$HOME/.local/share/linxai/bin/linxai-agent" --workspace "$HOME/linxai-workspace"
# In another terminal:
"$HOME/.local/share/linxai/bin/linxai-desktop"
```

The workspace must already satisfy the private owned confinement checks. No
desktop/model/privileged service is enabled by the app installer. The unit template
deployment/linxai-agent.service is an optional user-service deployment input; review
its workspace configuration and install path before enabling on a target. For a
custom prefix invoke its bin/launchers directly. GUI errors explain missing Qt or
agent access. No model is warmed or downloaded on startup. Unsupported commands
produce errors, never an inherited shell fallback.

Natural language first uses the existing deterministic fast path; otherwise a
bounded loopback-only Ollama /api/chat request is made. Generated plans pass the
existing schema and adapt_plan; raw command/risk/sudo/rollback fields cannot grant
authority. Owner workspace/identity/target are outside the model. Five bounded
validated context summaries are retained for subsequent planning. The legacy
main.py pipeline is retained for compatibility but is not used by this desktop.

The desktop has Assistant, Operations, Assets, Security and Activity views. All
IPC is dispatched through a bounded Qt thread pool. Requests produce a server-side
60-second preview. Confirmation binds the request, workspace, target and owner
digest; changes/replay/expiry require a new preview. Mandatory checks run at actual
dispatch. Service mutations go only to the authenticated Gate B broker. A UI click
does not replace polkit. Rendering uses plain text, never model-provided HTML.

CLI can use the same agent: `linxai --ask 'show memory usage'`, then
`linxai --confirm PREVIEW_ID --digest EXACT_DIGEST`; `linxai --jobs` lists durable
results. The older positional typed CLI keeps its standalone service contract;
administrative callers use the agent path for OS authorization. No silent fallback
between these routes exists.

The version-1 Unix API uses private caller-owned socket/directory, SO_PEERCRED,
bounded framing/deadlines, four handlers and strict method fields. It accepts no
caller UID/approval flags. A lifetime flock prevents duplicate agents **before**
restart reconciliation or stale-socket cleanup. A second agent cannot unlink the
active socket or alter running jobs. A stale owned socket may be removed only
after obtaining the lock. Other entries are refused.

SQLite schema 1 stores previews, jobs and bounded live-output tails. Queue capacity
is 128, history admission 1000 rows, maximum database 8192 pages. Full storage or a
failed worker disables admission rather than accepting lost work. Job and operation
IDs are linked before dispatch; root requests use the job UUID throughout the
broker. Live output is rate-limited and bounded, with mandatory audit separate.
All four reads may be cancelled via process-group supervision. Atomic creation and
privileged mutations cannot be interrupted through a general cancellation command;
queued cancellation always prevents dispatch.

Restart marks pre-dispatch work interrupted and dispatching work unknown. No
operation is automatically replayed. Read-only reconciliation observes current
service/file postconditions while retaining uncertainty about the original
execution. It never invents successful dispatch or runs a model rollback string.
Actual restoration requires captured prior state and a new validated operation;
the broker acceptance runner demonstrates that bounded pattern.

Native automated evidence: Windows combined 144 run/3 skips; WSL combined 168
run/8 skips (160 passed, 20.292 s), including real ordinary-user agent sockets,
operation execution, SQLite state and duplicate exclusion. Qt offscreen verification
is separately runnable; it is not a physical desktop/device acceptance test.

```sh
QT_QPA_PLATFORM=offscreen LINXAI_TEST_DESKTOP=1 .venv/bin/python -B -m unittest tests.test_desktop -v
```

Real desktop/polkit workflow, fresh installed desktop and crash/load acceptance
remain separate target checks. Monitoring and Security integration continue in D;
adaptive response, network breadth and hardware remain E–G. Original requirements
1–9, 15–26, 58–62 and 63–70 advance partially; original IDs are not removed.

References: [Qt thread pool](https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThreadPool.html),
[Ollama bounded non-streaming JSON chat](https://docs.ollama.com/api/chat).

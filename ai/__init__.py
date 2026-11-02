"""Public AI exports, loaded only when requested."""
from importlib import import_module

__all__ = ["AIEngine", "ContextMemory", "SYSTEM_PROMPT"]
_EXPORT_MODULES = {"AIEngine": "engine", "ContextMemory": "context",
                   "SYSTEM_PROMPT": "prompts"}


def __getattr__(name):
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(f"{__name__}.{module_name}"), name)

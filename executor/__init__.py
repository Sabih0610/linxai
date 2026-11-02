"""Lazy public compatibility exports; importing face primitives loads no controller."""
__all__ = ["ExecutionController", "ExecutionResult", "make_blocked_result", "make_auth_failed_result", "make_timeout_result"]


def __getattr__(name):
    if name not in __all__:
        raise AttributeError(name)
    from importlib import import_module
    module = import_module("executor.controller" if name == "ExecutionController" else "executor.result")
    value = getattr(module, name)
    globals()[name] = value
    return value

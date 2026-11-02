"""Typed preparation only. This package does not execute or authorize operations."""
from .registry import (
    ACTIONS, ActionError, ActionRegistry, InvalidParameters, PreparedAction,
    Privilege, UnsupportedAction,
)
from .plans import adapt_plan

__all__ = [
    "ACTIONS", "ActionError", "ActionRegistry", "InvalidParameters",
    "PreparedAction", "Privilege", "UnsupportedAction", "adapt_plan",
]

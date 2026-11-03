"""Lazy legacy export; typed SSH metadata needs no optional Paramiko stack."""
__all__ = ["VPSManager"]


def __getattr__(name):
    if name != "VPSManager":
        raise AttributeError(name)
    from .manager import VPSManager
    return VPSManager

import os


def safe_cwd() -> str:
    """Return the current working directory, recovering if it was deleted."""
    try:
        return os.getcwd()
    except (FileNotFoundError, OSError):
        for fallback in (os.path.expanduser("~"), "/tmp", "/"):
            try:
                os.chdir(fallback)
                return fallback
            except Exception:
                continue
        return "/"

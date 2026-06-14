import threading


class OutputQueue:
    def __init__(self):
        self._q = []
        self._lock = threading.Lock()
        self._by_key = {}

    def push(self, text, key=None):
        with self._lock:
            item = {"text": text, "count": 1, "key": key}
            self._q.append(item)
            if key is not None:
                self._by_key[key] = item

    def bump(self, key):
        with self._lock:
            item = self._by_key.get(key)
            if not item:
                return False
            item["count"] += 1
            return True

    def flush(self):
        with self._lock:
            items = self._q
            self._q = []
            self._by_key = {}
        for item in items:
            text = self._with_count(item["text"], item["count"])
            end = "" if text.endswith("\n") else "\n"
            print(text, end=end, flush=True)

    def _with_count(self, text, count):
        if count <= 1:
            return text

        suffix = f" (seen {count} times)"
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if line.strip():
                lines[idx] = line + suffix
                break

        rendered = "\n".join(lines)
        if text.endswith("\n"):
            rendered += "\n"
        return rendered

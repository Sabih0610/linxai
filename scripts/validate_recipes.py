"""Prove the generated Go, C++ and Docker projects really build, test and run.

    LINXAI_TEST_RECIPES=1 python3 -B scripts/validate_recipes.py --out recipes.json

Each project is generated through the typed service (the same worker the agent uses),
regenerated to show idempotence, then checked with real toolchains:
  * C++   : host g++ (-std=c++17 -Wall -Wextra -Wpedantic -Werror) + the binary's self-test;
            CMake configure/build/ctest inside an Alpine container when Docker is available
  * Go    : go vet, go test and go build inside golang:1.22-alpine (stdlib only, offline)
  * Docker: docker build of the generated Dockerfile, run it, HTTP health check on
            127.0.0.1, confirm the process is not root, then remove container and image
Projects are mounted read-only into containers; nothing runs with the owner's privileges
beyond the compiler. Container images are public official images pulled by Docker.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def sh(argv, timeout=600, **kw):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL, **kw)
    # stderr first: image-pull progress there must not push the command's own result out of the tail
    return done.returncode, (done.stderr[-2000:] + done.stdout)[-4000:]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="recipes.json")
    args = parser.parse_args(argv)
    if os.environ.get("LINXAI_TEST_RECIPES") != "1":
        print("PENDING: opt in with LINXAI_TEST_RECIPES=1 (pulls official container images)"); return 3
    from operations.audit import JsonlAudit
    from operations.registry import ActionRegistry
    from operations.service import LocalPolicy, OperationService
    from operations.workflows import WorkflowSystem
    docker = shutil.which("docker")
    steps = {}

    def step(name, ok, **facts):
        steps[name] = {"ok": bool(ok), **facts}
        print(("PASS " if ok else "FAIL ") + name, json.dumps(facts)[:240], flush=True)

    with tempfile.TemporaryDirectory(prefix="linxai-recipes-", dir=Path.home()) as ws:
        os.chmod(ws, 0o700)
        svc = OperationService(ActionRegistry(ws, actor_uid=os.getuid()), WorkflowSystem(), LocalPolicy(os.getuid()),
                               JsonlAudit(Path(ws) / ".audit.jsonl"))
        for action, path in (("project.go", "gosvc"), ("project.cpp", "cppapp"), ("project.docker", "dockapp")):
            first = svc.run({"action": action, "parameters": {"path": path}})
            again = svc.run({"action": action, "parameters": {"path": path}})
            step(f"{action}: generated, verified and idempotent", first.status == again.status == "succeeded" and first.verified,
                 files=sorted(p.name for p in (Path(ws) / path).iterdir()), runtime_present=json.loads(first.stdout).get("runtime_present"))
        # An owner edit is never overwritten: the recipe refuses before writing anything.
        edited = Path(ws) / "gosvc" / "main.go"
        original = edited.read_bytes(); edited.write_text("package main\n// owner edit\nfunc main() {}\n")
        blocked = svc.run({"action": "project.go", "parameters": {"path": "gosvc"}})
        step("owner edit preserved (recipe refuses to overwrite)", blocked.status != "succeeded" and "owner edit" in edited.read_text(),
             status=blocked.status)
        edited.write_bytes(original); os.chmod(edited, 0o600)

        cpp = Path(ws) / "cppapp"
        build = Path(ws) / "cpp-build"; build.mkdir(mode=0o700)
        rc, out = sh(["g++", "-std=c++17", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-o", str(build / "app"), str(cpp / "main.cpp")])
        run_rc, run_out = sh([str(build / "app")]) if rc == 0 else (1, "")
        test_rc, _ = sh([str(build / "app"), "--self-test"]) if rc == 0 else (1, "")
        step("C++: host g++ builds warning-free, runs and self-tests", rc == 0 and run_rc == 0 and "Hello from LINxAI" in run_out and test_rc == 0,
             compile=out.strip()[-120:])
        if not docker:
            step("container toolchains available", False, reason="docker not installed"); return 1
        rc, out = sh([docker, "run", "--rm", "--network", "bridge", "-v", f"{cpp}:/src:ro", "alpine:3.20", "sh", "-c",
                      "apk add --no-cache -q cmake make g++ >/dev/null && cmake -S /src -B /tmp/b -DCMAKE_BUILD_TYPE=Release >/dev/null"
                      " && cmake --build /tmp/b >/dev/null && ctest --test-dir /tmp/b --output-on-failure && /tmp/b/app"], timeout=900)
        step("C++: CMake configure, build and ctest (alpine container)", rc == 0 and "100% tests passed" in out and "Hello from LINxAI" in out,
             tail=out.strip()[-160:])
        go = Path(ws) / "gosvc"
        rc, out = sh([docker, "run", "--rm", "-v", f"{go}:/src:ro", "-w", "/src", "-e", "GOCACHE=/tmp/gocache",
                      "-e", "GOPATH=/tmp/gopath", "-e", "GOTOOLCHAIN=local", "-e", "GOPROXY=off", "golang:1.22-alpine", "sh", "-c",
                      "go vet ./... && go test ./... && go build -o /tmp/svc . && echo BUILD-OK"], timeout=900)
        step("Go: vet, test and build offline (golang:1.22-alpine)", rc == 0 and "ok" in out and "BUILD-OK" in out, tail=out.strip()[-160:])
        dock, tag, name = Path(ws) / "dockapp", "linxai-recipe-check:qa", "linxai-recipe-check"
        rc, out = sh([docker, "build", "-q", "-t", tag, str(dock)], timeout=900)
        step("Docker: image builds from the generated Dockerfile", rc == 0, tail=out.strip()[-160:])
        if rc == 0:
            sh([docker, "rm", "-f", name])
            rc, out = sh([docker, "run", "-d", "--name", name, "--read-only", "--security-opt", "no-new-privileges:true",
                          "-p", "127.0.0.1:18000:8000", tag])
            body, deadline = "", time.monotonic() + 30
            while time.monotonic() < deadline and not body:
                try:
                    body = urllib.request.urlopen("http://127.0.0.1:18000/", timeout=2).read().decode()
                except OSError:
                    time.sleep(1)
            uid_rc, uid = sh([docker, "exec", name, "id", "-u"])
            step("Docker: container serves health on 127.0.0.1, read-only, as a non-root user",
                 json.loads(body or "{}").get("status") == "ok" and uid.strip() not in ("", "0"), body=body, uid=uid.strip())
            sh([docker, "rm", "-f", name]); sh([docker, "image", "rm", "-f", tag])
    Path(args.out).write_text(json.dumps(steps, indent=2) + "\n")
    passed = all(s["ok"] for s in steps.values())
    print(("PASS" if passed else "FAIL"), f"{sum(s['ok'] for s in steps.values())}/{len(steps)} steps")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

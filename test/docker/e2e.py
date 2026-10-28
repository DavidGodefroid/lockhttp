#!/usr/bin/env python3
"""End-to-end test of the lockhttp image through the launcher, following
docs/docker.md.

The console runs in a pseudo-terminal this script answers (y to every
prompt); the gate runs in its own container, sharing only the socket
volume with the console; curl on the runner sends requests through the
gate's published port. Needs docker, curl and network access to
example.com. Uses the launcher's real names (lockhttp-console,
lockhttp-gate, volumes lockhttp-run and lockhttp-home) and removes them:
run it on a CI runner, not on a machine with a lockhttp setup.

    LOCKHTTP_IMAGE=lockhttp python3 test/docker/e2e.py

Standard library only.
"""

import os
import pty
import select
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LAUNCHER = os.path.join(ROOT, "scripts", "lockhttp")
PROXY = "http://127.0.0.1:3130"

failures = []


def check(ok, what, detail=""):
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        failures.append(what)
        if detail:
            print(detail, flush=True)


def sh(*args, check_=True, **kw):
    r = subprocess.run(args, capture_output=True, text=True, **kw)
    if check_ and r.returncode != 0:
        raise SystemExit(f"{' '.join(args)}: exit {r.returncode}\n{r.stdout}{r.stderr}")
    return r


def launcher(*args, env=None, check_=True):
    e = dict(os.environ)
    e.update(env or {})
    return sh("sh", LAUNCHER, *args, check_=check_, env=e, stdin=subprocess.DEVNULL)


def cleanup():
    sh("docker", "rm", "-f", "lockhttp-console", "lockhttp-gate", check_=False)
    sh("docker", "volume", "rm", "-f", "lockhttp-run", "lockhttp-home", check_=False)


class Console:
    """The console in a pseudo-terminal, approving every prompt."""

    def __init__(self):
        self.out = b""
        self.lock = threading.Lock()
        self.answered = 0
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("sh", ["sh", LAUNCHER, "console"])
        threading.Thread(target=self.pump, daemon=True).start()

    def pump(self):
        while True:
            try:
                r, _, _ = select.select([self.fd], [], [], 0.2)
                if not r:
                    continue
                chunk = os.read(self.fd, 4096)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.out += chunk
                n = self.out.decode("utf-8", "replace").count("[y/N]")
                if n > self.answered:
                    self.answered = n
                    os.write(self.fd, b"y\r")

    def text(self):
        with self.lock:
            return self.out.decode("utf-8", "replace")

    def wait_for(self, s, timeout=60):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if s in self.text():
                return True
            time.sleep(0.2)
        return False


def curl(*args):
    r = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-D", "-", "-x", PROXY, "--max-time", "90", *args],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def gate_logs():
    return sh("docker", "logs", "lockhttp-gate", check_=False).stderr


def main():
    image = os.environ.get("LOCKHTTP_IMAGE", "lockhttp")
    cleanup()
    try:
        # The image's accounts.
        r = sh("docker", "run", "--rm", "--entrypoint", "id", image, "gate")
        check("uid=10003(gate)" in r.stdout and "lockhttp-clients" in r.stdout, "gate is uid 10003 in lockhttp-clients", r.stdout)
        r = sh("docker", "run", "--rm", "--entrypoint", "id", image, "lockhttp")
        check("uid=10021(lockhttp)" in r.stdout and "lockhttp-clients" not in r.stdout, "the console account is not a client", r.stdout)
        r = sh("docker", "run", "--rm", "--entrypoint", "stat", image, "-c", "%U %a", "/etc/lockhttp/system.toml", "/usr/local/bin/lockhttp")
        check(r.stdout.split("\n")[:2] == ["root 644", "root 755"], "system.toml and the binary are root's", r.stdout)

        # The launcher.
        r = launcher("version")
        check("lockhttp launcher dev (image " + image + ")" in r.stdout or "(image " + image + ")" in r.stdout, "version names the image", r.stdout)
        r = launcher("install", check_=False)
        check(r.returncode != 0 and "runs in Docker" in r.stderr, "install is refused", r.stderr)
        launcher("init", "--trusted", "example.com")
        r = launcher("policy", "show")
        check('"example.com",' in r.stdout, "init wrote the policy in the console's volume", r.stdout)
        r = launcher("doctor", check_=False)
        check(r.returncode == 0 and "separated setup" in r.stdout, "doctor passes as the console account", r.stdout + r.stderr)

        # The console approves its first policy, then the gate connects.
        console = Console()
        check(console.wait_for("Listening on"), "the console listens", console.text())
        sh("sh", LAUNCHER, "gate", env=dict(os.environ, LOCKHTTP_DOCKER_ARGS="-d"), stdin=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline and "console up" not in gate_logs():
            time.sleep(0.5)
        check("console up" in gate_logs(), "the gate reaches the console through the socket volume", gate_logs())

        code, head = curl("http://example.com/")
        check(code == 0 and " 200 " in head.split("\n")[0] and "X-Lockhttp-Request" in head.title(), "a trusted read is free", head)
        code, head = curl("https://example.com/")
        check(code == 0 and "200" in head, "a trusted CONNECT is free", head)
        code, head = curl("-X", "POST", "-H", "Content-Type: application/json", "-d", '{"e2e":1}', "http://example.com/")
        check(code == 0 and "X-Lockhttp-Code" not in head.title() and console.wait_for("POST example.com"),
              "a write asks the console and goes through once approved", head + console.text()[-2000:])
        check("container local" in console.text(), "the screen names the source", console.text()[-2000:])

        # Without a console, asks are refused at once; trusted reads go on.
        sh("docker", "rm", "-f", "lockhttp-console", check_=False)
        deadline = time.time() + 30
        while time.time() < deadline and "console lost" not in gate_logs():
            time.sleep(0.5)
        code, head = curl("-X", "POST", "-d", "x", "http://example.com/")
        check("E_NO_CONSOLE" in head, "no console: E_NO_CONSOLE", head)
        code, head = curl("http://example.com/")
        check(" 200 " in head.split("\n")[0], "no console: trusted reads go on", head)
    finally:
        cleanup()
    if failures:
        print(f"{len(failures)} failure(s)", flush=True)
        sys.exit(1)
    print("all ok", flush=True)


if __name__ == "__main__":
    main()

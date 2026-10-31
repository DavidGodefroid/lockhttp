#!/usr/bin/env python3
"""End-to-end test of the lockhttp image through the launcher, following
docs/docker.md.

The console runs in a pseudo-terminal this script answers (y to every
prompt). The console is lockkit's policy-only console: it starts without
hub flags, as `lox up` runs it (`console`, or `console --profile P`), and
refuses them. The gate is hub-attached only: without its hub flags the
launcher's gate refuses to start ("launched by `lox up` only"). A request
through a gate that asks a hub is tested end to end by lockhub's e2e,
which runs the lockhttp lock under `lox up`. Needs docker. Uses the
launcher's real names (lockhttp-console, lockhttp-gate, volumes
lockhttp-run and lockhttp-home) and removes them: run it on a CI runner,
not on a machine with a lockhttp setup.

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

    def __init__(self, *args):
        self.out = b""
        self.lock = threading.Lock()
        self.answered = 0
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("sh", ["sh", LAUNCHER, "console", *args])
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

        # The console starts without hub flags, as lox up runs it (lockhub
        # internal/family/compose.go gives a gate kind's console `console`,
        # plus `--profile P` when the lock names one): it approves its first
        # policy, listens, and asks no hub.
        for args in ([], ["--profile", "default"]):
            console = Console(*args)
            check(console.wait_for("Listening on"), f"the console listens without hub flags ({' '.join(['console', *args])})", console.text())
            check(console.wait_for("Policy only"), "the console is policy-only", console.text())
            check("lockhub at" not in console.text(), "the console asks no hub", console.text())
            sh("docker", "rm", "-f", "lockhttp-console", check_=False)

        # The hub flags lox up gives the other locks' consoles are refused.
        r = launcher("console", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/lockfamily/hub.pub", "--instance", "web", check_=False)
        check(r.returncode != 0 and "-hub" in r.stderr, "the console takes no hub flags", r.stdout + r.stderr)

        # The gate does not start without the hub: lox up gives its flags.
        r = launcher("gate", check_=False)
        check(r.returncode != 0 and "launched by `lox up` only" in r.stderr, "the gate needs the hub", r.stdout + r.stderr)
    finally:
        cleanup()
    if failures:
        print(f"{len(failures)} failure(s)", flush=True)
        sys.exit(1)
    print("all ok", flush=True)


if __name__ == "__main__":
    main()

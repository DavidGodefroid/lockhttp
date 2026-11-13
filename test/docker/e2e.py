#!/usr/bin/env python3
"""End-to-end test of the lockhttp image through the launcher, following
docs/docker.md.

The console runs in a pseudo-terminal this script answers (y to every
prompt). The console is lockkit's policy-only console: it starts without
hub flags, as `lox run` runs it (`console`, or `console --profile P`), and
refuses them. The gate is hub-attached only: without its hub flags the
launcher's gate refuses to start ("launched by `lox run` only"). A request
through a gate that asks a hub is tested end to end by lockhub's e2e,
which runs the lockhttp lock under `lox run`. Needs docker. Uses the
launcher's real names (lockhttp-console, lockhttp-gate, volumes
lockhttp-run and lockhttp-home) and removes them: run it on a CI runner,
not on a machine with a lockhttp setup.

    LOCKHTTP_IMAGE=lockhttp python3 test/docker/e2e.py

Standard library only.
"""

import json
import os
import pty
import select
import subprocess
import sys
import tempfile
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


def launcher(*args, env=None, check_=True, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return sh("sh", LAUNCHER, *args, check_=check_, env=e, stdin=subprocess.DEVNULL, cwd=cwd)


# MANAGED_VOLUME holds the company's managed file the managed checks place
# at /etc/lockfamily in the containers (through LOCKHTTP_DOCKER_ARGS).
MANAGED_VOLUME = "lockhttp-e2e-managed"

MANAGED = """version = 1
organisation = "Example Corp"

[lockhttp.bounds]
mode = "enforce"
"""


def cleanup():
    sh("docker", "rm", "-f", "lockhttp-console", "lockhttp-gate", check_=False)
    sh("docker", "volume", "rm", "-f", "lockhttp-run", "lockhttp-home", MANAGED_VOLUME, check_=False)


def place_managed(image, mode):
    """Writes MANAGED into MANAGED_VOLUME as root, the file at mode, the
    directory root's 0755: what an admin's package installs."""
    sh("docker", "run", "-i", "--rm", "--user", "0:0", "-v", MANAGED_VOLUME + ":/m", "--entrypoint", "sh", image,
       "-c", f"cat > /m/managed.toml && chown 0:0 /m /m/managed.toml && chmod 0755 /m && chmod {mode} /m/managed.toml",
       input=MANAGED)


class Console:
    """The console in a pseudo-terminal, approving every prompt."""

    def __init__(self, *args, env=None):
        self.out = b""
        self.lock = threading.Lock()
        self.answered = 0
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ.update(env or {})
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
        # The launcher verbs lox add runs, as the invoking user on the
        # project (lockkit GUIDE.md section 14).
        project = tempfile.mkdtemp(prefix="lockhttp-e2e-")
        sub = os.path.join(project, "sub")
        os.makedirs(os.path.join(project, ".git"))
        os.makedirs(sub)
        r = launcher("profile", "add", "--non-interactive", "--json", "--trusted", "example.com", cwd=sub, check_=False)
        out = json.loads(r.stdout) if r.returncode == 0 else {}
        config = os.path.join(project, ".lockhttp", "config.toml")
        check(out == {"lock": "lockhttp", "profile": "default", "config": config, "production": False},
              "profile add writes the project's policy and prints one verbs.Profile", r.stdout + r.stderr)
        with open(config) as f:
            policy = f.read()
        check('"example.com",' in policy, "profile add imports --trusted", policy)
        check(os.stat(config).st_uid == os.getuid(), "the policy is the invoking user's", str(os.stat(config)))
        r = launcher("profile", "add", "--non-interactive", "--json", cwd=sub, check_=False)
        check(r.returncode != 0 and json.loads(r.stdout or "{}").get("code") == "exists", "an existing profile is kept (exists)", r.stdout + r.stderr)
        r = launcher("profile", "add", "--non-interactive", "--json", "--profile", "web", "--password", "x", cwd=sub, check_=False)
        check(r.returncode != 0 and json.loads(r.stdout or "{}").get("code") == "secret", "profile add refuses a secret", r.stdout + r.stderr)
        r = launcher("init", "claude", cwd=sub, check_=False)
        check(r.returncode == 0 and "nothing to write" in r.stdout, "init claude writes nothing", r.stdout + r.stderr)
        r = launcher("doctor", "--fix", "--yes", "--json", cwd=sub, check_=False)
        out = json.loads(r.stdout) if r.stdout.startswith("{") else {}
        check(r.returncode == 0 and out.get("ok") is True and "checks" in out, "doctor --fix --yes --json passes on the project", r.stdout + r.stderr)

        # lox run copies the project's policy into the console's volume; do
        # the same for the launcher's console.
        sh("docker", "run", "-i", "--rm", "--user", "lockhttp", "-v", "lockhttp-home:/home/lockhttp", "--entrypoint", "sh", image,
           "-c", "umask 077 && mkdir -p /home/lockhttp/.config/lockhttp && cat > /home/lockhttp/.config/lockhttp/config.toml", input=policy)
        r = launcher("policy", "show")
        check('"example.com",' in r.stdout, "the policy is in the console's volume", r.stdout)

        # The console starts without hub flags, as lox run runs it (lockhub
        # internal/family/compose.go gives a gate kind's console `console`,
        # plus `--profile P` when the lock names one): it approves its first
        # policy, listens, and asks no hub.
        for args in ([], ["--profile", "default"]):
            console = Console(*args)
            check(console.wait_for("Listening on"), f"the console listens without hub flags ({' '.join(['console', *args])})", console.text())
            check(console.wait_for("Policy only"), "the console is policy-only", console.text())
            check("lockhub at" not in console.text(), "the console asks no hub", console.text())
            sh("docker", "rm", "-f", "lockhttp-console", check_=False)

        # The company's managed file, root-owned in the container (0:0,
        # 0644, its directory 0755), in a release image (no test tag): the
        # console names it and refuses a shadow profile beyond its bounds.
        managed_env = {"LOCKHTTP_DOCKER_ARGS": "-v " + MANAGED_VOLUME + ":/etc/lockfamily:ro"}
        place_managed(image, "0644")
        r = launcher("managed", "show", env=managed_env, check_=False)
        check(r.returncode == 0 and "path: /etc/lockfamily/managed.toml" in r.stdout and "organisation: Example Corp" in r.stdout
              and "mode = enforce" in r.stdout, "managed show reads the root-owned file", r.stdout + r.stderr)
        shadow = "[profiles.default]\nmode = \"shadow\"\n"
        sh("docker", "run", "-i", "--rm", "--user", "lockhttp", "-v", "lockhttp-home:/home/lockhttp", "--entrypoint", "sh", image,
           "-c", "umask 077 && cat > /home/lockhttp/.config/lockhttp/config.toml", input=shadow)
        r = launcher("managed", "check", env=managed_env, check_=False)
        check(r.returncode == 3 and r.stdout == "blocked by company policy: lockhttp.bounds.mode = enforce (profile default: mode = shadow)\n",
              "managed check: the violation line and exit 3", f"exit {r.returncode}\n{r.stdout}{r.stderr}")
        console = Console(env=managed_env)
        check(console.wait_for("Managed by Example Corp (sha256:"), "the console names the managed file", console.text())
        check(console.wait_for("blocked by company policy: lockhttp.bounds.mode = enforce (profile default: mode = shadow)"),
              "the console refuses a shadow profile beyond the bounds", console.text())
        check(console.answered == 0 and "Listening on" not in console.text(), "no prompt, no socket", console.text())
        sh("docker", "rm", "-f", "lockhttp-console", check_=False)
        # The same file writable by others than root: a refusal to start.
        place_managed(image, "0666")
        console = Console(env=managed_env)
        check(console.wait_for("must be writable by root only"), "a managed file others may write is a refusal to start", console.text())
        check("Listening on" not in console.text(), "no socket under a badly owned managed file", console.text())
        sh("docker", "rm", "-f", "lockhttp-console", check_=False)
        r = launcher("managed", "show", env=managed_env, check_=False)
        check(r.returncode == 3 and "must be writable by root only" in r.stderr, "managed show: the lockkit error, exit 3", r.stdout + r.stderr)

        # The hub flags lox run gives the other locks' consoles are refused.
        r = launcher("console", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/lockfamily/hub.pub", "--instance", "web", check_=False)
        check(r.returncode != 0 and "-hub" in r.stderr, "the console takes no hub flags", r.stdout + r.stderr)

        # The gate does not start without the hub: lox run gives its flags.
        r = launcher("gate", check_=False)
        check(r.returncode != 0 and "launched by `lox run` only" in r.stderr, "the gate needs the hub", r.stdout + r.stderr)
    finally:
        cleanup()
    if failures:
        print(f"{len(failures)} failure(s)", flush=True)
        sys.exit(1)
    print("all ok", flush=True)


if __name__ == "__main__":
    main()

# LockHTTP

**Your AI browses. You hold the key.**

LockHTTP is the proxy every outbound HTTP(S) request of an AI agent goes
through. Reads of trusted hosts pass; anything that sends data, triggers an
action or reaches an unknown host waits for a human, in a console the agent
cannot reach. Every decision is traced to the container, the agent and the
session that asked.

LockHTTP is a member of the Lock family:
[LockSQL](https://github.com/DavidGodefroid/locksql) ·
[LockMQ](https://github.com/DavidGodefroid/lockmq) ·
[LockFile](https://github.com/DavidGodefroid/lockfile) ·
**LockHTTP**, all built on [lockkit](https://github.com/DavidGodefroid/lockkit).

> Status: under construction, first pre-release `v0.1.0` in progress.
> Design decisions: [docs/decisions.md](docs/decisions.md).

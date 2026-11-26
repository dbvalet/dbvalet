# dbvalet

A valet key for your database. Hand it to your AI agent, not the master key.

```
dbvalet run --role reader -- claude
```

dbvalet gives an AI coding agent (Claude Code, Codex, Cursor, or any command) a temporary PostgreSQL login for one run:

- The agent connects through a local proxy with a per-run token. The real password never enters its environment or its conversation.
- The login is read-only unless your repository's `dbvalet.toml` allows more.
- When the agent exits, its sessions end and the login is dropped.
- Two Ctrl-C presses (`SIGINT`) end the run: the first waits for the child to exit cleanly, and the second forwards `SIGTERM` and tears down as soon as the child exits, or after 5 seconds if it hasn't (returning the child's exit code, or 130 on timeout). `SIGINT`s sent in quick succession may count as one; supervisors and scripts should send `SIGTERM` (or `SIGHUP`), which forwards the signal and tears down when the child exits, or after 5 seconds if it hasn't (returning the child's code, or 143 / 129 on timeout).
- On Linux, if `dbvalet` is killed with `SIGKILL`, the child receives `SIGTERM` via `PR_SET_PDEATHSIG`. On macOS, an orphaned child keeps running, but loses database access because the local proxy is gone.
- Every run is logged locally, including the SQL it ran.

**Status: not usable yet.** First release planned for December 2026.

Licensed under [Apache-2.0](LICENSE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

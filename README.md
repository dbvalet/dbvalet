# dbvalet

A valet key for your database. Hand it to your AI agent, not the master key.

```
dbvalet run --role reader -- claude
```

dbvalet gives an AI coding agent (Claude Code, Codex, Cursor, or any command) a temporary PostgreSQL login for one run:

- The agent connects through a local proxy with a per-run token. The real password never enters its environment or its conversation.
- The login is read-only unless your repository's `dbvalet.toml` allows more.
- When the agent exits, its sessions end and the login is dropped.
- On Ctrl-C (`SIGINT`), `dbvalet` waits for the child to exit cleanly; a second Ctrl-C forwards `SIGTERM` to the child and tears down after 5 seconds whether or not it exits (returning the child's exit code, or 130 on timeout). `SIGTERM` and `SIGHUP` forward the signal and tear down after 5 seconds (returning the child's code, or 143 / 129 on timeout).
- On Linux, if `dbvalet` is killed with `SIGKILL`, the child receives `SIGTERM` via `PR_SET_PDEATHSIG`. On macOS, an orphaned child keeps running, but loses database access because the local proxy is gone.
- Every run is logged locally, including the SQL it ran.

**Status: not usable yet.** First release planned for December 2026.

Licensed under [Apache-2.0](LICENSE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

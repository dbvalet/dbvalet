# dbvalet

A valet key for your database. Hand it to your AI agent, not the master key.

```
dbvalet run --role reader -- claude
```

dbvalet gives an AI coding agent (Claude Code, Codex, Cursor, or any command) a temporary PostgreSQL login for one run:

- The agent connects through a local proxy with a per-run token. The real password never enters its environment or its conversation.
- The login is read-only unless your repository's `dbvalet.toml` allows more.
- When the agent exits, its sessions end and the login is dropped.
- Every run is logged locally, including the SQL it ran.

**Status: not usable yet.** First release planned for December 2026.

Licensed under [Apache-2.0](LICENSE). Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

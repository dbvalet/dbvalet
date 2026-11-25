# 1. The agent reaches the database through a local proxy, not environment variables

Status: accepted, 25 November 2026

## Context

The simplest design passes the temporary login's password to the child process as `PGPASSWORD` or `DATABASE_URL`. When the child is an AI agent (Claude Code, Codex, Cursor), the agent can print its own environment, and the password lands in its conversation, its transcript and the model provider's logs. `envconsul` and `infisical run` work this way; Infisical Agent Vault and hoophq `cloak` avoid it with a proxy.

## Decision

dbvalet starts a PostgreSQL proxy on `127.0.0.1` and gives the child a connection string with a per-run token as the password. The proxy checks the token and connects upstream with the real temporary login.

## Consequences

- Printing the environment reveals only the token, which works only against this proxy during this run.
- dbvalet must speak the PostgreSQL wire protocol on both sides, including SCRAM and TLS upstream.
- The proxy can record the SQL each run sends, which gives the run log its value.

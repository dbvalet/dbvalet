# 3. dbvalet protects against accidental exposure, not a hostile process running as you

Status: accepted, 26 November 2026

## Context

dbvalet runs an AI coding agent as a child process. That process runs as the same operating-system user as dbvalet, so it can do anything that user can:
- run `dbvalet` itself;
- edit `dbvalet.toml`;
- read keychain entries. On Linux, Secret Service gives any process in an unlocked session the stored secrets without a prompt. On macOS, a different program gets a prompt, but the `dbvalet` binary itself doesn't.

The common way a database password leaks today isn't an agent attacking its own machine. It's a password in `PGPASSWORD`, `DATABASE_URL` or a `.env` file that the agent prints, quotes or logs. It then ends up in the conversation, the transcript and the model provider's logs.

## Decision

dbvalet's promises cover accidental exposure:
- the agent's environment never holds a real password, only a per-run token (ADR-0001);
- nothing dbvalet prints or logs contains a password or token;
- each temporary login is dropped when the run ends, or by the next sweep.

A hostile process running as the same OS user is out of scope. dbvalet doesn't claim to stop it reading the keychain, starting its own run, or changing `dbvalet.toml`. Anyone who needs that boundary runs the agent as a different OS user, or in a container or VM without access to the keychain.

## Consequences

- The README states this threat model in plain words, next to what dbvalet does promise.
- There are no partial defences against a same-user attacker, such as detecting a nested run or adding a Linux keychain prompt. They would suggest a boundary that dbvalet can't hold.
- Checks that guard against mistakes still apply. One is refusing a dangerous group role in `dbvalet.toml`: a reviewed, committed file can still contain an error.

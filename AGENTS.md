# dbvalet: instructions for coding agents

An open-source Rust CLI (Apache-2.0) that runs an AI coding agent or any command with a temporary PostgreSQL login behind a local proxy, and drops the login when the command exits. Read `CONTEXT.md` for the vocabulary and `docs/adr/` for settled decisions.

**Read `CODING_STANDARDS.md` before writing or reviewing code.**

## Build and test

- Format: `cargo fmt --all --check`
- Lint: `cargo clippy --all-targets --locked -- -D warnings`
- Test: `cargo test --locked`
- Licences and advisories: `cargo deny check` (CI runs it; install with `cargo install --locked cargo-deny`)
- End-to-end tests run against real PostgreSQL 15 through 19 in Docker (plus PostgreSQL 14 for refusal checks). Never mock the database in a test that claims to prove a login was created, refused or dropped.
- Prove a change before handing it back: run all of the above and say which you ran.

## Promises the code must never break

- The agent never receives the real database password: only a per-run token for the local proxy.
- A login dbvalet creates is dropped when the run ends, or by the next sweep (`dbvalet gc` or the next run) after a crash.
- No password or token appears in any log, error message, panic or `Debug` output. Hold them in `secrecy` types.
- No `unsafe` code (`unsafe_code = "forbid"` in `Cargo.toml`).
- Upstream connections use TLS with certificate checks; plaintext only for a database on localhost with `--allow-plaintext`.
- No telemetry of any kind.
- The proxy never claims to block SQL. Enforcement is the database's own permissions (ADR-0002).

## Models and review

- Implementers: Claude Opus 5.5 (`claude-opus-5-5`, effort high) or Gemini 4 Neon (`gemini-4-neon`, high).
- Reviewer: GPT Sol 6.2 (`gpt-6.2-sol`, reasoning xhigh). It also implements when neither implementer is available.
- Research: Grok 4.7.
- The reviewer is never the model that wrote the change. A change GPT Sol wrote is reviewed by a fresh Claude Opus 5.5 session, which says so.
- One review and one re-check per change; anything left becomes a follow-up issue.

## Workflow

`grilling` → `to-spec` → pstack `architect` → `to-tickets` (GitHub issues here) → `tdd` → CI → cross-model `code-review` → owner merges.

- Run lifecycle changes are checked against the pstack `statechart` model first.
- Pull requests touching the proxy, the cleanup or the keychain also go through pstack `interrogate`.
- pstack skills are user-triggered: a coordinator starts the brief with the slash command (`/architect`, `/interrogate`).

## Working rules

- Do not merge pull requests, push tags, force-push or delete branches unless the owner asks for that specific action.
- Never read, print or paste a real credential, keychain entry or private key.
- Commit messages follow `CODING_STANDARDS.md`.

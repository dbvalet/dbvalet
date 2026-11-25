# 2. The proxy records SQL but never blocks it

Status: accepted, 25 November 2026

## Context

A proxy that sees every statement invites a feature: refuse `DELETE`, `DROP` or writes. SQL parsing for enforcement is easy to get around (functions, `DO` blocks, prepared statements, extensions), and a tool that claims to block writes but can be bypassed is worse than one that doesn't claim it.

## Decision

The proxy only records statement text for the run log. Enforcement is the database's own permissions: temporary logins join a group role (`dbvalet_reader` by default) and read roles also set `default_transaction_read_only`. Write roles exist only when `dbvalet.toml` lists them.

## Consequences

- The README never promises that dbvalet stops an agent deleting data. A write role can still `DELETE`.
- What dbvalet does promise: the password never reaches the agent, every run is attributable, and nothing is left to rotate.

# Glossary

- **Run:** one `dbvalet run -- <command>`. It owns one login, one proxy and one child process, and ends with a teardown.
- **Admin login:** the PostgreSQL login dbvalet uses to create and drop temporary logins. Stored only in the OS keychain, under a database alias.
- **Database alias:** a name in `dbvalet.toml` (e.g. `app`) that matches a keychain entry. The repository never holds the address or the admin login.
- **Temporary login:** a PostgreSQL role named `dbvalet_<run-id>` with `LOGIN`, a random password and a `VALID UNTIL` expiry. The agent never sees its password.
- **Role (in `dbvalet.toml`):** a group role a temporary login joins, e.g. `dbvalet_reader`. Only roles listed for the database may be used.
- **Proxy:** the local PostgreSQL endpoint on `127.0.0.1` that the child connects to. It checks the run token and connects upstream as the temporary login.
- **Run token:** the per-run random password the child uses against the proxy. Worthless outside that proxy and that run.
- **Expiry push:** while a run lives, dbvalet moves the login's `VALID UNTIL` forward, never past the database's `max_ttl`.
- **Teardown:** end of a run: terminate the login's sessions, then drop it.
- **Sweep:** cleanup of leftover `dbvalet_` logins after a crash, done at the start of every run and by `dbvalet gc`.
- **Ledger:** the local files, one per temporary login a run created and hasn't yet confirmed dropped, each locked while its run lives.
- **Run log:** the local per-run file with the time, command, role, lease and the SQL text. Never a password or token.

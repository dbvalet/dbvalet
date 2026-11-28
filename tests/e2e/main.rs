//! `dbvalet` as a subprocess, against real PostgreSQL on localhost:5432 and the real OS
//! keychain. CI runs these with `cargo test --test e2e -- --ignored`.
//!
//! Every test uses its own alias and admin role, so they can run in parallel.

mod dangerous_roles;
mod expiry;
mod init;
mod login_doctor;
mod protocol;
mod role_default;
mod run_log;
mod run_proxy;
mod signals;
mod support;
mod sweep_gc;
mod write_runs;

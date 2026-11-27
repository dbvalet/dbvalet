//! Where temporary logins come from.

use std::sync::Arc;

use secrecy::SecretString;

use crate::DatabaseAlias;
use crate::config::RoleGrant;
use crate::keychain::AdminLogin;
use crate::ledger::{self, LedgerError};

pub mod direct;

/// The temporary login the proxy connects upstream as. Its password never leaves dbvalet.
#[derive(Debug, Clone)]
pub struct UpstreamLogin {
    user: String,
    password: SecretString,
}

impl UpstreamLogin {
    pub fn user(&self) -> &str {
        &self.user
    }

    pub fn password(&self) -> &SecretString {
        &self.password
    }
}

/// No variant carries a password: reasons are built from SQLSTATEs and server messages only.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("can't connect as the admin login for `{alias}`: {reason}")]
    Connect {
        alias: DatabaseAlias,
        reason: String,
    },
    #[error("PostgreSQL {version} is end-of-life: dbvalet needs 15 or later")]
    TooOld { version: String },
    #[error(
        "the admin login `{user}` has NOINHERIT on PostgreSQL {version}, so it can't drop \
         temporary logins it creates: run ALTER ROLE {quoted} INHERIT, or run `dbvalet doctor {alias}`"
    )]
    AdminNoInherit {
        alias: DatabaseAlias,
        user: String,
        quoted: String,
        version: String,
    },
    #[error("couldn't create a temporary login: {reason}")]
    CreateLogin { reason: String },
    #[error(
        "couldn't drop the temporary login `{login}`: {reason}. \
         It stops accepting new connections within 15 minutes"
    )]
    DropLogin { login: String, reason: String },
    #[error("couldn't drop the leftover login `{login}`: {reason}")]
    DropLeftoverLogin { login: String, reason: String },
    #[error("couldn't list the expired temporary logins: {reason}")]
    ListExpiredLogins { reason: String },
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("the OS random number generator failed")]
    Random(#[source] getrandom::Error),
}

pub enum MintOutcome {
    Created(Lease),
    Interrupted(i32),
}

#[expect(
    async_fn_in_trait,
    reason = "run is generic over the source on a single-threaded runtime, so no Send bound is needed"
)]
pub trait CredentialSource {
    /// Drops the logins that ended runs left behind. A failure on one login doesn't stop the rest.
    async fn sweep(&self) -> Result<SweepReport, SourceError>;
    async fn mint(
        &self,
        grant: &RoleGrant,
        interrupted: impl Future<Output = i32>,
    ) -> Result<MintOutcome, SourceError>;
}

/// What a sweep cleaned up, and what it couldn't.
#[derive(Debug, Default)]
pub struct SweepReport {
    /// Leftover logins the sweep dropped.
    pub dropped: Vec<String>,
    /// Logins whose ledger entry the sweep removed because the login no longer existed.
    pub already_gone: Vec<String>,
    pub failures: Vec<SourceError>,
}

/// A temporary login that exists until [`Lease::release`] drops it.
#[derive(Debug)]
pub struct Lease {
    login: UpstreamLogin,
    valid_until: String,
    alias: DatabaseAlias,
    admin: Arc<AdminLogin>,
    member_of: String,
    read_only: bool,
    ledger_entry: ledger::Entry,
}

impl Lease {
    pub fn login(&self) -> &UpstreamLogin {
        &self.login
    }

    pub fn valid_until(&self) -> &str {
        &self.valid_until
    }

    pub fn run_id(&self) -> &str {
        self.login
            .user()
            .strip_prefix(crate::LOGIN_PREFIX)
            .unwrap_or(self.login.user())
    }

    /// Ends the login's sessions and drops it. On failure the ledger entry stays for the next sweep.
    pub async fn release(self) -> Result<(), SourceError> {
        direct::drop_login(
            &self.alias,
            &self.admin,
            self.login.user(),
            &self.member_of,
            self.read_only,
        )
        .await?;
        self.ledger_entry.remove()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_upstream_login_debug_output_hides_the_password() {
        let login = UpstreamLogin {
            user: "dbvalet_aaaaaaaaaaaaaaaa".to_owned(),
            password: SecretString::from("pw-upstream-unit-3e7"),
        };
        assert!(!format!("{login:?}").contains("pw-upstream-unit-3e7"));
    }
}

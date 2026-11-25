//! The command line, mapped onto library calls.

use std::io::{self, IsTerminal, Read};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};

use crate::DatabaseAlias;
use crate::keychain::{self, KeychainError};
use crate::source::direct;

const INITIAL_STDIN_CAPACITY: usize = 256;

#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Store a database's admin connection string in the OS keychain.
    ///
    /// Reads it from a hidden prompt, or from stdin when stdin isn't a terminal.
    Login { alias: DatabaseAlias },
    /// Check that dbvalet can use a database's stored admin login.
    Doctor {
        alias: DatabaseAlias,
        /// Connect without TLS. Allowed only for a database on localhost.
        #[arg(long)]
        allow_plaintext: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("couldn't read the connection string")]
    ReadConnectionString(#[source] io::Error),
    #[error(transparent)]
    Keychain(#[from] KeychainError),
}

pub async fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Command::Login { alias } => {
            let connection_string =
                read_connection_string(&alias).map_err(CliError::ReadConnectionString)?;
            keychain::store(&alias, connection_string)?;
            println!("Stored the admin login for `{alias}` in the OS keychain.");
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor {
            alias,
            allow_plaintext,
        } => {
            let checks = direct::doctor(&alias, allow_plaintext).await;
            for check in &checks {
                println!("{check}");
            }
            let all_passed = checks.iter().all(|check| check.passed);
            Ok(if all_passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

fn read_connection_string(alias: &DatabaseAlias) -> io::Result<SecretString> {
    if io::stdin().is_terminal() {
        let prompt = format!("Admin connection string for `{alias}`: ");
        return rpassword::prompt_password(prompt).map(SecretString::from);
    }
    read_secret_line(io::stdin())
}

fn read_secret_line(mut reader: impl Read) -> io::Result<SecretString> {
    let mut buffer = SecretBox::new(Box::new(String::with_capacity(INITIAL_STDIN_CAPACITY)));
    reader.read_to_string(buffer.expose_secret_mut())?;
    Ok(SecretString::from(buffer.expose_secret().trim_end()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_a_piped_secret_trims_trailing_newlines() {
        let secret =
            read_secret_line(b"postgresql://admin:pw@localhost/db\r\n".as_slice()).unwrap();
        assert_eq!(secret.expose_secret(), "postgresql://admin:pw@localhost/db");
    }

    #[test]
    fn reading_a_piped_secret_rejects_invalid_utf8() {
        let err = read_secret_line(b"postgresql://admin:pw@\xff".as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

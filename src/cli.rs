//! The command line, mapped onto library calls.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Read};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};

use crate::DatabaseAlias;
use crate::config::{self, ConfigError};
use crate::keychain::{self, KeychainError};
use crate::policy::{self, PolicyError};
use crate::run::{self, RunError, RunOutcome};
use crate::source::direct::{self, DirectSource};

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
    /// Run a command with a temporary login behind a local proxy, dropped when it exits.
    Run {
        /// The database from dbvalet.toml. Needed when the file lists more than one.
        #[arg(long)]
        db: Option<DatabaseAlias>,
        /// A role dbvalet.toml lists for the database.
        #[arg(long, default_value = "reader")]
        role: String,
        /// Connect without TLS. Allowed only for a database on localhost.
        #[arg(long)]
        allow_plaintext: bool,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("couldn't read the connection string")]
    ReadConnectionString(#[source] io::Error),
    #[error("the connection string must be a single line")]
    MultipleLines,
    #[error("the connection string didn't contain valid UTF-8")]
    InvalidUtf8,
    #[error(transparent)]
    Keychain(#[from] KeychainError),
    #[error("couldn't read the current directory")]
    CurrentDirectory(#[source] io::Error),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Run(#[from] RunError),
}

pub async fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Command::Login { alias } => {
            let connection_string = read_connection_string(&alias)?;
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
        Command::Run {
            db,
            role,
            allow_plaintext,
            command,
        } => {
            let cwd = std::env::current_dir().map_err(CliError::CurrentDirectory)?;
            let config = config::find_and_load(&cwd)?;
            let (alias, database) = policy::choose_database(&config, db.as_ref())?;
            let grant = policy::choose_role(alias, database, &role)?;
            let admin = keychain::load(alias, allow_plaintext)?;
            let upstream = admin.endpoint().clone();
            let source = DirectSource::new(alias.clone(), admin);
            let outcome = run::run(&source, grant, upstream, &command).await?;
            Ok(exit_code(outcome))
        }
    }
}

/// The child's exit code, or 128 plus the signal that ended the run, as a shell reports it.
fn exit_code(outcome: RunOutcome) -> ExitCode {
    let code = match outcome {
        RunOutcome::Exited(status) => status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(1),
        RunOutcome::TimedOut(signal) => 128 + signal.number(),
    };
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}

fn read_connection_string(alias: &DatabaseAlias) -> Result<SecretString, CliError> {
    if io::stdin().is_terminal() {
        let prompt = format!("Admin connection string for `{alias}`: ");
        return read_prompt_secret(prompt, rpassword::ConfigBuilder::new().build());
    }
    read_secret_line(io::stdin())
}

fn read_prompt_secret(prompt: String, config: rpassword::Config) -> Result<SecretString, CliError> {
    let secret = rpassword::prompt_password_with_config(prompt, config)
        .map(SecretString::from)
        .map_err(CliError::ReadConnectionString)?;
    // rpassword turns invalid UTF-8 bytes into U+FFFD rather than returning an error.
    if secret.expose_secret().contains('\u{FFFD}') {
        return Err(CliError::InvalidUtf8);
    }
    Ok(secret)
}

fn read_secret_line(mut reader: impl Read) -> Result<SecretString, CliError> {
    // Inputs past INITIAL_STDIN_CAPACITY reallocate, and the old buffer isn't zeroed.
    let mut buffer = SecretBox::new(Box::new(String::with_capacity(INITIAL_STDIN_CAPACITY)));
    reader
        .read_to_string(buffer.expose_secret_mut())
        .map_err(|err| {
            if err.kind() == io::ErrorKind::InvalidData {
                CliError::InvalidUtf8
            } else {
                CliError::ReadConnectionString(err)
            }
        })?;
    let mut non_empty_lines = buffer
        .expose_secret()
        .split(['\n', '\r'])
        .filter(|line| !line.trim().is_empty());
    let first = non_empty_lines.next().unwrap_or("");
    if non_empty_lines.next().is_some() {
        return Err(CliError::MultipleLines);
    }
    Ok(SecretString::from(first.trim_end()))
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
        assert!(matches!(err, CliError::InvalidUtf8));
    }

    #[test]
    fn reading_a_piped_secret_rejects_more_than_one_non_empty_line() {
        let err = read_secret_line(
            b"postgresql://admin:pw1@localhost/db\npostgresql://other:pw2@localhost/db\n"
                .as_slice(),
        )
        .unwrap_err();
        assert!(matches!(err, CliError::MultipleLines));
    }

    #[test]
    fn reading_a_prompt_secret_rejects_invalid_utf8() {
        let config = rpassword::ConfigBuilder::new()
            .input_data(b"postgresql://admin:pw-prompt-9c1\xff@localhost/db\n".to_vec())
            .output_discard()
            .build();
        let err = read_prompt_secret("Prompt: ".to_owned(), config).unwrap_err();
        assert!(matches!(err, CliError::InvalidUtf8));
        assert!(!format!("{err}").contains("pw-prompt-9c1"));
        assert!(!format!("{err:?}").contains("pw-prompt-9c1"));
    }

    #[test]
    fn exit_code_reports_128_plus_signal_when_teardown_timed_out_after_a_signal() {
        use crate::signals::TerminationSignal;

        assert_eq!(
            exit_code(RunOutcome::TimedOut(TerminationSignal::Terminate)),
            ExitCode::from(143)
        );
        assert_eq!(
            exit_code(RunOutcome::TimedOut(TerminationSignal::Hangup)),
            ExitCode::from(129)
        );
    }
}

//! The command line, mapped onto library calls.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};

use crate::DatabaseAlias;
use crate::config::{self, ConfigError};
use crate::keychain::{self, KeychainError};
use crate::ledger;
use crate::policy::{self, PolicyError};
use crate::run::{self, RunError, RunOptions};
use crate::runlog::{self, RunLogError};
use crate::signals::WaitOutcome;
use crate::source::CredentialSource;
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
    /// Prepare a database for read-only runs: create dbvalet_reader and let it read the tables.
    ///
    /// Safe to run again, for example with another schema. Creates dbvalet.toml when there's
    /// none, and otherwise prints the entry to add to it.
    Init {
        alias: DatabaseAlias,
        /// A schema whose tables dbvalet_reader may read. Repeat it for more than one.
        #[arg(long = "schema", value_name = "NAME", default_value = "public")]
        schemas: Vec<String>,
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
        /// Record only the run header, without command arguments or SQL statements.
        #[arg(long)]
        no_sql_log: bool,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
    /// List recent runs (newest first), or print one run's log.
    ///
    /// The run token and temporary login password are always scrubbed. SQL password redaction
    /// (such as `ALTER ROLE ... PASSWORD '[REDACTED]'`) is lexical and best-effort; use
    /// `dbvalet run --no-sql-log` when query text must stay off disk.
    /// Statements over the 64 KiB capture limit are recorded as a truncation marker.
    Log {
        /// The run ID to print. Omit to list recent runs.
        run_id: Option<String>,
    },
    /// Drop the temporary logins that killed runs left behind.
    ///
    /// Sweeps every database in this machine's ledger and in dbvalet.toml.
    Gc {
        /// Connect without TLS. Allowed only for a database on localhost.
        #[arg(long)]
        allow_plaintext: bool,
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
    Init(#[from] direct::InitError),
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Run(#[from] RunError),
    #[error(transparent)]
    RunLog(#[from] RunLogError),
    #[error("couldn't write to stdout")]
    WriteStdout(#[source] io::Error),
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
            let cwd = std::env::current_dir().map_err(CliError::CurrentDirectory)?;
            let roles = match config::find_and_load(&cwd) {
                Ok(config) => config
                    .databases
                    .get(&alias)
                    .map(|policy| policy.roles.clone())
                    .unwrap_or_default(),
                Err(ConfigError::NotFound { .. }) => BTreeMap::new(),
                Err(err) => return Err(err.into()),
            };
            let checks = direct::doctor(&alias, allow_plaintext, &roles).await;
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
        Command::Init {
            alias,
            schemas,
            allow_plaintext,
        } => {
            let cwd = std::env::current_dir().map_err(CliError::CurrentDirectory)?;
            let admin = keychain::load(&alias, allow_plaintext)?;
            let report = direct::init(&alias, &admin, &schemas).await?;
            let schema_list = schemas
                .iter()
                .map(|schema| format!("`{schema}`"))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "dbvalet_reader can read the tables in {schema_list} of database `{}`.",
                report.database
            );
            for (schema, count) in &report.unreadable_tables {
                println!(
                    "{count} existing tables in `{schema}` stay unreadable because another role \
                     owns them: their owner must GRANT SELECT on them TO dbvalet_reader."
                );
            }
            println!(
                "Tables that `{}` creates later in {schema_list} will be readable too. \
                 Tables another role creates need their own GRANT SELECT ... TO dbvalet_reader.",
                admin.user()
            );
            let entry = config::reader_entry(&alias);
            let existing = match config::find(&cwd) {
                Some(path) => path,
                None => {
                    let path = cwd.join(config::FILE_NAME);
                    match config::create(&path, &entry) {
                        Ok(()) => {
                            println!("\nCreated {} with a `reader` role.", path.display());
                            return Ok(ExitCode::SUCCESS);
                        }
                        // Another init in this directory created it first.
                        Err(err)
                            if err.kind() == io::ErrorKind::AlreadyExists && path.is_file() =>
                        {
                            path
                        }
                        // The grants are in place, so the entry is still worth having.
                        Err(err) => {
                            let _ = writeln!(
                                io::stderr(),
                                "dbvalet: couldn't create {}: {err}",
                                path.display()
                            );
                            println!("\nAdd this entry to a {}:\n\n{entry}", config::FILE_NAME);
                            return Ok(ExitCode::FAILURE);
                        }
                    }
                }
            };
            println!(
                "\n{} already exists, so dbvalet left it unchanged. \
                 Add this entry to it if it's missing:\n\n{entry}",
                existing.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Run {
            db,
            role,
            allow_plaintext,
            no_sql_log,
            command,
        } => {
            let cwd = std::env::current_dir().map_err(CliError::CurrentDirectory)?;
            let config = config::find_and_load(&cwd)?;
            let (alias, database) = policy::choose_database(&config, db.as_ref())?;
            let grant = policy::choose_role(alias, database, &role)?;
            let max_ttl = policy::max_ttl(database);
            let admin = keychain::load(alias, allow_plaintext)?;
            let upstream = admin.endpoint().clone();
            let source = DirectSource::new(alias.clone(), admin);
            let options = RunOptions {
                database: alias,
                role: &role,
                grant,
                max_ttl,
                sql_log: !no_sql_log,
            };
            let outcome = run::run(&source, &options, upstream, &command).await?;
            Ok(exit_code(outcome))
        }
        Command::Log { run_id: None } => {
            let runs = runlog::list()?;
            let mut stdout = io::stdout().lock();
            if runs.is_empty() {
                write_stdout(&mut stdout, b"No runs logged yet.\n")?;
            } else {
                for summary in &runs {
                    write_stdout(&mut stdout, format!("{summary}\n").as_bytes())?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Log {
            run_id: Some(run_id),
        } => {
            let mut stdout = io::stdout().lock();
            match runlog::copy_to(&run_id, &mut stdout) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(RunLogError::WriteOutput(err)) if err.kind() == io::ErrorKind::BrokenPipe => {
                    Ok(ExitCode::SUCCESS)
                }
                Err(err) => Err(err.into()),
            }
        }
        Command::Gc { allow_plaintext } => {
            let cwd = std::env::current_dir().map_err(CliError::CurrentDirectory)?;
            // Without the ledger no database can be swept safely, so none is tried.
            let mut aliases = match ledger::aliases() {
                Ok(aliases) => aliases,
                Err(err) => {
                    let _ = writeln!(io::stderr(), "dbvalet: {err}");
                    return Ok(ExitCode::FAILURE);
                }
            };
            match config::find_and_load(&cwd) {
                Ok(config) => aliases.extend(config.databases.into_keys()),
                Err(ConfigError::NotFound { .. }) => {}
                Err(err) => return Err(err.into()),
            }
            if aliases.is_empty() {
                print_line(format_args!(
                    "nothing to clean up: no database in the ledger or in {}",
                    config::FILE_NAME
                ));
            }
            let mut all_swept = true;
            for alias in &aliases {
                all_swept &= gc(alias, allow_plaintext).await;
            }
            Ok(if all_swept {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

/// Writes to stdout, treating a closed downstream pipe (`head`, `less`) as a clean stop.
fn write_stdout(stdout: &mut impl Write, bytes: &[u8]) -> Result<(), CliError> {
    match stdout.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(CliError::WriteStdout(err)),
    }
}

/// Sweeps one database and prints what it dropped. Returns whether nothing failed.
async fn gc(alias: &DatabaseAlias, allow_plaintext: bool) -> bool {
    let admin = match keychain::load(alias, allow_plaintext) {
        Ok(admin) => admin,
        Err(err) => {
            let _ = writeln!(io::stderr(), "dbvalet: `{alias}`: {err}");
            return false;
        }
    };
    let report = match DirectSource::new(alias.clone(), admin).sweep().await {
        Ok(report) => report,
        Err(err) => {
            let _ = writeln!(io::stderr(), "dbvalet: `{alias}`: {err}");
            return false;
        }
    };
    for login in &report.dropped {
        print_line(format_args!(
            "`{alias}`: dropped the leftover login `{login}`"
        ));
    }
    for login in &report.already_gone {
        print_line(format_args!(
            "`{alias}`: removed the ledger entry for `{login}`, whose login was already gone"
        ));
    }
    for err in &report.failures {
        let _ = writeln!(io::stderr(), "dbvalet: `{alias}`: {err}");
    }
    if report.dropped.is_empty() && report.already_gone.is_empty() && report.failures.is_empty() {
        print_line(format_args!("`{alias}`: nothing to clean up"));
    }
    report.failures.is_empty()
}

/// Prints a line of `gc`'s report. A closed stdout mustn't stop the sweep of the next database.
fn print_line(line: fmt::Arguments<'_>) {
    let _ = writeln!(io::stdout(), "{line}");
}

/// The child's exit code, or 128 plus the signal that ended the run, as a shell reports it.
fn exit_code(outcome: WaitOutcome) -> ExitCode {
    let code = match outcome {
        WaitOutcome::Exited(status) => status
            .code()
            .or_else(|| status.signal().map(|signal| 128 + signal))
            .unwrap_or(1),
        WaitOutcome::SignalledBeforeSpawn(signal) => 128 + signal,
        WaitOutcome::TimedOut(signal) => 128 + signal.number(),
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
    fn exit_code_reports_128_plus_signal_for_signal_ended_runs() {
        use crate::signals::TerminationSignal;

        assert_eq!(
            exit_code(WaitOutcome::TimedOut(TerminationSignal::Interrupt)),
            ExitCode::from(130)
        );
        assert_eq!(
            exit_code(WaitOutcome::TimedOut(TerminationSignal::Terminate)),
            ExitCode::from(143)
        );
        assert_eq!(
            exit_code(WaitOutcome::TimedOut(TerminationSignal::Hangup)),
            ExitCode::from(129)
        );
        assert_eq!(
            exit_code(WaitOutcome::SignalledBeforeSpawn(2)),
            ExitCode::from(130)
        );
    }
}

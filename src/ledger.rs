//! Which temporary logins this machine created and hasn't confirmed dropped.
//!
//! One file per login, named `<alias>.<login>`, each locked by the run that owns it.
//! A sweep that can take an entry's lock knows that run has ended.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::{DatabaseAlias, is_login_name};

const READ_ONLY: &str = "read-only\n";
const WRITABLE: &str = "writable\n";
const STATE_DIRECTORY_MODE: u32 = 0o700;

/// No variant carries anything but a path under the state directory and an OS error.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("can't find the state directory: set HOME or XDG_STATE_HOME")]
    NoStateDirectory,
    #[error("couldn't {action} {}: {reason}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        reason: io::Error,
    },
}

/// A ledger entry, locked for as long as this value lives.
#[derive(Debug)]
pub struct Entry {
    path: PathBuf,
    login: String,
    read_only: Option<bool>,
    _lock: File,
}

impl Entry {
    pub fn login(&self) -> &str {
        &self.login
    }

    /// Whether the run that wrote the entry was read-only, or `None` if the entry can't say.
    pub fn read_only(&self) -> Option<bool> {
        self.read_only
    }

    /// Deletes the entry while still holding its lock, so no sweep can take it in between.
    pub fn remove(self) -> Result<(), LedgerError> {
        match fs::remove_file(&self.path) {
            // A sweep that opened the entry before its last owner deleted it may find it gone.
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            result => {
                result.map_err(|reason| io_error("remove the ledger entry", &self.path, reason))
            }
        }
    }
}

/// Writes and locks the entry for `login`, before the login exists.
pub fn create(alias: &DatabaseAlias, login: &str, read_only: bool) -> Result<Entry, LedgerError> {
    let dir = ledger_dir()?;
    DirBuilder::new()
        .recursive(true)
        .mode(STATE_DIRECTORY_MODE)
        .create(&dir)
        .map_err(|reason| io_error("create the ledger directory", &dir, reason))?;
    let name = format!("{alias}.{login}");
    let path = dir.join(&name);
    // Written under a hidden name and renamed once locked, so a sweep never sees it unlocked.
    // shortcut: a crash before the rename leaves the hidden file behind; sweep those if they pile up.
    let staging = dir.join(format!(".{name}"));
    let failed = |reason| io_error("write the ledger entry", &path, reason);
    let mut file = File::create_new(&staging).map_err(failed)?;
    file.lock().map_err(failed)?;
    file.write_all(if read_only { READ_ONLY } else { WRITABLE }.as_bytes())
        .map_err(failed)?;
    fs::rename(&staging, &path).map_err(failed)?;
    Ok(Entry {
        path,
        login: login.to_owned(),
        read_only: Some(read_only),
        _lock: file,
    })
}

/// One entry [`list`] found, not yet opened.
#[derive(Debug)]
pub struct Listed {
    pub alias: DatabaseAlias,
    pub login: String,
    path: PathBuf,
}

impl Listed {
    /// Opens and locks the entry. `None` means its run removed it after it was listed.
    pub fn lock(self) -> Option<State> {
        match lock(&self.path, &self.login) {
            Ok(Some(entry)) => Some(State::Orphan(entry)),
            Ok(None) => Some(State::Held),
            Err(err) if is_not_found(&err) => None,
            Err(err) => Some(State::Unreadable(err)),
        }
    }
}

#[derive(Debug)]
pub enum State {
    /// Its run has ended, and the caller now holds its lock.
    Orphan(Entry),
    /// Another process holds its lock: its run is still going, or another sweep has it.
    Held,
    /// It couldn't be opened, locked or read.
    Unreadable(LedgerError),
}

/// Every entry in the ledger, under any alias, without opening any of them.
pub fn list() -> Result<Vec<Listed>, LedgerError> {
    entries(&ledger_dir()?)
}

/// Opens, locks and reads one entry. `None` means another process holds its lock.
fn lock(path: &Path, login: &str) -> Result<Option<Entry>, LedgerError> {
    let mut file =
        File::open(path).map_err(|reason| io_error("read the ledger entry", path, reason))?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(None),
        Err(TryLockError::Error(reason)) => {
            return Err(io_error("lock the ledger entry", path, reason));
        }
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .map_err(|reason| io_error("read the ledger entry", path, reason))?;
    let read_only = match contents.as_slice() {
        bytes if bytes == READ_ONLY.as_bytes() => Some(true),
        bytes if bytes == WRITABLE.as_bytes() => Some(false),
        _ => None,
    };
    Ok(Some(Entry {
        path: path.to_owned(),
        login: login.to_owned(),
        read_only,
        _lock: file,
    }))
}

fn is_not_found(err: &LedgerError) -> bool {
    matches!(err, LedgerError::Io { reason, .. } if reason.kind() == io::ErrorKind::NotFound)
}

/// Every database alias with at least one entry, live or not.
pub fn aliases() -> Result<BTreeSet<DatabaseAlias>, LedgerError> {
    Ok(list()?.into_iter().map(|listed| listed.alias).collect())
}

fn entries(dir: &Path) -> Result<Vec<Listed>, LedgerError> {
    let listing = match fs::read_dir(dir) {
        Ok(listing) => listing,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(reason) => return Err(io_error("read the ledger", dir, reason)),
    };
    let mut entries = Vec::new();
    for file in listing {
        let file = file.map_err(|reason| io_error("read the ledger", dir, reason))?;
        let name = file.file_name();
        // Anything else in the directory, such as a README, is never opened. No alias starts
        // with `.`, so staging files are skipped too.
        let Some((alias, login)) = name.to_str().and_then(|name| name.split_once('.')) else {
            continue;
        };
        let Ok(alias) = alias.parse() else {
            continue;
        };
        if !is_login_name(login) {
            continue;
        }
        match file.file_type() {
            Ok(file_type) if file_type.is_file() => {}
            Ok(_) => continue,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(reason) => return Err(io_error("read the ledger", dir, reason)),
        }
        entries.push(Listed {
            alias,
            login: login.to_owned(),
            path: file.path(),
        });
    }
    Ok(entries)
}

fn ledger_dir() -> Result<PathBuf, LedgerError> {
    state_dir(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
        .map(|dir| dir.join("ledger"))
        .ok_or(LedgerError::NoStateDirectory)
}

/// `$XDG_STATE_HOME/dbvalet`, else `~/.local/state/dbvalet`. The XDG spec says to ignore a
/// relative `XDG_STATE_HOME`.
fn state_dir(xdg_state_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let base = match xdg_state_home
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
    {
        Some(dir) => dir,
        None => PathBuf::from(home.filter(|home| !home.is_empty())?).join(".local/state"),
    };
    Some(base.join("dbvalet"))
}

fn io_error(action: &'static str, path: &Path, reason: io::Error) -> LedgerError {
    LedgerError::Io {
        action,
        path: path.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_xdg_state_home_holds_the_state_directory() {
        assert_eq!(
            state_dir(Some("/xdg/state".into()), Some("/home/dev".into())),
            Some(PathBuf::from("/xdg/state/dbvalet"))
        );
    }

    #[test]
    fn a_relative_or_missing_xdg_state_home_falls_back_to_home() {
        assert_eq!(
            state_dir(Some("relative/state".into()), Some("/home/dev".into())),
            Some(PathBuf::from("/home/dev/.local/state/dbvalet"))
        );
        assert_eq!(
            state_dir(None, Some("/home/dev".into())),
            Some(PathBuf::from("/home/dev/.local/state/dbvalet"))
        );
    }

    #[test]
    fn without_xdg_state_home_or_home_there_is_no_state_directory() {
        assert_eq!(state_dir(None, None), None);
        assert_eq!(state_dir(None, Some("".into())), None);
    }
}

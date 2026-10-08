//! Persistent client state for registry rollback protection.
//!
//! The highest registry version this client has accepted, and the exact bytes
//! of that document, must survive a restart. Without them a restarted client
//! would accept an older registry, which is the rollback an attacker with a
//! stale signed document would want (SECURITY_MODEL §5.3).
//!
//! The document bytes are stored, not just the number, because the equivocation
//! check compares bytes: two different documents carrying the same version is
//! local evidence that the authority signed more than one registry for that
//! version, and only the stored bytes can detect it.
//!
//! **Trust on first use.** With no stored state there is no baseline, so the
//! first valid document is accepted and recorded. Rollback protection begins at
//! that point. A client that has never fetched a registry cannot tell a current
//! one from an old one, and nothing in this design changes that.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ClientError;

/// Mode for the state file. It holds no secret, but it governs which registry
/// this client will accept, so another local user must not be able to rewrite
/// it and re-enable a rollback.
#[cfg(unix)]
const STATE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryState {
    /// Highest version accepted so far.
    pub highest_version: i64,
    /// The exact document bytes for `highest_version`, base64.
    pub document_b64: String,
    /// Key ids whose signatures were accepted for that document.
    pub key_ids: Vec<String>,
}

/// Where the state file lives.
///
/// `QUIETHOP_STATE_DIR` wins, then `XDG_STATE_HOME/quiethop`, then
/// `~/.local/state/quiethop`, which is the XDG default.
pub fn state_dir() -> Result<PathBuf, ClientError> {
    if let Ok(dir) = std::env::var("QUIETHOP_STATE_DIR") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("quiethop"));
        }
    }
    let home = std::env::var("HOME")
        .map_err(|_| ClientError::State("no QUIETHOP_STATE_DIR, XDG_STATE_HOME or HOME".into()))?;
    Ok(PathBuf::from(home).join(".local/state/quiethop"))
}

pub fn state_path(dir: &Path) -> PathBuf {
    dir.join("registry.json")
}

/// Read the stored state.
///
/// `Ok(None)` means there is no file yet, which is first run. A file that
/// exists but cannot be read or parsed is an error, never a silent reset: a
/// corrupt file that reset the baseline would disable rollback protection at
/// exactly the moment it matters.
pub fn load(dir: &Path) -> Result<Option<RegistryState>, ClientError> {
    let path = state_path(dir);
    let raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ClientError::State(format!(
                "{} is not readable: {e}",
                path.display()
            )))
        }
    };
    let state: RegistryState = serde_json::from_slice(&raw).map_err(|e| {
        ClientError::State(format!(
            "{} is corrupt and will not be ignored: {e}",
            path.display()
        ))
    })?;
    if state.highest_version <= 0 {
        return Err(ClientError::State(format!(
            "{} records a non-positive version",
            path.display()
        )));
    }
    Ok(Some(state))
}

/// Write the state atomically: a temporary file in the same directory, synced,
/// then renamed over the target.
///
/// A partial write would leave a version recorded without the bytes that
/// version refers to, and the equivocation check would then compare against
/// nothing.
pub fn store(dir: &Path, state: &RegistryState) -> Result<(), ClientError> {
    std::fs::create_dir_all(dir)
        .map_err(|e| ClientError::State(format!("cannot create {}: {e}", dir.display())))?;

    let target = state_path(dir);
    let tmp = dir.join("registry.json.tmp");
    let body = serde_json::to_vec_pretty(state)
        .map_err(|e| ClientError::State(format!("cannot encode state: {e}")))?;

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(STATE_MODE);
        }
        let mut f = opts
            .open(&tmp)
            .map_err(|e| ClientError::State(format!("cannot open {}: {e}", tmp.display())))?;
        f.write_all(&body)
            .map_err(|e| ClientError::State(format!("cannot write {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| ClientError::State(format!("cannot sync {}: {e}", tmp.display())))?;
    }

    std::fs::rename(&tmp, &target).map_err(|e| {
        ClientError::State(format!(
            "cannot replace {} with {}: {e}",
            target.display(),
            tmp.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RegistryState {
        RegistryState {
            highest_version: 42,
            document_b64: "eyJ2ZXJzaW9uIjo0Mn0=".to_string(),
            key_ids: vec!["219ec80850bdf73c".to_string()],
        }
    }

    #[test]
    fn first_run_has_no_state() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            load(dir.path()).unwrap(),
            None,
            "first run must report no state"
        );
    }

    #[test]
    fn store_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), &sample()).unwrap();
        assert_eq!(load(dir.path()).unwrap(), Some(sample()));
    }

    #[cfg(unix)]
    #[test]
    fn stored_file_is_mode_0600_and_leaves_no_temp_behind() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), &sample()).unwrap();
        let meta = std::fs::metadata(state_path(dir.path())).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, STATE_MODE);
        assert!(
            !dir.path().join("registry.json.tmp").exists(),
            "the temporary file must be renamed away, not left beside the target"
        );
    }

    #[test]
    fn corrupt_state_is_an_error_not_a_silent_reset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(state_path(dir.path()), b"{not json").unwrap();
        match load(dir.path()) {
            Err(ClientError::State(m)) => assert!(m.contains("corrupt"), "message was {m}"),
            other => panic!("corrupt state was tolerated: {other:?}"),
        }
    }

    #[test]
    fn non_positive_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let bad = RegistryState {
            highest_version: 0,
            ..sample()
        };
        std::fs::write(state_path(dir.path()), serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(matches!(load(dir.path()), Err(ClientError::State(_))));
    }

    #[test]
    fn store_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        store(dir.path(), &sample()).unwrap();
        let newer = RegistryState {
            highest_version: 43,
            document_b64: "eyJ2ZXJzaW9uIjo0M30=".to_string(),
            key_ids: vec!["aaaaaaaaaaaaaaaa".to_string()],
        };
        store(dir.path(), &newer).unwrap();
        assert_eq!(load(dir.path()).unwrap(), Some(newer));
    }

    #[test]
    fn quiethop_state_dir_wins_over_xdg() {
        // Serialised through a mutex because env vars are process-global and
        // these tests would otherwise race each other.
        let _g = env_lock().lock().unwrap();
        let prev_q = std::env::var("QUIETHOP_STATE_DIR").ok();
        let prev_x = std::env::var("XDG_STATE_HOME").ok();
        std::env::set_var("QUIETHOP_STATE_DIR", "/tmp/quiethop-explicit");
        std::env::set_var("XDG_STATE_HOME", "/tmp/quiethop-xdg");
        assert_eq!(
            state_dir().unwrap(),
            PathBuf::from("/tmp/quiethop-explicit")
        );

        std::env::remove_var("QUIETHOP_STATE_DIR");
        assert_eq!(
            state_dir().unwrap(),
            PathBuf::from("/tmp/quiethop-xdg/quiethop")
        );

        restore("QUIETHOP_STATE_DIR", prev_q);
        restore("XDG_STATE_HOME", prev_x);
    }

    fn restore(key: &str, prev: Option<String>) {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }
}

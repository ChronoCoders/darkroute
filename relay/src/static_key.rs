//! On-disk storage for the relay's long-term X25519 static key.
//!
//! The file holds both halves, `private(32) || public(32)`, because snow
//! exposes no way to derive a public key from a private one and
//! ARCHITECTURE §5.1 removes the bare x25519-dalek path. The two halves are
//! checked against each other at load time, so an edited or truncated file
//! fails at startup rather than at the first client connection.
//!
//! The private half is never logged, never printed and never written anywhere
//! but this file (SECURITY_MODEL §8). Only the public half is ever reported.
//!
//! Key generation is a separate subcommand. A relay with no key must fail to
//! start rather than invent one: a fresh key silently invalidates the registry
//! entry that names the old one, so every circuit would fail authentication
//! with no indication why.
//!
//! Unix only. The mode check below is the whole point of the module and there
//! is no equivalent on other platforms.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use quiethop_crypto::noise::{generate_static_keypair, StaticKeypair, STATIC_KEY_LEN};

/// `private(32) || public(32)`.
pub const KEY_FILE_LEN: usize = STATIC_KEY_LEN * 2;

/// The only acceptable mode. Anything with a bit outside this is too loose.
const REQUIRED_MODE: u32 = 0o600;

#[derive(Debug, thiserror::Error)]
pub enum StaticKeyError {
    #[error("static key file {0} does not exist")]
    Missing(String),
    #[error("static key file {0} is not readable: {1}")]
    Unreadable(String, std::io::Error),
    #[error(
        "static key file {path} has mode {mode:04o}, which is looser than {REQUIRED_MODE:04o}"
    )]
    Mode { path: String, mode: u32 },
    #[error("static key file {path} is {got} bytes, expected {KEY_FILE_LEN}")]
    Length { path: String, got: usize },
    #[error("static key file {0} holds halves that do not correspond")]
    Mismatched(String),
    #[error("static key file {0} already exists; refusing to overwrite it")]
    Exists(String),
    #[error("could not generate a static keypair")]
    Generate,
    #[error("could not write {0}: {1}")]
    Write(String, std::io::Error),
}

/// Generate a keypair and write it to `path` with mode 0600.
///
/// Fails if the path already exists. The create is exclusive, so two concurrent
/// keygen runs cannot both believe they wrote the file.
///
/// Returns the public half as hex, for the operator to pass to
/// `/admin/relays/provision`. The private half is not returned and not logged.
pub fn generate(path: &Path) -> Result<String, StaticKeyError> {
    let shown = path.display().to_string();
    let kp = generate_static_keypair().map_err(|_| StaticKeyError::Generate)?;

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(REQUIRED_MODE)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => StaticKeyError::Exists(shown.clone()),
            _ => StaticKeyError::Write(shown.clone(), e),
        })?;

    let mut buf = [0u8; KEY_FILE_LEN];
    buf[..STATIC_KEY_LEN].copy_from_slice(kp.private());
    buf[STATIC_KEY_LEN..].copy_from_slice(&kp.public);
    let write_result = f
        .write_all(&buf)
        .and_then(|()| f.flush())
        .map_err(|e| StaticKeyError::Write(shown.clone(), e));
    for b in buf.iter_mut() {
        *b = 0;
    }
    write_result?;

    Ok(hex_of(&kp.public))
}

/// Load the keypair, refusing anything that is missing, unreadable, too
/// loosely permissioned, the wrong length, or internally inconsistent.
pub fn load(path: &Path) -> Result<StaticKeypair, StaticKeyError> {
    let shown = path.display().to_string();

    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => StaticKeyError::Missing(shown.clone()),
        _ => StaticKeyError::Unreadable(shown.clone(), e),
    })?;

    let mode = meta.permissions().mode() & 0o7777;
    if mode & !REQUIRED_MODE != 0 {
        return Err(StaticKeyError::Mode { path: shown, mode });
    }

    let mut f =
        std::fs::File::open(path).map_err(|e| StaticKeyError::Unreadable(shown.clone(), e))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| StaticKeyError::Unreadable(shown.clone(), e))?;

    if buf.len() != KEY_FILE_LEN {
        let got = buf.len();
        for b in buf.iter_mut() {
            *b = 0;
        }
        return Err(StaticKeyError::Length { path: shown, got });
    }

    let mut private = [0u8; STATIC_KEY_LEN];
    let mut public = [0u8; STATIC_KEY_LEN];
    private.copy_from_slice(&buf[..STATIC_KEY_LEN]);
    public.copy_from_slice(&buf[STATIC_KEY_LEN..]);
    for b in buf.iter_mut() {
        *b = 0;
    }

    StaticKeypair::from_parts(private, public).map_err(|_| StaticKeyError::Mismatched(shown))
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0F) as u32, 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn generate_then_load_round_trips() {
        let dir = tmp();
        let path = dir.path().join("static.key");
        let pub_hex = generate(&path).unwrap();
        assert_eq!(pub_hex.len(), STATIC_KEY_LEN * 2);

        let kp = load(&path).unwrap();
        assert_eq!(
            hex_of(&kp.public),
            pub_hex,
            "load saw a different public key"
        );
    }

    #[test]
    fn generated_file_is_mode_0600_and_the_right_length() {
        let dir = tmp();
        let path = dir.path().join("static.key");
        generate(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, REQUIRED_MODE);
        assert_eq!(meta.len() as usize, KEY_FILE_LEN);
    }

    #[test]
    fn generate_refuses_to_overwrite() {
        let dir = tmp();
        let path = dir.path().join("static.key");
        let first = generate(&path).unwrap();
        assert!(matches!(generate(&path), Err(StaticKeyError::Exists(_))));
        // The original is untouched.
        assert_eq!(hex_of(&load(&path).unwrap().public), first);
    }

    #[test]
    fn load_rejects_a_missing_file() {
        let dir = tmp();
        let path = dir.path().join("absent.key");
        assert!(matches!(load(&path), Err(StaticKeyError::Missing(_))));
    }

    #[test]
    fn load_rejects_a_mode_looser_than_0600() {
        let dir = tmp();
        let path = dir.path().join("static.key");
        generate(&path).unwrap();
        // Control: it loads at 0600.
        assert!(load(&path).is_ok());

        for loose in [0o640u32, 0o604, 0o660, 0o644, 0o700] {
            fs::set_permissions(&path, fs::Permissions::from_mode(loose)).unwrap();
            match load(&path) {
                Err(StaticKeyError::Mode { mode, .. }) => assert_eq!(mode, loose),
                other => panic!("mode {loose:04o} was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn load_accepts_a_stricter_mode() {
        let dir = tmp();
        let path = dir.path().join("static.key");
        generate(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(
            load(&path).is_ok(),
            "0400 is stricter than 0600 and must load"
        );
    }

    #[test]
    fn load_rejects_a_wrong_length() {
        let dir = tmp();
        for (name, len) in [
            ("short.key", KEY_FILE_LEN - 1),
            ("long.key", KEY_FILE_LEN + 1),
        ] {
            let path = dir.path().join(name);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(REQUIRED_MODE)
                .open(&path)
                .unwrap();
            f.write_all(&vec![7u8; len]).unwrap();
            drop(f);
            match load(&path) {
                Err(StaticKeyError::Length { got, .. }) => assert_eq!(got, len),
                other => panic!("length {len} was accepted: {other:?}"),
            }
        }
    }

    #[test]
    fn load_rejects_halves_that_do_not_correspond() {
        let dir = tmp();
        let a = dir.path().join("a.key");
        let b = dir.path().join("b.key");
        generate(&a).unwrap();
        generate(&b).unwrap();

        // Splice a's private half onto b's public half.
        let mut abytes = fs::read(&a).unwrap();
        let bbytes = fs::read(&b).unwrap();
        abytes[STATIC_KEY_LEN..].copy_from_slice(&bbytes[STATIC_KEY_LEN..]);

        let spliced = dir.path().join("spliced.key");
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(REQUIRED_MODE)
            .open(&spliced)
            .unwrap();
        f.write_all(&abytes).unwrap();
        drop(f);

        assert!(matches!(load(&spliced), Err(StaticKeyError::Mismatched(_))));
    }

    #[test]
    fn two_generates_produce_different_keys() {
        let dir = tmp();
        let a = generate(&dir.path().join("a.key")).unwrap();
        let b = generate(&dir.path().join("b.key")).unwrap();
        assert_ne!(a, b, "keygen must not be deterministic");
    }
}

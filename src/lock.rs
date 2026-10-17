//! The application lock: a PIN or password asked before the interface
//! shows, on top of the vault encryption.
//!
//! The vault is already encrypted with a key the platform keeps; the
//! lock is the curtain in front of it, what stops the person holding
//! an unlocked phone rather than the one who extracted the file. The
//! secret itself is never stored: only an Argon2id hash under its own
//! salt, compared in constant time, and guesses slow down after a few
//! failures so that a short PIN cannot be tried a thousand times. The
//! failure count is mirrored in a small file beside the vault, so that
//! quitting and relaunching the app between guesses buys nothing, and
//! moving the clock forward buys a shorter wait, never a free guess.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::{CoreError, CoreResult};
use crate::now_secs;
use crate::store::cipher;

/// What kind of secret unlocks the app. Kept next to the hash so the
/// unlock screen knows which keyboard to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockKind {
    /// Digits only, 4 to 12 of them.
    Pin,
    /// Anything, 8 characters or more.
    Password,
}

/// The stored form of the secret: hex salt and hex Argon2id output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockSecret {
    pub salt: String,
    pub hash: String,
}

/// The lock as the vault keeps it. The apps get a copy with `secret`
/// blanked: they need the kind, never the hash.
///
/// When the lock comes back is not a setting: the secret is asked when
/// the app opens, and again once it has been away — the desktop ends
/// its session by closing, the phone by going to the background. A
/// delay to choose between only ever asked the user to guess how long
/// their own screen is safe for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppLock {
    pub kind: LockKind,
    /// Whether the platform's biometric prompt may stand in for the
    /// secret. The core never sees a biometric: the app asks the OS,
    /// and only skips the secret when the OS says yes.
    #[serde(default)]
    pub biometric: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<LockSecret>,
}

/// Outcome of an unlock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockVerdict {
    pub unlocked: bool,
    /// Consecutive failures so far; zero once unlocked.
    pub failures: u32,
    /// Seconds before the next attempt is even evaluated; zero when it
    /// can be tried now.
    pub retry_after_secs: u32,
}

/// Failures before the delays start.
const FREE_ATTEMPTS: u32 = 3;
/// First delay, doubled at every further failure.
const FIRST_DELAY_SECS: u64 = 5;
/// Longest delay between two attempts.
const MAX_DELAY_SECS: u64 = 300;

/// How long to wait after `failures` consecutive failures: nothing for
/// the first three, then 5 s doubling up to 5 min.
pub fn delay_after(failures: u32) -> Duration {
    if failures < FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    let doublings = (failures - FREE_ATTEMPTS).min(16);
    Duration::from_secs((FIRST_DELAY_SECS << doublings).min(MAX_DELAY_SECS))
}

/// Record of recent failures. It lives with the manager, never in the
/// vault, and is mirrored in a small file beside it: without the file a
/// restart would hand out three free attempts again, and a script that
/// relaunches the app between salvos would try every PIN with no delay
/// at all. In memory the block is an `Instant`, precise and deaf to
/// clock changes; the file stores wall-clock seconds, the only clock
/// that survives a restart, and the one a person can move.
///
/// The file holds a count and a time, nothing derived from the secret,
/// so it is not sensitive: reading it tells an attacker how many
/// guesses they made. Deleting it hands the free attempts back and
/// drops whatever delay had built up: the record slows a script down,
/// it does not stop one that also deletes files, and the strength of
/// the secret has to do the rest.
#[derive(Debug, Default)]
pub struct LockAttempts {
    failures: u32,
    blocked_until: Option<Instant>,
    /// Where the record is mirrored; `None` keeps it in memory only.
    path: Option<PathBuf>,
}

/// The record as the sidecar file stores it.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredAttempts {
    #[serde(default)]
    failures: u32,
    #[serde(default)]
    blocked_until_unix: Option<u64>,
}

impl LockAttempts {
    /// The record mirrored at `path`, read back if the file is there. A
    /// missing or unreadable file is an empty record: the lock must open
    /// for its owner whatever happened to a file that is not the vault.
    pub fn load(path: PathBuf) -> Self {
        remove_stale_temporaries(&path);
        let stored = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<StoredAttempts>(&bytes).ok())
            .unwrap_or_default();
        let mut attempts = Self::restore(stored, now_secs(), Instant::now());
        attempts.path = Some(path);
        attempts
    }

    /// Turns a stored record back into a live one. The block is what the
    /// file says minus the time that passed, with saturating arithmetic:
    /// a clock set back must not shorten it, and a time far in the
    /// future, whether from a clock jump or a doctored file, blocks no
    /// longer than the longest delay ever handed out. A block that reads
    /// as over is re-armed for the first delay all the same: the file
    /// cannot tell an app that stayed closed from a clock moved forward
    /// to end the block, and the first delay costs the owner little.
    fn restore(stored: StoredAttempts, now_unix: u64, now: Instant) -> Self {
        let blocked_until = stored.blocked_until_unix.and_then(|until| {
            let mut remaining = until.saturating_sub(now_unix).min(MAX_DELAY_SECS);
            if stored.failures >= FREE_ATTEMPTS {
                remaining = remaining.max(FIRST_DELAY_SECS);
            }
            (remaining > 0).then(|| now + Duration::from_secs(remaining))
        });
        LockAttempts {
            failures: stored.failures,
            blocked_until,
            path: None,
        }
    }

    /// The record as the file stores it, the block converted to
    /// wall-clock seconds and rounded up so a restart never rounds it
    /// down.
    fn stored(&self, now_unix: u64, now: Instant) -> StoredAttempts {
        StoredAttempts {
            failures: self.failures,
            blocked_until_unix: self
                .blocked_until
                .filter(|until| *until > now)
                .map(|until| {
                    now_unix + until.duration_since(now).as_millis().div_ceil(1000) as u64
                }),
        }
    }

    /// Seconds still to wait, zero when an attempt may be made.
    pub fn retry_after(&self, now: Instant) -> u32 {
        match self.blocked_until {
            Some(until) if until > now => until.duration_since(now).as_secs().max(1) as u32,
            _ => 0,
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Records a failed attempt and starts the matching delay.
    pub fn fail(&mut self, now: Instant) -> LockVerdict {
        self.failures = self.failures.saturating_add(1);
        let delay = delay_after(self.failures);
        self.blocked_until = (delay > Duration::ZERO).then(|| now + delay);
        self.mirror();
        LockVerdict {
            unlocked: false,
            failures: self.failures,
            retry_after_secs: delay.as_secs() as u32,
        }
    }

    pub fn succeed(&mut self) -> LockVerdict {
        self.failures = 0;
        self.blocked_until = None;
        self.forget();
        LockVerdict {
            unlocked: true,
            failures: 0,
            retry_after_secs: 0,
        }
    }

    /// Writes the record to its file, whole or not at all: a new file
    /// beside it, then a rename, the way the vault is saved. Best
    /// effort, since a verdict has no room for a disk error: the record
    /// in memory keeps counting either way, and the file is only what
    /// carries it across a restart.
    fn mirror(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let stored = self.stored(now_secs(), Instant::now());
        let _ = write_whole(path, &stored);
    }

    /// Removes the file: a success ends the count.
    fn forget(&self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn write_whole(path: &Path, stored: &StoredAttempts) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(stored).map_err(std::io::Error::other)?;
    write_through(path, &temporary_path(path), &bytes)
}

/// Writes `bytes` to the new file `tmp`, then renames it over `path`.
/// A new file of its own, its owner's alone: a name no other write
/// picks, so two writers never truncate, remove or rename each other's
/// file, and one that already stands there, a link planted there among
/// others, fails the write instead of being followed.
fn write_through(path: &Path, tmp: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let written = (|| {
        use std::io::Write;
        let mut file =
            crate::store::owner_only(std::fs::OpenOptions::new().write(true).create_new(true))
                .open(tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(tmp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    written
}

/// `gerfaut.attempts.<random>.tmp` beside `gerfaut.attempts`. Not
/// `with_extension`: that would land on a name the vault uses for its
/// own temporary file, and the two are written under different locks.
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".{:016x}.tmp", rand::random::<u64>()));
    path.with_file_name(name)
}

/// Removes the temporary files of writes that never finished: those
/// named after the record, and the one fixed name older builds used.
/// One that another writer is still filling goes too, which only fails
/// its rename: the record it was replacing stays whole.
fn remove_stale_temporaries(path: &Path) {
    let Some(name) = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return;
    };
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        let ours = entry_name
            .strip_prefix(name.as_str())
            .is_some_and(|rest| rest.starts_with('.') && rest.ends_with(".tmp"));
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
        if ours && !is_dir {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Checks that a secret is acceptable for its kind, before it is ever
/// hashed. Rules are deliberately few: the delays are the defence, not
/// a composition policy.
pub fn validate_secret(kind: LockKind, secret: &str) -> CoreResult<()> {
    match kind {
        LockKind::Pin => {
            let digits = secret.chars().count();
            if !(4..=12).contains(&digits) || !secret.chars().all(|c| c.is_ascii_digit()) {
                return Err(CoreError::InvalidInput {
                    kind: "pin",
                    detail: "a PIN is 4 to 12 digits".to_owned(),
                });
            }
        }
        LockKind::Password => {
            let length = secret.chars().count();
            if length < 8 {
                return Err(CoreError::InvalidInput {
                    kind: "password",
                    detail: "a password is at least 8 characters".to_owned(),
                });
            }
            if length > 256 {
                return Err(CoreError::InvalidInput {
                    kind: "password",
                    detail: "a password is at most 256 characters".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Hashes a secret under a fresh salt. Argon2id with the vault's own
/// pinned parameters (m=19456 KiB, t=2, p=1): a dependency bump must
/// never change what an existing lock expects.
pub fn hash_secret(secret: &str) -> CoreResult<LockSecret> {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut hash = derive(secret, &salt)?;
    let stored = LockSecret {
        salt: hex(&salt),
        hash: hex(&hash),
    };
    hash.zeroize();
    Ok(stored)
}

/// Whether `secret` is the one behind `stored`, in constant time over
/// the hash. Malformed stored material counts as a mismatch, never as
/// a match.
pub fn verify_secret(secret: &str, stored: &LockSecret) -> bool {
    let (Some(salt), Some(expected)) = (unhex(&stored.salt), unhex(&stored.hash)) else {
        return false;
    };
    let Ok(mut derived) = derive(secret, &salt) else {
        return false;
    };
    let matches = derived.len() == expected.len() && bool::from(derived.ct_eq(&expected));
    derived.zeroize();
    matches
}

fn derive(secret: &str, salt: &[u8]) -> CoreResult<[u8; 32]> {
    let argon = cipher::argon2id(cipher::OWASP_COST)
        .map_err(|e| CoreError::Internal(format!("argon2 parameters: {e}")))?;
    let mut out = [0u8; 32];
    argon
        .hash_password_into(secret.as_bytes(), salt, &mut out)
        .map_err(|e| CoreError::Internal(format!("argon2: {e}")))?;
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let stored = hash_secret("123456").unwrap();
        assert!(verify_secret("123456", &stored));
        assert!(!verify_secret("123457", &stored));
        assert!(!verify_secret("", &stored));
    }

    /// A stored hash names no profile: the one it was made under must
    /// never move, whatever the vault's profiles do.
    #[test]
    fn a_stored_hash_keeps_matching() {
        let stored = LockSecret {
            salt: "00112233445566778899aabbccddeeff".to_owned(),
            hash: "c13a995629afb54a46a6463d6d828616abf2229ce42a7972afcef4235c4d310b".to_owned(),
        };
        let derived = derive("1234", &unhex(&stored.salt).unwrap()).unwrap();
        assert_eq!(hex(&derived), stored.hash);
        assert!(verify_secret("1234", &stored));
    }

    #[test]
    fn same_secret_different_salts() {
        let a = hash_secret("correct horse").unwrap();
        let b = hash_secret("correct horse").unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.hash, b.hash);
        assert!(!a.hash.contains("correct"));
    }

    #[test]
    fn malformed_stored_material_never_matches() {
        let stored = LockSecret {
            salt: "zz".to_owned(),
            hash: "00".to_owned(),
        };
        assert!(!verify_secret("anything", &stored));
    }

    #[test]
    fn pin_rules() {
        assert!(validate_secret(LockKind::Pin, "1234").is_ok());
        assert!(validate_secret(LockKind::Pin, "123456789012").is_ok());
        assert!(validate_secret(LockKind::Pin, "123").is_err());
        assert!(validate_secret(LockKind::Pin, "1234567890123").is_err());
        assert!(validate_secret(LockKind::Pin, "12a4").is_err());
        assert!(validate_secret(LockKind::Pin, "").is_err());
    }

    #[test]
    fn password_rules() {
        assert!(validate_secret(LockKind::Password, "12345678").is_ok());
        assert!(validate_secret(LockKind::Password, "1234567").is_err());
        assert!(validate_secret(LockKind::Password, &"a".repeat(257)).is_err());
        // Unicode counts in characters, not bytes.
        assert!(validate_secret(LockKind::Password, "ééééééé").is_err());
        assert!(validate_secret(LockKind::Password, "éééééééé").is_ok());
    }

    #[test]
    fn delays_start_after_three_failures_and_cap() {
        assert_eq!(delay_after(0), Duration::ZERO);
        assert_eq!(delay_after(2), Duration::ZERO);
        assert_eq!(delay_after(3), Duration::from_secs(5));
        assert_eq!(delay_after(4), Duration::from_secs(10));
        assert_eq!(delay_after(5), Duration::from_secs(20));
        assert_eq!(delay_after(9), Duration::from_secs(300));
        assert_eq!(delay_after(40), Duration::from_secs(300));
    }

    #[test]
    fn attempts_block_then_reset() {
        let now = Instant::now();
        let mut attempts = LockAttempts::default();
        assert_eq!(attempts.retry_after(now), 0);
        attempts.fail(now);
        attempts.fail(now);
        assert_eq!(attempts.retry_after(now), 0);
        let verdict = attempts.fail(now);
        assert_eq!(verdict.failures, 3);
        assert_eq!(verdict.retry_after_secs, 5);
        assert_eq!(attempts.retry_after(now), 5);
        assert_eq!(attempts.retry_after(now + Duration::from_secs(6)), 0);
        let verdict = attempts.succeed();
        assert!(verdict.unlocked);
        assert_eq!(attempts.failures(), 0);
        assert_eq!(attempts.retry_after(now), 0);
    }

    #[test]
    fn a_stored_block_is_read_back_minus_the_time_that_passed() {
        let now = Instant::now();
        let stored = StoredAttempts {
            failures: 4,
            blocked_until_unix: Some(1_000_010),
        };
        let attempts = LockAttempts::restore(stored, 1_000_000, now);
        assert_eq!(attempts.failures(), 4);
        assert_eq!(attempts.retry_after(now), 10);
        assert_eq!(attempts.retry_after(now + Duration::from_secs(11)), 0);

        // A block that ended while the app was closed is re-armed for
        // the first delay: the file cannot tell a closed app from a
        // clock moved forward.
        let over = StoredAttempts {
            failures: 3,
            blocked_until_unix: Some(999_000),
        };
        assert_eq!(
            LockAttempts::restore(over, 1_000_000, now).retry_after(now),
            FIRST_DELAY_SECS as u32
        );

        // The count alone, no block: the next failure is the fourth.
        let counted = StoredAttempts {
            failures: 3,
            blocked_until_unix: None,
        };
        let mut attempts = LockAttempts::restore(counted, 1_000_000, now);
        assert_eq!(attempts.fail(now).failures, 4);
        assert_eq!(attempts.retry_after(now), 10);
    }

    #[test]
    fn a_clock_set_back_never_shortens_a_block_nor_stretches_it_past_the_cap() {
        let now = Instant::now();
        // Written at 1_000_000 with 10 s to go; the clock now says an
        // hour earlier. Saturating: the block is not over, and it is not
        // an hour long either.
        let skewed = StoredAttempts {
            failures: 4,
            blocked_until_unix: Some(1_000_010),
        };
        let attempts = LockAttempts::restore(skewed, 996_400, now);
        assert_eq!(attempts.retry_after(now), MAX_DELAY_SECS as u32);

        // A time no schedule could have produced is capped the same way.
        let doctored = StoredAttempts {
            failures: 4,
            blocked_until_unix: Some(u64::MAX),
        };
        let attempts = LockAttempts::restore(doctored, 1_000_000, now);
        assert_eq!(attempts.retry_after(now), MAX_DELAY_SECS as u32);
        // And the count cannot overflow a doctored value either.
        let mut attempts = LockAttempts::restore(
            StoredAttempts {
                failures: u32::MAX,
                blocked_until_unix: None,
            },
            1_000_000,
            now,
        );
        assert_eq!(attempts.fail(now).failures, u32::MAX);
    }

    #[test]
    fn a_clock_moved_forward_does_not_end_a_stored_block() {
        let now = Instant::now();
        // Written with five minutes to go; the clock now says a day
        // later. The block is not over: it is the first delay again,
        // and the count stays, so the next failure earns the longest.
        let jumped = StoredAttempts {
            failures: 9,
            blocked_until_unix: Some(1_000_300),
        };
        let attempts = LockAttempts::restore(jumped, 1_086_400, now);
        assert_eq!(attempts.retry_after(now), FIRST_DELAY_SECS as u32);
        assert_eq!(attempts.failures(), 9);

        // A block with more than the first delay left keeps what it has.
        let running = StoredAttempts {
            failures: 5,
            blocked_until_unix: Some(1_000_020),
        };
        assert_eq!(
            LockAttempts::restore(running, 1_000_000, now).retry_after(now),
            20
        );

        // Below the free attempts no block is ever handed out: a file
        // that carries one anyway is read as written.
        let doctored = StoredAttempts {
            failures: 1,
            blocked_until_unix: Some(999_000),
        };
        assert_eq!(
            LockAttempts::restore(doctored, 1_000_000, now).retry_after(now),
            0
        );
    }

    #[test]
    fn the_stored_form_rounds_the_block_up() {
        let now = Instant::now();
        let mut attempts = LockAttempts::default();
        for _ in 0..3 {
            attempts.fail(now);
        }
        // 5 s from `now`, asked 1.5 s later: 3.5 s left, stored as 4.
        let stored = attempts.stored(1_000_000, now + Duration::from_millis(1500));
        assert_eq!(stored.failures, 3);
        assert_eq!(stored.blocked_until_unix, Some(1_000_004));
        // Over: nothing to store but the count.
        let stored = attempts.stored(1_000_000, now + Duration::from_secs(6));
        assert_eq!(stored.blocked_until_unix, None);
        let json = serde_json::to_string(&stored).unwrap();
        assert_eq!(json, r#"{"failures":3,"blocked_until_unix":null}"#);
    }

    /// On Unix the record of failed unlocks is its owner's alone, even
    /// when a write that never finished left its temporary file open to
    /// others.
    #[cfg(unix)]
    #[test]
    fn the_record_is_its_owners_alone() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.attempts");
        let tmp = dir.path().join("gerfaut.attempts.tmp");
        std::fs::write(&tmp, b"half a record").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut attempts = LockAttempts::load(path.clone());
        attempts.fail(Instant::now());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// A link planted at the temporary name a write uses is never
    /// followed: the write fails, the file the link points to keeps its
    /// content, and the next write, under a name of its own, goes
    /// through.
    #[cfg(unix)]
    #[test]
    fn the_record_never_writes_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.attempts");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep me").unwrap();
        // The name the write is about to use, taken by a link first.
        let tmp = temporary_path(&path);
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        let refused = write_through(&path, &tmp, b"{\"failures\":1}").unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        assert!(!path.exists(), "nothing renamed into place");
        // The next write picks a name of its own and goes through.
        let mut attempts = LockAttempts::load(path.clone());
        attempts.fail(Instant::now());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        assert_eq!(LockAttempts::load(path).failures(), 1);
    }

    /// Two writers of the same record with no lock in common, two
    /// copies of the app on one vault: whatever either reads is a whole
    /// record, never one half written or cut by the other's write.
    #[test]
    fn two_writers_never_leave_half_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.attempts");
        let writers: Vec<_> = (0..4)
            .map(|_| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let mut attempts = LockAttempts::load(path.clone());
                    for _ in 0..150 {
                        attempts.fail(Instant::now());
                        if let Ok(bytes) = std::fs::read(&path) {
                            serde_json::from_slice::<StoredAttempts>(&bytes)
                                .expect("a whole record");
                        }
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        assert!(LockAttempts::load(path).failures() > 0);
    }

    #[test]
    fn the_record_survives_in_its_file_and_a_success_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gerfaut.attempts");
        let now = Instant::now();

        let mut attempts = LockAttempts::load(path.clone());
        assert_eq!(attempts.failures(), 0, "no file, nothing counted");
        attempts.fail(now);
        attempts.fail(now);
        attempts.fail(now);
        assert!(path.exists());
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["gerfaut.attempts"], "no temporary file left behind");

        // Another process, later: the block is still on.
        let again = LockAttempts::load(path.clone());
        assert_eq!(again.failures(), 3);
        let wait = again.retry_after(Instant::now());
        assert!((4..=5).contains(&wait), "{wait}");

        let mut again = again;
        again.succeed();
        assert!(!path.exists(), "a success ends the count");
        assert_eq!(LockAttempts::load(path.clone()).failures(), 0);

        // A file that is not the record reads as none.
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(LockAttempts::load(path.clone()).failures(), 0);
        std::fs::write(&path, r#"{"failures":"three"}"#).unwrap();
        assert_eq!(LockAttempts::load(path).failures(), 0);
    }

    #[test]
    fn app_lock_serde_keeps_the_secret_only_when_present() {
        let lock = AppLock {
            kind: LockKind::Pin,
            biometric: true,
            secret: Some(hash_secret("1234").unwrap()),
        };
        let json = serde_json::to_string(&lock).unwrap();
        assert!(json.contains("\"secret\""));
        let back: AppLock = serde_json::from_str(&json).unwrap();
        assert_eq!(back, lock);

        // A redacted copy serializes without the field.
        let redacted = AppLock {
            secret: None,
            ..lock
        };
        assert!(!serde_json::to_string(&redacted).unwrap().contains("secret"));
        // A record written before the delay was dropped still reads:
        // the field it carries is simply no longer anyone's business.
        let old: AppLock =
            serde_json::from_str(r#"{"kind":"password","auto_lock_secs":900}"#).unwrap();
        assert_eq!(old.kind, LockKind::Password);
        assert!(!old.biometric);
        assert!(old.secret.is_none());
    }
}

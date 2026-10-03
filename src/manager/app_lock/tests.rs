//! The app lock, its delays across a restart included.

use super::*;
use crate::manager::ATTEMPTS_FILE;
use crate::manager::tests::support::{key, manager};

#[tokio::test]
async fn app_lock_set_verify_change_clear() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    assert!(manager.app_lock().await.is_none());
    assert!(manager.verify_app_lock("1234").await.is_err());

    manager
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    let lock = manager.app_lock().await.unwrap();
    assert_eq!(lock.kind, LockKind::Pin);
    assert!(lock.secret.is_none(), "the hash never leaves the vault");
    assert!(manager.settings().await.app_lock.unwrap().secret.is_none());
    assert!(manager.verify_app_lock("1234").await.unwrap().unlocked);
    assert!(!manager.verify_app_lock("4321").await.unwrap().unlocked);
    assert!(manager.verify_app_lock("1234").await.unwrap().unlocked);

    // Changing or clearing needs the current secret.
    assert!(
        manager
            .set_app_lock(LockKind::Password, "long enough", None)
            .await
            .is_err()
    );
    assert!(
        manager
            .set_app_lock(LockKind::Password, "long enough", Some("0000"))
            .await
            .is_err()
    );
    manager
        .set_app_lock(LockKind::Password, "long enough", Some("1234"))
        .await
        .unwrap();
    assert_eq!(manager.app_lock().await.unwrap().kind, LockKind::Password);
    assert!(
        manager
            .verify_app_lock("long enough")
            .await
            .unwrap()
            .unlocked
    );
    assert!(manager.clear_app_lock("nope nope").await.is_err());
    manager.clear_app_lock("long enough").await.unwrap();
    assert!(manager.app_lock().await.is_none());

    // It survives a reopen, hash included.
    manager
        .set_app_lock(LockKind::Pin, "9876", None)
        .await
        .unwrap();
    drop(manager);
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    assert!(reopened.verify_app_lock("9876").await.unwrap().unlocked);
}

#[tokio::test]
async fn app_lock_slows_down_after_three_failures() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    for expected in 1..=2 {
        let verdict = manager.verify_app_lock("0000").await.unwrap();
        assert_eq!(verdict.failures, expected);
        assert_eq!(verdict.retry_after_secs, 0);
    }
    let verdict = manager.verify_app_lock("0000").await.unwrap();
    assert_eq!(verdict.failures, 3);
    assert!(verdict.retry_after_secs >= 4);
    // While delayed, even the right secret is not looked at.
    let verdict = manager.verify_app_lock("1234").await.unwrap();
    assert!(!verdict.unlocked);
    assert!(verdict.retry_after_secs > 0);
    assert!(manager.clear_app_lock("1234").await.is_err());
}

/// Quitting and relaunching the app is the obvious way around a
/// delay, and the one a script would take: the count and the block
/// must come back with the vault.
#[tokio::test]
async fn app_lock_delay_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let attempts_file = dir.path().join(ATTEMPTS_FILE);
    let manager = manager(dir.path()).await;
    manager
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    for _ in 0..3 {
        assert!(!manager.verify_app_lock("0000").await.unwrap().unlocked);
    }
    assert!(attempts_file.exists());
    drop(manager);

    // The right PIN, straight after relaunching: still not looked at.
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    let verdict = reopened.verify_app_lock("1234").await.unwrap();
    assert!(!verdict.unlocked);
    assert_eq!(verdict.failures, 3);
    assert!(verdict.retry_after_secs > 0, "{verdict:?}");
    drop(reopened);

    // Two failures carry no delay yet, but they are counted: the
    // first guess after a relaunch is the third, not the first.
    let dir = tempfile::tempdir().unwrap();
    let counted = WalletManager::open(dir.path(), key()).unwrap();
    counted
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    for _ in 0..2 {
        counted.verify_app_lock("0000").await.unwrap();
    }
    drop(counted);
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    let verdict = reopened.verify_app_lock("0000").await.unwrap();
    assert_eq!(verdict.failures, 3);
    assert!(verdict.retry_after_secs >= 4);
    drop(reopened);

    // A success clears the record, file included.
    let dir = tempfile::tempdir().unwrap();
    let attempts_file = dir.path().join(ATTEMPTS_FILE);
    let cleared = WalletManager::open(dir.path(), key()).unwrap();
    cleared
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    cleared.verify_app_lock("0000").await.unwrap();
    assert!(attempts_file.exists());
    assert!(cleared.verify_app_lock("1234").await.unwrap().unlocked);
    assert!(!attempts_file.exists());
}

/// The record is a convenience for the delays, not part of the
/// vault: a file that cannot be read must never lock the owner out.
#[tokio::test]
async fn a_corrupt_attempts_file_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    manager
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    drop(manager);
    std::fs::write(dir.path().join(ATTEMPTS_FILE), b"\x00\xff not a record").unwrap();
    let reopened = WalletManager::open(dir.path(), key()).unwrap();
    let verdict = reopened.verify_app_lock("1234").await.unwrap();
    assert!(verdict.unlocked);
    assert_eq!(verdict.failures, 0);
}

#[tokio::test]
async fn biometric_unlock_needs_a_lock_and_its_secret() {
    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path()).await;
    assert!(manager.set_biometric_unlock(true, "1234").await.is_err());
    manager
        .set_app_lock(LockKind::Pin, "1234", None)
        .await
        .unwrap();
    // Guarded by the secret in place: a wrong one changes nothing,
    // the right one goes through.
    assert!(manager.set_biometric_unlock(true, "0000").await.is_err());
    assert!(!manager.app_lock().await.unwrap().biometric);
    manager.set_biometric_unlock(true, "1234").await.unwrap();
    assert!(manager.app_lock().await.unwrap().biometric);
    // A new secret keeps the biometric choice.
    manager
        .set_app_lock(LockKind::Pin, "5678", Some("1234"))
        .await
        .unwrap();
    assert!(manager.app_lock().await.unwrap().biometric);
}

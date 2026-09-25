//! One process per vault, checked with real processes.
//!
//! The vault is rewritten whole on every save, so two processes on the
//! same data directory would each save their own copy over the other's.
//! The lock that prevents it belongs to the operating system, and only a
//! second process shows what the system does with it: this test binary
//! runs itself again as that process, through `child_process_role`,
//! which does nothing unless the parent asked for it.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};

use gerfaut_core::error::VaultError;
use gerfaut_core::store::VaultKey;
use gerfaut_core::{CoreError, WalletManager};

/// Tells the child what to do: `open`, or `hold` until it is killed.
const ROLE: &str = "GERFAUT_VAULT_LOCK_ROLE";
/// The data directory the child opens.
const DIR: &str = "GERFAUT_VAULT_LOCK_DIR";

fn key() -> VaultKey {
    VaultKey::Raw([7u8; 32])
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// The child's side. It opens the vault and says what happened after
/// `RESULT:` on a line of its output.
#[test]
fn child_process_role() {
    let (Ok(role), Some(dir)) = (std::env::var(ROLE), std::env::var_os(DIR)) else {
        return;
    };
    let say = |line: String| {
        let mut out = std::io::stdout();
        writeln!(out, "RESULT:{line}").unwrap();
        out.flush().unwrap();
    };
    match WalletManager::open(&dir, key()) {
        Err(CoreError::Vault(VaultError::AlreadyOpen)) => say("already_open".to_owned()),
        Err(other) => say(format!("error:{other}")),
        Ok(manager) => {
            let gap = runtime().block_on(manager.settings()).gap_limit;
            if role == "hold" {
                say("holding".to_owned());
                // Until the parent kills this process, or goes away.
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
            } else {
                say(format!("opened:{gap}"));
            }
        }
    }
}

fn spawn_child(role: &str, dir: &Path) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "child_process_role",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .env(DIR, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// What a child that holds on said, read as soon as it is written.
fn result_of(child: &mut Child) -> String {
    let stdout = child.stdout.take().unwrap();
    for line in BufReader::new(stdout).lines() {
        let line = line.unwrap();
        // The harness may have begun the line with the test's name.
        if let Some((_, result)) = line.split_once("RESULT:") {
            return result.to_owned();
        }
    }
    panic!("the child process said nothing");
}

/// Runs a child that opens the vault, to the end, and returns what it
/// said.
fn run_child(dir: &Path) -> String {
    let output = spawn_child("open", dir).wait_with_output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let (_, result) = stdout
        .split_once("RESULT:")
        .expect("the child said nothing");
    result.lines().next().unwrap().to_owned()
}

#[test]
fn a_second_process_is_refused_and_the_first_vault_is_intact() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("gerfaut.vault");
    let rt = runtime();

    let manager = WalletManager::open(dir.path(), key()).unwrap();
    rt.block_on(manager.set_gap_limit(42)).unwrap();
    let before = std::fs::read(&vault).unwrap();

    assert_eq!(run_child(dir.path()), "already_open");

    // The refused process wrote nothing, and the first one carries on.
    assert_eq!(std::fs::read(&vault).unwrap(), before);
    let mut names: Vec<String> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["gerfaut.vault", "gerfaut.vault.lock"]);
    rt.block_on(manager.set_gap_limit(43)).unwrap();

    // Closed here, the vault opens there, with everything saved here.
    drop(manager);
    assert_eq!(run_child(dir.path()), "opened:43");
}

#[test]
fn a_killed_holder_leaves_no_stale_lock() {
    let dir = tempfile::tempdir().unwrap();
    drop(WalletManager::open(dir.path(), key()).unwrap());

    let mut holder = spawn_child("hold", dir.path());
    assert_eq!(result_of(&mut holder), "holding");
    assert!(matches!(
        WalletManager::open(dir.path(), key()),
        Err(CoreError::Vault(VaultError::AlreadyOpen))
    ));

    // A crash, as far as the vault can tell: no destructor runs.
    holder.kill().unwrap();
    holder.wait().unwrap();

    let manager = WalletManager::open(dir.path(), key()).unwrap();
    assert_eq!(runtime().block_on(manager.settings()).gap_limit, 20);
}
